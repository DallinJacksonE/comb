//! User-service bootstrap: no network listeners or decrypted keys until local unlock.
use crate::{daemon, identity, store::Store};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{
    io::ErrorKind,
    net::SocketAddr,
    os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    sync::oneshot,
    task::JoinHandle,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const MAX_MESSAGE: usize = 32 * 1024;
// Identity profiles already have a 1 MiB on-disk limit; leave room for IPC framing.
const MAX_PROFILE_MESSAGE: usize = 1024 * 1024 + 1024;
pub const MAX_PASSWORD_BYTES: usize = 4096;
const SOCKET: &str = "service.sock";

#[derive(Clone)]
pub struct Config {
    pub data: PathBuf,
    pub listen: SocketAddr,
    pub peer_listen: SocketAddr,
    pub ssh_listen: Option<SocketAddr>,
    pub assets: PathBuf,
    pub sync_seconds: u64,
    pub web: Option<crate::web_host::Config>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Uninitialized,
    Locked,
    Ready,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Request {
    Status,
    Session,
    Profile,
    Unlock { password: Vec<u8> },
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
struct Response {
    #[zeroize(skip)]
    state: State,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[zeroize(skip)]
    profile: Option<identity::Profile>,
}

pub struct Session {
    pub token: Zeroizing<String>,
}

struct SocketGuard(PathBuf);
impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct Running {
    task: JoinHandle<Result<()>>,
    stop: oneshot::Sender<()>,
    app: crate::api::App,
}

/// Unlock off the async executor and acknowledge only after listeners bind.
async fn start_frame(config: Config, secret: Zeroizing<Vec<u8>>) -> Result<Running> {
    let data = config.data.clone();
    let store = tokio::task::spawn_blocking(move || Store::open(&data, &secret)).await??;
    let (stop, stopped) = oneshot::channel();
    let (ready, receipt) = oneshot::channel();
    let task = tokio::spawn(daemon::run_until(
        store,
        daemon::Listeners {
            http: config.listen,
            peer: config.peer_listen,
            ssh: config.ssh_listen,
            web: config.web,
        },
        config.assets,
        config.sync_seconds,
        async {
            let _ = stopped.await;
        },
        Some(ready),
    ));
    let app = match receipt.await {
        Ok(app) => app,
        Err(_) => {
            task.await??;
            bail!("FRAME did not bind its listeners");
        }
    };
    Ok(Running { task, stop, app })
}

/// Start a locked service; the socket is private to the same trusted local user.
pub async fn run(config: Config) -> Result<()> {
    if let Some(web) = &config.web {
        web.validate()?;
    }
    ensure!(
        config.listen.ip().is_loopback(),
        "management HTTP must bind loopback"
    );
    identity::private_directory(&config.data)?;
    let lock = config.data.join("service.lock");
    ensure!(!lock.is_symlink(), "refusing service lock symlink");
    let lock = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(lock)?;
    lock.try_lock()
        .context("another managed FRAME owns this data directory")?;
    let socket = config.data.join(SOCKET);
    match std::fs::symlink_metadata(&socket) {
        Ok(meta) => {
            ensure!(
                meta.file_type().is_socket(),
                "refusing to replace non-socket control path"
            );
            std::fs::remove_file(&socket)?;
        }
        Err(error) if error.kind() == ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener =
        UnixListener::bind(&socket).context("cannot bind private FRAME service socket")?;
    let _socket = SocketGuard(socket.clone());
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
    let mut running: Option<Running> = None;
    let shutdown = daemon::shutdown_signal();
    tokio::pin!(shutdown);
    tracing::info!("Managed FRAME waiting for local initialization/unlock; run comb in a terminal");
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            finished = async {
                match running.as_mut() {
                    Some(frame) => (&mut frame.task).await,
                    None => std::future::pending().await,
                }
            } => {
                finished??;
                bail!("unlocked FRAME stopped unexpectedly; restart the user service");
            }
            connection = listener.accept() => {
                let (mut stream, _) = connection?;
                let request = tokio::time::timeout(Duration::from_secs(5), read_request(&mut stream)).await;
                let request = match request { Ok(Ok(request)) => request, _ => continue };
                let mut response = Response { state: current_state(&config.data, running.is_some()), error: None, token: None, profile: None };
                if let Request::Unlock { password } = &request
                    && running.is_none() {
                        if password.is_empty() || password.len() > MAX_PASSWORD_BYTES {
                            response.error = Some("Invalid unlock request".into());
                        } else {
                            match start_frame(config.clone(), Zeroizing::new(password.clone())).await {
                                Ok(frame) => {
                                    running = Some(frame);
                                    response.state = State::Ready;
                                }
                                Err(error) if error.is::<identity::IncorrectPassword>() => {
                                    response.error = Some(identity::IncorrectPassword.to_string());
                                }
                                Err(_) => response.error = Some("Could not unlock/start FRAME. Verify local state and configured ports".into()),
                            }
                        }
                }
                if matches!(&request, Request::Session | Request::Profile) {
                    if let Some(frame) = &running {
                        if matches!(&request, Request::Session) {
                            response.token = Some(frame.app.execute(|store| Ok(store.local.token.clone())).await?);
                        } else {
                            response.profile = Some(frame.app.execute(|store| Ok(store.profile().clone())).await?);
                        }
                    } else {
                        response.error = Some("FRAME is locked; unlock it in an interactive terminal first".into());
                    }
                }
                let mut bytes = Zeroizing::new(serde_json::to_vec(&response)?);
                bytes.push(b'\n');
                // A disconnected client must not terminate a working FRAME.
                let _ = tokio::time::timeout(Duration::from_secs(5), stream.write_all(&bytes)).await;
            }
        }
    }
    if let Some(frame) = running {
        let _ = frame.stop.send(());
        frame.task.await??;
    }
    Ok(())
}

fn current_state(data: &Path, ready: bool) -> State {
    if ready {
        State::Ready
    } else if data.join("node.vault").exists() {
        State::Locked
    } else {
        State::Uninitialized
    }
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let bytes = read_message(stream, MAX_MESSAGE).await?;
    Ok(serde_json::from_slice(&bytes)?)
}

/// Bound IPC before deserialization, and clear password-bearing buffers on drop.
async fn read_message(stream: &mut UnixStream, limit: usize) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        let count = stream.read(&mut *chunk).await?;
        ensure!(count != 0, "FRAME service closed the connection");
        let end = chunk[..count].iter().position(|&b| b == b'\n');
        let length = end.unwrap_or(count);
        ensure!(bytes.len() + length <= limit, "oversized service message");
        bytes.extend_from_slice(&chunk[..length]);
        if end.is_some() {
            return Ok(bytes);
        }
    }
}

async fn exchange(data: &Path, request: &Request) -> Result<Option<Response>> {
    let socket = data.join(SOCKET);
    match std::fs::symlink_metadata(&socket) {
        Ok(meta) => ensure!(
            meta.file_type().is_socket() && meta.permissions().mode() & 0o077 == 0,
            "FRAME service socket must be a private Unix socket"
        ),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let mut stream = match UnixStream::connect(socket).await {
        Ok(stream) => stream,
        Err(error)
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Zeroizing::new(serde_json::to_vec(request)?);
    bytes.push(b'\n');
    let response = tokio::time::timeout(Duration::from_secs(120), async {
        stream.write_all(&bytes).await?;
        let limit = if matches!(request, Request::Profile) {
            MAX_PROFILE_MESSAGE
        } else {
            MAX_MESSAGE
        };
        let bytes = read_message(&mut stream, limit).await?;
        Ok::<Response, anyhow::Error>(serde_json::from_slice(&bytes)?)
    })
    .await
    .context("FRAME service request timed out")??;
    Ok(Some(response))
}

/// Read private service state without initialization, decryption, or network listeners.
pub async fn status(data: &Path) -> Result<Option<State>> {
    Ok(exchange(data, &Request::Status)
        .await?
        .map(|response| response.state))
}

/// Send an ephemeral unlock secret only over the private local control socket.
pub async fn unlock(data: &Path, password: &[u8]) -> Result<()> {
    ensure!(
        !password.is_empty() && password.len() <= MAX_PASSWORD_BYTES,
        "Managed FRAME unlock password must contain 1..4096 bytes. For an existing longer-password vault, stop the user service and use manual comb serve; recover/enroll a fresh FRAME with a compatible password before using managed startup"
    );
    let request = Request::Unlock {
        password: password.to_vec(),
    };
    let mut response = exchange(data, &request)
        .await?
        .context("managed FRAME is not running; start the user service")?;
    if let Some(error) = response.error.take() {
        if error == identity::IncorrectPassword.to_string() {
            return Err(identity::IncorrectPassword.into());
        }
        bail!("{error}");
    }
    ensure!(response.state == State::Ready, "FRAME did not become ready");
    Ok(())
}

/// Reuse the unlocked local session without saving secrets or prompting per command.
/// Read current credentials so restore/reset token rotation is respected.
pub async fn session(data: &Path) -> Result<Option<Session>> {
    let Some(mut response) = exchange(data, &Request::Session).await? else {
        return Ok(None);
    };
    if response.state != State::Ready {
        return Ok(None);
    }
    let token = response
        .token
        .take()
        .context("FRAME session omitted its credential")?;
    Ok(Some(Session {
        token: Zeroizing::new(token),
    }))
}

/// Retrieve public profile data separately from the small credential message.
pub async fn profile(data: &Path) -> Result<Option<identity::Profile>> {
    let Some(mut response) = exchange(data, &Request::Profile).await? else {
        return Ok(None);
    };
    if response.state != State::Ready {
        return Ok(None);
    }
    Ok(Some(
        response
            .profile
            .take()
            .context("FRAME omitted its public profile")?,
    ))
}
