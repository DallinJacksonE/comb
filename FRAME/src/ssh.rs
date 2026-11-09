//! Public-key-only, native streaming Git SSH transport. No shell is invoked.
//!
//! SSH keys identify locally validated or explicitly pinned FRAME profiles, not
//! arbitrary system users. Authentication alone grants no CELL access: each pack
//! operation is reauthorized through `Store::ssh_transfer`, holding the serialized
//! store lock through transfer and publication. Writes use a private stage; native
//! Git protocol success is followed by store validation and signed persistence.
mod command;

use crate::api::App;
use anyhow::{Context, Result, ensure};
use comb_cell::FrameCertificate;
use russh::{
    Channel, ChannelId, Disconnect,
    server::{self, Msg, Session},
};
use std::{
    collections::HashMap, future::Future, path::Path, process::Stdio, sync::Arc, time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    sync::{Mutex, Semaphore, watch},
    task::JoinHandle,
};

const IDLE: Duration = Duration::from_secs(30);
const SESSION: Duration = Duration::from_secs(15 * 60);
/// Transfer tasks retained so normal server shutdown can wait for child cleanup.
type Jobs = Arc<Mutex<Vec<JoinHandle<()>>>>;

/// Cloned socket guard that forcibly shuts down both directions when dropped.
struct CloseSocket(std::net::TcpStream);
impl Drop for CloseSocket {
    /// Interrupt the SSH transport even if another task still owns the socket.
    fn drop(&mut self) {
        let _ = self.0.shutdown(std::net::Shutdown::Both);
    }
}

/// Broadcast cancellation on drop, including when the owning future is cancelled.
struct Stop(watch::Sender<bool>);
impl Drop for Stop {
    /// Mark the watched lifecycle stopped without requiring a live receiver.
    fn drop(&mut self) {
        self.0.send_replace(true);
    }
}

/// Serve public-key Git SSH on an already-bound listener until shutdown/revocation.
///
/// Allows at most 64 connections and eight queued/running transfers, with one
/// session channel and exec per connection. Applies a 10-second startup timeout,
/// 30-second inactivity limit, and 15-minute session limit. Shells, PTYs,
/// subsystems, and environment changes are refused. Accept/socket errors propagate;
/// per-client failures are isolated. Normal shutdown closes the listener, broadcasts
/// cancellation, and awaits session/transfer cleanup; dropping the future also
/// broadcasts cancellation but cannot await cleanup.
pub async fn run(
    listener: TcpListener,
    app: App,
    host_key: russh::keys::PrivateKey,
    shutdown: impl Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let (stop, _) = watch::channel(false);
    let stop = Stop(stop);
    let config = Arc::new(server::Config {
        keys: vec![host_key],
        methods: (&[russh::MethodKind::PublicKey][..]).into(),
        auth_rejection_time: Duration::from_millis(200),
        auth_rejection_time_initial: Some(Duration::from_millis(200)),
        inactivity_timeout: Some(IDLE),
        channel_buffer_size: 8,
        event_buffer_size: 8,
        window_size: 256 * 1024,
        maximum_packet_size: 32768,
        max_auth_attempts: 3,
        ..Default::default()
    });
    let jobs: Jobs = Arc::default();
    let limit = Arc::new(Semaphore::new(64));
    let transfers = Arc::new(Semaphore::new(8));
    let mut sessions: Vec<JoinHandle<()>> = Vec::new();
    let mut enabled = app.peer_enabled.subscribe();
    tokio::pin!(shutdown);
    loop {
        if !*enabled.borrow() {
            break;
        }
        tokio::select! {
            _ = &mut shutdown => break,
            _ = enabled.changed() => { if !*enabled.borrow() { break; } },
            incoming = listener.accept() => {
                let (socket, _) = incoming?;
                let socket = socket.into_std()?;
                let transport = CloseSocket(socket.try_clone()?);
                let socket = tokio::net::TcpStream::from_std(socket)?;
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue };
                let (connection, disconnected) = watch::channel(false);
                let handler = GitHandler { app: app.clone(), certificate: None, channels: HashMap::new(),
                    stop: stop.0.subscribe(), _connection: Stop(connection), disconnected, jobs: jobs.clone(), transfers: transfers.clone(), used: false };
                let config = config.clone();
                let mut cancelled = stop.0.subscribe();
                sessions.retain(|task| !task.is_finished());
                sessions.push(tokio::spawn(async move {
                    let _permit = permit;
                    let transport = transport;
                    let started = tokio::select! {
                        _ = cancelled.changed() => return,
                        result = tokio::time::timeout(Duration::from_secs(10), server::run_stream(config, socket, handler)) => result,
                    };
                    if let Ok(Ok(mut session)) = started {
                        let handle = session.handle();
                        tokio::select! {
                            _ = &mut session => return,
                            _ = cancelled.changed() => {},
                            _ = tokio::time::sleep(SESSION) => {},
                        }
                        drop(transport);
                        let _ = handle.disconnect(Disconnect::ByApplication, "FRAME SSH session ended".into(), "en".into()).await;
                        let _ = tokio::time::timeout(Duration::from_secs(5), session).await;
                    }
                }));
            }
        }
    }
    drop(listener);
    stop.0.send_replace(true);
    for session in sessions {
        let _ = session.await;
    }
    let pending = std::mem::take(&mut *jobs.lock().await);
    for job in pending {
        let _ = job.await;
    }
    Ok(())
}

/// Per-connection principal and bounded, single-exec channel state.
struct GitHandler {
    app: App,
    /// Profile certificate selected by username/key authentication, never by exec data.
    certificate: Option<FrameCertificate>,
    /// Accepted channels waiting for their sole exec request.
    channels: HashMap<ChannelId, Channel<Msg>>,
    /// Server-wide cancellation, distinct from this connection's disconnect signal.
    stop: watch::Receiver<bool>,
    /// Signals disconnection when russh drops this handler.
    _connection: Stop,
    disconnected: watch::Receiver<bool>,
    jobs: Jobs,
    /// Shared permit pool also bounds jobs waiting for the store transaction lock.
    transfers: Arc<Semaphore>,
    /// Prevent a second exec even after the first channel leaves the map.
    used: bool,
}

impl server::Handler for GitHandler {
    type Error = anyhow::Error;

    /// Match a username/key to a validated local or pinned profile certificate.
    /// Store errors are deliberately converted into authentication rejection.
    async fn auth_publickey(
        &mut self,
        user: &str,
        key: &russh::keys::PublicKey,
    ) -> Result<server::Auth> {
        let user = user.to_owned();
        let key = key.clone();
        self.certificate = self
            .app
            .execute(move |store| store.ssh_authenticate(&user, &key))
            .await
            .ok();
        Ok(if self.certificate.is_some() {
            server::Auth::Accept
        } else {
            server::Auth::reject()
        })
    }

    /// Accept one session channel only after authentication; reject additional ones.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _: &mut Session,
    ) -> Result<()> {
        // One channel and one exec per connection bounds resources and avoids
        // multi-channel dependencies while holding the serialized Store lock.
        if self.used || !self.channels.is_empty() || self.certificate.is_none() {
            reply
                .reject(russh::ChannelOpenFailure::AdministrativelyProhibited)
                .await;
        } else {
            self.channels.insert(channel.id(), channel);
            reply.accept().await;
        }
        Ok(())
    }

    /// Parse a fixed pack command and enqueue a store-authorized streaming transfer.
    ///
    /// Channel success acknowledges exec admission, not repository authorization
    /// or push publication. Failures subsequently produce exit status 1 and close
    /// the channel; detailed errors are debug-logged rather than sent as shell text.
    async fn exec_request(
        &mut self,
        id: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<()> {
        let parsed = command::parse(data);
        let Some(channel) = self.channels.remove(&id) else {
            session.channel_failure(id)?;
            return Ok(());
        };
        let (Ok(command), Some(certificate)) = (parsed, self.certificate.clone()) else {
            session.channel_failure(id)?;
            session.close(id)?;
            return Ok(());
        };
        if self.used {
            session.channel_failure(id)?;
            session.close(id)?;
            return Ok(());
        }
        let Ok(permit) = self.transfers.clone().try_acquire_owned() else {
            session.channel_failure(id)?;
            session.close(id)?;
            return Ok(());
        };
        self.used = true;
        session.channel_success(id)?;
        let app = self.app.clone();
        let handle = session.handle();
        let stop = self.stop.clone();
        let disconnected = self.disconnected.clone();
        let runtime = tokio::runtime::Handle::current();
        let job = tokio::spawn(async move {
            // Bound queued Store jobs even when clients disconnect while a
            // different transfer owns the serialized transaction lock.
            let _permit = permit;
            let result = app
                .execute(move |store| {
                    ensure!(
                        !*stop.borrow() && !*disconnected.borrow(),
                        "SSH session closed"
                    );
                    store.ssh_transfer(&certificate, &command.repository, command.write, |path| {
                        runtime.block_on(transfer(path, command.write, channel, stop, disconnected))
                    })
                })
                .await;
            if let Err(error) = &result {
                tracing::debug!(%error, "SSH Git transfer rejected or interrupted");
            }
            let _ = handle
                .exit_status_request(id, if result.is_ok() { 0 } else { 1 })
                .await;
            let _ = handle.eof(id).await;
            let _ = handle.close(id).await;
        });
        let mut jobs = self.jobs.lock().await;
        jobs.retain(|job| !job.is_finished());
        jobs.push(job);
        Ok(())
    }

    /// Reject interactive shells and close the requesting channel.
    async fn shell_request(&mut self, id: ChannelId, s: &mut Session) -> Result<()> {
        s.channel_failure(id)?;
        s.close(id)?;
        Ok(())
    }
    /// Reject all subsystems, including SFTP, and close the channel.
    async fn subsystem_request(&mut self, id: ChannelId, _: &str, s: &mut Session) -> Result<()> {
        s.channel_failure(id)?;
        s.close(id)?;
        Ok(())
    }
    /// Reject terminal allocation and close the channel; Git requires no PTY.
    async fn pty_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: u32,
        _: u32,
        _: u32,
        _: u32,
        _: &[(russh::Pty, u32)],
        s: &mut Session,
    ) -> Result<()> {
        s.channel_failure(id)?;
        s.close(id)?;
        Ok(())
    }
    /// Refuse client environment injection without closing an otherwise usable channel.
    async fn env_request(
        &mut self,
        id: ChannelId,
        _: &str,
        _: &str,
        s: &mut Session,
    ) -> Result<()> {
        s.channel_failure(id)?;
        Ok(())
    }
}

/// Fixed-size buffers plus russh's bounded queues propagate backpressure all the
/// way to the child pipes. A shared deadline counts activity on any pipe;
/// a quiet stderr must not terminate a healthy bulk transfer.
/// Copies until EOF without closing the destination; read/write errors propagate.
async fn pump(
    mut input: impl AsyncRead + Unpin,
    mut output: impl AsyncWrite + Unpin,
    activity: &watch::Sender<tokio::time::Instant>,
) -> Result<()> {
    let mut buffer = [0; 32768];
    loop {
        let n = input.read(&mut buffer).await?;
        if n == 0 {
            return Ok(());
        }
        activity.send_replace(tokio::time::Instant::now());
        output.write_all(&buffer[..n]).await?;
        activity.send_replace(tokio::time::Instant::now());
    }
}

/// Wait until no pipe reports activity for `deadline`, or all senders are dropped.
async fn idle(mut activity: watch::Receiver<tokio::time::Instant>, deadline: Duration) {
    loop {
        let until = *activity.borrow_and_update() + deadline;
        tokio::select! {
            _ = tokio::time::sleep_until(until) => return,
            changed = activity.changed() => { if changed.is_err() { return; } },
        }
    }
}

/// Bridge one SSH channel to a fixed native Git pack process at an authorized path.
///
/// Clears the environment, streams stdout and extended-data stderr with bounded
/// buffers, and closes child stdin at client EOF. The caller supplies the trusted
/// repository/stage and owns authorization/publication. I/O errors, nonzero Git
/// status, cancellation, and deadlines fail the transfer; error cleanup attempts
/// to kill the process group (including pack descendants) and reap the child.
async fn transfer(
    path: &Path,
    write: bool,
    mut channel: Channel<Msg>,
    mut stop: watch::Receiver<bool>,
    mut disconnected: watch::Receiver<bool>,
) -> Result<()> {
    ensure!(
        !*stop.borrow() && !*disconnected.borrow(),
        "SSH session closed"
    );
    let mut child = tokio::process::Command::new("git")
        .arg(if write { "receive-pack" } else { "upload-pack" })
        .arg(path)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("HOME", "/nonexistent")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .process_group(0)
        .spawn()
        .context("spawn native Git SSH backend")?;
    let mut stdin = child.stdin.take().context("Git stdin")?;
    let stdout = child.stdout.take().context("Git stdout")?;
    let stderr = child.stderr.take().context("Git stderr")?;
    let output = channel.make_writer();
    let errors = channel.make_writer_ext(Some(1));
    let reader = channel.make_reader();
    let (activity, progress) = watch::channel(tokio::time::Instant::now());
    let operation = async {
        let input = async {
            pump(reader, &mut stdin, &activity).await?;
            stdin.shutdown().await?;
            drop(stdin);
            Ok::<_, anyhow::Error>(())
        };
        let complete = async {
            let (status, _, _) = tokio::try_join!(
                async { Ok::<_, anyhow::Error>(child.wait().await?) },
                pump(stdout, output, &activity),
                pump(stderr, errors, &activity)
            )?;
            ensure!(status.success(), "Git pack process failed");
            Ok::<_, anyhow::Error>(())
        };
        tokio::pin!(input, complete);
        tokio::select! {
            result = &mut complete => result,
            result = &mut input => { result?; complete.await },
        }
    };
    let result = tokio::select! {
        _ = idle(progress, IDLE) => Err(anyhow::anyhow!("SSH Git idle deadline")),
        _ = stop.changed() => Err(anyhow::anyhow!("SSH server stopped")),
        _ = disconnected.changed() => Err(anyhow::anyhow!("SSH client disconnected")),
        result = tokio::time::timeout(SESSION, operation) => result.context("SSH Git session deadline").and_then(|result| result),
    };
    if result.is_err() {
        // Native Git may have pack-objects/index-pack descendants. Put the
        // backend in its own process group and terminate that entire group,
        // not only the immediate child. This executable is never a shell.
        if let Some(pid) = child.id() {
            let mut kill = tokio::process::Command::new("/bin/kill");
            kill.args(["-KILL", "--", &format!("-{pid}")])
                .env_clear()
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let _ = tokio::time::timeout(Duration::from_secs(1), kill.status()).await;
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

#[cfg(test)]
/// Transport timing regression tests independent of a running SSH listener.
mod tests {
    #[tokio::test]
    /// Activity on any shared pipe postpones the inactivity timeout.
    async fn idle_deadline_is_shared_by_all_pipes() {
        let (activity, receiver) = tokio::sync::watch::channel(tokio::time::Instant::now());
        let waiter = tokio::spawn(super::idle(receiver, std::time::Duration::from_millis(100)));
        for _ in 0..8 {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            activity.send_replace(tokio::time::Instant::now());
            assert!(!waiter.is_finished(), "active transfer was timed out");
        }
        tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();
    }
}
