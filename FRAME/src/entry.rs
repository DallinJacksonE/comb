//! CLI execution. All domain/network behavior uses the shared library services.
use crate::cli::{CellCommand, Cli, Command, Enrollment, IceCommand, PeerCommand};
use anyhow::{Context, Result, bail};
use clap::CommandFactory;

use comb_frame::{identity, snapshot::Snapshot, store::Store};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    io::{self, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

pub async fn run() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let cli = Cli::parse_compatible_from(std::env::args_os()).unwrap_or_else(|error| error.exit());
    let data = cli.data.clone().unwrap_or_else(default_data);
    let show_help = cli.command.is_none();
    if show_help && data.join("node.vault").exists() {
        Cli::command().print_help()?;
        return Ok(());
    }
    let command = cli.command.unwrap_or(Command::User {
        username: None,
        ssh_config: None,
        ssh_listen: None,
        name: None,
        email: None,
        recovery: None,
    });
    let mut cached_password = crate::onboarding::prepare(&data, &command).await?;
    if show_help {
        Cli::command().print_help()?;
        return Ok(());
    }
    let session = if matches!(
        &command,
        Command::ServiceStatus
            | Command::Serve { .. }
            | Command::Enroll { .. }
            | Command::Recover { .. }
            | Command::Ice { .. }
            | Command::Ssh { .. }
    ) {
        None
    } else {
        comb_frame::managed::session(&data).await?
    };
    match command {
        Command::Ssh { action } => crate::cli_ssh::run(&data, action)?,
        Command::ServiceStatus => {
            let state = comb_frame::managed::status(&data)
                .await?
                .context("Managed FRAME control socket is not ready")?;
            print_json(&serde_json::json!({"state": state}))?;
        }
        Command::User {
            name,
            email,
            recovery,
            username,
            ssh_config,
            ssh_listen,
        } => {
            if session.is_some() {
                print_json(
                    &comb_frame::managed::profile(&data)
                        .await?
                        .context("FRAME session ended before reading profile")?,
                )?;
                return Ok(());
            }
            let local = if data.join("node.vault").exists() {
                crate::onboarding::unlock_local(
                    &mut cached_password,
                    "FRAME password: ",
                    |secret| identity::load(&data, secret),
                )?
                .1
            } else {
                let secret = crate::onboarding::initialize(
                    &data,
                    crate::onboarding::Options {
                        name,
                        email,
                        recovery,
                        username,
                        ssh_config,
                        ssh_listen,
                    },
                )?;
                identity::load(&data, &secret)?
            };
            print_json(&local.profile)?;
        }
        Command::Serve {
            managed,
            listen,
            peer_listen,
            ssh_listen,
            assets,
            sync_seconds,
            web_listen,
            web_origin,
            tls_cert,
            tls_key,
            web_behind_proxy,
        } => {
            let web = match (web_listen, web_origin) {
                (Some(listen), Some(origin)) => {
                    let config = comb_frame::web_host::Config {
                        listen,
                        origin,
                        tls_cert,
                        tls_key,
                        behind_proxy: web_behind_proxy,
                    };
                    config.validate()?;
                    Some(config)
                }
                (None, None) => None,
                _ => bail!("--web-listen and --web-origin are required together"),
            };
            if managed {
                comb_frame::managed::run(comb_frame::managed::Config {
                    data,
                    listen,
                    peer_listen,
                    ssh_listen,
                    assets,
                    sync_seconds,
                    web,
                })
                .await?;
            } else {
                let (_, store) = crate::onboarding::unlock_local(
                    &mut cached_password,
                    "Unlock FRAME: ",
                    |secret| Store::open(&data, secret),
                )?;
                comb_frame::daemon::run_with_web(
                    store,
                    listen,
                    peer_listen,
                    assets,
                    sync_seconds,
                    ssh_listen,
                    web,
                )
                .await?;
            }
        }
        Command::Token => {
            if let Some(session) = session {
                println!("{}", *session.token);
            } else {
                let (_, local) = crate::onboarding::unlock_local(
                    &mut cached_password,
                    "Unlock FRAME: ",
                    |secret| identity::load(&data, secret),
                )?;
                println!("{}", local.token);
            }
        }
        Command::Profile { out } => {
            let profile = if session.is_some() {
                comb_frame::managed::profile(&data)
                    .await?
                    .context("FRAME session ended before reading profile")?
            } else {
                crate::onboarding::unlock_local(&mut cached_password, "Unlock FRAME: ", |secret| {
                    identity::load(&data, secret)
                })?
                .1
                .profile
                .clone()
            };
            if let Some(out) = out {
                write_json(&out, &profile)?;
            } else {
                print_json(&profile)?;
            }
        }
        Command::Enroll { action } => {
            let password = password("FRAME password: ")?;
            match action {
                Enrollment::Request { out } => {
                    crate::onboarding::validate_new_password(&password)?;
                    write_json(&out, &identity::prepare_enrollment(&data, &password)?)?
                }
                Enrollment::Authorize { request, out } => write_json(
                    &out,
                    &identity::authorize(&data, &password, &read_json(&request)?)?,
                )?,
                Enrollment::Complete {
                    grant,
                    identity_key,
                } => {
                    crate::onboarding::validate_new_password(&password)?;
                    let grant: identity::EnrollmentGrant = read_json(&grant)?;
                    check_identity_pin(&identity_key, &grant.identity)?;
                    print_json(
                        &identity::complete_enrollment(&data, &password, &grant, &grant.identity)?
                            .profile,
                    )?;
                }
            }
        }
        Command::Recover {
            recovery,
            backup,
            owner_key,
        } => {
            let password = password("New FRAME password: ")?;
            crate::onboarding::validate_new_password(&password)?;
            let recovery_password = Zeroizing::new(match std::env::var("COMB_RECOVERY_PASSWORD") {
                Ok(v) => v,
                Err(_) => rpassword::prompt_password("Recovery-file password: ")?,
            });
            let local =
                identity::recover(&data, &password, &recovery, recovery_password.as_bytes())?;
            print_json(&local.profile)?;
            drop(local);
            if let Some(backup) = backup {
                let snapshot: Snapshot = read_json(&backup)?;
                let context = snapshot.context()?;
                check_identity_pin(
                    &owner_key.context("--owner-key required to pin backup owner")?,
                    &context.owner,
                )?;
                let root = identity::load_root(&data, &password)?;
                let mut store = Store::open(&data, &password)?;
                print_json(&store.import_snapshot(&snapshot, &context.owner, Some(&root))?)?;
            }
        }
        Command::Webgui => println!("{}", cli.api_url),
        Command::Ice {
            action: IceCommand::Health { address },
        } => {
            let mapped = tokio::task::spawn_blocking(move || {
                comb_guard::stun::binding(address, std::time::Duration::from_secs(3))
            })
            .await??;
            print_json(
                &serde_json::json!({"server":address.to_string(),"mapped_address":mapped.to_string()}),
            )?;
        }
        command => online(&data, &cli.api_url, command, cached_password, session).await?,
    }
    Ok(())
}
async fn online(
    data: &Path,
    url: &str,
    command: Command,
    mut cached: Option<Zeroizing<Vec<u8>>>,
    session: Option<comb_frame::managed::Session>,
) -> Result<()> {
    let token = if let Ok(token) = std::env::var("COMB_TOKEN") {
        Zeroizing::new(token)
    } else if let Some(session) = session {
        session.token
    } else {
        let (password, local) =
            crate::onboarding::unlock_local(&mut cached, "Unlock local FRAME: ", |secret| {
                identity::load(data, secret)
            })?;
        let token = Zeroizing::new(local.token.clone());
        cached = Some(password);
        token
    };
    let base = local_api_url(url)?;
    let result = match command {
        Command::Cell { action } => match action {
            CellCommand::List => request(&base, &token, "GET", "/api/cells", None).await?,
            CellCommand::Create { name } => {
                request(
                    &base,
                    &token,
                    "POST",
                    "/api/cells",
                    Some(serde_json::json!({"name":name})),
                )
                .await?
            }
            CellCommand::Grant { id, profile, role } => {
                let profile: identity::Profile = read_json(&profile)?;
                request(
                    &base,
                    &token,
                    "POST",
                    &format!("/api/cells/{id}/members"),
                    Some(serde_json::json!({"profile":profile,"role":role})),
                )
                .await?
            }
            CellCommand::RegisterFrame { id, profile } => {
                let profile: identity::Profile = read_json(&profile)?;
                request(
                    &base,
                    &token,
                    "POST",
                    &format!("/api/cells/{id}/frames"),
                    Some(serde_json::to_value(profile)?),
                )
                .await?
            }
            CellCommand::Revoke { id, identity } => {
                request(
                    &base,
                    &token,
                    "POST",
                    &format!("/api/cells/{id}/revoke"),
                    Some(serde_json::json!({"identity_id":identity})),
                )
                .await?
            }
            CellCommand::Backup { id, out } => {
                write_json(
                    &out,
                    &request(
                        &base,
                        &token,
                        "GET",
                        &format!("/api/cells/{id}/backup"),
                        None,
                    )
                    .await?,
                )?;
                return Ok(());
            }
            CellCommand::Issues { id } => {
                request(
                    &base,
                    &token,
                    "GET",
                    &format!("/api/cells/{id}/issues"),
                    None,
                )
                .await?
            }
            CellCommand::Issue { id, title, body } => {
                request(
                    &base,
                    &token,
                    "POST",
                    &format!("/api/cells/{id}/issues"),
                    Some(serde_json::json!({"title":title,"body":body})),
                )
                .await?
            }
            CellCommand::Adopt { id, versions } => {
                request(
                    &base,
                    &token,
                    "POST",
                    &format!("/api/cells/{id}/adopt"),
                    Some(serde_json::json!({"version_ids":versions})),
                )
                .await?
            }
        },
        Command::Peers { action } => match action {
            PeerCommand::List => request(&base, &token, "GET", "/api/peers", None).await?,
            PeerCommand::Add { id, url, key } => {
                request(
                    &base,
                    &token,
                    "POST",
                    "/api/peers",
                    Some(serde_json::json!({"id":id,"url":url,"public_key":key})),
                )
                .await?
            }
            PeerCommand::AddProfile { profile, url } => {
                let profile: identity::Profile = read_json(&profile)?;
                let peer = comb_frame::store::Peer {
                    id: profile.frame_id(),
                    public_key: hex::encode(profile.noise_public),
                    url,
                    profile,
                };
                request(
                    &base,
                    &token,
                    "POST",
                    "/api/peers/profile",
                    Some(serde_json::to_value(peer)?),
                )
                .await?
            }
            PeerCommand::Sync { id } => {
                request(
                    &base,
                    &token,
                    "POST",
                    &format!("/api/peers/{id}/sync"),
                    None,
                )
                .await?
            }
        },
        Command::Restore {
            lost_frame,
            request_out,
            credential,
        } => {
            if let Some(path) = lost_frame {
                let record: comb_cell::SignedRecord = serde_json::from_value(
                    request(
                        &base,
                        &token,
                        "POST",
                        "/api/restore/issue",
                        Some(read_json(&path)?),
                    )
                    .await?,
                )?;
                println!("{}", comb_frame::restore::encode(&record)?);
                eprintln!(
                    "Long prototype restore credential: signed and bound to the requested replacement FRAME. Transfer privately."
                );
                return Ok(());
            } else if let Some(out) = request_out {
                let password = crate::onboarding::take_password(
                    &mut cached,
                    "FRAME password for restore request: ",
                )?;
                write_json(
                    &out,
                    &request(
                        &base,
                        &token,
                        "POST",
                        "/api/restore/request",
                        Some(serde_json::json!({"password":String::from_utf8_lossy(&password)})),
                    )
                    .await?,
                )?;
                return Ok(());
            } else {
                let password = crate::onboarding::take_password(
                    &mut cached,
                    "FRAME password for restored state: ",
                )?;
                let credential = Zeroizing::new(match credential {
                    Some(v) => v,
                    None => rpassword::prompt_password("Restore credential: ")?,
                });
                request(&base,&token,"POST","/api/restore/apply",Some(serde_json::json!({"password":String::from_utf8_lossy(&password),"credential":&*credential}))).await?
            }
        }
        Command::RevokeFrame { id } => {
            request(
                &base,
                &token,
                "POST",
                &format!("/api/frames/{id}/revoke"),
                None,
            )
            .await?
        }
        Command::Clean { cell } => {
            request(
                &base,
                &token,
                "POST",
                &format!("/api/cells/{cell}/clean"),
                Some(serde_json::json!({"version_ids":[],"confirm":false})),
            )
            .await?
        }
        _ => unreachable!("offline commands handled above"),
    };
    print_json(&result)
}
fn default_data() -> PathBuf {
    if let Some(path) = std::env::var_os("COMB_DATA_DIR") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("comb");
    }
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share/comb")
}
pub(crate) fn password(message: &str) -> Result<Zeroizing<Vec<u8>>> {
    let value = match std::env::var("COMB_PASSWORD") {
        Ok(value) => value,
        Err(_) => rpassword::prompt_password(message)?,
    };
    if value.is_empty() {
        bail!("empty FRAME passwords are not accepted");
    }
    Ok(Zeroizing::new(value.into_bytes()))
}
pub(crate) fn prompt(message: &str) -> Result<String> {
    eprint!("{message}");
    io::stderr().flush()?;
    let mut value = String::new();
    io::stdin().read_line(&mut value)?;
    Ok(value.trim().into())
}
fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let bytes = std::fs::read(path)?;
    if bytes.len() > 96 * 1024 * 1024 {
        bail!("input file exceeds limit");
    }
    Ok(serde_json::from_slice(&bytes)?)
}
fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    if path.exists() {
        bail!("output file already exists: {}", path.display());
    }
    identity::atomic_write(path, &serde_json::to_vec_pretty(value)?)?;
    Ok(())
}
fn print_json(value: &impl Serialize) -> Result<()> {
    println!("{}", serde_json::to_string_pretty(value)?);
    Ok(())
}
fn check_identity_pin(expected: &str, identity: &comb_cell::IdentityPublic) -> Result<()> {
    if expected != hex::encode(identity.signing_key) {
        bail!("identity key does not match explicit trusted pin");
    }
    Ok(())
}
fn local_api_url(input: &str) -> Result<String> {
    let base = comb_frame::api::validate_peer_url(input)?;
    let url = reqwest::Url::parse(&base)?;
    let host = url.host_str().context("missing host")?;
    if host != "localhost"
        && !host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
    {
        bail!("management credentials may only be sent to a loopback API");
    }
    Ok(base)
}
async fn request(
    base: &str,
    token: &str,
    method: &str,
    path: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value> {
    let client = comb_frame::api::http_client()?;
    let mut request = client
        .request(method.parse()?, format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await?;
    let status = response.status();
    let body: serde_json::Value = response.json().await?;
    if !status.is_success() {
        bail!("FRAME returned {status}: {body}");
    }
    Ok(body)
}
