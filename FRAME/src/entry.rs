//! CLI execution. All domain/network behavior uses the shared library services.
use crate::cli::{CellCommand, Cli, Command, Enrollment, IceCommand, PeerCommand};
use anyhow::{Context, Result, bail};

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
    match cli.command.unwrap_or(Command::User {
        name: None,
        email: None,
        recovery: None,
    }) {
        Command::User {
            name,
            email,
            recovery,
        } => {
            let password = password("FRAME password: ")?;
            if data.join("node.vault").exists() {
                print_json(&identity::load(&data, &password)?.profile)?;
            } else {
                let name = match name {
                    Some(v) => v,
                    None => prompt("Name: ")?,
                };
                let email = match email {
                    Some(v) => v,
                    None => prompt("Email: ")?,
                };
                let recovery = recovery.unwrap_or_else(|| data.join("identity.recovery"));
                let local = identity::initialize(&data, &name, &email, &password, &recovery)?;
                print_json(&local.profile)?;
                eprintln!(
                    "Encrypted recovery file: {}. Store it safely offline; COMB cannot replace it.",
                    recovery.display()
                );
            }
        }
        Command::Serve {
            listen,
            peer_listen,
            assets,
            sync_seconds,
        } => {
            let password = password("Unlock FRAME: ")?;
            let store = Store::open(&data, &password)?;
            comb_frame::daemon::run(store, listen, peer_listen, assets, sync_seconds).await?;
        }
        Command::Token => {
            let password = password("Unlock FRAME: ")?;
            println!("{}", identity::load(&data, &password)?.token);
        }
        Command::Profile { out } => {
            let password = password("Unlock FRAME: ")?;
            let local = identity::load(&data, &password)?;
            if let Some(out) = out {
                write_json(&out, &local.profile)?;
            } else {
                print_json(&local.profile)?;
            }
        }
        Command::Enroll { action } => {
            let password = password("FRAME password: ")?;
            match action {
                Enrollment::Request { out } => {
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
        command => online(&data, &cli.api_url, command).await?,
    }
    Ok(())
}
async fn online(data: &Path, url: &str, command: Command) -> Result<()> {
    let password = password("Unlock local FRAME: ")?;
    let token = Zeroizing::new(match std::env::var("COMB_TOKEN") {
        Ok(v) => v,
        Err(_) => identity::load(data, &password)?.token.clone(),
    });
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
    if let Some(path) = std::env::var_os("XDG_DATA_HOME") {
        return PathBuf::from(path).join("comb");
    }
    PathBuf::from(std::env::var_os("HOME").unwrap_or_default()).join(".local/share/comb")
}
fn password(message: &str) -> Result<Zeroizing<Vec<u8>>> {
    let value = match std::env::var("COMB_PASSWORD") {
        Ok(value) => value,
        Err(_) => rpassword::prompt_password(message)?,
    };
    if value.is_empty() {
        bail!("empty FRAME passwords are not accepted");
    }
    Ok(Zeroizing::new(value.into_bytes()))
}
fn prompt(message: &str) -> Result<String> {
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
