//! Pinned end-to-end Noise sessions over an untrusted HTTP carrier.
use crate::{
    api::{ApiError, App, http_client},
    identity::Profile,
    snapshot::Snapshot,
    store::Peer,
};
use anyhow::{Context, Result, bail};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use comb_cell::SignedRecord;
use comb_guard::{MAX_PLAINTEXT, SecureSession};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

const MAX_EXCHANGE: usize = 48 * 1024 * 1024;
const REVOCATION_DOMAIN: &[u8] = b"comb.frame.revoke.v1";

#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PeerRequest {
    Pull,
    Push { snapshots: Vec<Snapshot> },
    Revoke { notice: Box<SignedRecord> },
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PeerResponse {
    Snapshots { snapshots: Vec<Snapshot> },
    Ack,
    Failure { message: String },
}
#[derive(Serialize, Deserialize)]
pub struct SyncReport {
    pub received: usize,
    pub sent: usize,
}
#[derive(Serialize, Deserialize)]
struct Hello {
    peer_id: String,
    message: String,
}
#[derive(Serialize, Deserialize)]
struct Welcome {
    session_id: String,
    message: String,
}
#[derive(Serialize, Deserialize)]
struct Packet {
    session_id: String,
    chunks: Vec<String>,
}
#[derive(Serialize, Deserialize)]
struct Reply {
    chunks: Vec<String>,
}
struct Session {
    transport: SecureSession,
    peer: Peer,
    created: Instant,
}
#[derive(Clone)]
struct PeerApp {
    app: App,
    sessions: Arc<Mutex<BTreeMap<String, Session>>>,
}

pub fn peer_router(app: App) -> Router {
    Router::new()
        .route("/identity", get(profile))
        .route("/handshake", post(handshake))
        .route("/exchange", post(receive))
        .layer(DefaultBodyLimit::max(96 * 1024 * 1024))
        .with_state(PeerApp {
            app,
            sessions: Arc::new(Mutex::new(BTreeMap::new())),
        })
}
async fn profile(State(state): State<PeerApp>) -> Result<Json<Profile>, ApiError> {
    Ok(Json(state.app.execute(|s| Ok(s.profile().clone())).await?))
}
async fn handshake(
    State(state): State<PeerApp>,
    Json(hello): Json<Hello>,
) -> Result<Json<Welcome>, ApiError> {
    if hello.message.len() > 512 {
        return Err(anyhow::anyhow!("invalid handshake").into());
    }
    let message = STANDARD.decode(hello.message)?;
    let (transport, response, peer) = state
        .app
        .execute(move |s| {
            s.ensure_active()?;
            let peer = s.peer(&hello.peer_id)?;
            let pin: [u8; 32] = hex::decode(&peer.public_key)?
                .try_into()
                .map_err(|_| anyhow::anyhow!("invalid peer pin"))?;
            let (transport, response) =
                comb_guard::server_accept(&s.local.noise_private, &pin, &message)?;
            Ok((transport, response, peer))
        })
        .await?;
    let mut sessions = state
        .sessions
        .lock()
        .map_err(|_| anyhow::anyhow!("session state unavailable"))?;
    sessions.retain(|_, s| s.created.elapsed() < Duration::from_secs(60));
    if sessions.len() >= 64 {
        return Err(anyhow::anyhow!("peer session capacity reached").into());
    }
    let session_id = uuid::Uuid::new_v4().to_string();
    sessions.insert(
        session_id.clone(),
        Session {
            transport,
            peer,
            created: Instant::now(),
        },
    );
    Ok(Json(Welcome {
        session_id,
        message: STANDARD.encode(response),
    }))
}
async fn receive(
    State(state): State<PeerApp>,
    Json(packet): Json<Packet>,
) -> Result<Json<Reply>, ApiError> {
    // A session is single-use at the request layer, in addition to Noise nonce replay checks.
    let mut session = state
        .sessions
        .lock()
        .map_err(|_| anyhow::anyhow!("session state unavailable"))?
        .remove(&packet.session_id)
        .context("unknown or consumed session")?;
    if session.created.elapsed() > Duration::from_secs(60) {
        return Err(anyhow::anyhow!("expired session").into());
    }
    let plain = decode(&mut session.transport, &packet.chunks)?;
    let request: PeerRequest = serde_json::from_slice(&plain)?;
    let response = process(&state.app, session.peer, request)
        .await
        .unwrap_or_else(|e| PeerResponse::Failure {
            message: e.to_string(),
        });
    let plain = serde_json::to_vec(&response)?;
    Ok(Json(Reply {
        chunks: encode(&mut session.transport, &plain)?,
    }))
}
async fn process(app: &App, peer: Peer, request: PeerRequest) -> Result<PeerResponse> {
    match request {
        PeerRequest::Pull => {
            app.execute(move |s| {
                Ok(PeerResponse::Snapshots {
                    snapshots: s.snapshots_for(&peer.profile.certificate)?,
                })
            })
            .await
        }
        PeerRequest::Push { snapshots } => {
            app.execute(move |s| {
                for snapshot in snapshots {
                    let owner = snapshot.context()?.owner;
                    // For new repositories, trust is anchored in the explicitly pinned owner's peer profile.
                    if s.cell(&snapshot.context()?.cell_id).is_err()
                        && owner != peer.profile.identity
                    {
                        bail!("new CELL must originate from its pinned owner");
                    }
                    s.import_snapshot(&snapshot, &owner, None)?;
                }
                Ok(PeerResponse::Ack)
            })
            .await
        }
        PeerRequest::Revoke { notice } => {
            app.execute(move |s| {
                if peer.profile.identity != s.profile().identity {
                    bail!("only a same-identity authorized FRAME may invalidate this FRAME");
                }
                notice.verify(
                    &s.profile().identity,
                    &peer.profile.certificate.frame,
                    REVOCATION_DOMAIN,
                )?;
                let target: String = serde_json::from_slice(&notice.payload)?;
                if target != s.profile().frame_id() {
                    bail!("revocation target mismatch");
                }
                // A peer already known revoked in any local CELL cannot issue lifecycle notices.
                for cell in s.list_cells()? {
                    if s.cell(&cell.id)?.revoked_frames().contains(&peer.id) {
                        bail!("revocation issuer is revoked");
                    }
                }
                s.lock(hex::encode(notice.id()?))?;
                Ok(PeerResponse::Ack)
            })
            .await
        }
    }
}
fn encode(session: &mut SecureSession, plain: &[u8]) -> Result<Vec<String>> {
    if plain.len() > MAX_EXCHANGE {
        bail!("peer exchange exceeds prototype limit");
    }
    plain
        .chunks(MAX_PLAINTEXT)
        .map(|chunk| Ok(STANDARD.encode(session.encrypt(chunk)?)))
        .collect()
}
fn decode(session: &mut SecureSession, chunks: &[String]) -> Result<zeroize::Zeroizing<Vec<u8>>> {
    if chunks.is_empty() || chunks.len() > MAX_EXCHANGE / MAX_PLAINTEXT + 1 {
        bail!("invalid encrypted chunk count");
    }
    let mut plain = zeroize::Zeroizing::new(Vec::new());
    for chunk in chunks {
        if chunk.len() > 90_000 {
            bail!("oversized encrypted chunk");
        }
        plain.extend_from_slice(&session.decrypt(&STANDARD.decode(chunk)?)?);
        if plain.len() > MAX_EXCHANGE {
            bail!("oversized peer exchange");
        }
    }
    Ok(plain)
}

/// Both endpoint static keys are pinned before exchanging any repository bytes.
pub async fn exchange(app: &App, peer: &Peer, request: PeerRequest) -> Result<PeerResponse> {
    let pin: [u8; 32] = hex::decode(&peer.public_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid peer pin"))?;
    if pin != peer.profile.noise_public {
        bail!("peer pin differs from verified profile");
    }
    let (client, first, id) = app
        .execute(move |s| {
            let (client, first) = comb_guard::client_start(&s.local.noise_private, &pin)?;
            Ok((client, first, s.profile().frame_id()))
        })
        .await?;
    let http = http_client()?;
    let welcome: Welcome = http
        .post(format!("{}/handshake", peer.url))
        .json(&Hello {
            peer_id: id,
            message: STANDARD.encode(first),
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let mut session = client.finish(&STANDARD.decode(welcome.message)?)?;
    let plain = zeroize::Zeroizing::new(serde_json::to_vec(&request)?);
    let chunks = encode(&mut session, &plain)?;
    let reply: Reply = http
        .post(format!("{}/exchange", peer.url))
        .json(&Packet {
            session_id: welcome.session_id,
            chunks,
        })
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let plain = decode(&mut session, &reply.chunks)?;
    let response = serde_json::from_slice(&plain)?;
    if let PeerResponse::Failure { message } = &response {
        bail!("peer rejected exchange: {message}");
    }
    Ok(response)
}

pub async fn sync(app: &App, id: &str) -> Result<SyncReport> {
    let id = id.to_owned();
    let peer = app
        .execute(move |s| {
            s.ensure_active()?;
            s.peer(&id)
        })
        .await?;
    let mut received = 0;
    if let PeerResponse::Snapshots { snapshots } = exchange(app, &peer, PeerRequest::Pull).await? {
        received = snapshots.len();
        let owner_peer = peer.profile.identity.clone();
        app.execute(move |s| {
            for snapshot in snapshots {
                let context = snapshot.context()?;
                if s.cell(&context.cell_id).is_err() && context.owner != owner_peer {
                    bail!("new CELL owner is not the pinned peer");
                }
                s.import_snapshot(&snapshot, &context.owner, None)?;
            }
            Ok(())
        })
        .await?;
    }
    let cert = peer.profile.certificate.clone();
    let snapshots = app.execute(move |s| s.snapshots_for(&cert)).await?;
    let sent = snapshots.len();
    exchange(app, &peer, PeerRequest::Push { snapshots }).await?;
    Ok(SyncReport { received, sent })
}

pub async fn revoke_frame(app: &App, id: &str) -> Result<()> {
    let id = id.to_owned();
    let (peer, notice) = app
        .execute(move |s| {
            s.ensure_active()?;
            let peer = s.peer(&id)?;
            if peer.profile.identity != s.profile().identity {
                bail!("FRAME lifecycle revocation is limited to your own identity");
            }
            for cell in s.list_cells()? {
                if s.cell(&cell.id)?.frames().contains_key(&id) {
                    s.operate(
                        &cell.id,
                        comb_cell::domain::Operation::RevokeFrame {
                            frame_id: id.clone(),
                        },
                    )?;
                }
            }
            let notice = SignedRecord::new(
                &s.local.frame,
                &s.profile().certificate,
                REVOCATION_DOMAIN,
                &serde_json::to_vec(&id)?,
            )?;
            Ok((peer, notice))
        })
        .await?;
    exchange(
        app,
        &peer,
        PeerRequest::Revoke {
            notice: Box::new(notice),
        },
    )
    .await?;
    Ok(())
}
