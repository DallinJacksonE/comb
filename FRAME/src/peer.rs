//! Pinned end-to-end Noise sessions over an untrusted HTTP carrier.
//!
//! The public identity endpoint is discovery, not trust establishment: callers
//! must pin a verified peer profile separately. Each handshake permits one
//! encrypted request/reply within 60 seconds. HTTP still exposes routing, timing,
//! and message sizes; repository authorization is enforced by the store, not by
//! possession of a session ID alone.
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

/// Application operation carried inside an authenticated Noise exchange.
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum PeerRequest {
    /// Request snapshots visible to the pinned peer's FRAME certificate.
    Pull,
    /// Import signed snapshots; a previously unknown CELL must belong to the peer.
    Push { snapshots: Vec<Snapshot> },
    /// Ask a same-identity FRAME to lock itself using a signed lifecycle notice.
    Revoke { notice: Box<SignedRecord> },
}
/// Encrypted application reply; HTTP success can still contain `Failure`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PeerResponse {
    /// Snapshots selected for the requesting certificate.
    Snapshots { snapshots: Vec<Snapshot> },
    /// The operation completed without a snapshot payload.
    Ack,
    /// Application rejection, serialized inside the authenticated channel.
    Failure { message: String },
}
/// Snapshot counts for a completed pull-then-push synchronization.
#[derive(Serialize, Deserialize)]
pub struct SyncReport {
    /// Imported snapshots, excluding locally deleted CELLs (not a change count).
    pub received: usize,
    /// Snapshots offered to the peer in the subsequent push.
    pub sent: usize,
}
/// Cleartext handshake routing hint and base64-encoded initial Noise message.
#[derive(Serialize, Deserialize)]
struct Hello {
    /// Lookup key for a previously pinned peer, not an authentication assertion.
    peer_id: String,
    message: String,
}
/// Cleartext session handle and base64-encoded responder handshake message.
#[derive(Serialize, Deserialize)]
struct Welcome {
    session_id: String,
    message: String,
}
/// Single-use session handle with ordered base64 Noise ciphertext chunks.
#[derive(Serialize, Deserialize)]
struct Packet {
    session_id: String,
    chunks: Vec<String>,
}
/// Ordered ciphertext chunks for the sole reply on a session.
#[derive(Serialize, Deserialize)]
struct Reply {
    chunks: Vec<String>,
}
/// In-memory authenticated transport, pinned principal, and absolute expiry origin.
struct Session {
    transport: SecureSession,
    peer: Peer,
    created: Instant,
}
/// Router-local session registry shared by all clones of this router's state.
#[derive(Clone)]
struct PeerApp {
    app: App,
    sessions: Arc<Mutex<BTreeMap<String, Session>>>,
}

/// Build identity/handshake/exchange routes with a 96 MiB HTTP body cap.
///
/// Creates a fresh registry (at most 64 live handshakes). This router is not an
/// admin API: the handshake authenticates pinned peers and store policy gates
/// individual operations. Mount it only where peer transport is intended.
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
/// Publish the local public profile without requiring peer authentication.
async fn profile(State(state): State<PeerApp>) -> Result<Json<Profile>, ApiError> {
    Ok(Json(state.app.execute(|s| Ok(s.profile().clone())).await?))
}
/// Authenticate an active store's pinned peer and allocate a single-use session.
///
/// Rejects malformed base64/pins/Noise messages or exhausted capacity; expired
/// entries are pruned here rather than by a background timer.
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
/// Consume a session before decoding, then encrypt an application reply.
///
/// Even malformed requests consume the handle. Expiry, decoding, and serialization
/// failures become API errors; processing failures become encrypted `Failure`s.
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
/// Apply a peer operation through the serialized store boundary.
///
/// Snapshot imports can persist before a later item fails; the batch is not a
/// transaction. Revocation requires the same identity, a valid targeted signature,
/// and an issuer not locally revoked in any CELL, then persists a FRAME lock.
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
                    let context = snapshot.context()?;
                    if s.is_cell_deleted(&context.cell_id) {
                        continue;
                    }
                    let owner = context.owner;
                    // For new repositories, trust is anchored in the explicitly pinned owner's peer profile.
                    if s.cell(&context.cell_id).is_err() && owner != peer.profile.identity {
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
/// Encrypt ordered transport-sized chunks, advancing send nonces.
/// Rejects plaintext above 48 MiB; an empty input produces no chunks.
fn encode(session: &mut SecureSession, plain: &[u8]) -> Result<Vec<String>> {
    if plain.len() > MAX_EXCHANGE {
        bail!("peer exchange exceeds prototype limit");
    }
    plain
        .chunks(MAX_PLAINTEXT)
        .map(|chunk| Ok(STANDARD.encode(session.encrypt(chunk)?)))
        .collect()
}
/// Authenticate ordered chunks into a zeroizing buffer, advancing receive nonces.
/// Rejects empty/oversized exchanges, invalid base64, and Noise/replay failures;
/// a failed decode does not roll back transport state.
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
///
/// Performs a fresh HTTP handshake and one exchange; no retries or import occur
/// here. Rejects a pin/profile mismatch, network/status/codec errors, and remote
/// `Failure` replies. Callers must supply a previously verified peer profile and
/// enforce local lifecycle policy before invoking this low-level client.
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

/// Pull authorized snapshots from a configured peer, import, then push local ones.
///
/// Requires an active local FRAME. Unknown CELL owners must match the pinned
/// peer; deleted CELLs are skipped. Store, validation, or transport errors abort
/// the sequence without undoing earlier imports or remote effects.
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
        let owner_peer = peer.profile.identity.clone();
        received = app
            .execute(move |s| {
                let mut received = 0;
                for snapshot in snapshots {
                    let context = snapshot.context()?;
                    if s.is_cell_deleted(&context.cell_id) {
                        continue;
                    }
                    if s.cell(&context.cell_id).is_err() && context.owner != owner_peer {
                        bail!("new CELL owner is not the pinned peer");
                    }
                    s.import_snapshot(&snapshot, &context.owner, None)?;
                    received += 1;
                }
                Ok(received)
            })
            .await?;
    }
    let cert = peer.profile.certificate.clone();
    let snapshots = app.execute(move |s| s.snapshots_for(&cert)).await?;
    let sent = snapshots.len();
    exchange(app, &peer, PeerRequest::Push { snapshots }).await?;
    Ok(SyncReport { received, sent })
}

/// Revoke a same-identity peer in local CELLs, then send its signed lock notice.
///
/// Requires an active local FRAME and configured peer. Local revocations are
/// persisted before network delivery: a failed exchange does not undo them and
/// does not prove that the remote FRAME locked itself.
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
