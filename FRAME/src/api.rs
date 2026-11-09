//! Loopback management API and standard Git smart HTTP adapter.
//!
//! Routers share serialized access to an unlocked Store. Authentication guards
//! registered API/Git routes, not the static SPA fallback. Domain authorization
//! remains in Store; handler errors become HTTP 400 JSON rather than a granular
//! mapping of missing resources, permission failures, and internal errors.
use crate::{
    identity::Profile,
    snapshot::Snapshot,
    store::{CellSummary, Peer, Store},
};
use anyhow::{Context, Result};
use axum::{
    Json, Router,
    body::Bytes,
    extract::Request,
    extract::{DefaultBodyLimit, OriginalUri, Path, State},
    http::{HeaderMap, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::Engine;
use comb_cell::domain::{Issue, Operation, Role};
use serde::Deserialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
};
use subtle::ConstantTimeEq;
use tower_http::services::{ServeDir, ServeFile};

#[derive(Clone)]
/// Cloneable request state sharing one Store and its lifecycle notification channel.
pub struct App {
    pub(crate) store: Arc<Mutex<Store>>,
    /// Current active-state signal consumed by listener lifecycle tasks.
    pub peer_enabled: tokio::sync::watch::Sender<bool>,
}
impl App {
    /// Seed lifecycle notifications from the already-open Store.
    pub fn new(store: Store) -> Self {
        let (peer_enabled, _) = tokio::sync::watch::channel(store.is_active());
        Self {
            store: Arc::new(Mutex::new(store)),
            peer_enabled,
        }
    }
    /// Run blocking Store work under its mutex without blocking the async executor.
    ///
    /// Calls are serialized. After the closure returns (including an error), publish
    /// the Store's active state. Lock poisoning and task-join failures propagate;
    /// this wrapper supplies neither a transaction nor rollback of partial work.
    pub async fn execute<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut Store) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let app = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut store = app
                .store
                .lock()
                .map_err(|_| anyhow::anyhow!("FRAME state lock poisoned"))?;
            let result = operation(&mut store);
            app.peer_enabled.send_replace(store.is_active());
            result
        })
        .await?
    }
}

/// Handler error rendered as `400 {"error": "..."}` using its display message.
pub struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    /// Preserve the underlying error for the shared JSON response conversion.
    fn from(error: E) -> Self {
        Self(error.into())
    }
}
impl IntoResponse for ApiError {
    /// Expose the error's display text, without its backtrace or context chain.
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":self.0.to_string()})),
        )
            .into_response()
    }
}
/// Handler result using the common HTTP 400 conversion for service failures.
type ApiResult<T> = std::result::Result<T, ApiError>;
mod browser;
mod repository;
pub use browser::remote_router;

/// Build the local management/Git router with same-origin browser convenience access.
///
/// The caller must bind it only to loopback and must not expose it through a proxy.
/// CLI/Git use Bearer tokens or Basic passwords; the local GUI can use provenance
/// headers on `/api/` routes. Static assets and SPA fallback are unauthenticated.
pub fn router(app: App, assets: PathBuf) -> Router {
    let routes = api_routes()
        .route("/api/browser/session", get(browser::local_session))
        .layer(middleware::from_fn_with_state(app.clone(), authorize));
    finish_routes(routes, app, assets)
}

/// Register shared management and smart-HTTP handlers without an auth policy.
fn api_routes() -> Router<App> {
    Router::new()
        .route("/api/status", get(status))
        .route("/api/cells", get(list_cells).post(create_cell))
        .route("/api/cells/{id}", get(get_cell))
        .route("/api/cells/{id}/tree", get(repository::tree))
        .route("/api/cells/{id}/history", get(repository::history))
        .route("/api/cells/{id}/blob", get(repository::blob))
        .route("/api/cells/{id}/rename", post(repository::rename))
        .route("/api/cells/{id}/delete", post(repository::delete))
        .route("/api/cells/{id}/issues", get(issues).post(add_issue))
        .route("/api/cells/{id}/members", post(grant))
        .route("/api/cells/{id}/frames", post(register_frame))
        .route("/api/cells/{id}/revoke", post(revoke))
        .route("/api/cells/{id}/backup", get(backup))
        .route("/api/cells/{id}/adopt", post(adopt))
        .route("/api/cells/{id}/clean", post(clean))
        .route("/api/peers", get(peers).post(add_peer))
        .route("/api/peers/profile", post(add_peer_profile))
        .route("/api/peers/{id}/sync", post(sync_peer))
        .route("/api/frames/{id}/revoke", post(revoke_frame))
        .route("/api/restore/request", post(restore_request))
        .route("/api/restore/issue", post(restore_issue))
        .route("/api/restore/apply", post(restore_apply))
        .route("/git/{repo}/{*suffix}", get(git).post(git))
}

/// Attach Store state, a 64 MiB extractor limit, and an unguarded SPA fallback.
/// The body limit applies to extractors that honor Axum's DefaultBodyLimit.
fn finish_routes(routes: Router<App>, app: App, assets: PathBuf) -> Router {
    routes
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .fallback_service(
            ServeDir::new(&assets).not_found_service(ServeFile::new(assets.join("index.html"))),
        )
        .with_state(app)
}

/// Accept local GUI provenance or a constant-time token match, then gate revocation.
/// Authenticated status/restore routes remain available while revoked; other
/// routes return 423. Authentication failures return 401 with a Basic challenge.
async fn authorize(State(app): State<App>, request: Request, next: Next) -> Response {
    let browser_access = crate::browser_access::is_local_webgui(&request);
    let supplied = credential(request.headers());
    let result = app
        .execute(move |store| {
            Ok((
                browser_access
                    || bool::from(supplied.as_bytes().ct_eq(store.local.token.as_bytes())),
                store.is_active(),
            ))
        })
        .await;
    let mut response = match result {
        Ok((true,active)) if active || request.uri().path()=="/api/status" || request.uri().path().starts_with("/api/restore") => next.run(request).await,
        Ok((true,_))=>(StatusCode::LOCKED,Json(serde_json::json!({"error":"FRAME revoked: use another authorized FRAME to generate a restore credential"}))).into_response(),
        _=>{let mut response=(StatusCode::UNAUTHORIZED,Json(serde_json::json!({"error":"local management token required"}))).into_response();response.headers_mut().insert("www-authenticate","Basic realm=\"COMB FRAME\"".parse().unwrap());response}
    };
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
}
/// Extract a case-sensitive Bearer value or the password from UTF-8 Basic auth.
/// Basic usernames are ignored; missing, malformed, or unsupported values yield empty.
fn credential(headers: &HeaderMap) -> String {
    let value = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if let Some(token) = value.strip_prefix("Bearer ") {
        return token.to_owned();
    }
    if let Some(encoded) = value.strip_prefix("Basic ")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(encoded)
        && let Ok(value) = String::from_utf8(bytes)
        && let Some((_, password)) = value.split_once(':')
    {
        return password.to_owned();
    }
    String::new()
}
/// Report public identity/profile, lifecycle, and advertised daemon capabilities.
async fn status(State(app): State<App>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(app.execute(|store|Ok(serde_json::json!({
        "identity":{"id":store.profile().id(),"name":store.profile().name,"email":store.profile().email},
        "frame":{"id":store.profile().frame_id(),"active":store.is_active()},"cells":store.count(),
        "capabilities":["git-http","encrypted-snapshots","signed-cell-history","pinned-noise-peers","offline-recovery"],
        "lifecycle":store.lifecycle(),"profile":store.profile()
    }))).await?))
}
/// List local CELL summaries through the Store's visibility policy.
async fn list_cells(State(app): State<App>) -> ApiResult<Json<Vec<CellSummary>>> {
    Ok(Json(app.execute(|s| s.list_cells()).await?))
}
#[derive(Deserialize)]
/// JSON input for a new locally owned CELL.
struct CreateCell {
    name: String,
}
/// Create a CELL and return its summary with HTTP 201.
async fn create_cell(
    State(app): State<App>,
    Json(input): Json<CreateCell>,
) -> ApiResult<(StatusCode, Json<CellSummary>)> {
    Ok((
        StatusCode::CREATED,
        Json(app.execute(move |s| s.create_cell(input.name)).await?),
    ))
}
/// Resolve a CELL selector to its current summary; Store errors become HTTP 400.
async fn get_cell(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<CellSummary>> {
    Ok(Json(app.execute(move |s| s.cell_summary(&id)).await?))
}
/// Read issues from the selected CELL's domain state.
async fn issues(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Vec<Issue>>> {
    Ok(Json(app.execute(move |s| s.issues(&id)).await?))
}
#[derive(Deserialize)]
/// Issue creation payload; omitted body defaults to an empty string.
struct NewIssue {
    title: String,
    #[serde(default)]
    body: String,
}
/// Append an issue via Store authorization and return it with HTTP 201.
async fn add_issue(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<NewIssue>,
) -> ApiResult<(StatusCode, Json<Issue>)> {
    Ok((
        StatusCode::CREATED,
        Json(
            app.execute(move |s| s.add_issue(&id, input.title, input.body))
                .await?,
        ),
    ))
}
#[derive(Deserialize)]
/// Contributor profile and requested CELL role; Store validates the grant.
struct Grant {
    profile: Profile,
    role: Role,
}
/// Submit a membership grant and return the resulting CELL summary.
async fn grant(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Grant>,
) -> ApiResult<Json<CellSummary>> {
    Ok(Json(
        app.execute(move |s| s.grant(&id, &input.profile, input.role))
            .await?,
    ))
}
/// Validate a signed profile before submitting its FRAME certificate to the CELL.
async fn register_frame(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(profile): Json<Profile>,
) -> ApiResult<Json<CellSummary>> {
    crate::identity::validate_profile(&profile, &profile.identity)?;
    Ok(Json(
        app.execute(move |s| {
            s.operate(
                &id,
                Operation::RegisterFrame {
                    certificate: profile.certificate,
                },
            )
        })
        .await?,
    ))
}
#[derive(Deserialize)]
/// Identity identifier to revoke from a selected CELL.
struct Revoke {
    identity_id: String,
}
/// Submit a CELL membership revocation, with authority enforced by Store/domain code.
async fn revoke(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<Revoke>,
) -> ApiResult<Json<CellSummary>> {
    Ok(Json(
        app.execute(move |s| {
            s.operate(
                &id,
                Operation::Revoke {
                    identity_id: input.identity_id,
                },
            )
        })
        .await?,
    ))
}
/// Export an encrypted snapshot as JSON, not plaintext repository files.
async fn backup(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Snapshot>> {
    Ok(Json(app.execute(move |s| s.export_snapshot(&id)).await?))
}
#[derive(Deserialize)]
/// Version selection shared by adoption and cleanup preview; confirmation defaults false.
struct VersionSet {
    version_ids: Vec<String>,
    #[serde(default)]
    confirm: bool,
}
/// Submit adoption of the selected contribution versions; `confirm` is unused here.
async fn adopt(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<VersionSet>,
) -> ApiResult<Json<CellSummary>> {
    Ok(Json(
        app.execute(move |s| {
            s.operate(
                &id,
                Operation::Adopt {
                    version_ids: input.version_ids,
                },
            )
        })
        .await?,
    ))
}
/// Preview pending/requested versions only; confirmation deliberately fails.
/// No dependency-aware Git cleanup or history mutation is implemented here.
async fn clean(
    State(app): State<App>,
    Path(id): Path<String>,
    Json(input): Json<VersionSet>,
) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(app.execute(move|s| {
        let pending=s.cell(&id)?.pending();
        if input.confirm {anyhow::bail!("Git dependency-aware cleanup is not yet implemented; preview only, no history changed");}
        Ok(serde_json::json!({"pending":pending,"requested":input.version_ids,"requires_confirmation":true,"implemented":false,"message":"Preview only: destructive Git reconciliation is disabled until dependency-safe cleanup is implemented"}))
    }).await?))
}
/// Return saved peer profiles and pinned transport information.
async fn peers(State(app): State<App>) -> ApiResult<Json<Vec<Peer>>> {
    Ok(Json(app.execute(|s| Ok(s.peers())).await?))
}
/// Validate a supplied peer origin and let Store validate/persist the full peer record.
async fn add_peer_profile(State(app): State<App>, Json(peer): Json<Peer>) -> ApiResult<Json<Peer>> {
    validate_peer_url(&peer.url)?;
    let result = peer.clone();
    app.execute(move |s| s.add_peer(peer)).await?;
    Ok(Json(result))
}
/// Perform one explicit peer synchronization outside a single Store closure.
async fn sync_peer(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<crate::peer::SyncReport>> {
    Ok(Json(crate::peer::sync(&app, &id).await?))
}
/// Revoke another FRAME through the peer lifecycle service and report its identifier.
async fn revoke_frame(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::peer::revoke_frame(&app, &id).await?;
    Ok(Json(serde_json::json!({"revoked":id})))
}
#[derive(Deserialize)]
/// Password used to prepare replacement FRAME material for a restore request.
struct RestoreRequest {
    password: String,
}
/// Prepare a restore request, wrapping the extracted password in a zeroizing owner.
async fn restore_request(
    State(app): State<App>,
    Json(input): Json<RestoreRequest>,
) -> ApiResult<Json<crate::restore::RestoreRequest>> {
    let password = zeroize::Zeroizing::new(input.password);
    Ok(Json(
        app.execute(move |s| s.prepare_restore(password.as_bytes()))
            .await?,
    ))
}
#[derive(Deserialize)]
/// Encoded restore credential and password for the resulting local state.
struct RestoreInput {
    password: String,
    credential: String,
}
/// Ask the Store to sign a restore authorization for a supplied replacement request.
async fn restore_issue(
    State(app): State<App>,
    Json(request): Json<crate::restore::RestoreRequest>,
) -> ApiResult<Json<comb_cell::SignedRecord>> {
    Ok(Json(app.execute(move |s| s.issue_restore(&request)).await?))
}

/// Apply a restore attempt and report restored, denied, or reset-required outcomes.
/// Exhausted attempts can reinitialize local private state and rotate the token;
/// callers must inspect the JSON outcome even when HTTP status is successful.
async fn restore_apply(
    State(app): State<App>,
    Json(input): Json<RestoreInput>,
) -> ApiResult<Json<serde_json::Value>> {
    let password = zeroize::Zeroizing::new(input.password);
    let credential = zeroize::Zeroizing::new(input.credential);
    Ok(Json(app.execute(move|s|Ok(match s.restore_credential(&credential,password.as_bytes())? {
        crate::lifecycle::RestoreOutcome::Restored=>serde_json::json!({"outcome":"restored","frame":s.profile()}),
        crate::lifecycle::RestoreOutcome::Denied{remaining}=>serde_json::json!({"outcome":"denied","remaining":remaining}),
        crate::lifecycle::RestoreOutcome::ResetRequired=>serde_json::json!({"outcome":"reinitialized","frame":s.profile(),"message":"Restore attempts exhausted; private CELL state removed and a fresh local identity created. Reload the local token."}),
    })).await?))
}
#[derive(Deserialize)]
/// Peer discovery input with an explicit identifier and pinned transport public key.
struct NewPeer {
    id: String,
    url: String,
    public_key: String,
}
/// Fetch `/identity` from a validated origin, then validate/persist it with the pin.
/// The origin check is not an SSRF allowlist: arbitrary HTTP(S) hosts are accepted.
async fn add_peer(State(app): State<App>, Json(input): Json<NewPeer>) -> ApiResult<Json<Peer>> {
    let url = validate_peer_url(&input.url)?;
    let client = http_client()?;
    let profile: Profile = client
        .get(format!("{url}/identity"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let peer = Peer {
        id: input.id,
        url,
        public_key: input.public_key,
        profile,
    };
    let result = peer.clone();
    app.execute(move |s| s.add_peer(peer)).await?;
    Ok(Json(result))
}
/// Build a 30-second HTTP client that refuses redirects to avoid forwarding secrets.
pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}
/// Parse an HTTP(S) origin and return its URL-normalized form without a trailing slash.
/// Credentials, non-root paths, queries, and fragments are rejected. Hosts need
/// not be loopback or public; callers impose any additional destination policy.
pub fn validate_peer_url(input: &str) -> Result<String> {
    let url = reqwest::Url::parse(input)?;
    if !matches!(url.scheme(), "http" | "https")
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        anyhow::bail!("peer URL must be an http(s) origin without credentials, query, or path");
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}
/// Adapt `.git` smart-HTTP requests to Store and forward backend status/headers/body.
/// Authentication is router middleware; Git protocol and repository authorization
/// are delegated to `Store::git_http`, with the original query preserved.
async fn git(
    State(app): State<App>,
    Path((repo, suffix)): Path<(String, String)>,
    method: Method,
    OriginalUri(uri): OriginalUri,
    headers: HeaderMap,
    body: Bytes,
) -> ApiResult<Response> {
    let id = repo
        .strip_suffix(".git")
        .context("Git remote must end in .git")?
        .to_owned();
    let query = uri.query().unwrap_or("").to_owned();
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let result = app
        .execute(move |s| s.git_http(&id, method.as_str(), &suffix, &query, &content_type, &body))
        .await?;
    let mut response = axum::http::Response::builder().status(result.status);
    for (name, value) in result.headers {
        response = response.header(name, value);
    }
    Ok(response.body(axum::body::Body::from(result.body))?)
}
