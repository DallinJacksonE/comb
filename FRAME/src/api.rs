//! Loopback management API and standard Git smart HTTP adapter.
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
pub struct App {
    pub(crate) store: Arc<Mutex<Store>>,
    pub peer_enabled: tokio::sync::watch::Sender<bool>,
}
impl App {
    pub fn new(store: Store) -> Self {
        let (peer_enabled, _) = tokio::sync::watch::channel(store.is_active());
        Self {
            store: Arc::new(Mutex::new(store)),
            peer_enabled,
        }
    }
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

pub struct ApiError(anyhow::Error);
impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(error: E) -> Self {
        Self(error.into())
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error":self.0.to_string()})),
        )
            .into_response()
    }
}
type ApiResult<T> = std::result::Result<T, ApiError>;

pub fn router(app: App, assets: PathBuf) -> Router {
    let routes = Router::new()
        .route("/api/status", get(status))
        .route("/api/cells", get(list_cells).post(create_cell))
        .route("/api/cells/{id}", get(get_cell))
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
        .layer(middleware::from_fn_with_state(app.clone(), authorize));
    routes
        .layer(DefaultBodyLimit::max(64 * 1024 * 1024))
        .fallback_service(
            ServeDir::new(&assets).not_found_service(ServeFile::new(assets.join("index.html"))),
        )
        .with_state(app)
}

async fn authorize(State(app): State<App>, request: Request, next: Next) -> Response {
    let supplied = credential(request.headers());
    let result = app
        .execute(move |store| {
            Ok((
                supplied
                    .as_bytes()
                    .ct_eq(store.local.token.as_bytes())
                    .into(),
                store.is_active(),
            ))
        })
        .await;
    match result {
        Ok((true,active)) if active || request.uri().path()=="/api/status" || request.uri().path().starts_with("/api/restore") => next.run(request).await,
        Ok((true,_))=>(StatusCode::LOCKED,Json(serde_json::json!({"error":"FRAME revoked: use another authorized FRAME to generate a restore credential"}))).into_response(),
        _=>{let mut response=(StatusCode::UNAUTHORIZED,Json(serde_json::json!({"error":"local management token required"}))).into_response();response.headers_mut().insert("www-authenticate","Basic realm=\"COMB FRAME\"".parse().unwrap());response}
    }
}
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
async fn status(State(app): State<App>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(app.execute(|store|Ok(serde_json::json!({
        "identity":{"id":store.profile().id(),"name":store.profile().name,"email":store.profile().email},
        "frame":{"id":store.profile().frame_id(),"active":store.is_active()},"cells":store.count(),
        "capabilities":["git-http","encrypted-snapshots","signed-cell-history","pinned-noise-peers","offline-recovery"],
        "lifecycle":store.lifecycle(),"profile":store.profile()
    }))).await?))
}
async fn list_cells(State(app): State<App>) -> ApiResult<Json<Vec<CellSummary>>> {
    Ok(Json(app.execute(|s| s.list_cells()).await?))
}
#[derive(Deserialize)]
struct CreateCell {
    name: String,
}
async fn create_cell(
    State(app): State<App>,
    Json(input): Json<CreateCell>,
) -> ApiResult<(StatusCode, Json<CellSummary>)> {
    Ok((
        StatusCode::CREATED,
        Json(app.execute(move |s| s.create_cell(input.name)).await?),
    ))
}
async fn get_cell(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<CellSummary>> {
    Ok(Json(app.execute(move |s| s.cell_summary(&id)).await?))
}
async fn issues(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Vec<Issue>>> {
    Ok(Json(app.execute(move |s| s.issues(&id)).await?))
}
#[derive(Deserialize)]
struct NewIssue {
    title: String,
    #[serde(default)]
    body: String,
}
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
struct Grant {
    profile: Profile,
    role: Role,
}
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
struct Revoke {
    identity_id: String,
}
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
async fn backup(State(app): State<App>, Path(id): Path<String>) -> ApiResult<Json<Snapshot>> {
    Ok(Json(app.execute(move |s| s.export_snapshot(&id)).await?))
}
#[derive(Deserialize)]
struct VersionSet {
    version_ids: Vec<String>,
    #[serde(default)]
    confirm: bool,
}
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
async fn peers(State(app): State<App>) -> ApiResult<Json<Vec<Peer>>> {
    Ok(Json(app.execute(|s| Ok(s.peers())).await?))
}
async fn add_peer_profile(State(app): State<App>, Json(peer): Json<Peer>) -> ApiResult<Json<Peer>> {
    validate_peer_url(&peer.url)?;
    let result = peer.clone();
    app.execute(move |s| s.add_peer(peer)).await?;
    Ok(Json(result))
}
async fn sync_peer(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<crate::peer::SyncReport>> {
    Ok(Json(crate::peer::sync(&app, &id).await?))
}
async fn revoke_frame(
    State(app): State<App>,
    Path(id): Path<String>,
) -> ApiResult<Json<serde_json::Value>> {
    crate::peer::revoke_frame(&app, &id).await?;
    Ok(Json(serde_json::json!({"revoked":id})))
}
#[derive(Deserialize)]
struct RestoreRequest {
    password: String,
}
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
struct RestoreInput {
    password: String,
    credential: String,
}
async fn restore_issue(
    State(app): State<App>,
    Json(request): Json<crate::restore::RestoreRequest>,
) -> ApiResult<Json<comb_cell::SignedRecord>> {
    Ok(Json(app.execute(move |s| s.issue_restore(&request)).await?))
}

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
struct NewPeer {
    id: String,
    url: String,
    public_key: String,
}
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
pub fn http_client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(std::time::Duration::from_secs(30))
        .build()?)
}
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
