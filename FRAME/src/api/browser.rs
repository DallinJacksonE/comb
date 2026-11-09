//! Remote owner-management browser boundary. Never delegates to local authorization.
//!
//! Explicit tokens authenticate API and Git clients. Browser cookies authenticate
//! only provenance-checked `/api/` requests, never Git. Sessions are listener-local,
//! hashed in memory, bound to a FRAME ID, and expire eight hours after issuance.
//! TLS termination and preservation of the configured Host are caller obligations.
#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use std::{
        sync::atomic::{AtomicU64, Ordering},
        time::{Duration, Instant},
    };
    use tower::ServiceExt;

    fn request(method: &str, path: &str, token: &str, cookie: &str) -> Request {
        axum::http::Request::builder()
            .method(method)
            .uri(path)
            .header("host", "frame.example")
            .header("x-comb-webgui", "1")
            .header("sec-fetch-site", "same-origin")
            .header("origin", "https://frame.example")
            .header("cookie", cookie)
            .header("content-type", "application/json")
            .body(Body::from(serde_json::json!({"token":token}).to_string()))
            .unwrap()
    }
    #[tokio::test]
    async fn bounded_sessions_absolute_expiry_and_global_rolling_login_limit() {
        let dir = tempfile::tempdir().unwrap();
        let data = dir.path().join("frame");
        crate::identity::initialize(
            &data,
            "Alice",
            "alice@test",
            b"password",
            &dir.path().join("recovery"),
        )
        .unwrap();
        let store = Store::open(&data, b"password").unwrap();
        let token = store.local.token.clone();
        let app = App::new(store);
        let base = Instant::now();
        let ticks = Arc::new(AtomicU64::new(0));
        let clock = ticks.clone();
        let router = remote_router_with_clock(
            app.clone(),
            dir.path().join("assets"),
            "https://frame.example",
            Arc::new(move || base + Duration::from_secs(clock.load(Ordering::SeqCst))),
        )
        .unwrap();
        let mut cookies = Vec::new();
        for i in 0..128 {
            if i > 0 && i % 10 == 0 {
                ticks.fetch_add(61, Ordering::SeqCst);
            }
            let response = router
                .clone()
                .oneshot(request("POST", "/api/browser/session", &token, ""))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "session {i}");
            cookies.push(
                response.headers()["set-cookie"]
                    .to_str()
                    .unwrap()
                    .split(';')
                    .next()
                    .unwrap()
                    .to_owned(),
            );
            if i == 9 {
                let response = router
                    .clone()
                    .oneshot(request("POST", "/api/browser/session", &token, ""))
                    .await
                    .unwrap();
                assert_eq!(
                    response.status(),
                    StatusCode::UNAUTHORIZED,
                    "successes consume global budget"
                );
            }
        }
        let response = router
            .clone()
            .oneshot(request("POST", "/api/browser/session", &token, ""))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            StatusCode::UNAUTHORIZED,
            "capacity refuses session 129"
        );
        for cookie in &cookies {
            assert_eq!(
                router
                    .clone()
                    .oneshot(request("GET", "/api/status", "", cookie))
                    .await
                    .unwrap()
                    .status(),
                StatusCode::OK
            );
        }
        ticks.store(28799, Ordering::SeqCst);
        assert_eq!(
            router
                .clone()
                .oneshot(request("GET", "/api/status", "", &cookies[0]))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        ticks.store(28800, Ordering::SeqCst);
        assert_eq!(
            router
                .clone()
                .oneshot(request("GET", "/api/status", "", &cookies[0]))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "reads must not extend absolute TTL"
        );
        assert_eq!(
            router
                .clone()
                .oneshot(request("POST", "/api/browser/session", &token, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "expired entries reclaimed"
        );
        let fresh = remote_router(app, dir.path().join("assets"), "https://frame.example").unwrap();
        assert_eq!(
            fresh
                .oneshot(request("GET", "/api/status", "", &cookies[127]))
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED,
            "new listener has no persisted sessions"
        );
    }
}
use super::*;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    time::{Duration, Instant},
};

const TTL: Duration = Duration::from_secs(8 * 60 * 60);
const CAPACITY: usize = 128;
/// Injectable monotonic time source for expiry and rolling login-budget tests.
type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;
/// Session binding and absolute issuance time; reads do not refresh expiry.
struct Session {
    frame: String,
    issued: Instant,
}

#[derive(Clone)]
/// Shared origin policy, hashed sessions, and listener-wide login attempt budget.
struct Remote {
    origin: String,
    host: String,
    app: App,
    sessions: Arc<Mutex<HashMap<[u8; 32], Session>>>,
    attempts: Arc<Mutex<VecDeque<Instant>>>,
    clock: Clock,
}
/// Build remote owner administration for an exact canonical HTTPS origin.
///
/// Requires the configured Host even for assets. API/Git accept explicit Bearer
/// or Basic credentials; browser sessions require same-origin provenance and an
/// active FRAME. This is owner management, not a multi-user repository login.
pub fn remote_router(app: App, assets: PathBuf, origin: &str) -> Result<Router> {
    remote_router_with_clock(app, assets, origin, Arc::new(Instant::now))
}
/// Construct a fresh session namespace with a replaceable monotonic clock.
fn remote_router_with_clock(
    app: App,
    assets: PathBuf,
    origin: &str,
    clock: Clock,
) -> Result<Router> {
    let url = reqwest::Url::parse(origin)?;
    anyhow::ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.origin().ascii_serialization() == origin,
        "public browser origin must be a canonical HTTPS origin without credentials, path, query or fragment"
    );
    let remote = Remote {
        origin: origin.to_owned(),
        host: origin.strip_prefix("https://").unwrap().to_owned(),
        app: app.clone(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
        attempts: Arc::new(Mutex::new(VecDeque::new())),
        clock,
    };
    let routes = api_routes().layer(middleware::from_fn_with_state(
        remote.clone(),
        remote_authorize,
    ));
    let session = Router::new()
        .route(
            "/api/browser/session",
            get(session).post(session).delete(session),
        )
        .with_state(remote.clone());
    Ok(finish_routes(routes, app, assets)
        .merge(session)
        .layer(middleware::from_fn_with_state(remote, boundary)))
}
/// Read exactly one UTF-8 header value; duplicates and invalid bytes are rejected.
fn single<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() {
        return None;
    }
    Some(value)
}
/// Require GUI marker, same-origin Fetch Metadata, and matching Origin.
/// Origin may be absent only for GET/HEAD; duplicated headers never qualify.
fn provenance(remote: &Remote, request: &Request) -> bool {
    let headers = request.headers();
    single(headers, "x-comb-webgui") == Some("1")
        && single(headers, "sec-fetch-site") == Some("same-origin")
        && match single(headers, "origin") {
            Some(origin) => origin == remote.origin,
            None => {
                !headers.contains_key("origin")
                    && matches!(*request.method(), Method::GET | Method::HEAD)
            }
        }
}
/// Enforce exact Host and session-endpoint provenance, then add security headers.
/// Host failures are 403; session provenance failures use the generic 401 response.
async fn boundary(State(remote): State<Remote>, request: Request, next: Next) -> Response {
    let mut response = if single(request.headers(), "host") != Some(remote.host.as_str()) {
        StatusCode::FORBIDDEN.into_response()
    } else if request.uri().path() == "/api/browser/session" && !provenance(&remote, &request) {
        denied()
    } else {
        next.run(request).await
    };
    for (key, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("referrer-policy", "no-referrer"),
        ("x-frame-options", "DENY"),
        ("strict-transport-security", "max-age=86400"),
        (
            "content-security-policy",
            "default-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ] {
        response.headers_mut().insert(
            axum::http::HeaderName::from_static(key),
            value.parse().unwrap(),
        );
    }
    response
}
/// Return a generic 401 without disclosing which browser authentication check failed.
fn denied() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(serde_json::json!({"error":"browser authentication failed"})),
    )
        .into_response()
}
/// Hash one well-formed lowercase-hex session cookie; reject duplicate named cookies.
fn session_key(headers: &HeaderMap) -> Option<[u8; 32]> {
    let mut found = None;
    for header in headers.get_all("cookie") {
        for part in header.to_str().ok()?.split(';') {
            let Some((name, value)) = part.trim().split_once('=') else {
                continue;
            };
            if name == "__Host-comb_session" {
                if found.is_some()
                    || value.len() != 64
                    || !value
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return None;
                }
                found = Some(Sha256::digest(value.as_bytes()).into());
            }
        }
    }
    found
}
/// Snapshot token/lifecycle/profile and validate a cookie against live session state.
/// Explicit Authorization takes precedence, even when invalid. Expired sessions
/// are pruned; inactive FRAMEs clear sessions after this request's cookie lookup.
fn authentication<'a>(
    remote: &'a Remote,
    request: &Request,
) -> impl std::future::Future<Output = Result<(bool, bool, Profile)>> + Send + 'a {
    let explicit = request.headers().contains_key("authorization");
    let supplied = zeroize::Zeroizing::new(credential(request.headers()));
    let browser = request.uri().path().starts_with("/api/") && provenance(remote, request);
    let key = session_key(request.headers());
    async move {
        let (token_ok, active, profile) = remote
            .app
            .execute(move |s| {
                Ok((
                    !supplied.is_empty()
                        && bool::from(supplied.as_bytes().ct_eq(s.local.token.as_bytes())),
                    s.is_active(),
                    s.profile().clone(),
                ))
            })
            .await?;
        let mut sessions = remote
            .sessions
            .lock()
            .map_err(|_| anyhow::anyhow!("browser state unavailable"))?;
        let now = (remote.clock)();
        sessions.retain(|_, session| now.saturating_duration_since(session.issued) < TTL);
        let cookie_ok = !explicit
            && browser
            && key
                .and_then(|key| sessions.get(&key))
                .is_some_and(|session| session.frame == profile.frame_id());
        if !active {
            sessions.clear();
        }
        Ok((if explicit { token_ok } else { cookie_ok }, active, profile))
    }
}
/// Gate shared routes, retaining revoked status/restore access for explicit tokens only.
async fn remote_authorize(State(remote): State<Remote>, request: Request, next: Next) -> Response {
    match authentication(&remote, &request).await {
        Ok((true, active, _))
            if active
                || (request.headers().contains_key("authorization")
                    && (request.uri().path() == "/api/status"
                        || request.uri().path().starts_with("/api/restore"))) =>
        {
            next.run(request).await
        }
        Ok((true, _, _)) => (
            StatusCode::LOCKED,
            Json(serde_json::json!({"error":"FRAME revoked"})),
        )
            .into_response(),
        _ => {
            let mut response = denied();
            response.headers_mut().insert(
                "www-authenticate",
                "Basic realm=\"COMB FRAME\"".parse().unwrap(),
            );
            response
        }
    }
}
/// Describe remote login state, including the public profile only when supplied.
fn discovery(profile: Option<&Profile>) -> Response {
    Json(serde_json::json!({"mode":"remote","authenticated":profile.is_some(),"frame_id":profile.map(|p|p.frame_id()),"profile":profile})).into_response()
}
/// Set or expire a host-only Secure, HttpOnly, Strict same-site session cookie.
fn with_cookie(mut response: Response, value: &str, max_age: u64) -> Response {
    response.headers_mut().insert("set-cookie",format!("__Host-comb_session={value}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={max_age}").parse().unwrap());
    response
}
#[derive(Deserialize)]
/// JSON token exchange input; this endpoint is not a vault-password login.
struct Login {
    token: String,
}
/// Discover (GET), invalidate (DELETE), or exchange a management token (POST).
///
/// POST consumes the global rolling budget of ten attempts per minute, including
/// successes, and reads at most 4096 body bytes. It removes any presented session
/// before login and caps live sessions at 128. DELETE expires the cookie even if
/// no session exists. All methods require browser provenance; an invalid explicit
/// Authorization header prevents fallback to cookie or JSON-token authentication.
async fn session(State(remote): State<Remote>, request: Request) -> Response {
    if !provenance(&remote, &request) {
        return denied();
    }
    let Ok((authenticated, active, profile)) = authentication(&remote, &request).await else {
        return denied();
    };
    if request.headers().contains_key("authorization") && !authenticated {
        return denied();
    }
    match *request.method() {
        Method::GET | Method::HEAD => discovery((authenticated && active).then_some(&profile)),
        Method::DELETE => {
            if let Some(key) = session_key(request.headers()) {
                let Ok(mut sessions) = remote.sessions.lock() else {
                    return denied();
                };
                sessions.remove(&key);
            }
            with_cookie(discovery(None), "", 0)
        }
        Method::POST => {
            let key = session_key(request.headers());
            {
                let Ok(mut sessions) = remote.sessions.lock() else {
                    return denied();
                };
                if let Some(key) = key {
                    sessions.remove(&key);
                }
                let Ok(mut attempts) = remote.attempts.lock() else {
                    return denied();
                };
                let now = (remote.clock)();
                while attempts.front().is_some_and(|then| {
                    now.saturating_duration_since(*then) >= Duration::from_secs(60)
                }) {
                    attempts.pop_front();
                }
                if attempts.len() >= 10 {
                    return denied();
                }
                attempts.push_back(now);
            }
            let Ok(body) = axum::body::to_bytes(request.into_body(), 4096).await else {
                return denied();
            };
            let Ok(input) = serde_json::from_slice::<Login>(&body) else {
                return denied();
            };
            let token = zeroize::Zeroizing::new(input.token);
            let Ok((valid, active, profile)) = remote
                .app
                .execute(move |s| {
                    Ok((
                        !token.is_empty()
                            && bool::from(token.as_bytes().ct_eq(s.local.token.as_bytes())),
                        s.is_active(),
                        s.profile().clone(),
                    ))
                })
                .await
            else {
                return denied();
            };
            let Ok(mut sessions) = remote.sessions.lock() else {
                return denied();
            };
            if let Some(key) = key {
                sessions.remove(&key);
            }
            if !active {
                sessions.clear();
            }
            if !valid || !active {
                return denied();
            }
            let value = hex::encode(rand::random::<[u8; 32]>());
            let now = (remote.clock)();
            sessions.retain(|_, session| now.saturating_duration_since(session.issued) < TTL);
            if sessions.len() >= CAPACITY {
                return denied();
            }
            sessions.insert(
                Sha256::digest(value.as_bytes()).into(),
                Session {
                    frame: profile.frame_id(),
                    issued: now,
                },
            );
            with_cookie(discovery(Some(&profile)), &value, 28800)
        }
        _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
    }
}
/// Describe local GUI access after the local router's authentication/lifecycle gate.
pub(super) async fn local_session(State(app): State<App>) -> ApiResult<Json<serde_json::Value>> {
    Ok(Json(app.execute(|store| Ok(serde_json::json!({"mode":"local","authenticated":true,"frame_id":store.profile().frame_id(),"profile":store.profile()}))).await?))
}
