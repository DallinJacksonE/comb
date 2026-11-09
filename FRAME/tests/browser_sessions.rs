use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use comb_frame::{
    api::{self, App},
    identity,
    store::Store,
};
use tower::ServiceExt;

#[tokio::test]
async fn revocation_never_exposes_profile_via_cookie_status_exception() {
    let (dir, app, token) = fixture();
    let router = api::remote_router(
        app.clone(),
        dir.path().join("assets"),
        "https://frame.example",
    )
    .unwrap();
    let response = login(&router, &token, None).await;
    let session = cookie(&response);
    app.execute(|s| s.lock("revoked".into())).await.unwrap();
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/status", String::new())
                .header("cookie", &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::LOCKED);
    assert!(json(response).await.get("profile").is_none());
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/browser/session", String::new())
                .header("cookie", &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        json(response).await,
        serde_json::json!({"mode":"remote","authenticated":false,"frame_id":null,"profile":null})
    );
    let response = router
        .oneshot(
            request("GET", "/api/status", String::new())
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "explicit management token retains recovery access"
    );
}

async fn login(router: &Router, token: &str, cookie: Option<&str>) -> axum::response::Response {
    let mut req = request("POST", "/api/browser/session", String::new());
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    router
        .clone()
        .oneshot(
            req.body(Body::from(serde_json::json!({"token":token}).to_string()))
                .unwrap(),
        )
        .await
        .unwrap()
}
fn cookie(response: &axum::response::Response) -> String {
    response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
#[tokio::test]
async fn exchange_rotation_logout_and_explicit_credentials() {
    let (dir, app, token) = fixture();
    let router = api::remote_router(
        app.clone(),
        dir.path().join("assets"),
        "https://frame.example",
    )
    .unwrap();
    let response = login(&router, &token, None).await;
    assert_eq!(response.status(), StatusCode::OK);
    let set = response.headers()["set-cookie"].to_str().unwrap();
    for flag in [
        "__Host-comb_session=",
        "; HttpOnly",
        "; Secure",
        "; SameSite=Strict",
        "; Path=/",
        "; Max-Age=28800",
    ] {
        assert!(set.contains(flag), "{set}");
    }
    assert!(!set.contains("Domain="));
    let first = cookie(&response);
    assert_eq!(first.split('=').nth(1).unwrap().len(), 64);
    let profile = app.execute(|s| Ok(s.profile().clone())).await.unwrap();
    assert_eq!(
        json(response).await,
        serde_json::json!({"mode":"remote","authenticated":true,"frame_id":profile.frame_id(),"profile":profile})
    );
    let response = login(&router, &token, Some(&first)).await;
    let second = cookie(&response);
    assert_ne!(first, second);
    for (cookie_value, expected) in [
        (&first, StatusCode::UNAUTHORIZED),
        (&second, StatusCode::OK),
    ] {
        let response = router
            .clone()
            .oneshot(
                request("GET", "/api/status", String::new())
                    .header("cookie", cookie_value)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    for path in [
        "/api/status",
        "/api/browser/session",
        "/git/test.git/info/refs",
    ] {
        let response = router
            .clone()
            .oneshot(
                request("GET", path, String::new())
                    .header("cookie", &second)
                    .header("authorization", "Bearer invalid")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
    let response = router
        .clone()
        .oneshot(
            request("GET", "/git/test.git/info/refs", String::new())
                .header("cookie", &second)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for authorization in [
        format!("Bearer {token}"),
        format!(
            "Basic {}",
            base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                format!("git:{token}")
            )
        ),
    ] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/api/status")
                    .header("host", "frame.example")
                    .header("authorization", authorization)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }
    let response = router
        .clone()
        .oneshot(
            request("DELETE", "/api/browser/session", String::new())
                .header("cookie", &second)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/browser/session", String::new())
                .header("cookie", &second)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(json(response).await["authenticated"], false);
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/status", String::new())
                .header("cookie", &second)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = login(&router, &token, None).await;
    let active = cookie(&response);
    app.execute(|s| s.lock("test".into())).await.unwrap();
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/cells", String::new())
                .header("cookie", active)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::LOCKED);
    let response = login(&router, &token, None).await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(response.headers().get("set-cookie").is_none());
}

fn fixture() -> (tempfile::TempDir, App, String) {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"password",
        &dir.path().join("recovery"),
    )
    .unwrap();
    let store = Store::open(&data, b"password").unwrap();
    let token = store.local.token.clone();
    (dir, App::new(store), token)
}
fn request(method: &str, path: &str, body: String) -> axum::http::request::Builder {
    let _ = body;
    Request::builder()
        .method(method)
        .uri(path)
        .header("host", "frame.example")
        .header("x-comb-webgui", "1")
        .header("sec-fetch-site", "same-origin")
        .header("origin", "https://frame.example")
        .header("content-type", "application/json")
}
async fn json(response: axum::response::Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 100_000).await.unwrap()).unwrap()
}
#[tokio::test]
async fn anonymous_discovery_never_inherits_local_auto_auth() {
    let (dir, app, _) = fixture();
    let router =
        api::remote_router(app, dir.path().join("assets"), "https://frame.example").unwrap();
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/browser/session", String::new())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        json(response).await,
        serde_json::json!({"mode":"remote","authenticated":false,"frame_id":null,"profile":null})
    );
    let response = router
        .oneshot(
            request("GET", "/api/status", String::new())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn strict_origin_host_provenance_and_security_headers() {
    let (dir, app, token) = fixture();
    for origin in [
        "http://frame.example",
        "https://frame.example/",
        "https://FRAME.example",
        "https://frame.example:443",
        "https://user@frame.example",
        "https://frame.example/path",
        "https://frame.example?x",
        "https://frame.example#x",
        "https://frame.example/..",
        "https://frame.example\\evil",
    ] {
        assert!(
            api::remote_router(app.clone(), dir.path().join("assets"), origin).is_err(),
            "{origin}"
        );
    }
    let router =
        api::remote_router(app, dir.path().join("assets"), "https://frame.example").unwrap();
    for host in [
        "evil.example",
        "localhost",
        "127.0.0.1",
        "frame.example:443",
        "frame.example.",
        "FRAME.example",
        "user@frame.example",
    ] {
        for path in [
            "/api/status",
            "/api/browser/session",
            "/",
            "/git/a.git/info/refs",
        ] {
            let response = router
                .clone()
                .oneshot(
                    Request::builder()
                        .uri(path)
                        .header("host", host)
                        .header("authorization", format!("Bearer {token}"))
                        .header("forwarded", "host=frame.example;proto=https")
                        .header("x-forwarded-host", "frame.example")
                        .header("x-forwarded-proto", "https")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::FORBIDDEN, "{host} {path}");
        }
    }
    for (marker, site, origin) in [
        (None, Some("same-origin"), None),
        (Some("1"), None, None),
        (Some("1"), Some("same-site"), None),
        (Some("1"), Some("same-origin"), Some("null")),
        (Some("1"), Some("same-origin"), Some("https://evil.example")),
        (
            Some("1"),
            Some("same-origin"),
            Some("https://frame.example/"),
        ),
    ] {
        let mut req = Request::builder()
            .uri("/api/browser/session")
            .header("host", "frame.example");
        for (key, val) in [
            ("x-comb-webgui", marker),
            ("sec-fetch-site", site),
            ("origin", origin),
        ] {
            if let Some(val) = val {
                req = req.header(key, val);
            }
        }
        assert_eq!(
            router
                .clone()
                .oneshot(req.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            StatusCode::UNAUTHORIZED
        );
    }
    let response = router
        .clone()
        .oneshot(
            request("GET", "/api/browser/session", String::new())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
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
        assert_eq!(response.headers()[key], value);
    }
    assert!(
        response
            .headers()
            .get("access-control-allow-origin")
            .is_none()
    );
    assert_eq!(
        router
            .oneshot(Request::builder().uri("/").body(Body::empty()).unwrap())
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
}
