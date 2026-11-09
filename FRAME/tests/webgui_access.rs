//! Browser management reuses the unlocked daemon, not a user-entered token.
use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use comb_frame::{
    api::{App, router},
    identity,
    store::Store,
};
use tower::ServiceExt;

#[tokio::test]
async fn browser_access_rejects_cross_origin_rebinding_and_git_and_obeys_revocation() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"test-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let app = App::new(Store::open(&data, b"test-password").unwrap());
    let router = router(app.clone(), directory.path().join("assets"));
    for (name, path, method, host, site, origin, marker, auth) in [
        (
            "plain request",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            None,
            None,
            None,
            None,
        ),
        (
            "missing fetch metadata",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            None,
            None,
            Some("1"),
            None,
        ),
        (
            "missing marker",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("same-origin"),
            None,
            None,
            None,
        ),
        (
            "cross site",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("cross-site"),
            None,
            Some("1"),
            None,
        ),
        (
            "other local origin",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("same-site"),
            None,
            Some("1"),
            None,
        ),
        (
            "rebinding host",
            "/api/status",
            "GET",
            "attacker.example:7331",
            Some("same-origin"),
            None,
            Some("1"),
            None,
        ),
        (
            "non loopback IP",
            "/api/status",
            "GET",
            "192.0.2.1:7331",
            Some("same-origin"),
            None,
            Some("1"),
            None,
        ),
        (
            "foreign origin",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("same-origin"),
            Some("https://attacker.example"),
            Some("1"),
            None,
        ),
        (
            "null origin",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("same-origin"),
            Some("null"),
            Some("1"),
            None,
        ),
        (
            "different port",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("same-origin"),
            Some("http://127.0.0.1:7332"),
            Some("1"),
            None,
        ),
        (
            "write without origin",
            "/api/cells",
            "POST",
            "127.0.0.1:7331",
            Some("same-origin"),
            None,
            Some("1"),
            None,
        ),
        (
            "simple cross origin write",
            "/api/cells",
            "POST",
            "127.0.0.1:7331",
            Some("cross-site"),
            Some("https://attacker.example"),
            None,
            None,
        ),
        (
            "invalid explicit token",
            "/api/status",
            "GET",
            "127.0.0.1:7331",
            Some("same-origin"),
            None,
            Some("1"),
            Some("Bearer invalid"),
        ),
        (
            "Git still requires token",
            "/git/test.git/info/refs?service=git-upload-pack",
            "GET",
            "127.0.0.1:7331",
            Some("same-origin"),
            None,
            Some("1"),
            None,
        ),
    ] {
        let mut request = Request::builder()
            .method(method)
            .uri(path)
            .header("host", host);
        for (header, value) in [
            ("sec-fetch-site", site),
            ("origin", origin),
            ("x-comb-webgui", marker),
            ("authorization", auth),
        ] {
            if let Some(value) = value {
                request = request.header(header, value);
            }
        }
        let response = router
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED, "{name}");
        assert!(
            response
                .headers()
                .get("access-control-allow-origin")
                .is_none()
        );
    }
    for host in ["localhost:7331", "[::1]:7331"] {
        let request = Request::builder()
            .uri("/api/status")
            .header("host", host)
            .header("sec-fetch-site", "same-origin")
            .header("x-comb-webgui", "1")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            router.clone().oneshot(request).await.unwrap().status(),
            StatusCode::OK
        );
    }
    app.execute(|store| store.lock("test-revocation".into()))
        .await
        .unwrap();
    let request = Request::builder()
        .uri("/api/cells")
        .header("host", "localhost:7331")
        .header("sec-fetch-site", "same-origin")
        .header("x-comb-webgui", "1")
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        router.oneshot(request).await.unwrap().status(),
        StatusCode::LOCKED
    );
}

#[tokio::test]
async fn same_origin_webgui_manages_cells_without_a_token() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"test-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let app = App::new(Store::open(&data, b"test-password").unwrap());
    let router = router(app, directory.path().join("assets"));
    let request = |path: &str, body: Option<&str>| {
        let mut request = Request::builder()
            .uri(path)
            .header("host", "127.0.0.1:7331")
            .header("sec-fetch-site", "same-origin")
            .header("x-comb-webgui", "1");
        if body.is_some() {
            request = request
                .method("POST")
                .header("origin", "http://127.0.0.1:7331")
                .header("content-type", "application/json");
        }
        request
            .body(Body::from(body.unwrap_or("").to_owned()))
            .unwrap()
    };
    let status = router
        .clone()
        .oneshot(request("/api/status", None))
        .await
        .unwrap();
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(status.headers().get("cache-control").unwrap(), "no-store");
    let created = router
        .clone()
        .oneshot(request("/api/cells", Some(r#"{"name":"Browser CELL"}"#)))
        .await
        .unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
    let listed = router.oneshot(request("/api/cells", None)).await.unwrap();
    assert_eq!(listed.status(), StatusCode::OK);
    let cells: serde_json::Value =
        serde_json::from_slice(&to_bytes(listed.into_body(), 1_000_000).await.unwrap()).unwrap();
    assert_eq!(cells[0]["name"], "Browser CELL");
}
