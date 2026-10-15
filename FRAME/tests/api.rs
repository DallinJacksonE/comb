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
async fn api_requires_local_token_and_creates_persisted_cells() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"local-test-password",
        &dir.path().join("recovery"),
    )
    .unwrap();
    let store = Store::open(&data, b"local-test-password").unwrap();
    let token = store.local.token.clone();
    let router = router(
        App::new(store),
        std::path::PathBuf::from("FRAME/webgui/dist"),
    );
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/cells")
                .method("POST")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(r#"{"name":"Repository"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);
    let bytes = to_bytes(response.into_body(), 1_000_000).await.unwrap();
    let result: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(result["name"], "Repository");
    let response = router
        .oneshot(
            Request::builder()
                .uri("/api/status")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}
