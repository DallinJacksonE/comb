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

#[test]
fn another_frame_cannot_browse_an_unshared_cell() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("owner");
    let other = directory.path().join("other");
    for path in [&data, &other] {
        identity::initialize(
            path,
            "Fixture",
            "fixture@test",
            b"password",
            &path.with_extension("recovery"),
        )
        .unwrap();
    }
    let mut store = Store::open(&data, b"password").unwrap();
    let cell = store.create_cell("Private Repo".into()).unwrap();
    store.local = identity::load(&other, b"password").unwrap();
    let denied_tree = store.repository_tree(&cell.id, None, "").err().unwrap();
    assert!(
        denied_tree
            .to_string()
            .contains("FRAME lacks repository permission")
    );
    let denied_blob = store
        .repository_blob(&cell.id, None, "README.md")
        .err()
        .unwrap();
    assert!(
        denied_blob
            .to_string()
            .contains("FRAME lacks repository permission")
    );
    assert!(
        store
            .repository_history(&cell.id, None, 0)
            .err()
            .unwrap()
            .to_string()
            .contains("FRAME lacks repository permission")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn published_code_is_browsable_but_private_refs_and_revoked_frames_are_not() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"fixture-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut store = Store::open(&data, b"fixture-password").unwrap();
    let cell = store.create_cell("Published Browser Repo".into()).unwrap();
    let token = store.local.token.clone();
    let app = App::new(store);
    let router = router(app.clone(), directory.path().join("assets"));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let remote = format!(
        "http://{}/git/{}.git",
        listener.local_addr().unwrap(),
        cell.id
    );
    let serving = tokio::spawn(axum::serve(listener, router.clone()).into_future());
    let work = directory.path().join("work");
    let credential = token.clone();
    tokio::task::spawn_blocking(move || {
        std::fs::create_dir(&work).unwrap();
        let git = |args: &[&str]| {
            let result = std::process::Command::new("git")
                .current_dir(&work)
                .env("GIT_CONFIG_NOSYSTEM", "1")
                .env("GIT_CONFIG_GLOBAL", "/dev/null")
                .env("GIT_AUTHOR_NAME", "Fixture")
                .env("GIT_AUTHOR_EMAIL", "fixture@test")
                .env("GIT_COMMITTER_NAME", "Fixture")
                .env("GIT_COMMITTER_EMAIL", "fixture@test")
                .env("GIT_TERMINAL_PROMPT", "0")
                .args(args)
                .output()
                .unwrap();
            assert!(result.status.success(), "Git fixture operation failed");
        };
        git(&["init", "--initial-branch=main"]);
        std::fs::write(work.join("README.md"), "# Published README\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-m", "Publish README"]);
        for index in 1..35 {
            git(&["commit", "--allow-empty", "-m", &format!("History {index}")]);
        }
        git(&[
            "-c",
            &format!("http.extraHeader=Authorization: Bearer {credential}"),
            "push",
            &remote,
            "main",
        ]);
    })
    .await
    .unwrap();
    serving.abort();
    let get = |query: &str| {
        Request::builder()
            .uri(format!("/api/cells/{}/{query}", cell.id))
            .header("authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap()
    };
    let blob = router
        .clone()
        .oneshot(get("blob?path=README.md"))
        .await
        .unwrap();
    assert_eq!(blob.status(), StatusCode::OK);
    let blob: serde_json::Value =
        serde_json::from_slice(&to_bytes(blob.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(blob["content"], "# Published README\n");
    let mut pages = Vec::new();
    for query in ["history", "history?offset=30"] {
        let response = router.clone().oneshot(get(query)).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        pages.push(
            serde_json::from_slice::<serde_json::Value>(
                &to_bytes(response.into_body(), 1_100_000).await.unwrap(),
            )
            .unwrap(),
        );
    }
    assert_eq!(pages[0]["commits"].as_array().unwrap().len(), 30);
    assert_eq!(pages[0]["has_more"], true);
    assert_eq!(pages[0]["next_offset"], 30);
    assert_eq!(pages[1]["commits"].as_array().unwrap().len(), 5);
    assert_eq!(pages[1]["has_more"], false);
    assert!(pages[1]["next_offset"].is_null());
    let commits: Vec<_> = pages
        .iter()
        .flat_map(|page| page["commits"].as_array().unwrap())
        .collect();
    assert_eq!(pages[0]["revision"], commits[0]["id"]);
    assert_eq!(pages[1]["revision"], pages[0]["revision"]);
    assert_eq!(pages[0].as_object().unwrap().len(), 4);
    for (offset, count) in [(5, 30), (35, 0)] {
        let response = router
            .clone()
            .oneshot(get(&format!(
                "history?revision={}&offset={offset}",
                pages[0]["revision"].as_str().unwrap()
            )))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let page: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 1_100_000).await.unwrap())
                .unwrap();
        assert_eq!(page["commits"].as_array().unwrap().len(), count);
        assert_eq!(page["has_more"], false);
        assert!(page["next_offset"].is_null());
    }
    for (index, commit) in commits.iter().enumerate() {
        assert_eq!(commit.as_object().unwrap().len(), 5);
        assert_eq!(commit["author"], "Fixture");
        assert!(commit["authored_at"].as_str().unwrap().contains('T'));
        assert_eq!(
            commit["subject"],
            if index == 34 {
                "Publish README".into()
            } else {
                format!("History {}", 34 - index)
            }
        );
        if index < 34 {
            assert_eq!(
                commit["parents"],
                serde_json::json!([commits[index + 1]["id"]])
            );
        } else {
            assert_eq!(commit["parents"], serde_json::json!([]));
        }
    }
    for query in [
        "history?revision=refs%2Fcomb%2Fconflicts%2Fprivate",
        "history?revision=HEAD~1",
        "history?revision=refs%2Fheads%2Fmain%5E",
        "history?offset=10001",
        "tree?revision=refs%2Fcomb%2Fconflicts%2Fprivate",
        "tree?revision=HEAD~1",
        "blob?path=..%2Fconfig",
        "blob?path=config",
        "tree?path=README.md",
    ] {
        assert_eq!(
            router.clone().oneshot(get(query)).await.unwrap().status(),
            StatusCode::BAD_REQUEST,
            "{query}"
        );
    }
    app.execute(|store| store.lock("fixture-revocation".into()))
        .await
        .unwrap();
    assert_eq!(
        router
            .clone()
            .oneshot(get("history"))
            .await
            .unwrap()
            .status(),
        StatusCode::LOCKED
    );
    assert_eq!(
        router
            .oneshot(get("blob?path=README.md"))
            .await
            .unwrap()
            .status(),
        StatusCode::LOCKED
    );
}

#[tokio::test]
async fn repository_settings_rename_and_confirmed_delete_are_real_api_operations() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"fixture-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut store = Store::open(&data, b"fixture-password").unwrap();
    let cell = store.create_cell("Settings Browser Repo".into()).unwrap();
    let token = store.local.token.clone();
    let router = router(App::new(store), directory.path().join("assets"));
    let post = |action: &str, value: serde_json::Value| {
        Request::builder()
            .method("POST")
            .uri(format!("/api/cells/{}/{action}", cell.id))
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/json")
            .body(Body::from(value.to_string()))
            .unwrap()
    };
    let renamed = router
        .clone()
        .oneshot(post("rename", serde_json::json!({"name":"Friendly Repo"})))
        .await
        .unwrap();
    assert_eq!(renamed.status(), StatusCode::OK);
    let renamed: serde_json::Value =
        serde_json::from_slice(&to_bytes(renamed.into_body(), 100_000).await.unwrap()).unwrap();
    assert_eq!(renamed["name"], "Friendly Repo");
    assert_eq!(renamed["slug"], "friendly-repo");
    assert_eq!(renamed["id"], cell.id);
    let declined = router
        .clone()
        .oneshot(post(
            "delete",
            serde_json::json!({"confirmation":"Settings Browser Repo"}),
        ))
        .await
        .unwrap();
    assert_eq!(declined.status(), StatusCode::BAD_REQUEST);
    let deleted = router
        .clone()
        .oneshot(post(
            "delete",
            serde_json::json!({"confirmation":"Friendly Repo"}),
        ))
        .await
        .unwrap();
    assert_eq!(deleted.status(), StatusCode::OK);
    let missing = router
        .oneshot(
            Request::builder()
                .uri(format!("/api/cells/{}", cell.id))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn empty_repository_tree_is_authenticated_and_explicitly_empty() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"fixture-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut store = Store::open(&data, b"fixture-password").unwrap();
    let cell = store.create_cell("Empty Browser Repo".into()).unwrap();
    let token = store.local.token.clone();
    let router = router(App::new(store), directory.path().join("assets"));
    let url = format!("/api/cells/{}/tree", cell.id);
    let unauthorized = router
        .clone()
        .oneshot(Request::builder().uri(&url).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);
    let response = router
        .clone()
        .oneshot(
            Request::builder()
                .uri(&url)
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let result: serde_json::Value =
        serde_json::from_slice(&to_bytes(response.into_body(), 100_000).await.unwrap()).unwrap();
    assert!(result["revision"].is_null());
    assert_eq!(result["entries"], serde_json::json!([]));
    assert_eq!(result["path"], "");
    let selected_default = router
        .oneshot(
            Request::builder()
                .uri(format!("{url}?revision=refs%2Fheads%2Fmain"))
                .header("authorization", format!("Bearer {token}"))
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(selected_default.status(), StatusCode::OK);
}

#[tokio::test]
async fn empty_history_has_exact_authenticated_response() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut store = Store::open(&data, b"password").unwrap();
    let cell = store.create_cell("Empty History".into()).unwrap();
    let token = store.local.token.clone();
    let router = router(App::new(store), directory.path().join("assets"));
    let url = format!("/api/cells/{}/history", cell.id);
    let response = router
        .clone()
        .oneshot(Request::builder().uri(&url).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    for query in ["", "?revision=refs%2Fheads%2Fmain&offset=10000"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{url}{query}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_slice(&to_bytes(response.into_body(), 100_000).await.unwrap())
                .unwrap();
        assert_eq!(
            body,
            serde_json::json!({"revision":null,"commits":[],"has_more":false,"next_offset":null})
        );
    }
    for offset in ["10001", "-1", "not-a-number", "18446744073709551616"] {
        let response = router
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("{url}?offset={offset}"))
                    .header("authorization", format!("Bearer {token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{offset}");
    }
}
