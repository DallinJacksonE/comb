//! Real Git clients must retain all accepted ref namespaces through encrypted restart.
use comb_frame::{api::App, identity, store::Store};
use std::{path::Path, process::Command};
use tokio::{sync::oneshot, task::JoinHandle};

const PASSWORD: &[u8] = b"ref-round-trip-fixture";

#[test]
fn loose_and_packed_custom_refs_have_identical_archive_round_trips() {
    use comb_frame::{archive, git::GitRepository};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let repository = GitRepository::create(root, "source").unwrap();
    git(root, "", &["init", "--initial-branch=main", "work"]);
    git(
        root,
        "",
        &["-C", "work", "commit", "--allow-empty", "-m", "initial"],
    );
    git(
        root,
        "",
        &[
            "-C",
            "work",
            "push",
            repository.path().to_str().unwrap(),
            "HEAD:refs/reviews/approved",
        ],
    );
    let expected = repository.refs().unwrap();
    for name in ["loose", "packed"] {
        if name == "packed" {
            git(
                root,
                "",
                &[
                    "--git-dir",
                    repository.path().to_str().unwrap(),
                    "pack-refs",
                    "--all",
                    "--prune",
                ],
            );
        }
        let bytes = archive::pack_directory(repository.path()).unwrap();
        archive::unpack_directory(&bytes, &root.join(format!("{name}.git"))).unwrap();
        let restored = GitRepository::open(root, name).unwrap();
        assert_eq!(
            restored.refs().unwrap(),
            expected,
            "{name} refs must survive"
        );
        git(
            root,
            "",
            &[
                "--git-dir",
                restored.path().to_str().unwrap(),
                "fsck",
                "--full",
            ],
        );
    }
}

#[test]
fn clients_cannot_push_frame_managed_refs() {
    use comb_frame::git::GitRepository;
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let repository = GitRepository::create(root, "remote").unwrap();
    git(root, "", &["init", "--initial-branch=main", "work"]);
    git(
        root,
        "",
        &["-C", "work", "commit", "--allow-empty", "-m", "initial"],
    );
    let assert_rejected = |repository: &GitRepository| {
        let output = Command::new("git")
            .current_dir(root)
            .args([
                "-C",
                "work",
                "push",
                repository.path().to_str().unwrap(),
                "HEAD:refs/comb/divergent/forged",
            ])
            .output()
            .unwrap();
        assert!(
            !output.status.success(),
            "Git must reject reserved refs before acknowledging a push"
        );
        assert!(repository.refs().unwrap().is_empty());
    };
    assert_rejected(&repository);
    // Archives omit config: reopening must establish receive policy itself,
    // rather than inheriting protection from the original repository's config.
    let bytes = comb_frame::archive::pack_directory(repository.path()).unwrap();
    let restored = root.join("restored.git");
    comb_frame::archive::unpack_directory(&bytes, &restored).unwrap();
    assert!(!restored.join("config").exists());
    let repository = GitRepository::open(root, "restored").unwrap();
    assert_rejected(&repository);
    // FRAME itself can still install retained divergence refs for clients to fetch.
    git(
        root,
        "",
        &[
            "-C",
            "work",
            "push",
            repository.path().to_str().unwrap(),
            "main",
        ],
    );
    let hash = git(root, "", &["-C", "work", "rev-parse", "HEAD"]);
    repository
        .install_refs(&std::collections::BTreeMap::from([(
            "refs/comb/divergent/retained".into(),
            hash,
        )]))
        .unwrap();
    let advertised = git(
        root,
        "",
        &["ls-remote", repository.path().to_str().unwrap()],
    );
    assert!(advertised.contains("refs/comb/divergent/retained"));
}

struct RunningFrame {
    url: String,
    stop: oneshot::Sender<()>,
    task: JoinHandle<()>,
}

impl RunningFrame {
    async fn start(store: Store) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let (stop, stopped) = oneshot::channel();
        let router = comb_frame::api::router(App::new(store), "missing-test-assets".into());
        let task = tokio::spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .unwrap();
        });
        Self { url, stop, task }
    }

    async fn stop(self) {
        let _ = self.stop.send(());
        self.task.await.unwrap();
    }
}

/// Run ordinary Git, keeping fixture authentication out of URLs and diagnostics.
fn git(root: &Path, token: &str, args: &[&str]) -> String {
    let output = git_output(root, token, args);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

fn git_output(root: &Path, token: &str, args: &[&str]) -> std::process::Output {
    Command::new("git")
        .current_dir(root)
        .args(["-c", "user.name=Alice", "-c", "user.email=alice@test"])
        .args(args)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_COUNT", "1")
        .env("GIT_CONFIG_KEY_0", "http.extraHeader")
        .env(
            "GIT_CONFIG_VALUE_0",
            format!("Authorization: Bearer {token}"),
        )
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accepted_notes_custom_refs_and_tags_are_fetchable_after_restart() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        PASSWORD,
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut store = Store::open(&data, PASSWORD).unwrap();
    let token = store.local.token.clone();
    let cell = store.create_cell("Ref round trip".into()).unwrap();
    let frame = RunningFrame::start(store).await;
    let remote = format!("{}/git/{}.git", frame.url, cell.id);
    let root = directory.path();
    git(root, &token, &["init", "--initial-branch=main", "work"]);
    std::fs::write(root.join("work/code.txt"), "durable code\n").unwrap();
    git(root, &token, &["-C", "work", "add", "."]);
    git(root, &token, &["-C", "work", "commit", "-m", "initial"]);
    git(
        root,
        &token,
        &["-C", "work", "notes", "add", "-m", "durable note"],
    );
    git(
        root,
        &token,
        &["-C", "work", "tag", "-a", "v1-fixture", "-m", "durable tag"],
    );
    git(
        root,
        &token,
        &["-C", "work", "update-ref", "refs/reviews/approved", "HEAD"],
    );

    let expected = git(
        root,
        &token,
        &[
            "-C",
            "work",
            "for-each-ref",
            "--format=%(refname) %(objectname)",
        ],
    );
    git(
        root,
        &token,
        &[
            "-C",
            "work",
            "push",
            &remote,
            "refs/heads/main",
            "refs/notes/commits",
            "refs/tags/v1-fixture",
            "refs/reviews/approved",
        ],
    );
    assert!(
        !git_output(
            root,
            &token,
            &[
                "-C",
                "work",
                "push",
                &remote,
                "HEAD:refs/comb/divergent/forged"
            ]
        )
        .status
        .success()
    );
    frame.stop().await;

    let reopened = Store::open(&data, PASSWORD)
        .expect("every acknowledged ref must survive the encrypted archive and reopen");
    assert_eq!(reopened.cell_summary(&cell.id).unwrap().refs.len(), 4);
    let frame = RunningFrame::start(reopened).await;
    let remote = format!("{}/git/{}.git", frame.url, cell.id);
    assert!(
        !git_output(
            root,
            &token,
            &[
                "-C",
                "work",
                "push",
                &remote,
                "HEAD:refs/comb/divergent/forged"
            ]
        )
        .status
        .success()
    );
    git(root, &token, &["init", "--bare", "fetched.git"]);
    git(
        root,
        &token,
        &["-C", "fetched.git", "fetch", &remote, "+refs/*:refs/*"],
    );
    assert_eq!(
        git(
            root,
            &token,
            &[
                "-C",
                "fetched.git",
                "for-each-ref",
                "--format=%(refname) %(objectname)"
            ]
        ),
        expected
    );
    assert_eq!(
        git(
            root,
            &token,
            &[
                "-C",
                "fetched.git",
                "show",
                "refs/reviews/approved:code.txt"
            ]
        ),
        "durable code"
    );
    assert_eq!(
        git(
            root,
            &token,
            &["-C", "fetched.git", "notes", "show", "refs/heads/main"]
        ),
        "durable note"
    );
    assert_eq!(
        git(
            root,
            &token,
            &[
                "-C",
                "fetched.git",
                "cat-file",
                "-t",
                "refs/tags/v1-fixture"
            ]
        ),
        "tag"
    );
    git(root, &token, &["-C", "fetched.git", "fsck", "--full"]);
    frame.stop().await;
}
