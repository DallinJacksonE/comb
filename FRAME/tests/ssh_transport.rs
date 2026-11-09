use comb_frame::{api::App, identity, store::Store};
use std::path::Path;
use tokio::process::Command;

async fn checked(mut cmd: Command) -> std::process::Output {
    cmd.kill_on_drop(true);
    let output = tokio::time::timeout(std::time::Duration::from_secs(15), cmd.output())
        .await
        .unwrap()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
}
fn git(dir: &Path, args: &[&str]) -> Command {
    let mut cmd = Command::new("git");
    cmd.current_dir(dir)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null");
    cmd
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn openssh_clone_push_persists_and_rejects_unknown_identity() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("frame");
    let key = tmp.path().join("client");
    let mut keygen = Command::new("ssh-keygen");
    keygen
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key);
    checked(keygen).await;
    identity::initialize(
        &data,
        "Alice",
        "a@example.test",
        b"test password",
        &tmp.path().join("recovery"),
    )
    .unwrap();
    identity::configure_ssh_profile(
        &data,
        b"test password",
        "alice",
        &std::fs::read_to_string(key.with_extension("pub"))
            .unwrap()
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" "),
    )
    .unwrap();
    let mut store = Store::open(&data, b"test password").unwrap();
    let cell = store.create_cell("Demo".into()).unwrap();
    let app = App::new(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(comb_frame::ssh::run(listener, app.clone(), host, async {
        let _ = stopped.await;
    }));
    let ssh = format!(
        "ssh -F /dev/null -i {} -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=3 -p {port}",
        key.display()
    );
    let url = "alice@127.0.0.1:demo.git";
    let work = tmp.path().join("work");
    let mut clone = git(tmp.path(), &["clone", url, work.to_str().unwrap()]);
    clone.env("GIT_SSH_COMMAND", &ssh);
    checked(clone).await;
    let mut payload = vec![0; 512 * 1024];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut payload);
    std::fs::write(work.join("hello"), &payload).unwrap();
    checked(git(&work, &["add", "hello"])).await;
    checked(git(
        &work,
        &[
            "-c",
            "user.name=Alice",
            "-c",
            "user.email=a@example.test",
            "commit",
            "-m",
            "initial",
        ],
    ))
    .await;
    let mut push = git(&work, &["push", "origin", "HEAD:main"]);
    push.env("GIT_SSH_COMMAND", &ssh);
    checked(push).await;
    let checkout = tmp.path().join("checkout");
    let mut clone = git(tmp.path(), &["clone", url, checkout.to_str().unwrap()]);
    clone.env("GIT_SSH_COMMAND", &ssh);
    checked(clone).await;
    assert_eq!(std::fs::read(checkout.join("hello")).unwrap(), payload);
    let id = cell.id.clone();
    let before_rejected = app
        .execute(move |s| Ok(s.cell_summary(&id)?.version))
        .await
        .unwrap();
    checked(git(&work, &["checkout", "--orphan", "rejected-history"])).await;
    checked(git(
        &work,
        &[
            "-c",
            "user.name=Alice",
            "-c",
            "user.email=a@example.test",
            "commit",
            "--allow-empty",
            "-m",
            "divergent root",
        ],
    ))
    .await;
    for args in [
        vec!["push", "--force", "origin", "HEAD:main"],
        vec!["push", "origin", ":main"],
        vec!["push", "origin", "HEAD:refs/comb/forbidden"],
    ] {
        let mut reject = git(&work, &args);
        reject.env("GIT_SSH_COMMAND", &ssh).kill_on_drop(true);
        assert!(
            !tokio::time::timeout(std::time::Duration::from_secs(10), reject.output())
                .await
                .unwrap()
                .unwrap()
                .status
                .success()
        );
    }
    let id = cell.id.clone();
    assert_eq!(
        app.execute(move |s| Ok(s.cell_summary(&id)?.version))
            .await
            .unwrap(),
        before_rejected,
        "rejected pushes must not create signed publications"
    );
    let mut wrong = git(&work, &["ls-remote", "nobody@127.0.0.1:demo.git"]);
    wrong.env("GIT_SSH_COMMAND", &ssh);
    assert!(!wrong.output().await.unwrap().status.success());
    let accepted = app
        .execute(move |s| Ok(s.cell_summary(&cell.id)?.refs))
        .await
        .unwrap();
    assert!(accepted.contains_key("refs/heads/main"));
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    drop(app);
    let reopened = Store::open(&data, b"test password").unwrap();
    assert_eq!(reopened.list_cells().unwrap()[0].refs, accepted);
}

async fn fixture_profile(root: &Path, username: &str) -> (std::path::PathBuf, identity::Profile) {
    let key = root.join(format!("{username}-key"));
    let mut keygen = Command::new("ssh-keygen");
    keygen
        .args(["-q", "-t", "ed25519", "-N", "", "-f"])
        .arg(&key);
    checked(keygen).await;
    let data = root.join(username);
    identity::initialize(
        &data,
        username,
        "test@example.test",
        b"test password",
        &root.join(format!("{username}-recovery")),
    )
    .unwrap();
    let public = std::fs::read_to_string(key.with_extension("pub"))
        .unwrap()
        .split_whitespace()
        .take(2)
        .collect::<Vec<_>>()
        .join(" ");
    let profile =
        identity::configure_ssh_profile(&data, b"test password", username, &public).unwrap();
    (key, profile)
}

fn ssh(key: &Path, port: u16, user: &str, command: Option<&str>) -> Command {
    let mut cmd = Command::new("ssh");
    cmd.args([
        "-F",
        "/dev/null",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "IdentityAgent=none",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=3",
        "-i",
    ])
    .arg(key)
    .arg("-p")
    .arg(port.to_string())
    .arg(format!("{user}@127.0.0.1"));
    if let Some(command) = command {
        cmd.arg(command);
    }
    cmd.kill_on_drop(true);
    cmd
}

async fn rejected(cmd: &mut Command) {
    let out = tokio::time::timeout(std::time::Duration::from_secs(5), cmd.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!out.status.success(), "unexpected SSH acceptance");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pinned_reader_unknown_key_injection_and_revoked_certificate() {
    use comb_cell::domain::{Operation, Role};
    let root = tempfile::tempdir().unwrap();
    let (alice_key, _) = fixture_profile(root.path(), "alice").await;
    let (bob_key, bob) = fixture_profile(root.path(), "bob").await;
    let mut store = Store::open(&root.path().join("alice"), b"test password").unwrap();
    let cell = store.create_cell("Demo".into()).unwrap();
    store.grant(&cell.id, &bob, Role::Read).unwrap();
    let app = App::new(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)
        .unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let server = tokio::spawn(comb_frame::ssh::run(listener, app.clone(), host, async {
        let _ = stopped.await;
    }));
    // Even a granted CELL member must have an explicitly pinned profile.
    rejected(&mut ssh(
        &bob_key,
        port,
        "bob",
        Some("git-upload-pack 'demo.git'"),
    ))
    .await;
    let bob_id = bob.frame_id();
    app.execute(move |s| {
        s.add_peer(comb_frame::store::Peer {
            id: bob.frame_id(),
            url: "http://127.0.0.1:1".into(),
            public_key: hex::encode(bob.noise_public),
            profile: bob,
        })
    })
    .await
    .unwrap();
    let mut ls = git(root.path(), &["ls-remote", "bob@127.0.0.1:demo.git"]);
    ls.env("GIT_SSH_COMMAND", format!("ssh -F /dev/null -i {} -p {port} -o IdentitiesOnly=yes -o IdentityAgent=none -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null", bob_key.display()));
    checked(ls).await;
    rejected(&mut ssh(
        &bob_key,
        port,
        "bob",
        Some("git-receive-pack 'demo.git'"),
    ))
    .await;
    for command in [
        "uname -a",
        "git-upload-pack '../demo.git'",
        "git-upload-pack 'demo.git'; id",
        "git-upload-pack '$HOME'",
        "git-upload-pack 'demo.git' extra",
    ] {
        rejected(&mut ssh(&alice_key, port, "alice", Some(command))).await;
    }
    rejected(&mut ssh(&alice_key, port, "alice", None)).await;
    for (options, command) in [
        (vec!["-tt"], Some("git-upload-pack 'demo.git'")),
        (vec!["-s"], Some("sftp")),
        (vec!["-W", "127.0.0.1:9"], None),
        (
            vec![
                "-N",
                "-R",
                "127.0.0.1:0:127.0.0.1:9",
                "-o",
                "ExitOnForwardFailure=yes",
            ],
            None,
        ),
        (
            vec![
                "-o",
                "PreferredAuthentications=password,keyboard-interactive,none",
            ],
            Some("git-upload-pack 'demo.git'"),
        ),
    ] {
        let base = ssh(&alice_key, port, "alice", command);
        let mut denied = Command::new("ssh");
        denied
            .args(options)
            .args(base.as_std().get_args())
            .kill_on_drop(true);
        rejected(&mut denied).await;
    }
    let id = cell.id.clone();
    app.execute(move |s| s.operate(&id, Operation::RevokeFrame { frame_id: bob_id }))
        .await
        .unwrap();
    rejected(&mut ssh(
        &bob_key,
        port,
        "bob",
        Some("git-upload-pack 'demo.git'"),
    ))
    .await;
    assert!(
        app.execute(move |s| Ok(s.cell_summary(&cell.id)?.refs.is_empty()))
            .await
            .unwrap()
    );
    stop.send(()).unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn held_receive_is_cancelled_and_reaped_on_shutdown_and_drop() {
    use tokio::io::AsyncReadExt;
    for abort in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let (key, _) = fixture_profile(root.path(), "alice").await;
        let mut store = Store::open(&root.path().join("alice"), b"test password").unwrap();
        let cell = store.create_cell("Demo".into()).unwrap();
        let app = App::new(store);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let host =
            russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)
                .unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(comb_frame::ssh::run(listener, app.clone(), host, async {
            let _ = stopped.await;
        }));
        let mut client = ssh(&key, port, "alice", Some("git-receive-pack 'demo.git'"))
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        let mut packet = [0; 4];
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            client.stdout.as_mut().unwrap().read_exact(&mut packet),
        )
        .await
        .unwrap()
        .unwrap();
        // A real receive-pack is now blocked waiting for client input while
        // holding the Store transaction. Cancellation must release that lock.
        if abort {
            server.abort();
        } else {
            stop.send(()).unwrap();
        }
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), client.wait())
            .await
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                app.execute(move |s| Ok(s.cell_summary(&cell.id)?.refs.is_empty()))
            )
            .await
            .unwrap()
            .unwrap()
        );
        assert!(
            tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .is_err()
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoking_serving_frame_closes_authenticated_idle_connection_and_listener() {
    let root = tempfile::tempdir().unwrap();
    let (key, _) = fixture_profile(root.path(), "alice").await;
    let store = Store::open(&root.path().join("alice"), b"test password").unwrap();
    let app = App::new(store);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let host = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)
        .unwrap();
    let server = tokio::spawn(comb_frame::ssh::run(
        listener,
        app.clone(),
        host,
        std::future::pending(),
    ));
    let control = root.path().join("master.sock");
    let client = ssh(&key, port, "alice", None);
    // Options after destination are a remote command, so insert master flags
    // using a fresh command with OpenSSH's -o option values before destination.
    let mut master = Command::new("ssh");
    let args: Vec<_> = client
        .as_std()
        .get_args()
        .map(|s| s.to_os_string())
        .collect();
    master
        .args(["-N", "-M", "-S"])
        .arg(&control)
        .args(args)
        .kill_on_drop(true)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    let mut master = master.spawn().unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while !control.exists() {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    app.execute(|s| s.lock("test revocation".into()))
        .await
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), master.wait())
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(std::time::Duration::from_secs(5), server)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .is_err()
    );
}

#[path = "../src/ssh/command.rs"]
mod command;

#[test]
fn restricted_git_commands() {
    for (input, write, path) in [
        ("git-upload-pack 'demo.git'", false, "demo"),
        ("git-receive-pack '/demo.git'", true, "demo"),
        ("git-upload-pack \"demo\"", false, "demo"),
        ("git-upload-pack demo", false, "demo"),
    ] {
        let parsed = command::parse(input.as_bytes()).unwrap();
        assert_eq!((parsed.write, parsed.repository.as_str()), (write, path));
    }
    for bad in [
        "sh",
        "git-upload-pack",
        "git-upload-pack 'a';id",
        "git-upload-pack '../a'",
        "git-upload-pack 'a/b'",
        "git-upload-pack '$HOME'",
        "git-upload-pack `id`",
        "git-upload-pack 'a\\b'",
        "git-upload-pack 'a' 'b'",
        "git-upload-pack --help",
        "git-upload-pack 'a\n'",
        "git-upload-pack ''",
        "git-upload-pack '//a'",
        "git-upload-pack 'a'\n",
    ] {
        assert!(command::parse(bad.as_bytes()).is_err(), "accepted {bad:?}");
    }
}
