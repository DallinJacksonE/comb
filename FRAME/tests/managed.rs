//! Managed FRAME stays locked until a private local unlock request.
use std::{
    path::Path,
    process::{Child, Command, Stdio},
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::UnixStream,
};

const PASSWORD: &[u8] = b"managed-test-only-password";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn startup_failures_are_not_reported_as_incorrect_passwords() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    comb_frame::identity::initialize(
        &data,
        "Alice",
        "alice@test",
        PASSWORD,
        &directory.path().join("recovery"),
    )
    .unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut process = start(&data, occupied.local_addr().unwrap().port(), port());
    wait_socket(&mut process, &data).await;
    let failed = exchange(
        &data,
        serde_json::json!({"action":"unlock","password":PASSWORD}),
    )
    .await;
    assert_eq!(failed["state"], "locked");
    assert!(
        failed["error"]
            .as_str()
            .unwrap()
            .contains("configured ports")
    );
    let cli = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap(), "profile"])
        .env("COMB_PASSWORD", String::from_utf8_lossy(PASSWORD).as_ref())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!cli.status.success());
    assert!(!String::from_utf8_lossy(&cli.stderr).contains("Incorrect password"));
    terminate(&mut process).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn termination_bounds_held_http_connections() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    comb_frame::identity::initialize(
        &data,
        "Alice",
        "alice@test",
        PASSWORD,
        &directory.path().join("recovery"),
    )
    .unwrap();
    let management = port();
    let peer = port();
    let mut process = start(&data, management, peer);
    wait_socket(&mut process, &data).await;
    assert_eq!(
        exchange(
            &data,
            serde_json::json!({"action":"unlock","password":PASSWORD})
        )
        .await["state"],
        "ready"
    );
    let mut held = std::net::TcpStream::connect(("127.0.0.1", management)).unwrap();
    held.write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n")
        .unwrap();
    let mut held_peer = std::net::TcpStream::connect(("127.0.0.1", peer)).unwrap();
    held_peer
        .write_all(b"GET /handshake HTTP/1.1\r\nHost: localhost\r\n")
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    terminate(&mut process).await;
    assert!(std::net::TcpStream::connect(("127.0.0.1", peer)).is_err());
    assert!(!data.join("service.sock").exists());
    drop(held);
    drop(held_peer);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn legacy_large_profiles_do_not_break_session_credentials_or_profile_export() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    let name = "a".repeat(40_000);
    comb_frame::identity::initialize(
        &data,
        &name,
        "alice@test",
        PASSWORD,
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut process = start(&data, port(), port());
    wait_socket(&mut process, &data).await;
    let token = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap(), "token"])
        .env("COMB_PASSWORD", String::from_utf8_lossy(PASSWORD).as_ref())
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        token.status.success(),
        "{}",
        String::from_utf8_lossy(&token.stderr)
    );
    let profile = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap(), "profile"])
        .env_remove("COMB_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        profile.status.success(),
        "{}",
        String::from_utf8_lossy(&profile.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&profile.stdout).unwrap()["name"],
        name
    );
    terminate(&mut process).await;
}
struct Process(Child);
impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
fn port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}
fn start(data: &Path, management: u16, peer: u16) -> Process {
    Process(
        Command::new(env!("CARGO_BIN_EXE_comb"))
            .args([
                "--data",
                data.to_str().unwrap(),
                "serve",
                "--managed",
                "--ssh-listen",
                "127.0.0.1:0",
                "--listen",
                &format!("127.0.0.1:{management}"),
                "--peer-listen",
                &format!("127.0.0.1:{peer}"),
                "--assets",
                "missing-fixture-assets",
            ])
            .env_remove("COMB_PASSWORD")
            .env_remove("COMB_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    )
}
async fn exchange(data: &Path, request: serde_json::Value) -> serde_json::Value {
    let mut socket = UnixStream::connect(data.join("service.sock"))
        .await
        .unwrap();
    let mut bytes = serde_json::to_vec(&request).unwrap();
    bytes.push(b'\n');
    socket.write_all(&bytes).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(
        Duration::from_secs(60),
        BufReader::new(socket).read_line(&mut response),
    )
    .await
    .unwrap()
    .unwrap();
    serde_json::from_str(&response).unwrap()
}
async fn wait_socket(process: &mut Process, data: &Path) {
    for _ in 0..100 {
        assert!(
            process.0.try_wait().unwrap().is_none(),
            "managed service exited before creating its control socket"
        );
        if data.join("service.sock").exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("managed service did not bind its private control socket");
}
async fn terminate(process: &mut Process) {
    assert!(
        Command::new("kill")
            .args(["-TERM", &process.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    for _ in 0..200 {
        if let Some(status) = process.0.try_wait().unwrap() {
            assert!(status.success(), "SIGTERM should shut down cleanly");
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("service did not stop on SIGTERM");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn managed_service_starts_without_identity_unlocks_and_restarts_locked() {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    let management = port();
    let peer = port();
    let mut process = start(&data, management, peer);
    wait_socket(&mut process, &data).await;
    assert_eq!(
        exchange(&data, serde_json::json!({"action":"status"})).await["state"],
        "uninitialized"
    );
    let probe = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap(), "service-status"])
        .env_remove("COMB_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        probe.status.success(),
        "the installer probe must not prompt or initialize: {}",
        String::from_utf8_lossy(&probe.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&probe.stdout).unwrap()["state"],
        "uninitialized"
    );
    assert!(!data.join("node.vault").exists());
    assert_eq!(
        std::fs::metadata(data.join("service.sock"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(std::net::TcpStream::connect(("127.0.0.1", management)).is_err());
    let local = comb_frame::identity::initialize(
        &data,
        "Alice",
        "alice@test",
        PASSWORD,
        &directory.path().join("offline.recovery"),
    )
    .unwrap();
    let token = local.token.clone();
    drop(local);
    assert_eq!(
        exchange(&data, serde_json::json!({"action":"status"})).await["state"],
        "locked"
    );
    let locked_session = exchange(&data, serde_json::json!({"action":"session"})).await;
    assert!(locked_session.get("token").is_none());
    assert!(locked_session["error"].is_string());
    let failed = exchange(
        &data,
        serde_json::json!({"action":"unlock","password":b"wrong"}),
    )
    .await;
    assert_eq!(failed["error"], "Incorrect password");
    assert!(std::net::TcpStream::connect(("127.0.0.1", management)).is_err());
    assert_eq!(
        exchange(
            &data,
            serde_json::json!({"action":"unlock","password":PASSWORD})
        )
        .await["state"],
        "ready"
    );
    let response = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{management}/api/status"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap();
    assert!(response.status().is_success());
    terminate(&mut process).await;
    assert!(!data.join("service.sock").exists());
    assert!(std::net::TcpStream::connect(("127.0.0.1", management)).is_err());
    let mut process = start(&data, management, peer);
    wait_socket(&mut process, &data).await;
    assert_eq!(
        exchange(&data, serde_json::json!({"action":"status"})).await["state"],
        "locked"
    );
    assert!(std::net::TcpStream::connect(("127.0.0.1", peer)).is_err());
    terminate(&mut process).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn first_management_command_guides_setup_then_unlocks_again_after_restart() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    let management = port();
    let peer = port();
    let mut process = start(&data, management, peer);
    wait_socket(&mut process, &data).await;
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_comb"));
        command
            .args([
                "--data",
                data.to_str().unwrap(),
                "--api-url",
                &format!("http://127.0.0.1:{management}"),
                "cell",
                "list",
            ])
            .env_remove("COMB_TOKEN")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    };
    let declined = command().env_remove("COMB_PASSWORD").output().unwrap();
    assert!(!declined.status.success());
    assert!(String::from_utf8_lossy(&declined.stderr).contains("interactive terminal"));
    assert!(!data.join("node.vault").exists());
    let mut first = command()
        .env("COMB_PASSWORD", String::from_utf8_lossy(PASSWORD).as_ref())
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    first
        .stdin
        .take()
        .unwrap()
        .write_all(b"Alice\nalice@test\n")
        .unwrap();
    let first = first.wait_with_output().unwrap();
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&first.stdout).unwrap(),
        serde_json::json!([])
    );
    let explanation = String::from_utf8_lossy(&first.stderr);
    assert!(
        explanation.contains("recovery")
            && explanation.contains("offline")
            && explanation.contains("password")
    );
    assert!(!explanation.contains(String::from_utf8_lossy(PASSWORD).as_ref()));
    assert!(data.join("identity.recovery").is_file());
    let subsequent = command().env_remove("COMB_PASSWORD").output().unwrap();
    assert!(
        subsequent.status.success(),
        "an unlocked local user session must not prompt for the vault password again: {}",
        String::from_utf8_lossy(&subsequent.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&subsequent.stdout).unwrap(),
        serde_json::json!([])
    );
    assert_eq!(
        exchange(&data, serde_json::json!({"action":"status"})).await["state"],
        "ready"
    );
    terminate(&mut process).await;
    let mut process = start(&data, management, peer);
    wait_socket(&mut process, &data).await;
    let wrong = command()
        .env("COMB_PASSWORD", "wrong-test-only-password")
        .output()
        .unwrap();
    assert!(!wrong.status.success());
    assert!(String::from_utf8_lossy(&wrong.stderr).contains("Incorrect password"));
    let help = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap()])
        .env_remove("COMB_PASSWORD")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(String::from_utf8_lossy(&help.stdout).contains("Usage: comb"));
    assert!(help.stderr.is_empty());
    assert_eq!(
        exchange(&data, serde_json::json!({"action":"status"})).await["state"],
        "locked"
    );
    let unlocked = command()
        .env("COMB_PASSWORD", String::from_utf8_lossy(PASSWORD).as_ref())
        .output()
        .unwrap();
    assert!(
        unlocked.status.success(),
        "{}",
        String::from_utf8_lossy(&unlocked.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&unlocked.stdout).unwrap(),
        serde_json::json!([])
    );
    assert!(String::from_utf8_lossy(&unlocked.stderr).contains("restart"));
    terminate(&mut process).await;
}
