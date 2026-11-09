#[test]
fn bare_command_shows_short_help_after_setup_without_unlocking() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    comb_frame::identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"fixture-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let run = |arguments: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
            .args(["--data", data.to_str().unwrap()])
            .args(arguments)
            .env_remove("COMB_PASSWORD")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let expected = run(&["-h"]);
    let actual = run(&[]);
    assert!(
        actual.status.success(),
        "{}",
        String::from_utf8_lossy(&actual.stderr)
    );
    assert_eq!(actual.stdout, expected.stdout);
    assert!(actual.stderr.is_empty());
}

#[test]
fn first_ordinary_command_initializes_once_without_a_managed_service() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    let mut first = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap(), "webgui"])
        .env("COMB_PASSWORD", "fixture-password")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    first
        .stdin
        .take()
        .unwrap()
        .write_all(b"Alice\nalice@test\n")
        .unwrap();
    let output = first.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(data.join("node.vault").is_file());
    assert!(data.join("identity.recovery").is_file());
    let subsequent = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap(), "webgui"])
        .env_remove("COMB_PASSWORD")
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(subsequent.status.success());
    assert!(subsequent.stderr.is_empty());
}

#[test]
fn bare_first_run_initializes_then_shows_help() {
    use std::io::Write;
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    for flag in ["-h", "--help", "--version"] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
            .args(["--data", data.to_str().unwrap(), flag])
            .env_remove("COMB_PASSWORD")
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(!data.exists());
    }
    let mut first = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["--data", data.to_str().unwrap()])
        .env("COMB_PASSWORD", "fixture-password")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    first
        .stdin
        .take()
        .unwrap()
        .write_all(b"Alice\nalice@test\n")
        .unwrap();
    let output = first.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(data.join("node.vault").is_file());
    assert!(String::from_utf8_lossy(&output.stdout).contains("Usage: comb"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("Welcome to COMB"));
}

#[test]
fn oversized_metadata_and_new_enrollment_recovery_passwords_fail_before_writes() {
    let directory = tempfile::tempdir().unwrap();
    for (index, arguments) in [
        vec![
            "user".to_owned(),
            "--name".into(),
            "a".repeat(40_000),
            "--email".into(),
            "alice@test".into(),
        ],
        vec![
            "enroll".into(),
            "request".into(),
            "--out".into(),
            directory
                .path()
                .join("request.json")
                .to_str()
                .unwrap()
                .into(),
        ],
        vec![
            "enroll".into(),
            "complete".into(),
            "--grant".into(),
            directory
                .path()
                .join("missing-grant.json")
                .to_str()
                .unwrap()
                .into(),
            "--identity-key".into(),
            "00".repeat(32),
        ],
        vec![
            "recover".into(),
            "--recovery".into(),
            directory
                .path()
                .join("missing.recovery")
                .to_str()
                .unwrap()
                .into(),
        ],
    ]
    .into_iter()
    .enumerate()
    {
        let data = directory.path().join(format!("frame-{index}"));
        let secret = if index == 0 {
            "fixture-password".into()
        } else {
            "x".repeat(4097)
        };
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
            .args(["--data", data.to_str().unwrap()])
            .args(arguments)
            .env("COMB_PASSWORD", secret)
            .env("COMB_RECOVERY_PASSWORD", "fixture-recovery-password")
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(!data.join("node.vault").exists());
        assert!(!data.join("pending.vault").exists());
        let error = String::from_utf8_lossy(&output.stderr);
        assert!(
            if index == 0 {
                error.contains("Name")
            } else {
                error.contains("4096")
            },
            "{error}"
        );
    }
}

#[test]
fn configured_data_directory_is_used_without_explicit_data_flag() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("custom-frame");
    let xdg = directory.path().join("xdg");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .args(["user", "--name", "Alice", "--email", "alice@test"])
        .env("COMB_DATA_DIR", &data)
        .env("XDG_DATA_HOME", &xdg)
        .env("COMB_PASSWORD", "fixture-only-password")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        data.join("node.vault").is_file(),
        "the installed CLI and service must use the same configured data directory"
    );
    assert!(!xdg.join("comb/node.vault").exists());
}

#[test]
fn cli_exposes_management_commands_not_git_wrappers() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).unwrap();
    assert!(help.contains("serve"));
    assert!(help.contains("enroll"));
    assert!(help.contains("restore"));
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .arg("push")
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "comb must not expose Git wrappers"
    );
}

#[test]
fn setup_rejects_passwords_the_managed_protocol_cannot_unlock() {
    let directory = tempfile::tempdir().unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_comb"))
        .args([
            "--data",
            directory.path().join("frame").to_str().unwrap(),
            "user",
            "--name",
            "Alice",
            "--email",
            "alice@test",
        ])
        .env("COMB_PASSWORD", "x".repeat(4097))
        .output()
        .unwrap();
    assert!(
        !output.status.success(),
        "setup must enforce the service unlock bound before creating identity files"
    );
    assert!(!directory.path().join("frame/node.vault").exists());
    assert!(!directory.path().join("frame/identity.recovery").exists());
}
