//! CLI SSH setup never silently replaces an existing identity or edits user SSH files.
use std::process::{Command, Stdio};

#[test]
fn initialization_collects_username_and_creates_a_protected_frame_ssh_key() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    let config = directory.path().join("ssh-config");
    let result = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args([
            "--data",
            data.to_str().unwrap(),
            "user",
            "--name",
            "Alice",
            "--email",
            "alice@test",
            "--username",
            "alice",
        ])
        .env("COMB_PASSWORD", "fixture-password")
        .env("COMB_SSH_CONFIG", &config)
        .env("COMB_SSH_KEY_PASSPHRASE", "fixture-ssh-passphrase")
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let profile: comb_frame::identity::Profile = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(profile.username.as_deref(), Some("alice"));
    comb_frame::identity::validate_profile(&profile, &profile.identity).unwrap();
    let settings = comb_frame::ssh_keys::settings(&data).unwrap().unwrap();
    let key = russh::keys::PrivateKey::from_openssh(std::fs::read(&settings.client_key).unwrap())
        .unwrap();
    assert!(key.is_encrypted());
    assert!(config.is_file());
    assert!(
        std::fs::read_to_string(&config)
            .unwrap()
            .contains(&settings.alias)
    );
}

#[test]
fn existing_frame_ssh_setup_preserves_identity_and_cells() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    comb_frame::identity::initialize(
        &data,
        "Legacy",
        "legacy@test",
        b"fixture-password",
        &directory.path().join("recovery"),
    )
    .unwrap();
    let mut store = comb_frame::store::Store::open(&data, b"fixture-password").unwrap();
    let before = store.profile().frame_id();
    let cell = store.create_cell("Preserved Repo".into()).unwrap();
    drop(store);
    let config = directory.path().join("ssh-config");
    std::fs::write(&config, "Host example\n  HostName example.com\n").unwrap();
    let result = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args([
            "--data",
            data.to_str().unwrap(),
            "ssh",
            "setup",
            "--username",
            "legacy",
        ])
        .env("COMB_PASSWORD", "fixture-password")
        .env("COMB_SSH_CONFIG", &config)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let store = comb_frame::store::Store::open(&data, b"fixture-password").unwrap();
    assert_eq!(store.profile().frame_id(), before);
    assert_eq!(store.cell_summary(&cell.id).unwrap().version, cell.version);
    assert_eq!(store.profile().username.as_deref(), Some("legacy"));
    assert!(
        std::fs::read_to_string(&config)
            .unwrap()
            .contains("Host example\n  HostName example.com\n")
    );
}

#[test]
fn ssh_setup_requires_an_existing_frame() {
    let directory = tempfile::tempdir().unwrap();
    let data = directory.path().join("frame");
    let config = directory.path().join("ssh-config");
    let result = Command::new(env!("CARGO_BIN_EXE_comb"))
        .args([
            "--data",
            data.to_str().unwrap(),
            "ssh",
            "setup",
            "--username",
            "alice",
        ])
        .env("COMB_PASSWORD", "fixture-password")
        .env("COMB_SSH_CONFIG", &config)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("initialize a FRAME before configuring SSH"),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(!data.join("node.vault").exists());
    assert!(!config.exists());
}
