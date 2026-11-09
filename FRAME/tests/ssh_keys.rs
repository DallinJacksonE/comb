use comb_frame::{identity, ssh_keys};
use std::{fs, os::unix::fs::PermissionsExt, process::Command};

#[test]
fn username_preflight_is_bounded_ascii() {
    for valid in [
        "fixture",
        "a",
        "a_b-012",
        "abcdefghijklmnopqrstuvwxyzabcdef",
    ] {
        ssh_keys::validate_username(valid).unwrap();
    }
    for invalid in [
        "",
        "UPPER",
        "1name",
        "a name",
        "a\nname",
        "aé",
        "abcdefghijklmnopqrstuvwxyzabcdefg",
    ] {
        assert!(ssh_keys::validate_username(invalid).is_err());
    }
}

#[test]
fn alias_preserves_global_scope_and_escapes_paths() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("data with spaces%fixture");
    fs::create_dir_all(data.join("ssh")).unwrap();
    let key = russh::keys::PrivateKey::random(&mut rand10::rng(), russh::keys::Algorithm::Ed25519)
        .unwrap();
    let settings = ssh_keys::Settings {
        username: "fixture".into(),
        public_key: key.public_key().to_openssh().unwrap(),
        client_key: data.join("ssh/id_ed25519"),
        host_public_key: key.public_key().to_openssh().unwrap(),
        listen: "127.0.0.1:7333".parse().unwrap(),
        alias: "comb-0123456789abcdef".into(),
    };
    fs::write(
        data.join("ssh/settings.json"),
        serde_json::to_vec(&settings).unwrap(),
    )
    .unwrap();
    let config = tmp.path().join("config");
    let original = b"ServerAliveInterval 47\nHost *\n  User ordinary\n";
    fs::write(&config, original).unwrap();
    ssh_keys::configure_client(&data, &config).unwrap();
    let output = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&config)
        .arg("unrelated.example.test")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("serveraliveinterval 47\n")
    );
    let output = Command::new("ssh")
        .args(["-G", "-F"])
        .arg(&config)
        .arg(&settings.alias)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let rendered = String::from_utf8(output.stdout).unwrap();
    assert!(rendered.contains("user fixture\n"));
    assert!(rendered.contains("identitiesonly yes\n"));
    assert!(rendered.contains("port 7333\n"));
    assert!(fs::read(&config).unwrap().ends_with(original));
}

#[test]
fn setup_roundtrips_standard_keys_and_encrypted_host_vault() {
    for passphrase in [None, Some("fixture-key-passphrase")] {
        let tmp = tempfile::tempdir().unwrap();
        let data = tmp.path().join("data");
        let initial = identity::initialize(
            &data,
            "Fixture",
            "f@example.test",
            b"fixture password",
            &tmp.path().join("recovery"),
        )
        .unwrap();
        assert!(ssh_keys::settings(&data).unwrap().is_none());
        let config = tmp.path().join("ssh/config");
        fs::create_dir_all(config.parent().unwrap()).unwrap();
        let original = b"# untouched\nHost *\n  ServerAliveInterval 30\n";
        let collision = format!(
            "Host comb-{}\n  HostName example.test\n",
            &initial.profile.frame_id()[..16]
        );
        fs::write(&config, &collision).unwrap();
        assert!(
            ssh_keys::setup(
                &data,
                b"fixture password",
                "fixture",
                b"",
                Some(&config),
                "127.0.0.1:7333".parse().unwrap()
            )
            .is_err()
        );
        assert_eq!(fs::read(&config).unwrap(), collision.as_bytes());
        assert_eq!(fs::read_dir(data.join("ssh")).unwrap().count(), 0);
        assert!(
            identity::load(&data, b"fixture password")
                .unwrap()
                .profile
                .username
                .is_none()
        );
        fs::write(&config, original).unwrap();
        let settings = ssh_keys::setup(
            &data,
            b"fixture password",
            "fixture",
            passphrase.unwrap_or("").as_bytes(),
            Some(&config),
            "127.0.0.1:7333".parse().unwrap(),
        )
        .unwrap();
        assert_eq!(
            fs::metadata(&settings.client_key)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        let decoded =
            russh::keys::PrivateKey::from_openssh(fs::read(&settings.client_key).unwrap()).unwrap();
        assert_eq!(decoded.is_encrypted(), passphrase.is_some());
        if let Some(passphrase) = passphrase {
            assert!(decoded.decrypt("wrong fixture passphrase").is_err());
            assert_eq!(
                decoded
                    .decrypt(passphrase)
                    .unwrap()
                    .public_key()
                    .to_openssh()
                    .unwrap(),
                settings.public_key
            );
        }
        assert!(
            !String::from_utf8_lossy(&fs::read(data.join("ssh/host.vault")).unwrap())
                .contains("OPENSSH PRIVATE KEY")
        );
        assert_eq!(
            fs::metadata(data.join("ssh")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let output = Command::new("ssh-keygen")
            .args(["-y", "-P", passphrase.unwrap_or(""), "-f"])
            .arg(&settings.client_key)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap().trim(),
            settings.public_key
        );
        let host = ssh_keys::load_server(&data, b"fixture password")
            .unwrap()
            .unwrap();
        assert_eq!(
            host.host_key.public_key().to_openssh().unwrap(),
            settings.host_public_key
        );
        assert_ne!(settings.public_key, settings.host_public_key);
        assert!(ssh_keys::load_server(&data, b"wrong fixture password").is_err());
        let before = fs::read(&config).unwrap();
        assert!(before.ends_with(original));
        ssh_keys::configure_client(&data, &config).unwrap();
        assert_eq!(fs::read(&config).unwrap(), before);
        assert!(
            ssh_keys::setup(
                &data,
                b"fixture password",
                "fixture",
                b"",
                None,
                settings.listen
            )
            .is_err()
        );
        ssh_keys::set_listen(&data, "127.0.0.1:7444".parse().unwrap()).unwrap();
        assert_eq!(
            ssh_keys::settings(&data).unwrap().unwrap().listen.port(),
            7444
        );
        let foreign = tmp.path().join("foreign");
        fs::write(
            &foreign,
            format!("Host {}\n  HostName example.test\n", settings.alias),
        )
        .unwrap();
        assert!(ssh_keys::configure_client(&data, &foreign).is_err());
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&config, &link).unwrap();
        assert!(ssh_keys::configure_client(&data, &link).is_err());
        assert_eq!(fs::read(&config).unwrap(), before);
    }
}
