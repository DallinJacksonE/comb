use comb_frame::identity;
use russh::keys::{Algorithm, PrivateKey};

#[test]
fn enrolled_profile_extension_is_signed_without_root_and_legacy_is_unchanged() {
    let tmp = tempfile::tempdir().unwrap();
    let first = tmp.path().join("first");
    let second = tmp.path().join("second");
    let original = identity::initialize(
        &first,
        "Fixture",
        "fixture@example.test",
        b"fixture password",
        &tmp.path().join("recovery"),
    )
    .unwrap();
    let legacy = serde_json::to_vec(&original.profile).unwrap();
    assert!(!String::from_utf8_lossy(&legacy).contains("username"));
    let request = identity::prepare_enrollment(&second, b"fixture password").unwrap();
    let grant = identity::authorize_from_frame(&original, &request).unwrap();
    identity::complete_enrollment(
        &second,
        b"fixture password",
        &grant,
        &original.profile.identity,
    )
    .unwrap();
    let key = PrivateKey::random(&mut rand10::rng(), Algorithm::Ed25519).unwrap();
    let public = key.public_key().to_openssh().unwrap();
    let updated =
        identity::configure_ssh_profile(&second, b"fixture password", "fixture-user", &public)
            .unwrap();
    identity::validate_profile(&updated, &original.profile.identity).unwrap();
    assert_eq!(updated.username.as_deref(), Some("fixture-user"));
    assert_eq!(updated.signature.bytes, grant.signature.bytes);
    assert_eq!(
        identity::load(&second, b"fixture password")
            .unwrap()
            .profile
            .ssh_public_key
            .as_deref(),
        Some(public.as_str())
    );
    let mut tampered = updated.clone();
    tampered.username = Some("attacker".into());
    assert!(identity::validate_profile(&tampered, &original.profile.identity).is_err());
    for username in [
        "",
        "Upper",
        "1bad",
        "bad name",
        "bad\nname",
        "abcdefghijklmnopqrstuvwxyzabcdefg",
    ] {
        assert!(
            identity::configure_ssh_profile(&second, b"fixture password", username, &public)
                .is_err()
        );
    }
    assert!(
        identity::configure_ssh_profile(
            &second,
            b"fixture password",
            "valid",
            &(public + " comment")
        )
        .is_err()
    );
    assert_eq!(
        serde_json::to_vec(&identity::load(&first, b"fixture password").unwrap().profile).unwrap(),
        legacy
    );
}
