use comb_frame::identity;

#[test]
fn an_enrolled_frame_can_authorize_another_without_identity_root_secrets() {
    let root = tempfile::tempdir().unwrap();
    let a = root.path().join("a");
    let b = root.path().join("b");
    let c = root.path().join("c");
    let first = identity::initialize(
        &a,
        "Alice",
        "a@test",
        b"fixture-password",
        &root.path().join("recovery"),
    )
    .unwrap();
    let request = identity::prepare_enrollment(&b, b"fixture-password").unwrap();
    let grant = identity::authorize(&a, b"fixture-password", &request).unwrap();
    identity::complete_enrollment(&b, b"fixture-password", &grant, &first.profile.identity)
        .unwrap();
    assert!(!b.join("root.vault").exists());
    let request = identity::prepare_enrollment(&c, b"fixture-password").unwrap();
    let grant = identity::authorize(&b, b"fixture-password", &request).unwrap();
    let third =
        identity::complete_enrollment(&c, b"fixture-password", &grant, &first.profile.identity)
            .unwrap();
    assert_eq!(third.profile.identity, first.profile.identity);
    assert_ne!(third.profile.frame_id(), first.profile.frame_id());
}
