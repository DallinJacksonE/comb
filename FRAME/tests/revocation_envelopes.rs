use comb_cell::domain::{Operation, Role};
use comb_frame::{identity, store::Store};

#[test]
fn revoked_identity_cannot_open_new_versions_with_its_offline_recovery_secret() {
    let dir = tempfile::tempdir().unwrap();
    let alice = dir.path().join("alice");
    let bob = dir.path().join("bob");
    identity::initialize(
        &alice,
        "Alice",
        "a@test",
        b"password-fixture",
        &dir.path().join("a.recovery"),
    )
    .unwrap();
    let bob_local = identity::initialize(
        &bob,
        "Bob",
        "b@test",
        b"password-fixture",
        &dir.path().join("b.recovery"),
    )
    .unwrap();
    let bob_root = identity::load_root(&bob, b"password-fixture").unwrap();
    let mut store = Store::open(&alice, b"password-fixture").unwrap();
    let cell = store.create_cell("Revocation".into()).unwrap();
    store
        .grant(&cell.id, &bob_local.profile, Role::Write)
        .unwrap();
    let old = store.export_snapshot(&cell.id).unwrap();
    let owner = store.profile().identity.clone();
    assert!(old.open(&owner, &bob_root.recovery_secret()).is_ok());
    store
        .operate(
            &cell.id,
            Operation::Revoke {
                identity_id: bob_local.profile.id(),
            },
        )
        .unwrap();
    let new = store.export_snapshot(&cell.id).unwrap();
    assert!(
        new.open(&owner, &bob_local.frame.recipient_secret())
            .is_err()
    );
    assert!(
        new.open(&owner, &bob_root.recovery_secret()).is_err(),
        "revocation must exclude historical identity entries from recovery recipients"
    );
}
