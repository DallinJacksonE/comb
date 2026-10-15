use comb_cell::domain::Role;
use comb_frame::{identity, store::Store};

#[test]
fn recovered_read_only_membership_reopens_without_a_live_writer() {
    let directory = tempfile::tempdir().unwrap();
    let owner_data = directory.path().join("owner");
    let reader_data = directory.path().join("reader");
    let reader_recovery = directory.path().join("reader.recovery");
    identity::initialize(
        &owner_data,
        "Owner",
        "o@test",
        b"fixture-password",
        &directory.path().join("owner.recovery"),
    )
    .unwrap();
    let reader = identity::initialize(
        &reader_data,
        "Reader",
        "r@test",
        b"fixture-password",
        &reader_recovery,
    )
    .unwrap();
    let mut owner = Store::open(&owner_data, b"fixture-password").unwrap();
    let cell = owner.create_cell("Read-only recovery".into()).unwrap();
    owner.grant(&cell.id, &reader.profile, Role::Read).unwrap();
    let snapshot = owner.export_snapshot(&cell.id).unwrap();
    let pin = owner.profile().identity.clone();
    drop(reader);
    drop(owner);
    std::fs::remove_dir_all(&owner_data).unwrap();
    std::fs::remove_dir_all(&reader_data).unwrap();
    let fresh = directory.path().join("restored");
    identity::recover(
        &fresh,
        b"fixture-password",
        &reader_recovery,
        b"fixture-password",
    )
    .unwrap();
    let root = identity::load_root(&fresh, b"fixture-password").unwrap();
    let mut restored = Store::open(&fresh, b"fixture-password").unwrap();
    restored
        .import_snapshot(&snapshot, &pin, Some(&root))
        .unwrap();
    drop(restored);
    let reopened = Store::open(&fresh, b"fixture-password").unwrap();
    assert_eq!(reopened.list_cells().unwrap()[0].name, "Read-only recovery");
    assert!(
        !reopened
            .cell(&cell.id)
            .unwrap()
            .is_frame_authorized(&reopened.profile().certificate, true)
    );
}
