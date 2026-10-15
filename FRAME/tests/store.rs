use comb_frame::{identity, store::Store};

#[test]
fn cells_persist_encrypted_and_reload_with_the_same_version() {
    let dir = tempfile::tempdir().unwrap();
    let recovery = dir.path().join("offline.recovery");
    let data = dir.path().join("node");
    identity::initialize(
        &data,
        "Alice",
        "alice@test",
        b"correct horse battery",
        &recovery,
    )
    .unwrap();
    let mut store = Store::open(&data, b"correct horse battery").unwrap();
    assert!(
        Store::open(&data, b"correct horse battery").is_err(),
        "only one daemon may mutate a FRAME data directory"
    );
    let cell = store.create_cell("TOP SECRET PROJECT".into()).unwrap();
    let version = cell.version.clone();
    assert_eq!(store.list_cells().unwrap().len(), 1);
    drop(store);
    for entry in std::fs::read_dir(data.join("snapshots")).unwrap() {
        let bytes = std::fs::read(entry.unwrap().path()).unwrap();
        assert!(
            !bytes
                .windows(b"TOP SECRET PROJECT".len())
                .any(|b| b == b"TOP SECRET PROJECT")
        );
    }
    let reopened = Store::open(&data, b"correct horse battery").unwrap();
    assert_eq!(reopened.list_cells().unwrap()[0].version, version);
    assert!(Store::open(&data, b"wrong password").is_err());
}

#[test]
fn offline_recovery_restores_code_without_a_surviving_plaintext_peer() {
    let dir = tempfile::tempdir().unwrap();
    let original = dir.path().join("original");
    let recovery = dir.path().join("offline.recovery");
    let first = identity::initialize(
        &original,
        "Alice",
        "alice@test",
        b"recovery-password",
        &recovery,
    )
    .unwrap();
    let owner = first.profile.identity.clone();
    let original_frame = first.profile.frame_id();
    drop(first);
    let mut store = Store::open(&original, b"recovery-password").unwrap();
    let cell = store.create_cell("Restorable code".into()).unwrap();
    let backup = store.export_snapshot(&cell.id).unwrap();
    drop(store);
    std::fs::remove_dir_all(&original).unwrap();
    let restored = dir.path().join("restored");
    identity::recover(&restored, b"new-password", &recovery, b"recovery-password").unwrap();
    let root = identity::load_root(&restored, b"new-password").unwrap();
    let mut store = Store::open(&restored, b"new-password").unwrap();
    assert_ne!(store.profile().frame_id(), original_frame);
    store.import_snapshot(&backup, &owner, Some(&root)).unwrap();
    drop(store);
    assert_eq!(
        Store::open(&restored, b"new-password")
            .unwrap()
            .list_cells()
            .unwrap()[0]
            .name,
        "Restorable code"
    );
}
