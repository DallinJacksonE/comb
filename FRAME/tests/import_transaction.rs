use comb_cell::domain::{Cell, Issue, Operation};
use comb_frame::{
    identity,
    snapshot::{Snapshot, SnapshotContext},
    store::Store,
};

#[test]
fn rejected_git_payload_does_not_mutate_accepted_cell_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    identity::initialize(
        &data,
        "Alice",
        "a@test",
        b"fixture-password",
        &dir.path().join("recovery"),
    )
    .unwrap();
    let mut store = Store::open(&data, b"fixture-password").unwrap();
    let original = store.create_cell("Transactional".into()).unwrap();
    let snapshot = store.export_snapshot(&original.id).unwrap();
    let plaintext = snapshot
        .open(
            &store.profile().identity,
            &store.local.frame.recipient_secret(),
        )
        .unwrap();
    let mut payload: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    let mut cell: Cell = serde_json::from_value(payload["cell"].clone()).unwrap();
    cell.apply(
        Operation::AddIssue {
            issue: Issue {
                id: "bad-snapshot".into(),
                title: "Must not be accepted".into(),
                body: String::new(),
                closed: false,
            },
        },
        &store.local.frame,
        &store.profile().certificate,
    )
    .unwrap();
    payload["cell"] = serde_json::to_value(&cell).unwrap();
    payload["git"] = serde_json::json!([1, 2, 3]);
    let owner = store.profile().identity.clone();
    let hostile = Snapshot::seal(
        SnapshotContext {
            cell_id: original.id.clone(),
            version: cell.version_id(),
            owner: owner.clone(),
        },
        &serde_json::to_vec(&payload).unwrap(),
        &[store.local.frame.public().encryption_key],
        &store.local.frame,
        &store.profile().certificate,
    )
    .unwrap();
    assert!(store.import_snapshot(&hostile, &owner, None).is_err());
    assert_eq!(
        store.cell_summary(&original.id).unwrap().version,
        original.version,
        "invalid archive must not advance accepted metadata"
    );
    assert!(store.issues(&original.id).unwrap().is_empty());
}
