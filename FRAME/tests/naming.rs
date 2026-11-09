use comb_cell::domain::{Cell, Operation, Role};
use comb_frame::snapshot::{Snapshot, SnapshotContext};
use comb_frame::{archive::pack_directory, git::GitRepository};
use comb_frame::{identity, store::Store};

fn signed_snapshot(signer: &Store, cell: &Cell, recipient: &Store) -> Snapshot {
    let dir = tempfile::tempdir().unwrap();
    let repo = GitRepository::create(dir.path(), &cell.id).unwrap();
    let payload = serde_json::to_vec(&serde_json::json!({
        "cell": cell,
        "git": pack_directory(repo.path()).unwrap(),
    }))
    .unwrap();
    Snapshot::seal(
        SnapshotContext {
            cell_id: cell.id.clone(),
            version: cell.version_id(),
            owner: cell.owner.clone(),
        },
        &payload,
        &[recipient.local.frame.public().encryption_key],
        &signer.local.frame,
        &signer.profile().certificate,
    )
    .unwrap()
}

fn setup(root: &std::path::Path) -> Store {
    identity::initialize(
        root,
        "Owner",
        "owner@test",
        b"password",
        &root.with_extension("recovery"),
    )
    .unwrap();
    Store::open(root, b"password").unwrap()
}

#[test]
fn slug_validation_collision_and_id_remotes() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("node"));
    let repo = store.create_cell("My Repo".into()).unwrap();
    assert_eq!(serde_json::to_value(&repo).unwrap()["slug"], "my-repo");
    assert!(store.create_cell("MY---repo".into()).is_err());
    assert!(store.create_cell("!!!".into()).is_err());
    assert!(store.create_cell("a".repeat(64)).is_err());
    assert_eq!(store.resolve_git_cell("my-repo").unwrap(), repo.id);
    assert_eq!(store.resolve_git_cell(&repo.id).unwrap(), repo.id);
    assert!(
        store
            .git_http(
                "my-repo",
                "GET",
                "info/refs",
                "service=git-upload-pack",
                "",
                &[]
            )
            .is_ok()
    );
}

#[test]
fn rename_preserves_identity_rejects_collision_and_reopens() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let mut store = setup(&data);
    let original = store.create_cell("Original".into()).unwrap();
    store.create_cell("Other".into()).unwrap();
    assert!(store.rename_cell(&original.id, "Other".into()).is_err());
    for invalid in ["!!!".to_owned(), "b".repeat(64), "bad\nname".to_owned()] {
        assert!(store.rename_cell(&original.id, invalid).is_err());
    }
    assert!(
        store
            .operate(
                &original.id,
                Operation::Rename {
                    name: "Other".into()
                }
            )
            .is_err()
    );
    let renamed = store.rename_cell(&original.id, "My Repo".into()).unwrap();
    assert_eq!(renamed.name, "My Repo");
    assert_eq!(renamed.slug, "my-repo");
    assert_eq!(store.cell(&original.id).unwrap().name, "Original");
    assert_ne!(renamed.version, original.version);
    assert!(store.resolve_git_cell("original").is_err());
    drop(store);
    let mut reopened = Store::open(&data, b"password").unwrap();
    assert_eq!(reopened.cell_summary(&original.id).unwrap().name, "My Repo");
    assert_eq!(reopened.resolve_git_cell("my-repo").unwrap(), original.id);
    reopened.lock("revocation".into()).unwrap();
    assert!(reopened.rename_cell(&original.id, "Denied".into()).is_err());
}

#[test]
fn deletion_requires_current_name_is_local_and_blocks_reimport_after_restart() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let mut store = setup(&data);
    let cell = store.create_cell("Original".into()).unwrap();
    store.rename_cell(&cell.id, "Current Name".into()).unwrap();
    let backup = store.export_snapshot(&cell.id).unwrap();
    let owner = store.profile().identity.clone();
    let backup_path = dir.path().join("independent.cell");
    let backup_bytes = serde_json::to_vec(&backup).unwrap();
    std::fs::write(&backup_path, &backup_bytes).unwrap();
    let worktree = dir.path().join("independent-worktree");
    std::fs::create_dir(&worktree).unwrap();
    std::fs::write(worktree.join("file"), "keep").unwrap();
    assert!(store.delete_cell(&cell.id, "Original").is_err());
    assert!(store.delete_cell(&cell.id, " Current Name").is_err());
    assert!(store.cell(&cell.id).is_ok());
    store.delete_cell(&cell.id, "Current Name").unwrap();
    assert_eq!(store.count(), 0);
    assert!(store.export_snapshot(&cell.id).is_err());
    assert!(store.import_snapshot(&backup, &owner, None).is_err());
    assert!(
        std::fs::read_dir(data.join("snapshots"))
            .unwrap()
            .next()
            .is_none()
    );
    assert_eq!(std::fs::read(&backup_path).unwrap(), backup_bytes);
    assert_eq!(
        std::fs::read_to_string(worktree.join("file")).unwrap(),
        "keep"
    );
    drop(store);
    let mut reopened = Store::open(&data, b"password").unwrap();
    assert_eq!(reopened.count(), 0);
    assert!(reopened.resolve_git_cell(&cell.id).is_err());
    assert!(reopened.import_snapshot(&backup, &owner, None).is_err());
    let live = reopened.create_cell("Another".into()).unwrap();
    reopened.lock("revoked".into()).unwrap();
    assert!(reopened.delete_cell(&live.id, "Another").is_err());
}

#[test]
fn imported_slug_ambiguity_fails_closed_but_ids_still_work() {
    let dir = tempfile::tempdir().unwrap();
    let mut store = setup(&dir.path().join("node"));
    let original = store.create_cell("My Repo".into()).unwrap();
    let imported = Cell::create(
        "MY---REPO".into(),
        &store.local.frame,
        &store.profile().certificate,
    )
    .unwrap();
    let snapshot = signed_snapshot(&store, &imported, &store);
    let owner = store.profile().identity.clone();
    store.import_snapshot(&snapshot, &owner, None).unwrap();
    assert!(store.resolve_git_cell("my-repo").is_err());
    assert!(
        store
            .git_http(
                "my-repo",
                "GET",
                "info/refs",
                "service=git-upload-pack",
                "",
                &[]
            )
            .is_err()
    );
    for id in [&original.id, &imported.id] {
        assert_eq!(&store.resolve_git_cell(id).unwrap(), id);
        assert!(
            store
                .git_http(id, "GET", "info/refs", "service=git-upload-pack", "", &[])
                .is_ok()
        );
    }
    let id_shaped = Cell::create(
        original.id.clone(),
        &store.local.frame,
        &store.profile().certificate,
    )
    .unwrap();
    let snapshot = signed_snapshot(&store, &id_shaped, &store);
    store.import_snapshot(&snapshot, &owner, None).unwrap();
    assert_eq!(store.resolve_git_cell(&original.id).unwrap(), original.id);
}

#[test]
fn member_read_and_write_frames_cannot_rename_or_delete_owner_repository() {
    let dir = tempfile::tempdir().unwrap();
    let mut owner = setup(&dir.path().join("owner"));
    let mut member = setup(&dir.path().join("member"));
    let original = owner.create_cell("Owner Repo".into()).unwrap();
    for role in [Role::Read, Role::Write] {
        owner.grant(&original.id, member.profile(), role).unwrap();
        let snapshot = owner.export_snapshot(&original.id).unwrap();
        member
            .import_snapshot(&snapshot, &owner.profile().identity, None)
            .unwrap();
        assert!(member.rename_cell(&original.id, "Stolen".into()).is_err());
        assert!(
            member
                .operate(
                    &original.id,
                    Operation::Rename {
                        name: "Bypass".into()
                    }
                )
                .is_err()
        );
        assert!(member.delete_cell(&original.id, "Owner Repo").is_err());
        assert_eq!(
            member.cell_summary(&original.id).unwrap().name,
            "Owner Repo"
        );
        assert!(
            member
                .git_http(
                    "owner-repo",
                    "GET",
                    "info/refs",
                    "service=git-upload-pack",
                    "",
                    &[]
                )
                .is_ok()
        );
    }
}

#[test]
fn legacy_encrypted_control_without_tombstones_still_opens() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("node");
    let store = setup(&data);
    let encrypted: comb_cell::EncryptedSnapshot =
        serde_json::from_slice(&std::fs::read(data.join("control.enc")).unwrap()).unwrap();
    let plaintext = comb_cell::open_snapshot(
        &encrypted,
        &store.local.frame.recipient_secret(),
        b"comb.frame.control.v1",
    )
    .unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&plaintext).unwrap();
    legacy.as_object_mut().unwrap().remove("tombstones");
    let encrypted = comb_cell::seal_snapshot(
        &serde_json::to_vec(&legacy).unwrap(),
        &[store.local.frame.public().encryption_key],
        b"comb.frame.control.v1",
    )
    .unwrap();
    std::fs::write(
        data.join("control.enc"),
        serde_json::to_vec(&encrypted).unwrap(),
    )
    .unwrap();
    drop(store);
    assert_eq!(Store::open(&data, b"password").unwrap().count(), 0);
}
