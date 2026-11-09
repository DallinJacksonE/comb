//! Authenticated snapshots must also contain complete, uncorrupted Git objects.
use comb_cell::domain::{Cell, Operation};
use comb_frame::{
    archive::{pack_directory, unpack_directory},
    git::GitRepository,
    identity,
    snapshot::{Snapshot, SnapshotContext},
    store::Store,
};
use std::{
    collections::BTreeMap,
    io::Write,
    path::Path,
    process::{Command, Stdio},
};

const PASSWORD: &[u8] = b"snapshot-integrity-fixture";

struct Fixture {
    directory: tempfile::TempDir,
    store: Store,
    cell: Cell,
    repository: GitRepository,
    blob: String,
    tree: String,
    parent: String,
    tag_target: String,
    replacement: String,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("frame");
        identity::initialize(
            &data,
            "Alice",
            "alice@test",
            PASSWORD,
            &directory.path().join("recovery"),
        )
        .unwrap();
        let store = Store::open(&data, PASSWORD).unwrap();
        let mut cell = Cell::create(
            "Integrity fixture".into(),
            &store.local.frame,
            &store.profile().certificate,
        )
        .unwrap();
        let repository = GitRepository::create(directory.path(), &cell.id).unwrap();
        let blob = git(
            repository.path(),
            &["hash-object", "-w", "--stdin"],
            b"retained code\n",
        );
        let replacement = git(
            repository.path(),
            &["hash-object", "-w", "--stdin"],
            b"different bytes\n",
        );
        let tree = git(
            repository.path(),
            &["mktree"],
            format!("100644 blob {blob}\tcode.txt\n").as_bytes(),
        );
        let parent = git(
            repository.path(),
            &["commit-tree", &tree, "-m", "base"],
            b"",
        );
        let tip = git(
            repository.path(),
            &["commit-tree", &tree, "-p", &parent, "-m", "tip"],
            b"",
        );
        let tag_target = git(
            repository.path(),
            &["commit-tree", &tree, "-m", "tagged only"],
            b"",
        );
        let tag = git(repository.path(), &["mktag"], format!("object {tag_target}\ntype commit\ntag fixture\ntagger Alice <alice@test> 1700000000 +0000\n\nfixture tag\n").as_bytes());
        cell.apply(
            Operation::Publish {
                refs: BTreeMap::from([
                    ("refs/heads/main".into(), tip),
                    ("refs/tags/fixture".into(), tag),
                ]),
            },
            &store.local.frame,
            &store.profile().certificate,
        )
        .unwrap();
        repository.install_refs(&cell.refs()).unwrap();
        Self {
            directory,
            store,
            cell,
            repository,
            blob,
            tree,
            parent,
            tag_target,
            replacement,
        }
    }

    fn snapshot(&self, cell: &Cell, archive: Vec<u8>) -> Snapshot {
        Snapshot::seal(
            SnapshotContext {
                cell_id: cell.id.clone(),
                version: cell.version_id(),
                owner: cell.owner.clone(),
            },
            &serde_json::to_vec(&serde_json::json!({"cell": cell, "git": archive})).unwrap(),
            &[self.store.local.frame.public().encryption_key],
            &self.store.local.frame,
            &self.store.profile().certificate,
        )
        .unwrap()
    }

    fn damaged_archive(&self, object: &str, corrupt: bool) -> Vec<u8> {
        let stage = tempfile::tempdir_in(self.directory.path()).unwrap();
        let path = stage.path().join("damaged.git");
        unpack_directory(&pack_directory(self.repository.path()).unwrap(), &path).unwrap();
        let object_path =
            |root: &Path, id: &str| root.join("objects").join(&id[..2]).join(&id[2..]);
        let target = object_path(&path, object);
        // Loose Git objects are read-only; unlink inside the disposable fixture
        // before installing replacement bytes rather than altering permissions.
        std::fs::remove_file(&target).unwrap();
        if corrupt {
            // Valid compressed object bytes under the wrong content identifier.
            let source = if object == self.replacement {
                &self.blob
            } else {
                &self.replacement
            };
            std::fs::copy(object_path(self.repository.path(), source), &target).unwrap();
        }
        // The signed tips still exist: tip-only validation cannot detect this damage.
        git(
            &path,
            &["cat-file", "-e", &self.cell.refs()["refs/heads/main"]],
            b"",
        );
        pack_directory(&path).unwrap()
    }
}

fn git(path: &Path, args: &[&str], input: &[u8]) -> String {
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(path)
        .args(["-c", "user.name=Alice", "-c", "user.email=alice@test"])
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
fn new_cell_import_rejects_missing_or_corrupt_descendants_without_persisting_them() {
    let mut fixture = Fixture::new();
    let data = fixture.directory.path().join("frame");
    let control_before = std::fs::read(data.join("control.enc")).unwrap();
    for (object, corrupt) in [
        // Corrupt retained objects must also fail, even without an accepted ref.
        (fixture.replacement.clone(), true),
        (fixture.tag_target.clone(), false),
        (fixture.blob.clone(), false),
        (fixture.tree.clone(), false),
        (fixture.parent.clone(), false),
        (fixture.blob.clone(), true),
    ] {
        let hostile = fixture.snapshot(&fixture.cell, fixture.damaged_archive(&object, corrupt));
        // A tag can retain a commit which is not reachable from any branch.
        let error = fixture
            .store
            .import_snapshot(&hostile, &fixture.cell.owner, None)
            .err()
            .expect("signed tips must not authorize damaged descendant objects");
        assert!(
            format!("{error:#}").contains("object integrity check failed"),
            "{error:#}"
        );
        assert_eq!(fixture.store.count(), 0);
        assert_eq!(
            std::fs::read(data.join("control.enc")).unwrap(),
            control_before
        );
        assert_eq!(
            std::fs::read_dir(data.join("snapshots")).unwrap().count(),
            0
        );
    }
    drop(fixture.store);
    assert_eq!(Store::open(&data, PASSWORD).unwrap().count(), 0);
}

#[test]
fn damaged_update_cannot_change_live_or_reopened_accepted_state() {
    use comb_cell::domain::Issue;
    let mut fixture = Fixture::new();
    let valid = fixture.snapshot(
        &fixture.cell,
        pack_directory(fixture.repository.path()).unwrap(),
    );
    fixture
        .store
        .import_snapshot(&valid, &fixture.cell.owner, None)
        .unwrap();
    let accepted = fixture
        .store
        .export_snapshot(&fixture.cell.id)
        .unwrap()
        .id()
        .unwrap();
    let data = fixture.directory.path().join("frame");
    let control_before = std::fs::read(data.join("control.enc")).unwrap();
    let count_before = std::fs::read_dir(data.join("snapshots")).unwrap().count();
    let mut changed = fixture.cell.clone();
    changed
        .apply(
            Operation::AddIssue {
                issue: Issue {
                    id: "must-not-be-accepted".into(),
                    title: "uncommitted issue".into(),
                    body: String::new(),
                    closed: false,
                },
            },
            &fixture.store.local.frame,
            &fixture.store.profile().certificate,
        )
        .unwrap();
    for (object, corrupt) in [
        (fixture.tag_target.clone(), false),
        (fixture.blob.clone(), false),
        (fixture.tree.clone(), false),
        (fixture.parent.clone(), false),
        (fixture.blob.clone(), true),
    ] {
        let hostile = fixture.snapshot(&changed, fixture.damaged_archive(&object, corrupt));
        assert!(
            fixture
                .store
                .import_snapshot(&hostile, &fixture.cell.owner, None)
                .is_err()
        );
        assert_eq!(
            fixture
                .store
                .export_snapshot(&fixture.cell.id)
                .unwrap()
                .id()
                .unwrap(),
            accepted
        );
        assert_eq!(
            fixture.store.cell(&fixture.cell.id).unwrap().version_id(),
            fixture.cell.version_id()
        );
        assert!(fixture.store.issues(&fixture.cell.id).unwrap().is_empty());
        assert_eq!(
            std::fs::read(data.join("control.enc")).unwrap(),
            control_before
        );
        assert_eq!(
            std::fs::read_dir(data.join("snapshots")).unwrap().count(),
            count_before
        );
    }
    drop(fixture.store);
    let reopened = Store::open(&data, PASSWORD).unwrap();
    assert_eq!(
        reopened
            .export_snapshot(&fixture.cell.id)
            .unwrap()
            .id()
            .unwrap(),
        accepted
    );
    assert!(reopened.issues(&fixture.cell.id).unwrap().is_empty());
}

#[test]
fn packed_snapshots_require_valid_checksums_and_reopen_when_intact() {
    let mut fixture = Fixture::new();
    let stage = tempfile::tempdir_in(fixture.directory.path()).unwrap();
    let path = stage.path().join("packed.git");
    unpack_directory(&pack_directory(fixture.repository.path()).unwrap(), &path).unwrap();
    git(&path, &["repack", "-ad"], b"");
    let intact = pack_directory(&path).unwrap();
    let pack = std::fs::read_dir(path.join("objects/pack"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .find(|path| path.extension().is_some_and(|ext| ext == "pack"))
        .unwrap();
    let mut bytes = std::fs::read(&pack).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    std::fs::remove_file(&pack).unwrap();
    std::fs::write(&pack, bytes).unwrap();
    let hostile = fixture.snapshot(&fixture.cell, pack_directory(&path).unwrap());
    let data = fixture.directory.path().join("frame");
    let control_before = std::fs::read(data.join("control.enc")).unwrap();
    assert!(
        fixture
            .store
            .import_snapshot(&hostile, &fixture.cell.owner, None)
            .is_err()
    );
    assert_eq!(fixture.store.count(), 0);
    assert_eq!(
        std::fs::read(data.join("control.enc")).unwrap(),
        control_before
    );
    assert_eq!(
        std::fs::read_dir(data.join("snapshots")).unwrap().count(),
        0
    );
    let valid = fixture.snapshot(&fixture.cell, intact);
    fixture
        .store
        .import_snapshot(&valid, &fixture.cell.owner, None)
        .unwrap();
    drop(fixture.store);
    assert_eq!(
        Store::open(&data, PASSWORD)
            .unwrap()
            .cell(&fixture.cell.id)
            .unwrap()
            .refs(),
        fixture.cell.refs()
    );
}

#[test]
fn reopen_rejects_authenticated_snapshot_with_missing_descendant_object() {
    use comb_cell::{EncryptedSnapshot, open_snapshot, seal_snapshot};
    let mut fixture = Fixture::new();
    let valid = fixture.snapshot(
        &fixture.cell,
        pack_directory(fixture.repository.path()).unwrap(),
    );
    fixture
        .store
        .import_snapshot(&valid, &fixture.cell.owner, None)
        .unwrap();
    let hostile = fixture.snapshot(&fixture.cell, fixture.damaged_archive(&fixture.blob, false));
    let data = fixture.directory.path().join("frame");
    let original_control = std::fs::read(data.join("control.enc")).unwrap();
    let encrypted: EncryptedSnapshot = serde_json::from_slice(&original_control).unwrap();
    let plain = open_snapshot(
        &encrypted,
        &fixture.store.local.frame.recipient_secret(),
        b"comb.frame.control.v1",
    )
    .unwrap();
    let mut control: serde_json::Value = serde_json::from_slice(&plain).unwrap();
    let digest = hostile.id().unwrap();
    control["current"][&fixture.cell.id] = serde_json::json!(digest);
    let replacement = seal_snapshot(
        &serde_json::to_vec(&control).unwrap(),
        &[fixture.store.local.frame.public().encryption_key],
        b"comb.frame.control.v1",
    )
    .unwrap();
    let poisoned_control = serde_json::to_vec(&replacement).unwrap();
    drop(fixture.store);
    // Simulate a fully authenticated bad snapshot, not random disk corruption
    // which would already be rejected by ciphertext/hash/signature checks.
    std::fs::write(
        data.join("snapshots").join(format!("{digest}.cell")),
        serde_json::to_vec(&hostile).unwrap(),
    )
    .unwrap();
    std::fs::write(data.join("control.enc"), &poisoned_control).unwrap();
    assert!(
        Store::open(&data, PASSWORD).is_err(),
        "reopen must traverse beyond the signed tip"
    );
    assert_eq!(
        std::fs::read(data.join("control.enc")).unwrap(),
        poisoned_control
    );
    std::fs::write(data.join("control.enc"), original_control).unwrap();
    assert_eq!(
        Store::open(&data, PASSWORD)
            .unwrap()
            .cell(&fixture.cell.id)
            .unwrap()
            .refs(),
        fixture.cell.refs()
    );
}
