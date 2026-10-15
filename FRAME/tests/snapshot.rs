use comb_cell::{FrameSecrets, IdentitySecrets};
use comb_frame::snapshot::{Snapshot, SnapshotContext};

#[test]
fn signed_snapshot_is_private_tamper_evident_and_offline_recoverable() {
    let identity = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let cert = identity.certify_frame(&frame.public()).unwrap();
    let context = SnapshotContext {
        cell_id: "cell-a".into(),
        version: "version-a".into(),
        owner: identity.public(),
    };
    let snapshot = Snapshot::seal(
        context.clone(),
        b"SECRET CODE MARKER",
        &[
            frame.public().encryption_key,
            identity.public().recovery_key,
        ],
        &frame,
        &cert,
    )
    .unwrap();
    let encoded = serde_json::to_vec(&snapshot).unwrap();
    assert!(
        !encoded
            .windows(b"SECRET CODE MARKER".len())
            .any(|w| w == b"SECRET CODE MARKER")
    );
    assert_eq!(
        &*snapshot
            .open(&identity.public(), &frame.recipient_secret())
            .unwrap(),
        b"SECRET CODE MARKER"
    );
    let new_frame = FrameSecrets::generate();
    assert!(
        snapshot
            .open(&identity.public(), &new_frame.recipient_secret())
            .is_err()
    );
    assert_eq!(
        &*snapshot
            .open(&identity.public(), &identity.recovery_secret())
            .unwrap(),
        b"SECRET CODE MARKER"
    );
    let other = IdentitySecrets::generate();
    assert!(
        snapshot
            .open(&other.public(), &frame.recipient_secret())
            .is_err()
    );
    let mut changed = snapshot.clone();
    changed.record.payload[0] ^= 1;
    assert!(
        changed
            .open(&identity.public(), &frame.recipient_secret())
            .is_err()
    );
    assert_eq!(snapshot.context().unwrap(), context);
}
