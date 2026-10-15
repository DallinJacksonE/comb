mod common;
use comb_cell::domain::Operation;
use comb_frame::{lifecycle::RestoreOutcome, restore};
use common::{PASSWORD, siblings};

#[test]
fn restore_requires_a_different_authorized_frame_and_reset_preserves_working_copies() {
    let mut fixture = siblings();
    let outside = fixture.directory.path().join("working-copy");
    std::fs::create_dir(&outside).unwrap();
    std::fs::write(outside.join("code"), b"must survive").unwrap();
    let cell = fixture.target.create_cell("Private".into()).unwrap();
    fixture
        .target
        .operate(
            &cell.id,
            Operation::RegisterFrame {
                certificate: fixture.issuer.profile().certificate.clone(),
            },
        )
        .unwrap();
    let old = fixture.target.profile().frame_id();
    fixture.target.lock("signed-notice".into()).unwrap();
    let request = fixture.target.prepare_restore(PASSWORD).unwrap();
    assert!(
        fixture.target.issue_restore(&request).is_err(),
        "locked FRAME cannot generate its own restore password"
    );
    let credential = restore::encode(&fixture.issuer.issue_restore(&request).unwrap()).unwrap();
    assert_eq!(
        fixture
            .target
            .restore_credential(&credential, PASSWORD)
            .unwrap(),
        RestoreOutcome::Restored
    );
    assert_ne!(fixture.target.profile().frame_id(), old);
    assert_eq!(fixture.target.count(), 1);
    fixture.target.lock("new-notice".into()).unwrap();
    assert_eq!(
        fixture
            .target
            .restore_credential("wrong", PASSWORD)
            .unwrap(),
        RestoreOutcome::Denied { remaining: 2 }
    );
    fixture
        .target
        .restore_credential("wrong", PASSWORD)
        .unwrap();
    assert_eq!(
        fixture
            .target
            .restore_credential("wrong", PASSWORD)
            .unwrap(),
        RestoreOutcome::ResetRequired
    );
    assert_eq!(fixture.target.count(), 0);
    assert!(fixture.target.is_active());
    assert_eq!(
        std::fs::read(outside.join("code")).unwrap(),
        b"must survive"
    );
}
