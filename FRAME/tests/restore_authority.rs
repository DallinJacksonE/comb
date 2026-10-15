mod common;
use comb_cell::domain::Operation;
use comb_frame::{lifecycle::RestoreOutcome, restore};
use common::{PASSWORD, siblings};

#[test]
fn a_restore_grant_from_a_known_revoked_sibling_counts_as_a_failed_attempt() {
    let mut fixture = siblings();
    let cell = fixture.target.create_cell("Protected".into()).unwrap();
    fixture
        .target
        .operate(
            &cell.id,
            Operation::RegisterFrame {
                certificate: fixture.issuer.profile().certificate.clone(),
            },
        )
        .unwrap();
    fixture
        .target
        .operate(
            &cell.id,
            Operation::RevokeFrame {
                frame_id: fixture.issuer.profile().frame_id(),
            },
        )
        .unwrap();
    fixture.target.lock("validated-revocation".into()).unwrap();
    let request = fixture.target.prepare_restore(PASSWORD).unwrap();
    let credential = restore::encode(&fixture.issuer.issue_restore(&request).unwrap()).unwrap();
    assert_eq!(
        fixture
            .target
            .restore_credential(&credential, PASSWORD)
            .unwrap(),
        RestoreOutcome::Denied { remaining: 2 }
    );
    assert!(!fixture.target.is_active());
    // A rejected authorization does not consume the pending request/vault.
    let repeated = fixture.target.prepare_restore(PASSWORD).unwrap();
    assert_eq!(request.enrollment.nonce, repeated.enrollment.nonce);
    assert!(
        fixture
            .directory
            .path()
            .join("a/restore-pending/pending.vault")
            .is_file()
    );
}
