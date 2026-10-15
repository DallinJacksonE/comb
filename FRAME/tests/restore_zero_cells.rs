mod common;
use comb_cell::SignedRecord;
use comb_frame::{
    identity,
    lifecycle::RestoreOutcome,
    restore::{self, RESTORE_DOMAIN, RestoreAuthorization},
};
use common::{PASSWORD, siblings};

#[test]
fn even_without_cells_a_locked_frame_cannot_sign_its_own_unlock() {
    let mut fixture = siblings();
    assert_eq!(fixture.target.count(), 0);
    fixture.target.lock("specific-revocation".into()).unwrap();
    let request = fixture.target.prepare_restore(PASSWORD).unwrap();
    let grant = identity::authorize_from_frame(&fixture.target.local, &request.enrollment).unwrap();
    let body = RestoreAuthorization {
        grant,
        target_frame: request.target_frame.clone(),
        revocation: request.revocation.clone(),
    };
    let forged = SignedRecord::new(
        &fixture.target.local.frame,
        &fixture.target.profile().certificate,
        RESTORE_DOMAIN,
        &serde_json::to_vec(&body).unwrap(),
    )
    .unwrap();
    assert_eq!(
        fixture
            .target
            .restore_credential(&restore::encode(&forged).unwrap(), PASSWORD)
            .unwrap(),
        RestoreOutcome::Denied { remaining: 2 }
    );
    assert!(
        fixture
            .directory
            .path()
            .join("a/restore-pending/pending.vault")
            .is_file()
    );
    let valid = restore::encode(&fixture.issuer.issue_restore(&request).unwrap()).unwrap();
    assert_eq!(
        fixture.target.restore_credential(&valid, PASSWORD).unwrap(),
        RestoreOutcome::Restored
    );
}
