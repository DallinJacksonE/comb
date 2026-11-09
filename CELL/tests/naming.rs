use comb_cell::domain::{Cell, Operation, Role};
use comb_cell::{FrameCertificate, FrameSecrets, IdentitySecrets};

fn actor() -> (IdentitySecrets, FrameSecrets, FrameCertificate) {
    let identity = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let certificate = identity.certify_frame(&frame.public()).unwrap();
    (identity, frame, certificate)
}

#[test]
fn signed_owner_rename_replays_merges_and_preserves_genesis() {
    let (_, frame, cert) = actor();
    let mut cell = Cell::create("Original".into(), &frame, &cert).unwrap();
    let mut peer = cell.clone();
    cell.apply(
        Operation::Rename {
            name: "My Repo".into(),
        },
        &frame,
        &cert,
    )
    .unwrap();
    assert_eq!(cell.name, "Original");
    assert_eq!(cell.effective_name(), "My Repo");
    peer.merge(&cell).unwrap();
    let reopened: Cell = serde_json::from_slice(&serde_json::to_vec(&peer).unwrap()).unwrap();
    reopened.validate().unwrap();
    assert_eq!(reopened.effective_name(), "My Repo");
    assert_eq!(reopened.id, cell.id);
    let mut tampered = reopened;
    tampered.name = "My Repo".into();
    assert!(tampered.validate().is_err());
}

#[test]
fn members_cannot_rename_even_with_write_permission() {
    let (_, frame, cert) = actor();
    let (member, member_frame, member_cert) = actor();
    let mut cell = Cell::create("Original".into(), &frame, &cert).unwrap();
    for role in [Role::Read, Role::Write] {
        cell.apply(
            Operation::Grant {
                identity: member.public(),
                role,
            },
            &frame,
            &cert,
        )
        .unwrap();
        cell.apply(
            Operation::RegisterFrame {
                certificate: member_cert.clone(),
            },
            &frame,
            &cert,
        )
        .unwrap();
        assert!(
            cell.apply(
                Operation::Rename {
                    name: "Stolen".into()
                },
                &member_frame,
                &member_cert
            )
            .is_err()
        );
        assert_eq!(cell.effective_name(), "Original");
    }
}
