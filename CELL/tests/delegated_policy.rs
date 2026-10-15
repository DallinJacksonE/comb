use comb_cell::domain::*;
use comb_cell::*;

#[test]
fn revoked_issuer_cannot_mint_a_replacement_but_previously_enrolled_frames_survive() {
    let root = IdentitySecrets::generate();
    let a = FrameSecrets::generate();
    let ac = root.certify_frame(&a.public()).unwrap();
    let b = FrameSecrets::generate();
    let bc = root.certify_frame(&b.public()).unwrap();
    let c = FrameSecrets::generate();
    let cc = b.certify_frame(&bc, &c.public()).unwrap();
    let mut cell = Cell::create("Policy".into(), &a, &ac).unwrap();
    cell.apply(
        Operation::RegisterFrame {
            certificate: bc.clone(),
        },
        &a,
        &ac,
    )
    .unwrap();
    cell.apply(
        Operation::RegisterFrame {
            certificate: cc.clone(),
        },
        &c,
        &cc,
    )
    .unwrap();
    cell.apply(
        Operation::RevokeFrame {
            frame_id: frame_id(&bc.frame),
        },
        &a,
        &ac,
    )
    .unwrap();
    assert!(
        cell.is_frame_authorized(&cc, true),
        "revoking one FRAME must not invalidate already-enrolled siblings"
    );
    let d = FrameSecrets::generate();
    let dc = b.certify_frame(&bc, &d.public()).unwrap();
    assert!(
        cell.apply(
            Operation::RegisterFrame {
                certificate: dc.clone()
            },
            &d,
            &dc
        )
        .is_err(),
        "revoked issuer must not bypass revocation by minting a fresh FRAME key"
    );
    let intermediate = FrameSecrets::generate();
    let intermediate_cert = b.certify_frame(&bc, &intermediate.public()).unwrap();
    let leaf = FrameSecrets::generate();
    let leaf_cert = intermediate
        .certify_frame(&intermediate_cert, &leaf.public())
        .unwrap();
    assert!(
        cell.apply(
            Operation::RegisterFrame {
                certificate: leaf_cert.clone()
            },
            &leaf,
            &leaf_cert
        )
        .is_err(),
        "an unregistered intermediary must not launder a revoked issuer"
    );
}
