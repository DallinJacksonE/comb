use comb_cell::{FrameCertificate, FrameSecrets, IdentitySecrets, SignedRecord};

#[test]
fn delegated_enrollment_and_records_work_without_root_secrets() {
    let root = IdentitySecrets::generate();
    let identity = root.public();
    let parent = FrameSecrets::generate();
    let parent_cert = root.certify_frame(&parent.public()).unwrap();
    drop(root);
    let child = FrameSecrets::generate();
    let cert = parent.certify_frame(&parent_cert, &child.public()).unwrap();
    cert.verify(&identity).unwrap();
    assert_eq!(cert.issuers(), vec![parent.public()]);
    assert!(parent_cert.issuers().is_empty());
    let record = SignedRecord::new(&child, &cert, b"test", b"payload").unwrap();
    assert_eq!(
        record.verify(&identity, &child.public(), b"test").unwrap(),
        b"payload"
    );
    let encoded = serde_json::to_vec(&cert).unwrap();
    let decoded: FrameCertificate = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, cert);
    decoded.verify(&identity).unwrap();
}

#[test]
fn legacy_direct_certificate_encoding_is_unchanged() {
    let root = IdentitySecrets::generate();
    let cert = root
        .certify_frame(&FrameSecrets::generate().public())
        .unwrap();
    assert!(cert.delegation.is_none());
    let value = serde_json::to_value(&cert).unwrap();
    assert!(value.get("delegation").is_none());
    let decoded: FrameCertificate = serde_json::from_value(value).unwrap();
    decoded.verify(&root.public()).unwrap();
}

#[test]
fn issuance_checks_both_issuer_keys_and_certificate_authenticity() {
    let root = IdentitySecrets::generate();
    let issuer = FrameSecrets::generate();
    let cert = root.certify_frame(&issuer.public()).unwrap();
    let leaf = FrameSecrets::generate().public();
    assert!(
        FrameSecrets::generate()
            .certify_frame(&cert, &leaf)
            .is_err()
    );
    let mut changed = cert.clone();
    changed.frame.encryption_key[0] ^= 1;
    assert!(issuer.certify_frame(&changed, &leaf).is_err());
    changed = cert.clone();
    changed.identity.recovery_key[0] ^= 1;
    assert!(issuer.certify_frame(&changed, &leaf).is_err());
    changed = cert.clone();
    changed.signature.bytes[0] ^= 1;
    assert!(issuer.certify_frame(&changed, &leaf).is_err());
}

#[test]
fn every_identity_key_frame_key_signature_and_link_is_authenticated() {
    let root = IdentitySecrets::generate();
    let issuer = FrameSecrets::generate();
    let parent = root.certify_frame(&issuer.public()).unwrap();
    let child = FrameSecrets::generate();
    let cert = issuer.certify_frame(&parent, &child.public()).unwrap();
    let identity = root.public();
    assert!(cert.verify(&IdentitySecrets::generate().public()).is_err());
    for target_parent in [false, true] {
        for field in 0..5 {
            let mut altered = cert.clone();
            let target = if target_parent {
                altered.delegation.as_mut().unwrap()
            } else {
                &mut altered
            };
            match field {
                0 => target.identity.signing_key[0] ^= 1,
                1 => target.identity.recovery_key[0] ^= 1,
                2 => target.frame.signing_key[0] ^= 1,
                3 => target.frame.encryption_key[0] ^= 1,
                _ => target.signature.bytes[0] ^= 1,
            }
            assert!(altered.verify(&identity).is_err());
        }
    }
    let mut stripped = cert.clone();
    stripped.delegation = None;
    assert!(stripped.verify(&identity).is_err());
    let foreign_root = IdentitySecrets::generate();
    let mut spliced = cert.clone();
    spliced.delegation = Some(Box::new(
        foreign_root.certify_frame(&issuer.public()).unwrap(),
    ));
    assert!(spliced.verify(&identity).is_err());

    // Same signer and root, but a different encryption binding: valid in isolation,
    // invalid as a substituted lineage, including inside a signed record.
    let mut alternative_key = issuer.public();
    alternative_key.encryption_key[0] ^= 1;
    let alternative = root.certify_frame(&alternative_key).unwrap();
    let mut record = SignedRecord::new(&child, &cert, b"test", b"payload").unwrap();
    record.certificate.delegation = Some(Box::new(alternative));
    assert!(record.verify(&identity, &child.public(), b"test").is_err());
}

#[test]
fn depth_is_bounded_and_repeated_signers_are_rejected() {
    let root = IdentitySecrets::generate();
    let first = FrameSecrets::generate();
    let mut issuer = first;
    let mut cert = root.certify_frame(&issuer.public()).unwrap();
    let first_public = issuer.public();
    for _ in 1..8 {
        let next = FrameSecrets::generate();
        cert = issuer.certify_frame(&cert, &next.public()).unwrap();
        issuer = next;
        cert.verify(&root.public()).unwrap();
    }
    assert_eq!(cert.issuers().len(), 7);
    assert_eq!(cert.issuers().last(), Some(&first_public));
    assert!(
        issuer
            .certify_frame(&cert, &FrameSecrets::generate().public())
            .is_err()
    );
    let mut oversized = root
        .certify_frame(&FrameSecrets::generate().public())
        .unwrap();
    oversized.delegation = Some(Box::new(cert.clone()));
    assert!(oversized.verify(&root.public()).is_err());
    assert!(issuer.certify_frame(&cert, &first_public).is_err());

    let root_device = FrameSecrets::generate();
    let direct = root.certify_frame(&root_device.public()).unwrap();
    assert!(
        root_device
            .certify_frame(&direct, &root_device.public())
            .is_err()
    );
}

#[test]
fn alternate_valid_lineage_cannot_be_substituted() {
    let root = IdentitySecrets::generate();
    let a = FrameSecrets::generate();
    let b = FrameSecrets::generate();
    let c = FrameSecrets::generate();
    let a_direct = root.certify_frame(&a.public()).unwrap();
    let b_direct = root.certify_frame(&b.public()).unwrap();
    let a_via_b = b.certify_frame(&b_direct, &a.public()).unwrap();
    let cert = a.certify_frame(&a_direct, &c.public()).unwrap();
    let mut record = SignedRecord::new(&c, &cert, b"test", b"payload").unwrap();
    record.certificate.delegation = Some(Box::new(a_via_b));
    assert!(record.verify(&root.public(), &c.public(), b"test").is_err());
}
