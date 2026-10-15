use comb_cell::*;

#[test]
fn signed_records_bind_payload_certificate_frame_domain_and_version() {
    let root = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let other = FrameSecrets::generate();
    let cert = root.certify_frame(&frame.public()).unwrap();
    let record =
        SignedRecord::new(&frame, &cert, b"comb.snapshot.v1", b"ciphertext manifest").unwrap();
    assert_eq!(
        record
            .verify(&root.public(), &frame.public(), b"comb.snapshot.v1")
            .unwrap(),
        b"ciphertext manifest"
    );
    assert!(
        record
            .verify(&root.public(), &other.public(), b"comb.snapshot.v1")
            .is_err()
    );
    assert!(
        record
            .verify(&root.public(), &frame.public(), b"comb.acceptance.v1")
            .is_err()
    );
    assert!(SignedRecord::new(&other, &cert, b"comb.snapshot.v1", b"manifest").is_err());
    let mut bad = record.clone();
    bad.payload[0] ^= 1;
    assert!(
        bad.verify(&root.public(), &frame.public(), b"comb.snapshot.v1")
            .is_err()
    );
    let mut bad = record.clone();
    bad.certificate = root.certify_frame(&other.public()).unwrap();
    assert!(
        bad.verify(&root.public(), &other.public(), b"comb.snapshot.v1")
            .is_err()
    );
    let mut bad = record.clone();
    bad.version = 99;
    assert!(
        bad.verify(&root.public(), &frame.public(), b"comb.snapshot.v1")
            .is_err()
    );
    let wire = serde_json::to_vec(&record).unwrap();
    let decoded: SignedRecord = serde_json::from_slice(&wire).unwrap();
    assert_eq!(decoded.id().unwrap(), record.id().unwrap());
    assert_ne!(record.id().unwrap(), bad.id().unwrap());
}
