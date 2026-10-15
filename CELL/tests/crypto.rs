use comb_cell::*;

#[test]
fn identity_certifies_distinct_frame_keys_and_signatures_are_context_bound() {
    let identity = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let second = FrameSecrets::generate();
    let public = identity.public();
    assert_ne!(public.signing_key, frame.public().signing_key);
    assert_ne!(frame.public(), second.public());
    let cert = identity.certify_frame(&frame.public()).unwrap();
    cert.verify(&public).unwrap();
    let record = frame.sign(b"comb.acceptance.v1", b"exact commits + policy");
    record
        .verify(
            &frame.public().signing_key,
            b"comb.acceptance.v1",
            b"exact commits + policy",
        )
        .unwrap();
    assert!(
        record
            .verify(
                &frame.public().signing_key,
                b"comb.adoption.v1",
                b"exact commits + policy"
            )
            .is_err()
    );
    assert!(
        record
            .verify(
                &second.public().signing_key,
                b"comb.acceptance.v1",
                b"exact commits + policy"
            )
            .is_err()
    );
    assert!(
        record
            .verify(
                &frame.public().signing_key,
                b"comb.acceptance.v1",
                b"changed"
            )
            .is_err()
    );
    let roundtrip: FrameCertificate =
        serde_json::from_slice(&serde_json::to_vec(&cert).unwrap()).unwrap();
    roundtrip.verify(&public).unwrap();
}

#[test]
fn certificate_rejects_substitution_of_any_bound_key() {
    let identity = IdentitySecrets::generate();
    let attacker = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let other = FrameSecrets::generate();
    let cert = identity.certify_frame(&frame.public()).unwrap();
    assert!(cert.verify(&attacker.public()).is_err());
    let mut changed = cert.clone();
    changed.frame.encryption_key = other.public().encryption_key;
    assert!(changed.verify(&identity.public()).is_err());
    let mut changed = cert.clone();
    changed.frame.signing_key = other.public().signing_key;
    assert!(changed.verify(&identity.public()).is_err());
    let mut changed = cert.clone();
    changed.identity.recovery_key = attacker.public().recovery_key;
    assert!(changed.verify(&identity.public()).is_err());
    let mut changed = cert;
    changed.signature.bytes[0] ^= 1;
    assert!(changed.verify(&identity.public()).is_err());
}
