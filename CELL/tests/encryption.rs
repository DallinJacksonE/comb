use comb_cell::*;

#[test]
fn snapshot_recipient_envelopes_recover_with_explicit_offline_secret_only() {
    let identity = IdentitySecrets::generate();
    let lost = FrameSecrets::generate();
    let recovery_file = identity.export_encrypted(b"offline password").unwrap();
    let aad = b"cell=123;version=abc;policy=def";
    let snapshot = seal_snapshot(
        b"git pack + collaboration metadata",
        &[lost.public().encryption_key, identity.public().recovery_key],
        aad,
    )
    .unwrap();
    assert_eq!(
        &*open_snapshot(&snapshot, &lost.recipient_secret(), aad).unwrap(),
        b"git pack + collaboration metadata"
    );
    drop(identity);
    drop(lost);
    let recovered = IdentitySecrets::import_encrypted(&recovery_file, b"offline password").unwrap();
    let replacement = FrameSecrets::generate();
    recovered
        .certify_frame(&replacement.public())
        .unwrap()
        .verify(&recovered.public())
        .unwrap();
    // Certification does not magically give a new device historical decryption keys.
    assert!(open_snapshot(&snapshot, &replacement.recipient_secret(), aad).is_err());
    assert_eq!(
        &*open_snapshot(&snapshot, &recovered.recovery_secret(), aad).unwrap(),
        b"git pack + collaboration metadata"
    );
    let wire = serde_json::to_vec(&snapshot).unwrap();
    let restored: EncryptedSnapshot = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        &*open_snapshot(&restored, &recovered.recovery_secret(), aad).unwrap(),
        b"git pack + collaboration metadata"
    );
}

#[test]
fn snapshot_rejects_tamper_wrong_context_and_revoked_frame() {
    let active = FrameSecrets::generate();
    let revoked = FrameSecrets::generate();
    let snapshot = seal_snapshot(
        b"new version",
        &[active.public().encryption_key],
        b"version 2",
    )
    .unwrap();
    assert!(open_snapshot(&snapshot, &revoked.recipient_secret(), b"version 2").is_err());
    assert!(open_snapshot(&snapshot, &active.recipient_secret(), b"version 1").is_err());
    for field in 0..6 {
        let mut bad = snapshot.clone();
        match field {
            0 => bad.data.ciphertext[0] ^= 1,
            1 => bad.data.nonce[0] ^= 1,
            2 => bad.envelopes[0].ephemeral_key[0] ^= 1,
            3 => bad.envelopes[0].ciphertext[0] ^= 1,
            4 => bad.envelopes[0].recipient_key[0] ^= 1,
            _ => bad.envelopes[0].nonce[0] ^= 1,
        }
        assert!(
            open_snapshot(&bad, &active.recipient_secret(), b"version 2").is_err(),
            "field {field}"
        );
    }
    assert!(seal_snapshot(b"empty", &[], b"context").is_err());
    assert!(seal_snapshot(b"bad recipient", &[[0; 32]], b"context").is_err());
}

#[test]
fn low_level_key_wrap_and_arbitrary_byte_encryption_bind_all_headers() {
    let recipient = RecipientSecret::generate();
    let key = DataKey::generate();
    let ciphertext = encrypt_data(&key, b"arbitrary bytes", b"context").unwrap();
    let envelope = wrap_key(&key, &recipient.public(), b"context").unwrap();
    let opened = unwrap_key(&envelope, &recipient, b"context").unwrap();
    assert_eq!(
        &*decrypt_data(&opened, &ciphertext, b"context").unwrap(),
        b"arbitrary bytes"
    );
    assert!(unwrap_key(&envelope, &RecipientSecret::generate(), b"context").is_err());
    assert!(unwrap_key(&envelope, &recipient, b"other").is_err());
    assert!(decrypt_data(&DataKey::generate(), &ciphertext, b"context").is_err());
    let mut bad = envelope.clone();
    bad.key_id[0] ^= 1;
    assert!(unwrap_key(&bad, &recipient, b"context").is_err());
    let mut bad = envelope.clone();
    bad.ephemeral_key = [0; 32];
    assert!(unwrap_key(&bad, &recipient, b"context").is_err());
    let mut bad = envelope;
    bad.version = 99;
    assert!(unwrap_key(&bad, &recipient, b"context").is_err());
    let mut bad = ciphertext;
    bad.version = 99;
    assert!(decrypt_data(&key, &bad, b"context").is_err());
}
