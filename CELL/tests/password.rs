use comb_cell::*;

#[test]
fn password_secret_roundtrip_binds_password_context_header_and_ciphertext() {
    let sealed = seal_secret(b"private bytes", b"correct horse", b"local-purpose").unwrap();
    assert_eq!(
        &*open_secret(&sealed, b"correct horse", b"local-purpose").unwrap(),
        b"private bytes"
    );
    assert!(open_secret(&sealed, b"wrong", b"local-purpose").is_err());
    assert!(open_secret(&sealed, b"correct horse", b"another-purpose").is_err());
    let mut bad = sealed.clone();
    bad.ciphertext[0] ^= 1;
    assert!(open_secret(&bad, b"correct horse", b"local-purpose").is_err());
    let mut bad = sealed.clone();
    bad.salt[0] ^= 1;
    assert!(open_secret(&bad, b"correct horse", b"local-purpose").is_err());
    let mut bad = sealed.clone();
    bad.nonce[0] ^= 1;
    assert!(open_secret(&bad, b"correct horse", b"local-purpose").is_err());
    let mut bad = sealed;
    bad.version = 99;
    assert!(open_secret(&bad, b"correct horse", b"local-purpose").is_err());
}

#[test]
fn encrypted_exports_restore_roles_but_do_not_cross_import() {
    let identity = IdentitySecrets::generate();
    let frame = FrameSecrets::generate();
    let recovery = identity.export_encrypted(b"passphrase").unwrap();
    let local = frame.export_encrypted(b"passphrase").unwrap();
    let restored = IdentitySecrets::import_encrypted(&recovery, b"passphrase").unwrap();
    let restored_frame = FrameSecrets::import_encrypted(&local, b"passphrase").unwrap();
    assert_eq!(identity.public(), restored.public());
    assert_eq!(frame.public(), restored_frame.public());
    assert!(IdentitySecrets::import_encrypted(&local, b"passphrase").is_err());
    assert!(FrameSecrets::import_encrypted(&recovery, b"passphrase").is_err());
    assert!(IdentitySecrets::import_encrypted(&recovery, b"wrong").is_err());
    let wire = serde_json::to_vec(&recovery).unwrap();
    let decoded: PasswordEnvelope = serde_json::from_slice(&wire).unwrap();
    assert_eq!(
        IdentitySecrets::import_encrypted(&decoded, b"passphrase")
            .unwrap()
            .public(),
        identity.public()
    );
    assert_ne!(recovery, identity.export_encrypted(b"passphrase").unwrap());
}
