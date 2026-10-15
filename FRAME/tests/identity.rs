use comb_cell::{IdentitySecrets, open_snapshot, seal_snapshot};
use comb_frame::identity::*;
use std::fs;
use std::os::unix::fs::{PermissionsExt, symlink};

#[test]
fn persistence_is_private_authenticated_and_non_destructive() {
    let tmp = tempfile::tempdir().unwrap();
    let data = tmp.path().join("node");
    let recovery = tmp.path().join("offline/recovery.json");
    let local = initialize(&data, "Alice", "alice@example.test", b"password", &recovery).unwrap();
    validate_profile(&local.profile, &local.profile.identity).unwrap();
    assert_eq!(
        local.profile.id(),
        hex::encode(local.profile.identity.signing_key)
    );
    assert_eq!(
        local.profile.frame_id(),
        hex::encode(local.frame.public().signing_key)
    );
    assert_eq!(
        local.profile.noise_public,
        comb_guard::static_public(&local.noise_private)
    );
    assert_eq!(local.token.len(), 64);
    let loaded = load(&data, b"password").unwrap();
    assert_eq!(loaded.token, local.token);
    assert_eq!(loaded.frame.public(), local.frame.public());
    assert!(load(&data, b"wrong").is_err());
    assert!(load_root(&data, b"wrong").is_err());
    assert!(initialize(&data, "Overwrite", "bad", b"password", &recovery).is_err());
    assert_eq!(load(&data, b"password").unwrap().profile.name, "Alice");
    for entry in fs::read_dir(&data).unwrap() {
        let path = entry.unwrap().path();
        let bytes = fs::read(&path).unwrap();
        assert!(
            !bytes
                .windows(local.token.len())
                .any(|b| b == local.token.as_bytes())
        );
        let noise_json = serde_json::to_vec(&*local.noise_private).unwrap();
        assert!(!bytes.windows(noise_json.len()).any(|b| b == noise_json));
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    assert_eq!(
        fs::metadata(data).unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn enrollment_pins_identity_and_binds_every_profile_field() {
    let tmp = tempfile::tempdir().unwrap();
    let a = tmp.path().join("a");
    let b = tmp.path().join("b");
    let local = initialize(&a, "Alice", "a@b", b"a", &tmp.path().join("recovery")).unwrap();
    let request = prepare_enrollment(&b, b"b").unwrap();
    assert!(prepare_enrollment(&b, b"b").is_err());
    let grant = authorize(&a, b"a", &request).unwrap();
    assert!(complete_enrollment(&b, b"b", &grant, &IdentitySecrets::generate().public()).is_err());
    let mut tampered = grant.clone();
    tampered.noise_public[0] ^= 1;
    assert!(complete_enrollment(&b, b"b", &tampered, &local.profile.identity).is_err());
    tampered = grant.clone();
    tampered.nonce.push('x');
    assert!(complete_enrollment(&b, b"b", &tampered, &local.profile.identity).is_err());
    // Even a valid root-signed grant for substituted pending keys must fail.
    let mut substituted = request.clone();
    substituted.noise_public = local.profile.noise_public;
    let substituted_grant = authorize(&a, b"a", &substituted).unwrap();
    assert!(complete_enrollment(&b, b"b", &substituted_grant, &local.profile.identity).is_err());
    substituted = request.clone();
    substituted.frame = local.frame.public();
    let substituted_grant = authorize(&a, b"a", &substituted).unwrap();
    assert!(complete_enrollment(&b, b"b", &substituted_grant, &local.profile.identity).is_err());
    assert!(complete_enrollment(&b, b"wrong", &grant, &local.profile.identity).is_err());
    let enrolled = complete_enrollment(&b, b"b", &grant, &local.profile.identity).unwrap();
    assert_eq!(local.profile.id(), enrolled.profile.id());
    assert_ne!(local.profile.frame_id(), enrolled.profile.frame_id());
    assert_ne!(local.profile.noise_public, enrolled.profile.noise_public);
    assert_ne!(local.token, enrolled.token);
    assert!(load_root(&b, b"b").is_err());
    let mut profile = enrolled.profile.clone();
    profile.name.push('x');
    assert!(validate_profile(&profile, &local.profile.identity).is_err());
    profile = enrolled.profile.clone();
    profile.email.push('x');
    assert!(validate_profile(&profile, &local.profile.identity).is_err());
    assert!(complete_enrollment(&b, b"b", &grant, &local.profile.identity).is_err());
}

#[test]
fn recovery_restores_offline_authority_not_old_device_keys() {
    let tmp = tempfile::tempdir().unwrap();
    let old = tmp.path().join("old");
    let new = tmp.path().join("new");
    let recovery = tmp.path().join("recovery");
    let original = initialize(&old, "Alice", "a@b", b"old", &recovery).unwrap();
    let identity = original.profile.identity.clone();
    let frame = original.frame.public();
    let noise = original.profile.noise_public;
    let snapshot = seal_snapshot(b"historic content", &[identity.recovery_key], b"backup").unwrap();
    drop(original);
    assert!(recover(&new, b"new", &recovery, b"wrong").is_err());
    let restored = recover(&new, b"new", &recovery, b"old").unwrap();
    assert_eq!(identity, restored.profile.identity);
    assert_ne!(frame, restored.frame.public());
    assert_ne!(noise, restored.profile.noise_public);
    assert!(open_snapshot(&snapshot, &restored.frame.recipient_secret(), b"backup").is_err());
    let root = load_root(&new, b"new").unwrap();
    assert_eq!(
        &*open_snapshot(&snapshot, &root.recovery_secret(), b"backup").unwrap(),
        b"historic content"
    );
}

#[test]
fn filesystem_helpers_reject_symlinks_and_replace_atomically() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("target");
    private_directory(&target).unwrap();
    let link = tmp.path().join("link");
    symlink(&target, &link).unwrap();
    assert!(private_directory(&link).is_err());
    assert!(initialize(&link, "A", "B", b"p", &tmp.path().join("r")).is_err());
    atomic_write(&target.join("state"), b"first").unwrap();
    atomic_write(&target.join("state"), b"second").unwrap();
    assert_eq!(fs::read(target.join("state")).unwrap(), b"second");
    symlink(target.join("state"), target.join("alias")).unwrap();
    assert!(atomic_write(&target.join("alias"), b"bad").is_err());
    assert!(atomic_write(&link.join("state"), b"bad").is_err());
    assert_eq!(fs::read(target.join("state")).unwrap(), b"second");
}
