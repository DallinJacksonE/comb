use comb_guard::backup::BlobStore;
#[test]
fn durable_content_addressed_ciphertext() {
    let dir = tempfile::tempdir().unwrap();
    assert!(BlobStore::open(dir.path(), usize::MAX).is_err());
    let store = BlobStore::open(dir.path(), 1024).unwrap();
    let ciphertext = [0xa5; 100];
    let id = store.put_ciphertext(&ciphertext).unwrap();
    assert_eq!(id.len(), 64);
    assert_eq!(store.put_ciphertext(&ciphertext).unwrap(), id);
    drop(store);
    assert!(BlobStore::open(dir.path(), usize::MAX).is_err());
    let store = BlobStore::open(dir.path(), 1024).unwrap();
    assert_eq!(store.get(&id).unwrap(), ciphertext);
    assert!(store.get("../outside").is_err());
    assert!(store.get(&id.to_uppercase()).is_err());
    assert!(store.put_ciphertext(&[0; 1025]).is_err());
    std::fs::write(dir.path().join(&id), b"corrupted").unwrap();
    assert!(store.get(&id).is_err());
    assert!(store.put_ciphertext(&ciphertext).is_err());
}
#[cfg(unix)]
#[test]
fn rejects_symlink_blob() {
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::NamedTempFile::new().unwrap();
    let id = "0".repeat(64);
    std::os::unix::fs::symlink(external.path(), dir.path().join(&id)).unwrap();
    let store = BlobStore::open(dir.path(), 10).unwrap();
    assert!(store.get(&id).is_err());
}
