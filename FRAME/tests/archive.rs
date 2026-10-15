use comb_frame::archive::{pack_directory, unpack_directory};

#[test]
fn snapshot_round_trips_bare_git_files_without_paths_escaping() {
    let source = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(source.path().join("refs/heads")).unwrap();
    std::fs::write(source.path().join("refs/heads/main"), b"private-git-object").unwrap();
    let archive = pack_directory(source.path()).unwrap();
    let target = tempfile::tempdir().unwrap();
    unpack_directory(&archive, target.path()).unwrap();
    assert_eq!(
        std::fs::read(target.path().join("refs/heads/main")).unwrap(),
        b"private-git-object"
    );
}

#[test]
fn incoming_archive_rejects_git_commondir_path_escape() {
    let outside = tempfile::tempdir().unwrap();
    let original = b"external config must not change";
    std::fs::write(outside.path().join("config"), original).unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    let bytes = outside.path().to_string_lossy().into_owned().into_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o600);
    header.set_cksum();
    builder
        .append_data(&mut header, "commondir", bytes.as_slice())
        .unwrap();
    let archive = builder.into_inner().unwrap();
    let target = tempfile::tempdir().unwrap();
    assert!(
        unpack_directory(&archive, target.path()).is_err(),
        "Git-native directory pointers must not enter the runtime cache"
    );
    assert_eq!(
        std::fs::read(outside.path().join("config")).unwrap(),
        original
    );
}

#[test]
fn incoming_archive_cannot_install_git_hooks_or_links() {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(4);
    header.set_mode(0o755);
    header.set_cksum();
    builder
        .append_data(&mut header, "hooks/post-receive", &b"evil"[..])
        .unwrap();
    let bytes = builder.into_inner().unwrap();
    let target = tempfile::tempdir().unwrap();
    assert!(unpack_directory(&bytes, target.path()).is_err());
    assert!(!target.path().join("hooks/post-receive").exists());
}
