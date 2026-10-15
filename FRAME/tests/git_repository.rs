use comb_frame::git::GitRepository;

#[test]
fn http_backend_advertises_a_real_git_remote() {
    let directory = tempfile::tempdir().unwrap();
    let repo = GitRepository::create(directory.path(), "remote").unwrap();
    let response = repo
        .http("GET", "info/refs", "service=git-upload-pack", "", &[])
        .unwrap();
    assert_eq!(response.status, 200);
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name.eq_ignore_ascii_case("content-type")
                && value.contains("git-upload-pack-advertisement"))
    );
    assert!(
        response
            .body
            .windows(b"git-upload-pack".len())
            .any(|chunk| chunk == b"git-upload-pack")
    );
}

#[test]
fn runtime_git_open_refuses_external_common_directory_control() {
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let output = std::process::Command::new("git")
        .args(["init", "--bare"])
        .arg(external.path())
        .output()
        .unwrap();
    assert!(output.status.success());
    let original = std::fs::read(external.path().join("config")).unwrap();
    let malicious = root.path().join("malicious.git");
    std::fs::create_dir(&malicious).unwrap();
    std::fs::write(malicious.join("HEAD"), b"ref: refs/heads/main\n").unwrap();
    std::fs::write(
        malicious.join("commondir"),
        external.path().to_string_lossy().as_bytes(),
    )
    .unwrap();
    assert!(GitRepository::open(root.path(), "malicious").is_err());
    assert_eq!(
        std::fs::read(external.path().join("config")).unwrap(),
        original
    );
}

#[test]
fn repository_ids_cannot_escape_the_runtime_directory() {
    let directory = tempfile::tempdir().unwrap();
    assert!(GitRepository::create(directory.path(), "../outside").is_err());
}

#[test]
fn initialized_remote_accepts_standard_git_push_and_exposes_refs() {
    let directory = tempfile::tempdir().unwrap();
    let repository = GitRepository::create(directory.path(), "repo").unwrap();
    assert!(repository.refs().unwrap().is_empty());
    let work = directory.path().join("work");
    let run = |args: &[&str]| {
        let output = std::process::Command::new("git")
            .args(args)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    };
    run(&["init", "--initial-branch=main", work.to_str().unwrap()]);
    std::fs::write(work.join("hello.txt"), "encrypted-backup-test-marker").unwrap();
    let work = work.to_str().unwrap();
    run(&["-C", work, "add", "."]);
    run(&[
        "-C",
        work,
        "-c",
        "user.name=Alice",
        "-c",
        "user.email=alice@test",
        "commit",
        "-m",
        "initial",
    ]);
    run(&[
        "-C",
        work,
        "push",
        repository.path().to_str().unwrap(),
        "main",
    ]);
    assert!(repository.refs().unwrap().contains_key("refs/heads/main"));
    let archive = comb_frame::archive::pack_directory(repository.path()).unwrap();
    let replica = GitRepository::create(directory.path(), "replica").unwrap();
    replica.merge_archive(&archive, "peer-one").unwrap();
    assert_eq!(
        replica.refs().unwrap().get("refs/heads/main"),
        repository.refs().unwrap().get("refs/heads/main")
    );
    let mut refs = repository.refs().unwrap();
    refs.insert("refs/heads/copied".into(), refs["refs/heads/main"].clone());
    replica.install_refs(&refs).unwrap();
    assert_eq!(replica.refs().unwrap(), refs);
    let bad = std::collections::BTreeMap::from([("refs/heads/evil".into(), "--help".into())]);
    assert!(replica.install_refs(&bad).is_err());
    let deletion = std::process::Command::new("git")
        .args([
            "-C",
            work,
            "push",
            replica.path().to_str().unwrap(),
            ":refs/heads/copied",
        ])
        .output()
        .unwrap();
    assert!(
        !deletion.status.success(),
        "unsupported ref deletion must be rejected, not falsely acknowledged and resurrected"
    );
}
