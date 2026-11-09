//! Real Git objects, not filesystem fixtures pretending to be repository data.
use comb_frame::git::GitRepository;
use std::{path::Path, process::Command};

fn git(work: &Path, args: &[&str]) -> String {
    let result = Command::new("git")
        .current_dir(work)
        .env("GIT_AUTHOR_NAME", "Browser Fixture")
        .env("GIT_AUTHOR_EMAIL", "browser@test")
        .env("GIT_COMMITTER_NAME", "Browser Fixture")
        .env("GIT_COMMITTER_EMAIL", "browser@test")
        .args(args)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    String::from_utf8_lossy(&result.stdout).trim().to_owned()
}

#[test]
fn committed_browser_reads_text_and_bounds_binary_large_and_special_entries() {
    let directory = tempfile::tempdir().unwrap();
    let work = directory.path().join("work");
    std::fs::create_dir(&work).unwrap();
    git(&work, &["init", "--initial-branch=main"]);
    std::fs::create_dir(work.join("src")).unwrap();
    std::fs::write(work.join("README.md"), "# Hello\n\n**Read me**\n").unwrap();
    std::fs::write(work.join("src/main.rs"), "fn main() {}\n").unwrap();
    std::fs::write(work.join("image.bin"), b"a\0b").unwrap();
    std::fs::write(work.join("large.txt"), vec![b'a'; 1024 * 1024 + 1]).unwrap();
    std::fs::write(work.join("[literal].txt"), "literal pathspec").unwrap();
    std::os::unix::fs::symlink("/etc/passwd", work.join("outside")).unwrap();
    git(&work, &["add", "."]);
    git(&work, &["commit", "-m", "browser fixtures"]);
    let commit = git(&work, &["rev-parse", "HEAD"]);
    git(
        &work,
        &[
            "update-index",
            "--add",
            "--cacheinfo",
            &format!("160000,{commit},vendor"),
        ],
    );
    git(&work, &["commit", "-m", "submodule fixture"]);
    let repo = GitRepository::create(directory.path(), "remote").unwrap();
    git(&work, &["push", repo.path().to_str().unwrap(), "main"]);
    let root = repo.browse_tree("refs/heads/main", "").unwrap();
    assert_eq!(root.entries[0].name, "src");
    assert!(
        root.entries
            .iter()
            .any(|entry| entry.name == "outside" && entry.kind == "symlink")
    );
    assert!(
        root.entries
            .iter()
            .any(|entry| entry.name == "vendor" && entry.kind == "submodule")
    );
    let tree = repo
        .browse_tree(root.revision.as_ref().unwrap(), "src")
        .unwrap();
    assert_eq!(tree.entries[0].path, "src/main.rs");
    assert_eq!(
        repo.browse_blob("refs/heads/main", "README.md")
            .unwrap()
            .content
            .unwrap(),
        "# Hello\n\n**Read me**\n"
    );
    assert_eq!(
        repo.browse_blob("refs/heads/main", "[literal].txt")
            .unwrap()
            .content
            .unwrap(),
        "literal pathspec"
    );
    let binary = repo.browse_blob("refs/heads/main", "image.bin").unwrap();
    assert!(binary.binary && binary.content.is_none());
    let large = repo.browse_blob("refs/heads/main", "large.txt").unwrap();
    assert!(large.truncated && large.content.is_none());
    for path in [
        "outside",
        "vendor",
        "outside/anything",
        "../config",
        "/etc/passwd",
        "src/../README.md",
        "src//main.rs",
        "config",
        "src",
    ] {
        assert!(repo.browse_blob("refs/heads/main", path).is_err(), "{path}");
    }
    for revision in [
        "--help",
        "HEAD~1",
        "refs/comb/private",
        "refs/heads/main:README.md",
        "refs/heads/main^{tree}",
    ] {
        assert!(repo.browse_tree(revision, "").is_err(), "{revision}");
    }
    assert_eq!(
        repo.browse_blob(&commit, "README.md")
            .unwrap()
            .content
            .unwrap(),
        "# Hello\n\n**Read me**\n"
    );
}

#[test]
fn history_adapter_rejects_offsets_above_the_browsing_limit() {
    let directory = tempfile::tempdir().unwrap();
    let work = directory.path().join("work");
    std::fs::create_dir(&work).unwrap();
    git(&work, &["init", "--initial-branch=main"]);
    git(&work, &["commit", "--allow-empty", "-m", "root"]);
    let repo = GitRepository::create(directory.path(), "history").unwrap();
    git(&work, &["push", repo.path().to_str().unwrap(), "main"]);
    for offset in [10001, usize::MAX] {
        assert!(repo.browse_history("refs/heads/main", offset).is_err());
    }
    let page = repo.browse_history("refs/heads/main", 10000).unwrap();
    assert!(page.commits.is_empty() && !page.has_more && page.next_offset.is_none());
}

#[test]
fn history_preserves_merge_parents_and_rejects_oversized_output() {
    let directory = tempfile::tempdir().unwrap();
    let work = directory.path().join("work");
    std::fs::create_dir(&work).unwrap();
    git(&work, &["init", "--initial-branch=main"]);
    git(&work, &["commit", "--allow-empty", "-m", "root"]);
    let root = git(&work, &["rev-parse", "HEAD"]);
    git(&work, &["checkout", "-b", "feature"]);
    git(&work, &["commit", "--allow-empty", "-m", "feature"]);
    let feature = git(&work, &["rev-parse", "HEAD"]);
    git(&work, &["checkout", "main"]);
    git(&work, &["commit", "--allow-empty", "-m", "main"]);
    let main = git(&work, &["rev-parse", "HEAD"]);
    git(&work, &["merge", "--no-ff", "feature", "-m", "merge"]);
    let repo = GitRepository::create(directory.path(), "history").unwrap();
    git(&work, &["push", repo.path().to_str().unwrap(), "main"]);
    let history = repo.browse_history("refs/heads/main", 0).unwrap();
    assert_eq!(history.commits.len(), 4);
    assert_eq!(history.commits[0].subject, "merge");
    assert_eq!(history.commits[0].parents, vec![main, feature]);
    assert_eq!(history.commits[3].id, root);
    assert!(history.commits[3].parents.is_empty());
    std::fs::write(work.join("message"), "x".repeat(1024 * 1024 + 1)).unwrap();
    git(&work, &["commit", "--allow-empty", "-F", "message"]);
    git(&work, &["push", repo.path().to_str().unwrap(), "main"]);
    let error = repo.browse_history("refs/heads/main", 0).err().unwrap();
    assert!(error.to_string().contains("exceeds size limit"));
}
