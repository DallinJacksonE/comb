//! Bounded reads of committed Git objects. Never reads working-tree paths or executes filters.
//!
//! These reads do not authorize a principal or restrict objects to accepted refs;
//! the store must resolve visibility/reachability first. For example, pass a
//! store-approved `refs/heads/main` to `browse_tree(revision, "")`, then use the
//! returned commit ID and entry path for a stable blob read. Output is capped at
//! 1 MiB per command; directory listings also have a 2,000-entry cap.
use super::GitRepository;
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::{
    io::Read,
    process::{Command, Stdio},
};

const MAX_OUTPUT: usize = 1024 * 1024;
const MAX_ENTRIES: usize = 2000;

/// Commit metadata for history display, without signatures or message bodies.
#[derive(Serialize)]
pub struct RepositoryCommit {
    /// Full hexadecimal commit object ID.
    pub id: String,
    /// Parent object IDs in Git's recorded order.
    pub parents: Vec<String>,
    /// Untrusted author display name, not an authenticated FRAME identity.
    pub author: String,
    /// Git's strict ISO-8601 author timestamp, not a trusted server timestamp.
    pub authored_at: String,
    /// Untrusted one-line commit subject; consumers must escape for their UI.
    pub subject: String,
}

/// Bounded history page; store callers may represent an empty repository with no revision.
#[derive(Serialize)]
pub struct RepositoryHistory {
    /// Resolved commit ID anchoring this page, when a commit exists.
    pub revision: Option<String>,
    /// At most 30 newest-first topologically ordered commits.
    pub commits: Vec<RepositoryCommit>,
    /// Whether the single lookahead row found additional history.
    pub has_more: bool,
    /// Suggested offset for the next page, only when `has_more` is true.
    pub next_offset: Option<usize>,
}

/// One committed tree entry; symlinks and submodules are never dereferenced.
#[derive(Clone, Serialize)]
pub struct RepositoryEntry {
    /// UTF-8 entry name relative to its listed directory.
    pub name: String,
    /// Repository-relative path, not a filesystem path.
    pub path: String,
    /// One of `tree`, `blob`, `symlink`, or `submodule`.
    pub kind: String,
    /// Git-reported blob byte size; absent for trees and submodules.
    pub size: Option<u64>,
}
/// Nonrecursive directory listing, sorted with directories before other entries.
#[derive(Serialize)]
pub struct RepositoryTree {
    /// Resolved commit ID, or absent for a store-generated empty listing.
    pub revision: Option<String>,
    /// Listed repository-relative directory; empty string denotes the root.
    pub path: String,
    /// Entry metadata with no symlink targets or submodule contents.
    pub entries: Vec<RepositoryEntry>,
}
/// Regular-file preview; omitted content is not necessarily a binary file.
#[derive(Serialize)]
pub struct RepositoryBlob {
    /// Resolved commit ID anchoring the read.
    pub revision: String,
    /// Validated repository-relative regular-file path.
    pub path: String,
    /// Complete Git blob size, even when content is omitted.
    pub size: u64,
    /// Full UTF-8 text without NULs, present only for an in-limit text blob.
    pub content: Option<String>,
    /// True only after inspecting an in-limit blob with invalid UTF-8 or a NUL.
    pub binary: bool,
    /// True when size exceeds 1 MiB; no prefix is read or returned in that case.
    pub truncated: bool,
}
/// Public listing metadata paired with its object ID for subsequent internal reads.
struct Entry {
    item: RepositoryEntry,
    oid: String,
}

impl GitRepository {
    /// Newest-first topological history of a literal commit, with one lookahead row.
    /// Rejects offsets above 10,000, invalid revisions, non-UTF-8 metadata, and
    /// oversized/malformed Git output. Reachability authorization is the caller's job.
    pub fn browse_history(&self, revision: &str, offset: usize) -> Result<RepositoryHistory> {
        ensure!(offset <= 10000, "history offset exceeds 10000");
        let commit = self.browse_commit(revision)?;
        let bytes = self.browse_command(
            &[
                "log",
                "--topo-order",
                "--no-color",
                "--no-decorate",
                "--no-notes",
                "--no-show-signature",
                "--encoding=UTF-8",
                "-z",
                "--format=%H%x00%P%x00%an%x00%aI%x00%s",
                "--max-count=31",
                &format!("--skip={offset}"),
                &commit,
                "--",
            ],
            MAX_OUTPUT,
        )?;
        let text = std::str::from_utf8(&bytes).context("Git history must be UTF-8")?;
        let mut commits = Vec::new();
        if !text.is_empty() {
            let fields: Vec<_> = text
                .strip_suffix('\0')
                .context("invalid Git history record")?
                .split('\0')
                .collect();
            ensure!(
                fields.len() % 5 == 0 && fields.len() <= 31 * 5,
                "invalid Git history fields"
            );
            for row in fields.as_chunks::<5>().0 {
                let parents: Vec<String> = row[1].split_whitespace().map(str::to_owned).collect();
                ensure!(
                    is_oid(row[0]) && parents.iter().all(|parent| is_oid(parent)),
                    "invalid Git history object"
                );
                commits.push(RepositoryCommit {
                    id: row[0].into(),
                    parents,
                    author: row[2].into(),
                    authored_at: row[3].into(),
                    subject: row[4].into(),
                });
            }
        }
        let has_more = commits.len() > 30;
        commits.truncate(30);
        Ok(RepositoryHistory {
            revision: Some(commit),
            commits,
            has_more,
            next_offset: has_more.then_some(offset + 30),
        })
    }

    /// Resolve a literal branch/tag/object to a commit, without Git revision expressions.
    /// Accepts full 40/64-digit object IDs or qualified head/tag refs, peeling
    /// annotated tags. Rejects non-commit targets and unsupported expression syntax;
    /// does not check whether the object is visible to a given principal.
    pub fn browse_commit(&self, revision: &str) -> Result<String> {
        ensure!(
            is_oid(revision)
                || ((revision.starts_with("refs/heads/") || revision.starts_with("refs/tags/"))
                    && !revision.contains("..")
                    && !revision.contains("@{")
                    && !revision
                        .chars()
                        .any(|c| c.is_control()
                            || matches!(c, '^' | '~' | ':' | '\\' | '?' | '*' | '['))),
            "invalid repository revision"
        );
        let value = self.browse_command(
            &[
                "rev-parse",
                "--verify",
                "--end-of-options",
                &format!("{revision}^{{commit}}"),
            ],
            128,
        )?;
        let oid = std::str::from_utf8(&value)?.trim().to_owned();
        ensure!(is_oid(&oid), "invalid Git commit object");
        Ok(oid)
    }

    /// Check reachability from accepted tips, without exposing private managed refs.
    /// Both inputs must be full object IDs. Exit status 1 means not an ancestor;
    /// other command failures are errors, not negative authorization results.
    pub(crate) fn browse_is_ancestor(&self, commit: &str, tip: &str) -> Result<bool> {
        ensure!(is_oid(commit) && is_oid(tip), "invalid commit object");
        let status = Command::new("git")
            .arg("--no-replace-objects")
            .arg("--git-dir")
            .arg(&self.path)
            .args(["merge-base", "--is-ancestor", commit, tip])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;
        match status.code() {
            Some(0) => Ok(true),
            Some(1) => Ok(false),
            _ => bail!("cannot check Git commit reachability"),
        }
    }

    /// List a single committed directory. Symlinks/submodules are metadata only.
    /// Rejects invalid/missing/non-directory paths, non-UTF-8 names, unsupported
    /// modes, or listings over the byte/entry limits; never silently truncates.
    pub fn browse_tree(&self, revision: &str, path: &str) -> Result<RepositoryTree> {
        validate_path(path, true)?;
        let commit = self.browse_commit(revision)?;
        let tree = if path.is_empty() {
            commit.clone()
        } else {
            let entry = self.browse_entry(&commit, path)?;
            ensure!(entry.item.kind == "tree", "path is not a directory");
            entry.oid
        };
        let bytes = self.browse_command(&["ls-tree", "-z", "-l", &tree], MAX_OUTPUT)?;
        let mut entries = parse_entries(&bytes, path)?;
        ensure!(
            entries.len() <= MAX_ENTRIES,
            "directory exceeds browsing entry limit"
        );
        entries.sort_by(|a, b| {
            (a.item.kind != "tree", &a.item.name).cmp(&(b.item.kind != "tree", &b.item.name))
        });
        Ok(RepositoryTree {
            revision: Some(commit),
            path: path.to_owned(),
            entries: entries.into_iter().map(|entry| entry.item).collect(),
        })
    }

    /// Return UTF-8 text only up to the browsing limit; never follow Git symlinks.
    /// Oversized blobs return metadata with `truncated = true` and no content,
    /// rather than a prefix. In-limit binary blobs also omit content. Invalid
    /// paths, nonregular entries, Git failures, and size mismatches are errors.
    pub fn browse_blob(&self, revision: &str, path: &str) -> Result<RepositoryBlob> {
        validate_path(path, false)?;
        let commit = self.browse_commit(revision)?;
        let entry = self.browse_entry(&commit, path)?;
        ensure!(
            entry.item.kind == "blob",
            "path is not a regular file; symlinks and submodules are not followed"
        );
        let size = entry.item.size.context("missing Git blob size")?;
        let mut result = RepositoryBlob {
            revision: commit,
            path: path.to_owned(),
            size,
            content: None,
            binary: false,
            truncated: size > MAX_OUTPUT as u64,
        };
        if result.truncated {
            return Ok(result);
        }
        let bytes = self.browse_command(&["cat-file", "blob", &entry.oid], MAX_OUTPUT)?;
        ensure!(bytes.len() as u64 == size, "Git blob size mismatch");
        match String::from_utf8(bytes) {
            Ok(text) if !text.contains('\0') => result.content = Some(text),
            _ => result.binary = true,
        }
        Ok(result)
    }

    /// Read exactly one literal entry from a caller-validated commit/path pair.
    /// Rejects missing, multiple, differently named, or malformed output entries.
    fn browse_entry(&self, commit: &str, path: &str) -> Result<Entry> {
        let bytes =
            self.browse_command(&["ls-tree", "-z", "-l", commit, "--", path], MAX_OUTPUT)?;
        let mut entries = parse_entries(&bytes, "")?;
        ensure!(
            entries.len() == 1 && entries[0].item.path == path,
            "unknown repository path"
        );
        Ok(entries.remove(0))
    }

    /// Bound Git's stdout even for attacker-controlled tree names and blob sizes.
    /// Disables replacement objects and pathspec expansion, discards stderr, and
    /// kills/reaps the child on read failure or output overflow. No time deadline
    /// is imposed; arguments must come from internal fixed command templates.
    fn browse_command(&self, arguments: &[&str], limit: usize) -> Result<Vec<u8>> {
        let mut child = Command::new("git")
            .args(["--no-replace-objects", "--literal-pathspecs", "--git-dir"])
            .arg(&self.path)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("start repository browser Git read")?;
        let mut bytes = Vec::new();
        let read = child
            .stdout
            .take()
            .context("missing Git stdout")?
            .take(limit as u64 + 1)
            .read_to_end(&mut bytes);
        if read.is_err() || bytes.len() > limit {
            let _ = child.kill();
            let _ = child.wait();
            read?;
            bail!("repository browsing output exceeds size limit");
        }
        let status = child.wait()?;
        ensure!(status.success(), "unknown or unsupported repository object");
        Ok(bytes)
    }
}

/// Test full SHA-1/SHA-256 hexadecimal syntax, not object existence or type.
fn is_oid(value: &str) -> bool {
    matches!(value.len(), 40 | 64) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
/// Require a bounded relative slash-separated path without traversal or controls.
/// `root` additionally allows the empty root directory; no filesystem is consulted.
fn validate_path(path: &str, root: bool) -> Result<()> {
    if root && path.is_empty() {
        return Ok(());
    }
    ensure!(
        !path.is_empty()
            && path.len() <= 4096
            && !path.contains('\\')
            && !path.chars().any(char::is_control)
            && path
                .split('/')
                .all(|part| !part.is_empty() && part != "." && part != ".."),
        "invalid repository path"
    );
    Ok(())
}
/// Decode NUL-delimited `ls-tree -z -l` records and attach a listing parent path.
/// Rejects non-UTF-8 names, malformed IDs/sizes, and unsupported mode/type pairs;
/// leaves sorting, path validation, and entry-count enforcement to callers.
fn parse_entries(bytes: &[u8], parent: &str) -> Result<Vec<Entry>> {
    bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
        .map(|record| {
            let text = std::str::from_utf8(record)
                .context("repository filenames must be UTF-8 for browsing")?;
            let (header, name) = text.split_once('\t').context("invalid Git tree entry")?;
            let columns: Vec<_> = header.split_whitespace().collect();
            ensure!(
                columns.len() == 4 && is_oid(columns[2]),
                "invalid Git tree metadata"
            );
            let kind = match (columns[0], columns[1]) {
                ("040000", "tree") => "tree",
                ("100644" | "100755", "blob") => "blob",
                ("120000", "blob") => "symlink",
                ("160000", "commit") => "submodule",
                _ => bail!("unsupported Git entry mode"),
            };
            let size = if columns[3] == "-" {
                None
            } else {
                Some(columns[3].parse::<u64>()?)
            };
            let path = if parent.is_empty() {
                name.to_owned()
            } else {
                format!("{parent}/{name}")
            };
            Ok(Entry {
                item: RepositoryEntry {
                    name: name.to_owned(),
                    path,
                    kind: kind.into(),
                    size,
                },
                oid: columns[2].into(),
            })
        })
        .collect()
}
