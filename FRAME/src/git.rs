//! Standard Git operations on repositories under a caller-trusted runtime root.
//!
//! Commands use argument vectors, never a shell. This layer validates identifiers
//! and Git data, not CELL permissions: HTTP/SSH/store callers must authorize access
//! before invoking it. The runtime root and process environment are trusted;
//! these helpers are not a sandbox for arbitrary filesystem roots.
use anyhow::{Context, Result, bail};
mod browse;
pub use browse::{
    RepositoryBlob, RepositoryCommit, RepositoryEntry, RepositoryHistory, RepositoryTree,
};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

/// Parsed Git CGI response, kept independent of the HTTP framework.
pub struct GitResponse {
    /// CGI status code, defaulting to 200 when Git omits `Status`.
    pub status: u16,
    /// Backend headers other than `Status`, in emitted order.
    pub headers: Vec<(String, String)>,
    /// Unmodified binary Git response body.
    pub body: Vec<u8>,
}

/// A trusted, runtime-materialized bare repository owned by FRAME.
#[derive(Clone)]
pub struct GitRepository {
    /// Materialized bare repository; callers own its lifetime and synchronization.
    path: PathBuf,
}

impl GitRepository {
    /// Initialize a remote with ordinary Git object/ref storage.
    ///
    /// Creates the root and runs `git init`, then configures receive integrity,
    /// no-deletion/non-fast-forward policy and hidden managed refs. Existing paths
    /// are refused; I/O/Git failures can leave a partially configured repository.
    pub fn create(root: &Path, id: &str) -> Result<Self> {
        validate_id(id)?;
        std::fs::create_dir_all(root)?;
        let path = root.join(format!("{id}.git"));
        if path.exists() {
            bail!("repository already exists");
        }
        checked(
            Command::new("git")
                .args(["init", "--bare", "--initial-branch=main"])
                .arg(&path),
        )?;
        let repo = Self { path };
        repo.run(&["config", "http.receivepack", "true"])?;
        repo.run(&["config", "receive.denyNonFastForwards", "true"])?;
        repo.run(&["config", "receive.denyDeletes", "true"])?;
        repo.run(&["config", "receive.fsckObjects", "true"])?;
        repo.run(&["config", "transfer.fsckObjects", "true"])?;
        repo.run(&["config", "receive.hideRefs", "refs/comb/"])?;
        Ok(repo)
    }

    /// Open an existing repository only under the caller's trusted runtime root.
    ///
    /// This is mutating: resets HEAD to `main`, restores empty object/ref directories,
    /// and reapplies local receive policy with hooks disabled. Rejects selected
    /// external-pointer files and symlinks, but does not recursively sandbox the
    /// root or validate every object; use `validate_objects` for integrity checks.
    pub fn open(root: &Path, id: &str) -> Result<Self> {
        validate_id(id)?;
        let path = root.join(format!("{id}.git"));
        if !path.join("HEAD").is_file() {
            bail!("repository does not exist");
        }
        for control in [
            "commondir",
            "gitdir",
            ".git",
            "objects/info/alternates",
            "objects/info/http-alternates",
        ] {
            if path.join(control).try_exists()? {
                bail!("external Git directory/object pointers are forbidden");
            }
        }
        for entry in [
            &path,
            &path.join("HEAD"),
            &path.join("objects"),
            &path.join("refs"),
        ] {
            if entry.is_symlink() {
                bail!("runtime Git symlink refused");
            }
        }
        // The prototype's default branch is local policy, never an archive-controlled pointer.
        std::fs::write(path.join("HEAD"), b"ref: refs/heads/main\n")?;
        // Empty Git directories have no tar entries; restore their required structure.
        std::fs::create_dir_all(path.join("objects"))?;
        std::fs::create_dir_all(path.join("refs"))?;
        let repo = Self { path };
        repo.run(&["config", "http.receivepack", "true"])?;
        repo.run(&["config", "receive.denyNonFastForwards", "true"])?;
        repo.run(&["config", "receive.denyDeletes", "true"])?;
        repo.run(&["config", "receive.fsckObjects", "true"])?;
        repo.run(&["config", "fetch.fsckObjects", "true"])?;
        repo.run(&["config", "core.hooksPath", "/dev/null"])?;
        repo.run(&["config", "receive.hideRefs", "refs/comb/"])?;
        Ok(repo)
    }

    /// Runtime location for Git's own transport and snapshot adapter.
    /// The returned path conveys no independent authorization or lifetime lease.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read all refs, including notes, custom namespaces, and retained divergence.
    /// Returns Git/UTF-8/parse errors; does not filter refs for an external audience.
    pub fn refs(&self) -> Result<BTreeMap<String, String>> {
        let output = self.run(&["for-each-ref", "--format=%(refname) %(objectname)"])?;
        String::from_utf8(output)?
            .lines()
            .map(|line| {
                let (name, hash) = line.split_once(' ').context("invalid Git ref output")?;
                Ok((name.to_owned(), hash.to_owned()))
            })
            .collect()
    }

    /// Check object hashes, structure, and graph connectivity, not merely ref tips.
    /// Include retained/unreachable objects; never trust replacement refs as repairs.
    pub(crate) fn validate_objects(&self) -> Result<()> {
        self.run(&[
            "--no-replace-objects",
            "fsck",
            "--full",
            "--strict",
            "--no-reflogs",
            "--no-dangling",
        ])
        .context("Git repository object integrity check failed")?;
        Ok(())
    }

    /// Fetch validated snapshot objects; preserve divergent commits under stable conflict refs.
    ///
    /// Unpacks into a temporary repository and fetches into managed transfer refs.
    /// New branch/tag tips are installed, fast-forwards advance, and other tips
    /// are retained under `refs/comb/conflicts/<hash>`. Callers must validate and
    /// authorize the snapshot separately; `namespace` is validated but is not used
    /// to name conflict refs. Failures may leave objects or partially updated refs.
    pub fn merge_archive(&self, bytes: &[u8], namespace: &str) -> Result<()> {
        validate_id(namespace)?;
        let temp = tempfile::Builder::new().prefix("comb-import-").tempdir()?;
        let incoming_path = temp.path().join("incoming.git");
        crate::archive::unpack_directory(bytes, &incoming_path)?;
        let incoming = Self::open(temp.path(), "incoming")?;
        let refs = incoming.refs()?;
        if refs.is_empty() {
            return Ok(());
        }
        let path = incoming_path.to_str().context("non-UTF8 runtime path")?;
        self.run(&[
            "-c",
            "protocol.file.allow=always",
            "fetch",
            "--no-write-fetch-head",
            "--no-tags",
            path,
            "+refs/*:refs/comb/transfer/*",
        ])?;
        for (name, hash) in refs {
            let current = self.refs()?;
            if name.starts_with("refs/heads/") || name.starts_with("refs/tags/") {
                match current.get(&name) {
                    None => {
                        self.run(&["update-ref", &name, &hash])?;
                    }
                    Some(old) if old == &hash => {}
                    Some(old) => {
                        let ancestor = Command::new("git")
                            .arg("--git-dir")
                            .arg(&self.path)
                            .args(["merge-base", "--is-ancestor", old, &hash])
                            .status()?;
                        if ancestor.success() {
                            self.run(&["update-ref", &name, &hash, old])?;
                        } else {
                            self.run(&[
                                "update-ref",
                                &format!("refs/comb/conflicts/{hash}"),
                                &hash,
                            ])?;
                        }
                    }
                }
            } else {
                self.run(&["update-ref", &format!("refs/comb/conflicts/{hash}"), &hash])?;
            }
        }
        for name in self
            .refs()?
            .keys()
            .filter(|r| r.starts_with("refs/comb/transfer/"))
        {
            self.run(&["update-ref", "-d", name])?;
        }
        Ok(())
    }

    /// Set advertised refs to validated accepted metadata, not raw incoming archive refs.
    ///
    /// Checks names, hash syntax, and object existence before deleting absent refs
    /// and installing supplied ones. Does not verify signatures or CELL policy;
    /// updates are sequential and a Git failure may leave a partial ref set.
    pub fn install_refs(&self, refs: &BTreeMap<String, String>) -> Result<()> {
        for (name, hash) in refs {
            if !name.starts_with("refs/")
                || !matches!(hash.len(), 40 | 64)
                || !hash.bytes().all(|b| b.is_ascii_hexdigit())
            {
                bail!("invalid signed Git reference");
            }
            self.run(&["check-ref-format", name])?;
            self.run(&["cat-file", "-e", hash])?;
        }
        for name in self.refs()?.keys().filter(|name| !refs.contains_key(*name)) {
            self.run(&["update-ref", "-d", name])?;
        }
        for (name, hash) in refs {
            self.run(&["update-ref", name, hash])?;
        }
        Ok(())
    }

    /// Serve only Git's smart HTTP endpoints through the canonical Git backend.
    ///
    /// Accepts GET `info/refs` and POST pack endpoints, passing query/content type
    /// and binary body to `git http-backend`. The caller must authorize reads or
    /// writes first and persist/sign successful mutations afterward. `REMOTE_USER`
    /// is a fixed backend marker, not client authentication. Buffers the full
    /// request/reply; process, pipe, UTF-8 header, and malformed CGI errors propagate.
    pub fn http(
        &self,
        method: &str,
        suffix: &str,
        query: &str,
        content_type: &str,
        body: &[u8],
    ) -> Result<GitResponse> {
        use std::{io::Write, process::Stdio};
        if !matches!(
            (method, suffix),
            ("GET", "info/refs") | ("POST", "git-upload-pack") | ("POST", "git-receive-pack")
        ) {
            bail!("unsupported Git endpoint");
        }
        let root = self.path.parent().context("missing Git runtime root")?;
        let name = self
            .path
            .file_name()
            .context("missing repository name")?
            .to_string_lossy();
        let mut child = Command::new("git")
            .arg("http-backend")
            .env("GIT_PROJECT_ROOT", root)
            .env("GIT_HTTP_EXPORT_ALL", "1")
            .env("PATH_INFO", format!("/{name}/{suffix}"))
            .env("REQUEST_METHOD", method)
            .env("QUERY_STRING", query)
            .env("CONTENT_TYPE", content_type)
            .env("CONTENT_LENGTH", body.len().to_string())
            .env("REMOTE_USER", "comb")
            .env("REMOTE_ADDR", "127.0.0.1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        // A separate writer avoids pipe deadlock while Git produces its output.
        let mut input = child.stdin.take().context("Git stdin unavailable")?;
        let data = body.to_vec();
        let writer = std::thread::spawn(move || input.write_all(&data));
        let output = child.wait_with_output()?;
        writer
            .join()
            .map_err(|_| anyhow::anyhow!("Git input writer panicked"))??;
        if !output.status.success() {
            bail!(
                "Git HTTP failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        let separator = output
            .stdout
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .context("invalid Git CGI response")?;
        let mut status = 200;
        let mut headers = Vec::new();
        for line in std::str::from_utf8(&output.stdout[..separator])?.split("\r\n") {
            let (name, value) = line.split_once(':').context("invalid Git CGI header")?;
            if name.eq_ignore_ascii_case("status") {
                status = value
                    .split_whitespace()
                    .next()
                    .context("missing Git status")?
                    .parse()?;
            } else {
                headers.push((name.to_owned(), value.trim().to_owned()));
            }
        }
        Ok(GitResponse {
            status,
            headers,
            body: output.stdout[separator + 4..].to_vec(),
        })
    }

    /// Execute a fixed Git argument vector against this repository.
    /// Returns stdout or an execution/nonzero-exit error containing stderr.
    /// Internal callers must constrain arguments; this is not a user command API.
    pub(crate) fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        checked(
            Command::new("git")
                .arg("--git-dir")
                .arg(&self.path)
                .args(args),
        )
    }
}

/// Accept 1–80 ASCII alphanumeric/hyphen bytes for a single repository basename.
/// Rejects separators and traversal; does not establish that a CELL exists.
pub(crate) fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 80 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("invalid repository identifier");
    }
    Ok(())
}

/// Run a prepared command, buffering stdout/stderr and rejecting nonzero status.
/// Inherits the configured/default environment; imposes no output or time limit.
fn checked(command: &mut Command) -> Result<Vec<u8>> {
    let output = command.output().context("execute Git")?;
    if !output.status.success() {
        bail!("Git failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(output.stdout)
}
