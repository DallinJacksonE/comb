//! Standard Git repository operations. Never invokes a shell or accepts arbitrary paths.
use anyhow::{Context, Result, bail};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    process::Command,
};

/// Parsed Git CGI response, kept independent of the HTTP framework.
pub struct GitResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// A trusted, runtime-materialized bare repository owned by FRAME.
#[derive(Clone)]
pub struct GitRepository {
    path: PathBuf,
}

impl GitRepository {
    /// Initialize a remote with ordinary Git object/ref storage.
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
        Ok(repo)
    }

    /// Open an existing repository only under the caller's trusted runtime root.
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
        Ok(repo)
    }

    /// Runtime location for Git's own transport and snapshot adapter.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Read all branch/tag refs, preserving full ref names.
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

    /// Fetch validated snapshot objects; preserve divergent commits under stable conflict refs.
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
    pub(crate) fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        checked(
            Command::new("git")
                .arg("--git-dir")
                .arg(&self.path)
                .args(args),
        )
    }
}

pub(crate) fn validate_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > 80 || !id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        bail!("invalid repository identifier");
    }
    Ok(())
}

fn checked(command: &mut Command) -> Result<Vec<u8>> {
    let output = command.output().context("execute Git")?;
    if !output.status.success() {
        bail!("Git failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    Ok(output.stdout)
}
