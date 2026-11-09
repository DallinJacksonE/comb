//! Parse the deliberately restricted SSH exec grammar without invoking a shell.
//! Parsing selects a service and repository name only; store policy authorizes it.
use anyhow::{Result, bail, ensure};

/// Validated pack-service request, not an executable client-provided command line.
#[derive(Debug)]
pub struct GitCommand {
    /// Select receive-pack for writes, upload-pack for reads.
    pub write: bool,
    /// ASCII slug/ID stripped of the optional leading slash and `.git` suffix.
    pub repository: String,
}

/// Deliberately a tiny grammar, not a shell parser: exactly one optional pair
/// of matching quotes around one ASCII slug/ID, with an optional .git suffix.
/// No escapes, expansion, whitespace in paths, options, or path components.
/// One leading slash is allowed for standard SSH URLs. For example,
/// `git-upload-pack '/demo.git'` selects a read of `demo`. Rejects non-UTF-8,
/// commands above 256 bytes, unknown services, and invalid names above 120 bytes.
pub fn parse(bytes: &[u8]) -> Result<GitCommand> {
    ensure!(bytes.len() <= 256, "oversized Git command");
    let input = std::str::from_utf8(bytes)?;
    let (write, path) = if let Some(path) = input.strip_prefix("git-upload-pack ") {
        (false, path)
    } else if let Some(path) = input.strip_prefix("git-receive-pack ") {
        (true, path)
    } else {
        bail!("only Git pack commands are allowed")
    };
    let path = match path.as_bytes().first() {
        Some(b'\'' | b'"') => {
            ensure!(
                path.len() >= 2 && path.as_bytes().last() == path.as_bytes().first(),
                "unmatched quotes"
            );
            &path[1..path.len() - 1]
        }
        _ => path,
    };
    let path = path.strip_prefix('/').unwrap_or(path);
    let path = path.strip_suffix(".git").unwrap_or(path);
    ensure!(
        !path.is_empty() && path.len() <= 120 && path.as_bytes()[0].is_ascii_alphanumeric(),
        "invalid repository"
    );
    ensure!(
        path.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
        "invalid repository"
    );
    Ok(GitCommand {
        write,
        repository: path.to_owned(),
    })
}
