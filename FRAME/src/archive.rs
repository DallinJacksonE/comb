//! Bounded, allowlisted tar transport for bare Git storage.
//!
//! Archives carry objects and refs, never Git configuration or hooks. This is a
//! filesystem boundary, not proof of object integrity or signed-ref consistency:
//! callers must also validate the extracted repository against accepted CELL data.
use anyhow::{Result, bail};
use std::{
    io::Cursor,
    path::{Component, Path},
};

/// Maximum encoded tar size and maximum sum of declared extracted file sizes.
pub const MAX_SNAPSHOT_BYTES: u64 = 32 * 1024 * 1024;

/// Archive Git storage, excluding local executable hooks and host-specific configuration.
///
/// Reads `root` without modifying it. Non-regular entries encountered while
/// walking allowed directories, I/O errors, and oversized output are errors.
/// The output-size check occurs after building the archive in memory.
pub fn pack_directory(root: &Path) -> Result<Vec<u8>> {
    let mut builder = tar::Builder::new(Vec::new());
    append_files(&mut builder, root, root)?;
    let bytes = builder.into_inner()?;
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("snapshot exceeds size limit");
    }
    Ok(bytes)
}

/// Walk objects/refs beneath `root`, appending only allowlisted regular files.
/// Symlinks and other special entries encountered by the walk are rejected.
fn append_files(builder: &mut tar::Builder<Vec<u8>>, root: &Path, dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let relative = path.strip_prefix(root)?;
        let kind = entry.file_type()?;
        if kind.is_dir() {
            if relative.starts_with("objects") || relative.starts_with("refs") {
                append_files(builder, root, &path)?;
            }
        } else if kind.is_file() {
            if allowed(relative) {
                builder.append_path_with_name(&path, relative)?;
            }
        } else {
            bail!("snapshot contains non-regular file");
        }
    }
    Ok(())
}

/// Accept only normal UTF-8 components naming HEAD, packed refs, loose refs,
/// loose objects, or recognized pack sidecars; never config, hooks, or alternates.
fn allowed(path: &Path) -> bool {
    let Some(parts) = path
        .components()
        .map(|part| match part {
            Component::Normal(name) => name.to_str(),
            _ => None,
        })
        .collect::<Option<Vec<_>>>()
    else {
        return false;
    };
    match parts.as_slice() {
        ["HEAD"] | ["packed-refs"] => true,
        // Git accepts notes and custom namespaces as well as heads/tags. Preserve
        // every loose ref just as packed-refs does, without admitting config/hooks.
        ["refs", _, rest @ ..] if !rest.is_empty() => true,
        ["objects", directory, name]
            if directory.len() == 2 && directory.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            matches!(name.len(), 38 | 62) && name.bytes().all(|b| b.is_ascii_hexdigit())
        }
        ["objects", "pack", name] => name
            .strip_prefix("pack-")
            .and_then(|s| s.rsplit_once('.'))
            .is_some_and(|(hash, extension)| {
                matches!(hash.len(), 40 | 64)
                    && hash.bytes().all(|b| b.is_ascii_hexdigit())
                    && matches!(extension, "pack" | "idx" | "rev" | "bitmap")
            }),
        _ => false,
    }
}

/// Validate the entire archive before extracting into a caller-controlled directory.
///
/// Rejects disallowed paths, links/special files, excessive entry counts, and
/// encoded or expanded sizes above [`MAX_SNAPSHOT_BYTES`]. The caller must supply
/// a trusted, preferably fresh directory with no hostile existing links: this
/// function creates missing directories but does not require an empty target.
/// Validation errors precede extraction; extraction I/O errors can leave partial
/// output. No signature, Git object, or signed-ref verification is performed here.
pub fn unpack_directory(bytes: &[u8], root: &Path) -> Result<()> {
    if bytes.len() as u64 > MAX_SNAPSHOT_BYTES {
        bail!("snapshot exceeds size limit");
    }
    let mut total = 0u64;
    for (index, entry) in tar::Archive::new(Cursor::new(bytes)).entries()?.enumerate() {
        let entry = entry?;
        let path = entry.path()?;
        if index > 100_000 || !allowed(&path) || !entry.header().entry_type().is_file() {
            bail!("unsafe repository archive entry");
        }
        total = total
            .checked_add(entry.size())
            .ok_or_else(|| anyhow::anyhow!("snapshot size overflow"))?;
        if total > MAX_SNAPSHOT_BYTES {
            bail!("expanded snapshot exceeds size limit");
        }
    }
    std::fs::create_dir_all(root)?;
    for entry in tar::Archive::new(Cursor::new(bytes)).entries()? {
        if !entry?.unpack_in(root)? {
            bail!("archive escaped target");
        }
    }
    Ok(())
}
