//! Opaque, pre-encrypted blobs only. This module holds no decryption keys.
use crate::{Error, Result};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

pub struct BlobStore {
    root: PathBuf,
    max_blob_bytes: usize,
}
impl BlobStore {
    /// `root` must be service-owned and not writable by other users.
    pub fn open(root: impl AsRef<Path>, max_blob_bytes: usize) -> Result<Self> {
        if max_blob_bytes == 0 || max_blob_bytes == usize::MAX {
            return Err(Error::Invalid(
                "blob size limit must be positive and leave room for a sentinel byte",
            ));
        }
        fs::create_dir_all(root.as_ref())?;
        if !fs::symlink_metadata(root.as_ref())?.is_dir() {
            return Err(Error::Invalid("blob root must be a real directory"));
        }
        Ok(Self {
            root: fs::canonicalize(root)?,
            max_blob_bytes,
        })
    }
    /// The caller MUST encrypt/authenticate before calling; bytes cannot be classified as ciphertext.
    pub fn put_ciphertext(&self, ciphertext: &[u8]) -> Result<String> {
        if ciphertext.len() > self.max_blob_bytes {
            return Err(Error::Size);
        }
        let id = hex::encode(Sha256::digest(ciphertext));
        let mut temp = tempfile::NamedTempFile::new_in(&self.root)?;
        temp.write_all(ciphertext)?;
        temp.as_file().sync_all()?;
        match temp.persist_noclobber(self.root.join(&id)) {
            Ok(_) => {}
            Err(e) if e.error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.get(&id)?;
            }
            Err(e) => return Err(e.error.into()),
        }
        File::open(&self.root)?.sync_all()?;
        Ok(id)
    }
    pub fn get(&self, id: &str) -> Result<Vec<u8>> {
        if id.len() != 64
            || !id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid("expected lowercase SHA-256 identifier"));
        }
        let path = self.root.join(id);
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file() {
            return Err(Error::Invalid("blob must be a regular file"));
        }
        if meta.len() > self.max_blob_bytes as u64 {
            return Err(Error::Size);
        }
        let mut data = Vec::new();
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(Error::Invalid("blob must be a regular file"));
        }
        file.take(self.max_blob_bytes as u64 + 1)
            .read_to_end(&mut data)?;
        if data.len() > self.max_blob_bytes {
            return Err(Error::Size);
        }
        if hex::encode(Sha256::digest(&data)) != id {
            return Err(Error::Integrity);
        }
        Ok(data)
    }
}
