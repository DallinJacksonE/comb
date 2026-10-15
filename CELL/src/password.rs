use crate::{Error, FrameSecrets, IdentitySecrets, Result, message, random};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Version 1 fixes Argon2id v1.3 at 64 MiB, 3 passes, 1 lane, 32-byte output.
/// Untrusted files cannot request arbitrary KDF resources.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PasswordEnvelope {
    pub version: u32,
    pub salt: [u8; 16],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
fn key(password: &[u8], salt: &[u8; 16]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(65536, 3, 1, Some(32)).map_err(|_| Error::Format)?;
    let mut key = Zeroizing::new([0; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, key.as_mut())
        .map_err(|_| Error::Authentication)?;
    Ok(key)
}
fn aad(envelope: &PasswordEnvelope, context: &[u8]) -> Vec<u8> {
    message(
        b"password-envelope",
        &[
            &envelope.version.to_be_bytes(),
            &envelope.salt,
            &envelope.nonce,
            context,
        ],
    )
}
/// Encrypt arbitrary secret bytes; callers own password strength and password memory hygiene.
pub fn seal_secret(plaintext: &[u8], password: &[u8], context: &[u8]) -> Result<PasswordEnvelope> {
    let mut envelope = PasswordEnvelope {
        version: 1,
        salt: random(),
        nonce: random(),
        ciphertext: Vec::new(),
    };
    let key = key(password, &envelope.salt)?;
    envelope.ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: plaintext,
                aad: &aad(&envelope, context),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(envelope)
}
pub fn open_secret(
    envelope: &PasswordEnvelope,
    password: &[u8],
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if envelope.version != 1 {
        return Err(Error::Format);
    }
    let key = key(password, &envelope.salt)?;
    let plaintext = XChaCha20Poly1305::new((&*key).into())
        .decrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &envelope.ciphertext,
                aad: &aad(envelope, context),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}
impl IdentitySecrets {
    pub fn export_encrypted(&self, password: &[u8]) -> Result<PasswordEnvelope> {
        let mut bytes = Zeroizing::new([0; 64]);
        bytes[..32].copy_from_slice(&self.signing);
        bytes[32..].copy_from_slice(&self.recovery);
        seal_secret(&*bytes, password, b"identity-recovery-v1")
    }
    pub fn import_encrypted(envelope: &PasswordEnvelope, password: &[u8]) -> Result<Self> {
        let bytes = open_secret(envelope, password, b"identity-recovery-v1")?;
        if bytes.len() != 64 {
            return Err(Error::Format);
        }
        Ok(Self {
            signing: bytes[..32].try_into().map_err(|_| Error::Format)?,
            recovery: bytes[32..].try_into().map_err(|_| Error::Format)?,
        })
    }
}
impl FrameSecrets {
    /// Restores the SAME device key: use only for local persistence, never enrollment.
    pub fn export_encrypted(&self, password: &[u8]) -> Result<PasswordEnvelope> {
        let mut bytes = Zeroizing::new([0; 64]);
        bytes[..32].copy_from_slice(&self.signing);
        bytes[32..].copy_from_slice(&self.encryption);
        seal_secret(&*bytes, password, b"frame-local-v1")
    }
    pub fn import_encrypted(envelope: &PasswordEnvelope, password: &[u8]) -> Result<Self> {
        let bytes = open_secret(envelope, password, b"frame-local-v1")?;
        if bytes.len() != 64 {
            return Err(Error::Format);
        }
        Ok(Self {
            signing: bytes[..32].try_into().map_err(|_| Error::Format)?,
            encryption: bytes[32..].try_into().map_err(|_| Error::Format)?,
        })
    }
}
