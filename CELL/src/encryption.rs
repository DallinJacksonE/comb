//! Snapshot encryption and per-recipient data-key wrapping.
//! Context bytes are authenticated, not encrypted; callers select authorized recipients.
//! See `CELL/ENCRYPTION.md` for the version 1 format and key lifecycle.
use crate::{Error, FrameSecrets, IdentitySecrets, Result, encryption_public, message, random};
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Random 256-bit symmetric content key, zeroized on drop.
/// Its identifier is public; the key itself has no serialization or debug representation.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; 32]);
impl DataKey {
    /// Generate a fresh content key from OS entropy; panics if the RNG fails.
    pub fn generate() -> Self {
        Self(random())
    }
    /// Domain-separated SHA-256 identifier of the secret key; not an authorization proof.
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(message(b"data-key-id", &[&self.0])).into()
    }
}
/// X25519 recipient secret, zeroized on drop. Keep recovery recipients offline.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecipientSecret([u8; 32]);
/// Operations on independent X25519 recipient keys.
impl RecipientSecret {
    /// Generate an independent recipient secret from OS entropy; panics on RNG failure.
    pub fn generate() -> Self {
        Self(random())
    }
    /// Derive the public recipient key without exposing the secret.
    pub fn public(&self) -> [u8; 32] {
        encryption_public(&self.0)
    }
}
impl IdentitySecrets {
    /// Offline capability. Do not persist this on a routine FRAME.
    pub fn recovery_secret(&self) -> RecipientSecret {
        RecipientSecret(self.recovery)
    }
}
impl FrameSecrets {
    /// Copy the device recipient secret into a separately zeroizing owner.
    pub fn recipient_secret(&self) -> RecipientSecret {
        RecipientSecret(self.encryption)
    }
}
/// Versioned XChaCha20Poly1305 ciphertext; context must be supplied separately.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedData {
    /// Wire-format version; currently 1.
    pub version: u32,
    /// Random 24-byte XChaCha20Poly1305 nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
}
/// A content key encrypted for one X25519 recipient, bound to its public metadata.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyEnvelope {
    /// Wire-format version; currently 1.
    pub version: u32,
    /// Public X25519 key addressed by this envelope.
    pub recipient_key: [u8; 32],
    /// Fresh sender X25519 public key used for this wrapping operation.
    pub ephemeral_key: [u8; 32],
    /// Domain-separated SHA-256 identifier of the wrapped data key.
    pub key_id: [u8; 32],
    /// Random 24-byte XChaCha20Poly1305 nonce.
    pub nonce: [u8; 24],
    /// AEAD ciphertext including its authentication tag.
    pub ciphertext: Vec<u8>,
}
/// One encrypted payload plus independently generated recipient envelopes.
/// The envelope list is public and is not itself a signed manifest.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSnapshot {
    /// Encrypted snapshot payload.
    pub data: EncryptedData,
    /// Public per-recipient envelopes bound to this payload.
    pub envelopes: Vec<KeyEnvelope>,
}
/// Bind payload version, nonce, and caller context using the common binary encoding.
fn data_aad(data: &EncryptedData, context: &[u8]) -> Vec<u8> {
    message(
        b"encrypted-data",
        &[&data.version.to_be_bytes(), &data.nonce, context],
    )
}
/// Encrypt bytes with a fresh random nonce and authenticated context.
/// Prefer `seal_snapshot` when each version should receive a fresh content key.
pub fn encrypt_data(key: &DataKey, plaintext: &[u8], context: &[u8]) -> Result<EncryptedData> {
    let mut data = EncryptedData {
        version: 1,
        nonce: random(),
        ciphertext: Vec::new(),
    };
    data.ciphertext = XChaCha20Poly1305::new((&key.0).into())
        .encrypt(
            XNonce::from_slice(&data.nonce),
            Payload {
                msg: plaintext,
                aad: &data_aad(&data, context),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(data)
}
/// Authenticate and decrypt with the exact original key and context.
/// Unsupported versions return `Error::Format`; mismatches return `Error::Authentication`.
pub fn decrypt_data(
    key: &DataKey,
    data: &EncryptedData,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if data.version != 1 {
        return Err(Error::Format);
    }
    let plaintext = XChaCha20Poly1305::new((&key.0).into())
        .decrypt(
            XNonce::from_slice(&data.nonce),
            Payload {
                msg: &data.ciphertext,
                aad: &data_aad(data, context),
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(Zeroizing::new(plaintext))
}
/// Bind all public envelope fields and caller context to both HKDF and AEAD.
fn envelope_aad(envelope: &KeyEnvelope, context: &[u8]) -> Vec<u8> {
    message(
        b"recipient-envelope",
        &[
            &envelope.version.to_be_bytes(),
            &envelope.recipient_key,
            &envelope.ephemeral_key,
            &envelope.key_id,
            &envelope.nonce,
            context,
        ],
    )
}
/// Derive a wrapping key from contributory X25519 DH and the complete envelope AAD.
fn wrapping_key(
    secret: &StaticSecret,
    public: &[u8; 32],
    aad: &[u8],
) -> Result<Zeroizing<[u8; 32]>> {
    let shared = secret.diffie_hellman(&PublicKey::from(*public));
    if !shared.was_contributory() {
        return Err(Error::Authentication);
    }
    let mut key = Zeroizing::new([0; 32]);
    Hkdf::<Sha256>::new(Some(b"COMB-CELL-X25519-HKDF-SHA256-v1"), shared.as_bytes())
        .expand(aad, key.as_mut())
        .map_err(|_| Error::Format)?;
    Ok(key)
}
/// Wrap a data key using fresh ephemeral X25519 material and a random nonce.
/// Rejects non-contributory DH; the caller must authorize the supplied recipient.
pub fn wrap_key(key: &DataKey, recipient_key: &[u8; 32], context: &[u8]) -> Result<KeyEnvelope> {
    let ephemeral = StaticSecret::random_from_rng(rand::rngs::OsRng);
    let mut envelope = KeyEnvelope {
        version: 1,
        recipient_key: *recipient_key,
        ephemeral_key: PublicKey::from(&ephemeral).to_bytes(),
        key_id: key.id(),
        nonce: random(),
        ciphertext: Vec::new(),
    };
    let aad = envelope_aad(&envelope, context);
    let wrapping = wrapping_key(&ephemeral, recipient_key, &aad)?;
    envelope.ciphertext = XChaCha20Poly1305::new((&*wrapping).into())
        .encrypt(
            XNonce::from_slice(&envelope.nonce),
            Payload {
                msg: &key.0,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Authentication)?;
    Ok(envelope)
}
/// Authenticate an envelope, recover its 32-byte key, and verify the key identifier.
/// Requires the addressed recipient secret and the exact original context.
pub fn unwrap_key(
    envelope: &KeyEnvelope,
    recipient: &RecipientSecret,
    context: &[u8],
) -> Result<DataKey> {
    if envelope.version != 1 {
        return Err(Error::Format);
    }
    if envelope.recipient_key != recipient.public() {
        return Err(Error::Authentication);
    }
    let aad = envelope_aad(envelope, context);
    let wrapping = wrapping_key(
        &StaticSecret::from(recipient.0),
        &envelope.ephemeral_key,
        &aad,
    )?;
    let bytes = Zeroizing::new(
        XChaCha20Poly1305::new((&*wrapping).into())
            .decrypt(
                XNonce::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Authentication)?,
    );
    let key = DataKey(bytes.as_slice().try_into().map_err(|_| Error::Format)?);
    if key.id() != envelope.key_id {
        return Err(Error::Authentication);
    }
    Ok(key)
}
/// Bind envelopes to this payload ciphertext hash, version, nonce, and caller context.
fn snapshot_context(data: &EncryptedData, context: &[u8]) -> Vec<u8> {
    let digest: [u8; 32] = Sha256::digest(&data.ciphertext).into();
    message(
        b"snapshot-key",
        &[&data.version.to_be_bytes(), &data.nonce, &digest, context],
    )
}
/// Fresh random data key per call. Recipients MUST come from validated policy.
/// Include the offline identity recovery public key explicitly for recoverable backups.
pub fn seal_snapshot(
    plaintext: &[u8],
    recipients: &[[u8; 32]],
    context: &[u8],
) -> Result<EncryptedSnapshot> {
    if recipients.is_empty() {
        return Err(Error::Format);
    }
    let key = DataKey::generate();
    let data = encrypt_data(&key, plaintext, context)?;
    let binding = snapshot_context(&data, context);
    let envelopes = recipients
        .iter()
        .map(|recipient| wrap_key(&key, recipient, &binding))
        .collect::<Result<Vec<_>>>()?;
    Ok(EncryptedSnapshot { data, envelopes })
}
/// Try every matching recipient envelope and return authenticated, zeroizing plaintext.
/// Added invalid envelopes cannot shadow a valid one. Missing recipients, wrong context,
/// and failed authentication return `Error::Authentication`; publisher identity is unchecked.
pub fn open_snapshot(
    snapshot: &EncryptedSnapshot,
    recipient: &RecipientSecret,
    context: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let binding = snapshot_context(&snapshot.data, context);
    // Try all matching envelopes: an attacker adding junk cannot shadow a valid one.
    for envelope in snapshot
        .envelopes
        .iter()
        .filter(|e| e.recipient_key == recipient.public())
    {
        if let Ok(key) = unwrap_key(envelope, recipient, &binding)
            && let Ok(plaintext) = decrypt_data(&key, &snapshot.data, context)
        {
            return Ok(plaintext);
        }
    }
    Err(Error::Authentication)
}
