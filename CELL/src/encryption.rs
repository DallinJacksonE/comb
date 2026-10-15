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

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataKey([u8; 32]);
impl DataKey {
    pub fn generate() -> Self {
        Self(random())
    }
    pub fn id(&self) -> [u8; 32] {
        Sha256::digest(message(b"data-key-id", &[&self.0])).into()
    }
}
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecipientSecret([u8; 32]);
impl RecipientSecret {
    pub fn generate() -> Self {
        Self(random())
    }
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
    pub fn recipient_secret(&self) -> RecipientSecret {
        RecipientSecret(self.encryption)
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedData {
    pub version: u32,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyEnvelope {
    pub version: u32,
    pub recipient_key: [u8; 32],
    pub ephemeral_key: [u8; 32],
    pub key_id: [u8; 32],
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedSnapshot {
    pub data: EncryptedData,
    pub envelopes: Vec<KeyEnvelope>,
}
fn data_aad(data: &EncryptedData, context: &[u8]) -> Vec<u8> {
    message(
        b"encrypted-data",
        &[&data.version.to_be_bytes(), &data.nonce, context],
    )
}
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
