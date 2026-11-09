#![doc = include_str!("../README.md")]
//! The [`domain`] module adds the signed metadata DAG described in `CELL/DOMAIN.md`;
//! the README's primitive-only limitations do not describe that higher-level module.
//! Deserialization never establishes trust: pin identities externally, verify signatures,
//! enforce operation-specific policy, and bound untrusted input sizes before parsing.
#![forbid(unsafe_code)]
pub mod domain;
mod encryption;
pub use encryption::{
    DataKey, EncryptedData, EncryptedSnapshot, KeyEnvelope, RecipientSecret, decrypt_data,
    encrypt_data, open_snapshot, seal_snapshot, unwrap_key, wrap_key,
};
mod record;
pub use record::SignedRecord;
mod password;
pub use password::{PasswordEnvelope, open_secret, seal_secret};

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Failure to authenticate, interpret, or serialize CELL data.
/// Authentication groups wrong secrets, tampering, and policy failures; it does not
/// identify which credential or field was wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid signature, wrong secret/context, rejected key binding, or denied authority.
    #[error("authentication failed")]
    Authentication,
    /// Unsupported version, malformed structure, or violated format constraint.
    #[error("invalid or unsupported format")]
    Format,
    /// JSON encoding or decoding failed, including rejected unknown fields.
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}
/// Standard result for cryptographic primitives and signed metadata operations.
pub type Result<T> = std::result::Result<T, Error>;

/// Fill a fixed-size buffer from the operating system's cryptographic RNG.
///
/// # Panics
/// Panics if `OsRng` cannot obtain entropy; there is no weak-randomness fallback.
fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Length-delimited, domain-separated binary encoding, independent of JSON.
/// Prefixes `COMB-CELL-v1`, then the domain and each field with a big-endian
/// 64-bit byte length. Callers must use a distinct domain for each protocol role.
fn message(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes = b"COMB-CELL-v1".to_vec();
    for field in std::iter::once(domain).chain(fields.iter().copied()) {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

/// Public root signing authority and its independently generated recovery recipient.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityPublic {
    /// Ed25519 verification key and basis of the domain identity identifier.
    pub signing_key: [u8; 32],
    /// X25519 offline recovery recipient key; not a routine device key.
    pub recovery_key: [u8; 32],
}

/// Public device signing and encryption keys, bound together by a certificate.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FramePublic {
    /// Ed25519 device verification key and basis of the FRAME identifier.
    pub signing_key: [u8; 32],
    /// X25519 recipient key for this device's encrypted key envelopes.
    pub encryption_key: [u8; 32],
}

/// Root authority and offline recovery capability. Never install in a routine FRAME.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    /// Ed25519 root signing seed; wiped with this bundle on drop.
    signing: [u8; 32],
    /// Independent X25519 offline recovery secret; never distribute for enrollment.
    recovery: [u8; 32],
}

/// Device-only secrets, with no root certification or recovery authority.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FrameSecrets {
    /// Ed25519 device signing seed, distinct from identity authority.
    signing: [u8; 32],
    /// Independent X25519 device recipient secret.
    encryption: [u8; 32],
}

/// Derive an X25519 public key from raw secret bytes without exporting the secret.
fn encryption_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

impl IdentitySecrets {
    /// Generate independent root-signing and recovery secrets using OS entropy.
    /// Panics if the operating system RNG fails. The bundle is zeroized on drop.
    pub fn generate() -> Self {
        Self {
            signing: random(),
            recovery: random(),
        }
    }
    /// Derive the public signing/recovery binding without exporting secret material.
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            signing_key: SigningKey::from_bytes(&self.signing)
                .verifying_key()
                .to_bytes(),
            recovery_key: encryption_public(&self.recovery),
        }
    }
    /// Root-sign both device keys with no delegation parent.
    /// This binds supplied bytes, not proof of possession, secure pairing, or CELL
    /// permission. Currently always returns `Ok`.
    pub fn certify_frame(&self, frame: &FramePublic) -> Result<FrameCertificate> {
        let identity = self.public();
        let bytes = certificate_bytes(&identity, frame);
        Ok(FrameCertificate {
            identity,
            frame: frame.clone(),
            signature: sign(&self.signing, b"frame-certificate", &bytes),
            delegation: None,
        })
    }
    /// Sign exact bytes under a caller-selected protocol domain as root authority.
    /// Use distinct domains for distinct message roles; no authorization is checked.
    pub fn sign(&self, domain: &[u8], payload: &[u8]) -> Signature {
        sign(&self.signing, domain, payload)
    }
}
impl FrameSecrets {
    /// Issue a device-signed certificate without root secrets.
    /// The caller MUST independently pin the identity and authorize this issuer
    /// and every ancestor against current policy before enrolling the new FRAME.
    /// Returns [`Error::Authentication`] for a mismatched issuer device, invalid
    /// chain, repeated signer, or resulting chain longer than eight certificates.
    /// Supplied new keys are not proof that the new device possesses their secrets.
    pub fn certify_frame(
        &self,
        issuer: &FrameCertificate,
        new_frame: &FramePublic,
    ) -> Result<FrameCertificate> {
        issuer.verify(&issuer.identity)?;
        if issuer.frame != self.public() {
            return Err(Error::Authentication);
        }
        let certificate = FrameCertificate {
            identity: issuer.identity.clone(),
            frame: new_frame.clone(),
            signature: sign(
                &self.signing,
                b"delegated-frame-certificate",
                &delegated_certificate_bytes(&issuer.identity, new_frame, issuer),
            ),
            delegation: Some(Box::new(issuer.clone())),
        };
        // Also enforce the resulting depth limit and reject repeated signers.
        certificate.verify(&issuer.identity)?;
        Ok(certificate)
    }

    /// Generate independent device signing/recipient secrets using OS entropy.
    /// Panics on RNG failure. Generate a new bundle for each device, not a clone.
    pub fn generate() -> Self {
        Self {
            signing: random(),
            encryption: random(),
        }
    }
    /// Derive both public device keys without exporting secret material.
    pub fn public(&self) -> FramePublic {
        FramePublic {
            signing_key: SigningKey::from_bytes(&self.signing)
                .verifying_key()
                .to_bytes(),
            encryption_key: encryption_public(&self.encryption),
        }
    }
    /// Sign exact bytes under a distinct caller-selected protocol domain.
    /// A valid device signature alone establishes neither authorization nor freshness.
    pub fn sign(&self, domain: &[u8], payload: &[u8]) -> Signature {
        sign(&self.signing, domain, payload)
    }
}

/// Ed25519 signature over the shared domain-separated binary message encoding.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Raw signature bytes; verification requires exactly 64 bytes.
    pub bytes: Vec<u8>,
}
/// Sign one payload using an Ed25519 seed and the shared versioned domain encoding.
fn sign(secret: &[u8; 32], domain: &[u8], payload: &[u8]) -> Signature {
    Signature {
        bytes: SigningKey::from_bytes(secret)
            .sign(&message(domain, &[payload]))
            .to_bytes()
            .to_vec(),
    }
}
impl Signature {
    /// Strictly verify against the expected key, domain, and exact payload bytes.
    /// Returns [`Error::Authentication`] for malformed keys/signatures or any mismatch.
    /// Obtain the expected key from trusted policy and prevent replay separately.
    pub fn verify(&self, key: &[u8; 32], domain: &[u8], payload: &[u8]) -> Result<()> {
        let key = VerifyingKey::from_bytes(key).map_err(|_| Error::Authentication)?;
        let sig =
            ed25519_dalek::Signature::from_slice(&self.bytes).map_err(|_| Error::Authentication)?;
        key.verify_strict(&message(domain, &[payload]), &sig)
            .map_err(|_| Error::Authentication)
    }
}

/// Signed identity-to-device binding with an optional complete delegation chain.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrameCertificate {
    /// Full identity binding, identical at every node of a valid chain.
    pub identity: IdentityPublic,
    /// Device whose public signing and recipient keys are certified.
    pub frame: FramePublic,
    /// Root or immediate issuer signature, depending on `delegation`.
    pub signature: Signature,
    /// Immediate issuer's complete certificate; absent for root-issued certificates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Box<FrameCertificate>>,
}
/// Encode identity and FRAME keys in fixed role order for certificate/record binding.
fn certificate_bytes(identity: &IdentityPublic, frame: &FramePublic) -> Vec<u8> {
    message(
        b"certificate-fields",
        &[
            &identity.signing_key,
            &identity.recovery_key,
            &frame.signing_key,
            &frame.encryption_key,
        ],
    )
}
impl FrameCertificate {
    /// The expected identity must come from trusted enrollment/policy, not this certificate.
    /// Cryptographic verification does NOT check CELL permission or revocation.
    /// Returns [`Error::Authentication`] on binding/signature mismatch, repeated
    /// device signing keys, or more than eight certificates including the leaf.
    /// Limit serialized size and parser nesting separately before deserialization.
    pub fn verify(&self, expected_identity: &IdentityPublic) -> Result<()> {
        // Bound all work before any signature verification or canonical encoding.
        // Eight certificates total (leaf included); repeated signing keys are cycles
        // even if an attacker changes the accompanying encryption key.
        let mut chain: Vec<&FrameCertificate> = Vec::new();
        let mut current = Some(self);
        while let Some(cert) = current {
            if chain.len() == 8
                || &cert.identity != expected_identity
                || chain
                    .iter()
                    .any(|seen| seen.frame.signing_key == cert.frame.signing_key)
            {
                return Err(Error::Authentication);
            }
            chain.push(cert);
            current = cert.delegation.as_deref();
        }
        for cert in chain.into_iter().rev() {
            if let Some(issuer) = cert.delegation.as_deref() {
                cert.signature.verify(
                    &issuer.frame.signing_key,
                    b"delegated-frame-certificate",
                    &delegated_certificate_bytes(&cert.identity, &cert.frame, issuer),
                )?;
            } else {
                cert.signature.verify(
                    &expected_identity.signing_key,
                    b"frame-certificate",
                    &certificate_bytes(&cert.identity, &cert.frame),
                )?;
            }
        }
        Ok(())
    }

    /// Immediate issuer first, ending with the root-certified FRAME; excludes self.
    /// Call `verify` first, then check EVERY issuer against current caller policy.
    /// A cryptographically valid chain does not grant enrollment or restore rights.
    /// This traversal performs no validation or depth limiting of its own.
    pub fn issuers(&self) -> Vec<FramePublic> {
        let mut issuers = Vec::new();
        let mut current = self.delegation.as_deref();
        while let Some(cert) = current {
            issuers.push(cert.frame.clone());
            current = cert.delegation.as_deref();
        }
        issuers
    }
}

/// Bind the complete issuer path, including each signature and both key roles.
/// This prevents substituting a different valid path around a revoked ancestor;
/// SignedRecord already authenticates the resulting leaf certificate signature.
/// Verification calls this after bounded structural checks; issuance checks its
/// issuer first and validates the newly extended chain after signing.
fn delegated_certificate_bytes(
    identity: &IdentityPublic,
    frame: &FramePublic,
    issuer: &FrameCertificate,
) -> Vec<u8> {
    let mut lineage = Vec::new();
    let mut current = Some(issuer);
    while let Some(cert) = current {
        let node = message(
            b"issuer-certificate",
            &[
                &certificate_bytes(&cert.identity, &cert.frame),
                &cert.signature.bytes,
            ],
        );
        lineage.extend_from_slice(&(node.len() as u64).to_be_bytes());
        lineage.extend_from_slice(&node);
        current = cert.delegation.as_deref();
    }
    message(
        b"delegated-certificate-fields",
        &[&certificate_bytes(identity, frame), &lineage],
    )
}
