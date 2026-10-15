#![doc = include_str!("../README.md")]
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

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("authentication failed")]
    Authentication,
    #[error("invalid or unsupported format")]
    Format,
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),
}
pub type Result<T> = std::result::Result<T, Error>;

fn random<const N: usize>() -> [u8; N] {
    let mut bytes = [0; N];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

/// Length-delimited, domain-separated binary encoding, independent of JSON.
fn message(domain: &[u8], fields: &[&[u8]]) -> Vec<u8> {
    let mut bytes = b"COMB-CELL-v1".to_vec();
    for field in std::iter::once(domain).chain(fields.iter().copied()) {
        bytes.extend_from_slice(&(field.len() as u64).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct IdentityPublic {
    pub signing_key: [u8; 32],
    pub recovery_key: [u8; 32],
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FramePublic {
    pub signing_key: [u8; 32],
    pub encryption_key: [u8; 32],
}

/// Root authority and offline recovery capability. Never install in a routine FRAME.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct IdentitySecrets {
    signing: [u8; 32],
    recovery: [u8; 32],
}

/// Device-only secrets, with no root certification or recovery authority.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct FrameSecrets {
    signing: [u8; 32],
    encryption: [u8; 32],
}

fn encryption_public(secret: &[u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(*secret)).to_bytes()
}

impl IdentitySecrets {
    pub fn generate() -> Self {
        Self {
            signing: random(),
            recovery: random(),
        }
    }
    pub fn public(&self) -> IdentityPublic {
        IdentityPublic {
            signing_key: SigningKey::from_bytes(&self.signing)
                .verifying_key()
                .to_bytes(),
            recovery_key: encryption_public(&self.recovery),
        }
    }
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
    pub fn sign(&self, domain: &[u8], payload: &[u8]) -> Signature {
        sign(&self.signing, domain, payload)
    }
}
impl FrameSecrets {
    /// Issue a device-signed certificate without root secrets.
    /// The caller MUST independently pin the identity and authorize this issuer
    /// and every ancestor against current policy before enrolling the new FRAME.
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

    pub fn generate() -> Self {
        Self {
            signing: random(),
            encryption: random(),
        }
    }
    pub fn public(&self) -> FramePublic {
        FramePublic {
            signing_key: SigningKey::from_bytes(&self.signing)
                .verifying_key()
                .to_bytes(),
            encryption_key: encryption_public(&self.encryption),
        }
    }
    pub fn sign(&self, domain: &[u8], payload: &[u8]) -> Signature {
        sign(&self.signing, domain, payload)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub bytes: Vec<u8>,
}
fn sign(secret: &[u8; 32], domain: &[u8], payload: &[u8]) -> Signature {
    Signature {
        bytes: SigningKey::from_bytes(secret)
            .sign(&message(domain, &[payload]))
            .to_bytes()
            .to_vec(),
    }
}
impl Signature {
    pub fn verify(&self, key: &[u8; 32], domain: &[u8], payload: &[u8]) -> Result<()> {
        let key = VerifyingKey::from_bytes(key).map_err(|_| Error::Authentication)?;
        let sig =
            ed25519_dalek::Signature::from_slice(&self.bytes).map_err(|_| Error::Authentication)?;
        key.verify_strict(&message(domain, &[payload]), &sig)
            .map_err(|_| Error::Authentication)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct FrameCertificate {
    pub identity: IdentityPublic,
    pub frame: FramePublic,
    pub signature: Signature,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegation: Option<Box<FrameCertificate>>,
}
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
/// Only called after the chain has passed the bounded structural checks.
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
