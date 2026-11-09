//! Domain-separated signed payloads with certificate and content-ID bindings.
use crate::{
    Error, FrameCertificate, FramePublic, FrameSecrets, IdentityPublic, Result, Signature,
    certificate_bytes, message,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Immutable-by-convention signed bytes; mutation invalidates the signature.
/// Caller must separately enforce CELL policy, revoked FRAMEs, ancestry, and replay rules.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignedRecord {
    /// Signed-record wire version; currently 1.
    pub version: u32,
    /// Signer’s complete identity/device certificate binding.
    pub certificate: FrameCertificate,
    /// Application-selected payload purpose, authenticated by the record signature.
    pub domain: Vec<u8>,
    /// Exact application bytes; signed but not encrypted.
    pub payload: Vec<u8>,
    /// Device signature over the complete record signing encoding.
    pub signature: Signature,
}
impl SignedRecord {
    /// Sign exact payload bytes after checking the certificate chain and device keys.
    /// The embedded identity is checked internally, not externally pinned: callers
    /// must authorize the certificate and domain before issuing a record.
    pub fn new(
        frame: &FrameSecrets,
        certificate: &FrameCertificate,
        domain: &[u8],
        payload: &[u8],
    ) -> Result<Self> {
        certificate.verify(&certificate.identity)?;
        if frame.public() != certificate.frame {
            return Err(Error::Authentication);
        }
        let mut record = Self {
            version: 1,
            certificate: certificate.clone(),
            domain: domain.to_vec(),
            payload: payload.to_vec(),
            signature: Signature { bytes: Vec::new() },
        };
        record.signature = frame.sign(b"signed-record", &record.signing_bytes());
        Ok(record)
    }
    /// Encode the version, key binding, certificate signature, domain, and payload.
    fn signing_bytes(&self) -> Vec<u8> {
        message(
            b"record-fields",
            &[
                &self.version.to_be_bytes(),
                &certificate_bytes(&self.certificate.identity, &self.certificate.frame),
                &self.certificate.signature.bytes,
                &self.domain,
                &self.payload,
            ],
        )
    }
    /// Expected identity and FRAME must be selected from trusted caller policy.
    /// The returned bytes are authenticated, but not necessarily authorized or fresh.
    pub fn verify(
        &self,
        identity: &IdentityPublic,
        frame: &FramePublic,
        domain: &[u8],
    ) -> Result<&[u8]> {
        if self.version != 1 {
            return Err(Error::Format);
        }
        self.certificate.verify(identity)?;
        if &self.certificate.frame != frame || self.domain != domain {
            return Err(Error::Authentication);
        }
        self.signature
            .verify(&frame.signing_key, b"signed-record", &self.signing_bytes())?;
        Ok(&self.payload)
    }
    /// Content identifier, not an authenticity check. Includes the signature.
    pub fn id(&self) -> Result<[u8; 32]> {
        Ok(Sha256::digest(message(
            b"record-id",
            &[&self.signing_bytes(), &self.signature.bytes],
        ))
        .into())
    }
}
