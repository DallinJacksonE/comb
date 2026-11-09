//! Authenticated encrypted snapshot format shared by disk, backups, and peer replication.
//!
//! [`Snapshot::open`] checks the publisher signature and a caller-supplied owner
//! pin. CELL history validation and publisher membership checks remain the store's
//! responsibility; neither a valid envelope nor its content hash grants access.
use anyhow::{Result, bail};
use comb_cell::{
    EncryptedSnapshot, FrameCertificate, FrameSecrets, IdentityPublic, RecipientSecret,
    SignedRecord, open_snapshot, seal_snapshot,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Signature domain separating snapshots from other signed FRAME records.
const DOMAIN: &[u8] = b"comb.frame.snapshot.v1";

/// Public snapshot routing metadata, signed and also bound as encryption AAD.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotContext {
    /// Immutable CELL identifier; path syntax is checked by the store, not here.
    pub cell_id: String,
    /// Expected version of the signed CELL history inside the plaintext.
    pub version: String,
    /// Expected CELL owner, to be compared with an independently trusted pin.
    pub owner: IdentityPublic,
}

/// Serialized signed body; the same context is used as encryption AAD.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Payload {
    context: SnapshotContext,
    encrypted: EncryptedSnapshot,
}

/// Only identifiers, certificates, ciphertext and wrapped keys are public.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    /// Publisher certificate, signed public context, and encrypted payload.
    pub record: SignedRecord,
}
impl Snapshot {
    /// Encrypt bytes for the supplied recipient keys and sign the resulting body.
    ///
    /// Returns serialization, recipient/encryption, or certificate/signing errors.
    /// Does not write files or validate CELL history, context syntax, or whether
    /// the signer/recipients are authorized by that history; the caller does so.
    pub fn seal(
        context: SnapshotContext,
        plaintext: &[u8],
        recipients: &[[u8; 32]],
        frame: &FrameSecrets,
        certificate: &FrameCertificate,
    ) -> Result<Self> {
        let encrypted = seal_snapshot(plaintext, recipients, &serde_json::to_vec(&context)?)?;
        let payload = serde_json::to_vec(&Payload { context, encrypted })?;
        Ok(Self {
            record: SignedRecord::new(frame, certificate, DOMAIN, &payload)?,
        })
    }
    /// Return the hexadecimal signed-record content identifier, without authenticating it.
    /// Serialization failures are returned; no persistence is performed.
    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(self.record.id()?))
    }
    /// Decode untrusted context for routing, returning malformed-payload errors.
    /// Use [`Self::open`] and domain validation before accepting its claims.
    pub fn context(&self) -> Result<SnapshotContext> {
        Ok(serde_json::from_slice::<Payload>(&self.record.payload)?.context)
    }
    /// Verify the publisher's certificate/signature and decrypt for `recipient`.
    ///
    /// `owner` must come from a trusted CELL-owner pin, not blindly from
    /// [`Self::context`]. A publisher may belong to a different identity than the
    /// owner: the store must check its authorization against decrypted CELL history.
    /// Returns signature, owner-mismatch, parse, or decryption/AAD errors. Plaintext
    /// is zeroized on drop; this method has no filesystem side effects and provides
    /// no rollback/freshness guarantee.
    pub fn open(
        &self,
        owner: &IdentityPublic,
        recipient: &RecipientSecret,
    ) -> Result<Zeroizing<Vec<u8>>> {
        let cert = &self.record.certificate;
        let bytes = self.record.verify(&cert.identity, &cert.frame, DOMAIN)?;
        let payload: Payload = serde_json::from_slice(bytes)?;
        if &payload.context.owner != owner {
            bail!("snapshot owner does not match pinned CELL owner");
        }
        Ok(open_snapshot(
            &payload.encrypted,
            recipient,
            &serde_json::to_vec(&payload.context)?,
        )?)
    }
}
