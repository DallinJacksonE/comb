//! Authenticated encrypted snapshot format shared by disk, backups, and peer replication.
use anyhow::{Result, bail};
use comb_cell::{
    EncryptedSnapshot, FrameCertificate, FrameSecrets, IdentityPublic, RecipientSecret,
    SignedRecord, open_snapshot, seal_snapshot,
};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

const DOMAIN: &[u8] = b"comb.frame.snapshot.v1";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SnapshotContext {
    pub cell_id: String,
    pub version: String,
    pub owner: IdentityPublic,
}

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
    pub record: SignedRecord,
}
impl Snapshot {
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
    pub fn id(&self) -> Result<String> {
        Ok(hex::encode(self.record.id()?))
    }
    /// This reads a context, but does not confer authority; `open` authenticates it.
    pub fn context(&self) -> Result<SnapshotContext> {
        Ok(serde_json::from_slice::<Payload>(&self.record.payload)?.context)
    }
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
