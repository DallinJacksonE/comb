//! Restore-specific authorization records. Enrollment alone is not permission to unlock a revoked FRAME.
//!
//! [`crate::store::Store::issue_restore`] signs these bindings, and
//! [`crate::store::Store::restore_credential`] checks the trusted issuer, current
//! revocation, target, and pending enrollment before consuming replacement keys.
use crate::identity::{EnrollmentGrant, EnrollmentRequest};
use comb_cell::{IdentityPublic, SignedRecord};
use serde::{Deserialize, Serialize};

/// Domain separating restore authorizations from enrollment and other records.
pub const RESTORE_DOMAIN: &[u8] = b"comb.frame.restore.v1";

/// Public challenge for another trusted FRAME of the same identity.
/// Deserializing a request alone authenticates none of its fields.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    /// Fresh public keys and nonce backed by the target's pending vault.
    pub enrollment: EnrollmentRequest,
    /// Root identity whose revoked device is being replaced.
    pub identity: IdentityPublic,
    /// Signing-key identifier of the old, revoked FRAME.
    pub target_frame: String,
    /// Current revocation challenge, preventing reuse for another lock event.
    pub revocation: String,
}

/// Body of a restore-domain signed record, not a self-authenticating credential.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreAuthorization {
    /// Delegated replacement profile bound to the pending enrollment keys.
    pub grant: EnrollmentGrant,
    /// Old FRAME identifier that this authorization is permitted to replace.
    pub target_frame: String,
    /// Revocation challenge that must still be current on the target.
    pub revocation: String,
}

/// Serialize a signed record as standard Base64 JSON for credential transport.
/// Returns JSON serialization errors; does not verify the record or write files.
pub fn encode(record: &SignedRecord) -> anyhow::Result<String> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(record)?))
}
