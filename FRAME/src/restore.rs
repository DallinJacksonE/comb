//! Restore-specific authorization records. Enrollment alone is not permission to unlock a revoked FRAME.
use crate::identity::{EnrollmentGrant, EnrollmentRequest};
use comb_cell::{IdentityPublic, SignedRecord};
use serde::{Deserialize, Serialize};

pub const RESTORE_DOMAIN: &[u8] = b"comb.frame.restore.v1";

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreRequest {
    pub enrollment: EnrollmentRequest,
    pub identity: IdentityPublic,
    pub target_frame: String,
    pub revocation: String,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreAuthorization {
    pub grant: EnrollmentGrant,
    pub target_frame: String,
    pub revocation: String,
}

pub fn encode(record: &SignedRecord) -> anyhow::Result<String> {
    use base64::Engine;
    Ok(base64::engine::general_purpose::STANDARD.encode(serde_json::to_vec(record)?))
}
