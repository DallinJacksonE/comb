//! Persisted revocation/restore state; secret verification and scoped reset are services.
use serde::{Deserialize, Serialize};

const MAX_RESTORE_ATTEMPTS: u8 = 3;

/// A revoked FRAME stays locked across daemon restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Lifecycle {
    #[default]
    Active,
    Revoked {
        revocation: String,
        failed_attempts: u8,
    },
    ResetRequired,
}

#[derive(Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    Restored,
    Denied { remaining: u8 },
    ResetRequired,
}

impl Lifecycle {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Notice authority must be verified before entering this transition.
    pub fn revoke(&mut self, revocation: String) {
        if self.is_active() {
            *self = Self::Revoked {
                revocation,
                failed_attempts: 0,
            };
        }
    }

    /// The caller verifies a bound, current authorization before supplying `valid`.
    pub fn try_restore(&mut self, valid: bool) -> RestoreOutcome {
        match self {
            Self::Active => RestoreOutcome::Restored,
            Self::ResetRequired => RestoreOutcome::ResetRequired,
            Self::Revoked {
                failed_attempts, ..
            } if !valid => {
                *failed_attempts += 1;
                let remaining = MAX_RESTORE_ATTEMPTS.saturating_sub(*failed_attempts);
                if remaining == 0 {
                    *self = Self::ResetRequired;
                    RestoreOutcome::ResetRequired
                } else {
                    RestoreOutcome::Denied { remaining }
                }
            }
            Self::Revoked { .. } => {
                *self = Self::Active;
                RestoreOutcome::Restored
            }
        }
    }
}
