//! Persisted revocation/restore state; secret verification and scoped reset are services.
//!
//! Transitions here only mutate memory. [`crate::store::Store`] persists them in
//! encrypted control state and performs cleanup; callers must authenticate notices
//! and restore credentials before invoking this policy-only state machine.
use serde::{Deserialize, Serialize};

/// Failed credentials allowed for a revocation before requiring a reset.
const MAX_RESTORE_ATTEMPTS: u8 = 3;

/// A revoked FRAME stays locked across daemon restarts.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum Lifecycle {
    #[default]
    /// Routine operations are permitted, subject to CELL-specific authorization.
    Active,
    /// Routine operations are locked while a current restore challenge exists.
    Revoked {
        /// Identifier of the authenticated notice that caused the lock.
        revocation: String,
        /// Failed restore validations recorded for this challenge.
        failed_attempts: u8,
    },
    /// Attempt budget exhausted; a valid credential no longer unlocks this state.
    ResetRequired,
}

/// Policy result; cleanup and durable persistence are the caller's responsibility.
#[derive(Debug, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// Already active, or a revoked state accepted a valid credential.
    Restored,
    /// Credential rejected; the remaining budget has not been exhausted.
    Denied { remaining: u8 },
    /// Reset is required, either previously or because this attempt exhausted the budget.
    ResetRequired,
}

impl Lifecycle {
    /// Whether routine work is permitted by the global lifecycle gate.
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Active)
    }

    /// Notice authority must be verified before entering this transition.
    /// Only an active state changes; repeated notices do not replace a challenge
    /// or reset its failure counter. No persistence is performed here.
    pub fn revoke(&mut self, revocation: String) {
        if self.is_active() {
            *self = Self::Revoked {
                revocation,
                failed_attempts: 0,
            };
        }
    }

    /// The caller verifies a bound, current authorization before supplying `valid`.
    /// A revoked state accepts a valid credential or counts a failed attempt;
    /// the third failure makes reset mandatory. Active/reset states are unchanged.
    /// Persist the resulting state before reporting the outcome to a client.
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
