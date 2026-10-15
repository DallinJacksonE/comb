use comb_frame::lifecycle::{Lifecycle, RestoreOutcome};

#[test]
fn revoked_frame_cannot_operate_and_resets_after_bounded_failed_attempts() {
    let mut state = Lifecycle::default();
    assert!(state.is_active());
    state.revoke("revocation-1".into());
    assert!(!state.is_active());
    assert_eq!(
        state.try_restore(false),
        RestoreOutcome::Denied { remaining: 2 }
    );
    assert_eq!(
        state.try_restore(false),
        RestoreOutcome::Denied { remaining: 1 }
    );
    assert_eq!(state.try_restore(false), RestoreOutcome::ResetRequired);
    assert!(!state.is_active());
}

#[test]
fn a_valid_restore_reactivates_only_before_attempts_are_exhausted() {
    let mut state = Lifecycle::default();
    state.revoke("revocation-1".into());
    assert_eq!(state.try_restore(true), RestoreOutcome::Restored);
    assert!(state.is_active());
    state.revoke("revocation-2".into());
    for _ in 0..3 {
        state.try_restore(false);
    }
    assert_eq!(state.try_restore(true), RestoreOutcome::ResetRequired);
}
