use super::*;
use crypto::{registry::ALG_ED25519, scheme::Ed25519Scheme};
use validator::{NO_EXPIRY, SlotDecisionTip, ValidatorKey, ValidatorRecord, ValidatorSet};

fn slot(round: u64) -> SlotDecisionTip {
    let set = ValidatorSet {
        epoch: 2,
        validators: (0..4u8)
            .map(|i| ValidatorRecord {
                validator_id: vec![i],
                keys: vec![ValidatorKey {
                    key_id: vec![i],
                    algorithm_id: ALG_ED25519,
                    public_key: Ed25519Scheme::public_key_from_seed(&[i + 1; 32])
                        .unwrap()
                        .to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect(),
    };
    SlotDecisionTip::from_checkpoint(b"pacemaker-test".to_vec(), &set, round, [1; 32], 0, [2; 32])
        .unwrap()
}

fn snapshot() -> Snapshot {
    Snapshot {
        slot: slot(7),
        view: AgreementView(0),
        prevote: false,
        precommit: false,
        decided: false,
    }
}

fn planner() -> Pacemaker {
    Pacemaker::new(
        Policy::new(
            Duration::from_secs(2),
            Duration::from_secs(5),
            Duration::from_secs(11),
        )
        .unwrap(),
    )
}

#[test]
fn unequal_waits_fire_at_exact_boundaries_without_observation_resets() {
    let mut p = planner();
    let mut s = snapshot();
    let now = Instant::now();
    let epsilon = Duration::from_nanos(1);
    assert_eq!(p.plan(&s, now).unwrap(), None);
    let prevote_at = now + Duration::from_secs(2);
    assert_eq!(p.plan(&s, prevote_at - epsilon).unwrap(), None);
    let prevote = Some(Action::Timeout {
        view: s.view,
        phase: AgreementPhase::Prevote,
    });
    assert_eq!(p.plan(&s, prevote_at).unwrap(), prevote);
    assert_eq!(p.plan(&s, prevote_at).unwrap(), prevote);

    s.prevote = true;
    assert_eq!(p.plan(&s, prevote_at).unwrap(), None);
    let precommit_at = prevote_at + Duration::from_secs(5);
    assert_eq!(p.plan(&s, precommit_at - epsilon).unwrap(), None);
    assert_eq!(
        p.plan(&s, precommit_at).unwrap(),
        Some(Action::Timeout {
            view: s.view,
            phase: AgreementPhase::Precommit,
        })
    );

    s.precommit = true;
    assert_eq!(p.plan(&s, precommit_at).unwrap(), None);
    let advance_at = precommit_at + Duration::from_secs(11);
    assert_eq!(p.plan(&s, advance_at - epsilon).unwrap(), None);
    assert_eq!(
        p.plan(&s, advance_at).unwrap(),
        Some(Action::AdvanceView { from: s.view })
    );
}

#[test]
fn backwards_time_preserves_deadline_and_last_accepted_time() {
    let mut p = planner();
    let s = snapshot();
    let now = Instant::now();
    assert_eq!(p.plan(&s, now).unwrap(), None);
    assert_eq!(p.plan(&s, now + Duration::from_secs(1)).unwrap(), None);
    // Even a rejected snapshot with a different stage must not replace the timer.
    let mut changed = s.clone();
    changed.precommit = true;
    assert_eq!(
        p.plan(&changed, now).unwrap_err(),
        "pacemaker now moved backwards"
    );
    assert!(p.plan(&s, now + Duration::from_millis(500)).is_err());
    let deadline = now + Duration::from_secs(2);
    assert_eq!(
        p.plan(&s, deadline - Duration::from_nanos(1)).unwrap(),
        None
    );
    assert_eq!(
        p.plan(&s, deadline).unwrap(),
        Some(Action::Timeout {
            view: s.view,
            phase: AgreementPhase::Prevote,
        })
    );
}

#[test]
fn changed_actual_slot_rearms_same_view_and_stage() {
    let mut p = planner();
    let mut s = snapshot();
    let now = Instant::now();
    assert_eq!(p.plan(&s, now).unwrap(), None);
    let next_slot = slot(8);
    assert_ne!(s.slot, next_slot);
    s.slot = next_slot;
    let observed = now + Duration::from_secs(100);
    assert_eq!(p.plan(&s, observed).unwrap(), None);
    let deadline = observed + Duration::from_secs(2);
    assert_eq!(
        p.plan(&s, deadline - Duration::from_nanos(1)).unwrap(),
        None
    );
    assert_eq!(
        p.plan(&s, deadline).unwrap(),
        Some(Action::Timeout {
            view: s.view,
            phase: AgreementPhase::Prevote,
        })
    );
}

#[test]
fn sparse_observations_start_fresh_grace_even_without_observed_prevote() {
    let mut p = planner();
    let mut s = snapshot();
    let now = Instant::now();
    assert_eq!(p.plan(&s, now).unwrap(), None);
    s.precommit = true;
    let observed = now + Duration::from_secs(1_000);
    assert_eq!(p.plan(&s, observed).unwrap(), None);
    assert_eq!(p.plan(&s, observed + Duration::from_secs(5)).unwrap(), None);
    let deadline = observed + Duration::from_secs(11);
    assert_eq!(
        p.plan(&s, deadline - Duration::from_nanos(1)).unwrap(),
        None
    );
    assert_eq!(
        p.plan(&s, deadline).unwrap(),
        Some(Action::AdvanceView { from: s.view })
    );
    // Planning alone neither advances the view nor starts another view's timer.
    assert_eq!(
        p.plan(&s, deadline + Duration::from_secs(1_000)).unwrap(),
        Some(Action::AdvanceView { from: s.view })
    );
}

#[test]
fn decided_snapshot_idles_and_clears_elapsed_timer() {
    let mut p = planner();
    let mut s = snapshot();
    let now = Instant::now();
    assert_eq!(p.plan(&s, now).unwrap(), None);
    s.decided = true;
    s.precommit = true;
    s.view = AgreementView(u64::MAX);
    let observed = now + Duration::from_secs(100);
    assert_eq!(p.plan(&s, observed).unwrap(), None);
    let later = observed + Duration::from_secs(100);
    assert_eq!(p.plan(&s, later).unwrap(), None);
    assert!(p.timer.is_none());

    s.slot = slot(8);
    s.view = AgreementView(0);
    s.decided = false;
    s.precommit = false;
    assert_eq!(p.plan(&s, later).unwrap(), None);
    let deadline = later + Duration::from_secs(2);
    assert_eq!(
        p.plan(&s, deadline - Duration::from_nanos(1)).unwrap(),
        None
    );
    assert_eq!(
        p.plan(&s, deadline).unwrap(),
        Some(Action::Timeout {
            view: s.view,
            phase: AgreementPhase::Prevote,
        })
    );
}

#[test]
fn exhausted_view_errors_only_at_grace_deadline_without_wrapping() {
    let mut p = planner();
    let mut s = snapshot();
    s.view = AgreementView(u64::MAX);
    s.precommit = true;
    let now = Instant::now();
    assert_eq!(p.plan(&s, now).unwrap(), None);
    let deadline = now + Duration::from_secs(11);
    assert_eq!(
        p.plan(&s, deadline - Duration::from_nanos(1)).unwrap(),
        None
    );
    assert_eq!(
        p.plan(&s, deadline).unwrap_err(),
        "agreement view exhausted"
    );
    assert_eq!(
        p.plan(&s, deadline).unwrap_err(),
        "agreement view exhausted"
    );
    assert_eq!(s.view, AgreementView(u64::MAX));
    s.decided = true;
    assert_eq!(p.plan(&s, deadline).unwrap(), None);
}
