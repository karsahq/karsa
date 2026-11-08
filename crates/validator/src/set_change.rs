//! Checked validator-set transitions.
//!
//! A key rotation keeps the validator identities and moves only their active
//! keys. A set change moves identities, which is a different safety problem: an
//! old quorum and a new quorum can decide conflicting prefixes unless they
//! still overlap by more than the fault budget. This module checks that
//! condition without touching the DAG or the certificate code; the transition
//! mechanics are a separate step.
//!
//! The first implementation is deliberately conservative: exactly one identity
//! is added or removed per epoch, and the new set must keep the old fault
//! budget. A later version can allow more changes if it keeps both the
//! intersection and the fault-budget checks.

use std::collections::HashSet;

use crypto::{CryptoError, CryptoErrorKind};

use crate::schedule::{EpochSchedule, ValidatorSet};

/// The arithmetic of one checked transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// Epoch the old set is active.
    pub old_epoch: u64,
    /// Epoch the new set becomes active.
    pub new_epoch: u64,
    /// Validators in the old set.
    pub old_size: usize,
    /// Validators in the new set.
    pub new_size: usize,
    /// Validator ids present in both sets.
    pub shared: usize,
    /// Old quorum size.
    pub old_quorum: usize,
    /// New quorum size.
    pub new_quorum: usize,
    /// Smallest possible intersection of an old and a new quorum.
    pub min_intersection: usize,
    /// Fault budget the old set is designed for.
    pub fault_budget: usize,
    /// Fault budget the new set is designed for.
    pub new_fault_budget: usize,
}

impl Transition {
    /// Number of identities added or removed.
    #[must_use]
    pub fn changes(&self) -> usize {
        self.old_size + self.new_size - 2 * self.shared
    }
}

/// The set active at each epoch.
///
/// The prototype holds at most one transition. `SetSchedule::single` is the
/// unchanged one-set case; `SetSchedule::with_change` adds a checked transition
/// at `change_epoch`. Callers that do not need a transition keep using the
/// existing constructors.
#[derive(Debug, Clone)]
pub struct SetSchedule {
    base: ValidatorSet,
    change: Option<Change>,
}

#[derive(Debug, Clone)]
struct Change {
    epoch: u64,
    set: ValidatorSet,
    transition: Transition,
}

impl SetSchedule {
    /// A schedule with one set for every epoch.
    #[must_use]
    pub fn single(set: ValidatorSet) -> Self {
        Self {
            base: set,
            change: None,
        }
    }

    /// A schedule with one checked transition at `change_epoch`.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::InvalidKeySchedule`] when `change_epoch` does not
    /// name the new set's epoch, plus every error from [`check_transition`].
    pub fn with_change(
        base: ValidatorSet,
        change_epoch: u64,
        next: ValidatorSet,
    ) -> Result<Self, CryptoError> {
        if change_epoch != next.epoch {
            return Err(invalid(format!(
                "change epoch {change_epoch} does not match the new set epoch {}",
                next.epoch
            )));
        }
        let transition = check_transition(&base, &next)?;
        Ok(Self {
            base,
            change: Some(Change {
                epoch: change_epoch,
                set: next,
                transition,
            }),
        })
    }

    /// The set that is active before any transition.
    #[must_use]
    pub fn base(&self) -> &ValidatorSet {
        &self.base
    }

    /// The epoch the transition activates, if there is one.
    #[must_use]
    pub fn change_epoch(&self) -> Option<u64> {
        self.change.as_ref().map(|change| change.epoch)
    }

    /// The checked transition, if there is one.
    #[must_use]
    pub fn transition(&self) -> Option<&Transition> {
        self.change.as_ref().map(|change| &change.transition)
    }

    /// The largest set in the schedule.
    ///
    /// A mesh has to keep a channel and a key for every validator that can be
    /// active in either set, not only for the set that is active now.
    #[must_use]
    pub fn mesh_size(&self) -> usize {
        self.change
            .as_ref()
            .map_or(self.base.validators.len(), |change| {
                self.base.validators.len().max(change.set.validators.len())
            })
    }

    /// The set active at `epoch`.
    #[must_use]
    pub fn set_for_epoch(&self, epoch: u64) -> &ValidatorSet {
        match &self.change {
            Some(change) if epoch >= change.epoch => &change.set,
            _ => &self.base,
        }
    }

    /// The set active at `round`, using the DAG's epoch schedule.
    #[must_use]
    pub fn set_for_round(&self, schedule: &EpochSchedule, round: u64) -> &ValidatorSet {
        self.set_for_epoch(schedule.epoch_of(round))
    }
}

/// Smallest number of validators that any old quorum and any new quorum share.
///
/// With quorum sizes `old_quorum` and `new_quorum` drawn from sets whose union
/// has `old_size + new_size - shared` members, the smallest possible
/// intersection is the sum of the quorum sizes minus the union size. It
/// saturates at zero when the sets are disjoint.
#[must_use]
pub fn min_intersection(
    old_size: usize,
    new_size: usize,
    shared: usize,
    old_quorum: usize,
    new_quorum: usize,
) -> usize {
    let union = old_size.saturating_add(new_size).saturating_sub(shared);
    old_quorum.saturating_add(new_quorum).saturating_sub(union)
}

/// Checks a transition from `old` to `new`.
///
/// The rule is deliberately conservative:
///
/// - exactly one identity is added or removed;
/// - the new set keeps at least the old fault budget
///   (`new.max_faulty() >= old.max_faulty()`);
/// - any old quorum and any new quorum intersect in more than the old fault
///   budget, so at least one validator honest in both sets is in both.
///
/// The first two rules are a prototype policy. A later version can allow more
/// changes if it keeps the intersection and fault-budget checks.
///
/// # Errors
///
/// [`CryptoErrorKind::InvalidKeySchedule`] for a malformed set, a
/// non-advancing epoch, or a change count other than one;
/// [`CryptoErrorKind::PolicyUnsatisfied`] when the new set loses fault
/// tolerance or the quorum intersection is too small.
pub fn check_transition(old: &ValidatorSet, new: &ValidatorSet) -> Result<Transition, CryptoError> {
    old.validate()?;
    new.validate()?;
    if new.epoch <= old.epoch {
        return Err(invalid(format!(
            "new set epoch {} must advance past old epoch {}",
            new.epoch, old.epoch
        )));
    }

    let old_ids: HashSet<&[u8]> = old
        .validators
        .iter()
        .map(|record| record.validator_id.as_slice())
        .collect();
    let new_ids: HashSet<&[u8]> = new
        .validators
        .iter()
        .map(|record| record.validator_id.as_slice())
        .collect();
    let shared = old_ids.intersection(&new_ids).count();
    let changes = old.validators.len() + new.validators.len() - 2 * shared;
    if changes != 1 {
        return Err(invalid(format!(
            "a transition must add or remove exactly one validator, not {changes}"
        )));
    }

    let old_quorum = old.quorum_size();
    let new_quorum = new.quorum_size();
    let intersection = min_intersection(
        old.validators.len(),
        new.validators.len(),
        shared,
        old_quorum,
        new_quorum,
    );
    let fault_budget = old.max_faulty();
    let new_fault_budget = new.max_faulty();

    if new_fault_budget < fault_budget {
        return Err(policy(format!(
            "new set tolerates {new_fault_budget} faults, below the old {fault_budget}"
        )));
    }
    if intersection <= fault_budget {
        return Err(policy(format!(
            "old and new quorums intersect in at least {intersection}, not more than the \
             {fault_budget} fault budget"
        )));
    }

    Ok(Transition {
        old_epoch: old.epoch,
        new_epoch: new.epoch,
        old_size: old.validators.len(),
        new_size: new.validators.len(),
        shared,
        old_quorum,
        new_quorum,
        min_intersection: intersection,
        fault_budget,
        new_fault_budget,
    })
}

fn invalid(detail: String) -> CryptoError {
    CryptoError::new(CryptoErrorKind::InvalidKeySchedule, detail)
}

fn policy(detail: String) -> CryptoError {
    CryptoError::new(CryptoErrorKind::PolicyUnsatisfied, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;

    fn ids(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("val-{index}")).collect()
    }

    fn set(epoch: u64, ids: &[String]) -> ValidatorSet {
        let validators = ids
            .iter()
            .map(|id| ValidatorRecord {
                validator_id: id.as_bytes().to_vec(),
                keys: vec![ValidatorKey {
                    key_id: format!("{id}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: vec![0u8; 32],
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect();
        let set = ValidatorSet { epoch, validators };
        set.validate().expect("the fixture set is valid");
        set
    }

    #[test]
    fn adding_one_validator_is_safe_at_launch_sizes() {
        for count in [4, 10, 20, 30] {
            let old = set(1, &ids(count));
            let new = set(2, &ids(count + 1));
            let transition = check_transition(&old, &new).expect("one addition is safe");
            assert_eq!(transition.changes(), 1);
            assert!(transition.min_intersection > transition.fault_budget);
            assert!(transition.new_fault_budget >= transition.fault_budget);
        }
    }

    #[test]
    fn removing_one_validator_is_safe_when_the_fault_budget_holds() {
        for count in [5, 11, 20, 30] {
            let old = set(1, &ids(count));
            let new = set(2, &ids(count - 1));
            let transition = check_transition(&old, &new).expect("the shrunken set is safe");
            assert_eq!(transition.changes(), 1);
            assert!(transition.min_intersection > transition.fault_budget);
            assert!(transition.new_fault_budget >= transition.fault_budget);
        }
    }

    #[test]
    fn removing_from_ten_lowers_the_fault_budget_and_is_rejected() {
        let old = set(1, &ids(10));
        let new = set(2, &ids(9));
        let error = check_transition(&old, &new).expect_err("nine validators cannot keep f=3");
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn a_replacement_is_two_changes_and_is_rejected() {
        let old = set(1, &ids(10));
        let mut new_ids = ids(10);
        new_ids[0] = "new-validator".to_string();
        let new = set(2, &new_ids);
        let error = check_transition(&old, &new).expect_err("a replacement is two changes");
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn a_non_advancing_epoch_is_rejected() {
        let old = set(2, &ids(10));
        let new = set(2, &ids(11));
        let error = check_transition(&old, &new).expect_err("the epoch must advance");
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn the_quorum_arithmetic_matches_the_formula() {
        let old = set(1, &ids(10));
        let new = set(2, &ids(11));
        let transition = check_transition(&old, &new).expect("10 to 11 is safe");
        assert_eq!(transition.old_quorum, 7);
        assert_eq!(transition.new_quorum, 8);
        assert_eq!(transition.shared, 10);
        assert_eq!(transition.min_intersection, 4);
        assert_eq!(transition.fault_budget, 3);
        assert_eq!(transition.new_fault_budget, 3);
    }

    #[test]
    fn a_single_schedule_returns_the_base_set() {
        let base = set(1, &ids(10));
        let schedule = SetSchedule::single(base.clone());
        assert!(schedule.change_epoch().is_none());
        assert!(schedule.transition().is_none());
        assert_eq!(schedule.set_for_epoch(1), &base);
        assert_eq!(schedule.set_for_epoch(99), &base);
    }

    #[test]
    fn a_change_activates_at_the_epoch_boundary() {
        let base = set(1, &ids(4));
        let next = set(2, &ids(5));
        let schedule = SetSchedule::with_change(base.clone(), 2, next.clone()).unwrap();
        assert_eq!(schedule.change_epoch(), Some(2));
        assert_eq!(schedule.set_for_epoch(1), &base);
        assert_eq!(schedule.set_for_epoch(2), &next);

        let epoch_schedule = crate::schedule::EpochSchedule::advancing(1, 2);
        assert_eq!(schedule.set_for_round(&epoch_schedule, 1), &base);
        assert_eq!(schedule.set_for_round(&epoch_schedule, 2), &next);
        assert_eq!(schedule.transition().unwrap().changes(), 1);
    }

    #[test]
    fn a_change_epoch_must_match_the_new_set_epoch() {
        let base = set(1, &ids(4));
        let next = set(3, &ids(5));
        let error = SetSchedule::with_change(base, 2, next).expect_err("the epochs must agree");
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn an_unsafe_change_is_rejected_before_it_is_scheduled() {
        let base = set(1, &ids(10));
        let next = set(2, &ids(9));
        let error = SetSchedule::with_change(base, 2, next).expect_err("f must not drop");
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn the_intersection_formula_shows_an_unsafe_shrink() {
        // Ten to eight is two removals, which the prototype rejects before this
        // arithmetic. The formula still shows why the boundary matters: a
        // seven-of-ten quorum and a six-of-eight quorum share at least three
        // validators, which is not more than f=3.
        let old_quorum = 10 * 2 / 3 + 1;
        let new_quorum = 8 * 2 / 3 + 1;
        assert_eq!(min_intersection(10, 8, 8, old_quorum, new_quorum), 3);
    }
}
