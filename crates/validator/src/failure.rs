//! A local liveness view over the DAG.
//!
//! The detector answers one question: which validators have stopped advancing?
//! It reads only vertices the node holds, so the answer is a local view, not
//! shared evidence. It is deliberately not a consensus input: two nodes with
//! different delivery can hold different views, and a decision made from a local
//! view could make their commit sequences diverge. A validator declared failed by
//! this view is a *report*, and any transition that acts on it must be authorized
//! and agreed on by the set (the checked set-change path in `set_change`).
//!
//! The unit is rounds, not wall time: rounds are the protocol's own clock, and a
//! node that is slow to receive can only report what it has seen. Silence is
//! measured as *lack of progress*: a validator is silent when the fastest author
//! this node has seen advanced `threshold` rounds without that validator
//! advancing. Comparing absolute rounds instead would call a node that simply
//! started a few rounds behind silent forever, because its offset never closes.

use std::collections::BTreeMap;

use crate::schedule::ValidatorSet;

/// Tracks the last round each validator was seen at.
#[derive(Debug, Clone)]
pub struct FailureDetector {
    authors: Vec<Vec<u8>>,
    threshold: u64,
    highest: u64,
    last: BTreeMap<Vec<u8>, u64>,
    /// The highest round seen when this author last advanced.
    ///
    /// A node that is consistently a few rounds behind still advances its last
    /// round every time it authors; only the gap from this mark is silence.
    advanced_at: BTreeMap<Vec<u8>, u64>,
}

impl FailureDetector {
    /// Creates a detector for every validator in `set`.
    ///
    /// A threshold of zero reports nothing: absence is not measured, and the
    /// detector is the explicit owner of that policy.
    #[must_use]
    pub fn new(set: &ValidatorSet, threshold: u64) -> Self {
        Self {
            authors: set
                .validators
                .iter()
                .map(|validator| validator.validator_id.clone())
                .collect(),
            threshold,
            highest: 0,
            last: BTreeMap::new(),
            advanced_at: BTreeMap::new(),
        }
    }

    /// Records that `author` was seen at `round`.
    ///
    /// Seeing a later vertex after a silence clears the report. The highest round
    /// only moves forward; a vertex below it changes one author's last round.
    pub fn observe(&mut self, round: u64, author: &[u8]) {
        self.highest = self.highest.max(round);
        let last = self.last.entry(author.to_vec()).or_insert(round);
        if round > *last {
            *last = round;
            self.advanced_at.insert(author.to_vec(), self.highest);
        } else if !self.advanced_at.contains_key(author) {
            self.advanced_at.insert(author.to_vec(), self.highest);
        }
    }

    /// The highest round this detector has seen.
    #[must_use]
    pub fn highest_round(&self) -> u64 {
        self.highest
    }

    /// The configured silence threshold, in rounds.
    #[must_use]
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// Tracks the validators of the set active now.
    ///
    /// Observations for validators that remain are kept; a validator that left
    /// the set is dropped, and a new one starts unseen. A key rotation keeps the
    /// same identities, so it leaves the observations untouched.
    pub fn update_set(&mut self, set: &ValidatorSet) {
        self.authors = set
            .validators
            .iter()
            .map(|validator| validator.validator_id.clone())
            .collect();
        self.last
            .retain(|author, _| self.authors.iter().any(|tracked| tracked == author));
        self.advanced_at
            .retain(|author, _| self.authors.iter().any(|tracked| tracked == author));
    }

    /// Validators that have not advanced for more than `threshold` rounds, in
    /// set order.
    ///
    /// The second value is the last round each one was seen at; zero means it has
    /// never been seen. The list is empty when the threshold is zero.
    #[must_use]
    pub fn silent(&self) -> Vec<(Vec<u8>, u64)> {
        if self.threshold == 0 {
            return Vec::new();
        }
        self.authors
            .iter()
            .filter_map(|author| {
                let last = self.last.get(author).copied();
                // Never seen: silence is measured from round zero, so a peer that
                // never connects is reported. Seen: silence is measured from the
                // point its last round advanced, not from that round itself.
                let since = self.advanced_at.get(author).copied().unwrap_or(0);
                (self.highest.saturating_sub(since) > self.threshold)
                    .then(|| (author.clone(), last.unwrap_or(0)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;

    const EPOCH: u64 = 1;
    const COUNT: usize = 4;

    fn set() -> ValidatorSet {
        let mut validators = Vec::with_capacity(COUNT);
        for index in 0..COUNT {
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: vec![u8::try_from(index).unwrap(); 32],
                    activation_epoch: EPOCH,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
        }
        let set = ValidatorSet {
            epoch: EPOCH,
            validators,
        };
        set.validate().unwrap();
        set
    }

    #[test]
    fn a_validator_that_misses_more_than_the_threshold_is_silent() {
        let mut detector = FailureDetector::new(&set(), 2);
        for round in 1..=5 {
            for author in 0..4 {
                detector.observe(round, format!("val-{author}").as_bytes());
            }
        }
        assert_eq!(detector.highest_round(), 5);
        assert!(detector.silent().is_empty(), "all four authors are current");

        // From round 6 on, val-0 and val-1 keep authoring and val-2/val-3 stop.
        for round in 6..=8 {
            detector.observe(round, b"val-0");
            detector.observe(round, b"val-1");
        }
        let silent: Vec<String> = detector
            .silent()
            .into_iter()
            .map(|(author, last)| format!("{}@{last}", String::from_utf8(author).unwrap()))
            .collect();
        assert_eq!(silent, vec!["val-2@5", "val-3@5"]);
    }

    #[test]
    fn a_short_gap_is_not_silence_and_a_return_clears_it() {
        let mut detector = FailureDetector::new(&set(), 2);
        detector.observe(1, b"val-0");
        for round in 2..=3 {
            for author in [1, 2, 3] {
                detector.observe(round, format!("val-{author}").as_bytes());
            }
        }
        assert!(
            detector.silent().is_empty(),
            "two missed rounds is not silent"
        );

        for round in 4..=5 {
            for author in [1, 2, 3] {
                detector.observe(round, format!("val-{author}").as_bytes());
            }
        }
        assert_eq!(detector.silent().len(), 1, "val-0 missed four rounds");
        detector.observe(6, b"val-0");
        assert!(detector.silent().is_empty(), "a return clears the report");
    }

    #[test]
    fn a_constant_lag_is_not_silence() {
        // `val-3` started a few rounds late, so its absolute round stays behind.
        // It advances every round, which is liveness; the detector must not call
        // that silence forever.
        let mut detector = FailureDetector::new(&set(), 2);
        for round in 1..=20 {
            for author in 0..3 {
                detector.observe(round, format!("val-{author}").as_bytes());
            }
            if round > 5 {
                detector.observe(round - 5, b"val-3");
            }
        }
        assert!(
            detector.silent().is_empty(),
            "an advancing validator is not silent just because it is behind"
        );
    }

    #[test]
    fn a_removed_validator_is_no_longer_tracked() {
        let mut detector = FailureDetector::new(&set(), 2);
        for round in 1..=5 {
            for author in 0..4 {
                detector.observe(round, format!("val-{author}").as_bytes());
            }
        }
        for round in 6..=8 {
            for author in 0..3 {
                detector.observe(round, format!("val-{author}").as_bytes());
            }
        }
        assert_eq!(detector.silent().len(), 1, "val-3 went silent");

        let mut smaller = set();
        smaller
            .validators
            .retain(|validator| validator.validator_id != b"val-3");
        smaller.validate().unwrap();
        detector.update_set(&smaller);
        assert!(
            detector.silent().is_empty(),
            "a validator that left the set must not be reported"
        );
    }

    #[test]
    fn a_zero_threshold_reports_nothing() {
        let mut detector = FailureDetector::new(&set(), 0);
        detector.observe(10, b"val-0");
        assert!(detector.silent().is_empty());
        assert_eq!(detector.threshold(), 0);
    }
}
