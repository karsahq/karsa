//! A deterministic pacemaker: it decides which rounds to try to decide, and in
//! which order.
//!
//! The commit rules in [`crate::Dag`] answer "given what I hold, what can I
//! decide?". They never answer "what should I ask next?", and without a caller
//! doing that a stalled round stops the chain even though every later round is
//! fine. That caller is this module.
//!
//! # Why there is no clock here
//!
//! The pacemaker advances on `ticks`, and a tick is whatever the driver says it
//! is: a logical event, injected in a fixed order. There is no wall clock, no
//! `Instant`, and no randomness, so the same DAG plus the same tick sequence
//! always produces the same output. That is what keeps `karsa dagsim` a
//! reproducible record rather than a log.
//!
//! A real node turns a timeout into a *request for missing vertices*. It must not
//! turn it into a local decision, because a decision made by one node about data
//! it does not have is a decision other nodes may not make.
//!
//! # The two cursors
//!
//! - `cursor` is the lowest round whose leader is not yet decided. It only moves
//!   forward, never back.
//! - `anchor` is the leader of the highest round the DAG already supports, meaning
//!   a quorum of the next round references it. It is not necessarily emitted yet:
//!   emission happens only when the cursor reaches that round, so the committed
//!   sequence stays a function of the DAG rather than of arrival order.
//!
//! A leader whose vertex never arrives blocks the cursor. It cannot be skipped
//! from local knowledge alone: another node may hold it and commit it. So the
//! pacemaker does something narrower and provable: it looks for an anchor, and if
//! a committed anchor two or more rounds later does not reach the missing leader,
//! that leader can never be committed by anyone, and the round is skippable.
//!
//! To find such an anchor the cursor has to look past itself. [`Pacemaker::probe`]
//! only *finds* one; it never emits. Emitting out of cursor order was a real bug:
//! two nodes with the same final DAG committed different sequences, because the
//! one that had more data at the time probed further first. `crates/net` caught
//! that, and the fix is that the anchor unlocks the indirect rule while emission
//! stays ordered.

use crypto::{CryptoError, CryptoErrorKind};

use crate::dag::{Dag, Decision};
use crate::vertex::VertexId;

/// How the pacemaker is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacemakerConfig {
    /// Consecutive ticks without progress before a [`Step::TimedOut`].
    ///
    /// The counter restarts after every timeout, so a permanent stall keeps
    /// reporting rather than firing once and going quiet.
    pub timeout_ticks: u32,
}

impl Default for PacemakerConfig {
    fn default() -> Self {
        Self { timeout_ticks: 3 }
    }
}

/// What one [`Pacemaker::tick`] produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// At least one decision was made.
    Advanced {
        /// Lowest undecided round before the tick.
        from: u64,
        /// Lowest undecided round after the tick.
        cursor: u64,
        /// Leaders committed by this tick.
        commits: usize,
        /// Rounds skipped by this tick.
        skips: usize,
        /// Anchors found ahead of `cursor`. An anchor is quorum-supported but not
        /// yet emitted: emission happens in cursor order so that two nodes with the
        /// same DAG commit the same sequence.
        anchors: usize,
    },
    /// Nothing could be decided and the stall is shorter than the timeout.
    Waiting {
        /// Lowest undecided round.
        cursor: u64,
        /// Consecutive unproductive ticks so far.
        waited: u32,
    },
    /// Nothing could be decided for `timeout_ticks` consecutive ticks.
    ///
    /// On a real node this is the signal to request the missing vertices. It is
    /// deliberately not a decision.
    TimedOut {
        /// Lowest undecided round.
        cursor: u64,
        /// Highest round this node holds any vertex for.
        observed: u64,
        /// How many timeouts have fired since construction.
        timeouts: u64,
    },
}

/// One step of the decision loop.
enum Advance {
    /// A leader at the cursor committed.
    Commit,
    /// The cursor skipped its leader.
    Skip,
    /// A leader ahead of the cursor has quorum support, so the anchor moved.
    Anchor,
    /// Nothing could be decided.
    Stalled,
}

/// Drives a [`Dag`] forward one round at a time.
#[derive(Debug, Clone)]
pub struct Pacemaker {
    config: PacemakerConfig,
    cursor: u64,
    anchor: Option<VertexId>,
    observed: u64,
    ticks_waited: u32,
    timeouts: u64,
}

impl Pacemaker {
    /// Creates a pacemaker that will decide `start_round` first.
    ///
    /// `start_round` is the first round with a leader. Round 0 is genesis and has
    /// no leader to decide, so callers normally start at 1.
    #[must_use]
    pub fn new(config: PacemakerConfig, start_round: u64) -> Self {
        Self {
            config,
            cursor: start_round,
            anchor: None,
            observed: start_round,
            ticks_waited: 0,
            timeouts: 0,
        }
    }

    /// The lowest round whose leader has not been decided yet.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// The leader of the highest round the DAG supports, if any.
    ///
    /// Quorum-backed, not necessarily emitted: see the module documentation.
    #[must_use]
    pub fn anchor(&self) -> Option<&VertexId> {
        self.anchor.as_ref()
    }

    /// Highest round this node holds any vertex for.
    #[must_use]
    pub fn observed(&self) -> u64 {
        self.observed
    }

    /// How many timeouts have fired since construction.
    #[must_use]
    pub fn timeouts(&self) -> u64 {
        self.timeouts
    }

    /// Takes one logical tick.
    ///
    /// The tick first decides everything it can, then either reports progress or
    /// counts itself as part of a stall. It is safe to call after every received
    /// vertex as well as on a timer: a tick with nothing to do is cheap and only
    /// affects the stall counter.
    ///
    /// # Errors
    ///
    /// Propagates the commit rules' errors. A
    /// [`CryptoErrorKind::MissingReference`] here means a held vertex references
    /// one this node does not have, so the question is unanswerable until it
    /// arrives.
    pub fn tick(&mut self, dag: &mut Dag) -> Result<Step, CryptoError> {
        if let Some(highest) = dag.highest_round() {
            self.observed = self.observed.max(highest);
        }

        let from = self.cursor;
        let mut commits = 0usize;
        let mut skips = 0usize;
        let mut anchors = 0usize;
        loop {
            match self.advance_once(dag)? {
                Advance::Commit => commits += 1,
                Advance::Skip => skips += 1,
                Advance::Anchor => anchors += 1,
                Advance::Stalled => break,
            }
        }

        if commits > 0 || skips > 0 || anchors > 0 {
            self.ticks_waited = 0;
            return Ok(Step::Advanced {
                from,
                cursor: self.cursor,
                commits,
                skips,
                anchors,
            });
        }

        self.ticks_waited = self.ticks_waited.saturating_add(1);
        if self.ticks_waited >= self.config.timeout_ticks {
            self.ticks_waited = 0;
            self.timeouts += 1;
            return Ok(Step::TimedOut {
                cursor: self.cursor,
                observed: self.observed,
                timeouts: self.timeouts,
            });
        }
        Ok(Step::Waiting {
            cursor: self.cursor,
            waited: self.ticks_waited,
        })
    }

    /// Makes at most one decision.
    fn advance_once(&mut self, dag: &mut Dag) -> Result<Advance, CryptoError> {
        let round = self.cursor;

        match dag.try_commit(round)? {
            Decision::Commit(_) => {
                self.set_anchor(dag, round)?;
                self.cursor = round + 1;
                return Ok(Advance::Commit);
            }
            Decision::Skip => {
                self.cursor = round + 1;
                return Ok(Advance::Skip);
            }
            Decision::Undecided => {}
        }

        // An anchor two or more rounds ahead is what makes an earlier slot
        // decidable at all, so nothing else is worth trying without one.
        if let Some(anchor) = self.anchor.clone()
            && anchor.round >= round + 2
        {
            match dag.try_indirect_decide(round, &anchor)? {
                Decision::Commit(_) => {
                    self.set_anchor(dag, round)?;
                    self.cursor = round + 1;
                    return Ok(Advance::Commit);
                }
                Decision::Skip => {
                    self.cursor = round + 1;
                    return Ok(Advance::Skip);
                }
                Decision::Undecided => {
                    // Reaching here means the leader is absent: the indirect rule
                    // bails out before checking reachability when the node does
                    // not hold the leader's vertex.
                    if self.skip_absent_leader(dag, &anchor)? {
                        self.cursor = round + 1;
                        return Ok(Advance::Skip);
                    }
                }
            }
        }

        // The cursor is stuck. Earn an anchor from a later round instead of
        // waiting for data that may never come.
        if let Some(anchor) = self.probe(dag)? {
            self.anchor = Some(anchor);
            return Ok(Advance::Anchor);
        }

        Ok(Advance::Stalled)
    }

    /// Records `round`'s leader as the anchor after a commit there.
    fn set_anchor(&mut self, dag: &Dag, round: u64) -> Result<(), CryptoError> {
        let Some(leader) = dag.leader(round) else {
            return Ok(());
        };
        let anchor = leader.id()?;
        let better = match &self.anchor {
            None => true,
            Some(current) => anchor.round > current.round,
        };
        if better {
            self.anchor = Some(anchor);
        }
        Ok(())
    }

    /// Skips a leader whose vertex this node never received, when an anchor proves
    /// it can never be committed.
    ///
    /// Returns whether the skip was recorded.
    fn skip_absent_leader(
        &mut self,
        dag: &mut Dag,
        anchor: &VertexId,
    ) -> Result<bool, CryptoError> {
        let round = self.cursor;
        if dag.leader(round).is_some() {
            // The vertex is here, so the indirect rule already had its chance.
            return Ok(false);
        }
        let Some(author) = dag.leader_author(round) else {
            return Ok(false);
        };
        let author = author.to_vec();

        match dag.history_contains_author(anchor, round, &author) {
            // The anchor shows a vertex this node has not received. That is a
            // delivery problem, not a decision: wait for it.
            Ok(true) => return Ok(false),
            Ok(false) => {}
            // An incomplete walk cannot prove absence.
            Err(error) if error.kind() == CryptoErrorKind::MissingReference => return Ok(false),
            Err(error) => return Err(error),
        }

        Ok(dag.record_skip(round, author, None))
    }

    /// Finds the lowest leader ahead of the cursor that the DAG already supports,
    /// and returns it as a new anchor.
    ///
    /// Finding an anchor is not a commit. Emitting here would put a later leader's
    /// history into the sequence before the rounds in front of it, so two nodes
    /// that found the same anchor at different times would commit different
    /// sequences from the same DAG. The anchor only unlocks the indirect rule; the
    /// emission happens when the cursor reaches that round.
    fn probe(&self, dag: &Dag) -> Result<Option<VertexId>, CryptoError> {
        let floor = match &self.anchor {
            Some(anchor) => anchor.round.saturating_add(1).max(self.cursor + 1),
            None => self.cursor + 1,
        };
        for round in floor..=self.observed {
            if let Some(id) = dag.is_anchored(round)? {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet};
    use crate::vertex::Vertex;
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const EPOCH: u64 = 1;
    const COUNT: usize = 4;

    struct Fixture {
        keys: Vec<Vec<u8>>,
        dag: Dag,
    }

    fn fixture() -> Fixture {
        let mut keys = Vec::with_capacity(COUNT);
        let mut validators = Vec::with_capacity(COUNT);
        for index in 0..COUNT {
            let seed = [u8::try_from(index + 1).unwrap(); 32];
            let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
            let mut private_key = Vec::with_capacity(64);
            private_key.extend_from_slice(&seed);
            private_key.extend_from_slice(&public_key);
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: public_key.to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            keys.push(private_key);
        }
        let set = ValidatorSet {
            epoch: EPOCH,
            validators,
        };
        set.validate().unwrap();
        Fixture {
            keys,
            dag: Dag::new(set),
        }
    }

    fn vertex(fixture: &Fixture, author: usize, round: u64, references: Vec<VertexId>) -> Vertex {
        let mut vertex = Vertex {
            chain_id: b"karsa-pacemaker-1".to_vec(),
            epoch: EPOCH,
            round,
            author: format!("val-{author}").into_bytes(),
            payload_hash: [u8::try_from(author + 1).unwrap(); 32],
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload().unwrap();
        vertex.signature = Ed25519Scheme.sign(&fixture.keys[author], &payload).unwrap();
        vertex
    }

    impl Fixture {
        fn count(&self) -> usize {
            self.dag.set().validators.len()
        }

        /// Ids of every vertex this node holds in `round`, in author order.
        fn ids(&self, round: u64) -> Vec<VertexId> {
            let mut ids = Vec::new();
            for author in 0..self.count() {
                let key = format!("val-{author}");
                if let Some(vertex) = self.dag.get(round, key.as_bytes()) {
                    ids.push(vertex.id().unwrap());
                }
            }
            ids
        }

        /// Inserts `round` for every author except those listed in `absent`.
        fn insert_round(
            &mut self,
            round: u64,
            references: &[VertexId],
            absent: &[usize],
        ) -> Result<(), CryptoError> {
            for author in 0..self.count() {
                if absent.contains(&author) {
                    continue;
                }
                let vertex = vertex(self, author, round, references.to_vec());
                self.dag.insert(vertex)?;
            }
            Ok(())
        }

        /// Extends the DAG by one complete round referencing everything held in
        /// the round before it.
        fn add_round(&mut self, round: u64) -> Result<(), CryptoError> {
            let references = self.ids(round - 1);
            self.insert_round(round, &references, &[])
        }

        /// Ids of `round` except that round's leader.
        fn ids_without_leader(&self, round: u64) -> Vec<VertexId> {
            let leader = usize::try_from(round).unwrap() % self.count();
            self.ids(round)
                .into_iter()
                .filter(|id| id.author != format!("val-{leader}").into_bytes())
                .collect()
        }

        /// Adds a round whose vertices reference `references` rather than the
        /// previous round.
        fn insert_round_with(
            &mut self,
            round: u64,
            references: &[VertexId],
        ) -> Result<(), CryptoError> {
            self.insert_round(round, references, &[])
        }
    }

    /// Builds rounds `0..=upto`, omitting the listed `(round, author)` pairs.
    fn chain(upto: u64, absent: &[(u64, usize)]) -> Fixture {
        let mut fixture = fixture();
        for round in 0..=upto {
            let references = if round == 0 {
                Vec::new()
            } else {
                fixture.ids(round - 1)
            };
            let skip: Vec<usize> = absent
                .iter()
                .filter(|(at, _)| *at == round)
                .map(|(_, author)| *author)
                .collect();
            fixture.insert_round(round, &references, &skip).unwrap();
        }
        fixture
    }

    fn pacemaker(timeout_ticks: u32) -> Pacemaker {
        Pacemaker::new(PacemakerConfig { timeout_ticks }, 1)
    }

    /// A leader the pacemaker decided to skip must never also be committed.
    fn assert_skipped_leaders_stay_uncommitted(fixture: &Fixture) {
        for skipped in fixture.dag.skipped() {
            let committed = fixture
                .dag
                .order()
                .iter()
                .any(|id| id.round == skipped.round && id.author == skipped.author);
            assert!(
                !committed,
                "{}@{} was skipped and committed",
                String::from_utf8_lossy(&skipped.author),
                skipped.round
            );
        }
    }

    #[test]
    fn a_full_chain_commits_every_round_in_one_tick() {
        let mut fixture = chain(8, &[]);
        let mut pacemaker = pacemaker(3);

        let step = pacemaker.tick(&mut fixture.dag).unwrap();

        assert_eq!(
            step,
            Step::Advanced {
                from: 1,
                cursor: 8,
                commits: 7,
                skips: 0,
                anchors: 0
            }
        );
        assert!(fixture.dag.skipped().is_empty());
    }

    #[test]
    fn a_missing_leader_is_skipped_once_a_later_anchor_commits() {
        // Round 5 is led by `val-1` (5 % 4), and `val-1` never authored it.
        let mut fixture = chain(8, &[(5, 1)]);
        let mut pacemaker = pacemaker(3);

        let step = pacemaker.tick(&mut fixture.dag).unwrap();

        assert!(matches!(
            step,
            Step::Advanced {
                cursor: 8,
                skips: 1,
                ..
            }
        ));
        assert_eq!(pacemaker.cursor(), 8);
        assert_eq!(fixture.dag.skipped().len(), 1);
        let skipped = &fixture.dag.skipped()[0];
        assert_eq!(skipped.round, 5);
        assert_eq!(skipped.author, b"val-1");
        assert_eq!(skipped.digest, None);
    }

    #[test]
    fn a_present_but_unsupported_leader_is_skipped_and_never_committed() {
        // Rounds 0..=5 are complete, but round 6 references every author of
        // round 5 except that round's leader, `val-1`.
        let mut fixture = chain(5, &[]);
        let unsupported = fixture.ids_without_leader(5);
        fixture.insert_round_with(6, &unsupported).unwrap();
        fixture.add_round(7).unwrap();
        fixture.add_round(8).unwrap();

        let mut pacemaker = pacemaker(3);
        let step = pacemaker.tick(&mut fixture.dag).unwrap();

        assert!(matches!(
            step,
            Step::Advanced {
                cursor: 8,
                skips: 1,
                ..
            }
        ));
        let skipped = &fixture.dag.skipped()[0];
        assert_eq!(skipped.round, 5);
        assert_eq!(skipped.author, b"val-1");
        assert!(skipped.digest.is_some(), "the leader's vertex is held");
        assert_skipped_leaders_stay_uncommitted(&fixture);
    }

    #[test]
    fn an_absent_leader_is_never_committed() {
        let mut fixture = chain(8, &[(5, 1)]);
        let mut pacemaker = pacemaker(3);
        pacemaker.tick(&mut fixture.dag).unwrap();

        assert!(fixture.dag.leader(5).is_none());
        assert!(
            fixture
                .dag
                .order()
                .iter()
                .all(|id| !(id.round == 5 && id.author == b"val-1"))
        );
        // The rounds around the gap still committed.
        assert!(fixture.dag.order().iter().any(|id| id.round == 6));
        assert!(fixture.dag.order().iter().any(|id| id.round == 7));
    }

    #[test]
    fn an_unresolvable_stall_times_out() {
        // Round 3 is led by `val-3`, and that vertex never arrives.
        let mut fixture = chain(3, &[(3, 3)]);
        let mut pacemaker = pacemaker(2);

        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Advanced { cursor: 3, .. }
        ));
        assert_eq!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Waiting {
                cursor: 3,
                waited: 1
            }
        );
        assert_eq!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::TimedOut {
                cursor: 3,
                observed: 3,
                timeouts: 1
            }
        );
        // A permanent stall keeps reporting instead of going quiet.
        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Waiting { waited: 1, .. }
        ));
        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::TimedOut { timeouts: 2, .. }
        ));
    }

    #[test]
    fn progress_resets_the_stall_counter() {
        let mut fixture = chain(3, &[]);
        let mut pacemaker = pacemaker(3);

        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Advanced { cursor: 3, .. }
        ));
        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Waiting { waited: 1, .. }
        ));

        fixture.add_round(4).unwrap();
        fixture.add_round(5).unwrap();
        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Advanced {
                from: 3,
                cursor: 5,
                ..
            }
        ));

        assert!(matches!(
            pacemaker.tick(&mut fixture.dag).unwrap(),
            Step::Waiting { waited: 1, .. }
        ));
    }

    #[test]
    fn the_cursor_never_moves_backwards() {
        let mut fixture = chain(10, &[(6, 2)]);
        let mut pacemaker = pacemaker(2);

        let mut previous = pacemaker.cursor();
        for _ in 0..10 {
            pacemaker.tick(&mut fixture.dag).unwrap();
            assert!(pacemaker.cursor() >= previous);
            previous = pacemaker.cursor();
        }
        assert_eq!(pacemaker.cursor(), 10);
    }

    #[test]
    fn the_same_dag_produces_the_same_steps() {
        fn run() -> Vec<Step> {
            let mut fixture = chain(8, &[(5, 1)]);
            let mut pacemaker = pacemaker(2);
            (0..6)
                .map(|_| pacemaker.tick(&mut fixture.dag).unwrap())
                .collect()
        }

        assert_eq!(run(), run());
    }

    #[test]
    fn the_commit_sequence_is_a_function_of_the_dag() {
        fn run() -> Vec<VertexId> {
            let mut fixture = chain(8, &[(5, 1)]);
            let mut pacemaker = pacemaker(2);
            for _ in 0..4 {
                pacemaker.tick(&mut fixture.dag).unwrap();
            }
            fixture.dag.order().to_vec()
        }

        let first = run();
        assert!(!first.is_empty());
        assert_eq!(first, run());
    }

    #[test]
    fn a_gap_in_a_slot_that_is_not_the_leader_does_not_stop_the_chain() {
        // `val-2` is silent in round 5, but the round-5 leader is `val-1`.
        let mut fixture = chain(8, &[(5, 2)]);
        let mut pacemaker = pacemaker(2);
        let step = pacemaker.tick(&mut fixture.dag).unwrap();

        assert_eq!(
            step,
            Step::Advanced {
                from: 1,
                cursor: 8,
                commits: 7,
                skips: 0,
                anchors: 0
            }
        );
        assert!(fixture.dag.skipped().is_empty());
    }
}
