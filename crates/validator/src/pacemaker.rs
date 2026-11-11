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
//! - the anchor is not stored. It is derived from the DAG on every tick: a round is
//!   anchored when a quorum of the next round references its leader. The pacemaker
//!   uses the *lowest* anchored round two or more rounds ahead that skips only
//!   rounds whose leader its history proves absent. Deriving it rather than caching
//!   it is what stops two nodes with the same final DAG from deciding differently.
//!
//! A leader whose vertex never arrives blocks the cursor. It cannot be skipped
//! from local knowledge alone: another node may hold it and commit it. So the
//! pacemaker does something narrower and provable: it looks for an anchor, and if
//! an anchored round two or more rounds later does not reach the missing leader,
//! that leader can never be committed by anyone, and the round is skippable.
//!
//! To find such an anchor the cursor has to look past itself. The anchor never
//! emits: emission happens only when the cursor reaches that round, because
//! emitting out of cursor order was a real bug — two nodes with the same final DAG
//! committed different sequences, because the one that had more data at the time
//! probed further first.

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
    /// A leader ahead of the cursor already has quorum support, so the DAG is
    /// growing even though the cursor cannot move yet.
    Anchor,
    /// Nothing could be decided.
    Stalled,
}

/// Whether the leader of the cursor round is provably reachable from an anchor.
///
/// Three states, not two: "this node cannot tell" is not the same as "not
/// reachable", and only one of them permits a decision. Collapsing them is how a
/// node ends up deciding on a history it only partly holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Reach {
    /// The anchor's history contains the leader.
    Yes,
    /// The leader is held, and it is not on the anchored history.
    No,
    /// The leader's own vertex is not held; the indirect rule's absence proof
    /// decides whether the round may be skipped.
    Missing,
    /// The walk reached a vertex this node does not hold, so nothing is proved.
    Unknown,
}

/// How many times each decision rule moved the cursor past a leader.
///
/// The rules are not interchangeable: a direct or indirect skip is proved by the
/// DAG alone, while a fence skip is proved by a quorum declaration plus the
/// fault budget. Keeping them apart is what lets a live run say *why* a stuck
/// round was released instead of only that the cursor moved.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SkipCounts {
    /// A supermajority of the next round was observed not to vote.
    pub direct: u64,
    /// A committed anchor decided the round.
    pub indirect: u64,
    /// An anchor proved the leader's vertex cannot be in this node's history.
    pub absent: u64,
    /// A quorum fenced the leader itself.
    pub fence_leader: u64,
    /// A quorum fenced the only missing voter of a live leader.
    pub fence_voter: u64,
    /// A round-skip proof accounted for every voter below the quorum.
    ///
    /// Always zero after D74: a certificate is reporting evidence and never
    /// moves the cursor.
    pub attested: u64,
}

impl SkipCounts {
    /// Skips that needed a fence certificate.
    #[must_use]
    pub fn fenced(self) -> u64 {
        self.fence_leader.saturating_add(self.fence_voter)
    }

    /// All skips, whatever proved them.
    #[must_use]
    pub fn total(self) -> u64 {
        self.direct
            .saturating_add(self.indirect)
            .saturating_add(self.absent)
            .saturating_add(self.fenced())
            .saturating_add(self.attested)
    }
}

/// Drives a [`Dag`] forward one round at a time.
#[derive(Debug, Clone)]
pub struct Pacemaker {
    config: PacemakerConfig,
    cursor: u64,
    observed: u64,
    ticks_waited: u32,
    timeouts: u64,
    skips: SkipCounts,
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
            observed: start_round,
            ticks_waited: 0,
            timeouts: 0,
            skips: SkipCounts::default(),
        }
    }

    /// The lowest round whose leader has not been decided yet.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.cursor
    }

    /// Sets the first round the pacemaker will decide.
    ///
    /// A node that adopts a committed prefix from a snapshot starts after the
    /// last decision; it must not re-decide rounds the snapshot already covers.
    pub fn set_cursor(&mut self, cursor: u64) {
        self.cursor = cursor;
        self.observed = self.observed.max(cursor);
        self.ticks_waited = 0;
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

    /// How each skip decision was proved, since construction.
    #[must_use]
    pub fn skip_counts(&self) -> SkipCounts {
        self.skips
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
                Advance::Anchor => {
                    // Recording an anchor does not move the cursor, so another
                    // pass in the same tick would return the same anchor forever.
                    anchors += 1;
                    break;
                }
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

    /// Takes one decision and returns, instead of draining every one available.
    ///
    /// [`Pacemaker::tick`] is the normal driver: it keeps deciding while it can, and
    /// a caller that only observes the cursor sees the end state of that batch.
    /// A caller that materializes an artifact per decision — one header per commit,
    /// for example — needs the boundaries, so this stops after the first commit or
    /// skip. An anchor or a stall returns without moving the cursor and therefore
    /// without deciding anything.
    ///
    /// Calling this repeatedly produces the same decision sequence as calling
    /// [`Pacemaker::tick`] once, because both run the same [`Advance`] rules in the
    /// same order; only the reporting granularity differs.
    ///
    /// # Errors
    ///
    /// Propagates the commit rules' errors, as [`Pacemaker::tick`] does.
    pub fn tick_one(&mut self, dag: &mut Dag) -> Result<Step, CryptoError> {
        if let Some(highest) = dag.highest_round() {
            self.observed = self.observed.max(highest);
        }

        let from = self.cursor;
        let step = match self.advance_once(dag)? {
            Advance::Commit => Step::Advanced {
                from,
                cursor: self.cursor,
                commits: 1,
                skips: 0,
                anchors: 0,
            },
            Advance::Skip => Step::Advanced {
                from,
                cursor: self.cursor,
                commits: 0,
                skips: 1,
                anchors: 0,
            },
            Advance::Anchor => Step::Advanced {
                from,
                cursor: self.cursor,
                commits: 0,
                skips: 0,
                anchors: 1,
            },
            Advance::Stalled => {
                self.ticks_waited = self.ticks_waited.saturating_add(1);
                if self.ticks_waited >= self.config.timeout_ticks {
                    self.ticks_waited = 0;
                    self.timeouts += 1;
                    Step::TimedOut {
                        cursor: self.cursor,
                        observed: self.observed,
                        timeouts: self.timeouts,
                    }
                } else {
                    Step::Waiting {
                        cursor: self.cursor,
                        waited: self.ticks_waited,
                    }
                }
            }
        };
        if matches!(step, Step::Advanced { .. }) {
            self.ticks_waited = 0;
        }
        Ok(step)
    }

    /// Makes at most one decision.
    fn advance_once(&mut self, dag: &mut Dag) -> Result<Advance, CryptoError> {
        let round = self.cursor;

        match dag.try_commit(round)? {
            Decision::Commit(_) => {
                self.cursor = round + 1;
                return Ok(Advance::Commit);
            }
            Decision::Skip => {
                self.skips.direct = self.skips.direct.saturating_add(1);
                self.cursor = round + 1;
                return Ok(Advance::Skip);
            }
            Decision::Undecided => {}
        }

        // A fenced leader is failed by a quorum, so no honest quorum can vote
        // for it at or after the fence. This runs after the direct and indirect
        // rules: a commit always wins, and a fence only decides a round that is
        // otherwise stuck.
        if dag.skip_fenced_leader(round)? {
            self.skips.fence_leader = self.skips.fence_leader.saturating_add(1);
            self.cursor = round + 1;
            return Ok(Advance::Skip);
        }
        // A live leader can still be blocked by one failed voter. With at most
        // `f` held votes, even a late vote from every fenced validator cannot
        // reach the `2f + 1` quorum, so the skip is safe under the fence's
        // declaration.
        if dag.skip_with_fence(round)? {
            self.skips.fence_voter = self.skips.fence_voter.saturating_add(1);
            self.cursor = round + 1;
            return Ok(Advance::Skip);
        }

        // An anchor two or more rounds ahead is what makes an earlier slot
        // decidable at all. Use the *lowest* usable one and never skip over a
        // round whose status is still unknown: a higher anchor can contain a
        // leader the lower one does not, so choosing it early would make the
        // commit order depend on when data arrived rather than on the DAG.
        if let Some(anchor) = self.stable_anchor(dag, round)? {
            // A round-skip certificate is negative evidence: it proves that no
            // vote quorum can form, but it can arrive after another node has
            // already committed the same leader through its anchor. Overriding
            // that commit here forks the committed order (measured: an A/B
            // devnet changed the commit root on one node only). A certificate is
            // therefore reporting evidence, not a decision; the anchor rule and
            // the fence rules remain the only things that advance the cursor.
            // `try_indirect_decide` commits the leader's history as a side
            // effect, so the two ways this node could be wrong are ruled out
            // first: a walk it cannot finish (nothing is proved), and a skip
            // that could still win (a non-vote quorum may exist, and a skip must
            // not race a commit).
            let reach = match dag.leader(round) {
                Some(leader) => {
                    let leader_id = leader.id()?;
                    match dag.is_ancestor(&leader_id, &anchor) {
                        Ok(true) => Reach::Yes,
                        Ok(false) => Reach::No,
                        // A partial walk proves nothing. Deciding anyway is how the
                        // commit order starts to depend on arrival timing.
                        Err(error) if error.kind() == CryptoErrorKind::MissingReference => {
                            Reach::Unknown
                        }
                        Err(error) => return Err(error),
                    }
                }
                // Not held: the indirect rule's own absence proof decides.
                None => Reach::Missing,
            };

            let decision = match reach {
                Reach::Unknown => None,
                Reach::Yes if dag.held_voters(round)? <= dag.set().max_faulty() => None,
                _ => Some(dag.try_indirect_decide(round, &anchor)?),
            };

            if let Some(decision) = decision {
                match decision {
                    Decision::Commit(_) => {
                        self.cursor = round + 1;
                        return Ok(Advance::Commit);
                    }
                    Decision::Skip => {
                        self.skips.indirect = self.skips.indirect.saturating_add(1);
                        self.cursor = round + 1;
                        return Ok(Advance::Skip);
                    }
                    Decision::Undecided => {
                        // Reaching here means the leader is absent: the indirect
                        // rule bails out before checking reachability when the
                        // node does not hold the leader's vertex.
                        if self.skip_absent_leader(dag, &anchor)? {
                            self.skips.absent = self.skips.absent.saturating_add(1);
                            self.cursor = round + 1;
                            return Ok(Advance::Skip);
                        }
                    }
                }
            }
        }

        // The cursor is stuck. Note an anchored round ahead so the stall counter
        // does not fire while the DAG is still growing.
        if self.has_anchored_ahead(dag)? {
            return Ok(Advance::Anchor);
        }

        Ok(Advance::Stalled)
    }

    /// Finds the lowest anchor that can decide `round` without guessing about a
    /// round in between.
    ///
    /// An anchor at round `a` probes every round `q` in `round + 2 .. a`. If `q`
    /// is already anchored it is not the lowest; that cannot happen because the
    /// scan is ascending. A round can be passed over when the anchor proves its
    /// leader absent, or when the leader is inside the anchor's history and no
    /// vote quorum for `q` is possible any more (so `q` can never anchor). The
    /// remaining case — the round may still anchor, or the walk is incomplete —
    /// means the answer is unknown, so this node waits.
    ///
    /// Using a higher anchor while a lower one is still possible is what makes
    /// two nodes with the same final DAG commit the same vertices in different
    /// orders: the higher one can carry a leader the lower one does not, so one
    /// node commits that leader's slot while the other skips it and commits the
    /// vertex later as an ancestor.
    fn stable_anchor(&self, dag: &Dag, round: u64) -> Result<Option<VertexId>, CryptoError> {
        let start = round + 2;
        for candidate in start..=self.observed {
            let Some(anchor) = dag.is_anchored(candidate)? else {
                continue;
            };
            for between in start..candidate {
                let Some(author) = dag.leader_author(between) else {
                    continue;
                };
                match dag.history_contains_author(&anchor, between, author) {
                    // Proved absent from the anchor's history: passing the round
                    // cannot change the decision.
                    Ok(false) => {}
                    Ok(true) => {
                        // The leader is already inside the higher anchor's history.
                        // That is only a reason to wait while a vote quorum for the
                        // round is still possible; if it is not, the round can never
                        // anchor and the higher anchor is the canonical one.
                        if dag.can_still_anchor(between)? {
                            return Ok(None);
                        }
                    }
                    // An incomplete walk proves nothing. Deciding anyway is how
                    // the commit order starts to depend on arrival timing.
                    Err(_) => return Ok(None),
                }
            }
            return Ok(Some(anchor));
        }
        Ok(None)
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

    /// Whether any round ahead of the cursor already has quorum support.
    ///
    /// This is progress for the stall counter, not a decision: the cursor does not
    /// move and nothing is emitted. It is also not cached — [`Pacemaker::stable_anchor`]
    /// recomputes what may be decided for every tick, so a value seen earlier can
    /// never make two nodes decide differently.
    fn has_anchored_ahead(&self, dag: &Dag) -> Result<bool, CryptoError> {
        for round in self.cursor.saturating_add(1)..=self.observed {
            if dag.is_anchored(round)?.is_some() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{bitmap_len, set_bit};
    use crate::fence::{Fence, FenceCertificate};
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
    fn tick_one_exposes_each_decision_boundary() {
        let mut fixture = chain(8, &[]);
        let mut pacemaker = pacemaker(3);
        let mut decided = Vec::new();

        loop {
            match pacemaker.tick_one(&mut fixture.dag).unwrap() {
                Step::Advanced {
                    from,
                    commits: 1,
                    anchors: 0,
                    ..
                } => decided.push(from),
                Step::Advanced { anchors: 1, .. } => break,
                Step::Waiting { .. } | Step::TimedOut { .. } => break,
                other => panic!("unexpected step {other:?}"),
            }
        }

        assert_eq!(decided, (1..=7).collect::<Vec<_>>());
    }

    #[test]
    fn a_fenced_leader_is_skipped_without_a_vote_or_anchor() {
        let mut fixture = chain(0, &[]);
        let leader = fixture.dag.leader_author(1).unwrap().to_vec();
        let set = fixture.dag.set().clone();
        let fence = Fence::new(b"karsa-pacemaker-1".to_vec(), 1, leader);
        let payload = fence.signing_payload().unwrap();
        let mut signer_bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::new();
        for index in 0..set.quorum_size() {
            set_bit(&mut signer_bitmap, index);
            signatures.push(Ed25519Scheme.sign(&fixture.keys[index], &payload).unwrap());
        }
        let certificate = FenceCertificate {
            fence,
            signer_bitmap,
            signatures,
        };

        let mut pacemaker = pacemaker(1);
        let before = pacemaker.tick(&mut fixture.dag).unwrap();
        assert!(
            matches!(
                before,
                Step::TimedOut { cursor: 1, .. } | Step::Waiting { cursor: 1, .. }
            ),
            "without a fence the missing leader must not be skipped: {before:?}"
        );
        assert_eq!(pacemaker.cursor(), 1);

        fixture
            .dag
            .apply_fence(b"karsa-pacemaker-1", &certificate)
            .unwrap();
        let after = pacemaker.tick(&mut fixture.dag).unwrap();
        assert!(
            matches!(after, Step::Advanced { skips: 1, .. }),
            "the fenced leader must be skipped: {after:?}"
        );
        assert_eq!(pacemaker.cursor(), 2);
        assert_eq!(fixture.dag.skipped().len(), 1);
        assert_eq!(
            pacemaker.skip_counts(),
            SkipCounts {
                fence_leader: 1,
                ..SkipCounts::default()
            },
            "only the fenced-leader rule may release this round"
        );
    }

    #[test]
    fn a_fenced_missing_voter_frees_a_live_leaders_round() {
        let mut fixture = chain(1, &[]);
        let round1 = fixture.ids(1);
        let leader = round1[1].clone();
        let vote = vertex(
            &fixture,
            0,
            2,
            vec![leader, round1[0].clone(), round1[2].clone()],
        );
        fixture.dag.insert(vote).unwrap();
        for author in [1, 2] {
            let non_vote = vertex(
                &fixture,
                author,
                2,
                vec![round1[0].clone(), round1[2].clone(), round1[3].clone()],
            );
            fixture.dag.insert(non_vote).unwrap();
        }

        let mut pacemaker = pacemaker(1);
        let before = pacemaker.tick(&mut fixture.dag).unwrap();
        assert!(
            matches!(
                before,
                Step::TimedOut { cursor: 1, .. } | Step::Waiting { cursor: 1, .. }
            ),
            "without a fence the live leader must not be skipped: {before:?}"
        );

        let set = fixture.dag.set().clone();
        let fence = Fence::new(b"karsa-pacemaker-1".to_vec(), 1, b"val-3".to_vec());
        let payload = fence.signing_payload().unwrap();
        let mut signer_bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::new();
        for index in 0..set.quorum_size() {
            set_bit(&mut signer_bitmap, index);
            signatures.push(Ed25519Scheme.sign(&fixture.keys[index], &payload).unwrap());
        }
        fixture
            .dag
            .apply_fence(
                b"karsa-pacemaker-1",
                &FenceCertificate {
                    fence,
                    signer_bitmap,
                    signatures,
                },
            )
            .unwrap();

        let after = pacemaker.tick(&mut fixture.dag).unwrap();
        assert!(
            matches!(after, Step::Advanced { skips: 1, .. }),
            "one held vote plus one fenced missing voter is safe to skip: {after:?}"
        );
        assert_eq!(pacemaker.cursor(), 2);
        assert_eq!(
            pacemaker.skip_counts(),
            SkipCounts {
                fence_voter: 1,
                ..SkipCounts::default()
            },
            "one held vote plus one fenced missing voter is the only proof"
        );
    }

    #[test]
    fn a_dead_author_does_not_block_rounds_that_follow_it() {
        // `val-1` stops authoring at round 5, the way a killed validator does. The
        // later rounds have three vertices, which is still a quorum; the missing
        // leader must be skippable without ever receiving its vertex.
        let absent: Vec<(u64, usize)> = (5..=10).map(|round| (round, 1)).collect();
        let mut fixture = chain(10, &absent);
        let mut pacemaker = pacemaker(3);

        let step = pacemaker.tick(&mut fixture.dag).unwrap();
        assert!(
            matches!(step, Step::Advanced { .. }),
            "a dead author must not stall the cursor: {step:?}"
        );
        assert!(
            pacemaker.cursor() > 5,
            "the missing leader at round 5 was not passed: cursor {}",
            pacemaker.cursor()
        );
        assert_eq!(fixture.dag.skipped()[0].round, 5);
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
    fn a_deferred_indirect_commit_does_not_emit_history() {
        // Round 1 is led by `val-1`. Round 2 has one voter for it, two non-voters,
        // and one absent author, so the direct rule is undecided (no vote quorum,
        // and only two observed non-votes). An anchor at round 3 reaches the
        // leader, but only one voter is held (f = 1), so a non-vote quorum could
        // still exist. The pacemaker must wait without committing the history it
        // inspected.
        let mut fixture = chain(1, &[]);
        let round_one = fixture.ids(1);
        let non_voter_refs: Vec<VertexId> = round_one
            .iter()
            .filter(|id| id.author != b"val-1")
            .cloned()
            .collect();

        for author in 0..fixture.count() {
            if author == 1 {
                continue; // absent: the fourth vote/non-vote never arrives
            }
            let references = if author == 0 {
                round_one.clone() // the single voter
            } else {
                non_voter_refs.clone()
            };
            let vertex = vertex(&fixture, author, 2, references);
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(fixture.dag.held_voters(1).unwrap(), 1);
        assert_eq!(fixture.dag.skipped().len(), 0);

        // Round 3 references all three held round-2 vertices, and round 4 does the
        // same for round 3, so the round-3 leader is anchored.
        fixture.add_round(3).unwrap();
        fixture.add_round(4).unwrap();

        let mut pacemaker = pacemaker(3);
        pacemaker.tick(&mut fixture.dag).unwrap();

        assert!(
            fixture.dag.order().is_empty(),
            "a deferred indirect commit must not leave history behind"
        );
        assert_eq!(pacemaker.cursor(), 1);
        assert!(fixture.dag.skipped().is_empty());
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
        assert_eq!(
            pacemaker.skip_counts().fenced(),
            0,
            "an observed non-vote quorum needs no fence"
        );
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
        assert_eq!(pacemaker.skip_counts().fenced(), 0);
        assert!(pacemaker.skip_counts().absent > 0);
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
