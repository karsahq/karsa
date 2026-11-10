//! A round-based DAG: vertices, leader election, and the commit rules.
//!
//! What is here:
//!
//! - vertices stored one per `(round, author)`, verified against the schedule;
//! - deterministic leader election as a function of the round;
//! - the **direct** rule: a leader with a supermajority of next-round votes
//!   commits, a leader with a supermajority of next-round non-votes is skipped,
//!   and anything else is undecided;
//! - the **indirect** rule: a committed anchor two or more rounds later settles an
//!   earlier slot by reachability;
//! - causal history: a commit includes the leader's ancestors, each exactly once.
//!
//! What is **not** here, and must not be assumed: waves or pipelining, and any
//! treatment of asynchrony. In particular, absence of a vote is never evidence: a
//! leader is only skipped when a supermajority is *observed* not to reference it,
//! when a committed anchor two or more rounds later does not reach it, or when
//! `crate::Pacemaker` proves from an anchor that its vertex cannot exist. Driving
//! rounds forward is the pacemaker's job, not this module's.

use std::collections::{BTreeMap, HashSet};

use crypto::merkle::{MerkleProof, MerkleTree};
use crypto::{CryptoError, CryptoErrorKind};

use crate::frontier::CommitFrontier;
use crate::schedule::{EpochSchedule, ValidatorSet};
use crate::set_change::SetSchedule;
use crate::vertex::{Vertex, VertexId, tally_votes};

/// The outcome of asking a round to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The leader and its not-yet-committed history, in commit order.
    Commit(Vec<VertexId>),
    /// A supermajority of the next round did not reference the leader.
    Skip,
    /// Neither quorum has been observed yet.
    Undecided,
}

/// A round whose leader this node has decided to skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRound {
    /// The round whose leader was skipped.
    pub round: u64,
    /// The elected author of that round.
    pub author: Vec<u8>,
    /// Digest of the leader's vertex, or `None` when this node never received it.
    ///
    /// A missing digest matters: it records a skip argued from an anchor rather
    /// than from the leader's own content.
    pub digest: Option<[u8; 32]>,
}

/// Vertices this node holds, plus what it has already committed.
pub struct Dag {
    sets: SetSchedule,
    vertices: BTreeMap<(u64, Vec<u8>), Vertex>,
    committed: HashSet<[u8; 32]>,
    order: Vec<VertexId>,
    /// Committed entries below the retained tail, summarized by their peaks.
    ///
    /// A checkpoint restart drops the leaves at or below the DAG floor but must
    /// keep contributing them to every later `dag_root`; this is that contribution.
    /// A run that never seeded a compact prefix has an empty frontier and its
    /// `order` is the whole committed sequence.
    prefix: CommitFrontier,
    skipped: Vec<SkippedRound>,
    /// Which epoch each round belongs to.
    schedule: EpochSchedule,
    /// Highest round that has been committed and dropped, if any.
    ///
    /// Everything at or below it is already reflected in a state snapshot, so the
    /// node neither stores nor re-decides it.
    floor: Option<u64>,
}

impl Dag {
    /// Creates an empty DAG for `set`.
    #[must_use]
    pub fn new(set: ValidatorSet) -> Self {
        let epoch = set.epoch;
        Self {
            sets: SetSchedule::single(set),
            vertices: BTreeMap::new(),
            committed: HashSet::new(),
            order: Vec::new(),
            prefix: CommitFrontier::empty(),
            skipped: Vec::new(),
            schedule: EpochSchedule::single(epoch),
            floor: None,
        }
    }

    /// Creates an empty DAG whose set advances one epoch every `rounds_per_epoch`
    /// rounds, starting at the set's own epoch.
    ///
    /// This is the hook a key rotation hangs on: the validator identities stay
    /// fixed, only their active keys change with the epoch, so quorum intersection
    /// across the boundary is preserved and no round has to be re-decided.
    ///
    /// # Panics
    ///
    /// Does not panic; a zero length is treated as one epoch for the whole DAG.
    #[must_use]
    pub fn with_epoch_length(set: ValidatorSet, rounds_per_epoch: u64) -> Self {
        let base = set.epoch;
        let mut dag = Self::new(set);
        dag.schedule = EpochSchedule::advancing(base, rounds_per_epoch);
        dag
    }

    /// Creates an empty DAG with one checked set transition at `change_epoch`.
    ///
    /// This is the prototype hook for a validator-set change. Key rotation keeps
    /// the identities fixed and needs only [`Dag::with_epoch_length`]; this
    /// constructor moves identities and therefore validates the quorum
    /// intersection before any vertex is accepted.
    ///
    /// # Errors
    ///
    /// Every error from [`SetSchedule::with_change`].
    pub fn with_epoch_length_and_change(
        set: ValidatorSet,
        next: ValidatorSet,
        change_epoch: u64,
        rounds_per_epoch: u64,
    ) -> Result<Self, CryptoError> {
        let base = set.epoch;
        let sets = SetSchedule::with_change(set, change_epoch, next)?;
        Ok(Self {
            sets,
            vertices: BTreeMap::new(),
            committed: HashSet::new(),
            order: Vec::new(),
            prefix: CommitFrontier::empty(),
            skipped: Vec::new(),
            schedule: EpochSchedule::advancing(base, rounds_per_epoch),
            floor: None,
        })
    }

    /// The epoch a round belongs to.
    ///
    /// Derived from the round alone, never read from a message, so every node
    /// computes the same epoch for the same round.
    #[must_use]
    pub fn epoch_of(&self, round: u64) -> u64 {
        self.schedule.epoch_of(round)
    }

    /// The round-to-epoch mapping this DAG verifies against.
    #[must_use]
    pub fn epoch_schedule(&self) -> EpochSchedule {
        self.schedule
    }

    /// The highest round this node has pruned, if any.
    #[must_use]
    pub fn floor(&self) -> Option<u64> {
        self.floor
    }

    /// Treats every round at or below `round` as committed and drops it.
    ///
    /// Returns how many vertices were removed. Pruning is a statement that a state
    /// snapshot already covers those rounds, which is why nothing below the floor is
    /// stored or re-decided.
    ///
    /// The floor only ever rises, so calling this with a lower value is a no-op.
    ///
    /// # Panics
    ///
    /// Does not panic; a lower value simply leaves the floor unchanged.
    pub fn set_floor(&mut self, round: u64) -> usize {
        let floor = match self.floor {
            Some(current) => current.max(round),
            None => round,
        };
        self.floor = Some(floor);
        let before = self.vertices.len();
        self.vertices.retain(|(round, _), _| *round > floor);
        before - self.vertices.len()
    }

    fn is_pruned(&self, round: u64) -> bool {
        self.floor.is_some_and(|floor| round <= floor)
    }

    /// The validator set this DAG resolves keys against before any transition.
    #[must_use]
    pub fn set(&self) -> &ValidatorSet {
        self.sets.base()
    }

    /// The checked set schedule, including an optional transition.
    #[must_use]
    pub fn set_schedule(&self) -> &SetSchedule {
        &self.sets
    }

    /// The validator set active at `epoch`.
    #[must_use]
    pub fn set_for_epoch(&self, epoch: u64) -> &ValidatorSet {
        self.sets.set_for_epoch(epoch)
    }

    /// The validator set active at `round`.
    #[must_use]
    pub fn set_for_round(&self, round: u64) -> &ValidatorSet {
        self.sets.set_for_round(&self.schedule, round)
    }

    /// Inserts a vertex after verifying it and its shape.
    ///
    /// The shape rule is the one this module previously only assumed: a vertex in
    /// round `r > 0` MUST reference at least [`ValidatorSet::quorum_size`]
    /// **distinct, registered authors** of round `r - 1`. Without it, the indirect
    /// skip argument does not hold: an anchor could be committed while a valid
    /// path to an earlier leader exists on a branch the anchor does not cover.
    ///
    /// References to other rounds are allowed and not counted; they are weak edges
    /// that carry causal history.
    ///
    /// A second vertex from the same author in the same round is **ignored**: the
    /// first one wins, so an author cannot vote twice.
    ///
    /// # Errors
    ///
    /// Propagates [`Vertex::verify`], and returns
    /// [`CryptoErrorKind::InvalidVertex`] when the reference rule is not met.
    pub fn insert(&mut self, vertex: Vertex) -> Result<VertexId, CryptoError> {
        vertex.verify(
            self.set_for_round(vertex.round),
            self.epoch_of(vertex.round),
        )?;
        // Below the floor the vertex is already committed and its state is in a
        // snapshot. It is still signature-checked, then dropped.
        if self.is_pruned(vertex.round) {
            return vertex.id();
        }
        self.check_round_references(&vertex)?;
        let key = (vertex.round, vertex.author.clone());
        if let Some(existing) = self.vertices.get(&key) {
            return existing.id();
        }
        let id = vertex.id()?;
        self.vertices.insert(key, vertex);
        Ok(id)
    }

    /// Checks that a vertex references a quorum of the previous round.
    fn check_round_references(&self, vertex: &Vertex) -> Result<(), CryptoError> {
        if vertex.round == 0 {
            return Ok(());
        }
        let previous = vertex.round - 1;
        // A pruned previous round cannot be checked: the vertices are gone. The
        // first retained round is therefore accepted on its author's signature, and
        // a bad reference list simply fails to vote later.
        if self.is_pruned(previous) {
            return Ok(());
        }
        let set = self.set_for_round(vertex.round);
        let registered = |author: &[u8]| {
            set.validators
                .iter()
                .any(|record| record.validator_id == author)
        };
        let mut authors: HashSet<&[u8]> = HashSet::new();
        for reference in &vertex.references {
            if reference.round == previous && registered(&reference.author) {
                authors.insert(&reference.author);
            }
        }
        let required = set.quorum_size();
        if authors.len() < required {
            return Err(CryptoError::new(
                CryptoErrorKind::InvalidVertex,
                format!(
                    "round {} references {} of {required} required authors from round {previous}",
                    vertex.round,
                    authors.len()
                ),
            ));
        }
        Ok(())
    }

    /// Returns the vertex for one author and round.
    #[must_use]
    pub fn get(&self, round: u64, author: &[u8]) -> Option<&Vertex> {
        self.vertices.get(&(round, author.to_vec()))
    }

    /// The elected author of `round`, whether or not this node holds their vertex.
    ///
    /// Election is `round % n` over the set order: deterministic and trivial on
    /// purpose. A real deployment wants a stake-weighted or VRF schedule, which is
    /// a different problem from the commit rule.
    #[must_use]
    pub fn leader_author(&self, round: u64) -> Option<&[u8]> {
        let set = self.set_for_round(round);
        let index = usize::try_from(round).ok()? % set.validators.len();
        Some(&set.validators[index].validator_id)
    }

    /// The elected leader of `round`, if this node has it.
    #[must_use]
    pub fn leader(&self, round: u64) -> Option<&Vertex> {
        let author = self.leader_author(round)?;
        self.get(round, author)
    }

    /// The highest round this node holds any vertex for.
    #[must_use]
    pub fn highest_round(&self) -> Option<u64> {
        self.vertices.keys().next_back().map(|(round, _)| *round)
    }

    /// Vertices in the round after `round` that this node holds.
    fn round_vertices(&self, round: u64) -> Vec<&Vertex> {
        self.vertices
            .range((round, Vec::new())..)
            .take_while(|((r, _), _)| *r == round)
            .map(|(_, vertex)| vertex)
            .collect()
    }

    /// Returns the leader of `round` if a quorum of the next round references it,
    /// without committing anything.
    ///
    /// This is what the pacemaker uses to find an anchor. It deliberately does not
    /// emit a commit: emitting out of cursor order would make the committed
    /// sequence depend on arrival order, which two nodes with the same DAG may not
    /// share.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`].
    pub fn is_anchored(&self, round: u64) -> Result<Option<VertexId>, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(None);
        };
        let leader_id = leader.id()?;
        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?;
        if voter_set.has_supermajority(voters.len()) {
            Ok(Some(leader_id))
        } else {
            Ok(None)
        }
    }

    /// Asks this node to decide the leader of `round`.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`], and returns
    /// [`CryptoErrorKind::MissingReference`] when committing a leader whose
    /// history is incomplete.
    pub fn try_commit(&mut self, round: u64) -> Result<Decision, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(Decision::Undecided);
        };
        let leader_id = leader.id()?;

        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?;

        if voter_set.has_supermajority(voters.len()) {
            let history = self.commit_history(&leader_id)?;
            return Ok(Decision::Commit(history));
        }

        // Only observed non-votes count. A voter whose vertex has not arrived is
        // unknown, not against the leader, so it cannot produce a skip.
        let non_voters = candidates.len() - voters.len();
        if voter_set.has_supermajority(non_voters) {
            self.record_skip(round, leader_id.author.clone(), Some(leader_id.digest));
            return Ok(Decision::Skip);
        }
        Ok(Decision::Undecided)
    }

    /// Number of held vertices in `round + 1` that vote for the leader of
    /// `round`.
    ///
    /// Used by the pacemaker to decide whether an indirect commit is safe: if
    /// more than `f` votes are held, a supermajority of non-votes cannot exist,
    /// so the direct rule can never later decide to skip the same slot.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`].
    pub fn held_voters(&self, round: u64) -> Result<usize, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(0);
        };
        let leader_id = leader.id()?;
        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        Ok(tally_votes(
            self.set_for_round(round + 1),
            &leader_id,
            &candidates,
            &self.schedule,
        )?
        .len())
    }

    /// The first vertex the history walk from `round`'s leader cannot resolve.
    ///
    /// [`Dag::missing_references`] only sees gaps that a *held* vertex names
    /// directly. The reference rule requires a quorum of previous-round authors, not
    /// all of them, so a node can miss a vertex that no held vertex points at and
    /// still have a valid DAG — and then stall, because the commit walk needs it.
    /// This is the other half of the repair signal: the exact vertex blocking the
    /// cursor, found by the same walk the commit rule performs.
    #[must_use]
    pub fn missing_history(&self, round: u64) -> Option<VertexId> {
        let leader = self.leader(round)?;
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![leader.id().ok()?];
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let Some(vertex) = self.vertices.get(&(current.round, current.author.clone())) else {
                return Some(current);
            };
            stack.extend(vertex.references.iter().cloned());
        }
        None
    }

    /// Every reference this node holds that points at a vertex it does not hold.
    ///
    /// The reference rule is what makes a dropped frame *visible*: if a vertex
    /// never arrived, the next round's vertices still name it, so the gap lives in
    /// the DAG and not only on the wire. This is the repair list, and it is derived
    /// from what the node holds rather than from a guess about which authors ought
    /// to have authored.
    ///
    /// Note what insertion does *not* do: it accepts a vertex whose referenced
    /// neighbours are absent, because the shape rule is about a quorum of distinct
    /// authors, not about holding every edge. The absence only bites when a walk
    /// needs the missing vertex — a commit, an ancestry check, or an absence proof.
    /// So repair cannot hang off a rejected insert; it has to scan for dangling
    /// edges.
    ///
    /// References into a pruned round are excluded: they are gone by policy, not by
    /// delay, and asking for them would never succeed.
    #[must_use]
    pub fn missing_references(&self) -> Vec<VertexId> {
        let mut missing = Vec::new();
        let mut seen: HashSet<VertexId> = HashSet::new();
        for vertex in self.vertices.values() {
            for reference in &vertex.references {
                if self.is_pruned(reference.round) {
                    continue;
                }
                if self
                    .vertices
                    .contains_key(&(reference.round, reference.author.clone()))
                {
                    continue;
                }
                if seen.insert(reference.clone()) {
                    missing.push(reference.clone());
                }
            }
        }
        missing
    }

    /// Returns whether this node can still see a vote quorum for `round`'s
    /// leader if every vertex it has not received turns out to vote for it.
    ///
    /// A round that cannot reach a quorum can never anchor, so an anchor ahead
    /// of it is the lowest one that will ever exist and may be used without
    /// waiting for it.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`].
    pub fn can_still_anchor(&self, round: u64) -> Result<bool, CryptoError> {
        let Some(leader) = self.leader(round) else {
            // The leader's vertex is missing, not disproved. It may still arrive,
            // and a held vote already names its id, so the conservative answer is
            // "possible": the caller keeps waiting instead of passing the round.
            return Ok(true);
        };
        let leader_id = leader.id()?;
        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?.len();
        let missing = voter_set.validators.len().saturating_sub(candidates.len());
        Ok(voters.saturating_add(missing) >= voter_set.quorum_size())
    }

    /// Collects `id` and its ancestors that are not yet committed, in a
    /// deterministic order.
    fn commit_history(&mut self, id: &VertexId) -> Result<Vec<VertexId>, CryptoError> {
        let mut collected: Vec<VertexId> = Vec::new();
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![id.clone()];
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            // Pruned ancestors are already committed and already reflected in the
            // state snapshot, so the block stops there instead of failing.
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            if self.committed.contains(&current.digest) {
                continue;
            }
            collected.extend(vertex.references.iter().cloned());
            stack.extend(vertex.references.iter().cloned());
            collected.push(current);
        }

        // Deduplicate, drop already committed, and order by (round, author) so two
        // nodes with the same history commit the same sequence.
        // Pruned vertices reach `collected` through a reference list, so they have
        // to be dropped here as well as skipped in the walk.
        collected.retain(|vertex| {
            !self.committed.contains(&vertex.digest) && !self.is_pruned(vertex.round)
        });
        collected.sort_by(|a, b| a.round.cmp(&b.round).then_with(|| a.author.cmp(&b.author)));
        collected.dedup();

        for vertex in &collected {
            self.committed.insert(vertex.digest);
            self.order.push(vertex.clone());
        }
        Ok(collected)
    }

    /// The committed sequence above the retained prefix, in commit order.
    #[must_use]
    pub fn order(&self) -> &[VertexId] {
        &self.order
    }

    /// The committed prefix whose leaves the store no longer holds.
    #[must_use]
    pub fn prefix(&self) -> &CommitFrontier {
        &self.prefix
    }

    /// Total committed entries, retained tail included.
    #[must_use]
    pub fn order_len(&self) -> usize {
        self.prefix.len() + self.order.len()
    }

    /// Adopts a verified committed prefix from a snapshot.
    ///
    /// The caller has already verified the vertices and the header that commits
    /// this order. New commits append after the prefix.
    pub fn seed_order(&mut self, order: Vec<VertexId>) {
        self.prefix = CommitFrontier::empty();
        self.committed = order.iter().map(|id| id.digest).collect();
        self.order = order;
    }

    /// Adopts a compact prefix plus the committed tail above the floor.
    ///
    /// `prefix` covers the entries at or below the DAG floor, whose leaves the
    /// store dropped; `order` is the committed tail the checkpoint retained. The
    /// two together must reproduce the anchor's `dag_root`.
    pub fn seed_prefix(&mut self, prefix: CommitFrontier, order: Vec<VertexId>) {
        self.committed = order.iter().map(|id| id.digest).collect();
        self.prefix = prefix;
        self.order = order;
    }

    /// Truncates the committed order to `len` entries.
    ///
    /// Replay uses this when the stored certified head covers an earlier prefix
    /// than the decision sequence it just rebuilt. The compact prefix is
    /// immutable; only the retained tail can rewind.
    pub fn truncate_order(&mut self, len: usize) {
        let keep = len.saturating_sub(self.prefix.len()).min(self.order.len());
        self.order.truncate(keep);
        self.committed = self.order.iter().map(|id| id.digest).collect();
    }

    /// The Merkle root over the first `len` committed entries.
    #[must_use]
    pub fn commit_root_at(&self, len: usize) -> Option<[u8; 32]> {
        self.prefix
            .root_at(&self.order, len.checked_sub(self.prefix.len())?)
    }

    /// The Merkle root over everything this node has committed, in commit order.
    #[must_use]
    pub fn commit_root(&self) -> [u8; 32] {
        self.commit_root_at(self.order_len())
            .expect("the retained order length is in range")
    }

    /// Slots this node has decided to skip, in decision order.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedRound] {
        &self.skipped
    }

    /// Records a skipped round.
    ///
    /// Returns whether the record is new. A round is skipped at most once, so a
    /// second decision to skip it is a no-op.
    pub(crate) fn record_skip(
        &mut self,
        round: u64,
        author: Vec<u8>,
        digest: Option<[u8; 32]>,
    ) -> bool {
        if self.skipped.iter().any(|entry| entry.round == round) {
            return false;
        }
        self.skipped.push(SkippedRound {
            round,
            author,
            digest,
        });
        true
    }

    /// Returns whether `anchor`'s causal history contains a vertex at
    /// `(round, author)`.
    ///
    /// This answers a question about a vertex the node may not hold: an anchor can
    /// prove that a leader exists without the node having received that leader, and
    /// it can equally prove that no such leader can ever be committed.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::MissingReference`] when the walk reaches a vertex this
    /// node does not hold, which means the answer is unknown rather than negative.
    pub fn history_contains_author(
        &self,
        anchor: &VertexId,
        round: u64,
        author: &[u8],
    ) -> Result<bool, CryptoError> {
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![anchor.clone()];
        while let Some(current) = stack.pop() {
            if current.round == round && current.author == author {
                return Ok(true);
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            stack.extend(vertex.references.iter().cloned());
        }
        Ok(false)
    }

    /// Returns whether `ancestor` is reachable from `descendant` through
    /// references, counting a vertex as reachable from itself.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::MissingReference`] when the walk reaches a vertex this
    /// node does not hold.
    pub fn is_ancestor(
        &self,
        ancestor: &VertexId,
        descendant: &VertexId,
    ) -> Result<bool, CryptoError> {
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![descendant.clone()];
        while let Some(current) = stack.pop() {
            if current == *ancestor {
                return Ok(true);
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            stack.extend(vertex.references.iter().cloned());
        }
        Ok(false)
    }

    /// Decides an earlier leader using a **committed** anchor.
    ///
    /// This is the indirect rule. Once an anchor two or more rounds later is
    /// committed, the question for an earlier slot is no longer "did a quorum vote
    /// for it" but "is it inside the anchor's history":
    ///
    /// - reachable from the anchor: commit it and any history the anchor did not
    ///   already carry;
    /// - not reachable: skip it, because every future committed leader extends the
    ///   anchor, so a slot outside its history can never be committed;
    /// - the anchor is too recent to have had the chance to include a quorum path:
    ///   undecided.
    ///
    /// The skip half assumes the protocol rule that every vertex references a
    /// supermajority of the previous round. [`Dag::insert`] enforces that rule, so
    /// the argument holds for any DAG this node accepted.
    ///
    /// # Errors
    ///
    /// Propagates [`Dag::is_ancestor`] and [`Dag::commit_history`].
    pub fn try_indirect_decide(
        &mut self,
        round: u64,
        anchor: &VertexId,
    ) -> Result<Decision, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(Decision::Undecided);
        };
        // The anchor needs at least the intervening round to have carried a quorum
        // path to the earlier leader.
        if anchor.round < round + 2 {
            return Ok(Decision::Undecided);
        }
        let leader_id = leader.id()?;
        if self.is_ancestor(&leader_id, anchor)? {
            let history = self.commit_history(&leader_id)?;
            return Ok(Decision::Commit(history));
        }
        self.record_skip(round, leader_id.author.clone(), Some(leader_id.digest));
        Ok(Decision::Skip)
    }
}

/// The error for a vertex that is referenced but not held.
fn missing(id: &VertexId) -> CryptoError {
    CryptoError::new(
        CryptoErrorKind::MissingReference,
        format!(
            "vertex {}@{} is referenced but not held",
            String::from_utf8_lossy(&id.author),
            id.round
        ),
    )
}

/// The leaf commitment for one committed vertex.
///
/// The domain tag keeps a commit leaf from colliding with any other kind of leaf
/// built by the same tree implementation.
#[must_use]
pub fn commit_leaf(id: &VertexId) -> [u8; 32] {
    crypto::merkle::leaf(
        b"KARSA/DAG/COMMIT/v1",
        &[&id.round.to_le_bytes(), &id.author, &id.digest],
    )
}

/// A Merkle root over a commit sequence, in commit order.
#[must_use]
pub fn commit_root(order: &[VertexId]) -> [u8; 32] {
    MerkleTree::from_leaves(order.iter().map(commit_leaf).collect()).root()
}

/// Proof that one vertex is inside a commit sequence.
///
/// This is what a header's `dag_root` is for: a client that is handed a header can
/// check that a specific vertex was part of the commit it names, without being
/// handed the commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitProof {
    /// The vertex being proven.
    pub vertex: VertexId,
    /// Its path to the root.
    pub proof: MerkleProof,
}

impl CommitProof {
    /// Builds a proof for the vertex at `index` in `order`.
    #[must_use]
    pub fn prove(order: &[VertexId], index: usize) -> Option<Self> {
        let vertex = order.get(index)?.clone();
        let tree = MerkleTree::from_leaves(order.iter().map(commit_leaf).collect());
        Some(Self {
            vertex,
            proof: tree.proof(index)?,
        })
    }

    /// Returns whether the proven vertex is inside `dag_root`.
    #[must_use]
    pub fn verify(&self, dag_root: &[u8; 32]) -> bool {
        MerkleTree::verify(dag_root, &commit_leaf(&self.vertex), &self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const EPOCH: u64 = 1;
    /// Round 0 is genesis and needs no references, so the first leader is here.
    const LEADER_ROUND: u64 = 1;

    struct Fixture {
        keys: Vec<Vec<u8>>,
        dag: Dag,
    }

    fn fixture(count: usize) -> Fixture {
        let mut keys = Vec::with_capacity(count);
        let mut validators = Vec::with_capacity(count);
        for index in 0..count {
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
            chain_id: b"karsa-dag-1".to_vec(),
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

        fn leader_index(&self, round: u64) -> usize {
            usize::try_from(round).unwrap() % self.count()
        }

        /// Inserts one vertex per validator, all with the same references.
        fn full_round(&mut self, round: u64, references: &[VertexId]) -> Result<(), CryptoError> {
            for author in 0..self.count() {
                let vertex = vertex(self, author, round, references.to_vec());
                self.dag.insert(vertex)?;
            }
            Ok(())
        }

        fn ids(&self, round: u64) -> Vec<VertexId> {
            self.ids_where(round, |_| true)
        }

        /// Ids of every vertex in `round` except the round's leader.
        fn ids_without_leader(&self, round: u64) -> Vec<VertexId> {
            let leader = self.leader_index(round);
            self.ids_where(round, |author| author != leader)
        }

        fn ids_where(&self, round: u64, keep: impl Fn(usize) -> bool) -> Vec<VertexId> {
            let mut ids = Vec::new();
            for author in 0..self.count() {
                if !keep(author) {
                    continue;
                }
                let key = format!("val-{author}");
                if let Some(vertex) = self.dag.get(round, key.as_bytes()) {
                    ids.push(vertex.id().unwrap());
                }
            }
            ids
        }
    }

    /// Genesis round plus the first leader round, both full and well formed.
    fn bootstrapped(count: usize) -> Fixture {
        let mut fixture = fixture(count);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        fixture.full_round(LEADER_ROUND, &genesis).unwrap();
        fixture
    }

    #[test]
    fn round_zero_needs_no_references_and_later_rounds_do() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);

        // Two of the three required round-0 authors is not enough.
        let short = vertex(&fixture, 0, 1, genesis[..2].to_vec());
        let error = fixture.dag.insert(short).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);

        // The same author repeated three times is one author.
        let repeated = vec![genesis[0].clone(); 3];
        let error = fixture
            .dag
            .insert(vertex(&fixture, 0, 1, repeated))
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);

        // A full quorum of distinct authors is accepted.
        fixture.full_round(1, &genesis).unwrap();
    }

    #[test]
    fn references_to_other_rounds_do_not_count() {
        let mut fixture = bootstrapped(4);
        let genesis = fixture.ids(0);
        let error = fixture
            .dag
            .insert(vertex(&fixture, 0, 2, genesis))
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);
    }

    #[test]
    fn a_supermajority_of_votes_commits_the_leader_and_its_history() {
        let mut fixture = bootstrapped(4);
        let leader_id = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();

        let Decision::Commit(history) = fixture.dag.try_commit(LEADER_ROUND).unwrap() else {
            panic!("expected a commit");
        };
        assert!(history.contains(&leader_id));
        assert_eq!(history.len(), 5, "four genesis vertices plus the leader");
        assert_eq!(fixture.dag.order().len(), 5);
    }

    #[test]
    fn one_silent_validator_still_commits() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        for author in 0..3 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, votes.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Commit(_)
        ));
    }

    #[test]
    fn missing_votes_are_undecided_not_a_skip() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        for author in 0..2 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, votes.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn observed_non_votes_skip_the_leader() {
        let mut fixture = bootstrapped(4);
        // A quorum of the next round, none of it referencing the leader.
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);
        for author in 0..3 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, without_leader.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Skip
        );
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn a_missing_leader_is_undecided() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        let leader = fixture.leader_index(LEADER_ROUND);
        for author in 0..4 {
            if author == leader {
                continue;
            }
            let vertex = vertex(&fixture, author, LEADER_ROUND, genesis.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        let present = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &present).unwrap();

        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn a_second_vertex_from_the_same_author_is_ignored() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        for _ in 0..2 {
            let vertex = vertex(&fixture, 0, LEADER_ROUND + 1, votes.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(fixture.dag.round_vertices(LEADER_ROUND + 1).len(), 1);
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn history_is_committed_once_and_in_a_stable_order() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();

        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Commit(_)
        ));
        // Asking again changes nothing.
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Commit(Vec::new())
        );
        assert_eq!(fixture.dag.order().len(), 5);
    }

    #[test]
    fn a_missing_ancestor_blocks_the_commit() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        let mut references = genesis.clone();
        // Keep the shape rule satisfied, then add a reference nobody holds.
        references.truncate(fixture.dag.set().quorum_size());
        references.push(VertexId {
            round: 0,
            author: b"val-9".to_vec(),
            digest: [9u8; 32],
        });

        let leader = fixture.leader_index(LEADER_ROUND);
        for author in 0..4 {
            let chosen = if author == leader {
                references.clone()
            } else {
                genesis.clone()
            };
            let vertex = vertex(&fixture, author, LEADER_ROUND, chosen);
            fixture.dag.insert(vertex).unwrap();
        }

        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();

        let error = fixture.dag.try_commit(LEADER_ROUND).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn indirect_commit_finds_the_leader_inside_the_anchor_history() {
        let mut fixture = bootstrapped(4);
        let leader_id = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let votes = fixture.ids(LEADER_ROUND);
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);

        // A split round: two vote for the leader, two reference the rest.
        for author in 0..4 {
            let references = if author < 2 {
                votes.clone()
            } else {
                without_leader.clone()
            };
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, references);
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );

        // Two rounds later the anchor commits with its whole history.
        let round_two = fixture.ids(LEADER_ROUND + 1);
        fixture.full_round(LEADER_ROUND + 2, &round_two).unwrap();
        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND + 2).unwrap(),
            Decision::Commit(_)
        ));

        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Commit(Vec::new())
        );
        assert!(fixture.dag.skipped().is_empty());
        assert!(fixture.dag.order().contains(&leader_id));
    }

    #[test]
    fn indirect_skip_when_the_anchor_history_does_not_contain_the_leader() {
        let mut fixture = bootstrapped(4);
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);

        fixture
            .full_round(LEADER_ROUND + 1, &without_leader)
            .unwrap();
        let round_two = fixture.ids(LEADER_ROUND + 1);
        fixture.full_round(LEADER_ROUND + 2, &round_two).unwrap();
        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND + 2).unwrap(),
            Decision::Commit(_)
        ));

        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Skip
        );
        assert_eq!(fixture.dag.skipped().len(), 1);
        // Deciding twice does not record the skip twice.
        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Skip
        );
        assert_eq!(fixture.dag.skipped().len(), 1);
    }

    #[test]
    fn indirect_needs_an_anchor_two_rounds_later() {
        let mut fixture = bootstrapped(4);
        let round_two = fixture.ids(LEADER_ROUND + 1);
        let _ = round_two;
        let too_recent = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND - 1, &too_recent)
                .unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn the_same_input_commits_the_same_sequence() {
        let run = || {
            let mut fixture = bootstrapped(4);
            let votes = fixture.ids(LEADER_ROUND);
            fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
            let decision = fixture.dag.try_commit(LEADER_ROUND).unwrap();
            (decision, fixture.dag.order().to_vec())
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn a_commit_proof_proves_membership_in_the_dag_root() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
        fixture.dag.try_commit(LEADER_ROUND).unwrap();

        let order = fixture.dag.order().to_vec();
        assert!(!order.is_empty(), "there is something to prove");
        let root = fixture.dag.commit_root();
        assert_eq!(root, commit_root(&order));

        for index in 0..order.len() {
            let proof = CommitProof::prove(&order, index).expect("index is in range");
            assert!(
                proof.verify(&root),
                "commit {index} did not verify against the root"
            );
        }
        assert!(CommitProof::prove(&order, order.len()).is_none());
    }

    #[test]
    fn a_commit_proof_for_another_vertex_does_not_verify() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
        fixture.dag.try_commit(LEADER_ROUND).unwrap();

        let order = fixture.dag.order().to_vec();
        let root = fixture.dag.commit_root();
        let mut proof = CommitProof::prove(&order, 0).unwrap();
        proof.vertex.digest[0] ^= 0xff;
        assert!(!proof.verify(&root));
    }

    #[test]
    fn the_commit_root_depends_on_commit_order() {
        let first = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [1u8; 32],
        };
        let second = VertexId {
            round: 1,
            author: b"val-1".to_vec(),
            digest: [2u8; 32],
        };
        assert_ne!(
            commit_root(&[first.clone(), second.clone()]),
            commit_root(&[second, first])
        );
    }

    #[test]
    fn pruning_drops_below_the_floor_and_stops_the_history() {
        let mut fixture = bootstrapped(4);
        let one = fixture.ids(LEADER_ROUND);
        fixture.full_round(2, &one).unwrap();
        let two = fixture.ids(2);
        fixture.full_round(3, &two).unwrap();
        fixture.dag.try_commit(2).unwrap();

        let dropped = fixture.dag.set_floor(2);
        assert_eq!(dropped, 12, "rounds 0..=2 hold four vertices each");
        assert_eq!(fixture.dag.floor(), Some(2));
        assert!(fixture.dag.get(2, b"val-0").is_none());
        assert!(fixture.dag.get(3, b"val-0").is_some());

        // Round 4 references round 3, which itself referenced the now-pruned round 2.
        let three = fixture.ids(3);
        fixture.full_round(4, &three).unwrap();
        let four = fixture.ids(4);
        fixture.full_round(5, &four).unwrap();

        match fixture.dag.try_commit(4).unwrap() {
            Decision::Commit(history) => {
                assert!(!history.is_empty());
                assert!(
                    history.iter().all(|id| id.round > 2),
                    "a pruned ancestor was emitted again"
                );
            }
            other => panic!("expected a commit, got {other:?}"),
        }
    }

    #[test]
    fn a_vertex_below_the_floor_is_accepted_but_not_retained() {
        let mut fixture = bootstrapped(4);
        let vertex = fixture.dag.get(LEADER_ROUND, b"val-0").unwrap().clone();
        fixture.dag.set_floor(LEADER_ROUND);

        let id = fixture.dag.insert(vertex).expect("still signature-valid");
        assert_eq!(id.round, LEADER_ROUND);
        assert!(fixture.dag.get(LEADER_ROUND, b"val-0").is_none());
    }

    #[test]
    fn the_floor_never_moves_down() {
        let mut fixture = bootstrapped(4);
        fixture.dag.set_floor(1);
        assert_eq!(fixture.dag.set_floor(0), 0);
        assert_eq!(fixture.dag.floor(), Some(1));
    }

    /// The retiring and replacement private key for one validator.
    type RotatingKeys = (Vec<u8>, Vec<u8>);

    /// Builds a set where every validator rotates from an old to a new key at
    /// epoch 2, returning the two private keys per validator.
    fn rotating_set(count: usize) -> (ValidatorSet, Vec<RotatingKeys>) {
        let mut private = Vec::with_capacity(count);
        let mut validators = Vec::with_capacity(count);
        for index in 0..count {
            let old_seed = [u8::try_from(index + 1).unwrap(); 32];
            let new_seed = [u8::try_from(index + 51).unwrap(); 32];
            let old_public = Ed25519Scheme::public_key_from_seed(&old_seed).unwrap();
            let new_public = Ed25519Scheme::public_key_from_seed(&new_seed).unwrap();
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![
                    ValidatorKey {
                        key_id: format!("val-{index}-old").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: old_public.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: 2,
                    },
                    ValidatorKey {
                        key_id: format!("val-{index}-new").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: new_public.to_vec(),
                        activation_epoch: 2,
                        retirement_epoch: NO_EXPIRY,
                    },
                ],
            });

            let mut old_private = Vec::new();
            old_private.extend_from_slice(&old_seed);
            old_private.extend_from_slice(&old_public);
            let mut new_private = Vec::new();
            new_private.extend_from_slice(&new_seed);
            new_private.extend_from_slice(&new_public);
            private.push((old_private, new_private));
        }
        let set = ValidatorSet {
            epoch: 0,
            validators,
        };
        set.validate().unwrap();
        (set, private)
    }

    #[test]
    fn a_key_rotation_at_an_epoch_boundary_does_not_stop_the_chain() {
        let count = 4;
        let (set, private) = rotating_set(count);
        let mut dag = Dag::with_epoch_length(set, 2);

        // Two rounds per epoch, so the rotation lands at round 4.
        assert_eq!(dag.epoch_of(3), 1);
        assert_eq!(dag.epoch_of(4), 2);

        for round in 0..=8u64 {
            let epoch = dag.epoch_of(round);
            let references: Vec<VertexId> = (0..count)
                .filter_map(|author| {
                    dag.get(round.wrapping_sub(1), format!("val-{author}").as_bytes())
                        .and_then(|vertex| vertex.id().ok())
                })
                .collect();
            for (author, pair) in private.iter().enumerate() {
                let key = if epoch < 2 { &pair.0 } else { &pair.1 };
                let mut vertex = Vertex {
                    chain_id: b"karsa-epoch-1".to_vec(),
                    epoch,
                    round,
                    author: format!("val-{author}").into_bytes(),
                    payload_hash: [0u8; 32],
                    references: references.clone(),
                    signature: Vec::new(),
                };
                let payload = vertex.signing_payload().unwrap();
                vertex.signature = Ed25519Scheme.sign(key, &payload).unwrap();
                dag.insert(vertex)
                    .expect("a rotated schedule accepts its own key");
            }
        }

        // The leader of round 3 needs votes from round 4, which belongs to the next
        // epoch and is signed with a different key.
        assert!(matches!(dag.try_commit(3).unwrap(), Decision::Commit(_)));
        assert!(matches!(dag.try_commit(4).unwrap(), Decision::Commit(_)));
    }

    #[test]
    fn a_retired_key_cannot_sign_after_the_rotation() {
        let (set, private) = rotating_set(4);
        let mut stale = Vertex {
            chain_id: b"karsa-epoch-1".to_vec(),
            epoch: 2,
            round: 4,
            author: b"val-0".to_vec(),
            payload_hash: [0u8; 32],
            references: Vec::new(),
            signature: Vec::new(),
        };
        let payload = stale.signing_payload().unwrap();
        stale.signature = Ed25519Scheme.sign(&private[0].0, &payload).unwrap();

        // The schedule resolves epoch 2 to the new key, so the old key's signature
        // simply does not match. Either outcome keeps the retired key out; what
        // matters is that it never verifies.
        assert!(stale.verify(&set, 2).is_err());
        assert!(stale.verify(&set, 2).is_err(), "deterministic, not flaky");
    }

    #[test]
    fn the_set_is_exposed_for_callers() {
        let fixture = fixture(4);
        assert_eq!(fixture.dag.set().validators.len(), 4);
        assert_eq!(fixture.dag.set().quorum_size(), 3);
    }

    #[test]
    fn the_leader_author_is_known_without_holding_the_vertex() {
        let fixture = fixture(4);
        assert_eq!(fixture.dag.leader_author(1), Some(&b"val-1"[..]));
        assert!(fixture.dag.leader(1).is_none());
        assert_eq!(fixture.dag.highest_round(), None);
    }

    #[test]
    fn an_anchor_history_answers_whether_it_contains_a_slot() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
        fixture
            .full_round(LEADER_ROUND + 2, &fixture.ids(LEADER_ROUND + 1))
            .unwrap();
        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();

        // The anchor reaches every author of the round before it.
        for author in 0..fixture.count() {
            let id = format!("val-{author}");
            assert!(
                fixture
                    .dag
                    .history_contains_author(&anchor, LEADER_ROUND + 1, id.as_bytes())
                    .unwrap()
            );
        }
        // It does not reach a slot nobody authored, nor a round it never saw.
        assert!(
            !fixture
                .dag
                .history_contains_author(&anchor, LEADER_ROUND + 1, b"val-unknown")
                .unwrap()
        );
        assert!(
            !fixture
                .dag
                .history_contains_author(&anchor, LEADER_ROUND + 9, b"val-0")
                .unwrap()
        );
    }

    #[test]
    fn a_missing_leader_may_still_anchor() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        let leader = fixture.leader_index(LEADER_ROUND);

        // The leader's vertex is signed but deliberately not inserted.
        let missing_id = vertex(&fixture, leader, LEADER_ROUND, genesis.clone())
            .id()
            .unwrap();
        for author in 0..4 {
            if author == leader {
                continue;
            }
            let vertex = vertex(&fixture, author, LEADER_ROUND, genesis.clone());
            fixture.dag.insert(vertex).unwrap();
        }

        // Round-2 votes reference the missing leader by id, so a quorum for round 1
        // is still possible even though this node does not hold the leader's vertex.
        let mut references = fixture.ids(LEADER_ROUND);
        references.push(missing_id);
        fixture.full_round(LEADER_ROUND + 1, &references).unwrap();

        assert!(
            fixture.dag.can_still_anchor(LEADER_ROUND).unwrap(),
            "a missing leader with held votes can still anchor"
        );
    }

    #[test]
    fn an_impossible_quorum_cannot_anchor() {
        let mut fixture = bootstrapped(4);
        // Two held round-2 vertices that do not vote for the round-1 leader. Two
        // votes are missing, so even if both arrive, three voters cannot exist.
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);
        for author in 0..2 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, without_leader.clone());
            fixture.dag.insert(vertex).unwrap();
        }

        assert!(
            !fixture.dag.can_still_anchor(LEADER_ROUND).unwrap(),
            "two held non-votes plus two missing votes cannot reach three"
        );
    }

    fn transition_keys(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let seed = [u8::try_from(index + 1).unwrap(); 32];
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                let mut private = Vec::with_capacity(64);
                private.extend_from_slice(&seed);
                private.extend_from_slice(&public);
                private
            })
            .collect()
    }

    fn transition_records(count: usize, keys: &[Vec<u8>]) -> Vec<ValidatorRecord> {
        (0..count)
            .map(|index| ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: keys[index][32..].to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect()
    }

    /// Builds an old/new set pair and authors rounds 0..=3. The change lands at
    /// round 2, so the first two rounds use the old set and the last two use the
    /// new one.
    fn transition_dag(old_count: usize, new_count: usize) -> (Dag, Vec<Vec<u8>>) {
        let keys = transition_keys(old_count.max(new_count));
        let records = transition_records(old_count.max(new_count), &keys);
        let old_set = ValidatorSet {
            epoch: 1,
            validators: records[..old_count].to_vec(),
        };
        let new_set = ValidatorSet {
            epoch: 2,
            validators: records[..new_count].to_vec(),
        };
        let mut dag = Dag::with_epoch_length_and_change(old_set, new_set, 2, 2)
            .expect("the transition is safe");

        for round in 0..=3u64 {
            let epoch = dag.epoch_of(round);
            let active = if epoch < 2 { old_count } else { new_count };
            let previous_active = if round == 0 {
                0
            } else if dag.epoch_of(round - 1) < 2 {
                old_count
            } else {
                new_count
            };
            let references: Vec<VertexId> = if round == 0 {
                Vec::new()
            } else {
                (0..previous_active)
                    .filter_map(|author| {
                        dag.get(round - 1, format!("val-{author}").as_bytes())
                            .and_then(|vertex| vertex.id().ok())
                    })
                    .collect()
            };
            for (author, key) in keys.iter().enumerate().take(active) {
                let mut vertex = Vertex {
                    chain_id: b"karsa-transition-1".to_vec(),
                    epoch,
                    round,
                    author: format!("val-{author}").into_bytes(),
                    payload_hash: [0u8; 32],
                    references: references.clone(),
                    signature: Vec::new(),
                };
                let payload = vertex.signing_payload().unwrap();
                vertex.signature = Ed25519Scheme.sign(key, &payload).unwrap();
                dag.insert(vertex)
                    .expect("the active set accepts its own vertex");
            }
        }
        (dag, keys)
    }

    #[test]
    fn a_validator_join_at_an_epoch_boundary_keeps_committing() {
        let (mut dag, keys) = transition_dag(4, 5);
        assert_eq!(dag.set_for_round(1).validators.len(), 4);
        assert_eq!(dag.set_for_round(2).validators.len(), 5);
        assert_eq!(dag.leader_author(1), Some(b"val-1".as_slice()));
        assert_eq!(dag.leader_author(2), Some(b"val-2".as_slice()));
        assert!(matches!(dag.try_commit(1).unwrap(), Decision::Commit(_)));
        assert!(matches!(dag.try_commit(2).unwrap(), Decision::Commit(_)));

        // The new validator did not exist for the old epoch.
        let mut stale = Vertex {
            chain_id: b"karsa-transition-1".to_vec(),
            epoch: 1,
            round: 1,
            author: b"val-4".to_vec(),
            payload_hash: [0u8; 32],
            references: Vec::new(),
            signature: Vec::new(),
        };
        let payload = stale.signing_payload().unwrap();
        stale.signature = Ed25519Scheme.sign(&keys[4], &payload).unwrap();
        assert_eq!(
            dag.insert(stale).unwrap_err().kind(),
            CryptoErrorKind::UnknownValidator
        );
    }

    #[test]
    fn a_validator_removal_at_an_epoch_boundary_keeps_committing() {
        let (mut dag, keys) = transition_dag(5, 4);
        assert_eq!(dag.set_for_round(1).validators.len(), 5);
        assert_eq!(dag.set_for_round(2).validators.len(), 4);
        assert!(matches!(dag.try_commit(1).unwrap(), Decision::Commit(_)));
        assert!(matches!(dag.try_commit(2).unwrap(), Decision::Commit(_)));

        // The removed validator cannot author in the new epoch.
        let mut stale = Vertex {
            chain_id: b"karsa-transition-1".to_vec(),
            epoch: 2,
            round: 2,
            author: b"val-4".to_vec(),
            payload_hash: [0u8; 32],
            references: Vec::new(),
            signature: Vec::new(),
        };
        let payload = stale.signing_payload().unwrap();
        stale.signature = Ed25519Scheme.sign(&keys[4], &payload).unwrap();
        assert_eq!(
            dag.insert(stale).unwrap_err().kind(),
            CryptoErrorKind::UnknownValidator
        );
    }
}
