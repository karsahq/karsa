//! A round-based DAG with a direct commit rule.
//!
//! This is the first half of a DAG-BFT engine, and deliberately only the first
//! half. What is here:
//!
//! - vertices stored one per `(round, author)`, verified against the schedule;
//! - deterministic leader election as a function of the round;
//! - the **direct** rule: a leader with a supermajority of next-round votes
//!   commits, a leader with a supermajority of next-round non-votes is skipped,
//!   and anything else is undecided;
//! - causal history: a commit includes the leader's ancestors, each exactly once.
//!
//! What is **not** here, and must not be assumed: indirect commit through an
//! anchor, waves or pipelining, a pacemaker, and any treatment of asynchrony. In
//! particular, absence of a vote is never evidence: a leader is only skipped when
//! a supermajority is *observed* not to reference it.

use std::collections::{BTreeMap, HashSet};

use crypto::{CryptoError, CryptoErrorKind};

use crate::schedule::ValidatorSet;
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

/// Vertices this node holds, plus what it has already committed.
pub struct Dag {
    set: ValidatorSet,
    vertices: BTreeMap<(u64, Vec<u8>), Vertex>,
    committed: HashSet<[u8; 32]>,
    order: Vec<VertexId>,
    skipped: Vec<VertexId>,
}

impl Dag {
    /// Creates an empty DAG for `set`.
    #[must_use]
    pub fn new(set: ValidatorSet) -> Self {
        Self {
            set,
            vertices: BTreeMap::new(),
            committed: HashSet::new(),
            order: Vec::new(),
            skipped: Vec::new(),
        }
    }

    /// The validator set this DAG resolves keys against.
    #[must_use]
    pub fn set(&self) -> &ValidatorSet {
        &self.set
    }

    /// Inserts a vertex after verifying it.
    ///
    /// A second vertex from the same author in the same round is **ignored**: the
    /// first one wins, so an author cannot vote twice. That is the rule that stops
    /// a Byzantine validator from manufacturing quorum alone.
    ///
    /// # Errors
    ///
    /// Propagates [`Vertex::verify`].
    pub fn insert(&mut self, vertex: Vertex) -> Result<VertexId, CryptoError> {
        vertex.verify(&self.set)?;
        let key = (vertex.round, vertex.author.clone());
        if let Some(existing) = self.vertices.get(&key) {
            return existing.id();
        }
        let id = vertex.id()?;
        self.vertices.insert(key, vertex);
        Ok(id)
    }

    /// Returns the vertex for one author and round.
    #[must_use]
    pub fn get(&self, round: u64, author: &[u8]) -> Option<&Vertex> {
        self.vertices.get(&(round, author.to_vec()))
    }

    /// The elected leader of `round`, if this node has it.
    ///
    /// Election is `round % n` over the set order: deterministic and trivial on
    /// purpose. A real deployment wants a stake-weighted or VRF schedule, which is
    /// a different problem from the commit rule.
    #[must_use]
    pub fn leader(&self, round: u64) -> Option<&Vertex> {
        let index = usize::try_from(round).ok()? % self.set.validators.len();
        let author = &self.set.validators[index].validator_id;
        self.get(round, author)
    }

    /// Vertices in the round after `round` that this node holds.
    fn round_vertices(&self, round: u64) -> Vec<&Vertex> {
        self.vertices
            .range((round, Vec::new())..)
            .take_while(|((r, _), _)| *r == round)
            .map(|(_, vertex)| vertex)
            .collect()
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
        let voters = tally_votes(&self.set, &leader_id, &candidates)?;

        if self.set.has_supermajority(voters.len()) {
            let history = self.commit_history(&leader_id)?;
            return Ok(Decision::Commit(history));
        }

        // Only observed non-votes count. A voter whose vertex has not arrived is
        // unknown, not against the leader, so it cannot produce a skip.
        let non_voters = candidates.len() - voters.len();
        if self.set.has_supermajority(non_voters) {
            return Ok(Decision::Skip);
        }
        Ok(Decision::Undecided)
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
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| {
                    CryptoError::new(
                        CryptoErrorKind::MissingReference,
                        format!(
                            "vertex {}@{} is referenced but not held",
                            String::from_utf8_lossy(&current.author),
                            current.round
                        ),
                    )
                })?;
            if self.committed.contains(&current.digest) {
                continue;
            }
            collected.extend(vertex.references.iter().cloned());
            stack.extend(vertex.references.iter().cloned());
            collected.push(current);
        }

        // Deduplicate, drop already committed, and order by (round, author) so two
        // nodes with the same history commit the same sequence.
        collected.retain(|vertex| !self.committed.contains(&vertex.digest));
        collected.sort_by(|a, b| a.round.cmp(&b.round).then_with(|| a.author.cmp(&b.author)));
        collected.dedup();

        for vertex in &collected {
            self.committed.insert(vertex.digest);
            self.order.push(vertex.clone());
        }
        Ok(collected)
    }

    /// The committed sequence, in commit order.
    #[must_use]
    pub fn order(&self) -> &[VertexId] {
        &self.order
    }

    /// Slots this node has decided to skip, in decision order.
    #[must_use]
    pub fn skipped(&self) -> &[VertexId] {
        &self.skipped
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
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| {
                    CryptoError::new(
                        CryptoErrorKind::MissingReference,
                        format!(
                            "vertex {}@{} is referenced but not held",
                            String::from_utf8_lossy(&current.author),
                            current.round
                        ),
                    )
                })?;
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
    /// supermajority of the previous round. This simulator does not enforce that
    /// rule, so on an arbitrary DAG the argument does not hold — stated here rather
    /// than hidden.
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
        if !self.skipped.contains(&leader_id) {
            self.skipped.push(leader_id);
        }
        Ok(Decision::Skip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const EPOCH: u64 = 1;

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
        let dag = Dag::new(set);
        Fixture { keys, dag }
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

    /// Elects the leader of `round` by the same rule the DAG uses.
    fn leader_index(round: u64, count: usize) -> usize {
        usize::try_from(round).unwrap() % count
    }

    #[test]
    fn a_supermajority_of_votes_commits_the_leader() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();

        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, vec![leader_id.clone()]))
                .unwrap();
        }

        let decision = fixture.dag.try_commit(7).unwrap();
        match decision {
            Decision::Commit(history) => {
                assert!(history.contains(&leader_id));
                assert_eq!(history.len(), 1, "only the leader was referenced");
            }
            other => panic!("expected a commit, got {other:?}"),
        }
        assert_eq!(fixture.dag.order().len(), 1);
    }

    #[test]
    fn one_silent_validator_still_commits() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();

        for author in 0..3 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, vec![leader_id.clone()]))
                .unwrap();
        }
        assert!(matches!(
            fixture.dag.try_commit(7).unwrap(),
            Decision::Commit(_)
        ));
    }

    #[test]
    fn missing_votes_are_undecided_not_a_skip() {
        // n=4, quorum is 3. Two votes and two absent voters is neither quorum.
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();

        for author in 0..2 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, vec![leader_id.clone()]))
                .unwrap();
        }
        assert_eq!(fixture.dag.try_commit(7).unwrap(), Decision::Undecided);
    }

    #[test]
    fn observed_non_votes_skip_the_leader() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();

        // Three voters present, none of them referencing the leader: that is an
        // observed supermajority of non-votes, which is the only evidence that
        // may skip a leader.
        for author in 0..3 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, Vec::new()))
                .unwrap();
        }
        assert_eq!(fixture.dag.try_commit(7).unwrap(), Decision::Skip);
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn a_missing_leader_is_undecided() {
        let mut fixture = fixture(4);
        assert_eq!(fixture.dag.try_commit(7).unwrap(), Decision::Undecided);
    }

    #[test]
    fn a_second_vertex_from_the_same_author_is_ignored() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();

        // The same author submits twice in round 8: the vote still counts once.
        for _ in 0..2 {
            fixture
                .dag
                .insert(vertex(&fixture, 0, 8, vec![leader_id.clone()]))
                .unwrap();
        }
        assert_eq!(fixture.dag.round_vertices(8).len(), 1);
        assert_eq!(fixture.dag.try_commit(7).unwrap(), Decision::Undecided);
    }

    #[test]
    fn history_is_committed_once_and_in_a_stable_order() {
        let mut fixture = fixture(4);
        // Round 7 leader references round 6 vertices from two authors.
        for author in 0..2 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 6, Vec::new()))
                .unwrap();
        }
        let round6: Vec<VertexId> = (0..2)
            .map(|author| {
                fixture
                    .dag
                    .get(6, format!("val-{author}").as_bytes())
                    .unwrap()
                    .id()
                    .unwrap()
            })
            .collect();

        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, round6.clone()))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();

        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, vec![leader_id.clone()]))
                .unwrap();
        }

        let Decision::Commit(history) = fixture.dag.try_commit(7).unwrap() else {
            panic!("expected a commit");
        };
        assert_eq!(history.len(), 3, "two ancestors plus the leader");
        // Ancestors first, ordered by (round, author).
        assert_eq!(history[0].round, 6);
        assert_eq!(history[1].round, 6);
        assert_eq!(history[2].round, 7);

        // Asking again changes nothing.
        assert_eq!(
            fixture.dag.try_commit(7).unwrap(),
            Decision::Commit(Vec::new())
        );
        assert_eq!(fixture.dag.order().len(), 3);
    }

    #[test]
    fn a_missing_ancestor_blocks_the_commit() {
        let mut fixture = fixture(4);
        // A fabricated reference to a vertex this node never received.
        let phantom = VertexId {
            round: 6,
            author: b"val-2".to_vec(),
            digest: [9u8; 32],
        };
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, vec![phantom]))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, vec![leader_id.clone()]))
                .unwrap();
        }

        let error = fixture.dag.try_commit(7).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn the_same_input_commits_the_same_sequence() {
        let run = || {
            let mut fixture = fixture(4);
            for author in 0..3 {
                fixture
                    .dag
                    .insert(vertex(&fixture, author, 6, Vec::new()))
                    .unwrap();
            }
            let refs: Vec<VertexId> = (0..3)
                .map(|author| {
                    fixture
                        .dag
                        .get(6, format!("val-{author}").as_bytes())
                        .unwrap()
                        .id()
                        .unwrap()
                })
                .collect();
            let leader_author = leader_index(7, 4);
            fixture
                .dag
                .insert(vertex(&fixture, leader_author, 7, refs))
                .unwrap();
            let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();
            for author in 0..4 {
                fixture
                    .dag
                    .insert(vertex(&fixture, author, 8, vec![leader_id.clone()]))
                    .unwrap();
            }
            let decision = fixture.dag.try_commit(7).unwrap();
            (decision, fixture.dag.order().to_vec())
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn indirect_commit_finds_the_leader_inside_the_anchor_history() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();
        let leader_id = fixture.dag.leader(7).unwrap().id().unwrap();

        // Round 8: two authors vote for the round-7 leader, two do not. The direct
        // rule cannot decide, because two is not a quorum of four.
        for author in 0..4 {
            let references = if author < 2 {
                vec![leader_id.clone()]
            } else {
                Vec::new()
            };
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, references))
                .unwrap();
        }
        assert_eq!(fixture.dag.try_commit(7).unwrap(), Decision::Undecided);

        // Round 9 references the whole round 8, and round 10 commits its leader.
        let round8: Vec<VertexId> = (0..4)
            .map(|author| {
                fixture
                    .dag
                    .get(8, format!("val-{author}").as_bytes())
                    .unwrap()
                    .id()
                    .unwrap()
            })
            .collect();
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 9, round8.clone()))
                .unwrap();
        }
        let anchor_author = leader_index(9, 4);
        let anchor_id = fixture
            .dag
            .get(9, format!("val-{anchor_author}").as_bytes())
            .unwrap()
            .id()
            .unwrap();
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 10, vec![anchor_id.clone()]))
                .unwrap();
        }
        assert!(matches!(
            fixture.dag.try_commit(9).unwrap(),
            Decision::Commit(_)
        ));

        // The round-7 slot is inside the anchor's history, so it is decided, and
        // asking again yields nothing new.
        assert_eq!(
            fixture.dag.try_indirect_decide(7, &anchor_id).unwrap(),
            Decision::Commit(Vec::new())
        );
        assert!(fixture.dag.skipped().is_empty());
        assert!(fixture.dag.order().contains(&leader_id));
    }

    #[test]
    fn indirect_skip_when_the_anchor_history_does_not_contain_the_leader() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();

        // Nobody references the round-7 leader, so it is inside no one's history.
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, Vec::new()))
                .unwrap();
        }
        let round8: Vec<VertexId> = (0..4)
            .map(|author| {
                fixture
                    .dag
                    .get(8, format!("val-{author}").as_bytes())
                    .unwrap()
                    .id()
                    .unwrap()
            })
            .collect();
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 9, round8.clone()))
                .unwrap();
        }
        let anchor_author = leader_index(9, 4);
        let anchor_id = fixture
            .dag
            .get(9, format!("val-{anchor_author}").as_bytes())
            .unwrap()
            .id()
            .unwrap();
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 10, vec![anchor_id.clone()]))
                .unwrap();
        }
        assert!(matches!(
            fixture.dag.try_commit(9).unwrap(),
            Decision::Commit(_)
        ));

        assert_eq!(
            fixture.dag.try_indirect_decide(7, &anchor_id).unwrap(),
            Decision::Skip
        );
        assert_eq!(fixture.dag.skipped().len(), 1);
        // Deciding twice does not record the skip twice.
        assert_eq!(
            fixture.dag.try_indirect_decide(7, &anchor_id).unwrap(),
            Decision::Skip
        );
        assert_eq!(fixture.dag.skipped().len(), 1);
    }

    #[test]
    fn indirect_needs_an_anchor_two_rounds_later() {
        let mut fixture = fixture(4);
        let leader_author = leader_index(7, 4);
        fixture
            .dag
            .insert(vertex(&fixture, leader_author, 7, Vec::new()))
            .unwrap();
        for author in 0..4 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 8, Vec::new()))
                .unwrap();
        }
        let too_recent = fixture.dag.get(8, b"val-0").unwrap().id().unwrap();
        assert_eq!(
            fixture.dag.try_indirect_decide(7, &too_recent).unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn the_set_is_exposed_for_callers() {
        let fixture = fixture(4);
        assert_eq!(fixture.dag.set().validators.len(), 4);
    }
}
