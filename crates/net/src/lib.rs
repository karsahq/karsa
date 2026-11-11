//! Vertex dissemination between validator nodes, with deterministic scheduling.
//!
//! The consensus rules were proven in one process. This crate asks the next
//! question: do independent nodes that only exchange vertices end up with the same
//! DAG, and therefore the same commit sequence?
//!
//! # What is modelled
//!
//! - Each node holds its own `Dag`. It authors at most one vertex per round, and
//!   only when it holds a quorum of distinct previous-round authors — the same rule
//!   `Dag::insert` enforces, applied locally before signing rather than after.
//! - A broadcast reaches every other validator with a latency derived from
//!   `(seed, from, to, sequence)`. There is no clock out of the box: the driver
//!   advances a logical tick, so a run is reproducible bit for bit.
//! - A validator can be marked crashed. It authors nothing and receives nothing,
//!   which is the harshest realistic fault short of equivocation.
//!
//! # What is not modelled
//!
//! No sockets: [`wire`] turns a vertex into a length-prefixed frame and back, but
//! the crate itself does no I/O, so `karsa live` owns the transport and this crate
//! stays testable without a network. No retransmission beyond the reliable
//! in-order delivery this queue provides, no per-link capacity, and no headers or
//! certificates on the wire. Payload is absent too: a vertex here carries a zero
//! payload hash, because this crate is about *ordering* convergence, and batches
//! are a separate data plane.

use std::collections::{BTreeMap, BTreeSet, HashSet};

pub mod wire;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use crypto::{CryptoError, CryptoErrorKind};
use validator::{
    CommitFrontier, Dag, Fence, FenceCertificate, FenceError, NO_EXPIRY, Pacemaker,
    PacemakerConfig, SetChangeError, Step, Transition, TransitionCertificate, ValidatorKey,
    ValidatorRecord, ValidatorSet, Vertex, VertexId,
};

const CHAIN_ID: &[u8] = b"karsa-net-1";
const EPOCH: u64 = 1;

/// How the simulated network is configured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimConfig {
    /// Number of validators.
    ///
    /// Below four the quorum is everyone, so a single silent validator halts the
    /// chain. That is allowed for measurement — `karsa sweep` reports the fault
    /// tolerance next to the number — but it is not a BFT configuration.
    pub validators: usize,
    /// Deliveries always take at least this many ticks.
    pub latency_ticks: u64,
    /// Extra per-link delay, derived from a hash of `(seed, from, to, sequence)`.
    pub jitter_ticks: u64,
    /// The validator that never participates, if any.
    pub crashed: Option<usize>,
    /// Seed for the link-latency hash. The same seed reproduces the same schedule.
    pub seed: u64,
}

impl Default for SimConfig {
    fn default() -> Self {
        Self {
            validators: 4,
            latency_ticks: 1,
            jitter_ticks: 2,
            crashed: None,
            seed: 7,
        }
    }
}

/// A deterministic keypair from one seed byte, as the rest of the workspace does.
fn keypair(seed: u8) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let seed = [seed; 32];
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let mut private_key = Vec::with_capacity(64);
    private_key.extend_from_slice(&seed);
    private_key.extend_from_slice(&public_key);
    Ok((public_key.to_vec(), private_key))
}

/// One validator's view of the DAG.
pub struct Node {
    id: Vec<u8>,
    private_key: Vec<u8>,
    chain_id: Vec<u8>,
    round: u64,
    dag: Dag,
    pacemaker: Pacemaker,
    authored: usize,
}

impl Node {
    /// Creates a node that will author for `id`, which must be in `set`, signing
    /// over the crate's demo chain id.
    #[must_use]
    pub fn new(set: ValidatorSet, id: Vec<u8>, private_key: Vec<u8>) -> Self {
        Self::with_chain_id(set, id, private_key, CHAIN_ID.to_vec())
    }

    /// Creates a node that signs over `chain_id`.
    ///
    /// The chain id is part of the vertex signing payload, so a node given another
    /// chain's id produces vertices that chain's nodes would accept — which is why
    /// callers that know the genesis pass its hash here instead of relying on the
    /// default.
    #[must_use]
    pub fn with_chain_id(
        set: ValidatorSet,
        id: Vec<u8>,
        private_key: Vec<u8>,
        chain_id: Vec<u8>,
    ) -> Self {
        Self::with_chain_id_and_epoch_length(set, 0, id, private_key, chain_id)
    }

    /// Creates a node that signs over `chain_id` and resolves keys through an
    /// epoch schedule of `epoch_rounds` rounds.
    ///
    /// A zero length keeps the whole DAG in one epoch, which is the behaviour of
    /// [`Node::with_chain_id`] and the simulator. A non-zero length makes the
    /// vertex's epoch a function of its round, so a scheduled key rotation is
    /// accepted at the boundary instead of after a restart.
    #[must_use]
    pub fn with_chain_id_and_epoch_length(
        set: ValidatorSet,
        epoch_rounds: u64,
        id: Vec<u8>,
        private_key: Vec<u8>,
        chain_id: Vec<u8>,
    ) -> Self {
        Self {
            id,
            private_key,
            chain_id,
            round: 0,
            dag: Dag::with_epoch_length(set, epoch_rounds),
            pacemaker: Pacemaker::new(PacemakerConfig::default(), 1),
            authored: 0,
        }
    }

    /// Creates a node with one checked validator-set transition.
    ///
    /// The node resolves its authoring membership, the reference rule, and the
    /// vote quorum against the set active at the round. A node that is not in the
    /// current set stays passive instead of authoring a vertex the DAG would
    /// reject.
    ///
    /// # Errors
    ///
    /// Every error from [`Dag::with_epoch_length_and_change`].
    pub fn with_chain_id_epoch_and_set_change(
        set: ValidatorSet,
        next: ValidatorSet,
        change_epoch: u64,
        epoch_rounds: u64,
        id: Vec<u8>,
        private_key: Vec<u8>,
        chain_id: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        Ok(Self {
            id,
            private_key,
            chain_id,
            round: 0,
            dag: Dag::with_epoch_length_and_change(set, next, change_epoch, epoch_rounds)?,
            pacemaker: Pacemaker::new(PacemakerConfig::default(), 1),
            authored: 0,
        })
    }

    /// The validator id this node speaks for.
    #[must_use]
    pub fn id(&self) -> &[u8] {
        &self.id
    }

    /// The round this node will author in next.
    #[must_use]
    pub fn round(&self) -> u64 {
        self.round
    }

    /// The first round the pacemaker will decide.
    #[must_use]
    pub fn cursor(&self) -> u64 {
        self.pacemaker.cursor()
    }

    /// Sets the next decision round after adopting a snapshot prefix.
    pub fn set_cursor(&mut self, cursor: u64) {
        self.pacemaker.set_cursor(cursor);
    }

    /// Sets the round this node will author in next.
    ///
    /// A node that restarts from a store already authored the rounds the store
    /// holds. Without this it would try to author round zero again and broadcast
    /// duplicates.
    pub fn set_round(&mut self, round: u64) {
        self.round = round;
    }

    /// How each skip decision was proved, since this node started.
    #[must_use]
    pub fn skip_counts(&self) -> validator::SkipCounts {
        self.pacemaker.skip_counts()
    }

    /// Adopts a verified committed order prefix from a snapshot.
    pub fn seed_order(&mut self, order: Vec<VertexId>) {
        self.dag.seed_order(order);
    }

    /// Adopts a compact committed prefix plus the tail above the floor.
    pub fn seed_prefix(&mut self, prefix: CommitFrontier, order: Vec<VertexId>) {
        self.dag.seed_prefix(prefix, order);
    }

    /// Truncates the committed order to `len` entries.
    pub fn truncate_order(&mut self, len: usize) {
        self.dag.truncate_order(len);
    }

    /// Treats every round at or below `round` as covered by a state snapshot and
    /// drops the vertices in those rounds.
    ///
    /// A reference into a pruned round is accepted because the state it produced
    /// is already in the snapshot; the commit walk stops at the floor instead of
    /// asking for vertices the node is not supposed to hold.
    ///
    /// Returns how many vertices were dropped.
    pub fn set_floor(&mut self, round: u64) -> usize {
        self.dag.set_floor(round)
    }

    /// How many vertices this node has authored.
    #[must_use]
    pub fn authored(&self) -> usize {
        self.authored
    }

    /// This node's DAG.
    #[must_use]
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// Installs a set-change certificate in this node's DAG.
    ///
    /// # Errors
    ///
    /// Every error from [`Dag::adopt_set_change`].
    pub fn adopt_set_change(
        &mut self,
        certificate: &TransitionCertificate,
    ) -> Result<Transition, SetChangeError> {
        self.dag.adopt_set_change(certificate)
    }

    /// Installs a quorum-authorized fence in this node's DAG.
    ///
    /// # Errors
    ///
    /// Every error from [`Dag::apply_fence`].
    pub fn apply_fence(&mut self, certificate: &FenceCertificate) -> Result<(), FenceError> {
        self.dag.apply_fence(&self.chain_id, certificate)
    }

    /// Records a fence share this node signed.
    ///
    /// The node stops referencing the author from the fence round on, without
    /// rejecting that author's vertices: the promise is about this node's vote,
    /// not about what the DAG may hold.
    pub fn note_local_fence(&mut self, fence: &Fence) {
        self.dag.note_local_fence(fence);
    }

    /// Forgets a local fence promise whose certificate was abandoned.
    pub fn clear_local_fence(&mut self, validator_id: &[u8]) {
        self.dag.clear_local_fence(validator_id);
    }

    /// Ids of every vertex this node holds in `round`.
    fn ids(&self, round: u64) -> Vec<VertexId> {
        self.dag
            .set_for_round(round)
            .validators
            .iter()
            .filter(|record| !self.dag.is_fenced(&record.validator_id, round))
            .filter(|record| !self.dag.is_locally_fenced(&record.validator_id, round))
            .filter_map(|record| self.dag.get(round, &record.validator_id))
            .filter_map(|vertex| vertex.id().ok())
            .collect()
    }

    /// Authors this round's vertex if the reference rule can be met.
    ///
    /// Returns `None` while the node is still missing previous-round vertices. The
    /// check is the same one `Dag::insert` performs, done before signing so this
    /// node never produces a vertex it would reject itself.
    ///
    /// The vertex names no payload: this node only orders.
    ///
    /// # Errors
    ///
    /// Propagates signing and DAG insertion errors.
    pub fn author(&mut self) -> Result<Option<Vertex>, CryptoError> {
        self.author_with([0u8; 32])
    }

    /// Authors this round's vertex, naming the batch it orders.
    ///
    /// `payload_hash` is part of the signed payload, so it has to be known before
    /// signing — a node cannot add a batch to a vertex it already signed.
    ///
    /// # Errors
    ///
    /// Propagates signing and DAG insertion errors.
    pub fn author_with(&mut self, payload_hash: [u8; 32]) -> Result<Option<Vertex>, CryptoError> {
        let round = self.round;
        let current = self.dag.set_for_round(round);
        if !current
            .validators
            .iter()
            .any(|record| record.validator_id.as_slice() == self.id.as_slice())
        {
            // A node outside the active set still has to track the DAG: its round
            // only moves on authorship, so a validator added at a later epoch would
            // otherwise stay at round 0 and never reach the epoch where it is a
            // member. Jump to the round after the newest vertex this node holds; it
            // starts authoring as soon as that round belongs to a set containing it.
            if let Some(highest) = self.dag.highest_round() {
                self.round = self.round.max(highest.saturating_add(1));
            }
            return Ok(None);
        }
        let references = if round == 0 {
            Vec::new()
        } else {
            self.ids(round - 1)
        };

        if round > 0 {
            let authors: HashSet<&[u8]> = references
                .iter()
                .filter(|reference| {
                    current
                        .validators
                        .iter()
                        .any(|record| record.validator_id == reference.author)
                })
                .map(|reference| reference.author.as_slice())
                .collect();
            if authors.len() < current.quorum_size() {
                return Ok(None);
            }
        }

        let mut vertex = Vertex {
            chain_id: self.chain_id.clone(),
            epoch: self.dag.epoch_of(round),
            round,
            author: self.id.clone(),
            // Ordering only unless the caller names a batch.
            payload_hash,
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload()?;
        vertex.signature = Ed25519Scheme.sign(&self.private_key, &payload)?;

        self.dag.insert(vertex.clone())?;
        self.round += 1;
        self.authored += 1;
        Ok(Some(vertex))
    }

    /// Accepts a vertex from another validator.
    ///
    /// # Errors
    ///
    /// Every error from [`Dag::insert`]: a bad signature, an unknown author, or a
    /// vertex that does not carry the references its round requires.
    pub fn receive(&mut self, vertex: Vertex) -> Result<(), CryptoError> {
        self.dag.insert(vertex).map(|_| ())
    }

    /// Takes one pacemaker tick.
    ///
    /// # Errors
    ///
    /// Propagates the commit rules' errors.
    pub fn commit(&mut self) -> Result<Step, CryptoError> {
        self.pacemaker.tick(&mut self.dag)
    }

    /// Takes one decision rather than every decision available in a tick.
    ///
    /// A caller that records one artifact per commit needs the boundaries that
    /// [`Node::commit`] collapses into a single [`Step`]. The decision sequence is
    /// the same; only the reporting granularity differs.
    ///
    /// # Errors
    ///
    /// Propagates the commit rules' errors.
    pub fn commit_once(&mut self) -> Result<Step, CryptoError> {
        self.pacemaker.tick_one(&mut self.dag)
    }
}

/// The identity of one held vertex: round, author, and digest.
type HeldKey = (u64, Vec<u8>, [u8; 32]);

/// One in-flight vertex.
#[derive(Debug, Clone)]
struct Delivery {
    to: usize,
    vertex: Vertex,
}

/// What one simulation produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Summary {
    /// Ticks the driver ran.
    pub ticks: u64,
    /// Vertices delivered in total.
    pub delivered: u64,
    /// Vertices each node authored, indexed by validator.
    pub authored: Vec<usize>,
    /// Vertices each node holds, indexed by validator.
    pub held: Vec<usize>,
    /// Committed sequence length per node.
    pub committed: Vec<usize>,
    /// Commit root over each node's committed sequence.
    pub commit_roots: Vec<[u8; 32]>,
    /// Whether every node's DAG holds exactly the same vertices.
    pub same_dag: bool,
    /// Whether every node committed exactly the same sequence, in the same order.
    pub same_order: bool,
}

/// Drives nodes against a fixed delivery schedule.
pub struct Simulator {
    config: SimConfig,
    nodes: Vec<Node>,
    queue: BTreeMap<(u64, u64), Delivery>,
    tick: u64,
    sequence: u64,
    delivered: u64,
}

impl Simulator {
    /// Builds a network of `config.validators` nodes.
    ///
    /// # Errors
    ///
    /// Returns an error when the validator count is below 2, or when the set or a
    /// key cannot be built.
    pub fn new(config: SimConfig) -> Result<Self, CryptoError> {
        if config.validators < 2 {
            return Err(CryptoError::new(
                CryptoErrorKind::InvalidVertex,
                "at least 2 validators are required",
            ));
        }

        let mut validators = Vec::with_capacity(config.validators);
        let mut keys = Vec::with_capacity(config.validators);
        for index in 0..config.validators {
            let (public_key, private_key) = keypair(u8::try_from(index + 1).unwrap_or(1))?;
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key,
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
        set.validate()?;

        let nodes = (0..config.validators)
            .map(|index| {
                Node::new(
                    set.clone(),
                    format!("val-{index}").into_bytes(),
                    keys[index].clone(),
                )
            })
            .collect();

        Ok(Self {
            config,
            nodes,
            queue: BTreeMap::new(),
            tick: 0,
            sequence: 0,
            delivered: 0,
        })
    }

    /// The nodes, for inspection.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    fn crashed(&self, index: usize) -> bool {
        self.config.crashed == Some(index)
    }

    /// Delivery latency for one link, as a pure function of the configuration.
    fn latency(&self, from: usize, to: usize, sequence: u64) -> u64 {
        let mut hash = self.config.seed
            ^ u64::try_from(from)
                .unwrap_or(0)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
            ^ u64::try_from(to)
                .unwrap_or(0)
                .wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
            ^ sequence.wrapping_mul(0x1656_67B1_9E37_79F9);
        hash ^= hash >> 33;
        hash = hash.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
        hash ^= hash >> 33;

        let jitter = if self.config.jitter_ticks == 0 {
            0
        } else {
            hash % (self.config.jitter_ticks + 1)
        };
        self.config.latency_ticks + jitter
    }

    fn broadcast(&mut self, from: usize, vertex: Vertex) {
        for to in 0..self.nodes.len() {
            if to == from || self.crashed(to) {
                continue;
            }
            let sequence = self.sequence;
            self.sequence += 1;
            let at = self.tick + self.latency(from, to, sequence);
            self.queue.insert(
                (at, sequence),
                Delivery {
                    to,
                    vertex: vertex.clone(),
                },
            );
        }
    }

    /// Runs `max_ticks` of authoring and delivery, then drains and settles.
    ///
    /// The nodes never stop producing rounds on their own, so a run has to be cut
    /// at some tick. Cutting mid-flight would leave vertices in transit and make
    /// convergence unmeasurable, so the run first delivers everything still queued
    /// and then lets every pacemaker finish. Convergence is therefore a statement
    /// about *eventual* delivery, not about an arbitrary instant.
    ///
    /// # Errors
    ///
    /// Propagates any vertex rejection, which is a bug in a well-behaved run rather
    /// than a network condition.
    pub fn run(&mut self, max_ticks: u64) -> Result<Summary, CryptoError> {
        for _ in 0..max_ticks {
            self.deliver_due()?;
            self.author_round()?;
            self.settle()?;
            self.tick += 1;
        }
        self.drain()?;
        Ok(self.summarise())
    }

    /// Delivers everything still in flight, then lets each pacemaker finish.
    fn drain(&mut self) -> Result<(), CryptoError> {
        while let Some(at) = self.queue.keys().next().map(|(at, _)| *at) {
            self.tick = self.tick.max(at);
            self.deliver_due()?;
        }
        // A pacemaker can only decide so many rounds; the bound is a guard against
        // a rule that stops making progress, not an expected limit.
        for _ in 0..1_000 {
            let before = self
                .nodes
                .iter()
                .map(|node| node.dag().order().len())
                .sum::<usize>();
            self.settle()?;
            let after = self
                .nodes
                .iter()
                .map(|node| node.dag().order().len())
                .sum::<usize>();
            if after == before {
                break;
            }
        }
        Ok(())
    }

    /// One pacemaker tick per live node.
    fn settle(&mut self) -> Result<(), CryptoError> {
        for index in 0..self.nodes.len() {
            if self.crashed(index) {
                continue;
            }
            self.nodes[index].commit()?;
        }
        Ok(())
    }

    fn deliver_due(&mut self) -> Result<(), CryptoError> {
        let due: Vec<(u64, u64)> = self
            .queue
            .range(..=(self.tick, u64::MAX))
            .map(|(key, _)| *key)
            .collect();
        for key in due {
            let Some(delivery) = self.queue.remove(&key) else {
                continue;
            };
            if self.crashed(delivery.to) {
                continue;
            }
            self.nodes[delivery.to].receive(delivery.vertex)?;
            self.delivered += 1;
        }
        Ok(())
    }

    fn author_round(&mut self) -> Result<(), CryptoError> {
        for index in 0..self.nodes.len() {
            if self.crashed(index) {
                continue;
            }
            if let Some(vertex) = self.nodes[index].author()? {
                self.broadcast(index, vertex);
            }
        }
        Ok(())
    }

    fn held(&self, index: usize) -> BTreeSet<HeldKey> {
        let node = &self.nodes[index];
        let highest = node.dag().highest_round().unwrap_or(0);
        let mut set = BTreeSet::new();
        for round in 0..=highest {
            for record in &node.dag().set().validators {
                if let Some(vertex) = node.dag().get(round, &record.validator_id)
                    && let Ok(id) = vertex.id()
                {
                    set.insert((id.round, id.author, id.digest));
                }
            }
        }
        set
    }

    fn summarise(&self) -> Summary {
        let authored: Vec<usize> = self.nodes.iter().map(Node::authored).collect();
        let committed: Vec<usize> = self
            .nodes
            .iter()
            .map(|node| node.dag().order().len())
            .collect();
        let commit_roots: Vec<[u8; 32]> = self
            .nodes
            .iter()
            .map(|node| validator::commit_root(node.dag().order()))
            .collect();

        // A crashed node is expected to lag; every other node is expected to agree.
        let live: Vec<usize> = (0..self.nodes.len())
            .filter(|index| !self.crashed(*index))
            .collect();

        let held: Vec<BTreeSet<HeldKey>> = live.iter().map(|index| self.held(*index)).collect();
        let same_dag = held.windows(2).all(|pair| pair[0] == pair[1]);

        let orders: Vec<Vec<VertexId>> = live
            .iter()
            .map(|index| self.nodes[*index].dag().order().to_vec())
            .collect();
        let same_order = orders.windows(2).all(|pair| pair[0] == pair[1]);

        Summary {
            ticks: self.tick,
            delivered: self.delivered,
            authored,
            held: (0..self.nodes.len())
                .map(|index| self.held(index).len())
                .collect(),
            committed,
            commit_roots,
            same_dag,
            same_order,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(jitter: u64, crashed: Option<usize>) -> SimConfig {
        SimConfig {
            validators: 4,
            latency_ticks: 1,
            jitter_ticks: jitter,
            crashed,
            seed: 11,
        }
    }

    #[test]
    fn a_quiet_network_reaches_one_dag() {
        let mut simulator = Simulator::new(config(2, None)).unwrap();
        let summary = simulator.run(12).unwrap();

        assert!(summary.same_dag, "live nodes disagreed on the DAG");
        assert!(
            summary.same_order,
            "live nodes committed different sequences"
        );
        assert!(summary.delivered > 0, "nothing was exchanged");
        assert!(summary.authored.iter().all(|count| *count > 0));
    }

    #[test]
    fn a_crashed_validator_does_not_stop_the_others() {
        let mut simulator = Simulator::new(config(2, Some(3))).unwrap();
        let summary = simulator.run(12).unwrap();

        assert_eq!(summary.authored[3], 0, "the crashed node authored");
        assert_eq!(summary.held[3], 0, "the crashed node received");
        assert!(summary.same_dag);
        assert!(summary.same_order);
        assert!(summary.committed[0] > 0, "the live nodes committed nothing");
    }

    #[test]
    fn the_same_seed_reproduces_the_same_run() {
        let first = Simulator::new(config(3, None)).unwrap().run(12).unwrap();
        let second = Simulator::new(config(3, None)).unwrap().run(12).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn another_schedule_still_converges() {
        let mut other = config(3, None);
        other.seed = 99;
        let first = Simulator::new(config(3, None)).unwrap().run(12).unwrap();
        let second = Simulator::new(other).unwrap().run(12).unwrap();

        // A different schedule changes which references a node held when it
        // authored, so the two runs need not agree with each other. Each run must
        // still agree with itself.
        assert!(first.same_dag && first.same_order);
        assert!(second.same_dag && second.same_order);
        assert!(second.committed[0] > 0);
    }

    #[test]
    fn zero_latency_still_converges() {
        let mut zero = config(0, None);
        zero.latency_ticks = 0;
        let summary = Simulator::new(zero).unwrap().run(12).unwrap();
        assert!(summary.same_dag);
        assert!(summary.same_order);
    }

    #[test]
    fn fewer_than_two_validators_is_refused() {
        let mut small = config(0, None);
        small.validators = 1;
        assert!(Simulator::new(small).is_err());
    }

    #[test]
    fn a_signed_fence_share_stops_this_node_referencing_the_author() {
        let mut nodes = test_nodes(4);
        let mut rounds: Vec<Vec<Vertex>> = Vec::new();
        for _ in 0..2 {
            let mut authored = Vec::with_capacity(4);
            for node in &mut nodes {
                authored.push(node.author().unwrap().expect("a vertex"));
            }
            for vertex in &authored {
                for node in &mut nodes {
                    node.receive(vertex.clone()).unwrap();
                }
            }
            rounds.push(authored);
        }

        let target = rounds[1]
            .iter()
            .find(|vertex| vertex.author == b"val-1")
            .expect("val-1's round-1 vertex")
            .id()
            .unwrap();
        let fence = Fence::new(CHAIN_ID.to_vec(), 1, b"val-1".to_vec());
        nodes[0].note_local_fence(&fence);

        let authored = nodes[0]
            .author()
            .unwrap()
            .expect("a vertex after the promise");
        assert!(
            !authored.references.contains(&target),
            "a signed fence share must stop this node from voting for the author"
        );
        assert!(
            authored.references.len() >= 3,
            "the reference quorum still holds without the fenced author"
        );

        // The promise is about this node's vote, not about what the DAG may hold.
        let other = nodes[1].author().unwrap().expect("val-1 still authors");
        assert_eq!(other.author, b"val-1");
        nodes[0].receive(other).unwrap();
    }

    #[test]
    fn two_validators_converge_but_tolerate_no_faults() {
        let mut pair = config(0, None);
        pair.validators = 2;
        let summary = Simulator::new(pair).unwrap().run(6).unwrap();
        assert!(summary.same_dag);
        assert!(summary.same_order);

        // With two validators the quorum is both of them: one silent node halts it.
        let mut halved = config(0, Some(1));
        halved.validators = 2;
        let summary = Simulator::new(halved).unwrap().run(6).unwrap();
        assert_eq!(
            summary.committed[0], 0,
            "one node cannot form a quorum alone"
        );
    }

    /// Four nodes with the simulator's demo identities and independent keys.
    fn test_nodes(count: usize) -> Vec<Node> {
        let mut validators = Vec::with_capacity(count);
        let mut keys = Vec::with_capacity(count);
        for index in 0..count {
            let (public_key, private_key) = keypair(u8::try_from(index + 1).unwrap()).unwrap();
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key,
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
        (0..count)
            .map(|index| {
                Node::new(
                    set.clone(),
                    format!("val-{index}").into_bytes(),
                    keys[index].clone(),
                )
            })
            .collect()
    }
}
