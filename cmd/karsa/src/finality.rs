//! Client submit to finality, with a configurable network in between.
//!
//! Every other command that reports a round time measures authoring. This one
//! measures what a client sees: a batch is signed and submitted to a validator,
//! carried by a vertex, decided by the DAG commit rule, and committed into a
//! header that a quorum signs. The clock starts at the submit and stops at the
//! first moment a quorum certificate for the covering header exists.
//!
//! # What is measured, and what is not
//!
//! - **Commit** is the pacemaker decision. It is real: the same `Pacemaker` and
//!   `Dag` the nodes use, driven one decision at a time by
//!   [`net::Node::commit_once`].
//! - **Certificate** is a header over the committed prefix, signed by the
//!   certificate keys. The shares travel over the same simulated links, so the
//!   number includes the round trip a portable certificate needs.
//! - **Rounds** are the protocol-level metric, independent of wall-clock: the
//!   vertex's round to the round whose votes decided the commit. It is reported
//!   separately because it is what a design comparison should use; milliseconds
//!   here depend on the injected delay.
//!
//! All nodes live in one process, so there is no independent operator, no
//! encryption, and no peer discovery. The links are `mpsc` channels with a
//! one-way delay, not TCP; `karsa live` is the command that measures the wire.
//! What this adds is the part `live` cannot measure: one clock that starts before
//! the first frame and stops at a certified header.
//!
//! # Why one decision at a time
//!
//! A header is a commitment to a prefix of the committed order. Two nodes that
//! drain different numbers of decisions into one tick would otherwise build
//! different prefix headers for the same chain. [`net::Node::commit_once`] stops
//! at each decision boundary, so the header sequence is a function of the DAG and
//! not of arrival timing.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::error::Error;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crypto::CryptoErrorKind;
use crypto::scheme::Ed25519Scheme;
use exec::State;
use net::Node;
use tokio::sync::{mpsc, oneshot, watch};
use tx::batch::Batch;
use validator::{
    Certificate, Header, HeaderChain, SetSchedule, Step, Vertex, bitmap_len, commit_root, set_bit,
};

use crate::chain;

/// Tick floor for authoring and the decision loop, in milliseconds.
///
/// The same 2 ms `karsa live` uses. It is a pacing floor, not a slot time:
/// a node that is missing references simply authors later.
const TICK: Duration = Duration::from_millis(2);
/// Balance every demo account starts with, so a latency run does not turn into
/// a fee-exhaustion run halfway through.
const BALANCE: u64 = 1_000_000_000;
/// Opaque validator-set label carried by the certificates. It is not used to
/// resolve keys; the set and epoch are.
const VALIDATOR_SET_ID: &[u8] = b"karsa-finality-1";
/// Time kept after the last sample finalizes, so the other nodes can catch up
/// before the mesh is shut down.
const DRAIN: Duration = Duration::from_millis(200);

/// One validator added or removed at an epoch boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetChange {
    /// Append one validator to the set; the new set has one more.
    Add,
    /// Remove the last validator from the set; the new set has one fewer.
    Remove,
}

/// How a finality run is configured.
#[derive(Clone, Debug)]
pub struct Config {
    /// Committee size before any transition.
    pub validators: usize,
    /// Client submissions. Each one is a separate batch and a separate round.
    pub samples: usize,
    /// Transactions in each submitted batch.
    pub txs: u64,
    /// One-way delay on every frame.
    pub delay: Duration,
    /// Extra delay, drawn per frame in `0..=jitter_ms` from the link's hash.
    pub jitter: Duration,
    /// Wall-clock cap on the whole run.
    pub timeout: Duration,
    /// Home directory whose genesis fixes the identity and the epoch length.
    pub home: Option<PathBuf>,
    /// Override the epoch length for this experiment; `None` keeps the
    /// membership's value.
    pub epoch_rounds: Option<u64>,
    /// Optional validator-set transition at an epoch boundary.
    pub change: Option<(SetChange, u64)>,
    /// Start the added validator at the boundary from a replayed history instead
    /// of running it passively from round 0.
    pub cold_join: bool,
}

/// One client submission, as the client saw it.
#[derive(Debug)]
struct Submission {
    digest: [u8; 32],
    at: u64,
}

/// A sample a validator took from its own decision.
#[derive(Debug)]
struct CommittedSample {
    digest: [u8; 32],
    vertex_round: u64,
    header_round: u64,
    header_height: u64,
    commit_ns: u64,
    leader: bool,
}

/// The records a joining validator replays from validator 0's snapshot.
#[derive(Clone, Debug, Default)]
struct History {
    vertices: BTreeMap<(u64, Vec<u8>), Vertex>,
    batches: BTreeMap<[u8; 32], Batch>,
    headers: BTreeMap<u64, (Header, Certificate)>,
    /// Committed order up to the last header validator 0 built.
    order: Vec<validator::VertexId>,
    /// The last header validator 0 built, which commits `order`.
    last_built: Option<Header>,
    /// The next decision round after `last_built`.
    cursor: u64,
}

/// What one cold join cost before the validator entered the live mesh.
#[derive(Clone, Debug)]
struct CatchUpReport {
    elapsed_ns: u64,
    bytes: u64,
    rounds: u64,
    vertices: usize,
    batches: usize,
    headers: usize,
    replayed_commits: usize,
}

/// The history a joining validator starts with.
#[derive(Clone, Debug)]
struct ColdStart {
    history: History,
    joined_at: usize,
}

/// What one validator ended with.
#[derive(Debug)]
struct NodeResult {
    index: usize,
    authored: usize,
    headers: usize,
    committed: Vec<CommittedSample>,
    certified: BTreeMap<u64, u64>,
    certified_ids: BTreeMap<u64, [u8; 32]>,
    order: Vec<validator::VertexId>,
    head_height: u64,
    head_round: u64,
    state_root: [u8; 32],
    applied: usize,
    rejected: usize,
    conflicts: usize,
    /// Submissions before this index were already committed before the node
    /// joined; they are replayed, not counted as live finality.
    joined_at: Option<usize>,
    catch_up: Option<CatchUpReport>,
}

/// Everything one run produced.
#[derive(Debug)]
struct Outcome {
    config: Config,
    chain_id: Vec<u8>,
    submissions: Vec<Submission>,
    results: Vec<NodeResult>,
    elapsed: Duration,
    finalized_on_submitter: usize,
    timed_out: bool,
    /// First round whose epoch belongs to the new set, when configured.
    change_round: Option<u64>,
}

/// A frame moving between validators.
#[derive(Clone)]
enum Inbound {
    /// A client submission, only sent to validator 0.
    Submit(Batch),
    /// A consensus vertex.
    Vertex(Vertex),
    /// The batch a vertex names.
    Payload(Batch),
    /// One validator's signature over one header.
    Share(Share),
}

/// A certificate share, with the header it signs.
#[derive(Clone)]
struct Share {
    header: Header,
    signer: usize,
    signature: Vec<u8>,
    /// Nanoseconds since the mesh started, on the sender's clock.
    at: u64,
}

struct Signed {
    signature: Vec<u8>,
    at: u64,
}

/// Signatures collected for one header.
struct ShareSet {
    header: Header,
    signatures: BTreeMap<usize, Signed>,
}

/// A committed prefix waiting for its batches to arrive before it can be signed.
struct PendingHeader {
    round: u64,
    order_len: usize,
    height: u64,
    state_root: Option<[u8; 32]>,
    applied: u64,
}

/// A header that has collected enough shares to be certified.
struct Candidate {
    header: Header,
    id: [u8; 32],
    signed: Vec<(usize, Vec<u8>, u64)>,
}

/// One validator's whole state, so the tick loop does not thread a dozen
/// mutable locals through every helper.
struct Validator {
    index: usize,
    node: Node,
    sets: SetSchedule,
    chain_id: Vec<u8>,
    private_key: Vec<u8>,
    accounts: Vec<chain::Account>,
    state: State,
    batches: HashMap<[u8; 32], Batch>,
    history: History,
    last_built_order: usize,
    replaying: bool,
    catch_up: Option<CatchUpReport>,
    joined_at: Option<usize>,
    rejected: BTreeMap<&'static str, usize>,
    pending_batches: VecDeque<Batch>,
    pending_headers: VecDeque<PendingHeader>,
    share_sets: HashMap<[u8; 32], ShareSet>,
    chain: HeaderChain,
    last_built: Header,
    next_height: u64,
    order_len: usize,
    applied_cursor: usize,
    applied: usize,
    committed: Vec<CommittedSample>,
    certified: BTreeMap<u64, u64>,
    certified_ids: BTreeMap<u64, [u8; 32]>,
    notified: HashSet<[u8; 32]>,
    conflicts: usize,
    headers: usize,
    senders: Arc<Vec<mpsc::UnboundedSender<Inbound>>>,
    finalized: Option<mpsc::UnboundedSender<(usize, [u8; 32])>>,
    ack: Option<mpsc::UnboundedSender<u64>>,
    sequence: AtomicU64,
    started: Instant,
    delay: Duration,
    jitter_ms: u64,
}

/// The parts of the mesh every validator shares.
#[derive(Clone)]
struct Context {
    committee: chain::Membership,
    sets: SetSchedule,
    chain_id: Vec<u8>,
    senders: Arc<Vec<mpsc::UnboundedSender<Inbound>>>,
    started: Instant,
    delay: Duration,
    jitter: Duration,
}

/// One validator task's inputs.
struct ValidatorTask {
    index: usize,
    context: Context,
    inbound: mpsc::UnboundedReceiver<Inbound>,
    finalized: Option<mpsc::UnboundedSender<(usize, [u8; 32])>>,
    ack: Option<mpsc::UnboundedSender<u64>>,
    shutdown: watch::Receiver<bool>,
    cold: Option<ColdStart>,
    history_req: Option<mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<History>>>,
    round_tx: Option<watch::Sender<u64>>,
}

impl Validator {
    fn new(
        index: usize,
        context: &Context,
        finalized: Option<mpsc::UnboundedSender<(usize, [u8; 32])>>,
        ack: Option<mpsc::UnboundedSender<u64>>,
    ) -> Result<Self, String> {
        let committee = &context.committee;
        let sets = context.sets.clone();
        let base = sets.base().clone();
        let identity = committee
            .consensus
            .get(index)
            .ok_or_else(|| format!("no consensus key for validator {index}"))?;
        let node = match sets.change_epoch() {
            Some(change_epoch) => Node::with_chain_id_epoch_and_set_change(
                base.clone(),
                sets.set_for_epoch(change_epoch).clone(),
                change_epoch,
                committee.epoch_rounds,
                identity.id.clone(),
                identity.private_key.clone(),
                context.chain_id.clone(),
            )
            .map_err(|error| error.to_string())?,
            None => Node::with_chain_id_and_epoch_length(
                base.clone(),
                committee.epoch_rounds,
                identity.id.clone(),
                identity.private_key.clone(),
                context.chain_id.clone(),
            ),
        };
        let accounts = committee.accounts.clone();
        let mut state = chain::genesis_state(&accounts).map_err(|error| error.to_string())?;
        for account in &accounts {
            state
                .credit(&account.address, BALANCE)
                .map_err(|error| error.to_string())?;
        }

        let epoch = node.dag().epoch_of(0);
        let genesis = Header::genesis(
            context.chain_id.clone(),
            epoch,
            state.state_root(),
            commit_root(&[]),
        );
        let chain = match sets.change_epoch() {
            Some(change_epoch) => HeaderChain::with_schedule_and_change(
                base,
                sets.set_for_epoch(change_epoch).clone(),
                change_epoch,
                genesis.clone(),
                node.dag().epoch_schedule(),
            )
            .map_err(|error| error.to_string())?,
            None => HeaderChain::with_schedule(base, genesis.clone(), node.dag().epoch_schedule()),
        };

        Ok(Self {
            index,
            node,
            sets,
            chain_id: context.chain_id.clone(),
            private_key: identity.private_key.clone(),
            accounts,
            state,
            batches: HashMap::new(),
            history: History::default(),
            last_built_order: 0,
            replaying: false,
            catch_up: None,
            joined_at: None,
            rejected: BTreeMap::new(),
            pending_batches: VecDeque::new(),
            pending_headers: VecDeque::new(),
            share_sets: HashMap::new(),
            chain,
            last_built: genesis,
            next_height: 1,
            order_len: 0,
            applied_cursor: 0,
            applied: 0,
            committed: Vec::new(),
            certified: BTreeMap::new(),
            certified_ids: BTreeMap::new(),
            notified: HashSet::new(),
            conflicts: 0,
            headers: 0,
            senders: Arc::clone(&context.senders),
            finalized,
            ack,
            sequence: AtomicU64::new(0),
            started: context.started,
            delay: context.delay,
            jitter_ms: u64::try_from(context.jitter.as_millis()).unwrap_or(u64::MAX),
        })
    }

    fn now(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_nanos()).unwrap_or(u64::MAX)
    }

    fn round(&self) -> u64 {
        self.node.round()
    }

    fn history(&self) -> History {
        let mut history = self.history.clone();
        let order = self.node.dag().order();
        let prefix = order.len().min(self.last_built_order);
        history.order = order[..prefix].to_vec();
        history.last_built = Some(self.last_built.clone());
        history.cursor = self.last_built.round.saturating_add(1);
        history
    }

    /// Adopts the peer's committed prefix and state.
    ///
    /// The prefix is not re-decided: the history carries the exact commit order
    /// and the last header validator 0 built, so the joining validator starts
    /// from the same `dag_root` and state instead of deriving a possibly
    /// different order from a partially received DAG.
    fn catch_up(&mut self, cold: ColdStart) -> Result<(), String> {
        let started = Instant::now();
        let bytes = history_bytes(&cold.history)?;
        self.joined_at = Some(cold.joined_at);

        for vertex in cold.history.vertices.values() {
            self.node.receive(vertex.clone()).map_err(|error| {
                format!(
                    "validator {} cannot replay a vertex at round {}: {error}",
                    self.index, vertex.round
                )
            })?;
            self.history
                .vertices
                .insert((vertex.round, vertex.author.clone()), vertex.clone());
        }
        for (digest, batch) in &cold.history.batches {
            self.history.batches.insert(*digest, batch.clone());
            self.batches.insert(*digest, batch.clone());
        }

        let Some(last_built) = cold.history.last_built.clone() else {
            return Err(format!(
                "validator {} received no trusted header to join from",
                self.index
            ));
        };

        self.node.seed_order(cold.history.order.clone());
        self.order_len = cold.history.order.len();
        self.applied_cursor = 0;
        self.apply();
        if self.applied_cursor != self.order_len {
            return Err(format!(
                "validator {} replayed {} of {} committed entries",
                self.index, self.applied_cursor, self.order_len
            ));
        }
        if commit_root(&cold.history.order) != last_built.dag_root {
            return Err(format!(
                "validator {} rebuilt a different dag_root for {} commits",
                self.index, self.order_len
            ));
        }
        if self.state.state_root() != last_built.state_root {
            return Err(format!(
                "validator {} rebuilt a different state at the trusted header",
                self.index
            ));
        }
        if u64::try_from(self.applied).unwrap_or(u64::MAX) != last_built.applied {
            return Err(format!(
                "validator {} applied {} transactions but the trusted header says {}",
                self.index, self.applied, last_built.applied
            ));
        }

        for (height, (header, certificate)) in &cold.history.headers {
            self.chain.advance(header, certificate).map_err(|error| {
                format!(
                    "validator {} cannot verify the certified header at height {height}: {error}",
                    self.index
                )
            })?;
            self.certified.insert(*height, 0);
            self.certified_ids
                .insert(*height, header.id().map_err(|error| error.to_string())?);
        }

        self.last_built = last_built;
        self.last_built_order = self.order_len;
        self.next_height = self.last_built.height + 1;
        self.applied_cursor = self.order_len;
        self.node.set_cursor(cold.history.cursor);

        self.committed.clear();
        self.notified.clear();

        let rounds = cold
            .history
            .vertices
            .keys()
            .map(|(round, _)| *round)
            .max()
            .unwrap_or(0);
        self.catch_up = Some(CatchUpReport {
            elapsed_ns: u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX),
            bytes,
            rounds,
            vertices: cold.history.vertices.len(),
            batches: cold.history.batches.len(),
            headers: cold.history.headers.len(),
            replayed_commits: self.order_len,
        });
        Ok(())
    }

    /// One-way delay for this link and frame, so the run has a stable topology
    /// even though task scheduling is not deterministic.
    fn delay_for(&self, to: usize, sequence: u64) -> Duration {
        let jitter = if self.jitter_ms == 0 {
            0
        } else {
            let mut hash = u64::try_from(self.index)
                .unwrap_or(0)
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                ^ u64::try_from(to)
                    .unwrap_or(0)
                    .wrapping_mul(0xC2B2_AE3D_27D4_EB4F)
                ^ sequence.wrapping_mul(0x1656_67B1_9E37_79F9);
            hash ^= hash >> 33;
            hash = hash.wrapping_mul(0xFF51_AFD7_ED55_8CCD);
            hash ^= hash >> 33;
            hash % (self.jitter_ms + 1)
        };
        self.delay + Duration::from_millis(jitter)
    }

    fn broadcast(&self, message: Inbound) {
        let sequence = self.sequence.fetch_add(1, Ordering::Relaxed);
        for (to, sender) in self.senders.iter().enumerate() {
            if to == self.index {
                continue;
            }
            let delay = self.delay_for(to, sequence);
            let message = message.clone();
            let sender = sender.clone();
            tokio::spawn(async move {
                tokio::time::sleep(delay).await;
                let _ = sender.send(message);
            });
        }
    }

    fn receive(&mut self, frame: Inbound) -> Result<(), String> {
        match frame {
            Inbound::Submit(batch) => {
                if let Ok(digest) = batch.digest() {
                    self.history.batches.insert(digest, batch.clone());
                }
                self.pending_batches.push_back(batch);
            }
            Inbound::Vertex(vertex) => {
                let key = (vertex.round, vertex.author.clone());
                if self.node.receive(vertex.clone()).is_err() {
                    // A controlled mesh has no bad signatures; a rejection is a
                    // frame from a node this validator is not supposed to reject.
                    return Err(format!("validator {} refused a vertex", self.index));
                }
                self.history.vertices.insert(key, vertex);
            }
            Inbound::Payload(batch) => {
                if let Ok(digest) = batch.digest() {
                    self.history.batches.insert(digest, batch.clone());
                    self.batches.entry(digest).or_insert(batch);
                    self.apply();
                    self.build_ready_headers()?;
                }
            }
            Inbound::Share(share) => self.receive_share(share)?,
        }
        Ok(())
    }

    fn receive_share(&mut self, share: Share) -> Result<(), String> {
        if share.header.chain_id != self.chain_id {
            self.conflicts += 1;
            return Ok(());
        }
        if share.signer >= self.sets.set_for_epoch(share.header.epoch).validators.len() {
            self.conflicts += 1;
            return Ok(());
        }
        if share.header.height <= self.chain.head().height {
            return Ok(());
        }
        let id = share.header.id().map_err(|error| error.to_string())?;
        let entry = self.share_sets.entry(id).or_insert_with(|| ShareSet {
            header: share.header,
            signatures: BTreeMap::new(),
        });
        entry.signatures.entry(share.signer).or_insert(Signed {
            signature: share.signature,
            at: share.at,
        });
        self.advance_certified()
    }

    /// Advances the verified header chain for as long as a quorum certificate
    /// exists for the next height.
    fn advance_certified(&mut self) -> Result<(), String> {
        loop {
            let height = self.chain.head().height + 1;
            let previous = self.chain.head().id().map_err(|error| error.to_string())?;

            let mut candidate: Option<Candidate> = None;
            for (id, collected) in &self.share_sets {
                if collected.header.height != height || collected.header.previous != previous {
                    continue;
                }
                let quorum = self
                    .sets
                    .set_for_epoch(collected.header.epoch)
                    .quorum_size();
                if collected.signatures.len() < quorum {
                    continue;
                }
                // The certificate exists from the moment the earliest quorum of
                // shares exists, so take exactly that quorum and not every late
                // signature that happened to arrive before this scan.
                let mut signed: Vec<(usize, &Vec<u8>, u64)> = collected
                    .signatures
                    .iter()
                    .map(|(index, signed)| (*index, &signed.signature, signed.at))
                    .collect();
                signed.sort_by_key(|(_, _, at)| *at);
                signed.truncate(quorum);
                candidate = Some(Candidate {
                    header: collected.header.clone(),
                    id: *id,
                    signed: signed
                        .into_iter()
                        .map(|(index, signature, at)| (index, signature.clone(), at))
                        .collect(),
                });
                break;
            }
            let Some(Candidate {
                header,
                id,
                mut signed,
            }) = candidate
            else {
                break;
            };
            let at = signed.iter().map(|(_, _, at)| *at).max().unwrap_or(0);
            signed.sort_by_key(|(index, _, _)| *index);

            let set = self.sets.set_for_epoch(header.epoch);
            let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
            for (index, _, _) in &signed {
                set_bit(&mut bitmap, *index);
            }
            let certificate = Certificate {
                chain_id: header.chain_id.clone(),
                epoch: header.epoch,
                round: header.round,
                vertex_id: id.to_vec(),
                validator_set_id: VALIDATOR_SET_ID.to_vec(),
                signer_bitmap: bitmap,
                signatures: signed
                    .into_iter()
                    .map(|(_, signature, _)| signature)
                    .collect(),
            };
            certificate.verify_quorum(set).map_err(|error| {
                format!(
                    "validator {} cannot verify a certificate: {error}",
                    self.index
                )
            })?;
            self.chain.advance(&header, &certificate).map_err(|error| {
                format!(
                    "validator {} has a header that does not extend its chain: {error}",
                    self.index
                )
            })?;
            self.certified.insert(height, at);
            self.certified_ids.insert(height, id);
            self.history.headers.insert(height, (header, certificate));
            self.flush_finalized();
        }
        Ok(())
    }

    /// Tells the submitter which samples now have a certified header.
    fn flush_finalized(&mut self) {
        if self.replaying {
            return;
        }
        let Some(sender) = &self.finalized else {
            return;
        };
        for sample in &self.committed {
            if self.notified.contains(&sample.digest) {
                continue;
            }
            if self.certified.contains_key(&sample.header_height) {
                self.notified.insert(sample.digest);
                let _ = sender.send((self.index, sample.digest));
            }
        }
    }

    fn author(&mut self) -> Result<(), String> {
        if self.index == 0
            && let Some(batch) = self.pending_batches.pop_front()
        {
            let digest = batch.digest().map_err(|error| error.to_string())?;
            match self.node.author_with(digest) {
                Ok(Some(vertex)) => {
                    self.batches.insert(digest, batch.clone());
                    self.history
                        .vertices
                        .insert((vertex.round, vertex.author.clone()), vertex.clone());
                    self.broadcast(Inbound::Vertex(vertex.clone()));
                    self.broadcast(Inbound::Payload(batch));
                    if let Some(ack) = &self.ack {
                        let _ = ack.send(vertex.round);
                    }
                }
                Ok(None) => self.pending_batches.push_front(batch),
                Err(error) => {
                    return Err(format!("validator {} cannot author: {error}", self.index));
                }
            }
            return Ok(());
        }

        match self.node.author_with([0u8; 32]) {
            Ok(Some(vertex)) => {
                self.history
                    .vertices
                    .insert((vertex.round, vertex.author.clone()), vertex.clone());
                self.broadcast(Inbound::Vertex(vertex));
            }
            Ok(None) => {}
            Err(error) => {
                return Err(format!("validator {} cannot author: {error}", self.index));
            }
        }
        Ok(())
    }

    /// Drains every decision the pacemaker can make right now, one header per
    /// commit.
    fn decide(&mut self) -> Result<bool, String> {
        let mut progress = false;
        loop {
            match self.node.commit_once() {
                Ok(Step::Advanced {
                    from,
                    commits,
                    anchors,
                    ..
                }) => {
                    progress = true;
                    if commits > 0 {
                        self.record_commit(from)?;
                    }
                    if anchors > 0 {
                        break;
                    }
                }
                Ok(Step::Waiting { .. } | Step::TimedOut { .. }) => break,
                Err(error) if error.kind() == CryptoErrorKind::MissingReference => break,
                Err(error) => {
                    return Err(format!("validator {} cannot decide: {error}", self.index));
                }
            }
        }
        Ok(progress)
    }

    fn record_commit(&mut self, round: u64) -> Result<(), String> {
        let at = self.now();
        let old = self.order_len;
        let new = self.node.dag().order().len();
        let height = self.next_height;
        self.next_height += 1;

        for id in &self.node.dag().order()[old..new] {
            let Some(vertex) = self.node.dag().get(id.round, &id.author) else {
                continue;
            };
            if vertex.payload_hash == [0u8; 32] {
                continue;
            }
            let leader = self.node.dag().leader_author(id.round) == Some(id.author.as_slice());
            self.committed.push(CommittedSample {
                digest: vertex.payload_hash,
                vertex_round: id.round,
                header_round: round,
                header_height: height,
                commit_ns: at,
                leader,
            });
        }

        self.order_len = new;
        self.pending_headers.push_back(PendingHeader {
            round,
            order_len: new,
            height,
            state_root: None,
            applied: 0,
        });
        self.flush_finalized();
        Ok(())
    }

    /// Applies committed batches in commit order, one entry at a time, so a
    /// header can capture the exact state at its own prefix boundary.
    fn apply(&mut self) {
        loop {
            let order = self.node.dag().order();
            if self.applied_cursor >= order.len() {
                break;
            }
            let id = &order[self.applied_cursor];
            let Some(vertex) = self.node.dag().get(id.round, &id.author) else {
                break;
            };
            if vertex.payload_hash != [0u8; 32] {
                let Some(batch) = self.batches.get(&vertex.payload_hash) else {
                    // Payload availability gates execution, not consensus. The
                    // commit was already recorded; the header waits.
                    break;
                };
                self.applied +=
                    chain::apply_batch(&mut self.state, &self.accounts, batch, &mut self.rejected);
            }
            self.applied_cursor += 1;

            for pending in &mut self.pending_headers {
                if pending.order_len == self.applied_cursor && pending.state_root.is_none() {
                    pending.state_root = Some(self.state.state_root());
                    pending.applied = u64::try_from(self.applied).unwrap_or(0);
                }
            }
        }
    }

    /// Signs every committed prefix whose batches are all here, in height order.
    fn build_ready_headers(&mut self) -> Result<(), String> {
        while self
            .pending_headers
            .front()
            .is_some_and(|pending| pending.state_root.is_some())
        {
            let pending = self
                .pending_headers
                .pop_front()
                .ok_or("pending header disappeared")?;
            let state_root = pending.state_root.ok_or("pending header lost its root")?;
            let epoch = self.node.dag().epoch_of(pending.round);
            let active = self
                .sets
                .set_for_epoch(epoch)
                .validators
                .iter()
                .any(|record| record.validator_id.as_slice() == self.node.id());
            let header = Header {
                chain_id: self.chain_id.clone(),
                epoch,
                height: pending.height,
                round: pending.round,
                state_root,
                dag_root: commit_root(&self.node.dag().order()[..pending.order_len]),
                previous: self.last_built.id().map_err(|error| error.to_string())?,
                applied: pending.applied,
            };
            let id = header.id().map_err(|error| error.to_string())?;

            if let Some(certified) = self.certified_ids.get(&pending.height)
                && *certified != id
            {
                self.conflicts += 1;
            }

            self.last_built = header.clone();
            self.headers += 1;
            self.last_built_order = pending.order_len;

            if self.replaying {
                continue;
            }

            if active {
                let at = self.now();
                let payload = signing_payload(&header).map_err(|error| error.to_string())?;
                let signature = Ed25519Scheme
                    .sign(&self.private_key, &payload)
                    .map_err(|error| error.to_string())?;
                let entry = self.share_sets.entry(id).or_insert_with(|| ShareSet {
                    header: header.clone(),
                    signatures: BTreeMap::new(),
                });
                entry.signatures.entry(self.index).or_insert(Signed {
                    signature: signature.clone(),
                    at,
                });

                self.broadcast(Inbound::Share(Share {
                    header,
                    signer: self.index,
                    signature,
                    at,
                }));
                self.advance_certified()?;
            }
        }
        Ok(())
    }

    fn tick(&mut self) -> Result<(), String> {
        self.author()?;
        self.decide()?;
        self.apply();
        self.build_ready_headers()
    }

    fn finish(self) -> NodeResult {
        NodeResult {
            index: self.index,
            authored: self.node.authored(),
            headers: self.headers,
            committed: self.committed,
            certified: self.certified,
            certified_ids: self.certified_ids,
            head_height: self.chain.head().height,
            head_round: self.chain.head().round,
            order: self.node.dag().order().to_vec(),
            state_root: self.state.state_root(),
            applied: self.applied,
            rejected: self.rejected.values().sum(),
            conflicts: self.conflicts,
            joined_at: self.joined_at,
            catch_up: self.catch_up,
        }
    }
}

fn history_bytes(history: &History) -> Result<u64, String> {
    let mut bytes = 0u64;
    for vertex in history.vertices.values() {
        bytes = bytes.saturating_add(
            u64::try_from(vertex.encode().map_err(|error| error.to_string())?.len())
                .unwrap_or(u64::MAX),
        );
    }
    for batch in history.batches.values() {
        bytes = bytes.saturating_add(
            u64::try_from(batch.encode().map_err(|error| error.to_string())?.len())
                .unwrap_or(u64::MAX),
        );
    }
    for (header, certificate) in history.headers.values() {
        bytes = bytes.saturating_add(
            u64::try_from(header.encode().map_err(|error| error.to_string())?.len())
                .unwrap_or(u64::MAX),
        );
        bytes = bytes.saturating_add(
            u64::try_from(
                certificate
                    .encode()
                    .map_err(|error| error.to_string())?
                    .len(),
            )
            .unwrap_or(u64::MAX),
        );
    }
    for id in &history.order {
        bytes = bytes
            .saturating_add(8)
            .saturating_add(u64::try_from(id.author.len()).unwrap_or(u64::MAX))
            .saturating_add(32);
    }
    if let Some(header) = &history.last_built {
        bytes = bytes.saturating_add(
            u64::try_from(header.encode().map_err(|error| error.to_string())?.len())
                .unwrap_or(u64::MAX),
        );
    }
    bytes = bytes.saturating_add(8);
    Ok(bytes)
}

/// The bytes a certificate share signs. The bitmap and signatures are not part
/// of it, so the same payload covers every signer.
fn signing_payload(header: &Header) -> Result<Vec<u8>, crypto::CryptoError> {
    Certificate {
        chain_id: header.chain_id.clone(),
        epoch: header.epoch,
        round: header.round,
        vertex_id: header.id()?.to_vec(),
        validator_set_id: VALIDATOR_SET_ID.to_vec(),
        signer_bitmap: Vec::new(),
        signatures: Vec::new(),
    }
    .signing_payload()
}

async fn validator_task(task: ValidatorTask) -> Result<NodeResult, String> {
    let ValidatorTask {
        index,
        context,
        mut inbound,
        finalized,
        ack,
        mut shutdown,
        cold,
        mut history_req,
        round_tx,
    } = task;
    let mut validator = Validator::new(index, &context, finalized, ack)?;
    if let Some(mut cold) = cold {
        // The history is a snapshot from validator 0, but this node's inbound
        // queue has been collecting every broadcast since round 0. Drain what
        // has already arrived before replaying, so a vertex that was still in
        // flight when the snapshot was taken is not a hole in the replay. The
        // shares are kept and applied after the prefix is adopted, because they
        // are what advances the header chain to the snapshot height.
        let mut queued_shares = Vec::new();
        while let Ok(frame) = inbound.try_recv() {
            match frame {
                Inbound::Vertex(vertex) => {
                    cold.history
                        .vertices
                        .insert((vertex.round, vertex.author.clone()), vertex);
                }
                Inbound::Payload(batch) => {
                    if let Ok(digest) = batch.digest() {
                        cold.history.batches.insert(digest, batch);
                    }
                }
                Inbound::Share(share) => queued_shares.push(share),
                Inbound::Submit(_) => {}
            }
        }
        validator.catch_up(cold)?;
        for share in queued_shares {
            validator.receive_share(share)?;
        }
    }
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            frame = inbound.recv() => {
                let Some(frame) = frame else { break };
                validator.receive(frame)?;
            }
            _ = ticker.tick() => {
                validator.tick()?;
                if let Some(tx) = &round_tx {
                    let _ = tx.send(validator.round());
                }
            }
            request = recv_history(&mut history_req) => {
                if let Some(reply) = request {
                    let _ = reply.send(validator.history());
                }
            }
            _ = shutdown.changed() => break,
        }
    }
    Ok(validator.finish())
}

async fn recv_history(
    request: &mut Option<mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<History>>>,
) -> Option<tokio::sync::oneshot::Sender<History>> {
    match request {
        Some(receiver) => receiver.recv().await,
        None => std::future::pending().await,
    }
}

async fn client_task(
    config: Config,
    committee: chain::Membership,
    chain_id: Vec<u8>,
    started: Instant,
    submit: mpsc::UnboundedSender<Inbound>,
    mut ack: mpsc::UnboundedReceiver<u64>,
    submissions: Arc<Mutex<Vec<Submission>>>,
) -> Result<(), String> {
    for index in 0..config.samples {
        if index > 0 {
            ack.recv()
                .await
                .ok_or("validator 0 stopped before acknowledging the previous batch")?;
        }
        let round = u64::try_from(index).unwrap_or(u64::MAX);
        let batch = chain::demo_batch(&chain_id, &committee.accounts, 0, round, config.txs)
            .map_err(|error| error.to_string())?;
        let digest = batch.digest().map_err(|error| error.to_string())?;
        let at = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
        submissions
            .lock()
            .map_err(|_| "submission clock is poisoned")?
            .push(Submission { digest, at });
        submit
            .send(Inbound::Submit(batch))
            .map_err(|_| "validator 0 stopped accepting submissions")?;
    }
    // The last batch must be authored too, even though its certificate is what
    // the driver waits for.
    ack.recv()
        .await
        .ok_or("validator 0 stopped before acknowledging the last batch")?;
    Ok(())
}

fn change_round(config: &Config, committee: &chain::Membership) -> Option<u64> {
    config.change.map(|(_, epoch)| {
        epoch
            .saturating_sub(committee.set.epoch)
            .saturating_mul(committee.epoch_rounds)
    })
}

async fn run_mesh(
    config: Config,
    committee: chain::Membership,
    sets: SetSchedule,
    chain_id: Vec<u8>,
    started: Instant,
) -> Result<Outcome, String> {
    let mesh = sets.mesh_size();
    let mut senders = Vec::with_capacity(mesh);
    let mut receivers = Vec::with_capacity(mesh);
    for _ in 0..mesh {
        let (sender, receiver) = mpsc::unbounded_channel();
        senders.push(sender);
        receivers.push(receiver);
    }
    let senders = Arc::new(senders);
    let submit_sender = senders
        .first()
        .cloned()
        .ok_or("a finality run needs at least one validator")?;
    let (ack_tx, ack_rx) = mpsc::unbounded_channel();
    let (final_tx, mut final_rx) = mpsc::unbounded_channel();
    let submissions = Arc::new(Mutex::new(Vec::new()));
    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let mut tasks = Vec::with_capacity(mesh);
    let mut receivers = receivers.into_iter();
    let context = Context {
        committee: committee.clone(),
        sets: sets.clone(),
        chain_id: chain_id.clone(),
        senders: Arc::clone(&senders),
        started,
        delay: config.delay,
        jitter: config.jitter,
    };
    let cold_index = if config.cold_join {
        Some(mesh - 1)
    } else {
        None
    };
    let join_round = change_round(&config, &committee);
    if cold_index.is_some() && join_round.is_none() {
        return Err("--cold-join requires a set change".into());
    }
    let (history_tx, history_rx) = mpsc::unbounded_channel::<oneshot::Sender<History>>();
    let mut history_rx = Some(history_rx);
    let (round_tx, mut round_rx) = watch::channel(0u64);
    let mut cold_inbound: Option<mpsc::UnboundedReceiver<Inbound>> = None;

    for index in 0..mesh {
        let inbound = receivers
            .next()
            .ok_or("fewer inbound channels than validators")?;
        let shutdown = shutdown_rx.clone();
        let is_submitter = index == 0;
        let finalized = Some(final_tx.clone());
        let ack = is_submitter.then(|| ack_tx.clone());
        if cold_index == Some(index) {
            cold_inbound = Some(inbound);
            continue;
        }
        tasks.push(tokio::spawn(validator_task(ValidatorTask {
            index,
            context: context.clone(),
            inbound,
            finalized,
            ack,
            shutdown,
            cold: None,
            history_req: if is_submitter {
                history_rx.take()
            } else {
                None
            },
            round_tx: is_submitter.then(|| round_tx.clone()),
        })));
    }
    if cold_index.is_some() && cold_inbound.is_none() {
        return Err("no inbound channel for the cold validator".into());
    }
    let client = tokio::spawn(client_task(
        config.clone(),
        committee.clone(),
        chain_id.clone(),
        started,
        submit_sender,
        ack_rx,
        Arc::clone(&submissions),
    ));

    let mut finalized: Vec<HashSet<[u8; 32]>> = vec![HashSet::new(); mesh];
    let mut required = vec![config.samples; mesh];
    let deadline = tokio::time::sleep(config.timeout);
    tokio::pin!(deadline);
    let mut timed_out = false;
    let mut cold_started = cold_index.is_none();
    loop {
        tokio::select! {
            Some((index, digest)) = final_rx.recv() => {
                if let Some(set) = finalized.get_mut(index) {
                    set.insert(digest);
                }
                if finalized
                    .iter()
                    .enumerate()
                    .all(|(index, set)| set.len() >= required[index])
                {
                    break;
                }
            }
            _ = round_rx.changed(), if !cold_started => {
                let round = *round_rx.borrow();
                if round >= join_round.unwrap_or(u64::MAX) {
                    let (reply_tx, reply_rx) = oneshot::channel();
                    history_tx
                        .send(reply_tx)
                        .map_err(|_| "validator 0 stopped before serving history")?;
                    let history = reply_rx
                        .await
                        .map_err(|_| "validator 0 did not return a history")?;
                    let joined_at = submissions
                        .lock()
                        .map_err(|_| "submission clock is poisoned")?
                        .len();
                    let cold = cold_index.ok_or("cold index disappeared")?;
                    required[cold] = config.samples.saturating_sub(joined_at).max(1);
                    let inbound = cold_inbound
                        .take()
                        .ok_or("cold inbound channel disappeared")?;
                    tasks.push(tokio::spawn(validator_task(ValidatorTask {
                        index: cold,
                        context: context.clone(),
                        inbound,
                        finalized: Some(final_tx.clone()),
                        ack: None,
                        shutdown: shutdown_rx.clone(),
                        cold: Some(ColdStart { history, joined_at }),
                        history_req: None,
                        round_tx: None,
                    })));
                    cold_started = true;
                }
            }
            _ = &mut deadline => {
                timed_out = true;
                break;
            }
        }
    }
    if cold_index.is_some() && !cold_started {
        return Err("the mesh did not reach the cold-join round".into());
    }

    if !timed_out {
        tokio::time::sleep(DRAIN + config.delay.saturating_mul(2)).await;
    }
    let _ = shutdown_tx.send(true);

    // A timed-out client is blocked waiting for an acknowledgement that the
    // shutdown just made impossible. Its error is the timeout's consequence, not
    // a second finding, so it is only propagated when the run itself completed.
    let client = tokio::time::timeout(Duration::from_secs(5), client).await;
    if !timed_out {
        match client {
            Ok(Ok(result)) => result.map_err(|error| format!("client task failed: {error}"))?,
            Ok(Err(error)) => return Err(format!("client task failed: {error}")),
            Err(_) => return Err("client did not stop within five seconds".into()),
        }
    }

    let mut results = Vec::with_capacity(tasks.len());
    for task in tasks {
        match task.await {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(error)) => return Err(error),
            Err(error) => return Err(format!("validator task failed: {error}")),
        }
    }
    results.sort_by_key(|result| result.index);
    if results.is_empty() {
        return Err("no validator reported a result".into());
    }

    let submissions = submissions
        .lock()
        .map_err(|_| "submission clock is poisoned")?
        .drain(..)
        .collect();

    let change_round_at = change_round(&config, &committee);

    Ok(Outcome {
        config,
        chain_id,
        submissions,
        results,
        elapsed: started.elapsed(),
        finalized_on_submitter: finalized.first().map_or(0, HashSet::len),
        timed_out,
        change_round: change_round_at,
    })
}

/// Runs a finality measurement and prints it.
///
/// # Errors
///
/// A membership that does not build, a run that times out before every sample is
/// certified, or validators that disagree on the committed order, the state, or
/// the certified headers.
pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let outcome = measure(config)?;
    print(&outcome)?;
    Ok(())
}

fn measure(config: Config) -> Result<Outcome, Box<dyn Error>> {
    if config.validators < 4 {
        return Err("--validators must be at least 4 so that a quorum is not everyone".into());
    }
    if config.samples == 0 {
        return Err("--samples must be at least 1".into());
    }
    if config.txs == 0 {
        return Err(
            "--txs must be at least 1: a batch with no transactions has no lifecycle".into(),
        );
    }
    if config.cold_join && !matches!(config.change, Some((SetChange::Add, _))) {
        return Err("--cold-join requires --add-validator-at-epoch".into());
    }
    if config.cold_join && config.epoch_rounds.is_none() {
        return Err(
            "--cold-join requires --epoch-rounds so the boundary falls inside the run".into(),
        );
    }

    let home = config
        .home
        .clone()
        .map(|path| crate::home::Home::resolve(Some(path)))
        .transpose()?;
    let mesh = match config.change {
        Some((SetChange::Add, _)) => config.validators + 1,
        Some((SetChange::Remove, _)) | None => config.validators,
    };
    let mut committee = chain::membership(mesh, home.as_ref())?;
    if let Some(rounds) = config.epoch_rounds {
        committee.epoch_rounds = rounds;
    }
    let base_epoch = committee.set.epoch;
    let sets = match config.change {
        None => SetSchedule::single(committee.set.clone()),
        Some((kind, change_epoch)) => {
            let (old_set, new_set) = match kind {
                SetChange::Add => {
                    let mut old = committee.set.clone();
                    old.validators.truncate(config.validators);
                    old.epoch = base_epoch;
                    let mut new = committee.set.clone();
                    new.epoch = change_epoch;
                    (old, new)
                }
                SetChange::Remove => {
                    let mut old = committee.set.clone();
                    old.epoch = base_epoch;
                    let mut new = committee.set.clone();
                    new.validators.truncate(config.validators - 1);
                    new.epoch = change_epoch;
                    (old, new)
                }
            };
            SetSchedule::with_change(old_set, change_epoch, new_set)?
        }
    };
    let chain_id = match &home {
        Some(home) => chain::chain_id(Some(home))?,
        None => chain::demo_chain_id(),
    };
    if config.cold_join {
        let join = change_round(&config, &committee).ok_or("--cold-join requires a set change")?;
        if join >= u64::try_from(config.samples).unwrap_or(u64::MAX) {
            return Err("--cold-join boundary falls after the last sample".into());
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let started = Instant::now();
    let outcome = runtime.block_on(run_mesh(config, committee, sets, chain_id, started))?;
    Ok(outcome)
}

/// One sample after all nodes are merged: the earliest commit, the earliest
/// certificate, and the protocol-level round distance.
struct Finalized {
    submit_ns: u64,
    commit_ns: u64,
    cert_ns: u64,
    vertex_round: u64,
    header_round: u64,
    /// Commit time reported by the validator whose certificate was the first one.
    cert_commit_ns: u64,
    rounds: u64,
    leader: bool,
}

fn merge(outcome: &Outcome) -> (Vec<Finalized>, usize) {
    let mut finalized = Vec::new();
    let mut incomplete = 0usize;
    for (index, submission) in outcome.submissions.iter().enumerate() {
        let mut commit = u64::MAX;
        let mut cert = u64::MAX;
        let mut cert_commit = u64::MAX;
        let mut header_round = None;
        let mut vertex_round = None;
        let mut leader = false;
        let mut complete = true;

        for result in &outcome.results {
            if result.joined_at.is_some_and(|joined| index < joined) {
                continue;
            }
            let Some(sample) = result
                .committed
                .iter()
                .find(|sample| sample.digest == submission.digest)
            else {
                complete = false;
                continue;
            };
            commit = commit.min(sample.commit_ns);
            match result.certified.get(&sample.header_height) {
                Some(at) if *at < cert => {
                    cert = *at;
                    cert_commit = sample.commit_ns;
                }
                Some(_) => {}
                None => complete = false,
            }
            match (header_round, vertex_round) {
                (None, None) => {
                    header_round = Some(sample.header_round);
                    vertex_round = Some(sample.vertex_round);
                }
                (Some(header), Some(vertex))
                    if header == sample.header_round && vertex == sample.vertex_round => {}
                _ => {
                    // Two nodes credited the same batch to different prefixes.
                    // Reporting a percentile over that would hide a bug.
                    complete = false;
                }
            }
            leader = sample.leader;
        }

        if commit == u64::MAX || cert == u64::MAX || !complete {
            incomplete += 1;
            continue;
        }
        let (Some(header), Some(vertex)) = (header_round, vertex_round) else {
            incomplete += 1;
            continue;
        };
        finalized.push(Finalized {
            submit_ns: submission.at,
            commit_ns: commit,
            cert_ns: cert,
            vertex_round: vertex,
            header_round: header,
            cert_commit_ns: cert_commit,
            // The vote round is the one after the decided round: a decision at
            // `q` exists because round `q + 1` voted for its leader.
            rounds: (header + 1).saturating_sub(vertex),
            leader,
        });
    }
    (finalized, incomplete)
}

fn print(outcome: &Outcome) -> Result<(), Box<dyn Error>> {
    let (finalized, incomplete) = merge(outcome);
    let mut commit: Vec<u64> = finalized
        .iter()
        .map(|s| s.commit_ns - s.submit_ns)
        .collect();
    let mut cert: Vec<u64> = finalized.iter().map(|s| s.cert_ns - s.submit_ns).collect();
    let mut overhead: Vec<u64> = finalized
        .iter()
        .map(|s| s.cert_ns.saturating_sub(s.cert_commit_ns))
        .collect();
    let mut rounds: Vec<u64> = finalized.iter().map(|s| s.rounds).collect();
    commit.sort_unstable();
    cert.sort_unstable();
    overhead.sort_unstable();
    rounds.sort_unstable();

    let mut leader: Vec<u64> = finalized
        .iter()
        .filter(|sample| sample.leader)
        .map(|sample| sample.rounds)
        .collect();
    let mut non_leader: Vec<u64> = finalized
        .iter()
        .filter(|sample| !sample.leader)
        .map(|sample| sample.rounds)
        .collect();
    leader.sort_unstable();
    non_leader.sort_unstable();

    let chain = &outcome.results[0];
    // Nodes keep authoring while the mesh is alive, so the head of each order is
    // a shutdown artifact, not a disagreement. What must match is the prefix they
    // all had time to commit.
    let common_order = outcome
        .results
        .iter()
        .map(|result| result.order.len())
        .min()
        .unwrap_or(0);
    let reference = &outcome.results[0].order[..common_order];
    let agreed_order = outcome
        .results
        .iter()
        .all(|result| &result.order[..common_order] == reference);
    let agreed_state = outcome
        .results
        .iter()
        .all(|result| result.state_root == chain.state_root);
    let common: Vec<u64> = outcome.results[0]
        .certified_ids
        .keys()
        .filter(|height| {
            outcome
                .results
                .iter()
                .all(|result| result.certified_ids.contains_key(height))
        })
        .copied()
        .collect();
    let agreed_headers = common.iter().all(|height| {
        let first = outcome.results[0].certified_ids.get(height);
        outcome
            .results
            .iter()
            .all(|result| result.certified_ids.get(height) == first)
    });
    let conflicts: usize = outcome.results.iter().map(|result| result.conflicts).sum();

    println!("== Karsa finality: client submit to certified header ==");
    println!(
        "  chain {}: the same genesis the vertices and certificates sign",
        hex::encode(&outcome.chain_id[..outcome.chain_id.len().min(8)])
    );
    println!(
        "  {} validators, one-way delay {} (+0..={} ms jitter), tick floor {}",
        outcome.config.validators,
        millis(u64::try_from(outcome.config.delay.as_nanos()).unwrap_or(u64::MAX)),
        outcome.config.jitter.as_millis(),
        millis(u64::try_from(TICK.as_nanos()).unwrap_or(u64::MAX)),
    );
    if let Some((kind, epoch)) = outcome.config.change {
        let (verb, new_size) = match kind {
            SetChange::Add => ("add", outcome.config.validators + 1),
            SetChange::Remove => ("remove", outcome.config.validators - 1),
        };
        println!(
            "  set change: {verb} one validator at epoch {epoch} ({} -> {new_size} validators)",
            outcome.config.validators
        );
    }
    println!(
        "  {} submissions, {} transaction{} per batch, closed loop: the next submit waits for \
         the previous authoring",
        outcome.config.samples,
        outcome.config.txs,
        if outcome.config.txs == 1 { "" } else { "s" }
    );
    println!(
        "  wall clock: {}",
        millis(u64::try_from(outcome.elapsed.as_nanos()).unwrap_or(u64::MAX))
    );
    println!();

    println!(
        "  {}  {}  {}  {}  {}  {}  {}  {}",
        left("node", 7),
        pad("authored", 9),
        pad("headers", 8),
        pad("certified", 10),
        pad("applied", 8),
        pad("rejected", 9),
        pad("head", 12),
        pad("conflicts", 10)
    );
    for result in &outcome.results {
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}",
            left(&format!("val-{}", result.index), 7),
            pad(&result.authored.to_string(), 9),
            pad(&result.headers.to_string(), 8),
            pad(&result.certified.len().to_string(), 10),
            pad(&result.applied.to_string(), 8),
            pad(&result.rejected.to_string(), 9),
            pad(&format!("{}/{}", result.head_height, result.head_round), 12),
            pad(&result.conflicts.to_string(), 10),
        );
    }

    if let Some(result) = outcome
        .results
        .iter()
        .find(|result| result.catch_up.is_some())
        && let Some(report) = &result.catch_up
    {
        let joined = result.joined_at.unwrap_or(0);
        let live_required = outcome.config.samples.saturating_sub(joined);
        println!();
        println!(
            "  cold join                val-{} replayed {} vertices, {} batches, {} headers \
             in {} ({} bytes, {} commits, {} rounds)",
            result.index,
            report.vertices,
            report.batches,
            report.headers,
            millis(report.elapsed_ns),
            report.bytes,
            report.replayed_commits,
            report.rounds
        );
        println!(
            "                           live from sample {joined}; finalized {} of {live_required} \
             live samples, authored {} vertices",
            result.committed.len(),
            result.authored
        );
    }

    println!();
    println!(
        "  submit -> commit       p50 {}  p95 {}  p99 {}  max {}  ({} samples)",
        millis(percentile(&commit, 50)),
        millis(percentile(&commit, 95)),
        millis(percentile(&commit, 99)),
        millis(percentile(&commit, 100)),
        commit.len()
    );
    println!(
        "  submit -> certificate  p50 {}  p95 {}  p99 {}  max {}",
        millis(percentile(&cert, 50)),
        millis(percentile(&cert, 95)),
        millis(percentile(&cert, 99)),
        millis(percentile(&cert, 100))
    );
    if let Some(change_round) = outcome.change_round {
        println!("  set change at round {change_round}:");
        let groups = [
            (
                "before",
                finalized
                    .iter()
                    .filter(|sample| sample.header_round < change_round)
                    .collect::<Vec<_>>(),
            ),
            (
                "boundary",
                finalized
                    .iter()
                    .filter(|sample| {
                        sample.header_round >= change_round && sample.vertex_round < change_round
                    })
                    .collect::<Vec<_>>(),
            ),
            (
                "after",
                finalized
                    .iter()
                    .filter(|sample| sample.vertex_round >= change_round)
                    .collect::<Vec<_>>(),
            ),
        ];
        for (label, group) in groups {
            if group.is_empty() {
                continue;
            }
            let mut cert: Vec<u64> = group
                .iter()
                .map(|sample| sample.cert_ns - sample.submit_ns)
                .collect();
            cert.sort_unstable();
            println!(
                "    {label:<8} {:>3} samples  submit -> certificate p50 {}  p95 {}  p99 {}",
                group.len(),
                millis(percentile(&cert, 50)),
                millis(percentile(&cert, 95)),
                millis(percentile(&cert, 99))
            );
        }
        println!();
    }
    println!(
        "  commit -> certificate  p50 {}  p95 {}  p99 {}  (at the node whose certificate \
         was first)",
        millis(percentile(&overhead, 50)),
        millis(percentile(&overhead, 95)),
        millis(percentile(&overhead, 99))
    );
    println!(
        "  rounds to finality     p50 {}  p95 {}  p99 {}  max {}  (vertex round to vote round)",
        percentile(&rounds, 50),
        percentile(&rounds, 95),
        percentile(&rounds, 99),
        percentile(&rounds, 100)
    );
    if !leader.is_empty() {
        println!(
            "    leader vertex        {} samples, rounds p50 {} p95 {} p99 {} max {}",
            leader.len(),
            percentile(&leader, 50),
            percentile(&leader, 95),
            percentile(&leader, 99),
            percentile(&leader, 100)
        );
    }
    if !non_leader.is_empty() {
        println!(
            "    non-leader vertex    {} samples, rounds p50 {} p95 {} p99 {} max {}",
            non_leader.len(),
            percentile(&non_leader, 50),
            percentile(&non_leader, 95),
            percentile(&non_leader, 99),
            percentile(&non_leader, 100)
        );
    }

    let summary_scope = if outcome
        .results
        .iter()
        .any(|result| result.catch_up.is_some())
    {
        "every live node"
    } else {
        "every node"
    };
    println!();
    println!(
        "  samples                 {} of {} finalized on {}{}",
        finalized.len(),
        outcome.config.samples,
        summary_scope,
        if incomplete > 0 {
            format!(", {incomplete} incomplete")
        } else {
            String::new()
        }
    );
    println!(
        "  certified on submitter  {} of {}",
        outcome.finalized_on_submitter, outcome.config.samples
    );
    println!(
        "  agreement               order {agreed_order} on the first {common_order} commits, \
         state {agreed_state}, headers {agreed_headers} on {} common heights, {conflicts} \
         conflicts (commit root {})",
        common.len(),
        hex::encode(&commit_root(reference)[..6])
    );

    println!();
    println!("  A header is the committed prefix at one pacemaker decision, signed by the");
    println!("  certificate keys over its id. The certificate is complete when the earliest");
    println!("  quorum of shares exists, which is why the overhead line is a separate");
    println!("  measurement from the commit line. The round figure is the protocol one:");
    println!("  it counts a vertex's round to the round whose votes decided its commit, so");
    println!("  it is the number to compare with another DAG-BFT design, not the delay.");

    if outcome.timed_out {
        return Err(format!(
            "timed out before every sample was certified ({} of {})",
            outcome.finalized_on_submitter, outcome.config.samples
        )
        .into());
    }
    if finalized.len() < outcome.config.samples {
        return Err(format!(
            "only {} of {} samples finalized on every node",
            finalized.len(),
            outcome.config.samples
        )
        .into());
    }
    if !agreed_order {
        return Err("validators did not commit the same order".into());
    }
    if !agreed_state {
        return Err("validators applied the same commits to different state".into());
    }
    if !agreed_headers {
        return Err("validators did not certify the same header chain".into());
    }
    if conflicts > 0 {
        return Err(format!("{conflicts} certificate conflicts across the mesh").into());
    }
    Ok(())
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    // Nearest-rank, so a small sample still reports its maximum at p100 and a
    // single slow outlier is visible at p99 instead of being truncated away.
    let rank = (percent * sorted.len()).div_ceil(100);
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

fn millis(nanos: u64) -> String {
    format!("{:.2} ms", nanos as f64 / 1e6)
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn left(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(samples: usize) -> Config {
        Config {
            validators: 4,
            samples,
            txs: 1,
            delay: Duration::ZERO,
            jitter: Duration::ZERO,
            timeout: Duration::from_secs(20),
            home: None,
            epoch_rounds: None,
            change: None,
            cold_join: false,
        }
    }

    #[test]
    fn a_small_run_certifies_every_sample_and_agrees() {
        let outcome = measure(config(4)).unwrap();
        let (finalized, incomplete) = merge(&outcome);

        assert_eq!(incomplete, 0, "every node must credit every sample");
        assert_eq!(finalized.len(), 4);
        assert_eq!(outcome.finalized_on_submitter, 4);
        assert!(
            finalized
                .iter()
                .all(|sample| (1..=5).contains(&sample.rounds)),
            "rounds to finality: {:?}",
            finalized
                .iter()
                .map(|sample| sample.rounds)
                .collect::<Vec<_>>()
        );
        assert!(
            outcome.results.iter().all(|result| {
                let common = outcome.results[0].order.len().min(result.order.len());
                result.order[..common] == outcome.results[0].order[..common]
            }),
            "the common commit prefix must be identical"
        );
        assert!(
            outcome
                .results
                .windows(2)
                .all(|pair| pair[0].state_root == pair[1].state_root)
        );
    }

    #[test]
    fn a_validator_join_at_an_epoch_boundary_finalizes() {
        let mut config = config(8);
        config.epoch_rounds = Some(4);
        config.change = Some((SetChange::Add, 2));
        let outcome = measure(config).unwrap();
        assert_eq!(outcome.results.len(), 5, "the mesh keeps the new set's key");

        let (finalized, incomplete) = merge(&outcome);
        assert_eq!(incomplete, 0, "every node must credit every sample");
        assert_eq!(finalized.len(), 8);
        assert_eq!(outcome.finalized_on_submitter, 8);
        assert!(
            outcome
                .results
                .windows(2)
                .all(|pair| pair[0].state_root == pair[1].state_root),
            "the old and new sets must end on the same state"
        );
        assert!(outcome.results.iter().all(|result| result.conflicts == 0));
        assert!(
            outcome.results[4].authored > 0,
            "the added validator must author after the boundary"
        );
    }

    #[test]
    fn a_cold_validator_catches_up_and_joins() {
        let mut config = config(12);
        config.epoch_rounds = Some(4);
        config.change = Some((SetChange::Add, 2));
        config.cold_join = true;
        let outcome = measure(config).unwrap();
        assert_eq!(outcome.results.len(), 5);

        let cold = &outcome.results[4];
        let report = cold
            .catch_up
            .as_ref()
            .expect("the cold validator must replay its history");
        assert!(report.bytes > 0, "the history must have a byte size");
        assert!(report.vertices > 0, "the history must contain vertices");
        assert!(report.batches > 0, "the history must contain batches");
        assert!(
            cold.authored > 0,
            "the cold validator must author after joining"
        );
        assert!(
            cold.joined_at.is_some(),
            "the cold join needs a sample floor"
        );
        assert_eq!(
            (cold.head_height, cold.applied, cold.order.len()),
            (
                outcome.results[0].head_height,
                outcome.results[0].applied,
                outcome.results[0].order.len()
            ),
            "the cold validator must reach the same committed prefix"
        );
        assert_eq!(
            cold.state_root, outcome.results[0].state_root,
            "the cold validator must replay to the same state"
        );
    }

    #[test]
    fn a_validator_removal_at_an_epoch_boundary_finalizes() {
        let mut config = config(4);
        config.validators = 5;
        config.epoch_rounds = Some(4);
        config.change = Some((SetChange::Remove, 2));
        let outcome = measure(config).unwrap();
        assert_eq!(outcome.results.len(), 5, "the removed node still receives");

        let (finalized, incomplete) = merge(&outcome);
        assert_eq!(incomplete, 0, "every node must credit every sample");
        assert_eq!(finalized.len(), 4);
        assert_eq!(outcome.finalized_on_submitter, 4);
        assert!(
            outcome
                .results
                .windows(2)
                .all(|pair| pair[0].state_root == pair[1].state_root),
            "the removed node must end on the same state"
        );
        assert!(outcome.results.iter().all(|result| result.conflicts == 0));
    }

    #[test]
    fn fewer_than_four_validators_is_refused() {
        let mut config = config(1);
        config.validators = 3;
        let error = measure(config).unwrap_err().to_string();
        assert!(error.contains("at least 4"), "{error}");
    }

    #[test]
    fn zero_samples_is_refused() {
        let error = measure(config(0)).unwrap_err().to_string();
        assert!(error.contains("--samples"), "{error}");
    }
}
