//! HTTP endpoints over a live validator's actual state.
//!
//! This is the client-facing half of `karsa live`: a transaction is submitted
//! here, included in a batch by the validator that owns the mempool, committed by
//! the DAG, executed into the account state, and finally covered by a certified
//! header. The endpoints report those stages from the node loop's own data rather
//! than a model:
//!
//! | endpoint | what it answers |
//! |---|---|
//! | `POST /tx` | decode, verify, and admit a signed envelope; rejects replay and bad signatures |
//! | `GET /tx/{id}` | which stage the transaction reached, and optionally a commit proof |
//! | `GET /account/{addr}` | balance and Merkle proof against the *certified* state root |
//! | `GET /status` | head, round, committed entries, applied transactions, peers, and skips by proof |
//!
//! # What is shared, and how
//!
//! The node loop and the HTTP handlers share one [`RpcCore`] behind a mutex. The
//! node loop writes at well-defined points (batch taken, batch applied, header
//! certified) and every handler only reads a snapshot it can name. No handler
//! waits on consensus, and the node loop never waits on the network while it
//! holds the lock.
//!
//! # Authenticity of the account endpoint
//!
//! A proof is only useful against the root it was built from, so `/account`
//! serves the state snapshot at the certified header's `applied` count. If the
//! node has applied further batches than that header covers, the snapshot is
//! still there; if it has been evicted, the endpoint fails closed with 409 rather
//! than returning a proof against a root the caller did not ask for.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::{Path, Query, State as AxumState};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use exec::State;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tx::address;
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::AuthPolicy;
use validator::{CommitFrontier, CommitProof, Header, SkipCounts, VertexId};

use crate::chain::{self, TxResult};

/// Most transactions one mempool batch may carry.
///
/// The protocol already bounds a batch at
/// [`tx::batch::MAX_BATCH_TRANSACTIONS`]; this is the default target used when
/// the operator does not ask for a smaller one.
pub(crate) const DEFAULT_BATCH_MAX: usize = 1024;

/// Bound on admitted but not yet executed transactions.
///
/// A client cannot make the node allocate without limit by submitting; once the
/// cap is reached the endpoint refuses with 429 and the mempool drains at the
/// node's own pace.
const MAX_MEMPOOL: usize = 100_000;

/// How many per-`applied` state snapshots are kept for `/account` proofs.
///
/// Certification lags execution by a few commits in a live run, so a small ring
/// covers the gap. An older header answers 409 instead of a proof whose root is
/// no longer held.
const MAX_SNAPSHOTS: usize = 256;

/// How many certified headers stay available for `/tx` commit proofs.
///
/// The order itself is held once, so this bound is only about headers and their
/// prefix lengths, not about copying a growing order per height.
const MAX_PROOF_CONTEXTS: usize = 64;

/// How long a transaction waits for the validator that owns it before any live
/// node may author it.
///
/// Ownership is what keeps every node from putting the same gossiped
/// transaction in its next batch. The fallback keeps the transaction live when
/// its owner is down; the rare second author is resolved by the sequence rule.
const OWNER_FALLBACK: Duration = Duration::from_secs(2);

/// The shared handle the node loop and the HTTP handlers use.
pub(crate) type SharedRpc = Arc<Mutex<RpcCore>>;

/// What one transaction reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stage {
    /// Admitted, waiting for the next batch.
    Mempool,
    /// Carried by an authored batch.
    Batched,
    /// Executed into state.
    Executed,
    /// Refused during execution; the reason is the same string the executor uses.
    Rejected(&'static str),
    /// Covered by a certified header.
    Finalized,
}

impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Mempool => "mempool",
            Self::Batched => "batched",
            Self::Executed => "executed",
            Self::Rejected(_) => "rejected",
            Self::Finalized => "finalized",
        }
    }
}

/// A commit proof captured when a transaction finalized.
///
/// The proof is built while the committed order is still retained. Keeping it on
/// the record is what lets `/tx/{id}?proof=1` answer after a checkpoint has pruned
/// the leaf out of the retained prefix.
#[derive(Debug, Clone)]
struct Witness {
    state_root: [u8; 32],
    dag_root: [u8; 32],
    proof: CommitProof,
}

/// One admitted transaction and what happened to it.
#[derive(Debug, Clone)]
struct TxRecord {
    sender: Vec<u8>,
    sequence: u64,
    batch: Option<[u8; 32]>,
    vertex: Option<VertexId>,
    outcome: Option<TxResult>,
    order_len_after: Option<usize>,
    finalized_height: Option<u64>,
    /// The proof saved at finality, before the order prefix could be pruned.
    witness: Option<Witness>,
}

impl TxRecord {
    fn stage(&self) -> Stage {
        match self.outcome {
            // A refusal is the transaction's outcome even after the batch carrying
            // it is covered by a certificate: saying "finalized" alone would hide
            // why the sequence never advanced.
            Some(TxResult::Rejected(reason)) => Stage::Rejected(reason),
            _ if self.finalized_height.is_some() => Stage::Finalized,
            Some(TxResult::Applied) => Stage::Executed,
            None if self.batch.is_some() => Stage::Batched,
            None => Stage::Mempool,
        }
    }
}

/// One pending transaction, in submission order.
struct PendingTx {
    id: [u8; 32],
    transaction: Transaction,
    /// When this copy entered the local mempool, for the owner fallback.
    queued_at: Instant,
}

/// The batch that was taken from the mempool, before it is executed.
struct BatchEntry {
    tx_ids: Vec<[u8; 32]>,
    vertex: Option<VertexId>,
}

/// The certified head a handler reports against.
#[derive(Debug, Clone, Copy)]
struct HeadView {
    height: u64,
    round: u64,
    state_root: [u8; 32],
    applied: u64,
    covered_order: Option<usize>,
    dag_root: [u8; 32],
}

/// A snapshot of the live loop, cheap enough to refresh every tick.
#[derive(Debug, Clone, Copy, Default)]
struct RunView {
    round: u64,
    committed_entries: usize,
    applied_txs: u64,
    peers: usize,
    conflicts: usize,
    skips: SkipCounts,
}

/// The mutex-protected state behind every endpoint.
pub(crate) struct RpcCore {
    node: usize,
    /// Number of validators that author batches, for the transaction-owner rule.
    committee: usize,
    chain_id: Vec<u8>,
    accounts: Vec<(Vec<u8>, AuthPolicy)>,
    mempool: VecDeque<PendingTx>,
    /// Transactions that passed submit, by content id.
    records: HashMap<[u8; 32], TxRecord>,
    /// Canonical envelopes submitted here, waiting for the node loop to gossip
    /// them to peers. A received envelope is not put back here, so gossip cannot
    /// loop between two nodes.
    gossip: Vec<Vec<u8>>,
    /// Batches this node authored from its own mempool, by digest.
    batches: HashMap<[u8; 32], BatchEntry>,
    /// Per-sender last applied sequence, from the execution state.
    state_sequences: HashMap<Vec<u8>, u64>,
    /// `(sender, sequence)` pairs already waiting, so one slot is not admitted twice.
    pending_sequences: HashSet<(Vec<u8>, u64)>,
    /// Executed batches in execution order, waiting for a certified prefix to cover them.
    pending_finality: VecDeque<(usize, Vec<[u8; 32]>)>,
    /// State at each cumulative applied transaction count.
    states: BTreeMap<u64, State>,
    /// The committed order this node has seen, above `order_prefix`.
    ///
    /// The DAG order is append-only, so the node loop extends this by the new
    /// suffix instead of copying it each tick; a proof over any certified prefix
    /// is then built on demand. Entries below the floor are summarized by peaks
    /// rather than held.
    order: Vec<VertexId>,
    /// Peaks of the committed order at or below the DAG floor.
    order_prefix: CommitFrontier,
    /// Number of committed entries before `order`.
    order_base: usize,
    /// Rounds at or below this are summarized by the prefix and no longer held.
    floor: Option<u64>,
    /// Floors peers gossip, kept in validator-id order for a stable view.
    peer_floors: Vec<PeerFloorView>,
    /// Certified headers that finalized at least one tracked transaction, with
    /// the commit prefix each one covers. Bounded, and only the heights a client
    /// can still ask about need to be here.
    finalized_headers: BTreeMap<u64, (Header, usize)>,
    /// The current certified head.
    head: HeadView,
    run: RunView,
    certified_heights: usize,
    /// Validators this node's local failure detector reports as silent.
    silent: Vec<SilentView>,
}

impl RpcCore {
    /// Builds the shared state from the same committee and genesis the node uses.
    #[must_use]
    pub(crate) fn new(
        node: usize,
        chain_id: Vec<u8>,
        accounts: &[chain::Account],
        genesis: &Header,
        committee: usize,
    ) -> Self {
        Self {
            node,
            committee: committee.max(1),
            chain_id,
            accounts: accounts
                .iter()
                .map(|account| (account.address.to_vec(), account.policy.clone()))
                .collect(),
            mempool: VecDeque::new(),
            records: HashMap::new(),
            gossip: Vec::new(),
            batches: HashMap::new(),
            state_sequences: HashMap::new(),
            pending_sequences: HashSet::new(),
            pending_finality: VecDeque::new(),
            states: BTreeMap::new(),
            order: Vec::new(),
            order_prefix: CommitFrontier::empty(),
            order_base: 0,
            floor: None,
            peer_floors: Vec::new(),
            finalized_headers: BTreeMap::new(),
            head: HeadView {
                height: genesis.height,
                round: genesis.round,
                state_root: genesis.state_root,
                applied: genesis.applied,
                covered_order: Some(0),
                dag_root: genesis.dag_root,
            },
            run: RunView::default(),
            certified_heights: 0,
            silent: Vec::new(),
        }
    }

    /// Takes the envelopes submitted since the last tick.
    pub(crate) fn take_gossip(&mut self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.gossip)
    }

    /// Records the state at `applied` cumulative transactions.
    ///
    /// Called at startup, after a restore, and after every executed batch, so a
    /// certified header's `applied` count has a snapshot to answer from.
    pub(crate) fn note_state(&mut self, applied: u64, state: &State) {
        for (account, _) in &self.accounts {
            self.state_sequences
                .insert(account.clone(), state.sequence(account));
        }
        self.states.insert(applied, state.clone());
        while self.states.len() > MAX_SNAPSHOTS {
            let Some(oldest) = self.states.keys().next().copied() else {
                break;
            };
            self.states.remove(&oldest);
        }
    }

    /// Refreshes the fields `/status` reports.
    pub(crate) fn set_run(
        &mut self,
        round: u64,
        committed_entries: usize,
        applied_txs: u64,
        peers: usize,
        conflicts: usize,
        skips: SkipCounts,
    ) {
        self.run = RunView {
            round,
            committed_entries,
            applied_txs,
            peers,
            conflicts,
            skips,
        };
    }

    /// Admits a canonical transaction envelope.
    ///
    /// The check order is deliberate: decode, version, chain, policy, signature,
    /// then replay. A duplicate content id returns the existing record rather
    /// than creating a second one, which makes a client retry after a timeout
    /// safe.
    fn submit(&mut self, envelope: &[u8], now: u64) -> Result<SubmitView, RpcReject> {
        let transaction = Transaction::decode(envelope).map_err(|error| {
            RpcReject::new(
                StatusCode::BAD_REQUEST,
                i32::from(error.code()),
                error.to_string(),
            )
        })?;
        if transaction.protocol_version != PROTOCOL_VERSION_V1 {
            return Err(RpcReject::new(
                StatusCode::BAD_REQUEST,
                -1,
                format!(
                    "unsupported protocol version {}",
                    transaction.protocol_version
                ),
            ));
        }
        if transaction.chain_id != self.chain_id {
            return Err(RpcReject::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                -1,
                "transaction is signed for another chain",
            ));
        }
        let policy = self
            .accounts
            .iter()
            .find(|(address, _)| address.as_slice() == transaction.sender.as_slice())
            .map(|(_, policy)| policy)
            .ok_or_else(|| {
                RpcReject::new(
                    StatusCode::NOT_FOUND,
                    -1,
                    format!("unknown account: {}", hex::encode(&transaction.sender)),
                )
            })?;
        let _used = transaction.verify(policy, now).map_err(|error| {
            RpcReject::new(
                StatusCode::UNPROCESSABLE_ENTITY,
                i32::from(error.code()),
                error.to_string(),
            )
        })?;

        // The id is the digest of the canonical encoding, which is also what the
        // execution path derives from a batch. A client that sends an equivalent
        // envelope through another encoder still reaches the same record.
        let canonical = transaction.encode().map_err(|error| {
            RpcReject::new(
                StatusCode::BAD_REQUEST,
                i32::from(error.code()),
                error.to_string(),
            )
        })?;
        let id: [u8; 32] = Sha256::digest(&canonical).into();
        if self.records.contains_key(&id) {
            // A gossiped envelope has a record but no local author. A client
            // submitting it here claims that authoring, so the transaction is not
            // left waiting for the node that first gossiped it.
            let queued = self.mempool.iter().any(|pending| pending.id == id);
            let record = self.records.get(&id).expect("the record was just checked");
            let terminal = record.outcome.is_some();
            let batched = record.batch.is_some();
            let key = (record.sender.clone(), record.sequence);
            if !queued && !terminal && !batched {
                if self.mempool.len() >= MAX_MEMPOOL {
                    return Err(RpcReject::new(
                        StatusCode::TOO_MANY_REQUESTS,
                        -1,
                        format!("mempool holds {MAX_MEMPOOL} transactions"),
                    ));
                }
                self.pending_sequences.insert(key);
                self.mempool.push_back(PendingTx {
                    id,
                    transaction,
                    queued_at: Instant::now(),
                });
            }
            return self.record_view(&id).ok_or_else(|| {
                RpcReject::new(StatusCode::INTERNAL_SERVER_ERROR, -1, "record disappeared")
            });
        }
        if self.mempool.len() >= MAX_MEMPOOL {
            return Err(RpcReject::new(
                StatusCode::TOO_MANY_REQUESTS,
                -1,
                format!("mempool holds {MAX_MEMPOOL} transactions"),
            ));
        }

        let sender = transaction.sender.clone();
        let applied = self.state_sequences.get(&sender).copied().unwrap_or(0);
        if transaction.sequence <= applied {
            return Err(RpcReject::new(
                StatusCode::CONFLICT,
                -1,
                format!(
                    "replay: sequence {} is not greater than the applied sequence {applied}",
                    transaction.sequence
                ),
            ));
        }
        let key = (sender.clone(), transaction.sequence);
        if !self.pending_sequences.insert(key) {
            return Err(RpcReject::new(
                StatusCode::CONFLICT,
                -1,
                format!(
                    "sequence {} is already pending for this sender",
                    transaction.sequence
                ),
            ));
        }

        self.records.insert(
            id,
            TxRecord {
                sender,
                sequence: transaction.sequence,
                batch: None,
                vertex: None,
                outcome: None,
                order_len_after: None,
                finalized_height: None,
                witness: None,
            },
        );
        self.mempool.push_back(PendingTx {
            id,
            transaction,
            queued_at: Instant::now(),
        });
        self.gossip.push(canonical);
        self.record_view(&id)
            .ok_or_else(|| RpcReject::new(StatusCode::INTERNAL_SERVER_ERROR, -1, "record vanished"))
    }

    /// Admits an envelope a peer gossiped.
    ///
    /// The envelope gets the same checks as a submission: chain, policy,
    /// signature, replay, and slot reservation. A duplicate id is ignored, and
    /// `now` is the receiver's clock, not the sender's. The transaction joins the
    /// local mempool, so a live node can author what a client sent to another
    /// node; if two nodes author it in the same round, the sequence rule rejects
    /// the later copy and the state changes once.
    pub(crate) fn admit_gossip(&mut self, envelope: &[u8], now: u64) -> bool {
        let Ok(transaction) = Transaction::decode(envelope) else {
            return false;
        };
        if transaction.protocol_version != PROTOCOL_VERSION_V1
            || transaction.chain_id != self.chain_id
        {
            return false;
        }
        let Some(policy) = self
            .accounts
            .iter()
            .find(|(address, _)| address.as_slice() == transaction.sender.as_slice())
            .map(|(_, policy)| policy)
        else {
            return false;
        };
        if transaction.verify(policy, now).is_err() {
            return false;
        }
        let Ok(canonical) = transaction.encode() else {
            return false;
        };
        let id: [u8; 32] = Sha256::digest(&canonical).into();
        if self.records.contains_key(&id) || self.mempool.len() >= MAX_MEMPOOL {
            return false;
        }
        let sender = transaction.sender.clone();
        let applied = self.state_sequences.get(&sender).copied().unwrap_or(0);
        if transaction.sequence <= applied {
            return false;
        }
        let key = (sender.clone(), transaction.sequence);
        if !self.pending_sequences.insert(key) {
            return false;
        }
        self.records.insert(
            id,
            TxRecord {
                sender,
                sequence: transaction.sequence,
                batch: None,
                vertex: None,
                outcome: None,
                order_len_after: None,
                finalized_height: None,
                witness: None,
            },
        );
        self.mempool.push_back(PendingTx {
            id,
            transaction,
            queued_at: Instant::now(),
        });
        true
    }

    /// The validator that should author one transaction.
    ///
    /// The content id is already a hash, so its first eight bytes spread
    /// transactions over the committee without a second hasher. Every node
    /// computes the same owner, which is what makes a gossiped transaction have
    /// exactly one normal author instead of one per node.
    fn owner(&self, id: &[u8; 32]) -> usize {
        let seed = u64::from_le_bytes([id[0], id[1], id[2], id[3], id[4], id[5], id[6], id[7]]);
        usize::try_from(seed).unwrap_or(usize::MAX) % self.committee
    }

    /// Takes up to `max` transactions this node owns, or ones whose owner has
    /// not authored them within [`OWNER_FALLBACK`].
    ///
    /// The returned batch is removed from the mempool but its transactions are
    /// still tracked; [`RpcCore::return_batch`] puts them back if the DAG refuses
    /// the authoring attempt. Unselected entries keep their submission order.
    pub(crate) fn take_batch(&mut self, max: usize) -> Option<tx::batch::Batch> {
        let max = max.clamp(1, tx::batch::MAX_BATCH_TRANSACTIONS);
        if self.mempool.is_empty() {
            return None;
        }
        let now = Instant::now();
        let mut selected = Vec::new();
        let mut kept = VecDeque::with_capacity(self.mempool.len());
        for pending in std::mem::take(&mut self.mempool) {
            let due = self.owner(&pending.id) == self.node
                || now.saturating_duration_since(pending.queued_at) >= OWNER_FALLBACK;
            if due && selected.len() < max {
                selected.push(pending);
            } else {
                kept.push_back(pending);
            }
        }
        self.mempool = kept;
        if selected.is_empty() {
            return None;
        }
        let mut transactions = Vec::with_capacity(selected.len());
        let mut tx_ids = Vec::with_capacity(selected.len());
        for pending in selected {
            tx_ids.push(pending.id);
            transactions.push(pending.transaction);
        }
        let batch = tx::batch::Batch::new(transactions);
        let digest = batch.digest().ok()?;
        for id in &tx_ids {
            if let Some(record) = self.records.get_mut(id) {
                record.batch = Some(digest);
            }
        }
        self.batches.insert(
            digest,
            BatchEntry {
                tx_ids,
                vertex: None,
            },
        );
        Some(batch)
    }

    /// Puts a batch the DAG would not author back at the front of the mempool.
    pub(crate) fn return_batch(&mut self, batch: tx::batch::Batch) {
        let Ok(digest) = batch.digest() else {
            return;
        };
        let Some(entry) = self.batches.remove(&digest) else {
            return;
        };
        for (id, transaction) in entry.tx_ids.iter().zip(batch.transactions).rev() {
            if let Some(record) = self.records.get_mut(id) {
                record.batch = None;
                record.vertex = None;
            }
            self.mempool.push_front(PendingTx {
                id: *id,
                transaction,
                queued_at: Instant::now(),
            });
        }
    }

    /// Re-admits the transactions of a batch whose vertex was skipped.
    ///
    /// A skip leaves the leader's batch out of the committed order, so its
    /// transactions are never applied. A restart also loses the in-memory
    /// mempool, which is why this takes the batch content rather than a batch
    /// map entry. Each transaction is checked exactly like a client submission;
    /// one already recorded or already pending is skipped, so recovering the
    /// same batch twice is harmless.
    pub(crate) fn readmit_batch(&mut self, batch: &tx::batch::Batch, now: u64) -> usize {
        let mut admitted = 0;
        for transaction in &batch.transactions {
            if self.readmit_transaction(transaction, now) {
                admitted += 1;
            }
        }
        admitted
    }

    fn readmit_transaction(&mut self, transaction: &Transaction, now: u64) -> bool {
        if transaction.protocol_version != PROTOCOL_VERSION_V1
            || transaction.chain_id != self.chain_id
        {
            return false;
        }
        let Ok(canonical) = transaction.encode() else {
            return false;
        };
        let id: [u8; 32] = Sha256::digest(&canonical).into();
        if let Some(record) = self.records.get_mut(&id) {
            // The author still has the record from admission; the batch was
            // skipped before it could be applied. Clear the batch binding and
            // put the envelope back in the mempool. A terminal outcome is final
            // and must not be reopened.
            if record.outcome.is_some() {
                return false;
            }
            if record.batch.is_some() {
                record.batch = None;
                record.vertex = None;
            }
            if self.mempool.iter().any(|pending| pending.id == id) {
                return false;
            }
            self.mempool.push_back(PendingTx {
                id,
                transaction: transaction.clone(),
                queued_at: Instant::now(),
            });
            return true;
        }
        if self.mempool.len() >= MAX_MEMPOOL {
            return false;
        }
        let Some(policy) = self
            .accounts
            .iter()
            .find(|(address, _)| address.as_slice() == transaction.sender.as_slice())
            .map(|(_, policy)| policy)
        else {
            return false;
        };
        if transaction.verify(policy, now).is_err() {
            return false;
        }
        let sender = transaction.sender.clone();
        let applied = self.state_sequences.get(&sender).copied().unwrap_or(0);
        if transaction.sequence <= applied {
            return false;
        }
        let key = (sender.clone(), transaction.sequence);
        if !self.pending_sequences.insert(key) {
            return false;
        }
        self.records.insert(
            id,
            TxRecord {
                sender,
                sequence: transaction.sequence,
                batch: None,
                vertex: None,
                outcome: None,
                order_len_after: None,
                finalized_height: None,
                witness: None,
            },
        );
        self.mempool.push_back(PendingTx {
            id,
            transaction: transaction.clone(),
            queued_at: Instant::now(),
        });
        true
    }

    /// Records the vertex that carries a batch.
    pub(crate) fn note_authored(&mut self, digest: &[u8; 32], vertex: VertexId) {
        let Some(entry) = self.batches.get_mut(digest) else {
            return;
        };
        entry.vertex = Some(vertex.clone());
        for id in entry.tx_ids.clone() {
            if let Some(record) = self.records.get_mut(&id) {
                record.vertex = Some(vertex.clone());
            }
        }
    }

    /// Records that a batch was executed at `order_index`, whoever authored it.
    ///
    /// A gossiped transaction has a record on every node, but only one node may
    /// have authored the batch that carries it. Executing the committed order is
    /// what makes the status global: the record is updated from the batch itself,
    /// and an applied copy wins over a later duplicate the sequence rule rejects.
    pub(crate) fn note_applied(
        &mut self,
        digest: &[u8; 32],
        vertex: &VertexId,
        order_index: usize,
        batch: &tx::batch::Batch,
        results: &[TxResult],
    ) {
        let order_len = order_index.saturating_add(1);
        let mut executed: HashSet<[u8; 32]> = HashSet::new();
        let mut finalized: Vec<[u8; 32]> = Vec::with_capacity(batch.len());
        for (offset, transaction) in batch.transactions.iter().enumerate() {
            let Ok(envelope) = transaction.encode() else {
                continue;
            };
            let id: [u8; 32] = Sha256::digest(&envelope).into();
            executed.insert(id);
            let Some(result) = results.get(offset).copied() else {
                continue;
            };
            let Some(record) = self.records.get_mut(&id) else {
                continue;
            };
            let merged = match record.outcome {
                Some(TxResult::Applied) => Some(TxResult::Applied),
                _ if result == TxResult::Applied => Some(TxResult::Applied),
                Some(rejected) => Some(rejected),
                None => Some(result),
            };
            if merged != record.outcome {
                record.outcome = merged;
                // The applied occurrence is the one a proof must point at, and
                // an earlier rejection may already have been finalized with a
                // witness for a different position.
                record.finalized_height = None;
                record.witness = None;
                record.order_len_after = Some(order_len);
                record.batch = Some(*digest);
                record.vertex = Some(vertex.clone());
                finalized.push(id);
            }
            self.pending_sequences
                .remove(&(record.sender.clone(), record.sequence));
        }
        // A peer's copy that is still waiting here must not author a second batch
        // for a transaction the committed order already executed.
        self.mempool
            .retain(|pending| !executed.contains(&pending.id));
        if !finalized.is_empty() {
            self.pending_finality.push_back((order_len, finalized));
        }
    }

    /// Extends the local copy from a compact prefix plus its retained tail.
    ///
    /// The prefix is immutable after a checkpoint restart; only the tail grows.
    /// A changed prefix or a shorter tail is a rebuild and replaces both.
    pub(crate) fn note_order_from(&mut self, prefix: &CommitFrontier, order: &[VertexId]) {
        if self.order_base == prefix.len()
            && self.order_prefix == *prefix
            && order.len() >= self.order.len()
        {
            self.order.extend_from_slice(&order[self.order.len()..]);
        } else {
            self.order_base = prefix.len();
            self.order_prefix = prefix.clone();
            self.order.clear();
            self.order.extend_from_slice(order);
        }
    }

    /// Records the DAG floor a checkpoint or snapshot adopted.
    pub(crate) fn note_floor(&mut self, floor: Option<u64>) {
        self.floor = floor;
    }

    /// Records the pruning floors peers gossip.
    ///
    /// This is a view, not a decision: the frame names its sender and is not
    /// verified, so the node loop only uses it to report and to log a possible
    /// reseed trigger.
    pub(crate) fn note_peer_floors(&mut self, floors: &BTreeMap<Vec<u8>, Option<u64>>) {
        self.peer_floors = floors
            .iter()
            .map(|(validator, floor)| PeerFloorView {
                validator: hex::encode(validator),
                floor: *floor,
            })
            .collect();
    }

    /// Records a certified header and finalizes every executed batch its commit
    /// prefix covers.
    ///
    /// `covered` is the number of order entries the header commits, from
    /// [`validator::Finalizer::certified_order`]. `None` means this node did not
    /// build that header itself and therefore does not know its prefix; finality
    /// is then reported as unknown rather than guessed.
    pub(crate) fn note_certified(&mut self, header: &Header, covered: Option<usize>) {
        self.head = HeadView {
            height: header.height,
            round: header.round,
            state_root: header.state_root,
            applied: header.applied,
            covered_order: covered,
            dag_root: header.dag_root,
        };
        let Some(covered) = covered else {
            return;
        };
        let mut finalized = false;
        while let Some((order_len, _)) = self.pending_finality.front() {
            if *order_len > covered {
                break;
            }
            let Some((order_len, ids)) = self.pending_finality.pop_front() else {
                break;
            };
            for id in ids {
                let matches = self
                    .records
                    .get(&id)
                    .is_some_and(|record| record.order_len_after == Some(order_len));
                // An applied occurrence may have superseded an earlier rejection
                // for the same transaction. Finality follows the position the
                // record names now, not the position of a stale queue entry.
                if !matches {
                    continue;
                }
                if let Some(record) = self.records.get_mut(&id) {
                    record.finalized_height = Some(header.height);
                }
                self.capture_witness(&id, header, covered);
                finalized = true;
            }
        }
        if finalized {
            self.finalized_headers
                .insert(header.height, (header.clone(), covered));
            while self.finalized_headers.len() > MAX_PROOF_CONTEXTS {
                let Some(oldest) = self.finalized_headers.keys().next().copied() else {
                    break;
                };
                self.finalized_headers.remove(&oldest);
            }
        }
    }

    /// Saves the commit proof for one finalized record while its leaf is still
    /// in the retained order.
    ///
    /// A proof cannot be rebuilt from the frontier peaks alone once the leaf is
    /// below the floor, so a record that may outlive the prefix carries its own
    /// path. The captured roots also keep `/tx` answerable after the certified
    /// header context has been evicted from its window.
    fn capture_witness(&mut self, id: &[u8; 32], header: &Header, covered: usize) {
        let Some(record) = self.records.get(id) else {
            return;
        };
        if record.witness.is_some() {
            return;
        }
        let Some(index) = record.order_len_after.map(|len| len.saturating_sub(1)) else {
            return;
        };
        let Some(vertex) = record.vertex.clone() else {
            return;
        };
        let Some(tail_index) = index.checked_sub(self.order_base) else {
            return;
        };
        let Some(covered_tail) = covered.checked_sub(self.order_base) else {
            return;
        };
        if tail_index >= covered_tail || covered_tail > self.order.len() {
            return;
        }
        if self.order.get(tail_index) != Some(&vertex) {
            return;
        }
        let Some(proof) = self
            .order_prefix
            .proof_for(&self.order[..covered_tail], tail_index)
        else {
            return;
        };
        let Some(record) = self.records.get_mut(id) else {
            return;
        };
        record.witness = Some(Witness {
            state_root: header.state_root,
            dag_root: header.dag_root,
            proof: CommitProof { vertex, proof },
        });
    }

    /// Counts certified heights reported by the finalizer.
    pub(crate) fn note_certified_heights(&mut self, heights: usize) {
        self.certified_heights = heights;
    }

    /// Replaces the local silence report shown by `/status`.
    ///
    /// This is a view, not a decision: the node loop computes it from vertices it
    /// holds, and two nodes may disagree while their delivery differs.
    pub(crate) fn note_failures(&mut self, silent: &[(Vec<u8>, u64)]) {
        self.silent = silent
            .iter()
            .map(|(validator, last_round)| SilentView {
                validator: hex::encode(validator),
                last_round: *last_round,
            })
            .collect();
    }

    fn record_view(&self, id: &[u8; 32]) -> Option<SubmitView> {
        let record = self.records.get(id)?;
        Some(SubmitView {
            id: hex::encode(id),
            status: record.stage().name(),
            sender: hex::encode(&record.sender),
            sequence: record.sequence,
            mempool: self.mempool.len(),
        })
    }

    fn status(&self) -> StatusView {
        let order_len = self.order_base + self.order.len();
        let order_root = self
            .order_prefix
            .root_at(&self.order, self.order.len())
            .expect("the retained tail is covered by its own length");
        StatusView {
            node: self.node,
            chain_id: hex::encode(&self.chain_id),
            head_height: self.head.height,
            head_round: self.head.round,
            head_state_root: hex::encode(self.head.state_root),
            head_applied: self.head.applied,
            head_order_len: self.head.covered_order,
            head_dag_root: hex::encode(self.head.dag_root),
            certified_heights: self.certified_heights,
            round: self.run.round,
            committed_entries: self.run.committed_entries,
            order_len,
            order_root: hex::encode(order_root),
            dag_floor: self.floor,
            peer_floors: self.peer_floors.clone(),
            applied_txs: self.run.applied_txs,
            mempool: self.mempool.len(),
            peers: self.run.peers,
            conflicts: self.run.conflicts,
            skips: SkipView {
                direct: self.run.skips.direct,
                indirect: self.run.skips.indirect,
                absent: self.run.skips.absent,
                fence_leader: self.run.skips.fence_leader,
                fence_voter: self.run.skips.fence_voter,
                attested: self.run.skips.attested,
            },
            tracked_transactions: self.records.len(),
            silent: self.silent.clone(),
        }
    }

    fn transaction(&self, id: [u8; 32], with_proof: bool) -> Result<TxView, RpcReject> {
        let record = self.records.get(&id).ok_or_else(|| {
            RpcReject::new(
                StatusCode::NOT_FOUND,
                -1,
                format!("unknown transaction: {}", hex::encode(id)),
            )
        })?;
        let stage = record.stage();
        let mut view = TxView {
            id: hex::encode(id),
            status: stage.name(),
            sender: hex::encode(&record.sender),
            sequence: record.sequence,
            batch: record.batch.map(hex::encode),
            vertex: record.vertex.as_ref().map(vertex_view),
            reason: match stage {
                Stage::Rejected(reason) => Some(reason.to_string()),
                _ => None,
            },
            finalized_height: record.finalized_height,
            state_root: None,
            dag_root: None,
            commit_proof: None,
        };
        if let Some(witness) = &record.witness {
            view.state_root = Some(hex::encode(witness.state_root));
            view.dag_root = Some(hex::encode(witness.dag_root));
            if with_proof {
                view.commit_proof = Some(proof_view(&witness.proof));
            }
            return Ok(view);
        }
        let Some(height) = record.finalized_height else {
            return Ok(view);
        };
        let Some((header, covered)) = self.finalized_headers.get(&height) else {
            return Ok(view);
        };
        view.state_root = Some(hex::encode(header.state_root));
        view.dag_root = Some(hex::encode(header.dag_root));
        if with_proof {
            let Some(index) = record.order_len_after.map(|len| len.saturating_sub(1)) else {
                return Ok(view);
            };
            let Some(vertex) = &record.vertex else {
                return Ok(view);
            };
            let Some(tail_index) = index.checked_sub(self.order_base) else {
                // The leaf is below the retained prefix, and the node no longer
                // holds the data a proof would need. The status stays final.
                return Ok(view);
            };
            let Some(covered_tail) = (*covered).checked_sub(self.order_base) else {
                return Ok(view);
            };
            if covered_tail > self.order.len() {
                // The header was certified just before the node loop captured the
                // new order suffix. The status is already final; the proof can be
                // asked for again once the next tick has extended the copy.
                return Ok(view);
            }
            if tail_index >= covered_tail || self.order.get(tail_index) != Some(vertex) {
                return Err(RpcReject::new(
                    StatusCode::CONFLICT,
                    -1,
                    "the stored order does not name the transaction's vertex at that prefix",
                ));
            }
            let Some(proof) = self
                .order_prefix
                .proof_for(&self.order[..covered_tail], tail_index)
            else {
                return Err(RpcReject::new(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    -1,
                    "cannot build a commit proof",
                ));
            };
            let proof = CommitProof {
                vertex: vertex.clone(),
                proof,
            };
            view.commit_proof = Some(proof_view(&proof));
        }
        Ok(view)
    }

    fn account(&self, account: &[u8]) -> Result<AccountView, RpcReject> {
        let head = self.head;
        let Some(state) = self.states.get(&head.applied) else {
            return Err(RpcReject::new(
                StatusCode::CONFLICT,
                -1,
                format!(
                    "no state snapshot at the certified applied count {}; the header is older than the retained window",
                    head.applied
                ),
            ));
        };
        if state.state_root() != head.state_root {
            return Err(RpcReject::new(
                StatusCode::INTERNAL_SERVER_ERROR,
                -1,
                "the retained state does not match the certified root",
            ));
        }
        let Some(proof) = state.proof(account) else {
            return Err(RpcReject::new(
                StatusCode::NOT_FOUND,
                -1,
                format!("unknown account: {}", hex::encode(account)),
            ));
        };
        Ok(AccountView {
            account: hex::encode(account),
            address: <[u8; 32]>::try_from(account)
                .map(|bytes| address::encode(&bytes))
                .unwrap_or_else(|_| hex::encode(account)),
            balance: proof.balance,
            sequence: proof.sequence,
            height: head.height,
            state_root: hex::encode(head.state_root),
            certified: true,
            proof: ProofView {
                leaf_index: proof.proof.leaf_index,
                leaf_count: proof.proof.leaf_count,
                steps: proof
                    .proof
                    .steps
                    .iter()
                    .map(|step| ProofStepView {
                        left: step.sibling_is_left,
                        hash: hex::encode(step.hash),
                    })
                    .collect(),
            },
        })
    }
}

/// Why a request was refused.
#[derive(Debug)]
pub(crate) struct RpcReject {
    status: StatusCode,
    code: i32,
    message: String,
}

impl RpcReject {
    fn new(status: StatusCode, code: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            code,
            message: message.into(),
        }
    }
}

impl IntoResponse for RpcReject {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ApiError {
                code: self.code,
                error: self.message,
            }),
        )
            .into_response()
    }
}

#[derive(Serialize)]
struct ApiError {
    code: i32,
    error: String,
}

#[derive(Serialize, Debug)]
struct SubmitView {
    id: String,
    status: &'static str,
    sender: String,
    sequence: u64,
    mempool: usize,
}

#[derive(Serialize)]
struct VertexView {
    round: u64,
    author: String,
    digest: String,
}

fn vertex_view(vertex: &VertexId) -> VertexView {
    VertexView {
        round: vertex.round,
        author: hex::encode(&vertex.author),
        digest: hex::encode(vertex.digest),
    }
}

#[derive(Serialize)]
struct ProofStepView {
    left: bool,
    hash: String,
}

#[derive(Serialize)]
struct ProofView {
    leaf_index: usize,
    leaf_count: usize,
    steps: Vec<ProofStepView>,
}

fn proof_view(proof: &CommitProof) -> ProofView {
    ProofView {
        leaf_index: proof.proof.leaf_index,
        leaf_count: proof.proof.leaf_count,
        steps: proof
            .proof
            .steps
            .iter()
            .map(|step| ProofStepView {
                left: step.sibling_is_left,
                hash: hex::encode(step.hash),
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct TxView {
    id: String,
    status: &'static str,
    sender: String,
    sequence: u64,
    batch: Option<String>,
    vertex: Option<VertexView>,
    reason: Option<String>,
    finalized_height: Option<u64>,
    state_root: Option<String>,
    dag_root: Option<String>,
    commit_proof: Option<ProofView>,
}

#[derive(Serialize)]
struct AccountView {
    account: String,
    address: String,
    balance: u64,
    sequence: u64,
    height: u64,
    state_root: String,
    certified: bool,
    proof: ProofView,
}

/// One validator the local failure detector reports as silent.
#[derive(Debug, Clone, Serialize)]
struct SilentView {
    validator: String,
    last_round: u64,
}

/// What one peer reports about the history it has pruned.
#[derive(Debug, Clone, Serialize)]
struct PeerFloorView {
    validator: String,
    floor: Option<u64>,
}

#[derive(Serialize)]
struct StatusView {
    node: usize,
    chain_id: String,
    head_height: u64,
    head_round: u64,
    head_state_root: String,
    head_applied: u64,
    head_order_len: Option<usize>,
    head_dag_root: String,
    certified_heights: usize,
    round: u64,
    committed_entries: usize,
    /// Committed order entries this node has seen, prefix included.
    order_len: usize,
    /// Merkle root over the committed order, so two nodes can compare it.
    order_root: String,
    /// Rounds at or below this are summarized by the prefix and no longer held.
    dag_floor: Option<u64>,
    /// What each peer says it has pruned, sorted by validator id.
    peer_floors: Vec<PeerFloorView>,
    applied_txs: u64,
    mempool: usize,
    peers: usize,
    conflicts: usize,
    skips: SkipView,
    tracked_transactions: usize,
    silent: Vec<SilentView>,
}

/// How the decision rules moved the cursor, by proof.
#[derive(Serialize)]
struct SkipView {
    direct: u64,
    indirect: u64,
    absent: u64,
    fence_leader: u64,
    fence_voter: u64,
    attested: u64,
}

#[derive(Deserialize)]
struct ProofQuery {
    #[serde(default)]
    proof: Option<String>,
}

impl ProofQuery {
    fn wants_proof(&self) -> bool {
        match self.proof.as_deref() {
            None => true,
            Some(value) => !(value == "0" || value.eq_ignore_ascii_case("false")),
        }
    }
}

async fn status(AxumState(rpc): AxumState<SharedRpc>) -> Json<StatusView> {
    let core = rpc.lock().expect("rpc lock poisoned");
    Json(core.status())
}

async fn submit(AxumState(rpc): AxumState<SharedRpc>, body: Bytes) -> Result<Response, RpcReject> {
    let text = std::str::from_utf8(&body).map_err(|_| {
        RpcReject::new(
            StatusCode::BAD_REQUEST,
            -1,
            "body must be the hex encoding of a transaction envelope",
        )
    })?;
    let text = text.trim();
    if text.is_empty() {
        return Err(RpcReject::new(
            StatusCode::BAD_REQUEST,
            -1,
            "body must be the hex encoding of a transaction envelope",
        ));
    }
    let envelope = hex::decode(text).map_err(|error| {
        RpcReject::new(StatusCode::BAD_REQUEST, -1, format!("invalid hex: {error}"))
    })?;
    let mut core = rpc.lock().expect("rpc lock poisoned");
    let id: [u8; 32] = Sha256::digest(&envelope).into();
    let existed = core.records.contains_key(&id);
    let view = core.submit(&envelope, now())?;
    let status = if existed {
        StatusCode::OK
    } else {
        StatusCode::ACCEPTED
    };
    Ok((status, Json(view)).into_response())
}

async fn transaction(
    AxumState(rpc): AxumState<SharedRpc>,
    Path(id): Path<String>,
    Query(query): Query<ProofQuery>,
) -> Result<Json<TxView>, RpcReject> {
    let bytes = hex::decode(id.trim()).map_err(|error| {
        RpcReject::new(
            StatusCode::BAD_REQUEST,
            -1,
            format!("invalid transaction id: {error}"),
        )
    })?;
    let id: [u8; 32] = bytes.try_into().map_err(|_| {
        RpcReject::new(
            StatusCode::BAD_REQUEST,
            -1,
            "transaction id must be 32 bytes of hex",
        )
    })?;
    let core = rpc.lock().expect("rpc lock poisoned");
    core.transaction(id, query.wants_proof()).map(Json)
}

async fn account(
    AxumState(rpc): AxumState<SharedRpc>,
    Path(account): Path<String>,
) -> Result<Json<AccountView>, RpcReject> {
    let bytes = parse_account(&account)?;
    let core = rpc.lock().expect("rpc lock poisoned");
    core.account(&bytes).map(Json)
}

fn parse_account(text: &str) -> Result<Vec<u8>, RpcReject> {
    let trimmed = text.trim();
    if let Some(hex_text) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return hex::decode(hex_text).map_err(|error| {
            RpcReject::new(
                StatusCode::BAD_REQUEST,
                -1,
                format!("invalid account hex: {error}"),
            )
        });
    }
    // A 64-character alphabet string without a `K` prefix is treated as hex;
    // everything else must pass the Base58Check address decoder, so a typo is
    // refused rather than searched for.
    if trimmed.len() == 64 && trimmed.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return hex::decode(trimmed).map_err(|error| {
            RpcReject::new(
                StatusCode::BAD_REQUEST,
                -1,
                format!("invalid account hex: {error}"),
            )
        });
    }
    address::decode(trimmed)
        .map(|bytes| bytes.to_vec())
        .map_err(|error| {
            RpcReject::new(
                StatusCode::BAD_REQUEST,
                -1,
                format!("invalid account address: {error}"),
            )
        })
}

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Builds the HTTP surface over one node's shared state.
pub(crate) fn router(rpc: SharedRpc) -> Router {
    Router::new()
        .route("/status", get(status))
        .route("/tx", post(submit))
        .route("/tx/{id}", get(transaction))
        .route("/account/{account}", get(account))
        .with_state(rpc)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain;
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;
    use exec::Transfer;
    use tower::ServiceExt;
    use tx::policy::Authorization;

    fn fixture() -> (RpcCore, Vec<chain::Account>, Vec<u8>) {
        fixture_with(1)
    }

    fn fixture_with(committee: usize) -> (RpcCore, Vec<chain::Account>, Vec<u8>) {
        let accounts = chain::accounts(4).unwrap();
        let chain_id = chain::demo_chain_id();
        let state = chain::genesis_state(&accounts).unwrap();
        let genesis = Header::genesis(
            chain_id.clone(),
            0,
            state.state_root(),
            validator::commit_root(&[]),
        );
        let mut core = RpcCore::new(0, chain_id.clone(), &accounts, &genesis, committee);
        core.note_state(0, &state);
        (core, accounts, chain_id)
    }

    fn signed(
        chain_id: &[u8],
        account: &chain::Account,
        recipient: &[u8],
        sequence: u64,
        amount: u64,
    ) -> Vec<u8> {
        let mut transaction = Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: chain_id.to_vec(),
            sender: account.address.to_vec(),
            sequence,
            fee: 1,
            expiration: u64::MAX,
            policy_version: 1,
            payload: Transfer::new(recipient.to_vec(), amount).encode().unwrap(),
            authorization: Vec::new(),
        };
        let signature = Ed25519Scheme
            .sign(
                &account.private_key,
                &transaction.signing_payload().unwrap(),
            )
            .unwrap();
        transaction.authorization.push(Authorization {
            algorithm_id: ALG_ED25519,
            key_id: account.key_id.clone(),
            signature,
        });
        transaction.encode().unwrap()
    }

    fn body_id(body: &[u8]) -> [u8; 32] {
        Sha256::digest(body).into()
    }

    #[test]
    fn a_skipped_batch_is_readmitted_from_its_content() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        core.submit(&envelope, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).unwrap();

        // A restart loses the records and the batch map, so recovery works from
        // the payload alone on a fresh core.
        let (mut recovered, _, _) = fixture();
        assert_eq!(recovered.readmit_batch(&batch, 1_700_000_000), 1);
        assert_eq!(recovered.mempool.len(), 1);

        // Recovering the same batch again is harmless: the record dedupes it.
        assert_eq!(recovered.readmit_batch(&batch, 1_700_000_000), 0);
        assert_eq!(recovered.mempool.len(), 1);
        assert_eq!(recovered.take_batch(16).unwrap().len(), 1);
    }

    #[test]
    fn a_skipped_batch_reuses_the_authors_record() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        core.submit(&envelope, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).unwrap();
        assert_eq!(core.mempool.len(), 0);

        // The author still has the record from admission. The skipped batch must
        // clear its batch binding and go back to the mempool anyway.
        assert_eq!(core.readmit_batch(&batch, 1_700_000_000), 1);
        assert_eq!(core.mempool.len(), 1);
        assert_eq!(core.readmit_batch(&batch, 1_700_000_000), 0);
        assert_eq!(core.take_batch(16).unwrap().len(), 1);
    }

    #[test]
    fn a_returned_batch_is_authored_again() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        core.submit(&envelope, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).unwrap();
        assert!(core.mempool.is_empty());

        core.return_batch(batch);
        assert_eq!(core.mempool.len(), 1);
        assert_eq!(core.take_batch(16).unwrap().len(), 1);
    }

    #[test]
    fn a_valid_transfer_is_admitted_and_tracked_through_finality() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        let view = core.submit(&envelope, 1_700_000_000).unwrap();
        assert_eq!(view.status, "mempool");
        assert_eq!(view.sequence, 1);

        let batch = core.take_batch(16).expect("the mempool had one");
        assert_eq!(batch.len(), 1);
        let digest = batch.digest().unwrap();
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [7; 32],
        };
        core.note_authored(&digest, vertex.clone());

        let state = chain::genesis_state(&accounts).unwrap();
        let mut state = state;
        let mut rejected = BTreeMap::new();
        let mut report = Vec::new();
        let applied = chain::apply_batch_timed_report(
            &mut state,
            &accounts,
            &batch,
            &mut rejected,
            &mut chain::ApplyTiming::default(),
            1,
            Some(&mut report),
        );
        assert_eq!(applied, 1);
        core.note_applied(&digest, &vertex, 0, &batch, &report);
        core.note_state(1, &state);

        let id = body_id(&envelope);
        assert_eq!(core.transaction(id, true).unwrap().status, "executed");

        let header = Header {
            chain_id: chain_id.clone(),
            epoch: 0,
            height: 1,
            round: 1,
            state_root: state.state_root(),
            dag_root: validator::commit_root(std::slice::from_ref(&vertex)),
            previous: [0; 32],
            applied: 1,
        };
        core.note_order_from(&CommitFrontier::empty(), std::slice::from_ref(&vertex));
        core.note_certified(&header, Some(1));
        let view = core.transaction(id, true).unwrap();
        assert_eq!(view.status, "finalized");
        assert_eq!(view.finalized_height, Some(1));
        assert!(view.commit_proof.is_some());
        let proof = view.commit_proof.unwrap();
        assert_eq!(proof.leaf_count, 1);
    }

    #[test]
    fn a_replayed_sequence_is_refused() {
        let (mut core, accounts, chain_id) = fixture();
        let first = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 1);
        core.submit(&first, 1_700_000_000).unwrap();

        // A different transaction at the same sequence is a replay, even though
        // it is not the same content id.
        let replay = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 2);
        let error = core.submit(&replay, 1_700_000_000).unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("already pending"));

        let batch = core.take_batch(16).unwrap();
        let digest = batch.digest().unwrap();
        let state = chain::genesis_state(&accounts).unwrap();
        let mut state = state;
        chain::apply_batch(&mut state, &accounts, &batch, &mut BTreeMap::new());
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [8; 32],
        };
        core.note_applied(&digest, &vertex, 0, &batch, &[TxResult::Applied]);
        core.note_state(1, &state);

        let error = core.submit(&replay, 1_700_000_000).unwrap_err();
        assert_eq!(error.status, StatusCode::CONFLICT);
        assert!(error.message.contains("applied sequence 1"));
    }

    #[test]
    fn a_tampered_signature_is_refused() {
        let (mut core, accounts, chain_id) = fixture();
        let mut envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 1);
        let last = envelope.len() - 1;
        envelope[last] ^= 0xff;
        let error = core.submit(&envelope, 1_700_000_000).unwrap_err();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn another_chain_is_refused() {
        let (mut core, accounts, _) = fixture();
        let envelope = signed(b"another-chain", &accounts[0], &accounts[1].address, 1, 1);
        let error = core.submit(&envelope, 1_700_000_000).unwrap_err();
        assert_eq!(error.status, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message.contains("another chain"));
    }

    #[test]
    fn an_account_proof_verifies_against_the_certified_root() {
        let (core, accounts, _) = fixture();
        let view = core.account(&accounts[1].address).unwrap();
        let root: [u8; 32] = hex::decode(&view.state_root).unwrap().try_into().unwrap();
        assert_eq!(view.balance, chain::GENESIS_BALANCE);
        assert!(view.certified);
        assert_eq!(view.height, 0);
        assert_eq!(view.proof.leaf_count, accounts.len());
        let proof = exec::AccountProof {
            account: accounts[1].address.to_vec(),
            balance: view.balance,
            sequence: view.sequence,
            proof: crypto::merkle::MerkleProof {
                leaf_index: view.proof.leaf_index,
                leaf_count: view.proof.leaf_count,
                steps: view
                    .proof
                    .steps
                    .iter()
                    .map(|step| crypto::merkle::ProofStep {
                        sibling_is_left: step.left,
                        hash: hex::decode(&step.hash).unwrap().try_into().unwrap(),
                    })
                    .collect(),
            },
        };
        assert!(proof.verify(&root));
    }

    #[test]
    fn a_rejected_transaction_keeps_its_reason_after_finality() {
        let (mut core, accounts, chain_id) = fixture();
        // A gap is admitted by the mempool (the sequence is not a replay), then
        // refused by execution because the next expected sequence is 1.
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 2, 1);
        let view = core.submit(&envelope, 1_700_000_000).unwrap();
        assert_eq!(view.status, "mempool");
        let batch = core.take_batch(16).unwrap();
        let digest = batch.digest().unwrap();
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [9; 32],
        };
        let state = chain::genesis_state(&accounts).unwrap();
        let mut state = state;
        let mut report = Vec::new();
        let applied = chain::apply_batch_timed_report(
            &mut state,
            &accounts,
            &batch,
            &mut BTreeMap::new(),
            &mut chain::ApplyTiming::default(),
            1,
            Some(&mut report),
        );
        assert_eq!(applied, 0);
        core.note_applied(&digest, &vertex, 0, &batch, &report);
        core.note_state(0, &state);
        let header = Header {
            chain_id: chain_id.clone(),
            epoch: 0,
            height: 1,
            round: 1,
            state_root: state.state_root(),
            dag_root: validator::commit_root(std::slice::from_ref(&vertex)),
            previous: [0; 32],
            applied: 0,
        };
        core.note_order_from(&CommitFrontier::empty(), std::slice::from_ref(&vertex));
        core.note_certified(&header, Some(1));
        let view = core.transaction(body_id(&envelope), true).unwrap();
        assert_eq!(view.status, "rejected");
        assert_eq!(view.reason.as_deref(), Some("bad_sequence"));
        assert_eq!(view.finalized_height, Some(1));
    }

    #[test]
    fn the_router_accepts_a_transaction_and_reports_it() {
        let (core, accounts, chain_id) = fixture();
        let shared: SharedRpc = Arc::new(Mutex::new(core));
        let app = router(Arc::clone(&shared));
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 5);
        let id = body_id(&envelope);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri("/tx")
                .body(axum::body::Body::from(hex::encode(&envelope)))
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::ACCEPTED);

            let request = axum::http::Request::builder()
                .method("GET")
                .uri(format!("/tx/{}", hex::encode(id)))
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.clone().oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);

            let request = axum::http::Request::builder()
                .method("GET")
                .uri("/status")
                .body(axum::body::Body::empty())
                .unwrap();
            let response = app.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
        });
    }

    #[test]
    fn gossip_refuses_a_duplicate_and_a_foreign_chain() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 1);
        assert!(core.admit_gossip(&envelope, 1_700_000_000));
        assert!(!core.admit_gossip(&envelope, 1_700_000_000));

        let foreign = signed(b"another-chain", &accounts[0], &accounts[1].address, 1, 1);
        assert!(!core.admit_gossip(&foreign, 1_700_000_000));
    }

    #[test]
    fn a_gossiped_transfer_finalizes_from_another_nodes_batch() {
        let (mut author, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        author.submit(&envelope, 1_700_000_000).unwrap();
        let gossip = author.take_gossip();
        assert_eq!(gossip.len(), 1);

        // The receiving node did not author the transaction; it learns the
        // outcome and the proof from executing the committed batch.
        let (mut peer, _, _) = fixture();
        assert!(peer.admit_gossip(&gossip[0], 1_700_000_000));
        let id = body_id(&envelope);
        assert_eq!(peer.transaction(id, false).unwrap().status, "mempool");

        let batch = author.take_batch(16).unwrap();
        let digest = batch.digest().unwrap();
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [3; 32],
        };
        let mut state = chain::genesis_state(&accounts).unwrap();
        let mut report = Vec::new();
        let applied = chain::apply_batch_timed_report(
            &mut state,
            &accounts,
            &batch,
            &mut BTreeMap::new(),
            &mut chain::ApplyTiming::default(),
            1,
            Some(&mut report),
        );
        assert_eq!(applied, 1);
        peer.note_order_from(&CommitFrontier::empty(), std::slice::from_ref(&vertex));
        peer.note_applied(&digest, &vertex, 0, &batch, &report);
        assert_eq!(peer.transaction(id, false).unwrap().status, "executed");

        let header = Header {
            chain_id: chain_id.clone(),
            epoch: 0,
            height: 1,
            round: 1,
            state_root: state.state_root(),
            dag_root: validator::commit_root(std::slice::from_ref(&vertex)),
            previous: [0; 32],
            applied: 1,
        };
        peer.note_certified(&header, Some(1));
        let view = peer.transaction(id, true).unwrap();
        assert_eq!(view.status, "finalized");
        assert_eq!(view.finalized_height, Some(1));
        assert!(view.commit_proof.is_some());
    }

    #[test]
    fn a_later_duplicate_does_not_undo_an_applied_outcome() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        core.submit(&envelope, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).unwrap();
        let digest = batch.digest().unwrap();
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [4; 32],
        };
        core.note_applied(&digest, &vertex, 0, &batch, &[TxResult::Applied]);
        core.note_applied(
            &digest,
            &vertex,
            1,
            &batch,
            &[TxResult::Rejected("bad sequence")],
        );

        let view = core.transaction(body_id(&envelope), false).unwrap();
        assert_eq!(view.status, "executed");
        assert!(view.finalized_height.is_none());
    }

    #[test]
    fn only_the_owner_authors_a_transaction_before_the_fallback() {
        let (core, accounts, chain_id) = fixture_with(4);
        let mut owned = None;
        let mut foreign = None;
        for amount in 1..=256 {
            let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, amount);
            let id = body_id(&envelope);
            if core.owner(&id) == 0 && owned.is_none() {
                owned = Some(envelope);
            } else if core.owner(&id) != 0 && foreign.is_none() {
                foreign = Some(envelope);
            }
            if owned.is_some() && foreign.is_some() {
                break;
            }
        }
        let owned = owned.expect("an envelope owned by node 0");
        let foreign = foreign.expect("an envelope owned by another node");

        let (mut core, _, _) = fixture_with(4);
        core.submit(&owned, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).expect("the owner authors immediately");
        assert_eq!(batch.len(), 1);

        // The same mempool on a node that does not own the transaction must not
        // author it, or every node would produce a duplicate batch.
        let (mut core, _, _) = fixture_with(4);
        core.submit(&foreign, 1_700_000_000).unwrap();
        assert!(
            core.take_batch(16).is_none(),
            "node 0 authored a transaction owned by another node"
        );
        assert_eq!(core.mempool.len(), 1);

        // Once the owner has had its window, a live node takes over.
        core.mempool[0].queued_at = Instant::now() - OWNER_FALLBACK - Duration::from_millis(1);
        let batch = core
            .take_batch(16)
            .expect("the fallback releases the transaction");
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn a_finalized_proof_survives_the_order_prefix() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        core.submit(&envelope, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).unwrap();
        let digest = batch.digest().unwrap();
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [6; 32],
        };
        let mut state = chain::genesis_state(&accounts).unwrap();
        let mut report = Vec::new();
        chain::apply_batch_timed_report(
            &mut state,
            &accounts,
            &batch,
            &mut BTreeMap::new(),
            &mut chain::ApplyTiming::default(),
            1,
            Some(&mut report),
        );
        core.note_order_from(&CommitFrontier::empty(), std::slice::from_ref(&vertex));
        core.note_applied(&digest, &vertex, 0, &batch, &report);
        let header = Header {
            chain_id: chain_id.clone(),
            epoch: 0,
            height: 1,
            round: 1,
            state_root: state.state_root(),
            dag_root: validator::commit_root(std::slice::from_ref(&vertex)),
            previous: [0; 32],
            applied: 1,
        };
        core.note_certified(&header, Some(1));

        let id = body_id(&envelope);
        let witness = core
            .records
            .get(&id)
            .unwrap()
            .witness
            .clone()
            .expect("a witness is captured at finality");
        assert!(witness.proof.verify(&witness.dag_root));

        // The checkpoint has now pruned the only leaf out of the retained prefix,
        // and the certified-header window no longer holds that height.
        core.order.clear();
        core.order_base = 1;
        core.order_prefix = CommitFrontier::empty();
        core.finalized_headers.clear();

        let view = core.transaction(id, true).unwrap();
        assert_eq!(view.status, "finalized");
        assert_eq!(view.dag_root, Some(hex::encode(header.dag_root)));
        assert!(view.commit_proof.is_some());
    }

    #[test]
    fn a_stale_rejection_does_not_finalize_a_later_applied_occurrence() {
        let (mut core, accounts, chain_id) = fixture();
        let envelope = signed(&chain_id, &accounts[0], &accounts[1].address, 1, 10);
        core.submit(&envelope, 1_700_000_000).unwrap();
        let batch = core.take_batch(16).unwrap();
        let digest = batch.digest().unwrap();
        let vertex = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [5; 32],
        };
        core.note_applied(
            &digest,
            &vertex,
            0,
            &batch,
            &[TxResult::Rejected("bad sequence")],
        );
        core.note_applied(&digest, &vertex, 1, &batch, &[TxResult::Applied]);
        core.note_order_from(&CommitFrontier::empty(), &[vertex.clone(), vertex.clone()]);

        // The header covers the rejection's order position only. The record now
        // names the applied position, so this header must not finalize it.
        let mut header = Header {
            chain_id: chain_id.clone(),
            epoch: 0,
            height: 1,
            round: 1,
            state_root: exec::State::new().state_root(),
            dag_root: validator::commit_root(std::slice::from_ref(&vertex)),
            previous: [0; 32],
            applied: 0,
        };
        core.note_certified(&header, Some(1));
        let view = core.transaction(body_id(&envelope), true).unwrap();
        assert_eq!(view.status, "executed");
        assert!(view.finalized_height.is_none());

        header.height = 2;
        header.applied = 1;
        core.note_certified(&header, Some(2));
        let view = core.transaction(body_id(&envelope), true).unwrap();
        assert_eq!(view.status, "finalized");
        assert_eq!(view.finalized_height, Some(2));
        assert!(view.commit_proof.is_some());
    }

    #[test]
    fn the_status_reports_the_root_of_the_committed_order() {
        let (mut core, _accounts, _chain_id) = fixture();
        let first = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [1; 32],
        };
        let second = VertexId {
            round: 2,
            author: b"val-1".to_vec(),
            digest: [2; 32],
        };
        core.note_order_from(&CommitFrontier::empty(), &[first.clone(), second.clone()]);
        let view = core.status();
        assert_eq!(view.order_len, 2);
        assert_eq!(view.dag_floor, None);
        core.note_floor(Some(3));
        assert_eq!(core.status().dag_floor, Some(3));
        core.note_peer_floors(&BTreeMap::from([
            (b"val-1".to_vec(), Some(4)),
            (b"val-2".to_vec(), None),
        ]));
        let view = core.status();
        assert_eq!(view.peer_floors.len(), 2);
        assert_eq!(view.peer_floors[0].validator, hex::encode(b"val-1"));
        assert_eq!(view.peer_floors[0].floor, Some(4));
        assert_eq!(view.peer_floors[1].validator, hex::encode(b"val-2"));
        assert_eq!(view.peer_floors[1].floor, None);
        assert_eq!(
            view.order_root,
            hex::encode(CommitFrontier::from_order(&[first.clone(), second.clone()]).root())
        );

        // The same two entries summarized as a pruned prefix plus a retained tail
        // must hash to the same root; that is the shape a checkpoint restart
        // reports, so a survivor can still compare order with a fresher node.
        let prefix = CommitFrontier::from_order(std::slice::from_ref(&first));
        core.note_order_from(&prefix, std::slice::from_ref(&second));
        let view = core.status();
        assert_eq!(view.order_len, 2);
        assert_eq!(
            view.order_root,
            hex::encode(prefix.root_at(std::slice::from_ref(&second), 1).unwrap())
        );
    }
}
