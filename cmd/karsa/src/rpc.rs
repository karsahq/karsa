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
//! | `GET /status` | head, round, committed entries, applied transactions, peers |
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
use validator::{CommitFrontier, CommitProof, Header, VertexId};

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
}

/// The mutex-protected state behind every endpoint.
pub(crate) struct RpcCore {
    node: usize,
    chain_id: Vec<u8>,
    accounts: Vec<(Vec<u8>, AuthPolicy)>,
    mempool: VecDeque<PendingTx>,
    /// Transactions that passed submit, by content id.
    records: HashMap<[u8; 32], TxRecord>,
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
    /// Certified headers that finalized at least one tracked transaction, with
    /// the commit prefix each one covers. Bounded, and only the heights a client
    /// can still ask about need to be here.
    finalized_headers: BTreeMap<u64, (Header, usize)>,
    /// The current certified head.
    head: HeadView,
    run: RunView,
    certified_heights: usize,
}

impl RpcCore {
    /// Builds the shared state from the same committee and genesis the node uses.
    #[must_use]
    pub(crate) fn new(
        node: usize,
        chain_id: Vec<u8>,
        accounts: &[chain::Account],
        genesis: &Header,
    ) -> Self {
        Self {
            node,
            chain_id,
            accounts: accounts
                .iter()
                .map(|account| (account.address.to_vec(), account.policy.clone()))
                .collect(),
            mempool: VecDeque::new(),
            records: HashMap::new(),
            batches: HashMap::new(),
            state_sequences: HashMap::new(),
            pending_sequences: HashSet::new(),
            pending_finality: VecDeque::new(),
            states: BTreeMap::new(),
            order: Vec::new(),
            order_prefix: CommitFrontier::empty(),
            order_base: 0,
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
        }
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
    ) {
        self.run = RunView {
            round,
            committed_entries,
            applied_txs,
            peers,
            conflicts,
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

        let id: [u8; 32] = Sha256::digest(envelope).into();
        if self.records.contains_key(&id) {
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
            },
        );
        self.mempool.push_back(PendingTx { id, transaction });
        self.record_view(&id)
            .ok_or_else(|| RpcReject::new(StatusCode::INTERNAL_SERVER_ERROR, -1, "record vanished"))
    }

    /// Takes up to `max` transactions for the next authored batch.
    ///
    /// The returned batch is removed from the mempool but its transactions are
    /// still tracked; [`RpcCore::return_batch`] puts them back if the DAG refuses
    /// the authoring attempt.
    pub(crate) fn take_batch(&mut self, max: usize) -> Option<tx::batch::Batch> {
        let max = max.clamp(1, tx::batch::MAX_BATCH_TRANSACTIONS);
        if self.mempool.is_empty() {
            return None;
        }
        let count = self.mempool.len().min(max);
        let mut transactions = Vec::with_capacity(count);
        let mut tx_ids = Vec::with_capacity(count);
        for _ in 0..count {
            let Some(pending) = self.mempool.pop_front() else {
                break;
            };
            tx_ids.push(pending.id);
            transactions.push(pending.transaction);
        }
        if transactions.is_empty() {
            return None;
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
            });
        }
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

    /// Records that a tracked batch was executed at `order_index`.
    pub(crate) fn note_applied(
        &mut self,
        digest: &[u8; 32],
        order_index: usize,
        results: &[TxResult],
    ) {
        let Some(entry) = self.batches.get(digest) else {
            return;
        };
        let ids = entry.tx_ids.clone();
        for (offset, id) in ids.iter().enumerate() {
            let Some(record) = self.records.get_mut(id) else {
                continue;
            };
            record.order_len_after = Some(order_index + 1);
            record.outcome = results.get(offset).copied();
            self.pending_sequences
                .remove(&(record.sender.clone(), record.sequence));
        }
        self.pending_finality.push_back((order_index + 1, ids));
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
            let Some((_, ids)) = self.pending_finality.pop_front() else {
                break;
            };
            for id in ids {
                if let Some(record) = self.records.get_mut(&id) {
                    record.finalized_height = Some(header.height);
                }
            }
            finalized = true;
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

    /// Counts certified heights reported by the finalizer.
    pub(crate) fn note_certified_heights(&mut self, heights: usize) {
        self.certified_heights = heights;
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
            applied_txs: self.run.applied_txs,
            mempool: self.mempool.len(),
            peers: self.run.peers,
            conflicts: self.run.conflicts,
            tracked_transactions: self.records.len(),
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
    applied_txs: u64,
    mempool: usize,
    peers: usize,
    conflicts: usize,
    tracked_transactions: usize,
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
        let accounts = chain::accounts(4).unwrap();
        let chain_id = chain::demo_chain_id();
        let state = chain::genesis_state(&accounts).unwrap();
        let genesis = Header::genesis(
            chain_id.clone(),
            0,
            state.state_root(),
            validator::commit_root(&[]),
        );
        let mut core = RpcCore::new(0, chain_id.clone(), &accounts, &genesis);
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
        core.note_applied(&digest, 0, &report);
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
        core.note_applied(&digest, 0, &[TxResult::Applied]);
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
        core.note_applied(&digest, 0, &report);
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
}
