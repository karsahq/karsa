//! Inactive real-batch execution over certified ordering, independent of the legacy DAG.

use std::collections::{BTreeMap, BTreeSet};

use exec::State;
use store::AgreementOrderingSnapshot;
use tx::batch::Batch;
use validator::VertexId;

use super::{Adapter, OrderingConsumer};
use crate::chain::{self, Membership};

/// Owns execution state and its certified cursor together; no live or RPC effects.
/// Rejection diagnostics are volatile and reset on restore. Accounts and control
/// classifications must come from the same trusted chain configuration as the WAL.
pub struct CertifiedExecution {
    consumer: OrderingConsumer,
    state: State,
    applied: u64,
    rejected: BTreeMap<&'static str, usize>,
}

impl CertifiedExecution {
    /// Starts only at an empty certified prefix with caller-trusted genesis state.
    /// # Errors
    /// Rejects nonempty checkpoints, which require paired state/cursor recovery instead.
    pub fn begin(snapshot: AgreementOrderingSnapshot, genesis: State) -> Result<Self, String> {
        if !snapshot.order().is_empty() {
            return Err("nonempty certified order requires execution checkpoint recovery".into());
        }
        Ok(Self {
            consumer: OrderingConsumer::restore(snapshot, &[])?,
            state: genesis,
            applied: 0,
            rejected: BTreeMap::new(),
        })
    }

    pub(super) fn from_empty_consumer(consumer: OrderingConsumer, state: State) -> Self {
        Self {
            consumer,
            state,
            applied: 0,
            rejected: BTreeMap::new(),
        }
    }

    /// Restores state and cursor from one locally validated checkpoint, if present.
    /// # Errors
    /// Propagates corrupt, stale, incompatible or undecodable checkpoint errors.
    pub fn restore(adapter: &mut Adapter) -> Result<Option<Self>, String> {
        Ok(adapter
            .restore_execution()?
            .map(|(consumer, state, applied)| Self {
                consumer,
                state,
                applied,
                rejected: BTreeMap::new(),
            }))
    }

    /// Verifies certified prefix continuity before making any new state changes.
    /// # Errors
    /// Rejects changed contexts, conflicting prefixes and regressing snapshots.
    pub fn update(&mut self, snapshot: AgreementOrderingSnapshot) -> Result<(), String> {
        self.consumer.update(snapshot)
    }

    /// Executes available batches in certified order with the shared chain executor.
    /// Missing batches stop progress. Zero payloads and caller-authenticated control
    /// digests advance the cursor without executing transactions. Never classify an
    /// unknown payload as control merely to unblock execution.
    /// Earlier successfully processed vertices remain consumed if a later one fails.
    /// # Errors
    /// Rejects digest mismatches, ambiguous batch/control classification, bad batch
    /// encoding and transaction-counter overflow before modifying the affected vertex.
    pub fn execute_ready(
        &mut self,
        membership: &Membership,
        batches: &BTreeMap<[u8; 32], Batch>,
        authenticated_controls: &BTreeSet<[u8; 32]>,
    ) -> Result<(), String> {
        self.execute_through(
            self.consumer.snapshot().order().len(),
            membership,
            batches,
            authenticated_controls,
        )
        .map(|_| ())
    }

    /// Executes no further than a certified prefix, returning whether it was reached.
    /// # Errors
    /// Rejects backward/out-of-range boundaries and the same batch failures as `execute_ready`.
    pub fn execute_through(
        &mut self,
        order_len: usize,
        membership: &Membership,
        batches: &BTreeMap<[u8; 32], Batch>,
        authenticated_controls: &BTreeSet<[u8; 32]>,
    ) -> Result<bool, String> {
        let Self {
            consumer,
            state,
            applied,
            rejected,
        } = self;
        consumer.consume_through(order_len, |vertex| {
            let hash = &vertex.payload_hash;
            if *hash == [0; 32] {
                return Ok(true);
            }
            if authenticated_controls.contains(hash) {
                if batches.contains_key(hash) {
                    return Err(
                        "certified payload has ambiguous batch/control classification".into(),
                    );
                }
                return Ok(true);
            }
            let Some(batch) = batches.get(hash) else {
                return Ok(false);
            };
            if batch.digest().map_err(|error| error.to_string())? != *hash {
                return Err("certified batch payload digest mismatch".into());
            }
            let upper =
                u64::try_from(batch.transactions.len()).map_err(|error| error.to_string())?;
            applied
                .checked_add(upper)
                .ok_or("certified execution counter overflow")?;
            let count = chain::apply_batch(state, &membership.accounts, batch, rejected);
            *applied += count as u64;
            Ok(true)
        })?;
        Ok(consumer.consumed_order().len() == order_len)
    }

    pub(super) fn snapshot(&self) -> &AgreementOrderingSnapshot {
        self.consumer.snapshot()
    }

    /// Atomically persists the owned state/count and exact consumed certified cursor.
    /// External side effects are not covered; finalizer/RPC publication is still disabled.
    /// # Errors
    /// Propagates incompatible owner, encoding, bounds and checkpoint publication errors.
    pub fn checkpoint(&mut self, adapter: &mut Adapter) -> Result<(), String> {
        adapter.checkpoint_execution(&mut self.consumer, &self.state, self.applied)
    }

    /// Current account state; mutable access is deliberately not exposed.
    pub fn state(&self) -> &State {
        &self.state
    }
    /// Successfully applied transactions, not consumed vertices.
    pub fn applied(&self) -> u64 {
        self.applied
    }
    /// Exact prefix already processed, including controls and rejected batches.
    pub fn consumed_order(&self) -> &[VertexId] {
        self.consumer.consumed_order()
    }
    /// Volatile rejection diagnostics accumulated since begin or restore.
    pub fn rejected(&self) -> &BTreeMap<&'static str, usize> {
        &self.rejected
    }
}
