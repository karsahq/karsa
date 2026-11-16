//! Inactive certified-order consumption; no legacy DAG, execution, or durable acknowledgement.

use store::AgreementOrderingSnapshot;
use validator::{Vertex, VertexId};

/// Volatile cursor over authenticated snapshots, independent of legacy DAG decisions.
/// Callers must restore execution state and its exact consumed order together. This
/// cursor cannot establish that association or provide crash-safe exactly-once effects.
#[derive(Debug)]
pub struct OrderingConsumer {
    snapshot: AgreementOrderingSnapshot,
    consumed: usize,
}

impl OrderingConsumer {
    /// Restores a cursor only when the caller's trusted consumed order is an exact prefix.
    /// An empty prefix starts consumption from the beginning, including checkpoint vertices.
    /// # Errors
    /// Rejects a restored order that differs from or exceeds the certified snapshot.
    pub fn restore(
        snapshot: AgreementOrderingSnapshot,
        consumed_order: &[VertexId],
    ) -> Result<Self, String> {
        if !snapshot.order().starts_with(consumed_order) {
            return Err("restored consumed order is not a certified prefix".into());
        }
        Ok(Self {
            snapshot,
            consumed: consumed_order.len(),
        })
    }

    /// Accepts a non-regressing snapshot without changing the consumption cursor.
    /// Checks the entire previously observed order, including unconsumed vertices.
    /// Authentication remains the store's responsibility; this is not a lineage proof
    /// between independent WALs, nor support for epoch transitions or pruning.
    /// # Errors
    /// Rejects changed chain/set/epoch, round regression, changed same-round binding,
    /// and any truncation or rewrite of the previously observed certified prefix.
    pub fn update(&mut self, snapshot: AgreementOrderingSnapshot) -> Result<(), String> {
        let old = self.snapshot.binding().tip();
        let new = snapshot.binding().tip();
        if old.chain_id() != new.chain_id()
            || old.set_id() != new.set_id()
            || old.epoch() != new.epoch()
        {
            return Err("certified ordering context changed".into());
        }
        if new.next_round() < old.next_round()
            || (new.next_round() == old.next_round()
                && snapshot.binding() != self.snapshot.binding())
        {
            return Err("certified ordering binding regressed or conflicted".into());
        }
        if !snapshot.order().starts_with(self.snapshot.order()) {
            return Err("certified ordering prefix regressed or conflicted".into());
        }
        if !snapshot
            .applications()
            .starts_with(self.snapshot.applications())
        {
            return Err("certified application history regressed or conflicted".into());
        }
        self.snapshot = snapshot;
        Ok(())
    }

    /// Offers vertices in certified order, stopping at the first unavailable payload.
    /// Return `Ok(true)` only after consuming a vertex, or `Ok(false)` to retry it later.
    /// A successful callback advances only this volatile cursor. A callback error must
    /// leave that vertex's external effects unchanged; earlier successes remain consumed.
    /// No batching, control-payload classification, execution, or persistence is implied.
    /// # Errors
    /// Propagates callback errors without advancing past the failed vertex.
    pub fn consume_ready(
        &mut self,
        mut consume: impl FnMut(&Vertex) -> Result<bool, String>,
    ) -> Result<(), String> {
        self.consume_through(self.snapshot.order().len(), &mut consume)
    }

    pub(super) fn snapshot(&self) -> &AgreementOrderingSnapshot {
        &self.snapshot
    }

    pub(super) fn consume_through(
        &mut self,
        order_len: usize,
        mut consume: impl FnMut(&Vertex) -> Result<bool, String>,
    ) -> Result<(), String> {
        if order_len < self.consumed || order_len > self.snapshot.order().len() {
            return Err("execution boundary is outside the remaining certified order".into());
        }
        while self.consumed < order_len {
            let vertex = &self.snapshot.vertices()[self.consumed];
            if !consume(vertex)? {
                break;
            }
            self.consumed += 1;
        }
        Ok(())
    }

    /// Exact consumed prefix to associate with a caller-owned execution checkpoint.
    pub fn consumed_order(&self) -> &[VertexId] {
        &self.snapshot.order()[..self.consumed]
    }
}
