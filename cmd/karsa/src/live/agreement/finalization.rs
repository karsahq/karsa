//! Inactive, fresh-start certified execution and header production with isolated signing keys.

use std::collections::{BTreeMap, BTreeSet};

use exec::State;
use store::AgreementOrderingSnapshot;
use tx::batch::Batch;
use validator::{Build, Finalizer};

use super::{CertifiedExecution, Membership};

/// Captures execution roots at durable application boundaries, never legacy DAG commits.
/// This offline path can sign headers: use isolated identities, not live signing keys.
/// Finalizer recovery/signing durability and publication are deliberately unsupported.
/// Chain membership, finalizer set configuration and genesis state are caller-trusted.
/// Skips do not allocate header heights; every applied commit does, including empty ones.
pub struct CertifiedFinalization {
    execution: CertifiedExecution,
    finalizer: Finalizer,
    next_application: usize,
    outbox: Build,
    failed: bool,
}

impl CertifiedFinalization {
    /// Starts from an empty, round-one agreement checkpoint and a pristine genesis finalizer.
    /// The snapshot may already contain applied decisions, which are executed one boundary at a time.
    /// # Errors
    /// Rejects non-genesis anchors, preexisting execution or incompatible chain/state/order roots.
    pub fn begin(
        snapshot: AgreementOrderingSnapshot,
        genesis: State,
        finalizer: Finalizer,
    ) -> Result<Self, String> {
        let checkpoint = snapshot.checkpoint_binding().tip();
        let anchor = finalizer.head();
        if checkpoint.order_len() != 0
            || checkpoint.next_round() != 1
            || anchor.height != 0
            || anchor.applied != 0
            || anchor.chain_id != checkpoint.chain_id()
            || finalizer.chain_id() != checkpoint.chain_id()
            || anchor.epoch != checkpoint.epoch()
            || anchor.state_root != genesis.state_root()
            || &anchor.dag_root != checkpoint.order_root()
            || finalizer.last_built() != anchor
            || finalizer.last_built_order() != 0
            || finalizer.built_headers() != 0
            || finalizer.next_height() != 1
            || !finalizer.certified_ids().is_empty()
        {
            return Err(
                "certified finalization requires a matching pristine genesis anchor".into(),
            );
        }
        // Unlike execution-only begin, backlog is allowed here: the roots will be
        // captured before advancing past each replay-derived application boundary.
        let consumer = super::OrderingConsumer::restore(snapshot, &[])?;
        Ok(Self {
            execution: CertifiedExecution::from_empty_consumer(consumer, genesis),
            finalizer,
            next_application: 0,
            outbox: Build::default(),
            failed: false,
        })
    }

    /// Accepts only a continuation of the same observed order and application history.
    /// # Errors
    /// Rejects a poisoned instance or regressing/conflicting snapshots before execution.
    pub fn update(&mut self, snapshot: AgreementOrderingSnapshot) -> Result<(), String> {
        self.ensure_usable()?;
        if snapshot.checkpoint_binding() != self.execution.snapshot().checkpoint_binding() {
            return Err("certified finalization checkpoint anchor changed".into());
        }
        self.execution.update(snapshot)
    }

    /// Executes available boundaries and returns locally built shares/certificates.
    /// Missing payloads stop before the affected boundary; retries do not reserve extra heights.
    /// Earlier output is retained internally across execution errors until a successful call.
    /// Returned shares are not published or durably reserved by this offline coordinator.
    /// # Errors
    /// Propagates batch errors. A finalizer error permanently poisons this instance because
    /// the underlying finalizer may already have mutated or signed; never retry it in place.
    pub fn build_ready(
        &mut self,
        membership: &Membership,
        batches: &BTreeMap<[u8; 32], Batch>,
        authenticated_controls: &BTreeSet<[u8; 32]>,
        at: u64,
    ) -> Result<Build, String> {
        self.ensure_usable()?;
        while let Some(boundary) = self
            .execution
            .snapshot()
            .applications()
            .get(self.next_application)
            .cloned()
        {
            if self.finalizer.schedule().epoch_of(boundary.round())
                != self.execution.snapshot().binding().tip().epoch()
            {
                self.failed = true;
                return Err("certified finalization does not support epoch transitions".into());
            }
            if !self.execution.execute_through(
                boundary.order_len(),
                membership,
                batches,
                authenticated_controls,
            )? {
                break;
            }
            if boundary.is_commit() {
                self.finalizer
                    .record_commit(boundary.round(), boundary.order_len());
                self.finalizer.mark_applied(
                    boundary.order_len(),
                    self.execution.state().state_root(),
                    self.execution.applied(),
                );
                match self
                    .finalizer
                    .build_ready(self.execution.snapshot().order(), at)
                {
                    Ok(mut build) => {
                        self.outbox.shares.append(&mut build.shares);
                        self.outbox.certified.append(&mut build.certified);
                    }
                    Err(error) => {
                        self.failed = true;
                        return Err(error.to_string());
                    }
                }
            }
            self.next_application += 1;
        }
        Ok(std::mem::take(&mut self.outbox))
    }

    /// Execution state and exact consumed prefix; mutable access would bypass boundaries.
    pub fn execution(&self) -> &CertifiedExecution {
        &self.execution
    }

    /// Read-only header builder state; no legacy commits can be injected through this handle.
    pub fn finalizer(&self) -> &Finalizer {
        &self.finalizer
    }

    fn ensure_usable(&self) -> Result<(), String> {
        if self.failed {
            return Err(
                "certified finalization requires reconstruction after finalizer failure".into(),
            );
        }
        Ok(())
    }
}
