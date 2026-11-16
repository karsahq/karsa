//! Inactive, fresh-start certified execution and header production with isolated signing keys.

use std::collections::{BTreeMap, BTreeSet};

use crypto::scheme::verify_signature;
use exec::State;
use store::AgreementOrderingSnapshot;
use tx::batch::Batch;
use validator::{Build, Certified, Finalizer, Header, Share, signing_payload};

use super::{CertifiedExecution, Membership};

/// Captures execution roots at durable application boundaries, never legacy DAG commits.
/// This offline path can sign headers: use isolated identities, not live signing keys.
/// Finalizer recovery and publication remain unsupported. Durable signing intent requires
/// an external reservation callback; the default build method makes no durable reservation.
/// Chain membership, finalizer set configuration and genesis state are caller-trusted.
/// Skips do not allocate header heights; every applied commit does, including empty ones.
pub struct CertifiedFinalization {
    execution: CertifiedExecution,
    finalizer: Finalizer,
    next_application: usize,
    outbox: Build,
    built_headers: BTreeMap<u64, Header>,
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
            || finalizer.has_pending_work()
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
            built_headers: BTreeMap::new(),
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
        self.build_ready_with_reservation(
            membership,
            batches,
            authenticated_controls,
            at,
            |_, _| Ok(()),
        )
    }

    /// Reserves each executed commit's exact header and coverage before any local signing.
    /// The callback must durably bind the header to its agreement history before succeeding.
    /// Header round/height distinguish commits that share an order length. This hook alone
    /// does not restore execution, finalizer queues, certificates or application progress.
    /// # Errors
    /// As with [`Self::build_ready`]; a reservation failure also poisons this instance,
    /// since storage publication can be uncertain and earlier headers may already be signed.
    pub fn build_ready_with_reservation(
        &mut self,
        membership: &Membership,
        batches: &BTreeMap<[u8; 32], Batch>,
        authenticated_controls: &BTreeSet<[u8; 32]>,
        at: u64,
        mut reserve: impl FnMut(&Header, usize) -> Result<(), crypto::CryptoError>,
    ) -> Result<Build, String> {
        self.ensure_usable()?;
        self.validate_membership(membership)?;
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
                match self.finalizer.build_ready_with_reservation(
                    self.execution.snapshot().order(),
                    at,
                    &mut reserve,
                ) {
                    Ok(mut build) => {
                        let header = self.finalizer.last_built().clone();
                        self.built_headers.insert(header.height, header);
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

    /// Authenticates a peer share only for an exact header already built from local execution.
    /// Unknown or conflicting headers are rejected, not buffered or adopted. A missing payload
    /// must be obtained and executed before retrying its share. Duplicate signers do not add weight.
    /// Certificates returned here are volatile; no persistence, transport or pruning is authorized.
    /// # Errors
    /// Rejects incompatible membership, unbuilt/conflicting headers, invalid signers and signatures
    /// before changing finalizer state. An error from the underlying finalizer poisons the instance.
    pub fn receive_share(
        &mut self,
        membership: &Membership,
        share: Share,
    ) -> Result<Vec<Certified>, String> {
        self.validate_share(membership, &share)?;
        match self.finalizer.receive_share(share) {
            Ok(certified) => Ok(certified),
            Err(error) => {
                self.failed = true;
                Err(error.to_string())
            }
        }
    }

    // Journaled collection must authenticate before writing or mutating quorum state.
    pub(super) fn validate_share(
        &self,
        membership: &Membership,
        share: &Share,
    ) -> Result<(), String> {
        self.ensure_usable()?;
        self.validate_membership(membership)?;
        if self.built_headers.get(&share.header.height) != Some(&share.header) {
            return Err("peer header does not match a locally executed certified boundary".into());
        }
        let signer = membership
            .set
            .validators
            .get(share.signer)
            .ok_or("peer header share signer is outside the pinned validator set")?;
        let key = signer
            .active_key(share.header.epoch)
            .map_err(|error| error.to_string())?;
        let payload = signing_payload(&share.header).map_err(|error| error.to_string())?;
        // The underlying finalizer keeps the first signature for each signer. Verify
        // before insertion so an invalid first arrival cannot suppress a later valid share.
        verify_signature(
            key.algorithm_id,
            &key.public_key,
            &payload,
            &share.signature,
        )
        .map_err(|error| error.to_string())
    }

    fn validate_membership(&self, membership: &Membership) -> Result<(), String> {
        let tip = self.execution.snapshot().binding().tip();
        if membership.set.epoch != tip.epoch()
            || &membership.set.id().map_err(|error| error.to_string())? != tip.set_id()
        {
            return Err(
                "certified finalization membership differs from the pinned validator set".into(),
            );
        }
        Ok(())
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
