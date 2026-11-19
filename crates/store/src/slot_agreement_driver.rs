use crate::{AuthenticatedSlotAgreement, AuthenticatedSlotAgreementRequest, StoreError};
use validator::slot_agreement::{AgreementPhase, AgreementTransitionResult};
use validator::{SlotAgreementPolCandidate, SlotAgreementProof};

/// Inactive owned coordinator; never signs, transports, or applies a decision.
#[derive(Debug)]
pub struct SlotAgreementDriver {
    session: AuthenticatedSlotAgreement,
}

/// Carrier-free evidence requiring external signing and subsequent full inspection.
#[derive(Debug)]
pub enum SlotAgreementCarrierCandidate {
    /// A digest to carry; binding an ID does not authenticate that carrier.
    PendingPol(SlotAgreementPolCandidate),
    /// Final evidence without an authenticated final carrier or decision authority.
    PendingFinalProof(SlotAgreementProof),
}

/// Deterministic durable replay output, not application authorization.
#[derive(Debug)]
pub struct SlotAgreementDriverOutput {
    /// Latest durable transition, containing unsigned local intent or an inspected decision.
    /// This is a snapshot, not a queue or exactly-once delivery: observations can replace
    /// an earlier transition's vote with `None`, and repeated reads can repeat output.
    pub transition: Option<AgreementTransitionResult>,
    /// Frozen current-view candidates; empty after a durable decision.
    pub candidates: Vec<SlotAgreementCarrierCandidate>,
    /// Highest valid authenticated POL material, retained across view advances.
    pub reproposal: Option<crate::AgreementReproposalCandidate>,
    /// Active replay-derived predecessor binding for read-only DAG inspection.
    pub binding: validator::SlotAgreementBinding,
    /// Current undecided vote obligations appropriate to the reducer phase and lock.
    /// These IDs are not transport or signing authority without local DAG checks.
    pub authorable_vote_ids: Vec<[u8; 32]>,
}

impl SlotAgreementDriver {
    /// Arms an owner-local share publication fault for recovery tests.
    #[cfg(feature = "test-support")]
    pub fn fail_share_publication(&mut self, stage: crate::SharePublicationStage, skip: usize) {
        self.session.fail_share_publication(stage, skip);
    }
    /// Takes exclusive ownership of a new or recovered authenticated session.
    pub fn new(session: AuthenticatedSlotAgreement) -> Self {
        Self { session }
    }

    /// Returns the full bounded signing history, not merely the latest transition.
    ///
    /// Entries are never removed; unsupported nil intents remain explicit.
    ///
    /// # Errors
    /// Rejects stale or uncertain sessions and invalid durable evidence.
    pub fn signing_outbox(&self) -> Result<Vec<crate::AgreementSigningIntent>, StoreError> {
        self.session.signing_outbox()
    }

    /// Returns every durable pre-sign reservation, including historical slots and views.
    ///
    /// # Errors
    /// Rejects stale or uncertain sessions and invalid durable evidence.
    pub fn reserved_carriers(&self) -> Result<Vec<crate::AgreementReservedCarrier>, StoreError> {
        self.session.reserved_carriers()
    }

    /// Returns every durable signed publication, including historical slots and views.
    ///
    /// # Errors
    /// Rejects stale or uncertain sessions and invalid durable evidence.
    pub fn completed_carriers(&self) -> Result<Vec<crate::AgreementCompletedCarrier>, StoreError> {
        self.session.completed_carriers()
    }

    /// Returns durable signed nil publications, including historical slots and views.
    ///
    /// # Errors
    /// Rejects stale or uncertain sessions and invalid durable evidence.
    pub fn completed_nil_votes(&self) -> Result<Vec<crate::AgreementCompletedNilVote>, StoreError> {
        self.session.completed_nil_votes()
    }

    /// Returns original local request authorizations with immutable signed completions.
    /// # Errors
    /// Rejects stale or uncertain owners and invalid durable evidence.
    pub fn view_request_reservations(
        &self,
    ) -> Result<Vec<crate::AgreementViewRequestReservation>, StoreError> {
        self.session.view_request_reservations()
    }

    /// Exports the latest validated current-slot durable view-entry certificate.
    /// # Errors
    /// Rejects stale or uncertain owners and invalid durable evidence.
    pub fn entered_view_certificate(
        &self,
    ) -> Result<Option<Vec<validator::SlotAgreementViewRequest>>, StoreError> {
        self.session.entered_view_certificate()
    }

    /// Exports the applied certified prefix and signed vertices from the owner's
    /// verified durable state. Deciding evidence alone does not extend this prefix;
    /// `AdvanceSlot` must be durable.
    /// # Errors
    /// Rejects stale or uncertain sessions, corrupt evidence, and missing ordered vertices.
    pub fn ordering_snapshot(&self) -> Result<crate::AgreementOrderingSnapshot, StoreError> {
        self.session.ordering_snapshot()
    }

    /// Loads the execution state/cursor pair after validating owner and certified prefix.
    /// # Errors
    /// Rejects stale owners, corrupt records, and incompatible certified histories.
    pub fn execution_checkpoint(
        &self,
    ) -> Result<Option<crate::AgreementExecutionCheckpoint>, StoreError> {
        self.session.execution_checkpoint()
    }

    /// Publishes opaque execution state and its certified cursor as one synced record.
    /// # Errors
    /// Rejects invalid or regressing prefixes, conflicting state, and publication failures.
    pub fn put_execution_checkpoint(
        &mut self,
        order: &[validator::VertexId],
        applied: u64,
        state: &[u8],
    ) -> Result<(), StoreError> {
        self.session.put_execution_checkpoint(order, applied, state)
    }

    /// Loads exact pre-sign header intents bound to applied agreement history.
    /// # Errors
    /// Rejects stale owners, corrupt records and incompatible history.
    pub fn header_intents(&self) -> Result<Vec<crate::AgreementHeaderIntent>, StoreError> {
        self.session.header_intents()
    }

    /// Reserves a header durably before an external signer is invoked.
    /// # Errors
    /// Rejects conflicts, missing application boundaries and publication failures.
    pub fn reserve_header(
        &mut self,
        anchor: &validator::Header,
        header: &validator::Header,
        order_len: usize,
    ) -> Result<(), StoreError> {
        self.session.reserve_header(anchor, header, order_len)
    }

    /// Loads completed header shares verified against exact intents and the pinned set.
    /// # Errors
    /// Rejects stale/uncertain sessions, corrupt records and invalid signatures or history.
    pub fn header_shares(&self) -> Result<Vec<validator::Share>, StoreError> {
        self.session.header_shares()
    }

    /// Durably records a share for an exact existing header intent.
    /// Exact duplicates include the timestamp and repeat durability barriers.
    /// # Errors
    /// Rejects invalid anchors, signatures, conflicts, bounds and publication failures.
    /// Publication failure makes the session uncertain and requires recovery.
    pub fn reserve_header_share(
        &mut self,
        anchor: &validator::Header,
        share: &validator::Share,
    ) -> Result<(), StoreError> {
        self.session.reserve_header_share(anchor, share)
    }

    /// Returns the number of durable requests installed by this owner.
    pub fn sequence(&self) -> u64 {
        self.session.sequence()
    }

    /// Diagnostic journal fold count, replay/read nanoseconds and the resumed subset.
    /// Cost observation only; grants no freshness, durability or progress authority.
    pub fn replay_costs(&self) -> (u64, u64, u64, u64, u64) {
        self.session.replay_costs()
    }

    /// Delegates inspection and durability before releasing replay-derived output.
    ///
    /// # Errors
    /// Rejects invalid requests, stale or uncertain sessions, bounds, and I/O failures.
    /// An error does not imply rollback: durable apply may have succeeded before the
    /// output snapshot fails, for example if another owner advances the journal.
    /// Recover and inspect durable state rather than assuming the request was not installed.
    pub fn apply(
        &mut self,
        sequence: u64,
        request: AuthenticatedSlotAgreementRequest,
    ) -> Result<SlotAgreementDriverOutput, StoreError> {
        self.session.apply(sequence, request)?;
        self.output()
    }

    /// Rebuilds immutable output from the owner's verified durable state.
    ///
    /// Durable reads reuse the replay verified for the owner's exact journal tip; a
    /// reported sequence and transition always describe that same durable state.
    /// Output is still a snapshot, not a queue: repeated reads can repeat output.
    ///
    /// # Errors
    /// Rejects stale or uncertain owners, corrupt evidence, and invalid candidates.
    pub fn output(&self) -> Result<SlotAgreementDriverOutput, StoreError> {
        let (bootstrap, transition, frozen, reproposal, binding, authorable_vote_ids) =
            self.session.driver_snapshot()?;
        let mut candidates = Vec::new();
        let view = transition
            .as_ref()
            .map_or(validator::slot_agreement::AgreementView(0), |t| t.view);
        let decided = transition.as_ref().is_some_and(|t| t.decision.is_some());
        for candidate in frozen {
            if !candidate.is_fresh(view, decided) {
                continue;
            }
            candidates.push(match candidate.certificate.vote.phase {
                AgreementPhase::Prevote => SlotAgreementCarrierCandidate::PendingPol(
                    candidate.lineage.pol_candidate_digest(
                        candidate.certificate,
                        candidate.witnesses,
                        &bootstrap.set,
                    )?,
                ),
                AgreementPhase::Precommit => {
                    SlotAgreementCarrierCandidate::PendingFinalProof(candidate.lineage.into_proof(
                        candidate.certificate,
                        candidate.witnesses,
                        &bootstrap.set,
                    )?)
                }
            });
        }
        Ok(SlotAgreementDriverOutput {
            transition,
            candidates,
            reproposal,
            binding,
            authorable_vote_ids,
        })
    }
}
