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

    /// Returns the number of durable requests installed by this owner.
    pub fn sequence(&self) -> u64 {
        self.session.sequence()
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

    /// Reconstructs output without trusting cached evidence or mutable external context.
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
