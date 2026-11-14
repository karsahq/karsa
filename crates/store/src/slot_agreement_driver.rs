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
}

impl SlotAgreementDriver {
    /// Takes exclusive ownership of a new or recovered authenticated session.
    pub fn new(session: AuthenticatedSlotAgreement) -> Self {
        Self { session }
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
        let (bootstrap, transition, frozen, reproposal) = self.session.driver_snapshot()?;
        let mut candidates = Vec::new();
        if !transition.as_ref().is_some_and(|t| t.decision.is_some()) {
            for candidate in frozen {
                if transition
                    .as_ref()
                    .is_some_and(|t| t.view != candidate.certificate.vote.view)
                {
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
                    AgreementPhase::Precommit => SlotAgreementCarrierCandidate::PendingFinalProof(
                        candidate.lineage.into_proof(
                            candidate.certificate,
                            candidate.witnesses,
                            &bootstrap.set,
                        )?,
                    ),
                });
            }
        }
        Ok(SlotAgreementDriverOutput {
            transition,
            candidates,
            reproposal,
        })
    }
}
