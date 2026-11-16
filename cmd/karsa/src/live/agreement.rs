//! Inactive durable signing boundary with explicit local carrier authoring, never live transport.

use crypto::registry::{self, ALG_ED25519};
use crypto::scheme::{Ed25519Scheme, verify_signature};
use store::{AgreementSigningIntent, AgreementSigningPrerequisite};
use store::{
    AuthenticatedSlotAgreementBootstrap, AuthenticatedSlotAgreementRequest,
    SlotAgreementCarrierCandidate, SlotAgreementDriver, SlotAgreementDriverOutput, Store,
    StoreError,
};
use validator::slot_agreement::AgreementValue;

pub use crate::chain::Membership;
use validator::{SlotAgreementVotePayload, ValidatorSet, ValidatorSignature, VertexId};

/// Carrier intent whose dependencies still require causal-readiness inspection.
#[derive(Debug)]
pub enum PendingIntent {
    /// Durable nil obligation with no DAG carrier; signed nil publication is supported separately.
    UnsupportedNil {
        /// Full original immutable signing context.
        intent: AgreementSigningIntent,
    },
    /// A durable local vote, not yet causally ready for a carrier.
    Vote {
        /// Exact signed statement and authenticated prerequisite.
        payload: SlotAgreementVotePayload,
        /// Existing vote-carrier payload digest.
        digest: [u8; 32],
        /// Exact full authenticated lineage from the original durable emission.
        lineage: validator::SlotAgreementViewLineage,
    },
    /// Authenticated prevote quorum awaiting a real carrier.
    Pol {
        /// Carrier-free POL evidence.
        candidate: validator::SlotAgreementPolCandidate,
        /// Existing POL digest.
        digest: [u8; 32],
    },
    /// Final evidence, not decision-application authority.
    FinalProof {
        /// Complete proof awaiting a real final carrier.
        proof: validator::SlotAgreementProof,
        /// Existing final proof digest.
        digest: [u8; 32],
    },
}

/// Failure to extract carrier ancestry prerequisites from an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrerequisiteExtractionError {
    /// Nil has no supported carrier representation.
    UnsupportedNil,
    /// An externally constructed final intent lacks its selected POL.
    MissingSelectedPol,
}

impl std::fmt::Display for PrerequisiteExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedNil => "nil carrier prerequisites are unsupported",
            Self::MissingSelectedPol => "final intent lacks selected POL",
        })
    }
}

impl std::error::Error for PrerequisiteExtractionError {}

impl PendingIntent {
    /// Extracts sorted, unique direct prerequisite IDs for a future ancestry check.
    /// This is not authentication, readiness, signing or publication authorization:
    /// externally constructed intents remain untrusted, including their digests.
    /// Nested evidence still requires unified DAG inspection.
    ///
    /// # Errors
    /// Rejects nil votes/obligations and final evidence without a selected POL.
    pub fn prerequisite_carriers(&self) -> Result<Vec<VertexId>, PrerequisiteExtractionError> {
        let mut ids = match self {
            Self::UnsupportedNil { .. } => return Err(PrerequisiteExtractionError::UnsupportedNil),
            Self::Vote { payload, .. } => {
                if payload.vote.value == AgreementValue::Nil {
                    return Err(PrerequisiteExtractionError::UnsupportedNil);
                }
                vec![payload.prerequisite.clone()]
            }
            Self::Pol { candidate, .. } => candidate.prerequisite_carriers(),
            Self::FinalProof { proof, .. } => {
                let pol = proof
                    .entries
                    .last()
                    .and_then(|entry| entry.pol.as_ref())
                    .ok_or(PrerequisiteExtractionError::MissingSelectedPol)?;
                let mut ids = vec![pol.carrier.clone()];
                ids.extend(proof.votes.iter().map(|w| w.carrier.clone()));
                ids
            }
        };
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        ids.dedup();
        Ok(ids)
    }
}

/// Live activation remains disabled; explicit local authoring is not transport authorization.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Historical compatibility label: explicit local authoring exists, but live wiring is disabled.
    DisabledMissingCausalReadinessAndTransport,
    /// A driver or reconstruction failure requires a fresh durable recovery.
    RecoveryRequiredHistoricalIntentsUnavailable,
}

/// Exclusive driver owner retaining obligations and explicitly authoring locally checked votes.
pub struct Adapter {
    driver: SlotAgreementDriver,
    set: ValidatorSet,
    validator_id: Vec<u8>,
    key_id: Vec<u8>,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    pending: Vec<PendingIntent>,
    history: Vec<AgreementSigningIntent>,
    readiness: Readiness,
    pacemaker: Option<pacemaker::Pacemaker>,
    // Partial remote support is never journaled and is lost on recovery.
    view_requests: Vec<validator::SlotAgreementViewRequest>,
}

#[derive(Clone, Copy)]
enum AggregateKind {
    Pol,
    Final,
}

/// Durable signed publication and evidence; no transport or delivery guarantee.
#[derive(Debug)]
pub struct AuthoredCarrier {
    /// Actual signed vertex, already inserted by Node's existing authoring path.
    pub vertex: validator::Vertex,
    /// Self-contained evidence bound to that actual vertex.
    pub envelope: CarrierEnvelope,
}

/// Backward-compatible name for the local vote authoring result.
pub type AuthoredVote = AuthoredCarrier;

impl Adapter {
    /// Opts into explicit local ticks, resetting volatile timers. Recovery starts disabled.
    pub fn configure_pacemaker(&mut self, policy: pacemaker::Policy) {
        self.pacemaker = Some(pacemaker::Pacemaker::new(policy));
    }

    /// Rechecks durable state and applies at most one timed action; never signs or sends.
    /// Nil obligations must subsequently use `author_nil_vote`. No delayed action is accepted.
    /// Observing any durable precommit starts a fresh, bounded publication grace. Its deadline
    /// is not remote evidence: no publication, acknowledgement, or pending control work gates
    /// local advancement. The driver still enforces durable votes and preserves locks.
    /// # Errors
    /// Snapshot failures require recovery; backwards time and arithmetic exhaustion are rejected.
    pub fn tick(&mut self, now: std::time::Instant) -> Result<Option<pacemaker::Action>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before timed actions".into());
        }
        if self.pacemaker.is_none() {
            return Ok(None);
        }
        let snapshot = self.timer_snapshot().inspect_err(|_| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        })?;
        let action = self
            .pacemaker
            .as_mut()
            .expect("configured pacemaker")
            .plan(&snapshot, now)?;
        if let Some(action) = action {
            self.apply(match action {
                pacemaker::Action::Timeout { view, phase } => {
                    AuthenticatedSlotAgreementRequest::Timeout { view, phase }
                }
                pacemaker::Action::AdvanceView { from } => {
                    AuthenticatedSlotAgreementRequest::AdvanceView { from }
                }
            })?;
        }
        Ok(action)
    }

    fn timer_snapshot(&self) -> Result<pacemaker::Snapshot, String> {
        use validator::slot_agreement::{AgreementPhase, AgreementView};
        let output = self.driver.output().map_err(|e| e.to_string())?;
        let history = self.driver.signing_outbox().map_err(|e| e.to_string())?;

        let slot = output.binding.tip().clone();
        let view = output
            .transition
            .as_ref()
            .map_or(AgreementView(0), |t| t.view);
        let mut state = pacemaker::Snapshot {
            slot,
            view,
            prevote: false,
            precommit: false,
            decided: output
                .transition
                .as_ref()
                .is_some_and(|t| t.decision.is_some()),
        };
        for intent in history
            .iter()
            .filter(|i| i.vote.context == state.slot && i.vote.view == view)
        {
            match intent.vote.phase {
                AgreementPhase::Prevote => state.prevote = true,
                AgreementPhase::Precommit => state.precommit = true,
            }
        }

        Ok(state)
    }

    /// Reserves, signs and completes a plain proposal without authorizing a view.
    /// # Errors
    /// Rejects stale owners, mismatched Nodes, invalid evidence and durable conflicts.
    pub fn author_proposal(
        &mut self,
        proposal: &validator::SlotProposalEnvelope,
        node: &mut net::Node,
    ) -> Result<Option<AuthoredCarrier>, String> {
        let output = self.local_authoring_output(node)?;
        CarrierEnvelope::preflight_local(
            node.id(),
            proposal.encode().map_err(|e| e.to_string())?.len(),
        )
        .map_err(|e| e.to_string())?;
        let Ok(prepared) = node.prepare_slot_proposal(proposal, &output.binding) else {
            return Ok(None);
        };
        let sequence = self.reserve_carrier(
            prepared.unsigned(),
            store::AgreementCarrierEvidence::Proposal {
                proposal: proposal.clone(),
            },
            prepared.dag(),
        )?;
        let Some(vertex) = prepared.author().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        self.complete_carrier(sequence, vertex).map(Some)
    }

    /// Reserves, signs and completes an elected view using exact current store policy.
    /// # Errors
    /// Rejects stale owners, mismatched Nodes, invalid evidence and durable conflicts.
    pub fn author_view(
        &mut self,
        candidate: &validator::SlotAgreementViewCandidate,
        node: &mut net::Node,
    ) -> Result<Option<AuthoredCarrier>, String> {
        let output = self.local_authoring_output(node)?;
        CarrierEnvelope::preflight_local(
            node.id(),
            candidate
                .bound_lineage_len(node.id(), &self.set)
                .map_err(|e| e.to_string())?,
        )
        .map_err(|e| e.to_string())?;
        let Ok(prepared) = node.prepare_slot_view(candidate, &output.binding) else {
            return Ok(None);
        };
        let lineage = candidate
            .clone()
            .bind_carrier(prepared.unsigned().id().map_err(|e| e.to_string())?);
        let sequence = self.reserve_carrier(
            prepared.unsigned(),
            store::AgreementCarrierEvidence::View { lineage },
            prepared.dag(),
        )?;
        let Some(vertex) = prepared.author().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        self.complete_carrier(sequence, vertex).map(Some)
    }

    fn local_authoring_output(
        &mut self,
        node: &net::Node,
    ) -> Result<SlotAgreementDriverOutput, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before carrier signing".into());
        }
        let output = self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        if !node.matches_authoring_context(
            output.binding.tip(),
            &self.set,
            &self.validator_id,
            &self.private_key,
        ) {
            return Err(
                "Node differs from pinned agreement identity, chain, epoch, set or key".into(),
            );
        }
        Ok(output)
    }

    /// Durably reserves and authors a current POL candidate, never historical evidence.
    /// Returns `None` for stale digests or unavailable local evidence; never publishes.
    /// # Errors
    /// Rejects stale/uncertain owners, pinned Node mismatches, codec and authoring failures.
    pub fn author_pol(
        &mut self,
        digest: [u8; 32],
        node: &mut net::Node,
    ) -> Result<Option<AuthoredCarrier>, String> {
        self.author_aggregate(digest, node, AggregateKind::Pol)
    }

    /// Durably reserves and authors a current final candidate without publishing it.
    /// Returns `None` for stale digests or unavailable local evidence.
    /// # Errors
    /// Rejects stale/uncertain owners, pinned Node mismatches, codec and authoring failures.
    pub fn author_final_proof(
        &mut self,
        digest: [u8; 32],
        node: &mut net::Node,
    ) -> Result<Option<AuthoredCarrier>, String> {
        self.author_aggregate(digest, node, AggregateKind::Final)
    }

    fn author_aggregate(
        &mut self,
        digest: [u8; 32],
        node: &mut net::Node,
        kind: AggregateKind,
    ) -> Result<Option<AuthoredCarrier>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before carrier signing".into());
        }
        let output = match self.driver.output() {
            Ok(output) => output,
            Err(error) => {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                return Err(error.to_string());
            }
        };
        if !node.matches_authoring_context(
            output.binding.tip(),
            &self.set,
            &self.validator_id,
            &self.private_key,
        ) {
            return Err(
                "Node differs from pinned agreement identity, chain, epoch, set or key".into(),
            );
        }
        let mut selected = None;
        for candidate in output.candidates {
            match (kind, candidate) {
                (AggregateKind::Pol, SlotAgreementCarrierCandidate::PendingPol(candidate))
                    if candidate.digest() == digest =>
                {
                    selected = Some(PendingIntent::Pol { candidate, digest });
                    break;
                }
                (AggregateKind::Final, SlotAgreementCarrierCandidate::PendingFinalProof(proof))
                    if proof.digest(&self.set).map_err(|e| e.to_string())? == digest =>
                {
                    selected = Some(PendingIntent::FinalProof { proof, digest });
                    break;
                }
                _ => {}
            }
        }
        let Some(intent) = selected else {
            return Ok(None);
        };
        CarrierEnvelope::preflight_aggregate(node.id(), &intent, &self.set)
            .map_err(|e| e.to_string())?;
        let prepared = match &intent {
            PendingIntent::Pol { candidate, .. } => {
                node.prepare_slot_pol(candidate, &output.binding)
            }
            PendingIntent::FinalProof { proof, .. } => {
                node.prepare_slot_final(proof, &output.binding)
            }
            _ => unreachable!("selected only aggregate candidates"),
        };
        let Ok(prepared) = prepared else {
            return Ok(None);
        };
        let unsigned = prepared.unsigned().clone();
        let evidence = match &intent {
            PendingIntent::Pol { candidate, .. } => store::AgreementCarrierEvidence::Pol {
                lineage: candidate
                    .clone()
                    .bind_carrier(unsigned.id().map_err(|e| e.to_string())?),
            },
            PendingIntent::FinalProof { proof, .. } => store::AgreementCarrierEvidence::Final {
                proof: proof.clone(),
            },
            _ => unreachable!("selected only aggregate candidates"),
        };
        let reservation_sequence = self.reserve_carrier(&unsigned, evidence, prepared.dag())?;
        let Some(vertex) = prepared.author().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        self.complete_carrier(reservation_sequence, vertex)
            .map(Some)
    }

    /// Authors one stable durable vote intent, never arbitrary payloads or all history.
    ///
    /// Returns `None` for inactive/stale intents or unavailable local evidence. Nil
    /// remains explicitly unsupported. This does not activate any live wiring.
    /// Exact current prospective statements reuse durable reservations after recovery.
    /// Changed reference selection is rejected; historical-context resume is unsupported.
    /// # Errors
    /// Rejects recovery-required/stale owners, unknown IDs, Node context/key mismatch,
    /// codec failures and existing Node signing/insertion failures.
    pub fn author_vote(
        &mut self,
        intent_id: [u8; 32],
        node: &mut net::Node,
    ) -> Result<Option<AuthoredVote>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before carrier signing".into());
        }
        // Revalidate ownership and exact durable obligation rather than trusting caches.
        let output = match self.driver.output() {
            Ok(output) => output,
            Err(error) => {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                return Err(error.to_string());
            }
        };
        let history = match self.driver.signing_outbox() {
            Ok(history) => history,
            Err(error) => {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                return Err(error.to_string());
            }
        };
        let intent = history
            .iter()
            .find(|intent| intent.id == intent_id)
            .ok_or("unknown durable vote intent ID")?;
        if matches!(
            intent.prerequisite,
            AgreementSigningPrerequisite::UnsupportedNil
        ) {
            return Err("nil carrier is unsupported".into());
        }
        if !output.authorable_vote_ids.contains(&intent_id) {
            return Ok(None);
        }
        if !node.matches_authoring_context(
            &intent.agreement.context,
            &self.set,
            &self.validator_id,
            &self.private_key,
        ) {
            return Err(
                "Node differs from pinned agreement identity, chain, epoch, set or key".into(),
            );
        }
        validate_intent_lineage(intent)?;
        let pending = self
            .pending
            .iter()
            .find_map(|pending| match pending {
                PendingIntent::Vote {
                    payload,
                    digest,
                    lineage,
                } if payload.vote == intent.vote => Some((payload, digest, lineage)),
                _ => None,
            })
            .ok_or("durable vote intent unavailable in reconstructed history")?;
        let (payload, digest, lineage) = pending;
        let AgreementSigningPrerequisite::Carrier(prerequisite) = &intent.prerequisite else {
            return Err("nil carrier is unsupported".into());
        };
        if payload.prerequisite != *prerequisite || intent.lineage.as_ref() != Some(lineage) {
            return Err("reconstructed vote differs from durable intent".into());
        }
        payload
            .verify(&intent.agreement.context, &self.set)
            .map_err(|e| e.to_string())?;
        if payload.digest(&self.set).map_err(|e| e.to_string())? != *digest {
            return Err("reconstructed vote digest mismatch".into());
        }
        CarrierEnvelope::preflight_vote(node.id(), payload, lineage, &self.set)
            .map_err(|e| e.to_string())?;
        // WAL authentication does not authenticate this Node's actual selected cone.
        // Include siblings outside the lineage and share the full vote-inspection budget.
        let unsigned = match node.prospective_slot_vote(lineage, payload, &output.binding) {
            Ok(unsigned) => unsigned,
            Err(_) => return Ok(None),
        };
        let payload = payload.clone();
        let lineage = lineage.clone();
        let reservation_sequence = self.reserve_carrier(
            &unsigned,
            store::AgreementCarrierEvidence::Vote {
                lineage: lineage.clone(),
                payload: payload.clone(),
            },
            node.dag(),
        )?;
        let prepared = node
            .prepare_reserved_slot_vote(&unsigned, &lineage, &payload, &output.binding)
            .map_err(|e| e.to_string())?;
        let Some(vertex) = prepared.author().map_err(|e| e.to_string())? else {
            return Ok(None);
        };
        self.complete_carrier(reservation_sequence, vertex)
            .map(Some)
    }

    /// Explicitly authorizes and durably publishes advisory support for one exact future view.
    /// Retrying a completed, still-future target returns its immutable publication without signing.
    /// Historical publications remain available through `completed_view_requests`.
    /// # Errors
    /// Rejects inactive targets, key mismatch, stale ownership and uncertain durability.
    pub fn author_view_request(
        &mut self,
        target: validator::slot_agreement::AgreementView,
    ) -> Result<validator::SlotAgreementViewRequest, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before request signing".into());
        }
        let output = self.driver.output().map_err(|e| e.to_string())?;
        let reservations = self
            .driver
            .view_request_reservations()
            .map_err(|e| e.to_string())?;
        let existing = reservations
            .iter()
            .find(|r| r.agreement.context == *output.binding.tip() && r.target_view == target);
        if output
            .transition
            .as_ref()
            .is_some_and(|t| t.decision.is_some() || target <= t.view)
            || target.0 == 0
        {
            return Err("request target is not a future undecided view".into());
        }
        if let Some(message) = existing.and_then(|reservation| reservation.message.as_ref()) {
            return Ok(message.clone());
        }
        // Validate the pinned key before authorizing or invoking the signer.
        let bootstrap = AuthenticatedSlotAgreementBootstrap {
            agreement: store::SlotAgreementBootstrap {
                context: output.binding.tip().clone(),
                set: self.set.clone(),
                local_validator: self.validator_id.clone(),
            },
            predecessor: None,
            order: Vec::new(),
            vertices: Vec::new(),
        };
        if checked_key(&bootstrap, &self.private_key)?
            != (self.key_id.clone(), self.public_key.clone())
        {
            return Err("view request signing key mismatch".into());
        }
        let reservation_sequence = if let Some(reservation) = existing {
            let agreement = &reservation.agreement;
            if agreement.context != bootstrap.agreement.context
                || agreement.set != bootstrap.agreement.set
                || agreement.local_validator != bootstrap.agreement.local_validator
            {
                return Err("view request authorization identity mismatch".into());
            }
            reservation.sequence
        } else {
            self.apply(AuthenticatedSlotAgreementRequest::ReserveViewRequest {
                target_view: target,
            })?;
            self.driver.sequence()
        };
        let bytes = validator::SlotAgreementViewRequest::signing_payload(
            output.binding.tip(),
            target,
            &self.set,
        )
        .map_err(|e| e.to_string())?;
        let signature = Ed25519Scheme
            .sign(&self.private_key, &bytes)
            .map_err(|e| e.to_string())?;
        let message = validator::SlotAgreementViewRequest::new(
            output.binding.tip().clone(),
            target,
            ValidatorSignature {
                validator_id: self.validator_id.clone(),
                key_id: self.key_id.clone(),
                signature,
            },
            &self.set,
        )
        .map_err(|e| e.to_string())?;
        message
            .verify(output.binding.tip(), &self.set)
            .map_err(|e| e.to_string())?;
        self.apply(AuthenticatedSlotAgreementRequest::CompleteViewRequest {
            reservation_sequence,
            message: message.clone(),
        })?;
        Ok(message)
    }

    /// Returns exact durable signed request publications, including historical slots.
    /// # Errors
    /// Rejects uncertain or stale owners and invalid durable evidence.
    pub fn completed_view_requests(
        &self,
    ) -> Result<Vec<validator::SlotAgreementViewRequest>, String> {
        self.driver
            .view_request_reservations()
            .map(|items| items.into_iter().filter_map(|r| r.message).collect())
            .map_err(|e| e.to_string())
    }

    /// Exports volatile current-slot support in target/signer order; recovery starts empty.
    /// Only complete entry certificates are durable, not this rebroadcast collection.
    /// # Errors
    /// Rejects uncertain or stale owners and invalid retained evidence.
    pub fn observed_view_requests(
        &self,
    ) -> Result<Vec<validator::SlotAgreementViewRequest>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before request export".into());
        }
        let output = self.driver.output().map_err(|e| e.to_string())?;
        let mut requests = Vec::new();
        for request in &self.view_requests {
            if request.context() == output.binding.tip() {
                request
                    .verify(output.binding.tip(), &self.set)
                    .map_err(|e| e.to_string())?;
                requests.push(request.clone());
            }
        }
        requests.sort_by(|a, b| {
            (a.target_view(), &a.signature().validator_id)
                .cmp(&(b.target_view(), &b.signature().validator_id))
        });
        Ok(requests)
    }

    /// Exports the latest current-slot entry certificate, including after recovery.
    /// # Errors
    /// Rejects stale or uncertain owners and invalid durable evidence.
    pub fn entered_view_certificate(
        &self,
    ) -> Result<Option<Vec<validator::SlotAgreementViewRequest>>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before certificate export".into());
        }
        self.driver
            .entered_view_certificate()
            .map_err(|e| e.to_string())
    }

    /// Authenticates a complete certificate and durably enters only an active future view.
    /// Obsolete certificates are fully validated but never reopen voting phases.
    /// # Errors
    /// Rejects malformed certificates, stale ownership and uncertain durability.
    pub fn receive_view_certificate(
        &mut self,
        requests: Vec<validator::SlotAgreementViewRequest>,
    ) -> Result<(), String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before certificate receipt".into());
        }
        let output = self.driver.output().map_err(|e| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            e.to_string()
        })?;
        let target = validator::slot_agreement::SlotAgreement::verify_view_requests(
            output.binding.tip(),
            &self.set,
            &requests,
        )
        .map_err(|e| e.to_string())?;
        if output
            .transition
            .as_ref()
            .is_some_and(|t| t.decision.is_some() || target <= t.view)
        {
            return Ok(());
        }
        self.apply(AuthenticatedSlotAgreementRequest::EnterRequestedView { requests })
    }

    /// Collects bounded volatile latest-per-signer support; only a full entry is journaled.
    /// Partial support is lost on recovery and must be redelivered. Authenticated obsolete,
    /// late and decided-slot support does not change phase state or consume WAL capacity.
    /// # Errors
    /// Rejects invalid evidence, stale ownership and uncertain durability.
    pub fn receive_view_request(
        &mut self,
        message: validator::SlotAgreementViewRequest,
    ) -> Result<(), String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before request receipt".into());
        }
        // Recheck ownership even for duplicates and late support before touching the
        // volatile collection. Quorum entry independently rechecks it during apply.
        let output = self.driver.output().map_err(|e| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            e.to_string()
        })?;
        message
            .verify(output.binding.tip(), &self.set)
            .map_err(|e| e.to_string())?;
        self.view_requests
            .retain(|r| r.context() == output.binding.tip());
        let target = message.target_view();
        if output
            .transition
            .as_ref()
            .is_some_and(|t| t.decision.is_some() || target <= t.view)
        {
            return Ok(());
        }
        if let Some(old) = self
            .view_requests
            .iter_mut()
            .find(|r| r.signature().validator_id == message.signature().validator_id)
        {
            if old.target_view() >= target {
                return Ok(());
            }
            *old = message;
        } else {
            if self.view_requests.len() >= self.set.validators.len() {
                return Err("view request signer bound exceeded".into());
            }
            self.view_requests.push(message);
        }
        let mut requests: Vec<_> = self
            .view_requests
            .iter()
            .filter(|r| r.target_view() == target)
            .cloned()
            .collect();
        if requests.len() >= self.set.quorum_size() {
            requests.sort_by(|a, b| a.signature().validator_id.cmp(&b.signature().validator_id));
            self.apply(AuthenticatedSlotAgreementRequest::EnterRequestedView { requests })?;
        }
        Ok(())
    }

    /// Signs a current durable nil obligation and persists its exact publication before release.
    /// The intent itself is the pre-sign lock; no Node or fabricated DAG carrier is used.
    /// Returns `None` for known nonnil or inactive intents. Completed publications are
    /// retrieved separately, including after recovery, without signing again.
    /// # Errors
    /// Rejects unknown IDs, stale owners, pinned-key mismatch and persistence failures.
    pub fn author_nil_vote(
        &mut self,
        intent_id: [u8; 32],
    ) -> Result<Option<validator::SlotAgreementNilVote>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before nil signing".into());
        }
        let output = self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        let history = self.driver.signing_outbox().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        let intent = history
            .iter()
            .find(|intent| intent.id == intent_id)
            .ok_or("unknown durable nil vote intent ID")?;
        if !output.authorable_vote_ids.contains(&intent_id)
            || intent.vote.value != AgreementValue::Nil
            || intent.prerequisite != AgreementSigningPrerequisite::UnsupportedNil
        {
            return Ok(None);
        }
        if self
            .completed_nil_votes()?
            .iter()
            .any(|done| done.intent_id == intent_id)
        {
            return Ok(None);
        }
        if intent.agreement.context != *output.binding.tip()
            || intent.vote.context != intent.agreement.context
            || intent.agreement.set != self.set
            || intent.agreement.local_validator != self.validator_id
        {
            return Err("nil signing identity or context mismatch".into());
        }
        validate_intent_lineage(intent)?;
        let bootstrap = AuthenticatedSlotAgreementBootstrap {
            agreement: intent.agreement.clone(),
            predecessor: None,
            order: Vec::new(),
            vertices: Vec::new(),
        };
        if checked_key(&bootstrap, &self.private_key)?
            != (self.key_id.clone(), self.public_key.clone())
        {
            return Err("nil signing active key mismatch".into());
        }
        let bytes = intent
            .vote
            .signing_payload(&self.set)
            .map_err(|e| e.to_string())?;
        let signature = Ed25519Scheme
            .sign(&self.private_key, &bytes)
            .map_err(|e| e.to_string())?;
        let message = validator::SlotAgreementNilVote::new(
            intent.vote.clone(),
            ValidatorSignature {
                validator_id: self.validator_id.clone(),
                key_id: self.key_id.clone(),
                signature,
            },
            &self.set,
        )
        .map_err(|e| e.to_string())?;
        message
            .verify(&intent.agreement.context, &self.set)
            .map_err(|e| e.to_string())?;
        self.apply(AuthenticatedSlotAgreementRequest::CompleteNilVote {
            intent_id,
            message: message.clone(),
        })?;
        Ok(Some(message))
    }

    /// Retrieves exact durable nil publications across historical views and slots, without signing.
    /// # Errors
    /// Stale owners, uncertain writes and invalid durable evidence require recovery.
    pub fn completed_nil_votes(&mut self) -> Result<Vec<store::AgreementCompletedNilVote>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before publication retrieval".into());
        }
        self.driver.completed_nil_votes().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })
    }

    /// Receives carrier-free nil evidence through the authenticated durable request path.
    /// This neither advances the view nor applies a decision.
    /// # Errors
    /// Invalid evidence or driver failures require recovery before further operations.
    pub fn receive_nil_vote(
        &mut self,
        message: validator::SlotAgreementNilVote,
    ) -> Result<(), String> {
        self.apply(AuthenticatedSlotAgreementRequest::ObserveNilVote { message })
    }

    fn complete_carrier(
        &mut self,
        reservation_sequence: u64,
        signed: validator::Vertex,
    ) -> Result<AuthoredCarrier, String> {
        let result = (|| {
            let id = signed.id().map_err(|e| e.to_string())?;
            if let Some(publication) = self
                .completed_carriers()?
                .into_iter()
                .find(|publication| publication.vertex == signed)
            {
                return Ok(publication);
            }

            let sequence = self
                .driver
                .sequence()
                .checked_add(1)
                .ok_or("agreement sequence exhausted")?;
            self.driver
                .apply(
                    sequence,
                    AuthenticatedSlotAgreementRequest::CompleteCarrier {
                        reservation_sequence,
                        signed,
                    },
                )
                .map_err(|e| e.to_string())?;
            self.completed_carriers()?
                .into_iter()
                .find(|publication| publication.vertex.id().ok().as_ref() == Some(&id))
                .ok_or_else(|| "completed carrier unavailable after durable append".to_string())
        })();
        if result.is_err() {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        }
        result
    }

    /// Retrieves exact durable signed publications, including historical slots.
    /// Never signs, consults a Node, or accepts caller-supplied evidence.
    /// # Errors
    /// Stale owners, uncertain writes and reconstruction errors require recovery.
    pub fn completed_carriers(&mut self) -> Result<Vec<AuthoredCarrier>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before publication retrieval".into());
        }
        let result: Result<Vec<AuthoredCarrier>, String> = (|| {
            self.driver
                .completed_carriers()
                .map_err(|e| e.to_string())?
                .into_iter()
                .map(|completed| {
                    let set = &completed.reservation.agreement.set;
                    let carrier = completed.signed.id().map_err(|e| e.to_string())?;
                    let payload = match completed.reservation.evidence {
                        store::AgreementCarrierEvidence::Proposal { proposal } => {
                            CarrierPayload::Proposal(proposal)
                        }
                        store::AgreementCarrierEvidence::View { lineage } => {
                            CarrierPayload::View(lineage)
                        }
                        store::AgreementCarrierEvidence::Vote { lineage, payload } => {
                            CarrierPayload::Vote { lineage, payload }
                        }
                        store::AgreementCarrierEvidence::Pol { lineage } => {
                            CarrierPayload::Pol(lineage)
                        }
                        store::AgreementCarrierEvidence::Final { proof } => {
                            CarrierPayload::Final(proof)
                        }
                    };
                    let envelope = CarrierEnvelope::from_publication(
                        carrier,
                        payload,
                        completed.signed.payload_hash,
                        set,
                    )
                    .map_err(|e| e.to_string())?;
                    Ok(AuthoredCarrier {
                        vertex: completed.signed,
                        envelope,
                    })
                })
                .collect()
        })();
        if result.is_err() {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        }
        result
    }

    fn reserve_carrier(
        &mut self,
        unsigned: &validator::Vertex,
        evidence: store::AgreementCarrierEvidence,
        dag: &validator::Dag,
    ) -> Result<u64, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before carrier signing".into());
        }
        let reservations = self.driver.reserved_carriers().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        if let Some(reserved) = reservations.iter().find(|reserved| {
            reserved.unsigned.round == unsigned.round && reserved.unsigned.author == unsigned.author
        }) {
            if reserved.unsigned != *unsigned
                || std::mem::discriminant(&reserved.evidence) != std::mem::discriminant(&evidence)
            {
                return Err("reserved carrier differs from current prospective statement".into());
            }
            Ok(reserved.sequence)
        } else {
            let mut todo = unsigned.references.clone();
            let mut vertices = Vec::new();
            let mut seen = std::collections::BTreeSet::new();
            let mut edges = 0usize;
            while let Some(id) = todo.pop() {
                if !seen.insert((id.round, id.author.clone(), id.digest)) {
                    continue;
                }
                if seen.len() > 4096 {
                    return Err("carrier dependency count exceeds reservation bound".into());
                }
                let vertex = dag
                    .get(id.round, &id.author)
                    .ok_or("missing carrier reservation dependency")?;
                if vertex.id().map_err(|e| e.to_string())? != id {
                    return Err("carrier reservation dependency ID mismatch".into());
                }
                edges = edges.saturating_add(vertex.references.len());
                if edges > 65536 {
                    return Err("carrier dependency edges exceed reservation bound".into());
                }
                todo.extend(vertex.references.iter().cloned());
                vertices.push(vertex.clone());
            }
            let sequence = self
                .driver
                .sequence()
                .checked_add(1)
                .ok_or("agreement sequence exhausted")?;
            // Do not consume reducer output: reservation preserves the transition
            // and must not rebuild or shift the pending candidate selection.
            if let Err(error) = self.driver.apply(
                sequence,
                AuthenticatedSlotAgreementRequest::ReserveCarrier {
                    evidence,
                    unsigned: unsigned.clone(),
                    vertices,
                },
            ) {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                return Err(error.to_string());
            }
            Ok(sequence)
        }
    }

    /// Validates the pinned active key before creating a WAL. Never called by live startup.
    pub fn begin(
        store: &Store,
        bootstrap: AuthenticatedSlotAgreementBootstrap,
        membership: &Membership,
        index: usize,
    ) -> Result<Self, String> {
        let private_key = membership_key(&bootstrap, membership, index)?;
        let key = checked_key(&bootstrap, &private_key)?;
        let set = bootstrap.agreement.set.clone();
        let validator_id = bootstrap.agreement.local_validator.clone();
        let session = store
            .begin_authenticated_slot_agreement(bootstrap)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            driver: SlotAgreementDriver::new(session),
            set,
            validator_id,
            key_id: key.0,
            public_key: key.1,
            private_key,
            pending: Vec::new(),
            history: Vec::new(),
            pacemaker: None,
            view_requests: Vec::new(),
            readiness: Readiness::DisabledMissingCausalReadinessAndTransport,
        })
    }

    /// Reconstructs full durable signing history; repeated recovery may sign identical bytes.
    pub fn recover(
        store: &Store,
        bootstrap: AuthenticatedSlotAgreementBootstrap,
        membership: &Membership,
        index: usize,
    ) -> Result<Self, String> {
        let private_key = membership_key(&bootstrap, membership, index)?;
        let key = checked_key(&bootstrap, &private_key)?;
        let set = bootstrap.agreement.set.clone();
        let validator_id = bootstrap.agreement.local_validator.clone();
        let session = store
            .recover_authenticated_slot_agreement(bootstrap)
            .map_err(|e| e.to_string())?;
        let mut adapter = Self {
            driver: SlotAgreementDriver::new(session),
            set,
            validator_id,
            key_id: key.0,
            public_key: key.1,
            private_key,
            pending: Vec::new(),
            history: Vec::new(),
            pacemaker: None,
            view_requests: Vec::new(),
            readiness: Readiness::RecoveryRequiredHistoricalIntentsUnavailable,
        };
        let output = adapter.driver.output();
        adapter.consume_durable_result(output, None)?;
        Ok(adapter)
    }

    /// Returns the activation/recovery barrier, never transport authorization.
    pub fn readiness(&self) -> Readiness {
        self.readiness
    }

    /// Original contexts and stable IDs retained across slots, including carrier-free nil.
    /// No acknowledgement or removal is supported; this is not send authorization.
    pub fn signing_history(&self) -> &[AgreementSigningIntent] {
        &self.history
    }

    /// Retained across later observations; reading never signs or releases anything.
    pub fn pending(&self) -> &[PendingIntent] {
        &self.pending
    }

    /// Receives untrusted owned evidence through the existing authenticated WAL path.
    /// Envelope construction, caller-set decoding and external inspection grant no authority:
    /// the session reauthenticates with its pinned binding and supplied/retained signed DAG.
    /// This does not activate transport, carrier authoring or decision application.
    /// # Errors
    /// Returns existing apply errors and requires recovery after any driver/output failure.
    pub fn receive_envelope(
        &mut self,
        envelope: CarrierEnvelope,
        vertices: Vec<validator::Vertex>,
    ) -> Result<(), String> {
        self.apply(envelope.into_request(vertices).map_err(|e| e.to_string())?)
    }

    /// Accepts only authenticated requests and reconstructs the durable signing outbox.
    /// Any driver/output failure requires recovery, even when persistence may have succeeded.
    pub fn apply(&mut self, request: AuthenticatedSlotAgreementRequest) -> Result<(), String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before further signing".into());
        }
        let sequence = self
            .driver
            .sequence()
            .checked_add(1)
            .ok_or("agreement sequence exhausted")?;
        let result = self.driver.apply(sequence, request);
        self.consume_durable_result(result, None)
    }

    fn consume_durable_result(
        &mut self,
        result: Result<SlotAgreementDriverOutput, StoreError>,
        _prerequisite: Option<VertexId>,
    ) -> Result<(), String> {
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                return Err(error.to_string());
            }
        };
        // A post-durability encoding/signing failure must also block continued operation.
        self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        let history = self.driver.signing_outbox().map_err(|e| e.to_string())?;
        self.reconstruct_history(output, history)
    }

    fn reconstruct_history(
        &mut self,
        output: SlotAgreementDriverOutput,
        history: Vec<AgreementSigningIntent>,
    ) -> Result<(), String> {
        self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        self.view_requests
            .retain(|r| r.context() == output.binding.tip());
        // Validate every historical identity before producing any signature. Nil has
        // no DAG carrier and is signed only by the explicit durable publication path.
        for intent in &history {
            if intent.agreement.set != self.set
                || intent.agreement.local_validator != self.validator_id
                || intent.vote.context != intent.agreement.context
            {
                return Err("historical signing identity or context mismatch".into());
            }
            let bootstrap = AuthenticatedSlotAgreementBootstrap {
                agreement: intent.agreement.clone(),
                predecessor: None,
                order: Vec::new(),
                vertices: Vec::new(),
            };
            let key = checked_key(&bootstrap, &self.private_key)?;
            if key != (self.key_id.clone(), self.public_key.clone()) {
                return Err("historical active key mismatch".into());
            }
            validate_intent_lineage(intent)?;
            match (&intent.prerequisite, &intent.vote.value) {
                (AgreementSigningPrerequisite::UnsupportedNil, AgreementValue::Nil) => {}
                (AgreementSigningPrerequisite::Carrier(_), AgreementValue::Nil)
                | (AgreementSigningPrerequisite::UnsupportedNil, _) => {
                    return Err("historical prerequisite mismatch".into());
                }
                (AgreementSigningPrerequisite::Carrier(_), _) => {
                    intent
                        .vote
                        .signing_payload(&intent.agreement.set)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        for intent in history {
            if self.history.iter().any(|old| old.id == intent.id) {
                continue;
            }
            let pending = match &intent.prerequisite {
                AgreementSigningPrerequisite::UnsupportedNil => PendingIntent::UnsupportedNil {
                    intent: intent.clone(),
                },
                AgreementSigningPrerequisite::Carrier(prerequisite) => {
                    let set = &intent.agreement.set;
                    let bytes = intent
                        .vote
                        .signing_payload(set)
                        .map_err(|e| e.to_string())?;
                    let signature = Ed25519Scheme
                        .sign(&self.private_key, &bytes)
                        .map_err(|e| e.to_string())?;
                    verify_signature(ALG_ED25519, &self.public_key, &bytes, &signature)
                        .map_err(|e| e.to_string())?;
                    let payload = SlotAgreementVotePayload {
                        vote: intent.vote.clone(),
                        signature: ValidatorSignature {
                            validator_id: intent.agreement.local_validator.clone(),
                            key_id: self.key_id.clone(),
                            signature,
                        },
                        prerequisite: prerequisite.clone(),
                    };
                    payload
                        .verify(&intent.agreement.context, set)
                        .map_err(|e| e.to_string())?;
                    let digest = payload.digest(set).map_err(|e| e.to_string())?;
                    PendingIntent::Vote {
                        payload,
                        digest,
                        lineage: intent
                            .lineage
                            .clone()
                            .ok_or("historical vote lacks lineage")?,
                    }
                }
            };
            self.pending.push(pending);
            self.history.push(intent);
        }
        for candidate in output.candidates {
            let intent = match candidate {
                SlotAgreementCarrierCandidate::PendingPol(candidate) => {
                    let digest = candidate.digest();
                    PendingIntent::Pol { candidate, digest }
                }
                SlotAgreementCarrierCandidate::PendingFinalProof(proof) => {
                    let digest = proof.digest(&self.set).map_err(|e| e.to_string())?;
                    PendingIntent::FinalProof { proof, digest }
                }
            };
            let duplicate = self.pending.iter().any(|old| match (old, &intent) {
                (PendingIntent::Pol { digest: a, .. }, PendingIntent::Pol { digest: b, .. })
                | (
                    PendingIntent::FinalProof { digest: a, .. },
                    PendingIntent::FinalProof { digest: b, .. },
                ) => a == b,
                _ => false,
            });
            if !duplicate {
                self.pending.push(intent);
            }
        }
        self.readiness = Readiness::DisabledMissingCausalReadinessAndTransport;
        Ok(())
    }
}

fn validate_intent_lineage(intent: &AgreementSigningIntent) -> Result<(), String> {
    use validator::slot_agreement::AgreementPhase;

    let AgreementValue::Decision(decision) = &intent.vote.value else {
        if intent.lineage.is_some() {
            return Err("historical nil vote has lineage".into());
        }
        return Ok(());
    };
    let lineage = intent
        .lineage
        .as_ref()
        .ok_or("historical vote lacks lineage")?;
    let selected = lineage
        .entries
        .last()
        .ok_or("historical lineage is empty")?;
    if selected.view != intent.vote.view || selected.proposal.decision != *decision {
        return Err("historical selected view or decision mismatch".into());
    }
    for entry in &lineage.entries {
        if entry
            .pol
            .as_ref()
            .is_some_and(|pol| pol.certificate.vote.context != intent.vote.context)
        {
            return Err("historical POL context mismatch".into());
        }
    }
    let prerequisite = match intent.vote.phase {
        AgreementPhase::Prevote => &selected.view_carrier,
        AgreementPhase::Precommit => {
            &selected
                .pol
                .as_ref()
                .ok_or("historical precommit lacks selected POL")?
                .carrier
        }
    };
    if !matches!(&intent.prerequisite, AgreementSigningPrerequisite::Carrier(carrier) if carrier == prerequisite)
    {
        return Err("historical lineage prerequisite mismatch".into());
    }
    // Structural/codec validation only: the durable session authenticated this exact evidence.
    lineage
        .encode(&intent.agreement.set)
        .map_err(|e| e.to_string())?;
    Ok(())
}

fn membership_key(
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    membership: &Membership,
    index: usize,
) -> Result<Vec<u8>, String> {
    let identity = membership
        .consensus
        .get(index)
        .ok_or("no consensus key for this node")?;
    if membership.set != bootstrap.agreement.set
        || identity.id != bootstrap.agreement.local_validator
    {
        return Err("membership differs from pinned agreement identity or set".into());
    }
    Ok(identity.private_key.clone())
}

fn checked_key(
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    private: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let agreement = &bootstrap.agreement;
    let validator = agreement
        .set
        .validator(&agreement.local_validator)
        .ok_or("local validator absent from pinned set")?;
    let key = validator
        .active_key(agreement.context.epoch())
        .map_err(|e| e.to_string())?;
    registry::require_signature_algorithm(key.algorithm_id).map_err(|e| e.to_string())?;
    if key.algorithm_id != ALG_ED25519 {
        return Err("live adapter supports only Ed25519 private keys".into());
    }
    if private.len() != 64 {
        return Err("invalid Ed25519 private key length".into());
    }
    let derived = Ed25519Scheme::public_key_from_seed(&private[..32]).map_err(|e| e.to_string())?;
    if private[32..] != derived || key.public_key != derived {
        return Err("private key does not match pinned active public key".into());
    }
    Ok((key.key_id.clone(), key.public_key.clone()))
}

/// The legacy node must not run on an authenticated signing root (including staged generations).
pub(super) fn disabled_guard(store: &Store) -> Result<(), String> {
    store.slot_decision_locks().map(|_| ()).map_err(|e| {
        format!("live agreement adapter is disabled; legacy root signing check failed: {e}")
    })
}

mod envelope;
pub mod pacemaker;
pub use envelope::{CarrierEnvelope, CarrierPayload, MAX_ENVELOPE_BYTES};

#[cfg(test)]
mod tests;
