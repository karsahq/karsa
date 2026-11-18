//! Inactive durable signing boundary with explicit local carrier authoring, never live transport.

use std::time::{Duration, Instant};

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
    retransmission: Option<Retransmission>,
    carrier_retransmission: Option<Retransmission>,
    // Partial remote support is never journaled and is lost on recovery.
    view_requests: Vec<validator::SlotAgreementViewRequest>,
}

// Volatile scheduling only: never retain durable messages or export authority here.
struct Retransmission {
    interval: Duration,
    last_poll: Option<Instant>,
    last_sent: Option<Instant>,
    cursor: usize,
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

/// Limits event-count replay work for explicit carrier export; recovery does not reset it.
const MAX_CARRIER_EXPORT_EVENTS: u64 = 4096;

/// Caps caller selection and duplicate-check work per scheduled carrier poll.
const MAX_CARRIER_RETRY_IDS: usize = 64;

impl Adapter {
    /// Loads local pre-sign header intents; not certificates or recovered execution state.
    /// # Errors
    /// Rejects stale/uncertain owners and corrupt or incompatible durable history.
    pub fn header_intents(&mut self) -> Result<Vec<store::AgreementHeaderIntent>, String> {
        self.ordering_snapshot()?;
        self.driver.header_intents().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })
    }

    /// Reserves the exact header durably before the offline finalizer invokes its signer.
    /// The genesis state root is caller-trusted; execution correctness is not checked here.
    /// # Errors
    /// Rejects conflicting intent, unapplied boundaries, stale owners and publication failure.
    pub fn reserve_header(
        &mut self,
        anchor: &validator::Header,
        header: &validator::Header,
        order_len: usize,
    ) -> Result<(), String> {
        self.ordering_snapshot()?;
        self.driver
            .reserve_header(anchor, header, order_len)
            .map_err(|error| {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                error.to_string()
            })
    }

    /// Loads verified completed header shares bound to durable pre-sign intents.
    /// # Errors
    /// Rejects stale ownership, corrupt journals and invalid signatures or history.
    pub fn header_shares(&mut self) -> Result<Vec<validator::Share>, String> {
        self.ordering_snapshot()?;
        self.driver.header_shares().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })
    }

    /// Persists a verified share before releasing it or collecting its quorum weight.
    /// # Errors
    /// Rejects invalid or conflicting shares, stale ownership and publication failure.
    pub fn reserve_header_share(
        &mut self,
        anchor: &validator::Header,
        share: &validator::Share,
    ) -> Result<(), String> {
        self.ordering_snapshot()?;
        self.driver
            .reserve_header_share(anchor, share)
            .map_err(|error| {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                error.to_string()
            })
    }

    /// Publishes caller-owned execution state and its consumed certified prefix together.
    /// The caller must ensure the state and transaction count were produced by exactly
    /// this consumer. No live state, finalizer, or RPC effects are published here.
    /// # Errors
    /// Rejects incompatible consumers, invalid state encoding, stale ownership or I/O errors.
    pub fn checkpoint_execution(
        &mut self,
        consumer: &mut OrderingConsumer,
        state: &exec::State,
        applied: u64,
    ) -> Result<(), String> {
        consumer.update(self.ordering_snapshot()?)?;
        let bytes = state.encode().map_err(|error| error.to_string())?;
        self.driver
            .put_execution_checkpoint(consumer.consumed_order(), applied, &bytes)
            .map_err(|error| {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                error.to_string()
            })
    }

    /// Restores state and consumed cursor only from the same local durable record.
    /// Missing checkpoints are explicit; callers must not silently substitute legacy state.
    /// This is local recovery, not authenticated snapshot join or finality authority.
    /// # Errors
    /// Rejects corrupt/incompatible checkpoints, undecodable state, and stale owners.
    pub fn restore_execution(
        &mut self,
    ) -> Result<Option<(OrderingConsumer, exec::State, u64)>, String> {
        let snapshot = self.ordering_snapshot()?;
        let restored = (|| {
            let Some(checkpoint) = self
                .driver
                .execution_checkpoint()
                .map_err(|error| error.to_string())?
            else {
                return Ok(None);
            };
            let state =
                exec::State::decode(checkpoint.state()).map_err(|error| error.to_string())?;
            if state.encode().map_err(|error| error.to_string())? != checkpoint.state() {
                return Err("execution checkpoint state is not canonical".into());
            }
            let consumer = OrderingConsumer::restore(snapshot, checkpoint.order())?;
            Ok(Some((consumer, state, checkpoint.applied())))
        })();
        if restored.is_err() {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        }
        restored
    }

    /// Exports only the applied certified prefix, never speculative legacy DAG order.
    /// A durable decision is excluded until an explicit durable `AdvanceSlot` request.
    /// This read neither advances slots nor executes transactions or mutates a live DAG.
    /// # Errors
    /// Rejects recovery-required or stale owners and invalid durable ordering evidence.
    pub fn ordering_snapshot(&mut self) -> Result<store::AgreementOrderingSnapshot, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before ordering export".into());
        }
        self.driver.ordering_snapshot().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })
    }

    /// Enables caller-selected carrier retries independently of control retries.
    /// Recovery disables this volatile schedule. No publication or evidence is cached.
    /// # Errors
    /// Rejects zero intervals and intervals greater than one day.
    pub fn configure_carrier_retransmission(&mut self, interval: Duration) -> Result<(), String> {
        if interval.is_zero() || interval > Duration::from_secs(86_400) {
            return Err(
                "carrier retransmission interval must be positive and at most one day".into(),
            );
        }
        self.carrier_retransmission = Some(Retransmission {
            interval,
            last_poll: None,
            last_sent: None,
            cursor: 0,
        });
        Ok(())
    }

    /// Exports at most one caller-selected durable carrier on each due poll.
    /// Up to 64 distinct IDs are visited in caller order with a volatile round-robin
    /// cursor. Callers must select current-slot publications and provide their full
    /// ancestry. An unavailable/invalid selected carrier returns an error without
    /// consuming the send deadline or cursor; this deliberately does not skip evidence.
    /// First export is immediate, missed intervals never cause catch-up bursts, and
    /// control retries have an independent cadence. Nothing is signed, persisted or sent.
    /// Durable freshness is checked even when disabled or not due. Like explicit export,
    /// this replays the WAL and is not suitable for a hot loop.
    /// # Errors
    /// Rejects stale/recovery-required owners, backwards time, oversized/duplicate ID
    /// lists, and any explicit carrier-export authentication, availability or size error.
    pub fn retransmit_carrier(
        &mut self,
        now: Instant,
        carriers: &[VertexId],
        available: &validator::Dag,
    ) -> Result<Option<net::wire::Message>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before carrier retransmission".into());
        }
        if self.driver.sequence() > MAX_CARRIER_EXPORT_EVENTS {
            return Err("carrier retransmission exceeds 4096 durable events".into());
        }
        self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        if carriers.len() > MAX_CARRIER_RETRY_IDS {
            return Err("carrier retransmission exceeds 64 selected IDs".into());
        }
        for (index, id) in carriers.iter().enumerate() {
            if carriers[..index].contains(id) {
                return Err("carrier retransmission contains duplicate IDs".into());
            }
        }
        let Some(schedule) = self.carrier_retransmission.as_mut() else {
            return Ok(None);
        };
        if schedule.last_poll.is_some_and(|last| now < last) {
            return Err("carrier retransmission time moved backwards".into());
        }
        schedule.last_poll = Some(now);
        if carriers.is_empty()
            || schedule
                .last_sent
                .is_some_and(|last| now.duration_since(last) < schedule.interval)
        {
            return Ok(None);
        }
        let index = schedule.cursor % carriers.len();
        let message = self.export_carrier(&carriers[index], available)?;
        let schedule = self
            .carrier_retransmission
            .as_mut()
            .expect("configured carrier retries");
        schedule.cursor = (index + 1) % carriers.len();
        schedule.last_sent = Some(now);
        Ok(Some(message))
    }

    /// Explicitly exports one selected durable carrier with its complete authenticated cone.
    /// This is a separate opt-in API, not a scheduled class: callers select an exact ID
    /// so multiple publications in one slot/view cannot silently hide one another.
    /// The caller DAG supplies availability only; a fresh, unpruned DAG reauthenticates
    /// every vertex and the envelope against the current durable binding. Nothing is
    /// signed, persisted, sent, or cached. Historical-slot publications fail inspection.
    ///
    /// Work is capped at 4096 WAL events before replay, 4096 cone vertices, 65536
    /// reference edges, and the wire codec's two-MiB payload limit. Store getters still
    /// read/replay the WAL; this is not a byte-bounded storage reader or a hot-loop API.
    /// # Errors
    /// Rejects stale/recovery-required owners, unknown/nonlocal publications, missing
    /// ancestors (including below a caller's pruning floor), invalid cones and bounds.
    pub fn export_carrier(
        &mut self,
        carrier: &VertexId,
        available: &validator::Dag,
    ) -> Result<net::wire::Message, String> {
        use std::collections::BTreeMap;

        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before carrier export".into());
        }
        // Limit replay work independently of the size of the caller's DAG.
        if self.driver.sequence() > MAX_CARRIER_EXPORT_EVENTS {
            return Err(
                "carrier export exceeds 4096 durable events; bounded store export is required"
                    .into(),
            );
        }
        let output = self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        let publication = self
            .completed_carriers()?
            .into_iter()
            .find(|p| p.envelope.carrier() == carrier)
            .ok_or("carrier export requires an exact completed local publication")?;
        if publication.vertex.author != self.validator_id {
            return Err("carrier export requires a local publication".into());
        }
        let envelope = publication
            .envelope
            .encode(&self.set)
            .map_err(|e| e.to_string())?;
        let mut size = 8usize + envelope.len();
        let mut edges = 0usize;
        let mut cone = BTreeMap::new();
        let mut pending = vec![carrier.clone()];
        while let Some(id) = pending.pop() {
            let key = (id.round, id.author.clone());
            if let Some((seen, _)) = cone.get(&key) {
                if seen != &id {
                    return Err("carrier cone contains conflicting vertex IDs".into());
                }
                continue;
            }

            let vertex = if &id == carrier {
                &publication.vertex
            } else {
                available
                    .get(id.round, &id.author)
                    .ok_or("carrier cone missing ancestor")?
            };
            charge_carrier_vertex(vertex, cone.len(), &mut edges, &mut size)?;
            if vertex.id().map_err(|e| e.to_string())? != id {
                return Err("carrier cone ancestor digest mismatch".into());
            }
            pending.extend(vertex.references.iter().cloned());
            cone.insert(key, (id, vertex.clone()));
        }
        let mut checked = validator::Dag::new(self.set.clone());
        checked.set_chain_id(publication.vertex.chain_id.clone());
        let mut vertices = Vec::with_capacity(cone.len());
        for (_, (id, vertex)) in cone {
            if vertex.chain_id != publication.vertex.chain_id {
                return Err("carrier cone chain mismatch".into());
            }
            if checked.insert(vertex.clone()).map_err(|e| e.to_string())? != id {
                return Err("carrier cone insertion mismatch".into());
            }
            vertices.push(vertex);
        }
        publication
            .envelope
            .inspect(&checked, &output.binding)
            .map_err(|e| e.to_string())?;
        let message = net::wire::Message::AgreementCarrier { envelope, vertices };
        net::wire::frame(&message, 0).map_err(|e| e.to_string())?;
        Ok(message)
    }

    /// Opts into control-only retransmission, resetting the volatile schedule.
    /// Recovery starts disabled; this does not activate live transport.
    /// # Errors
    /// Rejects zero intervals and intervals greater than one day.
    pub fn configure_retransmission(&mut self, interval: Duration) -> Result<(), String> {
        if interval.is_zero() || interval > Duration::from_secs(86_400) {
            return Err(
                "agreement retransmission interval must be positive and at most one day".into(),
            );
        }
        self.retransmission = Some(Retransmission {
            interval,
            last_poll: None,
            last_sent: None,
            cursor: 0,
        });
        Ok(())
    }

    /// Exports at most one durable control message per due poll, without signing or sending.
    /// The first poll is immediate; delayed polls never cause catch-up bursts. Empty polls
    /// still enforce monotonic time. No echo, persistence, or acknowledgement is performed.
    /// Durable getters replay the full WAL: this API is not recommended for a hot loop.
    /// Carriers use the separate explicit `export_carrier` API with caller DAG availability.
    /// # Errors
    /// Rejects stale/recovery-required owners, backwards time, invalid durable evidence,
    /// and any candidate exceeding the wire codec's bounds.
    pub fn retransmit(&mut self, now: Instant) -> Result<Option<net::wire::Message>, String> {
        use net::wire::Message;
        use validator::slot_agreement::{AgreementPhase, AgreementView};

        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before retransmission".into());
        }
        // Freshness must be checked even when disabled, empty, or not yet due.
        let output = self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        let Some(schedule) = self.retransmission.as_mut() else {
            return Ok(None);
        };
        if schedule.last_poll.is_some_and(|last| now < last) {
            return Err("agreement retransmission time moved backwards".into());
        }
        schedule.last_poll = Some(now);
        if schedule
            .last_sent
            .is_some_and(|last| now.duration_since(last) < schedule.interval)
        {
            return Ok(None);
        }

        let slot = output.binding.tip();
        let view = output
            .transition
            .as_ref()
            .map_or(AgreementView(0), |t| t.view);
        let decided = output
            .transition
            .as_ref()
            .is_some_and(|t| t.decision.is_some());
        // Fixed class positions preserve fairness even when a class appears or disappears.
        let mut candidates: [Option<Message>; 4] = std::array::from_fn(|_| None);
        if let Some(request) = self
            .completed_view_requests()?
            .into_iter()
            .filter(|r| r.context() == slot && r.signature().validator_id == self.validator_id)
            .max_by_key(|r| r.target_view())
        {
            candidates[0] = Some(Message::AgreementViewRequest(
                request.encode(&self.set).map_err(|e| e.to_string())?,
            ));
        }
        // An entered certificate remains exportable after a decision.
        if let Some(requests) = self.entered_view_certificate()? {
            let bodies = requests
                .iter()
                .map(|r| r.encode(&self.set))
                .collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?;
            candidates[1] = Some(Message::AgreementViewCertificate(bodies));
        }
        if !decided {
            for completed in self.completed_nil_votes()? {
                let message = completed.message;
                if message.vote().context != *slot
                    || message.vote().view != view
                    || message.signature().validator_id != self.validator_id
                {
                    continue;
                }
                let index = match message.vote().phase {
                    AgreementPhase::Prevote => 2,
                    AgreementPhase::Precommit => 3,
                };
                if candidates[index].is_none() {
                    candidates[index] = Some(Message::AgreementNilVote(
                        message.encode(&self.set).map_err(|e| e.to_string())?,
                    ));
                }
            }
        }
        // Validate every candidate, not just the selected class; never silently omit
        // durable evidence that cannot fit the transport's actual frame bounds.
        for candidate in candidates.iter().flatten() {
            net::wire::frame(candidate, 0).map_err(|e| {
                format!("agreement retransmission candidate exceeds wire bounds: {e}")
            })?;
        }
        let schedule = self
            .retransmission
            .as_mut()
            .expect("configured retransmission");
        for offset in 0..candidates.len() {
            let index = (schedule.cursor + offset) % candidates.len();
            if let Some(message) = candidates[index].take() {
                schedule.cursor = (index + 1) % candidates.len();
                schedule.last_sent = Some(now);
                return Ok(Some(message));
            }
        }
        Ok(None)
    }

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

    /// Explicitly echoes the largest exact future target with at least f+1 distinct signers.
    /// Availability is conditional on exact-target support and the existing 16-request cap.
    /// Remote support is volatile; completed local publications survive recovery. This does
    /// not reuse nil authority or promise to echo mixed-target support cumulatively.
    /// # Errors
    /// Rejects stale or uncertain ownership and failures in durable request publication.
    pub fn echo_view_request(
        &mut self,
    ) -> Result<Option<validator::SlotAgreementViewRequest>, String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before request echo".into());
        }
        let output = self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        if output
            .transition
            .as_ref()
            .is_some_and(|t| t.decision.is_some())
        {
            return Ok(None);
        }
        let completed = self.completed_view_requests()?;
        let local_highest = completed
            .iter()
            .filter(|r| r.context() == output.binding.tip())
            .map(|r| r.target_view())
            .max();
        let mut latest = std::collections::BTreeMap::new();
        for request in self.view_requests.iter().chain(&completed) {
            if request.context() != output.binding.tip() {
                continue;
            }
            request
                .verify(output.binding.tip(), &self.set)
                .map_err(|e| e.to_string())?;
            let target = request.target_view();
            let retained = latest
                .entry(request.signature().validator_id.clone())
                .or_insert(target);
            *retained = (*retained).max(target);
        }
        let mut support = std::collections::BTreeMap::new();
        for target in latest.into_values() {
            if target.0 != 0 && output.transition.as_ref().is_none_or(|t| target > t.view) {
                *support.entry(target).or_insert(0usize) += 1;
            }
        }
        let Some(target) = support
            .into_iter()
            .rev()
            .find_map(|(target, count)| (count > self.set.max_faulty()).then_some(target))
        else {
            return Ok(None);
        };
        // A lower echo would be hidden by latest-per-signer retention at other peers.
        if local_highest.is_some_and(|highest| highest > target) {
            return Ok(None);
        }
        let request = self.author_view_request(target)?;
        self.receive_view_request(request.clone())?;
        Ok(Some(request))
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
            retransmission: None,
            carrier_retransmission: None,
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
            retransmission: None,
            carrier_retransmission: None,
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

    /// Dispatches a decoded agreement message through the pinned authenticated session.
    /// Receipt never signs, echoes, activates legacy transport, or applies an execution decision.
    /// Wire decoding is structural only; each typed receiver retains its authentication rules.
    /// # Errors
    /// Rejects stale/uncertain ownership, nonagreement messages, malformed bodies and evidence.
    /// Driver failures retain the existing recovery-required boundary.
    pub fn receive_message(&mut self, message: net::wire::Message) -> Result<(), String> {
        use net::wire::Message;
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before message receipt".into());
        }
        self.driver.output().map_err(|error| {
            self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
            error.to_string()
        })?;
        match message {
            Message::AgreementCarrier { envelope, vertices } => {
                let envelope = CarrierEnvelope::decode(&envelope, &self.set)
                    .map_err(|error| error.to_string())?;
                self.receive_envelope(envelope, vertices)
            }
            Message::AgreementViewRequest(bytes) => {
                let request = validator::SlotAgreementViewRequest::decode(&bytes, &self.set)
                    .map_err(|error| error.to_string())?;
                self.receive_view_request(request)
            }
            Message::AgreementViewCertificate(bodies) => {
                // Also bound direct callers that did not arrive through the wire parser.
                if bodies.is_empty() || bodies.len() > self.set.validators.len() {
                    return Err("agreement entry certificate signer count exceeds set".into());
                }
                let mut size = 4usize;
                for body in &bodies {
                    size = size
                        .checked_add(4)
                        .and_then(|n| n.checked_add(body.len()))
                        .ok_or("agreement entry certificate size overflows")?;
                    if size > net::wire::MAX_AGREEMENT_ENVELOPE {
                        return Err("agreement entry certificate exceeds one MiB".into());
                    }
                }
                let requests = bodies
                    .iter()
                    .map(|body| validator::SlotAgreementViewRequest::decode(body, &self.set))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| error.to_string())?;
                self.receive_view_certificate(requests)
            }
            Message::AgreementNilVote(bytes) => {
                let vote = validator::SlotAgreementNilVote::decode(&bytes, &self.set)
                    .map_err(|error| error.to_string())?;
                self.receive_nil_vote(vote)
            }
            _ => Err("nonagreement message on authenticated agreement session".into()),
        }
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

// Match wire preflight before hashing, cloning, or signature verification.
fn charge_carrier_vertex(
    vertex: &validator::Vertex,
    vertices: usize,
    edges: &mut usize,
    bytes: &mut usize,
) -> Result<(), String> {
    if vertices >= net::wire::MAX_AGREEMENT_VERTICES {
        return Err("carrier cone exceeds vertex bound".into());
    }
    *edges = edges
        .checked_add(vertex.references.len())
        .ok_or("carrier cone edge overflow")?;
    if *edges > net::wire::MAX_AGREEMENT_EDGES {
        return Err("carrier cone exceeds edge bound".into());
    }
    *bytes = bytes
        .saturating_add(74)
        .saturating_add(vertex.chain_id.len())
        .saturating_add(vertex.author.len())
        .saturating_add(vertex.signature.len());
    for reference in &vertex.references {
        *bytes = bytes
            .saturating_add(48)
            .saturating_add(reference.author.len());
        if reference.round >= vertex.round {
            return Err("carrier cone reference is not strictly ancestral".into());
        }
    }
    if *bytes > net::wire::MAX_AGREEMENT_PAYLOAD {
        return Err("carrier cone exceeds wire byte bound".into());
    }
    Ok(())
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
pub mod event_pump;
mod execution;
mod finalization;
mod journaled_finalization;
pub use journaled_finalization::local_authoring;
mod ordering;
pub mod output_dispatcher;
pub use execution::CertifiedExecution;
pub use finalization::CertifiedFinalization;
pub use journaled_finalization::JournaledFinalization;
pub mod pacemaker;
pub mod session;
pub use envelope::{CarrierEnvelope, CarrierPayload, MAX_ENVELOPE_BYTES};
pub use ordering::OrderingConsumer;

#[cfg(test)]
mod tests;
