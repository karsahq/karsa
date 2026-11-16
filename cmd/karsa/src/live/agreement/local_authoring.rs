//! Bounded trusted local driving, isolated from production agreement scheduling.

use net::wire::Message;
use validator::{SlotAgreementViewCandidate, SlotProposalEnvelope, Vertex};

use super::super::pacemaker;
use super::JournaledFinalization;

/// One caller-selected protocol phase. Votes and aggregates come only from durable state.
pub enum AuthoringAction {
    /// Select one positive durable vote, POL or final obligation automatically.
    Durable,
    /// Plain proposal; receipt grants no voting authority.
    Proposal(SlotProposalEnvelope),
    /// Elected view whose receipt can reserve a prevote intent.
    View(SlotAgreementViewCandidate),
    /// One current authorable durable vote intent in this phase.
    Vote(validator::slot_agreement::AgreementPhase),
    /// Current durable prevote-quorum candidate.
    Pol,
    /// Current durable precommit-quorum candidate, not slot-application authority.
    Final,
}

/// Trusted causal availability and round selection; network messages cannot create this.
pub struct AuthoringRequest {
    /// Caller-selected causal round; Node enforces authoring readiness.
    pub round: u64,
    /// Signed causal availability, chain-checked and authenticated before Node insertion.
    pub vertices: Vec<Vertex>,
    /// Single phase to attempt; never a batch scheduler.
    pub action: AuthoringAction,
}

/// Canonical bytes admitted by one trusted causal import, excluding decoded allocations.
const MAX_CAUSAL_BYTES: usize = 2 * 1024 * 1024;

// Mirrors Vertex::encode: version(2), epoch/round(16), reference count(4),
// payload hash field(36), and chain/author/signature length prefixes(12).
// Each reference adds round(8), author prefix(4), and digest field(36).
fn canonical_vertex_len(vertex: &Vertex) -> Result<usize, String> {
    use crypto::encoding::MAX_FIELD_LEN;
    let add_field = |size: usize, len: usize| {
        if len > MAX_FIELD_LEN {
            return Err("local causal vertex field exceeds codec limit".into());
        }
        size.checked_add(len)
            .ok_or_else(|| "local causal input size overflow".to_string())
    };
    u32::try_from(vertex.references.len())
        .map_err(|_| "local causal reference count exceeds codec limit")?;
    let reference_bytes = vertex
        .references
        .len()
        .checked_mul(48)
        .ok_or("local causal reference count overflow")?;
    let mut size = 70usize
        .checked_add(reference_bytes)
        .ok_or("local causal input size overflow")?;
    if size > MAX_CAUSAL_BYTES {
        return Err("local causal reference list exceeds two MiB".into());
    }
    for len in [
        vertex.chain_id.len(),
        vertex.author.len(),
        vertex.signature.len(),
    ] {
        size = add_field(size, len)?;
    }
    for reference in &vertex.references {
        size = add_field(size, reference.author.len())?;
        if size > MAX_CAUSAL_BYTES {
            return Err("local causal vertex exceeds two MiB".into());
        }
    }
    Ok(size)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DurableAction {
    Vote([u8; 32]),
    Pol([u8; 32]),
    Final([u8; 32]),
}

impl DurableAction {
    fn id(self) -> [u8; 32] {
        match self {
            Self::Vote(id) | Self::Pol(id) | Self::Final(id) => id,
        }
    }
}

fn select_uncompleted_aggregate(
    candidates: impl IntoIterator<Item = Result<DurableAction, String>>,
    completed: &std::collections::BTreeSet<[u8; 32]>,
) -> Result<Option<DurableAction>, String> {
    for candidate in candidates {
        let candidate = candidate?;
        if !completed.contains(&candidate.id()) {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

enum SelectedAction {
    Explicit(Box<AuthoringAction>),
    Durable(DurableAction),
}

pub(super) struct LocalAuthoring {
    node: net::Node,
    remaining_imports: usize,
}

impl JournaledFinalization {
    /// Pins one causal Node for this owner's lifetime. No mutable handle is returned.
    /// Recovery requires a fresh explicit setup; timers and retry cadence are volatile.
    /// # Errors
    /// Rejects unhealthy owners, replacement Nodes, mismatched identity and invalid cadence.
    pub fn enable_authoring(
        &mut self,
        node: net::Node,
        policy: pacemaker::Policy,
        retry_interval: std::time::Duration,
    ) -> Result<(), String> {
        self.check_health()?;
        if self.authoring.is_some() {
            return Err("local authoring is already pinned".into());
        }
        self.adapter.local_authoring_output(&node)?;
        self.adapter
            .configure_carrier_retransmission(retry_interval)?;
        self.adapter.configure_pacemaker(policy);
        self.authoring = Some(LocalAuthoring {
            node,
            remaining_imports: 4096,
        });
        Ok(())
    }

    /// Authors at most one current durable obligation and exports its authenticated cone.
    /// Supplied vertices are availability only: import checks chain and signatures; Node
    /// checks insertion rules, not complete ancestry or payload semantics. Durable inspection
    /// validates the actual full cone before authoring/export. Opaque payload control
    /// classification remains caller-trusted.
    /// At most 4096 supplied vertices over this offline lifetime and two MiB per request;
    /// failed imports consume budget too. Preloaded Node memory is the caller's responsibility.
    /// Export failure after signing is retryable using the durable carrier ID.
    /// Incoming carrier receipt does not populate this Node: the trusted driver must supply
    /// causal vertices explicitly, separately from the pump's certified payload admission.
    /// # Errors
    /// Rejects absent setup, import bounds, invalid vertices and durable authoring/export errors.
    /// Bounds, foreign chains, signature failures and known conflicting statements reject
    /// the whole request before import or budget mutation. Other Node insertion failures
    /// may retain an authenticated prefix and consume budget; imports are not transactional.
    /// Signing never precedes reservation.
    pub fn author_local(&mut self, request: AuthoringRequest) -> Result<Vec<Message>, String> {
        self.import_local(request.vertices)?;
        self.author_local_action(request.round, request.action)
    }

    /// Imports trusted availability and attempts one durable positive-phase obligation.
    /// The only prospective round is one above the highest retained causal round, not
    /// a protocol-phase counter. An empty DAG waits. Full durable cone validation remains
    /// authoritative; a high incomplete frontier can stall rather than invent progression.
    /// Completed payloads are not reauthored, including after explicit owner recovery.
    /// Durable selection/reconstruction is capped at 4096 WAL events, not storage bytes.
    /// Does not tick, retry, elect proposals/views, sign nil votes or apply slots.
    /// # Errors
    /// Propagates bounded import, ownership, round overflow and durable authoring errors.
    pub fn drive_local(&mut self, vertices: Vec<Vertex>) -> Result<Vec<Message>, String> {
        self.import_local(vertices)?;
        let local = self
            .authoring
            .as_ref()
            .ok_or("local authoring is not configured")?;
        let Some(highest) = local.node.dag().highest_round() else {
            return Ok(Vec::new());
        };
        let round = highest
            .checked_add(1)
            .ok_or("local causal round exhausted")?;
        self.author_local_action(round, AuthoringAction::Durable)
    }

    fn import_local(&mut self, vertices: Vec<Vertex>) -> Result<(), String> {
        self.check_health()?;
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        if vertices.len() > local.remaining_imports {
            return Err("local causal import budget exhausted".into());
        }
        let mut bytes = 0usize;
        for vertex in &vertices {
            bytes = bytes
                .checked_add(canonical_vertex_len(vertex)?)
                .ok_or("local causal input size overflow")?;
            if bytes > MAX_CAUSAL_BYTES {
                return Err("local causal input exceeds two MiB".into());
            }
        }
        // Node::receive authenticates signatures but does not enforce its chain ID.
        // Check every import before inserting any prefix into the first-statement-wins DAG.
        let mut statements = std::collections::BTreeMap::new();
        for vertex in &vertices {
            if vertex.chain_id != local.node.dag().chain_id() {
                return Err("local causal vertex differs from pinned chain".into());
            }
            vertex
                .verify(
                    local.node.dag().set_for_round(vertex.round),
                    local.node.dag().epoch_of(vertex.round),
                )
                .map_err(|e| e.to_string())?;
            let key = (vertex.round, vertex.author.as_slice());
            let previous = statements
                .insert(key, vertex)
                .or_else(|| local.node.dag().get(vertex.round, &vertex.author));
            if previous.is_some_and(|previous| previous != vertex) {
                return Err("local causal import conflicts with retained statement".into());
            }
        }
        local.remaining_imports -= vertices.len();
        for vertex in vertices {
            local.node.receive(vertex).map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn author_local_action(
        &mut self,
        round: u64,
        action: AuthoringAction,
    ) -> Result<Vec<Message>, String> {
        self.check_health()?;
        let action = if matches!(action, AuthoringAction::Durable) {
            if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
                return Err("local durable selection exceeds 4096 events".into());
            }
            let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
            let publications = self.adapter.completed_carriers()?;
            let completed: std::collections::BTreeSet<_> = publications
                .iter()
                .map(|carrier| carrier.vertex.payload_hash)
                .collect();
            let vote = self.adapter.signing_history().iter().find(|intent| {
                intent.vote.value != validator::slot_agreement::AgreementValue::Nil
                    && output.authorable_vote_ids.contains(&intent.id)
                    && !publications.iter().any(|carrier| matches!(
                        carrier.envelope.payload(),
                        super::super::CarrierPayload::Vote { payload, .. } if payload.vote == intent.vote
                    ))
            });
            if let Some(intent) = vote {
                SelectedAction::Durable(DurableAction::Vote(intent.id))
            } else {
                let candidates = output
                    .candidates
                    .into_iter()
                    .map(|candidate| match candidate {
                        store::SlotAgreementCarrierCandidate::PendingPol(candidate) => {
                            Ok(DurableAction::Pol(candidate.digest()))
                        }
                        store::SlotAgreementCarrierCandidate::PendingFinalProof(proof) => proof
                            .digest(&self.adapter.set)
                            .map(DurableAction::Final)
                            .map_err(|e| e.to_string()),
                    });
                let Some(action) = select_uncompleted_aggregate(candidates, &completed)? else {
                    return Ok(Vec::new());
                };
                SelectedAction::Durable(action)
            }
        } else {
            SelectedAction::Explicit(Box::new(action))
        };
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        local.node.set_round(round);
        let authored = match action {
            SelectedAction::Durable(DurableAction::Vote(id)) => {
                self.adapter.author_vote(id, &mut local.node)
            }
            SelectedAction::Durable(DurableAction::Pol(digest)) => {
                self.adapter.author_pol(digest, &mut local.node)
            }
            SelectedAction::Durable(DurableAction::Final(digest)) => {
                self.adapter.author_final_proof(digest, &mut local.node)
            }
            SelectedAction::Explicit(action) => match *action {
                AuthoringAction::Durable => unreachable!("durable selection resolved above"),
                AuthoringAction::Proposal(proposal) => {
                    self.adapter.author_proposal(&proposal, &mut local.node)
                }
                AuthoringAction::View(candidate) => {
                    self.adapter.author_view(&candidate, &mut local.node)
                }
                AuthoringAction::Vote(phase) => {
                    let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
                    let id = self
                        .adapter
                        .signing_history()
                        .iter()
                        .find(|intent| {
                            intent.vote.phase == phase
                                && output.authorable_vote_ids.contains(&intent.id)
                        })
                        .map(|intent| intent.id);
                    match id {
                        Some(id) => self.adapter.author_vote(id, &mut local.node),
                        None => Ok(None),
                    }
                }
                AuthoringAction::Pol | AuthoringAction::Final => {
                    let final_proof = matches!(*action, AuthoringAction::Final);
                    let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
                    let mut digest = None;
                    for candidate in output.candidates {
                        match candidate {
                            store::SlotAgreementCarrierCandidate::PendingPol(candidate)
                                if !final_proof =>
                            {
                                digest = Some(candidate.digest());
                                break;
                            }
                            store::SlotAgreementCarrierCandidate::PendingFinalProof(proof)
                                if final_proof =>
                            {
                                digest = Some(
                                    proof.digest(&self.adapter.set).map_err(|e| e.to_string())?,
                                );
                                break;
                            }
                            _ => {}
                        }
                    }
                    match digest {
                        Some(digest) if final_proof => {
                            self.adapter.author_final_proof(digest, &mut local.node)
                        }
                        Some(digest) => self.adapter.author_pol(digest, &mut local.node),
                        None => Ok(None),
                    }
                }
            },
        };
        let result = authored.and_then(|carrier| match carrier {
            Some(carrier) => self
                .adapter
                .export_carrier(
                    &carrier.vertex.id().map_err(|e| e.to_string())?,
                    local.node.dag(),
                )
                .map(|message| vec![message]),
            None => Ok(Vec::new()),
        });
        self.check_health()?;
        result
    }

    /// Applies at most one pacemaker action, without signing, publishing or applying a slot.
    /// Nil obligations and view-change publication are not driven by this positive-phase API.
    /// # Errors
    /// Rejects absent setup, backwards time, arithmetic exhaustion and unhealthy owners.
    pub fn tick_local(&mut self, now: std::time::Instant) -> Result<(), String> {
        self.check_health()?;
        if self.authoring.is_none() {
            return Err("local authoring is not configured".into());
        }
        let result = self.adapter.tick(now).map(|_| ());
        self.check_health()?;
        result
    }

    /// Discovers completed durable publication IDs without requiring authoring setup.
    /// Returns at most 64 IDs in durable completion order starting at `offset`, including
    /// historical slots (which current-slot export may reject). Available after reopen or
    /// lost output, including export failure after completion. No signatures or writes occur.
    /// Replay/reconstruction is capped at 4096 WAL events, not byte-bounded storage reads.
    /// # Errors
    /// Rejects unhealthy owners, histories beyond the replay cap and reconstruction errors.
    pub fn completed_publications(
        &mut self,
        offset: usize,
    ) -> Result<Vec<validator::VertexId>, String> {
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("publication discovery exceeds 4096 durable events".into());
        }
        self.check_health()?;
        let result = self.adapter.completed_carriers().map(|carriers| {
            carriers
                .into_iter()
                .skip(offset)
                .take(64)
                .map(|carrier| carrier.envelope.carrier().clone())
                .collect()
        });
        self.check_health()?;
        result
    }

    /// Retries at most one of at most 64 explicitly selected durable local carriers.
    /// # Errors
    /// Rejects absent setup, invalid IDs, cadence violations and unavailable authenticated cones.
    pub fn retry_local(
        &mut self,
        now: std::time::Instant,
        ids: &[validator::VertexId],
    ) -> Result<Vec<Message>, String> {
        self.check_health()?;
        let local = self
            .authoring
            .as_ref()
            .ok_or("local authoring is not configured")?;
        let result = self
            .adapter
            .retransmit_carrier(now, ids, local.node.dag())
            .map(|message| message.into_iter().collect());
        self.check_health()?;
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durable_selection_preserves_second_same_kind_digest() {
        for constructor in [DurableAction::Pol, DurableAction::Final] {
            let first = constructor([1; 32]);
            let second = constructor([2; 32]);
            let completed = std::collections::BTreeSet::from([first.id()]);
            let selected =
                select_uncompleted_aggregate([Ok(first), Ok(second)], &completed).unwrap();
            assert_eq!(
                selected,
                Some(second),
                "must dispatch the uncompleted candidate, not reselect the first of its kind"
            );
            let completed = std::collections::BTreeSet::from([first.id(), second.id()]);
            assert_eq!(
                select_uncompleted_aggregate([Ok(first), Ok(second)], &completed).unwrap(),
                None
            );
        }
    }

    #[test]
    fn causal_preflight_length_matches_canonical_vertex_codec() {
        let mut vertex = Vertex {
            chain_id: b"preflight-chain".to_vec(),
            epoch: 7,
            round: 3,
            author: b"validator".to_vec(),
            payload_hash: [1; 32],
            references: Vec::new(),
            signature: vec![2; 64],
        };
        assert_eq!(
            canonical_vertex_len(&vertex).unwrap(),
            vertex.encode().unwrap().len()
        );
        vertex.references = vec![
            validator::VertexId {
                round: 2,
                author: vec![3; 5],
                digest: [4; 32],
            },
            validator::VertexId {
                round: 1,
                author: vec![5; 100],
                digest: [6; 32],
            },
        ];
        assert_eq!(
            canonical_vertex_len(&vertex).unwrap(),
            vertex.encode().unwrap().len()
        );
        vertex.signature = vec![0; crypto::encoding::MAX_FIELD_LEN];
        assert_eq!(
            canonical_vertex_len(&vertex).unwrap(),
            vertex.encode().unwrap().len()
        );
        vertex.signature.push(0);
        assert!(
            canonical_vertex_len(&vertex)
                .unwrap_err()
                .contains("codec limit")
        );
    }
}
