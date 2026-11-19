use super::*;
#[path = "agreement_execution_checkpoint.rs"]
mod execution_checkpoint;
pub use execution_checkpoint::AgreementExecutionCheckpoint;
#[path = "agreement_header_intents.rs"]
mod header_intents;
#[path = "agreement_header_shares.rs"]
mod header_shares;
pub use header_intents::AgreementHeaderIntent;
#[cfg(feature = "test-support")]
pub use header_shares::SharePublicationStage;
use std::collections::BTreeMap;
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementTransitionResult, AgreementValue,
    AgreementView, AgreementVote, SlotAgreement,
};
use validator::{
    CertifiedDag, Dag, SlotAgreementBinding, SlotAgreementNilVote, SlotAgreementProof,
    SlotAgreementViewCandidate, SlotAgreementViewLineage, SlotAgreementVotePayload,
    SlotAgreementVoteWitness, SlotDecisionBinding, SlotProposalEnvelope, Vertex, VertexId,
};

pub(super) const FILE: &str = "authenticated-slot-agreement";
const MAX_BODY: usize = 2 * 1024 * 1024;
const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_EVENTS: usize = 4096;
const MAX_VERTICES: usize = 4096;
const MAX_DEPENDENCIES: usize = 65536;
const DOMAIN: &[u8] = b"KARSA/STORE/AUTHENTICATED_SLOT_AGREEMENT/v1";
fn invalid(message: &str) -> StoreError {
    CryptoError::new(crypto::CryptoErrorKind::MalformedCertificate, message).into()
}

/// Trusted fixed-set checkpoint with complete, unpruned signed dependencies.
#[derive(Debug, Clone)]
pub struct AuthenticatedSlotAgreementBootstrap {
    /// Fixed slot, validator set and local signing identity.
    pub agreement: SlotAgreementBootstrap,
    /// Exact trusted predecessor carrier, if one exists.
    pub predecessor: Option<VertexId>,
    /// Complete committed order; compact frontiers are unsupported.
    pub order: Vec<VertexId>,
    /// Complete signed dependencies needed by this checkpoint.
    pub vertices: Vec<Vertex>,
}

/// Closed authenticated requests; no raw reducer input or semantic callback.
#[derive(Debug, Clone, PartialEq, Eq)]

pub enum AuthenticatedSlotAgreementRequest {
    /// Apply the first durable deciding proof and derive the next same-set slot.
    AdvanceSlot,
    /// Explicit local authorization, durable before signing an advisory request.
    ReserveViewRequest {
        /// Exact positive future target; not a voting floor.
        target_view: AgreementView,
    },
    /// Persist the exact locally signed request before publication.
    CompleteViewRequest {
        /// One-based sequence of the original authorization.
        reservation_sequence: u64,
        /// Signed advisory request, independently verified on replay.
        message: validator::SlotAgreementViewRequest,
    },
    /// Enter a future view using a distinct-signer exact-target quorum, without voting.
    EnterRequestedView {
        /// Complete certificate, verified by the reducer.
        requests: Vec<validator::SlotAgreementViewRequest>,
    },
    /// Persist an exact signed nil publication for a current durable intent.
    CompleteNilVote {
        /// Stable original signing intent identity.
        intent_id: [u8; 32],
        /// Exact locally signed nil statement.
        message: SlotAgreementNilVote,
    },
    /// Authenticate current-view nil evidence and deliver its first quorum once.
    ObserveNilVote {
        /// Individually authenticated nil statement.
        message: SlotAgreementNilVote,
    },
    /// Retains an authenticated plain proposal without accepting a view or voting.
    /// Only the active undecided slot is eligible; no agreement view is implied.
    ObserveProposal {
        /// Plain proposal evidence.
        proposal: SlotProposalEnvelope,
        /// Actual signed proposal carrier.
        carrier: VertexId,
        /// Signed carrier and complete dependencies not already retained.
        vertices: Vec<Vertex>,
    },
    /// Persist the exact signed publication for an existing reservation.
    CompleteCarrier {
        /// Original one-based reservation WAL sequence.
        reservation_sequence: u64,
        /// Actual signed vertex; evidence is derived from the reservation.
        signed: Vertex,
    },
    /// Reserve an exact unsigned outer statement before invoking its signer.
    ReserveCarrier {
        /// Typed authenticated evidence bound to the exact prospective statement.
        evidence: AgreementCarrierEvidence,
        /// Actual prospective statement, with an empty outer signature.
        unsigned: Vertex,
        /// Complete additional signed dependencies.
        vertices: Vec<Vertex>,
    },
    /// Authenticate the exact lineage before emitting a prevote.
    Propose {
        /// Complete historical authorization, including exact carriers.
        lineage: SlotAgreementViewLineage,
        /// Additional signed dependencies, retained without pruning.
        vertices: Vec<Vertex>,
    },
    /// Authenticate the current lineage POL before emitting a precommit.
    ObservePrevote {
        /// Complete historical authorization, including exact carriers.
        lineage: SlotAgreementViewLineage,
        /// Additional signed dependencies, retained without pruning.
        vertices: Vec<Vertex>,
    },
    /// Authenticate a complete precommit proof before deciding this pinned slot.
    ObservePrecommit {
        /// Complete signed lineage and both voting phases; a bare QC is insufficient.
        proof: SlotAgreementProof,
        /// Exact signed carrier binding the complete proof.
        carrier: VertexId,
        /// Additional signed dependencies, retained without pruning.
        vertices: Vec<Vertex>,
    },
    /// Retain authenticated individual evidence without driving the local reducer.
    ObserveVote {
        /// Complete authorization for the individual vote.
        lineage: SlotAgreementViewLineage,
        /// Exact signed vote and its retained carrier.
        witness: SlotAgreementVoteWitness,
        /// Additional signed dependencies.
        vertices: Vec<Vertex>,
    },
    /// Request a phase-bound nil vote.
    Timeout {
        /// Exact current view.
        view: AgreementView,
        /// Exact phase.
        phase: AgreementPhase,
    },
    /// Advance exactly one view.
    AdvanceView {
        /// Expected current view.
        from: AgreementView,
    },
}
/// Typed evidence for a pre-sign reservation of a VOTE, POL or FINAL carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementCarrierEvidence {
    /// Semantically authenticated proposal without elected-view authority.
    Proposal {
        /// Exact proposal carried by the unsigned vertex.
        proposal: SlotProposalEnvelope,
    },
    /// Current elected authorization bound to the actual unsigned carrier.
    View {
        /// Exact retained prefix and selected carrier-bound view.
        lineage: SlotAgreementViewLineage,
    },
    /// A signed inner vote matching a durable local signing obligation.
    Vote {
        /// Full authenticated authorization.
        lineage: SlotAgreementViewLineage,
        /// Signed inner payload; the outer vertex remains unsigned.
        payload: SlotAgreementVotePayload,
    },
    /// Selected frozen prevotes bound to the actual prospective POL carrier ID.
    Pol {
        /// Full lineage, including the selected POL bound to `unsigned.id()`.
        lineage: SlotAgreementViewLineage,
    },
    /// Exact frozen precommit evidence awaiting an outer FINAL carrier.
    Final {
        /// Complete direct final proof.
        proof: SlotAgreementProof,
    },
}

/// Durable, replay-derived outer signing permission; never acknowledged or removed.
#[derive(Debug, Clone)]
pub struct AgreementReservedCarrier {
    /// Stable hash of the exact vertex signing statement (independent of request sequence).
    pub id: VertexId,
    /// Original one-based WAL event sequence.
    pub sequence: u64,
    /// Original local identity, set and slot context.
    pub agreement: SlotAgreementBootstrap,
    /// Original predecessor binding.
    pub binding: SlotAgreementBinding,
    /// Full authenticated evidence.
    pub evidence: AgreementCarrierEvidence,
    /// Exact statement to sign, with no outer signature.
    pub unsigned: Vertex,
}

/// Durable signed publication with its replay-derived original authorization.
#[derive(Debug, Clone)]
pub struct AgreementCompletedCarrier {
    /// Original reservation, including pinned context and authenticated evidence.
    pub reservation: AgreementReservedCarrier,
    /// Original one-based completion WAL sequence.
    pub sequence: u64,
    /// Exact signed publication bytes, recoverable through `Vertex::encode`.
    pub signed: Vertex,
}

/// Replay-derived signed nil publication retained across slots and views.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementCompletedNilVote {
    /// Original durable signing obligation.
    pub intent_id: [u8; 32],
    /// Original one-based completion WAL sequence.
    pub sequence: u64,
    /// Exact signed publication.
    pub message: SlotAgreementNilVote,
}

fn put_id(e: &mut Encoder, id: &VertexId) -> Result<(), StoreError> {
    if id.author.len() > 1024 {
        return Err(invalid("carrier author exceeds bound"));
    }
    e.put_u64(id.round);
    e.put_bytes(&id.author)?;
    e.put_bytes(&id.digest)?;
    Ok(())
}
fn get_id(d: &mut Decoder<'_>) -> Result<VertexId, StoreError> {
    Ok(VertexId {
        round: d.read_u64()?,
        author: d.read_bytes()?.to_vec(),
        digest: d
            .read_bytes()?
            .try_into()
            .map_err(|_| invalid("invalid carrier digest"))?,
    })
}
fn put_vertices(e: &mut Encoder, vertices: &[Vertex]) -> Result<(), StoreError> {
    if vertices.len() > MAX_VERTICES {
        return Err(invalid("vertex count exceeds bound"));
    }
    e.put_u32(vertices.len() as u32);
    let mut dependencies = 0usize;
    for vertex in vertices {
        dependencies = dependencies.saturating_add(vertex.references.len());
        if dependencies > MAX_DEPENDENCIES {
            return Err(invalid("dependency edge bound exceeded"));
        }
        e.put_bytes(&vertex.encode()?)?;
        if e.len() > MAX_BODY {
            return Err(invalid("authenticated vertices exceed envelope bound"));
        }
    }
    Ok(())
}
fn get_vertices(d: &mut Decoder<'_>) -> Result<Vec<Vertex>, StoreError> {
    let count = d.read_u32()? as usize;
    if count > MAX_VERTICES {
        return Err(invalid("vertex count exceeds bound"));
    }
    (0..count)
        .map(|_| Ok(Vertex::decode(d.read_bytes()?)?))
        .collect()
}
fn bounded(bytes: Vec<u8>) -> Result<Vec<u8>, StoreError> {
    if bytes.len() > MAX_BODY {
        return Err(invalid("authenticated envelope exceeds bound"));
    }
    Ok(bytes)
}
impl AuthenticatedSlotAgreementBootstrap {
    fn encode(&self) -> Result<Vec<u8>, StoreError> {
        let mut e = Encoder::new();
        e.put_u16(1);
        e.put_bytes(&self.agreement.encode()?)?;
        match &self.predecessor {
            Some(id) => {
                e.put_u8(1);
                put_id(&mut e, id)?;
            }
            None => e.put_u8(0),
        }
        if self.order.len() > MAX_VERTICES {
            return Err(invalid("order exceeds bound"));
        }
        e.put_u32(self.order.len() as u32);
        for id in &self.order {
            put_id(&mut e, id)?;
        }
        put_vertices(&mut e, &self.vertices)?;
        bounded(e.finish())
    }
    fn decode(bytes: &[u8]) -> Result<Self, StoreError> {
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != 1 {
            return Err(invalid("unknown authenticated WAL version"));
        }
        let agreement = SlotAgreementBootstrap::decode(d.read_bytes()?)?;
        let predecessor = match d.read_u8()? {
            0 => None,
            1 => Some(get_id(&mut d)?),
            _ => return Err(invalid("invalid predecessor tag")),
        };
        let count = d.read_u32()? as usize;
        if count > MAX_VERTICES {
            return Err(invalid("order exceeds bound"));
        }
        let order = (0..count)
            .map(|_| get_id(&mut d))
            .collect::<Result<_, _>>()?;
        let vertices = get_vertices(&mut d)?;
        d.finish()?;
        let value = Self {
            agreement,
            predecessor,
            order,
            vertices,
        };
        if value.encode()? != bytes {
            return Err(invalid("noncanonical authenticated bootstrap"));
        }
        Ok(value)
    }
}
impl AuthenticatedSlotAgreementRequest {
    fn encode(&self, set: &validator::ValidatorSet) -> Result<Vec<u8>, StoreError> {
        let mut e = Encoder::new();
        e.put_u16(1);
        match self {
            Self::ReserveViewRequest { target_view } => {
                e.put_u8(12);
                e.put_u64(target_view.0);
            }
            Self::CompleteViewRequest {
                reservation_sequence,
                message,
            } => {
                e.put_u8(13);
                e.put_u64(*reservation_sequence);
                e.put_bytes(&message.encode(set)?)?;
            }
            Self::EnterRequestedView { requests } => {
                if requests.len() > set.validators.len() {
                    return Err(invalid("view request certificate exceeds set size"));
                }
                e.put_u8(15);
                e.put_u32(requests.len() as u32);
                for request in requests {
                    e.put_bytes(&request.encode(set)?)?;
                }
            }
            Self::AdvanceSlot => e.put_u8(6),
            Self::CompleteNilVote { intent_id, message } => {
                e.put_u8(10);
                e.put_bytes(intent_id)?;
                e.put_bytes(&message.encode(set)?)?;
            }
            Self::ObserveNilVote { message } => {
                e.put_u8(11);
                e.put_bytes(&message.encode(set)?)?;
            }
            Self::ObserveProposal {
                proposal,
                carrier,
                vertices,
            } => {
                e.put_u8(9);
                e.put_bytes(&proposal.encode()?)?;
                put_id(&mut e, carrier)?;
                put_vertices(&mut e, vertices)?;
            }
            Self::CompleteCarrier {
                reservation_sequence,
                signed,
            } => {
                e.put_u8(8);
                e.put_u64(*reservation_sequence);
                e.put_bytes(&signed.encode()?)?;
            }
            Self::ReserveCarrier {
                evidence,
                unsigned,
                vertices,
            } => {
                e.put_u8(7);
                // Persisted inner tags: 0 VOTE, 1 POL, 2 FINAL, 3 PROPOSAL, 4 VIEW.
                match evidence {
                    AgreementCarrierEvidence::Proposal { proposal } => {
                        e.put_u8(3);
                        e.put_bytes(&proposal.encode()?)?;
                    }
                    AgreementCarrierEvidence::View { lineage } => {
                        e.put_u8(4);
                        e.put_bytes(&lineage.encode(set)?)?;
                    }
                    AgreementCarrierEvidence::Vote { lineage, payload } => {
                        e.put_u8(0);
                        e.put_bytes(&lineage.encode(set)?)?;
                        e.put_bytes(&payload.encode(set)?)?;
                    }
                    AgreementCarrierEvidence::Pol { lineage } => {
                        e.put_u8(1);
                        e.put_bytes(&lineage.encode(set)?)?;
                    }
                    AgreementCarrierEvidence::Final { proof } => {
                        e.put_u8(2);
                        e.put_bytes(&proof.encode(set)?)?;
                    }
                }
                e.put_bytes(&unsigned.encode()?)?;
                put_vertices(&mut e, vertices)?;
            }
            Self::Propose { lineage, vertices } | Self::ObservePrevote { lineage, vertices } => {
                e.put_u8(if matches!(self, Self::Propose { .. }) {
                    0
                } else {
                    1
                });
                e.put_bytes(&lineage.encode(set)?)?;
                put_vertices(&mut e, vertices)?;
            }
            Self::ObservePrecommit {
                proof,
                carrier,
                vertices,
            } => {
                e.put_u8(4);
                e.put_bytes(&proof.encode(set)?)?;
                put_id(&mut e, carrier)?;
                put_vertices(&mut e, vertices)?;
            }
            Self::ObserveVote {
                lineage,
                witness,
                vertices,
            } => {
                e.put_u8(5);
                e.put_bytes(&lineage.encode(set)?)?;
                e.put_bytes(&witness.payload.encode(set)?)?;
                put_id(&mut e, &witness.carrier)?;
                put_vertices(&mut e, vertices)?;
            }
            Self::Timeout { view, phase } => {
                e.put_u8(2);
                e.put_u64(view.0);
                e.put_u8(match phase {
                    AgreementPhase::Prevote => 0,
                    AgreementPhase::Precommit => 1,
                });
            }
            Self::AdvanceView { from } => {
                e.put_u8(3);
                e.put_u64(from.0);
            }
        }
        bounded(e.finish())
    }
    fn decode(bytes: &[u8], set: &validator::ValidatorSet) -> Result<Self, StoreError> {
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != 1 {
            return Err(invalid("unknown authenticated event version"));
        }
        let tag = d.read_u8()?;
        let value = match tag {
            12 => Self::ReserveViewRequest {
                target_view: AgreementView(d.read_u64()?),
            },
            13 => Self::CompleteViewRequest {
                reservation_sequence: d.read_u64()?,
                message: validator::SlotAgreementViewRequest::decode(d.read_bytes()?, set)?,
            },
            15 => {
                let count = d.read_u32()? as usize;
                if count > set.validators.len() {
                    return Err(invalid("view request certificate exceeds set size"));
                }
                let mut requests = Vec::with_capacity(count);
                for _ in 0..count {
                    requests.push(validator::SlotAgreementViewRequest::decode(
                        d.read_bytes()?,
                        set,
                    )?);
                }
                Self::EnterRequestedView { requests }
            }
            6 => Self::AdvanceSlot,
            10 => Self::CompleteNilVote {
                intent_id: d
                    .read_bytes()?
                    .try_into()
                    .map_err(|_| invalid("invalid nil intent ID"))?,
                message: SlotAgreementNilVote::decode(d.read_bytes()?, set)?,
            },
            11 => Self::ObserveNilVote {
                message: SlotAgreementNilVote::decode(d.read_bytes()?, set)?,
            },
            9 => Self::ObserveProposal {
                proposal: SlotProposalEnvelope::decode(d.read_bytes()?)?,
                carrier: get_id(&mut d)?,
                vertices: get_vertices(&mut d)?,
            },
            8 => Self::CompleteCarrier {
                reservation_sequence: d.read_u64()?,
                signed: Vertex::decode(d.read_bytes()?)?,
            },
            7 => {
                let evidence = match d.read_u8()? {
                    0 => AgreementCarrierEvidence::Vote {
                        lineage: SlotAgreementViewLineage::decode(d.read_bytes()?, set)?,
                        payload: SlotAgreementVotePayload::decode(d.read_bytes()?, set)?,
                    },
                    1 => AgreementCarrierEvidence::Pol {
                        lineage: SlotAgreementViewLineage::decode(d.read_bytes()?, set)?,
                    },
                    2 => AgreementCarrierEvidence::Final {
                        proof: SlotAgreementProof::decode(d.read_bytes()?, set)?,
                    },
                    3 => AgreementCarrierEvidence::Proposal {
                        proposal: SlotProposalEnvelope::decode(d.read_bytes()?)?,
                    },
                    4 => AgreementCarrierEvidence::View {
                        lineage: SlotAgreementViewLineage::decode(d.read_bytes()?, set)?,
                    },
                    _ => return Err(invalid("unsupported reservation evidence")),
                };
                Self::ReserveCarrier {
                    evidence,
                    unsigned: Vertex::decode(d.read_bytes()?)?,
                    vertices: get_vertices(&mut d)?,
                }
            }
            0 | 1 => {
                let lineage = SlotAgreementViewLineage::decode(d.read_bytes()?, set)?;
                let vertices = get_vertices(&mut d)?;
                if tag == 0 {
                    Self::Propose { lineage, vertices }
                } else {
                    Self::ObservePrevote { lineage, vertices }
                }
            }
            2 => Self::Timeout {
                view: AgreementView(d.read_u64()?),
                phase: match d.read_u8()? {
                    0 => AgreementPhase::Prevote,
                    1 => AgreementPhase::Precommit,
                    _ => return Err(invalid("invalid timeout phase")),
                },
            },
            3 => Self::AdvanceView {
                from: AgreementView(d.read_u64()?),
            },
            4 => Self::ObservePrecommit {
                proof: SlotAgreementProof::decode(d.read_bytes()?, set)?,
                carrier: get_id(&mut d)?,
                vertices: get_vertices(&mut d)?,
            },
            5 => Self::ObserveVote {
                lineage: SlotAgreementViewLineage::decode(d.read_bytes()?, set)?,
                witness: SlotAgreementVoteWitness {
                    payload: SlotAgreementVotePayload::decode(d.read_bytes()?, set)?,
                    carrier: get_id(&mut d)?,
                },
                vertices: get_vertices(&mut d)?,
            },
            _ => return Err(invalid("unknown authenticated request")),
        };
        d.finish()?;
        if value.encode(set)? != bytes {
            return Err(invalid("noncanonical authenticated request"));
        }
        Ok(value)
    }
}
fn digest(previous: &[u8; 32], sequence: u64, body: &[u8]) -> [u8; 32] {
    crypto::merkle::leaf(
        DOMAIN,
        &[
            previous,
            &sequence.to_le_bytes(),
            &(body.len() as u32).to_le_bytes(),
            body,
        ],
    )
}
fn frame(previous: &[u8; 32], sequence: u64, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    out.extend_from_slice(&digest(previous, sequence, body));
    out
}
struct Journal {
    bootstrap: AuthenticatedSlotAgreementBootstrap,
    header: Vec<u8>,
    events: Vec<AuthenticatedSlotAgreementRequest>,
    tip: [u8; 32],
    bytes: u64,
}
fn read(root: &Path) -> Result<Option<Journal>, StoreError> {
    let path = root.join(FILE);
    validate_pointer_file(&path)?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    if file.metadata()?.len() > MAX_BYTES {
        return Err(invalid("authenticated WAL exceeds byte bound"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid("authenticated WAL exceeds byte bound"));
    }
    let mut cursor = 0;
    let mut tip = [0; 32];
    let mut bodies = Vec::new();
    while cursor < bytes.len() {
        if bodies.len() > MAX_EVENTS {
            return Err(invalid("authenticated WAL exceeds event bound"));
        }
        let len = bytes
            .get(cursor..cursor + 4)
            .ok_or_else(|| invalid("torn authenticated length"))?;
        let len = u32::from_le_bytes(len.try_into().expect("four-byte length")) as usize;
        if len > MAX_BODY {
            return Err(invalid("authenticated body exceeds bound"));
        }
        cursor += 4;
        let body = bytes
            .get(cursor..cursor + len)
            .ok_or_else(|| invalid("torn authenticated body"))?;
        cursor += len;
        let checksum = bytes
            .get(cursor..cursor + 32)
            .ok_or_else(|| invalid("torn authenticated checksum"))?;
        cursor += 32;
        tip = digest(&tip, bodies.len() as u64, body);
        if checksum != tip {
            return Err(invalid("corrupt authenticated hash chain"));
        }
        bodies.push(body);
    }
    let header = *bodies
        .first()
        .ok_or_else(|| invalid("empty authenticated WAL"))?;
    let bootstrap = AuthenticatedSlotAgreementBootstrap::decode(header)?;
    let events = bodies[1..]
        .iter()
        .map(|b| AuthenticatedSlotAgreementRequest::decode(b, &bootstrap.agreement.set))
        .collect::<Result<_, _>>()?;
    Ok(Some(Journal {
        bootstrap,
        header: header.to_vec(),
        events,
        tip,
        bytes: bytes.len() as u64,
    }))
}
pub(super) fn exclude_legacy(root: &Path) -> Result<(), StoreError> {
    validate_pointer_file(&root.join(FILE))?;
    if root.join(FILE).try_exists()? {
        return Err(invalid("authenticated root excludes legacy APIs"));
    }
    Ok(())
}
fn exclusions(root: &Path) -> Result<(), StoreError> {
    validate_pointer_file(&root.join(slot_agreement_journal::FILE))?;
    validate_pointer_file(&root.join(slot_decision_journal::FILE))?;
    if root.join(slot_agreement_journal::FILE).try_exists()?
        || root.join(slot_decision_journal::FILE).try_exists()?
    {
        return Err(invalid("legacy root excludes authenticated session"));
    }
    Ok(())
}
fn sync(file: &File, root: &Path) -> Result<(), StoreError> {
    file.sync_all()?;
    slot_decision_journal::sync_ancestors(root, |p| File::open(p)?.sync_all())?;
    Ok(())
}
// All dependency bytes are retained. No compact frontier or changing set is accepted.
fn build_dag(
    b: &AuthenticatedSlotAgreementBootstrap,
    vertices: &BTreeMap<(u64, Vec<u8>), Vertex>,
) -> Result<Dag, StoreError> {
    let mut dag = Dag::new(b.agreement.set.clone());
    dag.set_chain_id(b.agreement.context.chain_id().to_vec());
    let mut dependencies = 0usize;
    for vertex in vertices.values() {
        dependencies = dependencies.saturating_add(vertex.references.len());
        if dependencies > MAX_DEPENDENCIES {
            return Err(invalid("retained dependency edge bound exceeded"));
        }
        for reference in &vertex.references {
            if reference.round >= vertex.round
                || vertices
                    .get(&(reference.round, reference.author.clone()))
                    .map(|v| v.id())
                    .transpose()?
                    .as_ref()
                    != Some(reference)
            {
                return Err(invalid("missing or conflicting authenticated dependency"));
            }
        }
        dag.insert(vertex.clone())?;
    }
    for id in &b.order {
        if vertices
            .get(&(id.round, id.author.clone()))
            .map(|v| v.id())
            .transpose()?
            .as_ref()
            != Some(id)
        {
            return Err(invalid("checkpoint order vertex missing"));
        }
    }
    dag.seed_order(b.order.clone());
    if dag.order_len() as u64 != b.agreement.context.order_len()
        || &dag.commit_root() != b.agreement.context.order_root()
    {
        return Err(invalid("unpruned checkpoint order mismatch"));
    }
    Ok(dag)
}
fn add(
    vertices: &mut BTreeMap<(u64, Vec<u8>), Vertex>,
    incoming: &[Vertex],
) -> Result<(), StoreError> {
    for vertex in incoming {
        let key = (vertex.round, vertex.author.clone());
        if let Some(old) = vertices.get(&key) {
            if old != vertex {
                return Err(invalid("conflicting retained signed vertex"));
            }
        } else {
            if vertices.len() >= MAX_VERTICES {
                return Err(invalid("retained dependency bound exceeded"));
            }
            vertices.insert(key, vertex.clone());
        }
    }
    Ok(())
}
fn ingest(
    dag: &mut CertifiedDag,
    vertices: &mut BTreeMap<(u64, Vec<u8>), Vertex>,
    incoming: &[Vertex],
) -> Result<(), StoreError> {
    let mut additions = BTreeMap::new();
    for vertex in incoming {
        let key = (vertex.round, vertex.author.clone());
        if !vertices.contains_key(&key) {
            additions.insert(key, vertex.clone());
        }
    }
    add(vertices, incoming)?;
    if vertices.values().map(|v| v.references.len()).sum::<usize>() > MAX_DEPENDENCIES {
        return Err(invalid("retained dependency edge bound exceeded"));
    }
    for vertex in additions.into_values() {
        for reference in &vertex.references {
            if reference.round >= vertex.round
                || vertices
                    .get(&(reference.round, reference.author.clone()))
                    .map(Vertex::id)
                    .transpose()?
                    .as_ref()
                    != Some(reference)
            {
                return Err(invalid("missing or conflicting authenticated dependency"));
            }
        }
        dag.insert(vertex)?;
    }
    Ok(())
}

/// Frozen quorum evidence, not an authenticated POL or finalization carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementQuorumCandidate {
    /// Authorization retained with the first admitted witness in this bucket.
    pub lineage: SlotAgreementViewLineage,
    /// Canonically ordered signatures frozen at the first quorum crossing.
    pub certificate: AgreementQc,
    /// Exact carriers in the same canonical validator order.
    pub witnesses: Vec<SlotAgreementVoteWitness>,
}

impl AgreementQuorumCandidate {
    pub(super) fn is_fresh(&self, view: AgreementView, decided: bool) -> bool {
        !decided && self.certificate.vote.view == view
    }

    pub(super) fn validate_envelope(
        &self,
        set: &validator::ValidatorSet,
    ) -> Result<(), StoreError> {
        match self.certificate.vote.phase {
            AgreementPhase::Prevote => {
                self.lineage.pol_candidate_digest(
                    self.certificate.clone(),
                    self.witnesses.clone(),
                    set,
                )?;
            }
            AgreementPhase::Precommit => {
                self.lineage.clone().into_proof(
                    self.certificate.clone(),
                    self.witnesses.clone(),
                    set,
                )?;
            }
        }
        Ok(())
    }
}

/// Authenticated lineage ending at the reducer-selected highest valid POL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgreementReproposalCandidate {
    lineage: SlotAgreementViewLineage,
}

impl AgreementReproposalCandidate {
    /// Returns the selected POL view.
    pub fn view(&self) -> validator::slot_agreement::AgreementView {
        self.lineage
            .entries
            .last()
            .expect("selected POL has a lineage")
            .pol
            .as_ref()
            .expect("selected lineage ends in a POL")
            .certificate
            .vote
            .view
    }

    /// Returns the exact authenticated lineage retained for the selected POL.
    pub fn lineage(&self) -> &SlotAgreementViewLineage {
        &self.lineage
    }
}

#[derive(Default)]
struct VoteBucket {
    lineage: Option<SlotAgreementViewLineage>,
    witnesses: BTreeMap<Vec<u8>, SlotAgreementVoteWitness>,
    candidate: Option<AgreementQuorumCandidate>,
}

/// Replay-derived signing intent. Entries are never acknowledged or removed.
#[derive(Debug, Clone)]
pub struct AgreementSigningIntent {
    /// Stable identity binding the full statement, prerequisite and pinned local identity.
    pub id: [u8; 32],
    /// Original one-based durable request sequence that emitted this vote.
    pub sequence: u64,
    /// Original slot context, complete pinned set and local signing identity.
    pub agreement: SlotAgreementBootstrap,
    /// Exact unsigned statement emitted by the authenticated reducer.
    pub vote: AgreementVote,
    /// Authenticated carrier to bind, or explicit unsupported nil intent.
    pub prerequisite: AgreementSigningPrerequisite,
    /// Full authenticated lineage from the original emission request; absent for nil votes.
    pub lineage: Option<SlotAgreementViewLineage>,
}

/// Signing support derived exclusively from authenticated request lineage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementSigningPrerequisite {
    /// Exact original proposal/view carrier for prevote, or POL carrier for precommit.
    Carrier(VertexId),
    /// Nil intent is retained, but has no supported signed carrier representation.
    UnsupportedNil,
}

type NilVoteBucket = (BTreeMap<Vec<u8>, validator::ValidatorSignature>, bool);

/// Durable local advisory authorization and its immutable signed publication, if completed.
#[derive(Debug, Clone)]
pub struct AgreementViewRequestReservation {
    /// Original one-based reservation WAL sequence.
    pub sequence: u64,
    /// Pinned slot context, validator set and local signing identity.
    pub agreement: SlotAgreementBootstrap,
    /// Exact authorized positive future target; not a voting floor.
    pub target_view: AgreementView,
    /// Exact signed publication, installed only after verified durable completion.
    pub message: Option<validator::SlotAgreementViewRequest>,
}
#[derive(Default)]
struct ViewRequests {
    reservations: Vec<AgreementViewRequestReservation>,
}

// Explicit local authorizations are separate from remotely supplied observations.
const MAX_LOCAL_REQUEST_TARGETS: usize = 16;

/// One certified slot application after the original checkpoint, including skips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementApplicationBoundary {
    round: u64,
    order_len: usize,
    is_commit: bool,
}

impl AgreementApplicationBoundary {
    /// Returns the applied slot's round.
    pub fn round(&self) -> u64 {
        self.round
    }

    /// Returns the cumulative order length immediately after this application.
    pub fn order_len(&self) -> usize {
        self.order_len
    }

    /// Returns whether the actual application committed rather than skipped.
    pub fn is_commit(&self) -> bool {
        self.is_commit
    }
}

/// Immutable replay-derived ordering at the last durable slot-application boundary.
/// A decided but unadvanced slot is excluded. This contains the complete retained
/// checkpoint prefix and subsequent certified applications, not transaction execution
/// state or permission to mutate a live DAG. No acknowledgement or compaction occurs.
#[derive(Debug, Clone)]
pub struct AgreementOrderingSnapshot {
    checkpoint_binding: SlotAgreementBinding,
    applications: Vec<AgreementApplicationBoundary>,
    binding: SlotAgreementBinding,
    order: Vec<VertexId>,
    vertices: Vec<Vertex>,
}

impl AgreementOrderingSnapshot {
    /// Returns the original trusted checkpoint binding, before replayed applications.
    pub fn checkpoint_binding(&self) -> &SlotAgreementBinding {
        &self.checkpoint_binding
    }

    /// Returns replayed applications, including skips but excluding the checkpoint itself.
    pub fn applications(&self) -> &[AgreementApplicationBoundary] {
        &self.applications
    }

    /// Returns the active next-slot binding derived from the same replay as the order.
    pub fn binding(&self) -> &SlotAgreementBinding {
        &self.binding
    }

    /// Returns the exact full applied prefix, including the original checkpoint order.
    pub fn order(&self) -> &[VertexId] {
        &self.order
    }

    /// Returns authenticated signed vertices in precisely the applied prefix order.
    /// These are DAG vertices, not transaction batches or execution receipts.
    pub fn vertices(&self) -> &[Vertex] {
        &self.vertices
    }
}

type ReplayState = (
    Option<AgreementTransitionResult>,
    Vec<AgreementQuorumCandidate>,
    SlotAgreementBootstrap,
    SlotAgreementBinding,
    Option<AgreementReproposalCandidate>,
    Vec<AgreementSigningIntent>,
    Vec<[u8; 32]>,
    Vec<AgreementReservedCarrier>,
    Vec<AgreementCompletedCarrier>,
    Vec<AgreementCompletedNilVote>,
    ViewRequests,
    CertifiedDag,
    Vec<AgreementApplicationBoundary>,
);

fn reservation_bounds(
    vertices: &BTreeMap<(u64, Vec<u8>), Vertex>,
    reservations: &[AgreementReservedCarrier],
    prospective: Option<&Vertex>,
) -> Result<(), StoreError> {
    let count = vertices.len() + reservations.len() + usize::from(prospective.is_some());
    let edges = vertices.values().map(|v| v.references.len()).sum::<usize>()
        + reservations
            .iter()
            .map(|r| r.unsigned.references.len())
            .sum::<usize>()
        + prospective.map_or(0, |v| v.references.len());
    if count > MAX_VERTICES || edges > MAX_DEPENDENCIES {
        return Err(invalid("combined reservation dependency bound exceeded"));
    }
    Ok(())
}

fn authorable_votes(
    outbox: &[AgreementSigningIntent],
    reducer: &SlotAgreement,
    active: &SlotAgreementBootstrap,
) -> Vec<[u8; 32]> {
    outbox
        .iter()
        .filter(|intent| {
            if reducer.decision().is_some()
                || intent.agreement.context != active.context
                || intent.vote.view != reducer.view()
            {
                return false;
            }
            match intent.vote.phase {
                AgreementPhase::Prevote => !outbox.iter().any(|other| {
                    other.agreement.context == active.context
                        && other.vote.view == reducer.view()
                        && other.vote.phase == AgreementPhase::Precommit
                }),
                AgreementPhase::Precommit => match &intent.vote.value {
                    AgreementValue::Decision(decision) => {
                        reducer.lock().is_some_and(|(view, locked)| {
                            *view == reducer.view() && locked == decision
                        })
                    }
                    AgreementValue::Nil => true,
                },
            }
        })
        .map(|intent| intent.id)
        .collect()
}

/// Canonical identity of one authenticated observation, including its availability.
/// Only a byte-identical receipt is a repeat: extra dependency vertices are independent
/// input that can conflict with a local reservation or fail retention, so a request that
/// merely resembles an earlier statement must still be replayed and validated.
fn observation_key(
    request: &AuthenticatedSlotAgreementRequest,
    set: &validator::ValidatorSet,
) -> Result<Option<Vec<u8>>, StoreError> {
    match request {
        AuthenticatedSlotAgreementRequest::ObserveProposal { .. }
        | AuthenticatedSlotAgreementRequest::Propose { .. }
        | AuthenticatedSlotAgreementRequest::ObserveVote { .. }
        | AuthenticatedSlotAgreementRequest::ObservePrevote { .. }
        | AuthenticatedSlotAgreementRequest::ObservePrecommit { .. }
        | AuthenticatedSlotAgreementRequest::ObserveNilVote { .. }
        | AuthenticatedSlotAgreementRequest::EnterRequestedView { .. } => {
            Ok(Some(request.encode(set)?))
        }
        _ => Ok(None),
    }
}

fn replay(
    b: &AuthenticatedSlotAgreementBootstrap,
    events: &[AuthenticatedSlotAgreementRequest],
) -> Result<ReplayState, StoreError> {
    let mut binding =
        SlotAgreementBinding::from_checkpoint(b.agreement.context.clone(), b.predecessor.clone())?;
    let mut vertices = BTreeMap::new();
    add(&mut vertices, &b.vertices)?;
    let mut dag = CertifiedDag::from_checkpoint(
        build_dag(b, &vertices)?,
        SlotDecisionBinding::from_checkpoint(b.agreement.context.clone(), b.predecessor.clone())?,
    )?;
    let mut active = b.agreement.clone();
    let mut finalization = None;
    let mut reducer = SlotAgreement::new(b.agreement.context.clone(), b.agreement.set.clone())?;
    let mut result = None;
    let mut reproposal = None;
    let mut buckets: BTreeMap<Vec<u8>, VoteBucket> = BTreeMap::new();
    let mut witness_count = 0usize;
    let mut evidence_bytes = 0usize;
    let mut outbox: Vec<AgreementSigningIntent> = Vec::new();
    let mut reserved: Vec<AgreementReservedCarrier> = Vec::new();
    let mut completed: Vec<AgreementCompletedCarrier> = Vec::new();
    let mut completed_nil: Vec<AgreementCompletedNilVote> = Vec::new();
    let mut nil_buckets: BTreeMap<Vec<u8>, NilVoteBucket> = BTreeMap::new();
    let mut view_requests = ViewRequests::default();
    let mut applications = Vec::new();
    let mut observations: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    for (index, event) in events.iter().enumerate() {
        if let Some(key) = observation_key(event, &b.agreement.set)? {
            if !observations.insert(key) {
                // The same authenticated observation can arrive twice: a local publication
                // may be self-delivered and then echoed by a peer, and a carrier retransmission
                // repeats evidence a peer already holds. Replaying it again would repeat a
                // one-shot reducer step (a view authorization emits the local prevote), so the
                // receipt is a durable no-op that emits no new vote.
                result = Some(AgreementTransitionResult {
                    vote: None,
                    view: reducer.view(),
                    decision: reducer.decision().cloned(),
                });
                continue;
            }
        }
        let incoming = match event {
            AuthenticatedSlotAgreementRequest::ObserveProposal { vertices, .. }
            | AuthenticatedSlotAgreementRequest::ReserveCarrier { vertices, .. }
            | AuthenticatedSlotAgreementRequest::Propose { vertices, .. }
            | AuthenticatedSlotAgreementRequest::ObservePrevote { vertices, .. }
            | AuthenticatedSlotAgreementRequest::ObservePrecommit { vertices, .. }
            | AuthenticatedSlotAgreementRequest::ObserveVote { vertices, .. } => {
                vertices.as_slice()
            }
            _ => &[],
        };
        for vertex in incoming {
            for reservation in &reserved {
                if vertex.author == reservation.unsigned.author
                    && vertex.round == reservation.unsigned.round
                    && vertex.id()? != reservation.id
                {
                    return Err(invalid(
                        "signed dependency conflicts with reserved local round",
                    ));
                }
            }
        }
        match event {
            AuthenticatedSlotAgreementRequest::ReserveViewRequest { target_view } => {
                validator::SlotAgreementViewRequest::signing_payload(
                    &active.context,
                    *target_view,
                    &active.set,
                )?;
                if reducer.decision().is_some() || *target_view <= reducer.view() {
                    return Err(invalid(
                        "view request authorization is not for a future undecided view",
                    ));
                }
                let local: Vec<_> = view_requests
                    .reservations
                    .iter()
                    .filter(|r| r.agreement.context == active.context)
                    .collect();
                if local.len() >= MAX_LOCAL_REQUEST_TARGETS
                    || local.iter().any(|r| r.target_view == *target_view)
                {
                    return Err(invalid(
                        "view request authorization bound or duplicate target",
                    ));
                }
                view_requests
                    .reservations
                    .push(AgreementViewRequestReservation {
                        sequence: index as u64 + 1,
                        agreement: active.clone(),
                        target_view: *target_view,
                        message: None,
                    });
            }
            AuthenticatedSlotAgreementRequest::CompleteViewRequest {
                reservation_sequence,
                message,
            } => {
                let reservation = view_requests
                    .reservations
                    .iter_mut()
                    .find(|r| r.sequence == *reservation_sequence)
                    .ok_or_else(|| invalid("view request completion lacks authorization"))?;
                if reservation.message.is_some()
                    || reservation.agreement.context != active.context
                    || reducer.decision().is_some()
                    || reservation.target_view <= reducer.view()
                    || message.target_view() != reservation.target_view
                    || message.signature().validator_id != reservation.agreement.local_validator
                {
                    return Err(invalid(
                        "view request completion differs from pending local authorization",
                    ));
                }
                message.verify(&reservation.agreement.context, &reservation.agreement.set)?;
                reservation.message = Some(message.clone());
            }
            AuthenticatedSlotAgreementRequest::EnterRequestedView { requests } => {
                reducer.enter_requested_view(requests)?;
                result = Some(AgreementTransitionResult {
                    vote: None,
                    view: reducer.view(),
                    decision: None,
                });
            }
            _ => {}
        }
        if matches!(
            event,
            AuthenticatedSlotAgreementRequest::ReserveViewRequest { .. }
                | AuthenticatedSlotAgreementRequest::CompleteViewRequest { .. }
                | AuthenticatedSlotAgreementRequest::EnterRequestedView { .. }
        ) {
            result.get_or_insert_with(|| AgreementTransitionResult {
                vote: None,
                view: reducer.view(),
                decision: reducer.decision().cloned(),
            });
            continue;
        }
        if let AuthenticatedSlotAgreementRequest::CompleteNilVote { intent_id, message } = event {
            let intent = outbox
                .iter()
                .find(|intent| intent.id == *intent_id)
                .ok_or_else(|| invalid("nil completion lacks durable intent"))?;
            if completed_nil.iter().any(|old| old.intent_id == *intent_id) {
                return Err(invalid(
                    "nil vote already completed; retry original sequence",
                ));
            }
            if !authorable_votes(&outbox, &reducer, &active).contains(intent_id)
                || intent.vote != *message.vote()
                || intent.vote.value != AgreementValue::Nil
                || message.signature().validator_id != intent.agreement.local_validator
            {
                return Err(invalid(
                    "nil completion differs from current local obligation",
                ));
            }
            message.verify(&intent.agreement.context, &intent.agreement.set)?;
            completed_nil.push(AgreementCompletedNilVote {
                intent_id: *intent_id,
                sequence: index as u64 + 1,
                message: message.clone(),
            });
            continue;
        }
        if let AuthenticatedSlotAgreementRequest::CompleteCarrier {
            reservation_sequence,
            signed,
        } = event
        {
            let reservation = reserved
                .iter()
                .find(|r| r.sequence == *reservation_sequence)
                .ok_or_else(|| invalid("completion lacks original reservation"))?;
            if completed
                .iter()
                .any(|c| c.reservation.sequence == *reservation_sequence)
            {
                return Err(invalid(
                    "carrier already completed; retry original sequence",
                ));
            }
            let mut unsigned = signed.clone();
            unsigned.signature.clear();
            if unsigned != reservation.unsigned || signed.id()? != reservation.id {
                return Err(invalid(
                    "completion differs from reserved signing statement",
                ));
            }
            signed.verify(&reservation.agreement.set, reservation.unsigned.epoch)?;
            if vertices
                .get(&(signed.round, signed.author.clone()))
                .is_some_and(|old| old != signed)
            {
                return Err(invalid("completion conflicts with retained signed vertex"));
            }
            completed.push(AgreementCompletedCarrier {
                reservation: reservation.clone(),
                sequence: index as u64 + 1,
                signed: signed.clone(),
            });
            // Publication is not a reducer input or a new signing authorization.
            continue;
        }
        if let AuthenticatedSlotAgreementRequest::ObserveProposal {
            proposal,
            carrier,
            vertices: incoming,
        } = event
        {
            if reducer.decision().is_some()
                || proposal.decision.round != active.context.next_round()
            {
                return Err(invalid(
                    "observed proposal is not for the active undecided slot",
                ));
            }
            ingest(&mut dag, &mut vertices, incoming)?;
            reservation_bounds(&vertices, &reserved, None)?;
            dag.dag()
                .inspect_slot_bound_proposal(proposal, carrier, &binding)?;
            result.get_or_insert_with(|| AgreementTransitionResult {
                vote: None,
                view: reducer.view(),
                decision: reducer.decision().cloned(),
            });
            continue;
        }
        if let AuthenticatedSlotAgreementRequest::ReserveCarrier {
            evidence,
            unsigned,
            vertices: incoming,
        } = event
        {
            if !unsigned.signature.is_empty() || unsigned.author != active.local_validator {
                return Err(invalid("reservation requires an unsigned local carrier"));
            }
            if reserved.iter().any(|old| old.unsigned == *unsigned) {
                return Err(invalid("carrier already reserved; retry original sequence"));
            }
            ingest(&mut dag, &mut vertices, incoming)?;
            reservation_bounds(&vertices, &reserved, None)?;
            let fresh = || {
                buckets
                    .values()
                    .filter_map(|bucket| bucket.candidate.as_ref())
                    .filter(|candidate| {
                        candidate.is_fresh(reducer.view(), reducer.decision().is_some())
                    })
            };
            match evidence {
                AgreementCarrierEvidence::Proposal { proposal } => {
                    if reducer.decision().is_some()
                        || proposal.decision.round != active.context.next_round()
                    {
                        return Err(invalid(
                            "proposal reservation is not for the active undecided slot",
                        ));
                    }
                    dag.dag()
                        .inspect_slot_proposal_authoring_cone(unsigned, proposal, &binding)?;
                }
                AgreementCarrierEvidence::View { lineage } => {
                    let mut prefix = lineage.entries.clone();
                    let selected = prefix
                        .pop()
                        .ok_or_else(|| invalid("empty view reservation"))?;
                    if reducer.decision().is_some()
                        || selected.view != reducer.view()
                        || selected.proposal.decision.round != active.context.next_round()
                    {
                        return Err(invalid(
                            "view reservation is not for the active current undecided slot",
                        ));
                    }
                    let required = reproposal
                        .as_ref()
                        .map(|candidate: &AgreementReproposalCandidate| {
                            candidate.lineage.entries.as_slice()
                        })
                        .unwrap_or(&[]);
                    if prefix != required {
                        return Err(invalid(
                            "view reservation differs from retained highest-valid prefix",
                        ));
                    }
                    let candidate = SlotAgreementViewCandidate::new(
                        prefix,
                        selected.proposal,
                        selected.proposal_carrier,
                        selected.view,
                        &active.set,
                    )?;
                    candidate.bound_lineage_len(&unsigned.author, &active.set)?;
                    if candidate.clone().bind_carrier(unsigned.id()?) != *lineage {
                        return Err(invalid(
                            "view reservation has noncanonical selected binding",
                        ));
                    }
                    if reserved.iter().any(|old| {
                        old.agreement.context == active.context
                            && matches!(&old.evidence, AgreementCarrierEvidence::View { lineage: prior }
                                if prior.entries.last().is_some_and(|entry| entry.view == selected.view))
                    }) {
                        return Err(invalid("view already reserved; retry original sequence"));
                    }
                    dag.dag()
                        .inspect_slot_view_authoring_cone(unsigned, &candidate, &binding)?;
                }
                AgreementCarrierEvidence::Vote { lineage, payload } => {
                    let eligible = authorable_votes(&outbox, &reducer, &active);
                    if !outbox.iter().any(|intent| {
                        eligible.contains(&intent.id)
                            && intent.vote == payload.vote
                            && intent.lineage.as_ref() == Some(lineage)
                            && intent.prerequisite
                                == AgreementSigningPrerequisite::Carrier(
                                    payload.prerequisite.clone(),
                                )
                    }) {
                        return Err(invalid("reservation lacks current durable vote obligation"));
                    }
                    dag.dag()
                        .inspect_slot_authoring_cone(unsigned, lineage, payload, &binding)?;
                }
                AgreementCarrierEvidence::Pol { lineage } => {
                    let mut unbound = lineage.clone();
                    let pol = unbound
                        .entries
                        .last_mut()
                        .and_then(|entry| entry.pol.take())
                        .ok_or_else(|| invalid("POL reservation lacks selected evidence"))?;
                    if pol.carrier != unsigned.id()? {
                        return Err(invalid(
                            "POL reservation does not bind actual prospective ID",
                        ));
                    }
                    let candidate =
                        unbound.pol_candidate_digest(pol.certificate, pol.votes, &active.set)?;
                    let mut matched = false;
                    for frozen in
                        fresh().filter(|c| c.certificate.vote.phase == AgreementPhase::Prevote)
                    {
                        let expected = frozen.lineage.pol_candidate_digest(
                            frozen.certificate.clone(),
                            frozen.witnesses.clone(),
                            &active.set,
                        )?;
                        if candidate == expected {
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        return Err(invalid(
                            "POL reservation lacks fresh exact frozen candidate",
                        ));
                    }
                    dag.dag()
                        .inspect_slot_pol_authoring_cone(unsigned, &candidate, &binding)?;
                }
                AgreementCarrierEvidence::Final { proof } => {
                    let mut matched = false;
                    for frozen in
                        fresh().filter(|c| c.certificate.vote.phase == AgreementPhase::Precommit)
                    {
                        let expected = frozen.lineage.clone().into_proof(
                            frozen.certificate.clone(),
                            frozen.witnesses.clone(),
                            &active.set,
                        )?;
                        if *proof == expected {
                            matched = true;
                            break;
                        }
                    }
                    if !matched {
                        return Err(invalid(
                            "FINAL reservation lacks fresh exact frozen candidate",
                        ));
                    }
                    dag.dag()
                        .inspect_slot_final_authoring_cone(unsigned, proof, &binding)?;
                }
            }
            reservation_bounds(&vertices, &reserved, Some(unsigned))?;
            let id = unsigned.id()?;
            if reserved.iter().any(|old| {
                old.unsigned.round == unsigned.round
                    && old.unsigned.author == unsigned.author
                    && old.unsigned != *unsigned
            }) || vertices
                .get(&(unsigned.round, unsigned.author.clone()))
                .is_some_and(|old| old.id().ok().as_ref() != Some(&id))
            {
                return Err(invalid("conflicting local round signing reservation"));
            }
            if reserved.len() >= MAX_EVENTS {
                return Err(invalid("reservation count exceeds bound"));
            }
            reserved.push(AgreementReservedCarrier {
                id,
                sequence: index as u64 + 1,
                agreement: active.clone(),
                binding: binding.clone(),
                evidence: evidence.clone(),
                unsigned: unsigned.clone(),
            });
            // Publication may be the first event; report state without a reducer input.
            result.get_or_insert_with(|| AgreementTransitionResult {
                vote: None,
                view: reducer.view(),
                decision: reducer.decision().cloned(),
            });
            continue;
        }
        if matches!(event, AuthenticatedSlotAgreementRequest::AdvanceSlot) {
            if reducer.decision().is_none() {
                return Err(invalid("cannot advance an undecided slot"));
            }
            let (proof, carrier) = finalization
                .take()
                .ok_or_else(|| invalid("missing durable deciding proof"))?;
            let application = dag.prepare_agreement(&proof, &carrier)?.apply();
            if let validator::SlotApplicationResult::Applied { round, decision } = application {
                applications.push(AgreementApplicationBoundary {
                    round,
                    order_len: dag.dag().order().len(),
                    is_commit: matches!(decision, validator::Decision::Commit(_)),
                });
            }
            binding = SlotAgreementBinding::from_checkpoint(
                dag.binding().tip().clone(),
                dag.binding().carrier().cloned(),
            )?;
            active.context = binding.tip().clone();
            reducer = SlotAgreement::new(active.context.clone(), active.set.clone())?;
            buckets.clear();
            nil_buckets.clear();
            reproposal = None;
            result = Some(AgreementTransitionResult {
                vote: None,
                view: reducer.view(),
                decision: None,
            });
            continue;
        }

        if let AuthenticatedSlotAgreementRequest::ObserveVote {
            lineage,
            witness,
            vertices: incoming,
        } = event
        {
            if witness.payload.vote.view != reducer.view() || reducer.decision().is_some() {
                return Err(invalid(
                    "individual evidence is not for the active current view",
                ));
            }
            ingest(&mut dag, &mut vertices, incoming)?;
            reservation_bounds(&vertices, &reserved, None)?;
            dag.dag()
                .inspect_slot_agreement_vote(lineage, witness, &binding)?;
            // Authenticate the supplied POL before removing it: a prevote authorizes
            // the selected view, not that view's subsequently assembled POL.
            let mut retained_lineage = lineage.clone();
            if witness.payload.vote.phase == AgreementPhase::Prevote {
                retained_lineage
                    .entries
                    .last_mut()
                    .ok_or_else(|| invalid("empty individual vote lineage"))?
                    .pol = None;
            }
            let mut key = Encoder::new();
            key.put_bytes(&witness.payload.vote.signing_payload(&b.agreement.set)?)?;
            put_id(&mut key, &witness.payload.prerequisite)?;
            let key = key.finish();
            if !buckets.contains_key(&key) && buckets.len() + nil_buckets.len() >= MAX_EVENTS {
                return Err(invalid("vote bucket bound exceeded"));
            }
            let bucket = buckets.entry(key).or_default();
            if let Some(old) = &bucket.lineage {
                if old.encode(&b.agreement.set)? != retained_lineage.encode(&b.agreement.set)? {
                    return Err(invalid("conflicting individual vote lineage"));
                }
            }
            let signer = witness.payload.signature.validator_id.clone();
            if let Some(old) = bucket.witnesses.get(&signer) {
                if old != witness {
                    return Err(invalid("conflicting individual vote witness"));
                }
            } else {
                witness_count += 1;
                evidence_bytes =
                    evidence_bytes.saturating_add(event.encode(&b.agreement.set)?.len());
                if witness_count > MAX_EVENTS || evidence_bytes > MAX_BYTES as usize {
                    return Err(invalid("retained vote evidence bound exceeded"));
                }
                bucket.lineage.get_or_insert(retained_lineage);
                bucket.witnesses.insert(signer, witness.clone());
                if bucket.candidate.is_none() {
                    let certificate = AgreementQc {
                        vote: witness.payload.vote.clone(),
                        signatures: bucket
                            .witnesses
                            .values()
                            .map(|w| w.payload.signature.clone())
                            .collect(),
                    };
                    if certificate
                        .verify(&active.context, &b.agreement.set)
                        .is_ok()
                    {
                        let candidate = AgreementQuorumCandidate {
                            lineage: bucket
                                .lineage
                                .clone()
                                .ok_or_else(|| invalid("missing bucket lineage"))?,
                            certificate,
                            witnesses: bucket.witnesses.values().cloned().collect(),
                        };
                        // Replay runs before opening the WAL for append. A quorum that
                        // cannot be exported must never become a frozen durable bucket.
                        candidate.validate_envelope(&b.agreement.set)?;
                        bucket.candidate = Some(candidate);
                    }
                }
            }
            result = Some(AgreementTransitionResult {
                vote: None,
                view: reducer.view(),
                decision: reducer.decision().cloned(),
            });
            continue;
        }
        let (input, decision) = match event {
            AuthenticatedSlotAgreementRequest::ReserveViewRequest { .. }
            | AuthenticatedSlotAgreementRequest::CompleteViewRequest { .. }
            | AuthenticatedSlotAgreementRequest::EnterRequestedView { .. }
            | AuthenticatedSlotAgreementRequest::CompleteNilVote { .. } => {
                unreachable!("publication handled above")
            }
            AuthenticatedSlotAgreementRequest::ObserveNilVote { message } => {
                if reducer.decision().is_some() || message.vote().view != reducer.view() {
                    return Err(invalid(
                        "nil evidence is not for the current undecided view",
                    ));
                }
                message.verify(&active.context, &active.set)?;
                let key = message.vote().signing_payload(&active.set)?;
                if !nil_buckets.contains_key(&key)
                    && nil_buckets.len() + buckets.len() >= MAX_EVENTS
                {
                    return Err(invalid("vote bucket bound exceeded"));
                }
                let (signatures, delivered) = nil_buckets.entry(key).or_default();
                let signer = &message.signature().validator_id;
                let mut qc = None;
                if !*delivered && !signatures.contains_key(signer) {
                    witness_count += 1;
                    evidence_bytes =
                        evidence_bytes.saturating_add(event.encode(&active.set)?.len());
                    if witness_count > MAX_EVENTS || evidence_bytes > MAX_BYTES as usize {
                        return Err(invalid("retained vote evidence bound exceeded"));
                    }
                    signatures.insert(signer.clone(), message.signature().clone());
                    let certificate = AgreementQc {
                        vote: message.vote().clone(),
                        signatures: signatures.values().cloned().collect(),
                    };
                    if certificate.verify(&active.context, &active.set).is_ok() {
                        *delivered = true;
                        // A nil POL cannot replace a precommit already emitted for this view.
                        let already_precommitted = outbox.iter().any(|intent| {
                            intent.agreement.context == active.context
                                && intent.vote.view == reducer.view()
                                && intent.vote.phase == AgreementPhase::Precommit
                        });
                        if message.vote().phase != AgreementPhase::Prevote || !already_precommitted
                        {
                            qc = Some(certificate);
                        }
                    }
                }
                let Some(qc) = qc else {
                    result = Some(AgreementTransitionResult {
                        vote: None,
                        view: reducer.view(),
                        decision: None,
                    });
                    continue;
                };
                (AgreementInput::Evidence { qc }, None)
            }
            AuthenticatedSlotAgreementRequest::ReserveCarrier { .. }
            | AuthenticatedSlotAgreementRequest::CompleteCarrier { .. } => {
                unreachable!("publication handled above")
            }
            AuthenticatedSlotAgreementRequest::AdvanceSlot => unreachable!("advance handled above"),
            AuthenticatedSlotAgreementRequest::ObserveVote { .. }
            | AuthenticatedSlotAgreementRequest::ObserveProposal { .. } => {
                unreachable!("observations handled without reducer input")
            }
            AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: incoming,
            }
            | AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage,
                vertices: incoming,
            } => {
                ingest(&mut dag, &mut vertices, incoming)?;
                reservation_bounds(&vertices, &reserved, None)?;
                let proposal = dag
                    .dag()
                    .inspect_slot_agreement_view_lineage(lineage, &binding)?;
                let AgreementInput::Propose { decision, .. } = &proposal else {
                    return Err(invalid("inspector returned nonproposal"));
                };
                let decision = decision.clone();
                let input = if matches!(
                    event,
                    AuthenticatedSlotAgreementRequest::ObservePrevote { .. }
                ) {
                    let pol = lineage
                        .entries
                        .last()
                        .and_then(|e| e.pol.as_ref())
                        .ok_or_else(|| invalid("missing current prevote POL"))?;
                    if pol.certificate.vote.phase != AgreementPhase::Prevote {
                        return Err(invalid("not a prevote POL"));
                    }
                    AgreementInput::Evidence {
                        qc: pol.certificate.clone(),
                    }
                } else {
                    proposal
                };
                (input, Some(decision))
            }
            AuthenticatedSlotAgreementRequest::ObservePrecommit {
                proof,
                carrier,
                vertices: incoming,
            } => {
                ingest(&mut dag, &mut vertices, incoming)?;
                reservation_bounds(&vertices, &reserved, None)?;
                dag.dag()
                    .inspect_slot_agreement_proof(proof, carrier, &binding)?;
                if reducer.decision().is_none() {
                    finalization = Some((proof.clone(), carrier.clone()));
                }
                (
                    AgreementInput::Evidence {
                        qc: proof.certificate.clone(),
                    },
                    Some(
                        proof
                            .entries
                            .last()
                            .ok_or_else(|| invalid("empty finalization lineage"))?
                            .proposal
                            .decision
                            .clone(),
                    ),
                )
            }
            AuthenticatedSlotAgreementRequest::Timeout { view, phase } => (
                AgreementInput::Timeout {
                    view: *view,
                    phase: *phase,
                },
                None,
            ),
            AuthenticatedSlotAgreementRequest::AdvanceView { from } => {
                (AgreementInput::AdvanceView { from: *from }, None)
            }
        };
        result = Some(
            reducer
                .prepare(input, |actual| {
                    if decision.as_ref() == Some(actual) {
                        Ok(())
                    } else {
                        Err(CryptoError::new(
                            crypto::CryptoErrorKind::MalformedCertificate,
                            "reducer decision differs from authenticated proof",
                        ))
                    }
                })?
                .apply(),
        );
        if let Some(vote) = result
            .as_ref()
            .and_then(|transition| transition.vote.as_ref())
        {
            let (prerequisite, lineage) = if matches!(vote.value, AgreementValue::Nil) {
                (AgreementSigningPrerequisite::UnsupportedNil, None)
            } else {
                let lineage = match event {
                    AuthenticatedSlotAgreementRequest::Propose { lineage, .. }
                    | AuthenticatedSlotAgreementRequest::ObservePrevote { lineage, .. } => lineage,
                    _ => return Err(invalid("nonnil signing intent lacks authenticated lineage")),
                };
                let entry = lineage
                    .entries
                    .last()
                    .ok_or_else(|| invalid("signing intent lacks lineage entry"))?;
                let carrier = match vote.phase {
                    AgreementPhase::Prevote => entry.view_carrier.clone(),
                    AgreementPhase::Precommit => entry
                        .pol
                        .as_ref()
                        .ok_or_else(|| invalid("precommit signing intent lacks POL"))?
                        .carrier
                        .clone(),
                };
                (
                    AgreementSigningPrerequisite::Carrier(carrier),
                    Some(lineage.clone()),
                )
            };
            let mut statement = Encoder::new();
            statement.put_bytes(b"KARSA/STORE/AGREEMENT_SIGNING_INTENT/v1")?;
            statement.put_bytes(&vote.signing_payload(&active.set)?)?;
            statement.put_bytes(&active.encode()?)?;
            match &prerequisite {
                AgreementSigningPrerequisite::Carrier(carrier) => {
                    statement.put_u8(1);
                    put_id(&mut statement, carrier)?;
                }
                AgreementSigningPrerequisite::UnsupportedNil => statement.put_u8(0),
            }
            outbox.push(AgreementSigningIntent {
                id: digest(&[0; 32], 0, &statement.finish()),
                sequence: index as u64 + 1,
                agreement: active.clone(),
                vote: vote.clone(),
                prerequisite,
                lineage,
            });
        }
        if let AuthenticatedSlotAgreementRequest::ObservePrevote { lineage, .. } = event {
            let pol = &lineage
                .entries
                .last()
                .expect("inspected lineage is nonempty")
                .pol
                .as_ref()
                .expect("observed prevote has a POL")
                .certificate;
            if reducer.valid() == Some(pol)
                && reproposal
                    .as_ref()
                    .is_none_or(|old: &AgreementReproposalCandidate| old.view() < pol.vote.view)
            {
                reproposal = Some(AgreementReproposalCandidate {
                    lineage: lineage.clone(),
                });
            }
        }
    }
    // Only current, undecided obligations may acquire a new outer carrier.
    let authorable = authorable_votes(&outbox, &reducer, &active);
    Ok((
        result,
        buckets.into_values().filter_map(|b| b.candidate).collect(),
        active,
        binding,
        reproposal,
        outbox,
        authorable,
        reserved,
        completed,
        completed_nil,
        view_requests,
        dag,
        applications,
    ))
}
pub(super) fn validate(root: &Path) -> Result<(), StoreError> {
    if let Some(journal) = read(root)? {
        exclusions(root)?;
        replay(&journal.bootstrap, &journal.events)?;
    }
    Ok(())
}
/// Exclusive durable session handle; uncertain I/O requires recovery.
#[derive(Debug)]
pub struct AuthenticatedSlotAgreement {
    store: Store,
    header: Vec<u8>,
    sequence: u64,
    tip: [u8; 32],
    uncertain: bool,
    #[cfg(feature = "test-support")]
    share_publication_fault: Option<(header_shares::SharePublicationStage, usize)>,
}
impl Store {
    /// Pins an authenticated-only root and persists its trusted checkpoint.
    ///
    /// # Errors
    /// Rejects existing legacy journals, unsupported checkpoints and I/O failures.
    pub fn begin_authenticated_slot_agreement(
        &self,
        bootstrap: AuthenticatedSlotAgreementBootstrap,
    ) -> Result<AuthenticatedSlotAgreement, StoreError> {
        let header = bootstrap.encode()?;
        replay(&bootstrap, &[])?;
        let root = self
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(FILE))?;
        file.write_all(&frame(&[0; 32], 0, &header))?;
        sync(&file, &root)?;
        Ok(AuthenticatedSlotAgreement {
            store: self.clone(),
            tip: digest(&[0; 32], 0, &header),
            header,
            sequence: 0,
            uncertain: false,
            #[cfg(feature = "test-support")]
            share_publication_fault: None,
        })
    }
    /// Reauthenticates all retained events and repeats durability barriers.
    ///
    /// # Errors
    /// Rejects checkpoint mismatches, corrupt evidence, reducer conflicts and I/O failures.
    pub fn recover_authenticated_slot_agreement(
        &self,
        bootstrap: AuthenticatedSlotAgreementBootstrap,
    ) -> Result<AuthenticatedSlotAgreement, StoreError> {
        let header = bootstrap.encode()?;
        let root = self
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != header {
            return Err(invalid("authenticated checkpoint mismatch"));
        }
        replay(&bootstrap, &journal.events)?;
        sync(&File::open(root.join(FILE))?, &root)?;
        Ok(AuthenticatedSlotAgreement {
            store: self.clone(),
            header,
            sequence: journal.events.len() as u64,
            tip: journal.tip,
            uncertain: false,
            #[cfg(feature = "test-support")]
            share_publication_fault: None,
        })
    }
}
type DriverSnapshot = (
    SlotAgreementBootstrap,
    Option<AgreementTransitionResult>,
    Vec<AgreementQuorumCandidate>,
    Option<AgreementReproposalCandidate>,
    SlotAgreementBinding,
    Vec<[u8; 32]>,
);

impl AuthenticatedSlotAgreement {
    /// Returns every durable signing intent in emission order, including unsupported nil votes.
    ///
    /// No acknowledgements or queue removal exist: repeated reads intentionally resend exact
    /// statements. History is bounded by the WAL's 4096 requests and 64 MiB capacity;
    /// capacity exhaustion rejects new requests rather than evicting signing obligations.
    /// Recovery repeats fsync before constructing an owner that can expose this output.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners, corrupt journals and invalid historical evidence.
    pub fn signing_outbox(&self) -> Result<Vec<AgreementSigningIntent>, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        Ok(replay(&journal.bootstrap, &journal.events)?.5)
    }

    /// Returns all durable pre-sign reservations in original WAL order.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners and invalid durable evidence.
    pub fn reserved_carriers(&self) -> Result<Vec<AgreementReservedCarrier>, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        Ok(replay(&journal.bootstrap, &journal.events)?.7)
    }

    /// Returns all durable signed publications in completion WAL order.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners and invalid durable evidence.
    pub fn completed_carriers(&self) -> Result<Vec<AgreementCompletedCarrier>, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        Ok(replay(&journal.bootstrap, &journal.events)?.8)
    }

    /// Returns all durable signed nil publications in completion WAL order.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners and invalid durable evidence.
    pub fn completed_nil_votes(&self) -> Result<Vec<AgreementCompletedNilVote>, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        Ok(replay(&journal.bootstrap, &journal.events)?.9)
    }

    fn view_requests(&self) -> Result<ViewRequests, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        Ok(replay(&journal.bootstrap, &journal.events)?.10)
    }

    /// Returns durable authorizations and their exact signed completions, including history.
    /// # Errors
    /// Rejects stale or uncertain owners and invalid journals.
    pub fn view_request_reservations(
        &self,
    ) -> Result<Vec<AgreementViewRequestReservation>, StoreError> {
        Ok(self.view_requests()?.reservations)
    }

    /// Exports the latest durable entry certificate for the current slot, not volatile support.
    ///
    /// # Errors
    /// Rejects stale or uncertain owners and invalid durable evidence.
    pub fn entered_view_certificate(
        &self,
    ) -> Result<Option<Vec<validator::SlotAgreementViewRequest>>, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        replay(&journal.bootstrap, &journal.events)?;
        let mut certificate = None;
        for event in &journal.events {
            match event {
                AuthenticatedSlotAgreementRequest::AdvanceSlot => certificate = None,
                AuthenticatedSlotAgreementRequest::EnterRequestedView { requests } => {
                    certificate = Some(requests.clone());
                }
                _ => {}
            }
        }
        Ok(certificate)
    }

    /// Reauthenticates durable evidence and returns frozen candidates without mutable state access.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners, corrupt journals and invalid evidence.
    pub fn quorum_candidates(&self) -> Result<Vec<AgreementQuorumCandidate>, StoreError> {
        Ok(self.driver_snapshot()?.2)
    }

    /// Reauthenticates the highest valid POL material, including older views.
    pub fn reproposal_candidate(&self) -> Result<Option<AgreementReproposalCandidate>, StoreError> {
        Ok(self.driver_snapshot()?.3)
    }

    fn replay_owned(&self) -> Result<ReplayState, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        replay(&journal.bootstrap, &journal.events)
    }

    pub(super) fn driver_snapshot(&self) -> Result<DriverSnapshot, StoreError> {
        let (transition, candidates, active, binding, reproposal, _, authorable, _, _, _, _, _, _) =
            self.replay_owned()?;
        Ok((
            active, transition, candidates, reproposal, binding, authorable,
        ))
    }

    /// Reauthenticates the WAL and exports the last applied certified ordering.
    /// The binding, IDs and signed vertices come from one freshness-checked replay.
    /// This read does not apply a decided slot, sign, append, or execute transactions.
    /// Like other durable getters it replays the bounded full WAL, not a hot-loop cache.
    /// # Errors
    /// Rejects stale or uncertain owners, corrupt evidence, and missing ordered vertices.
    pub fn ordering_snapshot(&self) -> Result<AgreementOrderingSnapshot, StoreError> {
        let (_, _, _, binding, _, _, _, _, _, _, _, dag, applications) = self.replay_owned()?;
        let bootstrap = AuthenticatedSlotAgreementBootstrap::decode(&self.header)?;
        let checkpoint_binding = SlotAgreementBinding::from_checkpoint(
            bootstrap.agreement.context,
            bootstrap.predecessor,
        )?;
        let order = dag.dag().order().to_vec();
        let vertices = order
            .iter()
            .map(|id| {
                dag.dag()
                    .get(id.round, &id.author)
                    .cloned()
                    .ok_or_else(|| invalid("applied ordering vertex missing"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(AgreementOrderingSnapshot {
            checkpoint_binding,
            applications,
            binding,
            order,
            vertices,
        })
    }

    /// Derives the next slot from the durable deciding proof without application effects.
    ///
    /// # Errors
    /// Rejects undecided sessions, stale owners, inexact retries and uncertain I/O.
    pub fn advance_slot(&mut self, sequence: u64) -> Result<AgreementTransitionResult, StoreError> {
        self.apply(sequence, AuthenticatedSlotAgreementRequest::AdvanceSlot)
    }

    /// Returns an owned active binding snapshot without exposing mutable replay state.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners and invalid durable evidence.
    pub fn binding(&self) -> Result<SlotAgreementBinding, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        Ok(replay(&journal.bootstrap, &journal.events)?.3)
    }

    /// Number of durably installed requests.
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    /// Persists the full canonical request before releasing a vote or session decision.
    ///
    /// # Errors
    /// Rejects stale owners, inexact retries, invalid evidence, bounds and uncertain I/O.
    pub fn apply(
        &mut self,
        sequence: u64,
        request: AuthenticatedSlotAgreementRequest,
    ) -> Result<AgreementTransitionResult, StoreError> {
        self.apply_with_io(sequence, request, |f, bytes| Ok(f.write_all(bytes)?), sync)
    }
    pub(super) fn apply_with_io(
        &mut self,
        sequence: u64,
        request: AuthenticatedSlotAgreementRequest,
        mut write: impl FnMut(&mut File, &[u8]) -> Result<(), StoreError>,
        mut barrier: impl FnMut(&File, &Path) -> Result<(), StoreError>,
    ) -> Result<AgreementTransitionResult, StoreError> {
        if self.uncertain {
            return Err(invalid("uncertain authenticated write requires recovery"));
        }
        let root = self
            .store
            .slot_decisions
            .lock()
            .expect("slot decision lock poisoned");
        exclusions(&root)?;
        let mut journal = read(&root)?.ok_or_else(|| invalid("authenticated WAL missing"))?;
        if journal.header != self.header
            || journal.events.len() as u64 != self.sequence
            || journal.tip != self.tip
        {
            return Err(invalid("stale authenticated owner"));
        }
        let body = request.encode(&journal.bootstrap.agreement.set)?;
        let reservation_retry = matches!(
            request,
            AuthenticatedSlotAgreementRequest::ReserveCarrier { .. }
                | AuthenticatedSlotAgreementRequest::CompleteCarrier { .. }
                | AuthenticatedSlotAgreementRequest::CompleteNilVote { .. }
                | AuthenticatedSlotAgreementRequest::ReserveViewRequest { .. }
                | AuthenticatedSlotAgreementRequest::CompleteViewRequest { .. }
        ) && sequence > 0
            && journal.events.get((sequence - 1) as usize) == Some(&request);
        let retry = reservation_retry
            || (sequence == self.sequence && journal.events.last() == Some(&request));
        if !retry && sequence != self.sequence + 1 {
            return Err(invalid("incorrect authenticated sequence or retry"));
        }
        let bytes = frame(&self.tip, sequence, &body);
        if !retry {
            if journal.events.len() >= MAX_EVENTS || journal.bytes + bytes.len() as u64 > MAX_BYTES
            {
                return Err(invalid("authenticated WAL capacity exhausted"));
            }
            journal.events.push(request);
        }
        let replay_events = if reservation_retry {
            &journal.events[..sequence as usize]
        } else {
            &journal.events
        };
        let result = replay(&journal.bootstrap, replay_events)?
            .0
            .ok_or_else(|| invalid("no authenticated transition"))?;
        self.uncertain = true;
        let mut file = OpenOptions::new().append(true).open(root.join(FILE))?;
        if !retry {
            write(&mut file, &bytes)?;
        }
        barrier(&file, &root)?;
        self.uncertain = false;
        if !retry {
            self.sequence = sequence;
            self.tip = digest(&self.tip, sequence, &body);
        }
        Ok(result)
    }
}

#[cfg(test)]
mod envelope_tests {
    use super::*;
    use crate::slot_application_tests::{TempDir, unified_fixture};
    use crypto::scheme::Ed25519Scheme;
    use validator::slot_agreement::AgreementValue;
    use validator::{SlotAgreementProofPol, SlotDecisionTip, SlotOutcome, ValidatorSignature};

    fn assembled(
        count: usize,
        phase: AgreementPhase,
    ) -> (validator::ValidatorSet, AgreementQuorumCandidate) {
        let (f, proof, _) = unified_fixture(false);
        let mut keys = Vec::new();
        let mut set = f.set.clone();
        set.validators = (0..count)
            .map(|i| {
                let mut seed = [0; 32];
                seed[..8].copy_from_slice(&i.to_le_bytes());
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                keys.push([seed.as_slice(), public.as_slice()].concat());
                let mut record = f.set.validators[0].clone();
                record.validator_id = format!("{i:04}").into_bytes();
                record.validator_id.resize(1024, b'a');
                record.keys[0].key_id = vec![b'k'; 1024];
                record.keys[0].public_key = public.to_vec();
                record
            })
            .collect();
        let old = f.binding.tip();
        let context = SlotDecisionTip::from_checkpoint(
            old.chain_id().to_vec(),
            &set,
            old.next_round(),
            *old.previous_id(),
            old.order_len(),
            *old.order_root(),
        )
        .unwrap();
        let mut lineage = SlotAgreementViewLineage {
            entries: proof.entries,
        };
        let entry = &mut lineage.entries[0];
        entry.proposal.decision.validator_set_id = set.id().unwrap();
        entry.proposal.decision.outcome = SlotOutcome::Skip {
            leader_author: set.validators[0].validator_id.clone(),
        };
        entry.view_carrier.author = set.validators[0].validator_id.clone();
        let pol_carrier = entry.pol.take().unwrap().carrier;
        let quorum = count * 2 / 3 + 1;
        let make = |phase, prerequisite: VertexId| {
            let mut vote = proof.certificate.vote.clone();
            vote.context = context.clone();
            vote.value = AgreementValue::Decision(entry.proposal.decision.clone());
            vote.phase = phase;
            let payload = vote.signing_payload(&set).unwrap();
            let signatures: Vec<_> = (0..quorum)
                .map(|i| ValidatorSignature {
                    validator_id: set.validators[i].validator_id.clone(),
                    key_id: set.validators[i].keys[0].key_id.clone(),
                    signature: Ed25519Scheme.sign(&keys[i], &payload).unwrap(),
                })
                .collect();
            let witnesses = signatures
                .iter()
                .map(|signature| SlotAgreementVoteWitness {
                    payload: SlotAgreementVotePayload {
                        vote: vote.clone(),
                        signature: signature.clone(),
                        prerequisite: prerequisite.clone(),
                    },
                    carrier: VertexId {
                        round: prerequisite.round + 1,
                        author: signature.validator_id.clone(),
                        digest: [7; 32],
                    },
                })
                .collect();
            (AgreementQc { vote, signatures }, witnesses)
        };
        let (certificate, witnesses) = make(AgreementPhase::Prevote, entry.view_carrier.clone());
        let (certificate, witnesses) = if phase == AgreementPhase::Precommit {
            let final_evidence = make(phase, pol_carrier.clone());
            entry.pol = Some(SlotAgreementProofPol {
                certificate,
                votes: witnesses,
                carrier: pol_carrier,
            });
            final_evidence
        } else {
            (certificate, witnesses)
        };
        (
            set,
            AgreementQuorumCandidate {
                lineage,
                certificate,
                witnesses,
            },
        )
    }

    #[test]
    fn reservations_share_vertex_and_dependency_capacity() {
        let (f, proof, _) = unified_fixture(true);
        let mut unsigned = f.vertices[0].clone();
        unsigned.signature.clear();
        unsigned.references.clear();
        let reservation = AgreementReservedCarrier {
            id: unsigned.id().unwrap(),
            sequence: 1,
            agreement: SlotAgreementBootstrap {
                context: f.binding.tip().clone(),
                set: f.set.clone(),
                local_validator: unsigned.author.clone(),
            },
            binding: SlotAgreementBinding::from_checkpoint(f.binding.tip().clone(), None).unwrap(),
            evidence: AgreementCarrierEvidence::Final { proof },
            unsigned: unsigned.clone(),
        };
        let mut vertices = BTreeMap::new();
        for round in 0..MAX_VERTICES - 1 {
            vertices.insert((round as u64, unsigned.author.clone()), unsigned.clone());
        }
        let reservations = [reservation];
        reservation_bounds(&vertices, &reservations, None).unwrap();
        assert!(reservation_bounds(&vertices, &reservations, Some(&unsigned)).is_err());
        vertices.clear();
        let mut reservations = reservations;
        reservations[0].unsigned.references = vec![unsigned.id().unwrap(); MAX_DEPENDENCIES];
        reservation_bounds(&vertices, &reservations, Some(&unsigned)).unwrap();
        unsigned.references.push(unsigned.id().unwrap());
        assert!(reservation_bounds(&vertices, &reservations, Some(&unsigned)).is_err());
    }

    #[test]
    fn aggregate_candidate_envelopes_are_bounded_before_admission() {
        for phase in [AgreementPhase::Prevote, AgreementPhase::Precommit] {
            let large = if phase == AgreementPhase::Prevote {
                400
            } else {
                180
            };
            for (count, fits) in [(80, true), (large, false)] {
                let (set, candidate) = assembled(count, phase);
                candidate
                    .certificate
                    .verify(&candidate.certificate.vote.context, &set)
                    .unwrap();
                for witness in &candidate.witnesses {
                    witness.payload.encode(&set).unwrap();
                    let request = AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: candidate.lineage.clone(),
                        witness: witness.clone(),
                        vertices: vec![],
                    };
                    request.encode(&set).unwrap();
                }
                assert!(
                    candidate.lineage.encode(&set).unwrap().len()
                        < validator::SLOT_AGREEMENT_PROOF_MAX_BYTES
                );
                assert_eq!(
                    candidate.validate_envelope(&set).is_ok(),
                    fits,
                    "phase {phase:?}, validator count {count}"
                );
                if !fits {
                    let dir = TempDir::new();
                    let store = Store::open(&dir.0).unwrap();
                    let bootstrap = AuthenticatedSlotAgreementBootstrap {
                        agreement: SlotAgreementBootstrap {
                            context: candidate.certificate.vote.context.clone(),
                            set: set.clone(),
                            local_validator: set.validators[0].validator_id.clone(),
                        },
                        predecessor: None,
                        order: vec![],
                        vertices: vec![],
                    };
                    let mut owner = store.begin_authenticated_slot_agreement(bootstrap).unwrap();
                    let path = dir.0.join(FILE);
                    let before = fs::read(&path).unwrap();
                    // The malformed DAG envelope must also fail closed through public
                    // admission; pure aggregate validation above isolates the size cause.
                    let request = AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: candidate.lineage,
                        witness: candidate.witnesses[0].clone(),
                        vertices: vec![],
                    };
                    assert!(
                        owner
                            .apply_with_io(
                                1,
                                request,
                                |_, _| panic!("rejected admission must not append"),
                                |_, _| panic!("rejected admission must not sync")
                            )
                            .is_err()
                    );
                    assert_eq!(owner.sequence(), 0);
                    assert_eq!(fs::read(path).unwrap(), before);
                }
            }
        }
    }
}
