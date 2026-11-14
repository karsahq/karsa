use super::*;
use std::collections::BTreeMap;
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementTransitionResult, AgreementView,
    SlotAgreement,
};
use validator::{
    Dag, SlotAgreementBinding, SlotAgreementProof, SlotAgreementViewLineage,
    SlotAgreementVotePayload, SlotAgreementVoteWitness, Vertex, VertexId,
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

#[derive(Default)]
struct VoteBucket {
    lineage: Option<SlotAgreementViewLineage>,
    witnesses: BTreeMap<Vec<u8>, SlotAgreementVoteWitness>,
    candidate: Option<AgreementQuorumCandidate>,
}

fn replay(
    b: &AuthenticatedSlotAgreementBootstrap,
    events: &[AuthenticatedSlotAgreementRequest],
) -> Result<
    (
        Option<AgreementTransitionResult>,
        Vec<AgreementQuorumCandidate>,
    ),
    StoreError,
> {
    let binding =
        SlotAgreementBinding::from_checkpoint(b.agreement.context.clone(), b.predecessor.clone())?;
    let mut vertices = BTreeMap::new();
    add(&mut vertices, &b.vertices)?;
    build_dag(b, &vertices)?;
    let mut reducer = SlotAgreement::new(b.agreement.context.clone(), b.agreement.set.clone())?;
    let mut result = None;
    let mut buckets: BTreeMap<Vec<u8>, VoteBucket> = BTreeMap::new();
    let mut witness_count = 0usize;
    let mut evidence_bytes = 0usize;
    for event in events {
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
            add(&mut vertices, incoming)?;
            build_dag(b, &vertices)?.inspect_slot_agreement_vote(lineage, witness, &binding)?;
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
            if !buckets.contains_key(&key) && buckets.len() >= MAX_EVENTS {
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
                        .verify(&b.agreement.context, &b.agreement.set)
                        .is_ok()
                    {
                        bucket.candidate = Some(AgreementQuorumCandidate {
                            lineage: bucket
                                .lineage
                                .clone()
                                .ok_or_else(|| invalid("missing bucket lineage"))?,
                            certificate,
                            witnesses: bucket.witnesses.values().cloned().collect(),
                        });
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
            AuthenticatedSlotAgreementRequest::ObserveVote { .. } => {
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
                add(&mut vertices, incoming)?;
                let dag = build_dag(b, &vertices)?;
                let proposal = dag.inspect_slot_agreement_view_lineage(lineage, &binding)?;
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
                add(&mut vertices, incoming)?;
                let dag = build_dag(b, &vertices)?;
                dag.inspect_slot_agreement_proof(proof, carrier, &binding)?;
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
    }
    Ok((
        result,
        buckets.into_values().filter_map(|b| b.candidate).collect(),
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
        })
    }
}
impl AuthenticatedSlotAgreement {
    /// Reauthenticates durable evidence and returns frozen candidates without mutable state access.
    ///
    /// # Errors
    /// Rejects uncertain or stale owners, corrupt journals and invalid evidence.
    pub fn quorum_candidates(&self) -> Result<Vec<AgreementQuorumCandidate>, StoreError> {
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
        Ok(replay(&journal.bootstrap, &journal.events)?.1)
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
        let retry = sequence == self.sequence && journal.events.last() == Some(&request);
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
        let result = replay(&journal.bootstrap, &journal.events)?
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
