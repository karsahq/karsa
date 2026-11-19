//! Bounded trusted local driving, isolated from production agreement scheduling.

use net::wire::Message;
use validator::{
    Decision, SlotAgreementViewCandidate, SlotDecision, SlotOutcome, SlotProposalEnvelope,
    SlotProposalEvidence, Vertex, VertexId,
};

use super::super::pacemaker;
use super::super::{AgreementProgress, CarrierPayload};
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

/// Everything the carrier at `round` will reference, transitively.
///
/// A prospective carrier references every held vertex of `round - 1`, and
/// `Node` requires those references' full retained cone to cover the authored
/// prerequisites (the selected voters and binding carrier). Selecting voters
/// that are outside this cone would make the proposal unready forever, so the
/// proposal builder filters by this exact walk. Budgets mirror the validator's
/// phase walk: exceeding them yields `None` (wait) rather than a signature.
fn prospective_cone(
    dag: &validator::Dag,
    round: u64,
) -> Result<Option<std::collections::HashSet<VertexId>>, String> {
    if round == 0 {
        return Ok(None);
    }
    let previous = round - 1;
    let mut cone = std::collections::HashSet::new();
    let mut stack = Vec::new();
    for record in &dag.set_for_round(previous).validators {
        let Some(vertex) = dag.get(previous, &record.validator_id) else {
            continue;
        };
        let id = vertex.id().map_err(|e| e.to_string())?;
        cone.insert(id.clone());
        stack.push(id);
    }
    let mut nodes = 0usize;
    let mut edges = 0usize;
    while let Some(id) = stack.pop() {
        nodes = nodes.saturating_add(1);
        if nodes > validator::SLOT_AGREEMENT_PHASE_WORK_BUDGET {
            return Ok(None);
        }
        let Some(vertex) = dag.get(id.round, &id.author) else {
            return Ok(None);
        };
        edges = edges.saturating_add(vertex.references.len());
        if edges > 65536 {
            return Ok(None);
        }
        for reference in &vertex.references {
            if reference.round >= id.round {
                return Ok(None);
            }
            if cone.insert(reference.clone()) {
                stack.push(reference.clone());
            }
        }
    }
    Ok(Some(cone))
}

/// First unoccupied local round at or above `min` whose previous round already meets
/// the reference rule.
///
/// A live availability DAG can have a frontier round authored only by this node while
/// peers still lag, so `highest + 1` may name a round that no majority of authors can
/// be referenced from. Scanning from `min` keeps a carrier inside a ready round instead
/// of signing a vertex the DAG would immediately reject.
fn first_reference_ready_round(dag: &validator::Dag, id: &[u8], min: u64) -> Option<u64> {
    let frontier = dag
        .highest_round()
        .map_or(min, |highest| highest.saturating_add(2));
    for round in min..=frontier.max(min) {
        if dag.get(round, id).is_some() {
            continue;
        }
        if round == 0 {
            return Some(0);
        }
        let set = dag.set_for_round(round);
        let authors = set
            .validators
            .iter()
            .filter(|record| dag.get(round - 1, &record.validator_id).is_some())
            .count();
        if authors >= set.quorum_size() {
            return Some(round);
        }
    }
    None
}

/// Earliest local round this node has not authored.
///
/// Carriers and plain causal vertices share one authoring slot per round. A node that
/// jumps its carrier to the global frontier leaves holes below it, and those holes can
/// only be filled once every author retained round `r - 1`; with a small set that is the
/// same quorum the carrier needs, so skipping ahead is what creates the wait. Filling the
/// earliest hole first keeps the local round sequence dense and the reference rule ready.
fn next_local_round(dag: &validator::Dag, id: &[u8]) -> u64 {
    let frontier = dag
        .highest_round()
        .map_or(0, |highest| highest.saturating_add(1));
    (0..=frontier)
        .find(|round| dag.get(*round, id).is_none())
        .unwrap_or(frontier)
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
    candidates: impl IntoIterator<Item = Result<(DurableAction, u64), String>>,
    completed: &std::collections::BTreeSet<[u8; 32]>,
) -> Result<Option<(DurableAction, u64)>, String> {
    for candidate in candidates {
        let (action, round) = candidate?;
        if !completed.contains(&action.id()) {
            return Ok(Some((action, round)));
        }
    }
    Ok(None)
}

/// First round a POL carrier can occupy: after the view carrier and every prevote witness.
fn pol_authoring_minimum(candidate: &validator::SlotAgreementPolCandidate) -> u64 {
    let mut minimum = 0;
    if let Some(entry) = candidate.lineage().entries.last() {
        minimum = minimum.max(entry.view_carrier.round.saturating_add(1));
    }
    let (_, votes) = candidate.evidence();
    for witness in votes {
        minimum = minimum.max(witness.carrier.round.saturating_add(1));
    }
    minimum
}

/// First round a final carrier can occupy: after the selected POL and every precommit witness.
fn final_authoring_minimum(proof: &validator::SlotAgreementProof) -> u64 {
    let mut minimum = 0;
    if let Some(pol) = proof.entries.last().and_then(|entry| entry.pol.as_ref()) {
        minimum = minimum.max(pol.carrier.round.saturating_add(1));
    }
    for witness in &proof.votes {
        minimum = minimum.max(witness.carrier.round.saturating_add(1));
    }
    minimum
}

enum SelectedAction {
    Explicit(Box<AuthoringAction>),
    Durable(DurableAction),
}

pub(super) struct LocalAuthoring {
    pub(super) node: net::Node,
    remaining_imports: usize,
}

impl JournaledFinalization {
    pub(in super::super) fn check_local_authoring(&mut self) -> Result<(), String> {
        self.check_health()?;
        if self.authoring.is_none() {
            return Err("local authoring is not configured".into());
        }
        Ok(())
    }

    /// Requires quorum-certificate entry for every timeout-driven view change.
    /// A live set then signs one advisory next-view request instead of drifting apart
    /// on independent local timers. Explicit offline flows keep the local step.
    pub fn require_certificate_view_change(&mut self) {
        self.adapter.require_certificate_view_change();
    }

    /// Collects end-of-run durable counters for the current slot and view.
    /// Replays the durable journal; grants no ordering, voting or entry authority.
    /// # Errors
    /// Rejects owners poisoned by durable history failures and uncertain evidence.
    pub fn progress_diagnostics(&self) -> Result<AgreementProgress, String> {
        self.ensure_usable()?;
        self.adapter.progress_diagnostics()
    }

    /// Pins one causal Node for this owner's lifetime. No mutable handle is returned.
    /// Recovery requires a fresh explicit setup; timers and retry cadence are volatile.
    /// The Node's committed order is seeded from the owner's applied certified prefix, so
    /// its causal history starts where the durable ordering does.
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
        let snapshot = self.adapter.ordering_snapshot()?;
        let mut node = node;
        node.seed_order(snapshot.order().to_vec());
        self.adapter
            .configure_carrier_retransmission(retry_interval)?;
        self.adapter.configure_retransmission(retry_interval)?;
        self.adapter.configure_pacemaker(policy);
        self.authoring = Some(LocalAuthoring {
            node,
            remaining_imports: 4096,
        });
        Ok(())
    }

    /// The owned causal Node's committed order and total coverage, for diagnostics only.
    /// `None` when local authoring is not configured. This is a clone of the prefix the
    /// Node was last seeded with, not a mutable handle or a second ordering authority.
    pub fn local_causal_coverage(&self) -> Option<(usize, Vec<VertexId>)> {
        self.authoring.as_ref().map(|local| {
            (
                local.node.dag().order_len(),
                local.node.dag().order().to_vec(),
            )
        })
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
    /// Signing never precedes reservation. Every signed publication is delivered back
    /// through the same authenticated receipt path peers use, so the author observes the
    /// exact evidence it published instead of waiting for a peer to echo it.
    pub fn author_local(&mut self, request: AuthoringRequest) -> Result<Vec<Message>, String> {
        let authored = self
            .import_local(request.vertices)
            .and_then(|()| self.author_local_action(request.round, request.action));
        self.deliver_own_publications(authored)
    }

    /// Imports trusted availability and attempts one durable nil or positive-phase obligation.
    /// When no carrier obligation is authorable, echoes the largest exact future view target with
    /// more than `f` distinct authenticated signers. The echo never invents a target, derives one
    /// from local view advancement, or signs a stale view; it only signs already-observed support
    /// once, and later retransmission belongs to the bounded control-retry cadence.
    /// A retained POL additionally makes an elected proposer author the re-proposal for the
    /// current view: one fresh plain proposal carrier first, then one exact view carrier bound to
    /// the durable POL prefix. Neither step invents a decision or evidence.
    /// The prospective round is the first reference-ready unoccupied round at or above the
    /// frontier, raised to at least one round after the selected action's prerequisite
    /// carrier (and after the previous decision carrier a proposal binds). It is not a
    /// protocol-phase counter. Nil votes use their durable intent, not a fabricated carrier;
    /// an empty DAG authors no carrier but can still echo observed view support. Full durable cone
    /// validation remains authoritative; a high incomplete frontier can stall rather than invent
    /// progression. Completed payloads are not reauthored, including after explicit owner
    /// recovery. Durable selection/reconstruction is capped at 4096 WAL events, not storage bytes.
    /// Authors at most one durable phase, one current-view direct-commit proposal and
    /// its elected view authorization (with an empty POL prefix when the view has none),
    /// one elected re-proposal, or one view echo; it does
    /// not tick, retry or apply a slot. A signed publication is delivered back through
    /// the same authenticated receipt path peers use, so the author observes it locally.
    /// # Errors
    /// Propagates bounded import, ownership, round overflow and durable authoring errors.
    pub fn drive_local(&mut self, vertices: Vec<Vertex>) -> Result<Vec<Message>, String> {
        let authored = self.drive_local_turn(vertices);
        self.deliver_own_publications(authored)
    }

    /// One local turn: at most one authored publication, without local receipt.
    fn drive_local_turn(&mut self, vertices: Vec<Vertex>) -> Result<Vec<Message>, String> {
        self.import_local(vertices)?;
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("local durable selection exceeds 4096 events".into());
        }
        let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
        let completed = self.adapter.completed_nil_votes()?;
        let nil_id = self
            .adapter
            .signing_history()
            .iter()
            .find(|intent| {
                intent.vote.value == validator::slot_agreement::AgreementValue::Nil
                    && output.authorable_vote_ids.contains(&intent.id)
                    && !completed.iter().any(|done| done.intent_id == intent.id)
            })
            .map(|intent| intent.id);
        if let Some(id) = nil_id {
            let result = self.adapter.author_nil_vote(id).and_then(|vote| {
                vote.map(|vote| {
                    vote.encode(&self.adapter.set)
                        .map(Message::AgreementNilVote)
                        .map_err(|e| e.to_string())
                })
                .transpose()
                .map(|message| message.into_iter().collect())
            });
            self.check_health()?;
            return result;
        }
        let local = self
            .authoring
            .as_ref()
            .ok_or("local authoring is not configured")?;
        // Author at a round the reference rule can actually satisfy. The frontier round
        // itself is often authored only by this node, so `highest + 1` would reference a
        // single author and every durable vote carrier would wait forever.
        let round = match local.node.dag().highest_round() {
            Some(highest) => first_reference_ready_round(
                local.node.dag(),
                local.node.id(),
                highest.saturating_add(1),
            ),
            None => Some(0),
        };
        let authored = match round {
            Some(round) => self.author_local_action(round, AuthoringAction::Durable)?,
            None => Vec::new(),
        };
        if !authored.is_empty() {
            return Ok(authored);
        }
        let proposed = self.propose_plain_local()?;
        if !proposed.is_empty() {
            return Ok(proposed);
        }
        let bound = self.bind_plain_view_local()?;
        if !bound.is_empty() {
            return Ok(bound);
        }
        let elected = self.elect_view_local()?;
        if !elected.is_empty() {
            return Ok(elected);
        }
        self.echo_view_local()
    }

    /// Authors one plain causal vertex for the owned availability mesh.
    ///
    /// The certified proposal and vote rules read a causal DAG, so a live node has to
    /// produce the same kind of vertex the legacy loop produces before any agreement
    /// evidence exists. This signs exactly that vertex: no proposal, view, vote or
    /// aggregate, and no slot application. `payload_hash` is local data-plane input;
    /// zero names no batch, and a digest names the batch the caller holds.
    ///
    /// The vertex is authored at the first unoccupied local round and only when the
    /// references that round requires are already retained. An unavailable round
    /// waits for the next turn; nothing is invented. The returned vertex is already
    /// inserted into the owned causal DAG, so the caller publishes it once.
    /// # Errors
    /// Rejects absent authoring, bounded import failures, a pinned-context mismatch,
    /// and signing or DAG insertion failures.
    pub fn author_causal_local(
        &mut self,
        vertices: Vec<Vertex>,
        payload_hash: [u8; 32],
    ) -> Result<Vec<Message>, String> {
        self.import_local(vertices)?;
        let output = self.adapter.driver.output().map_err(|error| {
            self.failed = true;
            error.to_string()
        })?;
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        if !local.node.matches_authoring_context(
            output.binding.tip(),
            &self.adapter.set,
            &self.adapter.validator_id,
            &self.adapter.private_key,
        ) {
            return Err(
                "Node differs from pinned agreement identity, chain, epoch, set or key".into(),
            );
        }
        // Fill the earliest local gap, not merely the frontier: a node that learns peers'
        // round-zero vertices before its first turn must still author its own, or it waits
        // forever for a quorum it can no longer join.
        let round = next_local_round(local.node.dag(), local.node.id());
        // Re-setting the round is deliberate: the durable obligation path moves the
        // Node to a carrier round between turns, and the next free round is what the
        // reference rule accepts, not whatever the last carrier used.
        local.node.set_round(round);
        let Some(vertex) = local
            .node
            .author_with(payload_hash)
            .map_err(|error| error.to_string())?
        else {
            return Ok(Vec::new());
        };
        Ok(vec![Message::Vertex(vertex)])
    }

    /// Delivers signed local publications to this owner as a peer's receipt would.
    ///
    /// The durable driver records a completed carrier as a publication, not as a reducer
    /// input, so without this the author would never observe the proposal, view
    /// authorization, vote or aggregate it just signed. Delivery re-authenticates the
    /// exact wire message against the pinned binding and retained causal evidence: it
    /// grants no voting authority and applies no slot. Control publications (view
    /// requests) are already self-observed where they are authorized, so they are not
    /// sent through this path again.
    fn deliver_own_publications(
        &mut self,
        authored: Result<Vec<Message>, String>,
    ) -> Result<Vec<Message>, String> {
        let messages = authored?;
        for message in &messages {
            if matches!(
                message,
                Message::AgreementCarrier { .. } | Message::AgreementNilVote(_)
            ) {
                self.receive_agreement_message(message.clone())?;
            }
        }
        Ok(messages)
    }

    /// Authors the current-view plain proposal when this validator is elected and the
    /// direct commit rule has already decided the slot.
    ///
    /// A view whose lock has no released POL still needs a proposal: a timeout can move
    /// the whole set to view 1 before any POL exists, and without this path no validator
    /// would ever propose again. The plain proposal is valid in any current view; a view
    /// with a retained POL is handled by [`Self::elect_view_local`] instead.
    /// # Errors
    /// Rejects unhealthy owners, histories above 4096 events, arithmetic
    /// exhaustion, and durable authoring failures.
    fn propose_plain_local(&mut self) -> Result<Vec<Message>, String> {
        self.check_health()?;
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("local proposal selection exceeds 4096 events".into());
        }
        let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
        let (view, decided) = match output.transition.as_ref() {
            Some(transition) => (transition.view, transition.decision.is_some()),
            None => (validator::slot_agreement::AgreementView(0), false),
        };
        if decided || output.reproposal.is_some() {
            return Ok(Vec::new());
        }
        let tip = output.binding.tip().clone();
        let round = tip.next_round();
        let elected = validator::slot_agreement_view_proposer(&self.adapter.set, round, view)
            .map_err(|e| e.to_string())?;
        if elected != self.adapter.validator_id.as_slice() {
            return Ok(Vec::new());
        }
        let proposal = {
            let local = self
                .authoring
                .as_mut()
                .ok_or("local authoring is not configured")?;
            let dag = local.node.dag();
            let Some(highest) = dag.highest_round() else {
                return Ok(Vec::new());
            };
            let voting_round = round.saturating_add(1);
            if highest < voting_round {
                return Ok(Vec::new());
            }
            // The proposal carrier must follow the previous decision carrier it binds and
            // the voting round one above this decision, so the scan starts at that exact
            // minimum rather than at a protocol-phase counter.
            let minimum = round.saturating_add(2).max(
                output
                    .binding
                    .carrier()
                    .map_or(0, |carrier| carrier.round.saturating_add(1)),
            );
            let Some(carrier_round) = first_reference_ready_round(
                dag,
                local.node.id(),
                highest.saturating_add(1).max(minimum),
            ) else {
                return Ok(Vec::new());
            };
            let Decision::Commit(history) = dag.inspect_commit(round).map_err(|e| e.to_string())?
            else {
                return Ok(Vec::new());
            };
            let Some(leader) = dag.leader(round) else {
                return Ok(Vec::new());
            };
            let leader_id = leader.id().map_err(|e| e.to_string())?;
            let Some(cone) = prospective_cone(dag, carrier_round)? else {
                return Ok(Vec::new());
            };
            let quorum = dag.set_for_round(round).quorum_size();
            let mut voters: Vec<VertexId> = dag
                .set_for_round(voting_round)
                .validators
                .iter()
                .filter_map(|record| dag.get(voting_round, &record.validator_id))
                .filter(|vertex| vertex.references.contains(&leader_id))
                .filter_map(|vertex| vertex.id().ok())
                .filter(|id| cone.contains(id))
                .collect();
            voters.sort_by(|a, b| {
                (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest))
            });
            if voters.len() < quorum {
                return Ok(Vec::new());
            }
            voters.truncate(quorum);
            let mut frontier = dag.prefix().clone();
            frontier.extend(dag.order());
            frontier.extend(&history);
            let decision = SlotDecision {
                chain_id: tip.chain_id().to_vec(),
                validator_set_id: *tip.set_id(),
                epoch: tip.epoch(),
                round,
                previous: *tip.previous_id(),
                before_len: tip.order_len(),
                before_root: *tip.order_root(),
                after_len: u64::try_from(frontier.len()).map_err(|_| "order length exceeds u64")?,
                after_root: frontier.root(),
                outcome: SlotOutcome::Commit { leader: leader_id },
            };
            (
                carrier_round,
                SlotProposalEnvelope {
                    decision,
                    evidence: SlotProposalEvidence::Direct { voters },
                },
            )
        };
        let (carrier_round, proposal) = proposal;
        let completed = self.adapter.completed_carriers()?;
        if completed.iter().any(|carrier| {
            matches!(
                carrier.envelope.payload(),
                CarrierPayload::Proposal(old) if old.decision == proposal.decision
            )
        }) {
            return Ok(Vec::new());
        }
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        local.node.set_round(carrier_round);
        let authored = self.adapter.author_proposal(&proposal, &mut local.node)?;
        let result = match authored {
            Some(carrier) => self
                .adapter
                .export_carrier(
                    &carrier.vertex.id().map_err(|e| e.to_string())?,
                    local.node.dag(),
                )
                .map(|message| vec![message]),
            None => Ok(Vec::new()),
        };
        self.check_health()?;
        result
    }

    /// Authorizes the elected plain step by binding the completed proposal in the current view.
    ///
    /// The candidate is copied from the durable proposal carrier, never rebuilt from
    /// local state: the same envelope, the same carrier, the same decision and an empty
    /// prefix (no prior POL). Only the elected proposer acts, only once per view, and
    /// only after its own plain proposal is completed. Receipt of this carrier is what
    /// authorizes peers' prevote intents; authoring it locally does not vote on its own.
    /// This is the view-change liveness pair to [`Self::propose_plain_local`]: a timeout
    /// can enter a new view before any POL exists, so an empty prefix is still valid.
    /// # Errors
    /// Rejects unhealthy owners, histories above 4096 events, missing authoring setup,
    /// candidate construction failures and durable authoring failures.
    fn bind_plain_view_local(&mut self) -> Result<Vec<Message>, String> {
        self.check_health()?;
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("local view authorization exceeds 4096 events".into());
        }
        let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
        let (view, decided) = match output.transition.as_ref() {
            Some(transition) => (transition.view, transition.decision.is_some()),
            None => (validator::slot_agreement::AgreementView(0), false),
        };
        if decided || output.reproposal.is_some() {
            return Ok(Vec::new());
        }
        let tip = output.binding.tip().clone();
        let round = tip.next_round();
        let elected = validator::slot_agreement_view_proposer(&self.adapter.set, round, view)
            .map_err(|e| e.to_string())?;
        if elected != self.adapter.validator_id.as_slice() {
            return Ok(Vec::new());
        }
        let completed = self.adapter.completed_carriers()?;
        if completed.iter().any(|old| {
            matches!(
                old.envelope.payload(),
                CarrierPayload::View(lineage)
                    if lineage.entries.last().is_some_and(|entry| {
                        entry.view == view && entry.proposal.decision.round == round
                    })
            )
        }) {
            return Ok(Vec::new());
        }
        let proposal = completed
            .iter()
            .rev()
            .find_map(|old| match old.envelope.payload() {
                CarrierPayload::Proposal(proposal)
                    if old.vertex.author == self.adapter.validator_id
                        && proposal.decision.round == round =>
                {
                    Some((proposal.clone(), old.envelope.carrier().clone()))
                }
                _ => None,
            });
        let Some((proposal, proposal_carrier)) = proposal else {
            return Ok(Vec::new());
        };
        let view_min_round = proposal_carrier.round.saturating_add(1);
        let candidate = validator::SlotAgreementViewCandidate::new(
            Vec::new(),
            proposal,
            proposal_carrier,
            view,
            &self.adapter.set,
        )
        .map_err(|e| e.to_string())?;
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        let highest = local.node.dag().highest_round().unwrap_or(0);
        let Some(round) = first_reference_ready_round(
            local.node.dag(),
            local.node.id(),
            highest.saturating_add(1).max(view_min_round),
        ) else {
            return Ok(Vec::new());
        };
        local.node.set_round(round);
        let authored = self.adapter.author_view(&candidate, &mut local.node)?;
        let result = match authored {
            Some(carrier) => self
                .adapter
                .export_carrier(
                    &carrier.vertex.id().map_err(|e| e.to_string())?,
                    local.node.dag(),
                )
                .map(|message| vec![message]),
            None => Ok(Vec::new()),
        };
        self.check_health()?;
        result
    }

    /// Authors at most one elected re-proposal step for the current durable view.
    /// A fresh plain proposal comes first; the next call binds its completed carrier to the exact
    /// retained POL prefix as the view carrier. The most recent local proposal for the selected
    /// decision is reused; when causal readiness cannot reach it, the step waits instead of
    /// signing another copy. The decision and evidence are copied from the authenticated
    /// reproposal lineage, never constructed from local timers or DAG guesses.
    /// Only the elected proposer acts, only after a prior POL exists, and never twice per view.
    /// A view with no released POL uses the plain proposal pair
    /// [`Self::propose_plain_local`] / [`Self::bind_plain_view_local`] instead; conservative
    /// or indirect initial evidence remains explicit.
    fn elect_view_local(&mut self) -> Result<Vec<Message>, String> {
        self.check_health()?;
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("local view election exceeds 4096 durable events".into());
        }
        let output = self.adapter.driver.output().map_err(|e| e.to_string())?;
        let Some(transition) = output.transition.as_ref() else {
            return Ok(Vec::new());
        };
        if transition.decision.is_some() {
            return Ok(Vec::new());
        }
        let view = transition.view;
        let Some(reproposal) = output.reproposal.as_ref() else {
            return Ok(Vec::new());
        };
        let entries = reproposal.lineage().entries.as_slice();
        let Some(prior) = entries.last() else {
            return Ok(Vec::new());
        };
        if prior.pol.is_none() || prior.view >= view {
            return Ok(Vec::new());
        }
        let decision = prior.proposal.decision.clone();
        let elected =
            validator::slot_agreement_view_proposer(&self.adapter.set, decision.round, view)
                .map_err(|e| e.to_string())?;
        if elected != self.adapter.validator_id.as_slice() {
            return Ok(Vec::new());
        }
        let publications = self.adapter.completed_carriers()?;
        if publications.iter().any(|carrier| {
            matches!(
                carrier.envelope.payload(),
                CarrierPayload::View(lineage)
                    if lineage.entries.last().is_some_and(|entry| {
                        entry.view == view && entry.proposal.decision == decision
                    })
            )
        }) {
            return Ok(Vec::new());
        }
        let proposal_carrier =
            publications
                .iter()
                .rev()
                .find_map(|carrier| match carrier.envelope.payload() {
                    CarrierPayload::Proposal(proposal)
                        if proposal == &prior.proposal
                            && carrier.vertex.author == self.adapter.validator_id =>
                    {
                        Some(carrier.envelope.carrier().clone())
                    }
                    _ => None,
                });
        let reproposal_min_round = match (&proposal_carrier, prior.pol.as_ref()) {
            (Some(carrier), Some(pol)) => carrier.round.max(pol.carrier.round).saturating_add(1),
            (Some(carrier), None) => carrier.round.saturating_add(1),
            // A plain proposal needs a carrier after its voting round and after the
            // previous decision carrier the proposal binds.
            (None, _) => decision.round.saturating_add(2).max(
                output
                    .binding
                    .carrier()
                    .map_or(0, |carrier| carrier.round.saturating_add(1)),
            ),
        };
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        let highest = local.node.dag().highest_round().unwrap_or(0);
        let Some(round) = first_reference_ready_round(
            local.node.dag(),
            local.node.id(),
            highest.saturating_add(1).max(reproposal_min_round),
        ) else {
            return Ok(Vec::new());
        };
        local.node.set_round(round);
        let authored = match proposal_carrier {
            None => self
                .adapter
                .author_proposal(&prior.proposal, &mut local.node)?,
            Some(carrier) => {
                let candidate = validator::SlotAgreementViewCandidate::new(
                    entries.to_vec(),
                    prior.proposal.clone(),
                    carrier,
                    view,
                    &self.adapter.set,
                )
                .map_err(|e| e.to_string())?;
                self.adapter.author_view(&candidate, &mut local.node)?
            }
        };
        let result = match authored {
            Some(carrier) => self
                .adapter
                .export_carrier(
                    &carrier.vertex.id().map_err(|e| e.to_string())?,
                    local.node.dag(),
                )
                .map(|message| vec![message]),
            None => Ok(Vec::new()),
        };
        self.check_health()?;
        result
    }

    /// Echoes at most one exact future view target already supported by more than `f`
    /// distinct authenticated signers. Support comes only from authenticated receipt or
    /// durable local publications; local timers, decisions and causal state create no target.
    /// Only a newly authored publication is returned; an already completed echo is left to the
    /// bounded control-retry cadence so automatic driving cannot starve carrier retries.
    fn echo_view_local(&mut self) -> Result<Vec<Message>, String> {
        self.check_health()?;
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("local view echo exceeds 4096 durable events".into());
        }
        let before = self.adapter.driver.sequence();
        let echoed = self.adapter.echo_view_request();
        let result = match echoed {
            Ok(Some(request)) if self.adapter.driver.sequence() != before => request
                .encode(&self.adapter.set)
                .map(Message::AgreementViewRequest)
                .map(|message| vec![message])
                .map_err(|e| e.to_string()),
            Ok(_) => Ok(Vec::new()),
            Err(error) => Err(error),
        };
        self.check_health()?;
        result
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
        let (action, minimum) = if matches!(action, AuthoringAction::Durable) {
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
            // A vote whose exact prerequisite carrier the owned Node has not retained
            // cannot be authored this turn: the prospective cone requires that carrier.
            // Prefer an aggregate this node is elected to publish before spending the turn
            // on a guaranteed no-op, which would starve the aggregate forever.
            let vote_ready = vote
                .as_ref()
                .is_some_and(|intent| match &intent.prerequisite {
                    store::AgreementSigningPrerequisite::Carrier(carrier) => self
                        .authoring
                        .as_ref()
                        .and_then(|local| local.node.dag().get(carrier.round, &carrier.author))
                        .and_then(|vertex| vertex.id().ok())
                        .is_some_and(|held| held == *carrier),
                    store::AgreementSigningPrerequisite::UnsupportedNil => false,
                });
            let vote_action = vote.as_ref().map(|intent| {
                // A vote carrier must follow its selected prerequisite carrier. Authoring it
                // one round early is rejected by the prospective cone, so the action carries
                // its exact minimum instead of trusting the caller's frontier scan.
                let minimum = match &intent.prerequisite {
                    store::AgreementSigningPrerequisite::Carrier(carrier) => {
                        carrier.round.saturating_add(1)
                    }
                    store::AgreementSigningPrerequisite::UnsupportedNil => 0,
                };
                (
                    SelectedAction::Durable(DurableAction::Vote(intent.id)),
                    Some(minimum),
                )
            });
            let selected = if vote_ready {
                vote_action
            } else {
                // The precommit vote binds its prerequisite POL carrier by exact vertex ID, and
                // a precommit quorum therefore needs one shared POL carrier. Every node can
                // assemble the same POL candidate, but a carrier is a locally authored vertex,
                // so competing carriers would make every precommit bind a different prerequisite
                // and no quorum could ever form. The elected view proposer publishes that carrier;
                // the other validators wait and bind their precommits to the one they observe.
                let candidates =
                    output
                        .candidates
                        .into_iter()
                        .filter_map(|candidate| match candidate {
                            store::SlotAgreementCarrierCandidate::PendingPol(candidate) => {
                                let Some(entry) = candidate.lineage().entries.last() else {
                                    return Some(Err("POL candidate lacks a lineage entry".into()));
                                };
                                match validator::slot_agreement_view_proposer(
                                    &self.adapter.set,
                                    entry.proposal.decision.round,
                                    entry.view,
                                ) {
                                    Ok(elected) if elected == self.adapter.validator_id => {
                                        let minimum = pol_authoring_minimum(&candidate);
                                        Some(Ok((DurableAction::Pol(candidate.digest()), minimum)))
                                    }
                                    Ok(_) => None,
                                    Err(error) => Some(Err(error.to_string())),
                                }
                            }
                            store::SlotAgreementCarrierCandidate::PendingFinalProof(proof) => Some(
                                proof
                                    .digest(&self.adapter.set)
                                    .map(|digest| {
                                        let minimum = final_authoring_minimum(&proof);
                                        (DurableAction::Final(digest), minimum)
                                    })
                                    .map_err(|e| e.to_string()),
                            ),
                        });
                match select_uncompleted_aggregate(candidates, &completed)? {
                    Some((action, minimum)) => {
                        Some((SelectedAction::Durable(action), Some(minimum)))
                    }
                    // Nothing this node may publish: keep the vote selected so the turn
                    // waits for the carrier instead of authoring anything.
                    None => vote_action,
                }
            };
            let Some(selected) = selected else {
                return Ok(Vec::new());
            };
            selected
        } else {
            (SelectedAction::Explicit(Box::new(action)), None)
        };
        let local = self
            .authoring
            .as_mut()
            .ok_or("local authoring is not configured")?;
        let round = match minimum {
            Some(minimum) => {
                // A carrier must follow its selected prerequisite, and the caller's frontier
                // scan may sit below it. Raising the minimum keeps the prospective carrier
                // valid without changing the reference-ready scan itself.
                let Some(ready) = first_reference_ready_round(
                    local.node.dag(),
                    local.node.id(),
                    round.max(minimum),
                ) else {
                    return Ok(Vec::new());
                };
                ready
            }
            None => round,
        };
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

    /// Applies at most one pacemaker action and returns one newly authored view request.
    /// Nil obligations are published by `drive_local`; ticks never sign a vote.
    /// Under the certificate policy an elapsed grace signs one next-view advisory request
    /// and leaves local view entry to the quorum certificate path.
    /// # Errors
    /// Rejects absent setup, backwards time, arithmetic exhaustion and unhealthy owners.
    pub fn tick_local(&mut self, now: std::time::Instant) -> Result<Vec<Message>, String> {
        self.check_health()?;
        if self.authoring.is_none() {
            return Err("local authoring is not configured".into());
        }
        let result = match self.adapter.tick(now) {
            Ok(Some(pacemaker::Action::RequestView { target })) => self
                .adapter
                .view_request_message(target)
                .map(|message| message.into_iter().collect()),
            Ok(_) => Ok(Vec::new()),
            Err(error) => Err(error),
        };
        self.check_health()?;
        result
    }

    /// Retries at most one durable control publication using the adapter's own cadence.
    /// Includes nil votes and already-authorized view requests/certificates, not new
    /// future-view authorization. Recovery must explicitly re-enable local authoring.
    /// # Errors
    /// Rejects absent setup, histories above 4096 events and adapter retransmission errors.
    pub(in super::super) fn retry_controls_local(
        &mut self,
        now: std::time::Instant,
    ) -> Result<Vec<Message>, String> {
        self.check_local_authoring()?;
        if self.adapter.driver.sequence() > super::super::MAX_CARRIER_EXPORT_EVENTS {
            return Err("local control retry exceeds 4096 events".into());
        }
        let result = self
            .adapter
            .retransmit(now)
            .map(|message| message.into_iter().collect());
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
                select_uncompleted_aggregate([Ok((first, 0)), Ok((second, 0))], &completed)
                    .unwrap();
            assert_eq!(
                selected,
                Some((second, 0)),
                "must dispatch the uncompleted candidate, not reselect the first of its kind"
            );
            let completed = std::collections::BTreeSet::from([first.id(), second.id()]);
            assert_eq!(
                select_uncompleted_aggregate([Ok((first, 0)), Ok((second, 0))], &completed)
                    .unwrap(),
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
