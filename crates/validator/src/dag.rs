//! A round-based DAG: vertices, leader election, and the commit rules.
//!
//! What is here:
//!
//! - vertices stored one per `(round, author)`, verified against the schedule;
//! - deterministic leader election as a function of the round;
//! - the **direct** rule: a leader with a supermajority of next-round votes
//!   commits, a leader with a supermajority of next-round non-votes is skipped,
//!   and anything else is undecided;
//! - the **indirect** rule: a committed anchor two or more rounds later settles an
//!   earlier slot by reachability;
//! - causal history: a commit includes the leader's ancestors, each exactly once.
//!
//! What is **not** here, and must not be assumed: waves or pipelining, and any
//! treatment of asynchrony. In particular, absence of a vote is never evidence: a
//! leader is only skipped when a supermajority is *observed* not to reference it,
//! when a committed anchor two or more rounds later does not reach it, or when
//! `crate::Pacemaker` proves from an anchor that its vertex cannot exist. Driving
//! rounds forward is the pacemaker's job, not this module's.

use std::collections::{BTreeMap, HashSet};

use crypto::merkle::{MerkleProof, MerkleTree};
use crypto::{CryptoError, CryptoErrorKind};

use crate::control::ControlPayload;
use crate::fence::{Fence, FenceCertificate, FenceError};
use crate::frontier::CommitFrontier;
use crate::round_skip::{RoundSkipCheck, RoundSkipError, RoundSkipProof};
use crate::schedule::{EpochSchedule, ValidatorSet};
use crate::set_change::{SetChangeError, SetSchedule, Transition, TransitionCertificate};
use crate::vertex::{Vertex, VertexId, tally_votes};

/// The outcome of asking a round to decide.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The leader and its not-yet-committed history, in commit order.
    Commit(Vec<VertexId>),
    /// A supermajority of the next round did not reference the leader.
    Skip,
    /// Neither quorum has been observed yet.
    Undecided,
}

/// What a selected anchor's causal history says about a round-skip certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnchorSkip {
    /// No valid certificate for the target round is inside the anchor history.
    None,
    /// A valid certificate is inside the anchor history.
    ///
    /// Stage B reports it without changing the anchor decision. The check is
    /// returned so the caller can audit which evidence the certificate used.
    Certificate(RoundSkipCheck),
}

/// A round whose leader this node has decided to skip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SkippedRound {
    /// The round whose leader was skipped.
    pub round: u64,
    /// The elected author of that round.
    pub author: Vec<u8>,
    /// Digest of the leader's vertex, or `None` when this node never received it.
    ///
    /// A missing digest matters: it records a skip argued from an anchor rather
    /// than from the leader's own content.
    pub digest: Option<[u8; 32]>,
}

/// Vertices this node holds, plus what it has already committed.
pub struct Dag {
    sets: SetSchedule,
    vertices: BTreeMap<(u64, Vec<u8>), Vertex>,
    committed: HashSet<[u8; 32]>,
    order: Vec<VertexId>,
    /// Committed entries below the retained tail, summarized by their peaks.
    ///
    /// A checkpoint restart drops the leaves at or below the DAG floor but must
    /// keep contributing them to every later `dag_root`; this is that contribution.
    /// A run that never seeded a compact prefix has an empty frontier and its
    /// `order` is the whole committed sequence.
    prefix: CommitFrontier,
    skipped: Vec<SkippedRound>,
    /// Which epoch each round belongs to.
    schedule: EpochSchedule,
    /// Highest round that has been committed and dropped, if any.
    ///
    /// Everything at or below it is already reflected in a state snapshot, so the
    /// node neither stores nor re-decides it.
    floor: Option<u64>,
    /// Quorum-authorized failures, keyed by validator id. The value is the first
    /// round at which the validator is fenced, plus the certificate that proved it.
    fences: BTreeMap<Vec<u8>, (u64, FenceCertificate)>,
    /// Failures this node signed but has not seen a quorum certificate for yet.
    ///
    /// A signature is a promise not to vote for that author from the round on.
    /// Keeping the promise here, separately from the certified fences, lets a
    /// node stop voting immediately without rejecting vertices it may still need
    /// to follow the chain.
    local_fences: BTreeMap<Vec<u8>, u64>,
    /// Round-skip proofs this node verified, keyed by leader round.
    ///
    /// A proof is evidence that the round cannot reach a vote quorum: held votes,
    /// held non-votes, no-vote promises, fenced absent voters, and explicitly
    /// missing voters are partitioned, and the bound stays below the quorum.
    /// Keeping it beside the vertices lets the pacemaker release the cursor from
    /// a quorum statement rather than from a local completeness check.
    round_skips: BTreeMap<u64, RoundSkipProof>,
    /// Chain identifier control payloads are verified against.
    ///
    /// Vertex signatures are bound by the set schedule, but a round-skip
    /// certificate carries its own chain id. `Node` sets this from the same id
    /// it signs vertices with; an empty value means no certificate can verify,
    /// which is the safe default for fixtures that never exercise one.
    chain_id: Vec<u8>,
    /// Control payloads received on the data plane, keyed by the digest their
    /// binding vertex names.
    ///
    /// A payload is not a decision here: it is applied only once the vertex that
    /// names it is held, so the skip has a causal position in the DAG. A payload
    /// that arrives first waits; the pacemaker also waits instead of deciding
    /// the same round through an anchor.
    controls: BTreeMap<[u8; 32], ControlPayload>,
    /// The first vertex that named each payload digest.
    ///
    /// This maps a control payload back to its binding vertex without scanning
    /// every held vertex.
    payload_vertices: BTreeMap<[u8; 32], VertexId>,
}

/// Inactive, exclusively owned DAG whose decisions can only advance through certificates.
///
/// This wrapper does not activate consensus, sign, finalize transactions, or provide persistence.
/// Checkpoint trust and durable request logging remain the caller's responsibility.
pub struct CertifiedDag {
    dag: Dag,
    binding: crate::SlotDecisionBinding,
    last_event: Option<([u8; 32], VertexId)>,
}

/// Outcome of applying a prepared certificate request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotApplicationResult {
    /// A new decision and its binding were installed together.
    Applied {
        /// The newly decided round.
        round: u64,
        /// The inspected effect in deterministic commit order.
        decision: Decision,
    },
    /// The exact most recently applied payload and QC carrier were retried.
    AlreadyApplied {
        /// The previously applied round.
        round: u64,
    },
}

/// Exclusive, validated application plan; dropping it leaves the DAG unchanged.
///
/// No persistence is performed. The borrow prevents ingest or another preparation
/// from invalidating the inspected effect before application.
///
/// ```compile_fail
/// use validator::{CertifiedDag, SlotCertificatePayload, Vertex, VertexId};
/// fn cannot_ingest_while_prepared(
///     dag: &mut CertifiedDag,
///     payload: &SlotCertificatePayload,
///     carrier: &VertexId,
///     vertex: Vertex,
/// ) {
///     let prepared = dag.prepare(payload, carrier).unwrap();
///     dag.insert(vertex).unwrap(); // The exclusive application borrow is still live.
///     prepared.apply();
/// }
/// ```
#[must_use = "dropping a prepared application leaves the DAG unchanged"]
pub struct PreparedSlotApplication<'a> {
    owner: &'a mut CertifiedDag,
    plan: SlotApplicationPlan,
}

#[expect(
    clippy::large_enum_variant,
    reason = "the short-lived exclusive plan stays inline to avoid an extra allocation per application"
)]
enum SlotApplicationPlan {
    AlreadyApplied {
        round: u64,
    },
    Apply {
        round: u64,
        decision: Decision,
        skipped: Option<SkippedRound>,
        tip: crate::SlotDecisionTip,
        fingerprint: ([u8; 32], VertexId),
    },
}

impl CertifiedDag {
    /// Takes ownership of a trusted checkpoint after checking its local context and frontier.
    ///
    /// This checks consistency, not checkpoint authentication or historical authorization.
    /// The caller must trust the DAG, tip, and predecessor-carrier association. No last
    /// event is restored: retry recognition starts only after a validated application.
    ///
    /// # Errors
    /// Rejects chain, frontier, or pinned validator-set/epoch mismatches and set encoding errors.
    pub fn from_checkpoint(
        dag: Dag,
        binding: crate::SlotDecisionBinding,
    ) -> Result<Self, CryptoError> {
        let tip = binding.tip();
        if dag.chain_id() != tip.chain_id()
            || dag.order_len() as u64 != tip.order_len()
            || dag.commit_root() != *tip.order_root()
            || dag.set_for_round(tip.next_round()).id()? != *tip.set_id()
            || dag.epoch_of(tip.next_round()) != tip.epoch()
        {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedCertificate,
                "certified DAG checkpoint context mismatch",
            ));
        }
        Ok(Self {
            dag,
            binding,
            last_event: None,
        })
    }

    /// Borrows the DAG without exposing legacy mutation or decision APIs.
    pub fn dag(&self) -> &Dag {
        &self.dag
    }

    /// Borrows the current tip and its associated QC carrier.
    pub fn binding(&self) -> &crate::SlotDecisionBinding {
        &self.binding
    }

    /// Ingests a vertex using the DAG's signature and reference checks.
    ///
    /// # Errors
    /// Propagates vertex validation errors from [`Dag::insert`].
    pub fn insert(&mut self, vertex: Vertex) -> Result<VertexId, CryptoError> {
        self.dag.insert(vertex)
    }

    /// Validates and exclusively borrows an application without changing state.
    ///
    /// This is NOT a durability boundary. Before calling [`PreparedSlotApplication::apply`],
    /// the caller must persist the full request (payload and exact QC carrier) plus
    /// supporting history, and complete a sync barrier. Neither preparation nor
    /// application signs anything or performs transaction/finalizer effects.
    /// Only an exact retry of the last event applied by this instance is recognized;
    /// checkpoint construction does not validate or restore a last-event cache.
    ///
    /// # Errors
    /// Rejects invalid certificates, history, continuity, encodings, or skip metadata.
    /// All failures leave the DAG, binding, and retry cache unchanged.
    pub fn prepare<'a>(
        &'a mut self,
        payload: &crate::SlotCertificatePayload,
        carrier: &VertexId,
    ) -> Result<PreparedSlotApplication<'a>, CryptoError> {
        let digest = payload.digest()?;
        let round = payload.proposal.decision.round;
        if self
            .last_event
            .as_ref()
            .is_some_and(|(last, previous)| *last == digest && previous == carrier)
        {
            return Ok(PreparedSlotApplication {
                owner: self,
                plan: SlotApplicationPlan::AlreadyApplied { round },
            });
        }
        let decision = self
            .dag
            .inspect_slot_certificate(payload, carrier, &self.binding)?;
        let mut tip = self.binding.tip().clone();
        tip.advance_authorized(&payload.certificate, self.dag.set_for_round(round))?;
        self.prepare_inspected(round, decision, tip, digest, carrier)
    }

    /// Validates a unified agreement proof without changing the owned DAG.
    ///
    /// As with [`Self::prepare`], the caller must durably persist the complete proof,
    /// exact carrier, and supporting history before applying the returned plan.
    /// Only the exact most recently applied proof digest and carrier are retriable.
    ///
    /// # Errors
    /// Rejects invalid lineage, authorization, causal history, continuity, or skip metadata.
    /// Every failure leaves the DAG, binding, and retry cache unchanged.
    pub fn prepare_agreement<'a>(
        &'a mut self,
        proof: &crate::SlotAgreementProof,
        carrier: &VertexId,
    ) -> Result<PreparedSlotApplication<'a>, CryptoError> {
        let selected = &proof
            .entries
            .last()
            .ok_or_else(|| {
                CryptoError::new(CryptoErrorKind::MalformedCertificate, "empty lineage")
            })?
            .proposal
            .decision;
        let round = selected.round;
        let digest = proof.digest(self.dag.set_for_round(round))?;
        if self
            .last_event
            .as_ref()
            .is_some_and(|(last, previous)| *last == digest && previous == carrier)
        {
            return Ok(PreparedSlotApplication {
                owner: self,
                plan: SlotApplicationPlan::AlreadyApplied { round },
            });
        }
        let binding = crate::SlotAgreementBinding::from_checkpoint(
            self.binding.tip().clone(),
            self.binding.carrier().cloned(),
        )?;
        let decision = self
            .dag
            .inspect_slot_agreement_proof(proof, carrier, &binding)?;
        let mut tip = self.binding.tip().clone();
        tip.advance_inspected(selected)?;
        self.prepare_inspected(round, decision, tip, digest, carrier)
    }

    fn prepare_inspected<'a>(
        &'a mut self,
        round: u64,
        decision: Decision,
        tip: crate::SlotDecisionTip,
        digest: [u8; 32],
        carrier: &VertexId,
    ) -> Result<PreparedSlotApplication<'a>, CryptoError> {
        if self.dag.skipped.iter().any(|entry| entry.round == round) {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedCertificate,
                "certified slot already has skip metadata",
            ));
        }
        let skipped = if decision == Decision::Skip {
            let leader = self
                .dag
                .leader(round)
                .ok_or_else(|| {
                    CryptoError::new(
                        CryptoErrorKind::MalformedCertificate,
                        "certified skip requires a held leader",
                    )
                })?
                .id()?;
            Some(SkippedRound {
                round,
                author: leader.author,
                digest: Some(leader.digest),
            })
        } else {
            None
        };
        Ok(PreparedSlotApplication {
            owner: self,
            plan: SlotApplicationPlan::Apply {
                round,
                decision,
                skipped,
                tip,
                fingerprint: (digest, carrier.clone()),
            },
        })
    }
}

impl PreparedSlotApplication<'_> {
    /// Installs the inspected effect, tip, carrier, and retry fingerprint together.
    ///
    /// Performs no fallible validation or I/O; allocation failure may abort the process.
    pub fn apply(self) -> SlotApplicationResult {
        match self.plan {
            SlotApplicationPlan::AlreadyApplied { round } => {
                SlotApplicationResult::AlreadyApplied { round }
            }
            SlotApplicationPlan::Apply {
                round,
                decision,
                skipped,
                tip,
                fingerprint,
            } => {
                if let Decision::Commit(history) = &decision {
                    for vertex in history {
                        self.owner.dag.committed.insert(vertex.digest);
                        self.owner.dag.order.push(vertex.clone());
                    }
                }
                if let Some(skipped) = skipped {
                    self.owner.dag.skipped.push(skipped);
                }
                self.owner
                    .binding
                    .replace_validated(tip, fingerprint.1.clone());
                self.owner.last_event = Some(fingerprint);
                SlotApplicationResult::Applied { round, decision }
            }
        }
    }
}

impl Dag {
    /// Creates an empty DAG for `set`.
    #[must_use]
    pub fn new(set: ValidatorSet) -> Self {
        let epoch = set.epoch;
        Self {
            sets: SetSchedule::single(set),
            vertices: BTreeMap::new(),
            committed: HashSet::new(),
            order: Vec::new(),
            prefix: CommitFrontier::empty(),
            skipped: Vec::new(),
            schedule: EpochSchedule::single(epoch),
            floor: None,
            fences: BTreeMap::new(),
            local_fences: BTreeMap::new(),
            round_skips: BTreeMap::new(),
            chain_id: Vec::new(),
            controls: BTreeMap::new(),
            payload_vertices: BTreeMap::new(),
        }
    }

    /// Creates an empty DAG whose set advances one epoch every `rounds_per_epoch`
    /// rounds, starting at the set's own epoch.
    ///
    /// This is the hook a key rotation hangs on: the validator identities stay
    /// fixed, only their active keys change with the epoch, so quorum intersection
    /// across the boundary is preserved and no round has to be re-decided.
    ///
    /// # Panics
    ///
    /// Does not panic; a zero length is treated as one epoch for the whole DAG.
    #[must_use]
    pub fn with_epoch_length(set: ValidatorSet, rounds_per_epoch: u64) -> Self {
        let base = set.epoch;
        let mut dag = Self::new(set);
        dag.schedule = EpochSchedule::advancing(base, rounds_per_epoch);
        dag
    }

    /// Creates an empty DAG with one checked set transition at `change_epoch`.
    ///
    /// This is the prototype hook for a validator-set change. Key rotation keeps
    /// the identities fixed and needs only [`Dag::with_epoch_length`]; this
    /// constructor moves identities and therefore validates the quorum
    /// intersection before any vertex is accepted.
    ///
    /// # Errors
    ///
    /// Every error from [`SetSchedule::with_change`].
    pub fn with_epoch_length_and_change(
        set: ValidatorSet,
        next: ValidatorSet,
        change_epoch: u64,
        rounds_per_epoch: u64,
    ) -> Result<Self, CryptoError> {
        let base = set.epoch;
        let sets = SetSchedule::with_change(set, change_epoch, next)?;
        Ok(Self {
            sets,
            vertices: BTreeMap::new(),
            committed: HashSet::new(),
            order: Vec::new(),
            prefix: CommitFrontier::empty(),
            skipped: Vec::new(),
            schedule: EpochSchedule::advancing(base, rounds_per_epoch),
            floor: None,
            fences: BTreeMap::new(),
            local_fences: BTreeMap::new(),
            round_skips: BTreeMap::new(),
            chain_id: Vec::new(),
            controls: BTreeMap::new(),
            payload_vertices: BTreeMap::new(),
        })
    }

    /// Installs a transition certificate authorized by the old set.
    ///
    /// The DAG keeps every vertex it already holds; only the set schedule changes,
    /// so rounds before the activation epoch still verify against the old set and
    /// rounds at or after it verify against the new one. A second, different
    /// transition is refused: the prototype supports one boundary per schedule.
    /// Re-adopting the same certificate is idempotent.
    ///
    /// # Errors
    ///
    /// Every error from [`TransitionCertificate::verify`], and
    /// [`SetChangeError::Mismatch`] when another transition is already installed.
    pub fn adopt_set_change(
        &mut self,
        certificate: &TransitionCertificate,
    ) -> Result<Transition, SetChangeError> {
        if self.sets.change_epoch().is_some() {
            if self
                .sets
                .certificate()
                .is_some_and(|current| current == certificate)
            {
                return Ok(self
                    .sets
                    .transition()
                    .expect("a change epoch always carries its transition")
                    .clone());
            }
            return Err(SetChangeError::Mismatch(
                "this DAG already installed a different set change".to_string(),
            ));
        }
        let sets = SetSchedule::with_certificate(self.sets.base().clone(), certificate.clone())?;
        let transition = sets
            .transition()
            .expect("a certificate always installs a transition")
            .clone();
        self.sets = sets;
        Ok(transition)
    }

    /// Installs a quorum-authorized fence.
    ///
    /// The certificate is checked against the set active at its `from_round`.
    /// At most `f` validators may be fenced; a larger fence would exceed the
    /// fault budget the set was built for. The earliest `from_round` wins for a
    /// repeated fence on the same validator.
    ///
    /// # Errors
    ///
    /// Every error from [`FenceCertificate::verify`], plus
    /// [`FenceError::TooMany`] when the fence would exceed the fault budget.
    pub fn apply_fence(
        &mut self,
        chain_id: &[u8],
        certificate: &FenceCertificate,
    ) -> Result<(), FenceError> {
        let set = self.set_for_round(certificate.fence.from_round).clone();
        certificate.verify(chain_id, &set)?;
        let validator_id = certificate.fence.validator_id.clone();
        let from_round = certificate.fence.from_round;
        // A fence may start at or below the floor. The rounds below it are
        // already decided, but the declaration still governs every later round;
        // rejecting it would make a restart forget a fence whose round a
        // checkpoint has since pruned. The retained order above the floor is
        // still checked against the declaration below.
        if self
            .order
            .iter()
            .any(|id| id.round >= from_round && id.author == validator_id)
        {
            return Err(FenceError::Mismatch(
                "the fenced validator already has a committed vertex at or after the fence round"
                    .to_string(),
            ));
        }
        if let Some((current, _)) = self.fences.get(&validator_id) {
            if *current <= from_round {
                return Ok(());
            }
        } else if self.fences.len() >= set.max_faulty() {
            return Err(FenceError::TooMany {
                count: self.fences.len() + 1,
                limit: set.max_faulty(),
            });
        }
        self.fences
            .insert(validator_id, (from_round, certificate.clone()));
        Ok(())
    }

    /// Every fence certificate this DAG adopted.
    pub fn fences(&self) -> impl Iterator<Item = &FenceCertificate> {
        self.fences.values().map(|(_, certificate)| certificate)
    }

    /// Whether `validator_id` is fenced at `round`.
    #[must_use]
    pub fn is_fenced(&self, validator_id: &[u8], round: u64) -> bool {
        self.fences
            .get(validator_id)
            .is_some_and(|(from_round, _)| round >= *from_round)
    }

    /// Records a fence share this node signed, before a quorum certificate exists.
    ///
    /// The earliest round wins: signing two fences for the same validator promises
    /// not to vote at either boundary, and the earlier one is the stricter promise.
    pub fn note_local_fence(&mut self, fence: &Fence) {
        let entry = self
            .local_fences
            .entry(fence.validator_id.clone())
            .or_insert(fence.from_round);
        *entry = (*entry).min(fence.from_round);
    }

    /// Forgets a local promise whose partial certificate was abandoned.
    pub fn clear_local_fence(&mut self, validator_id: &[u8]) {
        self.local_fences.remove(validator_id);
    }

    /// Whether this node has promised not to vote for `validator_id` from `round`.
    #[must_use]
    pub fn is_locally_fenced(&self, validator_id: &[u8], round: u64) -> bool {
        self.local_fences
            .get(validator_id)
            .is_some_and(|from_round| round >= *from_round)
    }

    /// Whether the leader of `round` is fenced and the round can be skipped.
    #[must_use]
    pub fn can_skip_fenced_leader(&self, round: u64) -> bool {
        self.leader_author(round)
            .is_some_and(|author| self.is_fenced(author, round))
    }

    /// Records a skip for a fenced leader.
    ///
    /// The direct and indirect rules run first; this only runs when neither can
    /// decide. A fence quorum is a statement that the validator is failed from
    /// `from_round`, so an honest signer will not vote for that leader at or after
    /// the fence. At most `f` Byzantine validators can vote for it, which is below
    /// the quorum, so no commit can exist.
    ///
    /// # Errors
    ///
    /// Propagates vertex id encoding when the leader is held.
    pub fn skip_fenced_leader(&mut self, round: u64) -> Result<bool, CryptoError> {
        if !self.can_skip_fenced_leader(round) {
            return Ok(false);
        }
        let author = self
            .leader_author(round)
            .expect("a skippable leader has an author")
            .to_vec();
        let digest = self
            .leader(round)
            .map(|vertex| vertex.id())
            .transpose()?
            .map(|id| id.digest);
        Ok(self.record_skip(round, author, digest))
    }

    /// Whether a held leader can be skipped because its only missing voters are
    /// fenced and fewer than `f + 1` votes are held.
    ///
    /// A missing voter could still vote, so the rule is conservative: every
    /// voter whose vertex is missing must be fenced, and the held vote count must
    /// not exceed the fault budget. Then even if every fenced validator voted,
    /// the total would be at most `2f`, below the `2f + 1` quorum.
    ///
    /// # Errors
    ///
    /// Propagates vertex id encoding and vote tallying.
    pub fn can_skip_with_fence(&self, round: u64) -> Result<bool, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(false);
        };
        let leader_id = leader.id()?;
        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?;
        if voters.len() > voter_set.max_faulty() {
            return Ok(false);
        }
        let held: HashSet<&[u8]> = candidates
            .iter()
            .map(|vertex| vertex.author.as_slice())
            .collect();
        let mut missing_fenced = false;
        for record in &voter_set.validators {
            if held.contains(record.validator_id.as_slice()) {
                continue;
            }
            if !self.is_fenced(&record.validator_id, round + 1) {
                return Ok(false);
            }
            missing_fenced = true;
        }
        Ok(missing_fenced)
    }

    /// Records a skip allowed by a fence and the held-vote cap.
    ///
    /// # Errors
    ///
    /// Every error from [`Dag::can_skip_with_fence`] and vertex id encoding.
    pub fn skip_with_fence(&mut self, round: u64) -> Result<bool, CryptoError> {
        if !self.can_skip_with_fence(round)? {
            return Ok(false);
        }
        let leader = self.leader(round).expect("a skippable leader is held");
        let author = leader.author.clone();
        let digest = Some(leader.id()?.digest);
        Ok(self.record_skip(round, author, digest))
    }

    /// Verifies a round-skip proof against this DAG without adopting it.
    ///
    /// This is the check a builder runs before it publishes a certificate, so a
    /// node never authors a payload it would reject itself.
    ///
    /// # Errors
    ///
    /// Every error from [`RoundSkipProof::verify`], plus
    /// [`RoundSkipError::Mismatch`] when the named leader is not held or is not
    /// this DAG's leader for the round.
    pub fn check_round_skip(
        &self,
        chain_id: &[u8],
        proof: &RoundSkipProof,
    ) -> Result<RoundSkipCheck, RoundSkipError> {
        let round = proof.attestation.skip.round();
        if self.is_pruned(round) {
            return Ok(RoundSkipCheck::default());
        }
        let leader_id = self
            .leader(round)
            .ok_or_else(|| RoundSkipError::Mismatch("the skipped leader is not held".to_string()))?
            .id()
            .map_err(RoundSkipError::Encoding)?;
        if proof.attestation.skip.leader != leader_id {
            return Err(RoundSkipError::Mismatch(
                "the proof names a different leader vertex".to_string(),
            ));
        }
        let voter_set = self.set_for_round(round.saturating_add(1)).clone();
        proof.verify(
            chain_id,
            &voter_set,
            &leader_id,
            |fence_round| self.set_for_round(fence_round).clone(),
            |id| self.get(id.round, &id.author).cloned(),
        )
    }

    /// Whether any held control payload targets `round`.
    ///
    /// This is the cheap gate before the causal walk: when no certificate for a
    /// round is held, the anchor decision cannot depend on one.
    #[must_use]
    pub fn has_control_for_round(&self, round: u64) -> bool {
        self.controls
            .values()
            .any(|payload| payload.round() == round)
    }

    /// Looks for a valid round-skip certificate inside a selected anchor's
    /// causal history.
    ///
    /// The walk is the causal rule stage B is testing: a certificate only counts
    /// when the binding vertex is an ancestor of the anchor, and the leader and
    /// every vote/non-vote the proof names are also in that history. A listed id
    /// that is not an ancestor is not causal evidence for this anchor and is
    /// ignored; an ancestor this node does not hold is a missing reference, so
    /// the caller repairs the anchor history instead of deciding on a partial
    /// one.
    ///
    /// The returned certificate is reported, not applied: the anchor decision
    /// stays exactly what [`Dag::try_indirect_decide`] would make. A certificate
    /// is negative evidence that can arrive late, so overriding a commit with it
    /// forked the committed order on one devnet node; the pacemaker therefore
    /// treats this as reporting only.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::MissingReference`] when the anchor's causal history is
    /// incomplete. Verification errors on individual certificates are ignored:
    /// an invalid payload is not evidence and must not block the anchor.
    pub fn anchor_skip(&self, anchor: &VertexId, round: u64) -> Result<AnchorSkip, CryptoError> {
        if !self.has_control_for_round(round) {
            return Ok(AnchorSkip::None);
        }

        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![anchor.clone()];
        let mut candidates: Vec<[u8; 32]> = Vec::new();
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            if let Some(payload) = self.controls.get(&vertex.payload_hash)
                && payload.round() == round
            {
                candidates.push(vertex.payload_hash);
            }
            stack.extend(vertex.references.iter().cloned());
        }

        // A digest order makes the reported certificate reproducible when more
        // than one valid proof is in the same history. Both imply a skip, so the
        // decision does not depend on which one is returned first.
        candidates.sort_unstable();
        candidates.dedup();
        for digest in candidates {
            let Some(payload) = self.controls.get(&digest) else {
                continue;
            };
            let Some(proof) = payload.round_skip() else {
                continue;
            };
            if !self.is_ancestor(&proof.attestation.skip.leader, anchor)? {
                continue;
            }
            let mut closed = true;
            for id in proof.votes.iter().chain(&proof.non_votes) {
                if !self.is_ancestor(id, anchor)? {
                    closed = false;
                    break;
                }
            }
            if !closed {
                continue;
            }
            match self.check_round_skip(&self.chain_id, proof) {
                Ok(check) => return Ok(AnchorSkip::Certificate(check)),
                Err(_) => continue,
            }
        }
        Ok(AnchorSkip::None)
    }

    /// Installs a round-skip proof for the leader of its round.
    ///
    /// The proof is checked against the voter set active at the voting round,
    /// the set active at each carried fence, and the vertices this DAG holds. The
    /// named leader must be the vertex this DAG elected and holds for the round.
    ///
    /// # Errors
    ///
    /// Every error from [`RoundSkipProof::verify`], plus
    /// [`RoundSkipError::Mismatch`] when the DAG does not hold the named leader
    /// or already adopted a different proof for the same round.
    pub fn apply_round_skip(
        &mut self,
        chain_id: &[u8],
        proof: RoundSkipProof,
    ) -> Result<RoundSkipCheck, RoundSkipError> {
        let round = proof.attestation.skip.round();
        if self.is_pruned(round) {
            // The round is already covered by a checkpoint, so the decision is
            // part of the adopted prefix. A restart that replays the proof must
            // not fail because the leader's vertex is gone.
            return Ok(RoundSkipCheck::default());
        }
        if let Some(current) = self.round_skips.get(&round)
            && current.attestation.skip != proof.attestation.skip
        {
            return Err(RoundSkipError::Mismatch(
                "this round already has a different skip proof".to_string(),
            ));
        }
        let check = self.check_round_skip(chain_id, &proof)?;
        self.round_skips.entry(round).or_insert(proof);
        Ok(check)
    }

    /// The round-skip proof this DAG adopted for `round`, if any.
    #[must_use]
    pub fn round_skip(&self, round: u64) -> Option<&RoundSkipProof> {
        self.round_skips.get(&round)
    }

    /// Every round-skip proof this DAG adopted, one per leader round.
    ///
    /// A snapshot carries these so a joining node starts with the same decision
    /// inputs as the sender rather than depending on a live rebroadcast.
    pub fn round_skips(&self) -> impl Iterator<Item = &RoundSkipProof> {
        self.round_skips.values()
    }

    /// Whether a verified round-skip proof authorizes skipping `round`'s leader.
    ///
    /// The proof is only accepted when it names the leader this DAG holds. A
    /// proof for another vertex at the same round, or one this DAG has not
    /// adopted, decides nothing.
    ///
    /// The pacemaker does not call this: certificates are reporting evidence,
    /// not decisions. A certificate is negative evidence and can arrive after
    /// another node has committed the same round, so it must not move the
    /// cursor. The method remains available to tests and to a future rule that
    /// proves the round cannot be committed, not merely that no vote quorum can
    /// form.
    ///
    /// # Errors
    ///
    /// Propagates vertex id encoding when the leader is held.
    pub fn skip_with_attestation(&mut self, round: u64) -> Result<bool, CryptoError> {
        let Some(proof) = self.round_skips.get(&round) else {
            return Ok(false);
        };
        let Some(leader) = self.leader(round) else {
            return Ok(false);
        };
        let leader_id = leader.id()?;
        if proof.attestation.skip.leader != leader_id {
            return Ok(false);
        }
        let author = leader.author.clone();
        let digest = Some(leader_id.digest);
        Ok(self.record_skip(round, author, digest))
    }

    /// Installs a control payload received on the data plane.
    ///
    /// The payload is not a decision: it becomes one only when the vertex whose
    /// `payload_hash` names its digest is held. Keeping it here makes a payload
    /// that arrived first survive until the binding vertex arrives, and lets the
    /// pacemaker wait instead of deciding the round through an anchor.
    ///
    /// # Errors
    ///
    /// Propagates [`ControlPayload::digest`].
    pub fn add_control(&mut self, payload: ControlPayload) -> Result<[u8; 32], CryptoError> {
        let digest = payload.digest()?;
        // A rebroadcast of a certificate this DAG already adopted is a duplicate,
        // not a new pending payload: keeping it would delay the same round again.
        if let Some(proof) = payload.round_skip()
            && self
                .round_skips
                .contains_key(&proof.attestation.skip.round())
        {
            return Ok(digest);
        }
        self.controls.entry(digest).or_insert(payload);
        Ok(digest)
    }

    /// The control payload this DAG holds for `digest`, if any.
    #[must_use]
    pub fn control(&self, digest: &[u8; 32]) -> Option<&ControlPayload> {
        self.controls.get(digest)
    }

    /// The vertex that names `digest`, if this DAG holds it.
    #[must_use]
    pub fn vertex_for_payload(&self, digest: &[u8; 32]) -> Option<&VertexId> {
        self.payload_vertices.get(digest)
    }

    /// Whether a held control payload targets `round` and has not been decided.
    ///
    /// Stage B keeps this as a reporting helper. The pacemaker no longer blocks
    /// on a pending payload: a certificate counts only through the selected
    /// anchor's causal history, so a missing binding vertex simply leaves the
    /// ordinary anchor decision in place.
    #[must_use]
    pub fn has_pending_control(&self, round: u64) -> bool {
        !self.round_skips.contains_key(&round)
            && self.leader(round).is_some()
            && self
                .controls
                .values()
                .any(|payload| payload.round() == round)
    }

    /// Digests of control payloads that have not been applied yet.
    #[must_use]
    pub fn pending_controls(&self) -> Vec<[u8; 32]> {
        self.controls
            .iter()
            .filter(|(_, payload)| !self.round_skips.contains_key(&payload.round()))
            .map(|(digest, _)| *digest)
            .collect()
    }

    /// Applies every held control payload whose binding vertex and evidence are
    /// available.
    ///
    /// This is the eager path used by tests and kept for the pending-control
    /// bookkeeping. The pacemaker does not call it: a certificate is reporting
    /// evidence, and only the anchor and fence rules decide a round.
    ///
    /// A payload whose binding vertex or leader is missing stays queued, so a
    /// later delivery completes it. A proof that verifies is installed exactly
    /// as [`Dag::apply_round_skip`] installs one; a proof with missing evidence
    /// also stays queued, and the caller can request the named vertex. A
    /// permanently invalid proof is dropped instead of blocking a round forever.
    ///
    /// Returns one `(round, result)` per payload attempted in this call, in
    /// digest order, so two nodes starting from the same DAG apply in the same
    /// order.
    pub fn apply_controls(
        &mut self,
        chain_id: &[u8],
    ) -> Vec<(u64, Result<RoundSkipCheck, RoundSkipError>)> {
        // A payload for a round this DAG already decided is not pending: another
        // proof for the same leader won the race. Keeping it would make the
        // pacemaker wait on a decision it already has.
        let decided: Vec<u64> = self.round_skips.keys().copied().collect();
        self.controls
            .retain(|_, payload| !decided.contains(&payload.round()));
        let ready: Vec<[u8; 32]> = self
            .controls
            .keys()
            .filter(|digest| self.payload_vertices.contains_key(*digest))
            .copied()
            .collect();
        let mut applied = Vec::with_capacity(ready.len());
        for digest in ready {
            let Some(payload) = self.controls.get(&digest) else {
                continue;
            };
            let round = payload.round();
            // A missing leader is a delivery condition: the proof cannot decide
            // the round yet, and the indirect rule may still settle it.
            if !self.is_pruned(round) && self.leader(round).is_none() {
                continue;
            }
            let Some(payload) = self.controls.remove(&digest) else {
                continue;
            };
            let result = match &payload {
                ControlPayload::RoundSkip(proof) => {
                    self.apply_round_skip(chain_id, (**proof).clone())
                }
            };
            if matches!(result, Err(RoundSkipError::MissingEvidence(_))) {
                // The proof may still be valid; keep it for the pass that holds
                // the missing vertex. The binding vertex is already here.
                self.controls.insert(digest, payload);
            }
            applied.push((round, result));
        }
        applied
    }

    /// The epoch a round belongs to.
    ///
    /// Derived from the round alone, never read from a message, so every node
    /// computes the same epoch for the same round.
    #[must_use]
    pub fn epoch_of(&self, round: u64) -> u64 {
        self.schedule.epoch_of(round)
    }

    /// The round-to-epoch mapping this DAG verifies against.
    #[must_use]
    pub fn epoch_schedule(&self) -> EpochSchedule {
        self.schedule
    }

    /// The highest round this node has pruned, if any.
    #[must_use]
    pub fn floor(&self) -> Option<u64> {
        self.floor
    }

    /// Treats every round at or below `round` as committed and drops it.
    ///
    /// Returns how many vertices were removed. Pruning is a statement that a state
    /// snapshot already covers those rounds, which is why nothing below the floor is
    /// stored or re-decided.
    ///
    /// The floor only ever rises, so calling this with a lower value is a no-op.
    ///
    /// # Panics
    ///
    /// Does not panic; a lower value simply leaves the floor unchanged.
    pub fn set_floor(&mut self, round: u64) -> usize {
        let floor = match self.floor {
            Some(current) => current.max(round),
            None => round,
        };
        self.floor = Some(floor);
        let before = self.vertices.len();
        self.vertices.retain(|(round, _), _| *round > floor);
        self.controls.retain(|_, payload| payload.round() > floor);
        self.payload_vertices.retain(|_, id| id.round > floor);
        before - self.vertices.len()
    }

    fn is_pruned(&self, round: u64) -> bool {
        self.floor.is_some_and(|floor| round <= floor)
    }

    /// The validator set this DAG resolves keys against before any transition.
    #[must_use]
    pub fn set(&self) -> &ValidatorSet {
        self.sets.base()
    }

    /// The checked set schedule, including an optional transition.
    #[must_use]
    pub fn set_schedule(&self) -> &SetSchedule {
        &self.sets
    }

    /// The validator set active at `epoch`.
    #[must_use]
    pub fn set_for_epoch(&self, epoch: u64) -> &ValidatorSet {
        self.sets.set_for_epoch(epoch)
    }

    /// The validator set active at `round`.
    #[must_use]
    pub fn set_for_round(&self, round: u64) -> &ValidatorSet {
        self.sets.set_for_round(&self.schedule, round)
    }

    /// Sets the chain id control payloads are verified against.
    ///
    /// `Node` calls this with the same id it signs vertices with. A DAG that
    /// never adopts a certificate can leave it empty.
    pub fn set_chain_id(&mut self, chain_id: Vec<u8>) {
        self.chain_id = chain_id;
    }

    /// The chain id control payloads are verified against.
    #[must_use]
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }

    /// Inserts a vertex after verifying it and its shape.
    ///
    /// The shape rule is the one this module previously only assumed: a vertex in
    /// round `r > 0` MUST reference at least [`ValidatorSet::quorum_size`]
    /// **distinct, registered authors** of round `r - 1`. Without it, the indirect
    /// skip argument does not hold: an anchor could be committed while a valid
    /// path to an earlier leader exists on a branch the anchor does not cover.
    ///
    /// References to other rounds are allowed and not counted; they are weak edges
    /// that carry causal history.
    ///
    /// A second vertex from the same author in the same round is **ignored**: the
    /// first one wins, so an author cannot vote twice.
    ///
    /// # Errors
    ///
    /// Propagates [`Vertex::verify`], and returns
    /// [`CryptoErrorKind::InvalidVertex`] when the reference rule is not met.
    pub fn insert(&mut self, vertex: Vertex) -> Result<VertexId, CryptoError> {
        vertex.verify(
            self.set_for_round(vertex.round),
            self.epoch_of(vertex.round),
        )?;
        // A fence is a quorum statement that the validator is failed from this
        // round on. Accepting its new vertices would let a delayed vertex become
        // a vote for a leader the fence quorum already agreed to skip.
        if self.is_fenced(&vertex.author, vertex.round) {
            return Err(CryptoError::new(
                CryptoErrorKind::InvalidVertex,
                format!("author is fenced at round {}", vertex.round),
            ));
        }
        // Below the floor the vertex is already committed and its state is in a
        // snapshot. It is still signature-checked, then dropped.
        if self.is_pruned(vertex.round) {
            return vertex.id();
        }
        self.check_round_references(&vertex)?;
        let key = (vertex.round, vertex.author.clone());
        if let Some(existing) = self.vertices.get(&key) {
            return existing.id();
        }
        let id = vertex.id()?;
        if vertex.payload_hash != [0u8; 32] {
            self.payload_vertices
                .entry(vertex.payload_hash)
                .or_insert_with(|| id.clone());
        }
        self.vertices.insert(key, vertex);
        Ok(id)
    }

    /// Checks that a vertex references a quorum of the previous round.
    fn check_round_references(&self, vertex: &Vertex) -> Result<(), CryptoError> {
        if vertex.round == 0 {
            return Ok(());
        }
        let previous = vertex.round - 1;
        // A pruned previous round cannot be checked: the vertices are gone. The
        // first retained round is therefore accepted on its author's signature, and
        // a bad reference list simply fails to vote later.
        if self.is_pruned(previous) {
            return Ok(());
        }
        let set = self.set_for_round(vertex.round);
        let registered = |author: &[u8]| {
            set.validators
                .iter()
                .any(|record| record.validator_id == author)
        };
        let mut authors: HashSet<&[u8]> = HashSet::new();
        for reference in &vertex.references {
            if reference.round == previous && registered(&reference.author) {
                authors.insert(&reference.author);
            }
        }
        let required = set.quorum_size();
        if authors.len() < required {
            return Err(CryptoError::new(
                CryptoErrorKind::InvalidVertex,
                format!(
                    "round {} references {} of {required} required authors from round {previous}",
                    vertex.round,
                    authors.len()
                ),
            ));
        }
        Ok(())
    }

    /// Returns the vertex for one author and round.
    #[must_use]
    pub fn get(&self, round: u64, author: &[u8]) -> Option<&Vertex> {
        self.vertices.get(&(round, author.to_vec()))
    }

    /// The elected author of `round`, whether or not this node holds their vertex.
    ///
    /// Election is `round % n` over the set order: deterministic and trivial on
    /// purpose. A real deployment wants a stake-weighted or VRF schedule, which is
    /// a different problem from the commit rule.
    #[must_use]
    pub fn leader_author(&self, round: u64) -> Option<&[u8]> {
        let set = self.set_for_round(round);
        let index = usize::try_from(round).ok()? % set.validators.len();
        Some(&set.validators[index].validator_id)
    }

    /// The elected leader of `round`, if this node has it.
    #[must_use]
    pub fn leader(&self, round: u64) -> Option<&Vertex> {
        let author = self.leader_author(round)?;
        self.get(round, author)
    }

    /// The highest round this node holds any vertex for.
    #[must_use]
    pub fn highest_round(&self) -> Option<u64> {
        self.vertices.keys().next_back().map(|(round, _)| *round)
    }

    /// Eligible voting vertices held in `round`.
    fn round_vertices(&self, round: u64) -> Vec<&Vertex> {
        self.vertices
            .range((round, Vec::new())..)
            .take_while(|((r, _), _)| *r == round)
            // Late fenced vertices are rejected on insertion; already-held votes
            // must follow the same rule or fence decisions depend on arrival order.
            .filter(|((_, author), _)| !self.is_fenced(author, round))
            .map(|(_, vertex)| vertex)
            .collect()
    }

    /// Returns the leader of `round` if a quorum of the next round references it,
    /// without committing anything.
    ///
    /// This is what the pacemaker uses to find an anchor. It deliberately does not
    /// emit a commit: emitting out of cursor order would make the committed
    /// sequence depend on arrival order, which two nodes with the same DAG may not
    /// share.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`].
    pub fn is_anchored(&self, round: u64) -> Result<Option<VertexId>, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(None);
        };
        let leader_id = leader.id()?;
        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?;
        if voter_set.has_supermajority(voters.len()) {
            Ok(Some(leader_id))
        } else {
            Ok(None)
        }
    }

    /// Asks this node to decide the leader of `round`.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`], and returns
    /// [`CryptoErrorKind::MissingReference`] when committing a leader whose
    /// history is incomplete.
    pub fn try_commit(&mut self, round: u64) -> Result<Decision, CryptoError> {
        let decision = self.inspect_commit(round)?;
        self.apply_inspected_decision(round, &decision)?;
        Ok(decision)
    }

    /// Inspects the direct rule without changing the order or recording a skip.
    ///
    /// A result describes only the current view, not authorization to apply it later.
    /// Repeated commits may return an empty history. This does not check slot-decision
    /// certificates or resolve conflicts between direct, indirect, and fence rules.
    ///
    /// # Errors
    /// Propagates vote tally, vertex encoding, and missing-history errors.
    pub fn inspect_commit(&self, round: u64) -> Result<Decision, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(Decision::Undecided);
        };
        let leader_id = leader.id()?;

        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?;

        if voter_set.has_supermajority(voters.len()) {
            let history = self.collect_uncommitted_history(&leader_id)?;
            return Ok(Decision::Commit(history));
        }

        // Only observed non-votes count. A voter whose vertex has not arrived is
        // unknown, not against the leader, so it cannot produce a skip.
        let non_voters = candidates.len() - voters.len();
        if voter_set.has_supermajority(non_voters) {
            return Ok(Decision::Skip);
        }
        Ok(Decision::Undecided)
    }

    /// Inspects an inactive direct-rule proposal bound to a held signed carrier.
    ///
    /// Checks a fixed-set quorum of explicit vote/nonvote vertices in the carrier's
    /// causal history, exact vertex digests, elected leadership, trusted-tip continuity,
    /// and the proposed frontier effect. Fence eligibility is deliberately not consulted.
    /// All references must point to strictly older rounds. All retained causal history
    /// must be available; pruned history is a trusted boundary,
    /// but the carrier, leader, and voters themselves must be retained. A set/epoch change
    /// in retained history is unsupported and rejected.
    ///
    /// This neither signs nor applies a decision. It does not authenticate the bootstrap
    /// tip, bind its predecessor to a previous carrier, verify a QC, provide a view-change
    /// rule, or activate live consensus. Its result is only a current-view inspection.
    /// Work scales with the entire retained causal cone (including signature checks)
    /// and committed tail, not merely the bounded proposal body. Callers must budget
    /// this work before exposing inspection to untrusted request-driven processing.
    ///
    /// # Errors
    /// Rejects malformed proposals, missing or inconsistent history, invalid signatures,
    /// noncausal evidence, unsupported contexts, and incorrect frontier effects.
    pub fn inspect_slot_proposal(
        &self,
        proposal: &crate::SlotProposal,
        carrier: &VertexId,
        tip: &crate::SlotDecisionTip,
    ) -> Result<Decision, CryptoError> {
        self.inspect_slot_proposal_with_causal(proposal, carrier, tip)
            .map(|(decision, _)| decision)
    }

    fn inspect_slot_proposal_with_causal(
        &self,
        proposal: &crate::SlotProposal,
        carrier: &VertexId,
        tip: &crate::SlotDecisionTip,
    ) -> Result<(Decision, HashSet<VertexId>), CryptoError> {
        let mut budget = usize::MAX;
        self.inspect_slot_proposal_with_budget(proposal, carrier, tip, &mut budget)
    }

    fn inspect_slot_proposal_with_budget(
        &self,
        proposal: &crate::SlotProposal,
        carrier: &VertexId,
        tip: &crate::SlotDecisionTip,
        budget: &mut usize,
    ) -> Result<(Decision, HashSet<VertexId>), CryptoError> {
        use crate::SlotOutcome;

        let invalid =
            |message: &str| CryptoError::new(CryptoErrorKind::MalformedCertificate, message);
        let d = &proposal.decision;
        let digest = proposal.digest()?;
        let set = self.set_for_round(d.round);
        d.validate(set)?;
        if d.round == 0 || d.round == u64::MAX || self.is_pruned(d.round) {
            return Err(invalid("unsupported slot proposal round"));
        }
        if d.chain_id != self.chain_id
            || d.chain_id != tip.chain_id()
            || d.validator_set_id != *tip.set_id()
            || d.epoch != tip.epoch()
            || d.round != tip.next_round()
            || d.previous != *tip.previous_id()
            || d.before_len != tip.order_len()
            || d.before_root != *tip.order_root()
            || d.before_len != self.order_len() as u64
            || d.before_root != self.commit_root()
        {
            return Err(invalid("slot proposal context or continuity mismatch"));
        }
        let voting_round = d.round + 1;
        if self.set_for_round(voting_round).id()? != d.validator_set_id
            || self.epoch_of(d.round) != d.epoch
            || self.epoch_of(voting_round) != d.epoch
            || carrier.round <= voting_round
            || proposal.voters.len() != set.quorum_size()
        {
            return Err(invalid("slot proposal needs a fixed-set direct quorum"));
        }

        let causal = self.slot_causal_history_with_budget(carrier, digest, d, budget)?;
        let leader = self
            .leader(d.round)
            .ok_or_else(|| invalid("slot proposal requires the retained elected leader"))?;
        let leader_id = leader.id()?;
        if leader.chain_id != d.chain_id {
            return Err(invalid("slot proposal leader chain mismatch"));
        }
        leader.verify(set, d.epoch)?;
        let committing = match &d.outcome {
            SlotOutcome::Commit { leader } if *leader == leader_id => true,
            SlotOutcome::Skip { leader_author } if *leader_author == leader_id.author => false,
            _ => return Err(invalid("slot proposal names the wrong elected leader")),
        };
        let mut authors = HashSet::new();
        for voter in &proposal.voters {
            if voter.round != voting_round
                || !causal.contains(voter)
                || !authors.insert(&voter.author)
            {
                return Err(invalid("slot proposal has noncausal or duplicate voters"));
            }
            let vertex = self
                .get(voter.round, &voter.author)
                .ok_or_else(|| missing(voter))?;
            if vertex.references.contains(&leader_id) != committing {
                return Err(invalid("slot proposal evidence contradicts its outcome"));
            }
        }
        let history = if committing {
            self.collect_uncommitted_history(&leader_id)?
        } else {
            Vec::new()
        };
        let mut frontier = self.prefix.clone();
        frontier.extend(&self.order);
        frontier.extend(&history);
        if d.after_len != frontier.len() as u64 || d.after_root != frontier.root() {
            return Err(invalid("slot proposal frontier effect mismatch"));
        }
        let decision = if committing {
            Decision::Commit(history)
        } else {
            Decision::Skip
        };
        Ok((decision, causal))
    }

    // Validate the complete retained cone, not an early-return ancestry predicate.
    // Exact references at the trusted pruning boundary are retained in the result;
    // they name boundary vertices but do not authenticate their pruned contents.
    fn slot_causal_history(
        &self,
        carrier: &VertexId,
        digest: [u8; 32],
        decision: &crate::SlotDecision,
    ) -> Result<HashSet<VertexId>, CryptoError> {
        let mut budget = usize::MAX;
        self.slot_causal_history_with_budget(carrier, digest, decision, &mut budget)
    }

    fn slot_causal_history_with_budget(
        &self,
        carrier: &VertexId,
        digest: [u8; 32],
        decision: &crate::SlotDecision,
        budget: &mut usize,
    ) -> Result<HashSet<VertexId>, CryptoError> {
        let invalid =
            |message: &str| CryptoError::new(CryptoErrorKind::MalformedCertificate, message);
        if self.is_pruned(carrier.round) {
            return Err(invalid("slot carrier is pruned"));
        }
        let set = self.set_for_round(decision.round);
        let mut causal = HashSet::new();
        let mut stack = vec![carrier.clone()];
        while let Some(current) = stack.pop() {
            *budget = budget
                .checked_sub(1)
                .ok_or_else(|| invalid("agreement phase traversal work budget exhausted"))?;
            if !causal.insert(current.clone()) || self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .get(current.round, &current.author)
                .ok_or_else(|| missing(&current))?;
            if vertex.references.len() > budget.saturating_sub(stack.len()) {
                return Err(invalid("agreement phase traversal work budget exhausted"));
            }
            if vertex.id()? != current || vertex.chain_id != decision.chain_id {
                return Err(invalid("slot causal vertex mismatch"));
            }
            if self.set_for_round(current.round).id()? != decision.validator_set_id
                || self.epoch_of(current.round) != decision.epoch
            {
                return Err(invalid("slot causal history changes set or epoch"));
            }
            vertex.verify(set, decision.epoch)?;
            self.check_round_references(vertex)?;
            if vertex
                .references
                .iter()
                .any(|reference| reference.round >= vertex.round)
            {
                return Err(invalid(
                    "slot causal history contains a noncausal reference",
                ));
            }
            if current == *carrier && vertex.payload_hash != digest {
                return Err(invalid("slot payload is not bound to its carrier"));
            }
            stack.extend(vertex.references.iter().cloned());
        }
        Ok(causal)
    }

    /// Inspects an inactive QC payload with proposal and predecessor causal binding.
    ///
    /// The retained signed QC carrier must name the entire payload and descend from
    /// its retained proposal carrier. The proposal must pass direct-rule evidence and
    /// frontier checks and descend from the trusted binding's predecessor carrier,
    /// if one exists. A pruned predecessor can be named by an exact signed boundary
    /// reference, but its pruned payload is trusted rather than reauthenticated.
    /// QC signatures authorize the exact decision, not a particular evidence or signer
    /// subset; both payload and proposal carrier hashes bind the supplied evidence.
    ///
    /// This is read-only inspection, not application, signing permission, or an update
    /// to the binding. Bootstrap authentication, durable progress, certified-only
    /// application, view changes and live activation remain the caller's responsibility.
    /// Full retained causal cones and the order are scanned; callers must budget work
    /// before exposing this API to untrusted request-driven processing.
    ///
    /// # Errors
    /// Rejects invalid QC signatures, context/effect mismatches, missing or inconsistent
    /// retained history, and absent, unbound, or noncausal proposal/predecessor carriers.
    pub fn inspect_slot_certificate(
        &self,
        payload: &crate::SlotCertificatePayload,
        carrier: &VertexId,
        binding: &crate::SlotDecisionBinding,
    ) -> Result<Decision, CryptoError> {
        let invalid =
            |message: &str| CryptoError::new(CryptoErrorKind::MalformedCertificate, message);
        let digest = payload.digest()?;
        if carrier.round <= payload.proposal_carrier.round {
            return Err(invalid("slot QC carrier must follow its proposal carrier"));
        }
        let (decision, proposal_causal) = self.inspect_slot_proposal_with_causal(
            &payload.proposal,
            &payload.proposal_carrier,
            binding.tip(),
        )?;
        if let Some(previous) = binding.carrier()
            && (previous.round >= payload.proposal_carrier.round
                || !proposal_causal.contains(previous))
        {
            return Err(invalid(
                "slot proposal does not causally extend its predecessor carrier",
            ));
        }
        let set = self.set_for_round(payload.certificate.decision.round);
        // Exercise the same QC and continuity preflight as the eventual tip update,
        // but leave both the trusted binding and the DAG completely unchanged.
        let mut tip = binding.tip().clone();
        tip.advance_authorized(&payload.certificate, set)?;
        let causal = self.slot_causal_history(carrier, digest, &payload.proposal.decision)?;
        if !causal.contains(&payload.proposal_carrier) {
            return Err(invalid(
                "slot QC does not causally extend its proposal carrier",
            ));
        }
        Ok(decision)
    }

    /// Inspects an inactive final agreement QC and its complete retained causal cone.
    ///
    /// Checks direct proposal evidence, trusted predecessor ancestry, exact payload
    /// binding and final QC signatures against the trusted binding context. Pruned
    /// predecessor contents remain trusted, as with the proposal inspector.
    /// This is read-only: no signing, application, WAL or checkpoint advancement.
    /// Intermediate prevote/POL causal carriers are NOT proven; this API is not
    /// sufficient for live activation. Work scales with both complete retained
    /// cones and committed history; callers must budget it independently of wire bounds.
    ///
    /// # Errors
    /// Rejects nonfinal QCs, context/effect/signature mismatches, invalid retained
    /// history and unbound or noncausal proposal/predecessor/QC carriers.
    pub fn inspect_slot_agreement_certificate(
        &self,
        payload: &crate::SlotAgreementCertificatePayload,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
    ) -> Result<Decision, CryptoError> {
        let invalid =
            |message: &str| CryptoError::new(CryptoErrorKind::MalformedCertificate, message);
        let set = self.set_for_round(payload.proposal.decision.round);
        let digest = payload.digest(set)?;
        if carrier.round <= payload.proposal_carrier.round {
            return Err(invalid("agreement QC carrier must follow its proposal"));
        }
        let (decision, proposal_causal) = self.inspect_slot_proposal_with_causal(
            &payload.proposal,
            &payload.proposal_carrier,
            binding.tip(),
        )?;
        if let Some(previous) = binding.carrier()
            && (previous.round >= payload.proposal_carrier.round
                || !proposal_causal.contains(previous))
        {
            return Err(invalid(
                "agreement proposal does not extend predecessor carrier",
            ));
        }
        payload.certificate.verify(binding.tip(), set)?;
        let causal = self.slot_causal_history(carrier, digest, &payload.proposal.decision)?;
        if !causal.contains(&payload.proposal_carrier) {
            return Err(invalid(
                "agreement QC does not causally extend proposal carrier",
            ));
        }
        Ok(decision)
    }

    /// Inspects an inactive nonnil proposal → prevote QC → precommit QC chain.
    ///
    /// This separate, stronger-than-final-only API authenticates both QCs and their
    /// exact carriers in strict causal order. Full retained cones are verified;
    /// pruned boundary contents remain trusted. It does NOT prove individual vote
    /// carriers, POL/view-proposal authorization, leader selection or reducer safety.
    /// The caller must authorize the proposer externally. No live state is changed.
    ///
    /// # Errors
    /// Rejects codec/statement bounds first, then carrier ordering, proposal/context
    /// and predecessor errors, QC authentication failures and invalid causal cones.
    pub fn inspect_slot_agreement_phase_chain(
        &self,
        payload: &crate::SlotAgreementPhaseChain,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
    ) -> Result<Decision, CryptoError> {
        use crate::slot_agreement_phase::invalid;
        let p = &payload.prevote;
        let set = self.set_for_round(p.proposal.decision.round);
        let digest = payload.digest(set)?;
        if p.proposal_carrier.round >= payload.prevote_carrier.round
            || payload.prevote_carrier.round >= carrier.round
        {
            return Err(invalid("agreement phase carriers must strictly increase"));
        }
        let (decision, proposal_cone) = self.inspect_slot_proposal_with_causal(
            &p.proposal,
            &p.proposal_carrier,
            binding.tip(),
        )?;
        if let Some(previous) = binding.carrier()
            && (previous.round >= p.proposal_carrier.round || !proposal_cone.contains(previous))
        {
            return Err(invalid(
                "agreement proposal does not extend predecessor carrier",
            ));
        }
        p.certificate.verify(binding.tip(), set)?;
        payload.certificate.verify(binding.tip(), set)?;
        let prevote_cone = self.slot_causal_history(
            &payload.prevote_carrier,
            p.digest(set)?,
            &p.proposal.decision,
        )?;
        if !prevote_cone.contains(&p.proposal_carrier) {
            return Err(invalid("prevote QC does not extend exact proposal carrier"));
        }
        let final_cone = self.slot_causal_history(carrier, digest, &p.proposal.decision)?;
        if !final_cone.contains(&payload.prevote_carrier) {
            return Err(invalid(
                "precommit QC does not extend exact prevote QC carrier",
            ));
        }
        Ok(decision)
    }

    /// Verifies an inactive individual-vote phase chain without changing live state.
    ///
    /// Both strong QC carriers bind complete witness lists. Every witness must match
    /// its QC signature exactly, be authored by that signer, bind its vote payload,
    /// and contain the exact earlier phase prerequisite in its verified cone.
    /// No POL, view-proposal or proposer authorization is inferred; callers must
    /// supply proposer authorization externally. Pruned boundary contents are trusted.
    ///
    /// All cone walks share [`crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET`] visits,
    /// counting repeated references and repeated walks of shared ancestors. Pending
    /// references are also bounded by remaining work. Exhaustion rejects, not truncates.
    /// This bounds traversal, not signature algorithm cost or direct-rule evaluation.
    ///
    /// # Errors
    /// Rejects canonical bounds/statement mismatches first, then carrier ordering,
    /// QC/vote authentication, invalid cones, context/predecessor errors or work exhaustion.
    pub fn inspect_slot_agreement_strong_phase_chain(
        &self,
        payload: &crate::SlotAgreementStrongPhaseChain,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
    ) -> Result<Decision, CryptoError> {
        self.inspect_slot_agreement_strong_with_budget(
            payload,
            carrier,
            binding,
            crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET,
        )
    }

    fn inspect_slot_agreement_strong_with_budget(
        &self,
        payload: &crate::SlotAgreementStrongPhaseChain,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
        mut budget: usize,
    ) -> Result<Decision, CryptoError> {
        use crate::slot_agreement_phase::invalid;
        let p = &payload.prevote.aggregate;
        let set = self.set_for_round(p.proposal.decision.round);
        let digest = payload.digest(set)?;
        if p.proposal_carrier.round >= payload.prevote_carrier.round
            || payload.prevote_carrier.round >= carrier.round
        {
            return Err(invalid("strong phase carriers must strictly increase"));
        }
        p.certificate.verify(binding.tip(), set)?;
        payload.certificate.verify(binding.tip(), set)?;
        let final_cone = self.slot_causal_history_with_budget(
            carrier,
            digest,
            &p.proposal.decision,
            &mut budget,
        )?;
        if !final_cone.contains(&payload.prevote_carrier) {
            return Err(invalid(
                "strong final QC does not extend strong prevote carrier",
            ));
        }
        let prevote_cone = self.slot_causal_history_with_budget(
            &payload.prevote_carrier,
            payload.prevote.digest(set)?,
            &p.proposal.decision,
            &mut budget,
        )?;
        if !prevote_cone.contains(&p.proposal_carrier) {
            return Err(invalid(
                "strong prevote QC does not extend exact proposal carrier",
            ));
        }
        for (votes, prerequisite, qc_carrier, cone) in [
            (
                &payload.prevote.votes,
                &p.proposal_carrier,
                &payload.prevote_carrier,
                &prevote_cone,
            ),
            (
                &payload.votes,
                &payload.prevote_carrier,
                carrier,
                &final_cone,
            ),
        ] {
            for witness in votes {
                // Structural encoding already checked exact QC vote/signature equality,
                // canonical identity order, signer authorship and prerequisite identity.
                if witness.carrier.round >= qc_carrier.round || !cone.contains(&witness.carrier) {
                    return Err(invalid(
                        "QC does not extend every exact individual vote carrier",
                    ));
                }
                witness.payload.verify(binding.tip(), set)?;
                let vote_cone = self.slot_causal_history_with_budget(
                    &witness.carrier,
                    witness.payload.digest(set)?,
                    &p.proposal.decision,
                    &mut budget,
                )?;
                if !vote_cone.contains(prerequisite) {
                    return Err(invalid(
                        "individual vote does not extend its exact prerequisite",
                    ));
                }
            }
        }
        let (decision, proposal_cone) = self.inspect_slot_proposal_with_budget(
            &p.proposal,
            &p.proposal_carrier,
            binding.tip(),
            &mut budget,
        )?;
        if let Some(previous) = binding.carrier()
            && (previous.round >= p.proposal_carrier.round || !proposal_cone.contains(previous))
        {
            return Err(invalid(
                "strong proposal does not extend predecessor carrier",
            ));
        }
        Ok(decision)
    }

    /// Inspects an inactive authenticated view proposal with a legacy strong POL.
    ///
    /// Earlier POLs prove plain-proposal prerequisites, not earlier view authorization.
    /// Does not inspect local locks, activate agreement, or authorize application.
    /// All retained cones share one work budget; pruning retains its existing trust boundary.
    ///
    /// # Errors
    /// Rejects wrong proposers, invalid direct evidence, non-earlier or mismatched
    /// POLs, invalid signatures, noncausal evidence and exhausted traversal budgets.
    pub fn inspect_slot_agreement_view_proposal(
        &self,
        payload: &crate::SlotAgreementViewProposal,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
    ) -> Result<Decision, CryptoError> {
        self.inspect_slot_agreement_view_with_budget(
            payload,
            carrier,
            binding,
            crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET,
        )
    }

    fn inspect_slot_agreement_view_with_budget(
        &self,
        payload: &crate::SlotAgreementViewProposal,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
        mut budget: usize,
    ) -> Result<Decision, CryptoError> {
        use crate::slot_agreement_phase::invalid;
        let d = &payload.proposal.decision;
        let set = self.set_for_round(d.round);
        let digest = payload.digest(set)?;
        if carrier.author != crate::slot_agreement_view_proposer(set, d.round, payload.view)?
            || payload.proposal_carrier.round >= carrier.round
        {
            return Err(invalid("wrong view proposer or noncausal proposal carrier"));
        }
        let cone = self.slot_causal_history_with_budget(carrier, digest, d, &mut budget)?;
        let (decision, proposal_cone) = self.inspect_slot_proposal_with_budget(
            &payload.proposal,
            &payload.proposal_carrier,
            binding.tip(),
            &mut budget,
        )?;
        if !cone.contains(&payload.proposal_carrier) {
            return Err(invalid(
                "view proposal does not extend direct evidence carrier",
            ));
        }
        if let Some(previous) = binding.carrier()
            && (previous.round >= payload.proposal_carrier.round
                || !proposal_cone.contains(previous))
        {
            return Err(invalid("view proposal does not extend predecessor"));
        }
        if let Some(pol) = &payload.previous_pol {
            let p = &pol.payload.aggregate;
            if p.certificate.vote.view >= payload.view
                || p.proposal.decision != *d
                || p.proposal_carrier.round >= pol.carrier.round
                || pol.carrier.round >= carrier.round
                || !cone.contains(&pol.carrier)
            {
                return Err(invalid(
                    "view POL must be earlier, causal and for the exact decision",
                ));
            }
            p.certificate.verify(binding.tip(), set)?;
            let pol_cone = self.slot_causal_history_with_budget(
                &pol.carrier,
                pol.payload.digest(set)?,
                d,
                &mut budget,
            )?;
            let (_, prior_cone) = self.inspect_slot_proposal_with_budget(
                &p.proposal,
                &p.proposal_carrier,
                binding.tip(),
                &mut budget,
            )?;
            if !pol_cone.contains(&p.proposal_carrier) {
                return Err(invalid("POL lacks direct proposal carrier"));
            }
            if let Some(previous) = binding.carrier()
                && (previous.round >= p.proposal_carrier.round || !prior_cone.contains(previous))
            {
                return Err(invalid("POL proposal lacks predecessor"));
            }
            for witness in &pol.payload.votes {
                if witness.carrier.round >= pol.carrier.round
                    || !pol_cone.contains(&witness.carrier)
                {
                    return Err(invalid("POL lacks individual vote carrier"));
                }
                witness.payload.verify(binding.tip(), set)?;
                let vote_cone = self.slot_causal_history_with_budget(
                    &witness.carrier,
                    witness.payload.digest(set)?,
                    d,
                    &mut budget,
                )?;
                if !vote_cone.contains(&p.proposal_carrier) {
                    return Err(invalid("POL vote lacks plain proposal prerequisite"));
                }
            }
        }
        Ok(decision)
    }

    /// Inspects inactive flat view authorization and both individual voting phases.
    /// Does not certify local lock/WAL execution, timeout validity or application.
    pub fn inspect_slot_agreement_proof(
        &self,
        proof: &crate::SlotAgreementProof,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
    ) -> Result<Decision, CryptoError> {
        self.inspect_slot_agreement_proof_with_budget(
            proof,
            carrier,
            binding,
            crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET,
        )
    }

    fn inspect_slot_agreement_proof_with_budget(
        &self,
        proof: &crate::SlotAgreementProof,
        carrier: &VertexId,
        binding: &crate::SlotAgreementBinding,
        mut budget: usize,
    ) -> Result<Decision, CryptoError> {
        use crate::slot_agreement_phase::invalid;
        let last = proof
            .entries
            .last()
            .ok_or_else(|| invalid("empty lineage"))?;
        let d = &last.proposal.decision;
        let set = self.set_for_round(d.round);
        // Encoding checks every statement and exact witness relationship first.
        let digest = proof.digest(set)?;
        // Preflight the entire lineage before authenticating even its first entry.
        // This bounds structural work, not total cryptographic CPU time.
        for p in &proof.entries {
            if p.view_carrier.author != crate::slot_agreement_view_proposer(set, d.round, p.view)?
                || p.proposal_carrier.round >= p.view_carrier.round
            {
                return Err(invalid("wrong proposer or view carrier ordering"));
            }
            if let Some(prior) = p.previous_pol {
                let pol = proof.entries[prior]
                    .pol
                    .as_ref()
                    .ok_or_else(|| invalid("missing POL"))?;
                if pol.carrier.round >= p.view_carrier.round {
                    return Err(invalid("prior POL must precede view carrier"));
                }
            }
            if let Some(pol) = &p.pol {
                if p.view_carrier.round >= pol.carrier.round {
                    return Err(invalid("view carrier must precede own POL"));
                }
                if pol
                    .votes
                    .iter()
                    .any(|w| w.carrier.round >= pol.carrier.round)
                {
                    return Err(invalid("prevote witness must precede POL carrier"));
                }
            }
        }
        let selected_pol = last
            .pol
            .as_ref()
            .ok_or_else(|| invalid("missing final POL"))?;
        if selected_pol.carrier.round >= carrier.round {
            return Err(invalid("selected POL must precede final carrier"));
        }
        if proof.votes.iter().any(|w| w.carrier.round >= carrier.round) {
            return Err(invalid("precommit witness must precede final carrier"));
        }
        let mut result = None;
        for (i, p) in proof.entries.iter().enumerate() {
            let (decision, plain_cone) = self.inspect_slot_proposal_with_budget(
                &p.proposal,
                &p.proposal_carrier,
                binding.tip(),
                &mut budget,
            )?;
            result = Some(decision);
            if let Some(previous) = binding.carrier()
                && (previous.round >= p.proposal_carrier.round || !plain_cone.contains(previous))
            {
                return Err(invalid("plain proposal lacks predecessor"));
            }
            let view_cone = self.slot_causal_history_with_budget(
                &p.view_carrier,
                proof.view_digest(i)?,
                d,
                &mut budget,
            )?;
            if !view_cone.contains(&p.proposal_carrier) {
                return Err(invalid("view lacks plain proposal"));
            }
            if let Some(prior) = p.previous_pol {
                let pol = proof.entries[prior]
                    .pol
                    .as_ref()
                    .ok_or_else(|| invalid("missing POL"))?;
                if !view_cone.contains(&pol.carrier) {
                    return Err(invalid("view lacks exact prior POL"));
                }
            }
            if let Some(pol) = &p.pol {
                pol.certificate.verify(binding.tip(), set)?;
                let cone = self.slot_causal_history_with_budget(
                    &pol.carrier,
                    proof.pol_digest(i, set)?,
                    d,
                    &mut budget,
                )?;
                if !cone.contains(&p.view_carrier) {
                    return Err(invalid("POL lacks view proposal"));
                }
                for w in &pol.votes {
                    if !cone.contains(&w.carrier) {
                        return Err(invalid("POL lacks vote witness"));
                    }
                    w.payload.verify(binding.tip(), set)?;
                    let c = self.slot_causal_history_with_budget(
                        &w.carrier,
                        w.payload.digest(set)?,
                        d,
                        &mut budget,
                    )?;
                    if !c.contains(&p.view_carrier) {
                        return Err(invalid("prevote lacks view authorization"));
                    }
                }
            }
        }
        proof.certificate.verify(binding.tip(), set)?;
        let cone = self.slot_causal_history_with_budget(carrier, digest, d, &mut budget)?;
        let pol = last
            .pol
            .as_ref()
            .ok_or_else(|| invalid("missing final POL"))?;
        if !cone.contains(&pol.carrier) {
            return Err(invalid("final lacks selected POL"));
        }
        for w in &proof.votes {
            if !cone.contains(&w.carrier) {
                return Err(invalid("final lacks witness"));
            }
            w.payload.verify(binding.tip(), set)?;
            let c = self.slot_causal_history_with_budget(
                &w.carrier,
                w.payload.digest(set)?,
                d,
                &mut budget,
            )?;
            if !c.contains(&pol.carrier) {
                return Err(invalid("precommit lacks selected POL"));
            }
        }
        result.ok_or_else(|| invalid("empty lineage"))
    }

    /// Number of held vertices in `round + 1` that vote for the leader of
    /// `round`.
    ///
    /// Used by the pacemaker to decide whether an indirect commit is safe: if
    /// more than `f` votes are held, a supermajority of non-votes cannot exist,
    /// so the direct rule can never later decide to skip the same slot.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`].
    pub fn held_voters(&self, round: u64) -> Result<usize, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(0);
        };
        let leader_id = leader.id()?;
        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        Ok(tally_votes(
            self.set_for_round(round + 1),
            &leader_id,
            &candidates,
            &self.schedule,
        )?
        .len())
    }

    /// The first vertex the history walk from `round`'s leader cannot resolve.
    ///
    /// [`Dag::missing_references`] only sees gaps that a *held* vertex names
    /// directly. The reference rule requires a quorum of previous-round authors, not
    /// all of them, so a node can miss a vertex that no held vertex points at and
    /// still have a valid DAG — and then stall, because the commit walk needs it.
    /// This is the other half of the repair signal: the exact vertex blocking the
    /// cursor, found by the same walk the commit rule performs.
    #[must_use]
    pub fn missing_history(&self, round: u64) -> Option<VertexId> {
        let leader = self.leader(round)?;
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![leader.id().ok()?];
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let Some(vertex) = self.vertices.get(&(current.round, current.author.clone())) else {
                return Some(current);
            };
            stack.extend(vertex.references.iter().cloned());
        }
        None
    }

    /// Every reference this node holds that points at a vertex it does not hold.
    ///
    /// The reference rule is what makes a dropped frame *visible*: if a vertex
    /// never arrived, the next round's vertices still name it, so the gap lives in
    /// the DAG and not only on the wire. This is the repair list, and it is derived
    /// from what the node holds rather than from a guess about which authors ought
    /// to have authored.
    ///
    /// Note what insertion does *not* do: it accepts a vertex whose referenced
    /// neighbours are absent, because the shape rule is about a quorum of distinct
    /// authors, not about holding every edge. The absence only bites when a walk
    /// needs the missing vertex — a commit, an ancestry check, or an absence proof.
    /// So repair cannot hang off a rejected insert; it has to scan for dangling
    /// edges.
    ///
    /// References into a pruned round are excluded: they are gone by policy, not by
    /// delay, and asking for them would never succeed.
    #[must_use]
    pub fn missing_references(&self) -> Vec<VertexId> {
        let mut missing = Vec::new();
        let mut seen: HashSet<VertexId> = HashSet::new();
        for vertex in self.vertices.values() {
            for reference in &vertex.references {
                if self.is_pruned(reference.round)
                    || self.is_fenced(&reference.author, reference.round)
                {
                    continue;
                }
                if self
                    .vertices
                    .contains_key(&(reference.round, reference.author.clone()))
                {
                    continue;
                }
                if seen.insert(reference.clone()) {
                    missing.push(reference.clone());
                }
            }
        }
        missing
    }

    /// Returns whether this node can still see a vote quorum for `round`'s
    /// leader if every vertex it has not received turns out to vote for it.
    ///
    /// A round that cannot reach a quorum can never anchor, so an anchor ahead
    /// of it is the lowest one that will ever exist and may be used without
    /// waiting for it.
    ///
    /// # Errors
    ///
    /// Propagates [`tally_votes`].
    pub fn can_still_anchor(&self, round: u64) -> Result<bool, CryptoError> {
        let Some(leader) = self.leader(round) else {
            // A fenced author can never produce the missing leader, so waiting
            // for it would keep the cursor below a fence forever. Without a
            // fence the leader's vertex is missing, not disproved: it may still
            // arrive, and a held vote already names its id, so the conservative
            // answer is "possible".
            return Ok(self
                .leader_author(round)
                .is_none_or(|author| !self.is_fenced(author, round)));
        };
        let leader_id = leader.id()?;

        let candidates: Vec<Vertex> = self
            .round_vertices(round + 1)
            .into_iter()
            .cloned()
            .collect();
        let voter_set = self.set_for_round(round + 1);
        let voters = tally_votes(voter_set, &leader_id, &candidates, &self.schedule)?;
        let held: HashSet<&[u8]> = candidates
            .iter()
            .map(|vertex| vertex.author.as_slice())
            .collect();
        // A fenced validator cannot vote from its fence round on. Counting a
        // fenced held vote or a fenced missing voter as possible would keep a
        // round "possible" forever and make a restarted node wait below its own
        // fence (measured: a node killed at its fence round stalled on the round
        // just before it).
        let possible = voter_set
            .validators
            .iter()
            .filter(|record| {
                !self.is_fenced(&record.validator_id, round + 1)
                    && (voters.contains(&record.validator_id)
                        || !held.contains(record.validator_id.as_slice()))
            })
            .count();
        Ok(possible >= voter_set.quorum_size())
    }

    /// Collects `id` and its ancestors that are not yet committed, in a
    /// deterministic order.
    fn collect_uncommitted_history(&self, id: &VertexId) -> Result<Vec<VertexId>, CryptoError> {
        let mut collected: Vec<VertexId> = Vec::new();
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![id.clone()];
        while let Some(current) = stack.pop() {
            if !seen.insert(current.clone()) {
                continue;
            }
            // Pruned ancestors are already committed and already reflected in the
            // state snapshot, so the block stops there instead of failing.
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            if self.committed.contains(&current.digest) {
                continue;
            }
            collected.extend(vertex.references.iter().cloned());
            stack.extend(vertex.references.iter().cloned());
            collected.push(current);
        }

        // Deduplicate, drop already committed, and order by (round, author) so two
        // nodes with the same history commit the same sequence.
        // Pruned vertices reach `collected` through a reference list, so they have
        // to be dropped here as well as skipped in the walk.
        collected.retain(|vertex| {
            !self.committed.contains(&vertex.digest) && !self.is_pruned(vertex.round)
        });
        collected.sort_by(|a, b| a.round.cmp(&b.round).then_with(|| a.author.cmp(&b.author)));
        collected.dedup();

        Ok(collected)
    }

    // Apply only the inspection result for this same round and unchanged DAG.
    // Keeping application private prevents external callers from applying stale candidates.
    fn apply_inspected_decision(
        &mut self,
        round: u64,
        decision: &Decision,
    ) -> Result<(), CryptoError> {
        match decision {
            Decision::Commit(history) => {
                for vertex in history {
                    self.committed.insert(vertex.digest);
                    self.order.push(vertex.clone());
                }
            }
            Decision::Skip => {
                let leader = self
                    .leader(round)
                    .expect("inspection found a held leader")
                    .id()?;
                self.record_skip(round, leader.author, Some(leader.digest));
            }
            Decision::Undecided => {}
        }
        Ok(())
    }

    /// The committed sequence above the retained prefix, in commit order.
    #[must_use]
    pub fn order(&self) -> &[VertexId] {
        &self.order
    }

    /// The committed prefix whose leaves the store no longer holds.
    #[must_use]
    pub fn prefix(&self) -> &CommitFrontier {
        &self.prefix
    }

    /// Total committed entries, retained tail included.
    #[must_use]
    pub fn order_len(&self) -> usize {
        self.prefix.len() + self.order.len()
    }

    /// Adopts a verified committed prefix from a snapshot.
    ///
    /// The caller has already verified the vertices and the header that commits
    /// this order. New commits append after the prefix.
    pub fn seed_order(&mut self, order: Vec<VertexId>) {
        self.prefix = CommitFrontier::empty();
        self.committed = order.iter().map(|id| id.digest).collect();
        self.order = order;
    }

    /// Adopts a compact prefix plus the committed tail above the floor.
    ///
    /// `prefix` covers the entries at or below the DAG floor, whose leaves the
    /// store dropped; `order` is the committed tail the checkpoint retained. The
    /// two together must reproduce the anchor's `dag_root`.
    pub fn seed_prefix(&mut self, prefix: CommitFrontier, order: Vec<VertexId>) {
        self.committed = order.iter().map(|id| id.digest).collect();
        self.prefix = prefix;
        self.order = order;
    }

    /// Truncates the committed order to `len` entries.
    ///
    /// Replay uses this when the stored certified head covers an earlier prefix
    /// than the decision sequence it just rebuilt. The compact prefix is
    /// immutable; only the retained tail can rewind.
    pub fn truncate_order(&mut self, len: usize) {
        let keep = len.saturating_sub(self.prefix.len()).min(self.order.len());
        self.order.truncate(keep);
        self.committed = self.order.iter().map(|id| id.digest).collect();
    }

    /// The Merkle root over the first `len` committed entries.
    #[must_use]
    pub fn commit_root_at(&self, len: usize) -> Option<[u8; 32]> {
        self.prefix
            .root_at(&self.order, len.checked_sub(self.prefix.len())?)
    }

    /// The Merkle root over everything this node has committed, in commit order.
    #[must_use]
    pub fn commit_root(&self) -> [u8; 32] {
        self.commit_root_at(self.order_len())
            .expect("the retained order length is in range")
    }

    /// Slots this node has decided to skip, in decision order.
    #[must_use]
    pub fn skipped(&self) -> &[SkippedRound] {
        &self.skipped
    }

    /// Records a skipped round.
    ///
    /// Returns whether the record is new. A round is skipped at most once, so a
    /// second decision to skip it is a no-op.
    pub(crate) fn record_skip(
        &mut self,
        round: u64,
        author: Vec<u8>,
        digest: Option<[u8; 32]>,
    ) -> bool {
        if self.skipped.iter().any(|entry| entry.round == round) {
            return false;
        }
        self.skipped.push(SkippedRound {
            round,
            author,
            digest,
        });
        true
    }

    /// Returns whether `anchor`'s causal history contains a vertex at
    /// `(round, author)`.
    ///
    /// This answers a question about a vertex the node may not hold: an anchor can
    /// prove that a leader exists without the node having received that leader, and
    /// it can equally prove that no such leader can ever be committed.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::MissingReference`] when the walk reaches a vertex this
    /// node does not hold, which means the answer is unknown rather than negative.
    pub fn history_contains_author(
        &self,
        anchor: &VertexId,
        round: u64,
        author: &[u8],
    ) -> Result<bool, CryptoError> {
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![anchor.clone()];
        while let Some(current) = stack.pop() {
            if current.round == round && current.author == author {
                return Ok(true);
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            stack.extend(vertex.references.iter().cloned());
        }
        Ok(false)
    }

    /// Returns whether `ancestor` is reachable from `descendant` through
    /// references, counting a vertex as reachable from itself.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::MissingReference`] when the walk reaches a vertex this
    /// node does not hold.
    pub fn is_ancestor(
        &self,
        ancestor: &VertexId,
        descendant: &VertexId,
    ) -> Result<bool, CryptoError> {
        let mut seen: HashSet<VertexId> = HashSet::new();
        let mut stack = vec![descendant.clone()];
        while let Some(current) = stack.pop() {
            if current == *ancestor {
                return Ok(true);
            }
            if !seen.insert(current.clone()) {
                continue;
            }
            if self.is_pruned(current.round) {
                continue;
            }
            let vertex = self
                .vertices
                .get(&(current.round, current.author.clone()))
                .ok_or_else(|| missing(&current))?;
            stack.extend(vertex.references.iter().cloned());
        }
        Ok(false)
    }

    /// Decides an earlier leader using a **committed** anchor.
    ///
    /// This is the indirect rule. Once an anchor two or more rounds later is
    /// committed, the question for an earlier slot is no longer "did a quorum vote
    /// for it" but "is it inside the anchor's history":
    ///
    /// - reachable from the anchor: commit it and any history the anchor did not
    ///   already carry;
    /// - not reachable: skip it, because every future committed leader extends the
    ///   anchor, so a slot outside its history can never be committed;
    /// - the anchor is too recent to have had the chance to include a quorum path:
    ///   undecided.
    ///
    /// The skip half assumes the protocol rule that every vertex references a
    /// supermajority of the previous round. [`Dag::insert`] enforces that rule, so
    /// the argument holds for any DAG this node accepted.
    ///
    /// # Errors
    ///
    /// Propagates ancestry, vertex encoding, and missing-history errors.
    pub fn try_indirect_decide(
        &mut self,
        round: u64,
        anchor: &VertexId,
    ) -> Result<Decision, CryptoError> {
        let decision = self.inspect_indirect_decide(round, anchor)?;
        self.apply_inspected_decision(round, &decision)?;
        Ok(decision)
    }

    /// Inspects the indirect rule without changing the order or recording a skip.
    ///
    /// The caller must establish anchor eligibility and any additional voting gates.
    /// This method does not check that the anchor is committed or quorum-supported.
    /// Results describe the current view only and are not durable authorizations.
    ///
    /// # Errors
    /// Propagates ancestry, vertex encoding, and missing-history errors.
    pub fn inspect_indirect_decide(
        &self,
        round: u64,
        anchor: &VertexId,
    ) -> Result<Decision, CryptoError> {
        let Some(leader) = self.leader(round) else {
            return Ok(Decision::Undecided);
        };
        // The anchor needs at least the intervening round to have carried a quorum
        // path to the earlier leader.
        if anchor.round < round + 2 {
            return Ok(Decision::Undecided);
        }
        let leader_id = leader.id()?;
        if self.is_ancestor(&leader_id, anchor)? {
            let history = self.collect_uncommitted_history(&leader_id)?;
            return Ok(Decision::Commit(history));
        }
        Ok(Decision::Skip)
    }
}

/// The error for a vertex that is referenced but not held.
fn missing(id: &VertexId) -> CryptoError {
    CryptoError::new(
        CryptoErrorKind::MissingReference,
        format!(
            "vertex {}@{} is referenced but not held",
            String::from_utf8_lossy(&id.author),
            id.round
        ),
    )
}

/// The leaf commitment for one committed vertex.
///
/// The domain tag keeps a commit leaf from colliding with any other kind of leaf
/// built by the same tree implementation.
#[must_use]
pub fn commit_leaf(id: &VertexId) -> [u8; 32] {
    crypto::merkle::leaf(
        b"KARSA/DAG/COMMIT/v1",
        &[&id.round.to_le_bytes(), &id.author, &id.digest],
    )
}

/// A Merkle root over a commit sequence, in commit order.
#[must_use]
pub fn commit_root(order: &[VertexId]) -> [u8; 32] {
    MerkleTree::from_leaves(order.iter().map(commit_leaf).collect()).root()
}

/// Proof that one vertex is inside a commit sequence.
///
/// This is what a header's `dag_root` is for: a client that is handed a header can
/// check that a specific vertex was part of the commit it names, without being
/// handed the commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitProof {
    /// The vertex being proven.
    pub vertex: VertexId,
    /// Its path to the root.
    pub proof: MerkleProof,
}

impl CommitProof {
    /// Builds a proof for the vertex at `index` in `order`.
    #[must_use]
    pub fn prove(order: &[VertexId], index: usize) -> Option<Self> {
        let vertex = order.get(index)?.clone();
        let tree = MerkleTree::from_leaves(order.iter().map(commit_leaf).collect());
        Some(Self {
            vertex,
            proof: tree.proof(index)?,
        })
    }

    /// Returns whether the proven vertex is inside `dag_root`.
    #[must_use]
    pub fn verify(&self, dag_root: &[u8; 32]) -> bool {
        MerkleTree::verify(dag_root, &commit_leaf(&self.vertex), &self.proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::{bitmap_len, set_bit};
    use crate::pacemaker::{Pacemaker, PacemakerConfig, Step};
    use crate::round_skip::{NoVoteAttestation, RoundSkip, RoundSkipProof};
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crate::set_change::SetChange;
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const EPOCH: u64 = 1;
    /// Round 0 is genesis and needs no references, so the first leader is here.
    const LEADER_ROUND: u64 = 1;

    struct Fixture {
        keys: Vec<Vec<u8>>,
        dag: Dag,
    }

    fn fixture(count: usize) -> Fixture {
        let mut keys = Vec::with_capacity(count);
        let mut validators = Vec::with_capacity(count);
        for index in 0..count {
            let seed = [u8::try_from(index + 1).unwrap(); 32];
            let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
            let mut private_key = Vec::with_capacity(64);
            private_key.extend_from_slice(&seed);
            private_key.extend_from_slice(&public_key);
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: public_key.to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            keys.push(private_key);
        }
        let set = ValidatorSet {
            epoch: EPOCH,
            validators,
        };
        set.validate().unwrap();
        let mut dag = Dag::new(set);
        // The fixtures sign round-skip certificates over this chain, so the same
        // id has to be available to the control-payload verifier.
        dag.set_chain_id(b"karsa-dag-1".to_vec());
        Fixture { keys, dag }
    }

    fn fence_certificate(fixture: &Fixture, from_round: u64, validator: &[u8]) -> FenceCertificate {
        let set = fixture.dag.set();
        let fence =
            crate::fence::Fence::new(b"karsa-dag-1".to_vec(), from_round, validator.to_vec());
        let payload = fence.signing_payload().unwrap();
        let mut signer_bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::new();
        for index in 0..set.quorum_size() {
            set_bit(&mut signer_bitmap, index);
            signatures.push(Ed25519Scheme.sign(&fixture.keys[index], &payload).unwrap());
        }
        FenceCertificate {
            fence,
            signer_bitmap,
            signatures,
        }
    }

    fn vertex(fixture: &Fixture, author: usize, round: u64, references: Vec<VertexId>) -> Vertex {
        vertex_with_payload(
            fixture,
            author,
            round,
            references,
            [u8::try_from(author + 1).unwrap(); 32],
        )
    }

    fn vertex_with_payload(
        fixture: &Fixture,
        author: usize,
        round: u64,
        references: Vec<VertexId>,
        payload_hash: [u8; 32],
    ) -> Vertex {
        let mut vertex = Vertex {
            chain_id: b"karsa-dag-1".to_vec(),
            epoch: EPOCH,
            round,
            author: format!("val-{author}").into_bytes(),
            payload_hash,
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload().unwrap();
        vertex.signature = Ed25519Scheme.sign(&fixture.keys[author], &payload).unwrap();
        vertex
    }

    impl Fixture {
        fn count(&self) -> usize {
            self.dag.set().validators.len()
        }

        fn leader_index(&self, round: u64) -> usize {
            usize::try_from(round).unwrap() % self.count()
        }

        /// Inserts one vertex per validator, all with the same references.
        fn full_round(&mut self, round: u64, references: &[VertexId]) -> Result<(), CryptoError> {
            for author in 0..self.count() {
                let vertex = vertex(self, author, round, references.to_vec());
                self.dag.insert(vertex)?;
            }
            Ok(())
        }

        fn ids(&self, round: u64) -> Vec<VertexId> {
            self.ids_where(round, |_| true)
        }

        /// Ids of every vertex in `round` except the round's leader.
        fn ids_without_leader(&self, round: u64) -> Vec<VertexId> {
            let leader = self.leader_index(round);
            self.ids_where(round, |author| author != leader)
        }

        fn ids_where(&self, round: u64, keep: impl Fn(usize) -> bool) -> Vec<VertexId> {
            let mut ids = Vec::new();
            for author in 0..self.count() {
                if !keep(author) {
                    continue;
                }
                let key = format!("val-{author}");
                if let Some(vertex) = self.dag.get(round, key.as_bytes()) {
                    ids.push(vertex.id().unwrap());
                }
            }
            ids
        }
    }

    /// Genesis round plus the first leader round, both full and well formed.
    fn bootstrapped(count: usize) -> Fixture {
        let mut fixture = fixture(count);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        fixture.full_round(LEADER_ROUND, &genesis).unwrap();
        fixture
    }

    #[test]
    fn a_fence_below_the_floor_still_applies_to_later_rounds() {
        let mut fixture = fixture(4);
        let certificate = fence_certificate(&fixture, 1, b"val-0");
        // A checkpoint above the declared round must not make the certificate
        // unusable: the promise still covers every round this DAG will decide.
        fixture.dag.set_floor(5);
        fixture
            .dag
            .apply_fence(b"karsa-dag-1", &certificate)
            .unwrap();
        assert!(fixture.dag.is_fenced(b"val-0", 5));
        assert!(fixture.dag.is_fenced(b"val-0", 9));
        assert!(!fixture.dag.is_fenced(b"val-0", 0));
    }

    #[test]
    fn two_fences_coexist_at_seven_validators_and_a_third_is_refused() {
        let mut fixture = fixture(7);
        for validator in [b"val-0".as_slice(), b"val-1".as_slice()] {
            let certificate = fence_certificate(&fixture, 1, validator);
            fixture
                .dag
                .apply_fence(b"karsa-dag-1", &certificate)
                .unwrap();
        }
        assert!(fixture.dag.is_fenced(b"val-0", 1));
        assert!(fixture.dag.is_fenced(b"val-1", 1));

        let third = fence_certificate(&fixture, 1, b"val-2");
        assert!(matches!(
            fixture.dag.apply_fence(b"karsa-dag-1", &third),
            Err(crate::fence::FenceError::TooMany { count: 3, limit: 2 })
        ));
    }

    #[test]
    fn two_fenced_missing_voters_free_a_live_leader_at_two_faults() {
        let mut fixture = fixture(7);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        fixture.full_round(1, &genesis).unwrap();
        let leader = fixture.dag.leader_author(1).unwrap().to_vec();
        let non_leader: Vec<VertexId> = fixture
            .ids(1)
            .into_iter()
            .filter(|id| id.author != leader)
            .take(5)
            .collect();
        // Five voters, none of them naming the leader. The two authors that did
        // not vote are both fenced; with f = 2 that is the whole fault budget.
        for author in 0..5 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 2, non_leader.clone()))
                .unwrap();
        }
        for validator in [b"val-5".as_slice(), b"val-6".as_slice()] {
            let certificate = fence_certificate(&fixture, 2, validator);
            fixture
                .dag
                .apply_fence(b"karsa-dag-1", &certificate)
                .unwrap();
        }
        assert!(fixture.dag.can_skip_with_fence(1).unwrap());
        assert!(fixture.dag.skip_with_fence(1).unwrap());
        assert_eq!(fixture.dag.skipped().len(), 1);
        assert_eq!(fixture.dag.skipped()[0].round, 1);
    }

    #[test]
    fn three_held_votes_block_a_fence_skip_at_two_faults() {
        let mut fixture = fixture(7);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        fixture.full_round(1, &genesis).unwrap();
        let leader = fixture.dag.leader(1).unwrap().id().unwrap();
        let non_leader: Vec<VertexId> = fixture
            .ids(1)
            .into_iter()
            .filter(|id| id.author != leader.author)
            .take(5)
            .collect();
        let mut vote_refs = non_leader[..4].to_vec();
        vote_refs.push(leader);
        for author in 0..3 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 2, vote_refs.clone()))
                .unwrap();
        }
        for author in 3..5 {
            fixture
                .dag
                .insert(vertex(&fixture, author, 2, non_leader.clone()))
                .unwrap();
        }
        for validator in [b"val-5".as_slice(), b"val-6".as_slice()] {
            let certificate = fence_certificate(&fixture, 2, validator);
            fixture
                .dag
                .apply_fence(b"karsa-dag-1", &certificate)
                .unwrap();
        }
        assert!(
            !fixture.dag.can_skip_with_fence(1).unwrap(),
            "three held votes exceed the two-fault budget"
        );
    }

    /// The stalled shape from the live run: round 73's leader is held, round 74
    /// is held from four of five validators (two votes, two non-votes), and
    /// validator 0 is missing.
    ///
    /// Only the vertices a decision touches are materialized. The reference rule
    /// counts previous-round authors, not held vertices, so the earlier rounds
    /// can be named by id without building them.
    fn stalled_round_skip() -> (Fixture, VertexId) {
        let mut fixture = fixture(5);
        let fabricated = |round: u64, author: usize| VertexId {
            round,
            author: format!("val-{author}").into_bytes(),
            digest: [u8::try_from(author + 1).unwrap(); 32],
        };
        let references: Vec<VertexId> = (0..4).map(|author| fabricated(72, author)).collect();
        let leader = fixture
            .dag
            .insert(vertex(&fixture, 3, 73, references))
            .unwrap();
        for author in 1..5 {
            let mut references: Vec<VertexId> =
                (0..4).map(|author| fabricated(73, author)).collect();
            if author <= 2 {
                references.push(leader.clone());
            }
            fixture
                .dag
                .insert(vertex(&fixture, author, 74, references))
                .unwrap();
        }
        (fixture, leader)
    }

    fn stall_proof(fixture: &Fixture, leader: &VertexId) -> RoundSkipProof {
        let id = |author: usize| {
            fixture
                .dag
                .get(74, format!("val-{author}").as_bytes())
                .expect("the stall holds every survivor's voting-round vertex")
                .id()
                .unwrap()
        };
        RoundSkipProof {
            attestation: NoVoteAttestation {
                skip: RoundSkip::new(b"karsa-dag-1".to_vec(), leader.clone()),
                signer_bitmap: vec![0u8; bitmap_len(5)],
                signatures: Vec::new(),
            },
            votes: vec![id(1), id(2)],
            non_votes: vec![id(3), id(4)],
            fenced_absent: Vec::new(),
            missing: vec![b"val-0".to_vec()],
        }
    }

    /// Bootstrapped four-validator DAG with a split voting round for round one.
    ///
    /// Authors 0 and 1 vote for the round-one leader; authors 2 and 3 do not.
    /// The returned proof partitions that round into two votes and two non-votes,
    /// which bounds the possible vote quorum at two of three.
    fn split_round_two() -> (Fixture, RoundSkipProof) {
        let mut fixture = bootstrapped(4);
        let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let votes = fixture.ids(LEADER_ROUND);
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);
        for author in 0..4 {
            let references = if author < 2 {
                votes.clone()
            } else {
                without_leader.clone()
            };
            fixture
                .dag
                .insert(vertex(&fixture, author, LEADER_ROUND + 1, references))
                .unwrap();
        }
        let round_two = fixture.ids(LEADER_ROUND + 1);
        let proof = RoundSkipProof {
            attestation: NoVoteAttestation {
                skip: RoundSkip::new(b"karsa-dag-1".to_vec(), leader),
                signer_bitmap: vec![0u8; bitmap_len(4)],
                signatures: Vec::new(),
            },
            votes: round_two[..2].to_vec(),
            non_votes: round_two[2..].to_vec(),
            fenced_absent: Vec::new(),
            missing: Vec::new(),
        };
        (fixture, proof)
    }

    /// Inserts round three with one author naming the certificate digest.
    fn insert_certificate_round(
        fixture: &mut Fixture,
        carrier: usize,
        digest: [u8; 32],
        references: Vec<VertexId>,
    ) {
        for author in 0..4 {
            let payload = if author == carrier {
                digest
            } else {
                [u8::try_from(author + 1).unwrap(); 32]
            };
            let vertex = vertex_with_payload(
                fixture,
                author,
                LEADER_ROUND + 2,
                references.clone(),
                payload,
            );
            fixture.dag.insert(vertex).unwrap();
        }
    }

    #[test]
    fn a_verified_round_skip_proof_is_stored_but_waits_for_an_anchor() {
        let (mut fixture, leader) = stalled_round_skip();
        assert_eq!(
            fixture.dag.try_commit(73).unwrap(),
            Decision::Undecided,
            "two votes of four commit nothing and are not a quorum of non-votes"
        );
        assert!(!fixture.dag.skip_with_attestation(73).unwrap());

        let proof = stall_proof(&fixture, &leader);
        let check = fixture
            .dag
            .apply_round_skip(b"karsa-dag-1", proof)
            .expect("two votes plus one missing voter stay below the quorum");
        assert_eq!(check.votes, 2);
        assert_eq!(check.non_votes, 2);
        assert_eq!(check.missing, 1);
        assert_eq!(check.possible_votes, 3);
        assert_eq!(check.quorum, 4);
        assert!(fixture.dag.round_skip(73).is_some());

        // The DAG can still record the skip when a caller asks directly, but the
        // pacemaker no longer treats a held proof as a decision. Without an anchor
        // in this fixture the cursor has to wait.
        assert!(fixture.dag.skip_with_attestation(73).unwrap());
        assert_eq!(fixture.dag.skipped()[0].round, 73);

        let mut pacemaker = Pacemaker::new(PacemakerConfig::default(), 73);
        let step = pacemaker.tick(&mut fixture.dag).unwrap();
        assert_eq!(pacemaker.cursor(), 73);
        assert_eq!(pacemaker.skip_counts().attested, 0);
        assert!(matches!(step, Step::Waiting { .. } | Step::TimedOut { .. }));
    }

    #[test]
    fn a_causal_certificate_does_not_override_a_commit() {
        let (mut fixture, proof) = split_round_two();
        let digest = ControlPayload::RoundSkip(Box::new(proof.clone()))
            .digest()
            .unwrap();
        let round_two = fixture.ids(LEADER_ROUND + 1);
        // The round-three leader (author 3) carries the certificate, so the anchor
        // the pacemaker selects for round one has the payload in its own history.
        insert_certificate_round(&mut fixture, 3, digest, round_two);
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        fixture
            .dag
            .add_control(ControlPayload::RoundSkip(Box::new(proof)))
            .unwrap();

        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let skip = fixture.dag.anchor_skip(&anchor, LEADER_ROUND).unwrap();
        assert!(matches!(
            skip,
            AnchorSkip::Certificate(check)
                if check.votes == 2
                    && check.non_votes == 2
                    && check.possible_votes == 2
                    && check.quorum == 3
        ));

        // The primitive still reports the certificate, but the pacemaker must not
        // turn the anchor's commit into a skip. A node that has not received the
        // certificate yet commits the same round; overriding here is what made
        // one devnet node's commit root diverge from the other three. Only the
        // anchor rule and the fence rules advance the cursor.
        let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let mut pacemaker = Pacemaker::new(PacemakerConfig::default(), LEADER_ROUND);
        let step = pacemaker.tick_one(&mut fixture.dag).unwrap();
        assert_eq!(pacemaker.cursor(), LEADER_ROUND + 1);
        assert_eq!(pacemaker.skip_counts().attested, 0);
        assert!(matches!(
            step,
            Step::Advanced { commits, skips: 0, .. } if commits > 0
        ));
        assert!(fixture.dag.order().contains(&leader));
        assert!(fixture.dag.skipped().is_empty());
    }

    #[test]
    fn a_certificate_outside_the_selected_anchors_history_is_ignored() {
        let (mut fixture, proof) = split_round_two();
        let digest = ControlPayload::RoundSkip(Box::new(proof.clone()))
            .digest()
            .unwrap();
        let round_two = fixture.ids(LEADER_ROUND + 1);
        // Author 0 carries the certificate, but the round-three leader is author
        // 3. Same-round vertices do not reference each other, so the payload is
        // not in the selected anchor's causal past.
        insert_certificate_round(&mut fixture, 0, digest, round_two);
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        fixture
            .dag
            .add_control(ControlPayload::RoundSkip(Box::new(proof)))
            .unwrap();

        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        assert_eq!(
            fixture.dag.anchor_skip(&anchor, LEADER_ROUND).unwrap(),
            AnchorSkip::None
        );
        assert!(matches!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Commit(_)
        ));
    }

    #[test]
    fn a_certificate_whose_evidence_is_outside_the_anchor_history_is_ignored() {
        let (mut fixture, proof) = split_round_two();
        let digest = ControlPayload::RoundSkip(Box::new(proof.clone()))
            .digest()
            .unwrap();
        let round_two = fixture.ids(LEADER_ROUND + 1);
        // The anchor references authors 1, 2 and 3, omitting author 0's vote. The
        // proof names that vote, but it is not in the anchor's causal past, so the
        // certificate is not causal evidence for this anchor.
        insert_certificate_round(&mut fixture, 3, digest, round_two[1..].to_vec());
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        fixture
            .dag
            .add_control(ControlPayload::RoundSkip(Box::new(proof)))
            .unwrap();

        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        assert_eq!(
            fixture.dag.anchor_skip(&anchor, LEADER_ROUND).unwrap(),
            AnchorSkip::None
        );
        assert!(matches!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Commit(_)
        ));
    }

    #[test]
    fn a_missing_ancestor_stops_the_certificate_check() {
        let (mut fixture, proof) = split_round_two();
        let digest = ControlPayload::RoundSkip(Box::new(proof.clone()))
            .digest()
            .unwrap();
        let mut references = fixture.ids(LEADER_ROUND + 1);
        references.push(VertexId {
            round: LEADER_ROUND + 1,
            author: b"val-9".to_vec(),
            digest: [9u8; 32],
        });
        insert_certificate_round(&mut fixture, 3, digest, references);
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        fixture
            .dag
            .add_control(ControlPayload::RoundSkip(Box::new(proof)))
            .unwrap();

        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let error = fixture
            .dag
            .anchor_skip(&anchor, LEADER_ROUND)
            .expect_err("a partial anchor history cannot decide the certificate");
        assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
    }

    #[test]
    fn a_control_payload_applies_only_after_its_binding_vertex_is_held() {
        let (mut fixture, leader) = stalled_round_skip();
        let payload = ControlPayload::RoundSkip(Box::new(stall_proof(&fixture, &leader)));
        let digest = payload.digest().unwrap();
        fixture.dag.add_control(payload).unwrap();

        // The payload arrived first. Holding it is not a decision; the binding
        // vertex is what lets the causal anchor walk find it later.
        assert!(fixture.dag.has_pending_control(73));
        assert!(fixture.dag.round_skip(73).is_none());
        let mut pacemaker = Pacemaker::new(PacemakerConfig::default(), 73);
        let step = pacemaker.tick(&mut fixture.dag).unwrap();
        assert_eq!(pacemaker.cursor(), 73);
        assert!(matches!(step, Step::Waiting { .. } | Step::TimedOut { .. }));

        // The author names the payload digest in a later vertex. Holding that
        // vertex is what makes the payload reachable from an anchor's history.
        let references = fixture.ids(74);
        let binding = vertex_with_payload(&fixture, 0, 75, references, digest);
        fixture.dag.insert(binding).unwrap();
        let applied = fixture.dag.apply_controls(b"karsa-dag-1");
        assert_eq!(applied.len(), 1);
        assert_eq!(applied[0].0, 73);
        assert!(applied[0].1.is_ok());
        assert!(!fixture.dag.has_pending_control(73));
        assert!(fixture.dag.round_skip(73).is_some());

        // Stage B stores the proof but still does not move the pacemaker on it.
        let step = pacemaker.tick(&mut fixture.dag).unwrap();
        assert_eq!(pacemaker.cursor(), 73);
        assert_eq!(pacemaker.skip_counts().attested, 0);
        assert!(matches!(step, Step::Waiting { .. } | Step::TimedOut { .. }));
    }

    #[test]
    fn a_control_payload_without_a_binding_vertex_stays_pending() {
        let (mut fixture, leader) = stalled_round_skip();
        let payload = ControlPayload::RoundSkip(Box::new(stall_proof(&fixture, &leader)));
        let digest = payload.digest().unwrap();
        fixture.dag.add_control(payload).unwrap();

        assert!(fixture.dag.apply_controls(b"karsa-dag-1").is_empty());
        assert_eq!(fixture.dag.pending_controls(), vec![digest]);
        assert!(fixture.dag.round_skip(73).is_none());
    }

    #[test]
    fn a_second_proof_for_a_decided_round_is_not_pending() {
        let (mut fixture, leader) = stalled_round_skip();
        let first = ControlPayload::RoundSkip(Box::new(stall_proof(&fixture, &leader)));
        fixture.dag.add_control(first).unwrap();

        // A second, equally valid proof for the same leader. Its evidence is the
        // same votes in another order, so the encoding and digest differ and it
        // does not share the first payload's binding vertex.
        let mut other = stall_proof(&fixture, &leader);
        other.votes.reverse();
        let second = ControlPayload::RoundSkip(Box::new(other));
        let second_digest = second.digest().unwrap();
        fixture.dag.add_control(second).unwrap();

        let references = fixture.ids(74);
        let binding = vertex_with_payload(&fixture, 0, 75, references, second_digest);
        fixture.dag.insert(binding).unwrap();
        let applied = fixture.dag.apply_controls(b"karsa-dag-1");
        assert_eq!(applied.len(), 1);
        assert!(applied[0].1.is_ok());

        // The first proof was never bound, but its round is decided. It must not
        // keep the pacemaker waiting on a decision the DAG already has.
        assert!(!fixture.dag.has_pending_control(73));
        assert!(fixture.dag.apply_controls(b"karsa-dag-1").is_empty());
        assert!(fixture.dag.pending_controls().is_empty());
    }

    #[test]
    fn a_round_skip_proof_for_another_leader_is_refused() {
        let (mut fixture, leader) = stalled_round_skip();
        let mut proof = stall_proof(&fixture, &leader);
        proof.attestation.skip.leader.digest = [9u8; 32];
        assert!(matches!(
            fixture.dag.apply_round_skip(b"karsa-dag-1", proof),
            Err(RoundSkipError::Mismatch(_))
        ));
        assert!(fixture.dag.round_skip(73).is_none());
    }

    #[test]
    fn a_fenced_author_cannot_insert_a_new_vertex() {
        let mut fixture = fixture(4);
        let certificate = fence_certificate(&fixture, 1, b"val-0");
        fixture
            .dag
            .apply_fence(b"karsa-dag-1", &certificate)
            .unwrap();
        let error = fixture
            .dag
            .insert(vertex(&fixture, 0, 1, Vec::new()))
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);
    }

    #[test]
    fn an_authorized_certificate_switches_the_set_at_the_epoch_boundary() {
        let fixture = fixture(4);
        let old = fixture.dag.set().clone();
        let (public_key, _) = Ed25519Scheme::generate_keypair().unwrap();
        let mut new = old.clone();
        new.epoch = 2;
        new.validators.push(ValidatorRecord {
            validator_id: b"val-4".to_vec(),
            keys: vec![ValidatorKey {
                key_id: b"val-4-k0".to_vec(),
                algorithm_id: ALG_ED25519,
                public_key: public_key.to_vec(),
                activation_epoch: 0,
                retirement_epoch: NO_EXPIRY,
            }],
        });
        let change = SetChange::new(b"karsa-dag-1".to_vec(), &old, &new).unwrap();
        let payload = change.signing_payload().unwrap();
        let mut signer_bitmap = vec![0u8; bitmap_len(old.validators.len())];
        let mut signatures = Vec::new();
        for index in 0..old.quorum_size() {
            set_bit(&mut signer_bitmap, index);
            signatures.push(Ed25519Scheme.sign(&fixture.keys[index], &payload).unwrap());
        }
        let certificate = TransitionCertificate {
            change,
            new_set: new.clone(),
            signer_bitmap,
            signatures,
        };

        let mut dag = fixture.dag;
        let transition = dag.adopt_set_change(&certificate).unwrap();
        assert_eq!(transition.old_epoch, 1);
        assert_eq!(transition.new_epoch, 2);
        assert_eq!(dag.set_for_epoch(1).validators.len(), 4);
        assert_eq!(dag.set_for_epoch(2), &new);
        assert!(dag.adopt_set_change(&certificate).is_ok());
    }

    #[test]
    fn round_zero_needs_no_references_and_later_rounds_do() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);

        // Two of the three required round-0 authors is not enough.
        let short = vertex(&fixture, 0, 1, genesis[..2].to_vec());
        let error = fixture.dag.insert(short).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);

        // The same author repeated three times is one author.
        let repeated = vec![genesis[0].clone(); 3];
        let error = fixture
            .dag
            .insert(vertex(&fixture, 0, 1, repeated))
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);

        // A full quorum of distinct authors is accepted.
        fixture.full_round(1, &genesis).unwrap();
    }

    #[test]
    fn references_to_other_rounds_do_not_count() {
        let mut fixture = bootstrapped(4);
        let genesis = fixture.ids(0);
        let error = fixture
            .dag
            .insert(vertex(&fixture, 0, 2, genesis))
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidVertex);
    }

    #[test]
    fn a_supermajority_of_votes_commits_the_leader_and_its_history() {
        let mut fixture = bootstrapped(4);
        let leader_id = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();

        let Decision::Commit(history) = fixture.dag.try_commit(LEADER_ROUND).unwrap() else {
            panic!("expected a commit");
        };
        assert!(history.contains(&leader_id));
        assert_eq!(history.len(), 5, "four genesis vertices plus the leader");
        assert_eq!(fixture.dag.order().len(), 5);
    }

    #[test]
    fn one_silent_validator_still_commits() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        for author in 0..3 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, votes.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Commit(_)
        ));
    }

    #[test]
    fn missing_votes_are_undecided_not_a_skip() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        for author in 0..2 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, votes.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn observed_non_votes_skip_the_leader() {
        let mut fixture = bootstrapped(4);
        // A quorum of the next round, none of it referencing the leader.
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);
        for author in 0..3 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, without_leader.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Skip
        );
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn a_missing_leader_is_undecided() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        let leader = fixture.leader_index(LEADER_ROUND);
        for author in 0..4 {
            if author == leader {
                continue;
            }
            let vertex = vertex(&fixture, author, LEADER_ROUND, genesis.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        let present = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &present).unwrap();

        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn a_second_vertex_from_the_same_author_is_ignored() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        for _ in 0..2 {
            let vertex = vertex(&fixture, 0, LEADER_ROUND + 1, votes.clone());
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(fixture.dag.round_vertices(LEADER_ROUND + 1).len(), 1);
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );
    }

    mod slot_agreement_phase_tests {
        include!("slot_agreement_phase_tests.rs");
    }

    mod slot_agreement_certificate_tests {
        include!("slot_agreement_certificate_tests.rs");
    }

    fn bind_slot_certificate(
        fixture: &mut Fixture,
        payload: &crate::SlotCertificatePayload,
        references: Vec<VertexId>,
    ) -> VertexId {
        let carrier = vertex_with_payload(
            fixture,
            1,
            LEADER_ROUND + 3,
            references,
            payload.digest().unwrap(),
        );
        fixture
            .dag
            .vertices
            .remove(&(carrier.round, carrier.author.clone()));
        fixture.dag.insert(carrier).unwrap()
    }

    fn slot_certificate_fixture(
        committing: bool,
    ) -> (
        Fixture,
        crate::SlotCertificatePayload,
        VertexId,
        crate::SlotDecisionBinding,
    ) {
        let (mut fixture, proposal, proposal_carrier, tip) = direct_slot_proposal(committing);
        let signing_payload = proposal.decision.signing_payload().unwrap();
        // Test-only QC construction: this does not exercise durable signing intents.
        let signatures = (0..fixture.dag.set().quorum_size())
            .map(|index| crate::ValidatorSignature {
                validator_id: format!("val-{index}").into_bytes(),
                key_id: format!("val-{index}-k0").into_bytes(),
                signature: Ed25519Scheme
                    .sign(&fixture.keys[index], &signing_payload)
                    .unwrap(),
            })
            .collect();
        let payload = crate::SlotCertificatePayload {
            certificate: crate::SlotDecisionCertificate {
                decision: proposal.decision.clone(),
                signatures,
            },
            proposal,
            proposal_carrier,
        };
        let references = fixture.ids(LEADER_ROUND + 1);
        fixture.full_round(LEADER_ROUND + 2, &references).unwrap();
        let previous = fixture.ids(0)[0].clone();
        let binding = crate::SlotDecisionBinding::from_checkpoint(tip, Some(previous)).unwrap();
        let references = fixture.ids(LEADER_ROUND + 2);
        let carrier = bind_slot_certificate(&mut fixture, &payload, references);
        (fixture, payload, carrier, binding)
    }

    #[test]
    fn certified_dag_prepare_drop_apply_and_exact_retry() {
        for committing in [false, true] {
            let (fixture, payload, carrier, binding) = slot_certificate_fixture(committing);
            let expected = fixture
                .dag
                .inspect_slot_certificate(&payload, &carrier, &binding)
                .unwrap();
            let before_order = fixture.dag.order().to_vec();
            let before_root = fixture.dag.commit_root();
            let before_skipped = fixture.dag.skipped().to_vec();
            let mut certified =
                CertifiedDag::from_checkpoint(fixture.dag, binding.clone()).unwrap();
            drop(certified.prepare(&payload, &carrier).unwrap());
            assert_eq!(certified.dag().order(), before_order);
            assert_eq!(certified.dag().commit_root(), before_root);
            assert_eq!(certified.dag().skipped(), before_skipped);
            assert_eq!(certified.binding(), &binding);
            assert!(certified.last_event.is_none());

            assert_eq!(
                certified.prepare(&payload, &carrier).unwrap().apply(),
                SlotApplicationResult::Applied {
                    round: LEADER_ROUND,
                    decision: expected.clone()
                }
            );
            let d = &payload.proposal.decision;
            assert_eq!(certified.dag().order_len() as u64, d.after_len);
            assert_eq!(certified.dag().commit_root(), d.after_root);
            assert_eq!(certified.binding().tip().previous_id(), &d.id().unwrap());
            assert_eq!(certified.binding().tip().next_round(), d.round + 1);
            assert_eq!(certified.binding().tip().order_len(), d.after_len);
            assert_eq!(certified.binding().tip().order_root(), &d.after_root);
            assert_eq!(certified.binding().carrier(), Some(&carrier));
            match expected {
                Decision::Commit(history) => {
                    assert_eq!(
                        certified.dag().order(),
                        [before_order, history.clone()].concat()
                    );
                    assert!(
                        history
                            .iter()
                            .all(|id| certified.dag.committed.contains(&id.digest))
                    );
                    assert_eq!(certified.dag().skipped(), before_skipped);
                }
                Decision::Skip => {
                    assert_eq!(certified.dag().order(), before_order);
                    let leader = certified.dag().leader(d.round).unwrap().id().unwrap();
                    assert_eq!(
                        certified.dag().skipped().last(),
                        Some(&SkippedRound {
                            round: d.round,
                            author: leader.author,
                            digest: Some(leader.digest),
                        })
                    );
                }
                Decision::Undecided => panic!("certificate inspection must decide"),
            }
            let order = certified.dag().order().to_vec();
            let skipped = certified.dag().skipped().to_vec();
            let applied_binding = certified.binding().clone();
            for _ in 0..2 {
                assert_eq!(
                    certified.prepare(&payload, &carrier).unwrap().apply(),
                    SlotApplicationResult::AlreadyApplied { round: d.round }
                );
            }
            let mut wrong_carrier = carrier.clone();
            wrong_carrier.digest[0] ^= 1;
            assert!(certified.prepare(&payload, &wrong_carrier).is_err());
            let mut conflict = payload.clone();
            conflict.certificate.signatures.reverse();
            assert!(certified.prepare(&conflict, &carrier).is_err());
            assert_eq!(certified.dag().order(), order);
            assert_eq!(certified.dag().skipped(), skipped);
            assert_eq!(certified.binding(), &applied_binding);

            // A checkpoint does not reconstruct an exact-event retry cache.
            let mut restored =
                CertifiedDag::from_checkpoint(certified.dag, certified.binding).unwrap();
            assert!(restored.prepare(&payload, &carrier).is_err());
        }
    }

    #[test]
    fn certified_dag_invalid_preparation_and_checkpoint_are_atomic() {
        let (fixture, payload, carrier, binding) = slot_certificate_fixture(true);
        let mut certified = CertifiedDag::from_checkpoint(fixture.dag, binding.clone()).unwrap();
        let order = certified.dag().order().to_vec();
        let root = certified.dag().commit_root();
        let mut invalid = payload.clone();
        invalid.certificate.signatures.clear();
        assert!(certified.prepare(&invalid, &carrier).is_err());
        let mut invalid = payload.clone();
        invalid.proposal.decision.after_len += 1;
        assert!(certified.prepare(&invalid, &carrier).is_err());
        assert_eq!(certified.dag().order(), order);
        assert_eq!(certified.dag().commit_root(), root);
        assert!(certified.dag().skipped().is_empty());
        assert_eq!(certified.binding(), &binding);
        assert!(certified.last_event.is_none());
        certified.dag.set_chain_id(b"wrong-chain".to_vec());
        assert!(CertifiedDag::from_checkpoint(certified.dag, binding).is_err());

        let (mut fixture, _, _, binding) = slot_certificate_fixture(true);
        fixture.dag.seed_order(vec![carrier]);
        assert!(CertifiedDag::from_checkpoint(fixture.dag, binding).is_err());
    }

    #[test]
    fn slot_certificate_requires_bound_proposal_evidence_and_valid_qc_without_mutation() {
        for committing in [false, true] {
            let (fixture, payload, carrier, binding) = slot_certificate_fixture(committing);
            let before_binding = binding.clone();
            let inspected = inspect_without_effects(&fixture.dag, |dag| {
                dag.inspect_slot_certificate(&payload, &carrier, &binding)
            });
            assert_eq!(
                inspected,
                fixture
                    .dag
                    .inspect_slot_proposal(
                        &payload.proposal,
                        &payload.proposal_carrier,
                        binding.tip()
                    )
                    .unwrap()
            );
            assert_eq!(binding, before_binding);
        }
    }

    #[test]
    fn slot_certificate_rejects_invalid_quorums_even_with_a_bound_carrier() {
        let (mut fixture, original, _, binding) = slot_certificate_fixture(true);
        for mutation in 0..3 {
            let mut payload = original.clone();
            match mutation {
                0 => {
                    payload.certificate.signatures.pop();
                }
                1 => payload.certificate.signatures[0].signature[0] ^= 1,
                2 => payload.certificate.signatures[1] = payload.certificate.signatures[0].clone(),
                _ => unreachable!("bounded mutations"),
            }
            let references = fixture.ids(LEADER_ROUND + 2);
            let carrier = bind_slot_certificate(&mut fixture, &payload, references);
            assert!(
                fixture
                    .dag
                    .inspect_slot_certificate(&payload, &carrier, &binding)
                    .is_err(),
                "invalid quorum mutation {mutation}"
            );
            assert!(fixture.dag.order().is_empty());
            assert!(fixture.dag.committed.is_empty());
            assert!(fixture.dag.skipped().is_empty());
        }
    }

    #[test]
    fn slot_certificate_qc_transport_cannot_bypass_proposal_binding_or_evidence() {
        let (mut fixture, mut payload, carrier, binding) = slot_certificate_fixture(true);
        let mut forged = carrier.clone();
        forged.digest[0] ^= 1;
        assert!(
            fixture
                .dag
                .inspect_slot_certificate(&payload, &forged, &binding)
                .is_err()
        );
        // A valid decision QC is insufficient if its supplied proposal is not the
        // one bound by the proposal carrier, even when that evidence is also valid.
        payload.proposal.voters[2] = fixture.ids(LEADER_ROUND + 1)[3].clone();
        let references = fixture.ids(LEADER_ROUND + 2);
        let carrier = bind_slot_certificate(&mut fixture, &payload, references);
        assert!(
            fixture
                .dag
                .inspect_slot_certificate(&payload, &carrier, &binding)
                .is_err()
        );
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn slot_certificate_checks_side_branches_exclusive_to_the_qc_carrier() {
        for missing_vertex in [false, true] {
            let (mut fixture, payload, carrier, binding) = slot_certificate_fixture(true);
            let key = (LEADER_ROUND + 2, b"val-3".to_vec());
            if missing_vertex {
                fixture.dag.vertices.remove(&key);
            } else {
                fixture.dag.vertices.get_mut(&key).unwrap().signature[0] ^= 1;
            }
            // This vertex is not in the proposal's cone, so proposal validation
            // still succeeds. QC validation must inspect its own complete cone.
            assert!(
                fixture
                    .dag
                    .inspect_slot_proposal(
                        &payload.proposal,
                        &payload.proposal_carrier,
                        binding.tip(),
                    )
                    .is_ok()
            );
            assert!(
                fixture
                    .dag
                    .inspect_slot_certificate(&payload, &carrier, &binding)
                    .is_err()
            );
            assert!(fixture.dag.order().is_empty());
            assert!(fixture.dag.skipped().is_empty());
        }
    }

    #[test]
    fn slot_certificate_requires_proposal_carrier_in_qc_history() {
        let (mut fixture, payload, _, binding) = slot_certificate_fixture(true);
        let references = fixture.ids(LEADER_ROUND + 2)[1..].to_vec();
        let carrier = bind_slot_certificate(&mut fixture, &payload, references);
        // The carrier has a valid previous-round quorum, just not this proposal.
        assert!(
            fixture
                .dag
                .inspect_slot_certificate(&payload, &carrier, &binding)
                .is_err()
        );
    }

    #[test]
    fn slot_certificate_predecessor_must_be_in_proposal_not_only_qc_history() {
        let (mut fixture, mut payload, _, binding) = slot_certificate_fixture(true);
        let previous = fixture.ids(LEADER_ROUND + 1)[3].clone();
        let references = fixture.ids(LEADER_ROUND + 1)[..3].to_vec();
        let proposal_carrier = vertex_with_payload(
            &fixture,
            0,
            LEADER_ROUND + 2,
            references,
            payload.proposal.digest().unwrap(),
        );
        fixture
            .dag
            .vertices
            .remove(&(proposal_carrier.round, proposal_carrier.author.clone()));
        payload.proposal_carrier = fixture.dag.insert(proposal_carrier).unwrap();
        let references = fixture.ids(LEADER_ROUND + 2);
        let carrier = bind_slot_certificate(&mut fixture, &payload, references);
        assert!(fixture.dag.is_ancestor(&previous, &carrier).unwrap());
        assert!(
            !fixture
                .dag
                .is_ancestor(&previous, &payload.proposal_carrier)
                .unwrap()
        );
        let binding =
            crate::SlotDecisionBinding::from_checkpoint(binding.tip().clone(), Some(previous))
                .unwrap();
        assert!(
            fixture
                .dag
                .inspect_slot_certificate(&payload, &carrier, &binding)
                .is_err()
        );
    }

    #[test]
    fn slot_certificate_can_reference_a_trusted_pruned_predecessor_exactly() {
        let (mut fixture, payload, carrier, binding) = slot_certificate_fixture(false);
        fixture.dag.set_floor(0);
        assert_eq!(
            fixture
                .dag
                .inspect_slot_certificate(&payload, &carrier, &binding)
                .unwrap(),
            Decision::Skip
        );
        let mut wrong = binding.carrier().unwrap().clone();
        wrong.digest[0] ^= 1;
        let binding =
            crate::SlotDecisionBinding::from_checkpoint(binding.tip().clone(), Some(wrong))
                .unwrap();
        assert!(
            fixture
                .dag
                .inspect_slot_certificate(&payload, &carrier, &binding)
                .is_err()
        );
    }

    fn bind_slot_proposal(fixture: &mut Fixture, proposal: &crate::SlotProposal) -> VertexId {
        let carrier = vertex_with_payload(
            fixture,
            0,
            LEADER_ROUND + 2,
            fixture.ids(LEADER_ROUND + 1),
            proposal.digest().unwrap(),
        );
        fixture
            .dag
            .vertices
            .remove(&(carrier.round, carrier.author.clone()));
        fixture.dag.insert(carrier).unwrap()
    }

    fn direct_slot_proposal(
        committing: bool,
    ) -> (
        Fixture,
        crate::SlotProposal,
        VertexId,
        crate::SlotDecisionTip,
    ) {
        let mut fixture = bootstrapped(4);
        let references = if committing {
            fixture.ids(LEADER_ROUND)
        } else {
            fixture.ids_without_leader(LEADER_ROUND)
        };
        fixture.full_round(LEADER_ROUND + 1, &references).unwrap();
        let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let history = if committing {
            fixture.dag.collect_uncommitted_history(&leader).unwrap()
        } else {
            Vec::new()
        };
        let root = fixture.dag.commit_root();
        let tip = crate::SlotDecisionTip::from_checkpoint(
            fixture.dag.chain_id().to_vec(),
            fixture.dag.set(),
            LEADER_ROUND,
            [7; 32],
            0,
            root,
        )
        .unwrap();
        let proposal = crate::SlotProposal {
            decision: crate::SlotDecision {
                chain_id: fixture.dag.chain_id().to_vec(),
                validator_set_id: fixture.dag.set().id().unwrap(),
                epoch: EPOCH,
                round: LEADER_ROUND,
                previous: [7; 32],
                before_len: 0,
                before_root: root,
                after_len: history.len() as u64,
                after_root: commit_root(&history),
                outcome: if committing {
                    crate::SlotOutcome::Commit { leader }
                } else {
                    crate::SlotOutcome::Skip {
                        leader_author: leader.author,
                    }
                },
            },
            voters: fixture.ids(LEADER_ROUND + 1)[..3].to_vec(),
        };
        let carrier = bind_slot_proposal(&mut fixture, &proposal);
        (fixture, proposal, carrier, tip)
    }

    #[test]
    fn slot_proposal_validates_explicit_direct_evidence_without_mutation() {
        for committing in [false, true] {
            let (fixture, proposal, carrier, tip) = direct_slot_proposal(committing);
            let inspected = inspect_without_effects(&fixture.dag, |dag| {
                dag.inspect_slot_proposal(&proposal, &carrier, &tip)
            });
            assert_eq!(matches!(inspected, Decision::Commit(_)), committing);
            assert_eq!(inspected, fixture.dag.inspect_commit(LEADER_ROUND).unwrap());
        }
    }

    #[test]
    fn slot_proposal_rejects_changed_effect_context_and_evidence() {
        for committing in [false, true] {
            let (mut fixture, original, _, tip) = direct_slot_proposal(committing);
            for mutation in 0..14 {
                let mut proposal = original.clone();
                match mutation {
                    0 => proposal.decision.previous[0] ^= 1,
                    1 => proposal.decision.after_root[0] ^= 1,
                    2 => proposal.decision.before_root[0] ^= 1,
                    3 => {
                        proposal.voters.pop();
                    }
                    4 => proposal.voters[0].digest[0] ^= 1,
                    5 => proposal.voters[0].round = LEADER_ROUND,
                    6 => {
                        proposal.decision.outcome = if committing {
                            crate::SlotOutcome::Skip {
                                leader_author: b"val-1".to_vec(),
                            }
                        } else {
                            crate::SlotOutcome::Commit {
                                leader: fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap(),
                            }
                        }
                    }
                    7 => proposal.decision.chain_id = b"another-chain".to_vec(),
                    8 => proposal.decision.validator_set_id[0] ^= 1,
                    9 => proposal.decision.epoch += 1,
                    10 => proposal.decision.round = 0,
                    11 => proposal.decision.round = u64::MAX,
                    12 => proposal.decision.after_len += 1,
                    13 => {
                        proposal.decision.outcome = crate::SlotOutcome::Skip {
                            leader_author: b"val-2".to_vec(),
                        }
                    }
                    _ => unreachable!("bounded mutations"),
                }
                let carrier = bind_slot_proposal(&mut fixture, &proposal);
                assert!(
                    fixture
                        .dag
                        .inspect_slot_proposal(&proposal, &carrier, &tip)
                        .is_err(),
                    "mutation {mutation}, committing {committing}"
                );
                assert!(fixture.dag.order().is_empty());
                assert!(fixture.dag.committed.is_empty());
                assert!(fixture.dag.skipped().is_empty());
            }
        }
    }

    #[test]
    fn slot_proposal_requires_exact_held_carrier_and_complete_causal_history() {
        let (mut fixture, proposal, carrier, tip) = direct_slot_proposal(true);
        let mut forged = carrier.clone();
        forged.digest[0] ^= 1;
        assert!(
            fixture
                .dag
                .inspect_slot_proposal(&proposal, &forged, &tip)
                .is_err()
        );
        let mut unbound = proposal.clone();
        unbound.voters[2] = fixture.ids(LEADER_ROUND + 1)[3].clone();
        assert!(
            fixture
                .dag
                .inspect_slot_proposal(&unbound, &carrier, &tip)
                .is_err()
        );
        let victim = fixture.ids(0)[0].clone();
        fixture.dag.vertices.remove(&(victim.round, victim.author));
        assert_eq!(
            fixture
                .dag
                .inspect_slot_proposal(&proposal, &carrier, &tip)
                .unwrap_err()
                .kind(),
            CryptoErrorKind::MissingReference
        );
        assert!(fixture.dag.order().is_empty());
    }

    #[test]
    fn slot_proposal_does_not_accept_held_but_noncausal_voters() {
        let (mut fixture, mut proposal, _, tip) = direct_slot_proposal(true);
        proposal.voters = fixture.ids(LEADER_ROUND + 1)[1..].to_vec();
        let references = fixture.ids(LEADER_ROUND + 1)[..3].to_vec();
        let carrier = vertex_with_payload(
            &fixture,
            0,
            LEADER_ROUND + 2,
            references,
            proposal.digest().unwrap(),
        );
        fixture
            .dag
            .vertices
            .remove(&(carrier.round, carrier.author.clone()));
        let carrier = fixture.dag.insert(carrier).unwrap();
        assert!(
            fixture
                .dag
                .inspect_slot_proposal(&proposal, &carrier, &tip)
                .is_err()
        );
    }

    #[test]
    fn slot_proposal_checks_the_full_cone_not_just_its_selected_voters() {
        for bad_signature in [false, true] {
            let (mut fixture, proposal, _, tip) = direct_slot_proposal(true);
            if bad_signature {
                fixture
                    .dag
                    .vertices
                    .get_mut(&(0, b"val-3".to_vec()))
                    .unwrap()
                    .signature[0] ^= 1;
            }
            let mut references = fixture.ids(LEADER_ROUND + 1);
            if !bad_signature {
                let mut unrelated = fixture.ids(0)[3].clone();
                unrelated.digest[0] ^= 1;
                references.push(unrelated);
            }
            let carrier = vertex_with_payload(
                &fixture,
                0,
                LEADER_ROUND + 2,
                references,
                proposal.digest().unwrap(),
            );
            fixture
                .dag
                .vertices
                .remove(&(carrier.round, carrier.author.clone()));
            let carrier = fixture.dag.insert(carrier).unwrap();
            assert!(
                fixture
                    .dag
                    .inspect_slot_proposal(&proposal, &carrier, &tip)
                    .is_err()
            );
            assert!(fixture.dag.committed.is_empty());
        }
    }

    #[test]
    fn slot_proposal_extends_a_trusted_pruned_prefix() {
        for committing in [false, true] {
            let (mut fixture, mut proposal, _, _) = direct_slot_proposal(committing);
            let prefix = CommitFrontier::from_order(&fixture.ids(0));
            fixture.dag.seed_prefix(prefix.clone(), Vec::new());
            fixture.dag.set_floor(0);
            let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
            let history = if committing {
                fixture.dag.collect_uncommitted_history(&leader).unwrap()
            } else {
                Vec::new()
            };
            let mut after = prefix.clone();
            after.extend(&history);
            proposal.decision.before_len = prefix.len() as u64;
            proposal.decision.before_root = prefix.root();
            proposal.decision.after_len = after.len() as u64;
            proposal.decision.after_root = after.root();
            let tip = crate::SlotDecisionTip::from_checkpoint(
                fixture.dag.chain_id().to_vec(),
                fixture.dag.set(),
                LEADER_ROUND,
                proposal.decision.previous,
                prefix.len() as u64,
                prefix.root(),
            )
            .unwrap();
            let carrier = bind_slot_proposal(&mut fixture, &proposal);
            inspect_without_effects(&fixture.dag, |dag| {
                dag.inspect_slot_proposal(&proposal, &carrier, &tip)
            });
            fixture.dag.set_floor(LEADER_ROUND);
            assert!(
                fixture
                    .dag
                    .inspect_slot_proposal(&proposal, &carrier, &tip)
                    .is_err()
            );
        }
    }

    #[test]
    fn slot_proposal_rejects_same_round_and_forward_weak_references() {
        for referenced_round in [LEADER_ROUND + 2, LEADER_ROUND + 3] {
            let (mut fixture, proposal, _, tip) = direct_slot_proposal(true);
            let references = fixture.ids(LEADER_ROUND + 1);
            // These authors do not depend on the proposal carrier (author zero).
            for author in 1..4 {
                let vertex = vertex(&fixture, author, LEADER_ROUND + 2, references.clone());
                fixture.dag.insert(vertex).unwrap();
            }
            if referenced_round == LEADER_ROUND + 3 {
                let references = fixture.ids(LEADER_ROUND + 2)[1..].to_vec();
                let vertex = vertex(&fixture, 1, referenced_round, references);
                fixture.dag.insert(vertex).unwrap();
            }
            let weak = fixture
                .dag
                .get(referenced_round, b"val-1")
                .unwrap()
                .id()
                .unwrap();
            let mut references = fixture.ids(LEADER_ROUND + 1);
            references.push(weak);
            let carrier = vertex_with_payload(
                &fixture,
                0,
                LEADER_ROUND + 2,
                references,
                proposal.digest().unwrap(),
            );
            fixture
                .dag
                .vertices
                .remove(&(carrier.round, carrier.author.clone()));
            let carrier = fixture.dag.insert(carrier).unwrap();
            assert!(
                fixture
                    .dag
                    .inspect_slot_proposal(&proposal, &carrier, &tip)
                    .is_err(),
                "noncausal edge to round {referenced_round} must fail"
            );
        }
    }

    #[test]
    fn slot_proposal_evidence_does_not_change_when_a_fence_arrives() {
        for committing in [false, true] {
            let (mut fixture, proposal, carrier, tip) = direct_slot_proposal(committing);
            let before = fixture
                .dag
                .inspect_slot_proposal(&proposal, &carrier, &tip)
                .unwrap();
            let fence = fence_certificate(&fixture, LEADER_ROUND + 1, b"val-0");
            fixture.dag.apply_fence(b"karsa-dag-1", &fence).unwrap();
            assert_eq!(
                fixture
                    .dag
                    .inspect_slot_proposal(&proposal, &carrier, &tip)
                    .unwrap(),
                before
            );
        }
    }

    fn inspect_without_effects(
        dag: &Dag,
        inspect: impl Fn(&Dag) -> Result<Decision, CryptoError>,
    ) -> Decision {
        let order = dag.order().to_vec();
        let committed = dag.committed.clone();
        let skipped = dag.skipped().to_vec();
        let len = dag.order_len();
        let root = dag.commit_root();
        let decision = inspect(dag).unwrap();
        assert_eq!(inspect(dag).unwrap(), decision);
        assert_eq!(dag.order(), order);
        assert_eq!(dag.committed, committed);
        assert_eq!(dag.skipped(), skipped);
        assert_eq!(dag.order_len(), len);
        assert_eq!(dag.commit_root(), root);
        decision
    }

    #[test]
    fn inspection_preserves_direct_commit_skip_and_undecided_state() {
        for positive_votes in [0, 2, 4] {
            let mut fixture = bootstrapped(4);
            let votes = fixture.ids(LEADER_ROUND);
            let non_votes = fixture.ids_without_leader(LEADER_ROUND);
            for author in 0..4 {
                let references = if author < positive_votes {
                    votes.clone()
                } else {
                    non_votes.clone()
                };
                let vertex = vertex(&fixture, author, LEADER_ROUND + 1, references);
                fixture.dag.insert(vertex).unwrap();
            }
            let inspected =
                inspect_without_effects(&fixture.dag, |dag| dag.inspect_commit(LEADER_ROUND));
            match positive_votes {
                0 => assert_eq!(inspected, Decision::Skip),
                2 => assert_eq!(inspected, Decision::Undecided),
                4 => assert!(matches!(inspected, Decision::Commit(_))),
                _ => unreachable!("fixture uses only three vote counts"),
            }
            assert_eq!(fixture.dag.try_commit(LEADER_ROUND).unwrap(), inspected);
            if inspected == Decision::Skip {
                let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
                assert_eq!(fixture.dag.skipped().len(), 1);
                assert_eq!(fixture.dag.skipped()[0].round, LEADER_ROUND);
                assert_eq!(fixture.dag.skipped()[0].author, leader.author);
                assert_eq!(fixture.dag.skipped()[0].digest, Some(leader.digest));
            }
            if let Decision::Commit(history) = inspected {
                assert_eq!(fixture.dag.order(), history);
                assert_eq!(fixture.dag.commit_root(), commit_root(&history));
                assert_eq!(
                    inspect_without_effects(&fixture.dag, |dag| dag.inspect_commit(LEADER_ROUND)),
                    Decision::Commit(Vec::new())
                );
            }
        }
    }

    #[test]
    fn inspection_preserves_indirect_commit_skip_and_undecided_state() {
        for includes_leader in [false, true] {
            let mut fixture = bootstrapped(4);
            let references = if includes_leader {
                fixture.ids(LEADER_ROUND)
            } else {
                fixture.ids_without_leader(LEADER_ROUND)
            };
            fixture.full_round(LEADER_ROUND + 1, &references).unwrap();
            let references = fixture.ids(LEADER_ROUND + 1);
            fixture.full_round(LEADER_ROUND + 2, &references).unwrap();
            let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
            let inspected = inspect_without_effects(&fixture.dag, |dag| {
                dag.inspect_indirect_decide(LEADER_ROUND, &anchor)
            });
            if includes_leader {
                assert!(matches!(inspected, Decision::Commit(_)));
            } else {
                assert_eq!(inspected, Decision::Skip);
            }
            assert_eq!(
                fixture
                    .dag
                    .try_indirect_decide(LEADER_ROUND, &anchor)
                    .unwrap(),
                inspected
            );
            match inspected {
                Decision::Commit(history) => {
                    assert_eq!(fixture.dag.order(), history);
                    assert_eq!(fixture.dag.commit_root(), commit_root(&history));
                }
                Decision::Skip => {
                    let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
                    assert_eq!(fixture.dag.skipped().len(), 1);
                    assert_eq!(fixture.dag.skipped()[0].round, LEADER_ROUND);
                    assert_eq!(fixture.dag.skipped()[0].author, leader.author);
                    assert_eq!(fixture.dag.skipped()[0].digest, Some(leader.digest));
                }
                Decision::Undecided => panic!("complete fixture must decide"),
            }
            let too_recent = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
            assert_eq!(
                inspect_without_effects(&fixture.dag, |dag| {
                    dag.inspect_indirect_decide(LEADER_ROUND, &too_recent)
                }),
                Decision::Undecided
            );
        }
    }

    #[test]
    fn history_is_committed_once_and_in_a_stable_order() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();

        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Commit(_)
        ));
        // Asking again changes nothing.
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Commit(Vec::new())
        );
        assert_eq!(fixture.dag.order().len(), 5);
    }

    #[test]
    fn a_missing_ancestor_blocks_the_commit() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        let mut references = genesis.clone();
        // Keep the shape rule satisfied, then add a reference nobody holds.
        references.truncate(fixture.dag.set().quorum_size());
        references.push(VertexId {
            round: 0,
            author: b"val-9".to_vec(),
            digest: [9u8; 32],
        });

        let leader = fixture.leader_index(LEADER_ROUND);
        for author in 0..4 {
            let chosen = if author == leader {
                references.clone()
            } else {
                genesis.clone()
            };
            let vertex = vertex(&fixture, author, LEADER_ROUND, chosen);
            fixture.dag.insert(vertex).unwrap();
        }

        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();

        let root = fixture.dag.commit_root();
        for _ in 0..2 {
            let error = fixture.dag.inspect_commit(LEADER_ROUND).unwrap_err();
            assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
            assert!(fixture.dag.order().is_empty());
            assert!(fixture.dag.committed.is_empty());
            assert!(fixture.dag.skipped().is_empty());
            assert_eq!(fixture.dag.commit_root(), root);
        }
        let error = fixture.dag.try_commit(LEADER_ROUND).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
        assert!(fixture.dag.order().is_empty());

        let references = fixture.ids(LEADER_ROUND + 1);
        fixture.full_round(LEADER_ROUND + 2, &references).unwrap();
        let held_anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let missing_anchor = VertexId {
            round: LEADER_ROUND + 2,
            author: b"val-9".to_vec(),
            digest: [9; 32],
        };
        let leader = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        assert!(fixture.dag.is_ancestor(&leader, &held_anchor).unwrap());
        // A missing anchor fails during traversal; a reachable leader with missing
        // history fails during collection. Neither may partially apply a decision.
        for anchor in [missing_anchor, held_anchor] {
            for _ in 0..2 {
                let error = fixture
                    .dag
                    .inspect_indirect_decide(LEADER_ROUND, &anchor)
                    .unwrap_err();
                assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
                assert!(fixture.dag.order().is_empty());
                assert!(fixture.dag.committed.is_empty());
                assert!(fixture.dag.skipped().is_empty());
                assert_eq!(fixture.dag.commit_root(), root);
            }
            let error = fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap_err();
            assert_eq!(error.kind(), CryptoErrorKind::MissingReference);
            assert!(fixture.dag.order().is_empty());
            assert!(fixture.dag.committed.is_empty());
            assert!(fixture.dag.skipped().is_empty());
            assert_eq!(fixture.dag.commit_root(), root);
        }
    }

    #[test]
    fn indirect_commit_finds_the_leader_inside_the_anchor_history() {
        let mut fixture = bootstrapped(4);
        let leader_id = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        let votes = fixture.ids(LEADER_ROUND);
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);

        // A split round: two vote for the leader, two reference the rest.
        for author in 0..4 {
            let references = if author < 2 {
                votes.clone()
            } else {
                without_leader.clone()
            };
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, references);
            fixture.dag.insert(vertex).unwrap();
        }
        assert_eq!(
            fixture.dag.try_commit(LEADER_ROUND).unwrap(),
            Decision::Undecided
        );

        // Two rounds later the anchor commits with its whole history.
        let round_two = fixture.ids(LEADER_ROUND + 1);
        fixture.full_round(LEADER_ROUND + 2, &round_two).unwrap();
        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND + 2).unwrap(),
            Decision::Commit(_)
        ));

        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Commit(Vec::new())
        );
        assert!(fixture.dag.skipped().is_empty());
        assert!(fixture.dag.order().contains(&leader_id));
    }

    #[test]
    fn indirect_skip_when_the_anchor_history_does_not_contain_the_leader() {
        let mut fixture = bootstrapped(4);
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);

        fixture
            .full_round(LEADER_ROUND + 1, &without_leader)
            .unwrap();
        let round_two = fixture.ids(LEADER_ROUND + 1);
        fixture.full_round(LEADER_ROUND + 2, &round_two).unwrap();
        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let round_three = fixture.ids(LEADER_ROUND + 2);
        fixture.full_round(LEADER_ROUND + 3, &round_three).unwrap();
        assert!(matches!(
            fixture.dag.try_commit(LEADER_ROUND + 2).unwrap(),
            Decision::Commit(_)
        ));

        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Skip
        );
        assert_eq!(fixture.dag.skipped().len(), 1);
        // Deciding twice does not record the skip twice.
        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND, &anchor)
                .unwrap(),
            Decision::Skip
        );
        assert_eq!(fixture.dag.skipped().len(), 1);
    }

    #[test]
    fn indirect_needs_an_anchor_two_rounds_later() {
        let mut fixture = bootstrapped(4);
        let round_two = fixture.ids(LEADER_ROUND + 1);
        let _ = round_two;
        let too_recent = fixture.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
        assert_eq!(
            fixture
                .dag
                .try_indirect_decide(LEADER_ROUND - 1, &too_recent)
                .unwrap(),
            Decision::Undecided
        );
    }

    #[test]
    fn the_same_input_commits_the_same_sequence() {
        let run = || {
            let mut fixture = bootstrapped(4);
            let votes = fixture.ids(LEADER_ROUND);
            fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
            let decision = fixture.dag.try_commit(LEADER_ROUND).unwrap();
            (decision, fixture.dag.order().to_vec())
        };
        assert_eq!(run(), run());
    }

    #[test]
    fn a_commit_proof_proves_membership_in_the_dag_root() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
        fixture.dag.try_commit(LEADER_ROUND).unwrap();

        let order = fixture.dag.order().to_vec();
        assert!(!order.is_empty(), "there is something to prove");
        let root = fixture.dag.commit_root();
        assert_eq!(root, commit_root(&order));

        for index in 0..order.len() {
            let proof = CommitProof::prove(&order, index).expect("index is in range");
            assert!(
                proof.verify(&root),
                "commit {index} did not verify against the root"
            );
        }
        assert!(CommitProof::prove(&order, order.len()).is_none());
    }

    #[test]
    fn a_commit_proof_for_another_vertex_does_not_verify() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
        fixture.dag.try_commit(LEADER_ROUND).unwrap();

        let order = fixture.dag.order().to_vec();
        let root = fixture.dag.commit_root();
        let mut proof = CommitProof::prove(&order, 0).unwrap();
        proof.vertex.digest[0] ^= 0xff;
        assert!(!proof.verify(&root));
    }

    #[test]
    fn the_commit_root_depends_on_commit_order() {
        let first = VertexId {
            round: 1,
            author: b"val-0".to_vec(),
            digest: [1u8; 32],
        };
        let second = VertexId {
            round: 1,
            author: b"val-1".to_vec(),
            digest: [2u8; 32],
        };
        assert_ne!(
            commit_root(&[first.clone(), second.clone()]),
            commit_root(&[second, first])
        );
    }

    #[test]
    fn pruning_drops_below_the_floor_and_stops_the_history() {
        let mut fixture = bootstrapped(4);
        let one = fixture.ids(LEADER_ROUND);
        fixture.full_round(2, &one).unwrap();
        let two = fixture.ids(2);
        fixture.full_round(3, &two).unwrap();
        fixture.dag.try_commit(2).unwrap();

        let dropped = fixture.dag.set_floor(2);
        assert_eq!(dropped, 12, "rounds 0..=2 hold four vertices each");
        assert_eq!(fixture.dag.floor(), Some(2));
        assert!(fixture.dag.get(2, b"val-0").is_none());
        assert!(fixture.dag.get(3, b"val-0").is_some());

        // Round 4 references round 3, which itself referenced the now-pruned round 2.
        let three = fixture.ids(3);
        fixture.full_round(4, &three).unwrap();
        let four = fixture.ids(4);
        fixture.full_round(5, &four).unwrap();

        match fixture.dag.try_commit(4).unwrap() {
            Decision::Commit(history) => {
                assert!(!history.is_empty());
                assert!(
                    history.iter().all(|id| id.round > 2),
                    "a pruned ancestor was emitted again"
                );
            }
            other => panic!("expected a commit, got {other:?}"),
        }
    }

    #[test]
    fn a_vertex_below_the_floor_is_accepted_but_not_retained() {
        let mut fixture = bootstrapped(4);
        let vertex = fixture.dag.get(LEADER_ROUND, b"val-0").unwrap().clone();
        fixture.dag.set_floor(LEADER_ROUND);

        let id = fixture.dag.insert(vertex).expect("still signature-valid");
        assert_eq!(id.round, LEADER_ROUND);
        assert!(fixture.dag.get(LEADER_ROUND, b"val-0").is_none());
    }

    #[test]
    fn the_floor_never_moves_down() {
        let mut fixture = bootstrapped(4);
        fixture.dag.set_floor(1);
        assert_eq!(fixture.dag.set_floor(0), 0);
        assert_eq!(fixture.dag.floor(), Some(1));
    }

    /// The retiring and replacement private key for one validator.
    type RotatingKeys = (Vec<u8>, Vec<u8>);

    /// Builds a set where every validator rotates from an old to a new key at
    /// epoch 2, returning the two private keys per validator.
    fn rotating_set(count: usize) -> (ValidatorSet, Vec<RotatingKeys>) {
        let mut private = Vec::with_capacity(count);
        let mut validators = Vec::with_capacity(count);
        for index in 0..count {
            let old_seed = [u8::try_from(index + 1).unwrap(); 32];
            let new_seed = [u8::try_from(index + 51).unwrap(); 32];
            let old_public = Ed25519Scheme::public_key_from_seed(&old_seed).unwrap();
            let new_public = Ed25519Scheme::public_key_from_seed(&new_seed).unwrap();
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![
                    ValidatorKey {
                        key_id: format!("val-{index}-old").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: old_public.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: 2,
                    },
                    ValidatorKey {
                        key_id: format!("val-{index}-new").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: new_public.to_vec(),
                        activation_epoch: 2,
                        retirement_epoch: NO_EXPIRY,
                    },
                ],
            });

            let mut old_private = Vec::new();
            old_private.extend_from_slice(&old_seed);
            old_private.extend_from_slice(&old_public);
            let mut new_private = Vec::new();
            new_private.extend_from_slice(&new_seed);
            new_private.extend_from_slice(&new_public);
            private.push((old_private, new_private));
        }
        let set = ValidatorSet {
            epoch: 0,
            validators,
        };
        set.validate().unwrap();
        (set, private)
    }

    #[test]
    fn a_key_rotation_at_an_epoch_boundary_does_not_stop_the_chain() {
        let count = 4;
        let (set, private) = rotating_set(count);
        let mut dag = Dag::with_epoch_length(set, 2);

        // Two rounds per epoch, so the rotation lands at round 4.
        assert_eq!(dag.epoch_of(3), 1);
        assert_eq!(dag.epoch_of(4), 2);

        for round in 0..=8u64 {
            let epoch = dag.epoch_of(round);
            let references: Vec<VertexId> = (0..count)
                .filter_map(|author| {
                    dag.get(round.wrapping_sub(1), format!("val-{author}").as_bytes())
                        .and_then(|vertex| vertex.id().ok())
                })
                .collect();
            for (author, pair) in private.iter().enumerate() {
                let key = if epoch < 2 { &pair.0 } else { &pair.1 };
                let mut vertex = Vertex {
                    chain_id: b"karsa-epoch-1".to_vec(),
                    epoch,
                    round,
                    author: format!("val-{author}").into_bytes(),
                    payload_hash: [0u8; 32],
                    references: references.clone(),
                    signature: Vec::new(),
                };
                let payload = vertex.signing_payload().unwrap();
                vertex.signature = Ed25519Scheme.sign(key, &payload).unwrap();
                dag.insert(vertex)
                    .expect("a rotated schedule accepts its own key");
            }
        }

        // The leader of round 3 needs votes from round 4, which belongs to the next
        // epoch and is signed with a different key.
        assert!(matches!(dag.try_commit(3).unwrap(), Decision::Commit(_)));
        assert!(matches!(dag.try_commit(4).unwrap(), Decision::Commit(_)));
    }

    #[test]
    fn a_retired_key_cannot_sign_after_the_rotation() {
        let (set, private) = rotating_set(4);
        let mut stale = Vertex {
            chain_id: b"karsa-epoch-1".to_vec(),
            epoch: 2,
            round: 4,
            author: b"val-0".to_vec(),
            payload_hash: [0u8; 32],
            references: Vec::new(),
            signature: Vec::new(),
        };
        let payload = stale.signing_payload().unwrap();
        stale.signature = Ed25519Scheme.sign(&private[0].0, &payload).unwrap();

        // The schedule resolves epoch 2 to the new key, so the old key's signature
        // simply does not match. Either outcome keeps the retired key out; what
        // matters is that it never verifies.
        assert!(stale.verify(&set, 2).is_err());
        assert!(stale.verify(&set, 2).is_err(), "deterministic, not flaky");
    }

    #[test]
    fn the_set_is_exposed_for_callers() {
        let fixture = fixture(4);
        assert_eq!(fixture.dag.set().validators.len(), 4);
        assert_eq!(fixture.dag.set().quorum_size(), 3);
    }

    #[test]
    fn the_leader_author_is_known_without_holding_the_vertex() {
        let fixture = fixture(4);
        assert_eq!(fixture.dag.leader_author(1), Some(&b"val-1"[..]));
        assert!(fixture.dag.leader(1).is_none());
        assert_eq!(fixture.dag.highest_round(), None);
    }

    #[test]
    fn an_anchor_history_answers_whether_it_contains_a_slot() {
        let mut fixture = bootstrapped(4);
        let votes = fixture.ids(LEADER_ROUND);
        fixture.full_round(LEADER_ROUND + 1, &votes).unwrap();
        fixture
            .full_round(LEADER_ROUND + 2, &fixture.ids(LEADER_ROUND + 1))
            .unwrap();
        let anchor = fixture.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();

        // The anchor reaches every author of the round before it.
        for author in 0..fixture.count() {
            let id = format!("val-{author}");
            assert!(
                fixture
                    .dag
                    .history_contains_author(&anchor, LEADER_ROUND + 1, id.as_bytes())
                    .unwrap()
            );
        }
        // It does not reach a slot nobody authored, nor a round it never saw.
        assert!(
            !fixture
                .dag
                .history_contains_author(&anchor, LEADER_ROUND + 1, b"val-unknown")
                .unwrap()
        );
        assert!(
            !fixture
                .dag
                .history_contains_author(&anchor, LEADER_ROUND + 9, b"val-0")
                .unwrap()
        );
    }

    #[test]
    fn a_missing_leader_may_still_anchor() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let genesis = fixture.ids(0);
        let leader = fixture.leader_index(LEADER_ROUND);

        // The leader's vertex is signed but deliberately not inserted.
        let missing_id = vertex(&fixture, leader, LEADER_ROUND, genesis.clone())
            .id()
            .unwrap();
        for author in 0..4 {
            if author == leader {
                continue;
            }
            let vertex = vertex(&fixture, author, LEADER_ROUND, genesis.clone());
            fixture.dag.insert(vertex).unwrap();
        }

        // Round-2 votes reference the missing leader by id, so a quorum for round 1
        // is still possible even though this node does not hold the leader's vertex.
        let mut references = fixture.ids(LEADER_ROUND);
        references.push(missing_id);
        fixture.full_round(LEADER_ROUND + 1, &references).unwrap();

        assert!(
            fixture.dag.can_still_anchor(LEADER_ROUND).unwrap(),
            "a missing leader with held votes can still anchor"
        );
    }

    #[test]
    fn an_impossible_quorum_cannot_anchor() {
        let mut fixture = bootstrapped(4);
        // Two held round-2 vertices that do not vote for the round-1 leader. Two
        // votes are missing, so even if both arrive, three voters cannot exist.
        let without_leader = fixture.ids_without_leader(LEADER_ROUND);
        for author in 0..2 {
            let vertex = vertex(&fixture, author, LEADER_ROUND + 1, without_leader.clone());
            fixture.dag.insert(vertex).unwrap();
        }

        assert!(
            !fixture.dag.can_still_anchor(LEADER_ROUND).unwrap(),
            "two held non-votes plus two missing votes cannot reach three"
        );
    }

    #[test]
    fn a_fenced_missing_leader_cannot_anchor() {
        let mut fixture = fixture(4);
        fixture.full_round(0, &[]).unwrap();
        let leader = fixture.leader_index(LEADER_ROUND);
        let author = format!("val-{leader}");
        let certificate = fence_certificate(&fixture, LEADER_ROUND, author.as_bytes());
        fixture
            .dag
            .apply_fence(b"karsa-dag-1", &certificate)
            .unwrap();

        // The leader vertex is missing. Without the fence a held vote could still
        // name it; the fence says the author is failed from this round, so the
        // round can never anchor and a higher anchor must be used.
        assert!(!fixture.dag.can_still_anchor(LEADER_ROUND).unwrap());
    }

    fn transition_keys(count: usize) -> Vec<Vec<u8>> {
        (0..count)
            .map(|index| {
                let seed = [u8::try_from(index + 1).unwrap(); 32];
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                let mut private = Vec::with_capacity(64);
                private.extend_from_slice(&seed);
                private.extend_from_slice(&public);
                private
            })
            .collect()
    }

    fn transition_records(count: usize, keys: &[Vec<u8>]) -> Vec<ValidatorRecord> {
        (0..count)
            .map(|index| ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: keys[index][32..].to_vec(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect()
    }

    /// Builds an old/new set pair and authors rounds 0..=3. The change lands at
    /// round 2, so the first two rounds use the old set and the last two use the
    /// new one.
    fn transition_dag(old_count: usize, new_count: usize) -> (Dag, Vec<Vec<u8>>) {
        let keys = transition_keys(old_count.max(new_count));
        let records = transition_records(old_count.max(new_count), &keys);
        let old_set = ValidatorSet {
            epoch: 1,
            validators: records[..old_count].to_vec(),
        };
        let new_set = ValidatorSet {
            epoch: 2,
            validators: records[..new_count].to_vec(),
        };
        let mut dag = Dag::with_epoch_length_and_change(old_set, new_set, 2, 2)
            .expect("the transition is safe");

        for round in 0..=3u64 {
            let epoch = dag.epoch_of(round);
            let active = if epoch < 2 { old_count } else { new_count };
            let previous_active = if round == 0 {
                0
            } else if dag.epoch_of(round - 1) < 2 {
                old_count
            } else {
                new_count
            };
            let references: Vec<VertexId> = if round == 0 {
                Vec::new()
            } else {
                (0..previous_active)
                    .filter_map(|author| {
                        dag.get(round - 1, format!("val-{author}").as_bytes())
                            .and_then(|vertex| vertex.id().ok())
                    })
                    .collect()
            };
            for (author, key) in keys.iter().enumerate().take(active) {
                let mut vertex = Vertex {
                    chain_id: b"karsa-transition-1".to_vec(),
                    epoch,
                    round,
                    author: format!("val-{author}").into_bytes(),
                    payload_hash: [0u8; 32],
                    references: references.clone(),
                    signature: Vec::new(),
                };
                let payload = vertex.signing_payload().unwrap();
                vertex.signature = Ed25519Scheme.sign(key, &payload).unwrap();
                dag.insert(vertex)
                    .expect("the active set accepts its own vertex");
            }
        }
        (dag, keys)
    }

    #[test]
    fn a_validator_join_at_an_epoch_boundary_keeps_committing() {
        let (mut dag, keys) = transition_dag(4, 5);
        assert_eq!(dag.set_for_round(1).validators.len(), 4);
        assert_eq!(dag.set_for_round(2).validators.len(), 5);
        assert_eq!(dag.leader_author(1), Some(b"val-1".as_slice()));
        assert_eq!(dag.leader_author(2), Some(b"val-2".as_slice()));
        assert!(matches!(dag.try_commit(1).unwrap(), Decision::Commit(_)));
        assert!(matches!(dag.try_commit(2).unwrap(), Decision::Commit(_)));

        // The new validator did not exist for the old epoch.
        let mut stale = Vertex {
            chain_id: b"karsa-transition-1".to_vec(),
            epoch: 1,
            round: 1,
            author: b"val-4".to_vec(),
            payload_hash: [0u8; 32],
            references: Vec::new(),
            signature: Vec::new(),
        };
        let payload = stale.signing_payload().unwrap();
        stale.signature = Ed25519Scheme.sign(&keys[4], &payload).unwrap();
        assert_eq!(
            dag.insert(stale).unwrap_err().kind(),
            CryptoErrorKind::UnknownValidator
        );
    }

    #[test]
    fn a_validator_removal_at_an_epoch_boundary_keeps_committing() {
        let (mut dag, keys) = transition_dag(5, 4);
        assert_eq!(dag.set_for_round(1).validators.len(), 5);
        assert_eq!(dag.set_for_round(2).validators.len(), 4);
        assert!(matches!(dag.try_commit(1).unwrap(), Decision::Commit(_)));
        assert!(matches!(dag.try_commit(2).unwrap(), Decision::Commit(_)));

        // The removed validator cannot author in the new epoch.
        let mut stale = Vertex {
            chain_id: b"karsa-transition-1".to_vec(),
            epoch: 2,
            round: 2,
            author: b"val-4".to_vec(),
            payload_hash: [0u8; 32],
            references: Vec::new(),
            signature: Vec::new(),
        };
        let payload = stale.signing_payload().unwrap();
        stale.signature = Ed25519Scheme.sign(&keys[4], &payload).unwrap();
        assert_eq!(
            dag.insert(stale).unwrap_err().kind(),
            CryptoErrorKind::UnknownValidator
        );
    }
}
