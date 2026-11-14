//! Inactive, pure volatile two-phase agreement simulation for one fixed slot.
//!
//! NOT FOR LIVE USE: resetting or cloning this state loses anti-equivocation history.
//! There is no signer, persistence, recovery, pacemaker, network, or certificate conversion.
//! Canonical inputs and prepared transitions are only volatile building blocks;
//! callers must persist exact inputs themselves before apply if their policy requires it.
//! Outputs are unsigned simulation intents, never authorization to sign durably.
//! Signatures authenticate votes, not elected leadership, DAG evidence, ancestry, or
//! application effects. Proposal semantics remain an explicit external trust boundary.
//! Memory is bounded independently of the number of views: no vote history is retained.

use crypto::encoding::Encoder;
use crypto::{CryptoError, CryptoErrorKind};

use crate::{SlotDecision, SlotDecisionTip, ValidatorSet, ValidatorSignature};

/// Domain used only for agreement votes, never legacy slot certificates.
pub const SLOT_AGREEMENT_VOTE_DOMAIN: &[u8] = b"KARSA/SLOT_AGREEMENT/VOTE/v1";

#[path = "slot_agreement_codec.rs"]
mod codec;

/// Owned canonical event for a volatile agreement simulation.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded events retain complete inline decisions and evidence"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementInput {
    /// Current-view proposal with optional earlier proof of lock.
    Propose {
        /// Exact current view.
        view: AgreementView,
        /// Complete proposed decision, not an arbitrary digest.
        decision: SlotDecision,
        /// Untrusted earlier prevote quorum evidence.
        pol: Option<AgreementQc>,
    },
    /// Phase timeout bound to an exact view.
    Timeout {
        /// Exact current view.
        view: AgreementView,
        /// Phase in which to emit nil.
        phase: AgreementPhase,
    },
    /// Advance exactly one view from the named current view.
    AdvanceView {
        /// Expected current view, guarding stale replay.
        from: AgreementView,
    },
    /// Untrusted quorum evidence, reverified during preparation.
    Evidence {
        /// Full quorum statement and signatures.
        qc: AgreementQc,
    },
}

/// Observations released only after applying a prepared volatile transition.
#[derive(Debug, PartialEq, Eq)]
pub struct AgreementTransitionResult {
    /// Optional unsigned vote emitted by this transition.
    pub vote: Option<AgreementVote>,
    /// Current view after this transition.
    pub view: AgreementView,
    /// Current decision, including an already observed idempotent decision.
    pub decision: Option<SlotDecision>,
}

/// Exclusive preparation guard; dropping it leaves the owner unchanged.
///
/// This is not a durable transaction. Persist [`Self::input`] externally before
/// applying if required; this API provides no store, WAL, crash safety, or signer.
/// The next state and output deliberately have no public access before apply.
///
/// ```compile_fail,E0499
/// use validator::slot_agreement::{AgreementInput, AgreementView, SlotAgreement};
/// fn exclusive(owner: &mut SlotAgreement) {
///     let pending = owner.prepare(
///         AgreementInput::AdvanceView { from: AgreementView(0) }, |_| Ok(())
///     ).unwrap();
///     owner.advance_view().unwrap(); // owner remains exclusively borrowed
///     pending.apply();
/// }
/// ```
#[must_use = "drop cancels preparation; apply installs the volatile transition"]
pub struct PreparedAgreementTransition<'a> {
    owner: &'a mut SlotAgreement,
    input: AgreementInput,
    next: SlotAgreement,
    output: AgreementTransitionResult,
}

impl std::fmt::Debug for PreparedAgreementTransition<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedAgreementTransition")
            .field("input", &self.input)
            .finish_non_exhaustive()
    }
}

impl PreparedAgreementTransition<'_> {
    /// Exact immutable input validated by this preparation, suitable for encoding.
    pub fn input(&self) -> &AgreementInput {
        &self.input
    }

    /// Infallibly installs the private next state and releases simulation output.
    /// No persistence, signing, or external side effects are performed.
    pub fn apply(self) -> AgreementTransitionResult {
        *self.owner = self.next;
        self.output
    }
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

/// Agreement view, distinct from the fixed slot's DAG round.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct AgreementView(pub u64);

/// The two disjoint voting phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgreementPhase {
    /// First-phase vote; a nonnil quorum can establish a lock.
    Prevote,
    /// Second-phase vote; only a nonnil quorum decides.
    Precommit,
}

/// Nil is abstention, not a decision to skip the slot.
#[expect(
    clippy::large_enum_variant,
    reason = "bounded simulation values stay inline rather than allocating each nonnil vote"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AgreementValue {
    /// No value supported in this phase.
    Nil,
    /// A structurally valid slot decision (which may itself be a Skip).
    Decision(SlotDecision),
}

/// Unsigned simulation vote with its complete immutable slot context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementVote {
    /// Fixed chain/set/epoch/slot/previous/before-frontier context.
    pub context: SlotDecisionTip,
    /// Agreement view, not slot number.
    pub view: AgreementView,
    /// Voting phase.
    pub phase: AgreementPhase,
    /// Explicit nil or complete decision.
    pub value: AgreementValue,
}

impl AgreementVote {
    /// Returns a domain-separated signing payload; does not sign or promise durability.
    ///
    /// # Errors
    /// Rejects an invalid or mismatched context, set, or decision.
    pub fn signing_payload(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        let c = &self.context;
        let checked = SlotDecisionTip::from_checkpoint(
            c.chain_id().to_vec(),
            set,
            c.next_round(),
            *c.previous_id(),
            c.order_len(),
            *c.order_root(),
        )?;
        if checked != *c {
            return Err(invalid("agreement set context mismatch"));
        }
        let mut e = Encoder::new();
        e.put_bytes(SLOT_AGREEMENT_VOTE_DOMAIN)?;
        e.put_bytes(c.chain_id())?;
        e.put_raw(c.set_id());
        e.put_u64(c.epoch());
        e.put_u64(c.next_round());
        e.put_raw(c.previous_id());
        e.put_u64(c.order_len());
        e.put_raw(c.order_root());
        e.put_u64(self.view.0);
        e.put_u8(match self.phase {
            AgreementPhase::Prevote => 0,
            AgreementPhase::Precommit => 1,
        });
        match &self.value {
            AgreementValue::Nil => e.put_u8(0),
            AgreementValue::Decision(d) => {
                d.validate(set)?;
                if d.chain_id != c.chain_id()
                    || d.validator_set_id != *c.set_id()
                    || d.epoch != c.epoch()
                    || d.round != c.next_round()
                    || d.previous != *c.previous_id()
                    || d.before_len != c.order_len()
                    || d.before_root != *c.order_root()
                {
                    return Err(invalid("agreement decision context mismatch"));
                }
                e.put_u8(1);
                e.put_raw(&d.id()?);
            }
        }
        Ok(e.finish())
    }
}

/// Untrusted quorum evidence; every use re-verifies all signatures and context.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgreementQc {
    /// One exact statement signed by every listed signer.
    pub vote: AgreementVote,
    /// Distinct active validator signatures over the agreement signing payload.
    pub signatures: Vec<ValidatorSignature>,
}

impl AgreementQc {
    /// Authenticates a bounded quorum, not the semantics of its decision.
    ///
    /// # Errors
    /// Rejects malformed context, oversized evidence, duplicate signers, invalid
    /// signatures (including mixed views/values/phases), or insufficient quorum.
    pub fn verify(&self, context: &SlotDecisionTip, set: &ValidatorSet) -> Result<(), CryptoError> {
        if self.vote.context != *context || self.signatures.len() > set.validators.len() {
            return Err(invalid("agreement quorum context or signer bound mismatch"));
        }
        self.encode(set)?;
        let signers = set.verify_signatures(
            &self.vote.signing_payload(set)?,
            context.epoch(),
            &self.signatures,
        )?;
        if signers.len() < set.quorum_size() {
            return Err(invalid("agreement evidence has no quorum"));
        }
        Ok(())
    }
}

/// Constant-history volatile reducer. No instances are connected to live consensus.
#[derive(Debug)]
pub struct SlotAgreement {
    context: SlotDecisionTip,
    set: ValidatorSet,
    view: AgreementView,
    prevote: Option<AgreementValue>,
    precommit: Option<AgreementValue>,
    lock: Option<(AgreementView, SlotDecision)>,
    valid: Option<AgreementQc>,
    decision: Option<SlotDecision>,
}

impl SlotAgreement {
    fn copy_for_prepare(&self) -> Self {
        Self {
            context: self.context.clone(),
            set: self.set.clone(),
            view: self.view,
            prevote: self.prevote.clone(),
            precommit: self.precommit.clone(),
            lock: self.lock.clone(),
            valid: self.valid.clone(),
            decision: self.decision.clone(),
        }
    }

    /// Validates a canonical input on a private deep copy, leaving this owner unchanged.
    /// The exclusive guard prevents further owner access until drop or apply.
    /// Replay uses this same API and MUST supply semantic validation again; callback
    /// side effects are external and cannot be rolled back by this volatile kernel.
    ///
    /// # Errors
    /// Rejects codec bounds, noncanonical signer order, incorrect exact views, and
    /// all existing reducer validation errors. Failure leaves every owner field unchanged.
    pub fn prepare(
        &mut self,
        input: AgreementInput,
        validate_semantics: impl FnOnce(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<PreparedAgreementTransition<'_>, CryptoError> {
        input.encode(&self.set)?;
        let mut next = self.copy_for_prepare();
        let vote = match &input {
            AgreementInput::Propose {
                view,
                decision,
                pol,
            } => Some(next.propose(*view, decision.clone(), pol.as_ref(), validate_semantics)?),
            AgreementInput::Timeout { view, phase } => {
                if *view != next.view {
                    return Err(invalid("timeout is not in current view"));
                }
                Some(next.timeout(*phase)?)
            }
            AgreementInput::AdvanceView { from } => {
                if *from != next.view {
                    return Err(invalid("advance from is not current view"));
                }
                next.advance_view()?;
                None
            }
            AgreementInput::Evidence { qc } => next.evidence(qc, validate_semantics)?,
        };
        let output = AgreementTransitionResult {
            vote,
            view: next.view,
            decision: next.decision.clone(),
        };
        Ok(PreparedAgreementTransition {
            owner: self,
            input,
            next,
            output,
        })
    }

    /// Starts a fresh simulation; this is NOT restart-safe restoration.
    ///
    /// # Errors
    /// Rejects a context not bound to a valid bounded fixed validator set.
    pub fn new(context: SlotDecisionTip, set: ValidatorSet) -> Result<Self, CryptoError> {
        AgreementVote {
            context: context.clone(),
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
            value: AgreementValue::Nil,
        }
        .signing_payload(&set)?;
        Ok(Self {
            context,
            set,
            view: AgreementView(0),
            prevote: None,
            precommit: None,
            lock: None,
            valid: None,
            decision: None,
        })
    }

    /// Current agreement view.
    pub fn view(&self) -> AgreementView {
        self.view
    }
    /// Current lock; nil and timeouts never erase it.
    pub fn lock(&self) -> Option<&(AgreementView, SlotDecision)> {
        self.lock.as_ref()
    }
    /// Highest authenticated, semantically validated nonnil prevote QC at or below this view.
    /// The first QC at the retained view is preserved. Authenticated QCs for the same
    /// exact vote statement are accepted regardless of signer subset; conflicting
    /// statements are rejected. Lower-view QCs cannot replace it. This cache does not
    /// authorize unlocking; proposals still require an explicit matching POL.
    pub fn valid(&self) -> Option<&AgreementQc> {
        self.valid.as_ref()
    }

    /// Decided value, if a verified nonnil precommit quorum was received.
    pub fn decision(&self) -> Option<&SlotDecision> {
        self.decision.as_ref()
    }

    fn active(&self) -> Result<(), CryptoError> {
        if self.decision.is_some() {
            return Err(invalid("agreement already decided"));
        }
        Ok(())
    }

    fn emit(
        &mut self,
        phase: AgreementPhase,
        value: AgreementValue,
    ) -> Result<AgreementVote, CryptoError> {
        self.active()?;
        let previous = match phase {
            AgreementPhase::Prevote => &mut self.prevote,
            AgreementPhase::Precommit => &mut self.precommit,
        };
        if previous.is_some() {
            return Err(invalid("already voted in this phase and view"));
        }
        *previous = Some(value.clone());
        Ok(AgreementVote {
            context: self.context.clone(),
            view: self.view,
            phase,
            value,
        })
    }

    /// Considers a current-view proposal after explicit external semantic validation.
    /// The callback MUST check leadership, evidence, ancestry, and application effects;
    /// returning success is a caller trust assertion, not signature authentication.
    /// A conflicting lock requires a matching verified prevote POL strictly newer
    /// than the lock and strictly earlier than this proposal's view.
    ///
    /// # Errors
    /// Rejects invalid semantics/context/POL, stale views, or repeated prevotes.
    pub fn propose(
        &mut self,
        view: AgreementView,
        decision: SlotDecision,
        pol: Option<&AgreementQc>,
        validate_semantics: impl FnOnce(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<AgreementVote, CryptoError> {
        self.active()?;
        if view != self.view {
            return Err(invalid("proposal is not in current view"));
        }
        let value = AgreementValue::Decision(decision.clone());
        AgreementVote {
            context: self.context.clone(),
            view,
            phase: AgreementPhase::Prevote,
            value: value.clone(),
        }
        .signing_payload(&self.set)?;
        validate_semantics(&decision)?;
        if let Some(qc) = pol {
            qc.verify(&self.context, &self.set)?;
            if qc.vote.phase != AgreementPhase::Prevote
                || qc.vote.value != value
                || qc.vote.view >= view
            {
                return Err(invalid("POL must match proposal in an earlier view"));
            }
        }
        if let Some((locked_view, locked)) = &self.lock {
            if *locked != decision && !pol.is_some_and(|qc| qc.vote.view > *locked_view) {
                return Err(invalid("conflicting proposal lacks newer POL"));
            }
        }
        self.emit(AgreementPhase::Prevote, value)
    }

    /// Emits nil on an externally triggered phase timeout, preserving the lock.
    ///
    /// # Errors
    /// Rejects repeated phase votes or an already decided simulation.
    pub fn timeout(&mut self, phase: AgreementPhase) -> Result<AgreementVote, CryptoError> {
        self.emit(phase, AgreementValue::Nil)
    }

    /// Applies authenticated evidence. Only current-view prevote QCs can lock and
    /// emit a precommit; after any precommit, late evidence cannot replace the lock.
    /// Nonnil prevote QCs are retained independently of the lock even when old or
    /// received after a precommit; these cases return no vote and preserve the lock.
    /// Old nonnil precommit QCs still decide this exact fixed context.
    /// QC decisions also cross the explicit semantic-validation trust boundary.
    ///
    /// # Errors
    /// Rejects invalid evidence/semantics, future evidence, conflicting statements at the retained
    /// valid view, repeated nil precommits, or evidence conflicting with an existing
    /// decision. Errors leave state unchanged.
    pub fn evidence(
        &mut self,
        qc: &AgreementQc,
        validate_semantics: impl FnOnce(&SlotDecision) -> Result<(), CryptoError>,
    ) -> Result<Option<AgreementVote>, CryptoError> {
        qc.verify(&self.context, &self.set)?;
        if qc.vote.view > self.view {
            return Err(invalid("future quorum evidence"));
        }
        if let AgreementValue::Decision(d) = &qc.vote.value {
            validate_semantics(d)?;
        }
        if let Some(d) = &self.decision {
            if qc.vote.phase == AgreementPhase::Precommit
                && qc.vote.value == AgreementValue::Decision(d.clone())
            {
                return Ok(None);
            }
            return Err(invalid("agreement already decided"));
        }
        match (&qc.vote.phase, &qc.vote.value) {
            (AgreementPhase::Precommit, AgreementValue::Decision(d)) => {
                self.decision = Some(d.clone());
                Ok(None)
            }
            (AgreementPhase::Prevote, AgreementValue::Decision(d)) => {
                if let Some(valid) = &self.valid
                    && valid.vote.view == qc.vote.view
                    && valid.vote != qc.vote
                {
                    return Err(invalid("conflicting QC at retained valid view"));
                }
                if self
                    .valid
                    .as_ref()
                    .is_none_or(|valid| qc.vote.view > valid.vote.view)
                {
                    self.valid = Some(qc.clone());
                }
                if qc.vote.view < self.view || self.precommit.is_some() {
                    return Ok(None);
                }
                let output = self.emit(AgreementPhase::Precommit, qc.vote.value.clone())?;
                self.lock = Some((self.view, d.clone()));
                Ok(Some(output))
            }
            (AgreementPhase::Prevote, value) if qc.vote.view == self.view => {
                let output = self.emit(AgreementPhase::Precommit, value.clone())?;
                Ok(Some(output))
            }
            _ => Ok(None),
        }
    }

    /// Advances exactly one view on an external simulation timeout, preserving locks.
    ///
    /// # Errors
    /// Rejects overflow or a decided simulation without changing any state.
    pub fn advance_view(&mut self) -> Result<AgreementView, CryptoError> {
        self.active()?;
        let next = self
            .view
            .0
            .checked_add(1)
            .ok_or_else(|| invalid("agreement view overflow"))?;
        self.view = AgreementView(next);
        self.prevote = None;
        self.precommit = None;
        Ok(self.view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NO_EXPIRY, SlotOutcome, ValidatorKey, ValidatorRecord};
    use crypto::{registry::ALG_ED25519, scheme::Ed25519Scheme};

    fn fixture() -> (SlotAgreement, Vec<Vec<u8>>, SlotDecision) {
        let mut keys = Vec::new();
        let validators = (0..4u8)
            .map(|i| {
                let seed = [i + 1; 32];
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                keys.push([seed.as_slice(), public.as_slice()].concat());
                ValidatorRecord {
                    validator_id: vec![i],
                    keys: vec![ValidatorKey {
                        key_id: vec![i],
                        algorithm_id: ALG_ED25519,
                        public_key: public.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: NO_EXPIRY,
                    }],
                }
            })
            .collect();
        let set = ValidatorSet {
            epoch: 2,
            validators,
        };
        let d = SlotDecision {
            chain_id: b"agreement-test".to_vec(),
            validator_set_id: set.id().unwrap(),
            epoch: 2,
            round: 7,
            previous: [1; 32],
            before_len: 3,
            before_root: [2; 32],
            after_len: 3,
            after_root: [2; 32],
            outcome: SlotOutcome::Skip {
                leader_author: vec![0],
            },
        };
        let context = SlotDecisionTip::from_checkpoint(
            d.chain_id.clone(),
            &set,
            7,
            d.previous,
            3,
            d.before_root,
        )
        .unwrap();
        (SlotAgreement::new(context, set).unwrap(), keys, d)
    }

    fn qc(
        k: &SlotAgreement,
        keys: &[Vec<u8>],
        view: u64,
        phase: AgreementPhase,
        value: AgreementValue,
    ) -> AgreementQc {
        let vote = AgreementVote {
            context: k.context.clone(),
            view: AgreementView(view),
            phase,
            value,
        };
        let payload = vote.signing_payload(&k.set).unwrap();
        let signatures = (0..3u8)
            .map(|i| ValidatorSignature {
                validator_id: vec![i],
                key_id: vec![i],
                signature: Ed25519Scheme.sign(&keys[usize::from(i)], &payload).unwrap(),
            })
            .collect();
        AgreementQc { vote, signatures }
    }
    fn other(d: &SlotDecision) -> SlotDecision {
        let mut d = d.clone();
        d.outcome = SlotOutcome::Skip {
            leader_author: vec![1],
        };
        d
    }

    // The harness never manufactures a signed statement: every signature is
    // recorded immediately from a successful reducer output for that signer.
    struct Harness {
        nodes: Vec<SlotAgreement>,
        keys: Vec<Vec<u8>>,
        emitted: Vec<(usize, AgreementVote, ValidatorSignature)>,
    }

    impl Harness {
        fn new() -> (Self, SlotDecision) {
            let (node, keys, decision) = fixture();
            let nodes = (0..4)
                .map(|_| SlotAgreement::new(node.context.clone(), node.set.clone()).unwrap())
                .collect();
            (
                Self {
                    nodes,
                    keys,
                    emitted: Vec::new(),
                },
                decision,
            )
        }

        fn record(&mut self, id: usize, vote: AgreementVote) {
            for (signer, previous, _) in &self.emitted {
                if *signer == id && previous.view == vote.view && previous.phase == vote.phase {
                    assert_eq!(previous, &vote, "honest signer {id} equivocated");
                    panic!("honest signer {id} emitted twice in one phase/view");
                }
            }
            let signer = u8::try_from(id).unwrap();
            let signature = ValidatorSignature {
                validator_id: vec![signer],
                key_id: vec![signer],
                signature: Ed25519Scheme
                    .sign(
                        &self.keys[id],
                        &vote.signing_payload(&self.nodes[id].set).unwrap(),
                    )
                    .unwrap(),
            };
            self.emitted.push((id, vote, signature));
        }

        fn propose(&mut self, id: usize, decision: &SlotDecision, pol: Option<&AgreementQc>) {
            let view = self.nodes[id].view();
            let vote = self.nodes[id]
                .propose(view, decision.clone(), pol, |_| Ok(()))
                .unwrap();
            self.record(id, vote);
        }

        fn timeout(&mut self, id: usize, phase: AgreementPhase) {
            let vote = self.nodes[id].timeout(phase).unwrap();
            self.record(id, vote);
        }

        fn deliver(&mut self, id: usize, qc: &AgreementQc) {
            if let Some(vote) = self.nodes[id].evidence(qc, |_| Ok(())).unwrap() {
                self.record(id, vote);
            }
        }

        fn quorum(
            &self,
            view: u64,
            phase: AgreementPhase,
            value: &AgreementValue,
        ) -> Option<AgreementQc> {
            let matching: Vec<_> = self
                .emitted
                .iter()
                .filter(|(_, v, _)| {
                    v.view == AgreementView(view) && v.phase == phase && v.value == *value
                })
                .collect();
            let first = matching.first()?;
            let mut signatures: Vec<_> = matching.iter().map(|(_, _, s)| s.clone()).collect();
            signatures.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
            let qc = AgreementQc {
                vote: first.1.clone(),
                signatures,
            };
            qc.verify(&self.nodes[0].context, &self.nodes[0].set).ok()?;
            Some(qc)
        }
    }

    #[test]
    fn four_honest_nodes_split_then_converge_using_only_emitted_votes() {
        let (mut h, d) = Harness::new();
        let conflict = other(&d);
        for id in 0..4 {
            h.propose(id, if id < 2 { &d } else { &conflict }, None);
        }
        for value in [&d, &conflict] {
            assert!(
                h.quorum(
                    0,
                    AgreementPhase::Prevote,
                    &AgreementValue::Decision(value.clone())
                )
                .is_none()
            );
        }
        for id in 0..4 {
            h.timeout(id, AgreementPhase::Precommit);
            assert!(h.nodes[id].lock().is_none());
            assert!(h.nodes[id].decision().is_none());
            h.nodes[id].advance_view().unwrap();
            h.propose(id, &d, None);
        }
        let pol = h
            .quorum(
                1,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(d.clone()),
            )
            .unwrap();
        for id in [2, 0, 3, 1] {
            h.deliver(id, &pol);
        }
        let commit = h
            .quorum(
                1,
                AgreementPhase::Precommit,
                &AgreementValue::Decision(d.clone()),
            )
            .unwrap();
        // One replica receives the commit after moving to another view.
        h.nodes[3].advance_view().unwrap();
        for id in [1, 3, 0, 2] {
            h.deliver(id, &commit);
        }
        assert!(h.nodes.iter().all(|n| n.decision() == Some(&d)));
        assert_eq!(h.emitted.len(), 16);
    }

    #[test]
    fn reachable_newer_pol_then_current_qc_replaces_lock() {
        let (mut h, d) = Harness::new();
        let conflict = other(&d);
        for id in 0..4 {
            h.propose(id, &d, None);
        }
        let initial = h
            .quorum(
                0,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(d.clone()),
            )
            .unwrap();
        // Only node zero receives the first QC and locks; the others time out.
        h.deliver(0, &initial);
        for id in 1..4 {
            h.timeout(id, AgreementPhase::Precommit);
        }
        for node in &mut h.nodes {
            node.advance_view().unwrap();
        }
        h.timeout(0, AgreementPhase::Prevote);
        for id in 1..4 {
            h.propose(id, &conflict, None);
        }
        let newer = h
            .quorum(
                1,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(conflict.clone()),
            )
            .unwrap();
        // Do not deliver this QC: it is a POL for the following proposal.
        for id in 0..4 {
            h.timeout(id, AgreementPhase::Precommit);
            h.nodes[id].advance_view().unwrap();
            h.propose(id, &conflict, Some(&newer));
        }
        assert_eq!(h.nodes[0].lock(), Some(&(AgreementView(0), d)));
        let current = h
            .quorum(
                2,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(conflict.clone()),
            )
            .unwrap();
        for id in 0..4 {
            h.deliver(id, &current);
            assert_eq!(
                h.nodes[id].lock(),
                Some(&(AgreementView(2), conflict.clone()))
            );
        }
        let commit = h
            .quorum(
                2,
                AgreementPhase::Precommit,
                &AgreementValue::Decision(conflict.clone()),
            )
            .unwrap();
        for id in 0..4 {
            h.deliver(id, &commit);
        }
        assert!(h.nodes.iter().all(|n| n.decision() == Some(&conflict)));
    }

    // Every field is included, including immutable context and validator keys.
    #[derive(Debug, PartialEq, Eq)]
    struct StateSnapshot {
        context: SlotDecisionTip,
        set: ValidatorSet,
        view: AgreementView,
        prevote: Option<AgreementValue>,
        precommit: Option<AgreementValue>,
        lock: Option<(AgreementView, SlotDecision)>,
        valid: Option<AgreementQc>,
        decision: Option<SlotDecision>,
    }

    fn snapshot(k: &SlotAgreement) -> StateSnapshot {
        StateSnapshot {
            context: k.context.clone(),
            set: k.set.clone(),
            view: k.view,
            prevote: k.prevote.clone(),
            precommit: k.precommit.clone(),
            lock: k.lock.clone(),
            valid: k.valid.clone(),
            decision: k.decision.clone(),
        }
    }

    #[test]
    fn semantic_callback_rejection_is_fully_atomic() {
        let (mut h, d) = Harness::new();
        let conflict = other(&d);
        for id in 0..4 {
            h.propose(id, &d, None);
        }
        let initial = h
            .quorum(
                0,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(d.clone()),
            )
            .unwrap();
        h.deliver(0, &initial);
        for id in 1..4 {
            h.timeout(id, AgreementPhase::Precommit);
        }
        for node in &mut h.nodes {
            node.advance_view().unwrap();
        }
        for id in 1..4 {
            h.propose(id, &conflict, None);
        }
        let pol = h
            .quorum(
                1,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(conflict.clone()),
            )
            .unwrap();
        for id in 1..4 {
            h.deliver(id, &pol);
        }
        let old_commit = h
            .quorum(
                1,
                AgreementPhase::Precommit,
                &AgreementValue::Decision(conflict.clone()),
            )
            .unwrap();
        for node in &mut h.nodes {
            node.advance_view().unwrap();
        }
        let before = snapshot(&h.nodes[0]);
        let mut calls = 0;
        assert!(
            h.nodes[0]
                .propose(AgreementView(2), conflict.clone(), Some(&pol), |_| {
                    calls += 1;
                    Err(invalid("external proposal rejection"))
                })
                .is_err()
        );
        assert_eq!(calls, 1);
        assert_eq!(snapshot(&h.nodes[0]), before);
        // A successful retry demonstrates that rejection did not consume prevote.
        h.propose(0, &conflict, Some(&pol));
        for id in 1..4 {
            h.propose(id, &conflict, Some(&pol));
        }
        let current = h
            .quorum(
                2,
                AgreementPhase::Prevote,
                &AgreementValue::Decision(conflict.clone()),
            )
            .unwrap();
        let before = snapshot(&h.nodes[0]);
        for evidence in [&current, &old_commit] {
            let mut calls = 0;
            assert!(
                h.nodes[0]
                    .evidence(evidence, |_| {
                        calls += 1;
                        Err(invalid("external evidence rejection"))
                    })
                    .is_err()
            );
            assert_eq!(calls, 1);
            assert_eq!(snapshot(&h.nodes[0]), before);
        }
        h.deliver(0, &current);
        assert_eq!(
            h.nodes[0].lock(),
            Some(&(AgreementView(2), conflict.clone()))
        );
        h.deliver(0, &old_commit);
        assert_eq!(h.nodes[0].decision(), Some(&conflict));
    }

    fn raw_qc(qc: &AgreementQc, set: &ValidatorSet) -> Vec<u8> {
        let mut e = Encoder::new();
        e.put_u16(1);
        e.put_u8(2);
        e.put_bytes(&qc.vote.encode(set).unwrap()).unwrap();
        e.put_u32(u32::try_from(qc.signatures.len()).unwrap());
        for s in &qc.signatures {
            e.put_bytes(&s.validator_id).unwrap();
            e.put_bytes(&s.key_id).unwrap();
            e.put_bytes(&s.signature).unwrap();
        }
        e.finish()
    }

    #[test]
    fn canonical_inputs_votes_and_qcs_roundtrip_and_reject_truncation() {
        let (k, keys, d) = fixture();
        let pol = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        let events = [
            AgreementInput::Propose {
                view: AgreementView(1),
                decision: d.clone(),
                pol: Some(pol.clone()),
            },
            AgreementInput::Propose {
                view: AgreementView(0),
                decision: d,
                pol: None,
            },
            AgreementInput::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            },
            AgreementInput::Timeout {
                view: AgreementView(1),
                phase: AgreementPhase::Precommit,
            },
            AgreementInput::AdvanceView {
                from: AgreementView(0),
            },
            AgreementInput::Evidence { qc: pol.clone() },
        ];
        for event in events {
            let bytes = event.encode(&k.set).unwrap();
            let decoded = AgreementInput::decode(&bytes, &k.set).unwrap();
            assert_eq!(decoded, event);
            assert_eq!(decoded.encode(&k.set).unwrap(), bytes);
            for end in 0..bytes.len() {
                assert!(
                    AgreementInput::decode(&bytes[..end], &k.set).is_err(),
                    "accepted truncated input at {end}"
                );
            }
            let mut trailing = bytes.clone();
            trailing.push(0);
            assert!(AgreementInput::decode(&trailing, &k.set).is_err());
            for offset in [0, 2, 3] {
                let mut bad = bytes.clone();
                bad[offset] = 255;
                assert!(AgreementInput::decode(&bad, &k.set).is_err());
            }
        }
        for value in [AgreementValue::Nil, pol.vote.value.clone()] {
            for phase in [AgreementPhase::Prevote, AgreementPhase::Precommit] {
                let q = qc(&k, &keys, 0, phase, value.clone());
                let bytes = q.vote.encode(&k.set).unwrap();
                assert_eq!(AgreementVote::decode(&bytes, &k.set).unwrap(), q.vote);
                assert_ne!(bytes, q.vote.signing_payload(&k.set).unwrap());
                for end in 0..bytes.len() {
                    assert!(AgreementVote::decode(&bytes[..end], &k.set).is_err());
                }
                let bytes = q.encode(&k.set).unwrap();
                assert_eq!(AgreementQc::decode(&bytes, &k.set).unwrap(), q);
                for end in 0..bytes.len() {
                    assert!(AgreementQc::decode(&bytes[..end], &k.set).is_err());
                }
                let mut trailing = bytes;
                trailing.push(0);
                assert!(AgreementQc::decode(&trailing, &k.set).is_err());
            }
        }
        let mut commit_vote = pol.vote.clone();
        if let AgreementValue::Decision(d) = &mut commit_vote.value {
            d.outcome = SlotOutcome::Commit {
                leader: crate::VertexId {
                    round: d.round,
                    author: vec![0],
                    digest: [9; 32],
                },
            };
        }
        assert_eq!(
            AgreementVote::decode(&commit_vote.encode(&k.set).unwrap(), &k.set).unwrap(),
            commit_vote
        );
        let timeout = AgreementInput::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        };
        let mut bad_phase = timeout.encode(&k.set).unwrap();
        *bad_phase.last_mut().unwrap() = 255;
        assert!(AgreementInput::decode(&bad_phase, &k.set).is_err());
        let nil = qc(&k, &keys, 0, AgreementPhase::Prevote, AgreementValue::Nil);
        let vote = nil.vote.encode(&k.set).unwrap();
        for offset in [0, 2, vote.len() - 2, vote.len() - 1] {
            let mut bad = vote.clone();
            bad[offset] = 255;
            assert!(AgreementVote::decode(&bad, &k.set).is_err());
        }
        let mut trailing = vote;
        trailing.push(0);
        assert!(AgreementVote::decode(&trailing, &k.set).is_err());
        let mut wrong_set = k.set.clone();
        wrong_set.epoch += 1;
        assert!(AgreementQc::decode(&pol.encode(&k.set).unwrap(), &wrong_set).is_err());
        let mut proposal = AgreementInput::Propose {
            view: AgreementView(0),
            decision: other(match &pol.vote.value {
                AgreementValue::Decision(d) => d,
                _ => unreachable!(),
            }),
            pol: None,
        }
        .encode(&k.set)
        .unwrap();
        *proposal.last_mut().unwrap() = 2;
        assert!(AgreementInput::decode(&proposal, &k.set).is_err());
    }

    #[test]
    fn codec_enforces_total_count_field_bounds_and_strict_signer_order() {
        const LIMIT: usize = 1 << 20;
        let (k, keys, _) = fixture();
        let base = qc(&k, &keys, 0, AgreementPhase::Prevote, AgreementValue::Nil);
        for duplicate in [false, true] {
            let mut bad = base.clone();
            if duplicate {
                bad.signatures[1] = bad.signatures[0].clone();
            } else {
                bad.signatures.swap(0, 1);
            }
            assert!(bad.encode(&k.set).is_err());
            assert!(AgreementQc::decode(&raw_qc(&bad, &k.set), &k.set).is_err());
            assert!(bad.verify(&k.context, &k.set).is_err());
        }
        for field in 0..3 {
            let mut bad = base.clone();
            let s = &mut bad.signatures[0];
            match field {
                0 => s.validator_id = vec![0; 1025],
                1 => s.key_id = vec![0; 1025],
                _ => s.signature = vec![0; LIMIT],
            }
            assert!(bad.encode(&k.set).is_err());
            assert!(AgreementQc::decode(&raw_qc(&bad, &k.set), &k.set).is_err());
        }
        let mut maximum_count = base.clone();
        maximum_count.signatures = (0..4096u16)
            .map(|i| ValidatorSignature {
                validator_id: i.to_be_bytes().to_vec(),
                key_id: Vec::new(),
                signature: Vec::new(),
            })
            .collect();
        let bytes = maximum_count.encode(&k.set).unwrap();
        assert_eq!(AgreementQc::decode(&bytes, &k.set).unwrap(), maximum_count);
        // Codec acceptance is not quorum authentication or membership validation.
        assert!(maximum_count.verify(&k.context, &k.set).is_err());
        let mut huge = base.clone();
        huge.signatures = vec![base.signatures[0].clone(); 4097];
        assert!(huge.encode(&k.set).is_err());
        let mut prefix = Encoder::new();
        prefix.put_u16(1);
        prefix.put_u8(2);
        prefix
            .put_bytes(&base.vote.encode(&k.set).unwrap())
            .unwrap();
        prefix.put_u32(4097);
        assert!(AgreementQc::decode(&prefix.finish(), &k.set).is_err());
        // The QC limit includes every framing byte, not just signature bytes.
        let mut exact = base.clone();
        let original_size = exact.encode(&k.set).unwrap().len();
        let signature = &mut exact.signatures[0].signature;
        signature.resize(signature.len() + LIMIT - original_size, 0);
        let bytes = exact.encode(&k.set).unwrap();
        assert_eq!(bytes.len(), LIMIT);
        assert_eq!(AgreementQc::decode(&bytes, &k.set).unwrap(), exact);
        assert!(
            AgreementInput::Evidence { qc: exact.clone() }
                .encode(&k.set)
                .is_err()
        );
        let mut exact_input_qc = exact.clone();
        let signature_len = exact_input_qc.signatures[0].signature.len();
        exact_input_qc.signatures[0]
            .signature
            .truncate(signature_len - 8);
        let exact_input = AgreementInput::Evidence { qc: exact_input_qc };
        let bytes = exact_input.encode(&k.set).unwrap();
        assert_eq!(bytes.len(), LIMIT);
        assert_eq!(AgreementInput::decode(&bytes, &k.set).unwrap(), exact_input);
        exact.signatures[0].signature.push(0);
        assert!(exact.encode(&k.set).is_err());
        let oversize = vec![0; LIMIT + 1];
        assert!(AgreementInput::decode(&oversize, &k.set).is_err());
        assert!(AgreementVote::decode(&oversize, &k.set).is_err());
        assert!(AgreementQc::decode(&oversize, &k.set).is_err());
        let mut claimed = base.encode(&k.set).unwrap();
        claimed[3..7].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(AgreementQc::decode(&claimed, &k.set).is_err());
    }

    #[test]
    fn prepare_drop_failure_and_exact_view_guards_preserve_full_state() {
        let (mut k, keys, d) = fixture();
        let before = snapshot(&k);
        let input = AgreementInput::Propose {
            view: k.view(),
            decision: d.clone(),
            pol: None,
        };
        {
            let prepared = k.prepare(input.clone(), |_| Ok(())).unwrap();
            assert_eq!(prepared.input(), &input);
            assert_eq!(
                prepared.input().encode(&before.set).unwrap(),
                input.encode(&before.set).unwrap()
            );
        }
        assert_eq!(snapshot(&k), before);
        let mut calls = 0;
        assert!(
            k.prepare(input.clone(), |_| {
                calls += 1;
                Err(invalid("reject"))
            })
            .is_err()
        );
        assert_eq!(calls, 1);
        assert_eq!(snapshot(&k), before);
        for input in [
            AgreementInput::Timeout {
                view: AgreementView(1),
                phase: AgreementPhase::Prevote,
            },
            AgreementInput::AdvanceView {
                from: AgreementView(1),
            },
        ] {
            assert!(
                k.prepare(input, |_| panic!("no semantic callback for view guards"))
                    .is_err()
            );
            assert_eq!(snapshot(&k), before);
        }
        let mut wrong = d.clone();
        wrong.chain_id = b"wrong-chain".to_vec();
        assert!(
            k.prepare(
                AgreementInput::Propose {
                    view: k.view(),
                    decision: wrong,
                    pol: None
                },
                |_| Ok(())
            )
            .is_err()
        );
        assert_eq!(snapshot(&k), before);
        let mut wrong_qc = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        wrong_qc.vote.context = SlotDecisionTip::from_checkpoint(
            b"wrong-chain".to_vec(),
            &k.set,
            d.round,
            d.previous,
            d.before_len,
            d.before_root,
        )
        .unwrap();
        assert!(
            k.prepare(AgreementInput::Evidence { qc: wrong_qc }, |_| Ok(()))
                .is_err()
        );
        assert_eq!(snapshot(&k), before);
        k.prepare(
            AgreementInput::AdvanceView {
                from: AgreementView(0),
            },
            |_| Ok(()),
        )
        .unwrap()
        .apply();
        let advanced = snapshot(&k);
        for stale in [
            AgreementInput::AdvanceView {
                from: AgreementView(0),
            },
            AgreementInput::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Precommit,
            },
            input,
        ] {
            assert!(k.prepare(stale, |_| Ok(())).is_err());
            assert_eq!(snapshot(&k), advanced);
        }
    }

    #[test]
    fn prepared_apply_matches_direct_reducer_and_replay_revalidates() {
        let (mut prepared, keys, d) = fixture();
        let mut direct = prepared.copy_for_prepare();
        let proposal = AgreementInput::Propose {
            view: AgreementView(0),
            decision: d.clone(),
            pol: None,
        };
        let pol = qc(
            &prepared,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        let commit = qc(
            &prepared,
            &keys,
            0,
            AgreementPhase::Precommit,
            AgreementValue::Decision(d),
        );
        let late = qc(
            &prepared,
            &keys,
            1,
            AgreementPhase::Prevote,
            pol.vote.value.clone(),
        );
        let events = [
            proposal,
            AgreementInput::Evidence { qc: pol },
            AgreementInput::AdvanceView {
                from: AgreementView(0),
            },
            AgreementInput::Timeout {
                view: AgreementView(1),
                phase: AgreementPhase::Prevote,
            },
            AgreementInput::Timeout {
                view: AgreementView(1),
                phase: AgreementPhase::Precommit,
            },
            AgreementInput::Evidence { qc: late.clone() },
            AgreementInput::AdvanceView {
                from: AgreementView(1),
            },
            AgreementInput::Evidence { qc: late },
            AgreementInput::Evidence { qc: commit },
        ];
        for event in events {
            let decoded =
                AgreementInput::decode(&event.encode(&prepared.set).unwrap(), &prepared.set)
                    .unwrap();
            let before = snapshot(&prepared);
            let needs_semantics = matches!(
                event,
                AgreementInput::Propose { .. } | AgreementInput::Evidence { .. }
            );
            if needs_semantics {
                let mut calls = 0;
                assert!(
                    prepared
                        .prepare(decoded.clone(), |_| {
                            calls += 1;
                            Err(invalid("replay rejection"))
                        })
                        .is_err()
                );
                assert_eq!(calls, 1);
                assert_eq!(snapshot(&prepared), before);
            }
            let expected_vote = match &event {
                AgreementInput::Propose {
                    view,
                    decision,
                    pol,
                } => Some(
                    direct
                        .propose(*view, decision.clone(), pol.as_ref(), |_| Ok(()))
                        .unwrap(),
                ),
                AgreementInput::Timeout { phase, .. } => Some(direct.timeout(*phase).unwrap()),
                AgreementInput::AdvanceView { .. } => {
                    direct.advance_view().unwrap();
                    None
                }
                AgreementInput::Evidence { qc } => direct.evidence(qc, |_| Ok(())).unwrap(),
            };
            let mut calls = 0;
            let transition = prepared
                .prepare(decoded, |_| {
                    calls += 1;
                    Ok(())
                })
                .unwrap();
            assert_eq!(transition.input(), &event);
            let output = transition.apply();
            assert_eq!(calls, usize::from(needs_semantics));
            assert_eq!(output.vote, expected_vote);
            assert_eq!(output.view, direct.view());
            assert_eq!(output.decision.as_ref(), direct.decision());
            assert_eq!(snapshot(&prepared), snapshot(&direct));
        }
    }

    #[test]
    fn late_valid_prepare_drop_and_apply_preserve_nil_votes_without_locking() {
        let (mut k, keys, d) = fixture();
        k.timeout(AgreementPhase::Prevote).unwrap();
        k.timeout(AgreementPhase::Precommit).unwrap();
        let late = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d),
        );
        let input = AgreementInput::Evidence { qc: late.clone() };
        let before = snapshot(&k);
        drop(k.prepare(input.clone(), |_| Ok(())).unwrap());
        assert_eq!(snapshot(&k), before);
        assert!(
            k.prepare(input.clone(), |_| Err(invalid("rejected")))
                .is_err()
        );
        assert_eq!(snapshot(&k), before);
        let output = k.prepare(input, |_| Ok(())).unwrap().apply();
        assert_eq!(output.vote, None);
        assert_eq!(k.valid(), Some(&late));
        assert_eq!(k.lock(), None);
        assert_eq!(k.prevote, Some(AgreementValue::Nil));
        assert_eq!(k.precommit, Some(AgreementValue::Nil));
        let retained = snapshot(&k);
        assert_eq!(k.evidence(&late, |_| Ok(())).unwrap(), None);
        assert_eq!(snapshot(&k), retained);
        k.advance_view().unwrap();
        assert_eq!(k.valid(), Some(&late));
        assert_eq!(k.lock(), None);
    }

    #[test]
    fn old_valid_evidence_is_monotonic_and_never_unlocks_or_votes() {
        let (mut k, keys, d) = fixture();
        assert_eq!(k.valid(), None);
        let initial = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        assert!(k.evidence(&initial, |_| Ok(())).unwrap().is_some());
        assert_eq!(k.valid(), Some(&initial));
        assert_eq!(k.lock(), Some(&(AgreementView(0), d.clone())));
        k.advance_view().unwrap();
        k.advance_view().unwrap();
        let old = qc(
            &k,
            &keys,
            1,
            AgreementPhase::Prevote,
            AgreementValue::Decision(other(&d)),
        );
        let before = snapshot(&k);
        assert!(
            k.evidence(&old, |_| Err(invalid("semantic rejection")))
                .is_err()
        );
        assert_eq!(snapshot(&k), before);
        let mut forged = old.clone();
        forged.signatures[0].signature[0] ^= 1;
        assert!(k.evidence(&forged, |_| Ok(())).is_err());
        assert_eq!(snapshot(&k), before);
        let future = qc(
            &k,
            &keys,
            3,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        assert!(k.evidence(&future, |_| Ok(())).is_err());
        assert_eq!(snapshot(&k), before);
        assert_eq!(k.evidence(&old, |_| Ok(())).unwrap(), None);
        assert_eq!(k.valid(), Some(&old));
        assert_eq!(k.lock(), Some(&(AgreementView(0), d.clone())));
        assert_eq!(k.prevote, None);
        assert_eq!(k.precommit, None);
        let retained = snapshot(&k);
        for evidence in [&initial, &old] {
            assert_eq!(k.evidence(evidence, |_| Ok(())).unwrap(), None);
            assert_eq!(snapshot(&k), retained);
        }
        // Cached POL is evidence, not implicit permission to override the lock.
        assert!(k.propose(k.view(), other(&d), None, |_| Ok(())).is_err());
        assert_eq!(snapshot(&k), retained);
        let conflict = qc(
            &k,
            &keys,
            1,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        assert!(k.evidence(&conflict, |_| Ok(())).is_err());
        assert_eq!(snapshot(&k), retained);
        let mut different_signers = old.clone();
        let payload = old.vote.signing_payload(&k.set).unwrap();
        different_signers.signatures.remove(0);
        different_signers.signatures.push(ValidatorSignature {
            validator_id: vec![3],
            key_id: vec![3],
            signature: Ed25519Scheme.sign(&keys[3], &payload).unwrap(),
        });
        different_signers.verify(&k.context, &k.set).unwrap();
        let mut calls = 0;
        assert_eq!(
            k.evidence(&different_signers, |_| {
                calls += 1;
                Ok(())
            })
            .unwrap(),
            None
        );
        assert_eq!(calls, 1);
        assert_eq!(k.valid(), Some(&old));
        assert_eq!(snapshot(&k), retained);
        assert!(
            k.evidence(&different_signers, |_| Err(invalid("semantic rejection")))
                .is_err()
        );
        assert_eq!(snapshot(&k), retained);
        different_signers.signatures[0].signature[0] ^= 1;
        assert!(k.evidence(&different_signers, |_| Ok(())).is_err());
        assert_eq!(snapshot(&k), retained);
        k.timeout(AgreementPhase::Prevote).unwrap();
        k.timeout(AgreementPhase::Precommit).unwrap();
        let nil = qc(&k, &keys, 1, AgreementPhase::Prevote, AgreementValue::Nil);
        assert_eq!(k.evidence(&nil, |_| Ok(())).unwrap(), None);
        k.advance_view().unwrap();
        assert_eq!(k.valid(), Some(&old));
        assert_eq!(k.lock(), Some(&(AgreementView(0), d)));
    }

    #[test]
    fn split_initial_votes_recover_later_view() {
        let (mut a, keys, d) = fixture();
        let mut b = SlotAgreement::new(a.context.clone(), a.set.clone()).unwrap();
        a.propose(AgreementView(0), d.clone(), None, |_| Ok(()))
            .unwrap();
        b.propose(AgreementView(0), other(&d), None, |_| Ok(()))
            .unwrap();
        for k in [&mut a, &mut b] {
            k.timeout(AgreementPhase::Precommit).unwrap();
            k.advance_view().unwrap();
            k.propose(AgreementView(1), d.clone(), None, |_| Ok(()))
                .unwrap();
            let pol = qc(
                k,
                &keys,
                1,
                AgreementPhase::Prevote,
                AgreementValue::Decision(d.clone()),
            );
            assert_eq!(
                k.evidence(&pol, |_| Ok(())).unwrap().unwrap().value,
                pol.vote.value
            );
            let commit = qc(
                k,
                &keys,
                1,
                AgreementPhase::Precommit,
                AgreementValue::Decision(d.clone()),
            );
            k.evidence(&commit, |_| Ok(())).unwrap();
            assert_eq!(k.decision(), Some(&d));
        }
    }

    #[test]
    fn locks_survive_nil_and_timeouts_and_late_pol_cannot_double_vote() {
        let (mut k, keys, d) = fixture();
        let pol = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        k.evidence(&pol, |_| Ok(())).unwrap();
        k.advance_view().unwrap();
        k.timeout(AgreementPhase::Prevote).unwrap();
        let nil = qc(&k, &keys, 1, AgreementPhase::Prevote, AgreementValue::Nil);
        k.evidence(&nil, |_| Ok(())).unwrap();
        let late = qc(
            &k,
            &keys,
            1,
            AgreementPhase::Prevote,
            AgreementValue::Decision(other(&d)),
        );
        assert_eq!(k.evidence(&late, |_| Ok(())).unwrap(), None);
        assert_eq!(k.valid(), Some(&late));
        assert_eq!(k.precommit, Some(AgreementValue::Nil));
        assert_eq!(k.lock(), Some(&(AgreementView(0), d.clone())));
        k.advance_view().unwrap();
        k.timeout(AgreementPhase::Precommit).unwrap();
        assert_eq!(k.lock(), Some(&(AgreementView(0), d)));
    }

    #[test]
    fn pol_requires_authentication_matching_value_and_strict_view_order() {
        let (mut k, keys, d) = fixture();
        let initial = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        k.evidence(&initial, |_| Ok(())).unwrap();
        k.advance_view().unwrap();
        let conflict = other(&d);
        let stale = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(conflict.clone()),
        );
        assert!(
            k.propose(k.view(), conflict.clone(), Some(&stale), |_| Ok(()))
                .is_err()
        );
        let fresh = qc(
            &k,
            &keys,
            1,
            AgreementPhase::Prevote,
            AgreementValue::Decision(conflict.clone()),
        );
        assert!(
            k.propose(k.view(), conflict.clone(), Some(&fresh), |_| Ok(()))
                .is_err()
        );
        k.advance_view().unwrap();
        let mut forged = fresh.clone();
        forged.signatures[0].signature[0] ^= 1;
        assert!(
            k.propose(k.view(), conflict.clone(), Some(&forged), |_| Ok(()))
                .is_err()
        );
        let mut mixed = fresh.clone();
        mixed.signatures[0] = initial.signatures[0].clone();
        assert!(
            k.propose(k.view(), conflict.clone(), Some(&mixed), |_| Ok(()))
                .is_err()
        );
        assert!(
            k.propose(k.view(), d.clone(), Some(&fresh), |_| Ok(()))
                .is_err()
        );
        k.propose(k.view(), conflict, Some(&fresh), |_| Ok(()))
            .unwrap();
        assert_eq!(k.lock(), Some(&(AgreementView(0), d)));
    }

    #[test]
    fn old_commit_decides_but_other_context_and_nil_do_not() {
        let (mut k, keys, d) = fixture();
        let commit = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Precommit,
            AgreementValue::Decision(d.clone()),
        );
        let nil = qc(&k, &keys, 0, AgreementPhase::Precommit, AgreementValue::Nil);
        k.advance_view().unwrap();
        k.evidence(&nil, |_| Ok(())).unwrap();
        assert!(k.decision().is_none());
        let mut wrong = commit.clone();
        wrong.vote.context = SlotDecisionTip::from_checkpoint(
            b"other".to_vec(),
            &k.set,
            7,
            d.previous,
            3,
            d.before_root,
        )
        .unwrap();
        assert!(k.evidence(&wrong, |_| Ok(())).is_err());
        assert!(
            k.evidence(&commit, |_| Err(invalid("semantics rejected")))
                .is_err()
        );
        k.evidence(&commit, |_| Ok(())).unwrap();
        assert_eq!(k.decision(), Some(&d));
    }

    #[test]
    fn conflicting_votes_domains_context_and_overflow() {
        let (mut k, keys, d) = fixture();
        let v = k.propose(k.view(), d.clone(), None, |_| Ok(())).unwrap();
        assert!(k.propose(k.view(), other(&d), None, |_| Ok(())).is_err());
        assert!(k.timeout(AgreementPhase::Prevote).is_err());
        let pol = qc(
            &k,
            &keys,
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        );
        k.evidence(&pol, |_| Ok(())).unwrap();
        assert!(k.timeout(AgreementPhase::Precommit).is_err());
        assert_ne!(
            v.signing_payload(&k.set).unwrap(),
            d.signing_payload().unwrap()
        );
        let mut bad = v;
        if let AgreementValue::Decision(d) = &mut bad.value {
            d.before_len += 1;
        }
        assert!(bad.signing_payload(&k.set).is_err());
        k.view = AgreementView(u64::MAX);
        let lock = k.lock.clone();
        assert!(k.advance_view().is_err());
        assert_eq!(k.view(), AgreementView(u64::MAX));
        assert_eq!(k.lock, lock);
    }
}
