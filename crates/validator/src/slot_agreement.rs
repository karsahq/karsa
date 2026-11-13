//! Inactive, pure volatile two-phase agreement simulation for one fixed slot.
//!
//! NOT FOR LIVE USE: resetting or cloning this state loses anti-equivocation history.
//! There is no signer, persistence, recovery, pacemaker, network, or certificate conversion.
//! Outputs are unsigned simulation intents, never authorization to sign durably.
//! Signatures authenticate votes, not elected leadership, DAG evidence, ancestry, or
//! application effects. Proposal semantics remain an explicit external trust boundary.
//! Memory is bounded independently of the number of views: no vote history is retained.

use std::collections::BTreeSet;

use crypto::encoding::Encoder;
use crypto::{CryptoError, CryptoErrorKind};

use crate::{SlotDecision, SlotDecisionTip, ValidatorSet, ValidatorSignature};

/// Domain used only for agreement votes, never legacy slot certificates.
pub const SLOT_AGREEMENT_VOTE_DOMAIN: &[u8] = b"KARSA/SLOT_AGREEMENT/VOTE/v1";
const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;

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
        let mut bytes = 0usize;
        let mut seen = BTreeSet::new();
        for s in &self.signatures {
            for len in [s.validator_id.len(), s.key_id.len(), s.signature.len()] {
                bytes = bytes
                    .checked_add(len)
                    .ok_or_else(|| invalid("quorum size overflow"))?;
            }
            if bytes > MAX_SIGNATURE_BYTES || !seen.insert(s.validator_id.as_slice()) {
                return Err(invalid("oversized quorum or duplicate signer"));
            }
        }
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
    decision: Option<SlotDecision>,
}

impl SlotAgreement {
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
    /// Old nonnil precommit QCs still decide this exact fixed context.
    /// QC decisions also cross the explicit semantic-validation trust boundary.
    ///
    /// # Errors
    /// Rejects invalid evidence/semantics, future evidence, repeated precommits,
    /// or evidence conflicting with an existing decision. Errors leave state unchanged.
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
            (AgreementPhase::Prevote, value) if qc.vote.view == self.view => {
                let output = self.emit(AgreementPhase::Precommit, value.clone())?;
                if let AgreementValue::Decision(d) = value {
                    self.lock = Some((self.view, d.clone()));
                }
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
            let qc = AgreementQc {
                vote: first.1.clone(),
                signatures: matching.iter().map(|(_, _, s)| s.clone()).collect(),
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
        assert!(k.evidence(&late, |_| Ok(())).is_err());
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
