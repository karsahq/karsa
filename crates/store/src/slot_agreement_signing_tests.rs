//! Abstract synthetic reducer/WAL histories for the inactive agreement signing boundary.
//!
//! These are NOT valid DAG histories: semantic callbacks deliberately accept all decisions,
//! and the conflicting Skip authors need not match the elected leader. The histories test
//! reducer, persistence, and signature invariants, not election or DAG validity.
use super::*;
use crypto::{registry::ALG_ED25519, scheme::Ed25519Scheme};
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementTransitionResult, AgreementValue,
    AgreementView, AgreementVote,
};
use validator::{
    SlotDecision, SlotDecisionTip, SlotOutcome, ValidatorKey, ValidatorRecord, ValidatorSet,
    ValidatorSignature,
};

struct Node {
    store: Store,
    session: DurableSlotAgreement,
}

struct Harness {
    roots: Vec<PathBuf>,
    nodes: Vec<Option<Node>>,
    bootstraps: Vec<SlotAgreementBootstrap>,
    keys: Vec<Vec<u8>>,
    decision: SlotDecision,
    // External test oracle, retained across restarts; NOT durable signer state.
    // Every release invocation signs and publishes, including repeated exact statements.
    log: Vec<(usize, AgreementVote, ValidatorSignature)>,
}

impl Harness {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let mut keys = Vec::new();
        let set = ValidatorSet {
            epoch: 2,
            validators: (0..4u8)
                .map(|id| {
                    let seed = [id + 1; 32];
                    let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                    keys.push([seed.as_slice(), public.as_slice()].concat());
                    ValidatorRecord {
                        validator_id: vec![id],
                        keys: vec![ValidatorKey {
                            key_id: vec![id],
                            algorithm_id: ALG_ED25519,
                            public_key: public.to_vec(),
                            activation_epoch: 0,
                            retirement_epoch: u64::MAX,
                        }],
                    }
                })
                .collect(),
        };
        let decision = SlotDecision {
            chain_id: b"durable-signing-test".to_vec(),
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
            decision.chain_id.clone(),
            &set,
            7,
            decision.previous,
            3,
            decision.before_root,
        )
        .unwrap();
        let bootstraps: Vec<_> = (0..4u8)
            .map(|id| SlotAgreementBootstrap {
                context: context.clone(),
                set: set.clone(),
                local_validator: vec![id],
            })
            .collect();
        let roots: Vec<_> = (0..4)
            .map(|_| {
                std::env::temp_dir().join(format!(
                    "karsa-signing-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed),
                ))
            })
            .collect();
        let nodes = roots
            .iter()
            .zip(&bootstraps)
            .map(|(root, bootstrap)| {
                let store = Store::open(root).unwrap();
                let session = store.begin_slot_agreement(bootstrap.clone()).unwrap();
                Some(Node { store, session })
            })
            .collect();
        Self {
            roots,
            nodes,
            bootstraps,
            keys,
            decision,
            log: Vec::new(),
        }
    }

    fn node(&mut self, id: usize) -> &mut Node {
        self.nodes[id].as_mut().unwrap()
    }

    // The only honest signing entry point consumes an apply result, never an input/QC.
    fn release(&mut self, id: usize, result: &AgreementTransitionResult) {
        let Some(vote) = &result.vote else { return };
        let bootstrap = &self.bootstraps[id];
        assert_eq!(vote.context, bootstrap.context);
        let record = &bootstrap.set.validators[id];
        assert_eq!(record.validator_id, bootstrap.local_validator);
        let key = &record.keys[0];
        assert_eq!(key.algorithm_id, ALG_ED25519);
        assert_eq!(
            Ed25519Scheme::public_key_from_seed(&self.keys[id][..32])
                .unwrap()
                .as_slice(),
            key.public_key
        );
        let payload = vote.signing_payload(&bootstrap.set).unwrap();
        for (signer, old, _) in &self.log {
            if *signer == id && old.view == vote.view && old.phase == vote.phase {
                assert_eq!(
                    old, vote,
                    "honest signer {id} changed its phase/view target"
                );
            }
        }
        let signature = ValidatorSignature {
            validator_id: bootstrap.local_validator.clone(),
            key_id: key.key_id.clone(),
            signature: Ed25519Scheme.sign(&self.keys[id], &payload).unwrap(),
        };
        crypto::scheme::verify_signature(
            key.algorithm_id,
            &key.public_key,
            &payload,
            &signature.signature,
        )
        .unwrap();
        self.log.push((id, vote.clone(), signature));
    }

    fn apply(
        &mut self,
        id: usize,
        input: AgreementInput,
    ) -> Result<AgreementTransitionResult, StoreError> {
        let node = self.node(id);
        let result = node
            .session
            .apply(node.session.sequence() + 1, input, |_| Ok(()))?;
        self.release(id, &result);
        Ok(result)
    }

    fn propose(&mut self, id: usize, view: u64, decision: &SlotDecision) {
        self.apply(id, proposal(view, decision)).unwrap();
    }

    fn advance(&mut self, id: usize, from: u64) {
        self.apply(
            id,
            AgreementInput::AdvanceView {
                from: AgreementView(from),
            },
        )
        .unwrap();
    }

    fn deliver(&mut self, id: usize, qc: &AgreementQc) -> AgreementTransitionResult {
        self.apply(id, AgreementInput::Evidence { qc: qc.clone() })
            .unwrap()
    }

    fn quorum(
        &self,
        view: u64,
        phase: AgreementPhase,
        value: AgreementValue,
    ) -> Option<AgreementQc> {
        let matching: Vec<_> = self
            .log
            .iter()
            .filter(|(_, vote, _)| {
                vote.view == AgreementView(view) && vote.phase == phase && vote.value == value
            })
            .collect();
        let first = matching.first()?;
        let mut signatures: Vec<_> = matching
            .iter()
            .map(|(_, _, signature)| signature.clone())
            .collect();
        signatures.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
        // Retransmitted signatures cannot count as additional quorum members.
        signatures.dedup_by(|a, b| a.validator_id == b.validator_id);
        let qc = AgreementQc {
            vote: first.1.clone(),
            signatures,
        };
        qc.verify(&self.bootstraps[0].context, &self.bootstraps[0].set)
            .ok()?;
        Some(qc)
    }

    fn restart(&mut self, id: usize) {
        assert!(
            Store::open(&self.roots[id]).is_err(),
            "live node must retain OS lock"
        );
        let Node { store, session } = self.nodes[id].take().unwrap();
        drop(store);
        assert!(
            Store::open(&self.roots[id]).is_err(),
            "session clone must retain OS lock"
        );
        drop(session);
        let store = Store::open(&self.roots[id]).expect("all owners dropped: OS lock released");
        let session = store
            .recover_slot_agreement(self.bootstraps[id].clone(), |_| Ok(()))
            .unwrap();
        self.nodes[id] = Some(Node { store, session });
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.nodes.clear();
        for root in &self.roots {
            let _ = fs::remove_dir_all(root);
        }
    }
}

fn proposal(view: u64, decision: &SlotDecision) -> AgreementInput {
    AgreementInput::Propose {
        view: AgreementView(view),
        decision: decision.clone(),
        pol: None,
    }
}
// Synthetic alternative only: this does not establish a valid elected-leader Skip.
fn conflict(decision: &SlotDecision) -> SlotDecision {
    let mut other = decision.clone();
    other.outcome = SlotOutcome::Skip {
        leader_author: vec![1],
    };
    other
}
fn failure() -> StoreError {
    std::io::Error::other("injected WAL failure").into()
}
fn barrier(file: &File, root: &Path) -> Result<(), StoreError> {
    file.sync_all()?;
    slot_decision_journal::sync_ancestors(root, |directory| File::open(directory)?.sync_all())?;
    Ok(())
}

#[test]
fn synthetic_durable_signing_split_restart_and_delayed_commit_converge() {
    let mut h = Harness::new();
    let d = h.decision.clone();
    let other = conflict(&d);
    for id in 0..4 {
        h.propose(id, 0, if id < 2 { &d } else { &other });
    }
    for value in [&d, &other] {
        assert!(
            h.quorum(
                0,
                AgreementPhase::Prevote,
                AgreementValue::Decision(value.clone())
            )
            .is_none()
        );
    }
    for id in 0..4 {
        h.apply(
            id,
            AgreementInput::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Precommit,
            },
        )
        .unwrap();
    }
    assert!(
        h.quorum(0, AgreementPhase::Precommit, AgreementValue::Nil)
            .is_some()
    );
    for id in 0..4 {
        h.advance(id, 0);
        h.propose(id, 1, &d);
    }
    let pol = h
        .quorum(
            1,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        )
        .unwrap();
    for id in [2, 0, 3, 1] {
        h.deliver(id, &pol);
        h.restart(id); // Lock and precommit were one durable event.
        assert!(
            h.apply(
                id,
                AgreementInput::Timeout {
                    view: AgreementView(1),
                    phase: AgreementPhase::Precommit
                }
            )
            .is_err()
        );
    }
    let commit = h
        .quorum(
            1,
            AgreementPhase::Precommit,
            AgreementValue::Decision(d.clone()),
        )
        .unwrap();
    h.advance(3, 1);
    h.restart(3);
    for id in [1, 3, 0, 2] {
        assert_eq!(h.deliver(id, &commit).decision, Some(d.clone()));
    }
    assert_eq!(h.log.len(), 16);
}

#[test]
fn synthetic_durable_signing_io_failures_release_nothing_and_retry_rebarriers() {
    for write_failure in [false, true] {
        let mut h = Harness::new();
        let input = proposal(0, &h.decision);
        let result = h.node(0).session.apply_with_io(
            1,
            input.clone(),
            |_| Ok(()),
            |file, bytes| {
                if write_failure {
                    return Err(failure());
                }
                file.write_all(bytes)?;
                Ok(())
            },
            |_, _| Err(failure()),
        );
        assert!(result.is_err());
        assert!(h.log.is_empty());
        assert!(
            h.apply(0, input.clone()).is_err(),
            "uncertain owner is fenced"
        );
        h.restart(0);
        let sequence = h.node(0).session.sequence();
        assert_eq!(sequence, u64::from(!write_failure));
        let mut barriers = 0;
        let result = h
            .node(0)
            .session
            .apply_with_barrier(
                1,
                input.clone(),
                |_| Ok(()),
                |file, root| {
                    barriers += 1;
                    barrier(file, root)
                },
            )
            .unwrap();
        if write_failure {
            assert_eq!(
                barriers, 1,
                "zero-write recovery requires a new append and full barrier"
            );
        } else {
            assert_eq!(
                barriers, 1,
                "complete-record exact retry must repeat the full barrier"
            );
        }
        h.release(0, &result);
        let retry = h.node(0).session.apply(1, input, |_| Ok(())).unwrap();
        assert_eq!(retry.vote, result.vote);
        h.release(0, &retry);
        assert_eq!(
            h.log.len(),
            2,
            "both successful results are signed and published"
        );
        assert_eq!(
            h.log[0], h.log[1],
            "retries reproduce the same signed statement"
        );
    }
}

#[test]
fn synthetic_durable_signing_torn_write_releases_nothing_and_fails_closed() {
    let mut h = Harness::new();
    let input = proposal(0, &h.decision);
    let result = h.node(0).session.apply_with_io(
        1,
        input.clone(),
        |_| Ok(()),
        |file, bytes| {
            file.write_all(&bytes[..bytes.len() / 2])?;
            Err(failure())
        },
        barrier,
    );
    assert!(result.is_err());
    assert!(h.log.is_empty());
    assert!(h.apply(0, input).is_err());
    drop(h.nodes[0].take());
    assert!(
        Store::open(&h.roots[0]).is_err(),
        "torn WAL must not recover a signable session"
    );
    assert!(h.log.is_empty());
}

#[test]
fn synthetic_durable_signing_sync_before_sign_crash_recovers_exact_last_result() {
    let mut h = Harness::new();
    let input = proposal(0, &h.decision);
    let before = h
        .node(0)
        .session
        .apply(1, input.clone(), |_| Ok(()))
        .unwrap();
    assert!(h.log.is_empty(), "crash before release");
    h.restart(0);
    let mut barriers = 0;
    let after = h
        .node(0)
        .session
        .apply_with_barrier(
            1,
            input,
            |_| Ok(()),
            |file, root| {
                barriers += 1;
                barrier(file, root)
            },
        )
        .unwrap();
    assert_eq!(barriers, 1);
    assert_eq!(after.vote, before.vote);
    assert_eq!(after.view, before.view);
    assert_eq!(after.decision, before.decision);
    h.release(0, &after);
    h.release(0, &after);
    assert_eq!(
        h.log.len(),
        2,
        "repeated release is allowed, not exactly-once signing"
    );
    assert_eq!(h.log[0], h.log[1]);
}

#[test]
fn synthetic_durable_signing_nonnil_lock_sync_before_sign_recovers_precommit() {
    let mut h = Harness::new();
    let d = h.decision.clone();
    for id in 0..3 {
        h.propose(id, 0, &d);
    }
    let pol = h
        .quorum(
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        )
        .unwrap();
    let input = AgreementInput::Evidence { qc: pol };
    let sequence = h.node(0).session.sequence() + 1;
    // Persist the atomic lock/precommit event, but crash before invoking the signer.
    let before = h
        .node(0)
        .session
        .apply(sequence, input.clone(), |_| Ok(()))
        .unwrap();
    let vote = before.vote.as_ref().unwrap();
    assert_eq!(vote.phase, AgreementPhase::Precommit);
    assert_eq!(vote.value, AgreementValue::Decision(d.clone()));
    assert_eq!(h.log.len(), 3, "only prevotes have been signed");
    assert!(
        h.quorum(
            0,
            AgreementPhase::Precommit,
            AgreementValue::Decision(d.clone())
        )
        .is_none()
    );
    h.restart(0);
    assert_eq!(h.node(0).session.sequence(), sequence);
    let mut barriers = 0;
    let after = h
        .node(0)
        .session
        .apply_with_barrier(
            sequence,
            input.clone(),
            |_| Ok(()),
            |file, root| {
                barriers += 1;
                barrier(file, root)
            },
        )
        .unwrap();
    assert_eq!(
        barriers, 1,
        "recovered exact lock/precommit retry repeats full barrier"
    );
    assert_eq!(after.vote, before.vote);
    assert_eq!(after.view, before.view);
    assert_eq!(after.decision, before.decision);
    assert_eq!(
        h.node(0).session.sequence(),
        sequence,
        "exact retry is not a new append"
    );
    h.release(0, &after);
    let retry = h
        .node(0)
        .session
        .apply(sequence, input, |_| Ok(()))
        .unwrap();
    h.release(0, &retry);
    assert_eq!(h.log.len(), 5);
    assert_eq!(
        h.log[3], h.log[4],
        "repeated signing publishes only the same precommit statement"
    );
    assert!(
        h.quorum(
            0,
            AgreementPhase::Precommit,
            AgreementValue::Decision(d.clone())
        )
        .is_none(),
        "two publications by one signer are not a quorum"
    );
    h.advance(0, 0);
    h.restart(0);
    let count = h.log.len();
    assert!(
        h.apply(0, proposal(1, &conflict(&d))).is_err(),
        "lock survives the unsigned crash window and a later-view restart"
    );
    assert_eq!(
        h.log.len(),
        count,
        "rejected conflict releases no signature"
    );
    h.propose(0, 1, &d);
}

#[test]
fn synthetic_durable_signing_byzantine_equivocation_withholding_and_delayed_views_preserve_lock() {
    let mut h = Harness::new();
    let d = h.decision.clone();
    let other = conflict(&d);
    // Signer 3 withholds: the three honest durable votes alone can form a QC.
    for id in 0..3 {
        h.propose(id, 0, &d);
    }
    let pol = h
        .quorum(
            0,
            AgreementPhase::Prevote,
            AgreementValue::Decision(d.clone()),
        )
        .unwrap();
    for id in 0..3 {
        h.deliver(id, &pol);
        h.restart(id);
        h.advance(id, 0);
    }
    // Adversarial signatures are not entered in the external oracle log or used by quorum().
    let mut adversarial = pol.clone();
    adversarial.vote.value = AgreementValue::Decision(other.clone());
    let payload = adversarial
        .vote
        .signing_payload(&h.bootstraps[3].set)
        .unwrap();
    let evil = ValidatorSignature {
        validator_id: vec![3],
        key_id: vec![3],
        signature: Ed25519Scheme.sign(&h.keys[3], &payload).unwrap(),
    };
    let pinned_key = &h.bootstraps[3].set.validators[3].keys[0];
    crypto::scheme::verify_signature(
        ALG_ED25519,
        &pinned_key.public_key,
        &payload,
        &evil.signature,
    )
    .unwrap();
    let original_payload = pol.vote.signing_payload(&h.bootstraps[3].set).unwrap();
    let equivocation = Ed25519Scheme.sign(&h.keys[3], &original_payload).unwrap();
    crypto::scheme::verify_signature(
        ALG_ED25519,
        &pinned_key.public_key,
        &original_payload,
        &equivocation,
    )
    .unwrap();
    assert!(
        crypto::scheme::verify_signature(
            ALG_ED25519,
            &pinned_key.public_key,
            &payload,
            &equivocation
        )
        .is_err(),
        "signature binds exact payload"
    );
    assert!(
        crypto::scheme::verify_signature(
            ALG_ED25519,
            &h.bootstraps[0].set.validators[0].keys[0].public_key,
            &payload,
            &evil.signature
        )
        .is_err(),
        "signature binds pinned identity key"
    );
    adversarial.signatures = vec![evil];
    assert!(
        adversarial
            .verify(&h.bootstraps[0].context, &h.bootstraps[0].set)
            .is_err()
    );
    for id in 0..3 {
        let count = h.log.len();
        assert!(
            h.apply(
                id,
                AgreementInput::Evidence {
                    qc: adversarial.clone()
                }
            )
            .is_err()
        );
        assert!(
            h.apply(id, proposal(1, &other)).is_err(),
            "recovered honest lock rejects conflict"
        );
        assert_eq!(h.log.len(), count);
        assert!(
            h.deliver(id, &pol).vote.is_none(),
            "delayed prevote QC cannot emit in newer view"
        );
        h.propose(id, 1, &d);
    }
    assert!(
        h.quorum(1, AgreementPhase::Prevote, AgreementValue::Decision(other))
            .is_none()
    );
    let commit = h
        .quorum(
            0,
            AgreementPhase::Precommit,
            AgreementValue::Decision(d.clone()),
        )
        .unwrap();
    for id in 0..3 {
        assert_eq!(h.deliver(id, &commit).decision, Some(d.clone()));
    }
    assert!(h.log.iter().all(|(id, _, _)| *id != 3));
}
