//! Concrete signed DAG integration, not a live network driver.
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use crate::{SlotAgreementBootstrap, Store};
use crypto::scheme::Ed25519Scheme;
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementValue, AgreementView,
};
use validator::{
    SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol, SlotAgreementVotePayload,
    SlotAgreementVoteWitness, SlotApplicationResult, ValidatorSignature,
};

// Each signature comes only from a successful durable apply. The semantic callback
// pins both the complete proposal and its checkpoint, including during WAL recovery.
fn emitted_qc(f: &Fixture, prevote: Option<&AgreementQc>) -> AgreementQc {
    let state = f.state(f.vertices.clone());
    let proposal = &f.payload.proposal;
    let inspect = |decision: &validator::SlotDecision| {
        assert_eq!(
            decision, &proposal.decision,
            "only the exact proposal is accepted"
        );
        state
            .dag()
            .inspect_slot_proposal(proposal, &f.payload.proposal_carrier, f.binding.tip())
            .map(|_| ())
    };
    let mut votes = Vec::new();
    let mut signatures = Vec::new();
    for id in 0..3 {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let bootstrap = SlotAgreementBootstrap {
            context: f.binding.tip().clone(),
            set: f.set.clone(),
            local_validator: f.set.validators[id].validator_id.clone(),
        };
        let mut session = store.begin_slot_agreement(bootstrap.clone()).unwrap();
        let proposed = session
            .apply(
                1,
                AgreementInput::Propose {
                    view: AgreementView(0),
                    decision: proposal.decision.clone(),
                    pol: None,
                },
                inspect,
            )
            .unwrap();
        let result = if let Some(qc) = prevote {
            let input = AgreementInput::Evidence { qc: qc.clone() };
            let persisted = session.apply(2, input.clone(), inspect).unwrap();
            assert_eq!(
                persisted.vote.as_ref().unwrap().phase,
                AgreementPhase::Precommit
            );
            // Crash window: no signature has been made for the persisted lock.
            drop(session);
            drop(store);
            let reopened = Store::open(&dir.0).unwrap();
            let mut recovered = reopened.recover_slot_agreement(bootstrap, inspect).unwrap();
            assert_eq!(recovered.sequence(), 2);
            let retried = recovered.apply(2, input, inspect).unwrap();
            assert_eq!(retried.vote, persisted.vote);
            assert_eq!(
                recovered.sequence(),
                2,
                "retry must not append another transition"
            );
            retried
        } else {
            proposed
        };
        let vote = result
            .vote
            .expect("durable transition emits the signing statement");
        assert_eq!(vote.context, *f.binding.tip());
        assert_eq!(vote.view, AgreementView(0));
        assert_eq!(
            vote.value,
            AgreementValue::Decision(proposal.decision.clone())
        );
        let key = &f.set.validators[id].keys[0];
        let bytes = vote.signing_payload(&f.set).unwrap();
        let signature = ValidatorSignature {
            validator_id: f.set.validators[id].validator_id.clone(),
            key_id: key.key_id.clone(),
            signature: Ed25519Scheme.sign(&f.keys[id], &bytes).unwrap(),
        };
        crypto::scheme::verify_signature(
            key.algorithm_id,
            &key.public_key,
            &bytes,
            &signature.signature,
        )
        .unwrap();
        votes.push(vote);
        signatures.push(signature);
    }
    assert!(votes.iter().all(|vote| vote == &votes[0]));
    let qc = AgreementQc {
        vote: votes.remove(0),
        signatures,
    };
    qc.verify(f.binding.tip(), &f.set).unwrap();
    qc
}

fn run(commit: bool) {
    let mut f = Fixture::new(commit);
    // Discard the legacy certificate carrier: it is not agreement evidence.
    f.vertices.retain(|v| v.round < 4);
    let prevote = emitted_qc(&f, None);
    assert_eq!(prevote.vote.phase, AgreementPhase::Prevote);
    let mut proof = SlotAgreementProof {
        entries: vec![SlotAgreementProofEntry {
            proposal: f.payload.proposal.clone(),
            proposal_carrier: f.payload.proposal_carrier.clone(),
            view: AgreementView(0),
            view_carrier: f.payload.proposal_carrier.clone(),
            previous_pol: None,
            pol: None,
        }],
        // Replaced by emitted precommits after the POL carrier exists.
        certificate: prevote.clone(),
        votes: vec![],
    };
    let proposer = validator::slot_agreement_view_proposer(&f.set, 1, AgreementView(0)).unwrap();
    let author = f
        .set
        .validators
        .iter()
        .position(|v| v.validator_id == proposer)
        .unwrap();
    let mut refs: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect();
    for offset in 0..=4 {
        let round = 4 + offset;
        let mut hashes = [[9; 32]; 4];
        if offset == 0 {
            hashes[author] = proof.view_digest(0).unwrap();
        }
        if offset == 3 {
            proof.certificate = emitted_qc(&f, Some(&prevote));
            assert_eq!(proof.certificate.vote.phase, AgreementPhase::Precommit);
        }
        if offset == 1 || offset == 3 {
            let certificate = if offset == 1 {
                &prevote
            } else {
                &proof.certificate
            };
            for (i, signature) in certificate.signatures.iter().enumerate() {
                let payload = SlotAgreementVotePayload {
                    vote: certificate.vote.clone(),
                    signature: signature.clone(),
                    prerequisite: if offset == 1 {
                        proof.entries[0].view_carrier.clone()
                    } else {
                        proof.entries[0].pol.as_ref().unwrap().carrier.clone()
                    },
                };
                hashes[i] = payload.digest(&f.set).unwrap();
                let vertex = signed_vertex(&f.keys, i, round, refs.clone(), hashes[i]);
                let witness = SlotAgreementVoteWitness {
                    payload,
                    carrier: vertex.id().unwrap(),
                };
                if offset == 1 {
                    proof.entries[0]
                        .pol
                        .get_or_insert(SlotAgreementProofPol {
                            certificate: prevote.clone(),
                            votes: vec![],
                            carrier: f.payload.proposal_carrier.clone(),
                        })
                        .votes
                        .push(witness);
                } else {
                    proof.votes.push(witness);
                }
            }
        }
        if offset == 2 {
            hashes[0] = proof.pol_digest(0, &f.set).unwrap();
        }
        if offset == 4 {
            hashes[0] = proof.digest(&f.set).unwrap();
        }
        let mut next = Vec::new();
        for (i, hash) in hashes.into_iter().enumerate() {
            let vertex = signed_vertex(&f.keys, i, round, refs.clone(), hash);
            next.push(vertex.id().unwrap());
            f.vertices.push(vertex);
        }
        if offset == 0 {
            proof.entries[0].view_carrier = next[author].clone();
        }
        if offset == 2 {
            proof.entries[0].pol.as_mut().unwrap().carrier = next[0].clone();
        }
        refs = next;
    }
    let carrier = refs[0].clone();
    f.carrier = carrier.clone();
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    f.persist(&store);
    let mut state = f.state(store.vertices().unwrap());
    let mut invalid = proof.clone();
    invalid.certificate.signatures[0].signature[0] ^= 1;
    assert!(
        store
            .apply_slot_agreement(&mut state, &invalid, &carrier)
            .is_err()
    );
    assert_eq!(state.binding(), &f.binding);
    assert!(store.slot_application_requests().unwrap().is_empty());
    assert!(matches!(
        store
            .apply_slot_agreement(&mut state, &proof, &carrier)
            .unwrap(),
        SlotApplicationResult::Applied { round: 1, .. }
    ));
    f.assert_applied(&state);
    let expected = state.binding().clone();
    drop(state);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut recovered = f.state(store.vertices().unwrap());
    assert_eq!(
        store
            .replay_slot_applications(&mut recovered)
            .unwrap()
            .len(),
        1
    );
    f.assert_applied(&recovered);
    assert_eq!(recovered.binding(), &expected);
    assert!(
        store
            .replay_slot_applications(&mut recovered)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        store
            .apply_slot_agreement(&mut recovered, &proof, &carrier)
            .unwrap(),
        SlotApplicationResult::AlreadyApplied { round: 1 }
    );
    assert_eq!(store.slot_application_requests().unwrap().len(), 1);
}

#[test]
fn signed_dag_durable_commit_view_zero_reopen_replay() {
    run(true);
}

#[test]
fn signed_dag_durable_skip_view_zero_reopen_replay() {
    run(false);
}
