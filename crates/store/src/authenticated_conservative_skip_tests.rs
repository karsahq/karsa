use super::*;
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use crypto::scheme::Ed25519Scheme;
use validator::slot_agreement::{AgreementPhase, AgreementView};
use validator::{
    Fence, FenceCertificate, SlotAgreementProofEntry, SlotAgreementViewLineage,
    SlotAgreementVotePayload, SlotAgreementVoteWitness, SlotProposalEnvelope, SlotProposalEvidence,
    ValidatorSignature,
};

fn fixture(
    signed_votes: usize,
    known: usize,
    fenced: Option<usize>,
    invalid_fence: bool,
) -> (
    Fixture,
    SlotAgreementViewLineage,
    AuthenticatedSlotAgreementBootstrap,
) {
    let mut f = Fixture::new(false);
    f.vertices.retain(|v| v.round <= 1);
    let target = f
        .vertices
        .iter()
        .find(|v| {
            v.round == 1
                && v.author
                    == match &f.payload.proposal.decision.outcome {
                        validator::SlotOutcome::Skip { leader_author } => leader_author.clone(),
                        _ => unreachable!(),
                    }
        })
        .unwrap()
        .id()
        .unwrap();
    let refs: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == 1)
        .map(|v| v.id().unwrap())
        .collect();
    let mut voters = Vec::new();
    for id in 0..4 {
        let references = refs
            .iter()
            .filter(|v| id < signed_votes || **v != target)
            .cloned()
            .collect();
        let v = signed_vertex(&f.keys, id, 2, references, [2; 32]);
        voters.push(v.id().unwrap());
        f.vertices.push(v);
    }
    let fences = fenced
        .map(|id| {
            let fence = Fence::new(
                b"slot-store-tests".to_vec(),
                2,
                f.set.validators[id].validator_id.clone(),
            );
            let bytes = fence.signing_payload().unwrap();
            let mut certificate = FenceCertificate {
                fence,
                signer_bitmap: vec![0b111],
                signatures: (0..3)
                    .map(|i| Ed25519Scheme.sign(&f.keys[i], &bytes).unwrap())
                    .collect(),
            };
            if invalid_fence {
                certificate.signatures[0][0] ^= 1;
            }
            certificate
        })
        .into_iter()
        .collect();
    let proposal = SlotProposalEnvelope {
        decision: f.payload.proposal.decision.clone(),
        evidence: SlotProposalEvidence::ConservativeSkip {
            voters: voters[..known].to_vec(),
            missing: voters[known..].iter().map(|v| v.author.clone()).collect(),
            fences,
        },
    };
    assert_eq!(
        SlotProposalEnvelope::decode(&proposal.encode().unwrap()).unwrap(),
        proposal
    );
    let mut proposal_carrier = None;
    for id in 0..4 {
        let hash = if id == 0 {
            proposal.digest().unwrap()
        } else {
            [3; 32]
        };
        let v = signed_vertex(&f.keys, id, 3, voters.clone(), hash);
        if id == 0 {
            proposal_carrier = Some(v.id().unwrap());
        }
        f.vertices.push(v);
    }
    let carrier = proposal_carrier.unwrap();
    let mut lineage = SlotAgreementViewLineage {
        entries: vec![SlotAgreementProofEntry {
            proposal,
            proposal_carrier: carrier.clone(),
            view: AgreementView(0),
            view_carrier: carrier,
            previous_pol: None,
            pol: None,
        }],
    };
    let proposer = validator::slot_agreement_view_proposer(&f.set, 1, AgreementView(0)).unwrap();
    let refs = f
        .vertices
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect::<Vec<_>>();
    for id in 0..4 {
        let hash = if f.set.validators[id].validator_id == proposer {
            lineage.view_digest(0).unwrap()
        } else {
            [4; 32]
        };
        let v = signed_vertex(&f.keys, id, 4, refs.clone(), hash);
        if v.author == proposer {
            lineage.entries[0].view_carrier = v.id().unwrap();
        }
        f.vertices.push(v);
    }
    let bootstrap = AuthenticatedSlotAgreementBootstrap {
        agreement: SlotAgreementBootstrap {
            context: f.binding.tip().clone(),
            set: f.set.clone(),
            local_validator: f.set.validators[0].validator_id.clone(),
        },
        predecessor: None,
        order: vec![],
        vertices: vec![],
    };
    (f, lineage, bootstrap)
}

#[test]
fn conservative_skip_rejects_counted_fenced_vote_unknowns_and_invalid_fence_before_append() {
    // A fenced signed vote still counts: 1 signed + 2 unknown reaches quorum.
    // A fenced unknown still counts: 0 signed + 3 unknown reaches quorum.
    for (signed, known, fenced, invalid) in [
        (1, 2, Some(0), false),
        (0, 1, Some(3), false),
        (0, 2, Some(3), true),
    ] {
        let (f, lineage, bootstrap) = fixture(signed, known, fenced, invalid);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store.begin_authenticated_slot_agreement(bootstrap).unwrap();
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let before = fs::read(&path).unwrap();
        assert!(
            owner
                .apply(
                    1,
                    AuthenticatedSlotAgreementRequest::Propose {
                        lineage,
                        vertices: f.vertices
                    }
                )
                .is_err()
        );
        assert_eq!(owner.sequence(), 0);
        assert_eq!(fs::read(path).unwrap(), before);
    }
}

#[test]
fn conservative_skip_durable_signers_driver_recovery_advance_and_explicit_replay() {
    for fenced in [None, Some(3)] {
        let (mut f, mut lineage, bootstrap) = fixture(0, 2, fenced, false);
        let dirs = (0..3).map(|_| TempDir::new()).collect::<Vec<_>>();
        let stores = dirs
            .iter()
            .map(|d| Store::open(&d.0).unwrap())
            .collect::<Vec<_>>();
        let bootstraps = (0..3)
            .map(|id| {
                let mut b = bootstrap.clone();
                b.agreement.local_validator = f.set.validators[id].validator_id.clone();
                b
            })
            .collect::<Vec<_>>();
        let mut owners = stores
            .iter()
            .zip(&bootstraps)
            .map(|(s, b)| {
                SlotAgreementDriver::new(s.begin_authenticated_slot_agreement(b.clone()).unwrap())
            })
            .collect::<Vec<_>>();
        let propose = AuthenticatedSlotAgreementRequest::Propose {
            lineage: lineage.clone(),
            vertices: f.vertices.clone(),
        };
        let mut outputs = owners
            .iter_mut()
            .map(|o| o.apply(1, propose.clone()).unwrap())
            .collect::<Vec<_>>();
        let mut final_proof = None;
        for (round, phase) in [(5, AgreementPhase::Prevote), (7, AgreementPhase::Precommit)] {
            let prerequisite = if round == 5 {
                lineage.entries[0].view_carrier.clone()
            } else {
                lineage.entries[0].pol.as_ref().unwrap().carrier.clone()
            };
            let refs = f
                .vertices
                .iter()
                .filter(|v| v.round == round - 1)
                .map(|v| v.id().unwrap())
                .collect::<Vec<_>>();
            let mut witnesses = Vec::new();
            let mut next = Vec::new();
            for id in 0..3 {
                // Sign only this validator's own returned, durable intent.
                let vote = outputs[id]
                    .transition
                    .as_ref()
                    .unwrap()
                    .vote
                    .clone()
                    .unwrap();
                assert_eq!(vote.phase, phase);
                assert!(owners[id].sequence() > 0);
                let signature = ValidatorSignature {
                    validator_id: f.set.validators[id].validator_id.clone(),
                    key_id: f.set.validators[id].keys[0].key_id.clone(),
                    signature: Ed25519Scheme
                        .sign(&f.keys[id], &vote.signing_payload(&f.set).unwrap())
                        .unwrap(),
                };
                let payload = SlotAgreementVotePayload {
                    vote,
                    signature,
                    prerequisite: prerequisite.clone(),
                };
                let v = signed_vertex(
                    &f.keys,
                    id,
                    round,
                    refs.clone(),
                    payload.digest(&f.set).unwrap(),
                );
                let carrier = v.id().unwrap();
                next.push(carrier.clone());
                witnesses.push(SlotAgreementVoteWitness { payload, carrier });
                f.vertices.push(v);
            }
            for (index, witness) in witnesses.into_iter().enumerate() {
                for (owner, output) in owners.iter_mut().zip(&mut outputs) {
                    *output = owner
                        .apply(
                            owner.sequence() + 1,
                            AuthenticatedSlotAgreementRequest::ObserveVote {
                                lineage: lineage.clone(),
                                witness: witness.clone(),
                                vertices: f.vertices.clone(),
                            },
                        )
                        .unwrap();
                    if index < 2 {
                        assert!(output.candidates.iter().all(|c| !matches!(
                            (phase, c),
                            (
                                AgreementPhase::Prevote,
                                SlotAgreementCarrierCandidate::PendingPol(_)
                            ) | (
                                AgreementPhase::Precommit,
                                SlotAgreementCarrierCandidate::PendingFinalProof(_)
                            )
                        )));
                    }
                }
            }
            let output = outputs.remove(0);
            if round == 5 {
                let pending = output
                    .candidates
                    .into_iter()
                    .find_map(|c| match c {
                        SlotAgreementCarrierCandidate::PendingPol(p) => Some(p),
                        _ => None,
                    })
                    .unwrap();
                let v = signed_vertex(&f.keys, 0, 6, next.clone(), pending.digest());
                lineage = pending.bind_carrier(v.id().unwrap());
                f.vertices.push(v);
                for id in 1..3 {
                    f.vertices
                        .push(signed_vertex(&f.keys, id, 6, next.clone(), [6; 32]));
                }
                outputs = owners
                    .iter_mut()
                    .map(|o| {
                        o.apply(
                            o.sequence() + 1,
                            AuthenticatedSlotAgreementRequest::ObservePrevote {
                                lineage: lineage.clone(),
                                vertices: f.vertices.clone(),
                            },
                        )
                        .unwrap()
                    })
                    .collect();
            } else {
                let proof = output
                    .candidates
                    .into_iter()
                    .find_map(|c| match c {
                        SlotAgreementCarrierCandidate::PendingFinalProof(p) => Some(p),
                        _ => None,
                    })
                    .unwrap();
                let v = signed_vertex(&f.keys, 0, 8, next, proof.digest(&f.set).unwrap());
                let carrier = v.id().unwrap();
                f.vertices.push(v);
                for owner in &mut owners {
                    let output = owner
                        .apply(
                            owner.sequence() + 1,
                            AuthenticatedSlotAgreementRequest::ObservePrecommit {
                                proof: proof.clone(),
                                carrier: carrier.clone(),
                                vertices: f.vertices.clone(),
                            },
                        )
                        .unwrap();
                    assert_eq!(
                        output.transition.unwrap().decision,
                        Some(f.payload.proposal.decision.clone())
                    );
                    assert!(output.candidates.is_empty());
                }
                final_proof = Some((proof, carrier));
            }
        }
        drop(lineage);
        drop(outputs);
        drop(owners);
        drop(stores);
        // No external lineage or ordinary vertex log is needed to recover finalization.
        for (dir, b) in dirs.iter().zip(bootstraps) {
            let store = Store::open(&dir.0).unwrap();
            assert!(store.vertices().unwrap().is_empty());
            let path = dir.0.join(authenticated_slot_agreement::FILE);
            let bytes = fs::read(&path).unwrap();
            let mut owner = store
                .recover_authenticated_slot_agreement(b.clone())
                .unwrap();
            let output = SlotAgreementDriver::new(
                store
                    .recover_authenticated_slot_agreement(b.clone())
                    .unwrap(),
            )
            .output()
            .unwrap();
            assert_eq!(
                output.transition.unwrap().decision,
                Some(f.payload.proposal.decision.clone())
            );
            assert_eq!(fs::read(&path).unwrap(), bytes);
            owner.advance_slot(owner.sequence() + 1).unwrap();
            let sequence = owner.sequence();
            drop(owner);
            drop(store);
            let store = Store::open(&dir.0).unwrap();
            assert_eq!(
                store
                    .recover_authenticated_slot_agreement(b)
                    .unwrap()
                    .sequence(),
                sequence
            );
        }
        let (proof, carrier) = final_proof.unwrap();
        let store = Store::open(&dirs[0].0).unwrap();
        f.persist(&store);
        let mut state = f.state(store.vertices().unwrap());
        let root = state.dag().commit_root();
        let order = state.dag().order().to_vec();
        assert_eq!(state.binding(), &f.binding);
        store
            .apply_slot_agreement(&mut state, &proof, &carrier)
            .unwrap();
        assert_eq!(state.dag().order(), order);
        assert_eq!(state.dag().commit_root(), root);
        assert_eq!(state.binding().tip().next_round(), 2);
        let expected = state.binding().clone();
        drop(state);
        drop(store);
        let store = Store::open(&dirs[0].0).unwrap();
        let mut state = f.state(store.vertices().unwrap());
        assert_eq!(store.replay_slot_applications(&mut state).unwrap().len(), 1);
        assert_eq!(state.binding(), &expected);
        assert_eq!(state.dag().order(), order);
        assert_eq!(state.dag().commit_root(), root);
        assert!(
            store
                .replay_slot_applications(&mut state)
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            store
                .apply_slot_agreement(&mut state, &proof, &carrier)
                .unwrap(),
            validator::SlotApplicationResult::AlreadyApplied { round: 1 }
        );
    }
}
