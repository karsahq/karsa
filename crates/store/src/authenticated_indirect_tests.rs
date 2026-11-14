use super::*;
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use crypto::scheme::Ed25519Scheme;
use validator::{Dag, SlotDecisionTip, ValidatorSignature, VertexId};

fn append_indirect_proof(
    f: &mut Fixture,
    proposal: validator::SlotProposalEnvelope,
    proposal_carrier: VertexId,
    context: SlotDecisionTip,
    first_round: u64,
) -> (validator::SlotAgreementProof, VertexId) {
    use validator::slot_agreement::{
        AgreementPhase, AgreementQc, AgreementValue, AgreementView, AgreementVote,
    };
    use validator::{
        SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol,
        SlotAgreementVotePayload, SlotAgreementVoteWitness,
    };
    f.vertices.retain(|v| v.round < first_round);
    let qc = |phase| {
        let vote = AgreementVote {
            context: context.clone(),
            view: AgreementView(0),
            phase,
            value: AgreementValue::Decision(proposal.decision.clone()),
        };
        let bytes = vote.signing_payload(&f.set).unwrap();
        let signatures = (0..3)
            .map(|i| ValidatorSignature {
                validator_id: f.set.validators[i].validator_id.clone(),
                key_id: f.set.validators[i].keys[0].key_id.clone(),
                signature: Ed25519Scheme.sign(&f.keys[i], &bytes).unwrap(),
            })
            .collect();
        AgreementQc { vote, signatures }
    };
    let prevote = qc(AgreementPhase::Prevote);
    let mut proof = SlotAgreementProof {
        entries: vec![SlotAgreementProofEntry {
            proposal: proposal.clone(),
            proposal_carrier,
            view: AgreementView(0),
            view_carrier: f.carrier.clone(),
            previous_pol: None,
            pol: None,
        }],
        certificate: qc(AgreementPhase::Precommit),
        votes: vec![],
    };
    let mut refs: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == first_round - 1)
        .map(|v| v.id().unwrap())
        .collect();
    let proposer =
        validator::slot_agreement_view_proposer(&f.set, proposal.decision.round, AgreementView(0))
            .unwrap();
    let author = f
        .set
        .validators
        .iter()
        .position(|v| v.validator_id == proposer)
        .unwrap();
    for offset in 0..=4 {
        let round = first_round + offset;
        let mut hashes = [[9; 32]; 4];
        if offset == 0 {
            hashes[author] = proof.view_digest(0).unwrap();
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
                            carrier: f.carrier.clone(),
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
        let mut next = vec![];
        for (i, hash) in hashes.into_iter().enumerate() {
            let v = signed_vertex(&f.keys, i, round, refs.clone(), hash);
            next.push(v.id().unwrap());
            f.vertices.push(v);
        }
        if offset == 0 {
            proof.entries[0].view_carrier = next[author].clone();
        }
        if offset == 2 {
            proof.entries[0].pol.as_mut().unwrap().carrier = next[0].clone();
        }
        refs = next;
    }
    (proof, refs[0].clone())
}

fn fixture() -> (Fixture, validator::SlotAgreementProof, VertexId) {
    let mut f = Fixture::new(true);
    f.vertices.retain(|v| v.round <= 1);
    let target = match &f.payload.proposal.decision.outcome {
        validator::SlotOutcome::Commit { leader } => leader.clone(),
        _ => unreachable!(),
    };
    let refs: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == 1)
        .map(|v| v.id().unwrap())
        .collect();
    for author in 0..4 {
        let references = refs
            .iter()
            .filter(|id| author == 0 || *id != &target)
            .cloned()
            .collect();
        f.vertices
            .push(signed_vertex(&f.keys, author, 2, references, [2; 32]));
    }
    assert_eq!(
        f.vertices
            .iter()
            .filter(|v| v.round == 2 && v.references.contains(&target))
            .count(),
        1
    );
    assert!(
        1 < f.set.quorum_size(),
        "the target must not have direct quorum"
    );
    for round in 3..=4 {
        let refs = f
            .vertices
            .iter()
            .filter(|v| v.round == round - 1)
            .map(|v| v.id().unwrap())
            .collect::<Vec<_>>();
        for author in 0..4 {
            f.vertices
                .push(signed_vertex(&f.keys, author, round, refs.clone(), [3; 32]));
        }
    }
    let mut dag = Dag::new(f.set.clone());
    dag.set_chain_id(b"slot-store-tests".to_vec());
    for vertex in &f.vertices {
        dag.insert(vertex.clone()).unwrap();
    }
    let anchor = dag.leader(3).unwrap().id().unwrap();
    let support = f
        .vertices
        .iter()
        .filter(|v| v.round == 4)
        .take(3)
        .map(|v| v.id().unwrap())
        .collect();
    let proposal = validator::SlotProposalEnvelope {
        decision: f.payload.proposal.decision.clone(),
        evidence: validator::SlotProposalEvidence::IndirectCommit { anchor, support },
    };
    let refs = f
        .vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect::<Vec<_>>();
    let mut carrier = None;
    for author in 0..4 {
        let hash = if author == 0 {
            proposal.digest().unwrap()
        } else {
            [5; 32]
        };
        let v = signed_vertex(&f.keys, author, 5, refs.clone(), hash);
        if author == 0 {
            carrier = Some(v.id().unwrap());
        }
        f.vertices.push(v);
    }
    let context = f.binding.tip().clone();
    let (proof, carrier) = append_indirect_proof(&mut f, proposal, carrier.unwrap(), context, 6);
    f.carrier = carrier.clone();
    (f, proof, carrier)
}

#[test]
fn authenticated_indirect_proposal_votes_finalization_advance_and_wal_recovery() {
    use validator::SlotAgreementViewLineage;
    use validator::slot_agreement::AgreementPhase;
    let (f, proof, carrier) = fixture();
    let dirs = (0..3).map(|_| TempDir::new()).collect::<Vec<_>>();
    let mut bootstraps = Vec::new();
    for (id, dir) in dirs.iter().enumerate() {
        let bootstrap = AuthenticatedSlotAgreementBootstrap {
            agreement: SlotAgreementBootstrap {
                context: f.binding.tip().clone(),
                set: f.set.clone(),
                local_validator: f.set.validators[id].validator_id.clone(),
            },
            predecessor: None,
            order: vec![],
            vertices: vec![],
        };
        let store = Store::open(&dir.0).unwrap();
        let mut session = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let mut lineage = SlotAgreementViewLineage {
            entries: proof.entries.clone(),
        };
        lineage.entries[0].pol = None;
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let before = fs::read(&path).unwrap();
        for missing in [false, true] {
            let mut bad = lineage.clone();
            let mut vertices = f
                .vertices
                .iter()
                .filter(|v| v.round <= 6)
                .cloned()
                .collect::<Vec<_>>();
            if missing {
                let validator::SlotProposalEvidence::IndirectCommit { support, .. } =
                    &bad.entries[0].proposal.evidence
                else {
                    unreachable!()
                };
                vertices.retain(|v| v.id().unwrap() != support[0]);
            } else {
                let validator::SlotProposalEvidence::IndirectCommit { support, .. } =
                    &mut bad.entries[0].proposal.evidence
                else {
                    unreachable!()
                };
                support[0] = lineage.entries[0].proposal_carrier.clone();
            }
            assert!(
                session
                    .apply(
                        1,
                        AuthenticatedSlotAgreementRequest::Propose {
                            lineage: bad,
                            vertices
                        }
                    )
                    .is_err()
            );
            assert_eq!(session.sequence(), 0);
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        for (sequence, request, certificate) in [
            (
                1,
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage,
                    vertices: f
                        .vertices
                        .iter()
                        .filter(|v| v.round <= 6)
                        .cloned()
                        .collect(),
                },
                &proof.entries[0].pol.as_ref().unwrap().certificate,
            ),
            (
                2,
                AuthenticatedSlotAgreementRequest::ObservePrevote {
                    lineage: SlotAgreementViewLineage {
                        entries: proof.entries.clone(),
                    },
                    vertices: f
                        .vertices
                        .iter()
                        .filter(|v| v.round <= 8)
                        .cloned()
                        .collect(),
                },
                &proof.certificate,
            ),
        ] {
            let result = session.apply(sequence, request.clone()).unwrap();
            let vote = result.vote.as_ref().unwrap();
            assert_eq!(vote, &certificate.vote);
            assert_eq!(
                vote.phase,
                if sequence == 1 {
                    AgreementPhase::Prevote
                } else {
                    AgreementPhase::Precommit
                }
            );
            let signature = Ed25519Scheme
                .sign(&f.keys[id], &vote.signing_payload(&f.set).unwrap())
                .unwrap();
            assert_eq!(signature, certificate.signatures[id].signature);
            let bytes = fs::read(&path).unwrap();
            assert_eq!(session.apply(sequence, request).unwrap(), result);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let result = session
            .apply(
                3,
                AuthenticatedSlotAgreementRequest::ObservePrecommit {
                    proof: proof.clone(),
                    carrier: carrier.clone(),
                    vertices: f.vertices.clone(),
                },
            )
            .unwrap();
        assert_eq!(result.decision.as_ref(), Some(&f.payload.proposal.decision));
        assert!(store.vertices().unwrap().is_empty());
        session.advance_slot(4).unwrap();
        assert_eq!(session.sequence(), 4);
        bootstraps.push(bootstrap);
    }
    drop(f);
    drop(proof);
    drop(carrier);
    for (dir, bootstrap) in dirs.iter().zip(bootstraps) {
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let bytes = fs::read(&path).unwrap();
        let store = Store::open(&dir.0).unwrap();
        assert!(store.vertices().unwrap().is_empty());
        let session = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(session.sequence(), 4);
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}

#[test]
fn indirect_application_target_only_root_and_retained_vertex_restart_replay() {
    let (f, proof, carrier) = fixture();
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    f.persist(&store);
    let mut state = f.state(store.vertices().unwrap());
    store
        .apply_slot_agreement(&mut state, &proof, &carrier)
        .unwrap();
    f.assert_applied(&state);
    assert!(
        state.dag().order().iter().all(|v| v.round <= 1),
        "anchor and support must not enter the committed order"
    );
    assert_eq!(
        state.dag().commit_root(),
        proof.entries[0].proposal.decision.after_root
    );
    let expected = state.binding().clone();
    drop(state);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut state = f.state(store.vertices().unwrap());
    assert_eq!(store.replay_slot_applications(&mut state).unwrap().len(), 1);
    f.assert_applied(&state);
    assert_eq!(state.binding(), &expected);
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
