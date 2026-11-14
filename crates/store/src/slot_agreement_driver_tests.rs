use super::*;
use crate::authenticated_slot_agreement_tests::fixture;
use crate::slot_application_tests::{TempDir, signed_vertex};
use crypto::scheme::Ed25519Scheme;
use validator::{SlotAgreementVotePayload, SlotAgreementVoteWitness, ValidatorSignature};

#[test]
fn driver_rejects_stale_and_uncertain_output() {
    let (_, _, bootstrap) = fixture(false);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let stale = SlotAgreementDriver::new(
        store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap(),
    );
    let request = AuthenticatedSlotAgreementRequest::Timeout {
        view: validator::slot_agreement::AgreementView(0),
        phase: validator::slot_agreement::AgreementPhase::Prevote,
    };
    owner.apply(1, request).unwrap();
    assert!(stale.output().is_err());
    let request = AuthenticatedSlotAgreementRequest::AdvanceView {
        from: validator::slot_agreement::AgreementView(0),
    };
    assert!(
        owner
            .apply_with_io(
                2,
                request,
                |file, bytes| {
                    file.write_all(bytes)?;
                    Ok(())
                },
                |_, _| Err(std::io::Error::other("injected barrier failure").into())
            )
            .is_err()
    );
    let uncertain = SlotAgreementDriver::new(owner);
    assert!(uncertain.output().is_err());
    let recovered = SlotAgreementDriver::new(
        store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap(),
    );
    assert!(recovered.output().is_ok());
}

#[test]
fn driver_signed_commit_and_skip() {
    for commit in [true, false] {
        let (mut f, mut lineage, bootstrap) = fixture(commit);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut driver = SlotAgreementDriver::new(
            store
                .begin_authenticated_slot_agreement(bootstrap.clone())
                .unwrap(),
        );
        let mut output = driver
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage: lineage.clone(),
                    vertices: f.vertices.clone(),
                },
            )
            .unwrap();
        let mut sequence = 1;
        let mut final_proof = None;
        for (round, phase) in [
            (5, validator::slot_agreement::AgreementPhase::Prevote),
            (7, validator::slot_agreement::AgreementPhase::Precommit),
        ] {
            let vote = output.transition.as_ref().unwrap().vote.clone().unwrap();
            assert_eq!(vote.phase, phase);
            let prerequisite = if round == 5 {
                lineage.entries[0].view_carrier.clone()
            } else {
                lineage.entries[0].pol.as_ref().unwrap().carrier.clone()
            };
            let refs: Vec<_> = f
                .vertices
                .iter()
                .filter(|v| v.round == round - 1)
                .map(|v| v.id().unwrap())
                .collect();
            let mut next = Vec::new();
            for id in 0..3 {
                let signature = ValidatorSignature {
                    validator_id: f.set.validators[id].validator_id.clone(),
                    key_id: f.set.validators[id].keys[0].key_id.clone(),
                    signature: Ed25519Scheme
                        .sign(&f.keys[id], &vote.signing_payload(&f.set).unwrap())
                        .unwrap(),
                };
                let payload = SlotAgreementVotePayload {
                    vote: vote.clone(),
                    signature,
                    prerequisite: prerequisite.clone(),
                };
                let vertex = signed_vertex(
                    &f.keys,
                    id,
                    round,
                    refs.clone(),
                    payload.digest(&f.set).unwrap(),
                );
                let carrier = vertex.id().unwrap();
                next.push(carrier.clone());
                f.vertices.push(vertex);
                sequence += 1;
                output = driver
                    .apply(
                        sequence,
                        AuthenticatedSlotAgreementRequest::ObserveVote {
                            lineage: lineage.clone(),
                            witness: SlotAgreementVoteWitness { payload, carrier },
                            vertices: f.vertices.clone(),
                        },
                    )
                    .unwrap();
                if id < 2 {
                    assert!(output.candidates.iter().all(|c| !matches!(
                        (round, c),
                        (5, SlotAgreementCarrierCandidate::PendingPol(_))
                            | (7, SlotAgreementCarrierCandidate::PendingFinalProof(_))
                    )));
                }
            }
            drop(driver);
            driver = SlotAgreementDriver::new(
                store
                    .recover_authenticated_slot_agreement(bootstrap.clone())
                    .unwrap(),
            );
            let recovered = driver.output().unwrap();
            assert_eq!(format!("{:?}", output), format!("{:?}", recovered));
            if round == 5 {
                let pending = output
                    .candidates
                    .into_iter()
                    .find_map(|c| match c {
                        SlotAgreementCarrierCandidate::PendingPol(p) => Some(p),
                        _ => None,
                    })
                    .unwrap();
                let vertex = signed_vertex(&f.keys, 0, 6, next.clone(), pending.digest());
                lineage = pending.bind_carrier(vertex.id().unwrap());
                f.vertices.push(vertex);
                for id in 1..3 {
                    f.vertices
                        .push(signed_vertex(&f.keys, id, 6, next.clone(), [9; 32]));
                }
                sequence += 1;
                output = driver
                    .apply(
                        sequence,
                        AuthenticatedSlotAgreementRequest::ObservePrevote {
                            lineage: lineage.clone(),
                            vertices: f.vertices.clone(),
                        },
                    )
                    .unwrap();
                assert!(output.transition.as_ref().unwrap().decision.is_none());
            } else {
                let proof = output
                    .candidates
                    .into_iter()
                    .find_map(|c| match c {
                        SlotAgreementCarrierCandidate::PendingFinalProof(p) => Some(p),
                        _ => None,
                    })
                    .unwrap();
                let vertex = signed_vertex(&f.keys, 0, 8, next, proof.digest(&f.set).unwrap());
                let carrier = vertex.id().unwrap();
                f.vertices.push(vertex);
                sequence += 1;
                output = driver
                    .apply(
                        sequence,
                        AuthenticatedSlotAgreementRequest::ObservePrecommit {
                            proof: proof.clone(),
                            carrier: carrier.clone(),
                            vertices: f.vertices.clone(),
                        },
                    )
                    .unwrap();
                assert!(output.transition.as_ref().unwrap().decision.is_some());
                assert!(output.candidates.is_empty());
                final_proof = Some((proof, carrier));
            }
        }
        f.persist(&store);
        let mut state = f.state(store.vertices().unwrap());
        assert!(state.dag().order().is_empty());
        let (proof, carrier) = final_proof.unwrap();
        store
            .apply_slot_agreement(&mut state, &proof, &carrier)
            .unwrap();
        assert_eq!(state.binding().tip().next_round(), 2);
        drop(driver);
        drop(store);
        let reopened = Store::open(&dir.0).unwrap();
        let mut replayed = f.state(reopened.vertices().unwrap());
        reopened.replay_slot_applications(&mut replayed).unwrap();
        assert_eq!(replayed.binding(), state.binding());
        assert_eq!(replayed.dag().commit_root(), state.dag().commit_root());
    }
}
