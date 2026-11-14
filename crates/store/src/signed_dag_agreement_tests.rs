//! Concrete signed DAG integration, not a live network driver.
//!
//! The semantic callback receives only a decision and captures the latest
//! authenticated lineage supplied to each harness phase. During recovery it
//! rechecks that lineage and decision, but cannot bind each historical WAL event
//! to its exact view/POL. These tests do not establish event-level lineage
//! authentication during recovery.
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use crate::{SlotAgreementBootstrap, Store};
use crypto::scheme::Ed25519Scheme;
use validator::slot_agreement::{
    AgreementInput, AgreementPhase, AgreementQc, AgreementValue, AgreementView,
};
use validator::{
    SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol, SlotAgreementViewLineage,
    SlotAgreementVotePayload, SlotAgreementVoteWitness, SlotApplicationResult, ValidatorSignature,
};

// Each signature comes only from a successful durable apply. The callback checks
// the captured lineage and exact decision, subject to the module-level limitation.
fn emitted_qc(
    f: &Fixture,
    lineage: &SlotAgreementViewLineage,
    prevote: Option<&AgreementQc>,
    dirs: &[TempDir],
    view: AgreementView,
    wrong_pol: Option<&AgreementQc>,
) -> AgreementQc {
    let state = f.state(f.vertices.clone());
    let binding = validator::SlotAgreementBinding::from_checkpoint(
        f.binding.tip().clone(),
        f.binding.carrier().cloned(),
    )
    .unwrap();
    let proposal = &f.payload.proposal;
    let input = state
        .dag()
        .inspect_slot_agreement_view_lineage(lineage, &binding)
        .unwrap();
    let inspect = |decision: &validator::SlotDecision| {
        assert_eq!(
            decision, &proposal.decision,
            "only the exact proposal is accepted"
        );
        state
            .dag()
            .inspect_slot_agreement_view_lineage(lineage, &binding)
            .map(|_| ())
    };
    let mut votes = Vec::new();
    let mut signatures = Vec::new();
    let members = if view.0 == 0 { 0..3 } else { 1..4 };
    for id in members {
        let dir = &dirs[id];
        let store = Store::open(&dir.0).unwrap();
        let bootstrap = SlotAgreementBootstrap {
            context: f.binding.tip().clone(),
            set: f.set.clone(),
            local_validator: f.set.validators[id].validator_id.clone(),
        };
        if prevote.is_some() || (view.0 > 0 && id < 3) {
            let mut unauthenticated = lineage.clone();
            let carrier = &lineage.entries.last().unwrap().view_carrier;
            let original = f
                .vertices
                .iter()
                .find(|v| v.id().unwrap() == *carrier)
                .unwrap();
            let author = f
                .set
                .validators
                .iter()
                .position(|v| v.validator_id == carrier.author)
                .unwrap();
            let mut wrong_digest = lineage.view_digest(lineage.entries.len() - 1).unwrap();
            wrong_digest[0] ^= 1;
            // Keep the elected author, causal references and exact round ordering;
            // only the signed payload commitment is wrong.
            let replacement = signed_vertex(
                &f.keys,
                author,
                carrier.round,
                original.references.clone(),
                wrong_digest,
            );
            unauthenticated.entries.last_mut().unwrap().view_carrier = replacement.id().unwrap();
            let mut vertices = f.vertices.clone();
            vertices.retain(|v| v.round != carrier.round || v.author != carrier.author);
            vertices.push(replacement);
            let wrong_state = f.state(vertices);
            let recovery = store.recover_slot_agreement(bootstrap.clone(), |decision| {
                assert_eq!(decision, &proposal.decision);
                wrong_state
                    .dag()
                    .inspect_slot_agreement_view_lineage(&unauthenticated, &binding)
                    .map(|_| ())
            });
            let error = match recovery {
                Ok(_) => panic!("recovery must reject the wrong captured lineage commitment"),
                Err(error) => error,
            };
            let crate::StoreError::Decode(error) = error else {
                panic!("expected lineage validation failure, got {error}");
            };
            assert_eq!(error.detail(), "slot payload is not bound to its carrier");
        }
        let mut session = store
            .recover_slot_agreement(bootstrap.clone(), inspect)
            .unwrap();
        let result = if let Some(qc) = prevote {
            let sequence = session.sequence();
            // A real current-view prevote QC is not an earlier POL. Reject
            // it before the repeated-prevote guard, without consuming sequence.
            let error = session
                .apply(
                    sequence + 1,
                    AgreementInput::Propose {
                        view,
                        decision: proposal.decision.clone(),
                        pol: Some(qc.clone()),
                    },
                    inspect,
                )
                .unwrap_err();
            let crate::StoreError::Decode(error) = error else {
                panic!("expected POL validation failure, got {error}");
            };
            assert_eq!(error.detail(), "POL must match proposal in an earlier view");
            assert_eq!(session.sequence(), sequence);
            let input = AgreementInput::Evidence { qc: qc.clone() };
            let sequence = session.sequence() + 1;
            let persisted = session.apply(sequence, input.clone(), inspect).unwrap();
            assert_eq!(
                persisted.vote.as_ref().unwrap().phase,
                AgreementPhase::Precommit
            );
            // Crash window: no signature has been made for the persisted lock.
            drop(session);
            drop(store);
            let reopened = Store::open(&dir.0).unwrap();
            let mut recovered = reopened.recover_slot_agreement(bootstrap, inspect).unwrap();
            assert_eq!(recovered.sequence(), sequence);
            let retried = recovered.apply(sequence, input, inspect).unwrap();
            assert_eq!(retried.vote, persisted.vote);
            assert_eq!(
                recovered.sequence(),
                sequence,
                "retry must not append another transition"
            );
            retried
        } else {
            if view.0 > 0 {
                // Every validator, including the new quorum member, advances its
                // original durable session rather than bootstrapping at the new view.
                for from in 0..view.0 {
                    let sequence = session.sequence() + 1;
                    session
                        .apply(
                            sequence,
                            AgreementInput::AdvanceView {
                                from: AgreementView(from),
                            },
                            inspect,
                        )
                        .unwrap();
                }
                let sequence = session.sequence() + 1;
                let stale = AgreementInput::Propose {
                    view: AgreementView(0),
                    decision: proposal.decision.clone(),
                    pol: None,
                };
                assert!(session.apply(sequence, stale, inspect).is_err());
                // This is cryptographically valid durable evidence, but its
                // precommit phase cannot authorize a reproposal as a POL.
                let wrong_pol = wrong_pol
                    .expect("later view has earlier precommits")
                    .clone();
                wrong_pol.verify(f.binding.tip(), &f.set).unwrap();
                assert_eq!(wrong_pol.vote.phase, AgreementPhase::Precommit);
                assert!(
                    session
                        .apply(
                            sequence,
                            AgreementInput::Propose {
                                view,
                                decision: proposal.decision.clone(),
                                pol: Some(wrong_pol),
                            },
                            inspect
                        )
                        .is_err()
                );
                assert_eq!(session.sequence(), sequence - 1);
                drop(session);
                drop(store);
                let reopened = Store::open(&dir.0).unwrap();
                session = reopened
                    .recover_slot_agreement(bootstrap.clone(), inspect)
                    .unwrap();
                assert_eq!(
                    session.sequence(),
                    sequence - 1,
                    "rejected inputs must not survive recovery"
                );
            }
            session
                .apply(session.sequence() + 1, input.clone(), inspect)
                .unwrap()
        };
        let vote = result
            .vote
            .expect("durable transition emits the signing statement");
        assert_eq!(vote.context, *f.binding.tip());
        assert_eq!(vote.view, view);
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

fn reject_unauthorized_view(f: &Fixture, lineage: &SlotAgreementViewLineage) {
    let mut unauthorized = lineage.clone();
    let elected = &lineage.entries[0].view_carrier.author;
    let wrong = f
        .set
        .validators
        .iter()
        .position(|v| &v.validator_id != elected)
        .unwrap();
    let refs = f
        .vertices
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect();
    let carrier = signed_vertex(&f.keys, wrong, 4, refs, lineage.view_digest(0).unwrap());
    unauthorized.entries[0].view_carrier = carrier.id().unwrap();
    let mut vertices = f.vertices.clone();
    vertices.retain(|v| v.round != 4 || v.author != carrier.author);
    vertices.push(carrier);
    let state = f.state(vertices);
    let binding = validator::SlotAgreementBinding::from_checkpoint(
        f.binding.tip().clone(),
        f.binding.carrier().cloned(),
    )
    .unwrap();
    assert!(
        state
            .dag()
            .inspect_slot_agreement_view_lineage(&unauthorized, &binding)
            .is_err()
    );
    let inspect = |decision: &validator::SlotDecision| {
        assert_eq!(decision, &f.payload.proposal.decision);
        state
            .dag()
            .inspect_slot_agreement_view_lineage(&unauthorized, &binding)
            .map(|_| ())
    };
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let bootstrap = SlotAgreementBootstrap {
        context: f.binding.tip().clone(),
        set: f.set.clone(),
        local_validator: f.set.validators[0].validator_id.clone(),
    };
    let mut session = store.begin_slot_agreement(bootstrap.clone()).unwrap();
    // Even a caller bypassing the owned-input inspection cannot release a vote.
    assert!(
        session
            .apply(
                1,
                AgreementInput::Propose {
                    view: AgreementView(0),
                    decision: f.payload.proposal.decision.clone(),
                    pol: None,
                },
                inspect,
            )
            .is_err()
    );
    assert_eq!(session.sequence(), 0);
    drop(session);
    drop(store);
    let reopened = Store::open(&dir.0).unwrap();
    let recovered = reopened.recover_slot_agreement(bootstrap, inspect).unwrap();
    assert_eq!(
        recovered.sequence(),
        0,
        "rejected view must not enter the WAL"
    );
}

fn run(commit: bool, later_view: Option<AgreementView>) {
    let mut f = Fixture::new(commit);
    // Discard the legacy certificate carrier: it is not agreement evidence.
    f.vertices.retain(|v| v.round < 4);
    let mut lineage = SlotAgreementViewLineage {
        entries: vec![SlotAgreementProofEntry {
            proposal: f.payload.proposal.clone(),
            proposal_carrier: f.payload.proposal_carrier.clone(),
            view: AgreementView(0),
            view_carrier: f.payload.proposal_carrier.clone(),
            previous_pol: None,
            pol: None,
        }],
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
    let digest = lineage.view_digest(0).unwrap();
    let mut next = Vec::new();
    for i in 0..4 {
        let hash = if i == author { digest } else { [9; 32] };
        let vertex = signed_vertex(&f.keys, i, 4, refs.clone(), hash);
        next.push(vertex.id().unwrap());
        f.vertices.push(vertex);
    }
    lineage.entries[0].view_carrier = next[author].clone();
    refs = next;
    reject_unauthorized_view(&f, &lineage);
    let dirs: Vec<_> = (0..4).map(|_| TempDir::new()).collect();
    // Establish all four logical sessions before either view, including the
    // validator that only joins the later signing quorum.
    for (id, dir) in dirs.iter().enumerate() {
        let store = Store::open(&dir.0).unwrap();
        store
            .begin_slot_agreement(SlotAgreementBootstrap {
                context: f.binding.tip().clone(),
                set: f.set.clone(),
                local_validator: f.set.validators[id].validator_id.clone(),
            })
            .unwrap();
    }
    let prevote = emitted_qc(&f, &lineage, None, &dirs, AgreementView(0), None);
    assert_eq!(prevote.vote.phase, AgreementPhase::Prevote);
    let mut proof = SlotAgreementProof {
        entries: lineage.entries.clone(),
        // Replaced by emitted precommits after the POL carrier exists.
        certificate: prevote.clone(),
        votes: vec![],
    };
    let mut base_round = 4;
    let views: Vec<_> = std::iter::once(AgreementView(0))
        .chain(later_view)
        .collect();
    for (entry, view) in views.into_iter().enumerate() {
        if entry > 0 {
            lineage.entries = proof.entries.clone();
            lineage.entries.push(SlotAgreementProofEntry {
                proposal: f.payload.proposal.clone(),
                proposal_carrier: f.payload.proposal_carrier.clone(),
                view,
                view_carrier: f.payload.proposal_carrier.clone(),
                previous_pol: Some(entry - 1),
                pol: None,
            });
            let author = validator::slot_agreement_view_proposer(&f.set, 1, view).unwrap();
            base_round += 1;
            let mut next = Vec::new();
            for id in 0..4 {
                let hash = if f.set.validators[id].validator_id == author {
                    lineage.view_digest(entry).unwrap()
                } else {
                    [9; 32]
                };
                let vertex = signed_vertex(&f.keys, id, base_round, refs.clone(), hash);
                next.push(vertex.id().unwrap());
                f.vertices.push(vertex);
            }
            lineage.entries[entry].view_carrier =
                next.iter().find(|v| v.author == author).unwrap().clone();
            refs = next;
            proof.entries = lineage.entries.clone();
        }
        let prevote = if entry == 0 {
            prevote.clone()
        } else {
            emitted_qc(&f, &lineage, None, &dirs, view, Some(&proof.certificate))
        };
        for offset in 1..=4 {
            let round = base_round + offset;
            let mut hashes = [[9; 32]; 4];
            if offset == 3 {
                proof.certificate = emitted_qc(&f, &lineage, Some(&prevote), &dirs, view, None);
                assert_eq!(proof.certificate.vote.phase, AgreementPhase::Precommit);
            }
            if offset == 1 || offset == 3 {
                let certificate = if offset == 1 {
                    &prevote
                } else {
                    &proof.certificate
                };
                for signature in &certificate.signatures {
                    let i = f
                        .set
                        .validators
                        .iter()
                        .position(|v| v.validator_id == signature.validator_id)
                        .unwrap();
                    let payload = SlotAgreementVotePayload {
                        vote: certificate.vote.clone(),
                        signature: signature.clone(),
                        prerequisite: if offset == 1 {
                            proof.entries[entry].view_carrier.clone()
                        } else {
                            proof.entries[entry].pol.as_ref().unwrap().carrier.clone()
                        },
                    };
                    hashes[i] = payload.digest(&f.set).unwrap();
                    let vertex = signed_vertex(&f.keys, i, round, refs.clone(), hashes[i]);
                    let witness = SlotAgreementVoteWitness {
                        payload,
                        carrier: vertex.id().unwrap(),
                    };
                    if offset == 1 {
                        proof.entries[entry]
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
                hashes[0] = proof.pol_digest(entry, &f.set).unwrap();
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

            if offset == 2 {
                proof.entries[entry].pol.as_mut().unwrap().carrier = next[0].clone();
            }
            refs = next;
        }
        base_round += 4;
        if later_view.is_some() && entry == 0 {
            // Only the final-view precommits belong in the final certificate.
            proof.votes.clear();
        }
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
fn signed_dag_durable_commit_view_zero_to_one_reopen_replay() {
    run(true, Some(AgreementView(1)));
}

#[test]
fn signed_dag_durable_skip_view_zero_to_three_reopen_replay() {
    run(false, Some(AgreementView(3)));
}

#[test]
fn signed_dag_durable_commit_view_zero_reopen_replay() {
    run(true, None);
}

#[test]
fn signed_dag_durable_skip_view_zero_reopen_replay() {
    run(false, None);
}
