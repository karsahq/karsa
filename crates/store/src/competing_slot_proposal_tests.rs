//! Inactive agreement only: competing evidence does not itself choose or apply a slot.
use super::*;
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use crypto::scheme::Ed25519Scheme;
use validator::slot_agreement::{AgreementPhase, AgreementValue, AgreementView};
use validator::{
    Dag, Decision, SlotAgreementProofEntry, SlotAgreementViewLineage, SlotAgreementVotePayload,
    SlotAgreementVoteWitness, SlotOutcome, SlotProposalEnvelope, SlotProposalEvidence,
    ValidatorSignature, VertexId,
};

fn ids(f: &Fixture, round: u64) -> Vec<VertexId> {
    f.vertices
        .iter()
        .filter(|v| v.round == round)
        .map(|v| v.id().unwrap())
        .collect()
}

fn append_round(f: &mut Fixture, round: u64, hashes: [[u8; 32]; 4]) -> Vec<VertexId> {
    let refs = ids(f, round - 1);
    let mut result = vec![];
    for (id, hash) in hashes.into_iter().enumerate() {
        let vertex = signed_vertex(&f.keys, id, round, refs.clone(), hash);
        result.push(vertex.id().unwrap());
        f.vertices.push(vertex);
    }
    result
}

fn authorize(f: &mut Fixture, lineage: &mut SlotAgreementViewLineage, round: u64) {
    let index = lineage.entries.len() - 1;
    let proposer =
        validator::slot_agreement_view_proposer(&f.set, 1, lineage.entries[index].view).unwrap();
    let author = f
        .set
        .validators
        .iter()
        .position(|v| v.validator_id == proposer)
        .unwrap();
    let mut hashes = [[42; 32]; 4];
    hashes[author] = lineage.view_digest(index).unwrap();
    lineage.entries[index].view_carrier = append_round(f, round, hashes)[author].clone();
}

fn competing_fixture() -> (Fixture, SlotAgreementViewLineage, SlotAgreementViewLineage) {
    let mut f = Fixture::new(true);
    // Discard the base fixture's synthetic certificates; no agreement signature from it is used.
    f.vertices.retain(|v| v.round <= 1);
    let SlotOutcome::Commit { leader } = &f.payload.proposal.decision.outcome else {
        unreachable!()
    };
    let target = leader.clone();
    let refs = ids(&f, 1);
    for author in 0..4 {
        let references = refs
            .iter()
            .filter(|id| author == 0 || **id != target)
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
    append_round(&mut f, 3, [[3; 32]; 4]);
    append_round(&mut f, 4, [[4; 32]; 4]);
    let mut dag = Dag::new(f.set.clone());
    dag.set_chain_id(b"slot-store-tests".to_vec());
    for vertex in &f.vertices {
        dag.insert(vertex.clone()).unwrap();
    }
    let commit = SlotProposalEnvelope {
        decision: f.payload.proposal.decision.clone(),
        evidence: SlotProposalEvidence::IndirectCommit {
            anchor: dag.leader(3).unwrap().id().unwrap(),
            support: ids(&f, 4)[..3].to_vec(),
        },
    };
    let mut decision = commit.decision.clone();
    decision.outcome = SlotOutcome::Skip {
        leader_author: target.author.clone(),
    };
    decision.after_len = decision.before_len;
    decision.after_root = decision.before_root;
    let voters = ids(&f, 2);
    let fence = validator::Fence::new(b"slot-store-tests".to_vec(), 2, voters[3].author.clone());
    let bytes = fence.signing_payload().unwrap();
    let fence = validator::FenceCertificate {
        fence,
        signer_bitmap: vec![0b111],
        signatures: (0..3)
            .map(|id| Ed25519Scheme.sign(&f.keys[id], &bytes).unwrap())
            .collect(),
    };
    let skip = SlotProposalEnvelope {
        decision,
        evidence: SlotProposalEvidence::ConservativeSkip {
            // One signed vote + one unknown is at most two, below the quorum of three.
            voters: voters[..3].to_vec(),
            missing: vec![voters[3].author.clone()],
            fences: vec![fence],
        },
    };
    let mut hashes = [[5; 32]; 4];
    hashes[0] = commit.digest().unwrap();
    hashes[1] = skip.digest().unwrap();
    let carriers = append_round(&mut f, 5, hashes);
    let entry = |proposal, author: usize, view| SlotAgreementProofEntry {
        proposal,
        proposal_carrier: carriers[author].clone(),
        view: AgreementView(view),
        view_carrier: carriers[author].clone(),
        previous_pol: None,
        pol: None,
    };
    let mut commit = SlotAgreementViewLineage {
        entries: vec![entry(commit, 0, 0)],
    };
    let mut skip = SlotAgreementViewLineage {
        entries: vec![entry(skip, 1, 1)],
    };
    authorize(&mut f, &mut commit, 6);
    authorize(&mut f, &mut skip, 7);
    (f, commit, skip)
}

fn apply(
    driver: &mut SlotAgreementDriver,
    request: AuthenticatedSlotAgreementRequest,
) -> SlotAgreementDriverOutput {
    driver.apply(driver.sequence() + 1, request).unwrap()
}

// Only sign an intent returned after this signer's own durable transition.
fn witness(
    f: &Fixture,
    driver: &SlotAgreementDriver,
    output: &SlotAgreementDriverOutput,
    id: usize,
    round: u64,
    prerequisite: VertexId,
) -> (validator::Vertex, SlotAgreementVoteWitness) {
    assert!(driver.sequence() > 0);
    let vote = output.transition.as_ref().unwrap().vote.clone().unwrap();
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
        prerequisite,
    };
    let vertex = signed_vertex(
        &f.keys,
        id,
        round,
        ids(f, round - 1),
        payload.digest(&f.set).unwrap(),
    );
    let carrier = vertex.id().unwrap();
    (vertex, SlotAgreementVoteWitness { payload, carrier })
}

#[test]
fn competing_indirect_and_conservative_skip_across_views_durable_lock_and_common_application() {
    let (mut f, commit, mut skip) = competing_fixture();
    let dirs = (0..4).map(|_| TempDir::new()).collect::<Vec<_>>();
    let mut stores = dirs
        .iter()
        .map(|d| Store::open(&d.0).unwrap())
        .collect::<Vec<_>>();
    let bootstraps = (0..4)
        .map(|id| AuthenticatedSlotAgreementBootstrap {
            agreement: SlotAgreementBootstrap {
                context: f.binding.tip().clone(),
                set: f.set.clone(),
                local_validator: f.set.validators[id].validator_id.clone(),
            },
            predecessor: None,
            order: vec![],
            vertices: vec![],
        })
        .collect::<Vec<_>>();
    let mut drivers = stores
        .iter()
        .zip(&bootstraps)
        .map(|(s, b)| {
            SlotAgreementDriver::new(s.begin_authenticated_slot_agreement(b.clone()).unwrap())
        })
        .collect::<Vec<_>>();
    let mut dag = Dag::new(f.set.clone());
    dag.set_chain_id(b"slot-store-tests".to_vec());
    for vertex in &f.vertices {
        dag.insert(vertex.clone()).unwrap();
    }
    let root = dag.commit_root();
    let SlotProposalEvidence::ConservativeSkip { fences, .. } = &skip.entries[0].proposal.evidence
    else {
        unreachable!()
    };
    // Fence adoption is tested in isolation: no fence-skipping/pacemaker routine is invoked.
    let mut fenced = Dag::new(f.set.clone());
    fenced.set_chain_id(b"slot-store-tests".to_vec());
    for vertex in &f.vertices {
        fenced.insert(vertex.clone()).unwrap();
    }
    fenced.apply_fence(b"slot-store-tests", &fences[0]).unwrap();
    assert!(fenced.order().is_empty());
    assert_eq!(fenced.commit_root(), root);
    assert!(matches!(
        dag.inspect_slot_proposal_envelope(
            &commit.entries[0].proposal,
            &commit.entries[0].proposal_carrier,
            f.binding.tip()
        )
        .unwrap(),
        Decision::Commit(_)
    ));
    assert_eq!(
        dag.inspect_slot_proposal_envelope(
            &skip.entries[0].proposal,
            &skip.entries[0].proposal_carrier,
            f.binding.tip()
        )
        .unwrap(),
        Decision::Skip
    );
    assert!(dag.order().is_empty());
    assert_eq!(
        dag.commit_root(),
        root,
        "standalone proposal inspection cannot apply either value"
    );
    assert_ne!(
        commit.entries[0].proposal.decision,
        skip.entries[0].proposal.decision
    );

    // Honest 2/2 decision/nil split, not proposer equivocation. Skip has authorization only in view 1.
    let mut outputs = vec![];
    for (id, driver) in drivers.iter_mut().enumerate() {
        outputs.push(apply(
            driver,
            if id < 2 {
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage: commit.clone(),
                    vertices: f.vertices.clone(),
                }
            } else {
                AuthenticatedSlotAgreementRequest::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Prevote,
                }
            },
        ));
    }
    let mut opposition = vec![];
    for id in 0..4 {
        let vote = outputs[id]
            .transition
            .as_ref()
            .unwrap()
            .vote
            .as_ref()
            .unwrap();
        assert_eq!(vote.phase, AgreementPhase::Prevote);
        assert_eq!(matches!(vote.value, AgreementValue::Nil), id >= 2);
        // A second proposal cannot replace a timed-out nil vote with a decision vote.
        let sequence = drivers[id].sequence();
        let again = drivers[id].apply(
            sequence + 1,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage: commit.clone(),
                vertices: f.vertices.clone(),
            },
        );
        assert!(again.is_err(), "a second same-phase vote must be rejected");
        assert_eq!(drivers[id].sequence(), sequence);
        if id < 2 {
            let (v, w) = witness(
                &f,
                &drivers[id],
                &outputs[id],
                id,
                8,
                commit.entries[0].view_carrier.clone(),
            );
            f.vertices.push(v);
            opposition.push(w);
        }
    }
    // Fill the remaining DAG authors without inventing agreement signatures.
    let refs = ids(&f, 7);
    for id in 2..4 {
        f.vertices
            .push(signed_vertex(&f.keys, id, 8, refs.clone(), [8; 32]));
    }
    for w in &opposition {
        for driver in &mut drivers {
            let out = apply(
                driver,
                AuthenticatedSlotAgreementRequest::ObserveVote {
                    lineage: commit.clone(),
                    witness: w.clone(),
                    vertices: f.vertices.clone(),
                },
            );
            assert!(
                out.candidates.is_empty(),
                "two opposing votes cannot form a POL"
            );
        }
    }
    for driver in &mut drivers {
        let out = apply(
            driver,
            AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Precommit,
            },
        );
        assert_eq!(
            out.transition.unwrap().vote.unwrap().value,
            AgreementValue::Nil
        );
        apply(
            driver,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        );
    }
    // The next elected proposer authorizes the other admissible value, with no fabricated QC.
    outputs = drivers
        .iter_mut()
        .map(|d| {
            apply(
                d,
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage: skip.clone(),
                    vertices: f.vertices.clone(),
                },
            )
        })
        .collect();

    // View 1 establishes a lock. View 2 must use its real, retained POL to repropose.
    let mut final_proof = None;
    for (view, vote_round) in [(1, 9), (2, 13)] {
        let mut witnesses = vec![];
        for id in 0..4 {
            let (v, w) = witness(
                &f,
                &drivers[id],
                &outputs[id],
                id,
                vote_round,
                skip.entries.last().unwrap().view_carrier.clone(),
            );
            assert_eq!(w.payload.vote.view, AgreementView(view));
            assert_eq!(w.payload.vote.phase, AgreementPhase::Prevote);
            f.vertices.push(v);
            witnesses.push(w);
        }
        for (index, w) in witnesses[..3].iter().enumerate() {
            for driver in &mut drivers {
                let out = apply(
                    driver,
                    AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: skip.clone(),
                        witness: w.clone(),
                        vertices: f.vertices.clone(),
                    },
                );
                if index < 2 {
                    assert!(out.candidates.is_empty());
                }
            }
        }
        let pending = drivers[0]
            .output()
            .unwrap()
            .candidates
            .into_iter()
            .find_map(|c| match c {
                SlotAgreementCarrierCandidate::PendingPol(p) => Some(p),
                _ => None,
            })
            .unwrap();
        let mut hashes = [[10; 32]; 4];
        hashes[0] = pending.digest();
        let carriers = append_round(&mut f, vote_round + 1, hashes);
        skip = pending.bind_carrier(carriers[0].clone());
        outputs = drivers
            .iter_mut()
            .map(|d| {
                apply(
                    d,
                    AuthenticatedSlotAgreementRequest::ObservePrevote {
                        lineage: skip.clone(),
                        vertices: f.vertices.clone(),
                    },
                )
            })
            .collect();
        if view == 1 {
            let sequences = drivers
                .iter()
                .map(SlotAgreementDriver::sequence)
                .collect::<Vec<_>>();
            drop(drivers);
            drop(stores);
            stores = dirs
                .iter()
                .map(|dir| Store::open(&dir.0).unwrap())
                .collect();
            drivers = stores
                .iter()
                .zip(&bootstraps)
                .map(|(store, bootstrap)| {
                    SlotAgreementDriver::new(
                        store
                            .recover_authenticated_slot_agreement(bootstrap.clone())
                            .unwrap(),
                    )
                })
                .collect();
            for id in 0..4 {
                assert_eq!(drivers[id].sequence(), sequences[id]);
                let material = drivers[id].output().unwrap().reproposal.unwrap();
                assert_eq!(material.lineage(), &skip);
                assert_eq!(material.view(), AgreementView(1));
                // Restart with an unresolved lock and no application or external vertex log.
                let sequence = drivers[id].sequence();
                drivers[id] = SlotAgreementDriver::new(
                    stores[id]
                        .recover_authenticated_slot_agreement(bootstraps[id].clone())
                        .unwrap(),
                );
                assert_eq!(drivers[id].sequence(), sequence);
                assert_eq!(
                    drivers[id].output().unwrap().reproposal,
                    Some(material.clone())
                );
                let path = dirs[id].0.join(authenticated_slot_agreement::FILE);
                let bytes = fs::read(&path).unwrap();
                assert!(
                    drivers[id]
                        .apply(
                            sequence + 1,
                            AuthenticatedSlotAgreementRequest::Propose {
                                lineage: commit.clone(),
                                vertices: f.vertices.clone(),
                            }
                        )
                        .is_err(),
                    "old conflicting proposal must not replace the unresolved lock"
                );
                assert_eq!(fs::read(path).unwrap(), bytes);
                assert!(
                    drivers[id]
                        .apply(
                            sequence + 1,
                            AuthenticatedSlotAgreementRequest::Timeout {
                                view: AgreementView(1),
                                phase: AgreementPhase::Precommit,
                            },
                        )
                        .is_err(),
                    "timeout cannot double-vote nil after a locked precommit"
                );
                apply(
                    &mut drivers[id],
                    AuthenticatedSlotAgreementRequest::AdvanceView {
                        from: AgreementView(1),
                    },
                );
                assert_eq!(drivers[id].output().unwrap().reproposal, Some(material));
            }
            // Precommits from view 1 were deliberately withheld, so no decision exists yet.
            assert!(
                drivers
                    .iter()
                    .all(|d| d.output().unwrap().transition.unwrap().decision.is_none())
            );
            // Counterfactual adversarial proposer branch: the elected view-2 author
            // signs a conflicting value. Keep its round-11 vertices separate from
            // the honest skip branch, so neither DAG contains author/round equivocation.
            let mut conflicting_f = Fixture::new(true);
            conflicting_f.vertices = f.vertices.clone();
            let mut conflicting = commit.clone();
            conflicting.entries[0].view = AgreementView(2);
            assert!(conflicting.entries[0].previous_pol.is_none());
            authorize(&mut conflicting_f, &mut conflicting, 11);
            let request = AuthenticatedSlotAgreementRequest::Propose {
                lineage: conflicting.clone(),
                vertices: conflicting_f.vertices.clone(),
            };
            // Same context and local identity, but no lock: validates the actual
            // signature, elected proposer, indirect evidence and DAG prerequisites.
            let control_dir = TempDir::new();
            let control_store = Store::open(&control_dir.0).unwrap();
            let mut control = SlotAgreementDriver::new(
                control_store
                    .begin_authenticated_slot_agreement(bootstraps[0].clone())
                    .unwrap(),
            );
            for view in 0..2 {
                apply(
                    &mut control,
                    AuthenticatedSlotAgreementRequest::AdvanceView {
                        from: AgreementView(view),
                    },
                );
            }
            let accepted = apply(&mut control, request.clone())
                .transition
                .unwrap()
                .vote
                .unwrap();
            assert_eq!(accepted.view, AgreementView(2));
            assert_eq!(accepted.phase, AgreementPhase::Prevote);
            assert_eq!(
                accepted.value,
                AgreementValue::Decision(commit.entries[0].proposal.decision.clone())
            );
            for (id, driver) in drivers.iter_mut().enumerate() {
                let sequence = driver.sequence();
                let before = format!("{:?}", driver.output().unwrap());
                let path = dirs[id].0.join(authenticated_slot_agreement::FILE);
                let bytes = fs::read(&path).unwrap();
                let error = driver.apply(sequence + 1, request.clone()).unwrap_err();
                assert!(
                    error
                        .to_string()
                        .contains("conflicting proposal lacks newer POL"),
                    "must reject at the lock guard, not authentication/view/duplicate vote: {error}"
                );
                assert_eq!(driver.sequence(), sequence);
                assert_eq!(fs::read(&path).unwrap(), bytes);
                assert_eq!(format!("{:?}", driver.output().unwrap()), before);
            }
            let previous = skip.entries.len() - 1;
            let mut entry = skip.entries[previous].clone();
            entry.view = AgreementView(2);
            entry.previous_pol = Some(previous);
            entry.pol = None;
            skip.entries.push(entry);
            authorize(&mut f, &mut skip, 11);
            append_round(&mut f, 12, [[12; 32]; 4]);
            outputs = drivers
                .iter_mut()
                .map(|d| {
                    apply(
                        d,
                        AuthenticatedSlotAgreementRequest::Propose {
                            lineage: skip.clone(),
                            vertices: f.vertices.clone(),
                        },
                    )
                })
                .collect();
        } else {
            let mut witnesses = vec![];
            for id in 0..4 {
                let (v, w) = witness(
                    &f,
                    &drivers[id],
                    &outputs[id],
                    id,
                    15,
                    skip.entries
                        .last()
                        .unwrap()
                        .pol
                        .as_ref()
                        .unwrap()
                        .carrier
                        .clone(),
                );
                assert_eq!(w.payload.vote.phase, AgreementPhase::Precommit);
                f.vertices.push(v);
                witnesses.push(w);
            }
            for (index, w) in witnesses[..3].iter().enumerate() {
                for driver in &mut drivers {
                    let out = apply(
                        driver,
                        AuthenticatedSlotAgreementRequest::ObserveVote {
                            lineage: skip.clone(),
                            witness: w.clone(),
                            vertices: f.vertices.clone(),
                        },
                    );
                    if index < 2 {
                        assert!(out.candidates.iter().all(|c| !matches!(
                            c,
                            SlotAgreementCarrierCandidate::PendingFinalProof(_)
                        )));
                    }
                }
            }
            let proof = drivers[0]
                .output()
                .unwrap()
                .candidates
                .into_iter()
                .find_map(|c| match c {
                    SlotAgreementCarrierCandidate::PendingFinalProof(p) => Some(p),
                    _ => None,
                })
                .unwrap();
            let mut hashes = [[16; 32]; 4];
            hashes[0] = proof.digest(&f.set).unwrap();
            let carrier = append_round(&mut f, 16, hashes)[0].clone();
            for driver in &mut drivers {
                let out = apply(
                    driver,
                    AuthenticatedSlotAgreementRequest::ObservePrecommit {
                        proof: proof.clone(),
                        carrier: carrier.clone(),
                        vertices: f.vertices.clone(),
                    },
                );
                assert_eq!(
                    out.transition.unwrap().decision,
                    Some(skip.entries.last().unwrap().proposal.decision.clone())
                );
            }
            final_proof = Some((proof, carrier));
        }
    }
    let (proof, carrier) = final_proof.unwrap();
    let mut expected = None;
    for (id, store) in stores.iter().enumerate() {
        assert!(
            store.vertices().unwrap().is_empty(),
            "agreement does not apply the DAG"
        );
        let mut delivered = vec![];
        // Different author delivery orders within each causal round, not invalid child-before-parent input.
        for round in 0..=16 {
            let mut vertices = f
                .vertices
                .iter()
                .filter(|v| v.round == round)
                .cloned()
                .collect::<Vec<_>>();
            vertices.rotate_left(id % 4);
            delivered.extend(vertices);
        }
        for vertex in &delivered {
            store.append_vertex(vertex).unwrap();
        }
        let mut state = f.state(delivered);
        assert!(state.dag().order().is_empty());
        store
            .apply_slot_agreement(&mut state, &proof, &carrier)
            .unwrap();
        let result = (
            state.dag().order().to_vec(),
            state.dag().commit_root(),
            state.binding().clone(),
        );
        if let Some(expected) = &expected {
            assert_eq!(&result, expected);
        } else {
            expected = Some(result);
        }
        assert_eq!(state.binding().tip().next_round(), 2);
        assert!(
            state.dag().order().is_empty(),
            "the selected skip keeps the empty committed prefix"
        );
        assert_eq!(state.dag().commit_root(), root);
    }
    // Release every agreement owner's Store clone and the original handles before
    // reopening: replay must reconstruct application state from disk alone.
    drop(drivers);
    drop(stores);
    let expected = expected.unwrap();
    for dir in &dirs {
        let store = Store::open(&dir.0).unwrap();
        let mut replayed = f.state(store.vertices().unwrap());
        assert_eq!(
            store.replay_slot_applications(&mut replayed).unwrap().len(),
            1
        );
        assert_eq!(
            (
                replayed.dag().order().to_vec(),
                replayed.dag().commit_root(),
                replayed.binding().clone()
            ),
            expected
        );
        assert!(
            store
                .replay_slot_applications(&mut replayed)
                .unwrap()
                .is_empty()
        );
    }
}
