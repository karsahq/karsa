use super::*;
use crate::chain;
use std::sync::atomic::{AtomicU64, Ordering};
use validator::slot_agreement::AgreementView;
use validator::{
    Dag, Decision, SlotAgreementProofEntry, SlotAgreementViewLineage, SlotDecision,
    SlotDecisionTip, SlotOutcome, SlotProposal, SlotProposalEvidence, Vertex,
};

#[test]
fn certified_finalization_replays_two_authenticated_commit_boundaries() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::ExistingBoundaries);
}

#[test]
fn certified_finalization_reopens_and_continues_durable_history() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::ContinueAfterRecovery);
}

#[test]
fn journaled_finalization_receives_wire_and_explicitly_continues_same_owner() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::SameOwnerWire);
}

#[test]
fn certified_finalization_restore_publication_failure_requires_reopening() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::RestorePublicationFailure);
}

#[test]
fn certified_finalization_restore_io_failures_require_reopening() {
    use store::SharePublicationStage;
    for stage in [
        SharePublicationStage::Write,
        SharePublicationStage::FileSync,
        SharePublicationStage::Rename,
        SharePublicationStage::DirectorySync,
    ] {
        authenticated_commit_replay_fixture(AuthenticatedReplayMode::RestoreIoFailure(stage));
    }
}

#[test]
fn isolated_event_pump_tcp_certified_execution() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::EventPump);
}

#[test]
fn isolated_event_pump_ready_cancel_precedes_local_apply() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::EventPumpCancelReady);
}

#[test]
fn isolated_event_pump_output_closed_after_reserve_precedes_local_apply() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::EventPumpClosedReady);
}

#[derive(Clone, Copy)]
enum AuthenticatedReplayMode {
    ShareMesh,
    EventPump,
    EventPumpCancelReady,
    EventPumpClosedReady,
    ExistingBoundaries,
    ContinueAfterRecovery,
    SameOwnerWire,
    RestorePublicationFailure,
    RestoreIoFailure(store::SharePublicationStage),
}

fn authenticated_commit_replay_fixture(mode: AuthenticatedReplayMode) {
    use std::collections::{BTreeMap, BTreeSet};
    use validator::slot_agreement::{AgreementPhase, AgreementQc, AgreementValue, AgreementVote};
    use validator::{
        SlotAgreementProof, SlotAgreementProofPol, SlotAgreementVotePayload,
        SlotAgreementVoteWitness,
    };

    // Like store's append_unified_proof fixture, retain signed witnesses for both
    // phases and bind each aggregate to its actual causal carrier.
    fn append_proof(
        m: &Membership,
        chain_id: &[u8],
        vertices: &mut Vec<Vertex>,
        context: SlotDecisionTip,
        proposal: SlotProposal,
        proposal_carrier: VertexId,
        first_round: u64,
    ) -> (SlotAgreementProof, VertexId) {
        vertices.retain(|v| v.round < first_round);
        let qc = |phase| {
            let vote = AgreementVote {
                context: context.clone(),
                view: AgreementView(0),
                phase,
                value: AgreementValue::Decision(proposal.decision.clone()),
            };
            let bytes = vote.signing_payload(&m.set).unwrap();
            let mut signatures: Vec<_> = (0..3)
                .map(|i| ValidatorSignature {
                    validator_id: m.consensus[i].id.clone(),
                    key_id: m.set.validators[i].keys[0].key_id.clone(),
                    signature: Ed25519Scheme
                        .sign(&m.consensus[i].private_key, &bytes)
                        .unwrap(),
                })
                .collect();
            signatures.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
            AgreementQc { vote, signatures }
        };
        let prevote = qc(AgreementPhase::Prevote);
        let mut proof = SlotAgreementProof {
            certificate: qc(AgreementPhase::Precommit),
            entries: vec![SlotAgreementProofEntry {
                proposal: proposal.clone().into(),
                proposal_carrier: proposal_carrier.clone(),
                view: AgreementView(0),
                view_carrier: proposal_carrier.clone(),
                previous_pol: None,
                pol: None,
            }],
            votes: vec![],
        };
        let proposer = validator::slot_agreement_view_proposer(
            &m.set,
            proposal.decision.round,
            AgreementView(0),
        )
        .unwrap();
        let author = m.consensus.iter().position(|v| v.id == proposer).unwrap();
        let mut refs: Vec<_> = vertices
            .iter()
            .filter(|v| v.round == first_round - 1)
            .map(|v| v.id().unwrap())
            .collect();
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
                for signature in &certificate.signatures {
                    let i = m
                        .consensus
                        .iter()
                        .position(|identity| identity.id == signature.validator_id)
                        .unwrap();
                    let payload = SlotAgreementVotePayload {
                        vote: certificate.vote.clone(),
                        signature: signature.clone(),
                        prerequisite: if offset == 1 {
                            proof.entries[0].view_carrier.clone()
                        } else {
                            proof.entries[0].pol.as_ref().unwrap().carrier.clone()
                        },
                    };
                    hashes[i] = payload.digest(&m.set).unwrap();
                    let vertex = signed_for_chain(m, i, round, refs.clone(), hashes[i], chain_id);
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
                                carrier: proposal_carrier.clone(),
                            })
                            .votes
                            .push(witness);
                    } else {
                        proof.votes.push(witness);
                    }
                }
            }
            if offset == 2 {
                hashes[0] = proof.pol_digest(0, &m.set).unwrap();
            }
            if offset == 4 {
                hashes[0] = proof.digest(&m.set).unwrap();
            }
            let mut next = vec![];
            for (i, hash) in hashes.into_iter().enumerate() {
                let vertex = signed_for_chain(m, i, round, refs.clone(), hash, chain_id);
                next.push(vertex.id().unwrap());
                vertices.push(vertex);
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

    let chain_id = b"certified-finalization-backlog";
    let accounts = chain::accounts(4).unwrap();
    let mut batches = BTreeMap::new();
    let mut hashes = BTreeMap::new();
    for round in 0..=2 {
        for author in 0..4 {
            let batch = chain::demo_batch(chain_id, &accounts, author, round, 1).unwrap();
            let hash = batch.digest().unwrap();
            hashes.insert((author, round), hash);
            batches.insert(hash, batch);
        }
    }
    let (m, bootstrap, request) =
        fixture_for_chain_with_payload(chain_id, |author, round| hashes[&(author, round)]);
    let AuthenticatedSlotAgreementRequest::Propose {
        lineage,
        mut vertices,
    } = request
    else {
        unreachable!()
    };
    let validator::SlotProposalEvidence::Direct { voters } = &lineage.entries[0].proposal.evidence
    else {
        panic!("fixture must supply direct proposal evidence")
    };
    let first_proposal = SlotProposal {
        decision: lineage.entries[0].proposal.decision.clone(),
        voters: voters.clone(),
    };
    let (proof, carrier) = append_proof(
        &m,
        chain_id,
        &mut vertices,
        bootstrap.agreement.context.clone(),
        first_proposal,
        lineage.entries[0].proposal_carrier.clone(),
        4,
    );
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    if matches!(
        mode,
        AuthenticatedReplayMode::EventPumpCancelReady
            | AuthenticatedReplayMode::EventPumpClosedReady
    ) {
        let owner = open_event_pump_owner(&store, &bootstrap, &m);
        let envelope = CarrierEnvelope::from_publication(
            carrier,
            CarrierPayload::Final(proof.clone()),
            proof.digest(&m.set).unwrap(),
            &m.set,
        )
        .unwrap();
        let message = net::wire::Message::AgreementCarrier {
            envelope: envelope.encode(&m.set).unwrap(),
            vertices,
        };
        exercise_event_pump_stop(owner, m, message, mode);
        return;
    }
    if matches!(mode, AuthenticatedReplayMode::ShareMesh) {
        exercise_share_mesh(bootstrap, m, batches, proof, carrier, vertices);
        return;
    }
    if matches!(mode, AuthenticatedReplayMode::EventPump) {
        exercise_event_pump(&store, bootstrap, m, batches, proof, carrier, vertices);
        return;
    }
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::ObservePrecommit {
            proof,
            carrier,
            vertices: vertices.clone(),
        })
        .unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::AdvanceSlot)
        .unwrap();
    let first = adapter.ordering_snapshot().unwrap();

    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(chain_id.to_vec());
    for vertex in &vertices {
        dag.insert(vertex.clone()).unwrap();
    }
    dag.seed_order(first.order().to_vec());
    let validator::Decision::Commit(suffix) = dag.inspect_commit(2).unwrap() else {
        panic!("round-three voters must commit round two")
    };
    let second_leader = dag.leader(2).unwrap().id().unwrap();
    assert!(!first.order().contains(&second_leader));
    assert!(suffix.contains(&second_leader));
    let mut order = first.order().to_vec();
    order.extend(suffix);
    let mut proposal = SlotProposal {
        decision: SlotDecision {
            chain_id: chain_id.to_vec(),
            validator_set_id: m.set.id().unwrap(),
            epoch: m.set.epoch,
            round: 2,
            previous: *first.binding().tip().previous_id(),
            before_len: first.order().len() as u64,
            before_root: validator::commit_root(first.order()),
            after_len: order.len() as u64,
            after_root: validator::commit_root(&order),
            outcome: SlotOutcome::Commit {
                leader: dag.leader(2).unwrap().id().unwrap(),
            },
        },
        voters: vertices
            .iter()
            .filter(|v| v.round == 3)
            .take(3)
            .map(|v| v.id().unwrap())
            .collect(),
    };
    proposal
        .voters
        .sort_by(|a, b| (&a.round, &a.author, &a.digest).cmp(&(&b.round, &b.author, &b.digest)));
    let refs: Vec<_> = vertices
        .iter()
        .filter(|v| v.round == 8)
        .map(|v| v.id().unwrap())
        .collect();
    let mut proposal_carrier = None;
    for author in 0..4 {
        let hash = if author == 0 {
            proposal.digest().unwrap()
        } else {
            [9; 32]
        };
        let vertex = signed_for_chain(&m, author, 9, refs.clone(), hash, chain_id);
        if author == 0 {
            proposal_carrier = Some(vertex.id().unwrap());
        }
        vertices.push(vertex);
    }
    let (proof, carrier) = append_proof(
        &m,
        chain_id,
        &mut vertices,
        first.binding().tip().clone(),
        proposal,
        proposal_carrier.unwrap(),
        10,
    );
    adapter
        .apply(AuthenticatedSlotAgreementRequest::ObservePrecommit {
            proof,
            carrier,
            vertices: vertices.clone(),
        })
        .unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::AdvanceSlot)
        .unwrap();
    let complete = adapter.ordering_snapshot().unwrap();
    assert_eq!(complete.order(), order);
    assert_eq!(complete.applications().len(), 2);
    assert!(
        complete
            .applications()
            .iter()
            .all(|boundary| boundary.is_commit())
    );
    assert_eq!(complete.applications()[0].round(), 1);
    assert_eq!(complete.applications()[1].round(), 2);
    // Each authenticated application collects its own leader's history, not the
    // later evidence carrier's cone. Consecutive fresh leaders extend the order.
    assert!(complete.applications()[0].order_len() < complete.applications()[1].order_len());
    let wal = std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap();
    drop(adapter);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    let recovered = adapter.ordering_snapshot().unwrap();
    assert_eq!(format!("{recovered:?}"), format!("{complete:?}"));

    let genesis = chain::genesis_state(&accounts).unwrap();
    let mut expected = genesis.clone();
    let mut rejected = BTreeMap::new();
    let mut applied = 0;
    let mut expected_prefixes = vec![];
    for (index, vertex) in recovered.vertices().iter().enumerate() {
        applied += chain::apply_batch(
            &mut expected,
            &accounts,
            &batches[&vertex.payload_hash],
            &mut rejected,
        ) as u64;
        if recovered
            .applications()
            .iter()
            .any(|boundary| boundary.order_len() == index + 1)
        {
            expected_prefixes.push((expected.state_root(), applied));
        }
    }
    assert!(rejected.is_empty());
    assert_eq!(expected_prefixes.len(), 2);
    assert_ne!(expected_prefixes[0].0, expected_prefixes[1].0);
    assert!(expected_prefixes[0].1 < expected_prefixes[1].1);
    let anchor = validator::Header {
        chain_id: chain_id.to_vec(),
        epoch: m.set.epoch,
        height: 0,
        round: 0,
        state_root: genesis.state_root(),
        dag_root: *recovered.checkpoint_binding().tip().order_root(),
        previous: [0; 32],
        applied: 0,
    };
    let finalizer = validator::Finalizer::new(
        validator::SetSchedule::single(m.set.clone()),
        validator::EpochSchedule::single(m.set.epoch),
        chain_id.to_vec(),
        m.consensus[0].id.clone(),
        m.consensus[0].private_key.clone(),
        anchor.clone(),
        0,
    )
    .unwrap();
    let mut coordinator =
        CertifiedFinalization::begin(recovered.clone(), genesis, finalizer).unwrap();
    let controls = BTreeSet::new();
    assert!(adapter.header_intents().unwrap().is_empty());
    let built = coordinator
        .build_ready_with_reservation(&m, &batches, &controls, 42, |header, coverage| {
            adapter
                .reserve_header(&anchor, header, coverage)
                .map_err(|error| {
                    crypto::CryptoError::new(crypto::CryptoErrorKind::InvalidVertex, error)
                })
        })
        .unwrap();
    let durable_intents = adapter.header_intents().unwrap();
    assert_eq!(durable_intents.len(), 2);
    for (index, intent) in durable_intents.iter().enumerate() {
        assert_eq!(intent.header(), &built.shares[index].header);
        assert_eq!(intent.application(), index);
        assert_eq!(intent.header().round, index as u64 + 1);
        assert_eq!(
            intent.order_len(),
            recovered.applications()[index].order_len()
        );
    }
    assert_eq!(built.shares.len(), 2);
    assert!(built.certified.is_empty());
    let mut previous = anchor.id().unwrap();
    for (index, share) in built.shares.iter().enumerate() {
        let boundary = &recovered.applications()[index];
        assert_eq!(share.header.height, index as u64 + 1);
        assert_eq!(share.header.round, boundary.round());
        assert_eq!(share.header.previous, previous);
        assert_eq!(share.header.state_root, expected_prefixes[index].0);
        assert_eq!(share.header.applied, expected_prefixes[index].1);
        assert_eq!(
            share.header.dag_root,
            validator::commit_root(&recovered.order()[..boundary.order_len()])
        );
        assert_eq!(share.signer, 0);
        assert_eq!(share.at, 42);
        assert_eq!(
            share.signature,
            Ed25519Scheme
                .sign(
                    &m.consensus[0].private_key,
                    &validator::signing_payload(&share.header).unwrap()
                )
                .unwrap()
        );
        previous = share.header.id().unwrap();
    }
    assert_eq!(coordinator.execution().state(), &expected);
    assert_eq!(coordinator.execution().applied(), applied);
    assert_eq!(coordinator.execution().consumed_order(), recovered.order());
    for at in 43..46 {
        coordinator.update(recovered.clone()).unwrap();
        let duplicate = coordinator
            .build_ready(&m, &batches, &controls, at)
            .unwrap();
        assert!(duplicate.shares.is_empty() && duplicate.certified.is_empty());
        assert_eq!(coordinator.finalizer().built_headers(), 2);
        assert_eq!(
            coordinator.finalizer().last_built(),
            &built.shares[1].header
        );
        assert_eq!(
            coordinator.finalizer().last_built_order(),
            recovered.order().len()
        );
    }
    let make_coordinator = || {
        CertifiedFinalization::begin(
            recovered.clone(),
            chain::genesis_state(&accounts).unwrap(),
            validator::Finalizer::new(
                validator::SetSchedule::single(m.set.clone()),
                validator::EpochSchedule::single(m.set.epoch),
                chain_id.to_vec(),
                m.consensus[0].id.clone(),
                m.consensus[0].private_key.clone(),
                anchor.clone(),
                0,
            )
            .unwrap(),
        )
        .unwrap()
    };
    let mut reserved_coordinator = make_coordinator();
    let mut intents = Vec::new();
    let reserved_build = reserved_coordinator
        .build_ready_with_reservation(&m, &batches, &controls, 42, |header, coverage| {
            intents.push((header.clone(), coverage));
            Ok(())
        })
        .unwrap();
    assert_eq!(intents.len(), 2);
    for (index, (header, coverage)) in intents.iter().enumerate() {
        assert_eq!(header, &built.shares[index].header);
        assert_eq!(header, &reserved_build.shares[index].header);
        assert_eq!(*coverage, recovered.applications()[index].order_len());
    }
    let mut reservation_failed = make_coordinator();
    assert!(
        reservation_failed
            .build_ready_with_reservation(&m, &batches, &controls, 42, |_, _| {
                Err(crypto::CryptoError::new(
                    crypto::CryptoErrorKind::InvalidVertex,
                    "reservation publication uncertain",
                ))
            })
            .is_err()
    );
    assert_eq!(reservation_failed.finalizer().built_headers(), 0);
    assert_eq!(reservation_failed.finalizer().last_built(), &anchor);
    assert!(reservation_failed.update(recovered.clone()).is_err());
    assert!(
        reservation_failed
            .build_ready(&m, &batches, &controls, 43)
            .is_err()
    );
    let boundary = recovered.applications()[0].order_len();
    let second_hash = recovered.vertices()[boundary].payload_hash;
    let mut missing = batches.clone();
    missing.remove(&second_hash);
    let mut partial = make_coordinator();
    let first_build = partial.build_ready(&m, &missing, &controls, 50).unwrap();
    assert_eq!(first_build.shares.len(), 1);
    assert_eq!(first_build.shares[0].header, built.shares[0].header);
    assert_eq!(
        partial.execution().consumed_order(),
        &recovered.order()[..boundary]
    );
    assert_eq!(
        partial.execution().state().state_root(),
        expected_prefixes[0].0
    );
    let second_build = partial.build_ready(&m, &batches, &controls, 51).unwrap();
    assert_eq!(second_build.shares.len(), 1);
    assert_eq!(second_build.shares[0].header, built.shares[1].header);

    // If a later batch is invalid, retain already built output until a successful retry.
    let mut wrong = batches.clone();
    let foreign = batches
        .iter()
        .find(|(hash, _)| **hash != second_hash)
        .unwrap()
        .1
        .clone();
    wrong.insert(second_hash, foreign);
    let mut retry = make_coordinator();
    assert!(retry.build_ready(&m, &wrong, &controls, 60).is_err());
    assert_eq!(retry.finalizer().built_headers(), 1);
    let retried = retry.build_ready(&m, &batches, &controls, 61).unwrap();
    assert_eq!(retried.shares.len(), 2);
    assert_eq!(retried.shares[0].header, built.shares[0].header);
    assert_eq!(retried.shares[0].at, 60);
    assert_eq!(retried.shares[1].header, built.shares[1].header);
    assert_eq!(retried.shares[1].at, 61);
    assert_eq!(retry.finalizer().built_headers(), 2);

    let peer_share = |height: usize, signer: usize| {
        let mut share = built.shares[height - 1].clone();
        share.signer = signer;
        share.signature = Ed25519Scheme
            .sign(
                &m.consensus[signer].private_key,
                &validator::signing_payload(&share.header).unwrap(),
            )
            .unwrap();
        share
    };
    // A raw finalizer can buffer future peer quorums while still appearing anchored
    // at genesis. Do not let that hidden queue enter the certified-only coordinator.
    let mut buffered = validator::Finalizer::new(
        validator::SetSchedule::single(m.set.clone()),
        validator::EpochSchedule::single(m.set.epoch),
        chain_id.to_vec(),
        m.consensus[0].id.clone(),
        m.consensus[0].private_key.clone(),
        anchor.clone(),
        0,
    )
    .unwrap();
    assert!(!buffered.has_pending_work());
    for signer in 0..3 {
        assert!(
            buffered
                .receive_share(peer_share(2, signer))
                .unwrap()
                .is_empty()
        );
    }
    assert_eq!(buffered.head(), &anchor);
    assert_eq!(buffered.built_headers(), 0);
    assert_eq!(buffered.next_height(), 1);
    assert!(buffered.has_pending_work());
    assert!(
        CertifiedFinalization::begin(
            recovered.clone(),
            chain::genesis_state(&accounts).unwrap(),
            buffered
        )
        .is_err()
    );

    let mut unexecuted = make_coordinator();
    assert!(unexecuted.receive_share(&m, peer_share(1, 1)).is_err());
    assert_eq!(unexecuted.finalizer().head(), &anchor);
    assert!(unexecuted.execution().consumed_order().is_empty());
    let foreign_membership = chain::membership(3, None).unwrap();
    assert!(
        unexecuted
            .build_ready(&foreign_membership, &batches, &controls, 70)
            .is_err()
    );
    assert!(unexecuted.execution().consumed_order().is_empty());
    assert!(
        coordinator
            .receive_share(&foreign_membership, peer_share(1, 1))
            .is_err()
    );
    let mut conflicting = peer_share(1, 1);
    conflicting.header.state_root[0] ^= 1;
    assert!(coordinator.receive_share(&m, conflicting).is_err());
    let mut invalid_signature = peer_share(1, 1);
    invalid_signature.signature[0] ^= 1;
    assert!(coordinator.receive_share(&m, invalid_signature).is_err());
    let mut wrong_signer = peer_share(1, 1);
    wrong_signer.signer = 2;
    assert!(coordinator.receive_share(&m, wrong_signer).is_err());
    let mut out_of_range = peer_share(1, 1);
    out_of_range.signer = m.set.validators.len();
    assert!(coordinator.receive_share(&m, out_of_range).is_err());
    assert_eq!(coordinator.finalizer().head(), &anchor);
    // Future built headers can collect valid shares, but cannot skip the missing height.
    assert!(
        coordinator
            .receive_share(&m, peer_share(2, 1))
            .unwrap()
            .is_empty()
    );
    assert!(
        coordinator
            .receive_share(&m, peer_share(2, 2))
            .unwrap()
            .is_empty()
    );
    assert_eq!(coordinator.finalizer().head(), &anchor);
    for _ in 0..3 {
        assert!(
            coordinator
                .receive_share(&m, peer_share(1, 1))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            coordinator.finalizer().head(),
            &anchor,
            "duplicates must not count as additional validators"
        );
    }
    let certified = coordinator.receive_share(&m, peer_share(1, 2)).unwrap();
    assert_eq!(
        certified.len(),
        2,
        "closing height one releases both contiguous certificates"
    );
    for (index, finalized) in certified.iter().enumerate() {
        assert_eq!(finalized.header, built.shares[index].header);
        coordinator
            .finalizer()
            .verify_certificate(&finalized.header, &finalized.certificate)
            .unwrap();
        assert_eq!(
            coordinator
                .finalizer()
                .certified_order(finalized.header.height),
            Some(recovered.applications()[index].order_len())
        );
    }
    assert_eq!(coordinator.finalizer().head(), &built.shares[1].header);
    for height in 1..=2 {
        for signer in 0..3 {
            assert!(
                coordinator
                    .receive_share(&m, peer_share(height, signer))
                    .unwrap()
                    .is_empty()
            );
        }
    }
    assert_eq!(coordinator.finalizer().head(), &built.shares[1].header);
    assert_eq!(coordinator.execution().state(), &expected);
    assert_eq!(coordinator.execution().applied(), applied);
    drop(adapter);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert_eq!(adapter.header_intents().unwrap(), durable_intents);
    let make_finalizer = |anchor: validator::Header| {
        validator::Finalizer::new(
            validator::SetSchedule::single(m.set.clone()),
            validator::EpochSchedule::single(m.set.epoch),
            chain_id.to_vec(),
            m.consensus[0].id.clone(),
            m.consensus[0].private_key.clone(),
            anchor,
            0,
        )
        .unwrap()
    };
    let open_replay = || {
        JournaledFinalization::open(
            Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap(),
            chain::genesis_state(&accounts).unwrap(),
            make_finalizer(anchor.clone()),
        )
        .unwrap()
    };
    // Crash boundary: intents survived but no completed share was journaled.
    // Recovery must re-execute exact headers rather than infer a completed signature.
    assert!(adapter.header_shares().unwrap().is_empty());
    assert!(!dir.0.join("agreement-header-shares").exists());
    // Recovery owns the adapter and cannot accidentally use a no-op reservation callback.
    // Keep earlier rebuilt output private until the entire old reserved history matches.
    let mut replay = open_replay();
    let deferred = replay.build_ready(&m, &missing, &controls, 99).unwrap();
    assert!(deferred.shares.is_empty() && deferred.certified.is_empty());
    assert_eq!(replay.finalization().finalizer().built_headers(), 1);
    assert!(replay.receive_share(&m, peer_share(1, 1)).is_err());
    let replayed = replay.build_ready(&m, &batches, &controls, 100).unwrap();
    assert_eq!(replayed.shares.len(), 2);
    for (index, share) in replayed.shares.iter().enumerate() {
        assert_eq!(share.header, built.shares[index].header);
        assert_eq!(share.signature, built.shares[index].signature);
    }
    assert_eq!(replayed.shares[0].at, 99);
    assert_eq!(replayed.shares[1].at, 100);
    assert_eq!(adapter.header_shares().unwrap(), replayed.shares);
    let share_journal = dir.0.join("agreement-header-shares");
    let local_share_bytes = std::fs::read(&share_journal).unwrap();
    let mut invalid_peer = peer_share(1, 1);
    invalid_peer.signature[0] ^= 1;
    assert!(replay.receive_share(&m, invalid_peer).is_err());
    assert_eq!(std::fs::read(&share_journal).unwrap(), local_share_bytes);
    assert_eq!(replay.finalization().execution().state(), &expected);
    assert_eq!(replay.finalization().execution().applied(), applied);
    assert_eq!(
        replay.finalization().finalizer().head(),
        &anchor,
        "header intents do not restore old finality certificates"
    );
    assert!(
        replay
            .build_ready(&m, &batches, &controls, 101)
            .unwrap()
            .shares
            .is_empty()
    );
    if matches!(
        mode,
        AuthenticatedReplayMode::RestorePublicationFailure
            | AuthenticatedReplayMode::RestoreIoFailure(_)
    ) {
        // Local output has already drained, so the next build has no signing or
        // reservation work. Only restore_shares can re-publish the visible shares.
        assert_eq!(replay.finalization().finalizer().built_headers(), 2);
        assert_eq!(
            replay.finalization().finalizer().last_built(),
            &built.shares[1].header
        );
        assert_eq!(adapter.header_intents().unwrap(), durable_intents);
        for height in [2, 1] {
            for signer in [1, 2] {
                adapter
                    .reserve_header_share(&anchor, &peer_share(height, signer))
                    .unwrap();
            }
        }
        // Simulate a stop after the quorum-closing share's durable reservation,
        // before wrapper collection/return. No certificate has been delivered here.
        let durable_shares = adapter.header_shares().unwrap();
        assert_eq!(durable_shares.len(), 6);
        assert_eq!(replay.finalization().finalizer().head(), &anchor);
        let journal_bytes = || {
            [
                "authenticated-slot-agreement",
                "agreement-header-intents",
                "agreement-header-shares",
            ]
            .into_iter()
            .map(|name| (name, std::fs::read(dir.0.join(name)).unwrap()))
            .collect::<BTreeMap<_, _>>()
        };
        let before = journal_bytes();
        let temporary = dir.0.join("agreement-header-shares.tmp");
        assert!(!temporary.exists());
        let injected = if let AuthenticatedReplayMode::RestoreIoFailure(stage) = mode {
            // Five complete re-publications precede the fault on the last record.
            // Even a complete earlier quorum must not escape the batch barrier.
            replay.fail_share_publication(stage, durable_shares.len() - 1);
            Some(stage)
        } else {
            std::fs::create_dir(&temporary).unwrap();
            None
        };
        // Reads and owner checks succeed. The directory obstruction exercises
        // pre-publication validation; injected cases enter the real pipeline.
        assert_eq!(adapter.header_shares().unwrap(), durable_shares);
        assert_eq!(adapter.header_intents().unwrap(), durable_intents);
        assert_eq!(
            format!("{:?}", adapter.ordering_snapshot().unwrap()),
            format!("{recovered:?}")
        );
        let failed = replay.build_ready(&m, &batches, &controls, 102);
        let error = match failed {
            Err(error) => error,
            Ok(_) => panic!("restore must fail without returning a Build"),
        };
        if let Some(stage) = injected {
            assert!(
                error.contains(&format!("injected share publication {stage:?} failure")),
                "{error}"
            );
            assert_eq!(
                temporary.exists(),
                stage != store::SharePublicationStage::DirectorySync
            );
        } else {
            assert_eq!(error, "store io: pointer is not a regular file");
        }
        assert_eq!(replay.finalization().finalizer().head(), &anchor);
        for height in 1..=2 {
            assert_eq!(
                replay.finalization().finalizer().certified_order(height),
                None
            );
        }
        assert_eq!(replay.finalization().finalizer().built_headers(), 2);
        assert_eq!(replay.finalization().execution().state(), &expected);
        assert_eq!(journal_bytes(), before);
        if injected.is_none() {
            std::fs::remove_dir(&temporary).unwrap();
        } else if temporary.exists() {
            std::fs::remove_file(&temporary).unwrap();
        }
        let poisoned = "journaled finalization requires reopening after durable history failure";
        assert_eq!(
            replay
                .build_ready(&m, &batches, &controls, 103)
                .err()
                .as_deref(),
            Some(poisoned)
        );
        assert_eq!(
            replay.receive_share(&m, peer_share(1, 2)).err().as_deref(),
            Some(poisoned)
        );
        assert_eq!(replay.finalization().finalizer().head(), &anchor);
        assert_eq!(journal_bytes(), before);

        if injected.is_some() {
            // A fresh owner cannot treat visible identical bytes as durable. Fail
            // its first directory barrier, proving it re-enters publication too.
            let mut retry = open_replay();
            retry.fail_share_publication(store::SharePublicationStage::DirectorySync, 0);
            assert!(retry.build_ready(&m, &batches, &controls, 104).is_err());
            assert_eq!(retry.finalization().finalizer().head(), &anchor);
            assert_eq!(journal_bytes(), before);
        }
        drop(replay);
        drop(adapter);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
        let mut fresh = JournaledFinalization::open(
            Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap(),
            chain::genesis_state(&accounts).unwrap(),
            make_finalizer(anchor.clone()),
        )
        .unwrap();
        let restored = fresh.build_ready(&m, &batches, &controls, 104).unwrap();
        assert_eq!(restored.shares, replayed.shares);
        assert_eq!(restored.certified.len(), 2);
        for (index, certified) in restored.certified.iter().enumerate() {
            assert_eq!(certified.header, built.shares[index].header);
            fresh
                .finalization()
                .finalizer()
                .verify_certificate(&certified.header, &certified.certificate)
                .unwrap();
            assert_eq!(
                fresh
                    .finalization()
                    .finalizer()
                    .certified_order(certified.header.height),
                Some(recovered.applications()[index].order_len())
            );
        }
        assert_eq!(
            fresh.finalization().finalizer().head(),
            &built.shares[1].header
        );
        assert_eq!(fresh.finalization().execution().state(), &expected);
        assert_eq!(fresh.finalization().execution().applied(), applied);
        assert_eq!(
            fresh.finalization().execution().consumed_order(),
            recovered.order()
        );
        assert_eq!(adapter.header_shares().unwrap(), durable_shares);
        assert_eq!(journal_bytes(), before);
        return;
    }
    for height in [2, 1] {
        assert!(
            replay
                .receive_share(&m, peer_share(height, 1))
                .unwrap()
                .is_empty()
        );
    }
    // Crash with partial shares at both heights; recovered duplicates add no weight.
    let mut replay = open_replay();
    let partial = replay.build_ready(&m, &batches, &controls, 10_000).unwrap();
    assert_eq!(partial.shares, replayed.shares);
    assert!(partial.certified.is_empty());
    assert_eq!(replay.finalization().finalizer().head(), &anchor);
    assert!(
        replay
            .receive_share(&m, peer_share(1, 1))
            .unwrap()
            .is_empty()
    );
    // A durable future quorum must wait for the missing lower height, even on restart.
    assert!(
        replay
            .receive_share(&m, peer_share(2, 2))
            .unwrap()
            .is_empty()
    );
    let mut replay = open_replay();
    let partial = replay.build_ready(&m, &missing, &controls, 20_000).unwrap();
    assert!(partial.shares.is_empty() && partial.certified.is_empty());
    assert_eq!(replay.finalization().finalizer().head(), &anchor);
    let partial = replay.build_ready(&m, &batches, &controls, 20_001).unwrap();
    assert_eq!(partial.shares, replayed.shares);
    assert!(partial.certified.is_empty());
    assert_eq!(replay.finalization().finalizer().built_headers(), 2);
    let recertified = replay.receive_share(&m, peer_share(1, 2)).unwrap();
    assert_eq!(recertified.len(), 2);
    let recertified = replay.receive_share(&m, peer_share(2, 2)).unwrap();
    assert!(recertified.is_empty());
    assert_eq!(
        replay.finalization().finalizer().head(),
        &built.shares[1].header
    );
    assert_eq!(adapter.header_intents().unwrap(), durable_intents);
    // Late records can change reconstructed certificate metadata, not the certified
    // header or its execution coverage. Signer order must not select the quorum.
    let mut late_share = peer_share(1, 3);
    late_share.at = 1;
    assert!(replay.receive_share(&m, late_share).unwrap().is_empty());
    let persisted = adapter.header_shares().unwrap();
    assert_eq!(persisted.len(), 7);
    for share in &persisted {
        assert_eq!(
            share.header,
            built.shares[share.header.height as usize - 1].header
        );
    }
    // A new owner re-executes rather than trusting the share journal as execution
    // proof. Local output preserves the first persisted timestamp, not this retry's.
    let mut share_replay = open_replay();
    let repeated = share_replay
        .build_ready(&m, &batches, &controls, 104)
        .unwrap();
    assert_eq!(repeated.shares, replayed.shares);
    assert_eq!(repeated.certified.len(), 2);
    assert_eq!(
        share_replay.finalization().finalizer().head(),
        &built.shares[1].header
    );
    for (index, certificate) in repeated.certified.iter().enumerate() {
        let mut times: Vec<_> = persisted
            .iter()
            .filter(|share| share.header.height == certificate.header.height)
            .map(|share| share.at)
            .collect();
        times.sort_unstable();
        assert_eq!(
            certificate.at,
            times[m.set.quorum_size() - 1],
            "reconstructed quorum must consider every durable record, not signer order"
        );
        if index == 0 {
            assert!(
                certificate.at < 99,
                "late share changes metadata, not the header"
            );
            assert_ne!(certificate.certificate.signer_bitmap[0] & (1 << 3), 0);
        }
        assert_eq!(
            share_replay
                .finalization()
                .finalizer()
                .certified_order(certificate.header.height),
            Some(recovered.applications()[index].order_len())
        );
        share_replay
            .finalization()
            .finalizer()
            .verify_certificate(&certificate.header, &certificate.certificate)
            .unwrap();
    }
    assert!(
        share_replay
            .build_ready(&m, &batches, &controls, 30_000)
            .unwrap()
            .certified
            .is_empty()
    );
    assert_eq!(adapter.header_shares().unwrap(), persisted);
    if matches!(
        mode,
        AuthenticatedReplayMode::ContinueAfterRecovery | AuthenticatedReplayMode::SameOwnerWire
    ) {
        // The third leader is fresh; its authenticated cone includes additional real
        // batches from round two, not just a synthetic snapshot boundary.
        let mut dag = Dag::new(m.set.clone());
        dag.set_chain_id(chain_id.to_vec());
        for vertex in &vertices {
            dag.insert(vertex.clone()).unwrap();
        }
        dag.seed_order(recovered.order().to_vec());
        let validator::Decision::Commit(suffix) = dag.inspect_commit(3).unwrap() else {
            panic!("round-four voters must commit round three")
        };
        let leader = dag.leader(3).unwrap().id().unwrap();
        assert!(!recovered.order().contains(&leader));
        assert!(suffix.contains(&leader));
        let mut third_order = recovered.order().to_vec();
        third_order.extend(suffix);
        let mut proposal = SlotProposal {
            decision: SlotDecision {
                chain_id: chain_id.to_vec(),
                validator_set_id: m.set.id().unwrap(),
                epoch: m.set.epoch,
                round: 3,
                previous: *recovered.binding().tip().previous_id(),
                before_len: recovered.order().len() as u64,
                before_root: validator::commit_root(recovered.order()),
                after_len: third_order.len() as u64,
                after_root: validator::commit_root(&third_order),
                outcome: SlotOutcome::Commit { leader },
            },
            voters: vertices
                .iter()
                .filter(|v| v.round == 4)
                .take(3)
                .map(|v| v.id().unwrap())
                .collect(),
        };
        proposal.voters.sort_by(|a, b| {
            (&a.round, &a.author, &a.digest).cmp(&(&b.round, &b.author, &b.digest))
        });
        let refs = vertices
            .iter()
            .filter(|v| v.round == 14)
            .map(|v| v.id().unwrap())
            .collect::<Vec<_>>();
        let mut proposal_carrier = None;
        for author in 0..4 {
            let hash = if author == 0 {
                proposal.digest().unwrap()
            } else {
                [9; 32]
            };
            let vertex = signed_for_chain(&m, author, 15, refs.clone(), hash, chain_id);
            if author == 0 {
                proposal_carrier = Some(vertex.id().unwrap());
            }
            vertices.push(vertex);
        }
        let (proof, carrier) = append_proof(
            &m,
            chain_id,
            &mut vertices,
            recovered.binding().tip().clone(),
            proposal,
            proposal_carrier.unwrap(),
            16,
        );
        if matches!(mode, AuthenticatedReplayMode::SameOwnerWire) {
            use net::wire::{self, Message};
            assert_eq!(
                share_replay.advance_certified_slot().unwrap_err(),
                "cannot advance an undecided slot"
            );
            // Structural rejection is not a durable failure and must not poison the owner.
            assert!(
                share_replay
                    .receive_agreement_message(Message::AgreementCarrier {
                        envelope: vec![0],
                        vertices: Vec::new(),
                    })
                    .is_err()
            );
            let envelope = CarrierEnvelope::from_publication(
                carrier,
                CarrierPayload::Final(proof.clone()),
                proof.digest(&m.set).unwrap(),
                &m.set,
            )
            .unwrap();
            let message = Message::AgreementCarrier {
                envelope: envelope.encode(&m.set).unwrap(),
                vertices: vertices.clone(),
            };
            let receive = |owner: &mut JournaledFinalization| {
                let mut bytes = wire::frame(&message, 123).unwrap();
                let frame = wire::take_frame(&mut bytes).unwrap().unwrap();
                assert!(bytes.is_empty());
                owner.receive_agreement_message(frame.message).unwrap();
            };
            receive(&mut share_replay);
            receive(&mut share_replay);
            assert!(
                share_replay
                    .build_ready(&m, &batches, &controls, 199)
                    .unwrap()
                    .shares
                    .is_empty()
            );
            assert_eq!(share_replay.finalization().execution().state(), &expected);
            assert_eq!(
                share_replay.finalization().finalizer().last_built(),
                &built.shares[1].header
            );
            share_replay.advance_certified_slot().unwrap();
            assert_eq!(
                share_replay.advance_certified_slot().unwrap_err(),
                "cannot advance an undecided slot"
            );
            let third = Adapter::recover(&store, bootstrap.clone(), &m, 0)
                .unwrap()
                .ordering_snapshot()
                .unwrap();
            assert_eq!(third.order(), third_order);
            assert_eq!(third.applications().len(), 3);
            let controls: BTreeSet<_> = vertices
                .iter()
                .filter(|v| !batches.contains_key(&v.payload_hash))
                .map(|v| v.payload_hash)
                .collect();
            let missing = third
                .vertices()
                .iter()
                .find(|v| {
                    third.order()[recovered.order().len()..].contains(&v.id().unwrap())
                        && batches.contains_key(&v.payload_hash)
                })
                .unwrap()
                .payload_hash;
            let mut incomplete = batches.clone();
            incomplete.remove(&missing);
            assert!(
                share_replay
                    .build_ready(&m, &incomplete, &controls, 200)
                    .unwrap()
                    .shares
                    .is_empty()
            );
            assert_eq!(
                share_replay.finalization().finalizer().last_built(),
                &built.shares[1].header
            );
            coordinator.update(third.clone()).unwrap();
            let expected_build = coordinator
                .build_ready(&m, &batches, &controls, 200)
                .unwrap();
            let resumed = share_replay
                .build_ready(&m, &batches, &controls, 200)
                .unwrap();
            assert_eq!(resumed.shares, expected_build.shares);
            assert_eq!(resumed.shares.len(), 1);
            let local = resumed.shares[0].clone();
            assert_eq!(local.header.height, 3);
            assert_eq!(local.header.previous, built.shares[1].header.id().unwrap());
            assert_eq!(
                share_replay.finalization().execution().state(),
                coordinator.execution().state()
            );
            assert_eq!(
                share_replay.finalization().execution().applied(),
                coordinator.execution().applied()
            );
            assert_eq!(
                share_replay.finalization().execution().consumed_order(),
                third.order()
            );
            for signer in [1, 2] {
                let mut peer = local.clone();
                peer.signer = signer;
                peer.at = 200 + signer as u64;
                peer.signature = Ed25519Scheme
                    .sign(
                        &m.consensus[signer].private_key,
                        &validator::signing_payload(&peer.header).unwrap(),
                    )
                    .unwrap();
                let expected = coordinator.receive_share(&m, peer.clone()).unwrap();
                let actual = share_replay.receive_share(&m, peer.clone()).unwrap();
                assert_eq!(actual.len(), expected.len());
                for (actual, expected) in actual.iter().zip(&expected) {
                    assert_eq!(actual.header, expected.header);
                    assert_eq!(actual.certificate, expected.certificate);
                    assert_eq!(actual.at, expected.at);
                    share_replay
                        .finalization()
                        .finalizer()
                        .verify_certificate(&actual.header, &actual.certificate)
                        .unwrap();
                }
                assert!(share_replay.receive_share(&m, peer).unwrap().is_empty());
            }
            assert_eq!(
                share_replay.finalization().finalizer().head(),
                &local.header
            );
            let applied = share_replay.finalization().execution().applied();
            assert!(
                share_replay
                    .build_ready(&m, &batches, &controls, 999)
                    .unwrap()
                    .shares
                    .is_empty()
            );
            assert_eq!(share_replay.finalization().execution().applied(), applied);
            assert_eq!(
                share_replay.finalization().finalizer().last_built(),
                &local.header
            );
            return;
        }
        let mut owner = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
        owner
            .apply(AuthenticatedSlotAgreementRequest::ObservePrecommit {
                proof,
                carrier,
                vertices: vertices.clone(),
            })
            .unwrap();
        owner
            .apply(AuthenticatedSlotAgreementRequest::AdvanceSlot)
            .unwrap();
        let third = owner.ordering_snapshot().unwrap();
        assert_eq!(third.applications().len(), 3);
        assert_eq!(third.applications()[2].round(), 3);
        assert!(third.applications()[2].is_commit());
        assert_eq!(third.order(), third_order);
        assert!(third.order().len() > recovered.order().len());
        let controls: BTreeSet<_> = vertices
            .iter()
            .filter(|v| !batches.contains_key(&v.payload_hash))
            .map(|v| v.payload_hash)
            .collect();
        let mut third_expected = chain::genesis_state(&accounts).unwrap();
        let mut rejected = BTreeMap::new();
        let mut third_applied = 0;
        for vertex in third.vertices() {
            if let Some(batch) = batches.get(&vertex.payload_hash) {
                third_applied +=
                    chain::apply_batch(&mut third_expected, &accounts, batch, &mut rejected) as u64;
            }
        }
        assert!(rejected.is_empty());
        assert!(third_applied > applied);
        assert_ne!(third_expected.state_root(), expected.state_root());

        coordinator.update(third.clone()).unwrap();
        let uninterrupted = coordinator
            .build_ready(&m, &batches, &controls, 200)
            .unwrap();
        assert_eq!(uninterrupted.shares.len(), 1);
        assert!(uninterrupted.certified.is_empty());
        // A sibling advance invalidates the recovered owner; continuation requires
        // reopening durable history, not an in-place agreement refresh.
        let stale = share_replay
            .build_ready(&m, &batches, &controls, 200)
            .err()
            .expect("sibling AdvanceSlot must invalidate the recovered owner");
        assert_eq!(
            stale,
            "store decode: crypto: malformed_certificate: stale authenticated owner"
        );
        assert_eq!(
            share_replay.finalization().finalizer().head(),
            &built.shares[1].header
        );
        assert_eq!(
            share_replay
                .build_ready(&m, &batches, &controls, 201)
                .err()
                .as_deref(),
            Some("journaled finalization requires reopening after durable history failure")
        );
        assert_eq!(
            share_replay.finalization().finalizer().head(),
            &built.shares[1].header
        );
        let mut continued = open_replay();
        let resumed = continued.build_ready(&m, &batches, &controls, 200).unwrap();
        assert_eq!(resumed.shares.len(), 3);
        assert_eq!(&resumed.shares[..2], replayed.shares.as_slice());
        assert_eq!(resumed.shares[2], uninterrupted.shares[0]);
        assert_eq!(resumed.certified.len(), 2);
        let local = &resumed.shares[2];
        assert_eq!(local.at, 200);
        assert_eq!(local.header.height, 3);
        assert_eq!(local.header.round, 3);
        assert_eq!(local.header.previous, built.shares[1].header.id().unwrap());
        assert_eq!(local.header.state_root, third_expected.state_root());
        assert_eq!(local.header.applied, third_applied);
        assert_eq!(local.header.dag_root, validator::commit_root(third.order()));
        let peer = |signer: usize, at| {
            let mut share = local.clone();
            share.signer = signer;
            share.at = at;
            share.signature = Ed25519Scheme
                .sign(
                    &m.consensus[signer].private_key,
                    &validator::signing_payload(&share.header).unwrap(),
                )
                .unwrap();
            share
        };
        assert!(
            coordinator
                .receive_share(&m, peer(1, 201))
                .unwrap()
                .is_empty()
        );
        assert!(
            continued
                .receive_share(&m, peer(1, 201))
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            continued.finalization().finalizer().head(),
            &built.shares[1].header
        );
        assert_eq!(
            continued.finalization().finalizer().last_built(),
            &local.header
        );
        assert_eq!(
            continued.finalization().finalizer().certified_order(3),
            None
        );
        drop(continued);
        let mut continued = open_replay();
        let partial = continued
            .build_ready(&m, &batches, &controls, 30_001)
            .unwrap();
        assert_eq!(partial.shares.len(), 3);
        assert_eq!(&partial.shares[..2], replayed.shares.as_slice());
        assert_eq!(partial.shares[2], *local);
        assert_eq!(partial.certified.len(), 2);
        assert_eq!(
            continued.finalization().finalizer().head(),
            &built.shares[1].header
        );
        assert!(
            continued
                .receive_share(&m, peer(1, 999))
                .unwrap()
                .is_empty()
        );
        let expected_certificate = coordinator.receive_share(&m, peer(2, 202)).unwrap();
        let actual_certificate = continued.receive_share(&m, peer(2, 202)).unwrap();
        assert_eq!(actual_certificate.len(), 1);
        assert_eq!(expected_certificate.len(), 1);
        assert_eq!(actual_certificate[0].header, expected_certificate[0].header);
        assert_eq!(
            actual_certificate[0].certificate,
            expected_certificate[0].certificate
        );
        assert_eq!(actual_certificate[0].at, 202);
        assert_eq!(actual_certificate[0].at, expected_certificate[0].at);
        continued
            .finalization()
            .finalizer()
            .verify_certificate(
                &actual_certificate[0].header,
                &actual_certificate[0].certificate,
            )
            .unwrap();
        for finalization in [&coordinator, continued.finalization()] {
            assert_eq!(finalization.finalizer().head(), &local.header);
            assert_eq!(finalization.finalizer().last_built(), &local.header);
            assert_eq!(
                finalization.finalizer().last_built_order(),
                third.order().len()
            );
            assert_eq!(
                finalization.finalizer().certified_order(3),
                Some(third.order().len())
            );
            assert_eq!(finalization.execution().state(), &third_expected);
            assert_eq!(finalization.execution().applied(), third_applied);
            assert_eq!(finalization.execution().consumed_order(), third.order());
        }
        let shares = owner.header_shares().unwrap();
        assert_eq!(shares.len(), persisted.len() + 3);
        for share in &persisted {
            assert!(shares.contains(share));
        }
        for share in [local.clone(), peer(1, 201), peer(2, 202)] {
            assert!(shares.contains(&share));
        }
        let intents = owner.header_intents().unwrap();
        assert_eq!(&intents[..2], durable_intents.as_slice());
        assert_eq!(intents.len(), 3);
        assert_eq!(intents[2].header(), &local.header);
        assert_eq!(intents[2].application(), 2);
        assert_eq!(intents[2].order_len(), third.order().len());
        return;
    }
    let mut wrong_anchor = anchor.clone();
    wrong_anchor.previous[0] ^= 1;
    assert!(
        JournaledFinalization::open(
            Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap(),
            chain::genesis_state(&accounts).unwrap(),
            make_finalizer(wrong_anchor),
        )
        .is_err()
    );
    // Caller-misclassified payloads change execution, but cannot change reserved bytes.
    let mut conflicting_replay = open_replay();
    let wrong_controls: BTreeSet<_> = recovered
        .vertices()
        .iter()
        .map(|v| v.payload_hash)
        .collect();
    assert!(
        conflicting_replay
            .build_ready(&m, &BTreeMap::new(), &wrong_controls, 102)
            .is_err()
    );
    assert_eq!(
        conflicting_replay
            .finalization()
            .finalizer()
            .built_headers(),
        0
    );
    assert!(
        conflicting_replay
            .build_ready(&m, &batches, &controls, 103)
            .is_err()
    );
    assert_eq!(adapter.header_intents().unwrap(), durable_intents);
    // A conflict at the second boundary must not leak the first rebuilt share.
    let mut late_conflict = open_replay();
    let late_controls: BTreeSet<_> = recovered.vertices()[boundary..]
        .iter()
        .map(|v| v.payload_hash)
        .collect();
    let early_batches: BTreeMap<_, _> = batches
        .iter()
        .filter(|(hash, _)| !late_controls.contains(*hash))
        .map(|(hash, batch)| (*hash, batch.clone()))
        .collect();
    assert!(
        late_conflict
            .build_ready(&m, &early_batches, &late_controls, 103)
            .is_err()
    );
    assert_eq!(late_conflict.finalization().finalizer().built_headers(), 1);
    assert!(
        late_conflict
            .build_ready(&m, &batches, &controls, 104)
            .is_err()
    );
    assert!(late_conflict.receive_share(&m, peer_share(1, 1)).is_err());
    assert_eq!(adapter.header_intents().unwrap(), durable_intents);
    // Sibling WAL handles must share this Store's exclusive OS lock. Prepare both
    // wrappers before journal corruption so stale ownership is checked independently.
    let mut stale_build = open_replay();
    let mut stale_share = open_replay();
    let stale_replayed = stale_share
        .build_ready(&m, &batches, &controls, 105)
        .unwrap();
    assert_eq!(stale_replayed.shares.len(), 2);
    assert_eq!(stale_replayed.certified.len(), 2);
    assert!(
        stale_share
            .receive_share(&m, peer_share(1, 1))
            .unwrap()
            .is_empty()
    );

    // Completed-share corruption must independently stop open, build and peer collection.
    let mut bad_share_build = open_replay();
    let mut bad_share_receive = open_replay();
    bad_share_receive
        .build_ready(&m, &batches, &controls, 108)
        .unwrap();
    let share_bytes = std::fs::read(&share_journal).unwrap();
    let mut bad_share_bytes = share_bytes.clone();
    bad_share_bytes[10] ^= 1;
    std::fs::write(&share_journal, &bad_share_bytes).unwrap();
    assert!(
        JournaledFinalization::open(
            Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap(),
            chain::genesis_state(&accounts).unwrap(),
            make_finalizer(anchor.clone()),
        )
        .is_err()
    );
    assert!(
        bad_share_build
            .build_ready(&m, &batches, &controls, 109)
            .is_err()
    );
    assert!(
        bad_share_receive
            .receive_share(&m, peer_share(1, 2))
            .is_err()
    );
    std::fs::write(&share_journal, &share_bytes).unwrap();
    for (wrapper, expected_head) in [
        (&mut bad_share_build, &anchor),
        (&mut bad_share_receive, &built.shares[1].header),
    ] {
        assert!(wrapper.build_ready(&m, &batches, &controls, 110).is_err());
        assert!(wrapper.receive_share(&m, peer_share(1, 2)).is_err());
        assert_eq!(wrapper.finalization().finalizer().head(), expected_head);
    }
    assert_eq!(std::fs::read(&share_journal).unwrap(), share_bytes);

    // Independently check both entry points, not just a wrapper already poisoned by one.
    let mut corrupt_build = open_replay();
    let path = dir.0.join("agreement-header-intents");
    let mut corrupt = std::fs::read(&path).unwrap();
    corrupt[0] ^= 1;
    std::fs::write(&path, &corrupt).unwrap();
    assert!(replay.receive_share(&m, peer_share(1, 1)).is_err());
    assert!(
        corrupt_build
            .build_ready(&m, &batches, &controls, 104)
            .is_err()
    );
    assert_eq!(corrupt_build.finalization().finalizer().built_headers(), 0);
    assert!(
        JournaledFinalization::open(
            Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap(),
            chain::genesis_state(&accounts).unwrap(),
            make_finalizer(anchor.clone()),
        )
        .is_err()
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);

    assert_eq!(
        std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap(),
        wal
    );

    // Advance through a sibling from the same Store, not a second Store::open.
    // Ownership must fail before the independently corrupted intent journal is read.
    let mut owner = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    let sequence = owner.driver.sequence();
    owner
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert_eq!(owner.driver.sequence(), sequence + 1);
    let advanced_wal = std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap();
    assert_ne!(advanced_wal, wal);
    let stale_error = stale_build
        .build_ready(&m, &batches, &controls, 106)
        .err()
        .expect("stale wrapper must not build or release shares");
    assert!(
        stale_error.contains("stale authenticated owner"),
        "{stale_error}"
    );
    let stale_error = stale_share
        .receive_share(&m, peer_share(1, 2))
        .err()
        .expect("stale wrapper must not accept a quorum-closing share");
    assert!(
        stale_error.contains("stale authenticated owner"),
        "{stale_error}"
    );
    for (wrapper, expected_head) in [
        (&mut stale_build, &anchor),
        (&mut stale_share, &built.shares[1].header),
    ] {
        let poisoned = "journaled finalization requires reopening after durable history failure";
        assert_eq!(
            wrapper
                .build_ready(&m, &batches, &controls, 107)
                .err()
                .as_deref(),
            Some(poisoned)
        );
        assert_eq!(
            wrapper.receive_share(&m, peer_share(1, 2)).err().as_deref(),
            Some(poisoned)
        );
        assert_eq!(wrapper.finalization().finalizer().head(), expected_head);
    }
    assert_eq!(stale_build.finalization().finalizer().built_headers(), 0);
    assert!(
        stale_build
            .finalization()
            .execution()
            .consumed_order()
            .is_empty()
    );
    assert_eq!(stale_share.finalization().finalizer().built_headers(), 2);
    assert_eq!(stale_share.finalization().execution().state(), &expected);
    assert_eq!(
        std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap(),
        advanced_wal
    );
    assert_eq!(std::fs::read(&path).unwrap(), corrupt);
}

#[test]
fn certified_execution_consumes_empty_controls_and_rejected_batches_in_order() {
    let (m, mut bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let before = adapter.driver.ordering_snapshot().unwrap();
    let accounts = chain::accounts(4).unwrap();
    let batch = chain::demo_batch(before.binding().tip().chain_id(), &accounts, 0, 0, 1).unwrap();
    let hash = batch.digest().unwrap();
    let control = [9; 32];
    // Trusted-checkpoint fixture for execution behavior, not evidence of a live QC.
    let vertices: Vec<_> = [[0; 32], control, hash, hash]
        .into_iter()
        .enumerate()
        .map(|(author, payload)| {
            signed_for_chain(
                &m,
                author,
                0,
                vec![],
                payload,
                before.binding().tip().chain_id(),
            )
        })
        .collect();
    let order: Vec<_> = vertices.iter().map(|vertex| vertex.id().unwrap()).collect();
    bootstrap.agreement.context = SlotDecisionTip::from_checkpoint(
        before.binding().tip().chain_id().to_vec(),
        &bootstrap.agreement.set,
        2,
        [7; 32],
        order.len() as u64,
        validator::commit_root(&order),
    )
    .unwrap();
    bootstrap.order = order.clone();
    bootstrap.vertices = vertices;
    let checkpoint_dir = Dir::new();
    let checkpoint_store = Store::open(&checkpoint_dir.0).unwrap();
    let snapshot = checkpoint_store
        .begin_authenticated_slot_agreement(bootstrap)
        .unwrap()
        .ordering_snapshot()
        .unwrap();
    let genesis = chain::genesis_state(&accounts).unwrap();
    let mut execution = CertifiedExecution::begin(before, genesis.clone()).unwrap();
    execution.update(snapshot).unwrap();
    let batches = std::collections::BTreeMap::from([(hash, batch.clone())]);
    execution
        .execute_ready(&m, &batches, &std::collections::BTreeSet::new())
        .unwrap();
    assert_eq!(execution.consumed_order(), &order[..1]);
    assert_eq!(execution.state(), &genesis);
    assert_eq!(execution.applied(), 0);
    let controls = std::collections::BTreeSet::from([control]);
    assert!(
        execution
            .execute_through(2, &m, &batches, &controls)
            .unwrap()
    );
    assert_eq!(execution.consumed_order(), &order[..2]);
    assert_eq!(execution.state(), &genesis);
    assert!(
        execution
            .execute_through(3, &m, &batches, &controls)
            .unwrap()
    );
    assert_eq!(execution.consumed_order(), &order[..3]);
    assert_eq!(execution.applied(), 1);
    let intermediate = execution.state().clone();
    assert!(
        execution
            .execute_through(2, &m, &batches, &controls)
            .is_err()
    );
    assert!(
        execution
            .execute_through(5, &m, &batches, &controls)
            .is_err()
    );
    assert_eq!(execution.state(), &intermediate);
    assert_eq!(execution.consumed_order(), &order[..3]);
    execution.execute_ready(&m, &batches, &controls).unwrap();
    assert_eq!(execution.consumed_order(), order);
    assert_eq!(
        execution.applied(),
        1,
        "a repeated sequence is rejected, not reapplied"
    );
    assert_eq!(execution.rejected().values().sum::<usize>(), 1);
    let mut expected = genesis;
    let mut rejected = std::collections::BTreeMap::new();
    assert_eq!(
        chain::apply_batch(&mut expected, &accounts, &batch, &mut rejected),
        1
    );
    assert_eq!(
        chain::apply_batch(&mut expected, &accounts, &batch, &mut rejected),
        0
    );
    assert_eq!(execution.state(), &expected);
    assert_eq!(execution.rejected(), &rejected);
}

#[test]
fn ordering_consumer_rejects_chain_set_and_epoch_changes() {
    let (_, bootstrap, _) = fixture();
    let snapshot = |bootstrap: AuthenticatedSlotAgreementBootstrap| {
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        store
            .begin_authenticated_slot_agreement(bootstrap)
            .unwrap()
            .ordering_snapshot()
            .unwrap()
    };
    let original = snapshot(bootstrap.clone());
    let mut consumer = OrderingConsumer::restore(original.clone(), &[]).unwrap();
    for kind in 0..3 {
        let mut changed = bootstrap.clone();
        let mut chain_id = original.binding().tip().chain_id().to_vec();
        match kind {
            0 => chain_id.push(1),
            1 => {
                changed.agreement.set.validators.pop();
            }
            2 => changed.agreement.set.epoch += 1,
            _ => unreachable!(),
        }
        changed.agreement.context = SlotDecisionTip::from_checkpoint(
            chain_id,
            &changed.agreement.set,
            original.binding().tip().next_round() + 1,
            *original.binding().tip().previous_id(),
            0,
            validator::commit_root(&[]),
        )
        .unwrap();
        assert!(
            consumer.update(snapshot(changed)).is_err(),
            "context case {kind}"
        );
        consumer.update(original.clone()).unwrap();
        assert!(consumer.consumed_order().is_empty());
    }
}

fn assert_ordering_consumer(
    before: &store::AgreementOrderingSnapshot,
    applied: &store::AgreementOrderingSnapshot,
) {
    let mut consumer = OrderingConsumer::restore(before.clone(), before.order()).unwrap();
    consumer.update(applied.clone()).unwrap();
    let mut offered = Vec::new();
    consumer
        .consume_ready(|vertex| {
            offered.push(vertex.id().unwrap());
            Ok(false)
        })
        .unwrap();
    assert_eq!(offered, applied.order()[..1]);
    assert!(consumer.consumed_order().is_empty());

    let mut calls = 0;
    assert!(
        consumer
            .consume_ready(|_| {
                calls += 1;
                if calls == 1 {
                    Ok(true)
                } else {
                    Err("payload application failed without effects".into())
                }
            })
            .is_err()
    );
    assert_eq!(consumer.consumed_order(), &applied.order()[..1]);
    let checkpoint = consumer.consumed_order().to_vec();
    drop(consumer);
    let mut consumer = OrderingConsumer::restore(applied.clone(), &checkpoint).unwrap();
    assert!(consumer.update(before.clone()).is_err());
    consumer.update(applied.clone()).unwrap();
    let mut resumed = Vec::new();
    consumer
        .consume_ready(|vertex| {
            resumed.push(vertex.id().unwrap());
            Ok(true)
        })
        .unwrap();
    assert_eq!(resumed, applied.order()[1..]);
    assert_eq!(consumer.consumed_order(), applied.order());
    consumer.update(applied.clone()).unwrap();
    consumer
        .consume_ready(|_| panic!("duplicate snapshots must not replay consumed vertices"))
        .unwrap();
    let mut conflicting = checkpoint;
    conflicting[0].digest[0] ^= 1;
    assert!(OrderingConsumer::restore(applied.clone(), &conflicting).is_err());
    let mut longer = applied.order().to_vec();
    longer.push(longer[0].clone());
    assert!(OrderingConsumer::restore(applied.clone(), &longer).is_err());
}

fn assert_ordering_consumer_rejects_conflicting_checkpoints(
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    vertices: &[Vertex],
    applied: &store::AgreementOrderingSnapshot,
) {
    // Independently trusted checkpoints can be internally valid without extending
    // this consumer's history. Store authentication alone cannot establish that link.
    let checkpoint = |order: Vec<VertexId>, round: u64, previous: [u8; 32]| {
        let mut bootstrap = bootstrap.clone();
        bootstrap.agreement.context = SlotDecisionTip::from_checkpoint(
            applied.binding().tip().chain_id().to_vec(),
            &bootstrap.agreement.set,
            round,
            previous,
            order.len() as u64,
            validator::commit_root(&order),
        )
        .unwrap();
        bootstrap.predecessor = applied.binding().carrier().cloned();
        bootstrap.order = order;
        bootstrap.vertices = vertices.to_vec();
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        store
            .begin_authenticated_slot_agreement(bootstrap)
            .unwrap()
            .ordering_snapshot()
            .unwrap()
    };
    let tip = applied.binding().tip();
    assert!(applied.order().len() > 1);
    let mut rewritten = applied.order().to_vec();
    rewritten.swap(0, 1);
    let truncated = applied.order()[..applied.order().len() - 1].to_vec();
    let mut previous = *tip.previous_id();
    previous[0] ^= 1;
    let conflicts = [
        checkpoint(rewritten, tip.next_round() + 1, *tip.previous_id()),
        checkpoint(truncated, tip.next_round() + 1, *tip.previous_id()),
        checkpoint(applied.order().to_vec(), tip.next_round(), previous),
    ];
    let mut consumer = OrderingConsumer::restore(applied.clone(), &[]).unwrap();
    for conflict in conflicts {
        assert!(consumer.update(conflict).is_err());
        assert!(consumer.consumed_order().is_empty());
    }
    // Failed updates must preserve the previously accepted vertices, not merely
    // the cursor: otherwise a rejected unconsumed tail could still be executed.
    let mut consumed = Vec::new();
    consumer
        .consume_ready(|vertex| {
            consumed.push(vertex.id().unwrap());
            Ok(true)
        })
        .unwrap();
    assert_eq!(consumed, applied.order());
    assert_eq!(consumer.consumed_order(), applied.order());
}

// Explicit acceptance-test orchestration, not a production scheduler: every signing
// call is made by the test, and every publication crosses the real TCP receive path.
#[test]
fn isolated_tcp_carrier_retry_control_retransmission_and_decision_survive_reopen() {
    use std::time::{Duration, Instant};

    let accounts = chain::accounts(4).unwrap();
    let chain_id = b"live-adapter-tests";
    let mut batches = std::collections::BTreeMap::new();
    let mut hashes = std::collections::BTreeMap::new();
    for round in 0..=2 {
        for author in 0..4 {
            let batch = chain::demo_batch(chain_id, &accounts, author, round, 1).unwrap();
            let hash = batch.digest().unwrap();
            batches.insert(hash, batch);
            hashes.insert((author, round), hash);
        }
    }
    let (m, bootstrap, request) =
        fixture_for_chain_with_payload(chain_id, |author, round| hashes[&(author, round)]);
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    let dirs: Vec<_> = (0..3).map(|_| Dir::new()).collect();
    let mut stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let bootstraps: Vec<_> = (0..3)
        .map(|i| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            b
        })
        .collect();
    let mut adapters: Vec<_> = (0..3)
        .map(|i| Adapter::begin(&stores[i], bootstraps[i].clone(), &m, i).unwrap())
        .collect();
    let mut available: Vec<_> = vertices.iter().filter(|v| v.round < 4).cloned().collect();

    // Author the actual proposal from the fixture's causal prefix, not a fabricated
    // envelope; plain proposal receipt must remain neutral.
    let prefix: Vec<_> = vertices.iter().filter(|v| v.round < 3).cloned().collect();
    let mut node = authoring_node_index(&m, &prefix, 0);
    node.set_round(3);
    let proposal = adapters[0]
        .author_proposal(&lineage.entries[0].proposal, &mut node)
        .unwrap()
        .expect("proposal is authorable");
    available.retain(|v| !(v.round == 3 && v.author == proposal.vertex.author));
    available.push(proposal.vertex.clone());
    let message = adapters[0]
        .export_carrier(&proposal.vertex.id().unwrap(), node.dag())
        .unwrap();
    for adapter in &mut adapters {
        adapter
            .receive_message(tcp_agreement_message(message.clone()))
            .unwrap();
        assert!(
            adapter.signing_history().is_empty(),
            "proposal receipt must not vote"
        );
    }

    let proposer = m
        .consensus
        .iter()
        .position(|v| v.id == lineage.entries[0].view_carrier.author)
        .unwrap();
    assert!(
        proposer < adapters.len(),
        "fixture view proposer must be in the honest quorum"
    );
    let mut node = authoring_node_index(&m, &available, proposer);
    node.set_round(4);
    let candidate = validator::SlotAgreementViewCandidate::new(
        vec![],
        lineage.entries[0].proposal.clone(),
        proposal.vertex.id().unwrap(),
        AgreementView(0),
        &m.set,
    )
    .unwrap();
    let view = adapters[proposer]
        .author_view(&candidate, &mut node)
        .unwrap()
        .expect("elected view");
    let refs: Vec<_> = available
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect();
    for i in 0..4 {
        if i != proposer {
            available.push(signed(&m, i, 4, refs.clone(), [4; 32]));
        }
    }
    available.push(view.vertex.clone());
    let message = adapters[proposer]
        .export_carrier(&view.vertex.id().unwrap(), node.dag())
        .unwrap();
    for adapter in &mut adapters {
        adapter
            .receive_message(tcp_agreement_message(message.clone()))
            .unwrap();
        assert_eq!(
            adapter.signing_history().len(),
            1,
            "view authorizes one explicit prevote intent"
        );
        assert!(
            adapter
                .completed_carriers()
                .unwrap()
                .iter()
                .all(|c| !matches!(c.envelope.payload(), CarrierPayload::Vote { .. })),
            "receive must not author vote carriers"
        );
    }

    // Both voting phases use real local authoring and durable export. Lose one
    // prevote entirely, then close/reopen its sender AND a partially fed receiver.
    for (round, phase) in [
        (5, validator::slot_agreement::AgreementPhase::Prevote),
        (7, validator::slot_agreement::AgreementPhase::Precommit),
    ] {
        let mut messages = Vec::new();
        let mut authored_vertices = Vec::new();
        for (i, adapter) in adapters.iter_mut().enumerate() {
            let id = adapter
                .signing_history()
                .iter()
                .find(|intent| intent.vote.phase == phase)
                .expect("phase intent")
                .id;
            let mut node = authoring_node_index(&m, &available, i);
            node.set_round(round);
            let vote = adapter
                .author_vote(id, &mut node)
                .unwrap()
                .expect("available vote prerequisites");
            messages.push(
                adapter
                    .export_carrier(&vote.vertex.id().unwrap(), node.dag())
                    .unwrap(),
            );
            authored_vertices.push(vote.vertex);
        }
        if round == 5 {
            adapters[2]
                .receive_message(tcp_agreement_message(messages[0].clone()))
                .unwrap();
            assert!(
                !adapters[2]
                    .pending()
                    .iter()
                    .any(|p| matches!(p, PendingIntent::Pol { .. })),
                "one vote is not quorum"
            );
            let lost = messages[1].clone();
            let wal = std::fs::read(dirs[1].0.join("authenticated-slot-agreement")).unwrap();
            // Reopen the actual Store handles, not merely the adapter objects.
            drop(adapters);
            drop(stores);
            stores = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
            adapters = (0..3)
                .map(|i| Adapter::recover(&stores[i], bootstraps[i].clone(), &m, i).unwrap())
                .collect();
            let mut node = authoring_node_index(&m, &available, 1);
            node.receive(authored_vertices[1].clone()).unwrap();
            let retry = adapters[1]
                .export_carrier(&authored_vertices[1].id().unwrap(), node.dag())
                .unwrap();
            assert_eq!(
                net::wire::frame(&retry, 0).unwrap(),
                net::wire::frame(&lost, 0).unwrap(),
                "restart retries exact durable publication"
            );
            assert_eq!(
                std::fs::read(dirs[1].0.join("authenticated-slot-agreement")).unwrap(),
                wal,
                "export must not sign or write"
            );
            messages[1] = retry;
        }
        available.extend(authored_vertices);
        for message in messages {
            for adapter in &mut adapters {
                adapter
                    .receive_message(tcp_agreement_message(message.clone()))
                    .unwrap();
            }
        }
        if round == 5 {
            let digest = adapters[0]
                .pending()
                .iter()
                .find_map(|p| match p {
                    PendingIntent::Pol { digest, .. } => Some(*digest),
                    _ => None,
                })
                .expect("prevote quorum POL");
            let mut node = authoring_node_index(&m, &available, 0);
            node.set_round(6);
            let pol = adapters[0]
                .author_pol(digest, &mut node)
                .unwrap()
                .expect("POL prerequisites");
            let message = adapters[0]
                .export_carrier(&pol.vertex.id().unwrap(), node.dag())
                .unwrap();
            let refs: Vec<_> = available
                .iter()
                .filter(|v| v.round == 5)
                .map(|v| v.id().unwrap())
                .collect();
            available.push(pol.vertex);
            for i in 1..3 {
                available.push(signed(&m, i, 6, refs.clone(), [6; 32]));
            }
            for adapter in &mut adapters {
                adapter
                    .receive_message(tcp_agreement_message(message.clone()))
                    .unwrap();
                assert_eq!(
                    adapter.signing_history().len(),
                    2,
                    "POL authorizes locked precommit"
                );
            }
        }
    }

    let digest = adapters[0]
        .pending()
        .iter()
        .find_map(|p| match p {
            PendingIntent::FinalProof { digest, .. } => Some(*digest),
            _ => None,
        })
        .expect("precommit quorum final proof");
    let mut node = authoring_node_index(&m, &available, 0);
    node.set_round(8);
    let final_proof = adapters[0]
        .author_final_proof(digest, &mut node)
        .unwrap()
        .expect("QC prerequisites");
    let lost_final = adapters[0]
        .export_carrier(&final_proof.vertex.id().unwrap(), node.dag())
        .unwrap();
    available.push(final_proof.vertex.clone());

    // While the QC publication is lost, retransmit dropped control requests to
    // enter a later view. Old-view final evidence must still settle the same slot.
    let now = Instant::now();
    let wait = Duration::from_millis(10);
    let mut controls = Vec::new();
    for adapter in &mut adapters {
        adapter.author_view_request(AgreementView(9)).unwrap();
        adapter.configure_retransmission(wait).unwrap();
        let lost = adapter
            .retransmit(now)
            .unwrap()
            .expect("initial control publication");
        assert_eq!(adapter.retransmit(now + wait / 2).unwrap(), None);
        let retry = adapter
            .retransmit(now + wait)
            .unwrap()
            .expect("due control retry");
        assert_eq!(retry, lost);
        controls.push(retry);
    }
    for control in controls {
        for adapter in &mut adapters {
            adapter
                .receive_message(tcp_agreement_message(control.clone()))
                .unwrap();
        }
    }
    for adapter in &mut adapters {
        assert_eq!(adapter.timer_snapshot().unwrap().view, AgreementView(9));
        assert!(
            adapter
                .driver
                .output()
                .unwrap()
                .transition
                .unwrap()
                .decision
                .is_none()
        );
    }
    drop(adapters);
    drop(stores);
    stores = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    adapters = (0..3)
        .map(|i| Adapter::recover(&stores[i], bootstraps[i].clone(), &m, i).unwrap())
        .collect();
    let node = authoring_node_index(&m, &available, 0);
    assert_eq!(
        adapters[0].retransmit(now).unwrap(),
        None,
        "restart must not enable scheduling"
    );
    let retry = adapters[0]
        .export_carrier(&final_proof.vertex.id().unwrap(), node.dag())
        .unwrap();
    assert_eq!(
        retry, lost_final,
        "QC survives control advancement and sender restart"
    );
    for adapter in &mut adapters {
        let history = format!("{:?}", adapter.signing_history());
        adapter
            .receive_message(tcp_agreement_message(retry.clone()))
            .unwrap();
        assert_eq!(
            format!("{:?}", adapter.signing_history()),
            history,
            "QC receipt never signs"
        );
    }
    let decision = adapters[0]
        .driver
        .output()
        .unwrap()
        .transition
        .unwrap()
        .decision
        .expect("real agreed decision");
    // Multiple local publications remain independently retryable in a caller-selected
    // order; control advancement does not replace older evidence for this slot.
    let retry_dag = authoring_node_index(&m, &available, 0);
    let publications = adapters[0].completed_carriers().unwrap();
    let ids: Vec<_> = publications
        .iter()
        .map(|p| p.vertex.id().unwrap())
        .collect();
    assert!(
        ids.len() > 1,
        "round-robin must exercise distinct publications"
    );
    adapters[0]
        .configure_carrier_retransmission(Duration::from_secs(1))
        .unwrap();
    let start = Instant::now();
    for index in 0..=ids.len() {
        let selected = &ids[index % ids.len()];
        let expected = adapters[0]
            .export_carrier(selected, retry_dag.dag())
            .unwrap();
        let actual = adapters[0]
            .retransmit_carrier(
                start + Duration::from_secs(index as u64),
                &ids,
                retry_dag.dag(),
            )
            .unwrap()
            .unwrap();
        assert_eq!(
            actual, expected,
            "every selected publication gets its own retry"
        );
    }
    let snapshots: Vec<_> = adapters
        .iter()
        .enumerate()
        .map(|(i, adapter)| {
            assert_eq!(
                adapter
                    .driver
                    .output()
                    .unwrap()
                    .transition
                    .unwrap()
                    .decision,
                Some(decision.clone()),
                "honest adapter {i} agrees exactly"
            );
            assert_eq!(
                adapter.readiness(),
                Readiness::DisabledMissingCausalReadinessAndTransport
            );
            (
                format!("{:?}", adapter.driver.output().unwrap()),
                std::fs::read(dirs[i].0.join("authenticated-slot-agreement")).unwrap(),
            )
        })
        .collect();
    drop(adapters);
    drop(stores);
    let mut agreed_order = None;
    let mut agreed_execution = None;
    let mut agreed_header = None;
    for i in 0..3 {
        let store = Store::open(&dirs[i].0).unwrap();
        let mut adapter = Adapter::recover(&store, bootstraps[i].clone(), &m, i).unwrap();
        assert_eq!(
            format!("{:?}", adapter.driver.output().unwrap()),
            snapshots[i].0,
            "reopen preserves exact outcome {i}"
        );
        let sequence = adapter.driver.sequence();
        let history = format!("{:?}", adapter.signing_history());
        adapter
            .receive_message(tcp_agreement_message(retry.clone()))
            .unwrap();
        assert_eq!(
            format!("{:?}", adapter.driver.output().unwrap()),
            snapshots[i].0,
            "duplicate QC preserves the exact outcome {i}"
        );
        assert_eq!(
            format!("{:?}", adapter.signing_history()),
            history,
            "duplicate QC creates no signing obligation {i}"
        );
        // Ingress allocates a new sequence even for duplicate evidence; replay treats the
        // exact repeat as a receipt-only no-op so it cannot re-emit the local prevote.
        assert_eq!(adapter.driver.sequence(), sequence + 1);
        let wal = std::fs::read(dirs[i].0.join("authenticated-slot-agreement")).unwrap();
        assert!(
            wal.len() > snapshots[i].1.len() && wal.starts_with(&snapshots[i].1),
            "duplicate receipt extends the existing journal {i}"
        );
        drop(adapter);
        drop(store);
        let store = Store::open(&dirs[i].0).unwrap();
        let mut adapter = Adapter::recover(&store, bootstraps[i].clone(), &m, i).unwrap();
        assert_eq!(adapter.driver.sequence(), sequence + 1);
        assert_eq!(
            format!("{:?}", adapter.driver.output().unwrap()),
            snapshots[i].0,
            "duplicate receipt replays to the exact outcome {i}"
        );
        assert_eq!(format!("{:?}", adapter.signing_history()), history);
        assert_eq!(
            std::fs::read(dirs[i].0.join("authenticated-slot-agreement")).unwrap(),
            wal,
            "recovery does not append another receipt {i}"
        );
        let before = adapter.ordering_snapshot().unwrap();
        assert_eq!(before.order(), bootstraps[i].order);
        adapter
            .apply(AuthenticatedSlotAgreementRequest::AdvanceSlot)
            .unwrap();
        let applied = adapter.ordering_snapshot().unwrap();
        assert!(
            !applied.order().is_empty(),
            "acceptance must apply a real nonempty commit"
        );
        assert_eq!(applied.order().len() as u64, decision.after_len);
        assert_eq!(validator::commit_root(applied.order()), decision.after_root);
        assert_eq!(applied.binding().tip().next_round(), decision.round + 1);
        let signed_ids: Vec<_> = applied.vertices().iter().map(|v| v.id().unwrap()).collect();
        assert_eq!(signed_ids, applied.order());
        if let Some(expected) = &agreed_order {
            assert_eq!(
                applied.order(),
                expected,
                "honest adapters expose identical applied order"
            );
        } else {
            agreed_order = Some(applied.order().to_vec());
        }
        let history = format!("{:?}", adapter.signing_history());
        let wal = std::fs::read(dirs[i].0.join("authenticated-slot-agreement")).unwrap();
        drop(adapter);
        drop(store);
        let store = Store::open(&dirs[i].0).unwrap();
        let mut adapter = Adapter::recover(&store, bootstraps[i].clone(), &m, i).unwrap();
        let recovered = adapter.ordering_snapshot().unwrap();
        assert_eq!(format!("{recovered:?}"), format!("{applied:?}"));
        assert_ordering_consumer(&before, &recovered);
        let mut honest_execution =
            CertifiedExecution::begin(before.clone(), chain::genesis_state(&accounts).unwrap())
                .unwrap();
        honest_execution.update(recovered.clone()).unwrap();
        honest_execution
            .execute_ready(&m, &batches, &std::collections::BTreeSet::new())
            .unwrap();
        assert!(honest_execution.applied() > 0);
        assert_eq!(honest_execution.consumed_order(), recovered.order());
        let result = (
            honest_execution.state().state_root(),
            honest_execution.applied(),
        );
        if let Some(expected) = agreed_execution {
            assert_eq!(
                result, expected,
                "honest certified consumers must agree on execution"
            );
        } else {
            agreed_execution = Some(result);
        }
        // This real carrier fixture supplies one applied commit, not a multi-slot backlog.
        assert_eq!(recovered.applications().len(), 1);
        assert!(recovered.applications()[0].is_commit());
        let genesis = chain::genesis_state(&accounts).unwrap();
        let anchor = validator::Header {
            chain_id: chain_id.to_vec(),
            epoch: recovered.checkpoint_binding().tip().epoch(),
            height: 0,
            round: 0,
            state_root: genesis.state_root(),
            dag_root: *recovered.checkpoint_binding().tip().order_root(),
            previous: [0; 32],
            applied: 0,
        };
        let make_finalizer = |anchor| {
            validator::Finalizer::new(
                validator::SetSchedule::single(m.set.clone()),
                validator::EpochSchedule::single(m.set.epoch),
                chain_id.to_vec(),
                m.consensus[i].id.clone(),
                m.consensus[i].private_key.clone(),
                anchor,
                0,
            )
            .unwrap()
        };
        if i == 0 {
            let mut speculative = make_finalizer(anchor.clone());
            assert!(
                speculative
                    .record_commit(99, recovered.order().len())
                    .is_some(),
                "the speculative decision allocates a header"
            );
            assert!(
                CertifiedFinalization::begin(recovered.clone(), genesis.clone(), speculative)
                    .is_err(),
                "legacy pending commits must not enter certified finalization"
            );
            let mut incompatible = anchor.clone();
            incompatible.state_root[0] ^= 1;
            let error = CertifiedFinalization::begin(
                recovered.clone(),
                genesis.clone(),
                make_finalizer(incompatible),
            )
            .err()
            .expect("incompatible genesis state root must be rejected");
            assert!(error.contains("matching pristine genesis anchor"));
        }
        let mut finalization = CertifiedFinalization::begin(
            recovered.clone(),
            genesis.clone(),
            make_finalizer(anchor.clone()),
        )
        .unwrap();
        let controls = std::collections::BTreeSet::new();
        let blocked = finalization
            .build_ready(&m, &std::collections::BTreeMap::new(), &controls, 10)
            .unwrap();
        assert!(blocked.shares.is_empty() && blocked.certified.is_empty());
        assert_eq!(finalization.execution().state(), &genesis);
        assert!(finalization.execution().consumed_order().is_empty());
        assert_eq!(finalization.execution().applied(), 0);
        assert_eq!(finalization.finalizer().built_headers(), 0);
        assert_eq!(finalization.finalizer().last_built(), &anchor);
        let mut missing = batches.clone();
        missing.remove(&recovered.vertices()[1].payload_hash);
        let partial = finalization
            .build_ready(&m, &missing, &controls, 11)
            .unwrap();
        assert!(partial.shares.is_empty() && partial.certified.is_empty());
        assert_eq!(
            finalization.execution().consumed_order(),
            &recovered.order()[..1]
        );
        assert_eq!(finalization.execution().applied(), 1);
        assert_ne!(finalization.execution().state(), &genesis);
        assert_eq!(finalization.finalizer().built_headers(), 0);
        assert_eq!(finalization.finalizer().last_built_order(), 0);
        finalization.update(recovered.clone()).unwrap();
        let built = finalization
            .build_ready(&m, &batches, &controls, 12)
            .unwrap();
        assert_eq!(built.shares.len(), 1);
        assert!(
            built.certified.is_empty(),
            "one local signer is not a quorum"
        );
        let share = &built.shares[0];
        assert_eq!(share.signer, i);
        assert_eq!(share.at, 12);
        assert_eq!(
            share.signature,
            Ed25519Scheme
                .sign(
                    &m.consensus[i].private_key,
                    &validator::signing_payload(&share.header).unwrap(),
                )
                .unwrap()
        );
        let header = &share.header;
        assert_eq!(header.height, 1);
        assert_eq!(header.round, decision.round);
        assert_eq!(header.previous, anchor.id().unwrap());
        assert_eq!(header.state_root, result.0);
        assert_eq!(header.applied, result.1);
        assert_eq!(header.dag_root, decision.after_root);
        assert_eq!(finalization.execution().state(), honest_execution.state());
        assert_eq!(finalization.execution().consumed_order(), recovered.order());
        assert_eq!(
            finalization.finalizer().last_built_order(),
            recovered.order().len()
        );
        if let Some(expected) = &agreed_header {
            assert_eq!(header, expected, "honest finalizers build the same header");
        } else {
            agreed_header = Some(header.clone());
        }
        for at in 13..16 {
            finalization.update(recovered.clone()).unwrap();
            let duplicate = finalization
                .build_ready(&m, &batches, &controls, at)
                .unwrap();
            assert!(duplicate.shares.is_empty() && duplicate.certified.is_empty());
            assert_eq!(finalization.finalizer().built_headers(), 1);
            assert_eq!(finalization.finalizer().last_built(), header);
            assert_eq!(finalization.execution().applied(), result.1);
        }
        if i == 0 {
            assert_ordering_consumer_rejects_conflicting_checkpoints(
                &bootstraps[i],
                &available,
                &recovered,
            );
        }
        assert_eq!(format!("{:?}", adapter.signing_history()), history);
        assert_eq!(
            std::fs::read(dirs[i].0.join("authenticated-slot-agreement")).unwrap(),
            wal
        );
        if i == 0 {
            assert!(adapter.restore_execution().unwrap().is_none());
            let genesis = chain::genesis_state(&accounts).unwrap();
            assert!(CertifiedExecution::begin(recovered.clone(), genesis.clone()).is_err());
            let mut execution = CertifiedExecution::begin(before.clone(), genesis.clone()).unwrap();
            execution.update(recovered.clone()).unwrap();
            let controls = std::collections::BTreeSet::new();
            execution
                .execute_ready(&m, &std::collections::BTreeMap::new(), &controls)
                .unwrap();
            assert!(execution.consumed_order().is_empty());
            assert_eq!(execution.state(), &genesis);
            let missing_hash = recovered.vertices()[1].payload_hash;
            let mut missing = batches.clone();
            missing.remove(&missing_hash);
            execution.execute_ready(&m, &missing, &controls).unwrap();
            assert_eq!(execution.consumed_order(), &recovered.order()[..1]);
            assert_eq!(execution.applied(), 1);
            let partial_state = execution.state().clone();
            let mut wrong = batches.clone();
            wrong.insert(
                missing_hash,
                batches[&recovered.vertices()[0].payload_hash].clone(),
            );
            assert!(execution.execute_ready(&m, &wrong, &controls).is_err());
            let ambiguous = std::collections::BTreeSet::from([missing_hash]);
            assert!(execution.execute_ready(&m, &batches, &ambiguous).is_err());
            assert_eq!(execution.state(), &partial_state);
            assert_eq!(execution.consumed_order(), &recovered.order()[..1]);
            execution.checkpoint(&mut adapter).unwrap();
            let checkpoint_path = dirs[i].0.join("agreement-execution-checkpoint");
            let partial_bytes = std::fs::read(&checkpoint_path).unwrap();
            execution.execute_ready(&m, &batches, &controls).unwrap();
            let complete_state = execution.state().clone();
            let mut expected = genesis;
            let mut rejected = std::collections::BTreeMap::new();
            let expected_count: usize = recovered
                .vertices()
                .iter()
                .map(|vertex| {
                    chain::apply_batch(
                        &mut expected,
                        &accounts,
                        &batches[&vertex.payload_hash],
                        &mut rejected,
                    )
                })
                .sum();
            assert!(expected_count > 1);
            assert!(rejected.is_empty());
            assert_eq!(execution.state(), &expected);
            assert_eq!(execution.applied() as usize, expected_count);
            assert!(execution.rejected().is_empty());
            // A blocked staging path prevents publication; the old complete record survives.
            let temporary = dirs[i].0.join("agreement-execution-checkpoint.tmp");
            std::fs::create_dir(&temporary).unwrap();
            assert!(execution.checkpoint(&mut adapter).is_err());
            assert!(adapter.restore_execution().is_err());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), partial_bytes);
            std::fs::remove_dir(&temporary).unwrap();
            drop(adapter);
            drop(store);
            let store = Store::open(&dirs[i].0).unwrap();
            let mut adapter = Adapter::recover(&store, bootstraps[i].clone(), &m, i).unwrap();
            let mut execution = CertifiedExecution::restore(&mut adapter).unwrap().unwrap();
            assert_eq!(execution.state(), &partial_state);
            assert_eq!(execution.applied(), 1);
            assert_eq!(execution.consumed_order(), &recovered.order()[..1]);
            execution.execute_ready(&m, &batches, &controls).unwrap();
            assert_eq!(execution.state(), &complete_state);
            assert_eq!(execution.applied() as usize, expected_count);
            execution.checkpoint(&mut adapter).unwrap();
            let complete_bytes = std::fs::read(&checkpoint_path).unwrap();
            execution.checkpoint(&mut adapter).unwrap();
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), complete_bytes);
            drop(adapter);
            drop(store);
            let store = Store::open(&dirs[i].0).unwrap();
            let mut adapter = Adapter::recover(&store, bootstraps[i].clone(), &m, i).unwrap();
            let mut execution = CertifiedExecution::restore(&mut adapter).unwrap().unwrap();
            assert_eq!(execution.state(), &complete_state);
            assert_eq!(execution.applied() as usize, expected_count);
            execution.update(recovered.clone()).unwrap();
            execution.execute_ready(&m, &batches, &controls).unwrap();
            assert_eq!(execution.state(), &complete_state);
            assert_eq!(execution.applied() as usize, expected_count);
            assert_eq!(execution.consumed_order(), recovered.order());
            assert_eq!(
                std::fs::read(dirs[i].0.join("authenticated-slot-agreement")).unwrap(),
                wal
            );
            let mut corrupt = complete_bytes;
            corrupt.push(1);
            std::fs::write(&checkpoint_path, &corrupt).unwrap();
            assert!(adapter.restore_execution().is_err());
            assert_eq!(std::fs::read(&checkpoint_path).unwrap(), corrupt);
        }
    }
}

#[test]
fn scheduled_carrier_retry_cadence_failure_and_recovery() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let prefix: Vec<_> = vertices.iter().filter(|v| v.round < 3).cloned().collect();
    let mut node = authoring_node_index(&m, &prefix, 0);
    node.set_round(3);
    let publication = adapter
        .author_proposal(&lineage.entries[0].proposal, &mut node)
        .unwrap()
        .unwrap();
    let id = publication.vertex.id().unwrap();
    let ids = [id.clone()];
    let now = Instant::now();
    let interval = Duration::from_secs(2);
    let wal = std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap();
    let history = format!("{:?}", adapter.signing_history());
    assert!(
        adapter
            .retransmit_carrier(now, &ids, node.dag())
            .unwrap()
            .is_none()
    );
    assert!(
        adapter
            .configure_carrier_retransmission(Duration::ZERO)
            .is_err()
    );
    assert!(
        adapter
            .configure_carrier_retransmission(Duration::from_secs(86_401))
            .is_err()
    );
    adapter.configure_carrier_retransmission(interval).unwrap();
    assert!(
        adapter
            .retransmit_carrier(now, &[], node.dag())
            .unwrap()
            .is_none()
    );
    assert!(
        adapter
            .retransmit_carrier(now - interval, &ids, node.dag())
            .is_err()
    );
    assert!(
        adapter
            .retransmit_carrier(now, &vec![id.clone(); 65], node.dag())
            .is_err()
    );
    assert!(
        adapter
            .retransmit_carrier(now, &[id.clone(), id.clone()], node.dag())
            .is_err()
    );
    let missing = Dag::new(m.set.clone());
    assert!(adapter.retransmit_carrier(now, &ids, &missing).is_err());
    let first = adapter
        .retransmit_carrier(now, &ids, node.dag())
        .unwrap()
        .unwrap();
    assert_eq!(first, adapter.export_carrier(&id, node.dag()).unwrap());
    assert!(
        adapter
            .retransmit_carrier(now + interval - Duration::from_nanos(1), &ids, node.dag())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        adapter
            .retransmit_carrier(now + interval, &ids, node.dag())
            .unwrap(),
        Some(first.clone())
    );
    let late = now + interval * 10;
    assert_eq!(
        adapter.retransmit_carrier(late, &ids, node.dag()).unwrap(),
        Some(first.clone())
    );
    assert!(
        adapter
            .retransmit_carrier(late, &ids, node.dag())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap(),
        wal
    );
    assert_eq!(format!("{:?}", adapter.signing_history()), history);
    drop(adapter);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(
        adapter
            .retransmit_carrier(now, &ids, node.dag())
            .unwrap()
            .is_none()
    );
    adapter.configure_carrier_retransmission(interval).unwrap();
    assert_eq!(
        adapter.retransmit_carrier(now, &ids, node.dag()).unwrap(),
        Some(first.clone())
    );
    assert_eq!(tcp_agreement_message(first.clone()), first);
    assert_eq!(
        std::fs::read(dir.0.join("authenticated-slot-agreement")).unwrap(),
        wal
    );
    let mut stale = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: validator::slot_agreement::AgreementPhase::Prevote,
        })
        .unwrap();
    assert!(
        stale.retransmit_carrier(now, &[], node.dag()).is_err(),
        "disabled empty poll still checks owner freshness"
    );
}

#[test]
fn carrier_export_preflight_limits() {
    let (m, _, _) = fixture();
    let mut vertex = signed(&m, 0, 0, vec![], [0; 32]);
    let vertex_bytes = 74 + vertex.chain_id.len() + vertex.author.len() + vertex.signature.len();
    let mut edges = 0;
    let mut bytes = net::wire::MAX_AGREEMENT_PAYLOAD - vertex_bytes;
    charge_carrier_vertex(
        &vertex,
        net::wire::MAX_AGREEMENT_VERTICES - 1,
        &mut edges,
        &mut bytes,
    )
    .unwrap();
    assert_eq!(bytes, net::wire::MAX_AGREEMENT_PAYLOAD);
    assert!(
        charge_carrier_vertex(&vertex, 0, &mut edges, &mut bytes)
            .unwrap_err()
            .contains("byte bound")
    );
    assert!(
        charge_carrier_vertex(&vertex, net::wire::MAX_AGREEMENT_VERTICES, &mut 0, &mut 0)
            .unwrap_err()
            .contains("vertex bound")
    );
    vertex.round = 1;
    vertex.references = vec![VertexId {
        round: 0,
        author: m.consensus[0].id.clone(),
        digest: [0; 32],
    }];
    edges = net::wire::MAX_AGREEMENT_EDGES - 1;
    charge_carrier_vertex(&vertex, 0, &mut edges, &mut 0).unwrap();
    assert_eq!(edges, net::wire::MAX_AGREEMENT_EDGES);
    assert!(
        charge_carrier_vertex(&vertex, 0, &mut edges, &mut 0)
            .unwrap_err()
            .contains("edge bound")
    );
    vertex.references[0].round = 1;
    assert!(
        charge_carrier_vertex(&vertex, 0, &mut 0, &mut 0)
            .unwrap_err()
            .contains("strictly ancestral")
    );
}

fn signed_view_request(
    m: &chain::Membership,
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    signer: usize,
    target: u64,
) -> validator::SlotAgreementViewRequest {
    let target = AgreementView(target);
    let bytes = validator::SlotAgreementViewRequest::signing_payload(
        &bootstrap.agreement.context,
        target,
        &m.set,
    )
    .unwrap();
    validator::SlotAgreementViewRequest::new(
        bootstrap.agreement.context.clone(),
        target,
        ValidatorSignature {
            validator_id: m.consensus[signer].id.clone(),
            key_id: m.set.validators[signer].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&m.consensus[signer].private_key, &bytes)
                .unwrap(),
        },
        &m.set,
    )
    .unwrap()
}

#[test]
fn retransmission_round_robin_cadence_recovery_and_tcp_certificate() {
    use net::wire::Message;
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut author = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    author.author_view_request(AgreementView(3)).unwrap();
    let request = author.author_view_request(AgreementView(9)).unwrap();
    author.receive_view_request(request.clone()).unwrap();
    for signer in [1, 2] {
        let remote = signed_view_request(&m, &bootstrap, signer, 9);
        author.receive_view_request(remote).unwrap();
    }
    let certificate = author.entered_view_certificate().unwrap().unwrap();
    let mut expected = vec![
        Message::AgreementViewRequest(request.encode(&m.set).unwrap()),
        Message::AgreementViewCertificate(
            certificate
                .iter()
                .map(|r| r.encode(&m.set).unwrap())
                .collect(),
        ),
    ];
    for phase in [AgreementPhase::Prevote, AgreementPhase::Precommit] {
        author
            .apply(AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(9),
                phase,
            })
            .unwrap();
        let id = author.signing_history().last().unwrap().id;
        let nil = author.author_nil_vote(id).unwrap().unwrap();
        expected.push(Message::AgreementNilVote(nil.encode(&m.set).unwrap()));
    }
    let wal = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    let history = format!("{:?}", author.signing_history());
    let pending = format!("{:?}", author.pending());
    let sequence = author.driver.sequence();
    let wait = Duration::from_secs(1);
    let now = Instant::now();
    assert_eq!(author.retransmit(now).unwrap(), None);
    author.configure_retransmission(wait).unwrap();
    for cycle in 0..2 {
        for (index, message) in expected.iter().enumerate() {
            let at = now + wait * (cycle * 4 + index as u32);
            assert_eq!(author.retransmit(at).unwrap(), Some(message.clone()));
            assert_eq!(author.retransmit(at).unwrap(), None);
            assert_eq!(author.retransmit(at + wait / 2).unwrap(), None);
        }
    }
    assert!(author.retransmit(now).unwrap_err().contains("backwards"));
    let delayed = now + wait * 100;
    assert_eq!(
        author.retransmit(delayed).unwrap(),
        Some(expected[0].clone())
    );
    assert_eq!(
        author.retransmit(delayed).unwrap(),
        None,
        "no catch-up burst"
    );
    assert_eq!(
        author.retransmit(delayed + wait).unwrap(),
        Some(expected[1].clone())
    );
    assert_eq!(author.driver.sequence(), sequence);
    assert_eq!(format!("{:?}", author.signing_history()), history);
    assert_eq!(format!("{:?}", author.pending()), pending);
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    drop(author);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut author = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert_eq!(
        author.retransmit(delayed).unwrap(),
        None,
        "recovery disables schedule"
    );
    author.configure_retransmission(wait).unwrap();
    let receiver_dir = Dir::new();
    let receiver_store = Store::open(&receiver_dir.0).unwrap();
    let mut b = bootstrap.clone();
    b.agreement.local_validator = m.consensus[3].id.clone();
    let mut receiver = Adapter::begin(&receiver_store, b, &m, 3).unwrap();
    for (index, message) in expected.iter().enumerate() {
        let replay = author
            .retransmit(now + wait * index as u32)
            .unwrap()
            .unwrap();
        assert_eq!(
            net::wire::frame(&replay, 0).unwrap(),
            net::wire::frame(message, 0).unwrap()
        );
        receiver
            .receive_message(tcp_agreement_message(replay))
            .unwrap();
    }
    assert_eq!(receiver.timer_snapshot().unwrap().view, AgreementView(9));
    assert_eq!(
        receiver.entered_view_certificate().unwrap(),
        Some(certificate)
    );
    assert!(
        receiver.signing_history().is_empty(),
        "receipt alone must not sign"
    );
    assert_eq!(std::fs::read(&wal).unwrap(), before);
}

#[test]
fn retransmission_dropped_publication_retry_reopen_and_quorum_without_ack() {
    use net::wire::Message;
    use std::time::{Duration, Instant};
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let wait = Duration::from_millis(10);
    let now = Instant::now();
    let mut retries = Vec::new();
    for (i, dir) in dirs[..3].iter().enumerate() {
        let store = Store::open(&dir.0).unwrap();
        let mut b = bootstrap.clone();
        b.agreement.local_validator = m.consensus[i].id.clone();
        let mut author = Adapter::begin(&store, b.clone(), &m, i).unwrap();
        let request = author.author_view_request(AgreementView(9)).unwrap();
        author.configure_retransmission(wait).unwrap();
        // Deliberately drop the first exported publication; no transport ACK is supplied.
        let lost = author.retransmit(now).unwrap().unwrap();
        assert_eq!(
            lost,
            Message::AgreementViewRequest(request.encode(&m.set).unwrap())
        );
        let wal = dir.0.join("authenticated-slot-agreement");
        let before = std::fs::read(&wal).unwrap();
        assert_eq!(author.retransmit(now + wait / 2).unwrap(), None);
        let retry = author.retransmit(now + wait).unwrap().unwrap();
        assert_eq!(
            net::wire::frame(&retry, 0).unwrap(),
            net::wire::frame(&lost, 0).unwrap()
        );
        drop(author);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut author = Adapter::recover(&store, b, &m, i).unwrap();
        assert_eq!(author.retransmit(now).unwrap(), None);
        author.configure_retransmission(wait).unwrap();
        assert_eq!(author.retransmit(now).unwrap(), Some(lost));
        assert_eq!(std::fs::read(&wal).unwrap(), before);
        retries.push(retry);
    }
    let store = Store::open(&dirs[3].0).unwrap();
    let mut b = bootstrap.clone();
    b.agreement.local_validator = m.consensus[3].id.clone();
    let mut receiver = Adapter::begin(&store, b, &m, 3).unwrap();
    for (index, retry) in retries.into_iter().enumerate() {
        receiver
            .receive_message(tcp_agreement_message(retry))
            .unwrap();
        assert_eq!(
            receiver.timer_snapshot().unwrap().view,
            AgreementView(if index + 1 == m.set.quorum_size() {
                9
            } else {
                0
            })
        );
    }
    assert!(receiver.completed_view_requests().unwrap().is_empty());
    assert!(receiver.signing_history().is_empty());
    receiver.configure_retransmission(wait).unwrap();
    let certificate = receiver.retransmit(now).unwrap().unwrap();
    assert!(matches!(certificate, Message::AgreementViewCertificate(_)));
    assert_eq!(
        receiver.retransmit(now + wait).unwrap(),
        Some(certificate.clone())
    );
    let laggard_dir = Dir::new();
    let laggard_store = Store::open(&laggard_dir.0).unwrap();
    let mut laggard = Adapter::begin(&laggard_store, bootstrap, &m, 0).unwrap();
    laggard
        .receive_message(tcp_agreement_message(certificate))
        .unwrap();
    assert_eq!(laggard.timer_snapshot().unwrap().view, AgreementView(9));
    assert_eq!(
        laggard.entered_view_certificate().unwrap(),
        receiver.entered_view_certificate().unwrap()
    );
}

#[test]
fn retransmission_stale_disabled_not_due_and_uncertain_owners_fail_closed() {
    use std::time::{Duration, Instant};
    let (m, bootstrap, _) = fixture();
    let wait = Duration::from_secs(1);
    let now = Instant::now();
    for configured in [false, true] {
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut stale = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
        stale.author_view_request(AgreementView(9)).unwrap();
        if configured {
            stale.configure_retransmission(wait).unwrap();
            assert!(stale.retransmit(now).unwrap().is_some());
        }
        let mut owner = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
        owner.author_view_request(AgreementView(10)).unwrap();
        let wal = dir.0.join("authenticated-slot-agreement");
        let before = std::fs::read(&wal).unwrap();
        let history = format!("{:?}", stale.signing_history());
        let sequence = stale.driver.sequence();
        assert!(
            stale.retransmit(now).is_err(),
            "disabled/not-due must check ownership"
        );
        assert_eq!(
            stale.readiness(),
            Readiness::RecoveryRequiredHistoricalIntentsUnavailable
        );
        stale.configure_retransmission(wait).unwrap();
        assert_eq!(
            stale.retransmit(now + wait).unwrap_err(),
            "agreement owner requires recovery before retransmission"
        );
        assert_eq!(stale.driver.sequence(), sequence);
        assert_eq!(format!("{:?}", stale.signing_history()), history);
        assert_eq!(std::fs::read(&wal).unwrap(), before);
    }
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut author = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    author.author_view_request(AgreementView(9)).unwrap();
    let wal = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    let result = Err(StoreError::Io(std::io::Error::other(
        "injected sync uncertainty",
    )));
    assert!(author.consume_durable_result(result, None).is_err());
    author.configure_retransmission(wait).unwrap();
    assert_eq!(
        author.retransmit(now).unwrap_err(),
        "agreement owner requires recovery before retransmission"
    );
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    let mut recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert_eq!(recovered.retransmit(now).unwrap(), None);
    recovered.configure_retransmission(wait).unwrap();
    assert!(recovered.retransmit(now).unwrap().is_some());
}

#[test]
fn retransmission_interval_empty_time_remote_support_and_old_view_filtering() {
    use net::wire::Message;
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut author = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let now = Instant::now();
    let wait = Duration::from_secs(1);
    for interval in [
        Duration::ZERO,
        Duration::from_secs(86_400) + Duration::from_nanos(1),
    ] {
        assert!(author.configure_retransmission(interval).is_err());
    }
    author
        .configure_retransmission(Duration::from_secs(86_400))
        .unwrap();
    assert_eq!(author.retransmit(now).unwrap(), None);
    assert!(
        author
            .retransmit(now - wait)
            .unwrap_err()
            .contains("backwards")
    );
    author.configure_retransmission(wait).unwrap();
    let wal = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    author
        .receive_view_request(signed_view_request(&m, &bootstrap, 1, 20))
        .unwrap();
    assert_eq!(
        author.retransmit(now).unwrap(),
        None,
        "remote volatile support is not publication"
    );
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    author
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let nil = author
        .author_nil_vote(author.signing_history()[0].id)
        .unwrap()
        .unwrap();
    // An empty poll did not consume a send interval.
    assert_eq!(
        author.retransmit(now).unwrap(),
        Some(Message::AgreementNilVote(nil.encode(&m.set).unwrap()))
    );
    author
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert_eq!(
        author.completed_nil_votes().unwrap().len(),
        1,
        "old completion remains durable"
    );
    let before = std::fs::read(&wal).unwrap();
    assert_eq!(
        author.retransmit(now + wait).unwrap(),
        None,
        "old-view nil must not escape"
    );
    let local = author.author_view_request(AgreementView(9)).unwrap();
    assert_eq!(
        author.retransmit(now + wait).unwrap(),
        Some(Message::AgreementViewRequest(local.encode(&m.set).unwrap()))
    );
    assert_eq!(author.retransmit(now + wait).unwrap(), None);
    assert!(author.configure_retransmission(Duration::ZERO).is_err());
    assert_eq!(
        author.retransmit(now + wait).unwrap(),
        None,
        "invalid configuration preserves cadence"
    );
    assert_eq!(author.completed_view_requests().unwrap(), vec![local]);
    assert_ne!(
        std::fs::read(&wal).unwrap(),
        before,
        "only local authoring changed WAL"
    );
}

#[test]
fn echo_exact_target_converges_after_restart() {
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut peers: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            Adapter::begin(store, b, &m, i).unwrap()
        })
        .collect();
    let a = peers[0].author_view_request(AgreementView(7)).unwrap();
    let b = peers[1].author_view_request(AgreementView(7)).unwrap();
    let low = peers[2].author_view_request(AgreementView(3)).unwrap();
    peers[2].receive_view_request(a.clone()).unwrap();
    peers[2].receive_view_request(b.clone()).unwrap();
    let mut third = bootstrap.clone();
    third.agreement.local_validator = m.consensus[2].id.clone();
    peers[2] = Adapter::recover(&stores[2], third, &m, 2).unwrap();
    assert_eq!(peers[2].completed_view_requests().unwrap(), vec![low]);
    assert!(peers[2].echo_view_request().unwrap().is_none());
    peers[2].receive_view_request(a.clone()).unwrap();
    peers[2].receive_view_request(b.clone()).unwrap();
    let echo = peers[2].echo_view_request().unwrap().unwrap();
    assert_eq!(echo.target_view(), AgreementView(7));
    let sequence = peers[2].driver.sequence();
    assert!(peers[2].echo_view_request().unwrap().is_none());
    assert_eq!(peers[2].driver.sequence(), sequence);
    for peer in &mut peers[..2] {
        // Local durable support also counts before it has been received locally.
        peer.receive_view_request(echo.clone()).unwrap();
        let own = peer.echo_view_request().unwrap().unwrap();
        let sequence = peer.driver.sequence();
        assert_eq!(peer.echo_view_request().unwrap(), Some(own));
        assert_eq!(peer.driver.sequence(), sequence);
        peer.receive_view_request(a.clone()).unwrap();
        peer.receive_view_request(b.clone()).unwrap();
    }
    for peer in &peers[..3] {
        assert_eq!(
            peer.driver.output().unwrap().transition.unwrap().view,
            AgreementView(7)
        );
    }
    assert!(peers[3].completed_view_requests().unwrap().is_empty());
}

#[test]
fn echo_recovers_reservation_preserves_highest_and_respects_cap() {
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut peer = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    peer.apply(AuthenticatedSlotAgreementRequest::ReserveViewRequest {
        target_view: AgreementView(7),
    })
    .unwrap();
    let mut peer = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    for signer in [1, 2] {
        peer.receive_view_request(signed_view_request(&m, &bootstrap, signer, 7))
            .unwrap();
    }
    let sequence = peer.driver.sequence();
    assert_eq!(
        peer.echo_view_request().unwrap().unwrap().target_view(),
        AgreementView(7)
    );
    // Complete the existing reservation and enter q, without a second reservation.
    assert_eq!(peer.driver.sequence(), sequence + 2);
    peer.author_view_request(AgreementView(20)).unwrap();
    for signer in [1, 2] {
        peer.receive_view_request(signed_view_request(&m, &bootstrap, signer, 10))
            .unwrap();
    }
    let sequence = peer.driver.sequence();
    assert!(peer.echo_view_request().unwrap().is_none());
    assert_eq!(peer.driver.sequence(), sequence);
    for target in 21..35 {
        peer.author_view_request(AgreementView(target)).unwrap();
    }
    assert_eq!(peer.completed_view_requests().unwrap().len(), 16);
    for signer in [1, 2] {
        peer.receive_view_request(signed_view_request(&m, &bootstrap, signer, 40))
            .unwrap();
    }
    let sequence = peer.driver.sequence();
    assert!(peer.echo_view_request().is_err());
    assert_eq!(peer.driver.sequence(), sequence);
}

#[test]
fn echo_requires_exact_distinct_support_and_fresh_owner() {
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut peer = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let sequence = peer.driver.sequence();
    for target in [10, 100, u64::MAX] {
        peer.receive_view_request(signed_view_request(&m, &bootstrap, 3, target))
            .unwrap();
        assert!(peer.echo_view_request().unwrap().is_none());
        assert_eq!(peer.driver.sequence(), sequence);
    }
    let mut peer = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    for (signer, target) in [(0, 1), (1, 2), (2, 3)] {
        peer.receive_view_request(signed_view_request(&m, &bootstrap, signer, target))
            .unwrap();
    }
    // Explicit coverage limitation: f+1 different targets cannot trigger an echo.
    assert!(peer.echo_view_request().unwrap().is_none());
    assert_eq!(peer.driver.sequence(), sequence);
    let mut newer = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    newer.author_view_request(AgreementView(9)).unwrap();
    assert!(peer.echo_view_request().is_err());
    assert_eq!(
        peer.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
}

#[test]
fn view_certificate_durable_restart_and_single_receipt() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut peers: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            Adapter::begin(store, b, &m, i).unwrap()
        })
        .collect();
    let mut requests: Vec<_> = peers
        .iter_mut()
        .take(m.set.quorum_size())
        .map(|a| a.author_view_request(AgreementView(9)).unwrap())
        .collect();
    requests.sort_by(|a, b| a.signature().validator_id.cmp(&b.signature().validator_id));
    for request in &requests {
        peers[0].receive_view_request(request.clone()).unwrap();
    }
    assert_eq!(
        peers[0].entered_view_certificate().unwrap(),
        Some(requests.clone())
    );
    assert!(peers[3].entered_view_certificate().unwrap().is_none());
    drop(peers);
    drop(stores);
    let store = Store::open(&dirs[0].0).unwrap();
    let peer = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(peer.observed_view_requests().unwrap().is_empty());
    let certificate = peer.entered_view_certificate().unwrap().unwrap();
    drop(peer);
    drop(store);
    let store = Store::open(&dirs[3].0).unwrap();
    let mut b = bootstrap.clone();
    b.agreement.local_validator = m.consensus[3].id.clone();
    let mut laggard = Adapter::recover(&store, b.clone(), &m, 3).unwrap();
    let before = laggard.driver.sequence();
    laggard
        .receive_view_certificate(certificate.clone())
        .unwrap();
    assert_eq!(laggard.driver.sequence(), before + 1);
    assert_eq!(
        laggard.driver.output().unwrap().transition.unwrap().view,
        AgreementView(9)
    );
    laggard
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(9),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let sequence = laggard.driver.sequence();
    let history = laggard.signing_history().len();
    laggard
        .receive_view_certificate(certificate.clone())
        .unwrap();
    assert_eq!(laggard.driver.sequence(), sequence);
    assert_eq!(laggard.signing_history().len(), history);
    let intent = laggard.signing_history().last().unwrap().id;
    assert!(laggard.author_nil_vote(intent).unwrap().is_some());
    let sequence = laggard.driver.sequence();
    let mut mixed = certificate.clone();
    mixed[0] = signed_view_request(&m, &bootstrap, 0, 8);
    let mut duplicate = certificate.clone();
    duplicate[1] = duplicate[0].clone();
    let mut foreign = bootstrap.clone();
    foreign.agreement.context = SlotDecisionTip::from_checkpoint(
        b"foreign-certificate-chain".to_vec(),
        &m.set,
        1,
        [0; 32],
        0,
        [0; 32],
    )
    .unwrap();
    let wrong: Vec<_> = (0..m.set.quorum_size())
        .map(|i| signed_view_request(&m, &foreign, i, 9))
        .collect();
    for malformed in [mixed, duplicate, wrong, Vec::new()] {
        assert!(laggard.receive_view_certificate(malformed).is_err());
        assert_eq!(laggard.driver.sequence(), sequence);
    }
    let mut newer = Adapter::recover(&store, b, &m, 3).unwrap();
    newer
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(9),
        })
        .unwrap();
    assert!(laggard.entered_view_certificate().is_err());
    assert!(laggard.receive_view_certificate(certificate).is_err());
}

#[test]
fn view_request_signing_skew_recovery_and_exact_quorum_convergence() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut adapters: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            let mut a = Adapter::begin(store, b, &m, i).unwrap();
            for v in 0..i {
                a.apply(AuthenticatedSlotAgreementRequest::AdvanceView {
                    from: AgreementView(v as u64),
                })
                .unwrap();
            }
            a
        })
        .collect();
    // A previous nil obligation is never repurposed into request signing authority.
    adapters[0]
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let nil = adapters[0].signing_history()[0].id;
    let messages: Vec<_> = adapters
        .iter_mut()
        .take(3)
        .map(|a| a.author_view_request(AgreementView(9)).unwrap())
        .collect();
    for (i, message) in messages.iter().enumerate() {
        message
            .verify(&bootstrap.agreement.context, &m.set)
            .unwrap();
        assert_eq!(message.signature().validator_id, m.consensus[i].id);
        let sequence = adapters[i].driver.sequence();
        assert_eq!(
            adapters[i].author_view_request(AgreementView(9)).unwrap(),
            *message
        );
        assert_eq!(adapters[i].driver.sequence(), sequence);
    }
    let other_target = adapters[2].author_view_request(AgreementView(8)).unwrap();
    for adapter in &mut adapters[..3] {
        for message in &messages[..2] {
            adapter.receive_view_request(message.clone()).unwrap();
        }
        adapter.receive_view_request(other_target.clone()).unwrap();
        assert_ne!(
            adapter.driver.output().unwrap().transition.unwrap().view,
            AgreementView(9),
            "mixed targets are not a quorum"
        );
    }
    // Crash with q-1 volatile observations: recovery must lose partial support.
    let sequence = adapters[3].driver.sequence();
    for message in &messages[..2] {
        adapters[3].receive_view_request(message.clone()).unwrap();
    }
    assert_eq!(adapters[3].driver.sequence(), sequence);
    drop(adapters);
    let mut adapters: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            Adapter::recover(store, b, &m, i).unwrap()
        })
        .collect();
    assert_eq!(
        adapters[0].completed_view_requests().unwrap(),
        vec![messages[0].clone()]
    );
    assert!(
        adapters
            .iter()
            .all(|a| a.observed_view_requests().unwrap().is_empty())
    );
    let now = std::time::Instant::now();
    let wait = std::time::Duration::from_secs(1);
    for (i, adapter) in adapters.iter_mut().enumerate() {
        let entry_sequence = adapter.driver.sequence();
        adapter.configure_pacemaker(pacemaker::Policy::new(wait, wait, wait).unwrap());
        assert_eq!(adapter.tick(now).unwrap(), None);
        for message in &messages[..2] {
            adapter.receive_view_request(message.clone()).unwrap();
        }
        assert_eq!(adapter.driver.sequence(), entry_sequence);
        assert_eq!(
            adapter
                .driver
                .output()
                .unwrap()
                .transition
                .as_ref()
                .map_or(AgreementView(0), |t| t.view),
            AgreementView(i as u64)
        );
        adapter.receive_view_request(messages[2].clone()).unwrap();
        assert_eq!(
            adapter.driver.sequence(),
            entry_sequence + 1,
            "only the full entry certificate is durable"
        );
        let transition = adapter.driver.output().unwrap().transition.unwrap();
        assert_eq!(transition.view, AgreementView(9));
        assert!(transition.vote.is_none());
        assert!(transition.decision.is_none());
        assert!(
            adapter.author_view_request(AgreementView(9)).is_err(),
            "entered targets are no longer authorable; use publication retrieval"
        );
        assert_eq!(
            adapter
                .observed_view_requests()
                .unwrap()
                .iter()
                .filter(|r| r.target_view() == AgreementView(9))
                .count(),
            3
        );
        assert_eq!(
            adapter.tick(now + wait * 100).unwrap(),
            None,
            "entry rearms rather than firing an old-view deadline"
        );
        assert_eq!(
            adapter.tick(now + wait * 101).unwrap(),
            Some(pacemaker::Action::Timeout {
                view: AgreementView(9),
                phase: AgreementPhase::Prevote
            })
        );
        let history = adapter.signing_history().len();
        let sequence = adapter.driver.sequence();
        for message in &messages {
            adapter.receive_view_request(message.clone()).unwrap();
        }
        assert_eq!(
            adapter.driver.sequence(),
            sequence,
            "duplicates must not consume WAL"
        );
        assert_eq!(adapter.signing_history().len(), history);
        assert!(
            adapter
                .author_nil_vote(adapter.signing_history().last().unwrap().id)
                .unwrap()
                .is_some(),
            "duplicates preserve the phase obligation"
        );
    }
    assert!(adapters[0].author_nil_vote(nil).unwrap().is_none());
    // Certificate export from one peer drives entry on another without local authoring.
    let exported: Vec<_> = adapters[0]
        .observed_view_requests()
        .unwrap()
        .into_iter()
        .filter(|r| r.target_view() == AgreementView(9))
        .collect();
    assert_eq!(exported.len(), m.set.quorum_size());
}

#[test]
fn view_request_signer_moves_do_not_accumulate_quorum_support() {
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    for signer in [0, 1] {
        adapter
            .receive_view_request(signed_view_request(&m, &bootstrap, signer, 9))
            .unwrap();
    }
    adapter
        .receive_view_request(signed_view_request(&m, &bootstrap, 1, 10))
        .unwrap();
    adapter
        .receive_view_request(signed_view_request(&m, &bootstrap, 2, 9))
        .unwrap();
    let retained = adapter.observed_view_requests().unwrap();
    assert_eq!(retained.len(), 3);
    assert_eq!(
        retained
            .iter()
            .filter(|r| r.target_view() == AgreementView(9))
            .count(),
        2
    );
    assert_eq!(
        retained
            .iter()
            .filter(|r| r.signature().validator_id == m.consensus[1].id)
            .count(),
        1
    );
    assert!(
        adapter.driver.output().unwrap().transition.is_none(),
        "partial support is not a durable transition"
    );
    assert_eq!(adapter.driver.sequence(), 0);
    let sequence = adapter.driver.sequence();
    adapter
        .receive_view_request(signed_view_request(&m, &bootstrap, 1, 9))
        .unwrap();
    assert_eq!(
        adapter.driver.sequence(),
        sequence,
        "lower signer target must not resurrect removed support"
    );
    assert_eq!(adapter.observed_view_requests().unwrap(), retained);
    drop(adapter);
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(adapter.observed_view_requests().unwrap().is_empty());
    for request in &retained {
        adapter.receive_view_request(request.clone()).unwrap();
    }
    for signer in [0, 2] {
        adapter
            .receive_view_request(signed_view_request(&m, &bootstrap, signer, 10))
            .unwrap();
    }
    assert_eq!(
        adapter.driver.output().unwrap().transition.unwrap().view,
        AgreementView(10)
    );
    assert!(
        adapter
            .observed_view_requests()
            .unwrap()
            .iter()
            .all(|r| r.target_view() == AgreementView(10)),
        "empty old buckets are removed"
    );
}

#[test]
fn view_request_late_and_old_support_are_authenticated_no_write_no_ops() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    for signer in 0..3 {
        adapter
            .receive_view_request(signed_view_request(&m, &bootstrap, signer, 9))
            .unwrap();
    }
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(9),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let sequence = adapter.driver.sequence();
    let before = adapter.driver.output().unwrap();
    let phase = format!("{:?}", before.transition);
    let authorable = before.authorable_vote_ids;
    let retained = adapter.observed_view_requests().unwrap();
    let history = format!("{:?}", adapter.signing_history());
    let readiness = adapter.readiness();
    // Previously unseen fourth-signer and old-view support are harmless at receipt.
    for target in [9, 8, 1] {
        let message = signed_view_request(&m, &bootstrap, 3, target);
        adapter.receive_view_request(message).unwrap();
        assert_eq!(adapter.driver.sequence(), sequence);
        assert_eq!(adapter.readiness(), readiness);
        assert_eq!(
            format!("{:?}", adapter.driver.output().unwrap().transition),
            phase
        );
        assert_eq!(
            adapter.driver.output().unwrap().authorable_vote_ids,
            authorable
        );
        assert_eq!(format!("{:?}", adapter.signing_history()), history);
        assert_eq!(adapter.observed_view_requests().unwrap(), retained);
    }
    // Authentication is mandatory even when the target is already obsolete.
    let message = signed_view_request(&m, &bootstrap, 3, 9);
    let mut signature = message.signature().clone();
    signature.signature[0] ^= 1;
    let forged = validator::SlotAgreementViewRequest::new(
        message.context().clone(),
        message.target_view(),
        signature,
        &m.set,
    )
    .unwrap();
    assert!(adapter.receive_view_request(forged).is_err());
    assert_eq!(adapter.driver.sequence(), sequence);
    assert_eq!(adapter.readiness(), readiness);
    assert!(
        adapter.author_nil_vote(authorable[0]).unwrap().is_some(),
        "phase remains authorable without recovery"
    );
}

#[test]
fn view_request_stale_owner_fails_closed_before_volatile_collection() {
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut stale = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let first = signed_view_request(&m, &bootstrap, 1, 9);
    stale.receive_view_request(first.clone()).unwrap();
    assert_eq!(stale.driver.sequence(), 0);
    let mut owner = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(owner.observed_view_requests().unwrap().is_empty());
    owner
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert!(
        stale.observed_view_requests().is_err(),
        "export must check fresh ownership"
    );
    // Even a duplicate/no-op receipt must check durable ownership first.
    assert!(stale.receive_view_request(first.clone()).is_err());
    assert_eq!(stale.view_requests, vec![first]);
    assert_eq!(
        stale.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    assert!(
        stale
            .receive_view_request(signed_view_request(&m, &bootstrap, 2, 9))
            .is_err()
    );
    assert_eq!(stale.view_requests.len(), 1);
    assert_eq!(owner.driver.sequence(), 1);
    assert!(owner.observed_view_requests().unwrap().is_empty());
}

#[test]
fn view_request_pending_authorization_recovery_is_not_a_voting_floor() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(adapter.author_view_request(AgreementView(0)).is_err());
    assert_eq!(adapter.driver.sequence(), 0);
    adapter
        .apply(AuthenticatedSlotAgreementRequest::ReserveViewRequest {
            target_view: AgreementView(99),
        })
        .unwrap();
    drop(adapter);
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    let message = adapter.author_view_request(AgreementView(99)).unwrap();
    assert_eq!(
        adapter.driver.sequence(),
        2,
        "recovery reuses the original authorization"
    );
    assert_eq!(
        adapter.driver.view_request_reservations().unwrap()[0].sequence,
        1
    );
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let nil = adapter.signing_history()[0].id;
    assert!(
        adapter.author_nil_vote(nil).unwrap().is_some(),
        "advisory support must not suppress lower-view votes"
    );
    let sequence = adapter.driver.sequence();
    let reservations = adapter.driver.view_request_reservations().unwrap();
    assert_eq!(reservations[0].message, Some(message.clone()));
    // Exact historical retries cannot replace completion or allocate a new event.
    adapter
        .driver
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::CompleteViewRequest {
                reservation_sequence: 1,
                message,
            },
        )
        .unwrap();
    assert_eq!(adapter.driver.sequence(), sequence);
    assert!(
        adapter
            .driver
            .apply(
                sequence + 1,
                AuthenticatedSlotAgreementRequest::ReserveViewRequest {
                    target_view: AgreementView(99)
                }
            )
            .is_err()
    );
    adapter
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert!(adapter.author_view_request(AgreementView(1)).is_err());
}

#[test]
fn view_request_authorization_completion_and_observation_bounds() {
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let message = adapter.author_view_request(AgreementView(20)).unwrap();
    let sequence = adapter.driver.sequence();
    let other_dir = Dir::new();
    let other_store = Store::open(&other_dir.0).unwrap();
    let mut other_bootstrap = bootstrap.clone();
    other_bootstrap.agreement.local_validator = m.consensus[1].id.clone();
    let mut other = Adapter::begin(&other_store, other_bootstrap, &m, 1).unwrap();
    assert!(
        other
            .driver
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::CompleteViewRequest {
                    reservation_sequence: 1,
                    message: message.clone()
                }
            )
            .is_err(),
        "completion without authorization"
    );
    other
        .apply(AuthenticatedSlotAgreementRequest::ReserveViewRequest {
            target_view: AgreementView(20),
        })
        .unwrap();
    assert!(
        other
            .driver
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::CompleteViewRequest {
                    reservation_sequence: 1,
                    message: message.clone()
                }
            )
            .is_err(),
        "completion must use pinned local signer"
    );
    let own = other.author_view_request(AgreementView(20)).unwrap();
    assert_eq!(own.signature().validator_id, m.consensus[1].id);
    assert_eq!(other.driver.sequence(), 2);
    let mut forged_signature = message.signature().clone();
    forged_signature.signature[0] ^= 1;
    let forged = validator::SlotAgreementViewRequest::new(
        message.context().clone(),
        message.target_view(),
        forged_signature,
        &m.set,
    )
    .unwrap();
    // Decode and construction are structural only; replay must authenticate explicitly.
    let forged =
        validator::SlotAgreementViewRequest::decode(&forged.encode(&m.set).unwrap(), &m.set)
            .unwrap();
    assert!(adapter.receive_view_request(forged).is_err());
    assert_eq!(adapter.driver.sequence(), sequence);
    assert!(
        adapter
            .driver
            .apply(
                sequence + 1,
                AuthenticatedSlotAgreementRequest::CompleteViewRequest {
                    reservation_sequence: 1,
                    message: message.clone()
                }
            )
            .is_err()
    );
    assert_eq!(
        adapter.completed_view_requests().unwrap(),
        vec![message.clone()]
    );
    // Increasing singleton support never consumes shared WAL events, regardless of
    // how many targets are sent; the only remote-write path requires a full quorum.
    let singleton_sequence = adapter.driver.sequence();
    for target in 1..=32 {
        let bytes = validator::SlotAgreementViewRequest::signing_payload(
            &bootstrap.agreement.context,
            AgreementView(target),
            &m.set,
        )
        .unwrap();
        let request = validator::SlotAgreementViewRequest::new(
            bootstrap.agreement.context.clone(),
            AgreementView(target),
            ValidatorSignature {
                validator_id: m.consensus[1].id.clone(),
                key_id: m.set.validators[1].keys[0].key_id.clone(),
                signature: Ed25519Scheme
                    .sign(&m.consensus[1].private_key, &bytes)
                    .unwrap(),
            },
            &m.set,
        )
        .unwrap();
        adapter.receive_view_request(request.clone()).unwrap();
        assert_eq!(adapter.driver.sequence(), singleton_sequence);
        let sequence = adapter.driver.sequence();
        adapter.receive_view_request(request).unwrap();
        assert_eq!(adapter.driver.sequence(), sequence);
    }
    let retained = adapter.observed_view_requests().unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].target_view(), AgreementView(32));
    let sequence = adapter.driver.sequence();
    for target in (1..=32).rev() {
        adapter
            .receive_view_request(signed_view_request(&m, &bootstrap, 1, target))
            .unwrap();
    }
    assert_eq!(
        adapter.driver.sequence(),
        sequence,
        "obsolete signer targets do not append"
    );
    // Recovery loses partial remote support but preserves local publication history.
    drop(adapter);
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(adapter.observed_view_requests().unwrap().is_empty());
    assert_eq!(adapter.completed_view_requests().unwrap(), vec![message]);
    // A fresh honest exact-target quorum is still usable after the signed flood.
    for signer in [0, 2] {
        adapter
            .receive_view_request(signed_view_request(&m, &bootstrap, signer, 100))
            .unwrap();
        assert_eq!(adapter.driver.sequence(), sequence);
        assert_eq!(
            adapter.driver.output().unwrap().transition.unwrap().view,
            AgreementView(0)
        );
    }
    adapter
        .receive_view_request(signed_view_request(&m, &bootstrap, 3, 100))
        .unwrap();
    assert_eq!(
        adapter.driver.output().unwrap().transition.unwrap().view,
        AgreementView(100)
    );
    assert_eq!(
        adapter.observed_view_requests().unwrap().len(),
        m.set.quorum_size()
    );
    assert_eq!(adapter.driver.sequence(), sequence + 1);
    drop(adapter);
    let adapter = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert!(adapter.observed_view_requests().unwrap().is_empty());
    assert_eq!(
        adapter.driver.output().unwrap().transition.unwrap().view,
        AgreementView(100)
    );
    assert_eq!(adapter.driver.sequence(), sequence + 1);
}

#[test]
fn nil_signing_publication_recovery_and_quorum_without_node() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let intent = adapter.signing_history()[0].clone();
    assert!(matches!(
        adapter.pending()[0],
        PendingIntent::UnsupportedNil { .. }
    ));
    let sequence = adapter.driver.sequence();
    assert!(adapter.author_nil_vote([255; 32]).is_err());
    assert_eq!(adapter.driver.sequence(), sequence);
    assert!(adapter.completed_nil_votes().unwrap().is_empty());
    let message = adapter.author_nil_vote(intent.id).unwrap().unwrap();
    message
        .verify(&bootstrap.agreement.context, &m.set)
        .unwrap();
    assert_eq!(message.vote(), &intent.vote);
    verify_signature(
        ALG_ED25519,
        &adapter.public_key,
        &intent.vote.signing_payload(&m.set).unwrap(),
        &message.signature().signature,
    )
    .unwrap();
    let bytes = message.encode(&m.set).unwrap();
    let completed = adapter.completed_nil_votes().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].intent_id, intent.id);
    assert_eq!(completed[0].sequence, sequence + 1);
    assert_eq!(completed[0].message.encode(&m.set).unwrap(), bytes);
    assert!(adapter.author_nil_vote(intent.id).unwrap().is_none());
    drop(adapter);
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    // Retrieval must not depend on signing again, even if the private key is unavailable.
    let private = std::mem::take(&mut adapter.private_key);
    assert_eq!(
        adapter.completed_nil_votes().unwrap()[0]
            .message
            .encode(&m.set)
            .unwrap(),
        bytes
    );
    assert!(adapter.author_nil_vote(intent.id).unwrap().is_none());
    adapter.private_key = private;
    let sign = |vote: validator::slot_agreement::AgreementVote, i: usize| {
        validator::SlotAgreementNilVote::new(
            vote.clone(),
            ValidatorSignature {
                validator_id: m.consensus[i].id.clone(),
                key_id: m.set.validators[i].keys[0].key_id.clone(),
                signature: Ed25519Scheme
                    .sign(
                        &m.consensus[i].private_key,
                        &vote.signing_payload(&m.set).unwrap(),
                    )
                    .unwrap(),
            },
            &m.set,
        )
        .unwrap()
    };
    for i in 0..3 {
        adapter
            .receive_nil_vote(sign(intent.vote.clone(), i))
            .unwrap();
    }
    assert_eq!(adapter.signing_history().len(), 2);
    let precommit = adapter.signing_history()[1].clone();
    assert_eq!(precommit.vote.phase, AgreementPhase::Precommit);
    assert_eq!(precommit.vote.value, AgreementValue::Nil);
    let sequence = adapter.driver.sequence();
    assert!(adapter.author_nil_vote(intent.id).unwrap().is_none());
    assert_eq!(adapter.driver.sequence(), sequence);
    let signed = adapter.author_nil_vote(precommit.id).unwrap().unwrap();
    assert_eq!(signed.vote(), &precommit.vote);
    for i in 0..3 {
        adapter
            .receive_nil_vote(sign(precommit.vote.clone(), i))
            .unwrap();
    }
    let output = adapter.driver.output().unwrap();
    let transition = output.transition.unwrap();
    assert_eq!(transition.view, AgreementView(0));
    assert!(transition.decision.is_none());
    assert!(output.candidates.is_empty());
    assert!(adapter.completed_carriers().unwrap().is_empty());
    let mut recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    let completed = recovered.completed_nil_votes().unwrap();
    assert_eq!(completed.len(), 2);
    assert_eq!(completed[0].message.encode(&m.set).unwrap(), bytes);
    assert_eq!(completed[1].message, signed);
}

#[test]
fn nil_signing_rejects_nonnil_stale_owner_and_bad_key_before_publication() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter.apply(request).unwrap();
    let nonnil = adapter.signing_history()[0].id;
    let sequence = adapter.driver.sequence();
    assert!(adapter.author_nil_vote(nonnil).unwrap().is_none());
    assert_eq!(adapter.driver.sequence(), sequence);
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Precommit,
        })
        .unwrap();
    let nil = adapter.signing_history().last().unwrap().id;
    let key = adapter.private_key.clone();
    adapter.private_key[0] ^= 1;
    assert!(adapter.author_nil_vote(nil).is_err());
    assert!(adapter.completed_nil_votes().unwrap().is_empty());
    adapter.private_key = key;
    let mut other = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    other
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert!(adapter.author_nil_vote(nil).is_err());
    assert_eq!(
        adapter.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    let mut recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert!(recovered.author_nil_vote(nil).unwrap().is_none());
    assert!(recovered.completed_nil_votes().unwrap().is_empty());
}

fn inspect_envelope(
    envelope: &CarrierEnvelope,
    m: &chain::Membership,
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    vertices: &[Vertex],
    lineage: &SlotAgreementViewLineage,
) {
    let binding =
        validator::SlotAgreementBinding::from_checkpoint(bootstrap.agreement.context.clone(), None)
            .unwrap();
    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(b"live-adapter-tests".to_vec());
    let is_vote = matches!(envelope.payload(), CarrierPayload::Vote { .. });
    // No retained ancestry, even though the wrapper itself is codec-consistent.
    assert!(envelope.inspect(&dag, &binding).is_err());
    for vertex in vertices {
        dag.insert(vertex.clone()).unwrap();
    }
    let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
    decoded.inspect(&dag, &binding).unwrap();
    let wrong_binding = validator::SlotAgreementBinding::from_checkpoint(
        bootstrap.agreement.context.clone(),
        Some(envelope.carrier().clone()),
    )
    .unwrap();
    assert!(decoded.inspect(&dag, &wrong_binding).is_err());
    if is_vote {
        let CarrierPayload::Vote { payload, .. } = envelope.payload() else {
            unreachable!()
        };
        let mut wrong = lineage.clone();
        wrong.entries[0].view_carrier.digest[0] ^= 1;
        let intent = PendingIntent::Vote {
            payload: payload.clone(),
            digest: envelope.payload_digest(),
            lineage: wrong,
        };
        if let Ok(wrong) = intent.into_envelope(envelope.carrier().clone(), &m.set) {
            assert!(wrong.inspect(&dag, &binding).is_err());
        }
        let mut wrong_payload = payload.clone();
        wrong_payload.prerequisite.digest[0] ^= 1;
        let wrong = PendingIntent::Vote {
            digest: wrong_payload.digest(&m.set).unwrap(),
            payload: wrong_payload,
            lineage: lineage.clone(),
        }
        .into_envelope(envelope.carrier().clone(), &m.set)
        .unwrap();
        assert!(wrong.inspect(&dag, &binding).is_err());
    }

    // A real signed carrier with an unrelated payload_hash is not authenticated
    // merely because the wrapper's digest and nested codecs agree.
    let original = vertices
        .iter()
        .find(|v| v.id().unwrap() == *envelope.carrier())
        .unwrap();
    let author = m
        .consensus
        .iter()
        .position(|id| id.id == original.author)
        .unwrap();
    let wrong = signed(
        m,
        author,
        original.round,
        original.references.clone(),
        [99; 32],
    );
    let mut wrong_dag = Dag::new(m.set.clone());
    wrong_dag.set_chain_id(b"live-adapter-tests".to_vec());
    for vertex in vertices.iter().filter(|v| v.round < original.round) {
        wrong_dag.insert(vertex.clone()).unwrap();
    }
    let wrong_id = wrong_dag.insert(wrong).unwrap();
    let payload = match envelope.payload() {
        CarrierPayload::Vote { payload, lineage } => CarrierPayload::Vote {
            payload: payload.clone(),
            lineage: lineage.clone(),
        },
        CarrierPayload::Pol(p) => {
            let mut p = p.clone();
            p.entries.last_mut().unwrap().pol.as_mut().unwrap().carrier = wrong_id.clone();
            CarrierPayload::Pol(p)
        }
        CarrierPayload::Proposal(p) => CarrierPayload::Proposal(p.clone()),
        CarrierPayload::View(p) => {
            let mut p = p.clone();
            p.entries.last_mut().unwrap().view_carrier = wrong_id.clone();
            CarrierPayload::View(p)
        }
        CarrierPayload::Final(p) => CarrierPayload::Final(p.clone()),
    };
    let body = match &payload {
        CarrierPayload::Vote { payload, lineage } => {
            let mut body = crypto::encoding::Encoder::new();
            body.put_bytes(&lineage.encode(&m.set).unwrap()).unwrap();
            body.put_bytes(&payload.encode(&m.set).unwrap()).unwrap();
            body.finish()
        }
        CarrierPayload::Proposal(p) => p.encode().unwrap(),
        CarrierPayload::View(p) => p.encode(&m.set).unwrap(),
        CarrierPayload::Pol(p) => p.encode(&m.set).unwrap(),
        CarrierPayload::Final(p) => p.encode(&m.set).unwrap(),
    };
    let mut e = crypto::encoding::Encoder::new();
    e.put_u16(2);
    e.put_u8(match payload {
        CarrierPayload::Vote { .. } => 0,
        CarrierPayload::Pol(_) => 1,
        CarrierPayload::Final(_) => 2,
        CarrierPayload::Proposal(_) => 3,
        CarrierPayload::View(_) => 4,
    });
    e.put_u64(wrong_id.round);
    e.put_bytes(&wrong_id.author).unwrap();
    e.put_raw(&wrong_id.digest);
    e.put_raw(&envelope.payload_digest());
    e.put_bytes(&body).unwrap();
    let wrong = CarrierEnvelope::decode(&e.finish(), &m.set).unwrap();
    assert!(wrong.inspect(&wrong_dag, &binding).is_err());
}

fn check_envelope(envelope: &CarrierEnvelope, set: &ValidatorSet) {
    let bytes = envelope.encode(set).unwrap();
    let decoded = CarrierEnvelope::decode(&bytes, set).unwrap();
    assert_eq!(&decoded, envelope);
    assert_eq!(decoded.encode(set).unwrap(), bytes);
    assert_eq!(decoded.carrier(), envelope.carrier());
    for end in 0..bytes.len() {
        assert!(
            CarrierEnvelope::decode(&bytes[..end], set).is_err(),
            "prefix {end}"
        );
    }
    let mut v1 = bytes.clone();
    v1[..2].copy_from_slice(&1u16.to_le_bytes());
    assert!(CarrierEnvelope::decode(&v1, set).is_err());
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(CarrierEnvelope::decode(&trailing, set).is_err());
    for offset in [0, 2] {
        let mut unknown = bytes.clone();
        unknown[offset] = 255;
        assert!(CarrierEnvelope::decode(&unknown, set).is_err());
    }
    let mut oversized = bytes.clone();
    oversized.resize(MAX_ENVELOPE_BYTES + 1, 0);
    assert!(CarrierEnvelope::decode(&oversized, set).is_err());
    let mut author_len = bytes.clone();
    author_len[11..15].copy_from_slice(&1025u32.to_le_bytes());
    assert!(CarrierEnvelope::decode(&author_len, set).is_err());
    let digest_offset = 15 + envelope.carrier().author.len() + 32;
    let mut wrong_digest = bytes.clone();
    wrong_digest[digest_offset] ^= 1;
    assert!(CarrierEnvelope::decode(&wrong_digest, set).is_err());
    let body_len_offset = digest_offset + 32;
    let mut body_len = bytes.clone();
    body_len[body_len_offset..body_len_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(CarrierEnvelope::decode(&body_len, set).is_err());
    let mut nested_trailing = bytes.clone();
    let body_len = bytes.len() - body_len_offset - 4;
    nested_trailing[body_len_offset..body_len_offset + 4]
        .copy_from_slice(&u32::try_from(body_len + 1).unwrap().to_le_bytes());
    nested_trailing.push(0);
    assert!(CarrierEnvelope::decode(&nested_trailing, set).is_err());
    if let CarrierPayload::Vote { payload, lineage } = envelope.payload() {
        let lineage_bytes = lineage.encode(set).unwrap();
        let vote_bytes = payload.encode(set).unwrap();
        for corrupt_lineage in [true, false] {
            let mut inner_lineage = lineage_bytes.clone();
            let mut inner_vote = vote_bytes.clone();
            if corrupt_lineage {
                inner_lineage.push(0);
            } else {
                inner_vote.push(0);
            }
            let mut body = crypto::encoding::Encoder::new();
            body.put_bytes(&inner_lineage).unwrap();
            body.put_bytes(&inner_vote).unwrap();
            let body = body.finish();
            let mut bad = bytes[..body_len_offset].to_vec();
            bad.extend_from_slice(&u32::try_from(body.len()).unwrap().to_le_bytes());
            bad.extend_from_slice(&body);
            assert!(CarrierEnvelope::decode(&bad, set).is_err());
        }
        let start = body_len_offset + 4;
        for offset in [start, start + 4 + lineage.encode(set).unwrap().len()] {
            let mut bad = bytes.clone();
            bad[offset..offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(CarrierEnvelope::decode(&bad, set).is_err());
        }
        if payload.vote.phase == validator::slot_agreement::AgreementPhase::Precommit {
            let mut incomplete = lineage.clone();
            incomplete.entries.last_mut().unwrap().pol = None;
            assert!(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: envelope.payload_digest(),
                    lineage: incomplete,
                }
                .into_envelope(envelope.carrier().clone(), set)
                .is_err()
            );
        }
    }
    let mut malformed_body = bytes.clone();
    malformed_body[body_len_offset + 4] = 255;
    assert!(CarrierEnvelope::decode(&malformed_body, set).is_err());
    if matches!(envelope.payload(), CarrierPayload::Pol(_)) {
        // Changing only the claimed outer ID cannot silently rebind the selected POL.
        let mut wrong_carrier = bytes.clone();
        wrong_carrier[3] ^= 1;
        assert!(CarrierEnvelope::decode(&wrong_carrier, set).is_err());
    }
}

fn historical_vote_envelopes(adapter: &Adapter) -> Vec<Vec<u8>> {
    adapter
        .pending()
        .iter()
        .filter_map(|intent| {
            let PendingIntent::Vote {
                payload,
                digest,
                lineage,
            } = intent
            else {
                return None;
            };
            let carrier = VertexId {
                round: payload.prerequisite.round + 1,
                author: payload.signature.validator_id.clone(),
                digest: [42; 32],
            };
            Some(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: *digest,
                    lineage: lineage.clone(),
                }
                .into_envelope(carrier, &adapter.set)
                .unwrap()
                .encode(&adapter.set)
                .unwrap(),
            )
        })
        .collect()
}

fn recover_envelope_adapter(
    adapter: &mut Adapter,
    store: &Store,
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    m: &chain::Membership,
    index: usize,
) {
    let envelopes = historical_vote_envelopes(adapter);
    let sequence = adapter.driver.sequence();
    let history = format!("{:?}", adapter.signing_history());
    let output = format!("{:?}", adapter.driver.output().unwrap());
    let votes: Vec<_> = adapter
        .pending()
        .iter()
        .filter_map(|p| match p {
            PendingIntent::Vote {
                payload, digest, ..
            } => Some((payload.clone(), *digest)),
            _ => None,
        })
        .collect();
    let mut bootstrap = bootstrap.clone();
    bootstrap.agreement.local_validator = m.consensus[index].id.clone();
    let recovered = Adapter::recover(store, bootstrap, m, index).unwrap();
    assert_eq!(recovered.driver.sequence(), sequence);
    assert_eq!(format!("{:?}", recovered.signing_history()), history);
    assert_eq!(format!("{:?}", recovered.driver.output().unwrap()), output);
    let recovered_votes: Vec<_> = recovered
        .pending()
        .iter()
        .filter_map(|p| match p {
            PendingIntent::Vote {
                payload, digest, ..
            } => Some((payload.clone(), *digest)),
            _ => None,
        })
        .collect();
    assert_eq!(recovered_votes, votes);
    assert_eq!(historical_vote_envelopes(&recovered), envelopes);
    assert_eq!(
        recovered.readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
    *adapter = recovered;
}

struct Dir(std::path::PathBuf);
impl Dir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "karsa-live-adapter-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).unwrap();
        Self(path)
    }
}
impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn signed(
    m: &chain::Membership,
    author: usize,
    round: u64,
    references: Vec<VertexId>,
    payload_hash: [u8; 32],
) -> Vertex {
    signed_for_chain(
        m,
        author,
        round,
        references,
        payload_hash,
        b"live-adapter-tests",
    )
}

fn signed_for_chain(
    m: &chain::Membership,
    author: usize,
    round: u64,
    references: Vec<VertexId>,
    payload_hash: [u8; 32],
    chain_id: &[u8],
) -> Vertex {
    let identity = &m.consensus[author];
    let mut v = Vertex {
        chain_id: chain_id.to_vec(),
        epoch: m.set.epoch,
        round,
        author: identity.id.clone(),
        payload_hash,
        references,
        signature: vec![],
    };
    v.signature = Ed25519Scheme
        .sign(&identity.private_key, &v.signing_payload().unwrap())
        .unwrap();
    v
}

fn fixture() -> (
    chain::Membership,
    AuthenticatedSlotAgreementBootstrap,
    AuthenticatedSlotAgreementRequest,
) {
    fixture_for_chain(b"live-adapter-tests")
}

fn fixture_for_chain(
    chain_id: &[u8],
) -> (
    chain::Membership,
    AuthenticatedSlotAgreementBootstrap,
    AuthenticatedSlotAgreementRequest,
) {
    fixture_for_chain_with_payload(chain_id, |_, _| [1; 32])
}

fn fixture_for_chain_with_payload(
    chain_id: &[u8],
    payload: impl Fn(usize, u64) -> [u8; 32],
) -> (
    chain::Membership,
    AuthenticatedSlotAgreementBootstrap,
    AuthenticatedSlotAgreementRequest,
) {
    let m = chain::membership(4, None).unwrap();
    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(chain_id.to_vec());
    let mut vertices = vec![];
    let mut refs = vec![];
    for round in 0..=2 {
        let mut ids = vec![];
        for author in 0..4 {
            let v = signed_for_chain(
                &m,
                author,
                round,
                refs.clone(),
                payload(author, round),
                chain_id,
            );
            ids.push(dag.insert(v.clone()).unwrap());
            vertices.push(v);
        }
        ids.sort_by(|a, b| (&a.round, &a.author, &a.digest).cmp(&(&b.round, &b.author, &b.digest)));
        refs = ids;
    }
    let leader = dag.leader(1).unwrap().id().unwrap();
    let mut order: Vec<_> = vertices
        .iter()
        .filter(|v| v.round == 0)
        .map(|v| v.id().unwrap())
        .collect();
    order.sort_by(|a, b| (&a.round, &a.author, &a.digest).cmp(&(&b.round, &b.author, &b.digest)));
    order.push(leader.clone());
    let mut ordered = Dag::new(m.set.clone());
    ordered.seed_order(order.clone());
    let context = SlotDecisionTip::from_checkpoint(
        dag.chain_id().to_vec(),
        &m.set,
        1,
        [7; 32],
        0,
        dag.commit_root(),
    )
    .unwrap();
    let proposal = SlotProposal {
        decision: SlotDecision {
            chain_id: dag.chain_id().to_vec(),
            validator_set_id: m.set.id().unwrap(),
            epoch: m.set.epoch,
            round: 1,
            previous: [7; 32],
            before_len: 0,
            before_root: dag.commit_root(),
            after_len: order.len() as u64,
            after_root: ordered.commit_root(),
            outcome: SlotOutcome::Commit { leader },
        },
        voters: refs[..3].to_vec(),
    };
    let mut carriers = vec![];
    for author in 0..4 {
        let v = signed_for_chain(
            &m,
            author,
            3,
            refs.clone(),
            if author == 0 {
                proposal.digest().unwrap()
            } else {
                [3; 32]
            },
            chain_id,
        );
        carriers.push(v.id().unwrap());
        vertices.push(v);
    }
    let mut lineage = SlotAgreementViewLineage {
        entries: vec![SlotAgreementProofEntry {
            proposal: proposal.into(),
            proposal_carrier: carriers[0].clone(),
            view: AgreementView(0),
            view_carrier: carriers[0].clone(),
            previous_pol: None,
            pol: None,
        }],
    };
    let proposer = validator::slot_agreement_view_proposer(&m.set, 1, AgreementView(0)).unwrap();
    for author in 0..4 {
        let elected = m.consensus[author].id == proposer;
        let v = signed_for_chain(
            &m,
            author,
            4,
            carriers.clone(),
            if elected {
                lineage.view_digest(0).unwrap()
            } else {
                [4; 32]
            },
            chain_id,
        );
        if elected {
            lineage.entries[0].view_carrier = v.id().unwrap();
        }
        vertices.push(v);
    }
    let bootstrap = AuthenticatedSlotAgreementBootstrap {
        agreement: store::SlotAgreementBootstrap {
            context,
            set: m.set.clone(),
            local_validator: m.consensus[0].id.clone(),
        },
        predecessor: None,
        order: vec![],
        vertices: vec![],
    };
    (
        m,
        bootstrap,
        AuthenticatedSlotAgreementRequest::Propose { lineage, vertices },
    )
}

fn authoring_node(m: &Membership, vertices: &[Vertex]) -> net::Node {
    authoring_node_index(m, vertices, 0)
}

fn authoring_node_index(m: &Membership, vertices: &[Vertex], index: usize) -> net::Node {
    let mut node = net::Node::with_chain_id(
        m.set.clone(),
        m.consensus[index].id.clone(),
        m.consensus[index].private_key.clone(),
        b"live-adapter-tests".to_vec(),
    );
    for vertex in vertices {
        node.receive(vertex.clone()).unwrap();
    }
    node.set_round(5);
    node
}

#[test]
fn the_elected_proposer_authors_the_initial_direct_proposal() {
    let m = chain::membership(4, None).unwrap();
    let chain_id = b"karsa-initial-proposal";
    let state = chain::genesis_state(&m.accounts).unwrap();
    let genesis = validator::Header::genesis(
        chain_id.to_vec(),
        m.set.epoch,
        state.state_root(),
        validator::commit_root(&[]),
    );
    let view = AgreementView(0);
    let proposer = validator::slot_agreement_view_proposer(&m.set, 1, view).unwrap();
    let index = m
        .consensus
        .iter()
        .position(|identity| identity.id == proposer)
        .unwrap();

    // Rounds 0..=3 with every round referencing the whole previous round: round 2
    // is a direct vote quorum for the round-1 leader, so the direct rule decides.
    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(chain_id.to_vec());
    let mut vertices = Vec::new();
    let mut previous = Vec::new();
    for round in 0..=3u64 {
        let mut ids = Vec::new();
        for author in 0..4 {
            let payload = [u8::try_from(author + 1).unwrap(); 32];
            let vertex = signed_for_chain(&m, author, round, previous.clone(), payload, chain_id);
            ids.push(dag.insert(vertex.clone()).unwrap());
            vertices.push(vertex);
        }
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        previous = ids;
    }
    let leader = dag.leader(1).unwrap().id().unwrap();
    assert!(matches!(
        dag.inspect_commit(1).unwrap(),
        Decision::Commit(history) if history.contains(&leader)
    ));

    let mut node = net::Node::with_chain_id(
        m.set.clone(),
        proposer.to_vec(),
        m.consensus[index].private_key.clone(),
        chain_id.to_vec(),
    );
    for vertex in &vertices {
        node.receive(vertex.clone()).unwrap();
    }
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = session::open_at_genesis(
        &store,
        &m,
        index,
        &genesis,
        state,
        validator::EpochSchedule::single(m.set.epoch),
    )
    .unwrap();
    owner
        .enable_authoring(
            node,
            pacemaker::Policy::new(
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(50),
                std::time::Duration::from_millis(100),
            )
            .unwrap(),
            std::time::Duration::from_millis(50),
        )
        .unwrap();

    let messages = owner.drive_local(Vec::new()).unwrap();
    assert_eq!(
        messages.len(),
        1,
        "the elected proposer authors one initial proposal"
    );
    let net::wire::Message::AgreementCarrier {
        envelope,
        vertices: cone,
    } = &messages[0]
    else {
        panic!("the initial publication must be a carrier");
    };
    let envelope = CarrierEnvelope::decode(envelope, &m.set).unwrap();
    let CarrierPayload::Proposal(proposal) = envelope.payload() else {
        panic!("the initial carrier must be a proposal");
    };
    assert_eq!(proposal.decision.round, 1);
    assert_eq!(proposal.decision.previous, genesis.id().unwrap());
    assert!(matches!(
        proposal.decision.outcome,
        SlotOutcome::Commit { leader: ref id } if *id == leader
    ));
    let SlotProposalEvidence::Direct { voters } = &proposal.evidence else {
        panic!("a direct commit must carry direct evidence");
    };
    assert_eq!(voters.len(), m.set.quorum_size());

    // The signed proposal must validate against an independent copy of the same
    // causal DAG under the durable binding, not merely against its own authoring.
    for vertex in cone {
        dag.insert(vertex.clone()).unwrap();
    }
    let binding = owner
        .finalization()
        .execution()
        .snapshot()
        .binding()
        .clone();
    let decision = dag
        .inspect_slot_proposal_envelope(proposal, envelope.carrier(), binding.tip())
        .unwrap();
    assert!(matches!(decision, Decision::Commit(_)));

    assert!(
        owner.drive_local(Vec::new()).unwrap().is_empty(),
        "a completed local proposal is not reauthored"
    );
}

#[test]
fn the_elected_proposer_binds_the_initial_view_and_a_peer_votes() {
    let m = chain::membership(4, None).unwrap();
    let chain_id = b"karsa-initial-view";
    let state = chain::genesis_state(&m.accounts).unwrap();
    let genesis = validator::Header::genesis(
        chain_id.to_vec(),
        m.set.epoch,
        state.state_root(),
        validator::commit_root(&[]),
    );
    let view = AgreementView(0);
    let proposer = validator::slot_agreement_view_proposer(&m.set, 1, view).unwrap();
    let index = m
        .consensus
        .iter()
        .position(|identity| identity.id == proposer)
        .unwrap();
    let peer = (index + 1) % 4;

    // Rounds 0..=2: the direct rule already commits the round-1 leader.
    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(chain_id.to_vec());
    let mut vertices = Vec::new();
    let mut previous = Vec::new();
    for round in 0..=2u64 {
        let mut ids = Vec::new();
        for author in 0..4 {
            let payload = [u8::try_from(author + 1).unwrap(); 32];
            let vertex = signed_for_chain(&m, author, round, previous.clone(), payload, chain_id);
            ids.push(dag.insert(vertex.clone()).unwrap());
            vertices.push(vertex);
        }
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        previous = ids;
    }
    let round_two = previous.clone();
    let leader = dag.leader(1).unwrap().id().unwrap();
    assert!(matches!(
        dag.inspect_commit(1).unwrap(),
        Decision::Commit(history) if history.contains(&leader)
    ));

    let mut proposer_node = net::Node::with_chain_id(
        m.set.clone(),
        m.consensus[index].id.clone(),
        m.consensus[index].private_key.clone(),
        chain_id.to_vec(),
    );
    let mut peer_node = net::Node::with_chain_id(
        m.set.clone(),
        m.consensus[peer].id.clone(),
        m.consensus[peer].private_key.clone(),
        chain_id.to_vec(),
    );
    for vertex in &vertices {
        proposer_node.receive(vertex.clone()).unwrap();
        peer_node.receive(vertex.clone()).unwrap();
    }
    let policy = pacemaker::Policy::new(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(100),
    )
    .unwrap();
    let proposer_dir = Dir::new();
    let proposer_store = Store::open(&proposer_dir.0).unwrap();
    let mut owner = session::open_at_genesis(
        &proposer_store,
        &m,
        index,
        &genesis,
        state.clone(),
        validator::EpochSchedule::single(m.set.epoch),
    )
    .unwrap();
    owner
        .enable_authoring(proposer_node, policy, std::time::Duration::from_millis(50))
        .unwrap();
    let peer_dir = Dir::new();
    let peer_store = Store::open(&peer_dir.0).unwrap();
    let mut receiver = session::open_at_genesis(
        &peer_store,
        &m,
        peer,
        &genesis,
        state,
        validator::EpochSchedule::single(m.set.epoch),
    )
    .unwrap();
    receiver
        .enable_authoring(peer_node, policy, std::time::Duration::from_millis(50))
        .unwrap();

    // The proposer authors the plain proposal, then binds it into the view-0
    // authorization once a quorum of round-3 authors is available.
    let proposal_message = owner.drive_local(Vec::new()).unwrap();
    assert_eq!(proposal_message.len(), 1);
    let net::wire::Message::AgreementCarrier {
        envelope: proposal_bytes,
        ..
    } = &proposal_message[0]
    else {
        panic!("the initial publication must be a proposal carrier");
    };
    let proposal_envelope = CarrierEnvelope::decode(proposal_bytes, &m.set).unwrap();
    let CarrierPayload::Proposal(proposal) = proposal_envelope.payload() else {
        panic!("the initial carrier must be a proposal");
    };
    let proposal = proposal.clone();
    let proposal_carrier = proposal_envelope.carrier().clone();

    let mut round_three = Vec::new();
    let mut placeholders = Vec::new();
    for author in 0..4 {
        if author == index {
            continue;
        }
        let vertex = signed_for_chain(
            &m,
            author,
            3,
            round_two.clone(),
            [u8::try_from(author + 20).unwrap(); 32],
            chain_id,
        );
        round_three.push(vertex.id().unwrap());
        placeholders.push(vertex);
    }
    round_three.push(proposal_carrier.clone());
    round_three.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    let view_message = owner.drive_local(placeholders.clone()).unwrap();
    assert_eq!(view_message.len(), 1, "the elected proposer binds one view");
    let net::wire::Message::AgreementCarrier {
        envelope: view_bytes,
        ..
    } = &view_message[0]
    else {
        panic!("the view authorization must be a carrier");
    };
    let view_envelope = CarrierEnvelope::decode(view_bytes, &m.set).unwrap();
    let CarrierPayload::View(lineage) = view_envelope.payload() else {
        panic!("the second carrier must be a view");
    };
    let entry = lineage.entries.last().unwrap();
    assert_eq!(entry.view, view);
    assert_eq!(entry.proposal, proposal);
    assert_eq!(entry.proposal_carrier, proposal_carrier);

    // A peer that receives the proposal and the view gains exactly one prevote
    // obligation; it becomes a carrier only when causal availability is supplied.
    receiver
        .receive_agreement_message(proposal_message[0].clone())
        .unwrap();
    receiver
        .receive_agreement_message(view_message[0].clone())
        .unwrap();
    assert_eq!(receiver.finalization().finalizer().built_headers(), 0);
    let mut availability = placeholders;
    for author in 0..4 {
        if author == index {
            continue;
        }
        let vertex = signed_for_chain(
            &m,
            author,
            4,
            round_three.clone(),
            [u8::try_from(author + 30).unwrap(); 32],
            chain_id,
        );
        availability.push(vertex);
    }
    for message in [&proposal_message[0], &view_message[0]] {
        if let net::wire::Message::AgreementCarrier { vertices, .. } = message {
            availability.extend(vertices.iter().cloned());
        }
    }
    let vote_message = receiver.drive_local(availability).unwrap();
    assert_eq!(
        vote_message.len(),
        1,
        "the peer authors one prevote carrier"
    );
    let net::wire::Message::AgreementCarrier {
        envelope: vote_bytes,
        ..
    } = &vote_message[0]
    else {
        panic!("the peer vote must be a carrier");
    };
    let vote_envelope = CarrierEnvelope::decode(vote_bytes, &m.set).unwrap();
    let CarrierPayload::Vote { payload, .. } = vote_envelope.payload() else {
        panic!("the peer publication must be a vote");
    };
    assert_eq!(
        payload.vote.phase,
        validator::slot_agreement::AgreementPhase::Prevote
    );
    assert!(matches!(
        payload.vote.value,
        validator::slot_agreement::AgreementValue::Decision(_)
    ));
}

#[test]
fn the_elected_proposer_observes_its_own_view_and_authors_its_vote() {
    let m = chain::membership(4, None).unwrap();
    let chain_id = b"karsa-initial-self-observation";
    let state = chain::genesis_state(&m.accounts).unwrap();
    let genesis = validator::Header::genesis(
        chain_id.to_vec(),
        m.set.epoch,
        state.state_root(),
        validator::commit_root(&[]),
    );
    let view = AgreementView(0);
    let proposer = validator::slot_agreement_view_proposer(&m.set, 1, view).unwrap();
    let index = m
        .consensus
        .iter()
        .position(|identity| identity.id == proposer)
        .unwrap();

    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(chain_id.to_vec());
    let mut vertices = Vec::new();
    let mut previous = Vec::new();
    for round in 0..=2u64 {
        let mut ids = Vec::new();
        for author in 0..4 {
            let payload = [u8::try_from(author + 1).unwrap(); 32];
            let vertex = signed_for_chain(&m, author, round, previous.clone(), payload, chain_id);
            ids.push(dag.insert(vertex.clone()).unwrap());
            vertices.push(vertex);
        }
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        previous = ids;
    }
    let round_two = previous.clone();
    let leader = dag.leader(1).unwrap().id().unwrap();
    assert!(matches!(
        dag.inspect_commit(1).unwrap(),
        Decision::Commit(history) if history.contains(&leader)
    ));

    let mut node = net::Node::with_chain_id(
        m.set.clone(),
        m.consensus[index].id.clone(),
        m.consensus[index].private_key.clone(),
        chain_id.to_vec(),
    );
    for vertex in &vertices {
        node.receive(vertex.clone()).unwrap();
    }
    let policy = pacemaker::Policy::new(
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(50),
        std::time::Duration::from_millis(100),
    )
    .unwrap();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = session::open_at_genesis(
        &store,
        &m,
        index,
        &genesis,
        state,
        validator::EpochSchedule::single(m.set.epoch),
    )
    .unwrap();
    owner
        .enable_authoring(node, policy, std::time::Duration::from_millis(50))
        .unwrap();

    // The proposal is signed, published and then received by its own author.
    let proposal_message = owner.drive_local(Vec::new()).unwrap();
    assert_eq!(proposal_message.len(), 1);
    let net::wire::Message::AgreementCarrier {
        envelope: proposal_bytes,
        ..
    } = &proposal_message[0]
    else {
        panic!("the initial publication must be a proposal carrier");
    };
    let proposal_envelope = CarrierEnvelope::decode(proposal_bytes, &m.set).unwrap();
    let proposal_carrier = proposal_envelope.carrier().clone();

    let mut round_three = Vec::new();
    let mut placeholders = Vec::new();
    for author in 0..4 {
        if author == index {
            continue;
        }
        let vertex = signed_for_chain(
            &m,
            author,
            3,
            round_two.clone(),
            [u8::try_from(author + 20).unwrap(); 32],
            chain_id,
        );
        round_three.push(vertex.id().unwrap());
        placeholders.push(vertex);
    }
    round_three.push(proposal_carrier.clone());
    round_three.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    let view_message = owner.drive_local(placeholders).unwrap();
    assert_eq!(view_message.len(), 1, "the elected proposer binds one view");
    let net::wire::Message::AgreementCarrier {
        envelope: view_bytes,
        ..
    } = &view_message[0]
    else {
        panic!("the view authorization must be a carrier");
    };
    let view_envelope = CarrierEnvelope::decode(view_bytes, &m.set).unwrap();
    let view_carrier = view_envelope.carrier().clone();

    // Receipt of its own view authorization is what gives the author a prevote
    // intent, but the carrier still needs a quorum of round-4 causal authors.
    assert!(
        owner.drive_local(Vec::new()).unwrap().is_empty(),
        "a prevote intent without causal readiness must wait"
    );

    let mut round_four = vec![view_carrier.clone()];
    let mut availability = Vec::new();
    for author in 0..4 {
        if author == index {
            continue;
        }
        let vertex = signed_for_chain(
            &m,
            author,
            4,
            round_three.clone(),
            [u8::try_from(author + 30).unwrap(); 32],
            chain_id,
        );
        round_four.push(vertex.id().unwrap());
        availability.push(vertex);
    }
    round_four.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));

    let vote_message = owner.drive_local(availability).unwrap();
    assert_eq!(
        vote_message.len(),
        1,
        "self-observation must let the proposer author its own prevote"
    );
    let net::wire::Message::AgreementCarrier {
        envelope: vote_bytes,
        vertices: vote_cone,
    } = &vote_message[0]
    else {
        panic!("the proposer vote must be a carrier");
    };
    let vote_envelope = CarrierEnvelope::decode(vote_bytes, &m.set).unwrap();
    let CarrierPayload::Vote { payload, lineage } = vote_envelope.payload() else {
        panic!("the proposer publication must be a vote");
    };
    assert_eq!(
        payload.vote.phase,
        validator::slot_agreement::AgreementPhase::Prevote
    );
    assert!(matches!(
        payload.vote.value,
        validator::slot_agreement::AgreementValue::Decision(_)
    ));
    assert_eq!(
        lineage.entries.last().unwrap().view_carrier,
        view_carrier,
        "the prevote must name the view authorization it observed"
    );
    let carrier = vote_envelope.carrier();
    assert_eq!(carrier.author.as_slice(), proposer);
    let mut held: Vec<_> = vote_cone
        .iter()
        .filter(|vertex| vertex.round == 4)
        .filter_map(|vertex| vertex.id().ok())
        .collect();
    held.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    assert_eq!(
        held, round_four,
        "the vote carrier must reference the held round-4 quorum"
    );
}

#[test]
fn actual_vote_authoring_rejects_foreign_chain_sibling_before_signing() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { vertices, lineage } = &request else {
        unreachable!()
    };
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    adapter.apply(request.clone()).unwrap();
    let id = adapter.signing_history()[0].id;
    let binding = adapter.driver.output().unwrap().binding;
    let mut foreign = vertices.clone();
    let sibling = foreign
        .iter_mut()
        .find(|v| v.round == 4 && v.author != lineage.entries[0].view_carrier.author)
        .unwrap();
    let author = m
        .consensus
        .iter()
        .position(|identity| identity.id == sibling.author)
        .unwrap();
    *sibling = signed_for_chain(
        &m,
        author,
        4,
        sibling.references.clone(),
        sibling.payload_hash,
        b"foreign-chain",
    );
    let mut node = authoring_node(&m, &foreign);
    // Legacy receive accepts this signed sibling, and it is outside the lineage cone.
    node.dag()
        .inspect_slot_agreement_view_lineage(lineage, &binding)
        .unwrap();
    assert!(node.dag().get(5, node.id()).is_none());
    assert!(adapter.author_vote(id, &mut node).unwrap().is_none());
    assert_eq!((node.round(), node.authored()), (5, 0));
    assert!(
        node.dag().get(5, node.id()).is_none(),
        "no rejected carrier may be inserted"
    );
    let mut valid = authoring_node(&m, vertices);
    let authored = adapter.author_vote(id, &mut valid).unwrap().unwrap();
    authored.envelope.inspect(valid.dag(), &binding).unwrap();
    assert_eq!((valid.round(), valid.authored()), (6, 1));
}

#[test]
fn actual_vote_authoring_preflights_node_and_dependencies() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { vertices, .. } = &request else {
        unreachable!()
    };
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter.apply(request.clone()).unwrap();
    let id = adapter.signing_history()[0].id;
    let mut occupied = authoring_node(&m, vertices);
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let existing = signed(&m, 0, 5, refs, [42; 32]);
    occupied.receive(existing.clone()).unwrap();
    occupied.set_round(5);
    assert!(
        adapter.author_vote(id, &mut occupied).unwrap().is_none(),
        "occupied vote slot must not sign a conflicting carrier"
    );
    assert_eq!((occupied.round(), occupied.authored()), (5, 0));
    assert_eq!(occupied.dag().get(5, occupied.id()), Some(&existing));
    let mut missing = authoring_node(&m, &[]);
    assert!(adapter.author_vote(id, &mut missing).unwrap().is_none());
    assert_eq!((missing.round(), missing.authored()), (5, 0));
    // Holding the direct prerequisite alone is not a complete cone or lineage.
    let partial: Vec<_> = vertices.iter().filter(|v| v.round < 4).cloned().collect();
    let mut partial = authoring_node(&m, &partial);
    assert!(adapter.author_vote(id, &mut partial).unwrap().is_none());
    assert_eq!((partial.round(), partial.authored()), (5, 0));
    for (identity, chain, key, set) in [
        (
            m.consensus[1].id.clone(),
            b"live-adapter-tests".to_vec(),
            m.consensus[0].private_key.clone(),
            m.set.clone(),
        ),
        (
            m.consensus[0].id.clone(),
            b"wrong-chain".to_vec(),
            m.consensus[0].private_key.clone(),
            m.set.clone(),
        ),
        (
            m.consensus[0].id.clone(),
            b"live-adapter-tests".to_vec(),
            m.consensus[1].private_key.clone(),
            m.set.clone(),
        ),
        (
            m.consensus[0].id.clone(),
            b"live-adapter-tests".to_vec(),
            m.consensus[0].private_key.clone(),
            chain::membership(3, None).unwrap().set,
        ),
    ] {
        let mut wrong = net::Node::with_chain_id(set, identity, key, chain);
        wrong.set_round(5);
        assert!(adapter.author_vote(id, &mut wrong).is_err());
        assert_eq!((wrong.round(), wrong.authored()), (5, 0));
    }
    let mut wrong_epoch = net::Node::with_chain_id_and_epoch_length(
        m.set.clone(),
        1,
        m.consensus[0].id.clone(),
        m.consensus[0].private_key.clone(),
        b"live-adapter-tests".to_vec(),
    );
    wrong_epoch.set_round(5);
    assert!(adapter.author_vote(id, &mut wrong_epoch).is_err());
    assert_eq!((wrong_epoch.round(), wrong_epoch.authored()), (5, 0));
    // An authenticated WAL lineage is not evidence for a different, valid signed DAG.
    let mut incompatible = vertices.clone();
    let selected = adapter.signing_history()[0]
        .lineage
        .as_ref()
        .unwrap()
        .entries[0]
        .view_carrier
        .clone();
    let index = incompatible
        .iter()
        .position(|v| v.id().unwrap() == selected)
        .unwrap();
    let old = &incompatible[index];
    let author = m
        .consensus
        .iter()
        .position(|identity| identity.id == old.author)
        .unwrap();
    incompatible[index] = signed(&m, author, old.round, old.references.clone(), [99; 32]);
    let mut incompatible = authoring_node(&m, &incompatible);
    assert!(
        adapter
            .author_vote(id, &mut incompatible)
            .unwrap()
            .is_none()
    );
    assert_eq!((incompatible.round(), incompatible.authored()), (5, 0));
    let mut node = authoring_node(&m, vertices);
    let PendingIntent::Vote {
        payload, lineage, ..
    } = adapter
        .pending()
        .iter()
        .find(|intent| matches!(intent, PendingIntent::Vote { .. }))
        .unwrap()
    else {
        unreachable!()
    };
    let payload = payload.clone();
    let lineage = lineage.clone();
    let binding = adapter.driver.output().unwrap().binding;
    let unsigned = node
        .prospective_slot_vote(&lineage, &payload, &binding)
        .unwrap();
    adapter
        .reserve_carrier(
            &unsigned,
            store::AgreementCarrierEvidence::Vote {
                lineage: lineage.clone(),
                payload: payload.clone(),
            },
            node.dag(),
        )
        .unwrap();
    assert_eq!((node.round(), node.authored()), (5, 0));
    assert_eq!(
        adapter.driver.reserved_carriers().unwrap()[0].unsigned,
        unsigned
    );
    let sequence = adapter.driver.sequence();
    assert!(
        adapter
            .reserve_carrier(
                &unsigned,
                store::AgreementCarrierEvidence::Pol {
                    lineage: lineage.clone(),
                },
                node.dag()
            )
            .is_err()
    );
    assert_eq!((node.round(), node.authored()), (5, 0));
    assert_eq!(adapter.driver.sequence(), sequence);
    // Crash boundary: the reservation exists, but no outer signer has run.
    drop(adapter);
    let mut adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    let mut changed_vertices = vertices.clone();
    let sibling = signed(
        &m,
        3,
        4,
        vertices
            .iter()
            .filter(|v| v.round == 3)
            .map(|v| v.id().unwrap())
            .collect(),
        [231; 32],
    );
    changed_vertices.retain(|v| !(v.round == 4 && v.author == sibling.author));
    changed_vertices.push(sibling);
    let mut changed = authoring_node(&m, &changed_vertices);
    assert!(adapter.author_vote(id, &mut changed).is_err());
    assert_eq!((changed.round(), changed.authored()), (5, 0));
    assert_eq!(adapter.driver.sequence(), sequence);
    let authored = adapter.author_vote(id, &mut node).unwrap().unwrap();
    assert_eq!(authored.vertex.id().unwrap(), unsigned.id().unwrap());
    assert_eq!(adapter.driver.sequence(), sequence + 1);
    assert_eq!((node.round(), node.authored()), (6, 1));
    assert_eq!(
        authored.vertex.payload_hash,
        authored.envelope.payload_digest()
    );
    assert_eq!(authored.vertex.id().unwrap(), *authored.envelope.carrier());
    authored
        .envelope
        .inspect(node.dag(), &adapter.driver.output().unwrap().binding)
        .unwrap();
    check_envelope(&authored.envelope, &m.set);
    let signed_bytes = authored.vertex.encode().unwrap();
    let envelope_bytes = authored.envelope.encode(&m.set).unwrap();
    let completed = adapter.driver.completed_carriers().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].signed.encode().unwrap(), signed_bytes);
    assert_eq!(completed[0].reservation.sequence, sequence);
    assert_eq!(completed[0].sequence, sequence + 1);
    let mut recovered = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    for _ in 0..2 {
        let publications = recovered.completed_carriers().unwrap();
        assert_eq!(publications.len(), 1);
        assert_eq!(publications[0].vertex.encode().unwrap(), signed_bytes);
        assert_eq!(
            publications[0].envelope.encode(&m.set).unwrap(),
            envelope_bytes
        );
        assert_eq!(recovered.driver.sequence(), sequence + 1);
    }
}

#[test]
fn actual_vote_authoring_blocks_stale_phase_view_and_owner() {
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { vertices, .. } = &request else {
        unreachable!()
    };
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter.apply(request.clone()).unwrap();
    let id = adapter.signing_history()[0].id;
    let mut node = authoring_node(&m, vertices);
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Precommit,
        })
        .unwrap();
    assert!(adapter.author_vote(id, &mut node).unwrap().is_none());
    let nil = adapter.signing_history()[1].id;
    assert!(
        adapter
            .author_vote(nil, &mut node)
            .unwrap_err()
            .contains("nil")
    );
    adapter
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert!(adapter.author_vote(id, &mut node).unwrap().is_none());
    let mut other = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    other
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(1),
        })
        .unwrap();
    assert!(adapter.author_vote(id, &mut node).is_err());
    assert_eq!(
        adapter.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    assert!(adapter.author_vote(id, &mut node).is_err());
    assert_eq!((node.round(), node.authored()), (5, 0));
}

#[test]
fn tampered_history_blocks_all_reconstruction_before_signing() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    adapter.apply(request.clone()).unwrap();
    let original = adapter.signing_history()[0].clone();
    let mut variants = Vec::new();
    let mut missing = original.clone();
    missing.lineage = None;
    variants.push(missing);
    let mut empty = original.clone();
    empty.lineage.as_mut().unwrap().entries.clear();
    variants.push(empty);
    let mut wrong_view = original.clone();
    wrong_view
        .lineage
        .as_mut()
        .unwrap()
        .entries
        .last_mut()
        .unwrap()
        .view
        .0 += 1;
    variants.push(wrong_view);
    let mut wrong_carrier = original.clone();
    wrong_carrier
        .lineage
        .as_mut()
        .unwrap()
        .entries
        .last_mut()
        .unwrap()
        .view_carrier
        .digest[0] ^= 1;
    variants.push(wrong_carrier);
    let mut wrong_decision = original.clone();
    wrong_decision.vote.value = AgreementValue::Nil;
    wrong_decision.prerequisite = AgreementSigningPrerequisite::UnsupportedNil;
    variants.push(wrong_decision);
    let mut missing_pol = original.clone();
    missing_pol.vote.phase = validator::slot_agreement::AgreementPhase::Precommit;
    variants.push(missing_pol);
    let mut wrong_context = original.clone();
    wrong_context.vote.context = fixture_for_chain(b"other-history").1.agreement.context;
    variants.push(wrong_context);
    for tampered in variants {
        adapter.pending.clear();
        adapter.history.clear();
        // A valid first entry must not be signed before a malformed later one is checked.
        let output = adapter.driver.output().unwrap();
        assert!(
            adapter
                .reconstruct_history(output, vec![original.clone(), tampered])
                .is_err()
        );
        assert!(adapter.pending().is_empty());
        assert!(adapter.signing_history().is_empty());
        assert_eq!(
            adapter.readiness(),
            Readiness::RecoveryRequiredHistoricalIntentsUnavailable
        );
        assert!(adapter.apply(request.clone()).is_err());
    }
}

#[test]
fn exact_durable_signature_retention_and_recovery_boundary() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let mut store = Store::open(&dir.0).unwrap();
    assert!(disabled_guard(&store).is_ok());
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    assert!(disabled_guard(&store).is_err());
    let stage = store.stage().unwrap();
    assert!(
        disabled_guard(stage.store()).is_err(),
        "a staged generation must still check the signing root"
    );
    drop(stage);
    adapter.apply(request.clone()).unwrap();
    assert_eq!(adapter.driver.sequence(), 1);
    let PendingIntent::Vote {
        payload, digest, ..
    } = &adapter.pending()[0]
    else {
        panic!("expected vote")
    };
    let expected = Ed25519Scheme
        .sign(
            &m.consensus[0].private_key,
            &payload.vote.signing_payload(&m.set).unwrap(),
        )
        .unwrap();
    assert_eq!(payload.signature.signature, expected);
    assert_eq!(*digest, payload.digest(&m.set).unwrap());
    let original = payload.clone();
    let original_envelopes = historical_vote_envelopes(&adapter);
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        panic!("proposal fixture")
    };
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let carrier = signed(&m, 0, 5, refs, original.digest(&m.set).unwrap());
    // An authenticated observation replaces the driver's latest transition with vote=None.
    adapter
        .apply(AuthenticatedSlotAgreementRequest::ObserveVote {
            lineage,
            witness: validator::SlotAgreementVoteWitness {
                payload: original.clone(),
                carrier: carrier.id().unwrap(),
            },
            vertices: vec![carrier],
        })
        .unwrap();
    assert_eq!(adapter.pending().len(), 1);
    let PendingIntent::Vote { payload, .. } = &adapter.pending()[0] else {
        panic!("expected retained vote")
    };
    assert_eq!(*payload, original);
    assert!(
        adapter
            .driver
            .output()
            .unwrap()
            .transition
            .unwrap()
            .vote
            .is_none()
    );
    drop(adapter);
    assert!(Adapter::recover(&store, bootstrap.clone(), &m, 1).is_err());
    let mut recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert_eq!(
        recovered.readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
    let PendingIntent::Vote { payload, .. } = &recovered.pending()[0] else {
        panic!("recovered historical vote")
    };
    assert_eq!(*payload, original);
    assert_eq!(historical_vote_envelopes(&recovered), original_envelopes);
    let output = recovered.driver.output();
    recovered.consume_durable_result(output, None).unwrap();
    assert_eq!(
        recovered.pending().len(),
        1,
        "outbox reads deduplicate by ID"
    );
}

#[test]
fn received_envelope_valid_for_other_chain_is_rejected_without_durable_change() {
    let (m, bootstrap, request) = fixture();
    let (other_m, other_bootstrap, other_request) = fixture_for_chain(b"other-envelope-chain");
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let other_dir = Dir::new();
    let other_store = Store::open(&other_dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter.apply(request.clone()).unwrap();
    let mut other = Adapter::begin(&other_store, other_bootstrap.clone(), &other_m, 0).unwrap();
    other.apply(other_request.clone()).unwrap();
    let AuthenticatedSlotAgreementRequest::Propose {
        lineage,
        mut vertices,
    } = other_request
    else {
        panic!("other proposal")
    };
    let PendingIntent::Vote {
        payload, digest, ..
    } = &other.pending()[0]
    else {
        panic!("other prevote")
    };
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let carrier = signed_for_chain(&other_m, 0, 5, refs, *digest, b"other-envelope-chain");
    let envelope = PendingIntent::Vote {
        payload: payload.clone(),
        digest: *digest,
        lineage: lineage.clone(),
    }
    .into_envelope(carrier.id().unwrap(), &other_m.set)
    .unwrap();
    vertices.push(carrier);
    let decoded =
        CarrierEnvelope::decode(&envelope.encode(&other_m.set).unwrap(), &other_m.set).unwrap();
    // Prove the complete signed envelope is independently valid, not a corrupt fixture.
    other.receive_envelope(decoded, vertices.clone()).unwrap();
    recover_envelope_adapter(&mut other, &other_store, &other_bootstrap, &other_m, 0);

    let sequence = adapter.driver.sequence();
    let history = format!("{:?}", adapter.signing_history());
    let pending = format!("{:?}", adapter.pending());
    let state = exposed_receipt_state(&store, &bootstrap);
    let decoded =
        CarrierEnvelope::decode(&envelope.encode(&other_m.set).unwrap(), &other_m.set).unwrap();
    assert!(adapter.receive_envelope(decoded, vertices).is_err());
    assert_eq!(adapter.driver.sequence(), sequence);
    assert_eq!(format!("{:?}", adapter.signing_history()), history);
    assert_eq!(format!("{:?}", adapter.pending()), pending);
    assert_eq!(
        adapter.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    recover_envelope_adapter(&mut adapter, &store, &bootstrap, &m, 0);
    assert_eq!(exposed_receipt_state(&store, &bootstrap), state);
    assert_eq!(adapter.driver.sequence(), sequence);
    assert_eq!(format!("{:?}", adapter.signing_history()), history);
    assert_eq!(format!("{:?}", adapter.pending()), pending);

    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        panic!("original proposal")
    };
    let PendingIntent::Vote {
        payload, digest, ..
    } = &adapter.pending()[0]
    else {
        panic!("original prevote")
    };
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let carrier = signed(&m, 0, 5, refs, *digest);
    let envelope = PendingIntent::Vote {
        payload: payload.clone(),
        digest: *digest,
        lineage: lineage.clone(),
    }
    .into_envelope(carrier.id().unwrap(), &m.set)
    .unwrap();
    let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
    adapter.receive_envelope(decoded, vec![carrier]).unwrap();
    assert_eq!(adapter.driver.sequence(), sequence + 1);
    assert_eq!(format!("{:?}", adapter.signing_history()), history);
    recover_envelope_adapter(&mut adapter, &store, &bootstrap, &m, 0);
    assert_eq!(exposed_receipt_state(&store, &bootstrap), state);
}

// The driver's session/DAG are private to store. Reopen through existing read/replay
// APIs: the binding includes the active tip's order length/root and predecessor carrier.
fn exposed_receipt_state(store: &Store, bootstrap: &AuthenticatedSlotAgreementBootstrap) -> String {
    let session = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    format!(
        "{:?}",
        (
            session.binding().unwrap(),
            store.slot_application_requests().unwrap(),
            store.slot_applications().unwrap(),
            store.live_snapshot().unwrap(),
        )
    )
}

#[test]
fn received_envelope_reauthenticates_carrier_before_wal_and_requires_recovery() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter.apply(request.clone()).unwrap();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        panic!("proposal")
    };
    let PendingIntent::Vote {
        payload, digest, ..
    } = &adapter.pending()[0]
    else {
        panic!("prevote")
    };
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    // This is a genuinely signed vertex, but it carries an unrelated payload hash.
    // The envelope codec cannot establish that association and must not authorize it.
    let wrong_vertex = signed(&m, 0, 5, refs, [99; 32]);
    let envelope = PendingIntent::Vote {
        payload: payload.clone(),
        digest: *digest,
        lineage: lineage.clone(),
    }
    .into_envelope(wrong_vertex.id().unwrap(), &m.set)
    .unwrap();
    let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
    let sequence = adapter.driver.sequence();
    let history = format!("{:?}", adapter.signing_history());
    let pending = format!("{:?}", adapter.pending());
    assert!(
        adapter
            .receive_envelope(decoded, vec![wrong_vertex])
            .is_err()
    );
    assert_eq!(adapter.driver.sequence(), sequence);
    assert_eq!(format!("{:?}", adapter.signing_history()), history);
    assert_eq!(format!("{:?}", adapter.pending()), pending);
    assert_eq!(
        adapter.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
    assert!(adapter.receive_envelope(decoded, vec![]).is_err());
    assert_eq!(adapter.driver.sequence(), sequence);
    recover_envelope_adapter(&mut adapter, &store, &bootstrap, &m, 0);
    assert_eq!(format!("{:?}", adapter.pending()), pending);
    assert!(adapter.driver.output().unwrap().candidates.is_empty());

    let PendingIntent::Vote {
        payload, digest, ..
    } = &adapter.pending()[0]
    else {
        panic!("recovered prevote")
    };
    let refs = vertices
        .iter()
        .filter(|v| v.round == 4)
        .map(|v| v.id().unwrap())
        .collect();
    let valid_vertex = signed(&m, 0, 5, refs, *digest);
    let envelope = PendingIntent::Vote {
        payload: payload.clone(),
        digest: *digest,
        lineage: lineage.clone(),
    }
    .into_envelope(valid_vertex.id().unwrap(), &m.set)
    .unwrap();
    let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
    // Proposal dependencies are retained by the authenticated session: only the new
    // carrier is supplied here. Recovery must preserve that authenticated history.
    adapter
        .receive_envelope(decoded, vec![valid_vertex])
        .unwrap();
    assert_eq!(adapter.driver.sequence(), sequence + 1);
    assert_eq!(format!("{:?}", adapter.signing_history()), history);
    recover_envelope_adapter(&mut adapter, &store, &bootstrap, &m, 0);
}

#[test]
fn identity_mismatch_precedes_wal_and_rejection_never_signs() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    assert!(Adapter::begin(&store, bootstrap.clone(), &m, 1).is_err());
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, .. } = request else {
        panic!("proposal")
    };
    assert!(
        adapter
            .apply(AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: vec![]
            })
            .is_err()
    );
    assert!(adapter.pending().is_empty());
    assert_eq!(adapter.driver.sequence(), 0);
}

#[test]
fn key_pair_mismatch_is_rejected_before_persistence() {
    let (mut m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    m.consensus[0].private_key[0] ^= 1;
    assert!(Adapter::begin(&store, bootstrap.clone(), &m, 0).is_err());
    // A valid constructor still succeeds: the failed identity check did not create a WAL.
    m.consensus[0].private_key[0] ^= 1;
    assert!(Adapter::begin(&store, bootstrap, &m, 0).is_ok());
}

#[test]
fn failed_durability_result_never_signs_and_requires_recovery() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap, &m, 0).unwrap();
    // Inject the result of an uncertain barrier at the adapter boundary, not a mock signer.
    let result = Err(StoreError::Io(std::io::Error::other(
        "injected sync uncertainty",
    )));
    assert!(adapter.consume_durable_result(result, None).is_err());
    assert!(adapter.pending().is_empty());
    assert_eq!(
        adapter.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    assert!(adapter.apply(request).is_err());
    assert_eq!(adapter.driver.sequence(), 0);
    let mut node = authoring_node(&m, &[]);
    assert!(adapter.author_pol([0; 32], &mut node).is_err());
    assert!(adapter.author_final_proof([0; 32], &mut node).is_err());
    assert_eq!((node.round(), node.authored()), (5, 0));
}

// Exercise both aggregate paths against the same complete quorum fixture.
fn check_aggregate_pre_sign_failures(
    adapter: &mut Adapter,
    m: &Membership,
    vertices: &[Vertex],
    round: u64,
    digest: [u8; 32],
    pol: bool,
) {
    let author = |adapter: &mut Adapter, node: &mut net::Node, digest| {
        if pol {
            adapter.author_pol(digest, node)
        } else {
            adapter.author_final_proof(digest, node)
        }
    };
    let history = format!("{:?}", adapter.pending());
    let sequence = adapter.driver.sequence();
    let mut occupied = authoring_node(m, vertices);
    let refs = vertices
        .iter()
        .filter(|v| v.round == round - 1)
        .map(|v| v.id().unwrap())
        .collect();
    let existing = signed(m, 0, round, refs, [42; 32]);
    occupied.receive(existing.clone()).unwrap();
    occupied.set_round(round);
    assert!(
        author(adapter, &mut occupied, digest).unwrap().is_none(),
        "occupied aggregate slot must not sign a conflicting carrier"
    );
    assert_eq!((occupied.round(), occupied.authored()), (round, 0));
    assert_eq!(occupied.dag().get(round, occupied.id()), Some(&existing));
    // Public preparation must reject occupancy too, not merely the Adapter wrapper.
    let output = adapter.driver.output().unwrap();
    for candidate in &output.candidates {
        match candidate {
            SlotAgreementCarrierCandidate::PendingPol(candidate)
                if pol && candidate.digest() == digest =>
            {
                assert!(
                    occupied
                        .prepare_slot_pol(candidate, &output.binding)
                        .is_err()
                )
            }
            SlotAgreementCarrierCandidate::PendingFinalProof(proof)
                if !pol && proof.digest(&m.set).unwrap() == digest =>
            {
                assert!(occupied.prepare_slot_final(proof, &output.binding).is_err())
            }
            _ => {}
        }
    }
    let mut missing = authoring_node(m, &[]);
    missing.set_round(round);
    assert!(author(adapter, &mut missing, digest).unwrap().is_none());
    assert_eq!((missing.round(), missing.authored()), (round, 0));
    // A foreign-chain sibling is accepted by legacy receive, but is not part of
    // the selected aggregate's witnesses. The prospective full cone must catch it.
    let refs = vertices
        .iter()
        .filter(|v| v.round == round - 2)
        .map(|v| v.id().unwrap())
        .collect();
    let sibling = signed_for_chain(m, 3, round - 1, refs, [42; 32], b"foreign-chain");
    let mut foreign = vertices.to_vec();
    foreign.retain(|v| !(v.round == round - 1 && v.author == m.consensus[3].id));
    foreign.push(sibling);
    let mut node = authoring_node(m, &foreign);
    node.set_round(round);
    assert!(author(adapter, &mut node, digest).unwrap().is_none());
    assert_eq!((node.round(), node.authored()), (round, 0));
    assert!(node.dag().get(round, node.id()).is_none());
    let mut wrong = authoring_node_index(m, vertices, 1);
    wrong.set_round(round);
    assert!(author(adapter, &mut wrong, digest).is_err());
    assert_eq!((wrong.round(), wrong.authored()), (round, 0));
    let mut pruned = authoring_node(m, vertices);
    pruned.set_round(round);
    pruned.set_floor(0);
    assert!(author(adapter, &mut pruned, digest).unwrap().is_none());
    assert_eq!((pruned.round(), pruned.authored()), (round, 0));
    for (chain, key) in [
        (b"wrong-chain".to_vec(), m.consensus[0].private_key.clone()),
        (
            b"live-adapter-tests".to_vec(),
            m.consensus[1].private_key.clone(),
        ),
    ] {
        let mut wrong =
            net::Node::with_chain_id(m.set.clone(), m.consensus[0].id.clone(), key, chain);
        wrong.set_round(round);
        assert!(author(adapter, &mut wrong, digest).is_err());
        assert_eq!((wrong.round(), wrong.authored()), (round, 0));
    }
    let mut wrong_epoch = net::Node::with_chain_id_and_epoch_length(
        m.set.clone(),
        1,
        m.consensus[0].id.clone(),
        m.consensus[0].private_key.clone(),
        b"live-adapter-tests".to_vec(),
    );
    wrong_epoch.set_round(round);
    assert!(author(adapter, &mut wrong_epoch, digest).is_err());
    assert_eq!((wrong_epoch.round(), wrong_epoch.authored()), (round, 0));
    let mut valid = authoring_node(m, vertices);
    valid.set_round(round);
    assert!(author(adapter, &mut valid, [255; 32]).unwrap().is_none());
    assert_eq!((valid.round(), valid.authored()), (round, 0));
    assert_eq!(adapter.driver.sequence(), sequence);
    assert_eq!(format!("{:?}", adapter.pending()), history);
}

#[test]
fn quorum_intents_use_existing_hashes_and_precommit_exact_pol_prerequisite() {
    let (m, bootstrap, request) = fixture();
    let dirs: Vec<_> = (0..3).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut adapters: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            let mut adapter = Adapter::begin(store, b, &m, i).unwrap();
            adapter.apply(request.clone()).unwrap();
            adapter
        })
        .collect();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        panic!("proposal")
    };
    let mut vote_vertices = Vec::new();
    let witnesses: Vec<_> = adapters
        .iter_mut()
        .enumerate()
        .map(|(i, a)| {
            let (payload, digest) = match &a.pending()[0] {
                PendingIntent::Vote {
                    payload, digest, ..
                } => (payload.clone(), *digest),
                _ => panic!("prevote"),
            };
            let (payload, digest) = (&payload, &digest);
            let before = payload.encode(&m.set).unwrap();
            assert_eq!(
                a.pending()[0].prerequisite_carriers().unwrap(),
                vec![payload.prerequisite.clone()]
            );
            assert_eq!(payload.encode(&m.set).unwrap(), before);
            assert_eq!(payload.digest(&m.set).unwrap(), *digest);
            let mut nil = payload.clone();
            nil.vote.value = AgreementValue::Nil;
            assert_eq!(
                PendingIntent::Vote {
                    payload: nil,
                    digest: *digest,
                    lineage: lineage.clone(),
                }
                .prerequisite_carriers(),
                Err(PrerequisiteExtractionError::UnsupportedNil)
            );
            let mut node = authoring_node_index(&m, &vertices, i);
            let id = a.signing_history()[0].id;
            let authored = a.author_vote(id, &mut node).unwrap().unwrap();
            authored
                .envelope
                .inspect(node.dag(), &a.driver.output().unwrap().binding)
                .unwrap();
            let v = authored.vertex;
            let carrier = v.id().unwrap();
            let envelope = PendingIntent::Vote {
                payload: payload.clone(),
                digest: *digest,
                lineage: lineage.clone(),
            }
            .into_envelope(carrier.clone(), &m.set)
            .unwrap();
            assert_eq!(
                envelope.payload(),
                &CarrierPayload::Vote {
                    payload: payload.clone(),
                    lineage: lineage.clone()
                }
            );
            check_envelope(&envelope, &m.set);
            let mut inspection_vertices = vertices.clone();
            inspection_vertices.push(v.clone());
            inspect_envelope(&envelope, &m, &bootstrap, &inspection_vertices, &lineage);
            let mut oversized = payload.clone();
            oversized
                .signature
                .signature
                .resize(MAX_ENVELOPE_BYTES + 1, 0);
            assert!(
                PendingIntent::Vote {
                    payload: oversized,
                    digest: *digest,
                    lineage: lineage.clone(),
                }
                .into_envelope(carrier.clone(), &m.set)
                .is_err()
            );
            // Structural construction must not be mistaken for signature verification.
            let mut unauthenticated = payload.clone();
            unauthenticated.signature.signature[0] ^= 1;
            assert!(
                unauthenticated
                    .verify(&payload.vote.context, &m.set)
                    .is_err()
            );
            let unauthenticated_digest = unauthenticated.digest(&m.set).unwrap();
            let constructed = PendingIntent::Vote {
                payload: unauthenticated,
                digest: unauthenticated_digest,
                lineage: lineage.clone(),
            }
            .into_envelope(carrier.clone(), &m.set)
            .unwrap();
            assert!(CarrierEnvelope::decode(&constructed.encode(&m.set).unwrap(), &m.set).is_ok());
            assert!(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: [0; 32],
                    lineage: lineage.clone(),
                }
                .into_envelope(carrier.clone(), &m.set)
                .is_err()
            );
            let mut wrong_author = carrier.clone();
            wrong_author.author = b"not-the-voter".to_vec();
            assert!(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: *digest,
                    lineage: lineage.clone(),
                }
                .into_envelope(wrong_author, &m.set)
                .is_err()
            );
            let mut nil = payload.clone();
            nil.vote.value = AgreementValue::Nil;
            assert!(
                PendingIntent::Vote {
                    payload: nil,
                    digest: *digest,
                    lineage: lineage.clone(),
                }
                .into_envelope(carrier.clone(), &m.set)
                .is_err()
            );
            let witness = validator::SlotAgreementVoteWitness {
                payload: payload.clone(),
                carrier,
            };
            vote_vertices.push(v);
            witness
        })
        .collect();
    for (i, adapter) in adapters.iter_mut().enumerate() {
        for (n, witness) in witnesses.iter().enumerate() {
            let envelope = PendingIntent::Vote {
                payload: witness.payload.clone(),
                digest: witness.payload.digest(&m.set).unwrap(),
                lineage: lineage.clone(),
            }
            .into_envelope(witness.carrier.clone(), &m.set)
            .unwrap();
            let decoded =
                CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
            adapter
                .receive_envelope(decoded, vote_vertices.clone())
                .unwrap();
            assert_eq!(
                adapter.signing_history().len(),
                1,
                "observing votes does not create local signing intent"
            );
            recover_envelope_adapter(adapter, &stores[i], &bootstrap, &m, i);
            if n < 2 {
                assert!(
                    !adapter
                        .pending()
                        .iter()
                        .any(|p| matches!(p, PendingIntent::Pol { .. }))
                );
            } else {
                assert!(
                    adapter
                        .pending()
                        .iter()
                        .any(|p| matches!(p, PendingIntent::Pol { .. })),
                    "replayed vote bucket reaches quorum"
                );
            }
        }
    }
    let (candidate, pol_digest) = adapters[0]
        .pending()
        .iter()
        .find_map(|intent| match intent {
            PendingIntent::Pol { candidate, digest } => Some((candidate.clone(), *digest)),
            _ => None,
        })
        .expect("quorum emits POL intent");
    assert_eq!(pol_digest, candidate.digest());
    let before = candidate.clone();
    let mut expected = vec![lineage.entries.last().unwrap().view_carrier.clone()];
    expected.extend(witnesses.iter().map(|w| w.carrier.clone()));
    expected.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    expected.dedup();
    assert_eq!(
        expected.len(),
        4,
        "all three prevote witnesses plus selected view"
    );
    assert_eq!(candidate.prerequisite_carriers(), expected);
    assert_eq!(
        PendingIntent::Pol {
            candidate: candidate.clone(),
            digest: pol_digest
        }
        .prerequisite_carriers()
        .unwrap(),
        expected
    );
    assert_eq!(candidate, before);
    assert_eq!(candidate.digest(), pol_digest);
    let refs: Vec<_> = vote_vertices.iter().map(|v| v.id().unwrap()).collect();
    let pol_vertices: Vec<_> = (0..4)
        .map(|i| signed(&m, i, 6, refs.clone(), pol_digest))
        .collect();
    let mut pol_node_vertices = vertices.clone();
    pol_node_vertices.extend(vote_vertices.clone());
    let mut pol_node = authoring_node(&m, &pol_node_vertices);
    pol_node.set_round(6);
    check_aggregate_pre_sign_failures(
        &mut adapters[0],
        &m,
        &pol_node_vertices,
        6,
        pol_digest,
        true,
    );
    let binding = adapters[0].driver.output().unwrap().binding;
    let prepared = pol_node.prepare_slot_pol(&candidate, &binding).unwrap();
    let unsigned = prepared.unsigned().clone();
    adapters[0]
        .reserve_carrier(
            &unsigned,
            store::AgreementCarrierEvidence::Pol {
                lineage: candidate.clone().bind_carrier(unsigned.id().unwrap()),
            },
            prepared.dag(),
        )
        .unwrap();
    drop(prepared);
    assert_eq!((pol_node.round(), pol_node.authored()), (6, 0));
    assert!(
        adapters[0]
            .driver
            .reserved_carriers()
            .unwrap()
            .iter()
            .any(|r| r.unsigned == unsigned)
    );
    let sequence = adapters[0].driver.sequence();
    // Replace the owner with a recovered session before invoking the outer signer.
    let recovered = Adapter::recover(&stores[0], bootstrap.clone(), &m, 0).unwrap();
    adapters[0] = recovered;
    let mut fresh_pol_node = authoring_node_index(&m, &pol_node_vertices, 1);
    fresh_pol_node.set_round(6);
    let fresh_pol = adapters[1]
        .author_pol(pol_digest, &mut fresh_pol_node)
        .unwrap()
        .unwrap();
    assert!(
        adapters[1]
            .driver
            .reserved_carriers()
            .unwrap()
            .iter()
            .any(|r| r.id == fresh_pol.vertex.id().unwrap())
    );
    let authored_pol = adapters[0]
        .author_pol(pol_digest, &mut pol_node)
        .unwrap()
        .unwrap();
    assert_eq!(adapters[0].driver.sequence(), sequence + 1);
    assert_eq!(authored_pol.vertex.id().unwrap(), unsigned.id().unwrap());
    assert_eq!(authored_pol.vertex, pol_vertices[0]);
    authored_pol
        .envelope
        .inspect(pol_node.dag(), &binding)
        .unwrap();
    assert_eq!((pol_node.round(), pol_node.authored()), (7, 1));
    let pol_carrier = pol_vertices[0].id().unwrap();
    let envelope = PendingIntent::Pol {
        candidate: candidate.clone(),
        digest: pol_digest,
    }
    .into_envelope(pol_carrier.clone(), &m.set)
    .unwrap();
    check_envelope(&envelope, &m.set);
    assert_eq!(envelope.payload_digest(), pol_digest);
    assert!(
        PendingIntent::Pol {
            candidate: candidate.clone(),
            digest: [0; 32]
        }
        .into_envelope(pol_carrier.clone(), &m.set)
        .is_err()
    );
    let lineage = candidate.bind_carrier(pol_carrier.clone());
    assert_eq!(envelope.payload(), &CarrierPayload::Pol(lineage.clone()));
    assert_eq!(lineage.pol_digest(0, &m.set).unwrap(), pol_digest);
    assert_eq!(
        before
            .bound_lineage_len(&pol_carrier.author, &m.set)
            .unwrap(),
        lineage.encode(&m.set).unwrap().len()
    );
    let mut inspection_vertices = vertices.clone();
    inspection_vertices.extend(vote_vertices.clone());
    inspection_vertices.extend(pol_vertices.clone());
    inspect_envelope(&envelope, &m, &bootstrap, &inspection_vertices, &lineage);
    let mut incoming = vote_vertices;
    incoming.extend(pol_vertices.clone());
    for (i, adapter) in adapters.iter_mut().enumerate() {
        let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
        adapter.receive_envelope(decoded, incoming.clone()).unwrap();
        assert_eq!(
            adapter.signing_history().len(),
            2,
            "POL durably emits local precommit"
        );
        recover_envelope_adapter(adapter, &stores[i], &bootstrap, &m, i);
    }
    let mut actual_node = authoring_node(&m, &inspection_vertices);
    actual_node.set_round(7);
    let stale_prevote = adapters[0].signing_history()[0].id;
    assert!(
        adapters[0]
            .author_vote(stale_prevote, &mut actual_node)
            .unwrap()
            .is_none()
    );
    let precommit_id = adapters[0].signing_history()[1].id;
    let authored = adapters[0]
        .author_vote(precommit_id, &mut actual_node)
        .unwrap()
        .unwrap();
    authored
        .envelope
        .inspect(
            actual_node.dag(),
            &adapters[0].driver.output().unwrap().binding,
        )
        .unwrap();
    assert_eq!((actual_node.round(), actual_node.authored()), (8, 1));
    let refs: Vec<_> = pol_vertices.iter().map(|v| v.id().unwrap()).collect();
    let mut precommit_vertices = Vec::new();
    let witnesses: Vec<_> = adapters
        .iter_mut()
        .enumerate()
        .map(|(i, a)| {
            let (payload, digest) = a
                .pending()
                .iter()
                .find_map(|intent| match intent {
                    PendingIntent::Vote {
                        payload, digest, ..
                    } if payload.vote.phase
                        == validator::slot_agreement::AgreementPhase::Precommit =>
                    {
                        Some((payload.clone(), *digest))
                    }
                    _ => None,
                })
                .expect("durable precommit");
            let (payload, digest) = (&payload, &digest);
            assert_eq!(payload.prerequisite, pol_carrier);
            assert_eq!(
                PendingIntent::Vote {
                    payload: payload.clone(),
                    digest: *digest,
                    lineage: lineage.clone(),
                }
                .prerequisite_carriers()
                .unwrap(),
                vec![pol_carrier.clone()]
            );
            assert_eq!(
                payload.signature.signature,
                Ed25519Scheme
                    .sign(
                        &m.consensus[i].private_key,
                        &payload.vote.signing_payload(&m.set).unwrap()
                    )
                    .unwrap()
            );
            let mut node = authoring_node_index(&m, &inspection_vertices, i);
            node.set_round(7);
            let id = a.signing_history()[1].id;
            let authored = a.author_vote(id, &mut node).unwrap().unwrap();
            authored
                .envelope
                .inspect(node.dag(), &a.driver.output().unwrap().binding)
                .unwrap();
            let v = authored.vertex;
            assert_eq!(v, signed(&m, i, 7, refs.clone(), *digest));
            let witness = validator::SlotAgreementVoteWitness {
                payload: payload.clone(),
                carrier: v.id().unwrap(),
            };
            precommit_vertices.push(v);
            witness
        })
        .collect();
    for (i, adapter) in adapters.iter_mut().enumerate() {
        let expected: Vec<_> = adapter
            .pending()
            .iter()
            .filter_map(|p| match p {
                PendingIntent::Vote { payload, .. } => Some(payload.clone()),
                _ => None,
            })
            .collect();
        let mut b = bootstrap.clone();
        b.agreement.local_validator = m.consensus[i].id.clone();
        let recovered = Adapter::recover(&stores[i], b, &m, i).unwrap();
        let actual: Vec<_> = recovered
            .pending()
            .iter()
            .filter_map(|p| match p {
                PendingIntent::Vote { payload, .. } => Some(payload.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(
            actual, expected,
            "restart preserves prevote and locked precommit"
        );
        *adapter = recovered;
    }
    // A real authenticated nonnil precommit and pending POL must not gate the timer.
    // Keep adapters 0/1 on the final-proof path; adapter 2 exercises local advancement.
    {
        use pacemaker::{Action, Policy};
        use std::time::{Duration, Instant};
        let adapter = &mut adapters[2];
        let reproposal = adapter.driver.output().unwrap().reproposal;
        assert!(reproposal.is_some());
        assert!(
            adapter
                .pending()
                .iter()
                .any(|p| matches!(p, PendingIntent::Pol { .. }))
        );
        let retained_votes = |adapter: &Adapter| {
            adapter
                .signing_history()
                .iter()
                .map(|i| (i.id, i.vote.clone()))
                .collect::<Vec<_>>()
        };
        let history = retained_votes(adapter);
        assert_ne!(history[1].1.value, AgreementValue::Nil);
        let wait = Duration::from_secs(1);
        let now = Instant::now();
        adapter.configure_pacemaker(Policy::new(wait, wait, wait).unwrap());
        assert_eq!(adapter.tick(now).unwrap(), None);
        assert_eq!(
            adapter.tick(now + wait).unwrap(),
            Some(Action::AdvanceView {
                from: AgreementView(0)
            })
        );
        assert_eq!(retained_votes(adapter), history);
        assert_eq!(adapter.driver.output().unwrap().reproposal, reproposal);
        recover_envelope_adapter(adapter, &stores[2], &bootstrap, &m, 2);
        assert_eq!(adapter.timer_snapshot().unwrap().view, AgreementView(1));
        assert_eq!(adapter.driver.output().unwrap().reproposal, reproposal);
        assert_eq!(retained_votes(adapter), history);
        assert_eq!(adapter.tick(now + wait * 100).unwrap(), None);
    }
    for witness in &witnesses {
        let envelope = PendingIntent::Vote {
            payload: witness.payload.clone(),
            digest: witness.payload.digest(&m.set).unwrap(),
            lineage: lineage.clone(),
        }
        .into_envelope(witness.carrier.clone(), &m.set)
        .unwrap();
        let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
        adapters[1]
            .receive_envelope(decoded.clone(), precommit_vertices.clone())
            .unwrap();
        adapters[0]
            .receive_envelope(decoded, precommit_vertices.clone())
            .unwrap();
        recover_envelope_adapter(&mut adapters[0], &stores[0], &bootstrap, &m, 0);
    }
    let pending = adapters[0].pending();
    assert_eq!(
        pending
            .iter()
            .filter(|p| matches!(p, PendingIntent::Pol { .. }))
            .count(),
        1,
        "snapshots must not enqueue the same POL again"
    );
    let (proof, digest) = pending
        .iter()
        .find_map(|p| match p {
            PendingIntent::FinalProof { proof, digest } => Some((proof, digest)),
            _ => None,
        })
        .expect("final proof intent");
    let (proof, digest) = (proof.clone(), *digest);
    let (proof, digest) = (&proof, &digest);
    let mut final_node_vertices = inspection_vertices.clone();
    final_node_vertices.extend(precommit_vertices.clone());
    check_aggregate_pre_sign_failures(
        &mut adapters[0],
        &m,
        &final_node_vertices,
        8,
        *digest,
        false,
    );
    let mut final_node = authoring_node(&m, &final_node_vertices);
    final_node.set_round(8);
    let mut invalid_proof = proof.clone();
    invalid_proof.certificate.signatures[0].signature[0] ^= 1;
    invalid_proof.votes[0].payload.signature.signature[0] ^= 1;
    // Matching malformed signatures pass structural encoding, not authentication.
    invalid_proof.encode(&m.set).unwrap();
    assert!(
        final_node
            .prepare_slot_final(
                &invalid_proof,
                &adapters[0].driver.output().unwrap().binding
            )
            .is_err()
    );
    assert_eq!((final_node.round(), final_node.authored()), (8, 0));
    let binding = adapters[0].driver.output().unwrap().binding;
    let prepared = final_node.prepare_slot_final(proof, &binding).unwrap();
    let unsigned = prepared.unsigned().clone();
    adapters[0]
        .reserve_carrier(
            &unsigned,
            store::AgreementCarrierEvidence::Final {
                proof: proof.clone(),
            },
            prepared.dag(),
        )
        .unwrap();
    drop(prepared);
    assert_eq!((final_node.round(), final_node.authored()), (8, 0));
    assert!(
        adapters[0]
            .driver
            .reserved_carriers()
            .unwrap()
            .iter()
            .any(|r| r.unsigned == unsigned)
    );
    let sequence = adapters[0].driver.sequence();
    let recovered = Adapter::recover(&stores[0], bootstrap.clone(), &m, 0).unwrap();
    adapters[0] = recovered;
    let mut fresh_final_node = authoring_node_index(&m, &final_node_vertices, 1);
    fresh_final_node.set_round(8);
    let fresh_final = adapters[1]
        .author_final_proof(*digest, &mut fresh_final_node)
        .unwrap()
        .unwrap();
    assert!(
        adapters[1]
            .driver
            .reserved_carriers()
            .unwrap()
            .iter()
            .any(|r| r.id == fresh_final.vertex.id().unwrap())
    );
    let authored_final = adapters[0]
        .author_final_proof(*digest, &mut final_node)
        .unwrap()
        .unwrap();
    assert_eq!(adapters[0].driver.sequence(), sequence + 1);
    assert_eq!(authored_final.vertex.id().unwrap(), unsigned.id().unwrap());
    authored_final
        .envelope
        .inspect(final_node.dag(), &binding)
        .unwrap();
    assert_eq!((final_node.round(), final_node.authored()), (9, 1));
    let before = proof.encode(&m.set).unwrap();
    let mut expected = vec![pol_carrier];
    expected.extend(witnesses.iter().map(|w| w.carrier.clone()));
    expected.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
    expected.dedup();
    assert_eq!(
        expected.len(),
        4,
        "all three precommit witnesses plus selected POL"
    );
    let intent = PendingIntent::FinalProof {
        proof: proof.clone(),
        digest: *digest,
    };
    assert_eq!(intent.prerequisite_carriers().unwrap(), expected);
    let refs = precommit_vertices.iter().map(|v| v.id().unwrap()).collect();
    let final_vertex = signed(&m, 0, 8, refs, *digest);
    assert_eq!(authored_final.vertex, final_vertex);
    let final_carrier = final_vertex.id().unwrap();
    let envelope = intent.into_envelope(final_carrier.clone(), &m.set).unwrap();
    assert_eq!(envelope.payload(), &CarrierPayload::Final(proof.clone()));
    assert_eq!(envelope.payload_digest(), *digest);
    check_envelope(&envelope, &m.set);
    inspection_vertices.extend(precommit_vertices.clone());
    inspection_vertices.push(final_vertex);
    inspect_envelope(&envelope, &m, &bootstrap, &inspection_vertices, &lineage);
    for witness in &witnesses {
        let vote = PendingIntent::Vote {
            payload: witness.payload.clone(),
            digest: witness.payload.digest(&m.set).unwrap(),
            lineage: lineage.clone(),
        }
        .into_envelope(witness.carrier.clone(), &m.set)
        .unwrap();
        check_envelope(&vote, &m.set);
        inspect_envelope(&vote, &m, &bootstrap, &inspection_vertices, &lineage);
    }
    assert!(
        PendingIntent::FinalProof {
            proof: proof.clone(),
            digest: [0; 32]
        }
        .into_envelope(final_carrier, &m.set)
        .is_err()
    );
    // Untrusted duplicate entries cannot duplicate a readiness requirement.
    let mut duplicate = proof.clone();
    duplicate.votes.push(duplicate.votes[0].clone());
    assert_eq!(
        PendingIntent::FinalProof {
            proof: duplicate,
            digest: *digest
        }
        .prerequisite_carriers()
        .unwrap(),
        expected
    );
    let mut missing = proof.clone();
    missing.entries.clear();
    assert_eq!(
        PendingIntent::FinalProof {
            proof: missing,
            digest: *digest
        }
        .prerequisite_carriers(),
        Err(PrerequisiteExtractionError::MissingSelectedPol)
    );
    assert_eq!(proof.encode(&m.set).unwrap(), before);
    assert_eq!(*digest, proof.digest(&m.set).unwrap());
    // Enter only after authoring the final carrier: an authenticated lower-view
    // commit must still decide, and its slot's entry certificate remains exportable.
    let first = adapters[0].author_view_request(AgreementView(98)).unwrap();
    let second = adapters[1].author_view_request(AgreementView(98)).unwrap();
    adapters[2].author_view_request(AgreementView(97)).unwrap();
    adapters[2].receive_view_request(first).unwrap();
    adapters[2].receive_view_request(second).unwrap();
    assert_eq!(
        adapters[2]
            .echo_view_request()
            .unwrap()
            .unwrap()
            .target_view(),
        AgreementView(98)
    );
    recover_envelope_adapter(&mut adapters[2], &stores[2], &bootstrap, &m, 2);
    let entry_certificate = adapters[2].entered_view_certificate().unwrap().unwrap();
    adapters[0]
        .receive_view_certificate(entry_certificate.clone())
        .unwrap();
    assert_eq!(
        adapters[0].entered_view_certificate().unwrap(),
        Some(entry_certificate.clone())
    );
    // Arm before receipt so the actual durable decision must cancel elapsed scheduling.
    let timer_now = std::time::Instant::now();
    let timer_wait = std::time::Duration::from_secs(1);
    adapters[0]
        .configure_pacemaker(pacemaker::Policy::new(timer_wait, timer_wait, timer_wait).unwrap());
    assert_eq!(adapters[0].tick(timer_now).unwrap(), None);
    // Final receipt is durable protocol observation, not chain application.
    let receipt_state = exposed_receipt_state(&stores[0], &bootstrap);
    let history = format!("{:?}", adapters[0].signing_history());
    let sequence = adapters[0].driver.sequence();
    let decoded = CarrierEnvelope::decode(&envelope.encode(&m.set).unwrap(), &m.set).unwrap();
    adapters[0]
        .receive_envelope(decoded, inspection_vertices)
        .unwrap();
    assert_eq!(exposed_receipt_state(&stores[0], &bootstrap), receipt_state);
    assert_eq!(adapters[0].driver.sequence(), sequence + 1);
    assert_eq!(
        adapters[0].tick(timer_now + timer_wait * 100).unwrap(),
        None
    );
    assert_eq!(
        adapters[0].tick(timer_now + timer_wait * 101).unwrap(),
        None
    );
    assert_eq!(adapters[0].driver.sequence(), sequence + 1);
    assert_eq!(format!("{:?}", adapters[0].signing_history()), history);
    assert!(
        adapters[0]
            .driver
            .output()
            .unwrap()
            .transition
            .unwrap()
            .decision
            .is_some()
    );
    // Advisory scheduling cannot reopen a decided slot, even with a real quorum.
    let mut requests: Vec<_> = (0..3)
        .map(|i| {
            let bytes = validator::SlotAgreementViewRequest::signing_payload(
                &bootstrap.agreement.context,
                AgreementView(99),
                &m.set,
            )
            .unwrap();
            validator::SlotAgreementViewRequest::new(
                bootstrap.agreement.context.clone(),
                AgreementView(99),
                ValidatorSignature {
                    validator_id: m.consensus[i].id.clone(),
                    key_id: m.set.validators[i].keys[0].key_id.clone(),
                    signature: Ed25519Scheme
                        .sign(&m.consensus[i].private_key, &bytes)
                        .unwrap(),
                },
                &m.set,
            )
            .unwrap()
        })
        .collect();
    requests.sort_by(|a, b| a.signature().validator_id.cmp(&b.signature().validator_id));
    let decided_sequence = adapters[0].driver.sequence();
    assert!(adapters[0].author_view_request(AgreementView(99)).is_err());
    let decided_readiness = adapters[0].readiness();
    let decided_transition = format!("{:?}", adapters[0].driver.output().unwrap().transition);
    adapters[0]
        .receive_view_certificate(requests.clone())
        .unwrap();
    adapters[0]
        .receive_view_certificate(entry_certificate.clone())
        .unwrap();
    let mut forged = requests.clone();
    let mut signature = forged[0].signature().clone();
    signature.signature[0] ^= 1;
    forged[0] = validator::SlotAgreementViewRequest::new(
        forged[0].context().clone(),
        forged[0].target_view(),
        signature,
        &m.set,
    )
    .unwrap();
    let mut duplicate = requests.clone();
    duplicate[1] = duplicate[0].clone();
    for malformed in [forged, duplicate, Vec::new()] {
        assert!(adapters[0].receive_view_certificate(malformed).is_err());
        assert_eq!(adapters[0].driver.sequence(), decided_sequence);
    }
    assert_eq!(
        adapters[0].entered_view_certificate().unwrap(),
        Some(entry_certificate.clone())
    );
    for request in &requests {
        adapters[0].receive_view_request(request.clone()).unwrap();
    }
    assert_eq!(adapters[0].readiness(), decided_readiness);
    assert_eq!(
        format!("{:?}", adapters[0].driver.output().unwrap().transition),
        decided_transition
    );
    assert_eq!(format!("{:?}", adapters[0].signing_history()), history);
    assert_eq!(adapters[0].driver.sequence(), decided_sequence);
    assert!(
        adapters[0]
            .driver
            .apply(
                decided_sequence + 1,
                AuthenticatedSlotAgreementRequest::EnterRequestedView { requests }
            )
            .is_err()
    );
    assert_eq!(adapters[0].driver.sequence(), decided_sequence);
    // The cache still contains historical aggregate material, but fresh driver
    // output has no candidates after final receipt.
    assert!(
        adapters[0]
            .pending()
            .iter()
            .any(|p| matches!(p, PendingIntent::FinalProof { .. }))
    );
    assert!(
        adapters[0]
            .author_final_proof(*digest, &mut final_node)
            .unwrap()
            .is_none()
    );
    recover_envelope_adapter(&mut adapters[0], &stores[0], &bootstrap, &m, 0);
    assert_eq!(exposed_receipt_state(&stores[0], &bootstrap), receipt_state);
    assert!(adapters[0].driver.output().unwrap().candidates.is_empty());
    assert!(
        adapters[0]
            .author_pol(pol_digest, &mut pol_node)
            .unwrap()
            .is_none()
    );
    assert!(
        adapters[0]
            .author_final_proof(*digest, &mut final_node)
            .unwrap()
            .is_none()
    );
    assert_eq!((pol_node.round(), pol_node.authored()), (7, 1));
    assert_eq!((final_node.round(), final_node.authored()), (9, 1));
    for id in [stale_prevote, precommit_id] {
        assert!(
            adapters[0]
                .author_vote(id, &mut actual_node)
                .unwrap()
                .is_none()
        );
    }
    let publication_bytes = |adapter: &mut Adapter| {
        adapter
            .completed_carriers()
            .unwrap()
            .into_iter()
            .map(|publication| {
                (
                    publication.vertex.encode().unwrap(),
                    publication.envelope.encode(&m.set).unwrap(),
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(
        adapters[0].entered_view_certificate().unwrap(),
        Some(entry_certificate.clone())
    );
    let before_advance = publication_bytes(&mut adapters[0]);
    let old_requests = adapters[0].completed_view_requests().unwrap();
    assert!(!old_requests.is_empty());
    let retry_now = std::time::Instant::now();
    let retry_interval = std::time::Duration::from_secs(1);
    adapters[0]
        .configure_retransmission(retry_interval)
        .unwrap();
    assert!(matches!(
        adapters[0].retransmit(retry_now).unwrap(),
        Some(net::wire::Message::AgreementViewRequest(_))
    ));
    assert!(matches!(
        adapters[0].retransmit(retry_now + retry_interval).unwrap(),
        Some(net::wire::Message::AgreementViewCertificate(_))
    ));
    assert!(
        before_advance.len() >= 3,
        "vote, POL and FINAL completions persisted"
    );
    adapters[0]
        .apply(AuthenticatedSlotAgreementRequest::AdvanceSlot)
        .unwrap();
    assert_eq!(publication_bytes(&mut adapters[0]), before_advance);
    assert_eq!(adapters[0].completed_view_requests().unwrap(), old_requests);
    assert!(adapters[0].entered_view_certificate().unwrap().is_none());
    let advanced_wal = dirs[0].0.join("authenticated-slot-agreement");
    let advanced_bytes = std::fs::read(&advanced_wal).unwrap();
    assert_eq!(
        adapters[0]
            .retransmit(retry_now + retry_interval * 2)
            .unwrap(),
        None,
        "durable requests and certificate from the decided old slot must not escape"
    );
    assert_eq!(std::fs::read(&advanced_wal).unwrap(), advanced_bytes);
    let advanced_sequence = adapters[0].driver.sequence();
    assert!(
        adapters[0]
            .receive_view_certificate(entry_certificate.clone())
            .is_err()
    );
    assert_eq!(adapters[0].driver.sequence(), advanced_sequence);
    recover_envelope_adapter(&mut adapters[0], &stores[0], &bootstrap, &m, 0);
    assert_eq!(publication_bytes(&mut adapters[0]), before_advance);
    assert!(adapters[0].entered_view_certificate().unwrap().is_none());
    assert!(
        adapters[0]
            .receive_view_certificate(entry_certificate)
            .is_err()
    );
    assert_eq!(adapters[0].driver.sequence(), advanced_sequence);

    for id in [stale_prevote, precommit_id] {
        assert!(
            adapters[0]
                .author_vote(id, &mut actual_node)
                .unwrap()
                .is_none()
        );
    }
    assert_eq!((actual_node.round(), actual_node.authored()), (8, 1));
    assert_eq!(
        adapters[0].pending().len(),
        2,
        "recovery retains signing obligations, not stale carrier candidates"
    );
    assert_eq!(
        adapters[0].readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
    // A view advance must not make historical POL cache entries authorable.
    adapters[1]
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert!(
        adapters[1]
            .pending()
            .iter()
            .any(|p| matches!(p, PendingIntent::Pol { .. }))
    );
    let mut old_pol_node = authoring_node_index(&m, &pol_node_vertices, 1);
    old_pol_node.set_round(6);
    assert!(
        adapters[1]
            .author_pol(pol_digest, &mut old_pol_node)
            .unwrap()
            .is_none()
    );
    assert_eq!((old_pol_node.round(), old_pol_node.authored()), (6, 0));
    let sequence = adapters[0].driver.sequence();
    let mut new_owner = Adapter::recover(&stores[0], bootstrap.clone(), &m, 0).unwrap();
    new_owner
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert!(adapters[0].author_pol(pol_digest, &mut pol_node).is_err());
    assert!(
        adapters[0]
            .author_final_proof(*digest, &mut final_node)
            .is_err()
    );
    assert_eq!(adapters[0].driver.sequence(), sequence);
    assert_eq!((pol_node.round(), pol_node.authored()), (7, 1));
    assert_eq!((final_node.round(), final_node.authored()), (9, 1));
}

#[derive(Clone, Copy)]
enum LockPreservingViewEntry {
    Timed,
    Certified,
}

#[test]
fn timed_advance_and_recovery_preserve_lock_against_authenticated_conflict() {
    advance_and_recovery_preserve_lock_against_authenticated_conflict(
        LockPreservingViewEntry::Timed,
    );
}

#[test]
fn certified_advance_and_recovery_preserve_lock_against_authenticated_conflict() {
    advance_and_recovery_preserve_lock_against_authenticated_conflict(
        LockPreservingViewEntry::Certified,
    );
}

fn advance_and_recovery_preserve_lock_against_authenticated_conflict(
    entry: LockPreservingViewEntry,
) {
    use pacemaker::{Action, Policy};
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    use validator::{SlotAgreementViewCandidate, SlotProposalEnvelope, SlotProposalEvidence};

    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose {
        lineage,
        mut vertices,
    } = request
    else {
        unreachable!()
    };
    let mut commit = lineage.entries[0].proposal.clone();
    let SlotOutcome::Commit { leader } = &commit.decision.outcome else {
        unreachable!()
    };
    let target = leader.clone();
    vertices.retain(|v| v.round <= 1);
    let ids = |vertices: &[Vertex], round| {
        let mut ids = vertices
            .iter()
            .filter(|v| v.round == round)
            .map(|v| v.id().unwrap())
            .collect::<Vec<_>>();
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        ids
    };
    // Only one direct supporter: indirect commit and conservative skip are both valid.
    let refs = ids(&vertices, 1);
    for author in 0..4 {
        let references = refs
            .iter()
            .filter(|id| author == 0 || **id != target)
            .cloned()
            .collect();
        vertices.push(signed(&m, author, 2, references, [2; 32]));
    }
    for round in 3..=4 {
        let refs = ids(&vertices, round - 1);
        for author in 0..4 {
            vertices.push(signed(&m, author, round, refs.clone(), [42; 32]));
        }
    }
    let mut dag = Dag::new(m.set.clone());
    dag.set_chain_id(b"live-adapter-tests".to_vec());
    for vertex in &vertices {
        dag.insert(vertex.clone()).unwrap();
    }
    commit.evidence = SlotProposalEvidence::IndirectCommit {
        anchor: dag.leader(3).unwrap().id().unwrap(),
        support: ids(&vertices, 4)[..3].to_vec(),
    };
    let voters = ids(&vertices, 2);
    let fence = validator::Fence::new(b"live-adapter-tests".to_vec(), 2, voters[3].author.clone());
    let bytes = fence.signing_payload().unwrap();
    let fence = validator::FenceCertificate {
        fence,
        signer_bitmap: vec![0b111],
        signatures: (0..3)
            .map(|i| {
                Ed25519Scheme
                    .sign(&m.consensus[i].private_key, &bytes)
                    .unwrap()
            })
            .collect(),
    };
    let mut decision = commit.decision.clone();
    decision.outcome = SlotOutcome::Skip {
        leader_author: target.author,
    };
    decision.after_len = decision.before_len;
    decision.after_root = decision.before_root;
    let skip = SlotProposalEnvelope {
        decision,
        evidence: SlotProposalEvidence::ConservativeSkip {
            voters: voters[..3].to_vec(),
            missing: vec![voters[3].author.clone()],
            fences: vec![fence],
        },
    };
    assert_ne!(commit.decision, skip.decision);
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut adapters: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            Adapter::begin(store, b, &m, i).unwrap()
        })
        .collect();
    let mut carriers = Vec::new();
    for (i, adapter) in adapters.iter_mut().enumerate() {
        let mut node = authoring_node_index(&m, &vertices, i);
        node.set_round(5);
        let vertex = if i < 2 {
            adapter
                .author_proposal(if i == 0 { &commit } else { &skip }, &mut node)
                .unwrap()
                .unwrap()
                .vertex
        } else {
            signed(&m, i, 5, ids(&vertices, 4), [42; 32])
        };
        carriers.push(vertex.id().unwrap());
        vertices.push(vertex);
    }
    let proposer_index = |view| {
        let elected = validator::slot_agreement_view_proposer(&m.set, 1, view).unwrap();
        m.consensus.iter().position(|id| id.id == elected).unwrap()
    };
    let candidate = SlotAgreementViewCandidate::new(
        vec![],
        commit.clone(),
        carriers[0].clone(),
        AgreementView(0),
        &m.set,
    )
    .unwrap();
    let elected = proposer_index(AgreementView(0));
    let mut node = authoring_node_index(&m, &vertices, elected);
    node.set_round(6);
    let view = adapters[elected]
        .author_view(&candidate, &mut node)
        .unwrap()
        .unwrap();
    vertices.push(view.vertex.clone());
    for i in 0..4 {
        if i != elected {
            vertices.push(signed(&m, i, 6, ids(&vertices, 5), [42; 32]));
        }
    }
    for adapter in &mut adapters[..3] {
        adapter
            .receive_envelope(view.envelope.clone(), vertices.clone())
            .unwrap();
    }
    let mut votes = Vec::new();
    for (i, adapter) in adapters[..3].iter_mut().enumerate() {
        let mut node = authoring_node_index(&m, &vertices, i);
        node.set_round(7);
        let id = adapter.signing_history()[0].id;
        votes.push(adapter.author_vote(id, &mut node).unwrap().unwrap());
    }
    vertices.extend(votes.iter().map(|v| v.vertex.clone()));
    vertices.push(signed(&m, 3, 7, ids(&vertices, 6), [42; 32]));
    for adapter in &mut adapters[..3] {
        for vote in &votes {
            adapter
                .receive_envelope(vote.envelope.clone(), vertices.clone())
                .unwrap();
        }
    }
    let pol_digest = adapters[0]
        .pending()
        .iter()
        .find_map(|p| match p {
            PendingIntent::Pol { digest, .. } => Some(*digest),
            _ => None,
        })
        .unwrap();
    let mut node = authoring_node_index(&m, &vertices, 0);
    node.set_round(8);
    let pol = adapters[0]
        .author_pol(pol_digest, &mut node)
        .unwrap()
        .unwrap();
    vertices.push(pol.vertex.clone());
    for i in 1..4 {
        vertices.push(signed(&m, i, 8, ids(&vertices, 7), [42; 32]));
    }
    let adapter = &mut adapters[2];
    adapter
        .receive_envelope(pol.envelope, vertices.clone())
        .unwrap();
    let history = adapter
        .signing_history()
        .iter()
        .map(|i| (i.id, i.vote.clone()))
        .collect::<Vec<_>>();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].1.phase, AgreementPhase::Precommit);
    assert_eq!(
        history[1].1.value,
        AgreementValue::Decision(commit.decision.clone())
    );
    let mut node = authoring_node_index(&m, &vertices, 2);
    node.set_round(9);
    let precommit = adapter
        .author_vote(history[1].0, &mut node)
        .unwrap()
        .unwrap();
    precommit
        .envelope
        .inspect(node.dag(), &adapter.driver.output().unwrap().binding)
        .unwrap();
    vertices.push(precommit.vertex);
    for i in [0, 1, 3] {
        vertices.push(signed(&m, i, 9, ids(&vertices, 8), [42; 32]));
    }
    let reproposal = adapter.driver.output().unwrap().reproposal.unwrap();
    match entry {
        LockPreservingViewEntry::Timed => {
            let wait = Duration::from_secs(1);
            let now = Instant::now();
            adapter.configure_pacemaker(Policy::new(wait, wait, wait).unwrap());
            assert_eq!(adapter.tick(now).unwrap(), None);
            assert_eq!(
                adapter.tick(now + wait).unwrap(),
                Some(Action::AdvanceView {
                    from: AgreementView(0)
                })
            );
        }
        LockPreservingViewEntry::Certified => {
            let requests: Vec<_> = [0, 1, 3]
                .into_iter()
                .map(|i| adapters[i].author_view_request(AgreementView(1)).unwrap())
                .collect();
            assert_eq!(requests.len(), m.set.quorum_size());
            let adapter = &mut adapters[2];
            for request in &requests[..requests.len() - 1] {
                adapter.receive_view_request(request.clone()).unwrap();
                assert_eq!(
                    adapter.timer_snapshot().unwrap().view,
                    AgreementView(0),
                    "q-1 exact-target requests cannot enter"
                );
            }
            adapter
                .receive_view_request(requests.last().unwrap().clone())
                .unwrap();
            let transition = adapter.driver.output().unwrap().transition.unwrap();
            assert_eq!(
                transition.view,
                AgreementView(1),
                "receive must automatically enter on q exact-target requests"
            );
            assert!(
                transition.vote.is_none(),
                "advisory entry must not emit a vote"
            );
            assert!(transition.decision.is_none());
            assert_eq!(
                adapter
                    .signing_history()
                    .iter()
                    .map(|i| (i.id, i.vote.clone()))
                    .collect::<Vec<_>>(),
                history,
                "advisory entry must preserve existing signing obligations"
            );
        }
    }
    let adapter = &mut adapters[2];
    recover_envelope_adapter(adapter, &stores[2], &bootstrap, &m, 2);
    assert_eq!(adapter.timer_snapshot().unwrap().view, AgreementView(1));
    assert_eq!(
        adapter.driver.output().unwrap().reproposal,
        Some(reproposal.clone())
    );

    let candidate = SlotAgreementViewCandidate::new(
        vec![],
        skip.clone(),
        carriers[1].clone(),
        AgreementView(1),
        &m.set,
    )
    .unwrap();
    let elected = proposer_index(AgreementView(1));
    for i in [elected, 3] {
        if adapters[i].timer_snapshot().unwrap().view == AgreementView(0) {
            adapters[i]
                .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
                    from: AgreementView(0),
                })
                .unwrap();
        }
    }
    let mut node = authoring_node_index(&m, &vertices, elected);
    node.set_round(10);
    let conflict = adapters[elected]
        .author_view(&candidate, &mut node)
        .unwrap()
        .unwrap();
    assert_eq!(conflict.vertex.author, m.consensus[elected].id);
    assert_eq!(
        conflict.envelope.carrier().author,
        validator::slot_agreement_view_proposer(&m.set, 1, AgreementView(1)).unwrap()
    );
    conflict
        .envelope
        .inspect(node.dag(), &adapters[2].driver.output().unwrap().binding)
        .unwrap();
    vertices.push(conflict.vertex);
    // A lock-free receiver accepts the exact same authenticated conflict and votes skip.
    adapters[3]
        .receive_envelope(conflict.envelope.clone(), vertices.clone())
        .unwrap();
    assert_eq!(
        adapters[3].signing_history().last().unwrap().vote.value,
        AgreementValue::Decision(skip.decision.clone())
    );
    let adapter = &mut adapters[2];
    let sequence = adapter.driver.sequence();
    let error = adapter
        .receive_envelope(conflict.envelope, vertices)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("conflicting proposal lacks newer POL"),
        "must reach the lock guard, not fail authentication or proposer election: {error}"
    );
    assert_eq!(adapter.driver.sequence(), sequence);
    assert_eq!(
        adapter
            .signing_history()
            .iter()
            .map(|i| (i.id, i.vote.clone()))
            .collect::<Vec<_>>(),
        history,
        "the conflict must not create any signing obligation"
    );
    assert!(
        !adapter
            .signing_history()
            .iter()
            .any(|i| i.vote.value == AgreementValue::Decision(skip.decision.clone()))
    );
    assert_eq!(
        adapter.driver.output().unwrap().reproposal,
        Some(reproposal.clone())
    );
    recover_envelope_adapter(adapter, &stores[2], &bootstrap, &m, 2);
    assert_eq!(
        adapter.driver.output().unwrap().reproposal,
        Some(reproposal)
    );
    assert!(
        !adapter
            .signing_history()
            .iter()
            .any(|i| i.vote.value == AgreementValue::Decision(skip.decision.clone()))
    );
}

#[test]
fn nil_has_no_dummy_carrier_or_signature() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { vertices, .. } = request else {
        panic!("fixture proposal");
    };
    let actual_carrier = vertices.last().unwrap().id().unwrap();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: validator::slot_agreement::AgreementPhase::Prevote,
        })
        .unwrap();
    assert_eq!(adapter.driver.sequence(), 1);
    assert_eq!(
        adapter.pending()[0].prerequisite_carriers(),
        Err(PrerequisiteExtractionError::UnsupportedNil)
    );
    assert!(matches!(
        &adapter.pending()[0],
        PendingIntent::UnsupportedNil { .. }
    ));
    let PendingIntent::UnsupportedNil { intent } = &adapter.pending()[0] else {
        panic!("durable nil obligation");
    };
    assert!(
        PendingIntent::UnsupportedNil {
            intent: intent.clone()
        }
        .into_envelope(actual_carrier, &m.set)
        .is_err()
    );
    let recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert!(matches!(
        &recovered.pending()[0],
        PendingIntent::UnsupportedNil { .. }
    ));
    assert_eq!(
        recovered.readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
}

#[test]
fn stale_owner_cannot_reconstruct_or_sign() {
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut stale = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let mut current = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    current.apply(request.clone()).unwrap();
    assert!(stale.apply(request).is_err());
    assert!(stale.pending().is_empty());
    assert!(stale.history.is_empty());
    assert_eq!(
        stale.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
}

#[test]
fn received_plain_proposal_is_neutral_durable_and_view_votes_after_recovery() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    let entry = &lineage.entries[0];
    let envelope = CarrierEnvelope::from_publication(
        entry.proposal_carrier.clone(),
        CarrierPayload::Proposal(entry.proposal.clone()),
        entry.proposal.digest().unwrap(),
        &m.set,
    )
    .unwrap();
    let proposal_vertices: Vec<_> = vertices
        .iter()
        .filter(|v| v.round <= entry.proposal_carrier.round)
        .cloned()
        .collect();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let path = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&path).unwrap();
    for kind in 0..4 {
        let mut carrier = entry.proposal_carrier.clone();
        let mut proposal = entry.proposal.clone();
        let mut evidence = proposal_vertices.clone();
        match kind {
            0 => carrier.digest[0] ^= 1,
            1 => {
                evidence
                    .iter_mut()
                    .find(|v| v.id().unwrap() == carrier)
                    .unwrap()
                    .signature[0] ^= 1
            }
            2 => proposal.decision.round += 1,
            _ => evidence.clear(),
        }
        let bad = CarrierEnvelope::from_publication(
            carrier,
            CarrierPayload::Proposal(proposal.clone()),
            proposal.digest().unwrap(),
            &m.set,
        )
        .unwrap();
        assert!(
            adapter.receive_envelope(bad, evidence).is_err(),
            "bad evidence {kind}"
        );
        assert_eq!(std::fs::read(&path).unwrap(), before);
        adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
        assert_eq!(adapter.driver.sequence(), 0);
        assert!(adapter.pending().is_empty());
        assert!(adapter.signing_history().is_empty());
    }
    adapter
        .receive_envelope(envelope, proposal_vertices)
        .unwrap();
    assert_eq!(adapter.driver.sequence(), 1);
    assert_ne!(std::fs::read(&path).unwrap(), before);
    let neutral = adapter.driver.output().unwrap().transition.unwrap();
    assert_eq!(neutral.view, AgreementView(0));
    assert!(neutral.vote.is_none());
    assert!(neutral.decision.is_none());
    assert!(adapter.pending().is_empty());
    assert!(adapter.signing_history().is_empty());
    adapter = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    assert_eq!(adapter.driver.sequence(), 1);
    assert!(adapter.pending().is_empty());
    assert!(adapter.signing_history().is_empty());
    let view = CarrierEnvelope::from_publication(
        entry.view_carrier.clone(),
        CarrierPayload::View(lineage.clone()),
        lineage.view_digest(0).unwrap(),
        &m.set,
    )
    .unwrap();
    adapter
        .receive_envelope(
            view,
            vertices
                .into_iter()
                .filter(|v| v.round > entry.proposal_carrier.round)
                .collect(),
        )
        .unwrap();
    assert_eq!(adapter.driver.sequence(), 2);
    let accepted = adapter.driver.output().unwrap().transition.unwrap();
    assert_eq!(
        accepted.vote.as_ref().unwrap().phase,
        validator::slot_agreement::AgreementPhase::Prevote
    );
    assert_eq!(adapter.pending().len(), 1);
    assert_eq!(adapter.signing_history().len(), 1);
    let PendingIntent::Vote {
        payload,
        lineage: retained,
        ..
    } = &adapter.pending()[0]
    else {
        panic!("view receive must emit a vote obligation")
    };
    assert_eq!(payload.prerequisite, entry.view_carrier);
    assert_eq!(retained, &lineage);
    let history = format!("{:?}", adapter.signing_history());
    let recovered = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert_eq!(recovered.driver.sequence(), 2);
    assert_eq!(format!("{:?}", recovered.signing_history()), history);
    assert_eq!(recovered.pending().len(), 1);
}

fn reproposal_lineage(
    m: &chain::Membership,
    chain_id: &[u8],
    vertices: &mut Vec<Vertex>,
    context: SlotDecisionTip,
    entry: SlotAgreementProofEntry,
) -> (
    SlotAgreementViewLineage,
    validator::SlotAgreementPolCandidate,
) {
    use validator::slot_agreement::{AgreementPhase, AgreementQc, AgreementValue, AgreementVote};
    let vote = AgreementVote {
        context,
        view: entry.view,
        phase: AgreementPhase::Prevote,
        value: AgreementValue::Decision(entry.proposal.decision.clone()),
    };
    let bytes = vote.signing_payload(&m.set).unwrap();
    let mut signatures: Vec<_> = (0..m.set.quorum_size())
        .map(|index| ValidatorSignature {
            validator_id: m.consensus[index].id.clone(),
            key_id: m.set.validators[index].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&m.consensus[index].private_key, &bytes)
                .unwrap(),
        })
        .collect();
    signatures.sort_by(|a, b| a.validator_id.cmp(&b.validator_id));
    let certificate = AgreementQc { vote, signatures };
    let round = entry.view_carrier.round;
    let references: Vec<_> = vertices
        .iter()
        .filter(|vertex| vertex.round == round)
        .map(|vertex| vertex.id().unwrap())
        .collect();
    let mut witnesses = Vec::new();
    for signature in &certificate.signatures {
        let index = m
            .consensus
            .iter()
            .position(|identity| identity.id == signature.validator_id)
            .unwrap();
        let payload = SlotAgreementVotePayload {
            vote: certificate.vote.clone(),
            signature: signature.clone(),
            prerequisite: entry.view_carrier.clone(),
        };
        let vertex = signed_for_chain(
            m,
            index,
            round + 1,
            references.clone(),
            payload.digest(&m.set).unwrap(),
            chain_id,
        );
        vertices.push(vertex.clone());
        witnesses.push(validator::SlotAgreementVoteWitness {
            payload,
            carrier: vertex.id().unwrap(),
        });
    }
    let lineage = SlotAgreementViewLineage {
        entries: vec![entry],
    };
    let candidate = lineage
        .pol_candidate_digest(certificate.clone(), witnesses.clone(), &m.set)
        .unwrap();
    let pol_references: Vec<_> = witnesses
        .iter()
        .map(|witness| witness.carrier.clone())
        .collect();
    let pol = signed_for_chain(
        m,
        0,
        round + 2,
        pol_references,
        candidate.digest(),
        chain_id,
    );
    let pol_carrier = pol.id().unwrap();
    vertices.push(pol);
    let bound = candidate.clone().bind_carrier(pol_carrier);
    (bound, candidate)
}

#[test]
fn elected_reproposal_authors_plain_then_exact_view_without_inventing_evidence() {
    use net::wire::Message;
    use std::time::Duration;
    use validator::slot_agreement::AgreementView;
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose {
        lineage,
        mut vertices,
    } = request
    else {
        unreachable!("fixture proposes")
    };
    let entry = lineage.entries[0].clone();
    let proposal = entry.proposal.clone();
    let (reproposal, pol_candidate) = reproposal_lineage(
        &m,
        b"live-adapter-tests",
        &mut vertices,
        bootstrap.agreement.context.clone(),
        entry,
    );
    let elected_id =
        validator::slot_agreement_view_proposer(&m.set, proposal.decision.round, AgreementView(1))
            .unwrap();
    let elected = m
        .consensus
        .iter()
        .position(|identity| identity.id == elected_id)
        .unwrap();
    let non_elected = (0..m.consensus.len())
        .find(|index| *index != elected)
        .unwrap();
    let pol_carrier = reproposal.entries[0].pol.as_ref().unwrap().carrier.clone();
    let evidence = PendingIntent::Pol {
        candidate: pol_candidate.clone(),
        digest: pol_candidate.digest(),
    }
    .into_envelope(pol_carrier, &m.set)
    .unwrap();
    let wait = Duration::from_secs(1);
    let policy = pacemaker::Policy::new(wait, wait, wait).unwrap();
    let round_ids = |source: &[Vertex], round: u64| {
        let mut ids: Vec<_> = source
            .iter()
            .filter(|vertex| vertex.round == round)
            .map(|vertex| vertex.id().unwrap())
            .collect();
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        ids
    };

    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut b = bootstrap.clone();
    b.agreement.local_validator = m.consensus[elected].id.clone();
    let mut adapter = Adapter::begin(&store, b.clone(), &m, elected).unwrap();
    adapter
        .receive_envelope(evidence.clone(), vertices.clone())
        .unwrap();
    let output_before_advance = adapter.driver.output().unwrap();
    assert_eq!(
        output_before_advance.reproposal.as_ref().unwrap().lineage(),
        &reproposal
    );
    adapter
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert_eq!(adapter.timer_snapshot().unwrap().view, AgreementView(1));
    let genesis = chain::genesis_state(&m.accounts).unwrap();
    let chain = b.agreement.context.chain_id().to_vec();
    let anchor = validator::Header::genesis(
        chain.clone(),
        m.set.epoch,
        genesis.state_root(),
        *b.agreement.context.order_root(),
    );
    let finalizer = validator::Finalizer::new(
        validator::SetSchedule::single(m.set.clone()),
        validator::EpochSchedule::single(m.set.epoch),
        chain,
        m.consensus[elected].id.clone(),
        m.consensus[elected].private_key.clone(),
        anchor,
        0,
    )
    .unwrap();
    let mut owner = JournaledFinalization::open(adapter, genesis, finalizer).unwrap();
    owner
        .enable_authoring(authoring_node_index(&m, &vertices, elected), policy, wait)
        .unwrap();
    let references = round_ids(&vertices, 5);
    let mut sixth = Vec::new();
    for author in [1, 2, 3] {
        sixth.push(signed(&m, author, 6, references.clone(), [42; 32]));
    }
    let authored_proposal = owner.drive_local(sixth.clone()).unwrap();
    assert_eq!(authored_proposal.len(), 1);
    let Message::AgreementCarrier { envelope, .. } = &authored_proposal[0] else {
        panic!("expected elected plain proposal")
    };
    let proposal_envelope = CarrierEnvelope::decode(envelope, &m.set).unwrap();
    assert!(matches!(
        proposal_envelope.payload(),
        CarrierPayload::Proposal(actual) if *actual == proposal
    ));
    assert_eq!(proposal_envelope.carrier().round, 7);
    assert_eq!(proposal_envelope.carrier().author, m.consensus[elected].id);
    let proposal_carrier = proposal_envelope.carrier().clone();
    let mut available = vertices.clone();
    available.extend(sixth);
    let references = round_ids(&available, 6);
    let mut seventh = Vec::new();
    for author in (0..m.consensus.len()).filter(|author| *author != elected) {
        seventh.push(signed(&m, author, 7, references.clone(), [42; 32]));
    }
    let authored_view = owner.drive_local(seventh).unwrap();
    assert_eq!(authored_view.len(), 1);
    let Message::AgreementCarrier { envelope, .. } = &authored_view[0] else {
        panic!("expected elected view carrier")
    };
    let view_envelope = CarrierEnvelope::decode(envelope, &m.set).unwrap();
    let CarrierPayload::View(view_lineage) = view_envelope.payload() else {
        panic!("expected view payload")
    };
    let selected = view_lineage.entries.last().unwrap();
    assert_eq!(selected.view, AgreementView(1));
    assert_eq!(selected.proposal_carrier, proposal_carrier);
    assert_eq!(
        &view_lineage.entries[..view_lineage.entries.len() - 1],
        reproposal.entries.as_slice(),
        "view must bind the exact retained POL prefix"
    );
    assert_eq!(view_envelope.carrier().round, 8);
    assert_eq!(view_envelope.carrier().author, m.consensus[elected].id);
    assert!(
        owner.drive_local(Vec::new()).unwrap().is_empty(),
        "a completed view election is not reauthored"
    );
    drop(owner);
    let mut recovered = Adapter::recover(&store, b, &m, elected).unwrap();
    let recovered_output = recovered.driver.output().unwrap();
    assert_eq!(
        recovered_output.reproposal.as_ref().unwrap().lineage(),
        &reproposal
    );
    assert_eq!(recovered_output.transition.unwrap().view, AgreementView(1));
    assert_eq!(recovered.completed_carriers().unwrap().len(), 2);

    // The same durable state on a non-elected validator must author nothing.
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut b = bootstrap.clone();
    b.agreement.local_validator = m.consensus[non_elected].id.clone();
    let mut adapter = Adapter::begin(&store, b.clone(), &m, non_elected).unwrap();
    adapter
        .receive_envelope(evidence, vertices.clone())
        .unwrap();
    adapter
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    assert_eq!(adapter.timer_snapshot().unwrap().view, AgreementView(1));
    let genesis = chain::genesis_state(&m.accounts).unwrap();
    let chain = b.agreement.context.chain_id().to_vec();
    let anchor = validator::Header::genesis(
        chain.clone(),
        m.set.epoch,
        genesis.state_root(),
        *b.agreement.context.order_root(),
    );
    let finalizer = validator::Finalizer::new(
        validator::SetSchedule::single(m.set.clone()),
        validator::EpochSchedule::single(m.set.epoch),
        chain,
        m.consensus[non_elected].id.clone(),
        m.consensus[non_elected].private_key.clone(),
        anchor,
        0,
    )
    .unwrap();
    let mut owner = JournaledFinalization::open(adapter, genesis, finalizer).unwrap();
    owner
        .enable_authoring(
            authoring_node_index(&m, &vertices, non_elected),
            policy,
            wait,
        )
        .unwrap();
    let wal = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    let references = round_ids(&vertices, 5);
    let mut sixth = Vec::new();
    for author in [1, 2, 3] {
        sixth.push(signed(&m, author, 6, references.clone(), [42; 32]));
    }
    assert!(
        owner.drive_local(sixth).unwrap().is_empty(),
        "a non-elected proposer must not author"
    );
    assert_eq!(
        std::fs::read(&wal).unwrap(),
        before,
        "no signing without election"
    );
}

fn open_event_pump_owner(
    store: &Store,
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    m: &Membership,
) -> JournaledFinalization {
    open_event_pump_owner_index(store, bootstrap, m, 0)
}

fn open_event_pump_owner_index(
    store: &Store,
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    m: &Membership,
    index: usize,
) -> JournaledFinalization {
    let chain_id = bootstrap.agreement.context.chain_id().to_vec();
    let genesis = chain::genesis_state(&m.accounts).unwrap();
    let anchor = validator::Header::genesis(
        chain_id.clone(),
        m.set.epoch,
        genesis.state_root(),
        *bootstrap.agreement.context.order_root(),
    );
    let finalizer = validator::Finalizer::new(
        validator::SetSchedule::single(m.set.clone()),
        validator::EpochSchedule::single(m.set.epoch),
        chain_id,
        m.consensus[index].id.clone(),
        m.consensus[index].private_key.clone(),
        anchor,
        0,
    )
    .unwrap();
    JournaledFinalization::open(
        Adapter::begin(store, bootstrap.clone(), m, index).unwrap(),
        genesis,
        finalizer,
    )
    .unwrap()
}

fn exercise_event_pump_stop(
    mut owner: JournaledFinalization,
    m: Membership,
    evidence: net::wire::Message,
    mode: AuthenticatedReplayMode,
) {
    use super::event_pump::{EventPump, LocalEvent};
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
        time::Duration,
    };
    use tokio::sync::watch;

    owner.receive_agreement_message(evidence).unwrap();
    assert!(
        owner
            .finalization()
            .execution()
            .snapshot()
            .applications()
            .is_empty()
    );
    let (pump, channels) =
        EventPump::new(owner, m, Default::default(), 1.try_into().unwrap(), 0, 0);
    let (cancel, cancel_rx) = watch::channel(false);
    let mut output = Some(channels.output);
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let mut run = Box::pin(pump.run(cancel_rx));
            let mut context = Context::from_waker(Waker::noop());
            // Poll exactly once while ingress is idle: the output permit is now held
            // and the second select is pending. No sleep or scheduler timing assumption.
            assert!(matches!(run.as_mut().poll(&mut context), Poll::Pending));
            assert_eq!(
                output.as_ref().unwrap().capacity(),
                0,
                "pump must have reserved output"
            );
            channels
                .local
                .try_send(LocalEvent::ApplyCertifiedSlot { at: 42 })
                .unwrap();
            if matches!(mode, AuthenticatedReplayMode::EventPumpCancelReady) {
                cancel.send(true).unwrap();
            } else {
                drop(output.take());
            }
            // Both stop notification and mutating local application are ready on
            // the very next poll. The queued application must remain unconsumed.
            let (owner, result) = tokio::time::timeout(Duration::from_secs(5), run)
                .await
                .unwrap();
            if matches!(mode, AuthenticatedReplayMode::EventPumpCancelReady) {
                result.unwrap();
            } else {
                assert!(result.unwrap_err().contains("output closed"));
            }
            if let Some(mut output) = output {
                assert!(output.recv().await.is_none());
            }
            assert!(
                owner
                    .finalization()
                    .execution()
                    .snapshot()
                    .applications()
                    .is_empty()
            );
            assert_eq!(owner.finalization().execution().applied(), 0);
            assert_eq!(owner.finalization().finalizer().built_headers(), 0);
            // Prove this was actionable certified evidence, not an inert test event.
            let mut owner = owner;
            owner.advance_certified_slot().unwrap();
            assert_eq!(
                owner
                    .finalization()
                    .execution()
                    .snapshot()
                    .applications()
                    .len(),
                1
            );
        });
}

#[test]
fn isolated_event_pump_share_mesh_quorum() {
    authenticated_commit_replay_fixture(AuthenticatedReplayMode::ShareMesh);
}

async fn exercise_dispatcher_false_updates(share: validator::Share) {
    use super::{
        event_pump::PumpOutput,
        output_dispatcher::{self, DispatchOutput, SharePeer},
    };
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    use tokio::sync::{mpsc, watch};

    let (cancel, cancel_rx) = watch::channel(false);
    let (input, input_rx) = mpsc::channel(1);
    let (writer, mut queued) = mpsc::channel(1);
    let (local, mut results) = mpsc::channel(1);
    writer.send(vec![7]).await.unwrap();
    local
        .send(DispatchOutput {
            local: PumpOutput {
                carriers: Vec::new(),
                build: validator::Build::default(),
                error: Some("saturated result".into()),
            },
            failed_peers: vec![],
        })
        .await
        .unwrap();
    let expected = net::wire::frame(&net::wire::Message::Share(share.clone()), 123).unwrap();
    input
        .send(PumpOutput {
            carriers: Vec::new(),
            build: validator::Build {
                shares: vec![share],
                certified: vec![],
            },
            error: None,
        })
        .await
        .unwrap();
    let mut dispatch = std::pin::pin!(output_dispatcher::dispatch(
        input_rx,
        vec![SharePeer { id: 1, writer }],
        local,
        cancel_rx,
        123,
    ));
    let mut context = Context::from_waker(Waker::noop());
    // Explicit polling proves each wait is reached; no sleeps or scheduler assumptions.
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    cancel.send(false).unwrap();
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    assert_eq!(
        input.capacity(),
        0,
        "full result queue must prevent input consumption"
    );
    assert_eq!(
        results.recv().await.unwrap().local.error.as_deref(),
        Some("saturated result")
    );
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    assert_eq!(input.capacity(), 1, "fanout now owns the consumed output");
    cancel.send(false).unwrap();
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    assert!(results.try_recv().is_err(), "writer is still saturated");
    assert_eq!(queued.recv().await.unwrap(), vec![7]);
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    assert_eq!(queued.recv().await.unwrap(), expected);
    let delivered = results.recv().await.unwrap();
    assert!(delivered.local.error.is_none());
    assert_eq!(delivered.local.build.shares.len(), 1);
    assert!(delivered.failed_peers.is_empty());
    // Also exercise a false update while waiting for the next input.
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    cancel.send(false).unwrap();
    assert!(dispatch.as_mut().poll(&mut context).is_pending());
    // Sender closure is cancellation even when the final value remains false.
    drop(cancel);
    assert!(matches!(
        dispatch.as_mut().poll(&mut context),
        Poll::Ready(())
    ));
}

fn exercise_share_mesh(
    bootstrap: AuthenticatedSlotAgreementBootstrap,
    m: Membership,
    batches: std::collections::BTreeMap<[u8; 32], tx::batch::Batch>,
    proof: validator::SlotAgreementProof,
    carrier: VertexId,
    vertices: Vec<Vertex>,
) {
    use super::{
        event_pump::{EventPump, LocalEvent},
        output_dispatcher::{self, SharePeer},
    };
    use net::wire::{self, Message};
    use std::{
        collections::{BTreeSet, VecDeque},
        sync::{Arc, Mutex},
        time::Duration,
    };
    use tokio::{
        net::{TcpListener, TcpStream},
        sync::{mpsc, watch},
    };

    let envelope = CarrierEnvelope::from_publication(
        carrier,
        CarrierPayload::Final(proof.clone()),
        proof.digest(&m.set).unwrap(),
        &m.set,
    )
    .unwrap();
    let evidence = Message::AgreementCarrier {
        envelope: envelope.encode(&m.set).unwrap(),
        vertices,
    };
    let chain_id = bootstrap.agreement.context.chain_id().to_vec();
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let (cancel, cancel_rx) = watch::channel(false);
            let mut dirs = Vec::new();
            let mut stores = Vec::new();
            let mut channels = Vec::new();
            let mut pumps = Vec::new();
            for index in 0..3 {
                dirs.push(Dir::new());
                stores.push(Store::open(&dirs[index].0).unwrap());
                let mut membership = m.clone();
                for (other, key) in membership.consensus.iter_mut().enumerate() {
                    if other != index {
                        key.private_key.clear();
                    }
                }
                let mut checkpoint = bootstrap.clone();
                checkpoint.agreement.local_validator = membership.consensus[index].id.clone();
                let owner =
                    open_event_pump_owner_index(&stores[index], &checkpoint, &membership, index);
                let (pump, ch) = EventPump::new(
                    owner,
                    membership,
                    BTreeSet::new(),
                    1.try_into().unwrap(),
                    batches.len(),
                    batches
                        .values()
                        .map(|batch| batch.encode().unwrap().len())
                        .sum(),
                );
                pumps.push(tokio::spawn(pump.run(cancel_rx.clone())));
                channels.push(ch);
            }
            let mut shares = Vec::new();
            // Build each owner before routing: early shares are deliberately not staged.
            for ch in &mut channels {
                ch.frames
                    .send(wire::Frame {
                        sent_at_nanos: u64::MAX,
                        len: 0,
                        message: evidence.clone(),
                    })
                    .await
                    .unwrap();
                assert!(ch.output.recv().await.unwrap().error.is_none());
                ch.local
                    .send(LocalEvent::ApplyCertifiedSlot { at: 41 })
                    .await
                    .unwrap();
                assert!(ch.output.recv().await.unwrap().error.is_none());
                let mut local = Vec::new();
                for batch in batches.values() {
                    ch.frames
                        .send(wire::Frame {
                            sent_at_nanos: u64::MAX,
                            len: 0,
                            message: Message::Payload(batch.clone()),
                        })
                        .await
                        .unwrap();
                    let out = ch.output.recv().await.unwrap();
                    // Non-required fixture batches are rejected, without authorizing execution.
                    local.extend(out.build.shares);
                }
                assert_eq!(local.len(), 1);
                assert_eq!(local[0].at, 41);
                shares.push(local.remove(0));
            }
            assert_eq!(
                shares
                    .iter()
                    .map(|s| s.signer)
                    .collect::<BTreeSet<_>>()
                    .len(),
                3
            );
            assert!(shares.iter().all(|s| s.header == shares[0].header));
            let mut writers = Vec::new();
            let mut readers = Vec::new();
            let mut routes: Vec<Vec<SharePeer>> = (0..3).map(|_| Vec::new()).collect();
            for (source, route) in routes.iter_mut().enumerate() {
                for (target, ch) in channels.iter().enumerate() {
                    if source == target {
                        continue;
                    }
                    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                        .await
                        .unwrap();
                    let mut sender = TcpStream::connect(listener.local_addr().unwrap())
                        .await
                        .unwrap();
                    let (mut receiver, _) = listener.accept().await.unwrap();
                    let mut send_buffer = Vec::new();
                    let mut receive_buffer = Vec::new();
                    let (a, b) = tokio::join!(
                        super::super::handshake(&mut sender, &mut send_buffer, &chain_id),
                        super::super::handshake(&mut receiver, &mut receive_buffer, &chain_id),
                    );
                    a.unwrap();
                    b.unwrap();
                    readers.push(tokio::spawn(super::super::read_peer(
                        receiver,
                        receive_buffer,
                        ch.frames.clone(),
                        Arc::new(AtomicU64::new(0)),
                        cancel_rx.clone(),
                    )));
                    let (control, control_rx) = mpsc::channel(1);
                    let (_data, data_rx) = mpsc::channel(1);
                    // Keep the unused data queue open for the writer's lifetime.
                    writers.push(tokio::spawn({
                        let cancel_rx = cancel_rx.clone();
                        let chain_id = chain_id.clone();
                        async move {
                            let _data = _data;
                            super::super::write_peer(
                                sender,
                                control_rx,
                                data_rx,
                                super::super::LinkTask {
                                    index: source,
                                    target: listener.local_addr().unwrap().to_string(),
                                    chain_id,
                                    bytes_out: Arc::new(AtomicU64::new(0)),
                                    up: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                                    recent_shares: Arc::new(Mutex::new(VecDeque::new())),
                                    recent_vertices: Arc::new(Mutex::new(VecDeque::new())),
                                    send_buffer: 0,
                                    shutdown: cancel_rx,
                                },
                            )
                            .await;
                        }
                    }));
                    route.push(SharePeer {
                        id: target,
                        writer: control,
                    });
                }
            }
            // A correctly signed but nonlocal executed header must not contribute.
            let mut wrong = shares[1].clone();
            wrong.header.state_root[0] ^= 1;
            wrong.signature = Ed25519Scheme
                .sign(
                    &m.consensus[1].private_key,
                    &validator::signing_payload(&wrong.header).unwrap(),
                )
                .unwrap();
            routes[1]
                .iter()
                .find(|peer| peer.id == 0)
                .unwrap()
                .writer
                .send(wire::frame(&Message::Share(wrong), u64::MAX).unwrap())
                .await
                .unwrap();
            let rejected = channels[0].output.recv().await.unwrap();
            assert!(rejected.error.is_some());
            assert!(rejected.build.shares.is_empty() && rejected.build.certified.is_empty());
            let mut dispatchers = Vec::new();
            let mut results = Vec::new();
            for (index, (ch, route)) in channels.iter_mut().zip(routes).enumerate() {
                let (unused, replacement) = mpsc::channel(1);
                drop(unused);
                let input = std::mem::replace(&mut ch.output, replacement);
                let (local, mut output) = mpsc::channel(1);
                // Initial shares were extracted above and are explicitly reinjected here;
                // only subsequent pump outputs use the direct receiver path.
                let (initial, initial_rx) = mpsc::channel(1);
                initial
                    .send(super::event_pump::PumpOutput {
                        carriers: Vec::new(),
                        build: validator::Build {
                            shares: vec![shares[index].clone()],
                            certified: vec![],
                        },
                        error: None,
                    })
                    .await
                    .unwrap();
                drop(initial);
                let initial_task = tokio::spawn(output_dispatcher::dispatch(
                    initial_rx,
                    route
                        .iter()
                        .map(|p| SharePeer {
                            id: p.id,
                            writer: p.writer.clone(),
                        })
                        .collect(),
                    local.clone(),
                    cancel_rx.clone(),
                    u64::MAX,
                ));
                let initial_output = output.recv().await.unwrap();
                assert!(initial_output.failed_peers.is_empty());
                assert!(initial_output.local.error.is_none());
                assert_eq!(initial_output.local.build.shares.len(), 1);
                assert!(initial_output.local.build.certified.is_empty());
                initial_task.await.unwrap();
                results.push(output);
                dispatchers.push(tokio::spawn(output_dispatcher::dispatch(
                    input,
                    route,
                    local,
                    cancel_rx.clone(),
                    u64::MAX,
                )));
            }
            for output in &mut results {
                let mut certificates = Vec::new();
                // Initial routing completed and its result was drained before live routing.
                for _ in 0..2 {
                    let receipt = output.recv().await.unwrap();
                    assert!(receipt.local.error.is_none(), "{:?}", receipt.local.error);
                    assert!(receipt.failed_peers.is_empty());
                    assert!(
                        receipt.local.build.shares.is_empty(),
                        "received shares must not rebroadcast"
                    );
                    certificates.extend(receipt.local.build.certified);
                }

                assert_eq!(certificates.len(), 1);
                assert_eq!(certificates[0].header, shares[0].header);
            }
            exercise_dispatcher_false_updates(shares[0].clone()).await;
            // Closed peers are reported individually; successful queueing is not delivery.
            let (closed, receiver) = mpsc::channel(1);
            drop(receiver);
            let (healthy, mut queued) = mpsc::channel(1);
            let (input, input_rx) = mpsc::channel(1);
            let (local, mut local_rx) = mpsc::channel(1);
            input
                .send(super::event_pump::PumpOutput {
                    carriers: Vec::new(),
                    build: validator::Build {
                        shares: vec![shares[0].clone()],
                        certified: vec![],
                    },
                    error: None,
                })
                .await
                .unwrap();
            let task = tokio::spawn(output_dispatcher::dispatch(
                input_rx,
                vec![
                    SharePeer {
                        id: 8,
                        writer: closed,
                    },
                    SharePeer {
                        id: 9,
                        writer: healthy.clone(),
                    },
                ],
                local,
                cancel_rx.clone(),
                0,
            ));
            let reported = local_rx.recv().await.unwrap();
            assert_eq!(reported.failed_peers, vec![8]);
            assert!(queued.recv().await.is_some());
            drop(input);
            task.await.unwrap();
            // Full writer queues backpressure and cancellation interrupts the wait.
            healthy.send(vec![1]).await.unwrap();
            let (input, input_rx) = mpsc::channel(1);
            let (local, mut local_rx) = mpsc::channel(1);
            input
                .send(super::event_pump::PumpOutput {
                    carriers: Vec::new(),
                    build: validator::Build {
                        shares: vec![shares[0].clone()],
                        certified: vec![],
                    },
                    error: None,
                })
                .await
                .unwrap();
            let task = tokio::spawn(output_dispatcher::dispatch(
                input_rx,
                vec![SharePeer {
                    id: 9,
                    writer: healthy,
                }],
                local,
                cancel_rx.clone(),
                0,
            ));
            while input.capacity() == 0 {
                tokio::task::yield_now().await;
            }
            assert!(local_rx.try_recv().is_err());
            cancel.send(true).unwrap();
            task.await.unwrap();
            assert!(local_rx.recv().await.is_none());
            assert_eq!(queued.recv().await.unwrap(), vec![1]);
            for task in dispatchers {
                task.await.unwrap();
            }
            for task in readers {
                task.await.unwrap();
            }
            for task in writers {
                task.await.unwrap();
            }
            for task in pumps {
                let (owner, result) = task.await.unwrap();
                result.unwrap();
                assert_eq!(owner.finalization().finalizer().built_headers(), 1);
            }
        })
        .await
        .expect("bounded share mesh timed out");
    });
}

fn exercise_event_pump(
    store: &Store,
    bootstrap: AuthenticatedSlotAgreementBootstrap,
    m: Membership,
    batches: std::collections::BTreeMap<[u8; 32], tx::batch::Batch>,
    proof: validator::SlotAgreementProof,
    carrier: VertexId,
    vertices: Vec<Vertex>,
) {
    use super::event_pump::{EventPump, LocalEvent};
    use net::wire::{self, Message};
    use std::{collections::BTreeSet, sync::Arc, time::Duration};
    use tokio::{
        io::AsyncWriteExt,
        net::{TcpListener, TcpStream},
        sync::watch,
    };

    let accounts = &m.accounts;
    let chain_id = bootstrap.agreement.context.chain_id().to_vec();
    let owner = open_event_pump_owner(store, &bootstrap, &m);
    let anchor = owner.finalization().finalizer().head().clone();
    // The authentic fixture commits all round-zero vertices and its round-one
    // leader. This expected set is test data, not runtime control inference.
    let validator::slot_agreement::AgreementValue::Decision(decision) =
        &proof.certificate.vote.value
    else {
        panic!("commit fixture");
    };
    let SlotOutcome::Commit { leader } = &decision.outcome else {
        panic!("commit fixture");
    };
    let required: BTreeSet<_> = vertices
        .iter()
        .filter(|vertex| vertex.round == 0 || vertex.id().unwrap() == *leader)
        .map(|vertex| vertex.payload_hash)
        .collect();
    // Exact retained canonical-byte/count budgets: unrelated traffic must consume
    // neither. These are not total-memory bounds on decoded batches or channels.
    let retained_encoded_bytes = required
        .iter()
        .map(|hash| batches[hash].encode().unwrap().len())
        .sum();
    let (pump, mut channels) = EventPump::new(
        owner,
        m.clone(),
        BTreeSet::new(),
        1.try_into().unwrap(),
        required.len(),
        retained_encoded_bytes,
    );
    let envelope = CarrierEnvelope::from_publication(
        carrier,
        CarrierPayload::Final(proof.clone()),
        proof.digest(&m.set).unwrap(),
        &m.set,
    )
    .unwrap();
    let evidence = Message::AgreementCarrier {
        envelope: envelope.encode(&m.set).unwrap(),
        vertices,
    };
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        tokio::time::timeout(Duration::from_secs(90), async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let mut sender = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut receiver, _) = listener.accept().await.unwrap();
            let mut send_buffer = Vec::new();
            let mut receive_buffer = Vec::new();
            let (a, b) = tokio::join!(
                super::super::handshake(&mut sender, &mut send_buffer, &chain_id),
                super::super::handshake(&mut receiver, &mut receive_buffer, &chain_id),
            );
            a.unwrap();
            b.unwrap();
            let (cancel, cancel_rx) = watch::channel(false);
            let (stop_reader, reader_rx) = watch::channel(false);
            let reader = super::super::read_peer(
                receiver,
                receive_buffer,
                channels.frames.clone(),
                Arc::new(AtomicU64::new(0)),
                reader_rx,
            );
            let client = async {
                sender
                    .write_all(&wire::frame(&evidence, 999).unwrap())
                    .await
                    .unwrap();
                let receipt = channels.output.recv().await.unwrap();
                assert!(receipt.error.is_none());
                assert!(receipt.build.shares.is_empty() && receipt.build.certified.is_empty());
                channels
                    .local
                    .send(LocalEvent::BuildReady { at: 40 })
                    .await
                    .unwrap();
                assert!(
                    channels
                        .output
                        .recv()
                        .await
                        .unwrap()
                        .build
                        .shares
                        .is_empty()
                );
                sender
                    .write_all(&wire::frame(&evidence, 0).unwrap())
                    .await
                    .unwrap();
                let duplicate = channels.output.recv().await.unwrap();
                assert!(duplicate.error.is_none());
                assert!(duplicate.build.shares.is_empty());
                // Even a required batch arriving before local certified application
                // is rejected, not staged. The sender must retransmit after apply.
                let early = batches[required.first().unwrap()].clone();
                sender
                    .write_all(&wire::frame(&Message::Payload(early), 0).unwrap())
                    .await
                    .unwrap();
                assert!(
                    channels
                        .output
                        .recv()
                        .await
                        .unwrap()
                        .error
                        .unwrap()
                        .contains("retransmit")
                );
                channels
                    .local
                    .send(LocalEvent::ApplyCertifiedSlot { at: 41 })
                    .await
                    .unwrap();
                let missing = channels.output.recv().await.unwrap();
                assert!(missing.error.is_none());
                assert!(missing.build.shares.is_empty());
                // Flood more unrelated, valid batches than the entire admission
                // budget, after certification but before any required batch arrives.
                for round in 100..100 + required.len() as u64 + 2 {
                    let unrelated = chain::demo_batch(&chain_id, accounts, 0, round, 1).unwrap();
                    sender
                        .write_all(&wire::frame(&Message::Payload(unrelated), 0).unwrap())
                        .await
                        .unwrap();
                    let rejected = channels.output.recv().await.unwrap();
                    assert!(rejected.error.unwrap().contains("not required"));
                    assert!(rejected.build.shares.is_empty());
                }
                let mut resumed = Vec::new();
                for hash in &required {
                    let batch = &batches[hash];
                    sender
                        .write_all(&wire::frame(&Message::Payload(batch.clone()), 999).unwrap())
                        .await
                        .unwrap();
                    let indexed = channels.output.recv().await.unwrap();
                    assert!(indexed.error.is_none());
                    resumed.extend(indexed.build.shares);
                }
                channels
                    .local
                    .send(LocalEvent::BuildReady { at: 42 })
                    .await
                    .unwrap();
                let built = channels.output.recv().await.unwrap();
                assert!(built.error.is_none(), "{:?}", built.error);
                assert!(
                    built.build.shares.is_empty(),
                    "payload arrival already resumed the build"
                );
                assert_eq!(resumed.len(), 1);
                let local = resumed[0].clone();
                assert_eq!(
                    local.at, 41,
                    "wire timestamps are not local authoring authority"
                );
                assert_eq!(local.header.height, 1);
                assert_eq!(local.header.previous, anchor.id().unwrap());
                let validator::slot_agreement::AgreementValue::Decision(decision) =
                    &proof.certificate.vote.value
                else {
                    panic!("commit fixture");
                };
                assert_eq!(local.header.dag_root, decision.after_root);
                channels
                    .local
                    .send(LocalEvent::ApplyCertifiedSlot { at: 43 })
                    .await
                    .unwrap();
                assert!(channels.output.recv().await.unwrap().error.is_some());
                channels
                    .local
                    .send(LocalEvent::BuildReady { at: 44 })
                    .await
                    .unwrap();
                assert!(
                    channels
                        .output
                        .recv()
                        .await
                        .unwrap()
                        .build
                        .shares
                        .is_empty()
                );
                for signer in [1, 2] {
                    let mut peer = local.clone();
                    peer.signer = signer;
                    peer.at = 50 + signer as u64;
                    peer.signature = Ed25519Scheme
                        .sign(
                            &m.consensus[signer].private_key,
                            &validator::signing_payload(&peer.header).unwrap(),
                        )
                        .unwrap();
                    if signer == 1 {
                        let mut invalid = peer.clone();
                        invalid.header.state_root[0] ^= 1;
                        sender
                            .write_all(&wire::frame(&Message::Share(invalid), 0).unwrap())
                            .await
                            .unwrap();
                        assert!(channels.output.recv().await.unwrap().error.is_some());
                    }
                    sender
                        .write_all(&wire::frame(&Message::Share(peer.clone()), 0).unwrap())
                        .await
                        .unwrap();
                    if signer == 2 {
                        // Leave certified output queued while a later ordinary error
                        // waits behind the output reservation barrier.
                        sender
                            .write_all(&wire::frame(&Message::SnapshotWant, 0).unwrap())
                            .await
                            .unwrap();
                    }
                    let output = channels.output.recv().await.unwrap();
                    assert!(output.error.is_none());
                    assert_eq!(output.build.certified.len(), usize::from(signer == 2));
                    if signer == 2 {
                        let certified = &output.build.certified[0];
                        assert_eq!(certified.header, local.header);
                        assert!(channels.output.recv().await.unwrap().error.is_some());
                    }
                    sender
                        .write_all(&wire::frame(&Message::Share(peer), 0).unwrap())
                        .await
                        .unwrap();
                    let duplicate = channels.output.recv().await.unwrap();
                    assert!(duplicate.error.is_none());
                    assert!(duplicate.build.certified.is_empty());
                }
                // Cancel while output is full; the completed response remains drainable.
                channels
                    .local
                    .send(LocalEvent::BuildReady { at: 60 })
                    .await
                    .unwrap();
                while channels.output.is_empty() {
                    tokio::task::yield_now().await;
                }
                cancel.send(true).unwrap();
                stop_reader.send(true).unwrap();
                let queued = channels.output.recv().await.unwrap();
                assert!(queued.error.is_none());
            };
            let ((owner, result), (), ()) = tokio::join!(pump.run(cancel_rx), reader, client);
            result.unwrap();
            assert_eq!(owner.finalization().finalizer().built_headers(), 1);
            assert_eq!(owner.finalization().finalizer().head().height, 1);
            assert!(owner.finalization().execution().applied() > 0);
            let mut expected = chain::genesis_state(accounts).unwrap();
            let Message::AgreementCarrier { vertices, .. } = &evidence else {
                unreachable!()
            };
            let mut rejected = std::collections::BTreeMap::new();
            for id in owner.finalization().execution().consumed_order() {
                let vertex = vertices
                    .iter()
                    .find(|vertex| vertex.id().unwrap() == *id)
                    .unwrap();
                chain::apply_batch(
                    &mut expected,
                    accounts,
                    &batches[&vertex.payload_hash],
                    &mut rejected,
                );
            }
            assert!(rejected.is_empty());
            assert_eq!(owner.finalization().execution().state(), &expected);
            assert_eq!(
                owner.finalization().finalizer().head().state_root,
                expected.state_root()
            );

            // Index exhaustion and ambiguous classification are ordinary errors;
            // neither may hide a subsequent loss of durable ownership.
            let first_batch = batches[required.first().unwrap()].clone();
            let controls = BTreeSet::from([first_batch.digest().unwrap()]);
            let (pump, mut bounded) =
                EventPump::new(owner, m.clone(), controls, 1.try_into().unwrap(), 0, 0);
            let (_cancel, cancel_rx) = watch::channel(false);
            let client = async {
                bounded
                    .frames
                    .send(wire::Frame {
                        sent_at_nanos: 0,
                        len: wire::frame(&Message::Payload(first_batch.clone()), 0)
                            .unwrap()
                            .len(),
                        message: Message::Payload(first_batch),
                    })
                    .await
                    .unwrap();
                assert!(
                    bounded
                        .output
                        .recv()
                        .await
                        .unwrap()
                        .error
                        .unwrap()
                        .contains("control")
                );
                let other = batches[required.iter().nth(1).unwrap()].clone();
                bounded
                    .frames
                    .send(wire::Frame {
                        sent_at_nanos: 0,
                        len: wire::frame(&Message::Payload(other.clone()), 0)
                            .unwrap()
                            .len(),
                        message: Message::Payload(other),
                    })
                    .await
                    .unwrap();
                assert!(
                    bounded
                        .output
                        .recv()
                        .await
                        .unwrap()
                        .error
                        .unwrap()
                        .contains("index full")
                );
                let mut replacement = Adapter::recover(store, bootstrap.clone(), &m, 0).unwrap();
                replacement
                    .apply(AuthenticatedSlotAgreementRequest::Timeout {
                        view: AgreementView(0),
                        phase: validator::slot_agreement::AgreementPhase::Prevote,
                    })
                    .unwrap();
                bounded
                    .local
                    .send(LocalEvent::BuildReady { at: 70 })
                    .await
                    .unwrap();
                assert!(bounded.output.recv().await.unwrap().error.is_some());
            };
            let ((owner, result), ()) = tokio::join!(pump.run(cancel_rx), client);
            assert!(result.is_err(), "stale owner must terminate, not retry");
            let (pump, closed) = EventPump::new(
                owner,
                m.clone(),
                BTreeSet::new(),
                1.try_into().unwrap(),
                0,
                0,
            );
            drop(closed);
            let (_cancel, cancel_rx) = watch::channel(false);
            assert!(
                pump.run(cancel_rx)
                    .await
                    .1
                    .unwrap_err()
                    .contains("output closed")
            );
        })
        .await
        .expect("isolated pump TCP test timed out");
    });
}

fn tcp_agreement_message(message: net::wire::Message) -> net::wire::Message {
    use net::wire;
    use std::sync::{Arc, atomic::AtomicU64};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};
    use tokio::sync::{mpsc, watch};
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let timeout = Duration::from_secs(5);
    let chain_id = b"isolated-agreement-test";
    runtime.block_on(async {
        tokio::time::timeout(timeout, async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let mut sender = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (mut receiver, remote) = listener.accept().await.unwrap();
            assert!(remote.ip().is_loopback());
            let mut sender_buffer = Vec::new();
            let mut receiver_buffer = Vec::new();
            let (sent_hello, received_hello) = tokio::join!(
                super::super::handshake(&mut sender, &mut sender_buffer, chain_id),
                super::super::handshake(&mut receiver, &mut receiver_buffer, chain_id),
            );
            sent_hello.unwrap();
            received_hello.unwrap();
            let bytes = wire::frame(&message, 7).unwrap();
            let (frames, mut received) = mpsc::channel(1);
            let (shutdown, shutdown_rx) = watch::channel(false);
            let reader = super::super::read_peer(
                receiver,
                receiver_buffer,
                frames,
                Arc::new(AtomicU64::new(0)),
                shutdown_rx,
            );
            let consumer = async {
                sender.write_all(&bytes).await.unwrap();
                let frame = received
                    .recv()
                    .await
                    .expect("peer reader closed before carrier");
                assert_eq!(frame.sent_at_nanos, 7);
                shutdown.send(true).unwrap();
                frame.message
            };
            let ((), carrier) = tokio::join!(reader, consumer);
            carrier
        })
        .await
        .expect("agreement carrier transfer timed out")
    })
}

#[test]
fn isolated_tcp_envelope_receipt_persists_neutral_proposal() {
    use net::wire::{self, Message};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let timeout = Duration::from_secs(5);
    let chain_id = b"isolated-agreement-test";

    // Exercise the real hello gate, including incompatible and foreign peers.
    for (protocol, peer_chain, expected) in [
        (16, chain_id.as_slice(), "protocol"),
        (wire::WIRE_PROTOCOL, b"other-chain".as_slice(), "chain"),
    ] {
        runtime.block_on(async {
            tokio::time::timeout(timeout, async {
                let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                    .await
                    .unwrap();
                let mut sender = TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                let (mut receiver, _) = listener.accept().await.unwrap();
                let hello = Message::Hello(wire::Hello {
                    protocol,
                    chain_id: peer_chain.to_vec(),
                });
                sender
                    .write_all(&wire::frame(&hello, 0).unwrap())
                    .await
                    .unwrap();
                let error = super::super::handshake(&mut receiver, &mut Vec::new(), chain_id)
                    .await
                    .unwrap_err();
                assert!(
                    error.contains(expected),
                    "unexpected hello rejection: {error}"
                );
            })
            .await
            .expect("hello rejection timed out");
        });
    }

    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    let history: Vec<_> = vertices.into_iter().filter(|v| v.round < 3).collect();
    let sender_dir = Dir::new();
    let sender_store = Store::open(&sender_dir.0).unwrap();
    let mut sender = Adapter::begin(&sender_store, bootstrap.clone(), &m, 0).unwrap();
    let mut node = authoring_node_index(&m, &history, 0);
    node.set_round(3);
    let authored = sender
        .author_proposal(&lineage.entries[0].proposal, &mut node)
        .unwrap()
        .unwrap();
    drop(sender);
    drop(sender_store);
    let sender_store = Store::open(&sender_dir.0).unwrap();
    let mut sender = Adapter::recover(&sender_store, bootstrap.clone(), &m, 0).unwrap();
    let publications = sender.completed_carriers().unwrap();
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].envelope, authored.envelope);
    assert_eq!(publications[0].vertex, authored.vertex);
    let envelope_bytes = publications[0].envelope.encode(&m.set).unwrap();
    let mut evidence = history;
    evidence.push(publications[0].vertex.clone());

    let mut available = validator::Dag::new(m.set.clone());
    for vertex in &evidence {
        available.insert(vertex.clone()).unwrap();
    }
    let id = authored.vertex.id().unwrap();
    let wal_sender = sender_dir.0.join("authenticated-slot-agreement");
    let before_export = std::fs::read(&wal_sender).unwrap();
    let sequence = sender.driver.sequence();
    let lost = sender.export_carrier(&id, &available).unwrap();
    let retry = sender.export_carrier(&id, &available).unwrap();
    assert_eq!(
        wire::frame(&lost, 0).unwrap(),
        wire::frame(&retry, 0).unwrap()
    );
    assert_eq!(sender.driver.sequence(), sequence);
    assert_eq!(std::fs::read(&wal_sender).unwrap(), before_export);
    assert!(
        sender
            .export_carrier(&id, &validator::Dag::new(m.set.clone()))
            .unwrap_err()
            .contains("missing ancestor")
    );
    let mut wrong = id.clone();
    wrong.digest[0] ^= 1;
    assert!(sender.export_carrier(&wrong, &available).is_err());
    drop(sender);
    drop(sender_store);
    let sender_store = Store::open(&sender_dir.0).unwrap();
    let mut sender = Adapter::recover(&sender_store, bootstrap.clone(), &m, 0).unwrap();
    let recovered = sender.export_carrier(&id, &available).unwrap();
    assert_eq!(
        wire::frame(&lost, 0).unwrap(),
        wire::frame(&recovered, 0).unwrap()
    );
    assert_eq!(std::fs::read(&wal_sender).unwrap(), before_export);
    let Message::AgreementCarrier { vertices: cone, .. } = &recovered else {
        unreachable!()
    };
    for missing in cone.iter().filter(|v| v.id().unwrap() != id) {
        let mut partial = Dag::new(m.set.clone());
        for vertex in cone.iter().filter(|v| *v != missing) {
            partial.insert(vertex.clone()).unwrap();
        }
        assert!(
            sender
                .export_carrier(&id, &partial)
                .unwrap_err()
                .contains("missing ancestor"),
            "must require ancestor at round {}",
            missing.round
        );
    }
    // A validly signed replacement at the same author/round is not the referenced ID.
    let ancestor = cone.iter().find(|v| v.round == 0).unwrap();
    let index = m
        .consensus
        .iter()
        .position(|v| v.id == ancestor.author)
        .unwrap();
    let replacement = signed(&m, index, 0, vec![], [73; 32]);
    let mut conflicting = Dag::new(m.set.clone());
    conflicting.insert(replacement).unwrap();
    for vertex in cone {
        conflicting.insert(vertex.clone()).unwrap();
    }
    assert!(
        sender
            .export_carrier(&id, &conflicting)
            .unwrap_err()
            .contains("digest mismatch")
    );
    let mut current = Adapter::recover(&sender_store, bootstrap.clone(), &m, 0).unwrap();
    current.author_view_request(AgreementView(9)).unwrap();
    assert!(
        sender.export_carrier(&id, &available).is_err(),
        "export must check stale ownership without scheduling"
    );
    assert_eq!(
        sender.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
    let received = tcp_agreement_message(recovered);

    let receiver_dir = Dir::new();
    let store = Store::open(&receiver_dir.0).unwrap();
    let mut receiver_bootstrap = bootstrap.clone();
    receiver_bootstrap.agreement.local_validator = m.consensus[1].id.clone();
    let mut receiver = Adapter::begin(&store, receiver_bootstrap.clone(), &m, 1).unwrap();
    let wal = receiver_dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    let rejected = receiver.receive_message(tcp_agreement_message(Message::AgreementCarrier {
        envelope: envelope_bytes[..envelope_bytes.len() - 1].to_vec(),
        vertices: evidence,
    }));
    assert!(rejected.is_err());
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    recover_envelope_adapter(&mut receiver, &store, &receiver_bootstrap, &m, 1);
    assert_eq!(receiver.driver.sequence(), 0);
    assert!(receiver.pending().is_empty());
    assert!(receiver.signing_history().is_empty());

    receiver.receive_message(received).unwrap();
    assert_eq!(receiver.driver.sequence(), 1);
    let persisted = std::fs::read(&wal).unwrap();
    assert_ne!(persisted, before);
    let output = format!("{:?}", receiver.driver.output().unwrap());
    drop(receiver);
    drop(store);
    let store = Store::open(&receiver_dir.0).unwrap();
    let mut receiver = Adapter::recover(&store, receiver_bootstrap, &m, 1).unwrap();
    assert_eq!(std::fs::read(&wal).unwrap(), persisted);
    assert_eq!(receiver.driver.sequence(), 1);
    assert_eq!(format!("{:?}", receiver.driver.output().unwrap()), output);
    let transition = receiver.driver.output().unwrap().transition.unwrap();
    assert_eq!(transition.view, AgreementView(0));
    assert!(transition.vote.is_none());
    assert!(transition.decision.is_none());
    assert!(receiver.pending().is_empty());
    assert!(receiver.signing_history().is_empty());
    assert!(receiver.completed_carriers().unwrap().is_empty());
    assert_eq!(
        receiver.readiness(),
        Readiness::DisabledMissingCausalReadinessAndTransport
    );
}

#[test]
fn proposal_and_view_durable_local_authoring_and_recovery() {
    let (m, bootstrap, request) = fixture();
    let AuthenticatedSlotAgreementRequest::Propose { lineage, vertices } = request else {
        unreachable!()
    };
    for is_view in [false, true] {
        let entry = &lineage.entries[0];
        let index = if is_view {
            m.consensus
                .iter()
                .position(|id| id.id == entry.view_carrier.author)
                .unwrap()
        } else {
            0
        };
        let mut bootstrap = bootstrap.clone();
        bootstrap.agreement.local_validator = m.consensus[index].id.clone();
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut adapter = Adapter::begin(&store, bootstrap.clone(), &m, index).unwrap();
        let round = if is_view { 4 } else { 3 };
        let history: Vec<_> = vertices
            .iter()
            .filter(|v| v.round < round)
            .cloned()
            .collect();
        let mut node = authoring_node_index(&m, &history, index);
        node.set_round(round);
        let candidate = validator::SlotAgreementViewCandidate::new(
            vec![],
            entry.proposal.clone(),
            entry.proposal_carrier.clone(),
            entry.view,
            &m.set,
        )
        .unwrap();
        let authored = if is_view {
            adapter.author_view(&candidate, &mut node)
        } else {
            adapter.author_proposal(&entry.proposal, &mut node)
        }
        .unwrap()
        .unwrap();
        check_envelope(&authored.envelope, &m.set);
        assert_eq!(adapter.driver.reserved_carriers().unwrap().len(), 1);
        assert_eq!(adapter.completed_carriers().unwrap().len(), 1);
        let mut all = history.clone();
        all.push(authored.vertex.clone());
        inspect_envelope(&authored.envelope, &m, &bootstrap, &all, &lineage);
        if !is_view {
            let sequence = adapter.driver.sequence();
            adapter
                .receive_envelope(authored.envelope.clone(), all)
                .unwrap();
            assert_eq!(adapter.driver.sequence(), sequence + 1);
            assert!(adapter.pending().is_empty());
            assert!(adapter.signing_history().is_empty());
            let transition = adapter.driver.output().unwrap().transition.unwrap();
            assert!(transition.vote.is_none());
            assert!(transition.decision.is_none());
        }
        let mut recovered = Adapter::recover(&store, bootstrap, &m, index).unwrap();
        let completed = recovered.completed_carriers().unwrap();
        assert_eq!(completed[0].vertex, authored.vertex);
        assert_eq!(completed[0].envelope, authored.envelope);
        // A changed reference cone at the reserved author/round cannot sign again.
        let mut conflicting = authoring_node_index(&m, &history, index);
        conflicting.set_round(round);
        let before = conflicting.authored();
        let result = if is_view {
            let wrong = validator::SlotAgreementViewCandidate::new(
                vec![],
                entry.proposal.clone(),
                entry.proposal_carrier.clone(),
                AgreementView(1),
                &m.set,
            )
            .unwrap();
            recovered.author_view(&wrong, &mut conflicting)
        } else {
            let mut wrong = entry.proposal.clone();
            wrong.decision.previous[0] ^= 1;
            recovered.author_proposal(&wrong, &mut conflicting)
        };
        assert!(result.is_err() || result.unwrap().is_none());
        assert_eq!(conflicting.authored(), before);
        assert_eq!(recovered.completed_carriers().unwrap().len(), 1);
    }
}

#[test]
fn pacemaker_nil_deadlines_publication_and_recovery_reset() {
    use pacemaker::{Action, Policy};
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut a = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let wait = Duration::from_secs(2);
    let policy = Policy::new(wait, wait, wait).unwrap();
    let now = Instant::now();
    assert_eq!(a.tick(now).unwrap(), None);
    a.configure_pacemaker(policy);
    assert_eq!(a.tick(now).unwrap(), None);
    assert_eq!(a.tick(now + wait - Duration::from_nanos(1)).unwrap(), None);
    assert_eq!(
        a.tick(now + wait).unwrap(),
        Some(Action::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
    );
    assert!(a.completed_nil_votes().unwrap().is_empty());
    let prevote = a.signing_history()[0].id;
    // Unpublished votes are not indefinite gates. Each observed stage gets a fresh wait.
    assert_eq!(a.tick(now + wait).unwrap(), None);
    assert_eq!(
        a.tick(now + wait * 2).unwrap(),
        Some(Action::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Precommit,
        })
    );
    assert_eq!(a.tick(now + wait * 2).unwrap(), None);
    assert_eq!(a.tick(now + wait * 2).unwrap(), None);
    assert!(a.author_nil_vote(prevote).unwrap().is_none());
    let precommit = a.signing_history()[1].id;
    a.author_nil_vote(precommit).unwrap().unwrap();
    assert_eq!(
        a.tick(now + wait * 3).unwrap(),
        Some(Action::AdvanceView {
            from: AgreementView(0)
        })
    );
    assert_eq!(a.tick(now + wait * 3).unwrap(), None);
    assert!(a.tick(now).is_err());
    drop(a);
    let mut a = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    assert_eq!(a.tick(now + wait * 100).unwrap(), None);
    a.configure_pacemaker(policy);
    assert_eq!(a.tick(now + wait * 100).unwrap(), None);
    assert_eq!(
        a.tick(now + wait * 101).unwrap(),
        Some(Action::Timeout {
            view: AgreementView(1),
            phase: AgreementPhase::Prevote,
        })
    );
    assert_eq!(a.signing_history().len(), 3);
}

#[test]
fn pacemaker_multi_adapter_nil_quorum_precommit_is_not_timed_out_again() {
    use pacemaker::{Action, Policy};
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut adapters: Vec<_> = stores
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            Adapter::begin(s, b, &m, i).unwrap()
        })
        .collect();
    let wait = Duration::from_secs(1);
    let now = Instant::now();
    let mut votes = Vec::new();
    for a in &mut adapters {
        a.configure_pacemaker(Policy::new(wait, wait, wait).unwrap());
        assert_eq!(a.tick(now).unwrap(), None);
        assert_eq!(
            a.tick(now + wait).unwrap(),
            Some(Action::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            })
        );
        votes.push(
            a.author_nil_vote(a.signing_history()[0].id)
                .unwrap()
                .unwrap(),
        );
    }
    let mut precommits = Vec::new();
    for a in &mut adapters {
        for vote in votes.iter().take(3) {
            a.receive_nil_vote(vote.clone()).unwrap();
        }
        assert_eq!(a.signing_history().len(), 2);
        assert_eq!(a.signing_history()[1].vote.phase, AgreementPhase::Precommit);
        assert_eq!(a.tick(now + wait).unwrap(), None);
        precommits.push(
            a.author_nil_vote(a.signing_history()[1].id)
                .unwrap()
                .unwrap(),
        );
    }
    for a in &mut adapters {
        for vote in &precommits {
            a.receive_nil_vote(vote.clone()).unwrap();
        }
        assert_eq!(a.tick(now + wait).unwrap(), None);
        assert_eq!(
            a.tick(now + wait * 2).unwrap(),
            Some(Action::AdvanceView {
                from: AgreementView(0)
            })
        );
        assert_eq!(a.tick(now + wait * 2).unwrap(), None);
        assert_eq!(a.signing_history().len(), 2);
        assert!(
            a.driver
                .output()
                .unwrap()
                .transition
                .unwrap()
                .decision
                .is_none()
        );
    }
}

#[test]
fn pacemaker_planner_resets_view_slot_and_idles_decided() {
    use pacemaker::{Action, Pacemaker, Policy, Snapshot};
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (_, bootstrap, _) = fixture();
    let wait = Duration::from_secs(1);
    assert!(Policy::new(Duration::ZERO, wait, wait).is_err());
    assert!(Policy::new(Duration::MAX, wait, wait).is_err());
    assert!(Policy::new(wait, wait, Duration::ZERO).is_err());
    assert!(Policy::new(wait, wait, Duration::MAX).is_err());
    let mut p = Pacemaker::new(Policy::new(wait, wait, wait).unwrap());
    let mut s = Snapshot {
        slot: bootstrap.agreement.context,
        view: AgreementView(0),
        prevote: false,
        precommit: false,
        decided: false,
    };
    let now = Instant::now();
    assert_eq!(p.plan(&s, now).unwrap(), None);
    s.view = AgreementView(1);
    assert_eq!(p.plan(&s, now + wait * 10).unwrap(), None);
    assert_eq!(
        p.plan(&s, now + wait * 11).unwrap(),
        Some(Action::Timeout {
            view: AgreementView(1),
            phase: AgreementPhase::Prevote,
        })
    );
    // A precommit emitted by evidence is authoritative even without a local prevote.
    s.precommit = true;
    assert_eq!(p.plan(&s, now + wait * 11).unwrap(), None);
    assert_eq!(
        p.plan(&s, now + wait * 12).unwrap(),
        Some(Action::AdvanceView {
            from: AgreementView(1)
        })
    );
    assert!(p.plan(&s, now).is_err());
    s.decided = true;
    assert_eq!(p.plan(&s, now + wait * 100).unwrap(), None);
    s.decided = false;
    assert_eq!(p.plan(&s, now + wait * 100).unwrap(), None);
    s.view = AgreementView(u64::MAX);
    assert_eq!(p.plan(&s, now + wait * 101).unwrap(), None);
    assert!(p.plan(&s, now + wait * 102).is_err());
}

#[test]
fn pacemaker_unpublished_nonnil_and_stale_owner() {
    use pacemaker::{Action, Policy};
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, request) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut a = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    a.apply(request).unwrap();
    assert_ne!(a.signing_history()[0].vote.value, AgreementValue::Nil);
    let wait = Duration::from_secs(1);
    let now = Instant::now();
    a.configure_pacemaker(Policy::new(wait, wait, wait).unwrap());
    assert_eq!(a.tick(now).unwrap(), None);
    assert_eq!(
        a.tick(now + wait).unwrap(),
        Some(Action::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Precommit,
        })
    );
    assert_eq!(a.tick(now + wait).unwrap(), None);
    assert_eq!(
        a.tick(now + wait * 2).unwrap(),
        Some(Action::AdvanceView {
            from: AgreementView(0)
        })
    );
    assert!(a.completed_carriers().unwrap().is_empty());
    let mut owner = Adapter::recover(&store, bootstrap, &m, 0).unwrap();
    owner
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(1),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let sequence = owner.driver.sequence();
    assert!(a.tick(now + wait * 2).is_err());
    assert_eq!(owner.driver.sequence(), sequence);
    assert_eq!(
        a.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
}

#[test]
fn pacemaker_future_nil_does_not_synchronize_a_slow_adapter() {
    use pacemaker::{Action, Policy};
    use std::time::{Duration, Instant};
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let fast_dir = Dir::new();
    let slow_dir = Dir::new();
    let fast_store = Store::open(&fast_dir.0).unwrap();
    let slow_store = Store::open(&slow_dir.0).unwrap();
    let mut fast = Adapter::begin(&fast_store, bootstrap.clone(), &m, 0).unwrap();
    let mut slow_bootstrap = bootstrap;
    slow_bootstrap.agreement.local_validator = m.consensus[1].id.clone();
    let mut slow = Adapter::begin(&slow_store, slow_bootstrap.clone(), &m, 1).unwrap();
    let wait = Duration::from_secs(1);
    let policy = Policy::new(wait, wait, wait).unwrap();
    let now = Instant::now();
    fast.configure_pacemaker(policy);
    for offset in [0, 1, 1, 2, 2, 3, 3, 4] {
        fast.tick(now + wait * offset).unwrap();
    }
    let future = fast.signing_history().last().unwrap();
    assert_eq!(future.vote.view, AgreementView(1));
    let future = fast.author_nil_vote(future.id).unwrap().unwrap();
    let sequence = slow.driver.sequence();
    assert!(slow.receive_nil_vote(future).is_err());
    assert_eq!(slow.driver.sequence(), sequence);
    assert!(slow.tick(now).is_err());
    let mut slow = Adapter::recover(&slow_store, slow_bootstrap, &m, 1).unwrap();
    assert_eq!(slow.timer_snapshot().unwrap().view, AgreementView(0));
    slow.configure_pacemaker(policy);
    assert_eq!(slow.tick(now + wait * 100).unwrap(), None);
    assert_eq!(
        slow.tick(now + wait * 101).unwrap(),
        Some(Action::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
    );
    assert_eq!(slow.timer_snapshot().unwrap().view, AgreementView(0));
}

#[test]
fn isolated_tcp_view_requests_certificate_catchup_and_duplicate_timeout() {
    use net::wire::Message;
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..5).map(|_| Dir::new()).collect();
    let mut requests = Vec::new();
    for (i, dir) in dirs[..3].iter().enumerate() {
        let store = Store::open(&dir.0).unwrap();
        let mut b = bootstrap.clone();
        b.agreement.local_validator = m.consensus[i].id.clone();
        let mut author = Adapter::begin(&store, b, &m, i).unwrap();
        let request = author.author_view_request(AgreementView(9)).unwrap();
        assert_eq!(
            author.completed_view_requests().unwrap(),
            vec![request.clone()]
        );
        requests.push(request.encode(&m.set).unwrap());
    }
    let store = Store::open(&dirs[3].0).unwrap();
    let mut receiver = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let wal = dirs[3].0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    for request in &requests[..m.set.quorum_size() - 1] {
        receiver
            .receive_message(tcp_agreement_message(Message::AgreementViewRequest(
                request.clone(),
            )))
            .unwrap();
    }
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    assert_eq!(receiver.driver.sequence(), 0);
    assert!(
        receiver.completed_view_requests().unwrap().is_empty(),
        "receipt must not sign an echo"
    );
    receiver
        .receive_message(tcp_agreement_message(Message::AgreementViewRequest(
            requests.last().unwrap().clone(),
        )))
        .unwrap();
    assert_eq!(receiver.driver.sequence(), 1);
    assert_ne!(std::fs::read(&wal).unwrap(), before);
    drop(receiver);
    drop(store);
    let store = Store::open(&dirs[3].0).unwrap();
    let receiver = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    let certificate: Vec<_> = receiver
        .entered_view_certificate()
        .unwrap()
        .unwrap()
        .iter()
        .map(|r| r.encode(&m.set).unwrap())
        .collect();
    assert_eq!(certificate.len(), m.set.quorum_size());
    let laggard_store = Store::open(&dirs[4].0).unwrap();
    let mut laggard = Adapter::begin(&laggard_store, bootstrap, &m, 0).unwrap();
    laggard
        .receive_message(tcp_agreement_message(Message::AgreementViewCertificate(
            certificate.clone(),
        )))
        .unwrap();
    assert_eq!(laggard.driver.sequence(), 1);
    let transition = laggard.driver.output().unwrap().transition.unwrap();
    assert_eq!(transition.view, AgreementView(9));
    assert!(transition.decision.is_none());
    assert!(laggard.signing_history().is_empty());
    laggard
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(9),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let intent = laggard.signing_history().last().unwrap().id;
    let nil = laggard.author_nil_vote(intent).unwrap().unwrap();
    let wal = dirs[4].0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    let output = format!("{:?}", laggard.driver.output().unwrap());
    laggard
        .receive_message(tcp_agreement_message(Message::AgreementViewCertificate(
            certificate,
        )))
        .unwrap();
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    assert_eq!(format!("{:?}", laggard.driver.output().unwrap()), output);
    assert_eq!(laggard.signing_history().len(), 1);
    assert_eq!(laggard.completed_nil_votes().unwrap()[0].message, nil);
    assert!(laggard.author_nil_vote(intent).unwrap().is_none());
}

#[test]
fn isolated_tcp_nil_quorum_obligations_survive_reopen_without_decision() {
    use net::wire::Message;
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let dirs: Vec<_> = (0..4).map(|_| Dir::new()).collect();
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut authors: Vec<_> = stores[..3]
        .iter()
        .enumerate()
        .map(|(i, store)| {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = m.consensus[i].id.clone();
            Adapter::begin(store, b, &m, i).unwrap()
        })
        .collect();
    let mut votes = Vec::new();
    for author in &mut authors {
        author
            .apply(AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            })
            .unwrap();
        let vote = author
            .author_nil_vote(author.signing_history()[0].id)
            .unwrap()
            .unwrap();
        votes.push(vote);
    }
    let mut receiver = Adapter::begin(&stores[3], bootstrap.clone(), &m, 0).unwrap();
    for vote in &votes[..2] {
        receiver
            .receive_message(tcp_agreement_message(Message::AgreementNilVote(
                vote.encode(&m.set).unwrap(),
            )))
            .unwrap();
    }
    assert!(receiver.signing_history().is_empty());
    let sequence = receiver.driver.sequence();
    drop(receiver);
    drop(authors);
    drop(stores);
    let stores: Vec<_> = dirs.iter().map(|d| Store::open(&d.0).unwrap()).collect();
    let mut receiver = Adapter::recover(&stores[3], bootstrap.clone(), &m, 0).unwrap();
    assert_eq!(receiver.driver.sequence(), sequence);
    receiver
        .receive_message(tcp_agreement_message(Message::AgreementNilVote(
            votes[2].encode(&m.set).unwrap(),
        )))
        .unwrap();
    assert_eq!(
        receiver.signing_history().len(),
        1,
        "the first two receipts must survive reopen"
    );
    let intent = receiver.signing_history()[0].clone();
    assert_eq!(intent.vote.phase, AgreementPhase::Precommit);
    assert_eq!(intent.vote.value, AgreementValue::Nil);
    assert!(receiver.completed_nil_votes().unwrap().is_empty());
    let precommit = receiver.author_nil_vote(intent.id).unwrap().unwrap();
    drop(receiver);
    let mut receiver = Adapter::recover(&stores[3], bootstrap, &m, 0).unwrap();
    assert_eq!(
        receiver.completed_nil_votes().unwrap()[0].message,
        precommit
    );
    let output = receiver.driver.output().unwrap();
    assert!(output.candidates.is_empty());
    let transition = output.transition.unwrap();
    assert_eq!(transition.view, AgreementView(0));
    assert!(transition.decision.is_none());
    assert!(receiver.completed_carriers().unwrap().is_empty());
}

#[test]
fn isolated_tcp_message_rejections_preserve_wal_and_check_stale_owner() {
    use net::wire::Message;
    let (m, bootstrap, _) = fixture();
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut receiver = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let mut foreign = bootstrap.clone();
    foreign.agreement.context = SlotDecisionTip::from_checkpoint(
        b"foreign-tcp-request".to_vec(),
        &m.set,
        1,
        [0; 32],
        0,
        [0; 32],
    )
    .unwrap();
    let wrong_context = signed_view_request(&m, &foreign, 1, 9)
        .encode(&m.set)
        .unwrap();
    let mut forged = signed_view_request(&m, &bootstrap, 1, 9)
        .encode(&m.set)
        .unwrap();
    *forged.last_mut().unwrap() ^= 1;
    let wal = dir.0.join("authenticated-slot-agreement");
    let before = std::fs::read(&wal).unwrap();
    for message in [
        Message::AgreementViewRequest(wrong_context),
        Message::AgreementViewRequest(forged),
        Message::AgreementViewCertificate(vec![vec![0]]),
        Message::Hello(net::wire::Hello {
            protocol: net::wire::WIRE_PROTOCOL,
            chain_id: b"isolated-agreement-test".to_vec(),
        }),
    ] {
        assert!(
            receiver
                .receive_message(tcp_agreement_message(message))
                .is_err()
        );
        assert_eq!(std::fs::read(&wal).unwrap(), before);
        recover_envelope_adapter(&mut receiver, &store, &bootstrap, &m, 0);
    }
    let mut owner = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
    owner
        .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        })
        .unwrap();
    let before = std::fs::read(&wal).unwrap();
    let request = signed_view_request(&m, &bootstrap, 1, 9)
        .encode(&m.set)
        .unwrap();
    assert!(
        receiver
            .receive_message(tcp_agreement_message(Message::AgreementViewRequest(
                request
            )))
            .is_err()
    );
    assert_eq!(std::fs::read(&wal).unwrap(), before);
    assert_eq!(
        receiver.readiness(),
        Readiness::RecoveryRequiredHistoricalIntentsUnavailable
    );
}

#[test]
fn isolated_tcp_malformed_messages_check_ownership_before_decode() {
    use net::wire::Message;
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    for malformed in [
        Message::AgreementViewRequest(vec![0]),
        Message::AgreementViewCertificate(vec![vec![0]]),
        Message::AgreementNilVote(vec![0]),
    ] {
        let dir = Dir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut stale = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
        stale
            .receive_view_request(signed_view_request(&m, &bootstrap, 1, 9))
            .unwrap();
        stale
            .apply(AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            })
            .unwrap();
        let support = stale.view_requests.clone();
        let history = format!("{:?}", stale.signing_history());
        let pending = format!("{:?}", stale.pending());
        let sequence = stale.driver.sequence();
        let mut owner = Adapter::recover(&store, bootstrap.clone(), &m, 0).unwrap();
        owner
            .apply(AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            })
            .unwrap();
        let ownership_error = stale.driver.output().unwrap_err().to_string();
        let wal = dir.0.join("authenticated-slot-agreement");
        let before = std::fs::read(&wal).unwrap();
        let malformed = tcp_agreement_message(malformed);
        // First receipt discovers stale ownership; the second exercises the latched
        // recovery-required boundary, both before attempting structural decoding.
        assert_eq!(
            stale.receive_message(malformed.clone()).unwrap_err(),
            ownership_error
        );
        assert_eq!(
            stale.readiness(),
            Readiness::RecoveryRequiredHistoricalIntentsUnavailable
        );
        assert_eq!(std::fs::read(&wal).unwrap(), before);
        assert_eq!(stale.view_requests, support);
        assert_eq!(format!("{:?}", stale.signing_history()), history);
        assert_eq!(format!("{:?}", stale.pending()), pending);
        assert_eq!(stale.driver.sequence(), sequence);
        assert_eq!(
            stale.receive_message(malformed).unwrap_err(),
            "agreement owner requires recovery before message receipt"
        );
        assert_eq!(std::fs::read(&wal).unwrap(), before);
        assert_eq!(stale.view_requests, support);
        assert_eq!(format!("{:?}", stale.signing_history()), history);
        assert_eq!(format!("{:?}", stale.pending()), pending);
        assert_eq!(stale.driver.sequence(), sequence);
    }
}

#[test]
fn isolated_tcp_invalid_certificate_tails_nil_authentication_and_kind_substitution_are_atomic() {
    use net::wire::Message;
    use validator::slot_agreement::AgreementPhase;
    let (m, bootstrap, _) = fixture();
    let mut foreign = bootstrap.clone();
    foreign.agreement.context = SlotDecisionTip::from_checkpoint(
        b"foreign-dispatch-evidence".to_vec(),
        &m.set,
        1,
        [0; 32],
        0,
        [0; 32],
    )
    .unwrap();
    let prefix: Vec<_> = (0..2)
        .map(|i| signed_view_request(&m, &bootstrap, i, 9))
        .collect();
    let valid_tail = signed_view_request(&m, &bootstrap, 2, 9);
    let mut signature = valid_tail.signature().clone();
    signature.signature[0] ^= 1;
    let forged_tail = validator::SlotAgreementViewRequest::new(
        bootstrap.agreement.context.clone(),
        AgreementView(9),
        signature,
        &m.set,
    )
    .unwrap();
    let mut messages = Vec::new();
    for tail in [
        forged_tail,
        signed_view_request(&m, &foreign, 2, 9),
        prefix[0].clone(),
        signed_view_request(&m, &bootstrap, 2, 8),
    ] {
        let certificate: Vec<_> = prefix
            .iter()
            .chain(std::iter::once(&tail))
            .map(|request| request.encode(&m.set).unwrap())
            .collect();
        messages.push(Message::AgreementViewCertificate(certificate));
    }
    let author_dir = Dir::new();
    let author_store = Store::open(&author_dir.0).unwrap();
    let mut author = Adapter::begin(&author_store, bootstrap.clone(), &m, 0).unwrap();
    author
        .apply(AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(0),
            phase: AgreementPhase::Prevote,
        })
        .unwrap();
    let nil = author
        .author_nil_vote(author.signing_history()[0].id)
        .unwrap()
        .unwrap();
    let mut signature = nil.signature().clone();
    signature.signature[0] ^= 1;
    let forged_nil =
        validator::SlotAgreementNilVote::new(nil.vote().clone(), signature, &m.set).unwrap();
    let mut foreign_vote = nil.vote().clone();
    foreign_vote.context = foreign.agreement.context.clone();
    let foreign_nil = validator::SlotAgreementNilVote::new(
        foreign_vote.clone(),
        ValidatorSignature {
            validator_id: m.consensus[0].id.clone(),
            key_id: m.set.validators[0].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(
                    &m.consensus[0].private_key,
                    &foreign_vote.signing_payload(&m.set).unwrap(),
                )
                .unwrap(),
        },
        &m.set,
    )
    .unwrap();
    messages.extend([
        Message::AgreementNilVote(forged_nil.encode(&m.set).unwrap()),
        Message::AgreementNilVote(foreign_nil.encode(&m.set).unwrap()),
        Message::AgreementViewRequest(nil.encode(&m.set).unwrap()),
        Message::AgreementNilVote(valid_tail.encode(&m.set).unwrap()),
    ]);
    let dir = Dir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut receiver = Adapter::begin(&store, bootstrap.clone(), &m, 0).unwrap();
    let wal = dir.0.join("authenticated-slot-agreement");
    for (case, message) in messages.into_iter().enumerate() {
        // Keep real existing support so rejected certificate prefixes cannot clear,
        // replace, or extend the collection. Recovery may discard it between cases.
        receiver
            .receive_view_request(signed_view_request(&m, &bootstrap, 3, 7))
            .unwrap();
        let before = std::fs::read(&wal).unwrap();
        let support = receiver.view_requests.clone();
        let history = format!("{:?}", receiver.signing_history());
        let pending = format!("{:?}", receiver.pending());
        let sequence = receiver.driver.sequence();
        assert!(
            receiver
                .receive_message(tcp_agreement_message(message))
                .is_err(),
            "rejection case {case}"
        );
        assert_eq!(std::fs::read(&wal).unwrap(), before, "WAL case {case}");
        assert_eq!(receiver.view_requests, support, "support case {case}");
        assert_eq!(
            format!("{:?}", receiver.signing_history()),
            history,
            "history case {case}"
        );
        assert_eq!(
            format!("{:?}", receiver.pending()),
            pending,
            "pending case {case}"
        );
        assert_eq!(receiver.driver.sequence(), sequence, "sequence case {case}");
        recover_envelope_adapter(&mut receiver, &store, &bootstrap, &m, 0);
    }
}

include!("local_authoring_tests.rs");
