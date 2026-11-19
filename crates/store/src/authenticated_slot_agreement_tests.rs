use super::*;
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use validator::slot_agreement::{AgreementPhase, AgreementView};
use validator::{SlotAgreementProofEntry, SlotAgreementViewLineage};

pub(super) fn fixture(
    commit: bool,
) -> (
    Fixture,
    SlotAgreementViewLineage,
    AuthenticatedSlotAgreementBootstrap,
) {
    let mut f = Fixture::new(commit);
    f.vertices.retain(|v| v.round < 4);
    let mut lineage = SlotAgreementViewLineage {
        entries: vec![SlotAgreementProofEntry {
            proposal: f.payload.proposal.clone().into(),
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
    let refs: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect();
    for id in 0..4 {
        let hash = if id == author {
            lineage.view_digest(0).unwrap()
        } else {
            [9; 32]
        };
        let vertex = signed_vertex(&f.keys, id, 4, refs.clone(), hash);
        if id == author {
            lineage.entries[0].view_carrier = vertex.id().unwrap();
        }
        f.vertices.push(vertex);
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
fn an_exact_repeated_view_receipt_replays_as_a_durable_no_op() {
    let (f, lineage, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let request = AuthenticatedSlotAgreementRequest::Propose {
        lineage,
        vertices: f.vertices,
    };
    let first = owner.apply(1, request.clone()).unwrap();
    assert!(
        matches!(
            first.vote,
            Some(ref vote) if vote.phase == AgreementPhase::Prevote
        ),
        "a view authorization emits the local prevote"
    );
    let sequence = owner.sequence();
    assert_eq!(sequence, 1);
    let outbox = format!("{:?}", owner.signing_outbox().unwrap());
    // A self-delivered publication may also be echoed by a peer, and a carrier retransmission
    // repeats evidence the peer already holds. The repeated receipt is journaled but must
    // replay as a no-op instead of emitting the prevote a second time.
    let repeated = owner.apply(sequence + 1, request).unwrap();
    assert!(repeated.vote.is_none(), "a repeated receipt emits no vote");
    assert_eq!(owner.sequence(), sequence + 1);
    assert_eq!(
        format!("{:?}", owner.signing_outbox().unwrap()),
        outbox,
        "state is unchanged"
    );
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let recovered = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(recovered.sequence(), sequence + 1);
    assert_eq!(format!("{:?}", recovered.signing_outbox().unwrap()), outbox);
}

#[test]
fn a_retransmitted_view_authorization_with_a_new_cone_is_a_durable_no_op() {
    let (f, lineage, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let first = owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage: lineage.clone(),
                vertices: f.vertices,
            },
        )
        .unwrap();
    assert!(
        matches!(
            first.vote,
            Some(ref vote) if vote.phase == AgreementPhase::Prevote
        ),
        "a view authorization emits the local prevote"
    );
    let outbox = format!("{:?}", owner.signing_outbox().unwrap());
    // A retransmission of the same authorized view can carry a different availability cone,
    // so the encoded receipt differs and byte-exact dedupe does not apply. The local prevote
    // was already emitted for exactly this inspected decision, so replay must journal the
    // receipt without emitting a second vote.
    let repeated = owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: Vec::new(),
            },
        )
        .unwrap();
    assert!(
        repeated.vote.is_none(),
        "a retransmitted view authorization emits no second prevote"
    );
    assert_eq!(owner.sequence(), 2);
    assert_eq!(format!("{:?}", owner.signing_outbox().unwrap()), outbox);
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let recovered = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(recovered.sequence(), 2);
    assert_eq!(format!("{:?}", recovered.signing_outbox().unwrap()), outbox);
}

#[test]
fn execution_checkpoint_stays_with_signing_root_across_generation_activation() {
    let (_, _, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let mut store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    owner
        .put_execution_checkpoint(&[], 0, b"local state")
        .unwrap();
    let staged = store.stage().unwrap();
    assert!(
        !staged
            .store()
            .root
            .join("agreement-execution-checkpoint")
            .exists()
    );
    staged.activate().unwrap();
    assert_eq!(
        owner.execution_checkpoint().unwrap().unwrap().state(),
        b"local state"
    );
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(
        owner.execution_checkpoint().unwrap().unwrap().state(),
        b"local state"
    );
}

#[test]
fn execution_checkpoint_rejects_conflicts_stale_owners_and_corruption() {
    let (f, lineage, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    assert!(owner.execution_checkpoint().unwrap().is_none());
    owner
        .put_execution_checkpoint(&[], 0, b"initial state")
        .unwrap();
    let path = dir.0.join("agreement-execution-checkpoint");
    let bytes = fs::read(&path).unwrap();
    owner
        .put_execution_checkpoint(&[], 0, b"initial state")
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert!(
        owner
            .put_execution_checkpoint(&[], 0, b"changed state")
            .is_err()
    );
    assert!(
        owner
            .put_execution_checkpoint(&[], 1, b"initial state")
            .is_err()
    );
    assert!(
        owner
            .put_execution_checkpoint(&[f.vertices[0].id().unwrap()], 0, b"state")
            .is_err()
    );
    assert!(
        owner
            .put_execution_checkpoint(&[], 0, &vec![0; 2 * 1024 * 1024 + 1])
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let mut stale = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: f.vertices,
            },
        )
        .unwrap();
    assert!(stale.execution_checkpoint().is_err());
    assert!(
        stale
            .put_execution_checkpoint(&[], 0, b"initial state")
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
    drop(stale);
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    let restored = owner.execution_checkpoint().unwrap().unwrap();
    assert!(restored.order().is_empty());
    assert_eq!(restored.applied(), 0);
    assert_eq!(restored.state(), b"initial state");
    let mut corrupt = bytes;
    corrupt[0] ^= 1;
    fs::write(&path, &corrupt).unwrap();
    assert!(owner.execution_checkpoint().is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupt);
}

#[test]
fn ordering_snapshot_tracks_only_applied_certified_prefix_and_recovers() {
    for committing in [true, false] {
        let (f, proof, carrier) = crate::slot_application_tests::unified_fixture(committing);
        let decision = proof.entries.last().unwrap().proposal.decision.clone();
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
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        assert!(owner.ordering_snapshot().unwrap().order().is_empty());
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::ObservePrecommit {
                    proof,
                    carrier: carrier.clone(),
                    vertices: f.vertices.clone(),
                },
            )
            .unwrap();
        let before = owner.ordering_snapshot().unwrap();
        assert!(
            before.order().is_empty(),
            "a decision is not an applied slot"
        );
        assert!(before.applications().is_empty());
        assert_eq!(before.checkpoint_binding(), before.binding());
        assert_eq!(before.binding().tip(), &bootstrap.agreement.context);
        let stale = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        owner.advance_slot(2).unwrap();
        assert!(
            stale.ordering_snapshot().is_err(),
            "snapshots enforce freshness"
        );
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let wal = fs::read(&path).unwrap();
        let applied = owner.ordering_snapshot().unwrap();
        assert_eq!(applied.checkpoint_binding(), before.checkpoint_binding());
        assert_eq!(applied.applications().len(), 1);
        let boundary = &applied.applications()[0];
        assert_eq!(boundary.round(), decision.round);
        assert_eq!(boundary.order_len(), applied.order().len());
        assert_eq!(boundary.is_commit(), committing);
        assert_eq!(applied.order().len() as u64, decision.after_len);
        assert_eq!(validator::commit_root(applied.order()), decision.after_root);
        assert_eq!(applied.binding().tip().order_len(), decision.after_len);
        assert_eq!(applied.binding().tip().order_root(), &decision.after_root);
        assert_eq!(applied.binding().tip().next_round(), decision.round + 1);
        assert_eq!(applied.binding().carrier(), Some(&carrier));
        assert_eq!(applied.order().is_empty(), !committing);
        if committing {
            owner
                .put_execution_checkpoint(&applied.order()[..1], 1, b"partial")
                .unwrap();
            let checkpoint = fs::read(dir.0.join("agreement-execution-checkpoint")).unwrap();
            assert!(owner.put_execution_checkpoint(&[], 0, b"initial").is_err());
            assert!(
                owner
                    .put_execution_checkpoint(applied.order(), 0, b"regressed count")
                    .is_err()
            );
            assert_eq!(
                fs::read(dir.0.join("agreement-execution-checkpoint")).unwrap(),
                checkpoint
            );
        }
        let ids: Vec<_> = applied.vertices().iter().map(|v| v.id().unwrap()).collect();
        assert_eq!(ids, applied.order());
        for vertex in applied.vertices() {
            assert!(
                f.vertices.contains(vertex),
                "snapshot retains exact signed bytes"
            );
        }
        assert_eq!(
            fs::read(&path).unwrap(),
            wal,
            "snapshot getter never writes"
        );
        drop(stale);
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        let recovered = owner.ordering_snapshot().unwrap();
        assert_eq!(recovered.applications(), applied.applications());
        assert_eq!(format!("{recovered:?}"), format!("{applied:?}"));
        assert_eq!(fs::read(&path).unwrap(), wal);
        let mut torn = wal.clone();
        torn.push(1);
        fs::write(&path, &torn).unwrap();
        assert!(
            owner.ordering_snapshot().is_err(),
            "corrupt WAL cannot export ordering"
        );
        assert_eq!(
            fs::read(&path).unwrap(),
            torn,
            "failed read does not repair the WAL"
        );
        // A nonempty trusted checkpoint prefix is included, not only new commits.
        let checkpoint = AuthenticatedSlotAgreementBootstrap {
            agreement: SlotAgreementBootstrap {
                context: applied.binding().tip().clone(),
                set: f.set.clone(),
                local_validator: f.set.validators[0].validator_id.clone(),
            },
            predecessor: Some(carrier),
            order: applied.order().to_vec(),
            vertices: f.vertices,
        };
        let next_dir = TempDir::new();
        let next_store = Store::open(&next_dir.0).unwrap();
        let next_owner = next_store
            .begin_authenticated_slot_agreement(checkpoint)
            .unwrap();
        let checkpoint_snapshot = next_owner.ordering_snapshot().unwrap();
        assert_eq!(checkpoint_snapshot.binding(), applied.binding());
        assert_eq!(checkpoint_snapshot.checkpoint_binding(), applied.binding());
        assert_eq!(checkpoint_snapshot.order(), applied.order());
        assert_eq!(checkpoint_snapshot.vertices(), applied.vertices());
        assert!(checkpoint_snapshot.applications().is_empty());
    }
}

#[test]
fn observe_plain_proposal_retains_without_voting_and_recovers() {
    let (f, lineage, bootstrap) = fixture(true);
    let selected = &lineage.entries[0];
    let request = AuthenticatedSlotAgreementRequest::ObserveProposal {
        proposal: selected.proposal.clone(),
        carrier: selected.proposal_carrier.clone(),
        vertices: f
            .vertices
            .iter()
            .filter(|v| v.round <= selected.proposal_carrier.round)
            .cloned()
            .collect(),
    };
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let before = fs::read(&path).unwrap();
    for kind in 0..5 {
        let mut bad = request.clone();
        let AuthenticatedSlotAgreementRequest::ObserveProposal {
            proposal,
            carrier,
            vertices,
        } = &mut bad
        else {
            unreachable!()
        };
        match kind {
            0 => carrier.digest[0] ^= 1,
            1 => {
                let signed = vertices
                    .iter_mut()
                    .find(|v| v.id().unwrap() == *carrier)
                    .unwrap();
                signed.signature[0] ^= 1;
            }
            2 => proposal.decision.round += 1,
            3 => {
                let signed = vertices
                    .iter_mut()
                    .find(|v| v.id().unwrap() == *carrier)
                    .unwrap();
                let author = f
                    .set
                    .validators
                    .iter()
                    .position(|v| v.validator_id == signed.author)
                    .unwrap();
                *signed = signed_vertex(
                    &f.keys,
                    author,
                    signed.round,
                    signed.references.clone(),
                    [42; 32],
                );
                *carrier = signed.id().unwrap();
            }
            _ => {
                // A pinned foreign chain cannot authenticate otherwise valid evidence.
                proposal.decision.chain_id.push(1);
            }
        }
        assert!(owner.apply(1, bad).is_err(), "invalid observation {kind}");
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let neutral = owner.apply(1, request.clone()).unwrap();
    assert!(neutral.vote.is_none());
    assert!(neutral.decision.is_none());
    assert_eq!(neutral.view, AgreementView(0));
    assert!(owner.signing_outbox().unwrap().is_empty());
    assert!(owner.reserved_carriers().unwrap().is_empty());
    drop(owner);
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert!(owner.apply(1, request).unwrap().vote.is_none());
    assert!(owner.signing_outbox().unwrap().is_empty());
    let accepted = owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage: lineage.clone(),
                vertices: f
                    .vertices
                    .iter()
                    .filter(|v| v.round > selected.proposal_carrier.round)
                    .cloned()
                    .collect(),
            },
        )
        .unwrap();
    assert_eq!(
        accepted.vote.as_ref().unwrap().phase,
        AgreementPhase::Prevote
    );
    assert_eq!(owner.signing_outbox().unwrap().len(), 1);
    let preserved = owner
        .apply(
            3,
            AuthenticatedSlotAgreementRequest::ObserveProposal {
                proposal: selected.proposal.clone(),
                carrier: selected.proposal_carrier.clone(),
                vertices: vec![],
            },
        )
        .unwrap();
    assert_eq!(preserved, accepted);
    assert_eq!(owner.signing_outbox().unwrap().len(), 1);
}

#[test]
fn presign_proposal_view_recovery_and_view_first_wins() {
    for view in [false, true] {
        let (f, lineage, mut bootstrap) = fixture(true);
        let selected = &lineage.entries[0];
        let id = if view {
            &selected.view_carrier
        } else {
            &selected.proposal_carrier
        };
        let signed = f
            .vertices
            .iter()
            .find(|v| v.id().unwrap() == *id)
            .unwrap()
            .clone();
        bootstrap.agreement.local_validator = signed.author.clone();
        let mut unsigned = signed.clone();
        unsigned.signature.clear();
        let evidence = if view {
            AgreementCarrierEvidence::View {
                lineage: lineage.clone(),
            }
        } else {
            AgreementCarrierEvidence::Proposal {
                proposal: selected.proposal.clone(),
            }
        };
        let request = AuthenticatedSlotAgreementRequest::ReserveCarrier {
            evidence,
            unsigned: unsigned.clone(),
            vertices: f
                .vertices
                .iter()
                .filter(|v| v.round < signed.round)
                .cloned()
                .collect(),
        };
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let mut bad = request.clone();
        if let AuthenticatedSlotAgreementRequest::ReserveCarrier { unsigned, .. } = &mut bad {
            unsigned.signature = signed.signature.clone();
        }
        assert!(owner.apply(1, bad).is_err());
        if view {
            let mut bad = request.clone();
            if let AuthenticatedSlotAgreementRequest::ReserveCarrier {
                evidence: AgreementCarrierEvidence::View { lineage },
                ..
            } = &mut bad
            {
                lineage.entries[0].view_carrier.digest[0] ^= 1;
            }
            assert!(owner.apply(1, bad).is_err());
        }
        owner.apply(1, request.clone()).unwrap();
        owner.apply(1, request.clone()).unwrap();
        assert!(owner.apply(2, request.clone()).is_err());
        if view {
            let mut conflict = request;
            if let AuthenticatedSlotAgreementRequest::ReserveCarrier {
                unsigned,
                evidence: AgreementCarrierEvidence::View { lineage },
                ..
            } = &mut conflict
            {
                unsigned.round += 1;
                lineage.entries[0].view_carrier = unsigned.id().unwrap();
            }
            assert!(owner.apply(2, conflict).is_err());
        }
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::CompleteCarrier {
                    reservation_sequence: 1,
                    signed: signed.clone(),
                },
            )
            .unwrap();
        drop(owner);
        let recovered = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(recovered.reserved_carriers().unwrap().len(), 1);
        assert_eq!(recovered.completed_carriers().unwrap()[0].signed, signed);
        assert!(recovered.signing_outbox().unwrap().is_empty());
    }
}

#[test]
fn authenticated_commit_skip_restart_and_exact_envelope() {
    for commit in [true, false] {
        let (f, lineage, bootstrap) = fixture(commit);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let request = AuthenticatedSlotAgreementRequest::Propose {
            lineage: lineage.clone(),
            vertices: f.vertices.clone(),
        };
        let result = owner.apply(1, request.clone()).unwrap();
        assert_eq!(result.vote.as_ref().unwrap().phase, AgreementPhase::Prevote);
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let bytes = fs::read(&path).unwrap();
        let mut wrong = lineage.clone();
        wrong.entries[0].view_carrier.digest[0] ^= 1;
        assert!(
            owner
                .apply(
                    2,
                    AuthenticatedSlotAgreementRequest::Propose {
                        lineage: wrong,
                        vertices: vec![]
                    }
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(
            owner
                .apply(
                    1,
                    AuthenticatedSlotAgreementRequest::Propose {
                        lineage,
                        vertices: vec![]
                    }
                )
                .is_err()
        );
        drop(f);
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.apply(1, request).unwrap().vote, result.vote);
        assert_eq!(fs::read(path).unwrap(), bytes);
    }
}
#[test]
fn authenticated_legacy_exclusion_and_stage() {
    let (f, lineage, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let mut store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    assert!(
        store
            .begin_slot_agreement(bootstrap.agreement.clone())
            .is_err()
    );
    assert!(
        store
            .recover_slot_agreement(bootstrap.agreement.clone(), |_| Ok(()))
            .is_err()
    );
    assert!(
        store
            .recover_slot_agreement_validated(bootstrap.agreement.clone(), |_| Ok(()), |_| Ok(()))
            .is_err()
    );
    assert!(
        store
            .lock_slot_decision(&f.payload.proposal.decision)
            .is_err()
    );
    let stage = store.stage().unwrap();
    assert!(
        !stage
            .view
            .root
            .join(authenticated_slot_agreement::FILE)
            .exists()
    );
    assert!(!stage.view.root.join(slot_agreement_journal::FILE).exists());
    assert!(
        stage
            .view
            .begin_slot_agreement(bootstrap.agreement.clone())
            .is_err()
    );
    drop(stage);
    owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: f.vertices,
            },
        )
        .unwrap();
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    store
        .begin_slot_agreement(bootstrap.agreement.clone())
        .unwrap();
    assert!(store.begin_authenticated_slot_agreement(bootstrap).is_err());
}
#[test]
fn authenticated_missing_dependency_and_uncertain_write() {
    let (f, lineage, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let before = fs::read(&path).unwrap();
    assert!(
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage: lineage.clone(),
                    vertices: f.vertices[1..].to_vec()
                }
            )
            .is_err()
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    let request = AuthenticatedSlotAgreementRequest::Propose {
        lineage,
        vertices: f.vertices,
    };
    assert!(
        owner
            .apply_with_io(
                1,
                request.clone(),
                |file, bytes| Ok(file.write_all(bytes)?),
                |_, _| Err(std::io::Error::other("injected barrier failure").into())
            )
            .is_err()
    );
    assert!(owner.apply(1, request.clone()).is_err());
    assert!(
        owner.ordering_snapshot().is_err(),
        "uncertain writes cannot export ordering"
    );
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert!(owner.apply(1, request).unwrap().vote.is_some());
    assert!(
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Prevote
                }
            )
            .is_err()
    );
}

#[test]
fn authenticated_signed_precommit_survives_all_history_loss() {
    use crypto::scheme::Ed25519Scheme;
    use validator::slot_agreement::AgreementQc;
    use validator::{
        SlotAgreementProofPol, SlotAgreementVotePayload, SlotAgreementVoteWitness,
        ValidatorSignature,
    };
    for commit in [true, false] {
        let (mut f, mut lineage, bootstrap) = fixture(commit);
        let dirs: Vec<_> = (0..3).map(|_| TempDir::new()).collect();
        let mut signatures = Vec::new();
        let mut vote = None;
        for (id, dir) in dirs.iter().enumerate() {
            let mut b = bootstrap.clone();
            b.agreement.local_validator = f.set.validators[id].validator_id.clone();
            let store = Store::open(&dir.0).unwrap();
            let mut session = store.begin_authenticated_slot_agreement(b).unwrap();
            let emitted = session
                .apply(
                    1,
                    AuthenticatedSlotAgreementRequest::Propose {
                        lineage: lineage.clone(),
                        vertices: f.vertices.clone(),
                    },
                )
                .unwrap()
                .vote
                .unwrap();
            signatures.push(ValidatorSignature {
                validator_id: f.set.validators[id].validator_id.clone(),
                key_id: f.set.validators[id].keys[0].key_id.clone(),
                signature: Ed25519Scheme
                    .sign(&f.keys[id], &emitted.signing_payload(&f.set).unwrap())
                    .unwrap(),
            });
            vote = Some(emitted);
        }
        let qc = AgreementQc {
            vote: vote.unwrap(),
            signatures,
        };
        let refs: Vec<_> = f
            .vertices
            .iter()
            .filter(|v| v.round == 4)
            .map(|v| v.id().unwrap())
            .collect();
        let mut witnesses = Vec::new();
        let mut next = Vec::new();
        for (id, signature) in qc.signatures.iter().enumerate() {
            let payload = SlotAgreementVotePayload {
                vote: qc.vote.clone(),
                signature: signature.clone(),
                prerequisite: lineage.entries[0].view_carrier.clone(),
            };
            let vertex = signed_vertex(
                &f.keys,
                id,
                5,
                refs.clone(),
                payload.digest(&f.set).unwrap(),
            );
            let carrier = vertex.id().unwrap();
            next.push(carrier.clone());
            f.vertices.push(vertex);
            witnesses.push(SlotAgreementVoteWitness { payload, carrier });
        }
        lineage.entries[0].pol = Some(SlotAgreementProofPol {
            certificate: qc,
            votes: witnesses,
            carrier: f.payload.proposal_carrier.clone(),
        });
        let vertex = signed_vertex(&f.keys, 0, 6, next, lineage.pol_digest(0, &f.set).unwrap());
        lineage.entries[0].pol.as_mut().unwrap().carrier = vertex.id().unwrap();
        f.vertices.push(vertex);
        let request = AuthenticatedSlotAgreementRequest::ObservePrevote {
            lineage,
            vertices: f.vertices.clone(),
        };
        let store = Store::open(&dirs[0].0).unwrap();
        let mut session = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let result = session.apply(2, request.clone()).unwrap();
        assert_eq!(
            result.vote.as_ref().unwrap().phase,
            AgreementPhase::Precommit
        );
        drop(session);
        drop(store);
        drop(f);
        let store = Store::open(&dirs[0].0).unwrap();
        let mut session = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(session.apply(2, request).unwrap(), result);
        assert_eq!(session.sequence(), 2);
    }
}

#[test]
fn authenticated_stale_checkpoint_bounds_and_torn_write_fail_closed() {
    let (_, _, bootstrap) = fixture(false);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let mut stale = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let timeout = AuthenticatedSlotAgreementRequest::Timeout {
        view: AgreementView(0),
        phase: AgreementPhase::Prevote,
    };
    owner.apply(1, timeout.clone()).unwrap();
    assert!(stale.apply(1, timeout).is_err());
    owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    let mut wrong = bootstrap.clone();
    wrong.predecessor = Some(validator::VertexId {
        round: 0,
        author: b"val-0".to_vec(),
        digest: [8; 32],
    });
    assert!(store.recover_authenticated_slot_agreement(wrong).is_err());
    let request = AuthenticatedSlotAgreementRequest::Timeout {
        view: AgreementView(1),
        phase: AgreementPhase::Prevote,
    };
    assert!(
        owner
            .apply_with_io(
                3,
                request.clone(),
                |file, bytes| {
                    file.write_all(&bytes[..7])?;
                    Err(std::io::Error::other("injected partial write").into())
                },
                |_, _| Ok(())
            )
            .is_err()
    );
    assert!(owner.apply(3, request).is_err());
    drop(owner);
    drop(stale);
    drop(store);
    assert!(Store::open(&dir.0).is_err());
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut wrong = bootstrap.clone();
    wrong.order.push(validator::VertexId {
        round: 0,
        author: b"val-0".to_vec(),
        digest: [8; 32],
    });
    assert!(store.begin_authenticated_slot_agreement(wrong).is_err());
    assert!(!dir.0.join(authenticated_slot_agreement::FILE).exists());
    fs::write(dir.0.join(slot_decision_journal::FILE), []).unwrap();
    assert!(store.begin_authenticated_slot_agreement(bootstrap).is_err());
}

#[test]
fn verified_replay_cache_revalidates_ownership_and_refreshes_on_append() {
    let (_, _, bootstrap) = fixture(false);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let mut sibling = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let timeout = AuthenticatedSlotAgreementRequest::Timeout {
        view: AgreementView(0),
        phase: AgreementPhase::Prevote,
    };

    // The first read verifies the journal and retains that replay; repeated reads must
    // return exactly the same durable state instead of a fresh unverified snapshot.
    let cached = owner.ordering_snapshot().unwrap();
    assert!(cached.order().is_empty());
    assert!(cached.applications().is_empty());
    assert!(owner.signing_outbox().unwrap().is_empty());
    assert_eq!(owner.binding().unwrap().tip(), cached.binding().tip());

    // A sibling recovery that does not append leaves bytes and tip unchanged, so the
    // verified cache stays valid rather than failing closed for unrelated activity.
    let refreshed = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    assert!(owner.ordering_snapshot().is_ok());
    drop(refreshed);

    // A sibling append changes the journal's byte length. The cached owner must not
    // serve its verified prefix as if it were current; every read and writer fails closed.
    sibling.apply(1, timeout.clone()).unwrap();
    assert_eq!(sibling.sequence(), 1);
    assert_eq!(sibling.signing_outbox().unwrap().len(), 1);
    assert_eq!(owner.sequence(), 0);
    assert!(owner.ordering_snapshot().is_err());
    assert!(owner.signing_outbox().is_err());
    assert!(owner.completed_carriers().is_err());
    assert!(owner.entered_view_certificate().is_err());
    assert!(owner.view_request_reservations().is_err());
    assert!(owner.binding().is_err());
    assert!(owner.header_intents().is_err());
    assert!(owner.execution_checkpoint().is_err());
    assert!(owner.apply(1, timeout).is_err());

    // A local append replaces the cache with the replay of the new full journal, so the
    // advancing owner can keep reading without reloading on every getter.
    let mut advancing = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    advancing
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    assert_eq!(advancing.sequence(), 2);
    assert_eq!(advancing.signing_outbox().unwrap().len(), 1);
    assert!(advancing.ordering_snapshot().is_ok());

    // Recovery re-authenticates the whole journal and seeds the new owner's cache.
    let recovered = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(recovered.sequence(), 2);
    assert_eq!(recovered.signing_outbox().unwrap().len(), 1);
    assert!(recovered.ordering_snapshot().unwrap().order().is_empty());
}

#[test]
fn incremental_append_fold_matches_full_recovery_at_every_step() {
    // Each append folds only the new event over the cached verified prefix. A second owner
    // that recovers from disk folds the whole journal instead: the two must never diverge.
    let (f, lineage, bootstrap) = fixture(true);
    let selected = &lineage.entries[0];
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let proposal = AuthenticatedSlotAgreementRequest::ObserveProposal {
        proposal: selected.proposal.clone(),
        carrier: selected.proposal_carrier.clone(),
        vertices: f
            .vertices
            .iter()
            .filter(|v| v.round <= selected.proposal_carrier.round)
            .cloned()
            .collect(),
    };
    let propose = AuthenticatedSlotAgreementRequest::Propose {
        lineage: lineage.clone(),
        vertices: f
            .vertices
            .iter()
            .filter(|v| v.round > selected.proposal_carrier.round)
            .cloned()
            .collect(),
    };
    let requests = vec![
        proposal,
        propose,
        AuthenticatedSlotAgreementRequest::ObserveProposal {
            proposal: selected.proposal.clone(),
            carrier: selected.proposal_carrier.clone(),
            vertices: vec![],
        },
        AuthenticatedSlotAgreementRequest::AdvanceView {
            from: AgreementView(0),
        },
        AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(1),
            phase: AgreementPhase::Prevote,
        },
        AuthenticatedSlotAgreementRequest::Timeout {
            view: AgreementView(1),
            phase: AgreementPhase::Precommit,
        },
    ];
    for (offset, request) in requests.into_iter().enumerate() {
        let sequence = offset as u64 + 1;
        owner.apply(sequence, request).unwrap();
        let full = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let folded = owner.ordering_snapshot().unwrap();
        let recovered = full.ordering_snapshot().unwrap();
        assert_eq!(folded.order(), recovered.order(), "step {sequence} order");
        assert_eq!(
            folded.applications(),
            recovered.applications(),
            "step {sequence} applications"
        );
        assert_eq!(
            folded.binding(),
            recovered.binding(),
            "step {sequence} binding"
        );
        assert_eq!(
            folded.vertices(),
            recovered.vertices(),
            "step {sequence} vertices"
        );
        assert_eq!(
            owner.binding().unwrap(),
            full.binding().unwrap(),
            "step {sequence} active binding"
        );
        assert_eq!(
            owner
                .signing_outbox()
                .unwrap()
                .iter()
                .map(|intent| intent.id)
                .collect::<Vec<_>>(),
            full.signing_outbox()
                .unwrap()
                .iter()
                .map(|intent| intent.id)
                .collect::<Vec<_>>(),
            "step {sequence} intents"
        );
        assert_eq!(
            owner
                .reserved_carriers()
                .unwrap()
                .iter()
                .map(|reserved| reserved.id.clone())
                .collect::<Vec<_>>(),
            full.reserved_carriers()
                .unwrap()
                .iter()
                .map(|reserved| reserved.id.clone())
                .collect::<Vec<_>>(),
            "step {sequence} reservations"
        );
        assert_eq!(
            owner
                .completed_carriers()
                .unwrap()
                .iter()
                .map(|completed| completed.reservation.id.clone())
                .collect::<Vec<_>>(),
            full.completed_carriers()
                .unwrap()
                .iter()
                .map(|completed| completed.reservation.id.clone())
                .collect::<Vec<_>>(),
            "step {sequence} completions"
        );
        assert_eq!(
            owner.completed_nil_votes().unwrap(),
            full.completed_nil_votes().unwrap(),
            "step {sequence} nil votes"
        );
        assert_eq!(
            owner.entered_view_certificate().unwrap(),
            full.entered_view_certificate().unwrap(),
            "step {sequence} view certificate"
        );
    }
}

#[test]
fn authenticated_dual_journal_rejects_raw_apply_and_open() {
    use validator::slot_agreement::AgreementInput;
    let (f, lineage, bootstrap) = fixture(true);
    let legacy_dir = TempDir::new();
    let legacy = Store::open(&legacy_dir.0).unwrap();
    let mut raw = legacy
        .begin_slot_agreement(bootstrap.agreement.clone())
        .unwrap();
    let auth_dir = TempDir::new();
    let authenticated = Store::open(&auth_dir.0).unwrap();
    authenticated
        .begin_authenticated_slot_agreement(bootstrap)
        .unwrap();
    fs::copy(
        auth_dir.0.join(authenticated_slot_agreement::FILE),
        legacy_dir.0.join(authenticated_slot_agreement::FILE),
    )
    .unwrap();
    let before = fs::read(legacy_dir.0.join(slot_agreement_journal::FILE)).unwrap();
    let input = AgreementInput::Propose {
        view: AgreementView(0),
        decision: f.payload.proposal.decision.clone(),
        pol: None,
    };
    assert!(raw.apply(1, input.clone(), |_| Ok(())).is_err());
    assert!(
        raw.apply_validated(1, input, |_| Ok(()), |_| Ok(()))
            .is_err()
    );
    assert_eq!(
        fs::read(legacy_dir.0.join(slot_agreement_journal::FILE)).unwrap(),
        before
    );
    drop(raw);
    drop(legacy);
    assert!(Store::open(&legacy_dir.0).is_err());
    let mut owner = authenticated
        .recover_authenticated_slot_agreement(fixture(true).2)
        .unwrap();
    let mut bad = f.vertices.clone();
    bad[0].signature[0] ^= 1;
    assert!(
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage,
                    vertices: bad
                }
            )
            .is_err()
    );
    assert_eq!(owner.sequence(), 0);
}

#[test]
fn authenticated_stage_rejects_torn_logical_root() {
    let (_, _, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let mut store = Store::open(&dir.0).unwrap();
    store.begin_authenticated_slot_agreement(bootstrap).unwrap();
    OpenOptions::new()
        .append(true)
        .open(dir.0.join(authenticated_slot_agreement::FILE))
        .unwrap()
        .write_all(&[1])
        .unwrap();
    assert!(
        store.stage().is_err(),
        "staging must validate the root WAL, not just generation files"
    );
    assert!(!dir.0.join("CURRENT").exists());
}

#[test]
fn authenticated_activation_rechecks_logical_root() {
    for torn in [false, true] {
        let (f, lineage, bootstrap) = fixture(true);
        let dir = TempDir::new();
        let mut store = Store::open(&dir.0).unwrap();
        let mut session = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        session
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage,
                    vertices: f.vertices,
                },
            )
            .unwrap();
        // Publish once so failure must preserve an existing CURRENT and active routing.
        store.stage().unwrap().activate().unwrap();
        let previous = fs::read(dir.0.join("CURRENT")).unwrap();
        let active = store.active.read().unwrap().clone();
        let stage = store.stage().unwrap();
        let generation = stage.view.root.clone();
        if torn {
            OpenOptions::new()
                .append(true)
                .open(dir.0.join(authenticated_slot_agreement::FILE))
                .unwrap()
                .write_all(&[1])
                .unwrap();
            assert!(
                stage.activate().is_err(),
                "publication must recheck changes after staging"
            );
            assert_eq!(fs::read(dir.0.join("CURRENT")).unwrap(), previous);
            assert_eq!(*store.active.read().unwrap(), active);
            assert!(
                !generation.exists(),
                "failed activation must clean its private generation"
            );
        } else {
            assert!(stage.store().slot_decision_locks().is_err());
            assert!(!generation.join(authenticated_slot_agreement::FILE).exists());
            stage.activate().unwrap();
            assert_ne!(fs::read(dir.0.join("CURRENT")).unwrap(), previous);
            store
                .recover_authenticated_slot_agreement(bootstrap)
                .unwrap();
        }
    }
}

#[test]
fn authenticated_public_decision_locks_excludes_clean_and_torn_roots() {
    let (_, _, bootstrap) = fixture(false);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    assert!(store.slot_decision_locks().unwrap().is_empty());
    store.begin_authenticated_slot_agreement(bootstrap).unwrap();
    assert!(
        store.slot_decision_locks().is_err(),
        "clean authenticated roots exclude legacy reads"
    );
    OpenOptions::new()
        .append(true)
        .open(dir.0.join(authenticated_slot_agreement::FILE))
        .unwrap()
        .write_all(&[1])
        .unwrap();
    assert!(
        store.slot_decision_locks().is_err(),
        "torn authenticated roots must not appear empty"
    );
}

#[test]
fn authenticated_generation_boundaries_validate_legacy_root_journals() {
    for agreement in [false, true] {
        for after_stage in [false, true] {
            let (f, _, bootstrap) = fixture(true);
            let dir = TempDir::new();
            let mut store = Store::open(&dir.0).unwrap();
            let name = if agreement {
                store.begin_slot_agreement(bootstrap.agreement).unwrap();
                slot_agreement_journal::FILE
            } else {
                store
                    .lock_slot_decision(&f.payload.proposal.decision)
                    .unwrap();
                assert_eq!(
                    store.slot_decision_locks().unwrap(),
                    vec![f.payload.proposal.decision]
                );
                slot_decision_journal::FILE
            };
            // Clean legacy roots must still support staging and publication.
            store.stage().unwrap().activate().unwrap();
            let previous = fs::read(dir.0.join("CURRENT")).unwrap();
            if after_stage {
                let stage = store.stage().unwrap();
                OpenOptions::new()
                    .append(true)
                    .open(dir.0.join(name))
                    .unwrap()
                    .write_all(&[1])
                    .unwrap();
                assert!(stage.activate().is_err());
            } else {
                OpenOptions::new()
                    .append(true)
                    .open(dir.0.join(name))
                    .unwrap()
                    .write_all(&[1])
                    .unwrap();
                assert!(store.stage().is_err());
            }
            assert_eq!(fs::read(dir.0.join("CURRENT")).unwrap(), previous);
        }
    }
}

// The shared harness builds signed multi-view DAGs and applies the final proof;
// this driver authorizes every transition exclusively through the closed WAL API.
fn authenticated_emitted_qc(
    f: &Fixture,
    lineage: &SlotAgreementViewLineage,
    _history: &std::collections::BTreeMap<AgreementView, SlotAgreementViewLineage>,
    prevote: Option<&validator::slot_agreement::AgreementQc>,
    dirs: &[TempDir],
    view: AgreementView,
    _wrong_pol: Option<&validator::slot_agreement::AgreementQc>,
) -> validator::slot_agreement::AgreementQc {
    use crypto::scheme::Ed25519Scheme;
    use validator::ValidatorSignature;
    use validator::slot_agreement::AgreementQc;

    let members = if view.0 == 0 { 0..3 } else { 1..4 };
    let mut votes = Vec::new();
    let mut signatures = Vec::new();
    for id in members {
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
        let store = Store::open(&dirs[id].0).unwrap();
        let mut session = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        if view.0 > 0 && prevote.is_none() {
            for from in 0..view.0 {
                session
                    .apply(
                        session.sequence() + 1,
                        AuthenticatedSlotAgreementRequest::AdvanceView {
                            from: AgreementView(from),
                        },
                    )
                    .unwrap();
            }
        }
        let request = if prevote.is_some() {
            AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage: lineage.clone(),
                vertices: f.vertices.clone(),
            }
        } else {
            AuthenticatedSlotAgreementRequest::Propose {
                lineage: lineage.clone(),
                vertices: f.vertices.clone(),
            }
        };
        // Reopen after the earlier lock and view advancement, before reproposal.
        drop(session);
        drop(store);
        let store = Store::open(&dirs[id].0).unwrap();
        let mut session = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let path = dirs[id].0.join(authenticated_slot_agreement::FILE);
        if view.0 > 0 && id < 3 {
            let sequence = session.sequence();
            let bytes = fs::read(&path).unwrap();
            let mut original = SlotAgreementViewLineage {
                entries: vec![lineage.entries[0].clone()],
            };
            original.entries[0].pol = None;
            let original_vertices: Vec<_> = f
                .vertices
                .iter()
                .filter(|vertex| vertex.round <= 4)
                .cloned()
                .collect();
            // Only the latest sequence is retryable, even for the original envelope.
            assert!(
                session
                    .apply(
                        1,
                        AuthenticatedSlotAgreementRequest::Propose {
                            lineage: original,
                            vertices: original_vertices.clone(),
                        },
                    )
                    .is_err()
            );
            assert_eq!(session.sequence(), sequence);
            assert_eq!(fs::read(&path).unwrap(), bytes);
            // Change only the lineage in the original sequence-one envelope.
            assert!(
                session
                    .apply(
                        1,
                        AuthenticatedSlotAgreementRequest::Propose {
                            lineage: lineage.clone(),
                            vertices: original_vertices,
                        }
                    )
                    .is_err()
            );
            assert_eq!(session.sequence(), sequence);
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
        let sequence = session.sequence() + 1;
        let result = session.apply(sequence, request.clone()).unwrap();
        let bytes = fs::read(&path).unwrap();
        // Crash after persisting the vote/lock, before producing any signature.
        drop(session);
        drop(store);
        let store = Store::open(&dirs[id].0).unwrap();
        let mut session = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(session.sequence(), sequence);
        let retried = session.apply(sequence, request).unwrap();
        assert_eq!(retried, result);
        assert_eq!(session.sequence(), sequence);
        assert_eq!(fs::read(&path).unwrap(), bytes);
        let vote = retried.vote.unwrap();
        assert_eq!(vote.view, view);
        assert_eq!(
            vote.phase,
            if prevote.is_some() {
                AgreementPhase::Precommit
            } else {
                AgreementPhase::Prevote
            }
        );
        signatures.push(ValidatorSignature {
            validator_id: f.set.validators[id].validator_id.clone(),
            key_id: f.set.validators[id].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&f.keys[id], &vote.signing_payload(&f.set).unwrap())
                .unwrap(),
        });
        votes.push(vote);
    }
    assert!(votes.iter().all(|vote| vote == &votes[0]));
    let qc = AgreementQc {
        vote: votes.remove(0),
        signatures,
    };
    qc.verify(f.binding.tip(), &f.set).unwrap();
    qc
}

#[test]
fn authenticated_multiview_commit_zero_to_one_root_wal_recovery() {
    crate::signed_dag_agreement_tests::run_with_qc(
        true,
        Some(AgreementView(1)),
        true,
        authenticated_emitted_qc,
    );
}

#[test]
fn authenticated_multiview_skip_zero_to_three_root_wal_recovery() {
    crate::signed_dag_agreement_tests::run_with_qc(
        false,
        Some(AgreementView(3)),
        true,
        authenticated_emitted_qc,
    );
}

#[test]
fn durable_presign_vote_reservation_retries_and_rejections() {
    use crypto::scheme::Ed25519Scheme;
    use validator::{SlotAgreementVotePayload, ValidatorSignature};
    let (f, lineage, bootstrap) = fixture(true);
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let vote = owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage: lineage.clone(),
                vertices: f.vertices.clone(),
            },
        )
        .unwrap()
        .vote
        .unwrap();
    let payload = SlotAgreementVotePayload {
        signature: ValidatorSignature {
            validator_id: f.set.validators[0].validator_id.clone(),
            key_id: f.set.validators[0].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&f.keys[0], &vote.signing_payload(&f.set).unwrap())
                .unwrap(),
        },
        vote,
        prerequisite: lineage.entries[0].view_carrier.clone(),
    };
    let mut unsigned = signed_vertex(
        &f.keys,
        0,
        5,
        f.vertices
            .iter()
            .filter(|v| v.round == 4)
            .map(|v| v.id().unwrap())
            .collect(),
        payload.digest(&f.set).unwrap(),
    );
    unsigned.signature.clear();
    let request = AuthenticatedSlotAgreementRequest::ReserveCarrier {
        evidence: AgreementCarrierEvidence::Vote {
            lineage: lineage.clone(),
            payload: payload.clone(),
        },
        unsigned: unsigned.clone(),
        vertices: vec![],
    };
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let before = fs::read(&path).unwrap();
    let mut bads = Vec::new();
    for kind in 0..6 {
        let mut bad = request.clone();
        let AuthenticatedSlotAgreementRequest::ReserveCarrier {
            evidence, unsigned, ..
        } = &mut bad
        else {
            unreachable!()
        };
        match kind {
            0 => unsigned.signature = vec![1],
            1 => unsigned.author = f.set.validators[1].validator_id.clone(),
            2 => unsigned.chain_id.push(1),
            3 => unsigned.references[0].digest[0] ^= 1,
            4 => {
                let AgreementCarrierEvidence::Vote { payload, .. } = evidence else {
                    unreachable!()
                };
                payload.signature.signature[0] ^= 1;
            }
            _ => {
                let AgreementCarrierEvidence::Vote { lineage, .. } = evidence else {
                    unreachable!()
                };
                lineage.entries[0].view_carrier.digest[0] ^= 1;
            }
        }
        bads.push(bad);
    }
    for bad in bads {
        assert!(owner.apply(2, bad).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
    }
    let before_driver = SlotAgreementDriver::new(
        store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap(),
    );
    let transition = before_driver.output().unwrap().transition.unwrap();
    let intents = before_driver.signing_outbox().unwrap();
    drop(before_driver);
    assert_eq!(owner.apply(2, request.clone()).unwrap(), transition);
    assert_eq!(
        owner.driver_snapshot().unwrap().1.as_ref(),
        Some(&transition)
    );
    let after_driver = SlotAgreementDriver::new(owner);
    assert_eq!(
        after_driver.output().unwrap().transition.as_ref(),
        Some(&transition)
    );
    assert_eq!(after_driver.signing_outbox().unwrap().len(), intents.len());
    drop(after_driver);
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    assert_eq!(owner.signing_outbox().unwrap().len(), intents.len());
    let reserved = owner.reserved_carriers().unwrap();
    assert_eq!(reserved.len(), 1);
    assert_eq!(reserved[0].id, unsigned.id().unwrap());
    assert_eq!(reserved[0].unsigned, unsigned);
    assert_eq!(reserved[0].sequence, 2);
    let durable = fs::read(&path).unwrap();
    assert!(owner.apply(3, request.clone()).is_err());
    assert_eq!(owner.sequence(), 2);
    assert_eq!(fs::read(&path).unwrap(), durable);
    let stale = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let driver = SlotAgreementDriver::new(stale);
    assert_eq!(
        driver.output().unwrap().transition.as_ref(),
        Some(&transition)
    );
    assert_eq!(driver.signing_outbox().unwrap().len(), intents.len());
    assert_eq!(driver.reserved_carriers().unwrap().len(), 1);
    assert_eq!(owner.apply(2, request.clone()).unwrap(), transition);
    assert_eq!(fs::read(&path).unwrap(), durable);
    let mut conflict = request.clone();
    let AuthenticatedSlotAgreementRequest::ReserveCarrier { unsigned, .. } = &mut conflict else {
        unreachable!()
    };
    unsigned.references.pop();
    assert!(owner.apply(3, conflict).is_err());
    assert_eq!(fs::read(&path).unwrap(), durable);
    owner
        .apply(
            3,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    let advanced = fs::read(&path).unwrap();
    assert!(driver.reserved_carriers().is_err());
    assert_eq!(owner.apply(2, request.clone()).unwrap(), transition);
    assert_eq!(owner.sequence(), 3);
    assert_eq!(fs::read(&path).unwrap(), advanced);
    assert!(owner.apply(4, request.clone()).is_err());
    drop(owner);
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    assert!(
        owner
            .apply_with_io(
                2,
                request.clone(),
                |file, bytes| Ok(file.write_all(bytes)?),
                |_, _| Err(std::io::Error::other("reservation barrier failure").into()),
            )
            .is_err()
    );
    assert!(owner.reserved_carriers().is_err());
    assert!(owner.apply(2, request.clone()).is_err());
    drop(owner);
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    owner.apply(2, request).unwrap();
    assert_eq!(
        owner.reserved_carriers().unwrap()[0].unsigned.signature,
        Vec::<u8>::new()
    );
    assert_eq!(fs::read(&path).unwrap(), advanced);
}

#[test]
fn observed_proposal_rejects_decided_and_stale_slots_without_writes() {
    let (f, proof, carrier) = crate::slot_application_tests::unified_fixture(true);
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
    let proposal = AuthenticatedSlotAgreementRequest::ObserveProposal {
        proposal: proof.entries[0].proposal.clone(),
        carrier: proof.entries[0].proposal_carrier.clone(),
        vertices: vec![],
    };
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store.begin_authenticated_slot_agreement(bootstrap).unwrap();
    owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::ObservePrecommit {
                proof,
                carrier,
                vertices: f.vertices,
            },
        )
        .unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let before = fs::read(&path).unwrap();
    assert!(owner.apply(2, proposal.clone()).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
    owner.advance_slot(2).unwrap();
    let before = fs::read(&path).unwrap();
    assert!(owner.apply(3, proposal).is_err());
    assert_eq!(fs::read(&path).unwrap(), before);
}

#[test]
fn presign_reservation_survives_slot_advance_without_reauthorizing() {
    use crate::slot_application_tests::unified_fixture;
    use crypto::scheme::Ed25519Scheme;
    use validator::{SlotAgreementVotePayload, ValidatorSignature};
    let (f, proof, carrier) = unified_fixture(true);
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
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let lineage = SlotAgreementViewLineage {
        entries: proof.entries.clone(),
    };
    let vote = owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage: lineage.clone(),
                vertices: f.vertices.clone(),
            },
        )
        .unwrap()
        .vote
        .unwrap();
    let payload = SlotAgreementVotePayload {
        signature: ValidatorSignature {
            validator_id: f.set.validators[0].validator_id.clone(),
            key_id: f.set.validators[0].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&f.keys[0], &vote.signing_payload(&f.set).unwrap())
                .unwrap(),
        },
        vote,
        prerequisite: lineage
            .entries
            .last()
            .unwrap()
            .pol
            .as_ref()
            .unwrap()
            .carrier
            .clone(),
    };
    let round = f.vertices.iter().map(|v| v.round).max().unwrap() + 1;
    let mut unsigned = signed_vertex(
        &f.keys,
        0,
        round,
        f.vertices
            .iter()
            .filter(|v| v.round == round - 1)
            .map(|v| v.id().unwrap())
            .collect(),
        payload.digest(&f.set).unwrap(),
    );
    unsigned.signature.clear();
    let request = AuthenticatedSlotAgreementRequest::ReserveCarrier {
        evidence: AgreementCarrierEvidence::Vote { lineage, payload },
        unsigned,
        vertices: vec![],
    };
    owner.apply(2, request.clone()).unwrap();
    owner
        .apply(
            3,
            AuthenticatedSlotAgreementRequest::ObservePrecommit {
                proof,
                carrier,
                vertices: vec![],
            },
        )
        .unwrap();
    owner.advance_slot(4).unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let bytes = fs::read(&path).unwrap();
    owner.apply(2, request.clone()).unwrap();
    assert!(owner.apply(5, request.clone()).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    let original = owner.reserved_carriers().unwrap().remove(0);
    assert_ne!(original.binding.tip(), owner.binding().unwrap().tip());
    drop(owner);
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    owner.apply(2, request).unwrap();
    assert_eq!(owner.reserved_carriers().unwrap()[0].id, original.id);
    assert_eq!(fs::read(&path).unwrap(), bytes);

    let mut signed = original.unsigned.clone();
    signed.signature = Ed25519Scheme
        .sign(&f.keys[0], &signed.signing_payload().unwrap())
        .unwrap();
    let completion = AuthenticatedSlotAgreementRequest::CompleteCarrier {
        reservation_sequence: original.sequence,
        signed: signed.clone(),
    };
    for mutation in 0..3 {
        let mut bad = completion.clone();
        let AuthenticatedSlotAgreementRequest::CompleteCarrier {
            reservation_sequence,
            signed,
        } = &mut bad
        else {
            unreachable!()
        };
        match mutation {
            0 => *reservation_sequence = 1,
            1 => signed.signature[0] ^= 1,
            _ => signed.payload_hash[0] ^= 1,
        }
        assert!(owner.apply(5, bad).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
    }
    let binding = owner.binding().unwrap();
    assert!(
        owner
            .apply_with_io(
                5,
                completion.clone(),
                |file, bytes| Ok(file.write_all(bytes)?),
                |_, _| Err(std::io::Error::other("completion barrier failure").into()),
            )
            .is_err()
    );
    assert!(owner.completed_carriers().is_err());
    assert!(owner.apply(5, completion.clone()).is_err());
    owner = store
        .recover_authenticated_slot_agreement(AuthenticatedSlotAgreementBootstrap {
            agreement: original.agreement.clone(),
            predecessor: None,
            order: vec![],
            vertices: vec![],
        })
        .unwrap();
    owner.apply(5, completion.clone()).unwrap();
    assert_eq!(owner.binding().unwrap(), binding);
    assert!(owner.apply(6, completion.clone()).is_err());
    owner
        .apply(
            6,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    let durable = fs::read(&path).unwrap();
    owner.apply(5, completion.clone()).unwrap();
    assert_eq!(owner.sequence(), 6);
    assert_eq!(fs::read(&path).unwrap(), durable);
    let recovered = store
        .recover_authenticated_slot_agreement(AuthenticatedSlotAgreementBootstrap {
            agreement: original.agreement.clone(),
            predecessor: None,
            order: vec![],
            vertices: vec![],
        })
        .unwrap();
    assert!(owner.completed_carriers().is_ok());
    let driver = SlotAgreementDriver::new(recovered);
    let completed = driver.completed_carriers().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].sequence, 5);
    assert_eq!(completed[0].reservation.sequence, 2);
    assert_eq!(
        completed[0].signed.encode().unwrap(),
        signed.encode().unwrap()
    );
    assert_eq!(fs::read(&path).unwrap(), durable);
}

#[test]
fn presign_aggregate_frozen_candidates_recovery_and_rejections() {
    use crate::slot_application_tests::unified_fixture;
    use crypto::scheme::Ed25519Scheme;
    use validator::SlotAgreementVotePayload;
    for final_carrier in [false, true] {
        let (f, proof, carrier) = unified_fixture(true);
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
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let full = SlotAgreementViewLineage {
            entries: proof.entries.clone(),
        };
        let mut base = full.clone();
        let pol = base.entries.last_mut().unwrap().pol.take().unwrap();
        let initial = if final_carrier {
            AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage: full.clone(),
                vertices: f.vertices.clone(),
            }
        } else {
            AuthenticatedSlotAgreementRequest::Propose {
                lineage: base.clone(),
                vertices: f.vertices.clone(),
            }
        };
        owner.apply(1, initial).unwrap();
        let round = f.vertices.iter().map(|v| v.round).max().unwrap() + 1;
        let refs: Vec<_> = f
            .vertices
            .iter()
            .filter(|v| v.round == round - 1)
            .map(|v| v.id().unwrap())
            .collect();
        let mut unsigned = signed_vertex(
            &f.keys,
            0,
            round,
            refs.clone(),
            if final_carrier {
                proof.digest(&f.set).unwrap()
            } else {
                full.pol_digest(0, &f.set).unwrap()
            },
        );
        unsigned.signature.clear();
        let evidence = if final_carrier {
            AgreementCarrierEvidence::Final {
                proof: proof.clone(),
            }
        } else {
            let mut bound = full.clone();
            bound
                .entries
                .last_mut()
                .unwrap()
                .pol
                .as_mut()
                .unwrap()
                .carrier = unsigned.id().unwrap();
            AgreementCarrierEvidence::Pol { lineage: bound }
        };
        let request = AuthenticatedSlotAgreementRequest::ReserveCarrier {
            evidence,
            unsigned: unsigned.clone(),
            vertices: vec![],
        };
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let before = fs::read(&path).unwrap();
        assert!(
            owner
                .apply(2, request.clone())
                .unwrap_err()
                .to_string()
                .contains("fresh exact frozen candidate")
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        let witnesses = if final_carrier {
            &proof.votes
        } else {
            &pol.votes
        };
        for witness in witnesses {
            owner
                .apply(
                    owner.sequence() + 1,
                    AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: if final_carrier {
                            full.clone()
                        } else {
                            base.clone()
                        },
                        witness: witness.clone(),
                        vertices: vec![],
                    },
                )
                .unwrap();
        }
        let candidates = owner.quorum_candidates().unwrap();
        assert_eq!(candidates.len(), 1);
        let frozen = &candidates[0];
        let evidence = if final_carrier {
            AgreementCarrierEvidence::Final {
                proof: frozen
                    .lineage
                    .clone()
                    .into_proof(frozen.certificate.clone(), frozen.witnesses.clone(), &f.set)
                    .unwrap(),
            }
        } else {
            AgreementCarrierEvidence::Pol {
                lineage: frozen
                    .lineage
                    .pol_candidate_digest(
                        frozen.certificate.clone(),
                        frozen.witnesses.clone(),
                        &f.set,
                    )
                    .unwrap()
                    .bind_carrier(unsigned.id().unwrap()),
            }
        };
        let request = AuthenticatedSlotAgreementRequest::ReserveCarrier {
            evidence,
            unsigned: unsigned.clone(),
            vertices: vec![],
        };
        let before = fs::read(&path).unwrap();
        for mutation in 0..7 {
            let mut bad = request.clone();
            let AuthenticatedSlotAgreementRequest::ReserveCarrier {
                evidence, unsigned, ..
            } = &mut bad
            else {
                unreachable!()
            };
            match mutation {
                0 => unsigned.signature = vec![1],
                1 => unsigned.references[0].digest[0] ^= 1,
                2 => unsigned.chain_id.push(1),
                5 => unsigned.epoch += 1,
                6 => unsigned.author = f.set.validators[1].validator_id.clone(),
                3 => match evidence {
                    AgreementCarrierEvidence::Pol { lineage } => {
                        lineage
                            .entries
                            .last_mut()
                            .unwrap()
                            .pol
                            .as_mut()
                            .unwrap()
                            .carrier
                            .digest[0] ^= 1
                    }
                    AgreementCarrierEvidence::Final { proof } => {
                        proof.votes[0].carrier.digest[0] ^= 1
                    }
                    _ => unreachable!(),
                },
                _ => match evidence {
                    AgreementCarrierEvidence::Pol { lineage } => {
                        lineage
                            .entries
                            .last_mut()
                            .unwrap()
                            .pol
                            .as_mut()
                            .unwrap()
                            .certificate
                            .signatures[0]
                            .signature[0] ^= 1
                    }
                    AgreementCarrierEvidence::Final { proof } => {
                        proof.certificate.signatures[0].signature[0] ^= 1
                    }
                    _ => unreachable!(),
                },
            }
            assert!(owner.apply(owner.sequence() + 1, bad).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        let sequence = owner.sequence() + 1;
        let transition = owner.driver_snapshot().unwrap().1;
        let intents = owner.signing_outbox().unwrap().len();
        owner.apply(sequence, request.clone()).unwrap();
        assert_eq!(owner.driver_snapshot().unwrap().1, transition);
        assert_eq!(owner.signing_outbox().unwrap().len(), intents);
        let durable = fs::read(&path).unwrap();
        assert!(owner.apply(sequence + 1, request.clone()).is_err());
        assert_eq!(owner.sequence(), sequence);
        assert_eq!(fs::read(&path).unwrap(), durable);
        let conflicting_dependency = signed_vertex(&f.keys, 0, round, refs, [4; 32]);
        assert!(
            owner
                .apply(
                    sequence + 1,
                    AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: if final_carrier {
                            full.clone()
                        } else {
                            base.clone()
                        },
                        witness: witnesses[0].clone(),
                        vertices: vec![conflicting_dependency],
                    }
                )
                .unwrap_err()
                .to_string()
                .contains("signed dependency conflicts")
        );
        assert_eq!(fs::read(&path).unwrap(), durable);
        let reserved = owner.reserved_carriers().unwrap().remove(0);
        assert_eq!(reserved.id, unsigned.id().unwrap());
        assert_eq!(reserved.sequence, sequence);
        if !final_carrier {
            let payload: SlotAgreementVotePayload = pol
                .votes
                .iter()
                .find(|w| w.payload.signature.validator_id == bootstrap.agreement.local_validator)
                .unwrap()
                .payload
                .clone();
            let mut vote_unsigned = unsigned.clone();
            vote_unsigned.payload_hash = payload.digest(&f.set).unwrap();
            let conflict = AuthenticatedSlotAgreementRequest::ReserveCarrier {
                evidence: AgreementCarrierEvidence::Vote {
                    lineage: base.clone(),
                    payload,
                },
                unsigned: vote_unsigned,
                vertices: vec![],
            };
            assert!(
                owner
                    .apply(sequence + 1, conflict)
                    .unwrap_err()
                    .to_string()
                    .contains("conflicting local round")
            );
            assert_eq!(fs::read(&path).unwrap(), durable);
        }
        drop(owner);
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        assert_eq!(
            owner.reserved_carriers().unwrap()[0].evidence,
            reserved.evidence
        );
        owner.apply(sequence, request.clone()).unwrap();
        assert_eq!(fs::read(&path).unwrap(), durable);
        owner
            .apply(
                sequence + 1,
                AuthenticatedSlotAgreementRequest::AdvanceView {
                    from: AgreementView(0),
                },
            )
            .unwrap();
        let mut stale = request.clone();
        let AuthenticatedSlotAgreementRequest::ReserveCarrier {
            unsigned, evidence, ..
        } = &mut stale
        else {
            unreachable!()
        };
        unsigned.round += 1;
        if let AgreementCarrierEvidence::Pol { lineage } = evidence {
            lineage
                .entries
                .last_mut()
                .unwrap()
                .pol
                .as_mut()
                .unwrap()
                .carrier = unsigned.id().unwrap();
        }
        assert!(
            owner
                .apply(sequence + 2, stale)
                .unwrap_err()
                .to_string()
                .contains("fresh exact frozen candidate")
        );
        owner.apply(sequence, request.clone()).unwrap();
        owner
            .apply(
                sequence + 2,
                AuthenticatedSlotAgreementRequest::ObservePrecommit {
                    proof,
                    carrier,
                    vertices: vec![],
                },
            )
            .unwrap();
        let mut decided = request.clone();
        let AuthenticatedSlotAgreementRequest::ReserveCarrier {
            unsigned, evidence, ..
        } = &mut decided
        else {
            unreachable!()
        };
        unsigned.round += 1;
        if let AgreementCarrierEvidence::Pol { lineage } = evidence {
            lineage
                .entries
                .last_mut()
                .unwrap()
                .pol
                .as_mut()
                .unwrap()
                .carrier = unsigned.id().unwrap();
        }
        let before = fs::read(&path).unwrap();
        assert!(
            owner
                .apply(sequence + 3, decided)
                .unwrap_err()
                .to_string()
                .contains("fresh exact frozen candidate")
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        owner.advance_slot(sequence + 3).unwrap();
        owner.apply(sequence, request.clone()).unwrap();
        drop(owner);
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        owner.apply(sequence, request).unwrap();
        assert_eq!(owner.reserved_carriers().unwrap()[0].id, reserved.id);
        let mut signed = reserved.unsigned.clone();
        signed.signature = Ed25519Scheme
            .sign(&f.keys[0], &signed.signing_payload().unwrap())
            .unwrap();
        let completion = AuthenticatedSlotAgreementRequest::CompleteCarrier {
            reservation_sequence: sequence,
            signed: signed.clone(),
        };
        let transition = owner.driver_snapshot().unwrap().1;
        owner.apply(sequence + 4, completion.clone()).unwrap();
        assert_eq!(owner.driver_snapshot().unwrap().1, transition);
        assert_eq!(
            owner.completed_carriers().unwrap()[0].reservation.evidence,
            reserved.evidence
        );
        let durable = fs::read(&path).unwrap();
        owner.apply(sequence + 4, completion).unwrap();
        assert_eq!(fs::read(&path).unwrap(), durable);
        let recovered = store
            .recover_authenticated_slot_agreement(AuthenticatedSlotAgreementBootstrap {
                agreement: reserved.agreement.clone(),
                predecessor: None,
                order: vec![],
                vertices: vec![],
            })
            .unwrap();
        assert_eq!(
            recovered.completed_carriers().unwrap()[0]
                .signed
                .encode()
                .unwrap(),
            signed.encode().unwrap()
        );
    }
}
