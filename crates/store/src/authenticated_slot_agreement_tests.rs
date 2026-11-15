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
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn presign_aggregate_frozen_candidates_recovery_and_rejections() {
    use crate::slot_application_tests::unified_fixture;
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
    }
}
