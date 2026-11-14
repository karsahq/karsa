use super::*;
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use validator::slot_agreement::{AgreementPhase, AgreementView};
use validator::{SlotAgreementProofEntry, SlotAgreementViewLineage};

fn fixture(
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
