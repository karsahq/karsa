use super::*;
use crate::slot_application_tests::{TempDir, signed_vertex, unified_fixture};
use crypto::scheme::Ed25519Scheme;
use validator::SlotAgreementViewLineage;
use validator::slot_agreement::{AgreementPhase, AgreementView};

#[test]
fn durable_signing_history_survives_observation_and_bootstrap_only_recovery() {
    let (f, proof, _) = unified_fixture(true);
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
    assert!(owner.signing_outbox().unwrap().is_empty());
    let mut lineage = SlotAgreementViewLineage {
        entries: proof.entries.clone(),
    };
    let pol = lineage.entries[0].pol.take().unwrap();
    let request = AuthenticatedSlotAgreementRequest::Propose {
        lineage: lineage.clone(),
        vertices: f.vertices.clone(),
    };
    let vote = owner.apply(1, request.clone()).unwrap().vote.unwrap();
    owner.apply(1, request).unwrap();
    let original = owner.signing_outbox().unwrap();
    assert_eq!(original.len(), 1);
    assert_eq!(original[0].vote, vote);
    assert_eq!(original[0].sequence, 1);
    assert_eq!(
        original[0]
            .lineage
            .as_ref()
            .unwrap()
            .encode(&f.set)
            .unwrap(),
        lineage.encode(&f.set).unwrap()
    );
    assert_eq!(vote.phase, AgreementPhase::Prevote);
    assert_eq!(vote.context, bootstrap.agreement.context);
    assert_eq!(original[0].agreement.set, bootstrap.agreement.set);
    assert_eq!(
        original[0].prerequisite,
        AgreementSigningPrerequisite::Carrier(lineage.entries[0].view_carrier.clone())
    );
    let result = owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::ObserveVote {
                lineage: lineage.clone(),
                witness: pol.votes[0].clone(),
                vertices: vec![],
            },
        )
        .unwrap();
    assert!(result.vote.is_none());
    assert_eq!(owner.signing_outbox().unwrap()[0].id, original[0].id);
    let precommit = owner
        .apply(
            3,
            AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage: SlotAgreementViewLineage {
                    entries: proof.entries.clone(),
                },
                vertices: vec![],
            },
        )
        .unwrap()
        .vote
        .unwrap();
    let history = owner.signing_outbox().unwrap();
    assert_eq!(history.len(), 2);
    assert_eq!(history[1].sequence, 3);
    assert_eq!(history[1].vote, precommit);
    assert_eq!(precommit.phase, AgreementPhase::Precommit);
    assert_eq!(precommit.context, bootstrap.agreement.context);
    let precommit_lineage = SlotAgreementViewLineage {
        entries: proof.entries.clone(),
    };
    assert_eq!(
        history[1].lineage.as_ref().unwrap().encode(&f.set).unwrap(),
        precommit_lineage.encode(&f.set).unwrap()
    );
    assert_eq!(
        history[0].lineage.as_ref().unwrap().encode(&f.set).unwrap(),
        lineage.encode(&f.set).unwrap()
    );
    assert_eq!(
        history[1].prerequisite,
        AgreementSigningPrerequisite::Carrier(pol.carrier)
    );
    assert_ne!(history[0].id, history[1].id);
    owner
        .apply(
            4,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    assert!(store.vertices().unwrap().is_empty());
    let owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    let recovered = owner.signing_outbox().unwrap();
    assert_eq!(recovered.len(), 2);
    assert_eq!(recovered[1].id, history[1].id);
    assert_eq!(recovered[1].vote, precommit);
    assert_eq!(recovered[0].id, original[0].id);
    assert_eq!(recovered[0].vote, vote);
    for (actual, expected) in recovered.iter().zip(&history) {
        assert_eq!(actual.sequence, expected.sequence);
        assert_eq!(
            actual.lineage.as_ref().unwrap().encode(&f.set).unwrap(),
            expected.lineage.as_ref().unwrap().encode(&f.set).unwrap()
        );
    }
}

#[test]
fn durable_signing_history_retains_explicit_unsupported_timeout_nil() {
    let (f, _, _) = unified_fixture(true);
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
    let vote = owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            },
        )
        .unwrap()
        .vote
        .unwrap();
    owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    let history = owner.signing_outbox().unwrap();
    assert_eq!(history.len(), 1);
    assert_eq!(history[0].vote, vote);
    assert!(history[0].lineage.is_none());
    assert_eq!(
        history[0].prerequisite,
        AgreementSigningPrerequisite::UnsupportedNil
    );
    let recovered = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    let recovered = recovered.signing_outbox().unwrap();
    assert_eq!(recovered[0].id, history[0].id);
    assert!(recovered[0].lineage.is_none());
}

#[test]
fn authenticated_vote_quorum_recovery_and_atomic_rejection() {
    for phase in [AgreementPhase::Prevote, AgreementPhase::Precommit] {
        let (f, proof, _) = unified_fixture(true);
        let mut lineage = SlotAgreementViewLineage {
            entries: proof.entries.clone(),
        };
        let witnesses = if phase == AgreementPhase::Prevote {
            lineage.entries[0].pol.take().unwrap().votes
        } else {
            proof.votes.clone()
        };
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
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let request = |witness| AuthenticatedSlotAgreementRequest::ObserveVote {
            lineage: lineage.clone(),
            witness,
            vertices: f.vertices.clone(),
        };
        for (index, witness) in witnesses.iter().rev().enumerate() {
            let before = fs::read(&path).unwrap();
            let mut bad = witness.clone();
            bad.carrier.digest[0] ^= 1;
            assert!(owner.apply(owner.sequence() + 1, request(bad)).is_err());
            let mut bad = witness.clone();
            bad.payload.prerequisite.digest[0] ^= 1;
            assert!(owner.apply(owner.sequence() + 1, request(bad)).is_err());
            let mut bad = witness.clone();
            bad.payload.signature.signature[0] ^= 1;
            assert!(owner.apply(owner.sequence() + 1, request(bad)).is_err());
            assert_eq!(fs::read(&path).unwrap(), before);
            let result = owner
                .apply(owner.sequence() + 1, request(witness.clone()))
                .unwrap();
            assert!(result.vote.is_none());
            assert!(result.decision.is_none());
            assert_eq!(result.view, AgreementView(0));
            assert_eq!(
                owner.quorum_candidates().unwrap().len(),
                usize::from(index + 1 == witnesses.len())
            );
            owner
                .apply(owner.sequence() + 1, request(witness.clone()))
                .unwrap();
            assert_eq!(
                owner.quorum_candidates().unwrap().len(),
                usize::from(index + 1 == witnesses.len())
            );
        }
        let candidates = owner.quorum_candidates().unwrap();
        assert_eq!(candidates.len(), 1);
        candidates[0]
            .certificate
            .verify(&bootstrap.agreement.context, &f.set)
            .unwrap();
        assert_eq!(candidates[0].witnesses, witnesses);
        let references: Vec<_> = f
            .vertices
            .iter()
            .filter(|v| v.round == 8)
            .map(|v| v.id().unwrap())
            .collect();
        let mut late = witnesses[0].clone();
        late.payload.signature = validator::ValidatorSignature {
            validator_id: f.set.validators[3].validator_id.clone(),
            key_id: f.set.validators[3].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(
                    &f.keys[3],
                    &late.payload.vote.signing_payload(&f.set).unwrap(),
                )
                .unwrap(),
        };
        let vertex = signed_vertex(
            &f.keys,
            3,
            9,
            references.clone(),
            late.payload.digest(&f.set).unwrap(),
        );
        late.carrier = vertex.id().unwrap();
        owner
            .apply(
                owner.sequence() + 1,
                AuthenticatedSlotAgreementRequest::ObserveVote {
                    lineage: lineage.clone(),
                    witness: late,
                    vertices: vec![vertex],
                },
            )
            .unwrap();
        assert_eq!(owner.quorum_candidates().unwrap(), candidates);
        let mut conflicting = witnesses[0].clone();
        let vertex = signed_vertex(
            &f.keys,
            0,
            9,
            references,
            conflicting.payload.digest(&f.set).unwrap(),
        );
        conflicting.carrier = vertex.id().unwrap();
        let before = fs::read(&path).unwrap();
        assert!(
            owner
                .apply(
                    owner.sequence() + 1,
                    AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: lineage.clone(),
                        witness: conflicting,
                        vertices: vec![vertex]
                    }
                )
                .is_err()
        );
        assert_eq!(fs::read(&path).unwrap(), before);
        drop(owner);
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.quorum_candidates().unwrap(), candidates);
        // Observation did not emit a local vote or move the reducer to precommit.
        let result = owner
            .apply(
                owner.sequence() + 1,
                AuthenticatedSlotAgreementRequest::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Prevote,
                },
            )
            .unwrap();
        assert_eq!(result.vote.unwrap().phase, AgreementPhase::Prevote);
        assert!(result.decision.is_none());
    }
}

#[test]
fn authenticated_vote_uncertain_write_releases_no_candidate() {
    for fail_sync in [false, true] {
        let (f, proof, _) = unified_fixture(true);
        let mut lineage = SlotAgreementViewLineage {
            entries: proof.entries,
        };
        let witnesses = lineage.entries[0].pol.take().unwrap().votes;
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
        for witness in &witnesses[..witnesses.len() - 1] {
            owner
                .apply(
                    owner.sequence() + 1,
                    AuthenticatedSlotAgreementRequest::ObserveVote {
                        lineage: lineage.clone(),
                        witness: witness.clone(),
                        vertices: f.vertices.clone(),
                    },
                )
                .unwrap();
        }
        assert!(owner.quorum_candidates().unwrap().is_empty());
        let request = AuthenticatedSlotAgreementRequest::ObserveVote {
            lineage,
            witness: witnesses.last().unwrap().clone(),
            vertices: f.vertices,
        };
        assert!(
            owner
                .apply_with_io(
                    owner.sequence() + 1,
                    request,
                    |file, bytes| {
                        if !fail_sync {
                            return Err(std::io::Error::other("injected write failure").into());
                        }
                        file.write_all(bytes)?;
                        Ok(())
                    },
                    |_, _| Err(std::io::Error::other("injected sync failure").into())
                )
                .is_err()
        );
        assert!(owner.quorum_candidates().is_err());
        drop(owner);
        let owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(
            owner.quorum_candidates().unwrap().len(),
            usize::from(fail_sync)
        );
    }
}

#[test]
fn authenticated_vote_prevote_lineage_normalizes_after_authentication() {
    let (f, proof, _) = unified_fixture(true);
    let with_pol = SlotAgreementViewLineage {
        entries: proof.entries,
    };
    let witnesses = with_pol.entries[0].pol.as_ref().unwrap().votes.clone();
    let mut without_pol = with_pol.clone();
    without_pol.entries[0].pol = None;
    let bootstrap = AuthenticatedSlotAgreementBootstrap {
        agreement: SlotAgreementBootstrap {
            context: f.binding.tip().clone(),
            set: f.set.clone(),
            local_validator: f.set.validators[0].validator_id.clone(),
        },
        predecessor: None,
        order: vec![],
        vertices: f.vertices.clone(),
    };
    let mut expected = None;
    for first_has_pol in [false, true] {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let request = |lineage: &SlotAgreementViewLineage, index: usize| {
            AuthenticatedSlotAgreementRequest::ObserveVote {
                lineage: lineage.clone(),
                witness: witnesses[index].clone(),
                vertices: vec![],
            }
        };
        let (first, second) = if first_has_pol {
            (&with_pol, &without_pol)
        } else {
            (&without_pol, &with_pol)
        };
        owner.apply(1, request(first, 0)).unwrap();
        // An exact witness at a new sequence must use the same normalization policy.
        owner.apply(2, request(second, 0)).unwrap();
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let before = fs::read(&path).unwrap();
        let mut malformed = with_pol.clone();
        malformed.entries[0].pol.as_mut().unwrap().carrier.digest[0] ^= 1;
        assert!(owner.apply(3, request(&malformed, 0)).is_err());
        assert_eq!(
            fs::read(&path).unwrap(),
            before,
            "must authenticate even a duplicate's discarded POL"
        );
        owner.apply(3, request(second, 1)).unwrap();
        owner.apply(4, request(first, 2)).unwrap();
        let candidates = owner.quorum_candidates().unwrap();
        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].lineage, without_pol);
        if let Some(expected) = &expected {
            assert_eq!(&candidates, expected);
        } else {
            expected = Some(candidates.clone());
        }
        drop(owner);
        let owner = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        assert_eq!(owner.quorum_candidates().unwrap(), candidates);
    }
}

#[test]
fn nil_publication_recovery_and_authenticated_quorum() {
    use validator::slot_agreement::AgreementValue;
    use validator::{SlotAgreementNilVote, ValidatorSignature};
    let (f, _, _) = unified_fixture(true);
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
    let vote = owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            },
        )
        .unwrap()
        .vote
        .unwrap();
    let sign = |vote: validator::slot_agreement::AgreementVote, i: usize| {
        let signature = ValidatorSignature {
            validator_id: f.set.validators[i].validator_id.clone(),
            key_id: f.set.validators[i].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(&f.keys[i], &vote.signing_payload(&f.set).unwrap())
                .unwrap(),
        };
        SlotAgreementNilVote::new(vote, signature, &f.set).unwrap()
    };
    let intent_id = owner.signing_outbox().unwrap()[0].id;
    let publication = AuthenticatedSlotAgreementRequest::CompleteNilVote {
        intent_id,
        message: sign(vote.clone(), 0),
    };
    let wrong_signer = AuthenticatedSlotAgreementRequest::CompleteNilVote {
        intent_id,
        message: sign(vote.clone(), 1),
    };
    assert!(owner.apply(2, wrong_signer).is_err());
    let mut bad_signature = sign(vote.clone(), 0).signature().clone();
    bad_signature.signature[0] ^= 1;
    let bad = SlotAgreementNilVote::new(vote.clone(), bad_signature, &f.set).unwrap();
    assert!(
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::CompleteNilVote {
                    intent_id,
                    message: bad.clone(),
                }
            )
            .is_err()
    );
    assert!(
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::ObserveNilVote { message: bad }
            )
            .is_err()
    );
    let mut wrong_view = vote.clone();
    wrong_view.view = AgreementView(1);
    assert!(
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::ObserveNilVote {
                    message: sign(wrong_view.clone(), 0),
                }
            )
            .is_err()
    );
    assert!(
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::CompleteNilVote {
                    intent_id,
                    message: sign(wrong_view, 0),
                }
            )
            .is_err()
    );
    owner.apply(2, publication.clone()).unwrap();
    assert_eq!(owner.signing_outbox().unwrap().len(), 1);
    assert!(owner.apply(3, publication.clone()).is_err());
    let mut sequence = 3;
    for i in 0..4 {
        let message = sign(vote.clone(), i);
        let transition = owner
            .apply(
                sequence,
                AuthenticatedSlotAgreementRequest::ObserveNilVote {
                    message: message.clone(),
                },
            )
            .unwrap();
        sequence += 1;
        assert_eq!(transition.view, AgreementView(0));
        assert!(transition.decision.is_none());
        if i == 2 {
            let emitted = transition.vote.unwrap();
            assert_eq!(emitted.phase, AgreementPhase::Precommit);
            assert_eq!(emitted.value, AgreementValue::Nil);
        } else {
            assert!(transition.vote.is_none());
        }
        assert!(
            owner
                .apply(
                    sequence,
                    AuthenticatedSlotAgreementRequest::ObserveNilVote { message }
                )
                .unwrap()
                .vote
                .is_none()
        );
        sequence += 1;
    }
    assert_eq!(owner.signing_outbox().unwrap().len(), 2);
    // Original publication retries survive phase changes and recovery.
    owner.apply(2, publication.clone()).unwrap();
    drop(owner);
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    owner.apply(2, publication).unwrap();
    let completed = owner.completed_nil_votes().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].sequence, 2);
    assert_eq!(completed[0].intent_id, intent_id);
    let precommit = owner.signing_outbox().unwrap()[1].vote.clone();
    for i in 0..4 {
        let transition = owner
            .apply(
                sequence,
                AuthenticatedSlotAgreementRequest::ObserveNilVote {
                    message: sign(precommit.clone(), i),
                },
            )
            .unwrap();
        sequence += 1;
        assert!(transition.vote.is_none());
        assert!(transition.decision.is_none());
        assert_eq!(transition.view, AgreementView(0));
    }
    assert_eq!(owner.signing_outbox().unwrap().len(), 2);
}

fn signed_nil_test_message(
    vote: validator::slot_agreement::AgreementVote,
    set: &validator::ValidatorSet,
    key: &[u8],
    signer: usize,
) -> validator::SlotAgreementNilVote {
    validator::SlotAgreementNilVote::new(
        vote.clone(),
        validator::ValidatorSignature {
            validator_id: set.validators[signer].validator_id.clone(),
            key_id: set.validators[signer].keys[0].key_id.clone(),
            signature: Ed25519Scheme
                .sign(key, &vote.signing_payload(set).unwrap())
                .unwrap(),
        },
        set,
    )
    .unwrap()
}

#[test]
fn nil_completion_uncertain_io_recovers_exact_publication_or_fails_closed() {
    for failure in ["write", "barrier", "torn"] {
        let (f, _, _) = unified_fixture(true);
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
        let vote = owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Prevote,
                },
            )
            .unwrap()
            .vote
            .unwrap();
        let intent = owner.signing_outbox().unwrap().remove(0);
        let message = signed_nil_test_message(vote, &f.set, &f.keys[0], 0);
        let request = AuthenticatedSlotAgreementRequest::CompleteNilVote {
            intent_id: intent.id,
            message: message.clone(),
        };
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let before = fs::read(&path).unwrap();
        let mut barriers = 0;
        assert!(
            owner
                .apply_with_io(
                    2,
                    request.clone(),
                    |file, bytes| {
                        match failure {
                            "write" => {
                                Err(std::io::Error::other("injected nil write failure").into())
                            }
                            "torn" => {
                                file.write_all(&bytes[..7])?;
                                Err(std::io::Error::other("injected torn nil completion").into())
                            }
                            _ => Ok(file.write_all(bytes)?),
                        }
                    },
                    |_, _| {
                        barriers += 1;
                        Err(std::io::Error::other("injected nil barrier failure").into())
                    }
                )
                .is_err(),
            "{failure}"
        );
        assert_eq!(barriers, usize::from(failure == "barrier"));
        assert_eq!(owner.sequence(), 1);
        assert!(owner.completed_nil_votes().is_err());
        assert!(owner.signing_outbox().is_err());
        assert!(owner.apply(2, request.clone()).is_err());
        drop(owner);
        if failure == "torn" {
            assert!(
                store
                    .recover_authenticated_slot_agreement(bootstrap)
                    .is_err()
            );
            drop(store);
            assert!(Store::open(&dir.0).is_err());
            continue;
        }
        if failure == "write" {
            assert_eq!(fs::read(&path).unwrap(), before);
        }
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.sequence(), if failure == "barrier" { 2 } else { 1 });
        assert_eq!(
            owner.completed_nil_votes().unwrap().len(),
            usize::from(failure == "barrier")
        );
        owner.apply(2, request.clone()).unwrap();
        let completed = owner.completed_nil_votes().unwrap();
        assert_eq!(completed.len(), 1);
        assert_eq!(completed[0].intent_id, intent.id);
        assert_eq!(completed[0].sequence, 2);
        assert_eq!(
            completed[0].message.encode(&f.set).unwrap(),
            message.encode(&f.set).unwrap()
        );
        owner
            .apply(
                3,
                AuthenticatedSlotAgreementRequest::AdvanceView {
                    from: AgreementView(0),
                },
            )
            .unwrap();
        let historical = fs::read(&path).unwrap();
        owner.apply(2, request).unwrap();
        assert_eq!(fs::read(&path).unwrap(), historical);
        assert_eq!(owner.signing_outbox().unwrap().len(), 1);
    }
}

#[test]
fn nil_late_prevote_quorum_preserves_nonnil_precommit_lock_on_replay() {
    use validator::slot_agreement::AgreementValue;
    let (f, proof, _) = unified_fixture(true);
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
    let mut lineage = SlotAgreementViewLineage {
        entries: proof.entries.clone(),
    };
    lineage.entries[0].pol = None;
    owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Propose {
                lineage,
                vertices: f.vertices.clone(),
            },
        )
        .unwrap();
    let precommit = owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::ObservePrevote {
                lineage: SlotAgreementViewLineage {
                    entries: proof.entries,
                },
                vertices: vec![],
            },
        )
        .unwrap()
        .vote
        .unwrap();
    assert!(matches!(precommit.value, AgreementValue::Decision(_)));
    let original = owner.signing_outbox().unwrap();
    let locked_id = original[1].id;
    assert_eq!(owner.driver_snapshot().unwrap().5, vec![locked_id]);
    let selected = owner.reproposal_candidate().unwrap().unwrap();
    let mut nil = precommit.clone();
    nil.phase = AgreementPhase::Prevote;
    nil.value = AgreementValue::Nil;
    for signer in 0..4 {
        let transition = owner
            .apply(
                owner.sequence() + 1,
                AuthenticatedSlotAgreementRequest::ObserveNilVote {
                    message: signed_nil_test_message(nil.clone(), &f.set, &f.keys[signer], signer),
                },
            )
            .unwrap();
        assert!(transition.vote.is_none(), "late nil signer {signer}");
        assert!(transition.decision.is_none());
        assert_eq!(transition.view, AgreementView(0));
        assert_eq!(owner.driver_snapshot().unwrap().5, vec![locked_id]);
    }
    drop(owner);
    drop(store);
    let store = Store::open(&dir.0).unwrap();
    let owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    let history = owner.signing_outbox().unwrap();
    assert_eq!(history.len(), 2);
    for (actual, expected) in history.iter().zip(&original) {
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.sequence, expected.sequence);
        assert_eq!(actual.vote, expected.vote);
    }
    // Nonnil precommit authorability requires the exact current reducer lock.
    assert_eq!(owner.driver_snapshot().unwrap().5, vec![locked_id]);
    assert_eq!(owner.reproposal_candidate().unwrap().unwrap(), selected);
    let output = SlotAgreementDriver::new(owner).output().unwrap();
    assert!(output.transition.unwrap().vote.is_none());
    assert_eq!(output.authorable_vote_ids, vec![locked_id]);
}

#[test]
fn nil_interleaved_phase_subquorums_preserve_authorable_publication() {
    use validator::slot_agreement::{AgreementValue, AgreementVote};
    let (f, _, _) = unified_fixture(true);
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
    let prevote = AgreementVote {
        context: bootstrap.agreement.context.clone(),
        view: AgreementView(0),
        phase: AgreementPhase::Prevote,
        value: AgreementValue::Nil,
    };
    let mut precommit = prevote.clone();
    precommit.phase = AgreementPhase::Precommit;
    for signer in 0..2 {
        for vote in [&prevote, &precommit] {
            let transition = owner
                .apply(
                    owner.sequence() + 1,
                    AuthenticatedSlotAgreementRequest::ObserveNilVote {
                        message: signed_nil_test_message(
                            vote.clone(),
                            &f.set,
                            &f.keys[signer],
                            signer,
                        ),
                    },
                )
                .unwrap();
            assert!(transition.vote.is_none());
            assert!(transition.decision.is_none());
            assert_eq!(transition.view, AgreementView(0));
            assert!(
                owner.signing_outbox().unwrap().is_empty(),
                "phases must not combine"
            );
        }
    }
    let transition = owner
        .apply(
            5,
            AuthenticatedSlotAgreementRequest::ObserveNilVote {
                message: signed_nil_test_message(prevote.clone(), &f.set, &f.keys[2], 2),
            },
        )
        .unwrap();
    assert_eq!(transition.vote, Some(precommit.clone()));
    let intent = owner.signing_outbox().unwrap().remove(0);
    assert_eq!(intent.sequence, 5);
    for (vote, signer) in [
        (&prevote, 2),
        (&prevote, 3),
        (&precommit, 2),
        (&precommit, 3),
    ] {
        let transition = owner
            .apply(
                owner.sequence() + 1,
                AuthenticatedSlotAgreementRequest::ObserveNilVote {
                    message: signed_nil_test_message(vote.clone(), &f.set, &f.keys[signer], signer),
                },
            )
            .unwrap();
        assert!(transition.vote.is_none());
        assert!(transition.decision.is_none());
        assert_eq!(transition.view, AgreementView(0));
        assert_eq!(owner.driver_snapshot().unwrap().5, vec![intent.id]);
        assert_eq!(owner.signing_outbox().unwrap().len(), 1);
    }
    drop(owner);
    let owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    let mut driver = SlotAgreementDriver::new(owner);
    let output = driver.output().unwrap();
    assert!(output.transition.unwrap().vote.is_none());
    assert_eq!(output.authorable_vote_ids, vec![intent.id]);
    let sequence = driver.sequence() + 1;
    let message = signed_nil_test_message(precommit, &f.set, &f.keys[0], 0);
    let output = driver
        .apply(
            sequence,
            AuthenticatedSlotAgreementRequest::CompleteNilVote {
                intent_id: intent.id,
                message: message.clone(),
            },
        )
        .unwrap();
    assert!(output.transition.unwrap().vote.is_none());
    assert_eq!(output.authorable_vote_ids, vec![intent.id]);
    let completed = driver.completed_nil_votes().unwrap();
    assert_eq!(completed.len(), 1);
    assert_eq!(completed[0].intent_id, intent.id);
    assert_eq!(completed[0].sequence, sequence);
    assert_eq!(completed[0].message, message);
    assert_eq!(driver.signing_outbox().unwrap().len(), 1);
}
