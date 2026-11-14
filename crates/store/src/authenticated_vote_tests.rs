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
    assert_eq!(original[0].agreement.set, bootstrap.agreement.set);
    assert_eq!(
        original[0].prerequisite,
        AgreementSigningPrerequisite::Carrier(lineage.entries[0].view_carrier.clone())
    );
    let result = owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::ObserveVote {
                lineage,
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
    assert_eq!(
        history[1].prerequisite,
        AgreementSigningPrerequisite::Carrier(pol.carrier)
    );
    assert_ne!(history[0].id, history[1].id);
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
    assert_eq!(
        history[0].prerequisite,
        AgreementSigningPrerequisite::UnsupportedNil
    );
    let recovered = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(recovered.signing_outbox().unwrap()[0].id, history[0].id);
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
