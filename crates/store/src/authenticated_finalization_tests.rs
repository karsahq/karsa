use super::*;
use crate::slot_application_tests::{TempDir, unified_fixture};
use validator::SlotAgreementViewLineage;
use validator::slot_agreement::AgreementView;

#[test]
fn authenticated_finalization_commit_skip_recovery_and_exact_retry() {
    for commit in [true, false] {
        for advance in [false, true] {
            let (f, proof, carrier) = unified_fixture(commit);
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
            if advance {
                owner
                    .apply(
                        1,
                        AuthenticatedSlotAgreementRequest::AdvanceView {
                            from: AgreementView(0),
                        },
                    )
                    .unwrap();
            }
            let sequence = owner.sequence() + 1;
            let request = AuthenticatedSlotAgreementRequest::ObservePrecommit {
                proof: proof.clone(),
                carrier: carrier.clone(),
                vertices: f.vertices.clone(),
            };
            let path = dir.0.join(authenticated_slot_agreement::FILE);
            let before = fs::read(&path).unwrap();
            let mut wrong_carrier = carrier.clone();
            wrong_carrier.digest[0] ^= 1;
            let mut malformed = proof.clone();
            malformed.votes.clear();
            let mut bare = proof.clone();
            bare.entries.clear();
            for (bad_proof, bad_carrier, vertices) in [
                (proof.clone(), wrong_carrier, f.vertices.clone()),
                (malformed, carrier.clone(), f.vertices.clone()),
                (bare, carrier.clone(), f.vertices.clone()),
                (proof.clone(), carrier.clone(), vec![]),
            ] {
                assert!(
                    owner
                        .apply(
                            sequence,
                            AuthenticatedSlotAgreementRequest::ObservePrecommit {
                                proof: bad_proof,
                                carrier: bad_carrier,
                                vertices,
                            }
                        )
                        .is_err()
                );
                assert_eq!(fs::read(&path).unwrap(), before);
                assert_eq!(owner.sequence(), sequence - 1);
            }
            let result = owner.apply(sequence, request.clone()).unwrap();
            assert_eq!(result.decision.as_ref(), Some(&f.payload.proposal.decision));
            assert!(result.vote.is_none());
            assert_eq!(result.view, AgreementView(u64::from(advance)));
            let durable = fs::read(&path).unwrap();
            assert_eq!(owner.apply(sequence, request.clone()).unwrap(), result);
            assert!(
                owner
                    .apply(
                        sequence,
                        AuthenticatedSlotAgreementRequest::ObservePrecommit {
                            proof: proof.clone(),
                            carrier: carrier.clone(),
                            vertices: vec![],
                        }
                    )
                    .is_err()
            );
            for blocked in [
                AuthenticatedSlotAgreementRequest::AdvanceView { from: result.view },
                AuthenticatedSlotAgreementRequest::Propose {
                    lineage: SlotAgreementViewLineage {
                        entries: proof.entries.clone(),
                    },
                    vertices: vec![],
                },
            ] {
                assert!(owner.apply(sequence + 1, blocked).is_err());
            }
            assert_eq!(fs::read(&path).unwrap(), durable);
            assert!(store.vertices().unwrap().is_empty());
            assert!(store.slot_decision_locks().is_err());
            drop(f);
            drop(proof);
            drop(carrier);
            drop(owner);
            drop(store);
            let store = Store::open(&dir.0).unwrap();
            let mut owner = store
                .recover_authenticated_slot_agreement(bootstrap)
                .unwrap();
            assert_eq!(owner.sequence(), sequence);
            assert_eq!(owner.apply(sequence, request).unwrap(), result);
            assert_eq!(fs::read(path).unwrap(), durable);
        }
    }
}

#[test]
fn authenticated_finalization_uncertain_io_requires_recovery() {
    for fail_sync in [false, true] {
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
        let request = AuthenticatedSlotAgreementRequest::ObservePrecommit {
            proof,
            carrier,
            vertices: f.vertices,
        };
        assert!(
            owner
                .apply_with_io(
                    1,
                    request.clone(),
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
        assert_eq!(owner.sequence(), 0);
        assert!(owner.apply(1, request.clone()).is_err());
        drop(owner);
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.sequence(), u64::from(fail_sync));
        assert!(owner.apply(1, request).unwrap().decision.is_some());
    }
}

#[test]
fn authenticated_finalization_application_is_separate_and_explicit() {
    for commit in [true, false] {
        let (f, proof, carrier) = unified_fixture(commit);
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        f.persist(&store);
        let mut state = f.state(store.vertices().unwrap());
        assert!(state.dag().order().is_empty());
        assert_eq!(state.binding(), &f.binding);
        store
            .apply_slot_agreement(&mut state, &proof, &carrier)
            .unwrap();
        assert_eq!(state.binding().tip().next_round(), 2);
        assert_eq!(state.binding().carrier(), Some(&carrier));
        assert_eq!(
            state.dag().commit_root(),
            f.payload.proposal.decision.after_root
        );
    }
}
