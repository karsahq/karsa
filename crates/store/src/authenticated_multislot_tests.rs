use super::*;
use crate::slot_application_tests::{Fixture, TempDir, append_unified_proof, signed_vertex};
use validator::SlotAgreementViewLineage;
use validator::slot_agreement::AgreementView;

#[test]
fn signed_contiguous_slots_recover_and_do_not_leak_outputs() {
    for commit in [false, true] {
        let mut f = Fixture::new(commit);
        let (mut second, _, _) = f.extend_second_commit();
        let proposal = f.payload.proposal.clone();
        let carrier = f.payload.proposal_carrier.clone();
        let context = f.binding.tip().clone();
        let (first, first_carrier) = append_unified_proof(&mut f, proposal, carrier, context, 4);
        let refs = f
            .vertices
            .iter()
            .filter(|v| v.round == 8)
            .map(|v| v.id().unwrap())
            .collect::<Vec<_>>();
        for author in 0..4 {
            let hash = if author == 0 {
                second.proposal.digest().unwrap()
            } else {
                [9; 32]
            };
            let vertex = signed_vertex(&f.keys, author, 9, refs.clone(), hash);
            if author == 0 {
                second.proposal_carrier = vertex.id().unwrap();
            }
            f.vertices.push(vertex);
        }
        let mut certified = f.state(f.vertices.clone());
        certified
            .prepare_agreement(&first, &first_carrier)
            .unwrap()
            .apply();
        let context = certified.binding().tip().clone();
        let (next, next_carrier) = append_unified_proof(
            &mut f,
            second.proposal.clone(),
            second.proposal_carrier.clone(),
            context.clone(),
            10,
        );
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
        let initial = fs::read(&path).unwrap();
        assert!(owner.advance_slot(1).is_err());
        assert_eq!(fs::read(&path).unwrap(), initial);
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::ObservePrecommit {
                    proof: first,
                    carrier: first_carrier,
                    vertices: f.vertices.clone(),
                },
            )
            .unwrap();
        let transition = owner.advance_slot(2).unwrap();
        assert!(transition.vote.is_none());
        assert!(transition.decision.is_none());
        assert_eq!(transition.view, AgreementView(0));
        let durable = fs::read(&path).unwrap();
        assert_eq!(owner.advance_slot(2).unwrap(), transition);
        assert_eq!(fs::read(&path).unwrap(), durable);
        assert!(owner.quorum_candidates().unwrap().is_empty());
        assert_eq!(owner.driver_snapshot().unwrap().0.context, context);
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let proposal = AuthenticatedSlotAgreementRequest::Propose {
            lineage: SlotAgreementViewLineage {
                entries: next.entries.clone(),
            },
            vertices: vec![],
        };
        let vote = owner.apply(3, proposal.clone()).unwrap();
        assert!(vote.vote.is_some());
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let mut owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(owner.apply(3, proposal).unwrap(), vote);
        let result = owner
            .apply(
                4,
                AuthenticatedSlotAgreementRequest::ObservePrecommit {
                    proof: next,
                    carrier: next_carrier,
                    vertices: vec![],
                },
            )
            .unwrap();
        assert_eq!(result.decision, Some(second.proposal.decision));
        owner.advance_slot(5).unwrap();
        assert!(owner.quorum_candidates().unwrap().is_empty());
        assert!(store.vertices().unwrap().is_empty());
    }
}

#[test]
fn transition_rejects_unresolved_sessions_and_preserves_uncertainty() {
    use crate::slot_application_tests::unified_fixture;
    for fail_write in [false, true] {
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
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::ObservePrevote {
                    lineage: SlotAgreementViewLineage {
                        entries: proof.entries.clone(),
                    },
                    vertices: f.vertices.clone(),
                },
            )
            .unwrap();
        let path = dir.0.join(authenticated_slot_agreement::FILE);
        let locked = fs::read(&path).unwrap();
        assert!(owner.advance_slot(2).is_err());
        assert_eq!(fs::read(&path).unwrap(), locked);
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::AdvanceView {
                    from: AgreementView(0),
                },
            )
            .unwrap();
        let locked = fs::read(&path).unwrap();
        assert!(owner.advance_slot(3).is_err());
        assert_eq!(fs::read(&path).unwrap(), locked);
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
        let mut stale = store
            .recover_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
        let error = || StoreError::Io(std::io::Error::other("injected transition failure"));
        assert!(
            owner
                .apply_with_io(
                    4,
                    AuthenticatedSlotAgreementRequest::AdvanceSlot,
                    |file, bytes| {
                        if fail_write {
                            return Err(error());
                        }
                        file.write_all(bytes)?;
                        Ok(())
                    },
                    |_, _| Err(error()),
                )
                .is_err()
        );
        assert!(owner.advance_slot(4).is_err());
        assert!(owner.binding().is_err());
        let mut recovered = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        recovered.advance_slot(4).unwrap();
        assert!(stale.advance_slot(4).is_err());
        let durable = fs::read(&path).unwrap();
        let mut barriers = 0;
        recovered
            .apply_with_io(
                4,
                AuthenticatedSlotAgreementRequest::AdvanceSlot,
                |_, _| panic!("retry must not append"),
                |_, _| {
                    barriers += 1;
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(barriers, 1);
        assert_eq!(fs::read(path).unwrap(), durable);
    }
}

#[test]
fn nil_and_view_advance_cannot_authorize_slot_transition() {
    use validator::slot_agreement::AgreementPhase;
    let f = Fixture::new(false);
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
    let mut owner = store.begin_authenticated_slot_agreement(bootstrap).unwrap();
    owner
        .apply(
            1,
            AuthenticatedSlotAgreementRequest::Timeout {
                view: AgreementView(0),
                phase: AgreementPhase::Prevote,
            },
        )
        .unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let bytes = fs::read(&path).unwrap();
    assert!(owner.advance_slot(2).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    let bytes = fs::read(&path).unwrap();
    assert!(owner.advance_slot(3).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
}
