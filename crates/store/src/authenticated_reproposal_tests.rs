use super::*;
use crate::slot_application_tests::{TempDir, unified_fixture};
use validator::SlotAgreementViewLineage;
use validator::slot_agreement::{AgreementPhase, AgreementView};

#[test]
fn signed_late_pol_is_retained_and_recovered() {
    for older in [false, true] {
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
        owner
            .apply(
                1,
                AuthenticatedSlotAgreementRequest::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Prevote,
                },
            )
            .unwrap();
        owner
            .apply(
                2,
                AuthenticatedSlotAgreementRequest::Timeout {
                    view: AgreementView(0),
                    phase: AgreementPhase::Precommit,
                },
            )
            .unwrap();
        let mut sequence = 3;
        if older {
            owner
                .apply(
                    sequence,
                    AuthenticatedSlotAgreementRequest::AdvanceView {
                        from: AgreementView(0),
                    },
                )
                .unwrap();
            sequence += 1;
        }
        let lineage = SlotAgreementViewLineage {
            entries: proof.entries.clone(),
        };
        let request = AuthenticatedSlotAgreementRequest::ObservePrevote {
            lineage: lineage.clone(),
            vertices: f.vertices.clone(),
        };
        let transition = owner.apply(sequence, request.clone()).unwrap();
        assert!(transition.vote.is_none());
        let material = owner.reproposal_candidate().unwrap().unwrap();
        assert_eq!(material.view(), AgreementView(0));
        assert_eq!(material.lineage(), &lineage);
        assert_eq!(owner.apply(sequence, request).unwrap(), transition);
        drop(owner);
        drop(store);
        let store = Store::open(&dir.0).unwrap();
        let owner = store
            .recover_authenticated_slot_agreement(bootstrap)
            .unwrap();
        assert_eq!(
            owner.reproposal_candidate().unwrap(),
            Some(material.clone())
        );
        let output = SlotAgreementDriver::new(owner).output().unwrap();
        assert_eq!(output.reproposal, Some(material));
        assert!(output.candidates.is_empty());
    }
}

#[test]
fn selected_material_clears_on_slot_advance() {
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
    assert!(owner.reproposal_candidate().unwrap().is_some());
    owner
        .apply(
            2,
            AuthenticatedSlotAgreementRequest::AdvanceView {
                from: AgreementView(0),
            },
        )
        .unwrap();
    assert!(owner.reproposal_candidate().unwrap().is_some());
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
    assert!(owner.reproposal_candidate().unwrap().is_none());
    drop(owner);
    let owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert!(owner.reproposal_candidate().unwrap().is_none());
    let output = SlotAgreementDriver::new(owner).output().unwrap();
    assert!(output.reproposal.is_none());
    assert!(output.candidates.is_empty());
}
