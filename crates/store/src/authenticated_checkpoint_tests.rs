use super::*;
use crate::slot_application_tests::{Fixture, TempDir, signed_vertex};
use validator::slot_agreement::{AgreementPhase, AgreementView};
use validator::{
    Dag, Decision, SlotAgreementProofEntry, SlotAgreementViewLineage, SlotDecision,
    SlotDecisionTip, SlotOutcome, SlotProposal,
};

fn checkpoint() -> (Fixture, AuthenticatedSlotAgreementBootstrap) {
    let f = Fixture::new(true);
    let mut state = f.state(f.vertices.clone());
    state.prepare(&f.payload, &f.carrier).unwrap().apply();
    f.assert_applied(&state);
    let order = state.dag().order().to_vec();
    assert!(!order.is_empty());
    let context = state.binding().tip().clone();
    assert_eq!(context.next_round(), 2);
    assert_eq!(context.order_len(), order.len() as u64);
    assert_eq!(context.order_root(), &state.dag().commit_root());
    let b = AuthenticatedSlotAgreementBootstrap {
        agreement: SlotAgreementBootstrap {
            context,
            set: f.set.clone(),
            local_validator: f.set.validators[0].validator_id.clone(),
        },
        // This legacy QC carrier is imported as trusted checkpoint data, not authenticated agreement evidence.
        predecessor: state.binding().carrier().cloned(),
        order,
        vertices: f.vertices.clone(),
    };
    assert_eq!(b.predecessor.as_ref(), Some(&f.carrier));
    (f, b)
}

fn later_proposal(
    f: &Fixture,
    b: &AuthenticatedSlotAgreementBootstrap,
) -> AuthenticatedSlotAgreementRequest {
    let mut state = f.state(f.vertices.clone());
    state.prepare(&f.payload, &f.carrier).unwrap().apply();
    let Decision::Commit(history) = state.dag().inspect_commit(2).unwrap() else {
        panic!("round three must support the round two leader");
    };
    assert!(!history.is_empty());
    let mut order = b.order.clone();
    order.extend(history);
    let mut ordered = Dag::new(f.set.clone());
    ordered.seed_order(order.clone());
    let proposal = SlotProposal {
        decision: SlotDecision {
            chain_id: b.agreement.context.chain_id().to_vec(),
            validator_set_id: f.set.id().unwrap(),
            epoch: f.set.epoch,
            round: 2,
            previous: *b.agreement.context.previous_id(),
            before_len: b.order.len() as u64,
            before_root: *b.agreement.context.order_root(),
            after_len: order.len() as u64,
            after_root: ordered.commit_root(),
            outcome: SlotOutcome::Commit {
                leader: state.dag().leader(2).unwrap().id().unwrap(),
            },
        },
        voters: f
            .vertices
            .iter()
            .filter(|v| v.round == 3)
            .take(3)
            .map(|v| v.id().unwrap())
            .collect(),
    };
    let round_three: Vec<_> = f
        .vertices
        .iter()
        .filter(|v| v.round == 3)
        .map(|v| v.id().unwrap())
        .collect();
    let mut vertices = Vec::new();
    let mut refs = vec![f.carrier.clone()];
    for author in [0, 2, 3] {
        let v = signed_vertex(&f.keys, author, 4, round_three.clone(), [4; 32]);
        refs.push(v.id().unwrap());
        vertices.push(v);
    }
    let mut round_five = Vec::new();
    for author in 0..4 {
        let hash = if author == 0 {
            proposal.digest().unwrap()
        } else {
            [5; 32]
        };
        let v = signed_vertex(&f.keys, author, 5, refs.clone(), hash);
        round_five.push(v.id().unwrap());
        vertices.push(v);
    }
    let mut lineage = SlotAgreementViewLineage {
        entries: vec![SlotAgreementProofEntry {
            proposal,
            proposal_carrier: round_five[0].clone(),
            view: AgreementView(0),
            view_carrier: round_five[0].clone(),
            previous_pol: None,
            pol: None,
        }],
    };
    let proposer = validator::slot_agreement_view_proposer(&f.set, 2, AgreementView(0)).unwrap();
    let author = f
        .set
        .validators
        .iter()
        .position(|v| v.validator_id == proposer)
        .unwrap();
    let v = signed_vertex(
        &f.keys,
        author,
        6,
        round_five,
        lineage.view_digest(0).unwrap(),
    );
    lineage.entries[0].view_carrier = v.id().unwrap();
    vertices.push(v);
    AuthenticatedSlotAgreementRequest::Propose { lineage, vertices }
}

#[test]
fn nonempty_checkpoint_later_proposal_survives_generation_cleanup_and_recovery() {
    let (f, bootstrap) = checkpoint();
    let request = later_proposal(&f, &bootstrap);
    let dir = TempDir::new();
    let mut store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let header = fs::read(&path).unwrap();
    drop(owner);
    drop(store);
    let reopened = Store::open(&dir.0).unwrap();
    owner = reopened
        .recover_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    assert_eq!(fs::read(&path).unwrap(), header);
    let result = owner.apply(1, request.clone()).unwrap();
    assert_eq!(result.vote.as_ref().unwrap().phase, AgreementPhase::Prevote);
    assert_eq!(
        result.vote.as_ref().unwrap().context,
        bootstrap.agreement.context
    );
    let bytes = fs::read(&path).unwrap();
    drop(owner);
    drop(reopened);
    store = Store::open(&dir.0).unwrap();
    store.stage().unwrap().activate().unwrap();
    let old_generation = store.active.read().unwrap().clone();
    store.stage().unwrap().activate().unwrap();
    assert!(
        !old_generation.exists(),
        "activation must clean the old generation"
    );
    assert!(
        store.vertices().unwrap().is_empty(),
        "dependencies live in the authenticated WAL, not the generation vertex log"
    );
    drop(store);
    drop(f);
    let store = Store::open(&dir.0).unwrap();
    let mut owner = store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(owner.apply(1, request).unwrap().vote, result.vote);
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn nonempty_checkpoint_rejects_wrong_order_frontier_and_recovery_carrier_without_writes() {
    let (_f, bootstrap) = checkpoint();
    let mut wrong_order = bootstrap.clone();
    wrong_order.order.swap(0, 1);
    let mut wrong_frontier = bootstrap.clone();
    let c = &bootstrap.agreement.context;
    let mut root = *c.order_root();
    root[0] ^= 1;
    wrong_frontier.agreement.context = SlotDecisionTip::from_checkpoint(
        c.chain_id().to_vec(),
        &bootstrap.agreement.set,
        c.next_round(),
        *c.previous_id(),
        c.order_len(),
        root,
    )
    .unwrap();
    let mut missing_dependency = bootstrap.clone();
    missing_dependency.vertices.remove(0);
    for invalid in [&wrong_order, &wrong_frontier, &missing_dependency] {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        assert!(
            store
                .begin_authenticated_slot_agreement(invalid.clone())
                .is_err()
        );
        assert!(!dir.0.join(authenticated_slot_agreement::FILE).exists());
        assert!(!dir.0.join("CURRENT").exists());
        store
            .begin_authenticated_slot_agreement(bootstrap.clone())
            .unwrap();
    }
    let dir = TempDir::new();
    let store = Store::open(&dir.0).unwrap();
    store
        .begin_authenticated_slot_agreement(bootstrap.clone())
        .unwrap();
    let path = dir.0.join(authenticated_slot_agreement::FILE);
    let bytes = fs::read(&path).unwrap();
    let mut wrong_carrier = bootstrap.clone();
    wrong_carrier.predecessor.as_mut().unwrap().digest[0] ^= 1;
    for invalid in [
        wrong_order,
        wrong_frontier,
        missing_dependency,
        wrong_carrier,
    ] {
        assert!(store.recover_authenticated_slot_agreement(invalid).is_err());
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert!(!dir.0.join("CURRENT").exists());
    }
    store
        .recover_authenticated_slot_agreement(bootstrap)
        .unwrap();
    assert_eq!(fs::read(path).unwrap(), bytes);
}
