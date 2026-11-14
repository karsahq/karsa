use super::*;
use crate::{SlotAgreementPreviousPol, SlotAgreementViewProposal, slot_agreement_view_proposer};

fn author_index(f: &Fixture, id: &VertexId) -> usize {
    f.dag
        .set()
        .validators
        .iter()
        .position(|v| v.validator_id == id.author)
        .unwrap()
}

fn rebind_view(
    f: &mut Fixture,
    p: &SlotAgreementViewProposal,
    c: &VertexId,
    refs: Vec<VertexId>,
) -> VertexId {
    let digest = p.digest(f.dag.set()).unwrap();
    bind_as(f, author_index(f, c), c.round, refs, digest)
}

fn assert_rejected(
    f: &Fixture,
    p: &SlotAgreementViewProposal,
    c: &VertexId,
    b: &SlotAgreementBinding,
    message: &str,
) {
    let bytes = p.encode(f.dag.set()).unwrap();
    assert_eq!(
        SlotAgreementViewProposal::decode(&bytes, f.dag.set()).unwrap(),
        *p
    );
    let error = f
        .dag
        .inspect_slot_agreement_view_proposal(p, c, b)
        .unwrap_err();
    assert!(
        error.to_string().contains(message),
        "expected {message}: {error}"
    );
}

fn view_fixture(
    pol: bool,
    view: u64,
    wrong_author: bool,
) -> (
    Fixture,
    SlotAgreementViewProposal,
    VertexId,
    SlotAgreementBinding,
) {
    let (mut f, chain, _, binding) = strong_fixture(true, 0);
    let p = SlotAgreementViewProposal {
        view: AgreementView(view),
        proposal: chain.prevote.aggregate.proposal.clone(),
        proposal_carrier: chain.prevote.aggregate.proposal_carrier.clone(),
        previous_pol: pol.then_some(SlotAgreementPreviousPol {
            payload: chain.prevote,
            carrier: chain.prevote_carrier,
        }),
    };
    let selected =
        slot_agreement_view_proposer(f.dag.set(), p.proposal.decision.round, p.view).unwrap();
    let mut author = f
        .dag
        .set()
        .validators
        .iter()
        .position(|v| v.validator_id == selected)
        .unwrap();
    if wrong_author {
        author = (author + 1) % f.count();
    }
    let prior_refs = f.ids(LEADER_ROUND + 5);
    for i in 1..f.count() {
        let v = vertex(&f, i, LEADER_ROUND + 6, prior_refs.clone());
        f.dag.insert(v).unwrap();
    }
    let refs = f.ids(LEADER_ROUND + 6);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind_as(&mut f, author, LEADER_ROUND + 7, refs, digest);
    (f, p, c, binding)
}

#[test]
fn authenticated_view_and_legacy_pol_roundtrip() {
    for pol in [false, true] {
        let (f, p, c, b) = view_fixture(pol, if pol { 3 } else { 0 }, false);
        assert_eq!(
            SlotAgreementViewProposal::decode(&p.encode(f.dag.set()).unwrap(), f.dag.set())
                .unwrap(),
            p
        );
        assert!(
            f.dag
                .inspect_slot_agreement_view_proposal(&p, &c, &b)
                .is_ok()
        );
        let bytes = p.encode(f.dag.set()).unwrap();
        for end in 0..bytes.len() {
            assert!(SlotAgreementViewProposal::decode(&bytes[..end], f.dag.set()).is_err());
        }
        let mut trailing = bytes;
        trailing.push(0);
        assert!(SlotAgreementViewProposal::decode(&trailing, f.dag.set()).is_err());
        assert!(SlotAgreementViewProposal::decode(&vec![0; 1024 * 1024 + 1], f.dag.set()).is_err());
    }
}

#[test]
fn rejects_wrong_proposer_and_equal_pol_view() {
    for (view, wrong) in [(3, true), (2, false), (1, false)] {
        let (f, p, c, b) = view_fixture(true, view, wrong);
        assert!(
            f.dag
                .inspect_slot_agreement_view_proposal(&p, &c, &b)
                .is_err()
        );
    }
}

#[test]
fn rejects_signed_bad_pol_value_context_and_missing_carrier() {
    for mode in 0..3 {
        let (mut f, mut p, c, b) = view_fixture(true, 3, false);
        let pol = p.previous_pol.as_mut().unwrap();
        match mode {
            0 => pol.payload.aggregate.proposal.decision.after_root[0] ^= 1,
            1 => {
                pol.payload.aggregate.certificate.vote.context =
                    crate::SlotDecisionTip::from_checkpoint(
                        b.tip().chain_id().to_vec(),
                        f.dag.set(),
                        b.tip().next_round(),
                        [99; 32],
                        b.tip().order_len(),
                        *b.tip().order_root(),
                    )
                    .unwrap()
            }
            _ => pol.carrier.digest[0] ^= 1,
        }
        // Wrong-value evidence may be rejected structurally before carrier signing.
        if let Ok(digest) = p.digest(f.dag.set()) {
            let refs = f.ids(c.round - 1);
            let author = f
                .dag
                .set()
                .validators
                .iter()
                .position(|v| v.validator_id == c.author)
                .unwrap();
            let carrier = bind_as(&mut f, author, c.round, refs, digest);
            assert!(
                f.dag
                    .inspect_slot_agreement_view_proposal(&p, &carrier, &b)
                    .is_err()
            );
        } else {
            assert!(mode < 2);
        }
    }
}

fn rebind_pol_at_outer_parent(f: &mut Fixture, p: &mut SlotAgreementViewProposal, c: &VertexId) {
    let pol = p.previous_pol.as_mut().unwrap();
    let refs = f.ids(c.round - 2);
    let digest = pol.payload.digest(f.dag.set()).unwrap();
    pol.carrier = bind_as(f, 3, c.round - 1, refs, digest);
}

#[test]
fn matching_invalid_qc_and_individual_signatures_reach_crypto() {
    let (mut f, mut p, c, b) = view_fixture(true, 3, false);
    let pol = p.previous_pol.as_mut().unwrap();
    pol.payload.aggregate.certificate.signatures[0].signature[0] ^= 1;
    pol.payload.votes[0].payload.signature =
        pol.payload.aggregate.certificate.signatures[0].clone();
    let w = &mut pol.payload.votes[0];
    let refs = f.ids(w.carrier.round - 1);
    let digest = w.payload.digest(f.dag.set()).unwrap();
    w.carrier = bind_as(&mut f, 0, w.carrier.round, refs, digest);
    for round in LEADER_ROUND + 4..c.round {
        let refs = f.ids(round - 1);
        f.dag.vertices.retain(|(r, _), _| *r != round);
        f.full_round(round, &refs).unwrap();
    }
    rebind_pol_at_outer_parent(&mut f, &mut p, &c);
    let refs = f.ids(c.round - 1);
    let c = rebind_view(&mut f, &p, &c, refs);
    let error = f
        .dag
        .inspect_slot_agreement_view_proposal(&p, &c, &b)
        .unwrap_err();
    p.encode(f.dag.set()).unwrap();
    assert_eq!(error.kind(), crypto::CryptoErrorKind::InvalidSignature);
    let pol = p.previous_pol.as_ref().unwrap();
    let vote_error = pol.payload.votes[0]
        .payload
        .verify(b.tip(), f.dag.set())
        .unwrap_err();
    assert_eq!(vote_error.kind(), crypto::CryptoErrorKind::InvalidSignature);
    f.dag
        .slot_causal_history_with_budget(
            &c,
            p.digest(f.dag.set()).unwrap(),
            &p.proposal.decision,
            &mut 100_000,
        )
        .unwrap();
    assert_eq!(
        SlotAgreementViewProposal::decode(&p.encode(f.dag.set()).unwrap(), f.dag.set()).unwrap(),
        p
    );
}

#[test]
fn alternate_context_pol_is_resigned_and_rebound() {
    let (mut f, mut p, c, b) = view_fixture(true, 3, false);
    let pol = p.previous_pol.as_mut().unwrap();
    let d = &mut pol.payload.aggregate.proposal.decision;
    d.previous = [99; 32];
    let tip = crate::SlotDecisionTip::from_checkpoint(
        d.chain_id.clone(),
        f.dag.set(),
        d.round,
        d.previous,
        d.before_len,
        d.before_root,
    )
    .unwrap();
    let qc = qc(
        &f,
        &tip,
        &pol.payload.aggregate.proposal,
        AgreementPhase::Prevote,
    );
    qc.verify(&tip, f.dag.set()).unwrap();
    pol.payload.aggregate.certificate = qc.clone();
    // Give the alternate context a genuine plain-proposal carrier too.
    let refs = f.ids(LEADER_ROUND + 1);
    let direct = bind_as(
        &mut f,
        3,
        LEADER_ROUND + 2,
        refs,
        pol.payload.aggregate.proposal.digest().unwrap(),
    );
    pol.payload.aggregate.proposal_carrier = direct.clone();
    for (i, w) in pol.payload.votes.iter_mut().enumerate() {
        w.payload.vote = qc.vote.clone();
        w.payload.signature = qc.signatures[i].clone();
        w.payload.prerequisite = direct.clone();
        w.payload.verify(&tip, f.dag.set()).unwrap();
        let refs = f.ids(LEADER_ROUND + 2);
        let digest = w.payload.digest(f.dag.set()).unwrap();
        w.carrier = bind_as(&mut f, i, LEADER_ROUND + 3, refs, digest);
    }
    let refs = f.ids(LEADER_ROUND + 2);
    let v = vertex(&f, 3, LEADER_ROUND + 3, refs);
    f.dag.vertices.remove(&(v.round, v.author.clone()));
    f.dag.insert(v).unwrap();
    // Rebuild descendants so no old witness IDs remain in the retained cone.
    for round in LEADER_ROUND + 4..c.round {
        let refs = f.ids(round - 1);
        f.dag.vertices.retain(|(r, _), _| *r != round);
        f.full_round(round, &refs).unwrap();
    }
    rebind_pol_at_outer_parent(&mut f, &mut p, &c);
    let refs = f.ids(c.round - 1);
    let c = rebind_view(&mut f, &p, &c, refs);
    assert_rejected(&f, &p, &c, &b, "exact decision");
}

#[test]
fn direct_proposal_outside_view_cone() {
    let (mut f, mut p, c, b) = view_fixture(false, 0, false);
    let refs = f.ids(c.round - 2);
    p.proposal_carrier = bind_as(&mut f, 3, c.round - 1, refs, p.proposal.digest().unwrap());
    let refs = f
        .ids(c.round - 1)
        .into_iter()
        .filter(|id| *id != p.proposal_carrier)
        .collect();
    let c = rebind_view(&mut f, &p, &c, refs);
    assert_rejected(&f, &p, &c, &b, "does not extend direct evidence");
}

#[test]
fn pol_outside_view_cone() {
    let (mut f, mut p, c, b) = view_fixture(true, 3, false);
    rebind_pol_at_outer_parent(&mut f, &mut p, &c);
    let refs = f
        .ids(c.round - 1)
        .into_iter()
        .filter(|id| *id != p.previous_pol.as_ref().unwrap().carrier)
        .collect();
    let c = rebind_view(&mut f, &p, &c, refs);
    assert_rejected(&f, &p, &c, &b, "POL must be earlier");
}

fn mode_view(
    mode: u8,
) -> (
    Fixture,
    SlotAgreementViewProposal,
    VertexId,
    SlotAgreementBinding,
) {
    let (mut f, chain, _, b) = strong_fixture(true, mode);
    let p = SlotAgreementViewProposal {
        view: AgreementView(3),
        proposal: chain.prevote.aggregate.proposal.clone(),
        proposal_carrier: chain.prevote.aggregate.proposal_carrier.clone(),
        previous_pol: Some(SlotAgreementPreviousPol {
            payload: chain.prevote,
            carrier: chain.prevote_carrier,
        }),
    };
    let selected =
        slot_agreement_view_proposer(f.dag.set(), p.proposal.decision.round, p.view).unwrap();
    let author = f
        .dag
        .set()
        .validators
        .iter()
        .position(|v| v.validator_id == selected)
        .unwrap();
    // The outer carrier sees all votes directly through a fresh full round,
    // even if the POL carrier omitted one witness.
    let mut refs = f.ids(LEADER_ROUND + 4);
    refs.push(
        p.previous_pol.as_ref().unwrap().payload.votes[0]
            .carrier
            .clone(),
    );
    f.dag.vertices.retain(|(r, _), _| *r != LEADER_ROUND + 5);
    f.full_round(LEADER_ROUND + 5, &refs).unwrap();
    let refs = f.ids(LEADER_ROUND + 5);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind_as(&mut f, author, LEADER_ROUND + 6, refs, digest);
    (f, p, c, b)
}

#[test]
fn witness_in_outer_cone_but_not_pol_cone() {
    let (f, p, c, b) = mode_view(5);
    let pol = p.previous_pol.as_ref().unwrap();
    let cone = f
        .dag
        .slot_causal_history_with_budget(
            &c,
            p.digest(f.dag.set()).unwrap(),
            &p.proposal.decision,
            &mut 100_000,
        )
        .unwrap();
    assert!(cone.contains(&pol.payload.votes[0].carrier));
    assert_rejected(&f, &p, &c, &b, "POL lacks individual vote carrier");
}

#[test]
fn prerequisite_absent_from_individual_vote_cone() {
    let (f, p, c, b) = mode_view(2);
    let pol = p.previous_pol.as_ref().unwrap();
    let w = &pol.payload.votes[0];
    let cone = f
        .dag
        .slot_causal_history_with_budget(
            &w.carrier,
            w.payload.digest(f.dag.set()).unwrap(),
            &p.proposal.decision,
            &mut 100_000,
        )
        .unwrap();
    assert!(!cone.contains(&pol.payload.aggregate.proposal_carrier));
    w.payload.verify(b.tip(), f.dag.set()).unwrap();
    assert_rejected(&f, &p, &c, &b, "POL vote lacks plain proposal prerequisite");
}

#[test]
fn predecessor_in_outer_cone_only_is_not_sufficient() {
    let (f, p, c, b) = view_fixture(true, 3, false);
    let predecessor = f.ids(c.round - 1)[0].clone();
    let b = SlotAgreementBinding::from_checkpoint(b.tip().clone(), Some(predecessor)).unwrap();
    assert_rejected(&f, &p, &c, &b, "does not extend predecessor");
}

#[test]
fn corrupt_outer_sidecone_is_not_skipped() {
    let (mut f, p, c, b) = view_fixture(true, 3, false);
    let side = f
        .ids(c.round - 1)
        .into_iter()
        .find(|id| id.author == b"val-1")
        .unwrap();
    let vertex = f
        .dag
        .vertices
        .get_mut(&(side.round, side.author.clone()))
        .unwrap();
    vertex.signature[0] ^= 1;
    assert_eq!(
        vertex.id().unwrap(),
        side,
        "signature corruption preserves the exact signed-content ID"
    );
    p.encode(f.dag.set()).unwrap();
    let error = f
        .dag
        .inspect_slot_agreement_view_proposal(&p, &c, &b)
        .unwrap_err();
    assert_eq!(error.kind(), crypto::CryptoErrorKind::InvalidSignature);
}

#[test]
fn positive_skip_with_pol_is_pure() {
    let (mut f, chain, _, b) = strong_fixture(false, 0);
    let p = SlotAgreementViewProposal {
        view: AgreementView(3),
        proposal: chain.prevote.aggregate.proposal.clone(),
        proposal_carrier: chain.prevote.aggregate.proposal_carrier.clone(),
        previous_pol: Some(SlotAgreementPreviousPol {
            payload: chain.prevote,
            carrier: chain.prevote_carrier,
        }),
    };
    let selected =
        slot_agreement_view_proposer(f.dag.set(), p.proposal.decision.round, p.view).unwrap();
    let author = f
        .dag
        .set()
        .validators
        .iter()
        .position(|v| v.validator_id == selected)
        .unwrap();
    let refs = f.ids(LEADER_ROUND + 5);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind_as(&mut f, author, LEADER_ROUND + 6, refs, digest);
    let before = b.clone();
    for _ in 0..2 {
        let decision = inspect_without_effects(&f.dag, |dag| {
            dag.inspect_slot_agreement_view_proposal(&p, &c, &b)
        });
        assert_eq!(decision, Decision::Skip);
        assert_eq!(b, before);
    }
}

#[test]
fn shared_budget_equals_sum_of_all_individual_walks() {
    let (f, p, c, b) = view_fixture(true, 3, false);
    let d = &p.proposal.decision;
    let set = f.dag.set();
    let pol = p.previous_pol.as_ref().unwrap();
    let mut walks = vec![
        (c.clone(), p.digest(set).unwrap()),
        (p.proposal_carrier.clone(), p.proposal.digest().unwrap()),
        (pol.carrier.clone(), pol.payload.digest(set).unwrap()),
        (
            pol.payload.aggregate.proposal_carrier.clone(),
            pol.payload.aggregate.proposal.digest().unwrap(),
        ),
    ];
    walks.extend(
        pol.payload
            .votes
            .iter()
            .map(|w| (w.carrier.clone(), w.payload.digest(set).unwrap())),
    );
    let costs: Vec<_> = walks
        .iter()
        .map(|(id, digest)| {
            let mut budget = 100_000;
            if id == &p.proposal_carrier {
                f.dag
                    .inspect_slot_proposal_with_budget(
                        &p.proposal.clone().into(),
                        id,
                        b.tip(),
                        &mut budget,
                    )
                    .unwrap();
            } else if id == &pol.payload.aggregate.proposal_carrier {
                f.dag
                    .inspect_slot_proposal_with_budget(
                        &pol.payload.aggregate.proposal.clone().into(),
                        id,
                        b.tip(),
                        &mut budget,
                    )
                    .unwrap();
            } else {
                f.dag
                    .slot_causal_history_with_budget(id, *digest, d, &mut budget)
                    .unwrap();
            }
            100_000 - budget
        })
        .collect();
    let sum: usize = costs.iter().sum();
    assert!(sum > *costs.iter().max().unwrap());
    assert!(
        f.dag
            .inspect_slot_agreement_view_with_budget(&p, &c, &b, sum)
            .is_ok()
    );
    let error = f
        .dag
        .inspect_slot_agreement_view_with_budget(&p, &c, &b, sum - 1)
        .unwrap_err();
    assert!(error.to_string().contains("budget exhausted"), "{error}");
    assert!(
        f.dag
            .inspect_slot_agreement_view_with_budget(&p, &c, &b, *costs.iter().max().unwrap())
            .is_err()
    );
}

#[test]
fn rotation_is_order_independent_and_rejects_duplicate_set() {
    let (f, _, _, _) = strong_fixture(true, 0);
    let mut set = f.dag.set().clone();
    for view in [0, 1, u64::MAX] {
        let expected = slot_agreement_view_proposer(&set, u64::MAX, AgreementView(view))
            .unwrap()
            .to_vec();
        set.validators.reverse();
        assert_eq!(
            slot_agreement_view_proposer(&set, u64::MAX, AgreementView(view)).unwrap(),
            expected
        );
    }
    set.validators.push(set.validators[0].clone());
    assert!(slot_agreement_view_proposer(&set, 1, AgreementView(0)).is_err());
}
