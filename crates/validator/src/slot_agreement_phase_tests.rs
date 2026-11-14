use super::*;
#[path = "slot_agreement_view_tests.rs"]
mod view_tests;
use crate::slot_agreement::{
    AgreementPhase, AgreementQc, AgreementValue, AgreementView, AgreementVote,
};
use crate::{
    SlotAgreementBinding, SlotAgreementPhaseChain, SlotAgreementPrevotePayload,
    SlotAgreementStrongPhaseChain, SlotAgreementStrongPrevotePayload, SlotAgreementVotePayload,
    SlotAgreementVoteWitness,
};

fn bind_as(
    f: &mut Fixture,
    author: usize,
    round: u64,
    refs: Vec<VertexId>,
    digest: [u8; 32],
) -> VertexId {
    let v = vertex_with_payload(f, author, round, refs, digest);
    f.dag.vertices.remove(&(v.round, v.author.clone()));
    f.dag.insert(v).unwrap()
}

// Modes isolate one invalid relation while retaining valid vertex/vote signatures.
fn strong_fixture(
    commit: bool,
    mode: u8,
) -> (
    Fixture,
    SlotAgreementStrongPhaseChain,
    VertexId,
    SlotAgreementBinding,
) {
    let (mut f, proposal, proposal_carrier, tip) = direct_slot_proposal(commit);
    let refs = f.ids(LEADER_ROUND + 1);
    for author in 1..f.count() {
        let v = vertex(&f, author, LEADER_ROUND + 2, refs.clone());
        f.dag.insert(v).unwrap();
    }
    let prevote_qc = qc(&f, &tip, &proposal, AgreementPhase::Prevote);
    let final_qc = qc(&f, &tip, &proposal, AgreementPhase::Precommit);
    let refs = f.ids(LEADER_ROUND + 2);
    f.full_round(LEADER_ROUND + 3, &refs).unwrap();
    let mut prevotes = Vec::new();
    for (i, signature) in prevote_qc.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: prevote_qc.vote.clone(),
            signature: signature.clone(),
            prerequisite: proposal_carrier.clone(),
        };
        let mut refs = refs.clone();
        if mode == 2 && i == 0 {
            refs.retain(|id| *id != proposal_carrier);
        }
        let author = if mode == 1 && i == 0 { 3 } else { i };
        let mut digest = payload.digest(f.dag.set()).unwrap();
        if mode == 6 && i == 0 {
            digest[0] ^= 1;
        }
        let carrier = bind_as(&mut f, author, LEADER_ROUND + 3, refs, digest);
        prevotes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    let prevote = SlotAgreementStrongPrevotePayload {
        aggregate: SlotAgreementPrevotePayload {
            proposal,
            proposal_carrier,
            certificate: prevote_qc,
        },
        votes: prevotes,
    };
    let mut refs = f.ids(LEADER_ROUND + 3);
    if mode == 5 {
        refs.retain(|id| *id != prevote.votes[0].carrier);
    }
    f.full_round(LEADER_ROUND + 4, &refs).unwrap();
    let digest = if mode == 1 {
        [0; 32]
    } else if mode == 7 {
        prevote.aggregate.digest(f.dag.set()).unwrap()
    } else {
        prevote.digest(f.dag.set()).unwrap()
    };
    let prevote_carrier = bind_as(&mut f, 0, LEADER_ROUND + 4, refs, digest);
    let refs = f.ids(LEADER_ROUND + 4);
    f.full_round(LEADER_ROUND + 5, &refs).unwrap();
    let mut votes = Vec::new();
    for (i, signature) in final_qc.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: final_qc.vote.clone(),
            signature: signature.clone(),
            prerequisite: prevote_carrier.clone(),
        };
        let mut refs = refs.clone();
        if mode == 3 && i == 0 {
            refs.retain(|id| *id != prevote_carrier);
        }
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(&mut f, i, LEADER_ROUND + 5, refs, digest);
        votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    let p = SlotAgreementStrongPhaseChain {
        prevote,
        prevote_carrier,
        certificate: final_qc,
        votes,
    };
    let mut refs = f.ids(LEADER_ROUND + 5);
    if mode == 4 {
        refs.retain(|id| *id != p.votes[0].carrier);
    }
    let digest = if mode == 1 {
        [0; 32]
    } else {
        p.digest(f.dag.set()).unwrap()
    };
    let c = bind_as(&mut f, 0, LEADER_ROUND + 6, refs, digest);
    let b = SlotAgreementBinding::from_checkpoint(tip, Some(f.ids(0)[0].clone())).unwrap();
    (f, p, c, b)
}

#[test]
fn strong_phase_chain_accepts_genuine_five_stage_signed_chain() {
    for commit in [false, true] {
        let (f, p, c, b) = strong_fixture(commit, 0);
        let before = b.clone();
        let result = inspect_without_effects(&f.dag, |dag| {
            dag.inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
        });
        assert_eq!(
            result,
            f.dag
                .inspect_slot_proposal(
                    &p.prevote.aggregate.proposal,
                    &p.prevote.aggregate.proposal_carrier,
                    b.tip()
                )
                .unwrap()
        );
        assert_eq!(before, b);
        let aggregate = SlotAgreementPhaseChain {
            prevote: p.prevote.aggregate.clone(),
            prevote_carrier: p.prevote_carrier.clone(),
            certificate: p.certificate.clone(),
        };
        assert!(
            f.dag
                .inspect_slot_agreement_phase_chain(&aggregate, &c, &b)
                .is_err(),
            "strong hashes must not masquerade as aggregate hashes"
        );
    }
}

#[test]
fn strong_phase_chain_rejects_missing_vote_or_prerequisite_cones() {
    for mode in 2..=5 {
        let (f, p, c, b) = strong_fixture(true, mode);
        if mode == 2 || mode == 3 {
            let witness = if mode == 2 {
                &p.prevote.votes[0]
            } else {
                &p.votes[0]
            };
            assert!(
                f.dag
                    .get(
                        witness.payload.prerequisite.round,
                        &witness.payload.prerequisite.author
                    )
                    .is_some()
            );
            assert!(
                !f.dag
                    .is_ancestor(&witness.payload.prerequisite, &witness.carrier)
                    .unwrap()
            );
            witness.payload.verify(b.tip(), f.dag.set()).unwrap();
        }
        let error = f
            .dag
            .inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
            .unwrap_err();
        let expected = if mode <= 3 {
            "individual vote does not extend its exact prerequisite"
        } else {
            "QC does not extend every exact individual vote carrier"
        };
        assert!(error.to_string().contains(expected), "mode {mode}: {error}");
    }
}

#[test]
fn strong_phase_chain_valid_divergent_vertex_author_is_rejected() {
    let (f, p, c, b) = strong_fixture(true, 1);
    let w = &p.prevote.votes[0];
    w.payload.verify(b.tip(), f.dag.set()).unwrap();
    let v = f.dag.get(w.carrier.round, &w.carrier.author).unwrap();
    v.verify(f.dag.set(), b.tip().epoch()).unwrap();
    assert_eq!(v.payload_hash, w.payload.digest(f.dag.set()).unwrap());
    assert_ne!(w.carrier.author, w.payload.signature.validator_id);
    assert!(
        f.dag
            .inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn strong_phase_chain_rejects_substituted_signer_carrier_signature_and_order() {
    let (f, p, c, b) = strong_fixture(true, 0);
    for mutation in 0..10 {
        let mut bad = p.clone();
        match mutation {
            0 => bad.votes[0].payload.signature.signature[0] ^= 1,
            1 => bad.votes[0].carrier = bad.votes[1].carrier.clone(),
            2 => bad.votes[0].payload.signature = bad.votes[1].payload.signature.clone(),
            3 => bad.votes.swap(0, 1),
            4 => {
                bad.votes.pop();
            }
            5 => bad.votes[0].payload.vote.view.0 += 1,
            6 => bad.votes[0].payload.vote.phase = AgreementPhase::Prevote,
            7 => bad.votes[0].payload.prerequisite = bad.prevote.aggregate.proposal_carrier.clone(),
            8 => bad.votes[0].payload.vote.value = AgreementValue::Nil,
            _ => bad.votes.push(bad.votes[0].clone()),
        }
        assert!(bad.encode(f.dag.set()).is_err(), "mutation {mutation}");
        assert!(
            f.dag
                .inspect_slot_agreement_strong_phase_chain(&bad, &c, &b)
                .is_err()
        );
    }
    // Rebinding the final body cannot make a nonexistent exact vote carrier valid.
    let mut bad = p.clone();
    bad.votes[0].carrier.digest[0] ^= 1;
    let refs = f.ids(LEADER_ROUND + 5);
    let mut f = f;
    let digest = bad.digest(f.dag.set()).unwrap();
    let c = bind_as(&mut f, 0, LEADER_ROUND + 6, refs, digest);
    assert!(
        f.dag
            .inspect_slot_agreement_strong_phase_chain(&bad, &c, &b)
            .is_err()
    );
}

#[test]
fn strong_phase_chain_rejects_work_exhaustion_and_corrupt_sidecone() {
    let (mut f, p, c, b) = strong_fixture(true, 0);
    let error = f
        .dag
        .inspect_slot_agreement_strong_with_budget(&p, &c, &b, 1)
        .unwrap_err();
    assert!(
        error.to_string().contains("work budget exhausted"),
        "{error}"
    );
    let side = f.ids(LEADER_ROUND + 5)[3].clone();
    f.dag
        .vertices
        .get_mut(&(side.round, side.author))
        .unwrap()
        .signature[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn strong_phase_budget_fanout_preflight_precedes_invalid_signature() {
    let (mut f, p, c, _) = strong_fixture(true, 0);
    let vertex = f
        .dag
        .vertices
        .get_mut(&(c.round, c.author.clone()))
        .unwrap();
    assert!(vertex.references.len() > 1);
    vertex.signature[0] ^= 1;
    let decision = &p.prevote.aggregate.proposal.decision;
    let digest = p.digest(f.dag.set()).unwrap();
    // The root consumes one visit, leaving only one for its larger fanout.
    let error = f
        .dag
        .slot_causal_history_with_budget(&c, digest, decision, &mut 2)
        .unwrap_err();
    assert!(
        error.to_string().contains("work budget exhausted"),
        "{error}"
    );
    let error = f.dag.slot_causal_history(&c, digest, decision).unwrap_err();
    assert!(
        !error.to_string().contains("work budget exhausted"),
        "unlimited wrapper must reach invalid vertex authentication: {error}"
    );
}

#[test]
fn strong_phase_budget_exact_shared_boundary_not_per_walk() {
    let (f, p, c, b) = strong_fixture(true, 0);
    let decision = &p.prevote.aggregate.proposal.decision;
    let set = f.dag.set();
    let mut walks = vec![
        (&c, p.digest(set).unwrap()),
        (&p.prevote_carrier, p.prevote.digest(set).unwrap()),
    ];
    for w in p.prevote.votes.iter().chain(&p.votes) {
        walks.push((&w.carrier, w.payload.digest(set).unwrap()));
    }
    walks.push((
        &p.prevote.aggregate.proposal_carrier,
        p.prevote.aggregate.proposal.digest().unwrap(),
    ));
    let mut total = 0;
    let mut maximum = 0;
    for (carrier, digest) in &walks {
        let mut remaining = usize::MAX;
        f.dag
            .slot_causal_history_with_budget(carrier, *digest, decision, &mut remaining)
            .unwrap();
        let used = usize::MAX - remaining;
        total += used;
        maximum = maximum.max(used);
    }
    assert!(total > maximum);
    // Every individual walk fits this budget, but their shared sum does not.
    for (carrier, digest) in &walks {
        let mut remaining = maximum;
        f.dag
            .slot_causal_history_with_budget(carrier, *digest, decision, &mut remaining)
            .unwrap();
    }
    let expected = f
        .dag
        .inspect_slot_proposal(
            &p.prevote.aggregate.proposal,
            &p.prevote.aggregate.proposal_carrier,
            b.tip(),
        )
        .unwrap();
    assert_eq!(
        f.dag
            .inspect_slot_agreement_strong_with_budget(&p, &c, &b, total)
            .unwrap(),
        expected
    );
    for budget in [total - 1, maximum] {
        let error = f
            .dag
            .inspect_slot_agreement_strong_with_budget(&p, &c, &b, budget)
            .unwrap_err();
        assert!(
            error.to_string().contains("work budget exhausted"),
            "budget {budget}, exact total {total}: {error}"
        );
    }
}

#[test]
fn strong_phase_rejects_wrong_witness_hash_and_aggregate_intermediate_with_rebuilt_dependents() {
    for mode in [6, 7] {
        let (f, p, c, b) = strong_fixture(true, mode);
        let set = f.dag.set();
        let decision = &p.prevote.aggregate.proposal.decision;
        // All downstream vertices are freshly signed over the changed exact IDs;
        // final binding and full-cone authentication are independently valid.
        f.dag
            .slot_causal_history(&c, p.digest(set).unwrap(), decision)
            .unwrap();
        for w in p.prevote.votes.iter().chain(&p.votes) {
            w.payload.verify(b.tip(), set).unwrap();
        }
        if mode == 6 {
            let w = &p.prevote.votes[0];
            f.dag
                .slot_causal_history(&p.prevote_carrier, p.prevote.digest(set).unwrap(), decision)
                .unwrap();
            assert_ne!(
                f.dag
                    .get(w.carrier.round, &w.carrier.author)
                    .unwrap()
                    .payload_hash,
                w.payload.digest(set).unwrap()
            );
        } else {
            f.dag
                .slot_causal_history(
                    &p.prevote_carrier,
                    p.prevote.aggregate.digest(set).unwrap(),
                    decision,
                )
                .unwrap();
            assert_ne!(
                p.prevote.digest(set).unwrap(),
                p.prevote.aggregate.digest(set).unwrap()
            );
        }
        let error = f
            .dag
            .inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("payload is not bound to its carrier"),
            "mode {mode}: {error}"
        );
    }
}

#[test]
fn strong_phase_chain_codec_roundtrips_and_rejects_malformed_envelopes() {
    let (f, p, _, b) = strong_fixture(true, 0);
    let set = f.dag.set();
    let bytes = p.encode(set).unwrap();
    assert_eq!(
        SlotAgreementStrongPhaseChain::decode(&bytes, set).unwrap(),
        p
    );
    let prevote = p.prevote.encode(set).unwrap();
    assert_eq!(
        SlotAgreementStrongPrevotePayload::decode(&prevote, set).unwrap(),
        p.prevote
    );
    let vote = p.votes[0].payload.encode(set).unwrap();
    assert_eq!(
        SlotAgreementVotePayload::decode(&vote, set).unwrap(),
        p.votes[0].payload
    );
    p.votes[0].payload.verify(b.tip(), set).unwrap();
    for (body, kind) in [(&bytes, 0), (&prevote, 1), (&vote, 2)] {
        let decode = |bytes: &[u8]| match kind {
            0 => SlotAgreementStrongPhaseChain::decode(bytes, set).map(|_| ()),
            1 => SlotAgreementStrongPrevotePayload::decode(bytes, set).map(|_| ()),
            _ => SlotAgreementVotePayload::decode(bytes, set).map(|_| ()),
        };
        for end in 0..body.len() {
            assert!(decode(&body[..end]).is_err(), "kind {kind}, end {end}");
        }
        let mut trailing = body.clone();
        trailing.push(0);
        assert!(decode(&trailing).is_err());
        for offset in [0, 2] {
            let mut bad = body.clone();
            bad[offset] = 255;
            assert!(decode(&bad).is_err());
        }
        assert!(decode(&vec![0; 1_048_577]).is_err());
    }
    assert!(SlotAgreementPhaseChain::decode(&bytes, set).is_err());
    assert!(SlotAgreementPrevotePayload::decode(&prevote, set).is_err());
    assert_ne!(
        p.prevote.digest(set).unwrap(),
        p.prevote.aggregate.digest(set).unwrap()
    );
    let mut bad = p.clone();
    bad.votes = vec![bad.votes[0].clone(); 4097];
    assert!(bad.encode(set).is_err());
    let mut bad = p.clone();
    bad.votes[0].payload.signature.signature = vec![0; 1_048_576];
    assert!(bad.encode(set).is_err());
}

#[test]
fn strong_phase_chain_enforces_combined_bound_and_exact_final_digest() {
    let (mut f, p, _, b) = strong_fixture(true, 0);
    let set = f.dag.set();
    let mut oversized = p.clone();
    oversized.certificate.signatures[0]
        .signature
        .resize(530_000, 0);
    oversized.votes[0].payload.signature = oversized.certificate.signatures[0].clone();
    assert!(oversized.certificate.encode(set).is_ok());
    assert!(oversized.votes[0].payload.encode(set).is_ok());
    assert!(oversized.prevote.encode(set).is_ok());
    assert!(
        oversized.encode(set).is_err(),
        "combined evidence must fit one MiB"
    );
    let aggregate = SlotAgreementPhaseChain {
        prevote: p.prevote.aggregate.clone(),
        prevote_carrier: p.prevote_carrier.clone(),
        certificate: p.certificate.clone(),
    };
    let digest = aggregate.digest(set).unwrap();
    let refs = f.ids(LEADER_ROUND + 5);
    let c = bind_as(&mut f, 0, LEADER_ROUND + 6, refs, digest);
    let error = f
        .dag
        .inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
        .unwrap_err();
    assert!(
        error.to_string().contains("payload is not bound"),
        "{error}"
    );
}

#[test]
fn strong_phase_chain_rejects_matching_but_unauthenticated_final_signatures() {
    let (mut f, mut p, _, b) = strong_fixture(true, 0);
    p.certificate.signatures[0].signature[0] ^= 1;
    p.votes[0].payload.signature = p.certificate.signatures[0].clone();
    // Consistent QC/witness bytes alone are not authentication, even when rebound.
    let digest = p.digest(f.dag.set()).unwrap();
    let refs = f.ids(LEADER_ROUND + 5);
    let c = bind_as(&mut f, 0, LEADER_ROUND + 6, refs, digest);
    assert!(
        f.dag
            .inspect_slot_agreement_strong_phase_chain(&p, &c, &b)
            .is_err()
    );
    let mut vote = p.votes[1].payload.clone();
    vote.signature.signature[0] ^= 1;
    assert!(vote.verify(b.tip(), f.dag.set()).is_err());
    vote = p.votes[1].payload.clone();
    vote.vote.context = crate::SlotDecisionTip::from_checkpoint(
        b.tip().chain_id().to_vec(),
        f.dag.set(),
        b.tip().next_round(),
        [9; 32],
        b.tip().order_len(),
        *b.tip().order_root(),
    )
    .unwrap();
    assert!(vote.verify(b.tip(), f.dag.set()).is_err());
}

fn qc(
    f: &Fixture,
    tip: &crate::SlotDecisionTip,
    proposal: &crate::SlotProposal,
    phase: AgreementPhase,
) -> AgreementQc {
    let vote = AgreementVote {
        context: tip.clone(),
        view: AgreementView(2),
        phase,
        value: AgreementValue::Decision(proposal.decision.clone()),
    };
    let bytes = vote.signing_payload(f.dag.set()).unwrap();
    let signatures = (0..f.dag.set().quorum_size())
        .map(|i| crate::ValidatorSignature {
            validator_id: format!("val-{i}").into_bytes(),
            key_id: format!("val-{i}-k0").into_bytes(),
            signature: Ed25519Scheme.sign(&f.keys[i], &bytes).unwrap(),
        })
        .collect();
    AgreementQc { vote, signatures }
}

fn bind(f: &mut Fixture, round: u64, refs: Vec<VertexId>, digest: [u8; 32]) -> VertexId {
    let v = vertex_with_payload(f, 0, round, refs, digest);
    f.dag.vertices.remove(&(v.round, v.author.clone()));
    f.dag.insert(v).unwrap()
}

fn fixture(
    commit: bool,
) -> (
    Fixture,
    SlotAgreementPhaseChain,
    VertexId,
    SlotAgreementBinding,
) {
    let (mut f, proposal, proposal_carrier, tip) = direct_slot_proposal(commit);
    let prevote = SlotAgreementPrevotePayload {
        certificate: qc(&f, &tip, &proposal, AgreementPhase::Prevote),
        proposal,
        proposal_carrier,
    };
    let refs = f.ids(LEADER_ROUND + 1);
    for author in 1..f.count() {
        let v = vertex(&f, author, LEADER_ROUND + 2, refs.clone());
        f.dag.insert(v).unwrap();
    }
    let refs = f.ids(LEADER_ROUND + 2);
    f.full_round(LEADER_ROUND + 3, &refs).unwrap();
    let digest = prevote.digest(f.dag.set()).unwrap();
    let prevote_carrier = bind(&mut f, LEADER_ROUND + 3, refs, digest);
    let p = SlotAgreementPhaseChain {
        certificate: qc(&f, &tip, &prevote.proposal, AgreementPhase::Precommit),
        prevote,
        prevote_carrier,
    };
    let refs = f.ids(LEADER_ROUND + 3);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind(&mut f, LEADER_ROUND + 4, refs, digest);
    let b = SlotAgreementBinding::from_checkpoint(tip, Some(f.ids(0)[0].clone())).unwrap();
    (f, p, c, b)
}

#[test]
fn phase_chain_accepts_commit_skip_without_effects() {
    for commit in [false, true] {
        let (f, p, c, b) = fixture(commit);
        let result = inspect_without_effects(&f.dag, |dag| {
            dag.inspect_slot_agreement_phase_chain(&p, &c, &b)
        });
        assert_eq!(
            result,
            f.dag
                .inspect_slot_proposal(&p.prevote.proposal, &p.prevote.proposal_carrier, b.tip())
                .unwrap()
        );
    }
}

#[test]
fn phase_chain_codec_is_canonical_bounded_and_domain_separated() {
    let (f, p, _, _) = fixture(true);
    let set = f.dag.set();
    let bytes = p.encode(set).unwrap();
    assert_eq!(SlotAgreementPhaseChain::decode(&bytes, set).unwrap(), p);
    let prevote = p.prevote.encode(set).unwrap();
    assert_eq!(
        SlotAgreementPrevotePayload::decode(&prevote, set).unwrap(),
        p.prevote
    );
    assert!(SlotAgreementPrevotePayload::decode(&bytes, set).is_err());
    assert!(SlotAgreementPhaseChain::decode(&prevote, set).is_err());
    for end in 0..bytes.len() {
        assert!(SlotAgreementPhaseChain::decode(&bytes[..end], set).is_err());
    }
    for end in 0..prevote.len() {
        assert!(SlotAgreementPrevotePayload::decode(&prevote[..end], set).is_err());
    }
    for offset in [0, 2] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(SlotAgreementPhaseChain::decode(&bad, set).is_err());
    }
    let mut bad = bytes;
    bad.push(0);
    assert!(SlotAgreementPhaseChain::decode(&bad, set).is_err());
    assert!(SlotAgreementPhaseChain::decode(&vec![0; 1_048_577], set).is_err());
    let mut bad = p.clone();
    bad.prevote_carrier.author = vec![0; 1025];
    assert!(bad.encode(set).is_err());
    let mut bad = p.clone();
    bad.certificate.signatures[0].signature = vec![0; 1_048_576];
    assert!(bad.encode(set).is_err());
    let mut changed = p.clone();
    changed.prevote_carrier.digest[0] ^= 1;
    assert_ne!(p.digest(set).unwrap(), changed.digest(set).unwrap());
    assert_ne!(p.digest(set).unwrap(), p.prevote.digest(set).unwrap());
}

#[test]
fn phase_chain_rejects_wrong_phase_view_context_value_before_carrier_checks() {
    let (f, p, c, b) = fixture(true);
    for mutation in 0..6 {
        let mut bad = p.clone();
        match mutation {
            0 => bad.prevote.certificate.vote.phase = AgreementPhase::Precommit,
            1 => bad.certificate.vote.phase = AgreementPhase::Prevote,
            2 => bad.certificate.vote.view.0 += 1,
            3 => bad.certificate.vote.value = AgreementValue::Nil,
            4 => bad.prevote.certificate.vote.value = AgreementValue::Nil,
            _ => {
                bad.certificate.vote.context = crate::SlotDecisionTip::from_checkpoint(
                    b.tip().chain_id().to_vec(),
                    f.dag.set(),
                    b.tip().next_round(),
                    [9; 32],
                    b.tip().order_len(),
                    *b.tip().order_root(),
                )
                .unwrap()
            }
        }
        assert!(bad.encode(f.dag.set()).is_err());
        assert!(
            f.dag
                .inspect_slot_agreement_phase_chain(&bad, &c, &b)
                .is_err()
        );
    }
}

#[test]
fn phase_chain_rejects_rebound_bad_signatures_in_either_qc() {
    for prevote in [false, true] {
        let (mut f, mut p, _, b) = fixture(true);
        let q = if prevote {
            &mut p.prevote.certificate
        } else {
            &mut p.certificate
        };
        q.signatures[0].signature[0] ^= 1;
        let refs = f.ids(LEADER_ROUND + 2);
        let digest = p.prevote.digest(f.dag.set()).unwrap();
        p.prevote_carrier = bind(&mut f, LEADER_ROUND + 3, refs, digest);
        let refs = f.ids(LEADER_ROUND + 3);
        let digest = p.digest(f.dag.set()).unwrap();
        let c = bind(&mut f, LEADER_ROUND + 4, refs, digest);
        assert!(
            f.dag
                .inspect_slot_agreement_phase_chain(&p, &c, &b)
                .is_err()
        );
    }
}

#[test]
fn phase_chain_final_must_descend_from_exact_prevote_not_only_proposal() {
    let (mut f, p, _, b) = fixture(true);
    let refs = f
        .ids(LEADER_ROUND + 3)
        .into_iter()
        .filter(|id| *id != p.prevote_carrier)
        .collect();
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind(&mut f, LEADER_ROUND + 4, refs, digest);
    assert!(f.dag.is_ancestor(&p.prevote.proposal_carrier, &c).unwrap());
    assert!(!f.dag.is_ancestor(&p.prevote_carrier, &c).unwrap());
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn phase_chain_rejects_exact_carrier_mismatch_order_and_nonpredecessor() {
    let (f, p, c, b) = fixture(true);
    let mut bad = p.clone();
    bad.prevote_carrier.digest[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&bad, &c, &b)
            .is_err()
    );
    let mut bad = p.clone();
    bad.prevote_carrier = c.clone();
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&bad, &c, &b)
            .is_err()
    );
    let mut bad_c = c.clone();
    bad_c.digest[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &bad_c, &b)
            .is_err()
    );
    let b = SlotAgreementBinding::from_checkpoint(b.tip().clone(), Some(p.prevote_carrier.clone()))
        .unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn phase_chain_predecessor_in_final_cone_is_not_enough() {
    let (mut f, mut p, _, b) = fixture(true);
    let previous = f.ids(LEADER_ROUND + 1)[3].clone();
    let refs = f.ids(LEADER_ROUND + 1)[..3].to_vec();
    let digest = p.prevote.proposal.digest().unwrap();
    p.prevote.proposal_carrier = bind(&mut f, LEADER_ROUND + 2, refs, digest);
    let refs = f.ids(LEADER_ROUND + 2);
    let digest = p.prevote.digest(f.dag.set()).unwrap();
    p.prevote_carrier = bind(&mut f, LEADER_ROUND + 3, refs, digest);
    let refs = f.ids(LEADER_ROUND + 3);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind(&mut f, LEADER_ROUND + 4, refs, digest);
    assert!(f.dag.is_ancestor(&previous, &c).unwrap());
    assert!(
        !f.dag
            .is_ancestor(&previous, &p.prevote.proposal_carrier)
            .unwrap()
    );
    let b = SlotAgreementBinding::from_checkpoint(b.tip().clone(), Some(previous)).unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn phase_chain_prevote_requires_exact_proposal_in_its_cone() {
    let (mut f, mut p, _, b) = fixture(true);
    let refs = f.ids(LEADER_ROUND + 2)[1..].to_vec();
    let digest = p.prevote.digest(f.dag.set()).unwrap();
    p.prevote_carrier = bind(&mut f, LEADER_ROUND + 3, refs, digest);
    let refs = f.ids(LEADER_ROUND + 3);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind(&mut f, LEADER_ROUND + 4, refs, digest);
    assert!(
        !f.dag
            .is_ancestor(&p.prevote.proposal_carrier, &p.prevote_carrier)
            .unwrap()
    );
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn phase_chain_aggregate_bound_and_signer_count_are_enforced() {
    use crypto::encoding::MAX_FIELD_LEN;
    let (f, mut p, _, _) = fixture(true);
    let set = f.dag.set();
    let size = p.certificate.encode(set).unwrap().len();
    let signature = &mut p.certificate.signatures[0].signature;
    signature.resize(signature.len() + MAX_FIELD_LEN - size, 0);
    assert_eq!(p.certificate.encode(set).unwrap().len(), MAX_FIELD_LEN);
    assert!(p.prevote.encode(set).is_ok());
    assert!(p.encode(set).is_err());
    let signature = p.certificate.signatures[0].clone();
    p.certificate.signatures = vec![signature; 4097];
    assert!(p.encode(set).is_err());
}

#[test]
fn phase_chain_rejects_corrupt_final_only_sidecone() {
    let (mut f, p, c, b) = fixture(true);
    let side = f
        .ids(LEADER_ROUND + 3)
        .into_iter()
        .find(|id| *id != p.prevote_carrier)
        .unwrap();
    f.dag
        .vertices
        .get_mut(&(side.round, side.author))
        .unwrap()
        .signature[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn phase_chain_valid_alternate_signer_subset_requires_new_intermediate_binding() {
    let (mut f, mut p, _, b) = fixture(true);
    let q = &mut p.prevote.certificate;
    let bytes = q.vote.signing_payload(f.dag.set()).unwrap();
    q.signatures.remove(0);
    q.signatures.push(crate::ValidatorSignature {
        validator_id: b"val-3".to_vec(),
        key_id: b"val-3-k0".to_vec(),
        signature: Ed25519Scheme.sign(&f.keys[3], &bytes).unwrap(),
    });
    q.verify(b.tip(), f.dag.set()).unwrap();
    let refs = f.ids(LEADER_ROUND + 3);
    let digest = p.digest(f.dag.set()).unwrap();
    let c = bind(&mut f, LEADER_ROUND + 4, refs, digest);
    assert!(
        f.dag
            .inspect_slot_agreement_phase_chain(&p, &c, &b)
            .is_err()
    );
}
