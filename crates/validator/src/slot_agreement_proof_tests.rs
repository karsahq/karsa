use super::*;
use crate::slot_agreement::AgreementInput;
use crate::{SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol};

fn fixture() -> (Fixture, SlotAgreementProof, VertexId, SlotAgreementBinding) {
    fixture_with_decision(true)
}

fn fixture_with_decision(
    commit: bool,
) -> (Fixture, SlotAgreementProof, VertexId, SlotAgreementBinding) {
    fixture_with_evidence(commit, false)
}

fn fixture_with_evidence(
    commit: bool,
    indirect: bool,
) -> (Fixture, SlotAgreementProof, VertexId, SlotAgreementBinding) {
    fixture_with_signed_indirect_mutation(commit, indirect, 0)
}

fn fixture_with_signed_indirect_mutation(
    commit: bool,
    indirect: bool,
    mutation: usize,
) -> (Fixture, SlotAgreementProof, VertexId, SlotAgreementBinding) {
    let (mut f, proposal, plain, tip) = direct_slot_proposal(commit);
    let (mut f, proposal, plain) = if indirect {
        let target_refs = f.ids(LEADER_ROUND);
        let nonvotes = f.ids_without_leader(LEADER_ROUND);
        f.dag
            .vertices
            .retain(|(round, _), _| *round <= LEADER_ROUND);
        for author in 0..f.count() {
            let refs = if author == 0 {
                target_refs.clone()
            } else {
                nonvotes.clone()
            };
            let v = vertex(&f, author, LEADER_ROUND + 1, refs);
            f.dag.insert(v).unwrap();
        }
        let refs = f.ids(LEADER_ROUND + 1);
        f.full_round(LEADER_ROUND + 2, &refs).unwrap();
        let anchor_author = f.dag.leader(LEADER_ROUND + 2).unwrap().author.clone();
        if mutation == 1 {
            // Other round-four vertices still reach the target, but this elected
            // anchor has a complete authenticated cone containing only nonvoters.
            let author = f
                .dag
                .set()
                .validators
                .iter()
                .position(|v| v.validator_id == anchor_author)
                .unwrap();
            let refs = f.ids(LEADER_ROUND + 1)[1..].to_vec();
            bind_as(&mut f, author, LEADER_ROUND + 2, refs, [19; 32]);
        }
        let anchor = f.dag.leader(LEADER_ROUND + 2).unwrap().id().unwrap();
        let refs = f.ids(LEADER_ROUND + 2);
        f.full_round(LEADER_ROUND + 3, &refs).unwrap();
        if mutation == 2 {
            let refs = f
                .ids(LEADER_ROUND + 2)
                .into_iter()
                .filter(|v| v != &anchor)
                .collect();
            bind_as(&mut f, 0, LEADER_ROUND + 3, refs, [20; 32]);
        }
        let support = f.ids(LEADER_ROUND + 3)[..f.dag.set().quorum_size()].to_vec();
        let proposal = crate::SlotProposalEnvelope {
            decision: proposal.decision,
            evidence: crate::SlotProposalEvidence::IndirectCommit { anchor, support },
        };
        let refs = if mutation == 3 {
            f.ids(LEADER_ROUND + 3)[1..].to_vec()
        } else {
            f.ids(LEADER_ROUND + 3)
        };
        let plain = bind_as(
            &mut f,
            0,
            LEADER_ROUND + 4,
            refs,
            proposal.digest().unwrap(),
        );
        (f, proposal, plain)
    } else {
        (f, proposal.into(), plain)
    };
    let base = plain.round;
    let refs = f.ids(base - 1);
    for a in 1..f.count() {
        let v = vertex(&f, a, base, refs.clone());
        f.dag.insert(v).unwrap();
    }
    let placeholder = plain.clone();
    let mut p = SlotAgreementProof {
        entries: vec![SlotAgreementProofEntry {
            proposal: proposal.clone(),
            proposal_carrier: plain,
            view: AgreementView(0),
            view_carrier: placeholder.clone(),
            previous_pol: None,
            pol: None,
        }],
        certificate: proof_qc(&f, &tip, &proposal, AgreementPhase::Precommit),
        votes: vec![],
    };
    let author_id =
        crate::slot_agreement_view_proposer(f.dag.set(), proposal.decision.round, AgreementView(0))
            .unwrap();
    let author = (0..f.count())
        .find(|i| f.dag.set().validators[*i].validator_id == author_id)
        .unwrap();
    let refs = f.ids(base);
    f.full_round(base + 1, &refs).unwrap();
    let digest = p.view_digest(0).unwrap();
    p.entries[0].view_carrier = bind_as(&mut f, author, base + 1, refs, digest);
    let certificate = proof_qc(&f, &tip, &proposal, AgreementPhase::Prevote);
    let refs = f.ids(base + 1);
    f.full_round(base + 2, &refs).unwrap();
    let mut votes = vec![];
    for (i, sig) in certificate.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: certificate.vote.clone(),
            signature: sig.clone(),
            prerequisite: p.entries[0].view_carrier.clone(),
        };
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(&mut f, i, base + 2, refs.clone(), digest);
        votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    let candidate = crate::SlotAgreementViewLineage {
        entries: p.entries.clone(),
    }
    .pol_candidate_digest(certificate, votes, f.dag.set())
    .unwrap();
    let digest = candidate.digest();
    let refs = f.ids(base + 2);
    f.full_round(base + 3, &refs).unwrap();
    let carrier = bind_as(&mut f, 0, base + 3, refs, digest);
    p.entries = candidate.bind_carrier(carrier.clone()).entries;
    assert_eq!(digest, p.pol_digest(0, f.dag.set()).unwrap());
    let refs = f.ids(base + 3);
    f.full_round(base + 4, &refs).unwrap();
    for (i, sig) in p.certificate.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: p.certificate.vote.clone(),
            signature: sig.clone(),
            prerequisite: carrier.clone(),
        };
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(&mut f, i, base + 4, refs.clone(), digest);
        p.votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    let refs = f.ids(base + 4);
    let digest = p.digest(f.dag.set()).unwrap();
    f.full_round(base + 5, &refs).unwrap();
    let c = bind_as(&mut f, 0, base + 5, refs, digest);
    let b = SlotAgreementBinding::from_checkpoint(tip, Some(f.ids(0)[0].clone())).unwrap();
    (f, p, c, b)
}
#[test]
fn indirect_positive_unified_view_proof_and_owned_application() {
    let (f, p, c, b) = fixture_with_evidence(true, true);
    let entry = &p.entries[0];
    assert_eq!(f.dag.held_voters(LEADER_ROUND).unwrap(), 1);
    let expected = f
        .dag
        .inspect_slot_proposal_envelope(&entry.proposal, &entry.proposal_carrier, b.tip())
        .unwrap();
    let Decision::Commit(history) = &expected else {
        panic!("positive evidence must commit")
    };
    assert!(history.iter().all(|id| id.round <= LEADER_ROUND));
    let lineage = crate::SlotAgreementViewLineage {
        entries: p.entries.clone(),
    };
    let bytes = lineage.encode(f.dag.set()).unwrap();
    assert_eq!(
        crate::SlotAgreementViewLineage::decode(&bytes, f.dag.set()).unwrap(),
        lineage
    );
    f.dag
        .inspect_slot_agreement_view_lineage(&lineage, &b)
        .unwrap();
    let bytes = p.encode(f.dag.set()).unwrap();
    assert_eq!(SlotAgreementProof::decode(&bytes, f.dag.set()).unwrap(), p);
    assert_eq!(
        f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap(),
        expected
    );
    for w in [&p.entries[0].pol.as_ref().unwrap().votes[0], &p.votes[0]] {
        f.dag.inspect_slot_agreement_vote(&lineage, w, &b).unwrap();
    }
    let selected = entry.proposal.decision.clone();
    let binding =
        crate::SlotDecisionBinding::from_checkpoint(b.tip().clone(), b.carrier().cloned()).unwrap();
    let mut dag = crate::CertifiedDag::from_checkpoint(f.dag, binding.clone()).unwrap();
    drop(dag.prepare_agreement(&p, &c).unwrap());
    assert_eq!(dag.binding(), &binding);
    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::Applied {
            round: selected.round,
            decision: expected
        }
    );
    assert_eq!(dag.dag().commit_root(), selected.after_root);
    assert_eq!(dag.dag().order_len() as u64, selected.after_len);
    assert_eq!(dag.binding().tip().previous_id(), &selected.id().unwrap());
    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::AlreadyApplied {
            round: selected.round
        }
    );
}

#[test]
fn indirect_positive_reproposal_preserves_target_effect() {
    let (mut f, mut p, c, b) = fixture_with_evidence(true, true);
    let expected = f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap();
    let c = extend(&mut f, &mut p, &b, c.round + 1, 3, false);
    assert_eq!(
        f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap(),
        expected
    );
    let lineage = crate::SlotAgreementViewLineage {
        entries: p.entries.clone(),
    };
    let bytes = lineage.encode(f.dag.set()).unwrap();
    assert_eq!(
        crate::SlotAgreementViewLineage::decode(&bytes, f.dag.set()).unwrap(),
        lineage
    );
    f.dag
        .inspect_slot_agreement_view_lineage(&lineage, &b)
        .unwrap();
}

#[test]
fn indirect_positive_preflights_entire_lineage_before_authentication() {
    let (mut f, p, c, b) = fixture_with_evidence(true, true);
    let mut lineage = crate::SlotAgreementViewLineage {
        entries: p.entries.clone(),
    };
    let mut next = lineage.entries[0].clone();
    next.view = AgreementView(1);
    next.previous_pol = Some(0);
    next.pol = None;
    next.view_carrier = c;
    next.view_carrier.author =
        crate::slot_agreement_view_proposer(f.dag.set(), LEADER_ROUND, next.view)
            .unwrap()
            .to_vec();
    if let crate::SlotProposalEvidence::IndirectCommit { support, .. } = &mut next.proposal.evidence
    {
        support[0].round -= 1;
    }
    lineage.entries.push(next);
    let first = &lineage.entries[0].proposal_carrier;
    f.dag
        .vertices
        .get_mut(&(first.round, first.author.clone()))
        .unwrap()
        .signature[0] ^= 1;
    let error = f
        .dag
        .inspect_slot_agreement_view_lineage(&lineage, &b)
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("invalid indirect-positive lineage evidence"),
        "{error}"
    );
}

#[test]
fn indirect_positive_mutations_are_rejected_with_resigned_proposal_carriers() {
    let (mut f, p, _, b) = fixture_with_evidence(true, true);
    let original = &p.entries[0];
    for mode in 0..19 {
        let mut proposal = original.proposal.clone();
        let crate::SlotProposalEvidence::IndirectCommit { anchor, support } =
            &mut proposal.evidence
        else {
            unreachable!()
        };
        match mode {
            0 => anchor.round = LEADER_ROUND + 1,
            1 => anchor.digest[0] ^= 1,
            2 => {
                *anchor = f
                    .ids(anchor.round)
                    .into_iter()
                    .find(|v| v.author != anchor.author)
                    .unwrap()
            }
            3 => {
                support.pop();
            }
            4 => support[1] = support[0].clone(),
            5 => support[0].digest[0] ^= 1,
            6 => support[0].round -= 1,
            7 => {
                proposal.decision.outcome = crate::SlotOutcome::Skip {
                    leader_author: f.dag.leader(LEADER_ROUND).unwrap().author.clone(),
                }
            }
            8 => proposal.decision.chain_id.push(1),
            9 => proposal.decision.validator_set_id[0] ^= 1,
            10 => proposal.decision.epoch += 1,
            11 => proposal.decision.before_root[0] ^= 1,
            12 => proposal.decision.after_root[0] ^= 1,
            13 => proposal.decision.after_len += 1,
            14 => {
                if let crate::SlotOutcome::Commit { leader } = &mut proposal.decision.outcome {
                    leader.digest[0] ^= 1;
                }
            }
            15 => {
                let history = f.dag.collect_uncommitted_history(anchor).unwrap();
                proposal.decision.after_len = history.len() as u64;
                proposal.decision.after_root = commit_root(&history);
            }
            16 => {
                let other = f
                    .ids(LEADER_ROUND)
                    .into_iter()
                    .find(|v| Some(v.author.as_slice()) != f.dag.leader_author(LEADER_ROUND))
                    .unwrap();
                proposal.decision.outcome = crate::SlotOutcome::Commit { leader: other };
            }
            17 => support.push(f.ids(support[0].round)[3].clone()),
            _ => {
                support[1].author = support[0].author.clone();
                support[1].digest = [255; 32];
            }
        }
        let Ok(digest) = proposal.digest() else {
            continue;
        };
        let round = original.proposal_carrier.round;
        let refs = f.ids(round - 1);
        let carrier = bind_as(&mut f, 0, round, refs, digest);
        assert!(
            f.dag
                .inspect_slot_proposal_envelope(&proposal, &carrier, b.tip())
                .is_err(),
            "mode {mode}"
        );
    }
}

#[test]
fn indirect_positive_authenticated_nonreachability_nonvotes_and_noncausal_support_reject() {
    for mutation in 1..=3 {
        let (f, p, c, b) = fixture_with_signed_indirect_mutation(true, true, mutation);
        let e = &p.entries[0];
        assert!(
            f.dag
                .inspect_slot_proposal_envelope(&e.proposal, &e.proposal_carrier, b.tip())
                .is_err(),
            "mutation {mutation}"
        );
        let lineage = crate::SlotAgreementViewLineage {
            entries: p.entries.clone(),
        };
        assert!(
            f.dag
                .inspect_slot_agreement_view_lineage(&lineage, &b)
                .is_err(),
            "mutation {mutation}"
        );
        assert!(
            f.dag.inspect_slot_agreement_proof(&p, &c, &b).is_err(),
            "mutation {mutation}"
        );
        let binding =
            crate::SlotDecisionBinding::from_checkpoint(b.tip().clone(), b.carrier().cloned())
                .unwrap();
        let mut dag = crate::CertifiedDag::from_checkpoint(f.dag, binding.clone()).unwrap();
        let root = dag.dag().commit_root();
        assert!(
            dag.prepare_agreement(&p, &c).is_err(),
            "mutation {mutation}"
        );
        assert_eq!(dag.binding(), &binding);
        assert_eq!(dag.dag().commit_root(), root);
    }
}

#[test]
fn indirect_positive_authenticates_every_retained_cone_vertex() {
    let (mut f, p, c, b) = fixture_with_evidence(true, true);
    let e = &p.entries[0];
    let crate::SlotProposalEvidence::IndirectCommit { anchor, support } = &e.proposal.evidence
    else {
        unreachable!()
    };
    let target = f.dag.leader(LEADER_ROUND).unwrap().id().unwrap();
    let other_branch = f
        .ids(anchor.round)
        .into_iter()
        .find(|id| id != anchor)
        .unwrap();
    for id in [
        target,
        anchor.clone(),
        support[0].clone(),
        other_branch,
        e.proposal_carrier.clone(),
    ] {
        let key = (id.round, id.author.clone());
        f.dag.vertices.get_mut(&key).unwrap().signature[0] ^= 1;
        assert!(
            f.dag
                .inspect_slot_proposal_envelope(&e.proposal, &e.proposal_carrier, b.tip())
                .is_err(),
            "tampered {id:?}"
        );
        assert!(
            f.dag.inspect_slot_agreement_proof(&p, &c, &b).is_err(),
            "tampered {id:?}"
        );
        f.dag.vertices.get_mut(&key).unwrap().signature[0] ^= 1;
        let missing_vertex = f.dag.vertices.remove(&key).unwrap();
        assert!(
            f.dag
                .inspect_slot_proposal_envelope(&e.proposal, &e.proposal_carrier, b.tip())
                .is_err(),
            "missing {id:?}"
        );
        f.dag.vertices.insert(key, missing_vertex);
    }
    f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap();
}

#[test]
fn indirect_positive_shared_budget_bounds_target_and_frontier_work() {
    let (f, p, _, b) = fixture_with_evidence(true, true);
    let e = &p.entries[0];
    let mut full = crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET;
    f.dag
        .inspect_slot_proposal_with_budget(&e.proposal, &e.proposal_carrier, b.tip(), &mut full)
        .unwrap();
    let used = crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET - full;
    for limit in [0, 1, used - 1] {
        let mut budget = limit;
        assert!(
            f.dag
                .inspect_slot_proposal_with_budget(
                    &e.proposal,
                    &e.proposal_carrier,
                    b.tip(),
                    &mut budget
                )
                .is_err(),
            "limit {limit}"
        );
    }
    let mut exact = used;
    f.dag
        .inspect_slot_proposal_with_budget(&e.proposal, &e.proposal_carrier, b.tip(), &mut exact)
        .unwrap();
    assert_eq!(exact, 0);
}

#[test]
fn pol_candidate_preserves_digest_and_rejects_invalid_evidence() {
    let (f, p, _, _) = fixture();
    let mut lineage = crate::SlotAgreementViewLineage {
        entries: p.entries.clone(),
    };
    let pol = lineage.entries[0].pol.take().unwrap();
    for mode in 0..7 {
        let mut certificate = pol.certificate.clone();
        let mut witnesses = pol.votes.clone();
        let mut prefix = lineage.clone();
        match mode {
            0 => certificate.vote.phase = AgreementPhase::Precommit,
            1 => certificate.vote.view = AgreementView(99),
            2 => certificate.vote.value = AgreementValue::Nil,
            3 => witnesses.reverse(),
            4 => witnesses[0].payload.prerequisite = prefix.entries[0].proposal_carrier.clone(),
            5 => certificate.signatures[0].signature[0] ^= 1,
            _ => prefix.entries.clear(),
        }
        assert!(
            prefix
                .pol_candidate_digest(certificate, witnesses, f.dag.set())
                .is_err(),
            "mode {mode}"
        );
    }
    let candidate = lineage
        .pol_candidate_digest(pol.certificate.clone(), pol.votes.clone(), f.dag.set())
        .unwrap();
    assert_eq!(candidate.digest(), p.pol_digest(0, f.dag.set()).unwrap());
    let completed = candidate.bind_carrier(pol.carrier);
    assert_eq!(completed.entries, p.entries);
    let rebuilt = completed
        .into_proof(p.certificate.clone(), p.votes.clone(), f.dag.set())
        .unwrap();
    assert_eq!(
        rebuilt.encode(f.dag.set()).unwrap(),
        p.encode(f.dag.set()).unwrap()
    );
}

#[test]
fn individual_lineage_votes_authenticate_both_phases_and_reject_mutations() {
    let (f, p, _, b) = fixture();
    let lineage = crate::SlotAgreementViewLineage {
        entries: p.entries.clone(),
    };
    for witness in [&p.entries[0].pol.as_ref().unwrap().votes[0], &p.votes[0]] {
        f.dag
            .inspect_slot_agreement_vote(&lineage, witness, &b)
            .unwrap();
        for mode in 0..8 {
            let mut bad = witness.clone();
            match mode {
                0 => bad.carrier.author = vec![255],
                1 => bad.payload.signature.signature[0] ^= 1,
                2 => {
                    bad.payload.vote.context = crate::SlotDecisionTip::from_checkpoint(
                        b"wrong-chain".to_vec(),
                        f.dag.set(),
                        b.tip().next_round(),
                        [7; 32],
                        b.tip().order_len(),
                        *b.tip().order_root(),
                    )
                    .unwrap()
                }
                3 => bad.payload.prerequisite = p.entries[0].proposal_carrier.clone(),
                4 => bad.carrier.digest[0] ^= 1,
                5 => bad.payload.vote.view = AgreementView(1),
                6 => bad.payload.vote.value = AgreementValue::Nil,
                _ => bad.carrier.round = bad.payload.prerequisite.round,
            }
            assert!(
                f.dag
                    .inspect_slot_agreement_vote(&lineage, &bad, &b)
                    .is_err(),
                "mode {mode}"
            );
        }
        // Find the exact lineage-only cost. A fresh vote budget would incorrectly pass.
        let mut remaining = 100_000;
        f.dag
            .inspect_agreement_lineage(&lineage.entries, &b, &mut remaining)
            .unwrap();
        let lineage_cost = 100_000 - remaining;
        assert!(
            f.dag
                .inspect_slot_agreement_vote_with_budget(&lineage, witness, &b, lineage_cost,)
                .is_err()
        );
        f.dag
            .inspect_slot_agreement_vote_with_budget(&lineage, witness, &b, 100_000)
            .unwrap();
    }
    let mut invalid_pol = lineage.clone();
    invalid_pol.entries[0]
        .pol
        .as_mut()
        .unwrap()
        .certificate
        .signatures[0]
        .signature[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_vote(&invalid_pol, &p.votes[0], &b)
            .is_err()
    );
}

#[test]
fn individual_lineage_votes_require_causal_prerequisite_and_complete_cone() {
    for precommit in [false, true] {
        let (mut f, p, _, b) = fixture();
        let lineage = crate::SlotAgreementViewLineage {
            entries: p.entries.clone(),
        };
        let mut w = if precommit {
            p.votes[0].clone()
        } else {
            p.entries[0].pol.as_ref().unwrap().votes[0].clone()
        };
        let round = w.carrier.round;
        // Exclude the exact prerequisite while retaining a quorum of other authors.
        let refs: Vec<_> = f
            .ids(round - 1)
            .into_iter()
            .filter(|id| id != &w.payload.prerequisite)
            .collect();
        let digest = w.payload.digest(f.dag.set()).unwrap();
        w.carrier = bind_as(&mut f, 0, round, refs, digest);
        assert!(f.dag.inspect_slot_agreement_vote(&lineage, &w, &b).is_err());
    }
}

#[test]
fn unified_owned_skip_application() {
    let (f, p, c, b) = fixture_with_decision(false);
    let selected = &p.entries.last().unwrap().proposal.decision;
    let binding =
        crate::SlotDecisionBinding::from_checkpoint(b.tip().clone(), b.carrier().cloned()).unwrap();
    let mut dag = crate::CertifiedDag::from_checkpoint(f.dag, binding).unwrap();
    let before_root = dag.dag().commit_root();
    let before_skips = dag.dag.skipped.len();
    drop(dag.prepare_agreement(&p, &c).unwrap());
    assert_eq!(dag.dag.skipped.len(), before_skips);
    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::Applied {
            round: selected.round,
            decision: Decision::Skip
        }
    );
    assert_eq!(dag.dag.skipped.len(), before_skips + 1);
    assert_eq!(dag.dag.skipped.last().unwrap().round, selected.round);
    assert_eq!(dag.dag().commit_root(), before_root);
    assert_eq!(dag.binding().tip().previous_id(), &selected.id().unwrap());
    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::AlreadyApplied {
            round: selected.round
        }
    );
    assert_eq!(dag.dag.skipped.len(), before_skips + 1);
}

#[test]
fn unified_owned_apply_drop_retry_and_errors() {
    let (mut f, mut p, _, b) = fixture();
    let c = extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, false);
    let expected = f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap();
    let selected = p.entries.last().unwrap().proposal.decision.clone();
    let binding =
        crate::SlotDecisionBinding::from_checkpoint(b.tip().clone(), b.carrier().cloned()).unwrap();
    let mut dag = crate::CertifiedDag::from_checkpoint(f.dag, binding.clone()).unwrap();
    let before_order = dag.dag().order_len();
    let before_root = dag.dag().commit_root();
    drop(dag.prepare_agreement(&p, &c).unwrap());
    assert_eq!(dag.binding(), &binding);
    assert_eq!(dag.dag().order_len(), before_order);
    assert_eq!(dag.dag().commit_root(), before_root);

    let mut bad = p.clone();
    bad.entries.clear();
    assert!(dag.prepare_agreement(&bad, &c).is_err());
    let mut bad = p.clone();
    bad.entries[0].view_carrier = c.clone();
    assert!(dag.prepare_agreement(&bad, &c).is_err());
    let mut wrong_carrier = c.clone();
    wrong_carrier.digest[0] ^= 1;
    assert!(dag.prepare_agreement(&p, &wrong_carrier).is_err());
    assert_eq!(dag.binding(), &binding);
    assert_eq!(dag.dag().commit_root(), before_root);

    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::Applied {
            round: selected.round,
            decision: expected
        }
    );
    assert_eq!(dag.binding().tip().next_round(), selected.round + 1);
    assert_eq!(dag.binding().tip().previous_id(), &selected.id().unwrap());
    assert_eq!(dag.binding().tip().order_len(), selected.after_len);
    assert_eq!(dag.binding().tip().order_root(), &selected.after_root);
    assert_eq!(dag.dag().order_len() as u64, selected.after_len);
    assert_eq!(dag.dag().commit_root(), selected.after_root);
    assert_eq!(dag.binding().carrier(), Some(&c));
    let applied = dag.binding().clone();
    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::AlreadyApplied {
            round: selected.round
        }
    );
    assert!(dag.prepare_agreement(&p, &wrong_carrier).is_err());
    assert!(dag.prepare_agreement(&bad, &c).is_err());
    assert_eq!(dag.binding(), &applied);
    assert_eq!(
        dag.prepare_agreement(&p, &c).unwrap().apply(),
        crate::SlotApplicationResult::AlreadyApplied {
            round: selected.round
        }
    );
}

#[test]
fn unified_signed_view_zero_and_codec() {
    let (f, p, c, b) = fixture();
    f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap();
    let bytes = p.encode(f.dag.set()).unwrap();
    assert_eq!(SlotAgreementProof::decode(&bytes, f.dag.set()).unwrap(), p);
    for end in 0..bytes.len() {
        assert!(
            SlotAgreementProof::decode(&bytes[..end], f.dag.set()).is_err(),
            "prefix {end}"
        );
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(SlotAgreementProof::decode(&trailing, f.dag.set()).is_err());
    assert!(
        SlotAgreementProof::decode(
            &vec![0; crate::SLOT_AGREEMENT_PROOF_MAX_BYTES + 1],
            f.dag.set()
        )
        .is_err()
    );
    assert!(
        f.dag
            .inspect_slot_agreement_proof_with_budget(&p, &c, &b, 1)
            .is_err()
    );
}
#[test]
fn unified_rejects_structural_and_authenticated_mutations() {
    let (f, p, c, b) = fixture();
    for mode in 0..11 {
        let mut bad = p.clone();
        match mode {
            0 => bad.entries[0].previous_pol = Some(0),
            1 => bad.entries[0].previous_pol = Some(1),
            2 => bad.entries.push(bad.entries[0].clone()),
            3 => bad.certificate.vote.phase = AgreementPhase::Prevote,
            4 => bad.entries[0].pol.as_mut().unwrap().certificate.vote.view = AgreementView(1),
            5 => {
                bad.entries[0].pol.as_mut().unwrap().votes[0]
                    .payload
                    .prerequisite = bad.entries[0].proposal_carrier.clone()
            }
            6 => bad.entries[0].view_carrier.author = vec![255],
            7 => bad.entries[0].pol.as_mut().unwrap().votes[0].carrier.digest[0] ^= 1,
            8 => bad.votes[0].payload.signature = bad.votes[1].payload.signature.clone(),
            9 => bad.certificate.vote.value = AgreementValue::Nil,
            _ => {
                bad.certificate.vote.context = crate::SlotDecisionTip::from_checkpoint(
                    b"wrong-chain".to_vec(),
                    f.dag.set(),
                    b.tip().next_round(),
                    [7; 32],
                    b.tip().order_len(),
                    *b.tip().order_root(),
                )
                .unwrap()
            }
        }
        assert!(
            f.dag.inspect_slot_agreement_proof(&bad, &c, &b).is_err(),
            "mode {mode}"
        );
    }
}

fn proof_qc(
    f: &Fixture,
    tip: &crate::SlotDecisionTip,
    proposal: &crate::SlotProposalEnvelope,
    phase: AgreementPhase,
) -> AgreementQc {
    let direct = crate::SlotProposal {
        decision: proposal.decision.clone(),
        voters: vec![],
    };
    let mut q = qc(f, tip, &direct, phase);
    q.vote.view = AgreementView(0);
    let bytes = q.vote.signing_payload(f.dag.set()).unwrap();
    for (i, s) in q.signatures.iter_mut().enumerate() {
        s.signature = Ed25519Scheme.sign(&f.keys[i], &bytes).unwrap();
    }
    q
}

fn extend(
    f: &mut Fixture,
    p: &mut SlotAgreementProof,
    b: &SlotAgreementBinding,
    base: u64,
    view: u64,
    omit_prior: bool,
) -> VertexId {
    let prior = p.entries.len() - 1;
    let proposal = p.entries[prior].proposal.clone();
    let plain = p.entries[prior].proposal_carrier.clone();
    let placeholder = plain.clone();
    p.entries.push(SlotAgreementProofEntry {
        proposal: proposal.clone(),
        proposal_carrier: plain,
        view: AgreementView(view),
        view_carrier: placeholder.clone(),
        previous_pol: Some(prior),
        pol: None,
    });
    let index = p.entries.len() - 1;
    let author_id = crate::slot_agreement_view_proposer(
        f.dag.set(),
        proposal.decision.round,
        AgreementView(view),
    )
    .unwrap();
    let author = (0..f.count())
        .find(|i| f.dag.set().validators[*i].validator_id == author_id)
        .unwrap();
    if omit_prior {
        let pol = p.entries[prior].pol.as_ref().unwrap().carrier.clone();
        f.dag.vertices.retain(|(r, _), _| *r <= pol.round);
        let mut branch = f.ids(pol.round);
        branch.retain(|id| *id != pol);
        for r in pol.round + 1..base {
            f.full_round(r, &branch).unwrap();
            branch = f.ids(r);
        }
    }
    let prior_refs = f.ids(base - 2);
    if f.ids(base - 1).len() < f.count() {
        f.full_round(base - 1, &prior_refs).unwrap();
    }
    let refs = f.ids(base - 1);

    f.full_round(base, &refs).unwrap();
    let digest = p.view_digest(index).unwrap();
    p.entries[index].view_carrier = bind_as(f, author, base, refs, digest);
    let mut q = proof_qc(f, b.tip(), &proposal, AgreementPhase::Prevote);
    q.vote.view = AgreementView(view);
    // Rotate the quorum membership across views, keeping canonical identity order.
    q.signatures.clear();
    let bytes = q.vote.signing_payload(f.dag.set()).unwrap();
    for i in 1..f.count() {
        q.signatures.push(crate::ValidatorSignature {
            validator_id: format!("val-{i}").into_bytes(),
            key_id: format!("val-{i}-k0").into_bytes(),
            signature: Ed25519Scheme.sign(&f.keys[i], &bytes).unwrap(),
        });
    }
    let refs = f.ids(base);
    f.full_round(base + 1, &refs).unwrap();
    let mut votes = vec![];
    for (i, sig) in q.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: q.vote.clone(),
            signature: sig.clone(),
            prerequisite: p.entries[index].view_carrier.clone(),
        };
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(f, i + 1, base + 1, refs.clone(), digest);
        votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    p.entries[index].pol = Some(SlotAgreementProofPol {
        certificate: q.clone(),
        votes,
        carrier: placeholder,
    });
    let refs = f.ids(base + 1);
    f.full_round(base + 2, &refs).unwrap();
    let digest = p.pol_digest(index, f.dag.set()).unwrap();
    let pol_carrier = bind_as(f, 0, base + 2, refs, digest);
    p.entries[index].pol.as_mut().unwrap().carrier = pol_carrier.clone();
    q.vote.phase = AgreementPhase::Precommit;
    let bytes = q.vote.signing_payload(f.dag.set()).unwrap();
    for (i, sig) in q.signatures.iter_mut().enumerate() {
        sig.signature = Ed25519Scheme.sign(&f.keys[i + 1], &bytes).unwrap();
    }
    p.certificate = q.clone();
    p.votes.clear();
    let refs = f.ids(base + 2);
    f.full_round(base + 3, &refs).unwrap();
    for (i, sig) in q.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: q.vote.clone(),
            signature: sig.clone(),
            prerequisite: pol_carrier.clone(),
        };
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(f, i + 1, base + 3, refs.clone(), digest);
        p.votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    let mut refs = f.ids(base + 3);
    if omit_prior {
        refs.push(p.entries[prior].pol.as_ref().unwrap().carrier.clone());
    }
    let digest = p.digest(f.dag.set()).unwrap();
    bind_as(f, 0, base + 4, refs, digest)
}
#[test]
fn unified_multiview_pol_with_changed_signers() {
    let (mut f, mut p, _, b) = fixture();
    let c = extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, false);
    f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap();
    let c = extend(&mut f, &mut p, &b, LEADER_ROUND + 13, 8, false);
    f.dag.inspect_slot_agreement_proof(&p, &c, &b).unwrap();
    let bytes = p.encode(f.dag.set()).unwrap();
    assert_eq!(SlotAgreementProof::decode(&bytes, f.dag.set()).unwrap(), p);
}
#[test]
fn unified_missing_retained_pol_cone_is_rejected() {
    let (mut f, mut p, _, b) = fixture();
    let c = extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, false);
    let pol = p.entries[0].pol.as_ref().unwrap();
    f.dag
        .vertices
        .remove(&(pol.carrier.round, pol.carrier.author.clone()));
    assert!(f.dag.inspect_slot_agreement_proof(&p, &c, &b).is_err());
}

#[test]
fn unified_prior_pol_only_in_final_cone_is_rejected() {
    let (mut f, mut p, _, b) = fixture();
    let c = extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, true);
    assert!(f.dag.inspect_slot_agreement_proof(&p, &c, &b).is_err());
}

#[test]
fn unified_all_entry_preflight_precedes_authentication_and_cone_budget() {
    let (mut f, mut p, _, b) = fixture();
    let c = extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, false);
    // The earliest direct carrier cannot authenticate, but all structural checks
    // must still reach the late entry before that carrier is inspected.
    let plain = &p.entries[0].proposal_carrier;
    f.dag
        .vertices
        .get_mut(&(plain.round, plain.author.clone()))
        .unwrap()
        .signature[0] ^= 1;
    let early_pol = p.entries[0].pol.as_mut().unwrap();
    early_pol.certificate.signatures[0].signature[0] ^= 1;
    early_pol.votes[0].payload.signature = early_pol.certificate.signatures[0].clone();
    assert!(early_pol.certificate.verify(b.tip(), f.dag.set()).is_err());
    for mode in 0..7 {
        let mut bad = p.clone();
        let mut final_carrier = c.clone();
        let expected = match mode {
            0 => {
                bad.entries[1].view_carrier.author = vec![255];
                "wrong proposer or view carrier ordering"
            }
            1 => {
                bad.entries[1].proposal_carrier.round = bad.entries[1].view_carrier.round;
                "wrong proposer or view carrier ordering"
            }
            2 => {
                bad.entries[1].view_carrier.round =
                    bad.entries[0].pol.as_ref().unwrap().carrier.round;
                "prior POL must precede view carrier"
            }
            3 => {
                bad.entries[1].pol.as_mut().unwrap().carrier.round =
                    bad.entries[1].view_carrier.round;
                "view carrier must precede own POL"
            }
            4 => {
                let pol = bad.entries[1].pol.as_mut().unwrap();
                pol.votes[0].carrier.round = pol.carrier.round;
                "prevote witness must precede POL carrier"
            }
            5 => {
                final_carrier.round = bad.entries[1].pol.as_ref().unwrap().carrier.round;
                "selected POL must precede final carrier"
            }
            _ => {
                bad.votes[0].carrier.round = final_carrier.round;
                "precommit witness must precede final carrier"
            }
        };
        // Keep prerequisites exact so encoding succeeds and the inspector's
        // additional ordering/proposer preflight is the rejection under test.
        for entry in &mut bad.entries {
            if let Some(pol) = &mut entry.pol {
                for witness in &mut pol.votes {
                    witness.payload.prerequisite = entry.view_carrier.clone();
                }
            }
        }
        for witness in &mut bad.votes {
            witness.payload.prerequisite = bad.entries[1].pol.as_ref().unwrap().carrier.clone();
        }
        bad.encode(f.dag.set()).unwrap();
        for budget in [0, crate::SLOT_AGREEMENT_PHASE_WORK_BUDGET] {
            let error = f
                .dag
                .inspect_slot_agreement_proof_with_budget(&bad, &final_carrier, &b, budget)
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                crate::slot_agreement_phase::invalid(expected).to_string(),
                "mode {mode}, budget {budget}"
            );
        }
    }
}

fn view_lineage(p: &SlotAgreementProof) -> crate::SlotAgreementViewLineage {
    let mut entries = p.entries.clone();
    entries.last_mut().unwrap().pol = None;
    crate::SlotAgreementViewLineage { entries }
}

#[test]
fn unified_view_lineage_signed_zero_before_pol_and_final_qc() {
    let (mut f, p, _, b) = fixture();
    let lineage = view_lineage(&p);
    let last = lineage.entries.last().unwrap();
    f.dag
        .vertices
        .retain(|(round, _), _| *round <= last.view_carrier.round);
    assert_eq!(
        f.dag
            .inspect_slot_agreement_view_lineage(&lineage, &b)
            .unwrap(),
        AgreementInput::Propose {
            view: last.view,
            decision: last.proposal.decision.clone(),
            pol: None,
        }
    );
    let bytes = lineage.encode(f.dag.set()).unwrap();
    assert_eq!(
        crate::SlotAgreementViewLineage::decode(&bytes, f.dag.set()).unwrap(),
        lineage
    );
    for end in 0..bytes.len() {
        assert!(crate::SlotAgreementViewLineage::decode(&bytes[..end], f.dag.set()).is_err());
    }
    let mut trailing = bytes;
    trailing.push(0);
    assert!(crate::SlotAgreementViewLineage::decode(&trailing, f.dag.set()).is_err());
}

#[test]
fn unified_view_lineage_multiview_returns_exact_earlier_pol() {
    let (mut f, mut p, _, b) = fixture();
    extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, false);
    extend(&mut f, &mut p, &b, LEADER_ROUND + 13, 8, false);
    let lineage = view_lineage(&p);
    let last = lineage.entries.last().unwrap();
    f.dag
        .vertices
        .retain(|(round, _), _| *round <= last.view_carrier.round);
    assert_eq!(
        f.dag
            .inspect_slot_agreement_view_lineage(&lineage, &b)
            .unwrap(),
        AgreementInput::Propose {
            view: last.view,
            decision: last.proposal.decision.clone(),
            pol: Some(lineage.entries[1].pol.as_ref().unwrap().certificate.clone()),
        }
    );
    let bytes = lineage.encode(f.dag.set()).unwrap();
    assert_eq!(
        crate::SlotAgreementViewLineage::decode(&bytes, f.dag.set()).unwrap(),
        lineage
    );
    let mut wrong = lineage.clone();
    wrong.entries[2].previous_pol = Some(0);
    assert!(
        f.dag
            .inspect_slot_agreement_view_lineage(&wrong, &b)
            .is_err()
    );
    let mut wrong = lineage.clone();
    wrong.entries[1].pol.as_mut().unwrap().certificate.vote.view = AgreementView(0);
    assert!(
        f.dag
            .inspect_slot_agreement_view_lineage(&wrong, &b)
            .is_err()
    );
    let pol = lineage.entries[0].pol.as_ref().unwrap();
    f.dag.vertices.remove(&(
        pol.votes[0].carrier.round,
        pol.votes[0].carrier.author.clone(),
    ));
    assert!(
        f.dag
            .inspect_slot_agreement_view_lineage(&lineage, &b)
            .is_err()
    );
}

#[test]
fn unified_view_lineage_rejects_signed_unauthorized_proposer() {
    let (mut f, p, _, b) = fixture();
    let mut lineage = view_lineage(&p);
    let elected = &lineage.entries[0].view_carrier.author;
    let wrong = (0..f.count())
        .find(|i| &f.dag.set().validators[*i].validator_id != elected)
        .unwrap();
    let round = lineage.entries[0].view_carrier.round;
    let refs = f.ids(round - 1);
    let digest = lineage.view_digest(0).unwrap();
    lineage.entries[0].view_carrier = bind_as(&mut f, wrong, round, refs, digest);
    assert!(
        f.dag
            .inspect_slot_agreement_view_lineage(&lineage, &b)
            .is_err()
    );
}

#[test]
fn unified_view_lineage_rejects_prior_pol_outside_view_cone() {
    let (mut f, mut p, _, b) = fixture();
    extend(&mut f, &mut p, &b, LEADER_ROUND + 8, 3, true);
    assert!(
        f.dag
            .inspect_slot_agreement_view_lineage(&view_lineage(&p), &b)
            .is_err()
    );
}

#[test]
fn unified_view_lineage_context_bounds_and_shared_budget() {
    let (f, p, _, b) = fixture();
    let lineage = view_lineage(&p);
    let d = &lineage.entries[0].proposal.decision;
    let wrong_tip = crate::SlotDecisionTip::from_checkpoint(
        b"other-chain".to_vec(),
        f.dag.set(),
        d.round,
        [0; 32],
        0,
        [0; 32],
    )
    .unwrap();
    let wrong = SlotAgreementBinding::from_checkpoint(wrong_tip, b.carrier().cloned()).unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_view_lineage(&lineage, &wrong)
            .is_err()
    );
    assert!(
        f.dag
            .inspect_agreement_lineage(&lineage.entries, &b, &mut 0)
            .is_err()
    );
    let mut oversized = lineage.clone();
    oversized.entries =
        vec![lineage.entries[0].clone(); crate::SLOT_AGREEMENT_PROOF_MAX_ENTRIES + 1];
    assert!(oversized.encode(f.dag.set()).is_err());
    assert!(
        crate::SlotAgreementViewLineage::decode(
            &vec![0; crate::SLOT_AGREEMENT_PROOF_MAX_BYTES + 1],
            f.dag.set(),
        )
        .is_err()
    );
    let mut bad = lineage.clone();
    bad.entries[0].view_carrier.author = vec![255];
    // Structural preflight fails even when the first direct signature is invalid.
    let mut f = f;
    let plain = &bad.entries[0].proposal_carrier;
    f.dag
        .vertices
        .get_mut(&(plain.round, plain.author.clone()))
        .unwrap()
        .signature[0] ^= 1;
    let error = f
        .dag
        .inspect_slot_agreement_view_lineage(&bad, &b)
        .unwrap_err();
    assert_eq!(
        error.to_string(),
        crate::slot_agreement_phase::invalid("wrong proposer or view carrier ordering").to_string()
    );
}
