use super::*;
use crate::{SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol};

fn fixture() -> (Fixture, SlotAgreementProof, VertexId, SlotAgreementBinding) {
    let (mut f, proposal, plain, tip) = direct_slot_proposal(true);
    let refs = f.ids(LEADER_ROUND + 1);
    for a in 1..f.count() {
        let v = vertex(&f, a, LEADER_ROUND + 2, refs.clone());
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
    let refs = f.ids(LEADER_ROUND + 2);
    f.full_round(LEADER_ROUND + 3, &refs).unwrap();
    let digest = p.view_digest(0).unwrap();
    p.entries[0].view_carrier = bind_as(&mut f, author, LEADER_ROUND + 3, refs, digest);
    let certificate = proof_qc(&f, &tip, &proposal, AgreementPhase::Prevote);
    let refs = f.ids(LEADER_ROUND + 3);
    f.full_round(LEADER_ROUND + 4, &refs).unwrap();
    let mut votes = vec![];
    for (i, sig) in certificate.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: certificate.vote.clone(),
            signature: sig.clone(),
            prerequisite: p.entries[0].view_carrier.clone(),
        };
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(&mut f, i, LEADER_ROUND + 4, refs.clone(), digest);
        votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    p.entries[0].pol = Some(SlotAgreementProofPol {
        certificate,
        votes,
        carrier: placeholder,
    });
    let digest = p.pol_digest(0, f.dag.set()).unwrap();
    let refs = f.ids(LEADER_ROUND + 4);
    f.full_round(LEADER_ROUND + 5, &refs).unwrap();
    let carrier = bind_as(&mut f, 0, LEADER_ROUND + 5, refs, digest);
    p.entries[0].pol.as_mut().unwrap().carrier = carrier.clone();
    let refs = f.ids(LEADER_ROUND + 5);
    f.full_round(LEADER_ROUND + 6, &refs).unwrap();
    for (i, sig) in p.certificate.signatures.iter().enumerate() {
        let payload = SlotAgreementVotePayload {
            vote: p.certificate.vote.clone(),
            signature: sig.clone(),
            prerequisite: carrier.clone(),
        };
        let digest = payload.digest(f.dag.set()).unwrap();
        let carrier = bind_as(&mut f, i, LEADER_ROUND + 6, refs.clone(), digest);
        p.votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    let refs = f.ids(LEADER_ROUND + 6);
    let digest = p.digest(f.dag.set()).unwrap();
    f.full_round(LEADER_ROUND + 7, &refs).unwrap();
    let c = bind_as(&mut f, 0, LEADER_ROUND + 7, refs, digest);
    let b = SlotAgreementBinding::from_checkpoint(tip, Some(f.ids(0)[0].clone())).unwrap();
    (f, p, c, b)
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
    proposal: &crate::SlotProposal,
    phase: AgreementPhase,
) -> AgreementQc {
    let mut q = qc(f, tip, proposal, phase);
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
