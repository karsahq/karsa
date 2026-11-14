use super::*;
use crate::slot_agreement::{
    AgreementPhase, AgreementQc, AgreementValue, AgreementView, AgreementVote,
};
use crate::{SlotAgreementBinding, SlotAgreementCertificatePayload};

fn bind(f: &mut Fixture, p: &SlotAgreementCertificatePayload, refs: Vec<VertexId>) -> VertexId {
    let v = vertex_with_payload(f, 1, LEADER_ROUND + 3, refs, p.digest(f.dag.set()).unwrap());
    f.dag.vertices.remove(&(v.round, v.author.clone()));
    f.dag.insert(v).unwrap()
}

fn fixture_agreement(
    commit: bool,
) -> (
    Fixture,
    SlotAgreementCertificatePayload,
    VertexId,
    SlotAgreementBinding,
) {
    let (mut f, proposal, proposal_carrier, tip) = direct_slot_proposal(commit);
    let vote = AgreementVote {
        context: tip.clone(),
        view: AgreementView(2),
        phase: AgreementPhase::Precommit,
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
    let p = SlotAgreementCertificatePayload {
        proposal,
        proposal_carrier,
        certificate: AgreementQc { vote, signatures },
    };
    let refs = f.ids(LEADER_ROUND + 1);
    f.full_round(LEADER_ROUND + 2, &refs).unwrap();
    let b = SlotAgreementBinding::from_checkpoint(tip, Some(f.ids(0)[0].clone())).unwrap();
    let refs = f.ids(LEADER_ROUND + 2);
    let c = bind(&mut f, &p, refs);
    (f, p, c, b)
}

#[test]
fn agreement_certificate_accepts_only_exact_trusted_pruned_predecessor() {
    let (mut f, p, c, b) = fixture_agreement(false);
    f.dag.set_floor(0);
    let previous = b.carrier().unwrap();
    assert!(f.dag.is_pruned(previous.round));
    assert_eq!(
        inspect_without_effects(&f.dag, |dag| {
            dag.inspect_slot_agreement_certificate(&p, &c, &b)
        }),
        Decision::Skip
    );
    let mut wrong = previous.clone();
    wrong.digest[0] ^= 1;
    let wrong = SlotAgreementBinding::from_checkpoint(b.tip().clone(), Some(wrong)).unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &wrong)
            .is_err()
    );
}

#[test]
fn agreement_certificate_rejects_resigned_rebound_different_context() {
    let (mut f, mut p, _, b) = fixture_agreement(false);
    let previous = [9; 32];
    let context = crate::SlotDecisionTip::from_checkpoint(
        b.tip().chain_id().to_vec(),
        f.dag.set(),
        b.tip().next_round(),
        previous,
        b.tip().order_len(),
        *b.tip().order_root(),
    )
    .unwrap();
    p.proposal.decision.previous = previous;
    p.certificate.vote.context = context.clone();
    p.certificate.vote.value = AgreementValue::Decision(p.proposal.decision.clone());
    let bytes = p.certificate.vote.signing_payload(f.dag.set()).unwrap();
    for (index, signature) in p.certificate.signatures.iter_mut().enumerate() {
        signature.signature = Ed25519Scheme.sign(&f.keys[index], &bytes).unwrap();
    }
    p.proposal_carrier = bind_slot_proposal(&mut f, &p.proposal);
    let refs = f.ids(LEADER_ROUND + 2);
    let c = bind(&mut f, &p, refs);
    let encoded = p.encode(f.dag.set()).unwrap();
    assert_eq!(
        SlotAgreementCertificatePayload::decode(&encoded, f.dag.set()).unwrap(),
        p
    );
    p.certificate.verify(&context, f.dag.set()).unwrap();
    let alternate = SlotAgreementBinding::from_checkpoint(context, b.carrier().cloned()).unwrap();
    assert_eq!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &alternate)
            .unwrap(),
        Decision::Skip
    );
    let error = f
        .dag
        .inspect_slot_agreement_certificate(&p, &c, &b)
        .unwrap_err();
    assert!(
        error.to_string().contains("context or continuity mismatch"),
        "{error}"
    );
}

#[test]
fn agreement_certificate_combined_bound_rejects_individually_valid_bodies() {
    use crypto::encoding::{Encoder, MAX_FIELD_LEN};

    let (f, mut p, _, _) = fixture_agreement(true);
    let set = f.dag.set();
    // Storage codecs do not authenticate signatures. Grow an opaque signature field
    // to make the QC alone exactly one MiB, isolating the outer envelope bound.
    let original = p.certificate.encode(set).unwrap().len();
    let signature = &mut p.certificate.signatures[0].signature;
    signature.resize(signature.len() + MAX_FIELD_LEN - original, 0);
    let proposal = p.proposal.encode().unwrap();
    let certificate = p.certificate.encode(set).unwrap();
    assert!(proposal.len() <= MAX_FIELD_LEN);
    assert_eq!(certificate.len(), MAX_FIELD_LEN);
    assert_eq!(crate::SlotProposal::decode(&proposal).unwrap(), p.proposal);
    assert_eq!(
        AgreementQc::decode(&certificate, set).unwrap(),
        p.certificate
    );
    assert!(p.encode(set).is_err());
    assert!(p.digest(set).is_err());

    let mut outer = Encoder::new();
    outer.put_u16(crate::SLOT_AGREEMENT_CERTIFICATE_VERSION_V1);
    outer.put_u8(0);
    outer.put_bytes(&proposal).unwrap();
    outer.put_u64(p.proposal_carrier.round);
    outer.put_bytes(&p.proposal_carrier.author).unwrap();
    outer.put_bytes(&p.proposal_carrier.digest).unwrap();
    outer.put_bytes(&certificate).unwrap();
    let outer = outer.finish();
    assert!(outer.len() > MAX_FIELD_LEN);
    assert!(SlotAgreementCertificatePayload::decode(&outer, set).is_err());
}

#[test]
fn agreement_certificate_valid_direct_evidence_is_read_only() {
    for commit in [false, true] {
        let (f, p, c, b) = fixture_agreement(commit);
        let before = b.clone();
        let result = inspect_without_effects(&f.dag, |dag| {
            dag.inspect_slot_agreement_certificate(&p, &c, &b)
        });
        assert_eq!(
            result,
            f.dag
                .inspect_slot_proposal(&p.proposal, &p.proposal_carrier, b.tip())
                .unwrap()
        );
        assert_eq!(b, before);
    }
}

#[test]
fn agreement_certificate_codec_strict_and_bounded() {
    let (f, p, _, _) = fixture_agreement(true);
    let set = f.dag.set();
    let bytes = p.encode(set).unwrap();
    assert_eq!(
        SlotAgreementCertificatePayload::decode(&bytes, set).unwrap(),
        p
    );
    for offset in [0, 2] {
        let mut bad = bytes.clone();
        bad[offset] = 255;
        assert!(SlotAgreementCertificatePayload::decode(&bad, set).is_err());
    }
    for end in 0..bytes.len() {
        assert!(SlotAgreementCertificatePayload::decode(&bytes[..end], set).is_err());
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(SlotAgreementCertificatePayload::decode(&bad, set).is_err());
    assert!(SlotAgreementCertificatePayload::decode(&vec![0; 1_048_577], set).is_err());
    let mut bad = p.clone();
    bad.proposal_carrier.author = vec![0; 1025];
    assert!(bad.encode(set).is_err());
    let mut bad = p.clone();
    bad.certificate.signatures[0].signature = vec![0; 1_048_576];
    assert!(bad.encode(set).is_err());
    let mut changed = p.clone();
    changed.certificate.signatures[0].signature[0] ^= 1;
    assert_ne!(p.digest(set).unwrap(), changed.digest(set).unwrap());
}

#[test]
fn agreement_certificate_rejects_nonfinal_and_wrong_proposal() {
    let (f, p, c, b) = fixture_agreement(true);
    for mutation in 0..4 {
        let mut bad = p.clone();
        match mutation {
            0 => bad.certificate.vote.phase = AgreementPhase::Prevote,
            1 => bad.certificate.vote.value = AgreementValue::Nil,
            2 => bad.proposal.decision.after_len += 1,
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
                .inspect_slot_agreement_certificate(&bad, &c, &b)
                .is_err()
        );
    }
}

#[test]
fn agreement_certificate_rejects_bad_signatures_even_when_rebound() {
    let (mut f, mut p, _, b) = fixture_agreement(true);
    p.certificate.signatures[0].signature[0] ^= 1;
    let refs = f.ids(LEADER_ROUND + 2);
    let c = bind(&mut f, &p, refs);
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn agreement_certificate_requires_exact_carrier_and_causal_predecessor() {
    let (f, mut p, c, b) = fixture_agreement(true);
    p.certificate.signatures[0].signature[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &b)
            .is_err()
    );
    let (f, p, c, b) = fixture_agreement(true);
    let mut forged = c.clone();
    forged.digest[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &forged, &b)
            .is_err()
    );
    let bad = SlotAgreementBinding::from_checkpoint(b.tip().clone(), Some(c.clone())).unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &bad)
            .is_err()
    );
}

#[test]
fn agreement_certificate_rejects_qc_only_corrupt_sidebranch() {
    let (mut f, p, c, b) = fixture_agreement(true);
    let side = f
        .ids(LEADER_ROUND + 2)
        .into_iter()
        .find(|id| *id != p.proposal_carrier)
        .unwrap();
    f.dag
        .vertices
        .get_mut(&(side.round, side.author.clone()))
        .unwrap()
        .signature[0] ^= 1;
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn agreement_certificate_requires_proposal_in_qc_cone() {
    let (mut f, p, _, b) = fixture_agreement(true);
    let refs = f.ids(LEADER_ROUND + 2)[1..].to_vec();
    let c = bind(&mut f, &p, refs);
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn agreement_certificate_predecessor_in_qc_cone_alone_is_insufficient() {
    let (mut f, mut p, _, b) = fixture_agreement(true);
    let previous = f.ids(LEADER_ROUND + 1)[3].clone();
    let refs = f.ids(LEADER_ROUND + 1)[..3].to_vec();
    let v = vertex_with_payload(&f, 0, LEADER_ROUND + 2, refs, p.proposal.digest().unwrap());
    f.dag.vertices.remove(&(v.round, v.author.clone()));
    p.proposal_carrier = f.dag.insert(v).unwrap();
    let refs = f.ids(LEADER_ROUND + 2);
    let c = bind(&mut f, &p, refs);
    assert!(f.dag.is_ancestor(&previous, &c).unwrap());
    assert!(!f.dag.is_ancestor(&previous, &p.proposal_carrier).unwrap());
    let b = SlotAgreementBinding::from_checkpoint(b.tip().clone(), Some(previous)).unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &b)
            .is_err()
    );
}

#[test]
fn agreement_certificate_valid_qc_with_different_signature_subset_is_not_bound() {
    let (f, mut p, c, b) = fixture_agreement(true);
    let bytes = p.certificate.vote.signing_payload(f.dag.set()).unwrap();
    p.certificate.signatures.remove(0);
    p.certificate.signatures.push(crate::ValidatorSignature {
        validator_id: b"val-3".to_vec(),
        key_id: b"val-3-k0".to_vec(),
        signature: Ed25519Scheme.sign(&f.keys[3], &bytes).unwrap(),
    });
    p.certificate.verify(b.tip(), f.dag.set()).unwrap();
    assert!(
        f.dag
            .inspect_slot_agreement_certificate(&p, &c, &b)
            .is_err()
    );
}
