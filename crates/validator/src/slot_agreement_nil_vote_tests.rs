use super::*;
use crate::slot_agreement::{AgreementPhase, AgreementView, SLOT_AGREEMENT_VOTE_DOMAIN};
use crate::{NO_EXPIRY, SlotDecision, SlotOutcome, ValidatorKey, ValidatorRecord};
use crypto::{registry::ALG_ED25519, scheme::Ed25519Scheme};

fn fixture(phase: AgreementPhase) -> (ValidatorSet, SlotAgreementNilVote) {
    let seed = [7; 32];
    let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
    let key = ValidatorKey {
        key_id: b"active".to_vec(),
        algorithm_id: ALG_ED25519,
        public_key: public.to_vec(),
        activation_epoch: 0,
        retirement_epoch: 3,
    };
    let mut inactive = key.clone();
    inactive.key_id = b"inactive".to_vec();
    inactive.activation_epoch = 3;
    inactive.retirement_epoch = NO_EXPIRY;
    let set = ValidatorSet {
        epoch: 2,
        validators: (0..4)
            .map(|i| {
                let mut active = key.clone();
                active.public_key = Ed25519Scheme::public_key_from_seed(&[7 + i; 32])
                    .unwrap()
                    .to_vec();
                ValidatorRecord {
                    validator_id: vec![i],
                    keys: vec![active, inactive.clone()],
                }
            })
            .collect(),
    };
    let context =
        SlotDecisionTip::from_checkpoint(b"nil-test".to_vec(), &set, 7, [1; 32], 3, [2; 32])
            .unwrap();
    let vote = AgreementVote {
        context,
        view: AgreementView(9),
        phase,
        value: AgreementValue::Nil,
    };
    let signature = ValidatorSignature {
        validator_id: vec![0],
        key_id: b"active".to_vec(),
        signature: Ed25519Scheme
            .sign(
                &[seed.as_slice(), public.as_slice()].concat(),
                &vote.signing_payload(&set).unwrap(),
            )
            .unwrap(),
    };
    (
        set.clone(),
        SlotAgreementNilVote::new(vote, signature, &set).unwrap(),
    )
}

fn wrap(qc: &[u8]) -> Vec<u8> {
    let mut e = Encoder::new();
    e.put_u16(VERSION);
    e.put_u8(NIL_VOTE);
    e.put_bytes(qc).unwrap();
    e.finish()
}

#[test]
fn nil_exact_signing_bytes_and_deterministic_roundtrip_both_phases() {
    for (phase, tag) in [(AgreementPhase::Prevote, 0), (AgreementPhase::Precommit, 1)] {
        let (set, message) = fixture(phase);
        assert!(set.quorum_size() > 1);
        message.verify(&message.vote().context, &set).unwrap();
        let c = &message.vote().context;
        let mut e = Encoder::new();
        e.put_bytes(SLOT_AGREEMENT_VOTE_DOMAIN).unwrap();
        e.put_bytes(c.chain_id()).unwrap();
        e.put_raw(c.set_id());
        e.put_u64(c.epoch());
        e.put_u64(c.next_round());
        e.put_raw(c.previous_id());
        e.put_u64(c.order_len());
        e.put_raw(c.order_root());
        e.put_u64(9);
        e.put_u8(tag);
        e.put_u8(0);
        assert_eq!(message.vote().signing_payload(&set).unwrap(), e.finish());
        let bytes = message.encode(&set).unwrap();
        assert_eq!(
            bytes.len(),
            179 + c.chain_id().len()
                + message.signature.validator_id.len()
                + message.signature.key_id.len()
                + message.signature.signature.len()
        );
        let decoded = SlotAgreementNilVote::decode(&bytes, &set).unwrap();
        assert_eq!(decoded, message);
        assert_eq!(decoded.encode(&set).unwrap(), bytes);
        assert_eq!(decoded.signature(), message.signature());
        for end in 0..bytes.len() {
            assert!(
                SlotAgreementNilVote::decode(&bytes[..end], &set).is_err(),
                "truncation {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(SlotAgreementNilVote::decode(&trailing, &set).is_err());
        for index in [0, 1, 2] {
            let mut bad = bytes.clone();
            bad[index] = 255;
            assert!(SlotAgreementNilVote::decode(&bad, &set).is_err());
        }
    }
}

#[test]
fn nil_construction_and_decode_are_not_authentication() {
    let (set, message) = fixture(AgreementPhase::Prevote);
    for mode in 0..6 {
        let mut vote = message.vote.clone();
        let mut signature = message.signature.clone();
        match mode {
            0 => vote.view.0 += 1,
            1 => vote.phase = AgreementPhase::Precommit,
            2 => signature.validator_id = vec![99],
            3 => signature.key_id = b"unknown".to_vec(),
            4 => signature.key_id = b"inactive".to_vec(),
            _ => signature.signature[0] ^= 1,
        }
        let bad = SlotAgreementNilVote::new(vote, signature, &set).unwrap();
        let decoded = SlotAgreementNilVote::decode(&bad.encode(&set).unwrap(), &set).unwrap();
        assert!(
            decoded.verify(&message.vote.context, &set).is_err(),
            "mode {mode}"
        );
    }
}

#[test]
fn nil_pins_every_context_field_and_set() {
    let (set, message) = fixture(AgreementPhase::Prevote);
    let c = &message.vote.context;
    for mode in 0..5 {
        let other = SlotDecisionTip::from_checkpoint(
            if mode == 0 {
                b"foreign".to_vec()
            } else {
                c.chain_id().to_vec()
            },
            &set,
            c.next_round() + u64::from(mode == 1),
            if mode == 2 { [8; 32] } else { *c.previous_id() },
            c.order_len() + u64::from(mode == 3),
            if mode == 4 { [8; 32] } else { *c.order_root() },
        )
        .unwrap();
        assert!(message.verify(&other, &set).is_err());
        let mut vote = message.vote.clone();
        vote.context = other.clone();
        let bad = SlotAgreementNilVote::new(vote, message.signature.clone(), &set).unwrap();
        assert!(bad.verify(&other, &set).is_err());
    }
    for epoch in [2, 3] {
        let mut foreign = set.clone();
        foreign.epoch = epoch;
        foreign.validators[0].validator_id = vec![10];
        assert!(
            SlotAgreementNilVote::new(message.vote.clone(), message.signature.clone(), &foreign)
                .is_err()
        );
        assert!(SlotAgreementNilVote::decode(&message.encode(&set).unwrap(), &foreign).is_err());
        assert!(message.verify(c, &foreign).is_err());
    }
}

#[test]
fn nil_rejects_decisions_counts_and_bounds() {
    let (set, message) = fixture(AgreementPhase::Prevote);
    let c = &message.vote.context;
    let decision = SlotDecision {
        chain_id: c.chain_id().to_vec(),
        validator_set_id: *c.set_id(),
        epoch: c.epoch(),
        round: c.next_round(),
        previous: *c.previous_id(),
        before_len: c.order_len(),
        before_root: *c.order_root(),
        after_len: c.order_len(),
        after_root: *c.order_root(),
        outcome: SlotOutcome::Skip {
            leader_author: vec![0],
        },
    };
    let mut vote = message.vote.clone();
    vote.value = AgreementValue::Decision(decision);
    assert!(SlotAgreementNilVote::new(vote.clone(), message.signature.clone(), &set).is_err());
    let qc = AgreementQc {
        vote,
        signatures: vec![message.signature.clone()],
    };
    assert!(SlotAgreementNilVote::decode(&wrap(&qc.encode(&set).unwrap()), &set).is_err());
    for count in [0, 2] {
        let mut signatures = vec![message.signature.clone(); count];
        if count == 2 {
            signatures[1].validator_id = vec![1];
        }
        let qc = AgreementQc {
            vote: message.vote.clone(),
            signatures,
        };
        assert!(SlotAgreementNilVote::decode(&wrap(&qc.encode(&set).unwrap()), &set).is_err());
    }
    for field in 0..3 {
        let mut signature = message.signature.clone();
        match field {
            0 => signature.validator_id = vec![0; 1025],
            1 => signature.key_id = vec![0; 1025],
            _ => signature.signature = vec![0; MAX_FIELD_LEN],
        }
        assert!(SlotAgreementNilVote::new(message.vote.clone(), signature, &set).is_err());
    }
    let mut signature = message.signature.clone();
    signature.validator_id = vec![0; 1024];
    signature.key_id = vec![0; 1024];
    signature.signature = vec![0; MAX_FIELD_LEN - 179 - c.chain_id().len() - 2048];
    let boundary =
        SlotAgreementNilVote::new(message.vote.clone(), signature.clone(), &set).unwrap();
    let bytes = boundary.encode(&set).unwrap();
    assert_eq!(bytes.len(), MAX_FIELD_LEN);
    assert_eq!(
        SlotAgreementNilVote::decode(&bytes, &set).unwrap(),
        boundary
    );
    signature.signature.push(0);
    assert!(SlotAgreementNilVote::new(message.vote.clone(), signature, &set).is_err());
    assert!(SlotAgreementNilVote::decode(&vec![0; MAX_FIELD_LEN + 1], &set).is_err());
    // Malicious nested identifier length is rejected by the existing QC preflight.
    let mut e = Encoder::new();
    e.put_u16(1);
    e.put_u8(2);
    e.put_bytes(&message.vote.encode(&set).unwrap()).unwrap();
    e.put_u32(1);
    e.put_bytes(&vec![0; 1025]).unwrap();
    e.put_bytes(b"active").unwrap();
    e.put_bytes(b"x").unwrap();
    assert!(SlotAgreementNilVote::decode(&wrap(&e.finish()), &set).is_err());
}
