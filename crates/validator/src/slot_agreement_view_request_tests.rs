use super::*;
use crate::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
use crypto::{registry::ALG_ED25519, scheme::Ed25519Scheme};

fn fixture() -> (ValidatorSet, SlotAgreementViewRequest) {
    let public = Ed25519Scheme::public_key_from_seed(&[7; 32]).unwrap();
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
                    keys: vec![
                        active.clone(),
                        ValidatorKey {
                            public_key: active.public_key,
                            ..inactive.clone()
                        },
                    ],
                }
            })
            .collect(),
    };
    let context =
        SlotDecisionTip::from_checkpoint(b"request-test".to_vec(), &set, 7, [1; 32], 3, [2; 32])
            .unwrap();
    let payload =
        SlotAgreementViewRequest::signing_payload(&context, AgreementView(9), &set).unwrap();
    let signature = ValidatorSignature {
        validator_id: vec![0],
        key_id: b"active".to_vec(),
        signature: Ed25519Scheme
            .sign(&[&[7; 32][..], public.as_slice()].concat(), &payload)
            .unwrap(),
    };
    let request =
        SlotAgreementViewRequest::new(context, AgreementView(9), signature, &set).unwrap();
    (set, request)
}

#[test]
fn real_signature_canonical_codec_and_immutable_getters() {
    let (set, request) = fixture();
    request.verify(request.context(), &set).unwrap();
    let context: &SlotDecisionTip = request.context();
    let signature: &ValidatorSignature = request.signature();
    assert_eq!(request.target_view(), AgreementView(9));
    let mut copy = signature.clone();
    copy.signature[0] ^= 1;
    assert_ne!(&copy, request.signature());
    let mut e = Encoder::new();
    e.put_bytes(b"KARSA/SLOT_AGREEMENT/VIEW_REQUEST/v1")
        .unwrap();
    e.put_bytes(context.chain_id()).unwrap();
    e.put_raw(context.set_id());
    e.put_u64(context.epoch());
    e.put_u64(context.next_round());
    e.put_raw(context.previous_id());
    e.put_u64(context.order_len());
    e.put_raw(context.order_root());
    e.put_u64(9);
    assert_eq!(
        SlotAgreementViewRequest::signing_payload(context, AgreementView(9), &set).unwrap(),
        e.finish()
    );
    let bytes = request.encode(&set).unwrap();
    assert_eq!(
        SlotAgreementViewRequest::decode(&bytes, &set).unwrap(),
        request
    );
    assert_eq!(
        SlotAgreementViewRequest::decode(&bytes, &set)
            .unwrap()
            .encode(&set)
            .unwrap(),
        bytes
    );
    for end in 0..bytes.len() {
        assert!(
            SlotAgreementViewRequest::decode(&bytes[..end], &set).is_err(),
            "truncation {end}"
        );
    }
    let mut bad = bytes.clone();
    bad.push(0);
    assert!(SlotAgreementViewRequest::decode(&bad, &set).is_err());
    for index in [0, 1, 2, 3, 4, 5] {
        let mut bad = bytes.clone();
        bad[index] = 255;
        assert!(
            SlotAgreementViewRequest::decode(&bad, &set).is_err(),
            "offset {index}"
        );
    }
}

#[test]
fn target_identity_key_signature_and_domain_are_authenticated() {
    let (set, request) = fixture();
    for mode in 0..7 {
        let mut signature = request.signature().clone();
        let target = if mode == 0 {
            AgreementView(10)
        } else {
            request.target_view()
        };
        match mode {
            1 => signature.validator_id = vec![99],
            2 => signature.validator_id = vec![1],
            3 => signature.key_id = b"unknown".to_vec(),
            4 => signature.key_id = b"inactive".to_vec(),
            5 => signature.signature[0] ^= 1,
            6 => {
                let mut payload =
                    SlotAgreementViewRequest::signing_payload(request.context(), target, &set)
                        .unwrap();
                payload[4] ^= 1;
                let public = Ed25519Scheme::public_key_from_seed(&[7; 32]).unwrap();
                signature.signature = Ed25519Scheme
                    .sign(&[&[7; 32][..], public.as_slice()].concat(), &payload)
                    .unwrap();
            }
            _ => {}
        }
        let bad = SlotAgreementViewRequest::new(request.context().clone(), target, signature, &set)
            .unwrap();
        let decoded = SlotAgreementViewRequest::decode(&bad.encode(&set).unwrap(), &set).unwrap();
        assert!(
            decoded.verify(request.context(), &set).is_err(),
            "mode {mode}"
        );
    }
    assert!(
        SlotAgreementViewRequest::signing_payload(request.context(), AgreementView(0), &set)
            .is_err()
    );
}

#[test]
fn every_context_field_and_pinned_set_is_checked() {
    let (set, request) = fixture();
    let c = request.context();
    for mode in 0..7 {
        let mut foreign = set.clone();
        if mode == 5 {
            foreign.epoch += 1;
        }
        if mode == 6 {
            foreign.validators[0].validator_id = vec![99];
        }
        let other = SlotDecisionTip::from_checkpoint(
            if mode == 0 {
                b"foreign".to_vec()
            } else {
                c.chain_id().to_vec()
            },
            &foreign,
            c.next_round() + u64::from(mode == 1),
            if mode == 2 { [8; 32] } else { *c.previous_id() },
            c.order_len() + u64::from(mode == 3),
            if mode == 4 { [8; 32] } else { *c.order_root() },
        )
        .unwrap();
        assert!(request.verify(&other, &foreign).is_err(), "mode {mode}");
        let bad = SlotAgreementViewRequest::new(
            other.clone(),
            request.target_view(),
            request.signature().clone(),
            &foreign,
        )
        .unwrap();
        assert!(bad.verify(&other, &foreign).is_err());
        if mode >= 5 {
            assert!(
                SlotAgreementViewRequest::signing_payload(c, request.target_view(), &foreign)
                    .is_err()
            );
            assert!(
                SlotAgreementViewRequest::decode(&request.encode(&set).unwrap(), &foreign).is_err()
            );
        }
    }
}

#[test]
fn signature_shape_and_exact_total_bounds() {
    let (set, request) = fixture();
    for mode in 0..6 {
        let mut signature = request.signature().clone();
        match mode {
            0 => signature.validator_id.clear(),
            1 => signature.key_id.clear(),
            2 => signature.signature.clear(),
            3 => signature.validator_id = vec![0; 1025],
            4 => signature.key_id = vec![0; 1025],
            _ => signature.signature = vec![0; MAX_FIELD_LEN],
        }
        assert!(
            SlotAgreementViewRequest::new(
                request.context().clone(),
                request.target_view(),
                signature,
                &set
            )
            .is_err()
        );
    }
    let mut signature = request.signature().clone();
    signature.validator_id = vec![0; 1024];
    signature.key_id = vec![0; 1024];
    signature.signature =
        vec![0; MAX_FIELD_LEN - FIXED_SIZE - request.context().chain_id().len() - 2048];
    let boundary = SlotAgreementViewRequest::new(
        request.context().clone(),
        request.target_view(),
        signature.clone(),
        &set,
    )
    .unwrap();
    let bytes = boundary.encode(&set).unwrap();
    assert_eq!(bytes.len(), MAX_FIELD_LEN);
    assert_eq!(
        SlotAgreementViewRequest::decode(&bytes, &set).unwrap(),
        boundary
    );
    signature.signature.push(0);
    assert!(
        SlotAgreementViewRequest::new(
            request.context().clone(),
            request.target_view(),
            signature,
            &set
        )
        .is_err()
    );
    assert!(SlotAgreementViewRequest::decode(&vec![0; MAX_FIELD_LEN + 1], &set).is_err());
    // Rewrite the signer length prefix without allocating from the claimed length.
    let mut bytes = request.encode(&set).unwrap();
    let offset = FIXED_SIZE - 12 + request.context().chain_id().len();
    bytes[offset..offset + 4].copy_from_slice(&1025u32.to_be_bytes());
    assert!(SlotAgreementViewRequest::decode(&bytes, &set).is_err());
}
