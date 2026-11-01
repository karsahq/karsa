//! Builds, encodes, and verifies one DAG-BFT certificate.
//!
//! `karsa dagbench` models the bytes; this command actually signs, encodes, and
//! verifies them through the same code the node would use. It also runs the
//! negative cases, because a certificate scheme is only interesting for what it
//! rejects.

use std::time::Instant;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};
use validator::{Certificate, NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet, bitmap_of};

const CHAIN_ID: &[u8] = b"karsa-certify-1";
const VERTEX_ID: &[u8] = b"vertex-0f1e2d3c";
const VALIDATOR_SET_ID: &[u8] = b"validator-set-genesis";
const CERTIFICATE_EPOCH: u64 = 1;
const CERTIFICATE_ROUND: u64 = 7;
const MEASUREMENT_ROUNDS: usize = 5;

/// Deterministic seed material, so two runs sign the same bytes.
fn seed_for(index: usize) -> [u8; 32] {
    Sha256::digest(index.to_le_bytes()).into()
}

pub fn run(validators: usize) -> Result<(), Box<dyn std::error::Error>> {
    if validators == 0 {
        return Err("--validators must be at least 1".into());
    }

    let mut private_keys = Vec::with_capacity(validators);
    let mut records = Vec::with_capacity(validators);
    for index in 0..validators {
        let seed = seed_for(index);
        let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
        let mut private_key = Vec::with_capacity(64);
        private_key.extend_from_slice(&seed);
        private_key.extend_from_slice(&public_key);
        records.push(ValidatorRecord {
            validator_id: format!("val-{index}").into_bytes(),
            keys: vec![ValidatorKey {
                key_id: format!("val-{index}-k0").into_bytes(),
                algorithm_id: ALG_ED25519,
                public_key: public_key.to_vec(),
                activation_epoch: 0,
                retirement_epoch: NO_EXPIRY,
            }],
        });
        private_keys.push(private_key);
    }

    let set = ValidatorSet {
        epoch: CERTIFICATE_EPOCH,
        validators: records,
    };
    set.validate()?;

    let mut certificate = Certificate {
        chain_id: CHAIN_ID.to_vec(),
        epoch: CERTIFICATE_EPOCH,
        round: CERTIFICATE_ROUND,
        vertex_id: VERTEX_ID.to_vec(),
        validator_set_id: VALIDATOR_SET_ID.to_vec(),
        signer_bitmap: bitmap_of(validators, validators),
        signatures: Vec::new(),
    };
    let payload = certificate.signing_payload()?;
    for private_key in &private_keys {
        certificate
            .signatures
            .push(Ed25519Scheme.sign(private_key, &payload)?);
    }
    let encoded = certificate.encode()?;

    // Decode and verify the decoded value, not the one we just built: that is the
    // only way the wire format gets exercised.
    let decoded = Certificate::decode(&encoded)?;
    if decoded != certificate {
        return Err("the certificate did not roundtrip".into());
    }

    let mut verify_ns = u128::MAX;
    for _ in 0..MEASUREMENT_ROUNDS {
        let start = Instant::now();
        decoded.verify_quorum(&set)?;
        verify_ns = verify_ns.min(start.elapsed().as_nanos());
    }

    println!("== DAG-BFT certificate ==");
    println!("  validators:        {validators}");
    println!("  epoch / round:     {CERTIFICATE_EPOCH} / {CERTIFICATE_ROUND}");
    println!(
        "  supermajority:     {} of {validators}",
        supermajority_of(validators)
    );
    println!("  signers:           {}", decoded.signer_count());
    println!("  bitmap:            {} bytes", decoded.signer_bitmap.len());
    println!("  encoded:           {} bytes", encoded.len());
    println!("  verify + quorum:   {} us", verify_ns / 1000);
    println!(
        "  certificates/s:    {} per core",
        1_000_000_000u128.checked_div(verify_ns).unwrap_or(0)
    );
    println!(
        "  per signature:     {} us",
        verify_ns / 1000 / validators as u128
    );

    println!();
    println!("== rejections ==");

    let below = validators / 2;
    let mut partial = certificate.clone();
    partial.signer_bitmap = bitmap_of(validators, below);
    partial.signatures.truncate(below);
    report(
        &format!("{below} signers (below quorum)"),
        partial.verify_quorum(&set).map(|_| ()),
    );

    let mut tampered = certificate.clone();
    if let Some(first) = tampered.signatures.first_mut() {
        first[0] ^= 0x01;
    }
    report(
        "tampered signature",
        tampered.verify_quorum(&set).map(|_| ()),
    );

    let mut retired = set.clone();
    if let Some(key) = retired
        .validators
        .first_mut()
        .and_then(|record| record.keys.first_mut())
    {
        key.retirement_epoch = CERTIFICATE_EPOCH;
    }
    report(
        "signer key retired at the epoch",
        certificate.verify_quorum(&retired).map(|_| ()),
    );

    let mut short = certificate.clone();
    short.signatures.pop();
    report(
        "bitmap and signature count disagree",
        short.encode().map(|_| ()),
    );

    println!();
    println!("  Codes are the frozen taxonomy from docs/crypto-registry.md §7.");
    println!("  The certificate carries no key ids: each signer's key is resolved");
    println!("  from the schedule at the certificate epoch.");

    Ok(())
}

/// Smallest signer count that is a supermajority of `validators`.
fn supermajority_of(validators: usize) -> usize {
    validators * 2 / 3 + 1
}

fn report(label: &str, result: Result<(), CryptoError>) {
    match result {
        Ok(()) => println!("  {label:<34} ACCEPTED (unexpected)"),
        Err(error) => println!(
            "  {label:<34} code {:>2} {}",
            error.code(),
            kind_name(error.kind())
        ),
    }
}

fn kind_name(kind: CryptoErrorKind) -> &'static str {
    kind.as_str()
}
