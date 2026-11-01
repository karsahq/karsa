//! Measures the cryptographic cost of one DAG-BFT certificate and of one round
//! of DAG headers.
//!
//! It is a measurement tool, not consensus: no dissemination, no aggregation, no
//! networking. Each measurement runs several rounds and keeps the fastest one,
//! because a single round on a shared machine picks up scheduler noise.

use std::time::Instant;

use crypto::domain::{VoteSigningFields, encode_vote_signing_payload};
use crypto::encoding::Encoder;
use crypto::registry::{ALG_ED25519, ALG_ML_DSA_65, lookup, ml_dsa_enabled};
use crypto::scheme::{Ed25519Scheme, verify_signature};

const VALIDATOR_COUNTS: [usize; 6] = [4, 7, 10, 20, 50, 100];
const CHAIN_ID: &[u8] = b"karsa-dagbench-1";
const VERTEX_ID: &[u8] = b"vertex-0f1e2d3c";
const VALIDATOR_SET_ID: &[u8] = b"validator-set-genesis";
const MEASUREMENT_ROUNDS: usize = 5;

/// Header model constants: a fixed part plus one reference digest per edge plus
/// one author signature.
const HEADER_OVERHEAD: usize = 64;
const REFERENCE_SIZE: usize = 32;

struct KeyPair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

struct Row {
    validators: usize,
    scheme: &'static str,
    cert_bytes: usize,
    sign_ns: u128,
    verify_ns: u128,
    verify_ns_sig: u128,
}

pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    let payload = encode_vote_signing_payload(&VoteSigningFields {
        chain_id: CHAIN_ID,
        epoch: 1,
        round: 7,
        vertex_id: VERTEX_ID,
    })?;

    println!("== DAG certificate cost (single core) ==");
    println!("  ed25519 backend: rust (ed25519-dalek)");
    println!("  ml-dsa enabled:  {}", ml_dsa_enabled());
    println!(
        "  payload:         {} bytes (domain-tagged vote)",
        payload.len()
    );

    let max_validators = VALIDATOR_COUNTS[VALIDATOR_COUNTS.len() - 1];
    let ed_keys = generate_ed25519_keys(max_validators)?;
    let pq_keys = generate_ml_dsa_keys(max_validators)?;

    println!();
    print_row_header();
    let mut ed_rows = Vec::new();
    let mut pq_rows = Vec::new();
    for count in VALIDATOR_COUNTS {
        let ed_row = bench_ed25519(&ed_keys[..count], &payload)?;
        print_row(&ed_row);
        ed_rows.push(ed_row);

        let pq_row = bench_ml_dsa(&pq_keys[..count], &payload)?;
        print_row(&pq_row);
        pq_rows.push(pq_row);
    }

    println!();
    print_note();
    println!();
    print_header_table(&ed_rows, &pq_rows)?;

    Ok(())
}

fn generate_ed25519_keys(count: usize) -> Result<Vec<KeyPair>, Box<dyn std::error::Error>> {
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair()?;
        keys.push(KeyPair {
            public_key: public_key.to_vec(),
            private_key: private_key.to_vec(),
        });
    }
    Ok(keys)
}

fn generate_ml_dsa_keys(count: usize) -> Result<Vec<KeyPair>, Box<dyn std::error::Error>> {
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        let (public_key, private_key) = crypto::ml_dsa::generate_keypair()?;
        keys.push(KeyPair {
            public_key,
            private_key,
        });
    }
    Ok(keys)
}

fn reps_for(validators: usize, target_ops: usize) -> usize {
    (target_ops / validators).max(1)
}

fn bench_ed25519(keys: &[KeyPair], payload: &[u8]) -> Result<Row, Box<dyn std::error::Error>> {
    let reps = reps_for(keys.len(), 200);
    let mut signatures = Vec::with_capacity(keys.len());
    for key in keys {
        signatures.push(Ed25519Scheme.sign(&key.private_key, payload)?);
    }

    // Warm up library initialisation and page faults before timing.
    for key in keys {
        let _ = Ed25519Scheme.sign(&key.private_key, payload)?;
    }
    for (index, key) in keys.iter().enumerate() {
        verify_signature(ALG_ED25519, &key.public_key, payload, &signatures[index])?;
    }

    let mut sign_ns = u128::MAX;
    for _ in 0..MEASUREMENT_ROUNDS {
        let start = Instant::now();
        for _ in 0..reps {
            for key in keys {
                let _ = Ed25519Scheme.sign(&key.private_key, payload)?;
            }
        }
        sign_ns = sign_ns.min(start.elapsed().as_nanos() / reps as u128);
    }

    let mut verify_ns = u128::MAX;
    for _ in 0..MEASUREMENT_ROUNDS {
        let start = Instant::now();
        for _ in 0..reps {
            for (index, key) in keys.iter().enumerate() {
                verify_signature(ALG_ED25519, &key.public_key, payload, &signatures[index])?;
            }
        }
        verify_ns = verify_ns.min(start.elapsed().as_nanos() / reps as u128);
    }

    Ok(Row {
        validators: keys.len(),
        scheme: "ed25519",
        cert_bytes: certificate_bytes(keys.len(), &signatures)?,
        sign_ns,
        verify_ns,
        verify_ns_sig: verify_ns / keys.len() as u128,
    })
}

fn bench_ml_dsa(keys: &[KeyPair], payload: &[u8]) -> Result<Row, Box<dyn std::error::Error>> {
    let reps = reps_for(keys.len(), 60);
    let mut signatures = Vec::with_capacity(keys.len());
    for key in keys {
        signatures.push(crypto::ml_dsa::sign_with_context(
            &key.private_key,
            payload,
            &[],
        )?);
    }

    for key in keys {
        let _ = crypto::ml_dsa::sign_with_context(&key.private_key, payload, &[])?;
    }
    for (index, key) in keys.iter().enumerate() {
        crypto::ml_dsa::verify_with_context(&key.public_key, payload, &signatures[index], &[])?;
    }

    let mut sign_ns = u128::MAX;
    for _ in 0..MEASUREMENT_ROUNDS {
        let start = Instant::now();
        for _ in 0..reps {
            for key in keys {
                let _ = crypto::ml_dsa::sign_with_context(&key.private_key, payload, &[])?;
            }
        }
        sign_ns = sign_ns.min(start.elapsed().as_nanos() / reps as u128);
    }

    let mut verify_ns = u128::MAX;
    for _ in 0..MEASUREMENT_ROUNDS {
        let start = Instant::now();
        for _ in 0..reps {
            for (index, key) in keys.iter().enumerate() {
                crypto::ml_dsa::verify_with_context(
                    &key.public_key,
                    payload,
                    &signatures[index],
                    &[],
                )?;
            }
        }
        verify_ns = verify_ns.min(start.elapsed().as_nanos() / reps as u128);
    }

    Ok(Row {
        validators: keys.len(),
        scheme: "ml-dsa-65",
        cert_bytes: certificate_bytes(keys.len(), &signatures)?,
        sign_ns,
        verify_ns,
        verify_ns_sig: verify_ns / keys.len() as u128,
    })
}

fn certificate_bytes(
    validators: usize,
    signatures: &[Vec<u8>],
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut encoder = Encoder::with_capacity(512);
    encoder.put_u16(1);
    encoder.put_bytes(CHAIN_ID)?;
    encoder.put_u64(1);
    encoder.put_u64(7);
    encoder.put_bytes(VERTEX_ID)?;
    encoder.put_bytes(VALIDATOR_SET_ID)?;
    encoder.put_bytes(&full_bitmap(validators))?;
    encoder.put_u32(u32::try_from(signatures.len())?);
    for signature in signatures {
        encoder.put_bytes(signature)?;
    }
    Ok(encoder.finish().len())
}

/// Marks every validator as a signer: `ceil(n/8)` bytes with the unused high bits
/// of the last byte cleared.
fn full_bitmap(validators: usize) -> Vec<u8> {
    let length = validators.div_ceil(8);
    let mut bitmap = vec![0xffu8; length];
    let used = validators % 8;
    if used != 0 {
        bitmap[length - 1] = u8::try_from((1u16 << used) - 1).expect("a byte mask fits");
    }
    bitmap
}

fn quorum_size(n: usize) -> usize {
    let f = (n - 1) / 3;
    2 * f + 1
}

/// Returns `(dense refs, sparse refs, dense bytes, sparse bytes)` for one round.
///
/// Dense: every block references a `2f+1` quorum.
/// Sparse (Bluestreak): non-leader blocks reference two blocks, the single leader
/// references every node.
fn header_model(n: usize, signature_size: usize) -> (usize, usize, usize, usize) {
    let quorum = quorum_size(n);
    let dense_refs = n * quorum;
    let sparse_refs = (n - 1) * 2 + n;
    let dense_bytes = n * (HEADER_OVERHEAD + quorum * REFERENCE_SIZE + signature_size);
    let non_leader_bytes = (n - 1) * (HEADER_OVERHEAD + 2 * REFERENCE_SIZE + signature_size);
    let leader_bytes = HEADER_OVERHEAD + n * REFERENCE_SIZE + signature_size;
    (
        dense_refs,
        sparse_refs,
        dense_bytes,
        non_leader_bytes + leader_bytes,
    )
}

fn pad_left(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn pad_right(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn print_row_header() {
    println!(
        "  {}  {}  {}  {}  {}  {}  {}",
        pad_left("validators", 10),
        pad_right("scheme", 10),
        pad_left("cert bytes", 10),
        pad_left("sign/cert", 9),
        pad_left("verify/cert", 11),
        pad_left("verify/sig", 10),
        pad_left("certs/s/core", 12),
    );
}

fn print_row(row: &Row) {
    let certs_per_second = 1_000_000_000u128.checked_div(row.verify_ns).unwrap_or(0);
    println!(
        "  {}  {}  {}  {}  {}  {}  {}",
        pad_left(&row.validators.to_string(), 10),
        pad_right(row.scheme, 10),
        pad_left(&row.cert_bytes.to_string(), 10),
        pad_left(&format!("{} us", row.sign_ns / 1000), 9),
        pad_left(&format!("{} us", row.verify_ns / 1000), 11),
        pad_left(&format!("{} us", row.verify_ns_sig / 1000), 10),
        pad_left(&certs_per_second.to_string(), 12),
    );
}

fn print_note() {
    println!("  Certificate = header + ceil(n/8) bitmap + n length-prefixed signatures.");
    println!("  Signature sizes come from the registry, so a PQ row is 3,309 bytes per");
    println!("  signer rather than 64. One core is used; no aggregation or batching.");
    println!("  Times are the fastest of {MEASUREMENT_ROUNDS} rounds per row.");
}

fn print_header_table(ed_rows: &[Row], pq_rows: &[Row]) -> Result<(), Box<dyn std::error::Error>> {
    let ed_sig = lookup(ALG_ED25519)?.signature_size;
    let pq_sig = lookup(ALG_ML_DSA_65)?.signature_size;

    println!("== DAG headers per round (n blocks, one signature each) ==");
    println!(
        "  {}  {}  {}  {}  {}  {}  {}  {}",
        pad_left("validators", 10),
        pad_right("scheme", 10),
        pad_left("refs dense", 10),
        pad_left("refs sparse", 11),
        pad_left("dense/round", 11),
        pad_left("sparse/round", 12),
        pad_left("gain", 6),
        pad_left("verify/round", 12),
    );
    for (index, row) in ed_rows.iter().enumerate() {
        print_header_row(row.validators, "ed25519", ed_sig, row.verify_ns);
        if let Some(pq_row) = pq_rows.get(index) {
            print_header_row(pq_row.validators, "ml-dsa-65", pq_sig, pq_row.verify_ns);
        }
    }
    println!();
    println!(
        "  Model: header = {HEADER_OVERHEAD} B fixed + {REFERENCE_SIZE} B per reference + one author signature."
    );
    println!(
        "  Dense = every block references a 2f+1 quorum ({} references at n=100);",
        quorum_size(100)
    );
    println!("  sparse = non-leaders reference two blocks and the single leader references");
    println!("  every node. Reference checking is hashing, not signature verification, so");
    println!("  verify/round is n signature checks in both designs.");
    Ok(())
}

fn print_header_row(n: usize, scheme: &str, signature_size: usize, verify_ns: u128) {
    let (dense_refs, sparse_refs, dense_bytes, sparse_bytes) = header_model(n, signature_size);
    let gain_x10 = (dense_bytes * 10 + sparse_bytes / 2)
        .checked_div(sparse_bytes)
        .unwrap_or(0);
    println!(
        "  {}  {}  {}  {}  {}  {}  {}  {}",
        pad_left(&n.to_string(), 10),
        pad_right(scheme, 10),
        pad_left(&dense_refs.to_string(), 10),
        pad_left(&sparse_refs.to_string(), 11),
        pad_left(&dense_bytes.to_string(), 11),
        pad_left(&sparse_bytes.to_string(), 12),
        pad_left(&format!("{}.{}x", gain_x10 / 10, gain_x10 % 10), 6),
        pad_left(&format!("{} us", verify_ns / 1000), 12),
    );
}
