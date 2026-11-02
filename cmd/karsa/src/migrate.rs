//! Demonstrates a validator key rotation across an epoch boundary.
//!
//! Rotation is what a post-quantum migration is. The point of this command is that
//! it is not a special mode: the same `Dag`, the same commit rules, and the same
//! vertex format carry the chain across the boundary. Only the key schedule
//! changes, and it changes at a round every node computes identically.
//!
//! The algorithm is intentionally not hardcoded. This run rotates between two
//! Ed25519 keys because that needs no feature flag; replacing the second key with
//! an ML-DSA key is a change to one `ValidatorKey`, and the epoch machinery does
//! not notice.

use std::error::Error;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use validator::{
    Dag, NO_EXPIRY, Pacemaker, PacemakerConfig, Step, ValidatorKey, ValidatorRecord, ValidatorSet,
    Vertex, VertexId, commit_root,
};

const CHAIN_ID: &[u8] = b"karsa-migrate-1";
/// Rounds per epoch. Small so the boundary is visible in a short run.
const ROUNDS_PER_EPOCH: u64 = 2;
/// Epoch at which every validator switches to its new key.
const ROTATION_EPOCH: u64 = 2;

struct Keypair {
    public_key: Vec<u8>,
    private_key: Vec<u8>,
}

fn keypair(seed: u8) -> Result<Keypair, crypto::CryptoError> {
    let seed = [seed; 32];
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let mut private_key = Vec::with_capacity(64);
    private_key.extend_from_slice(&seed);
    private_key.extend_from_slice(&public_key);
    Ok(Keypair {
        public_key: public_key.to_vec(),
        private_key,
    })
}

/// One validator: an identity with two keys, the old one retiring at the rotation.
struct Rotating {
    id: Vec<u8>,
    old: Keypair,
    new: Keypair,
}

fn validators(count: usize) -> Result<(ValidatorSet, Vec<Rotating>), crypto::CryptoError> {
    let mut records = Vec::with_capacity(count);
    let mut rotating = Vec::with_capacity(count);
    for index in 0..count {
        let old = keypair(u8::try_from(index + 1).unwrap_or(1))?;
        let new = keypair(u8::try_from(index + 101).unwrap_or(101))?;
        let id = format!("val-{index}").into_bytes();
        records.push(ValidatorRecord {
            validator_id: id.clone(),
            keys: vec![
                ValidatorKey {
                    key_id: format!("val-{index}-old").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: old.public_key.clone(),
                    activation_epoch: 0,
                    retirement_epoch: ROTATION_EPOCH,
                },
                ValidatorKey {
                    key_id: format!("val-{index}-new").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: new.public_key.clone(),
                    activation_epoch: ROTATION_EPOCH,
                    retirement_epoch: NO_EXPIRY,
                },
            ],
        });
        rotating.push(Rotating { id, old, new });
    }

    let set = ValidatorSet {
        epoch: 0,
        validators: records,
    };
    set.validate()?;
    Ok((set, rotating))
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

pub fn run(validators_count: usize, rounds: u64) -> Result<(), Box<dyn Error>> {
    if validators_count < 4 {
        return Err("validators must be at least 4 so that a quorum is not everyone".into());
    }
    if rounds == 0 {
        return Err("--rounds must be at least 1".into());
    }

    let (set, rotating) = validators(validators_count)?;
    let mut dag = Dag::with_epoch_length(set.clone(), ROUNDS_PER_EPOCH);

    // Two empty rounds past the data so the last data round can commit.
    let last = rounds + 2;
    let mut rows: Vec<(u64, u64, &'static str)> = Vec::new();

    for round in 0..=last {
        let epoch = dag.epoch_of(round);
        let references: Vec<VertexId> = (0..validators_count)
            .filter_map(|author| {
                dag.get(round.wrapping_sub(1), format!("val-{author}").as_bytes())
                    .and_then(|vertex| vertex.id().ok())
            })
            .collect();

        let label = if epoch < ROTATION_EPOCH { "old" } else { "new" };
        rows.push((round, epoch, label));

        for validator in &rotating {
            let key = if epoch < ROTATION_EPOCH {
                &validator.old
            } else {
                &validator.new
            };
            let mut vertex = Vertex {
                chain_id: CHAIN_ID.to_vec(),
                epoch,
                round,
                author: validator.id.clone(),
                payload_hash: [0u8; 32],
                references: references.clone(),
                signature: Vec::new(),
            };
            let payload = vertex.signing_payload()?;
            vertex.signature = Ed25519Scheme.sign(&key.private_key, &payload)?;
            dag.insert(vertex)?;
        }
    }

    let mut pacemaker = Pacemaker::new(PacemakerConfig { timeout_ticks: 3 }, 1);
    let mut quiet = 0usize;
    let mut ticks = 0usize;
    while quiet < 2 && ticks < 256 {
        match pacemaker.tick(&mut dag)? {
            Step::Advanced { .. } => quiet = 0,
            Step::Waiting { .. } | Step::TimedOut { .. } => quiet += 1,
        }
        ticks += 1;
    }

    println!("== Key rotation across an epoch boundary ==");
    println!("  chain:         {}", String::from_utf8_lossy(CHAIN_ID));
    println!("  validators:    {validators_count}");
    println!("  rounds/epoch:  {ROUNDS_PER_EPOCH}");
    println!("  rotation at:   epoch {ROTATION_EPOCH}");
    println!();
    println!(
        "  {}  {}  {}  status",
        pad("round", 7),
        pad("epoch", 7),
        pad("key", 6)
    );
    let boundary = ROTATION_EPOCH.saturating_sub(set.epoch) * ROUNDS_PER_EPOCH;
    for (round, epoch, label) in &rows {
        let status = if *round == boundary {
            "<- every validator switches key here"
        } else {
            ""
        };
        println!(
            "  {}  {}  {}  {}",
            pad(&round.to_string(), 7),
            pad(&epoch.to_string(), 7),
            pad(label, 6),
            status
        );
    }

    println!();
    println!("  committed vertices: {}", dag.order().len());
    println!(
        "  commit root:        {}",
        hex::encode(&commit_root(dag.order())[..6])
    );
    println!(
        "  epochs spanned:     {} -> {}",
        set.epoch,
        dag.epoch_of(last)
    );
    println!();
    println!("  The chain crossed the boundary without a restart, a new DAG, or a");
    println!("  format change. Swapping the new key for an ML-DSA key is a change to one");
    println!("  ValidatorKey and nothing else: the epoch mapping is a function of the");
    println!("  round, so every node derives the same key for the same round.");

    Ok(())
}
