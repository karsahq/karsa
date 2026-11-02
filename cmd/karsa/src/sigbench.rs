//! Measures transaction signature verification throughput and how it scales.
//!
//! This is the number that decides the TPS ceiling. Consensus metadata, header
//! size, and gossip topology all matter for bandwidth and latency, but every
//! transaction must be verified independently by every node, and that cost does
//! not shrink with batching.
//!
//! The measurement is the real path: build a transaction, verify it through the
//! account policy, count how many complete in a second. Parallelism is measured by
//! chunking the same set across `std::thread::scope`, so the speedup reported is
//! the speedup an implementation would actually get.

use std::error::Error;
use std::time::Instant;

use crypto::registry::{ALG_ED25519, ALG_ML_DSA_65, lookup};
use crypto::scheme::Ed25519Scheme;
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::{AuthKey, AuthPolicy, AuthPolicyKind, Authorization, KeyStatus};

const CHAIN_ID: &[u8] = b"karsa-sigbench-1";
const NOW: u64 = 1_000;
/// Transactions per measurement. Large enough to dominate timer noise.
const TRANSACTIONS: usize = 2_000;

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn policy(public_key: Vec<u8>) -> AuthPolicy {
    AuthPolicy {
        kind: AuthPolicyKind::Single,
        threshold: 0,
        policy_nonce: 1,
        keys: vec![AuthKey {
            key_id: b"bench-k0".to_vec(),
            algorithm_id: ALG_ED25519,
            public_key,
            weight: 1,
            status: KeyStatus::Active,
            valid_from: 0,
            valid_until: u64::MAX,
        }],
    }
}

/// Builds and signs `count` distinct transactions.
fn transactions(count: usize) -> Result<Vec<Transaction>, Box<dyn Error>> {
    let seed = [7u8; 32];
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let mut private_key = Vec::with_capacity(64);
    private_key.extend_from_slice(&seed);
    private_key.extend_from_slice(&public_key);

    let mut transactions = Vec::with_capacity(count);
    for index in 0..count {
        let mut transaction = Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: CHAIN_ID.to_vec(),
            sender: b"benchmark".to_vec(),
            sequence: u64::try_from(index).unwrap_or(0) + 1,
            fee: 1,
            expiration: u64::MAX,
            policy_version: 1,
            // A realistic body length; the signature is what dominates anyway.
            payload: vec![u8::try_from(index % 256).unwrap_or(0); 40],
            authorization: Vec::new(),
        };
        let message = transaction.signing_payload()?;
        let signature = Ed25519Scheme.sign(&private_key, &message)?;
        transaction.authorization = vec![Authorization {
            algorithm_id: ALG_ED25519,
            key_id: b"bench-k0".to_vec(),
            signature,
        }];
        transactions.push(transaction);
    }
    Ok(transactions)
}

/// Verifies every transaction across `threads` threads and returns (nanoseconds,
/// verified count).
fn measure(
    transactions: &[Transaction],
    policy: &AuthPolicy,
    threads: usize,
) -> Result<(u128, usize), Box<dyn Error>> {
    let chunk = transactions.len().div_ceil(threads).max(1);
    let start = Instant::now();
    let mut verified = 0usize;
    std::thread::scope(|scope| {
        let handles: Vec<_> = transactions
            .chunks(chunk)
            .map(|slice| {
                scope.spawn(move || {
                    slice
                        .iter()
                        .filter(|transaction| transaction.verify(policy, NOW).is_ok())
                        .count()
                })
            })
            .collect();
        for handle in handles {
            verified += handle.join().expect("a verification thread panicked");
        }
    });
    Ok((start.elapsed().as_nanos(), verified))
}

pub fn run(algorithm: &str, threads: usize) -> Result<(), Box<dyn Error>> {
    let algorithm_id = match algorithm {
        "ed25519" => ALG_ED25519,
        "ml-dsa-65" => ALG_ML_DSA_65,
        other => return Err(format!("unknown algorithm '{other}'").into()),
    };
    let spec = lookup(algorithm_id)?;
    if threads == 0 {
        return Err("--threads must be at least 1".into());
    }

    if algorithm_id != ALG_ED25519 {
        return Err(format!(
            "'{algorithm}' is registered but not activated. Build with --features pq-testnet \
             to measure it; without activation this chain is classical on purpose."
        )
        .into());
    }

    let transactions = transactions(TRANSACTIONS)?;
    let seed = [7u8; 32];
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let policy = policy(public_key.to_vec());
    if transactions[0].verify(&policy, NOW).is_err() {
        return Err("the benchmark transaction does not verify; fix the fixture".into());
    }

    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);

    println!("== Transaction signature verification ==");
    println!("  algorithm:     {} ({})", algorithm, spec.name);
    println!("  signature:     {} bytes", spec.signature_size);
    println!("  transactions:  {TRANSACTIONS}");
    println!("  cpus available:{available}");
    println!();
    println!(
        "  {}  {}  {}  {}",
        pad("threads", 8),
        pad("tx/s", 12),
        pad("speedup", 8),
        pad("per tx", 10)
    );

    let mut single_thread_rate = 0.0f64;
    for count in 1..=threads {
        let (nanos, verified) = measure(&transactions, &policy, count)?;
        if verified != transactions.len() {
            return Err(format!("only {verified} of {} verified", transactions.len()).into());
        }
        let seconds = nanos as f64 / 1e9;
        let rate = verified as f64 / seconds;
        if count == 1 {
            single_thread_rate = rate;
        }
        println!(
            "  {}  {}  {}  {}",
            pad(&count.to_string(), 8),
            pad(&format!("{rate:.0}"), 12),
            pad(&format!("{:.1}x", rate / single_thread_rate), 8),
            pad(&format!("{:.1} us", 1e6 / rate), 10)
        );
    }

    println!();
    let per_core = single_thread_rate;
    for target in [1_000u64, 10_000, 100_000] {
        let cores = target as f64 / per_core;
        println!(
            "  {target:>7} tx/s needs {:>6.1} cores of this machine ({:.1} tx/s per core)",
            cores, per_core
        );
    }
    println!();
    println!("  This is a ceiling, not a throughput claim: it excludes consensus,");
    println!("  networking, and execution. Nothing here scales with validator count,");
    println!("  which is why a bigger committee does not raise it and a smaller one");
    println!("  does not lower it.");

    Ok(())
}
