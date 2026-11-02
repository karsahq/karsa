//! End-to-end local chain: order transactions, then execute them.
//!
//! This is the first command that closes the loop. Earlier tools each measured or
//! demonstrated one layer; here a transaction is signed, batched, named by a
//! vertex, ordered by the DAG, committed by the pacemaker, and then applied to a
//! state machine whose root is printed.
//!
//! Everything is deterministic and local: fixed seeds, fixed batches, no clock,
//! no network. Running the simulation twice must produce the same state root, and
//! the command checks that rather than asserting it in prose.
//!
//! Deliberately absent: signature verification of the *consensus* vertices happens
//! during `Dag::insert` (it is not optional), but transaction authorization is
//! applied here through the account policy, so a rejected signature is a rejected
//! transaction and never reaches execution.

use std::collections::{BTreeMap, HashMap};
use std::error::Error;

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use exec::{RejectReason, State};
use tx::batch::Batch;
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::{AuthKey, AuthPolicy, AuthPolicyKind, Authorization, KeyStatus};
use validator::{
    Dag, NO_EXPIRY, Pacemaker, PacemakerConfig, ValidatorKey, ValidatorRecord, ValidatorSet, Vertex,
};

const CHAIN_ID: &[u8] = b"karsa-chain-1";
const EPOCH: u64 = 1;
const NOW: u64 = 1_000;
const FEE: u64 = 1;
const GENESIS_BALANCE: u64 = 1_000;

/// One validator's consensus key.
struct Consensus {
    id: Vec<u8>,
    private_key: Vec<u8>,
}

/// One account: its transfer key and the policy that guards it.
struct Account {
    id: Vec<u8>,
    private_key: Vec<u8>,
    key_id: Vec<u8>,
    policy: AuthPolicy,
}

/// A deterministic Ed25519 keypair from a single seed byte.
fn keypair(seed: u8) -> Result<(Vec<u8>, Vec<u8>), crypto::CryptoError> {
    let seed = [seed; 32];
    let public_key = Ed25519Scheme::public_key_from_seed(&seed)?;
    let mut private_key = Vec::with_capacity(64);
    private_key.extend_from_slice(&seed);
    private_key.extend_from_slice(&public_key);
    Ok((public_key.to_vec(), private_key))
}

fn consensus_set(count: usize) -> Result<(ValidatorSet, Vec<Consensus>), crypto::CryptoError> {
    let mut validators = Vec::with_capacity(count);
    let mut keys = Vec::with_capacity(count);
    for index in 0..count {
        let (public_key, private_key) = keypair(u8::try_from(index + 1).unwrap_or(1))?;
        let id = format!("val-{index}").into_bytes();
        validators.push(ValidatorRecord {
            validator_id: id.clone(),
            keys: vec![ValidatorKey {
                key_id: format!("val-{index}-k0").into_bytes(),
                algorithm_id: ALG_ED25519,
                public_key,
                activation_epoch: 0,
                retirement_epoch: NO_EXPIRY,
            }],
        });
        keys.push(Consensus { id, private_key });
    }
    let set = ValidatorSet {
        epoch: EPOCH,
        validators,
    };
    set.validate()?;
    Ok((set, keys))
}

fn accounts(count: usize) -> Result<Vec<Account>, crypto::CryptoError> {
    const NAMES: [&str; 4] = ["alice", "bob", "carol", "dave"];
    let mut accounts = Vec::with_capacity(count);
    for index in 0..count {
        let (public_key, private_key) = keypair(u8::try_from(index + 101).unwrap_or(101))?;
        let name = NAMES.get(index).copied().unwrap_or("account");
        let key_id = format!("{name}-k0").into_bytes();
        let policy = AuthPolicy {
            kind: AuthPolicyKind::Single,
            threshold: 0,
            policy_nonce: 1,
            keys: vec![AuthKey {
                key_id: key_id.clone(),
                algorithm_id: ALG_ED25519,
                public_key,
                weight: 1,
                status: KeyStatus::Active,
                valid_from: 0,
                valid_until: u64::MAX,
            }],
        };
        accounts.push(Account {
            id: name.as_bytes().to_vec(),
            private_key,
            key_id,
            policy,
        });
    }
    Ok(accounts)
}

/// Builds and signs one transaction.
fn signed_transaction(
    account: &Account,
    recipient: &[u8],
    sequence: u64,
    amount: u64,
) -> Result<Transaction, Box<dyn Error>> {
    let mut transaction = Transaction {
        protocol_version: PROTOCOL_VERSION_V1,
        chain_id: CHAIN_ID.to_vec(),
        sender: account.id.clone(),
        sequence,
        fee: FEE,
        expiration: u64::MAX,
        policy_version: 1,
        payload: exec::Transfer::new(recipient.to_vec(), amount).encode()?,
        authorization: Vec::new(),
    };
    let message = transaction.signing_payload()?;
    let signature = Ed25519Scheme.sign(&account.private_key, &message)?;
    transaction.authorization = vec![Authorization {
        algorithm_id: ALG_ED25519,
        key_id: account.key_id.clone(),
        signature,
    }];
    Ok(transaction)
}

/// One data round, summarised.
struct RoundReport {
    round: u64,
    transactions: usize,
    /// Distinct batch digests proposed in this round.
    digests: Vec<[u8; 32]>,
}

/// Everything the command prints, computed fresh each run.
struct Report {
    rounds: Vec<RoundReport>,
    committed_vertices: usize,
    applied: usize,
    rejected: BTreeMap<&'static str, usize>,
    balances: BTreeMap<Vec<u8>, u64>,
    burned: u64,
    root: [u8; 32],
    proof: exec::AccountProof,
}

fn simulate(validators: usize, data_rounds: u64) -> Result<Report, Box<dyn Error>> {
    let (set, consensus) = consensus_set(validators)?;
    let accounts = accounts(validators)?;

    let mut state = State::new();
    for account in &accounts {
        state.credit(&account.id, GENESIS_BALANCE)?;
    }

    let mut dag = Dag::new(set.clone());
    let mut batches: HashMap<[u8; 32], Batch> = HashMap::new();
    let mut rounds = Vec::new();

    // Two empty rounds after the last data round: a leader needs the next round's
    // votes, so the final data round only commits once rounds exist after it.
    let last_round = data_rounds + 2;
    for round in 0..=last_round {
        let references: Vec<validator::VertexId> = if round == 0 {
            Vec::new()
        } else {
            (0..validators)
                .filter_map(|author| {
                    dag.get(round - 1, format!("val-{author}").as_bytes())
                        .and_then(|vertex| vertex.id().ok())
                })
                .collect()
        };

        let mut digests = Vec::new();
        let mut round_transactions = 0usize;
        for (index, validator) in consensus.iter().enumerate() {
            let batch = if round == 0 || round > data_rounds {
                Batch::default()
            } else {
                let account = &accounts[index % accounts.len()];
                let recipient = &accounts[(index + 1) % accounts.len()];
                // Two transactions per sender per round, so a batch is never
                // trivially one transaction.
                let base = (round - 1) * 2;
                let amount = 10 + 5 * u64::try_from(index).unwrap_or(0);
                let mut transactions = Vec::new();
                for offset in 0..2u64 {
                    transactions.push(signed_transaction(
                        account,
                        &recipient.id,
                        base + offset + 1,
                        amount,
                    )?);
                }
                Batch::new(transactions)
            };
            round_transactions += batch.len();
            let digest = batch.digest()?;
            digests.push(digest);
            batches.insert(digest, batch);

            let mut vertex = Vertex {
                chain_id: CHAIN_ID.to_vec(),
                epoch: EPOCH,
                round,
                author: validator.id.clone(),
                payload_hash: digest,
                references: references.clone(),
                signature: Vec::new(),
            };
            let payload = vertex.signing_payload()?;
            vertex.signature = Ed25519Scheme.sign(&validator.private_key, &payload)?;
            dag.insert(vertex)?;
        }

        if round >= 1 && round <= data_rounds {
            rounds.push(RoundReport {
                round,
                transactions: round_transactions,
                digests,
            });
        }
    }

    let mut pacemaker = Pacemaker::new(PacemakerConfig { timeout_ticks: 3 }, 1);
    for _ in 0..8 {
        pacemaker.tick(&mut dag)?;
    }

    // Execute in commit order. The DAG decides the order; this loop only follows it.
    let mut applied = 0usize;
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let order = dag.order().to_vec();
    for id in &order {
        let Some(vertex) = dag.get(id.round, &id.author) else {
            continue;
        };
        let Some(batch) = batches.get(&vertex.payload_hash) else {
            continue;
        };

        // Authorization happens before execution, so an unsigned or mis-signed
        // transaction is dropped instead of reaching the state machine.
        let mut authorized = Vec::with_capacity(batch.len());
        for transaction in &batch.transactions {
            let policy = accounts
                .iter()
                .find(|account| account.id == transaction.sender)
                .map(|account| &account.policy);
            match policy {
                None => {
                    *rejected
                        .entry(RejectReason::UnknownSender.as_str())
                        .or_insert(0) += 1
                }
                Some(policy) if transaction.verify(policy, NOW).is_err() => {
                    *rejected.entry("unauthorized").or_insert(0) += 1;
                }
                Some(_) => authorized.push(transaction.clone()),
            }
        }

        for outcome in state.apply(&Batch::new(authorized)) {
            match outcome.reason() {
                None => applied += 1,
                Some(reason) => *rejected.entry(reason.as_str()).or_insert(0) += 1,
            }
        }
    }

    // Each applied transaction burns its whole fee, so nothing leaves the system
    // silently: genesis total equals circulating balance plus burned fees.
    let burned = u64::try_from(applied).unwrap_or(0) * FEE;

    let root = state.state_root();
    let first_account = state.balances().keys().next().cloned().unwrap_or_default();
    let proof = state
        .proof(&first_account)
        .ok_or("the state has no account to prove")?;

    Ok(Report {
        rounds,
        committed_vertices: order.len(),
        applied,
        rejected,
        balances: state.balances().clone(),
        burned,
        root,
        proof,
    })
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn short(digest: &[u8; 32]) -> String {
    hex::encode(&digest[..6])
}

pub fn run(validators: usize, data_rounds: u64) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("--validators must be at least 4 so that a quorum is not everyone".into());
    }
    if data_rounds == 0 {
        return Err("--rounds must be at least 1".into());
    }

    let first = simulate(validators, data_rounds)?;
    let second = simulate(validators, data_rounds)?;

    println!("== Karsa chain: order, then execute ==");
    println!("  chain:        {}", String::from_utf8_lossy(CHAIN_ID));
    println!("  validators:   {validators}");
    println!(
        "  accounts:     {:?}, genesis balance {GENESIS_BALANCE}",
        first.balances.len()
    );
    println!("  data rounds:  {data_rounds} plus genesis and two empty rounds");
    println!();

    println!("  {}  {}  batch digests", pad("round", 7), pad("txs", 6));
    for round in &first.rounds {
        let digests: Vec<String> = round.digests.iter().map(short).collect();
        println!(
            "  {}  {}  {}",
            pad(&round.round.to_string(), 7),
            pad(&round.transactions.to_string(), 6),
            digests.join(" ")
        );
    }

    println!();
    println!("== Execution, in commit order ==");
    println!("  committed vertices: {}", first.committed_vertices);
    println!("  applied:            {}", first.applied);
    if first.rejected.is_empty() {
        println!("  rejected:           0");
    } else {
        for (reason, count) in &first.rejected {
            println!("  rejected:           {count} ({reason})");
        }
    }

    println!();
    println!("  {}  balance", pad("account", 10));
    for (account, balance) in &first.balances {
        println!(
            "  {}  {}",
            pad(&String::from_utf8_lossy(account), 10),
            balance
        );
    }

    let circulating: u64 = first.balances.values().sum();
    let genesis_total = GENESIS_BALANCE * u64::try_from(first.balances.len()).unwrap_or(0);
    println!();
    println!("  state root:  {}", hex::encode(first.root));
    println!(
        "  conservation: {circulating} in accounts + {} burned = {genesis_total} at genesis: {}",
        first.burned,
        circulating + first.burned == genesis_total
    );
    println!(
        "  deterministic: {} (two runs, same root)",
        first.root == second.root
    );

    println!();
    println!("== State proof: what a light client checks without the state ==");
    let proof = &first.proof;
    println!(
        "  account:  {}  balance {}  sequence {}",
        String::from_utf8_lossy(&proof.account),
        proof.balance,
        proof.sequence
    );
    println!(
        "  path:     {} siblings for {} leaves",
        proof.proof.height(),
        proof.proof.leaf_count
    );
    println!("  verifies: {}", proof.verify(&first.root));

    let mut tampered = proof.clone();
    tampered.balance += 1;
    println!(
        "  same proof with balance + 1: {} (must be false)",
        tampered.verify(&first.root)
    );

    Ok(())
}
