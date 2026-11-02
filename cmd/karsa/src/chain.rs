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
    Certificate, CommitProof, Dag, Header, HeaderChain, NO_EXPIRY, Pacemaker, PacemakerConfig,
    Step, ValidatorKey, ValidatorRecord, ValidatorSet, Vertex, bitmap_of, commit_root,
};

const CHAIN_ID: &[u8] = b"karsa-chain-1";
const EPOCH: u64 = 1;
const NOW: u64 = 1_000;
const FEE: u64 = 1;
const GENESIS_BALANCE: u64 = 1_000;

/// One validator's consensus key.
pub(crate) struct Consensus {
    pub(crate) id: Vec<u8>,
    pub(crate) private_key: Vec<u8>,
}

/// One account: its transfer key and the policy that guards it.
pub(crate) struct Account {
    pub(crate) id: Vec<u8>,
    pub(crate) private_key: Vec<u8>,
    pub(crate) key_id: Vec<u8>,
    pub(crate) policy: AuthPolicy,
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

pub(crate) fn consensus_set(
    count: usize,
) -> Result<(ValidatorSet, Vec<Consensus>), crypto::CryptoError> {
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

pub(crate) fn accounts(count: usize) -> Result<Vec<Account>, crypto::CryptoError> {
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

/// Signs `header` with a quorum of the consensus keys.
pub(crate) fn certify(
    consensus: &[Consensus],
    header: &Header,
) -> Result<Certificate, Box<dyn Error>> {
    let quorum = consensus.len() * 2 / 3 + 1;
    let mut certificate = Certificate {
        chain_id: header.chain_id.clone(),
        epoch: header.epoch,
        round: header.round,
        vertex_id: header.id()?.to_vec(),
        validator_set_id: b"karsa-chain-1/epoch-1".to_vec(),
        signer_bitmap: bitmap_of(consensus.len(), quorum),
        signatures: Vec::new(),
    };
    let payload = certificate.signing_payload()?;
    certificate.signatures = consensus
        .iter()
        .take(quorum)
        .map(|validator| Ed25519Scheme.sign(&validator.private_key, &payload))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(certificate)
}

/// One data round, summarised.
pub(crate) struct RoundReport {
    round: u64,
    transactions: usize,
    /// Distinct batch digests proposed in this round.
    digests: Vec<[u8; 32]>,
}

/// Everything the command prints, computed fresh each run.
pub(crate) struct Report {
    pub(crate) rounds: Vec<RoundReport>,
    pub(crate) committed_vertices: usize,
    pub(crate) applied: usize,
    pub(crate) rejected: BTreeMap<&'static str, usize>,
    pub(crate) balances: BTreeMap<Vec<u8>, u64>,
    pub(crate) burned: u64,
    pub(crate) root: [u8; 32],
    pub(crate) proof: exec::AccountProof,
    pub(crate) headers: Vec<HeaderView>,
    pub(crate) head: Header,
    pub(crate) signed_headers: usize,
    pub(crate) commit_proof: Option<(u64, CommitProof)>,
}

/// One row of the header table.
pub(crate) struct HeaderView {
    height: u64,
    round: u64,
    applied: u64,
    signers: usize,
    state_root: [u8; 32],
    dag_root: [u8; 32],
}

/// Everything one simulated run produced, including the parts `karsa persist`
/// needs to save and replay.
pub(crate) struct Simulation {
    pub(crate) dag: Dag,
    pub(crate) batches: HashMap<[u8; 32], Batch>,
    pub(crate) state: State,
    pub(crate) report: Report,
    /// One certified header per committed round, in height order. This is what an
    /// auditor compares the stored data against.
    pub(crate) certified: Vec<(Header, Certificate)>,
}

pub(crate) fn simulate(validators: usize, data_rounds: u64) -> Result<Simulation, Box<dyn Error>> {
    let (set, consensus) = consensus_set(validators)?;
    let accounts = accounts(validators)?;

    let mut state = genesis_state(&accounts)?;

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

    // Execute in commit order, one header per committed round. The DAG decides the
    // order; these loops only follow it.
    let genesis_header = Header::genesis(
        CHAIN_ID.to_vec(),
        EPOCH,
        state.state_root(),
        commit_root(&[]),
    );
    let mut chain = HeaderChain::new(set.clone(), genesis_header.clone());

    let mut applied = 0usize;
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut headers = vec![HeaderView {
        height: 0,
        round: 0,
        applied: 0,
        signers: 0,
        state_root: genesis_header.state_root,
        dag_root: genesis_header.dag_root,
    }];
    let mut head = genesis_header.clone();
    let mut signed_headers = 0usize;
    let mut certified = Vec::new();
    let mut commit_proof: Option<(u64, CommitProof)> = None;

    let order = dag.order().to_vec();
    let mut cursor = 0usize;
    while cursor < order.len() {
        let round = order[cursor].round;
        let start = cursor;
        while cursor < order.len() && order[cursor].round == round {
            cursor += 1;
        }

        for id in &order[start..cursor] {
            let Some(vertex) = dag.get(id.round, &id.author) else {
                continue;
            };
            let Some(batch) = batches.get(&vertex.payload_hash) else {
                continue;
            };

            applied += apply_batch(&mut state, &accounts, batch, &mut rejected);
        }

        // Round 0 is genesis and is already covered by the genesis header, so it
        // closes no height of its own.
        if round == 0 {
            continue;
        }

        // A quorum signs the state this round produced. From here the root is no
        // longer a local computation: it is what the chain agreed on.
        // The commit prefix as of this height, so a proof taken here stays
        // verifiable against this header and not only against the final one.
        let prefix = &order[..cursor];
        let header = Header {
            chain_id: CHAIN_ID.to_vec(),
            epoch: EPOCH,
            height: head.height + 1,
            round,
            state_root: state.state_root(),
            dag_root: commit_root(prefix),
            previous: head.id()?,
            applied: u64::try_from(applied).unwrap_or(0),
        };
        let certificate = certify(&consensus, &header)?;
        chain.advance(&header, &certificate)?;
        certified.push((header.clone(), certificate.clone()));
        headers.push(HeaderView {
            height: header.height,
            round,
            applied: header.applied,
            signers: certificate.signer_count(),
            state_root: header.state_root,
            dag_root: header.dag_root,
        });
        if commit_proof.is_none()
            && let Some(proof) = CommitProof::prove(prefix, start)
        {
            if !proof.verify(&header.dag_root) {
                return Err("commit proof did not verify against its own header".into());
            }
            commit_proof = Some((header.height, proof));
        }
        signed_headers += 1;
        head = header;
    }

    // Each applied transaction burns its whole fee, so nothing leaves the system
    // silently: genesis total equals circulating balance plus burned fees.
    let burned = u64::try_from(applied).unwrap_or(0) * FEE;

    let root = state.state_root();
    let first_account = state.balances().keys().next().cloned().unwrap_or_default();
    let proof = state
        .proof(&first_account)
        .ok_or("the state has no account to prove")?;

    let report = Report {
        rounds,
        committed_vertices: order.len(),
        applied,
        rejected,
        balances: state.balances().clone(),
        burned,
        root,
        proof,
        headers,
        head,
        signed_headers,
        commit_proof,
    };
    Ok(Simulation {
        dag,
        batches,
        state,
        report,
        certified,
    })
}

/// Replays the pacemaker until it stops making progress.
///
/// Shared by `persist` and `audit` so that a replay and an audit cannot disagree
/// about when the commit cursor is done moving.
pub(crate) fn settle(dag: &mut Dag, start_round: u64) -> Result<usize, Box<dyn Error>> {
    let mut pacemaker = Pacemaker::new(PacemakerConfig { timeout_ticks: 3 }, start_round);
    let mut quiet = 0usize;
    let mut ticks = 0usize;
    while quiet < 2 && ticks < 256 {
        match pacemaker.tick(dag)? {
            Step::Advanced { .. } => quiet = 0,
            Step::Waiting { .. } | Step::TimedOut { .. } => quiet += 1,
        }
        ticks += 1;
    }
    Ok(dag.order().len())
}

/// The account state before any transaction: every account at its genesis balance.
pub(crate) fn genesis_state(accounts: &[Account]) -> Result<State, exec::ExecError> {
    let mut state = State::new();
    for account in accounts {
        state.credit(&account.id, GENESIS_BALANCE)?;
    }
    Ok(state)
}

/// Authorizes one transaction, then applies the authorized ones to `state`.
///
/// Shared by the simulator and the replay path: authorization is part of
/// execution, and two copies of this logic would be two chances to disagree.
pub(crate) fn apply_batch(
    state: &mut State,
    accounts: &[Account],
    batch: &Batch,
    rejected: &mut BTreeMap<&'static str, usize>,
) -> usize {
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

    let mut applied = 0usize;
    for outcome in state.apply(&Batch::new(authorized)) {
        match outcome.reason() {
            None => applied += 1,
            Some(reason) => *rejected.entry(reason.as_str()).or_insert(0) += 1,
        }
    }
    applied
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
    let second = simulate(validators, data_rounds)?.report;
    let first = first.report;

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
    println!("== Finality: one certified header per committed round ==");
    println!(
        "  {}  {}  {}  {}  {}  dag root",
        pad("height", 7),
        pad("round", 6),
        pad("applied", 8),
        pad("signers", 8),
        pad("state root", 13)
    );
    for header in &first.headers {
        let signers = if header.height == 0 {
            "-".to_string()
        } else {
            format!("{} of {}", header.signers, validators)
        };
        println!(
            "  {}  {}  {}  {}  {}  {}",
            pad(&header.height.to_string(), 7),
            pad(&header.round.to_string(), 6),
            pad(&header.applied.to_string(), 8),
            pad(&signers, 8),
            pad(&short(&header.state_root), 13),
            short(&header.dag_root)
        );
    }
    println!(
        "  light client: {} headers verified, head at height {}",
        first.signed_headers, first.head.height
    );

    if let Some((height, proof)) = &first.commit_proof {
        println!();
        println!("== Commit proof: a vertex inside the certified DAG root ==");
        println!(
            "  vertex:   {}@{}",
            String::from_utf8_lossy(&proof.vertex.author),
            proof.vertex.round
        );
        println!(
            "  against:  header at height {height} ({} siblings for {} commits)",
            proof.proof.height(),
            proof.proof.leaf_count
        );
        let header_root = first
            .headers
            .iter()
            .find(|header| header.height == *height)
            .map(|header| header.dag_root)
            .unwrap_or_default();
        println!("  verifies: {}", proof.verify(&header_root));
        println!(
            "  same proof against the head's dag root: {} (must be false)",
            proof.verify(&first.head.dag_root)
        );
    }

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
