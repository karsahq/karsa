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
use std::time::{Duration, Instant};

use crypto::encoding::MAX_FIELD_LEN;
use crypto::registry::ALG_ED25519;
use crypto::scheme::{Ed25519BatchEntry, Ed25519Scheme, verify_ed25519_batch};
use exec::{RejectReason, State};
use sha2::{Digest, Sha256};
use tx::address;
use tx::batch::Batch;

use crate::genesis::{Genesis, GenesisAccount, GenesisValidator};
use crate::home::Home;
use crate::keys::{Keys, decode_ed25519};
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::{AuthKey, AuthPolicy, AuthPolicyKind, Authorization, KeyStatus};
use validator::{
    Certificate, CommitProof, Dag, Header, HeaderChain, NO_EXPIRY, Pacemaker, PacemakerConfig,
    Step, ValidatorKey, ValidatorRecord, ValidatorSet, Vertex, bitmap_of, commit_root,
    validator_address,
};

const EPOCH: u64 = 1;
const NOW: u64 = 1_000;
const FEE: u64 = 1;
pub(crate) const GENESIS_BALANCE: u64 = 1_000;

/// One validator's consensus key.
#[derive(Clone)]
pub(crate) struct Consensus {
    pub(crate) id: Vec<u8>,
    pub(crate) private_key: Vec<u8>,
}

/// One account: its address, transfer key, and the policy that guards it.
///
/// There is no separate id. The address the policy derives (D32) is both the
/// identity and the state key, so there is nothing that can disagree with it. Two
/// accounts with the same policy therefore have the same address, and are one
/// account.
#[derive(Clone)]
pub(crate) struct Account {
    pub(crate) address: [u8; 32],
    pub(crate) private_key: Vec<u8>,
    pub(crate) key_id: Vec<u8>,
    pub(crate) policy: AuthPolicy,
    /// Opening balance. A genesis account states this; the demo uses a constant.
    pub(crate) balance: u64,
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
        let schedule = vec![ValidatorKey {
            key_id: format!("val-{index}-k0").into_bytes(),
            algorithm_id: ALG_ED25519,
            public_key,
            activation_epoch: 0,
            retirement_epoch: NO_EXPIRY,
        }];
        // The identity is the genesis schedule, not a label. `key_id` above is
        // metadata and is excluded from the address.
        let address = validator_address(&schedule)?;
        validators.push(ValidatorRecord {
            validator_id: address.to_vec(),
            keys: schedule,
        });
        keys.push(Consensus {
            id: address.to_vec(),
            private_key,
        });
    }
    let set = ValidatorSet {
        epoch: EPOCH,
        validators,
    };
    set.validate()?;
    Ok((set, keys))
}

/// Appends one deterministic validator identity for a checked set change.
///
/// The new validator is passive in the prototype: its public key lets the new
/// set verify a quorum, and its private key is not needed unless it later runs.
/// The address is derived from the key schedule, exactly like every other
/// validator identity, so every node computes the same record.
pub(crate) fn append_validator(
    set: &ValidatorSet,
    epoch: u64,
) -> Result<ValidatorSet, Box<dyn Error>> {
    let index = set.validators.len();
    let seed = u8::try_from(index + 1).map_err(|_| "a set change cannot index beyond 255")?;
    let (public_key, _) = keypair(seed)?;
    let keys = vec![ValidatorKey {
        key_id: format!("val-{index}-k0").into_bytes(),
        algorithm_id: ALG_ED25519,
        public_key,
        activation_epoch: 0,
        retirement_epoch: NO_EXPIRY,
    }];
    let address = validator_address(&keys)?;
    let mut next = set.clone();
    next.validators.push(ValidatorRecord {
        validator_id: address.to_vec(),
        keys,
    });
    next.epoch = epoch;
    next.validate()?;
    Ok(next)
}

/// Removes the last validator identity for a checked set change.
pub(crate) fn remove_last_validator(
    set: &ValidatorSet,
    epoch: u64,
) -> Result<ValidatorSet, Box<dyn Error>> {
    if set.validators.len() <= 1 {
        return Err("a set change cannot remove the last validator".into());
    }
    let mut next = set.clone();
    next.validators.pop();
    next.epoch = epoch;
    next.validate()?;
    Ok(next)
}

pub(crate) fn accounts(count: usize) -> Result<Vec<Account>, crypto::CryptoError> {
    let mut accounts = Vec::with_capacity(count);
    for index in 0..count {
        let (public_key, private_key) = keypair(u8::try_from(index + 101).unwrap_or(101))?;
        // The label is cosmetic and excluded from the address; keep it derived
        // from the index so the fixture does not imply an identity that is not one.
        let key_id = format!("acct-{index}-k0").into_bytes();
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
        let address = policy.address()?;
        accounts.push(Account {
            address,
            private_key,
            key_id,
            policy,
            balance: GENESIS_BALANCE,
        });
    }
    Ok(accounts)
}

/// Builds and signs one transaction.
fn signed_transaction(
    chain_id: &[u8],
    account: &Account,
    recipient: &[u8],
    sequence: u64,
    amount: u64,
) -> Result<Transaction, Box<dyn Error>> {
    let mut transaction = Transaction {
        protocol_version: PROTOCOL_VERSION_V1,
        chain_id: chain_id.to_vec(),
        sender: account.address.to_vec(),
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

/// A deterministic batch of transfers, for a transport that needs real payload.
///
/// Sequences are derived from the round so two rounds never reuse one. Nothing
/// here is executed: this exists so a vertex can name a batch that actually
/// exists and travels on the wire, which is what makes the measured bytes per
/// transaction a measurement rather than a model.
///
/// `chain_id` is the chain the transactions authorize against, not the identity
/// of the run's fixture: a node on another genesis would reject them.
pub(crate) fn demo_batch(
    chain_id: &[u8],
    accounts: &[Account],
    author: usize,
    round: u64,
    count: u64,
) -> Result<Batch, Box<dyn Error>> {
    if accounts.len() < 2 {
        return Err("a batch needs at least two accounts".into());
    }
    let sender = &accounts[author % accounts.len()];
    let recipient = &accounts[(author + 1) % accounts.len()];
    let capacity = usize::try_from(count).unwrap_or(0);
    let mut transactions = Vec::with_capacity(capacity);
    for offset in 0..count {
        let sequence = round.saturating_mul(count).saturating_add(offset) + 1;
        transactions.push(signed_transaction(
            chain_id,
            sender,
            &recipient.address,
            sequence,
            1,
        )?);
    }
    Ok(Batch::new(transactions))
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
    /// Sum of the opening balances, so conservation is checked against the state
    /// the chain actually started from rather than a compiled constant.
    pub(crate) genesis_total: u64,
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
    epoch: u64,
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

/// The chain id a run binds its signatures to.
///
/// With a genesis beside the node, this is that genesis's hash: 32 bytes that no
/// other chain shares by accident, which is what makes a signature unusable
/// anywhere else. Without one it is a fixed demo value of the same shape, so the
/// code paths do not differ in the thing that matters.
///
/// # Errors
///
/// Propagates a genesis that cannot be read, hashed, or parsed.
pub(crate) fn chain_id(home: Option<&crate::home::Home>) -> Result<Vec<u8>, Box<dyn Error>> {
    if let Some(path) = home.map(crate::home::Home::genesis_json)
        && path.exists()
    {
        return Ok(crate::genesis::Genesis::load(&path)?.hash()?.to_vec());
    }
    Ok(Sha256::digest(b"KARSA/GENESIS/v1/demo").to_vec())
}

/// The chain id when no genesis is supplied.
#[must_use]
pub(crate) fn demo_chain_id() -> Vec<u8> {
    Sha256::digest(b"KARSA/GENESIS/v1/demo").to_vec()
}

/// The committee and accounts one run acts for.
///
/// Without a home this is the deterministic demo. With one it is the genesis and
/// the keys beside it, which is what makes `--home` an actual chain membership
/// rather than a different chain id over the same fixtures.
#[derive(Clone)]
pub(crate) struct Membership {
    pub(crate) set: ValidatorSet,
    pub(crate) consensus: Vec<Consensus>,
    pub(crate) accounts: Vec<Account>,
    pub(crate) epoch_rounds: u64,
}

/// Builds the membership for `validators`, from a home when one is given.
///
/// A home without `genesis.json` gets the four-validator devnet, and a matching
/// `keys.json`, exactly as a first `karsa node` writes `node.toml`. Missing files
/// are generated once; existing ones are validated, never repaired.
///
/// # Errors
///
/// A genesis or keystore that does not parse, fails validation, disagrees with the
/// other, or does not have the requested validator count.
pub(crate) fn membership(
    validators: usize,
    home: Option<&Home>,
) -> Result<Membership, Box<dyn Error>> {
    let Some(home) = home else {
        let (set, consensus) = consensus_set(validators)?;
        return Ok(Membership {
            set,
            consensus,
            accounts: accounts(validators)?,
            epoch_rounds: crate::genesis::DEMO_EPOCH_ROUNDS,
        });
    };
    let genesis = Genesis::ensure(&home.genesis_json())?;
    let keys = Keys::ensure(&home.keys_json())?;
    membership_from(&genesis, &keys, validators)
}

fn membership_from(
    genesis: &Genesis,
    keys: &Keys,
    validators: usize,
) -> Result<Membership, Box<dyn Error>> {
    let problems = genesis.problems();
    if !problems.is_empty() {
        return Err(format!("genesis has problems: {}", problems.join("; ")).into());
    }
    let key_problems = keys.problems(genesis);
    if !key_problems.is_empty() {
        return Err(format!("keys.json has problems: {}", key_problems.join("; ")).into());
    }
    if genesis.validators.len() != validators {
        return Err(format!(
            "genesis has {} validators, --validators is {validators}",
            genesis.validators.len()
        )
        .into());
    }

    // The genesis hash sorts by address, so the runtime must too. A file written
    // with its entries in another order would otherwise elect a different leader
    // while hashing to the same chain id.
    let mut ordered: Vec<&GenesisValidator> = genesis.validators.iter().collect();
    ordered.sort_by_key(|validator| address::decode(&validator.address).unwrap_or([0u8; 32]));
    let mut records = Vec::with_capacity(ordered.len());
    let mut consensus = Vec::with_capacity(ordered.len());
    for validator in &ordered {
        let address = address::decode(&validator.address)?;
        let entry = keys
            .validator_key(&validator.address)
            .ok_or_else(|| format!("no private key for validator {}", validator.address))?;
        let private_key = decode_ed25519(&entry.private_key)
            .map_err(|error| format!("key {}: {error}", entry.key_id))?;
        records.push(ValidatorRecord {
            validator_id: address.to_vec(),
            keys: validator.runtime_keys()?,
        });
        consensus.push(Consensus {
            id: address.to_vec(),
            private_key,
        });
    }
    let set = ValidatorSet {
        epoch: EPOCH,
        validators: records,
    };
    set.validate()?;

    let mut ordered: Vec<&GenesisAccount> = genesis.accounts.iter().collect();
    ordered.sort_by_key(|account| address::decode(&account.address).unwrap_or([0u8; 32]));
    let mut runtime = Vec::with_capacity(ordered.len());
    for account in ordered {
        let address = address::decode(&account.address)?;
        let policy = account.runtime_policy()?;
        let entry = keys
            .account_key(&account.address)
            .ok_or_else(|| format!("no private key for account {}", account.address))?;
        let private_key = decode_ed25519(&entry.private_key)
            .map_err(|error| format!("key {}: {error}", entry.key_id))?;
        let key_id = entry.key_id.as_bytes().to_vec();
        if !policy.keys.iter().any(|key| key.key_id == key_id) {
            return Err(format!(
                "account {} policy has no key {}",
                account.address, entry.key_id
            )
            .into());
        }
        runtime.push(Account {
            address,
            private_key,
            key_id,
            policy,
            balance: account.balance,
        });
    }

    Ok(Membership {
        set,
        consensus,
        accounts: runtime,
        epoch_rounds: genesis.epoch_rounds,
    })
}

/// The demo membership, kept for tests and the commands that predate `--home`.
#[cfg(test)]
pub(crate) fn simulate(
    chain_id: &[u8],
    validators: usize,
    data_rounds: u64,
) -> Result<Simulation, Box<dyn Error>> {
    let membership = membership(validators, None)?;
    simulate_with(chain_id, &membership, data_rounds)
}

pub(crate) fn simulate_with(
    chain_id: &[u8],
    membership: &Membership,
    data_rounds: u64,
) -> Result<Simulation, Box<dyn Error>> {
    let set = membership.set.clone();
    let consensus = membership.consensus.as_slice();
    let accounts = membership.accounts.as_slice();

    let mut state = genesis_state(accounts)?;

    let mut dag = Dag::with_epoch_length(set.clone(), membership.epoch_rounds);
    let mut batches: HashMap<[u8; 32], Batch> = HashMap::new();
    let mut rounds = Vec::new();

    // Two empty rounds after the last data round: a leader needs the next round's
    // votes, so the final data round only commits once rounds exist after it.
    let last_round = data_rounds + 2;
    for round in 0..=last_round {
        let references: Vec<validator::VertexId> = if round == 0 {
            Vec::new()
        } else {
            (0..consensus.len())
                .filter_map(|author| {
                    dag.get(round - 1, &consensus[author].id)
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
                        chain_id,
                        account,
                        &recipient.address,
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
                chain_id: chain_id.to_vec(),
                epoch: dag.epoch_of(round),
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
        chain_id.to_vec(),
        dag.epoch_of(0),
        state.state_root(),
        commit_root(&[]),
    );
    let mut chain =
        HeaderChain::with_schedule(set.clone(), genesis_header.clone(), dag.epoch_schedule());

    let mut applied = 0usize;
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut headers = vec![HeaderView {
        height: 0,
        epoch: genesis_header.epoch,
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

            applied += apply_batch(&mut state, accounts, batch, &mut rejected);
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
            chain_id: chain_id.to_vec(),
            epoch: dag.epoch_of(round),
            height: head.height + 1,
            round,
            state_root: state.state_root(),
            dag_root: commit_root(prefix),
            previous: head.id()?,
            applied: u64::try_from(applied).unwrap_or(0),
        };
        let certificate = certify(consensus, &header)?;
        chain.advance(&header, &certificate)?;
        certified.push((header.clone(), certificate.clone()));
        headers.push(HeaderView {
            height: header.height,
            epoch: header.epoch,
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

    let genesis_total = accounts.iter().map(|account| account.balance).sum();
    let report = Report {
        rounds,
        committed_vertices: order.len(),
        applied,
        rejected,
        balances: state.balances().clone(),
        burned,
        genesis_total,
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
        state.credit(&account.address, account.balance)?;
    }
    Ok(state)
}

/// Time spent in the two halves of [`apply_batch`], for the live profile.
#[derive(Default, Clone, Copy)]
pub(crate) struct ApplyTiming {
    /// Policy lookup and signature verification.
    pub verify: Duration,
    /// State transitions after authorization.
    pub state: Duration,
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
    apply_batch_timed(
        state,
        accounts,
        batch,
        rejected,
        &mut ApplyTiming::default(),
        1,
    )
}

/// One transaction whose signature can join a batch verification.
struct BatchCandidate<'a> {
    index: usize,
    policy: &'a AuthPolicy,
    public_key: &'a [u8],
    message: Vec<u8>,
    signature: &'a [u8],
}

/// Returns the batch-verifiable form of `transaction`, when the account policy is
/// the common single-authorization Ed25519 shape and every cheap check already
/// passes.
///
/// Anything else returns `None` and takes the canonical per-transaction path, so
/// the fast path can only accept a transaction that path would also accept.
fn batch_candidate<'a>(
    index: usize,
    transaction: &'a Transaction,
    policy: &'a AuthPolicy,
) -> Option<BatchCandidate<'a>> {
    if policy.kind != AuthPolicyKind::Single || transaction.authorization.len() != 1 {
        return None;
    }
    let authorization = &transaction.authorization[0];
    if authorization.algorithm_id != ALG_ED25519 {
        return None;
    }
    let key = policy.keys.iter().find(|key| {
        key.key_id.as_slice() == authorization.key_id.as_slice()
            && key.algorithm_id == ALG_ED25519
            && key.is_usable(NOW)
    })?;
    let message = transaction.signing_payload().ok()?;
    // The canonical path refuses a message above the encoding limit before it
    // reaches the signature; the batch entry must not accept one it would reject.
    if message.len() > MAX_FIELD_LEN {
        return None;
    }
    Some(BatchCandidate {
        index,
        policy,
        public_key: &key.public_key,
        message,
        signature: &authorization.signature,
    })
}

/// What happened to one transaction in a batch, in batch order.
///
/// This is the per-transaction form of the aggregate [`RejectReason`] counters:
/// it exists so a client can be told whether the transaction it submitted was
/// applied or why it was refused, without changing the counts the simulator and
/// the live report already use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TxResult {
    /// The transaction changed state.
    Applied,
    /// The transaction was refused; the reason is the same string the aggregate
    /// counters use.
    Rejected(&'static str),
}

/// One chunk of authorization work, in input order.
struct AuthorizedChunk<'a> {
    /// Transactions that passed authorization, with their index in the batch.
    authorized: Vec<(usize, &'a Transaction)>,
    /// Rejection reasons and counts, for the aggregate map.
    rejected: Vec<(&'static str, usize)>,
    /// Per chunk index: `Some(reason)` when refused by authorization.
    reasons: Vec<Option<&'static str>>,
}

fn authorize_chunk<'a>(
    transactions: &'a [Transaction],
    accounts: &'a [Account],
) -> AuthorizedChunk<'a> {
    let mut accepted = vec![false; transactions.len()];
    let mut reasons: Vec<Option<&'static str>> = vec![None; transactions.len()];
    let mut rejected: Vec<(&'static str, usize)> = Vec::new();
    let mut candidates: Vec<BatchCandidate<'a>> = Vec::new();

    for (index, transaction) in transactions.iter().enumerate() {
        let policy = accounts
            .iter()
            .find(|account| account.address.as_slice() == transaction.sender.as_slice())
            .map(|account| &account.policy);
        match policy {
            None => {
                let reason = RejectReason::UnknownSender.as_str();
                reasons[index] = Some(reason);
                rejected.push((reason, 1));
            }
            Some(policy) => match batch_candidate(index, transaction, policy) {
                Some(candidate) => candidates.push(candidate),
                None => {
                    if transaction.verify(policy, NOW).is_ok() {
                        accepted[index] = true;
                    } else {
                        reasons[index] = Some("unauthorized");
                        rejected.push(("unauthorized", 1));
                    }
                }
            },
        }
    }

    if !candidates.is_empty() {
        let entries: Vec<Ed25519BatchEntry<'_>> = candidates
            .iter()
            .map(|candidate| Ed25519BatchEntry {
                public_key: candidate.public_key,
                message: &candidate.message,
                signature: candidate.signature,
            })
            .collect();
        if verify_ed25519_batch(&entries).is_ok() {
            for candidate in &candidates {
                accepted[candidate.index] = true;
            }
        } else {
            // The batch equation cannot attribute a failure, so re-check the
            // candidates one by one to keep the rejection count and reason exact.
            for candidate in &candidates {
                if transactions[candidate.index]
                    .verify(candidate.policy, NOW)
                    .is_ok()
                {
                    accepted[candidate.index] = true;
                } else {
                    reasons[candidate.index] = Some("unauthorized");
                    rejected.push(("unauthorized", 1));
                }
            }
        }
    }

    let mut authorized = Vec::with_capacity(transactions.len());
    for (index, transaction) in transactions.iter().enumerate() {
        if accepted[index] {
            authorized.push((index, transaction));
        }
    }
    AuthorizedChunk {
        authorized,
        rejected,
        reasons,
    }
}

/// [`apply_batch`], reporting how long authorization and state application took.
pub(crate) fn apply_batch_timed(
    state: &mut State,
    accounts: &[Account],
    batch: &Batch,
    rejected: &mut BTreeMap<&'static str, usize>,
    timing: &mut ApplyTiming,
    threads: usize,
) -> usize {
    apply_batch_timed_report(state, accounts, batch, rejected, timing, threads, None)
}

/// [`apply_batch_timed`], optionally recording one result per transaction.
///
/// The per-transaction report is filled in batch order. Without a report the
/// function does the same work and returns the same count, so the measured live
/// path is unchanged.
pub(crate) fn apply_batch_timed_report(
    state: &mut State,
    accounts: &[Account],
    batch: &Batch,
    rejected: &mut BTreeMap<&'static str, usize>,
    timing: &mut ApplyTiming,
    threads: usize,
    mut report: Option<&mut Vec<TxResult>>,
) -> usize {
    let verify_start = Instant::now();
    let mut authorized: Vec<(usize, &Transaction)> = Vec::with_capacity(batch.len());
    let mut reasons: Vec<Option<&'static str>> = vec![None; batch.len()];
    let mut chunk_rejected: Vec<(&'static str, usize)> = Vec::new();
    if threads <= 1 || batch.len() < 64 {
        let chunk = authorize_chunk(&batch.transactions, accounts);
        authorized = chunk.authorized;
        chunk_rejected = chunk.rejected;
        reasons = chunk.reasons;
    } else {
        let chunk_size = batch.len().div_ceil(threads).max(1);
        let chunks = std::thread::scope(|scope| {
            let handles: Vec<_> = batch
                .transactions
                .chunks(chunk_size)
                .enumerate()
                .map(|(chunk_index, slice)| {
                    let offset = chunk_index * chunk_size;
                    scope.spawn(move || (offset, authorize_chunk(slice, accounts)))
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("a verification thread panicked"))
                .collect::<Vec<_>>()
        });
        for (offset, mut chunk) in chunks {
            // `authorize_chunk` numbers its result from zero; adding the chunk
            // offset is what keeps the execution order global rather than four
            // independent 0-based streams.
            for (index, _) in &mut chunk.authorized {
                *index += offset;
            }
            for (local, reason) in chunk.reasons.iter().enumerate() {
                reasons[offset + local] = *reason;
            }
            authorized.extend(chunk.authorized);
            chunk_rejected.extend(chunk.rejected);
        }
        // Chunks arrive in order, but sorting by the original index keeps the
        // execution order correct even if that ever changes.
        authorized.sort_by_key(|(index, _)| *index);
    }
    for (reason, count) in chunk_rejected {
        *rejected.entry(reason).or_insert(0) += count;
    }
    timing.verify += verify_start.elapsed();

    let state_start = Instant::now();
    let refs: Vec<&Transaction> = authorized
        .iter()
        .map(|(_, transaction)| *transaction)
        .collect();
    let outcomes = state.apply_refs(&refs);
    let mut applied = 0usize;
    let mut results: Vec<Option<TxResult>> = reasons
        .into_iter()
        .map(|reason| reason.map(TxResult::Rejected))
        .collect();
    for ((index, _), outcome) in authorized.iter().zip(outcomes) {
        match outcome.reason() {
            None => {
                applied += 1;
                results[*index] = Some(TxResult::Applied);
            }
            Some(reason) => {
                *rejected.entry(reason.as_str()).or_insert(0) += 1;
                results[*index] = Some(TxResult::Rejected(reason.as_str()));
            }
        }
    }
    timing.state += state_start.elapsed();

    if let Some(report) = report.as_mut() {
        report.extend(
            results
                .into_iter()
                .map(|result| result.unwrap_or(TxResult::Rejected("unauthorized"))),
        );
    }
    applied
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn short(digest: &[u8; 32]) -> String {
    hex::encode(&digest[..6])
}

pub fn run(
    validators: usize,
    data_rounds: u64,
    home: Option<&crate::home::Home>,
) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("--validators must be at least 4 so that a quorum is not everyone".into());
    }
    if data_rounds == 0 {
        return Err("--rounds must be at least 1".into());
    }

    // Build the membership first: with a home it writes the devnet genesis and
    // keys when they are missing, and the chain id is that genesis's hash.
    let committee = membership(validators, home)?;
    let chain_id = chain_id(home)?;
    let first = simulate_with(&chain_id, &committee, data_rounds)?;
    let second = simulate_with(&chain_id, &committee, data_rounds)?.report;
    let first = first.report;

    println!("== Karsa chain: order, then execute ==");
    println!(
        "  chain id:     {} ({} bytes)",
        hex::encode(&chain_id[..8]),
        chain_id.len()
    );
    println!("  validators:   {validators}");
    println!(
        "  accounts:     {} holding {} at genesis",
        first.balances.len(),
        first.genesis_total
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
    println!("  {}  balance", pad("address", 51));
    for (key, balance) in &first.balances {
        // The full address, not a prefix: this is the value a person copies into
        // an explorer, and truncating it would make the table pretty and useless.
        let text = <[u8; 32]>::try_from(key.as_slice())
            .map_or_else(|_| hex::encode(key), |bytes| address::encode(&bytes));
        println!("  {text}  {balance}");
    }

    let circulating: u64 = first.balances.values().sum();
    let genesis_total = first.genesis_total;
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
        "  {}  {}  {}  {}  {}  {}  dag root",
        pad("height", 7),
        pad("epoch", 6),
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
            "  {}  {}  {}  {}  {}  {}  {}",
            pad(&header.height.to_string(), 7),
            pad(&header.epoch.to_string(), 6),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn certified_headers_cross_an_epoch_boundary() {
        let (set, consensus) = consensus_set(4).unwrap();
        let committee = Membership {
            set,
            consensus,
            accounts: accounts(4).unwrap(),
            epoch_rounds: 2,
        };

        let simulation = simulate_with(&demo_chain_id(), &committee, 4).unwrap();
        let epochs: Vec<u64> = simulation
            .certified
            .iter()
            .map(|(header, _)| header.epoch)
            .collect();

        assert!(
            epochs.windows(2).any(|pair| pair[1] > pair[0]),
            "expected a certified header in a later epoch, got {epochs:?}"
        );
        assert!(!simulation.report.headers.is_empty());
    }

    #[test]
    fn parallel_authorization_matches_the_serial_path() {
        let accounts = accounts(4).unwrap();
        let batch = demo_batch(&demo_chain_id(), &accounts, 0, 0, 100).unwrap();

        let mut serial_state = genesis_state(&accounts).unwrap();
        let mut serial_rejected = BTreeMap::new();
        let serial = apply_batch(&mut serial_state, &accounts, &batch, &mut serial_rejected);

        let mut parallel_state = genesis_state(&accounts).unwrap();
        let mut parallel_rejected = BTreeMap::new();
        let parallel = apply_batch_timed(
            &mut parallel_state,
            &accounts,
            &batch,
            &mut parallel_rejected,
            &mut ApplyTiming::default(),
            4,
        );

        assert_eq!(serial, parallel);
        assert_eq!(serial_rejected, parallel_rejected);
        assert_eq!(serial_state.state_root(), parallel_state.state_root());
    }

    #[test]
    fn batch_authorization_matches_the_single_transaction_path() {
        let accounts = accounts(4).unwrap();
        let mut batch = demo_batch(&demo_chain_id(), &accounts, 0, 0, 100).unwrap();
        let tampered = batch.len() / 2;
        batch.transactions[tampered].authorization[0].signature[0] ^= 0x01;

        let expected: Vec<&Transaction> = batch
            .transactions
            .iter()
            .filter(|transaction| {
                let Some(policy) = accounts
                    .iter()
                    .find(|account| account.address.as_slice() == transaction.sender.as_slice())
                    .map(|account| &account.policy)
                else {
                    return false;
                };
                transaction.verify(policy, NOW).is_ok()
            })
            .collect();
        let chunk = authorize_chunk(&batch.transactions, &accounts);
        let actual: Vec<&Transaction> = chunk
            .authorized
            .iter()
            .map(|(_, transaction)| *transaction)
            .collect();

        assert_eq!(actual, expected);
        assert_eq!(
            chunk
                .rejected
                .iter()
                .map(|(_, count)| *count)
                .sum::<usize>(),
            batch.len() - expected.len()
        );
    }
}
