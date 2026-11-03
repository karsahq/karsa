//! The chain's genesis: the one file every node must agree on.
//!
//! Genesis is not a preference, so it is not shaped like `node.toml`. It is a
//! consensus artifact: two nodes that disagree about it are on different chains.
//! That drives three choices.
//!
//! 1. **JSON, not TOML.** Genesis is generated once, written by tooling, read by
//!    every implementation, and queried with `jq` far more often than it is
//!    hand-edited. Comments lose their value; interoperability does not. Every
//!    chain an operator has met already ships `genesis.json`.
//! 2. **The hash is over the canonical encoding, not the file.** Reformatting,
//!    reordering keys, or adding whitespace must not change the identity of the
//!    chain. The file is input; the encoding is the object.
//! 3. **Nothing is inferred.** Unknown fields are errors, algorithms are named,
//!    and a public key that is the wrong length for its algorithm is a problem
//!    found before the node starts rather than at the first signature.
//!
//! The domain tag `KARSA/GENESIS/v1` is part of the encoding, so a genesis hash can
//! never collide with a transaction, header, or vertex hash that happens to encode
//! the same fields.

use std::collections::HashSet;
use std::error::Error;
use std::path::Path;

use crypto::encoding::Encoder;
use crypto::registry::{ALG_ED25519, ALG_ML_DSA_65, ALG_SLH_DSA_SHA2_128S};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tx::policy::{AuthKey, AuthPolicy, AuthPolicyKind, KeyStatus, NO_EXPIRY as POLICY_NO_EXPIRY};

/// The only protocol version this tree implements.
const PROTOCOL_VERSION: u16 = 1;

/// Domain tag mixed into the genesis hash.
const DOMAIN: &[u8] = b"KARSA/GENESIS/v1";

/// The example written by `karsa genesis --init`.
const EXAMPLE: &str = r#"{
  "chain_id": "karsa",
  "protocol_version": 1,
  "epoch_rounds": 1000,
  "validators": [
    {
      "id": "val-0",
      "keys": [
        {
          "key_id": "val-0-k0",
          "algorithm": "ed25519",
          "public_key": "0101010101010101010101010101010101010101010101010101010101010101",
          "activation_epoch": 0
        }
      ]
    }
  ],
  "accounts": [
    {
      "address": "K4aFUZMDDimgetMW8Vm3QsKAKCZ8jLGGziZ7bndkskcAYmLuVPx",
      "balance": 1000,
      "policy": {
        "kind": "single",
        "threshold": 0,
        "keys": [
          {
            "key_id": "alice-k0",
            "algorithm": "ed25519",
            "public_key": "0202020202020202020202020202020202020202020202020202020202020202"
          }
        ]
      }
    }
  ]
}
"#;

/// The whole file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Genesis {
    /// Chain identifier, the same string the node configuration carries.
    pub chain_id: String,
    /// Wire format this genesis is valid for.
    pub protocol_version: u16,
    /// Commits between key epochs.
    pub epoch_rounds: u64,
    /// The initial committee.
    pub validators: Vec<GenesisValidator>,
    /// The initial account state.
    pub accounts: Vec<GenesisAccount>,
}

/// One founding validator and its keys.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisValidator {
    /// Validator id, unique in the committee.
    pub id: String,
    /// Keys, at least one active at epoch 0.
    pub keys: Vec<GenesisKey>,
}

/// One consensus key.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisKey {
    /// Key id, unique within the validator.
    pub key_id: String,
    /// `ed25519`, `ml-dsa-65`, or `slh-dsa-sha2-128s`.
    pub algorithm: String,
    /// Hex-encoded public key, length fixed by the algorithm.
    pub public_key: String,
    /// First epoch this key is active.
    pub activation_epoch: u64,
}

/// One founding account.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisAccount {
    /// Base58Check address (`K...`) of the 32 bytes the policy derives.
    ///
    /// Written out rather than left implicit so an operator can copy it into an
    /// explorer. It is checked against the policy, not trusted: a value that does
    /// not match is refused, because a genesis where the address and the keys
    /// disagree would make every reader pick one of them. The text encoding is
    /// display only; the identity is still the 32 bytes it decodes to.
    pub address: String,
    /// Starting balance, in the chain's smallest unit.
    pub balance: u64,
    /// What authorizes a transaction from this account.
    pub policy: GenesisPolicy,
}

impl GenesisAccount {
    /// The policy in the runtime form execution uses.
    ///
    /// # Errors
    ///
    /// An unknown policy kind, a threshold that does not fit the runtime's width,
    /// an unknown algorithm, or a public key that is not hex.
    pub fn runtime_policy(&self) -> Result<AuthPolicy, Box<dyn Error>> {
        let kind = match self.policy.kind.as_str() {
            "single" => AuthPolicyKind::Single,
            "all" => AuthPolicyKind::All,
            "threshold" => AuthPolicyKind::Threshold,
            other => return Err(format!("unknown policy kind {other}").into()),
        };
        let threshold = u16::try_from(self.policy.threshold)
            .map_err(|_| format!("threshold {} does not fit a u16", self.policy.threshold))?;
        let mut keys = Vec::with_capacity(self.policy.keys.len());
        for key in &self.policy.keys {
            let algorithm_id = algorithm_id(&key.algorithm)
                .ok_or_else(|| format!("unknown algorithm {}", key.algorithm))?;
            keys.push(AuthKey {
                key_id: key.key_id.as_bytes().to_vec(),
                algorithm_id,
                public_key: hex::decode(&key.public_key)?,
                // Genesis lists no weights; one each keeps a threshold equal to a
                // key count, which is what the file's threshold field means here.
                weight: 1,
                status: KeyStatus::Active,
                valid_from: 0,
                valid_until: POLICY_NO_EXPIRY,
            });
        }
        Ok(AuthPolicy {
            kind,
            threshold,
            policy_nonce: 1,
            keys,
        })
    }

    /// The address this account's policy derives.
    ///
    /// # Errors
    ///
    /// Anything [`GenesisAccount::runtime_policy`] reports.
    pub fn derived_address(&self) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(self.runtime_policy()?.address()?)
    }
}

/// The authorization policy attached to a genesis account.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisPolicy {
    /// `single`, `all`, or `threshold`.
    pub kind: String,
    /// Weight threshold for `threshold`, ignored otherwise.
    pub threshold: u64,
    /// The keys the policy refers to.
    pub keys: Vec<GenesisPolicyKey>,
}

/// One key an account policy may authorize with.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GenesisPolicyKey {
    /// Key id, unique within the account.
    pub key_id: String,
    /// `ed25519`, `ml-dsa-65`, or `slh-dsa-sha2-128s`.
    pub algorithm: String,
    /// Hex-encoded public key.
    pub public_key: String,
}

/// Why a genesis file is not usable.
fn algorithm_id(name: &str) -> Option<u16> {
    match name {
        "ed25519" => Some(ALG_ED25519),
        "ml-dsa-65" => Some(ALG_ML_DSA_65),
        "slh-dsa-sha2-128s" => Some(ALG_SLH_DSA_SHA2_128S),
        _ => None,
    }
}

/// The fixed public-key length for an algorithm, so a wrong one is caught here.
fn key_length(algorithm: u16) -> Option<usize> {
    match algorithm {
        ALG_ED25519 => Some(32),
        ALG_ML_DSA_65 => Some(1952),
        ALG_SLH_DSA_SHA2_128S => Some(32),
        _ => None,
    }
}

impl Genesis {
    /// Reads a genesis file.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the file cannot be read, and the parse error when it
    /// is not this schema.
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Loads a genesis, writing the template first when the file is missing.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the directory or file cannot be written, and the
    /// parse error when an existing file is not this schema.
    pub fn ensure(path: &Path) -> Result<Self, Box<dyn Error>> {
        if !path.exists() {
            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::write(path, EXAMPLE)?;
            println!("  no genesis at {}; wrote the template", path.display());
            println!("  it carries placeholder keys: replace them before the chain does anything");
        }
        Self::load(path)
    }

    /// Everything wrong with this genesis, as sentences.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.chain_id.trim().is_empty() {
            problems.push("chain_id is empty".to_string());
        }
        if self.protocol_version != PROTOCOL_VERSION {
            problems.push(format!(
                "protocol_version is {}, this build speaks {PROTOCOL_VERSION}",
                self.protocol_version
            ));
        }
        if self.epoch_rounds == 0 {
            problems.push("epoch_rounds must be at least 1".to_string());
        }
        if self.validators.is_empty() {
            problems.push("there must be at least one validator".to_string());
        }

        let mut validator_ids = HashSet::new();
        for validator in &self.validators {
            if validator.id.trim().is_empty() {
                problems.push("a validator has an empty id".to_string());
            }
            if !validator_ids.insert(validator.id.as_str()) {
                problems.push(format!("validator id {} appears twice", validator.id));
            }
            if validator.keys.is_empty() {
                problems.push(format!("validator {} has no keys", validator.id));
            }
            let mut key_ids = HashSet::new();
            for key in &validator.keys {
                if !key_ids.insert(key.key_id.as_str()) {
                    problems.push(format!(
                        "validator {} has two keys with id {}",
                        validator.id, key.key_id
                    ));
                }
                problems.extend(check_key(
                    &format!("validator {} key {}", validator.id, key.key_id),
                    &key.algorithm,
                    &key.public_key,
                ));
            }
            if !validator.keys.iter().any(|key| key.activation_epoch == 0) {
                problems.push(format!(
                    "validator {} has no key active at epoch 0",
                    validator.id
                ));
            }
        }

        let mut account_addresses = HashSet::new();
        for account in &self.accounts {
            let label = if account.address.is_empty() {
                "(empty address)".to_string()
            } else {
                account.address.clone()
            };
            if account.address.trim().is_empty() {
                problems.push("an account has an empty address".to_string());
            }
            let decoded = match tx::address::decode(&account.address) {
                Ok(bytes) => {
                    if !account_addresses.insert(bytes) {
                        problems.push(format!("account address {label} appears twice"));
                    }
                    Some(bytes)
                }
                Err(error) => {
                    problems.push(format!("account {label} is not an address: {error}"));
                    None
                }
            };
            match account.policy.kind.as_str() {
                "single" | "all" => {}
                "threshold" => {
                    if account.policy.threshold == 0 {
                        problems.push(format!(
                            "account {label} has a threshold policy with threshold 0"
                        ));
                    }
                    if account.policy.threshold > account.policy.keys.len() as u64 {
                        problems.push(format!(
                            "account {label} needs {} keys but the policy lists {}",
                            account.policy.threshold,
                            account.policy.keys.len()
                        ));
                    }
                }
                other => {
                    problems.push(format!("account {label} has unknown policy kind {other}"));
                }
            }
            if account.policy.threshold > u64::from(u16::MAX) {
                problems.push(format!(
                    "account {label} threshold {} does not fit a u16",
                    account.policy.threshold
                ));
            }
            if account.policy.keys.is_empty() {
                problems.push(format!("account {label} has no policy keys"));
            }
            let mut key_ids = HashSet::new();
            for key in &account.policy.keys {
                if !key_ids.insert(key.key_id.as_str()) {
                    problems.push(format!(
                        "account {label} has two keys with id {}",
                        key.key_id
                    ));
                }
                problems.extend(check_key(
                    &format!("account {label} key {}", key.key_id),
                    &key.algorithm,
                    &key.public_key,
                ));
            }
            match account.derived_address() {
                Ok(derived) => {
                    if let Some(decoded) = decoded
                        && decoded != derived
                    {
                        problems.push(format!(
                            "account {label} does not match its policy; the policy derives {}",
                            tx::address::encode(&derived)
                        ));
                    }
                }
                Err(error) => {
                    problems.push(format!("account {label} cannot derive an address: {error}"))
                }
            }
        }
        problems
    }

    /// The bytes every node hashes, in a fixed order.
    ///
    /// Validators, accounts, and keys are sorted by id, so the same genesis written
    /// with a different field order produces the same bytes. Lengths are explicit,
    /// so no two different fields can encode to the same stream.
    ///
    /// # Errors
    ///
    /// [`crypto::CryptoError`] when a field is too long for the canonical codec, or
    /// when a key is not valid hex — which [`Genesis::problems`] also reports.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, Box<dyn Error>> {
        let mut encoder = Encoder::with_capacity(4096);
        encoder.put_bytes(DOMAIN)?;
        encoder.put_bytes(self.chain_id.as_bytes())?;
        encoder.put_u16(self.protocol_version);
        encoder.put_u64(self.epoch_rounds);

        let mut validators: Vec<&GenesisValidator> = self.validators.iter().collect();
        validators.sort_by(|left, right| left.id.cmp(&right.id));
        encoder.put_u32(u32::try_from(validators.len())?);
        for validator in validators {
            encoder.put_bytes(validator.id.as_bytes())?;
            let mut keys: Vec<&GenesisKey> = validator.keys.iter().collect();
            keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
            encoder.put_u32(u32::try_from(keys.len())?);
            for key in keys {
                encoder.put_bytes(key.key_id.as_bytes())?;
                encoder.put_u16(algorithm_id(&key.algorithm).unwrap_or(0));
                encoder.put_bytes(&hex::decode(&key.public_key)?)?;
                encoder.put_u64(key.activation_epoch);
            }
        }

        let mut accounts: Vec<([u8; 32], &GenesisAccount)> = self
            .accounts
            .iter()
            .map(
                |account| -> Result<([u8; 32], &GenesisAccount), Box<dyn Error>> {
                    Ok((tx::address::decode(&account.address)?, account))
                },
            )
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
        // Sort by the decoded bytes, not the text: case is a display choice and
        // must not be able to change the chain's identity.
        accounts.sort_by_key(|left| left.0);
        encoder.put_u32(u32::try_from(accounts.len())?);
        for (address, account) in accounts {
            encoder.put_bytes(&address)?;
            encoder.put_u64(account.balance);
            encoder.put_u16(policy_id(&account.policy.kind));
            encoder.put_u64(account.policy.threshold);
            let mut keys: Vec<&GenesisPolicyKey> = account.policy.keys.iter().collect();
            keys.sort_by(|left, right| left.key_id.cmp(&right.key_id));
            encoder.put_u32(u32::try_from(keys.len())?);
            for key in keys {
                encoder.put_bytes(key.key_id.as_bytes())?;
                encoder.put_u16(algorithm_id(&key.algorithm).unwrap_or(0));
                encoder.put_bytes(&hex::decode(&key.public_key)?)?;
            }
        }
        Ok(encoder.finish())
    }

    /// The chain's genesis hash: SHA-256 over [`Genesis::canonical_bytes`].
    ///
    /// This is the value two nodes compare when they want to know whether they are
    /// on the same chain. It is not a hash of the file.
    ///
    /// # Errors
    ///
    /// Propagates [`Genesis::canonical_bytes`].
    pub fn hash(&self) -> Result<[u8; 32], Box<dyn Error>> {
        Ok(Sha256::digest(self.canonical_bytes()?).into())
    }
}

fn policy_id(kind: &str) -> u16 {
    match kind {
        "single" => 1,
        "all" => 2,
        "threshold" => 3,
        _ => 0,
    }
}

fn check_key(where_: &str, algorithm: &str, public_key: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let Some(id) = algorithm_id(algorithm) else {
        problems.push(format!("{where_} has unknown algorithm {algorithm}"));
        return problems;
    };
    match hex::decode(public_key) {
        Ok(bytes) => {
            if let Some(expected) = key_length(id)
                && bytes.len() != expected
            {
                problems.push(format!(
                    "{where_} is {} bytes, {algorithm} keys are {expected}",
                    bytes.len()
                ));
            }
        }
        Err(error) => problems.push(format!("{where_} is not hex: {error}")),
    }
    problems
}

/// Writes the example, refusing to overwrite.
///
/// # Errors
///
/// [`std::io::Error`] when the file exists or cannot be written.
pub fn write_example(path: &Path) -> Result<(), Box<dyn Error>> {
    if path.exists() {
        return Err(format!("{} already exists; not overwriting", path.display()).into());
    }
    std::fs::write(path, EXAMPLE)?;
    Ok(())
}

pub fn run(
    home: &crate::home::Home,
    explicit: Option<std::path::PathBuf>,
    init: bool,
) -> Result<(), Box<dyn Error>> {
    let path = home.file(explicit, "genesis.json");
    if init {
        write_example(&path)?;
        println!("wrote {}", path.display());
        return Ok(());
    }

    let genesis = Genesis::ensure(&path)?;
    let mut problems = genesis.problems();
    let hash = genesis.hash()?;

    println!("== Genesis: {} ==", path.display());
    println!("  chain             {}", genesis.chain_id);
    println!(
        "  protocol          version {}, key epoch every {} commits",
        genesis.protocol_version, genesis.epoch_rounds
    );
    println!("  validators        {}", genesis.validators.len());
    let quorum = genesis.validators.len() * 2 / 3 + 1;
    println!(
        "  quorum            {quorum} of {} (tolerates {} silent)",
        genesis.validators.len(),
        genesis.validators.len() - quorum
    );
    let supply: u64 = genesis.accounts.iter().map(|account| account.balance).sum();
    println!(
        "  accounts          {} holding {supply} in total",
        genesis.accounts.len()
    );
    for account in &genesis.accounts {
        println!("    {}  {}", account.address, account.balance);
    }
    println!("  genesis hash      {}", hex::encode(hash));

    // The node configuration is the other half of the same membership. It carries
    // no chain identifier of its own: this genesis is the only thing that says
    // which chain the home belongs to, so there is nothing to disagree with.
    let node_path = home.node_toml();
    println!();
    if node_path.exists() {
        match crate::config::NodeConfig::load(&node_path) {
            Ok(config) => {
                println!(
                    "  node.toml         {} ({} · {})",
                    node_path.display(),
                    config.node.id,
                    config.role_label()
                );
                problems.extend(config.problems());
            }
            Err(error) => problems.push(format!("{error}")),
        }
    } else {
        println!(
            "  node.toml         {} (missing; `karsa config` writes a template)",
            node_path.display()
        );
    }
    println!();
    println!("  The hash is SHA-256 over the canonical encoding of this data, not over");
    println!("  the file: reformatting or reordering the JSON does not change it, and two");
    println!("  nodes that print different values here are on different chains.");

    if problems.is_empty() {
        Ok(())
    } else {
        println!();
        for problem in &problems {
            println!("  PROBLEM: {problem}");
        }
        Err(format!("{} genesis problem(s)", problems.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn genesis() -> Genesis {
        // The example's keys are placeholders, but of the right length for their
        // algorithm, so the committed file validates as it stands.
        serde_json::from_str(EXAMPLE).unwrap()
    }

    #[test]
    fn the_example_is_well_formed_and_valid() {
        let genesis = genesis();
        assert!(genesis.problems().is_empty(), "{:?}", genesis.problems());
    }

    #[test]
    fn the_committed_example_matches_the_generated_one() {
        let committed = include_str!("../../../genesis.json.example");
        assert_eq!(
            committed, EXAMPLE,
            "genesis.json.example is stale: regenerate it with `karsa genesis --init`"
        );
    }

    #[test]
    fn the_hash_ignores_order_and_formatting() {
        let original = genesis();
        let mut reordered: Genesis = original.clone();
        reordered.validators.reverse();
        reordered.accounts.reverse();
        assert_eq!(original.hash().unwrap(), reordered.hash().unwrap());

        // And the same data written with different whitespace hashes the same,
        // because the hash is over the encoding, not the file.
        let compact = serde_json::to_string(&original).unwrap();
        let reparsed: Genesis = serde_json::from_str(&compact).unwrap();
        assert_eq!(original.hash().unwrap(), reparsed.hash().unwrap());
    }

    #[test]
    fn a_field_change_changes_the_hash() {
        let original = genesis();
        let mut changed = original.clone();
        changed.accounts[0].balance += 1;
        assert_ne!(original.hash().unwrap(), changed.hash().unwrap());
    }

    #[test]
    fn a_wrong_key_length_is_reported() {
        let mut genesis = genesis();
        genesis.validators[0].keys[0].public_key = hex::encode([1u8; 31]);
        assert!(
            genesis
                .problems()
                .iter()
                .any(|problem| problem.contains("keys are 32"))
        );
    }

    #[test]
    fn duplicate_addresses_are_reported() {
        let mut genesis = genesis();
        let duplicate = genesis.accounts[0].clone();
        genesis.accounts.push(duplicate);
        assert!(
            genesis
                .problems()
                .iter()
                .any(|problem| problem.contains("address") && problem.contains("appears twice"))
        );
    }

    #[test]
    fn an_address_that_does_not_match_its_policy_is_reported() {
        let mut genesis = genesis();
        genesis.accounts[0].address = tx::address::encode(&[0u8; 32]);
        let problems = genesis.problems();
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("does not match its policy")),
            "{problems:?}"
        );
    }

    #[test]
    fn an_address_with_a_bad_checksum_is_reported() {
        let mut genesis = genesis();
        let mut characters: Vec<char> = genesis.accounts[0].address.chars().collect();
        let last = characters.len() - 1;
        characters[last] = if characters[last] == 'q' { 'p' } else { 'q' };
        genesis.accounts[0].address = characters.into_iter().collect();
        assert!(
            genesis
                .problems()
                .iter()
                .any(|problem| problem.contains("checksum"))
        );
    }

    #[test]
    fn duplicate_ids_are_reported() {
        let mut genesis = genesis();
        let duplicate = genesis.validators[0].clone();
        genesis.validators.push(duplicate);
        assert!(
            genesis
                .problems()
                .iter()
                .any(|problem| problem.contains("appears twice"))
        );
    }

    #[test]
    fn a_threshold_larger_than_the_key_set_is_reported() {
        let mut genesis = genesis();
        genesis.accounts[0].policy.kind = "threshold".into();
        genesis.accounts[0].policy.threshold = 5;
        assert!(
            genesis
                .problems()
                .iter()
                .any(|problem| problem.contains("needs 5 keys"))
        );
    }

    #[test]
    fn an_unknown_policy_kind_is_reported() {
        let mut genesis = genesis();
        genesis.accounts[0].policy.kind = "multisig".into();
        assert!(
            genesis
                .problems()
                .iter()
                .any(|problem| problem.contains("unknown policy kind"))
        );
    }

    #[test]
    fn an_unknown_field_is_rejected_rather_than_ignored() {
        let text = EXAMPLE.replace("\"epoch_rounds\": 1000", "\"epoch_roundz\": 1000");
        assert!(serde_json::from_str::<Genesis>(&text).is_err());
    }
}
