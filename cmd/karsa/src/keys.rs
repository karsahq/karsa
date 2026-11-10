//! The private half of a home: keys that match `genesis.json`.
//!
//! Genesis lists public keys only. A node that signs needs the private half, and it
//! must be able to prove the two match before it signs anything: a keystore for
//! another genesis, or with a public half that disagrees with its seed, is an
//! operator mistake that should stop the node rather than produce signatures nobody
//! accepts.
//!
//! The file sits beside `genesis.json` and is written with `0600` permissions. It is
//! never hashed: the chain's identity is the genesis, and private material must not
//! be part of a value that gets copied around.
//!
//! Only Ed25519 is listed here today. The crypto registry accepts post-quantum
//! algorithms for signatures, but the demo committee signs with Ed25519, and a
//! keystore format for keys this build cannot yet sign with would be a promise it
//! could not keep.

use std::error::Error;
use std::path::Path;

use crypto::registry::{ALG_ED25519, ALG_ML_DSA_65, ALG_SLH_DSA_SHA2_128S};
use crypto::scheme::Ed25519Scheme;
use serde::{Deserialize, Serialize};

use crate::chain::{self, Account};
use crate::genesis::{
    Genesis, GenesisAccount, GenesisKey, GenesisPolicy, GenesisPolicyKey, GenesisValidator,
    PROTOCOL_VERSION,
};

/// One private key, with the address and key id it belongs to.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KeyEntry {
    /// Address of the account or validator this key signs for.
    pub address: String,
    /// Key id inside that account's policy or validator's schedule.
    pub key_id: String,
    /// Algorithm name, as genesis writes it.
    pub algorithm: String,
    /// Private key, hex. Ed25519 uses Karsa's 64-byte `seed || public_key` form.
    pub private_key: String,
}

/// Every private key a node has for one chain.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Keys {
    /// Account keys.
    pub accounts: Vec<KeyEntry>,
    /// Consensus keys.
    pub validators: Vec<KeyEntry>,
}

impl Keys {
    /// Reads a keystore.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the file cannot be read, and the parse error when it
    /// is not this schema.
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let text = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&text)?)
    }

    /// Loads a keystore, writing the demo keys first when the file is missing.
    ///
    /// A fresh home is a one-machine devnet, so the keys that match the generated
    /// genesis are written rather than leaving the node unable to start. The file is
    /// explicitly a demo: replacing `genesis.json` without replacing `keys.json`
    /// fails validation, which is the point.
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
            let keys = demo_genesis(4)?.1;
            keys.save(path)?;
            println!(
                "  no keys at {}; wrote demo keys for the generated genesis",
                path.display()
            );
            println!("  these keys are public knowledge: replace them before a real chain");
        }
        Self::load(path)
    }

    /// Writes the keystore with owner-only permissions.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the file cannot be written or its mode cannot be set.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(path, format!("{text}\n"))?;
        restrict_permissions(path)?;
        Ok(())
    }

    /// The key for an account address, if this keystore has one.
    #[must_use]
    pub fn account_key(&self, address: &str) -> Option<&KeyEntry> {
        self.accounts.iter().find(|entry| entry.address == address)
    }

    /// The key for a validator address, if this keystore has one.
    #[must_use]
    pub fn validator_key(&self, address: &str) -> Option<&KeyEntry> {
        self.validators
            .iter()
            .find(|entry| entry.address == address)
    }

    /// Everything wrong with this keystore relative to `genesis`.
    ///
    /// Empty means the keys can sign for the chain the genesis describes. This is
    /// deliberately stricter than "parse succeeded": an address with no genesis
    /// entry, a key id the policy does not list, and a public half that disagrees
    /// with its seed are all refused here, before a signature exists.
    #[must_use]
    pub fn problems(&self, genesis: &Genesis) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen = std::collections::HashSet::new();
        for entry in &self.accounts {
            if !seen.insert(entry.address.as_str()) {
                problems.push(format!("account key {} appears twice", entry.address));
            }
            let Some(account) = genesis
                .accounts
                .iter()
                .find(|account| account.address == entry.address)
            else {
                problems.push(format!("account key {} is not in genesis", entry.address));
                continue;
            };
            let policy = match account.runtime_policy() {
                Ok(policy) => policy,
                Err(error) => {
                    problems.push(format!(
                        "account {} policy cannot be read: {error}",
                        entry.address
                    ));
                    continue;
                }
            };
            let Some(key) = policy
                .keys
                .iter()
                .find(|key| key.key_id == entry.key_id.as_bytes())
            else {
                problems.push(format!(
                    "account {} policy has no key {}",
                    entry.address, entry.key_id
                ));
                continue;
            };
            problems.extend(check_entry(entry, &key.public_key));
        }

        let mut seen = std::collections::HashSet::new();
        for entry in &self.validators {
            if !seen.insert(entry.address.as_str()) {
                problems.push(format!("validator key {} appears twice", entry.address));
            }
            let Some(validator) = genesis
                .validators
                .iter()
                .find(|validator| validator.address == entry.address)
            else {
                problems.push(format!("validator key {} is not in genesis", entry.address));
                continue;
            };
            let schedule = match validator.runtime_keys() {
                Ok(schedule) => schedule,
                Err(error) => {
                    problems.push(format!(
                        "validator {} keys cannot be read: {error}",
                        entry.address
                    ));
                    continue;
                }
            };
            let Some(key) = schedule
                .iter()
                .find(|key| key.key_id == entry.key_id.as_bytes())
            else {
                problems.push(format!(
                    "validator {} schedule has no key {}",
                    entry.address, entry.key_id
                ));
                continue;
            };
            problems.extend(check_entry(entry, &key.public_key));
        }
        problems
    }
}

/// Checks that one entry is Ed25519 and its public half is the listed key.
fn check_entry(entry: &KeyEntry, expected_public: &[u8]) -> Vec<String> {
    let mut problems = Vec::new();
    if entry.algorithm != "ed25519" {
        problems.push(format!(
            "key {} uses {}, only ed25519 keys are supported here",
            entry.key_id, entry.algorithm
        ));
        return problems;
    }
    match decode_ed25519(&entry.private_key) {
        Ok(private) => {
            if private[32..] != expected_public[..] {
                problems.push(format!(
                    "key {} has a public half that does not match genesis",
                    entry.key_id
                ));
            }
        }
        Err(error) => problems.push(format!("key {}: {error}", entry.key_id)),
    }
    problems
}

/// Decodes Karsa's 64-byte Ed25519 private key and checks seed against public half.
///
/// # Errors
///
/// A string that is not hex, the wrong length, or a pair whose halves disagree.
pub fn decode_ed25519(private_key: &str) -> Result<Vec<u8>, String> {
    let bytes = hex::decode(private_key).map_err(|error| format!("not hex: {error}"))?;
    if bytes.len() != 64 {
        return Err(format!("{} bytes, want 64 (seed || public)", bytes.len()));
    }
    let derived = Ed25519Scheme::public_key_from_seed(&bytes[..32])
        .map_err(|error| format!("seed is unusable: {error}"))?;
    if bytes[32..] != derived {
        return Err("public half does not match the seed".to_string());
    }
    Ok(bytes)
}

/// Restricts a private-key file to its owner, where the platform has modes.
#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)?.permissions();
    permissions.set_mode(0o600);
    std::fs::set_permissions(path, permissions)?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), Box<dyn Error>> {
    Ok(())
}

/// A four-validator, four-account devnet: the genesis and the keys that match it.
///
/// Both are derived from the same deterministic seeds the rest of the demo uses,
/// so the template is runnable out of the box and `--home` needs no extra setup. It
/// is a devnet by construction: the seeds are in the source, and the file says so.
///
/// # Errors
///
/// Propagates the demo key generation and the genesis schema conversions.
pub(crate) fn demo_genesis(validators: usize) -> Result<(Genesis, Keys), Box<dyn Error>> {
    let accounts = chain::accounts(validators)?;
    let (set, consensus) = chain::consensus_set(validators)?;

    let genesis_accounts = accounts
        .iter()
        .map(genesis_account)
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let account_keys = accounts
        .iter()
        .map(|account| -> Result<KeyEntry, Box<dyn Error>> {
            Ok(KeyEntry {
                address: tx::address::encode(&account.address),
                key_id: String::from_utf8(account.key_id.clone())?,
                algorithm: "ed25519".into(),
                private_key: hex::encode(&account.private_key),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    let genesis_validators = set
        .validators
        .iter()
        .map(genesis_validator)
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let validator_keys = set
        .validators
        .iter()
        .zip(&consensus)
        .map(|(record, consensus)| -> Result<KeyEntry, Box<dyn Error>> {
            Ok(KeyEntry {
                address: tx::address::encode(&address_of(record)?),
                key_id: String::from_utf8(record.keys[0].key_id.clone())?,
                algorithm: "ed25519".into(),
                private_key: hex::encode(&consensus.private_key),
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;

    Ok((
        Genesis {
            chain_id: "karsa".into(),
            protocol_version: PROTOCOL_VERSION,
            epoch_rounds: crate::genesis::DEMO_EPOCH_ROUNDS,
            validators: genesis_validators,
            accounts: genesis_accounts,
        },
        Keys {
            accounts: account_keys,
            validators: validator_keys,
        },
    ))
}

fn genesis_account(account: &Account) -> Result<GenesisAccount, Box<dyn Error>> {
    let kind = match account.policy.kind {
        tx::policy::AuthPolicyKind::Single => "single",
        tx::policy::AuthPolicyKind::All => "all",
        tx::policy::AuthPolicyKind::Threshold => "threshold",
    };
    Ok(GenesisAccount {
        address: tx::address::encode(&account.address),
        balance: account.balance,
        policy: GenesisPolicy {
            kind: kind.into(),
            threshold: u64::from(account.policy.threshold),
            keys: account
                .policy
                .keys
                .iter()
                .map(genesis_policy_key)
                .collect::<Result<Vec<_>, _>>()?,
        },
    })
}

fn genesis_policy_key(key: &tx::policy::AuthKey) -> Result<GenesisPolicyKey, Box<dyn Error>> {
    Ok(GenesisPolicyKey {
        key_id: String::from_utf8(key.key_id.clone())?,
        algorithm: algorithm_name(key.algorithm_id)?.to_string(),
        public_key: hex::encode(&key.public_key),
    })
}

fn genesis_validator(
    record: &validator::ValidatorRecord,
) -> Result<GenesisValidator, Box<dyn Error>> {
    Ok(GenesisValidator {
        address: tx::address::encode(&address_of(record)?),
        keys: record
            .keys
            .iter()
            .map(|key| {
                Ok(GenesisKey {
                    key_id: String::from_utf8(key.key_id.clone())?,
                    algorithm: algorithm_name(key.algorithm_id)?.to_string(),
                    public_key: hex::encode(&key.public_key),
                    activation_epoch: key.activation_epoch,
                })
            })
            .collect::<Result<Vec<_>, Box<dyn Error>>>()?,
    })
}

fn address_of(record: &validator::ValidatorRecord) -> Result<[u8; 32], Box<dyn Error>> {
    <[u8; 32]>::try_from(record.validator_id.as_slice())
        .map_err(|_| "validator id is not a 32-byte address".into())
}

fn algorithm_name(id: u16) -> Result<&'static str, Box<dyn Error>> {
    match id {
        ALG_ED25519 => Ok("ed25519"),
        ALG_ML_DSA_65 => Ok("ml-dsa-65"),
        ALG_SLH_DSA_SHA2_128S => Ok("slh-dsa-sha2-128s"),
        other => Err(format!("algorithm {other:#06x} has no genesis name").into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_demo_keys_match_the_demo_genesis() {
        let (genesis, keys) = demo_genesis(4).unwrap();
        assert!(genesis.problems().is_empty(), "{:?}", genesis.problems());
        assert!(
            keys.problems(&genesis).is_empty(),
            "{:?}",
            keys.problems(&genesis)
        );
    }

    #[test]
    fn a_larger_demo_genesis_keeps_matching_keys() {
        let (genesis, keys) = demo_genesis(5).unwrap();
        assert_eq!(genesis.validators.len(), 5);
        assert!(genesis.problems().is_empty(), "{:?}", genesis.problems());
        assert!(
            keys.problems(&genesis).is_empty(),
            "{:?}",
            keys.problems(&genesis)
        );
    }

    #[test]
    fn the_committed_keys_example_matches_the_generated_one() {
        let committed = include_str!("../../../keys.json.example");
        let generated = format!(
            "{}\n",
            serde_json::to_string_pretty(&demo_genesis(4).unwrap().1).unwrap()
        );
        assert_eq!(
            committed, generated,
            "keys.json.example is stale: regenerate it with `karsa genesis --init`"
        );
    }

    #[test]
    fn a_key_for_another_chain_is_reported() {
        let (genesis, mut keys) = demo_genesis(4).unwrap();
        keys.accounts[0].address = tx::address::encode(&[0u8; 32]);
        assert!(
            keys.problems(&genesis)
                .iter()
                .any(|problem| problem.contains("not in genesis"))
        );
    }

    #[test]
    fn a_public_half_that_disagrees_with_the_seed_is_reported() {
        let (genesis, mut keys) = demo_genesis(4).unwrap();
        let mut bytes = hex::decode(&keys.accounts[0].private_key).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0xff;
        keys.accounts[0].private_key = hex::encode(bytes);
        assert!(
            keys.problems(&genesis)
                .iter()
                .any(|problem| problem.contains("does not match the seed"))
        );
    }
}
