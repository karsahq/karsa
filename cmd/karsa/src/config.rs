//! Per-node configuration, in a file rather than in a flag.
//!
//! Two operators running the same chain do not have to make the same storage
//! trade. One keeps a day of history, another a month, an archive keeps all of it;
//! one exposes an RPC endpoint and one does not. Those are local decisions with
//! local costs, so they live in the node's own `node.toml`, in the shape Cosmos
//! operators already expect.
//!
//! The file is validated rather than trusted. A pruning setting that would delete
//! everything, or an RPC role with nowhere to listen, is a mistake worth catching
//! before the node starts writing — not after.
//!
//! # Why the summary prints disk arithmetic
//!
//! The interesting part of a retention setting is not the number, it is the disk it
//! implies. `karsa config` therefore prints the effective window and the bytes per
//! day it costs at a few throughputs, so the operator sees the consequence at the
//! moment of choosing rather than a month later when the volume fills.

use std::error::Error;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// The example written by `karsa config --init`.
const EXAMPLE: &str = r#"# Karsa node configuration.
#
# Every validator runs its own copy: retention and roles are local decisions with
# local costs, not chain constants.

[node]
id = "val-0"
chain_id = "karsa-1"
data_dir = "/var/lib/karsa"

[roles]
# Whether this node participates in consensus.
validator = true
# Serve RPC to wallets and indexers. An RPC node without pruning is an archive.
rpc = false
# Keep every vertex and batch forever. Overrides retention below.
archive = false

[storage]
# Full payload kept for this many days. A validator only needs enough to serve a
# peer that is behind; history itself is served by archive nodes.
retain_days = 30
# Hard cap. Retention is "this many days OR this much disk, whichever comes first",
# so a traffic spike cannot fill the volume.
max_disk_gb = 500
# Write a state snapshot every this many commits. Pruning never goes below the
# newest snapshot.
snapshot_interval = 10000
# Certified headers are what a light client checks; they are small and kept.
keep_headers = true

[network]
listen = "0.0.0.0:26656"
rpc_listen = "127.0.0.1:26657"
"#;

/// The whole file.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    /// Identity and paths.
    pub node: NodeSection,
    /// What this node does for the network.
    pub roles: RolesSection,
    /// What it keeps.
    pub storage: StorageSection,
    /// Where it listens.
    pub network: NetworkSection,
}

/// Identity and paths.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeSection {
    /// Validator id, unique in the committee.
    pub id: String,
    /// Chain this node belongs to.
    pub chain_id: String,
    /// Where the store lives.
    pub data_dir: PathBuf,
}

/// What this node does for the network.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RolesSection {
    /// Participates in consensus.
    pub validator: bool,
    /// Serves RPC.
    pub rpc: bool,
    /// Keeps everything forever; implies no pruning.
    pub archive: bool,
}

/// What this node keeps.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct StorageSection {
    /// Days of full payload retained.
    pub retain_days: u32,
    /// Hard disk cap in gigabytes.
    pub max_disk_gb: u32,
    /// Commits between state snapshots.
    pub snapshot_interval: u64,
    /// Keep certified headers forever.
    pub keep_headers: bool,
}

/// Where this node listens.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkSection {
    /// Peer-to-peer listen address.
    pub listen: String,
    /// RPC listen address, used when the RPC role is on.
    pub rpc_listen: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node: NodeSection {
                id: "val-0".into(),
                chain_id: "karsa-1".into(),
                data_dir: PathBuf::from("/var/lib/karsa"),
            },
            roles: RolesSection {
                validator: true,
                rpc: false,
                archive: false,
            },
            storage: StorageSection {
                retain_days: 30,
                max_disk_gb: 500,
                snapshot_interval: 10_000,
                keep_headers: true,
            },
            network: NetworkSection {
                listen: "0.0.0.0:26656".into(),
                rpc_listen: "127.0.0.1:26657".into(),
            },
        }
    }
}

impl NodeConfig {
    /// Reads a configuration file.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the file cannot be read, and the parse error when it
    /// is not this schema.
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        let text = std::fs::read_to_string(path)?;
        Ok(toml::from_str(&text)?)
    }

    /// Loads a configuration, writing the default file first when it is missing.
    ///
    /// A node that refuses to start because a file it could have written itself is
    /// missing is a bad first run. The file is created once, with its comments
    /// intact, and then treated like any other: validated, never silently repaired.
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
            println!("  no configuration at {}; wrote defaults", path.display());
        }
        Self::load(path)
    }

    /// Everything wrong with this configuration, as sentences.
    ///
    /// Empty means usable. This returns problems rather than failing on the first
    /// one, because a fresh operator usually has several and reading them together
    /// is faster than fixing them one restart at a time.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        if self.node.id.trim().is_empty() {
            problems.push("node.id is empty".to_string());
        }
        if self.node.chain_id.trim().is_empty() {
            problems.push("node.chain_id is empty".to_string());
        }
        if !self.roles.validator && !self.roles.rpc && !self.roles.archive {
            problems.push(
                "the node has no role: set at least one of validator, rpc, or archive".to_string(),
            );
        }
        if self.roles.archive {
            if self.storage.retain_days != 0 {
                problems.push(
                    "archive nodes keep everything, so storage.retain_days must be 0".to_string(),
                );
            }
            if self.storage.max_disk_gb != 0 {
                problems.push(
                    "archive nodes keep everything, so storage.max_disk_gb must be 0".to_string(),
                );
            }
        } else {
            if self.storage.retain_days == 0 {
                problems.push(
                    "storage.retain_days is 0 on a pruning node, which would delete everything"
                        .to_string(),
                );
            }
            if self.storage.max_disk_gb == 0 {
                problems.push(
                    "storage.max_disk_gb is 0 on a pruning node, which would leave no usable disk"
                        .to_string(),
                );
            }
        }
        if self.storage.snapshot_interval == 0 {
            problems.push("storage.snapshot_interval must be at least 1".to_string());
        }
        if !self.storage.keep_headers {
            problems.push(
                "storage.keep_headers = false is not supported: headers are what a light client \
                 verifies and they are small"
                    .to_string(),
            );
        }
        if self.roles.rpc && self.network.rpc_listen.trim().is_empty() {
            problems.push("roles.rpc is on but network.rpc_listen is empty".to_string());
        }
        if std::net::ToSocketAddrs::to_socket_addrs(&self.network.listen).is_err() {
            problems.push(format!(
                "network.listen is not an address: {}",
                self.network.listen
            ));
        }
        problems
    }

    /// Whether this node prunes at all.
    #[must_use]
    pub fn prunes(&self) -> bool {
        !self.roles.archive
    }
}

fn human(bytes: f64) -> String {
    if bytes >= 1e12 {
        format!("{:.1} TB", bytes / 1e12)
    } else if bytes >= 1e9 {
        format!("{:.1} GB", bytes / 1e9)
    } else {
        format!("{:.1} MB", bytes / 1e6)
    }
}

/// Writes the commented example, refusing to overwrite.
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

pub fn run(path: Option<PathBuf>, init: bool) -> Result<(), Box<dyn Error>> {
    if init {
        let target = path.unwrap_or_else(|| PathBuf::from("node.toml"));
        write_example(&target)?;
        println!("wrote {}", target.display());
        return Ok(());
    }

    let path = path.unwrap_or_else(|| PathBuf::from("node.toml"));
    let config = NodeConfig::ensure(&path)?;
    let problems = config.problems();

    println!("== Node configuration: {} ==", path.display());
    println!(
        "  identity          {} on {}",
        config.node.id, config.node.chain_id
    );
    println!("  data directory    {}", config.node.data_dir.display());
    println!(
        "  roles             validator={} rpc={} archive={}",
        config.roles.validator, config.roles.rpc, config.roles.archive
    );
    println!(
        "  network           p2p {}  rpc {}",
        config.network.listen, config.network.rpc_listen
    );
    println!();
    if config.prunes() {
        println!(
            "  storage           keep {} days of payload, capped at {} GB, snapshot every {} commits",
            config.storage.retain_days,
            config.storage.max_disk_gb,
            config.storage.snapshot_interval
        );
    } else {
        println!("  storage           archive: every vertex and batch kept forever");
        println!(
            "  storage           headers kept: {}",
            config.storage.keep_headers
        );
    }

    if config.prunes() {
        println!();
        println!("    What the setting costs, before any burst:");
        println!("    {:>7}  {:>18}  {:>18}", "TPS", "169 B tx", "3.5 kB tx");
        println!(
            "    {:>7}  {:>18}  {:>18}",
            "", "window / disk used", "window / disk used"
        );
        let cap = f64::from(config.storage.max_disk_gb) * 1e9;
        for tps in [10u64, 100, 1_000, 10_000] {
            let mut cells = String::new();
            for size in [169u64, 3_500] {
                let per_day = tps as f64 * size as f64 * 86_400.0;
                if per_day <= 0.0 {
                    continue;
                }
                let wanted = per_day * f64::from(config.storage.retain_days);
                let effective = wanted.min(cap);
                cells.push_str(&format!(
                    "  {:>18}",
                    format!("{:.1} d / {}", effective / per_day, human(effective))
                ));
            }
            println!("    {tps:>7}{cells}");
        }
        println!();
        println!("  A burst is charged in full: one hour at 10k TPS is 36 million");
        println!("  transactions, which at 3.5 kB is more than a quiet month. The disk cap");
        println!("  is what stops a spike from filling the volume.");
    }
    println!();
    println!("  Note: retention bounds disk only. Every node still receives and forwards");
    println!("  the whole payload, so per-node egress stays (n-1)/n of the originator total.");

    if problems.is_empty() {
        Ok(())
    } else {
        println!();
        for problem in &problems {
            println!("  PROBLEM: {problem}");
        }
        Err(format!("{} configuration problem(s)", problems.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_example_parses_and_is_valid() {
        let config: NodeConfig = toml::from_str(EXAMPLE).unwrap();
        assert_eq!(config, NodeConfig::default());
        assert!(config.problems().is_empty(), "{:?}", config.problems());
        assert!(config.prunes());
        assert!(config.roles.validator);
    }

    #[test]
    fn an_archive_node_must_not_also_prune() {
        let mut config = NodeConfig::default();
        config.roles.archive = true;
        let problems = config.problems();
        assert!(
            problems
                .iter()
                .any(|problem| problem.contains("retain_days")),
            "{problems:?}"
        );

        config.storage.retain_days = 0;
        config.storage.max_disk_gb = 0;
        assert!(config.problems().is_empty(), "{:?}", config.problems());
        assert!(!config.prunes());
    }

    #[test]
    fn a_pruning_node_must_keep_something() {
        let mut config = NodeConfig::default();
        config.storage.retain_days = 0;
        assert!(
            config
                .problems()
                .iter()
                .any(|problem| problem.contains("retain_days"))
        );

        config.storage.retain_days = 7;
        config.storage.max_disk_gb = 0;
        assert!(
            config
                .problems()
                .iter()
                .any(|problem| problem.contains("max_disk_gb"))
        );
    }

    #[test]
    fn an_rpc_role_needs_somewhere_to_listen() {
        let mut config = NodeConfig::default();
        config.roles.rpc = true;
        config.network.rpc_listen = String::new();
        assert!(
            config
                .problems()
                .iter()
                .any(|problem| problem.contains("rpc_listen"))
        );
    }

    #[test]
    fn an_unknown_field_is_rejected_rather_than_ignored() {
        let text = EXAMPLE.replace("retain_days = 30", "retain_dayz = 30");
        assert!(toml::from_str::<NodeConfig>(&text).is_err());
    }

    #[test]
    fn a_node_with_no_role_is_refused() {
        let mut config = NodeConfig::default();
        config.roles.validator = false;
        config.roles.rpc = false;
        config.roles.archive = false;
        assert!(
            config
                .problems()
                .iter()
                .any(|problem| problem.contains("no role"))
        );
    }
}
