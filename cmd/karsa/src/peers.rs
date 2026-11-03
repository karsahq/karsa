//! Known peers: the network half of a node's configuration.
//!
//! Genesis says who the validators *are* — their keys and account identities. It
//! deliberately says nothing about where they listen: an address is operational
//! data, it changes when a machine moves, and putting it in a file that every node
//! must agree on would turn a DNS change into a chain migration.
//!
//! So the endpoints live in `peers.json`, beside `node.toml` and `genesis.json`,
//! and that file is expected to change:
//!
//! - **grow** as the node learns peers from gossip, a seed list, or an operator
//!   adding one by hand,
//! - **shrink** as peers are retired or removed,
//! - and never participate in consensus, so a stale entry costs a reconnect, not a
//!   fork.
//!
//! An entry is a pair: the validator id (if it has one) and the address. Ids that
//! appear in genesis are marked as founding validators; ids that do not are peers
//! this node happens to know, which is a legitimate state for an RPC or a sentry.
//!
//! # What this does not do yet
//!
//! Nothing updates the file automatically: the transport in `karsa live` is a
//! fixed mesh with no discovery, and `karsa node` serves HTTP without peers. The
//! format and the validation exist so that the bookkeeping has a home when a
//! transport grows one; writing a file nothing reads automatically would be worse
//! than leaving it to the operator.

use std::error::Error;
use std::path::Path;

use serde::{Deserialize, Serialize};

fn left(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

/// The file, as written.
#[derive(Debug, Clone, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peers {
    /// Known peers, in the order they were learned.
    pub peers: Vec<Peer>,
}

/// One known peer.
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Validator id, when the peer has one.
    pub id: String,
    /// `host:port` a node can connect to.
    pub address: String,
}

impl Peers {
    /// Reads the file, treating a missing one as an empty list.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the file cannot be read, and the parse error when it
    /// is not this schema.
    pub fn load(path: &Path) -> Result<Self, Box<dyn Error>> {
        if !path.exists() {
            return Ok(Self::default());
        }
        Ok(serde_json::from_str(&std::fs::read_to_string(path)?)?)
    }

    /// Writes the file, creating parent directories.
    ///
    /// # Errors
    ///
    /// [`std::io::Error`] when the directory or file cannot be written.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn Error>> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let mut text = serde_json::to_string_pretty(self)?;
        text.push('\n');
        std::fs::write(path, text)?;
        Ok(())
    }

    /// Everything wrong with this list, as sentences.
    #[must_use]
    pub fn problems(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for peer in &self.peers {
            if peer.id.trim().is_empty() {
                problems.push(format!("peer {} has an empty id", peer.address));
            } else if !seen.insert(peer.id.as_str()) {
                problems.push(format!("peer id {} appears twice", peer.id));
            }
            if std::net::ToSocketAddrs::to_socket_addrs(&peer.address).is_err() {
                problems.push(format!(
                    "peer {} has an address that is not host:port: {}",
                    peer.id, peer.address
                ));
            }
        }
        problems
    }

    /// Adds a peer, replacing the address of one already known.
    pub fn add(&mut self, id: &str, address: &str) {
        match self.peers.iter_mut().find(|peer| peer.id == id) {
            Some(existing) => existing.address = address.to_string(),
            None => self.peers.push(Peer {
                id: id.to_string(),
                address: address.to_string(),
            }),
        }
    }

    /// Removes a peer, returning whether it was there.
    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.peers.len();
        self.peers.retain(|peer| peer.id != id);
        self.peers.len() != before
    }
}

/// Parses `id@host:port` as the command line takes it.
///
/// # Errors
///
/// Returns a sentence when the argument has no `@`.
pub fn parse_endpoint(argument: &str) -> Result<(String, String), Box<dyn Error>> {
    match argument.split_once('@') {
        Some((id, address)) if !id.is_empty() && !address.is_empty() => {
            Ok((id.to_string(), address.to_string()))
        }
        _ => Err(format!("expected id@host:port, got {argument}").into()),
    }
}

pub fn run(
    home: &crate::home::Home,
    add: Option<String>,
    remove: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let path = home.peers_json();
    let mut peers = Peers::load(&path)?;

    if let Some(argument) = add {
        let (id, address) = parse_endpoint(&argument)?;
        peers.add(&id, &address);
        peers.save(&path)?;
    }
    if let Some(id) = remove {
        if !peers.remove(&id) {
            return Err(format!("no peer with id {id} in {}", path.display()).into());
        }
        peers.save(&path)?;
    }
    if !path.exists() {
        // Listing a home that has no peer file yet writes an empty one, so the file
        // exists to be edited rather than appearing only after the first add.
        peers.save(&path)?;
    }

    let genesis = crate::genesis::Genesis::load(&home.genesis_json()).ok();
    let founding = |id: &str| {
        genesis.as_ref().is_some_and(|genesis| {
            genesis
                .validators
                .iter()
                .any(|validator| validator.id == id)
        })
    };

    println!("== Peers: {} ==", path.display());
    println!("  known             {}", peers.peers.len());
    println!();
    if peers.peers.is_empty() {
        println!("  none yet. This node can be reached, but it will not initiate.");
        println!("  add one:  karsa peers --add val-1@10.0.0.12:26656");
    } else {
        println!("  {}  address", left("id", 12));
        for peer in &peers.peers {
            println!(
                "  {}  {}{}",
                left(&peer.id, 12),
                peer.address,
                if founding(&peer.id) {
                    "  (founding validator)"
                } else {
                    "  (known only)"
                }
            );
        }
        println!();
        println!("  A founding validator is in genesis; a known-only peer is someone this");
        println!("  node can reach but does not count as part of the committee.");
    }

    let problems = peers.problems();
    if problems.is_empty() {
        Ok(())
    } else {
        println!();
        for problem in &problems {
            println!("  PROBLEM: {problem}");
        }
        Err(format!("{} peer problem(s)", problems.len()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adding_the_same_id_updates_its_address() {
        let mut peers = Peers::default();
        peers.add("val-1", "10.0.0.1:26656");
        peers.add("val-1", "10.0.0.2:26656");
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].address, "10.0.0.2:26656");
    }

    #[test]
    fn removing_reports_whether_it_was_there() {
        let mut peers = Peers::default();
        peers.add("val-1", "10.0.0.1:26656");
        assert!(peers.remove("val-1"));
        assert!(!peers.remove("val-1"));
    }

    #[test]
    fn a_bad_address_is_reported() {
        let mut peers = Peers::default();
        peers.add("val-1", "not an address");
        assert!(
            peers
                .problems()
                .iter()
                .any(|problem| problem.contains("host:port"))
        );
    }

    #[test]
    fn a_duplicate_id_is_reported() {
        let peers = Peers {
            peers: vec![
                Peer {
                    id: "val-1".into(),
                    address: "10.0.0.1:26656".into(),
                },
                Peer {
                    id: "val-1".into(),
                    address: "10.0.0.2:26656".into(),
                },
            ],
        };
        assert!(
            peers
                .problems()
                .iter()
                .any(|problem| problem.contains("appears twice"))
        );
    }

    #[test]
    fn the_endpoint_syntax_splits_on_at() {
        assert_eq!(
            parse_endpoint("val-1@10.0.0.12:26656").unwrap(),
            ("val-1".to_string(), "10.0.0.12:26656".to_string())
        );
        assert!(parse_endpoint("val-1").is_err());
        assert!(parse_endpoint("@10.0.0.1:26656").is_err());
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        assert!(
            serde_json::from_str::<Peers>(r#"{"peers":[{"id":"a","address":"1.2.3.4:1","x":1}]}"#)
                .is_err()
        );
    }
}
