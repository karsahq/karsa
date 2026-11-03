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
//! An entry is a pair: the validator address (when known) and the endpoint. An
//! address that appears in genesis is marked as a founding validator; one that does
//! not is a peer this node knows, which is a legitimate state for an RPC or a
//! sentry. An endpoint without an address is a peer whose identity this node has
//! not learned yet.
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
///
/// `address` is the chain identity (Base58Check `K...`) and `endpoint` is where to
/// reach it. They are different things on purpose: an address survives a move, an
/// endpoint does not belong in genesis, and a peer may be known without either
/// (a sentry whose validator address this node has not learned yet).
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Peer {
    /// Validator address (Base58Check `K...`), when this peer's identity is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// `host:port` a node can connect to.
    pub endpoint: String,
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
        let mut seen_addresses = std::collections::HashSet::new();
        let mut seen_endpoints = std::collections::HashSet::new();
        for peer in &self.peers {
            if let Some(address) = &peer.address {
                if address.trim().is_empty() {
                    problems.push(format!("peer {} has an empty address", peer.endpoint));
                } else {
                    if tx::address::decode(address).is_err() {
                        problems.push(format!(
                            "peer {} has an address that is not Base58Check: {address}",
                            peer.endpoint
                        ));
                    }
                    if !seen_addresses.insert(address.as_str()) {
                        problems.push(format!("peer address {address} appears twice"));
                    }
                }
            }
            if !seen_endpoints.insert(peer.endpoint.as_str()) {
                problems.push(format!("peer endpoint {} appears twice", peer.endpoint));
            }
            if std::net::ToSocketAddrs::to_socket_addrs(&peer.endpoint).is_err() {
                problems.push(format!("peer endpoint is not host:port: {}", peer.endpoint));
            }
        }
        problems
    }

    /// Adds a peer, replacing the endpoint of one already known.
    ///
    /// With an address, the address is the key: a validator that moves keeps one
    /// entry. Without one, the endpoint is the key, so a sentry added twice does not
    /// double the list. A later add with an address upgrades an addressless entry
    /// at the same endpoint rather than creating a second row for one machine.
    pub fn add(&mut self, address: Option<&str>, endpoint: &str) {
        if let Some(address) = address {
            if let Some(existing) = self
                .peers
                .iter_mut()
                .find(|peer| peer.address.as_deref() == Some(address))
            {
                existing.endpoint = endpoint.to_string();
                return;
            }
            if let Some(existing) = self
                .peers
                .iter_mut()
                .find(|peer| peer.address.is_none() && peer.endpoint == endpoint)
            {
                existing.address = Some(address.to_string());
                return;
            }
            self.peers.push(Peer {
                address: Some(address.to_string()),
                endpoint: endpoint.to_string(),
            });
            return;
        }
        if self
            .peers
            .iter()
            .any(|peer| peer.address.is_none() && peer.endpoint == endpoint)
        {
            return;
        }
        self.peers.push(Peer {
            address: None,
            endpoint: endpoint.to_string(),
        });
    }

    /// Removes a peer by address or endpoint, returning whether it was there.
    pub fn remove(&mut self, identity: &str) -> bool {
        let before = self.peers.len();
        self.peers
            .retain(|peer| peer.address.as_deref() != Some(identity) && peer.endpoint != identity);
        self.peers.len() != before
    }
}

/// Parses `address@endpoint` or a bare `endpoint` as the command line takes it.
///
/// The address, when present, is decoded here so a typo is refused before the file
/// is written, not discovered at the first connection.
///
/// # Errors
///
/// A malformed argument, an address that is not Base58Check, or an endpoint that is
/// not `host:port`.
pub fn parse_endpoint(argument: &str) -> Result<(Option<String>, String), Box<dyn Error>> {
    let (address, endpoint) = match argument.split_once('@') {
        Some((address, endpoint)) if !address.is_empty() && !endpoint.is_empty() => {
            (Some(address), endpoint)
        }
        Some(_) => {
            return Err(format!("expected address@endpoint or endpoint, got {argument}").into());
        }
        None if !argument.is_empty() => (None, argument),
        None => return Err("expected address@endpoint or endpoint".into()),
    };
    if let Some(address) = address {
        tx::address::decode(address).map_err(|error| format!("{address}: {error}"))?;
    }
    if std::net::ToSocketAddrs::to_socket_addrs(endpoint).is_err() {
        return Err(format!("endpoint is not host:port: {endpoint}").into());
    }
    Ok((address.map(str::to_string), endpoint.to_string()))
}

pub fn run(
    home: &crate::home::Home,
    add: Option<String>,
    remove: Option<String>,
) -> Result<(), Box<dyn Error>> {
    let path = home.peers_json();
    let mut peers = Peers::load(&path)?;

    if let Some(argument) = add {
        let (address, endpoint) = parse_endpoint(&argument)?;
        peers.add(address.as_deref(), &endpoint);
        peers.save(&path)?;
    }
    if let Some(identity) = remove {
        if !peers.remove(&identity) {
            return Err(format!(
                "no peer with address or endpoint {identity} in {}",
                path.display()
            )
            .into());
        }
        peers.save(&path)?;
    }
    if !path.exists() {
        // Listing a home that has no peer file yet writes an empty one, so the file
        // exists to be edited rather than appearing only after the first add.
        peers.save(&path)?;
    }

    let genesis = crate::genesis::Genesis::load(&home.genesis_json()).ok();
    let founding = |address: Option<&str>| {
        genesis.as_ref().is_some_and(|genesis| {
            genesis
                .validators
                .iter()
                .any(|validator| Some(validator.address.as_str()) == address)
        })
    };

    println!("== Peers: {} ==", path.display());
    println!("  known             {}", peers.peers.len());
    println!();
    if peers.peers.is_empty() {
        println!("  none yet. This node can be reached, but it will not initiate.");
        println!(
            "  add one:  karsa peers --add K2omunn2RZQ1xV6SemLxyAoFUEk6PKtV8pUsqJB5vUCusRcHmgN@10.0.0.12:26656"
        );
        println!("  or just an endpoint: karsa peers --add 10.0.0.12:26656");
    } else {
        println!("  {}  endpoint", left("address", 51));
        for peer in &peers.peers {
            let address = peer.address.as_deref().unwrap_or("-");
            let label = if founding(peer.address.as_deref()) {
                "  (founding validator)"
            } else if peer.address.is_some() {
                "  (known validator)"
            } else {
                "  (known only)"
            };
            println!("  {}  {}{}", left(address, 51), peer.endpoint, label);
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

    fn address(seed: u8) -> String {
        tx::address::encode(&[seed; 32])
    }

    #[test]
    fn adding_the_same_address_updates_its_endpoint() {
        let mut peers = Peers::default();
        let address = address(1);
        peers.add(Some(&address), "10.0.0.1:26656");
        peers.add(Some(&address), "10.0.0.2:26656");
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].endpoint, "10.0.0.2:26656");
    }

    #[test]
    fn an_addressless_peer_is_keyed_by_endpoint_and_can_be_upgraded() {
        let mut peers = Peers::default();
        peers.add(None, "10.0.0.1:26656");
        peers.add(None, "10.0.0.1:26656");
        assert_eq!(peers.peers.len(), 1);
        assert!(peers.peers[0].address.is_none());

        let address = address(1);
        peers.add(Some(&address), "10.0.0.1:26656");
        assert_eq!(peers.peers.len(), 1);
        assert_eq!(peers.peers[0].address.as_deref(), Some(address.as_str()));
    }

    #[test]
    fn removing_works_by_address_or_endpoint() {
        let mut peers = Peers::default();
        let address = address(1);
        peers.add(Some(&address), "10.0.0.1:26656");
        assert!(peers.remove(&address));
        peers.add(None, "10.0.0.2:26656");
        assert!(peers.remove("10.0.0.2:26656"));
        assert!(!peers.remove("10.0.0.3:26656"));
    }

    #[test]
    fn a_bad_endpoint_is_reported() {
        let mut peers = Peers::default();
        peers.add(None, "not an address");
        assert!(
            peers
                .problems()
                .iter()
                .any(|problem| problem.contains("host:port"))
        );
    }

    #[test]
    fn a_duplicate_address_is_reported() {
        let address = address(1);
        let peers = Peers {
            peers: vec![
                Peer {
                    address: Some(address.clone()),
                    endpoint: "10.0.0.1:26656".into(),
                },
                Peer {
                    address: Some(address),
                    endpoint: "10.0.0.2:26656".into(),
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
    fn the_endpoint_syntax_takes_an_optional_address() {
        let address = address(1);
        assert_eq!(
            parse_endpoint(&format!("{address}@10.0.0.12:26656")).unwrap(),
            (Some(address.clone()), "10.0.0.12:26656".to_string())
        );
        assert_eq!(
            parse_endpoint("10.0.0.12:26656").unwrap(),
            (None, "10.0.0.12:26656".to_string())
        );
        assert!(parse_endpoint("@10.0.0.1:26656").is_err());
        assert!(parse_endpoint("not-an-address@10.0.0.1:26656").is_err());
        assert!(parse_endpoint("10.0.0.1").is_err());
    }

    #[test]
    fn an_unknown_field_is_rejected() {
        assert!(
            serde_json::from_str::<Peers>(r#"{"peers":[{"endpoint":"1.2.3.4:1","x":1}]}"#).is_err()
        );
    }
}
