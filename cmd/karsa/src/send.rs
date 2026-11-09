//! One client: sign a transfer with a committee account and submit it to a live
//! node's RPC endpoint, then watch it reach finality.
//!
//! The signing key comes from the same deterministic committee fixture the live
//! mesh used (`--validators`, optionally `--home`), so this is a real envelope
//! with a real Ed25519 signature over the chain id the nodes announce. It is not
//! a privileged path: it uses the same `POST /tx` a wallet would.
//!
//! `--tamper-signature` and an explicit `--sequence` make the rejection paths
//! testable from the shell: a broken signature must fail verification, and a
//! sequence at or below the applied one must be refused as a replay.

use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crypto::registry::ALG_ED25519;
use crypto::scheme::Ed25519Scheme;
use sha2::{Digest, Sha256};
use tx::address;
use tx::envelope::{PROTOCOL_VERSION_V1, Transaction};
use tx::policy::Authorization;
use validator::{CommitProof, VertexId};

use crate::chain;
use crate::home::Home;

/// What `karsa send` was asked to do.
pub struct Config {
    /// RPC base, either `host:port` or `http://host:port`.
    pub rpc: String,
    /// Sender index in the committee fixture.
    pub from: usize,
    /// Recipient index in the committee fixture.
    pub to: usize,
    pub amount: u64,
    /// Sequence to sign; zero asks `/account` for the next one.
    pub sequence: u64,
    pub validators: usize,
    pub home: Option<PathBuf>,
    /// Flip the first signature byte after signing.
    pub tamper_signature: bool,
    /// Poll until the transaction is finalized or rejected.
    pub wait: bool,
    pub wait_seconds: u64,
}

/// Runs the client.
///
/// # Errors
///
/// A committee index outside the fixture, a signing error, a connection that
/// cannot be opened, a non-2xx submit, or a wait that expires before finality.
pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    let home = config
        .home
        .clone()
        .map(|path| Home::resolve(Some(path)))
        .transpose()?;
    let committee = chain::membership(config.validators, home.as_ref())?;
    let chain_id = match &home {
        Some(home) => chain::chain_id(Some(home))?,
        None => chain::demo_chain_id(),
    };
    let account = committee
        .accounts
        .get(config.from)
        .ok_or_else(|| format!("--from {} is outside the committee accounts", config.from))?;
    let recipient = committee
        .accounts
        .get(config.to)
        .ok_or_else(|| format!("--to {} is outside the committee accounts", config.to))?;

    let sequence = if config.sequence > 0 {
        config.sequence
    } else {
        let path = format!("/account/{}", hex::encode(account.address));
        let (status, body) = http(&config.rpc, "GET", &path, None)?;
        if status != 200 {
            return Err(format!("cannot read the next sequence: HTTP {status}: {body}").into());
        }
        let view: serde_json::Value = serde_json::from_str(&body)?;
        view.get("sequence")
            .and_then(serde_json::Value::as_u64)
            .ok_or("the account response has no sequence")?
            .saturating_add(1)
    };

    let mut transaction = Transaction {
        protocol_version: PROTOCOL_VERSION_V1,
        chain_id: chain_id.clone(),
        sender: account.address.to_vec(),
        sequence,
        fee: 1,
        expiration: u64::MAX,
        policy_version: 1,
        payload: exec::Transfer::new(recipient.address.to_vec(), config.amount).encode()?,
        authorization: Vec::new(),
    };
    let message = transaction.signing_payload()?;
    let mut signature = Ed25519Scheme.sign(&account.private_key, &message)?;
    if config.tamper_signature {
        signature[0] ^= 0xff;
    }
    transaction.authorization.push(Authorization {
        algorithm_id: ALG_ED25519,
        key_id: account.key_id.clone(),
        signature,
    });
    let envelope = transaction.encode()?;
    let id = hex::encode(Sha256::digest(&envelope));

    println!("== karsa send ==");
    let from_address = address::encode(&account.address);
    let to_address = address::encode(&recipient.address);
    println!("  from            account {} {from_address}", config.from);
    println!("  to              account {} {to_address}", config.to);
    println!("  sequence        {sequence}");
    println!("  amount          {} (fee 1)", config.amount);
    println!("  chain           {}", hex::encode(&chain_id[..6]));
    println!("  transaction     {id}");
    if config.tamper_signature {
        println!("  signature       tampered on purpose");
    }

    let (status, body) = http(&config.rpc, "POST", "/tx", Some(&hex::encode(&envelope)))?;
    println!("  submit          HTTP {status}");
    println!("  response        {}", body.trim());
    if status >= 400 {
        return Err(format!("submit was refused with HTTP {status}").into());
    }
    if !config.wait {
        return Ok(());
    }

    let deadline = Instant::now() + Duration::from_secs(config.wait_seconds);
    let mut last = String::new();
    loop {
        let (status, body) = http(&config.rpc, "GET", &format!("/tx/{id}"), None)?;
        if status != 200 {
            return Err(format!("status query failed with HTTP {status}: {body}").into());
        }
        let view: serde_json::Value = serde_json::from_str(&body)?;
        let stage = view
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        if stage != last {
            println!(
                "  status          {stage} after {} ms",
                elapsed_millis(config.wait_seconds, deadline)
            );
            println!("  detail          {}", body.trim());
            last = stage.to_string();
        }
        if stage == "finalized" || stage == "rejected" {
            if stage == "finalized" {
                verify_commit_proof(&view)?;
            }
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "transaction {id} did not reach finality within {} s (last stage {stage})",
                config.wait_seconds
            )
            .into());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn elapsed_millis(wait_seconds: u64, deadline: Instant) -> u64 {
    let total = Duration::from_secs(wait_seconds);
    let remaining = deadline.saturating_duration_since(Instant::now());
    u64::try_from(total.saturating_sub(remaining).as_millis()).unwrap_or(u64::MAX)
}

/// Rebuilds the commit proof the node returned and checks it against `dag_root`.
///
/// This closes the loop for the client: finality is not just a string in a JSON
/// response, it is a Merkle path to the exact `dag_root` the certified header
/// commits.
fn verify_commit_proof(view: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let Some(proof) = view.get("commit_proof").filter(|value| !value.is_null()) else {
        println!("  commit proof    not included by the node");
        return Ok(());
    };
    let dag_root: [u8; 32] = hex::decode(
        view.get("dag_root")
            .and_then(serde_json::Value::as_str)
            .ok_or("the finalized view has no dag_root")?,
    )?
    .try_into()
    .map_err(|_| "dag_root is not 32 bytes")?;
    let vertex = view
        .get("vertex")
        .ok_or("the finalized view has no vertex")?;
    let vertex = VertexId {
        round: vertex
            .get("round")
            .and_then(serde_json::Value::as_u64)
            .ok_or("the vertex has no round")?,
        author: hex::decode(
            vertex
                .get("author")
                .and_then(serde_json::Value::as_str)
                .ok_or("the vertex has no author")?,
        )?,
        digest: hex::decode(
            vertex
                .get("digest")
                .and_then(serde_json::Value::as_str)
                .ok_or("the vertex has no digest")?,
        )?
        .try_into()
        .map_err(|_| "the vertex digest is not 32 bytes")?,
    };
    let steps = proof
        .get("steps")
        .and_then(serde_json::Value::as_array)
        .ok_or("the commit proof has no steps")?
        .iter()
        .map(|step| {
            Ok(crypto::merkle::ProofStep {
                sibling_is_left: step
                    .get("left")
                    .and_then(serde_json::Value::as_bool)
                    .ok_or("a proof step has no side")?,
                hash: hex::decode(
                    step.get("hash")
                        .and_then(serde_json::Value::as_str)
                        .ok_or("a proof step has no hash")?,
                )?
                .try_into()
                .map_err(|_| "a proof hash is not 32 bytes")?,
            })
        })
        .collect::<Result<Vec<_>, Box<dyn Error>>>()?;
    let proof = CommitProof {
        vertex,
        proof: crypto::merkle::MerkleProof {
            leaf_index: proof
                .get("leaf_index")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize,
            leaf_count: proof
                .get("leaf_count")
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize,
            steps,
        },
    };
    let verified = proof.verify(&dag_root);
    println!(
        "  commit proof    leaf {} of {}, verified against dag_root: {verified}",
        proof.proof.leaf_index, proof.proof.leaf_count
    );
    if !verified {
        return Err("the commit proof does not verify against the header's dag_root".into());
    }
    Ok(())
}

/// A minimal HTTP/1.1 request with `Connection: close`.
///
/// The client deliberately has no dependency beyond `std`: one request per
/// connection is all this command needs, and it keeps the number of moving parts
/// in the experiment small.
fn http(
    base: &str,
    method: &str,
    path: &str,
    body: Option<&str>,
) -> Result<(u16, String), Box<dyn Error>> {
    let address = base
        .trim()
        .trim_start_matches("http://")
        .trim_end_matches('/');
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(15)))?;
    stream.set_write_timeout(Some(Duration::from_secs(15)))?;
    let body = body.unwrap_or("");
    let request = format!(
        "{method} {path} HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\
         Content-Type: text/plain\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes())?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    let (head, body) = response
        .split_once("\r\n\r\n")
        .ok_or("malformed HTTP response: no header separator")?;
    let status = head
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or("malformed HTTP response: no status code")?;
    Ok((status, body.to_string()))
}
