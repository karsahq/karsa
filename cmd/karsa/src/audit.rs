//! Audits a stored chain: does `state_root` actually follow from `dag_root`?
//!
//! A header commits two roots. `dag_root` is a Merkle root over the vertices in
//! commit order; `state_root` is a Merkle root over the account state. Nothing in
//! the header says the second came from the first, and until something checks it,
//! the link is trusted. That is the gap this command closes for a node holding the
//! data.
//!
//! # What is proved, and what is not
//!
//! The audit re-runs the chain from a trust anchor: it inserts the stored vertices
//! into a DAG (which verifies every consensus signature), lets the pacemaker
//! reproduce the commit order, recomputes the commit root at each height, applies
//! the batches in that order, and compares both roots with the certified header.
//! If a height matches, then for that height the vertex set the chain voted on is
//! exactly the set that produces the state the chain voted on.
//!
//! This is not a validity proof. It costs the verifier the same work as producing
//! the chain, and it needs the data, so it does not help a light client and it does
//! not survive pruning. A zk or fraud proof is what would make the claim small and
//! transferable; this makes it *checkable*, which is the cheaper half.
//!
//! # Trust anchors
//!
//! Two things are assumed rather than proved: the validator set (passed on the
//! command line, as in `karsa persist`) and the account genesis. When the store
//! still holds round 0 the audit re-derives everything from genesis. Once history
//! is pruned the anchor is the snapshot, and the audit says so instead of pretending
//! to have checked a prefix it no longer has.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;

use exec::State;
use store::{CertifiedHeader, Store};
use validator::{Dag, Header, HeaderChain, VertexId, commit_root};

use crate::chain;

/// What the audit found at one height.
struct Row {
    height: u64,
    round: u64,
    applied: usize,
    state_root: [u8; 32],
    dag_root: Option<[u8; 32]>,
    state_ok: bool,
    dag_ok: Option<bool>,
}

fn short(root: &[u8; 32]) -> String {
    hex::encode(&root[..6])
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn left(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

pub fn run(path: PathBuf, validators: usize, home: Option<PathBuf>) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("validators must be at least 4 so that a quorum is not everyone".into());
    }

    let home = home
        .map(|path| crate::home::Home::resolve(Some(path)))
        .transpose()?;
    let committee = chain::membership(validators, home.as_ref())?;

    let store = Store::open(&path)?;
    // Refuse a store written for another chain before spending a header chain's
    // worth of signature checks to discover it.
    let chain_id = chain::chain_id(home.as_ref())?;
    if let Ok(hash) = <[u8; 32]>::try_from(chain_id.as_slice()) {
        store.require_genesis(&hash)?;
    }
    let certified: Vec<CertifiedHeader> = store.headers()?;
    let Some(first) = certified.first() else {
        return Err(
            "this store holds no certified headers, so there is nothing to audit; \
             write one with `karsa persist --keep-history`"
                .into(),
        );
    };

    let set = committee.set.clone();
    let accounts = committee.accounts.clone();
    let genesis = Header::genesis(
        first.header.chain_id.clone(),
        first.header.epoch,
        chain::genesis_state(&accounts)?.state_root(),
        commit_root(&[]),
    );

    // Every height must extend the one before it and carry a quorum. This needs no
    // payload, so it is checked over the *whole* header chain even when the store
    // has been pruned.
    let mut verifier = HeaderChain::new(set.clone(), genesis.clone());
    for entry in &certified {
        verifier.advance(&entry.header, &entry.certificate)?;
    }

    let vertices = store.vertices()?;
    let batches: BTreeMap<[u8; 32], tx::batch::Batch> = store
        .batches()?
        .into_iter()
        .map(|batch| Ok((batch.digest()?, batch)))
        .collect::<Result<_, crypto::CryptoError>>()?;

    // A store that still holds round 0 can be re-derived from genesis; anything
    // else starts from the snapshot and says so.
    let lowest = vertices.iter().map(|vertex| vertex.round).min();
    let snapshot = store.snapshot()?;
    let full = lowest == Some(0);

    let (mut state, floor) = if full {
        (chain::genesis_state(&accounts)?, None)
    } else {
        let snapshot = snapshot.ok_or(
            "the store is pruned but holds no snapshot, so there is no trust anchor \
             to replay from",
        )?;
        (State::decode(&snapshot.state)?, Some(snapshot.round))
    };

    if let Some(round) = floor {
        let claimed = certified
            .iter()
            .find(|entry| entry.header.round == round)
            .map(|entry| entry.header.state_root);
        match claimed {
            Some(root) if root == state.state_root() => {}
            Some(root) => {
                return Err(format!(
                    "the snapshot at round {round} has state root {} but the certified header says {}",
                    short(&state.state_root()),
                    short(&root)
                )
                .into());
            }
            None => {
                return Err(
                    format!("the snapshot at round {round} is not covered by a header").into(),
                );
            }
        }
    }

    let mut dag = Dag::new(set);
    if let Some(round) = floor {
        dag.set_floor(round);
    }
    for vertex in &vertices {
        dag.insert(vertex.clone())?;
    }
    chain::settle(&mut dag, floor.map_or(1, |round| round + 1))?;

    let order: Vec<VertexId> = dag.order().to_vec();
    let mut headers_by_round: BTreeMap<u64, &Header> = BTreeMap::new();
    for entry in &certified {
        headers_by_round.insert(entry.header.round, &entry.header);
    }

    let mut applied = 0usize;
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut rows: Vec<Row> = Vec::new();
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
            applied += chain::apply_batch(&mut state, &accounts, batch, &mut rejected);
        }

        let Some(header) = headers_by_round.get(&round) else {
            continue;
        };
        let recomputed_state = state.state_root();
        let recomputed_dag = full.then(|| commit_root(&order[..cursor]));
        rows.push(Row {
            height: header.height,
            round,
            applied,
            state_root: recomputed_state,
            dag_root: recomputed_dag,
            state_ok: recomputed_state == header.state_root,
            dag_ok: recomputed_dag.map(|root| root == header.dag_root),
        });
    }

    // A certified height with no matching round in the replayed order means the
    // store cannot account for it at all.
    let missing = certified
        .iter()
        .filter(|entry| entry.header.round > floor.unwrap_or(0))
        .filter(|entry| !rows.iter().any(|row| row.height == entry.header.height))
        .count();

    println!("== Audit: does state_root follow from dag_root? ==");
    println!("  store:            {}", store.path().display());
    println!(
        "  headers:          {} certified, heights {}..={}, quorum checked on every one",
        certified.len(),
        certified.first().map_or(0, |entry| entry.header.height),
        certified.last().map_or(0, |entry| entry.header.height)
    );
    println!(
        "  genesis:          state {}  dag {}",
        short(&genesis.state_root),
        short(&genesis.dag_root)
    );
    println!(
        "  data:             {} vertices, {} batches",
        vertices.len(),
        batches.len()
    );
    println!(
        "  replayed order:   {} vertices over {} rounds",
        order.len(),
        rows.len()
    );
    if full {
        println!("  trust anchor:     genesis - the whole chain was re-derived");
    } else {
        println!(
            "  trust anchor:     snapshot at round {} (its root is a certified header)",
            floor.unwrap_or(0)
        );
        println!("  dag root:         not checkable below the snapshot; the payload is gone");
    }
    println!();
    println!(
        "  {}  {}  {}  {}  {}  {}",
        pad("height", 6),
        pad("round", 5),
        pad("applied", 7),
        pad("state root", 12),
        pad("dag root", 12),
        left("verdict", 8)
    );

    let mut state_ok = 0usize;
    let mut dag_ok = 0usize;
    let mut dag_checked = 0usize;
    for row in &rows {
        if row.state_ok {
            state_ok += 1;
        }
        let dag_column = match row.dag_root {
            Some(root) => {
                dag_checked += 1;
                if row.dag_ok == Some(true) {
                    dag_ok += 1;
                }
                short(&root)
            }
            None => "not checked".to_string(),
        };
        let verdict = match (row.state_ok, row.dag_ok) {
            (true, Some(true)) | (true, None) => "ok",
            (false, _) => "state mismatch",
            (true, Some(false)) => "dag mismatch",
        };
        println!(
            "  {}  {}  {}  {}  {}  {}",
            pad(&row.height.to_string(), 6),
            pad(&row.round.to_string(), 5),
            pad(&row.applied.to_string(), 7),
            pad(&short(&row.state_root), 12),
            pad(&dag_column, 12),
            left(verdict, 8)
        );
    }

    println!();
    println!(
        "  state root:       {state_ok} of {} heights re-derived",
        rows.len()
    );
    if dag_checked > 0 {
        println!("  dag root:         {dag_ok} of {dag_checked} heights re-derived");
    }
    println!(
        "  transactions:     {applied} applied, {} rejected by policy",
        rejected.values().sum::<usize>()
    );

    if missing > 0 {
        println!();
        println!("  unattributed:     {missing} certified heights have no data in this store");
    }

    if state_ok != rows.len() || dag_ok != dag_checked || missing > 0 {
        return Err("the store does not reproduce its own certified roots".into());
    }

    if !full {
        println!();
        println!("  applied counts from the snapshot, not from genesis.");
    }
    println!();
    if full {
        println!("  The certified state is the state these vertices produce. At every");
        println!("  height, the link between the two committed roots is checkable");
        println!("  rather than assumed.");
    } else {
        println!("  Above the snapshot, the certified state is the state these vertices");
        println!("  produce. Below it the DAG root is no longer checkable: pruning traded");
        println!("  auditability for disk, and the certified header chain is all that is");
        println!("  left to appeal to.");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    struct TempDir(PathBuf);

    impl TempDir {
        fn new() -> Self {
            let unique = COUNTER.fetch_add(1, Ordering::SeqCst);
            let path =
                std::env::temp_dir().join(format!("karsa-audit-{}-{unique}", std::process::id()));
            let _ = fs::remove_dir_all(&path);
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_store(dir: &TempDir, keep_history: bool) -> Store {
        let store = Store::open(&dir.0).unwrap();
        let simulation = chain::simulate(&chain::demo_chain_id(), 4, 4).unwrap();
        let accounts = chain::accounts(4).unwrap();
        crate::persist::save(
            &store,
            &simulation,
            2,
            &accounts,
            4,
            keep_history,
            &chain::demo_chain_id(),
        )
        .unwrap();
        store
    }

    #[test]
    fn a_full_history_store_is_re_derived_from_genesis() {
        let dir = TempDir::new();
        write_store(&dir, true);
        assert!(run(dir.0.clone(), 4, None).is_ok());
    }

    #[test]
    fn a_pruned_store_audits_only_above_its_snapshot() {
        let dir = TempDir::new();
        write_store(&dir, false);
        assert!(run(dir.0.clone(), 4, None).is_ok());
    }

    #[test]
    fn an_empty_store_has_nothing_to_audit() {
        let dir = TempDir::new();
        assert!(run(dir.0.clone(), 4, None).is_err());
    }

    #[test]
    fn a_forged_certified_root_is_caught() {
        let dir = TempDir::new();
        let store = write_store(&dir, true);

        // A quorum certifies a header whose state root is wrong. The certificate
        // is valid and the header still links to its predecessor, so only
        // re-deriving the state can catch it. Forging the last height keeps the
        // chain consistent: a lower height would break the successor's `previous`
        // and be rejected as a bad link instead, which is a different test.
        let (_, consensus) = chain::consensus_set(4).unwrap();
        let mut forged = store
            .headers()
            .unwrap()
            .last()
            .expect("the store has a head")
            .header
            .clone();
        forged.state_root = [0xAB; 32];
        let certificate = chain::certify(&consensus, &forged).unwrap();
        store.put_header(&forged, &certificate).unwrap();

        let error = run(dir.0.clone(), 4, None).unwrap_err().to_string();
        assert!(
            error.contains("reproduce"),
            "the audit must fail on the roots, not on the certificate: {error}"
        );
    }
}
