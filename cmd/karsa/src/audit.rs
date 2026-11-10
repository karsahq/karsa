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
use validator::{Dag, EpochSchedule, Header, HeaderChain, VertexId, commit_root};

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
    let live = store.live_snapshot()?;
    let transition_certificate = store.set_change()?.or_else(|| {
        live.as_ref()
            .and_then(|snapshot| snapshot.transition.clone())
    });

    let set = committee.set.clone();
    let accounts = committee.accounts.clone();
    let genesis = match store.genesis_header()? {
        Some(header) => header,
        None => Header::genesis(
            first.header.chain_id.clone(),
            first.header.epoch,
            chain::genesis_state(&accounts)?.state_root(),
            commit_root(&[]),
        ),
    };

    // Every height must extend the one before it and carry a quorum. This needs no
    // payload, so it is checked over the *whole* header chain even when the store
    // has been pruned. A snapshot join has no headers below its anchor; the
    // anchor's certificate is checked once and the chain starts there.
    let schedule = EpochSchedule::advancing(set.epoch, committee.epoch_rounds);
    let transition = match &transition_certificate {
        Some(certificate) => Some(certificate.verify(&set)?),
        None => None,
    };
    let mut verifier = if let Some(live) = &live {
        let id = live.header.id()?;
        if live.certificate.chain_id != live.header.chain_id
            || live.certificate.epoch != live.header.epoch
            || live.certificate.round != live.header.round
            || live.certificate.vertex_id != id
        {
            return Err("the live snapshot certificate does not name its anchor".into());
        }
        live.certificate.verify_quorum(&set)?;
        match &transition_certificate {
            Some(certificate) => HeaderChain::with_schedule_and_change(
                set.clone(),
                certificate.new_set.clone(),
                certificate.change.activation_epoch,
                live.header.clone(),
                schedule,
            )?,
            None => HeaderChain::with_schedule(set.clone(), live.header.clone(), schedule),
        }
    } else {
        match &transition_certificate {
            Some(certificate) => HeaderChain::with_schedule_and_change(
                set.clone(),
                certificate.new_set.clone(),
                certificate.change.activation_epoch,
                genesis.clone(),
                schedule,
            )?,
            None => HeaderChain::with_schedule(set.clone(), genesis.clone(), schedule),
        }
    };
    for entry in &certified {
        if live
            .as_ref()
            .is_some_and(|live| entry.header.height <= live.header.height)
        {
            continue;
        }
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

    let (mut state, floor, prefix_len, settle_from, mut applied) = if let Some(live) = &live {
        let state = State::decode(&live.state)?;
        if state.state_root() != live.header.state_root {
            return Err("the live snapshot state does not match its anchor root".into());
        }
        if live.prefix.len().checked_add(live.order.len()) != Some(live.order_len) {
            return Err("the live snapshot order length does not match its prefix and tail".into());
        }
        if live.prefix.root_at(&live.order, live.order.len()) != Some(live.header.dag_root) {
            return Err("the live snapshot order does not reproduce its anchor dag_root".into());
        }
        let applied = usize::try_from(live.applied)
            .map_err(|_| format!("{} applied transactions do not fit", live.applied))?;
        (state, live.floor, live.order_len, live.cursor, applied)
    } else if full {
        let state = match store.genesis_state()? {
            Some(bytes) => State::decode(&bytes)?,
            None => chain::genesis_state(&accounts)?,
        };
        (state, None, 0, 1, 0)
    } else {
        let snapshot = snapshot.ok_or(
            "the store is pruned but holds no snapshot, so there is no trust anchor \
             to replay from",
        )?;
        let round = snapshot.round;
        let state = State::decode(&snapshot.state)?;
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
        (state, Some(round), 0, round + 1, 0)
    };

    let mut dag = Dag::with_epoch_length(set, committee.epoch_rounds);
    if let Some(certificate) = &transition_certificate {
        dag.adopt_set_change(certificate)?;
    }
    if let Some(live) = &live {
        dag.seed_prefix(live.prefix.clone(), live.order.clone());
    }
    if let Some(round) = floor {
        dag.set_floor(round);
    }
    for vertex in &vertices {
        dag.insert(vertex.clone())?;
    }
    chain::settle(&mut dag, settle_from)?;

    let base = dag.prefix().len();
    let order: Vec<VertexId> = dag.order().to_vec();
    let order_len = dag.order_len();
    let mut headers_by_round: BTreeMap<u64, &Header> = BTreeMap::new();
    for entry in &certified {
        headers_by_round.insert(entry.header.round, &entry.header);
    }

    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut rows: Vec<Row> = Vec::new();

    if full || live.is_some() {
        // A commit can include only part of a round, so a round boundary is not
        // the prefix a header commits. The header's `dag_root` names that prefix
        // exactly; walk the order once and match it. This is an offline audit, so
        // the repeated prefix root is acceptable; it is the check, not a hot path.
        let mut previous = prefix_len;
        for entry in &certified {
            let header = &entry.header;
            if live
                .as_ref()
                .is_some_and(|live| header.height <= live.header.height)
            {
                continue;
            }
            let mut cursor = previous;
            let mut root = match dag.commit_root_at(cursor) {
                Some(root) => root,
                None => return Err(format!("the committed order has no root at {cursor}").into()),
            };
            while root != header.dag_root && cursor < order_len {
                cursor += 1;
                root = match dag.commit_root_at(cursor) {
                    Some(root) => root,
                    None => {
                        return Err(format!("the committed order has no root at {cursor}").into());
                    }
                };
            }
            if root != header.dag_root {
                rows.push(Row {
                    height: header.height,
                    round: header.round,
                    applied,
                    state_root: state.state_root(),
                    dag_root: Some(root),
                    state_ok: false,
                    dag_ok: Some(false),
                });
                continue;
            }
            for id in &order[previous - base..cursor - base] {
                let Some(vertex) = dag.get(id.round, &id.author) else {
                    continue;
                };
                let Some(batch) = batches.get(&vertex.payload_hash) else {
                    continue;
                };
                applied += chain::apply_batch(&mut state, &accounts, batch, &mut rejected);
            }
            previous = cursor;
            let recomputed_state = state.state_root();
            rows.push(Row {
                height: header.height,
                round: header.round,
                applied,
                state_root: recomputed_state,
                dag_root: Some(root),
                state_ok: recomputed_state == header.state_root,
                dag_ok: Some(root == header.dag_root),
            });
        }
    } else {
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
            rows.push(Row {
                height: header.height,
                round,
                applied,
                state_root: recomputed_state,
                dag_root: None,
                state_ok: recomputed_state == header.state_root,
                dag_ok: None,
            });
        }
    }

    // A certified height with no matching round in the replayed order means the
    // store cannot account for it at all. A snapshot's anchor is the trust root,
    // so it is not a missing row.
    let missing = certified
        .iter()
        .filter(|entry| entry.header.round > floor.unwrap_or(0))
        .filter(|entry| {
            !live
                .as_ref()
                .is_some_and(|live| entry.header.height <= live.header.height)
        })
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
    if let Some(transition) = &transition {
        println!(
            "  set change:       epoch {} -> {}, {} -> {} validators (old-set quorum)",
            transition.old_epoch, transition.new_epoch, transition.old_size, transition.new_size
        );
    }
    println!(
        "  replayed order:   {} vertices over {} rounds",
        order_len,
        rows.len()
    );
    if full {
        println!("  trust anchor:     genesis - the whole chain was re-derived");
    } else if let Some(live) = &live {
        println!(
            "  trust anchor:     live snapshot at height {} round {} (certificate verified)",
            live.header.height, live.header.round
        );
        println!(
            "  snapshot floor:   {}",
            live.floor
                .map_or_else(|| "none".to_string(), |floor| floor.to_string())
        );
        println!("  audit window:     heights above {}", live.header.height);
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
        if live.is_some() {
            println!("  applied counts from the live snapshot anchor, not from genesis.");
        } else {
            println!("  applied counts from the snapshot, not from genesis.");
        }
    }
    println!();
    if full {
        println!("  The certified state is the state these vertices produce. At every");
        println!("  height, the link between the two committed roots is checkable");
        println!("  rather than assumed.");
    } else if live.is_some() {
        println!("  Above the live snapshot anchor, the certified state is the state these");
        println!("  vertices produce. The anchor itself is trusted because its quorum");
        println!("  certificate verified; the prefix below it is not in this store.");
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
