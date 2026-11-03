//! Saves a node's state, drops it, reopens, and replays — then compares the roots.
//!
//! The point is not that bytes reach a disk. It is that a restart either
//! reproduces the same chain or says so.
//!
//! # Why a snapshot
//!
//! Replaying only vertices makes restart cost grow without bound: every restart
//! re-executes every transaction since genesis. So the store also keeps a state
//! snapshot at a prune point, drops every vertex and batch at or below it, and a
//! restart replays only the tail. The vertices are still needed above the snapshot
//! — the commit rule walks them — but everything below is already in the state.
//!
//! The cost of that is stated in `docs/crypto-registry.md` §8.16: a pruned node can
//! no longer re-validate the reference rule across the boundary, and it cannot
//! reproduce the historical commit root, because the sequence it committed is gone.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;

use erasure::Code;
use exec::State;
use store::{PruneReport, Roots, Store};
use validator::{Dag, VertexId, commit_root};

use crate::chain;

fn human(bytes: u64) -> String {
    let value = bytes as f64;
    if value >= 1e6 {
        format!("{:.1} MB", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{bytes} B")
    }
}

/// What a save wrote.
pub(crate) struct Saved {
    vertices_before: usize,
    batches_before: usize,
    applied_total: usize,
    prune_round: u64,
    keep_history: bool,
    report: PruneReport,
    roots: Roots,
}

/// What a replay produced.
struct Replayed {
    vertices: usize,
    batches: usize,
    applied: usize,
    committed: usize,
    state_root: [u8; 32],
    tail_commit_root: [u8; 32],
}

/// Applies every committed batch at or below `round` into `state`.
fn apply_until(
    simulation: &chain::Simulation,
    accounts: &[chain::Account],
    round: u64,
) -> Result<(State, usize), Box<dyn Error>> {
    let mut state = chain::genesis_state(accounts)?;
    let mut applied = 0usize;
    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    for id in simulation.dag.order() {
        if id.round > round {
            break;
        }
        let Some(vertex) = simulation.dag.get(id.round, &id.author) else {
            continue;
        };
        let Some(batch) = simulation.batches.get(&vertex.payload_hash) else {
            continue;
        };
        applied += chain::apply_batch(&mut state, accounts, batch, &mut rejected);
    }
    Ok((state, applied))
}

/// Writes the vertices, the batches, one shard per batch, the snapshot, and the
/// roots a node reported.
///
/// The shard is what makes pruning safe: the node drops a payload only when a
/// shard of it is already on disk, so the chain is never the sole holder of data
/// it then forgets. One store plays one validator here, so it keeps shard 0.
pub(crate) fn save(
    store: &Store,
    simulation: &chain::Simulation,
    prune_round: u64,
    accounts: &[chain::Account],
    validators: usize,
    keep_history: bool,
    chain_id: &[u8],
) -> Result<Saved, Box<dyn Error>> {
    let highest = simulation.dag.highest_round().unwrap_or(0);
    let mut vertices_before = 0usize;
    for round in 0..=highest {
        for record in &simulation.dag.set().validators {
            if let Some(vertex) = simulation.dag.get(round, &record.validator_id) {
                store.append_vertex(vertex)?;
                vertices_before += 1;
            }
        }
    }
    // The directory now remembers which chain it belongs to, so opening it against
    // another genesis is refused instead of silently producing a different root.
    if let Ok(hash) = <[u8; 32]>::try_from(chain_id) {
        store.bind_genesis(&hash)?;
    }

    let mut batches_before = 0usize;
    let code = Code::new(validators - validators / 3, validators)?;
    for batch in simulation.batches.values() {
        store.put_batch(batch)?;
        let encoded = code.encode(&batch.encode()?)?;
        if let Some(shard) = encoded.shards.first() {
            store.put_shard(&batch.digest()?, 0, shard)?;
        }
        batches_before += 1;
    }

    let (snapshot, _) = apply_until(simulation, accounts, prune_round)?;
    store.put_snapshot(prune_round, &snapshot.encode()?)?;

    let roots = Roots {
        commit_root: commit_root(simulation.dag.order()),
        state_root: snapshot.state_root(),
    };
    store.put_roots(roots)?;
    // The certified headers are what an auditor has to compare against. Without
    // them the stored roots are local arithmetic with nothing to appeal to.
    for (header, certificate) in &simulation.certified {
        store.put_header(header, certificate)?;
    }
    store.sync()?;

    let report = if keep_history {
        PruneReport::default()
    } else {
        store.prune_below(prune_round, 1)?
    };

    Ok(Saved {
        vertices_before,
        batches_before,
        applied_total: simulation.report.applied,
        prune_round,
        keep_history,
        report,
        roots: Roots {
            commit_root: roots.commit_root,
            state_root: simulation.state.state_root(),
        },
    })
}

/// Rebuilds the chain from a snapshot plus the retained tail.
fn replay(
    store: &Store,
    set: validator::ValidatorSet,
    accounts: &[chain::Account],
    chain_id: &[u8],
) -> Result<Replayed, Box<dyn Error>> {
    if let Ok(hash) = <[u8; 32]>::try_from(chain_id) {
        store.require_genesis(&hash)?;
    }
    let snapshot = store
        .snapshot()?
        .ok_or("the store has no snapshot; nothing to replay from")?;
    let mut state = State::decode(&snapshot.state)?;

    let mut dag = Dag::new(set);
    dag.set_floor(snapshot.round);

    let vertices = store.vertices()?;
    for vertex in &vertices {
        dag.insert(vertex.clone())?;
    }

    let committed = chain::settle(&mut dag, snapshot.round + 1)?;

    let mut batches = BTreeMap::new();
    for batch in store.batches()? {
        batches.insert(batch.digest()?, batch);
    }

    let mut rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut applied = 0usize;
    let order: Vec<VertexId> = dag.order().to_vec();
    for id in &order {
        let Some(vertex) = dag.get(id.round, &id.author) else {
            continue;
        };
        let Some(batch) = batches.get(&vertex.payload_hash) else {
            continue;
        };
        applied += chain::apply_batch(&mut state, accounts, batch, &mut rejected);
    }

    Ok(Replayed {
        vertices: vertices.len(),
        batches: batches.len(),
        applied,
        committed,
        state_root: state.state_root(),
        tail_commit_root: commit_root(&order),
    })
}

pub fn run(
    path: PathBuf,
    validators: usize,
    rounds: u64,
    keep_history: bool,
    home: Option<PathBuf>,
) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("validators must be at least 4 so that a quorum is not everyone".into());
    }

    let home = home
        .map(|path| crate::home::Home::resolve(Some(path)))
        .transpose()?;
    let committee = chain::membership(validators, home.as_ref())?;
    let store = Store::open(&path)?;
    let chain_id = chain::chain_id(home.as_ref())?;
    let saved = {
        let simulation = chain::simulate_with(&chain_id, &committee, rounds)?;
        let prune_round = (rounds / 2).max(1);
        save(
            &store,
            &simulation,
            prune_round,
            &committee.accounts,
            committee.consensus.len(),
            keep_history,
            &chain_id,
        )?
        // The simulation is dropped here: everything below reads from disk only.
    };
    let replayed = replay(&store, committee.set, &committee.accounts, &chain_id)?;
    let stored = store.roots()?;

    println!("== Persistence: save, prune, drop, reopen, replay ==");
    println!("  store:          {}", store.path().display());
    println!(
        "  saved:          {} vertices, {} batches, one shard each, {} certified headers",
        saved.vertices_before,
        saved.batches_before,
        store.headers()?.len()
    );
    if saved.keep_history {
        println!("  pruned:         nothing; every payload is on disk for an audit");
    } else {
        println!(
            "  pruned:         {} vertices and {} payloads below round {} ({} left, {} freed)",
            saved.report.vertices,
            saved.report.batches_dropped,
            saved.prune_round,
            saved.report.batches_held,
            human(saved.report.bytes_freed)
        );
    }
    println!(
        "  kept:           {} vertices, {} batches (the tail plus the window)",
        replayed.vertices, replayed.batches
    );
    println!(
        "  applied:        {} in total, {} replayed after the snapshot",
        saved.applied_total, replayed.applied
    );
    println!();
    println!(
        "  state root:     saved {}  replayed {}",
        hex::encode(&saved.roots.state_root[..6]),
        hex::encode(&replayed.state_root[..6])
    );
    println!(
        "  tail commit:    {} over {} committed rounds",
        hex::encode(&replayed.tail_commit_root[..6]),
        replayed.committed
    );
    println!();
    println!(
        "  account state reproduced: {}",
        replayed.state_root == saved.roots.state_root
    );
    println!("  roots record intact:      {}", stored.is_some());
    println!(
        "  replay work:              {} of {} transactions ({:.0}% skipped)",
        replayed.applied,
        saved.applied_total,
        if saved.applied_total == 0 {
            0.0
        } else {
            100.0 * (1.0 - replayed.applied as f64 / saved.applied_total as f64)
        }
    );

    if replayed.state_root != saved.roots.state_root {
        return Err("replay diverged from the saved state root".into());
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
                std::env::temp_dir().join(format!("karsa-persist-{}-{unique}", std::process::id()));
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

    #[test]
    fn a_pruned_store_replays_to_the_same_state_root() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let accounts = chain::accounts(4).unwrap();

        let saved = {
            let simulation = chain::simulate(&chain::demo_chain_id(), 4, 4).unwrap();
            save(
                &store,
                &simulation,
                2,
                &accounts,
                4,
                false,
                &chain::demo_chain_id(),
            )
            .unwrap()
        };
        let (set, _) = chain::consensus_set(4).unwrap();
        let replayed = replay(&store, set, &accounts, &chain::demo_chain_id()).unwrap();

        assert_eq!(replayed.state_root, saved.roots.state_root);
        assert!(
            replayed.applied < saved.applied_total,
            "the snapshot did work: replayed {} of {} applied transactions",
            replayed.applied,
            saved.applied_total
        );
        assert!(
            replayed.vertices < saved.vertices_before,
            "pruning removed vertices"
        );
    }

    #[test]
    fn pruning_at_zero_drops_only_the_genesis_round() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let accounts = chain::accounts(4).unwrap();

        let saved = {
            let simulation = chain::simulate(&chain::demo_chain_id(), 4, 2).unwrap();
            save(
                &store,
                &simulation,
                0,
                &accounts,
                4,
                false,
                &chain::demo_chain_id(),
            )
            .unwrap()
        };
        assert_eq!(
            saved.report.vertices, 4,
            "round 0 holds one vertex per validator"
        );
        assert_eq!(
            saved.report.batches_dropped, 0,
            "round 0 carries no payload, so nothing can be dropped"
        );
        assert!(saved.report.bytes_freed > 0, "the vertex log still shrank");
    }

    #[test]
    fn a_pruned_payload_is_dropped_only_when_its_shard_is_on_disk() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let accounts = chain::accounts(4).unwrap();

        let saved = {
            let simulation = chain::simulate(&chain::demo_chain_id(), 4, 6).unwrap();
            save(
                &store,
                &simulation,
                3,
                &accounts,
                4,
                false,
                &chain::demo_chain_id(),
            )
            .unwrap()
        };
        assert!(
            saved.report.batches_dropped > 0,
            "payloads behind the window are dropped"
        );
        assert_eq!(
            saved.report.batches_held, 0,
            "every dropped payload has a shard left on disk"
        );
        assert_eq!(
            store.shards().unwrap().len(),
            saved.batches_before,
            "the shards are the part that survives"
        );
        assert_eq!(
            store.batches().unwrap().len(),
            saved.batches_before - saved.report.batches_dropped
        );
    }
}
