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

use exec::State;
use store::{Roots, Store};
use validator::{Dag, Pacemaker, PacemakerConfig, Step, VertexId, commit_root};

use crate::chain;

/// What a save wrote.
struct Saved {
    vertices_before: usize,
    vertices_after: usize,
    batches_after: usize,
    applied_total: usize,
    prune_round: u64,
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

/// Writes the vertices, the batches, the snapshot, and the roots a node reported.
fn save(
    store: &Store,
    simulation: &chain::Simulation,
    prune_round: u64,
    accounts: &[chain::Account],
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
    for batch in simulation.batches.values() {
        store.put_batch(batch)?;
    }

    let (snapshot, _) = apply_until(simulation, accounts, prune_round)?;
    store.put_snapshot(prune_round, &snapshot.encode()?)?;

    let roots = Roots {
        commit_root: commit_root(simulation.dag.order()),
        state_root: snapshot.state_root(),
    };
    store.put_roots(roots)?;
    store.sync()?;

    store.prune_below(prune_round)?;

    Ok(Saved {
        vertices_before,
        vertices_after: store.vertices()?.len(),
        batches_after: store.batches()?.len(),
        applied_total: simulation.report.applied,
        prune_round,
        roots: Roots {
            commit_root: roots.commit_root,
            state_root: simulation.state.state_root(),
        },
    })
}

/// Rebuilds the chain from a snapshot plus the retained tail.
fn replay(store: &Store, validators: usize) -> Result<Replayed, Box<dyn Error>> {
    let snapshot = store
        .snapshot()?
        .ok_or("the store has no snapshot; nothing to replay from")?;
    let mut state = State::decode(&snapshot.state)?;

    let (set, _consensus) = chain::consensus_set(validators)?;
    let mut dag = Dag::new(set);
    dag.set_floor(snapshot.round);

    let vertices = store.vertices()?;
    for vertex in &vertices {
        dag.insert(vertex.clone())?;
    }

    let committed = settle(&mut dag, snapshot.round + 1)?;

    let mut batches = BTreeMap::new();
    for batch in store.batches()? {
        batches.insert(batch.digest()?, batch);
    }

    let accounts = chain::accounts(validators)?;
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
        applied += chain::apply_batch(&mut state, &accounts, batch, &mut rejected);
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

/// Replays the pacemaker until it stops making progress.
fn settle(dag: &mut Dag, start_round: u64) -> Result<usize, Box<dyn Error>> {
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

pub fn run(path: PathBuf, validators: usize, rounds: u64) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("validators must be at least 4 so that a quorum is not everyone".into());
    }

    let store = Store::open(&path)?;
    let saved = {
        let simulation = chain::simulate(validators, rounds)?;
        let accounts = chain::accounts(validators)?;
        let prune_round = (rounds / 2).max(1);
        save(&store, &simulation, prune_round, &accounts)?
        // The simulation is dropped here: everything below reads from disk only.
    };
    let replayed = replay(&store, validators)?;
    let stored = store.roots()?;

    println!("== Persistence: save, prune, drop, reopen, replay ==");
    println!("  store:          {}", store.path().display());
    println!(
        "  saved:          {} vertices, pruned to {} at round {} ({} batches kept)",
        saved.vertices_before, saved.vertices_after, saved.prune_round, saved.batches_after
    );
    println!(
        "  kept:           {} vertices, {} batches (only what the tail names)",
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
            let simulation = chain::simulate(4, 4).unwrap();
            save(&store, &simulation, 2, &accounts).unwrap()
        };
        let replayed = replay(&store, 4).unwrap();

        assert_eq!(replayed.state_root, saved.roots.state_root);
        assert!(
            replayed.applied < saved.applied_total,
            "the snapshot did work"
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
            let simulation = chain::simulate(4, 2).unwrap();
            save(&store, &simulation, 0, &accounts).unwrap()
        };
        assert_eq!(
            saved.vertices_after + 4,
            saved.vertices_before,
            "round 0 holds one vertex per validator"
        );
    }
}
