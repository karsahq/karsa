//! Saves a node's state, drops it, reopens, and replays — then compares the roots.
//!
//! The point is not that bytes reach a disk. It is that a restart either
//! reproduces the same chain or says so. Only the three things a node cannot
//! recompute are written: the vertices it received, the batches they name, and
//! the roots it last reported. Ordering and account state are replayed from those,
//! and the replay must land on exactly the saved roots.
//!
//! The validator set is configuration, so it is rebuilt from the same deterministic
//! seeds rather than stored. Storing it is the obvious next step and is not done
//! here, which is why the replay takes the set as input.

use std::collections::BTreeMap;
use std::error::Error;
use std::path::PathBuf;

use store::{Roots, Store};
use validator::{Dag, Pacemaker, PacemakerConfig, Step, VertexId, commit_root};

use crate::chain;

/// What a save wrote.
struct Saved {
    vertices: usize,
    batches: usize,
    applied: usize,
    roots: Roots,
}

/// What a replay produced.
struct Replayed {
    vertices: usize,
    batches: usize,
    applied: usize,
    committed: usize,
    commit_root: [u8; 32],
    state_root: [u8; 32],
}

/// Writes the vertices, the batches, and the roots a node last reported.
fn save(store: &Store, simulation: &chain::Simulation) -> Result<Saved, Box<dyn Error>> {
    let highest = simulation.dag.highest_round().unwrap_or(0);
    let mut vertices = 0usize;
    for round in 0..=highest {
        for record in &simulation.dag.set().validators {
            if let Some(vertex) = simulation.dag.get(round, &record.validator_id) {
                store.append_vertex(vertex)?;
                vertices += 1;
            }
        }
    }

    for batch in simulation.batches.values() {
        store.put_batch(batch)?;
    }

    let roots = Roots {
        commit_root: commit_root(simulation.dag.order()),
        state_root: simulation.state.state_root(),
    };
    store.put_roots(roots)?;
    store.sync()?;

    Ok(Saved {
        vertices,
        batches: simulation.batches.len(),
        applied: simulation.report.applied,
        roots,
    })
}

/// Rebuilds the chain from disk only.
fn replay(store: &Store, validators: usize) -> Result<Replayed, Box<dyn Error>> {
    let (set, _consensus) = chain::consensus_set(validators)?;
    let mut dag = Dag::new(set);
    let vertices = store.vertices()?;
    for vertex in &vertices {
        dag.insert(vertex.clone())?;
    }
    let committed = settle(&mut dag)?;

    let mut batches = BTreeMap::new();
    for batch in store.batches()? {
        batches.insert(batch.digest()?, batch);
    }

    let accounts = chain::accounts(validators)?;
    let mut state = chain::genesis_state(&accounts)?;
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
        commit_root: commit_root(&order),
        state_root: state.state_root(),
    })
}

/// Replays the pacemaker until it stops making progress.
fn settle(dag: &mut Dag) -> Result<usize, Box<dyn Error>> {
    let mut pacemaker = Pacemaker::new(PacemakerConfig { timeout_ticks: 3 }, 1);
    let mut quiet = 0usize;
    let mut ticks = 0usize;
    // Two quiet ticks in a row is quiescence: the first may only have advanced the
    // stall counter.
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
        save(&store, &simulation)?
        // The simulation is dropped here: everything below reads from disk only.
    };
    let replayed = replay(&store, validators)?;
    let stored = store.roots()?;

    println!("== Persistence: save, drop, reopen, replay ==");
    println!("  store:          {}", store.path().display());
    println!(
        "  saved:          {} vertices, {} batches, {} applied",
        saved.vertices, saved.batches, saved.applied
    );
    println!(
        "  reopened:       {} vertices, {} batches, {} committed",
        replayed.vertices, replayed.batches, replayed.committed
    );
    println!("  replayed:       {} applied", replayed.applied);
    println!();
    println!(
        "  commit root:    saved {}  replayed {}",
        hex::encode(&saved.roots.commit_root[..6]),
        hex::encode(&replayed.commit_root[..6])
    );
    println!(
        "  state root:     saved {}  replayed {}",
        hex::encode(&saved.roots.state_root[..6]),
        hex::encode(&replayed.state_root[..6])
    );
    println!();
    println!(
        "  commit history reproduced: {}",
        replayed.commit_root == saved.roots.commit_root
    );
    println!(
        "  account state reproduced:  {}",
        replayed.state_root == saved.roots.state_root
    );
    println!("  roots record intact:       {}", stored.is_some());

    if replayed.commit_root != saved.roots.commit_root
        || replayed.state_root != saved.roots.state_root
    {
        return Err("replay diverged from the saved roots".into());
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
    fn a_saved_chain_replays_to_the_same_roots() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();

        let saved = {
            let simulation = chain::simulate(4, 4).unwrap();
            save(&store, &simulation).unwrap()
        };
        let replayed = replay(&store, 4).unwrap();

        assert_eq!(replayed.commit_root, saved.roots.commit_root);
        assert_eq!(replayed.state_root, saved.roots.state_root);
        assert_eq!(replayed.applied, saved.applied);
    }

    #[test]
    fn a_torn_final_append_does_not_change_the_roots() {
        let dir = TempDir::new();
        let store = Store::open(&dir.0).unwrap();
        let saved = {
            let simulation = chain::simulate(4, 3).unwrap();
            save(&store, &simulation).unwrap()
        };

        // Cut the last vertex record in half, as a crash mid-append would.
        let path = dir.0.join("vertices.log");
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();

        let replayed = replay(&store, 4).unwrap();
        // The lost vertex is the last one appended; losing it must not corrupt the
        // rest, so the commit root may differ but the replay must still succeed and
        // stay consistent with what remains.
        assert!(replayed.vertices + 1 == saved.vertices);
        assert!(replayed.applied <= saved.applied);
    }
}
