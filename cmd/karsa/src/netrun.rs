//! Runs a small validator network and reports whether it converges.
//!
//! This is the first command where no single process holds the truth. Each node
//! owns its own DAG, authors only when it can satisfy the reference rule, and
//! learns everything else from its peers. The question the output answers is the
//! only one that matters: did every live node end up with the same DAG and the
//! same commit sequence?

use std::error::Error;

use net::{SimConfig, Simulator};
use validator::commit_root;

fn pad(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn short(digest: &[u8; 32]) -> String {
    hex::encode(&digest[..6])
}

pub fn run(validators: usize, jitter: u64, crashed: Option<usize>) -> Result<(), Box<dyn Error>> {
    if validators < 4 {
        return Err("validators must be at least 4 so that a quorum is not everyone".into());
    }
    if crashed.is_some_and(|index| index >= validators) {
        return Err("--crashed must name a validator in the set".into());
    }

    let config = SimConfig {
        validators,
        latency_ticks: 1,
        jitter_ticks: jitter,
        crashed,
        seed: 7,
    };
    let mut simulator = Simulator::new(config)?;
    let summary = simulator.run(12)?;

    println!("== Karsa network: vertices exchanged between validators ==");
    println!("  chain:        karsa-net-1");
    println!("  validators:   {validators}");
    println!(
        "  schedule:     latency 1 + 0..={jitter} ticks per link, seed {}, logical ticks only",
        config.seed
    );
    println!(
        "  crashed:      {}",
        crashed.map_or_else(|| "none".to_string(), |index| format!("val-{index}"))
    );
    println!();
    println!(
        "  ticks: {}   deliveries: {}",
        summary.ticks, summary.delivered
    );
    println!();

    println!(
        "  {}  {}  {}  {}  commit root",
        pad("node", 8),
        pad("authored", 10),
        pad("held", 6),
        pad("committed", 10)
    );
    for index in 0..validators {
        let label = if crashed == Some(index) {
            format!("val-{index}*")
        } else {
            format!("val-{index}")
        };
        let root = commit_root(simulator.nodes()[index].dag().order());
        println!(
            "  {}  {}  {}  {}  {}",
            pad(&label, 8),
            pad(&summary.authored[index].to_string(), 10),
            pad(&summary.held[index].to_string(), 6),
            pad(&summary.committed[index].to_string(), 10),
            short(&root)
        );
    }

    let live_roots: Vec<[u8; 32]> = summary
        .commit_roots
        .iter()
        .enumerate()
        .filter(|(index, _)| crashed != Some(*index))
        .map(|(_, root)| *root)
        .collect();
    let distinct = live_roots.windows(2).all(|pair| pair[0] == pair[1]);

    println!();
    println!("  same DAG across live nodes:     {}", summary.same_dag);
    println!("  same commit sequence:           {}", summary.same_order);
    println!("  one commit root across live:    {distinct}");
    if let Some(index) = crashed {
        println!();
        println!(
            "  val-{index} authored nothing and received nothing; the other {} nodes",
            validators - 1
        );
        println!(
            "  still committed, because a quorum of {} is enough.",
            validators * 2 / 3 + 1
        );
    }

    Ok(())
}
