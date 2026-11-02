//! Runs the network simulation across a range of committee sizes.
//!
//! One row per size, because the interesting questions are comparative: how commit
//! progress, delivery count, and agreement move as the committee grows. The number
//! that matters most is not the row, it is the delta between rows.

use std::error::Error;

use net::{SimConfig, Simulator};
use validator::commit_root;

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

/// Fault tolerance a BFT quorum of `n` provides.
fn fault_tolerance(n: usize) -> usize {
    n.saturating_sub(1) / 3
}

pub fn run(sizes: &[usize], jitter: u64, ticks: u64) -> Result<(), Box<dyn Error>> {
    if sizes.iter().any(|size| *size < 2) {
        return Err("every size must be at least 2".into());
    }
    if ticks == 0 {
        return Err("--ticks must be at least 1".into());
    }

    println!("== Network convergence by committee size ==");
    println!("  ticks: {ticks}, link latency 1 + 0..={jitter}, seed 7, no crashes");
    println!();
    let mut roots: Vec<(usize, [u8; 32])> = Vec::with_capacity(sizes.len());
    println!(
        "  {}  {}  {}  {}  {}  {}  {}  {}",
        pad("n", 4),
        pad("f", 3),
        pad("quorum", 7),
        pad("held", 6),
        pad("delivered", 10),
        pad("committed", 10),
        pad("same DAG", 9),
        pad("same order", 11)
    );

    for size in sizes {
        let config = SimConfig {
            validators: *size,
            latency_ticks: 1,
            jitter_ticks: jitter,
            crashed: None,
            seed: 7,
        };
        let mut simulator = Simulator::new(config)?;
        let summary = simulator.run(ticks)?;
        let committed = summary.committed.first().copied().unwrap_or(0);
        roots.push((*size, commit_root(simulator.nodes()[0].dag().order())));
        let note = if fault_tolerance(*size) == 0 {
            "  <-- quorum is everyone"
        } else {
            ""
        };
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}{note}",
            pad(&size.to_string(), 4),
            pad(&fault_tolerance(*size).to_string(), 3),
            pad(&(*size * 2 / 3 + 1).to_string(), 7),
            pad(&summary.held.first().copied().unwrap_or(0).to_string(), 6),
            pad(&summary.delivered.to_string(), 10),
            pad(&committed.to_string(), 10),
            pad(&summary.same_dag.to_string(), 9),
            pad(&summary.same_order.to_string(), 11)
        );
    }

    println!();
    println!("  f is the number of silent validators the quorum survives; at n below 4");
    println!("  it is zero, so a single failure halts the chain. Those rows are here to");
    println!("  show why the smallest BFT committee is four, not to recommend them.");
    println!();
    println!("  Deliveries grow ~n²: every vertex reaches every other validator. That is");
    println!("  the cost side of a bigger committee, and it is why the metadata order in");
    println!("  a real design matters more than the constant factor.");
    println!();
    println!("  The schedule is deterministic, so one seed can be unlucky: a size that");
    println!("  looks stalled usually just needs more ticks for its rounds to complete.");
    println!("  Compare shapes across sizes, not single cells, and raise --ticks before");
    println!("  concluding that a committee size stops committing.");

    println!();
    println!("  per-size commit roots (first node):");
    for (size, root) in &roots {
        println!("    n={size:<4} {}", hex::encode(&root[..6]));
    }

    Ok(())
}
