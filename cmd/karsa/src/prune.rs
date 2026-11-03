//! Applies a node's retention policy to its store.
//!
//! The policy itself lives in `node.toml`, because retention is a local cost and
//! not a chain constant (D28). This command is the runtime half: it reads the two
//! bounds, turns them into one round cutoff, and deletes what that cutoff says.
//!
//! An archive node is refused rather than silently ignored. Its whole purpose is
//! keeping everything; a prune command that accepted the flag and did nothing would
//! look like it had run.

use std::error::Error;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use store::{Retention, Store};

use crate::config::NodeConfig;
use crate::home::Home;

fn human(bytes: u64) -> String {
    let value = bytes as f64;
    if value >= 1e9 {
        format!("{:.1} GB", value / 1e9)
    } else if value >= 1e6 {
        format!("{:.1} MB", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{bytes} B")
    }
}

fn cutoff(cutoff: Option<u64>) -> String {
    match cutoff {
        Some(round) => format!("round {round}"),
        None => "none".to_string(),
    }
}

pub fn run(
    home_path: Option<PathBuf>,
    config_path: Option<PathBuf>,
    data_dir: Option<PathBuf>,
    dry_run: bool,
) -> Result<(), Box<dyn Error>> {
    let home = Home::resolve(home_path)?;
    let config_file = home.file(config_path, "node.toml");
    let config = NodeConfig::ensure(&config_file)?;

    let problems = config.problems();
    if !problems.is_empty() {
        let mut message = format!("{} has problems:", config_file.display());
        for problem in problems {
            message.push_str("\n  - ");
            message.push_str(&problem);
        }
        return Err(message.into());
    }
    if config.roles.archive {
        return Err("this node is an archive: it keeps everything and has nothing to prune".into());
    }

    let path = data_dir.unwrap_or_else(|| config.node.data_dir.clone());
    let store = Store::open(&path)?;
    let retention =
        Retention::from_days_and_gb(config.storage.retain_days, config.storage.max_disk_gb);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0);

    println!("== Pruning: {} ==", path.display());
    println!("  home              {}", home.dir().display());
    println!(
        "  role              {} ({})",
        config.role_label(),
        config.role_implies()
    );
    println!(
        "  policy            keep {} days, cap {} GB, whichever ends first",
        config.storage.retain_days, config.storage.max_disk_gb
    );

    let plan = store.plan(retention, now, 1)?;
    println!("  on disk           {}", human(plan.disk_bytes));
    println!("  snapshot covers   {}", cutoff(plan.snapshot_round));
    println!("  age cutoff        {}", cutoff(plan.age_cutoff));
    println!("  size cutoff       {}", cutoff(plan.size_cutoff));
    println!("  pruning below     {}", cutoff(plan.cutoff));
    if plan.cutoff.is_none()
        && plan.snapshot_round.is_none()
        && (plan.age_cutoff.is_some() || plan.size_cutoff.is_some())
    {
        println!();
        println!("  This store has no snapshot. Pruning without one would delete the");
        println!("  history a restart replays from, so the policy is held back until a");
        println!("  snapshot exists at or above the cutoff.");
    }

    if dry_run {
        println!();
        println!("  dry run: nothing was deleted");
        return Ok(());
    }

    let report = store.prune(retention, now, 1)?;
    println!();
    println!("  vertices removed  {}", report.vertices);
    println!("  batches dropped   {}", report.batches_dropped);
    println!("  batches held      {}", report.batches_held);
    println!("  bytes freed       {}", human(report.bytes_freed));
    println!("  on disk after     {}", human(store.disk_bytes()?));
    if report.cap_shortfall > 0 {
        println!(
            "  cap shortfall     {} still above the cap",
            human(report.cap_shortfall)
        );
        println!("                    shards and headers are kept forever, and a payload no shard");
        println!("                    backs is never dropped: deleting it would lose data");
    }
    Ok(())
}
