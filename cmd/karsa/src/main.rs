//! Karsa command-line entry point.
//!
//! One binary with subcommands, in the style of the Cosmos daemons:
//!
//! ```text
//! karsa node                       run the demo HTTP node
//! karsa sample-tx                  print a signed demo envelope as hex
//! karsa demo                       print the registry and a sample payload
//! karsa acvp <vectors.json>        check NIST ML-DSA or SLH-DSA sigVer vectors
//! karsa register-demo [epoch]      print a signed validator key rotation body
//! karsa certify [n]                build, encode, and verify a DAG certificate
//! karsa dagsim                     run the DAG commit rule on fixed scenarios
//! karsa chain                      order and execute a small chain end to end
//! karsa net                        exchange vertices between nodes and check convergence
//! karsa persist                    save, drop, reopen, and replay a node's state
//! karsa migrate                    rotate validator keys across an epoch boundary
//! karsa sigbench                   measure transaction verification throughput
//! karsa sweep                      run the network simulation across committee sizes
//! karsa bandwidth                  model per-node dissemination bandwidth
//! karsa dagbench                   measure DAG certificate and header cost
//! karsa loadtest [count] [conc]    drive the node and report tx/s
//! ```

mod acvp;
mod bandwidth;
mod certify;
mod chain;
mod dagbench;
mod dagsim;
mod demo;
mod loadtest;
mod migrate;
mod netrun;
mod node;
mod persist;
mod sigbench;
mod sweep;

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "karsa",
    version,
    about = "Karsa crypto-agile chain experiment",
    arg_required_else_help = true
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the demo HTTP node until interrupted.
    Node,
    /// Print a signed demo transaction envelope as hex on stdout.
    SampleTx,
    /// Print the signed key registration body for the demo validator.
    RegisterDemo {
        /// Epoch at which the new key becomes active.
        #[arg(default_value_t = 1)]
        activation_epoch: u64,
    },
    /// Build, encode, and verify a DAG-BFT certificate, then show rejections.
    Certify {
        /// Number of validators in the demo set.
        #[arg(default_value_t = 10)]
        validators: usize,
    },
    /// Run the DAG commit rule on fixed scenarios.
    Dagsim {
        /// Validators in the simulated committee (at least 4).
        #[arg(default_value_t = 4)]
        validators: usize,
    },
    /// Order and execute a small chain end to end.
    Chain {
        /// Validators in the simulated committee (at least 4).
        #[arg(default_value_t = 4)]
        validators: usize,
        /// Rounds that carry transactions.
        #[arg(long, default_value_t = 4)]
        rounds: u64,
    },
    /// Run the network simulation across a range of committee sizes.
    Sweep {
        /// Comma-separated committee sizes, e.g. 2,4,6,8,10.
        #[arg(long, default_value = "4,6,8,10")]
        sizes: String,
        /// Extra per-link delay, derived from a seeded hash.
        #[arg(long, default_value_t = 2)]
        jitter: u64,
        /// Logical ticks per size. Rounds need a few ticks each to complete.
        #[arg(long, default_value_t = 16)]
        ticks: u64,
    },
    /// Measure transaction signature verification throughput and scaling.
    Sigbench {
        /// Signature algorithm to measure.
        #[arg(long, default_value = "ed25519")]
        algorithm: String,
        /// Highest thread count to measure.
        #[arg(long, default_value_t = 8)]
        threads: usize,
    },
    /// Rotate validator keys across an epoch boundary and keep committing.
    Migrate {
        /// Validators in the simulated committee (at least 4).
        #[arg(default_value_t = 4)]
        validators: usize,
        /// Data rounds to run.
        #[arg(default_value_t = 8)]
        rounds: u64,
    },
    /// Save, drop, reopen, and replay a node's state, then compare the roots.
    Persist {
        /// Directory the store is written to.
        #[arg(long, default_value = "karsa-store")]
        path: PathBuf,
        /// Validators in the simulated committee (at least 4).
        #[arg(default_value_t = 4)]
        validators: usize,
        /// Rounds that carry transactions.
        #[arg(long, default_value_t = 4)]
        rounds: u64,
    },
    /// Exchange vertices between validator nodes and check convergence.
    Net {
        /// Validators in the simulated committee (at least 4).
        #[arg(default_value_t = 4)]
        validators: usize,
        /// Extra per-link delay, derived from a seeded hash.
        #[arg(long, default_value_t = 2)]
        jitter: u64,
        /// Validator index that never participates.
        #[arg(long)]
        crashed: Option<usize>,
    },
    /// Model per-node bandwidth for certificate and payload dissemination.
    Bandwidth {
        /// Validators in the set. 30 matches the assumed launch committee.
        #[arg(long, default_value_t = 30)]
        validators: usize,
        /// Committed transactions per second.
        #[arg(long, default_value_t = 100_000)]
        tps: u64,
        /// Peers each node forwards to.
        #[arg(long, default_value_t = 4)]
        fanout: usize,
        /// Transactions batched into one certificate.
        #[arg(long, default_value_t = 1_000)]
        transactions_per_certificate: u64,
    },
    /// Print the algorithm registry and a sample signing payload.
    Demo,
    /// Check NIST ACVP sigVer vectors for ML-DSA-65 or SLH-DSA-SHA2-128s.
    Acvp {
        /// Path to the ACVP internalProjection.json file.
        file: PathBuf,
    },
    /// Measure DAG certificate and header cost.
    Dagbench,
    /// Drive the node over TCP and report accepted transactions per second.
    Loadtest {
        /// Total transactions to send.
        #[arg(default_value_t = 20000)]
        count: usize,
        /// Parallel connections; at most 32 (one demo account per worker).
        #[arg(default_value_t = 16)]
        concurrency: usize,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Node => run_node(),
        Command::SampleTx => node::print_sample_transaction(),
        Command::RegisterDemo { activation_epoch } => {
            node::print_demo_registration(activation_epoch)
        }
        Command::Certify { validators } => certify::run(validators),
        Command::Dagsim { validators } => dagsim::run(validators),
        Command::Chain { validators, rounds } => chain::run(validators, rounds),
        Command::Net {
            validators,
            jitter,
            crashed,
        } => netrun::run(validators, jitter, crashed),
        Command::Migrate { validators, rounds } => migrate::run(validators, rounds),
        Command::Sigbench { algorithm, threads } => sigbench::run(&algorithm, threads),
        Command::Sweep {
            sizes,
            jitter,
            ticks,
        } => {
            match sizes
                .split(',')
                .map(|part| part.trim().parse::<usize>())
                .collect::<Result<Vec<usize>, _>>()
            {
                Ok(parsed) => sweep::run(&parsed, jitter, ticks),
                Err(_) => Err("sizes must be comma-separated integers".into()),
            }
        }
        Command::Persist {
            path,
            validators,
            rounds,
        } => persist::run(path, validators, rounds),
        Command::Bandwidth {
            validators,
            tps,
            fanout,
            transactions_per_certificate,
        } => bandwidth::run(validators, tps, fanout, transactions_per_certificate),
        Command::Demo => demo::run(),
        Command::Acvp { file } => acvp::run(&file),
        Command::Dagbench => dagbench::run(),
        Command::Loadtest { count, concurrency } => loadtest::run(count, concurrency),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_node() -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(node::serve())
}
