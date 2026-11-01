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
//! karsa dagbench                   measure DAG certificate and header cost
//! karsa loadtest [count] [conc]    drive the node and report tx/s
//! ```

mod acvp;
mod dagbench;
mod demo;
mod loadtest;
mod node;

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
