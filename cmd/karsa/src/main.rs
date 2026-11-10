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
//! karsa audit                      re-derive the certified state root from disk
//! karsa migrate                    rotate validator keys across an epoch boundary
//! karsa sigbench                   measure transaction verification throughput
//! karsa sweep                      run the network simulation across committee sizes
//! karsa shards                     erasure-code a batch and reconstruct it
//! karsa bandwidth                  model per-node dissemination bandwidth
//! karsa dagbench                   measure DAG certificate and header cost
//! karsa loadtest [count] [conc]    drive the node and report tx/s
//! karsa live                       run validator nodes over real loopback sockets
//! karsa config                     validate and explain a node.toml
//! karsa prune                      apply a node's retention policy to its store
//! ```

mod acvp;
mod audit;
mod bandwidth;
mod certify;
mod chain;
mod config;
mod dagbench;
mod dagsim;
mod demo;
mod finality;
mod genesis;
mod home;
mod keys;
mod live;
mod loadtest;
mod migrate;
mod netrun;
mod node;
mod peers;
mod persist;
mod prune;
mod rpc;
mod send;
mod shards;
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
    /// Run the demo HTTP node until interrupted, optionally from a node.toml.
    Node {
        /// Configuration file; defaults to the one in --home.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Node home directory holding node.toml and genesis.json.
        #[arg(long)]
        home: Option<PathBuf>,
    },
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
        /// Node home directory; its genesis decides the chain id.
        #[arg(long)]
        home: Option<PathBuf>,
    },
    /// Erasure-code a batch payload and reconstruct it after losing shards.
    Shards,
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
        /// Keep every vertex and payload so that `karsa audit` can re-derive the chain.
        #[arg(long)]
        keep_history: bool,
        /// Home directory whose genesis and keys the run uses; absent keeps the demo.
        #[arg(long)]
        home: Option<PathBuf>,
    },
    /// Re-derive the certified state root from the stored data, and say where
    /// trust begins.
    Audit {
        /// Directory the store was written to.
        #[arg(long, default_value = "karsa-store")]
        path: PathBuf,
        /// Validators in the committee the chain was produced by.
        #[arg(default_value_t = 4)]
        validators: usize,
        /// Home directory whose genesis and keys the audit uses; absent keeps the demo.
        #[arg(long)]
        home: Option<PathBuf>,
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
    /// List known peers, or add and remove one.
    Peers {
        /// Node home directory holding peers.json.
        #[arg(long)]
        home: Option<PathBuf>,
        /// Add or update a peer, as id@host:port.
        #[arg(long)]
        add: Option<String>,
        /// Remove a peer by id.
        #[arg(long)]
        remove: Option<String>,
    },
    /// Validate and explain a genesis, or write an example.
    Genesis {
        /// Explicit file; defaults to genesis.json in --home.
        path: Option<std::path::PathBuf>,
        /// Node home directory holding node.toml and genesis.json.
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Rounds per key epoch when --init writes a new genesis.
        #[arg(long)]
        epoch_rounds: Option<u64>,
        /// Validators the generated devnet has; only applies with --init.
        #[arg(long)]
        validators: Option<usize>,
        /// Write the example instead of reading it.
        #[arg(long)]
        init: bool,
    },
    /// Validate and explain a node configuration, or write an example.
    Config {
        /// Explicit file; defaults to node.toml in --home.
        path: Option<std::path::PathBuf>,
        /// Node home directory holding node.toml and genesis.json.
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Write the commented example instead of reading it.
        #[arg(long)]
        init: bool,
    },
    /// Run validator nodes over real loopback sockets and measure what crosses them.
    Live {
        /// Validators in the committee.
        #[arg(long, default_value_t = 5)]
        validators: usize,
        /// First loopback port; node `i` binds `port_base + i`.
        #[arg(long, default_value_t = 7100)]
        port_base: u16,
        /// Rounds each node authors before the run stops.
        #[arg(long, default_value_t = 20)]
        rounds: u64,
        /// Artificial per-frame delay on node 1, in milliseconds.
        #[arg(long, default_value_t = 0)]
        slow_ms: u64,
        /// Wall-clock cap on the whole run.
        #[arg(long, default_value_t = 30)]
        timeout_seconds: u64,
        /// Frames per peer queue. Small values force drops, which exercises repair.
        #[arg(long, default_value_t = 4096)]
        queue: usize,
        /// Socket send buffer in bytes; 0 keeps the OS default.
        #[arg(long, default_value_t = 0)]
        send_buffer: usize,
        /// Transactions per authored batch. Zero keeps the data plane empty.
        #[arg(long, default_value_t = 0)]
        txs: u64,
        /// Apply committed batches into an account state and compare the roots.
        #[arg(long)]
        execute: bool,
        /// Extra archive nodes: they store everything and never sign.
        #[arg(long, default_value_t = 0)]
        archives: usize,
        /// Run exactly this validator in this process, one process per validator.
        ///
        /// Requires `--archives 0`: an archive has no consensus role, and this mode
        /// exists to put each signing node in its own process instead of sharing one
        /// runtime. Every process must be given the same committee and port base.
        #[arg(long)]
        node_index: Option<usize>,
        /// Persist vertices and batches here, one subdirectory per node.
        #[arg(long)]
        store: Option<std::path::PathBuf>,
        /// Store one erasure shard per batch instead of the whole payload.
        #[arg(long)]
        shard: bool,
        /// How long the mesh stays up after the last node finishes authoring.
        #[arg(long, default_value_t = 500)]
        drain_ms: u64,
        /// Home directory whose genesis sets the chain identity; absent keeps the demo one.
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Print the time spent in each stage of the node loop.
        #[arg(long)]
        profile: bool,
        /// Sign every batch before the measured window instead of in the node loop.
        #[arg(long)]
        pre_sign: bool,
        /// Threads used to verify one batch. One keeps the serial path.
        #[arg(long, default_value_t = 1)]
        verify_threads: usize,
        /// First loopback HTTP port; node `i` serves `rpc_port + i`. Zero disables it.
        ///
        /// A nonzero port requires `--execute` and takes batches from submitted
        /// transactions instead of the demo data plane. Authoring then runs until
        /// the process lifetime ends rather than stopping after `--rounds`.
        #[arg(long, default_value_t = 0)]
        rpc_port: u16,
        /// Most mempool transactions one authored batch may carry.
        #[arg(long, default_value_t = rpc::DEFAULT_BATCH_MAX)]
        rpc_batch_max: usize,
        /// First loopback port for snapshot requests; node `i` serves
        /// `snapshot_port + i`. Zero disables the server and the client.
        #[arg(long, default_value_t = 0)]
        snapshot_port: u16,
        /// Ask a peer for a state snapshot. A store with history is moved forward
        /// to the peer's certified anchor.
        #[arg(long)]
        sync_from_peers: bool,
        /// Persist a live snapshot every N certified heights. Zero disables it.
        ///
        /// Needs --store and --execute; the checkpoint bounds how much history a
        /// restart has to replay, and each write prunes vertices, payloads, and
        /// headers below its floor.
        #[arg(long, default_value_t = 0)]
        checkpoint_every: u64,
        /// Rounds a validator may be silent before the local failure detector
        /// reports it. Zero disables the report.
        ///
        /// This is a liveness view, not a consensus decision: two nodes may see
        /// different silence while their delivery differs, and acting on it needs
        /// an authorized set change.
        #[arg(long, default_value_t = 50)]
        failure_rounds: u64,
        /// Append one validator at this epoch, authorized by the old-set quorum.
        #[arg(long, conflicts_with = "remove_validator_at_epoch")]
        add_validator_at_epoch: Option<u64>,
        /// Remove the last validator at this epoch, authorized by the old-set quorum.
        #[arg(long, conflicts_with = "add_validator_at_epoch")]
        remove_validator_at_epoch: Option<u64>,
        /// Collect a quorum fence for a validator the failure detector reports silent.
        #[arg(long)]
        fence_silent: bool,
    },
    /// Sign a transfer with a committee account and submit it to a live RPC node.
    Send {
        /// RPC base, as host:port or http://host:port.
        #[arg(long, default_value = "127.0.0.1:7300")]
        rpc: String,
        /// Sender index in the committee fixture.
        #[arg(long, default_value_t = 0)]
        from: usize,
        /// Recipient index in the committee fixture.
        #[arg(long, default_value_t = 1)]
        to: usize,
        #[arg(long, default_value_t = 1)]
        amount: u64,
        /// Sequence to sign; zero asks the certified account state for the next one.
        #[arg(long, default_value_t = 0)]
        sequence: u64,
        /// Committee size the live mesh was started with.
        #[arg(long, default_value_t = 4)]
        validators: usize,
        /// Home directory whose genesis and keys the live mesh used.
        #[arg(long)]
        home: Option<PathBuf>,
        /// Flip one signature byte after signing, to exercise rejection.
        #[arg(long)]
        tamper_signature: bool,
        /// Poll until the transaction is finalized or rejected.
        #[arg(long)]
        wait: bool,
        /// How long to poll, in seconds.
        #[arg(long, default_value_t = 30)]
        wait_seconds: u64,
    },
    /// Measure client submit to certified header over a delayed validator mesh.
    Finality {
        /// Validators in the committee (at least 4).
        #[arg(long, default_value_t = 4)]
        validators: usize,
        /// Client submissions; each is one batch and one round.
        #[arg(long, default_value_t = 100)]
        samples: usize,
        /// Transactions per submitted batch.
        #[arg(long, default_value_t = 1)]
        txs: u64,
        /// One-way delay on every frame, in milliseconds.
        #[arg(long, default_value_t = 20)]
        delay_ms: u64,
        /// Extra delay drawn per frame, in milliseconds.
        #[arg(long, default_value_t = 5)]
        jitter_ms: u64,
        /// Wall-clock cap on the whole run.
        #[arg(long, default_value_t = 60)]
        timeout_seconds: u64,
        /// Home directory whose genesis sets the chain identity.
        #[arg(long)]
        home: Option<std::path::PathBuf>,
        /// Override the epoch length in rounds for this experiment.
        #[arg(long)]
        epoch_rounds: Option<u64>,
        /// Add one validator at this epoch boundary.
        #[arg(long, conflicts_with = "remove_validator_at_epoch")]
        add_validator_at_epoch: Option<u64>,
        /// Remove the last validator at this epoch boundary.
        #[arg(long, conflicts_with = "add_validator_at_epoch")]
        remove_validator_at_epoch: Option<u64>,
        /// Start the added validator at the boundary from a replayed history.
        #[arg(long)]
        cold_join: bool,
        /// Replay every record from genesis instead of a state snapshot plus tail.
        #[arg(long, requires = "cold_join")]
        cold_full_history: bool,
    },
    /// Apply a node's retention policy to its store.
    Prune {
        /// Home directory holding node.toml; defaults to $HOME/.karsa.
        #[arg(long)]
        home: Option<PathBuf>,
        /// Configuration file; defaults to the one in --home.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Store directory; defaults to node.data_dir from the config.
        #[arg(long)]
        data_dir: Option<PathBuf>,
        /// Report the cutoffs without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Node { config, home } => run_node(config, home),
        Command::SampleTx => node::print_sample_transaction(),
        Command::RegisterDemo { activation_epoch } => {
            node::print_demo_registration(activation_epoch)
        }
        Command::Certify { validators } => certify::run(validators),
        Command::Dagsim { validators } => dagsim::run(validators),
        Command::Chain {
            validators,
            rounds,
            home,
        } => run_chain(home, validators, rounds),
        Command::Net {
            validators,
            jitter,
            crashed,
        } => netrun::run(validators, jitter, crashed),
        Command::Migrate { validators, rounds } => migrate::run(validators, rounds),
        Command::Sigbench { algorithm, threads } => sigbench::run(&algorithm, threads),
        Command::Shards => shards::run(),
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
            keep_history,
            home,
        } => persist::run(path, validators, rounds, keep_history, home),
        Command::Audit {
            path,
            validators,
            home,
        } => audit::run(path, validators, home),
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
        Command::Finality {
            validators,
            samples,
            txs,
            delay_ms,
            jitter_ms,
            timeout_seconds,
            home,
            epoch_rounds,
            add_validator_at_epoch,
            remove_validator_at_epoch,
            cold_join,
            cold_full_history,
        } => {
            let change = match (add_validator_at_epoch, remove_validator_at_epoch) {
                (Some(epoch), None) => Some((finality::SetChange::Add, epoch)),
                (None, Some(epoch)) => Some((finality::SetChange::Remove, epoch)),
                (None, None) => None,
                (Some(_), Some(_)) => {
                    unreachable!("clap rejects adding and removing in the same run")
                }
            };
            finality::run(finality::Config {
                validators,
                samples,
                txs,
                delay: std::time::Duration::from_millis(delay_ms),
                jitter: std::time::Duration::from_millis(jitter_ms),
                timeout: std::time::Duration::from_secs(timeout_seconds),
                home,
                epoch_rounds,
                change,
                cold_join,
                cold_history: if cold_full_history {
                    finality::ColdHistory::Full
                } else {
                    finality::ColdHistory::Snapshot
                },
            })
        }
        Command::Config { path, home, init } => run_config(home, path, init),
        Command::Peers { home, add, remove } => run_peers(home, add, remove),
        Command::Genesis {
            path,
            home,
            init,
            epoch_rounds,
            validators,
        } => run_genesis(home, path, init, epoch_rounds, validators),
        Command::Live {
            validators,
            port_base,
            rounds,
            slow_ms,
            timeout_seconds,
            queue,
            send_buffer,
            txs,
            execute,
            archives,
            node_index,
            store,
            shard,
            drain_ms,
            home,
            profile,
            pre_sign,
            verify_threads,
            rpc_port,
            rpc_batch_max,
            snapshot_port,
            sync_from_peers,
            checkpoint_every,
            failure_rounds,
            add_validator_at_epoch,
            remove_validator_at_epoch,
            fence_silent,
        } => live::run(live::Config {
            validators,
            port_base,
            rounds,
            slow_ms,
            timeout: std::time::Duration::from_secs(timeout_seconds),
            queue,
            send_buffer,
            txs,
            execute,
            archives,
            node_index,
            store: store.unwrap_or_default(),
            shard,
            drain: std::time::Duration::from_millis(drain_ms),
            home,
            profile,
            pre_sign,
            verify_threads,
            rpc_port,
            rpc_batch_max,
            snapshot_port,
            sync_from_peers,
            checkpoint_every,
            failure_rounds,
            change: add_validator_at_epoch
                .map(|epoch| (live::SetChangeKind::Add, epoch))
                .or_else(|| {
                    remove_validator_at_epoch.map(|epoch| (live::SetChangeKind::Remove, epoch))
                }),
            fence_silent,
        }),
        Command::Send {
            rpc,
            from,
            to,
            amount,
            sequence,
            validators,
            home,
            tamper_signature,
            wait,
            wait_seconds,
        } => send::run(send::Config {
            rpc,
            from,
            to,
            amount,
            sequence,
            validators,
            home,
            tamper_signature,
            wait,
            wait_seconds,
        }),
        Command::Prune {
            home,
            config,
            data_dir,
            dry_run,
        } => prune::run(home, config, data_dir, dry_run),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run_config(
    home_path: Option<PathBuf>,
    path: Option<PathBuf>,
    init: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = home::Home::resolve(home_path)?;
    config::run(&home, path, init)
}

fn run_chain(
    home_path: Option<PathBuf>,
    validators: usize,
    rounds: u64,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = home::Home::resolve(home_path)?;
    chain::run(validators, rounds, Some(&home))
}

fn run_peers(
    home_path: Option<PathBuf>,
    add: Option<String>,
    remove: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = home::Home::resolve(home_path)?;
    peers::run(&home, add, remove)
}

fn run_genesis(
    home_path: Option<PathBuf>,
    path: Option<PathBuf>,
    init: bool,
    epoch_rounds: Option<u64>,
    validators: Option<usize>,
) -> Result<(), Box<dyn std::error::Error>> {
    let home = home::Home::resolve(home_path)?;
    genesis::run(&home, path, init, epoch_rounds, validators)
}

fn run_node(
    config_path: Option<PathBuf>,
    home_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // A home names both halves of a membership, so it is resolved first; an
    // explicit --config still wins for a one-off run against a file elsewhere.
    let home = home::Home::resolve(home_path.clone())?;
    let listen = match (config_path, home_path) {
        (None, None) => node::DEMO_LISTEN.to_string(),
        (explicit, _) => {
            let path = home.file(explicit, "node.toml");
            // A missing file is written first: a node should not refuse its own
            // first run over a file it can generate.
            let config = crate::config::NodeConfig::ensure(&path)?;
            let mut problems = config.problems();

            // The other half of the same membership: a genesis in this home must at
            // least parse and validate before the node serves anything.
            let genesis_path = home.genesis_json();
            if genesis_path.exists() {
                let genesis = crate::genesis::Genesis::load(&genesis_path)?;
                problems.extend(genesis.problems());
            }

            if !problems.is_empty() {
                for problem in &problems {
                    eprintln!("  PROBLEM: {problem}");
                }
                return Err(format!(
                    "{} configuration problem(s) in {}",
                    problems.len(),
                    path.display()
                )
                .into());
            }
            if !config.rpc.enable {
                return Err(format!(
                    "{} has [rpc] enable = false, so there is nothing to serve",
                    path.display()
                )
                .into());
            }
            config.rpc.rpc_listen
        }
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(node::serve(&listen))
}
