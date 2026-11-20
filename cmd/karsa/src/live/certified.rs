//! Opt-in live certified session over the existing peer transport.
//!
//! The legacy loop decides slots with its own commit rules and builds headers from that
//! order. This task keeps the same TCP mesh and the same plain causal vertices, but the
//! durable certified session owns ordering, execution and header production. It is a
//! bounded first live wiring, not a production authority claim:
//!
//! - every node opens or recovers a certified session from the same trusted genesis;
//! - plain causal vertices feed the owned availability DAG, which is the only thing the
//!   certified proposal and vote rules read;
//! - only the elected view proposer authors the POL carrier: a carrier is a locally
//!   authored vertex, and precommits bind their prerequisite by exact vertex ID, so
//!   competing carriers would make every precommit bind a different prerequisite;
//! - agreement frames route through the same authenticated receipt path peers use;
//! - a grace deadline signs one advisory next-view request; the local view advances only
//!   when a quorum certificate enters it, so independent timers cannot drift the set
//!   into incompatible views;
//! - a decided slot is applied from the durable transition, then executed and built into
//!   a header whose shares are dispatched over the existing writer queues;
//! - with `--execute`, each node authors bounded local demo batches and names them in its
//!   plain causal vertices. The pump retains those bytes, broadcasts them with the naming
//!   vertex, and retries them once applied certified ordering requires them, so peers admit
//!   the payload after they apply the same slot. A peer blocked on another node's batch
//!   asks for that exact digest, and any holder answers with an ordinary payload frame;
//!   the request changes who triggers delivery, not the no-acknowledgement contract.
//!   Without `--execute`, payload hashes stay zero and applied slots order vertices
//!   without executing transactions;
//! - no RPC, snapshot, epoch transition, pruning or delivery acknowledgement is wired here.
//!
//! The single-validator path is proven end to end: plain causal rounds decide whenever a
//! majority of authors is held, the initial proposal and view bind, durable votes follow,
//! and the decided slot executes into a header whose share and certificate persist. The
//! multi-validator mesh routes the same evidence over the same links: durable reads reuse a
//! verified replay, refused peer receipts are dropped instead of poisoning the owner, and a
//! single elected publisher owns the shared POL carrier. A bounded three-validator test
//! certifies the first slots on every node. Without `--execute`, payloads stay zero and
//! slots order without executing transactions; with `--execute`, nodes author bounded demo
//! batches and exchange them after certified application, so headers carry real state roots.
//! Multi-slot progress is not free at this size: the causal DAG
//! requires a quorum of the previous round's authors, and a three-validator set has no
//! spare author, so every node has to fill every round before the next one is reference
//! ready. The test therefore proves the first decisions, not sustained slot throughput.
//!
//! The owner's causal import budget bounds one run, and both histories stay mutually
//! exclusive on disk: a store holding a legacy chain is refused by the session opener.

use std::collections::{BTreeSet, VecDeque};
use std::error::Error;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use net::Node;
use net::wire::{self, Message};
use store::Store;
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use validator::{EpochSchedule, Header, Share, Vertex, commit_root};

use super::agreement::AgreementProgress;
use super::agreement::event_pump::{EventPump, LocalEvent, PumpSnapshot};
use super::agreement::output_dispatcher::{self, SharePeer};
use super::agreement::{pacemaker, session};
use super::{Config, Link, LinkTask, credited_genesis};
use crate::chain;

/// Local maintenance and causal authoring cadence.
const TICK: Duration = Duration::from_millis(50);
/// Volatile durable obligation/discovery cadence inside the pump.
const SCHEDULE: Duration = Duration::from_millis(50);
/// Publication retry cadence; a lost carrier is recovered from its durable ID.
const RETRY: Duration = Duration::from_millis(100);
/// Phase waits bound one view attempt. The positive direct path runs first. A 3-validator
/// set needs every author's causal vertex and vote, so a deadline shorter than one full
/// causal round turns a slow import into a nil vote; one nil vote then rules out the
/// positive quorum for the whole view and the set spends its lifetime recycling views.
/// The wait keeps that round affordable while still letting a genuinely dead leader reach
/// a certificate view change inside a bounded run.
const PHASE_WAIT: Duration = Duration::from_secs(6);
/// Vertices imported by one trusted causal turn.
const MAX_IMPORTS_PER_TURN: usize = 64;
/// Pending peer vertices retained between turns; the owner re-checks each one.
const MAX_PENDING_VERTICES: usize = 512;
/// Distinct publication identities remembered for deduplication only.
const MAX_SEEN_VERTICES: usize = 8192;
/// Peer shares retried after a locally executed header exists.
const MAX_PENDING_SHARES: usize = 1024;
/// Peer shares re-injected by one turn.
const MAX_SHARES_PER_TURN: usize = 16;
/// Inbound frames retained when the pump ingress queue is transiently full.
const MAX_PENDING_FRAMES: usize = 64;
/// Batches one `--execute` node retains: its own authored payloads plus admitted peers'.
/// Bounds the offline lifetime; exhaustion rejects input instead of evicting required data.
const MAX_SESSION_BATCHES: usize = 512;
/// Encoded bytes of retained batches. Demo batches are small; this is a hard stop.
const MAX_SESSION_PAYLOAD_BYTES: usize = 4 << 20;

/// What one certified node observed before it stopped.
struct Report {
    index: usize,
    authored: usize,
    imported: usize,
    received: usize,
    rejected: usize,
    dropped: u64,
    bytes_in: u64,
    bytes_out: u64,
    applied_tx: u64,
    consumed: usize,
    applications: usize,
    order_root: [u8; 32],
    blocked: Option<(u64, usize, [u8; 32], bool)>,
    certified: usize,
    progress: AgreementProgress,
    head_height: u64,
    head_round: u64,
    pump: PumpSnapshot,
    local_full: u64,
    local_accepted: u64,
    ticks: u64,
    rejections: Vec<(String, usize)>,
    error: Option<String>,
}

/// Runs the certified session mode, one task per validator or one process-wide task.
pub(super) fn run(
    config: Config,
    committee: chain::Membership,
    chain_id: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let validators = config.validators;
    if let Some(index) = config.node_index {
        runtime.block_on(run_one(config, index, committee, chain_id))?;
        return Ok(());
    }
    runtime.block_on(run_mesh(config, committee, chain_id, validators))
}

async fn run_one(
    config: Config,
    index: usize,
    committee: chain::Membership,
    chain_id: Vec<u8>,
) -> Result<(), Box<dyn Error>> {
    let port = u32::from(config.port_base) + u32::try_from(index).unwrap_or(0);
    let lifetime = config.timeout;
    println!(
        "== Certified agreement node {index} of {} ==",
        config.validators
    );
    println!(
        "  listening on 127.0.0.1:{port}, certified session lifetime {}",
        super::millis(u64::try_from(lifetime.as_nanos()).unwrap_or(u64::MAX))
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut task = tokio::spawn(certified_node_task(
        index,
        config.clone(),
        committee,
        chain_id,
        shutdown_rx,
    ));
    let deadline = tokio::time::sleep(lifetime);
    tokio::pin!(deadline);
    let mut finished = None;
    tokio::select! {
        result = &mut task => finished = Some(result),
        _ = &mut deadline => {}
    }
    let _ = shutdown_tx.send(true);
    let report = match finished {
        Some(result) => join(result, index)?,
        None => join(task.await, index)?,
    };
    print_report(&report);
    if let Some(error) = &report.error {
        return Err(format!("node {index} stopped: {error}").into());
    }
    if report.certified == 0 {
        return Err(format!("node {index} certified no height within the run lifetime").into());
    }
    Ok(())
}

async fn run_mesh(
    config: Config,
    committee: chain::Membership,
    chain_id: Vec<u8>,
    validators: usize,
) -> Result<(), Box<dyn Error>> {
    let total = validators;
    println!("== Certified agreement session over live sockets ==");
    println!(
        "  {} validators on 127.0.0.1:{}..={}, full mesh, certified session lifetime {}",
        validators,
        config.port_base,
        u32::from(config.port_base) + u32::try_from(total - 1).unwrap_or(0),
        super::millis(u64::try_from(config.timeout.as_nanos()).unwrap_or(u64::MAX))
    );
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let (done_tx, mut done_rx) = mpsc::channel(validators);
    let mut handles = Vec::with_capacity(validators);
    for index in 0..validators {
        let config = config.clone();
        let committee = committee.clone();
        let chain_id = chain_id.clone();
        let shutdown_rx = shutdown_rx.clone();
        let done = done_tx.clone();
        handles.push(tokio::spawn(async move {
            let result = certified_node_task(index, config, committee, chain_id, shutdown_rx).await;
            let _ = done.send(()).await;
            result
        }));
    }
    drop(done_tx);

    let deadline = tokio::time::sleep(config.timeout);
    tokio::pin!(deadline);
    tokio::select! {
        _ = &mut deadline => {}
        // A task that stops early (fatal owner error included) ends the mesh wait;
        // the deadline still bounds the normal continuous run.
        _ = done_rx.recv() => {}
    }
    let _ = shutdown_tx.send(true);

    let mut reports = Vec::with_capacity(handles.len());
    let mut failures = Vec::new();
    for (index, handle) in handles.into_iter().enumerate() {
        match handle.await {
            Ok(Ok(report)) => reports.push(report),
            Ok(Err(error)) => failures.push(format!("node {index}: {error}")),
            Err(error) => failures.push(format!("node {index} stopped: {error}")),
        }
    }

    println!();
    println!(
        "  {:<7} {:>8} {:>9} {:>9} {:>8} {:>8} {:>9} {:>7} {:>9}",
        "node",
        "authored",
        "imported",
        "received",
        "dropped",
        "rejected",
        "certified",
        "head",
        "view/cert"
    );
    for report in &reports {
        println!(
            "  {:<7} {:>8} {:>9} {:>9} {:>8} {:>8} {:>9} {:>7} {:>9}",
            format!("val-{}", report.index),
            report.authored,
            report.imported,
            report.received,
            report.dropped,
            report.rejected,
            report.certified,
            format!("{}/{}", report.head_height, report.head_round),
            format!(
                "{}/{}",
                report.progress.view,
                report
                    .progress
                    .certificate
                    .map_or_else(|| String::from("-"), |target| target.to_string())
            )
        );
    }
    for report in &reports {
        let p = &report.progress;
        println!(
            "  val-{} view {} round {}: proposal {}, view carriers {}, votes {}, POLs {}, finals {}, nil {}/{}, intents {}, authorable {}/{} prevote/precommit, {} nil ({} unready), candidates {}, decided {}, POL {}, local round {}, own hole {}, proposer self {}, aggregate {:?}, view step {:?}",
            report.index,
            p.view,
            p.next_round,
            p.proposal,
            p.view_carriers,
            p.vote_carriers,
            p.pols,
            p.finals,
            p.nil_prevotes,
            p.nil_precommits,
            p.intents,
            p.authorable_prevotes,
            p.authorable_precommits,
            p.authorable_nil,
            p.authorable_unready,
            p.candidates,
            p.decided,
            p.reproposal,
            p.local_round,
            p.own_hole,
            p.view_proposer_self,
            p.last_aggregate_error,
            p.last_view_error
        );
        print_costs(&format!("  val-{} ", report.index), report);
    }
    for failure in &failures {
        eprintln!("  {failure}");
    }
    for report in &reports {
        if let Some(error) = &report.error {
            eprintln!("  node {} stopped: {error}", report.index);
        }
    }
    if reports.is_empty() {
        return Err("no certified node reported a result".into());
    }
    if reports.iter().any(|report| report.error.is_some()) {
        return Err("at least one certified node stopped with an error".into());
    }
    let certifying = reports.iter().filter(|report| report.certified > 0).count();
    if certifying == 0 {
        return Err("the certified session decided no slot".into());
    }
    println!(
        "  certified: {certifying} of {} nodes, {}..{} heights, applied {} tx total",
        reports.len(),
        reports
            .iter()
            .map(|report| report.certified)
            .min()
            .unwrap_or(0),
        reports
            .iter()
            .map(|report| report.certified)
            .max()
            .unwrap_or(0),
        reports.iter().map(|report| report.applied_tx).sum::<u64>()
    );
    if !failures.is_empty() {
        return Err(format!("{} certified node(s) stopped with an error", failures.len()).into());
    }
    Ok(())
}

fn join(
    result: Result<Result<Report, String>, tokio::task::JoinError>,
    index: usize,
) -> Result<Report, Box<dyn Error>> {
    match result {
        Ok(Ok(report)) => Ok(report),
        Ok(Err(error)) => Err(format!("node {index}: {error}").into()),
        Err(error) => Err(format!("node {index} stopped: {error}").into()),
    }
}

fn print_report(report: &Report) {
    println!();
    println!(
        "  node val-{}: certified {} heights, head {}/{}, applied {} tx over {} order entries",
        report.index,
        report.certified,
        report.head_height,
        report.head_round,
        report.applied_tx,
        report.consumed
    );
    println!(
        "  agreement:  durable view {}, entered certificate {}",
        report.progress.view,
        report
            .progress
            .certificate
            .map_or_else(|| String::from("none"), |target| target.to_string())
    );
    println!(
        "  current:    proposal {}, view carriers {}, votes {}, POLs {}, finals {}, nil votes {}/{}",
        report.progress.proposal,
        report.progress.view_carriers,
        report.progress.vote_carriers,
        report.progress.pols,
        report.progress.finals,
        report.progress.nil_prevotes,
        report.progress.nil_precommits
    );
    println!(
        "  durable:    intents {}, authorable {}, candidates {}, decided {}, POL {}",
        report.progress.intents,
        report.progress.authorable,
        report.progress.candidates,
        report.progress.decided,
        report.progress.reproposal
    );
    println!(
        "  causal:     next round {}, local round {}, own hole {}, authorable {}/{} prevote/precommit, {} nil, {} unready, first {} self {}",
        report.progress.next_round,
        report.progress.local_round,
        report.progress.own_hole,
        report.progress.authorable_prevotes,
        report.progress.authorable_precommits,
        report.progress.authorable_nil,
        report.progress.authorable_unready,
        report
            .progress
            .first_unready_round
            .map_or_else(|| String::from("-"), |round| round.to_string()),
        report
            .progress
            .first_unready_self
            .map_or_else(|| String::from("-"), |local| local.to_string())
    );
    if let Some(error) = &report.progress.last_aggregate_error {
        println!("  aggregate:  {error}");
    }
    if let Some(error) = &report.progress.last_view_error {
        println!("  view step:  {error}");
    }
    println!(
        "  causal:     {} authored, {} imported, {} frames received, {} rejected, {} dropped",
        report.authored, report.imported, report.received, report.rejected, report.dropped
    );
    println!(
        "  wire:       {} in, {} out",
        super::human(report.bytes_in),
        super::human(report.bytes_out)
    );
    print_costs("  ", report);
    if let Some(error) = &report.error {
        eprintln!("  error: {error}");
    }
}

/// Prints where the run's wall time went. A slot stall is either owner work (pump turns,
/// full journal replays) or waiting for availability, and this attributes it. Diagnostic
/// only: these counts are not progress, delivery or durability evidence.
fn print_costs(prefix: &str, report: &Report) {
    let p = &report.pump;
    println!(
        "{prefix}pump:       {} local turns {} (max {}), {} frames {}, {} wakes {}; {} ticks, {} local accepted, {} refused, {} payload wants, {} served",
        p.local_turns,
        super::millis(p.local_nanos),
        super::millis(p.max_local_nanos),
        p.frame_turns,
        super::millis(p.frame_nanos),
        p.scheduled_turns,
        super::millis(p.scheduled_nanos),
        report.ticks,
        report.local_accepted,
        report.local_full,
        p.payload_wants,
        p.payload_served
    );
    println!(
        "{prefix}journal:    {} events, {} applied slots, {} consumed vertices, root {:02x?}, {} folds {} ({} resumed over {}), {} read/decode, {} duplicate receipts skipped",
        report.progress.sequence,
        report.applications,
        report.consumed,
        &report.order_root[..8],
        report.progress.replays,
        super::millis(report.progress.replay_nanos),
        report.progress.resumed_replays,
        super::millis(report.progress.resumed_replay_nanos),
        super::millis(report.progress.replay_read_nanos),
        report.progress.duplicate_receipts
    );
    for (reason, count) in &report.rejections {
        println!("{prefix}rejected:   {count}x {reason}");
    }
    if let Some((round, author, payload, id_matches)) = &report.blocked {
        println!(
            "{prefix}blocked:    round {round} author val-{author} payload {:02x?} id-match {id_matches}",
            &payload[..8]
        );
    }
}

/// One validator's bounded certified session over the shared peer mesh.
async fn certified_node_task(
    index: usize,
    config: Config,
    committee: chain::Membership,
    chain_id: Vec<u8>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<Report, String> {
    let total = config.validators;
    let identity = committee
        .consensus
        .get(index)
        .ok_or("no consensus key for this node")?
        .clone();
    let store = Store::open(config.store.join(format!("val-{index}")).as_path())
        .map_err(|error| error.to_string())?;
    // The certified session starts from the trusted genesis, so nothing legacy is
    // written here: the opener refuses a store that already holds a genesis state or
    // header, and a certified store is recovered through the same exact checkpoint.
    let genesis_state = credited_genesis(&committee.accounts)?;
    let epoch = committee.set.epoch;
    let genesis = Header::genesis(
        chain_id.clone(),
        epoch,
        genesis_state.state_root(),
        commit_root(&[]),
    );
    let epoch_schedule = EpochSchedule::single(epoch);
    let mut owner = if store
        .has_authenticated_slot_agreement()
        .map_err(|error| error.to_string())?
    {
        session::recover_at_genesis(
            &store,
            &committee,
            index,
            &genesis,
            genesis_state.clone(),
            epoch_schedule,
        )?
    } else {
        session::open_at_genesis(
            &store,
            &committee,
            index,
            &genesis,
            genesis_state,
            epoch_schedule,
        )?
    };
    // One epoch, matching the single-set schedule: epoch transitions are not supported.
    let authoring = Node::with_chain_id_and_epoch_length(
        committee.set.clone(),
        0,
        identity.id.clone(),
        identity.private_key.clone(),
        chain_id.clone(),
    );
    let policy = pacemaker::Policy::new(PHASE_WAIT, PHASE_WAIT, PHASE_WAIT)?;
    owner.enable_authoring(authoring, policy, RETRY)?;
    // A live set must not drift into different views on independent timers: a grace
    // deadline signs one advisory next-view request, and only a quorum certificate enters.
    owner.require_certificate_view_change();
    // A one-account genesis cannot author a transfer batch, and a run without `--execute`
    // keeps the order-only zero-payload path.
    let authored_payloads = config.execute && committee.accounts.len() >= 2;
    let (mut pump, mut channels) = EventPump::new(
        owner,
        committee.clone(),
        BTreeSet::new(),
        NonZeroUsize::new(config.queue.max(1)).ok_or("certified pump capacity must be nonzero")?,
        if authored_payloads {
            MAX_SESSION_BATCHES
        } else {
            0
        },
        if authored_payloads {
            MAX_SESSION_PAYLOAD_BYTES
        } else {
            0
        },
    );
    pump.enable_scheduling(SCHEDULE)?;
    let pump_stats = Arc::clone(&channels.stats);

    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let (cancel, cancel_rx) = watch::channel(false);

    // Inbound: the same handshake and reader the legacy mesh uses, feeding this task's
    // own router instead of the legacy node loop.
    let listener = tokio::net::TcpListener::bind(super::address(config.port_base, index))
        .await
        .map_err(|error| format!("node {index} cannot listen: {error}"))?;
    let (inbound_tx, mut inbound_rx) = mpsc::channel(config.queue.max(1));
    {
        let frames = inbound_tx.clone();
        let bytes_in = Arc::clone(&bytes_in);
        let mut cancel = cancel_rx.clone();
        let chain_id = chain_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { return };
                        let frames = frames.clone();
                        let bytes_in = Arc::clone(&bytes_in);
                        let cancel = cancel.clone();
                        let chain_id = chain_id.clone();
                        tokio::spawn(async move {
                            let mut buffer = Vec::new();
                            match tokio::time::timeout(
                                super::HANDSHAKE_TIMEOUT,
                                super::handshake(&mut stream, &mut buffer, &chain_id),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    super::read_peer(stream, buffer, frames, bytes_in, cancel)
                                        .await;
                                }
                                Ok(Err(error)) => {
                                    eprintln!("certified node {index} refused an inbound peer: {error}");
                                }
                                Err(_) => {
                                    eprintln!(
                                        "certified node {index} timed out an inbound handshake"
                                    );
                                }
                            }
                        });
                    }
                    _ = cancel.changed() => return,
                }
            }
        });
    }

    // Outbound: one writer per peer, sharing the legacy link shape. Agreement output
    // goes through the dispatcher's control queue; plain causal vertices use the data
    // queue so a repair burst cannot sit behind them.
    let mut links: Vec<Link> = Vec::with_capacity(total.saturating_sub(1));
    let mut peers: Vec<SharePeer> = Vec::with_capacity(total.saturating_sub(1));
    for peer in 0..total {
        if peer == index {
            continue;
        }
        let target = super::address(config.port_base, peer);
        let mut attempt = 0usize;
        let stream = loop {
            match TcpStream::connect(&target).await {
                Ok(stream) => break stream,
                Err(error) => {
                    attempt += 1;
                    if attempt >= super::CONNECT_TRIES {
                        return Err(format!("node {index} cannot reach {target}: {error}"));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        };
        let mut stream = stream;
        let mut trailing = Vec::new();
        match tokio::time::timeout(
            super::HANDSHAKE_TIMEOUT,
            super::handshake(&mut stream, &mut trailing, &chain_id),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                return Err(format!("node {index} refused {target}: {error}"));
            }
            Err(_) => {
                return Err(format!("node {index} handshake with {target} timed out"));
            }
        }
        let (control, control_rx) = mpsc::channel(super::CONTROL_QUEUE);
        let (data, data_rx) = mpsc::channel(config.queue.max(1));
        let up = Arc::new(AtomicBool::new(true));
        links.push(Link {
            control: control.clone(),
            data,
            up: Arc::clone(&up),
        });
        peers.push(SharePeer {
            id: peer,
            writer: control,
        });
        let bytes_out = Arc::clone(&bytes_out);
        let cancel = cancel_rx.clone();
        let target = target.clone();
        let chain_id = chain_id.clone();
        let send_buffer = config.send_buffer;
        tokio::spawn(async move {
            super::write_peer(
                stream,
                control_rx,
                data_rx,
                LinkTask {
                    index,
                    target,
                    chain_id,
                    bytes_out,
                    up,
                    recent_shares: Arc::new(Mutex::new(VecDeque::new())),
                    recent_vertices: Arc::new(Mutex::new(VecDeque::new())),
                    send_buffer,
                    shutdown: cancel,
                },
            )
            .await;
        });
    }

    // Dispatcher output is drained by this task, so the pump's backpressure stays
    // bounded: one output is in flight, not a growing queue.
    let (dispatch_tx, mut dispatch_rx) = mpsc::channel::<output_dispatcher::DispatchOutput>(1);
    let dispatcher = tokio::spawn(output_dispatcher::dispatch(
        channels.output,
        peers,
        dispatch_tx,
        cancel_rx.clone(),
        super::unix_nanos(),
    ));
    let pump_task = tokio::spawn(pump.run(cancel_rx));

    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pending: Vec<Vertex> = Vec::new();
    let mut pending_frames: VecDeque<wire::Frame> = VecDeque::new();
    let mut seen: BTreeSet<(u64, Vec<u8>, [u8; 32])> = BTreeSet::new();
    let mut pending_shares: VecDeque<Share> = VecDeque::new();
    let mut built_height: u64 = 0;
    let mut import_exhausted = false;
    let mut authored = 0usize;
    let mut imported = 0usize;
    let mut received = 0usize;
    let mut rejected = 0usize;
    let mut dropped = 0u64;
    let mut local_error: Option<String> = None;
    let mut error_reports = 0usize;
    let mut inbound_open = true;
    let mut dispatch_open = true;
    let mut advance_after = 0u64;
    let mut author_turn = true;
    let mut local_full = 0u64;
    let mut local_accepted = 0u64;
    let mut ticks = 0u64;
    let mut batch_round: u64 = 0;
    let mut rejections: std::collections::BTreeMap<String, usize> =
        std::collections::BTreeMap::new();

    loop {
        if *shutdown.borrow() {
            break;
        }
        tokio::select! {
            biased;
            _ = shutdown.changed() => break,
            frame = inbound_rx.recv(), if inbound_open => {
                let Some(frame) = frame else {
                    inbound_open = false;
                    continue;
                };
                received += 1;
                match &frame.message {
                    Message::Vertex(vertex) => {
                        remember_vertex(&mut seen, &mut pending, vertex);
                        continue;
                    }
                    Message::AgreementCarrier { vertices, .. } => {
                        for vertex in vertices {
                            remember_vertex(&mut seen, &mut pending, vertex);
                        }
                    }
                    Message::Share(share) => {
                        remember_share(&mut pending_shares, share);
                    }
                    Message::Hello(_) | Message::Want(_) | Message::WantSlot { .. } => {
                        rejected += 1;
                        continue;
                    }
                    Message::Floor { .. } => continue,
                    _ => {}
                }
                match channels.frames.try_send(frame) {
                    Ok(()) => {}
                    Err(mpsc::error::TrySendError::Full(frame)) => {
                        // A dropped certificate or vote never reaches the reducer, and the peer
                        // has no way to know. Keep a bounded local retry backlog instead of
                        // counting it as lost; the next ticks retry one frame each.
                        if pending_frames.len() < MAX_PENDING_FRAMES {
                            pending_frames.push_back(frame);
                        } else {
                            dropped = dropped.saturating_add(1);
                        }
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => break,
                }
            }
            _ = ticker.tick(), if inbound_open || dispatch_open => {
                ticks = ticks.saturating_add(1);
                // Retry one frame the pump could not accept yet. The backlog is bounded and
                // the pump's own queue stays the only backpressure boundary.
                if let Some(frame) = pending_frames.pop_front() {
                    match channels.frames.try_send(frame) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(frame)) => {
                            pending_frames.push_front(frame);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                    }
                }
                // Strict turn alternation, not "author only when nothing is pending": a live
                // mesh keeps imports arriving continuously, so waiting for an empty batch
                // would let this node import every turn and never extend its own frontier.
                // The proposal rules still see the imported DAG before this node authors,
                // because each turn is one or the other and imports arrive between them.
                if author_turn {
                    author_turn = false;
                    // With --execute the vertex names a real local demo batch. The pump
                    // retains it, publishes it with the vertex, and retries it once applied
                    // certified ordering requires the bytes; peers admit it after they
                    // apply the same slot. Batch authoring failure falls back to a zero
                    // payload rather than stopping the node.
                    let event = if authored_payloads {
                        match chain::demo_batch(
                            &chain_id,
                            &committee.accounts,
                            index,
                            batch_round,
                            1,
                        ) {
                            Ok(batch) => LocalEvent::AuthorCausalBatch {
                                vertices: Vec::new(),
                                batch,
                            },
                            Err(error) => {
                                *rejections
                                    .entry(format!("batch authoring failed: {error}"))
                                    .or_insert(0) += 1;
                                LocalEvent::AuthorCausal {
                                    payload_hash: [0u8; 32],
                                    vertices: Vec::new(),
                                }
                            }
                        }
                    } else {
                        LocalEvent::AuthorCausal {
                            payload_hash: [0u8; 32],
                            vertices: Vec::new(),
                        }
                    };
                    match channels.local.try_send(event) {
                        Ok(()) => {
                            local_accepted = local_accepted.saturating_add(1);
                            batch_round = batch_round.saturating_add(1);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => break,
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            local_full = local_full.saturating_add(1);
                        }
                    }
                } else {
                    author_turn = true;
                    let batch: Vec<Vertex> = if import_exhausted {
                        Vec::new()
                    } else {
                        let take = pending.len().min(MAX_IMPORTS_PER_TURN);
                        pending.drain(..take).collect()
                    };
                    if !batch.is_empty() {
                        let count = batch.len();
                        match channels.local.try_send(LocalEvent::Drive(batch)) {
                            Ok(()) => {
                                local_accepted = local_accepted.saturating_add(1);
                                imported = imported.saturating_add(count);
                            }
                            Err(mpsc::error::TrySendError::Full(LocalEvent::Drive(vertices))) => {
                                // Keep the availability for the next turn; the pump is busy,
                                // not unhealthy, and dropping signed vertices would just force
                                // a peer to resend them.
                                requeue_vertices(&mut pending, vertices);
                                local_full = local_full.saturating_add(1);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                            Err(_) => {}
                        }
                    }
                }
                // A decided-slot check replays the durable journal, so it runs far less
                // often than causal authoring; decisions arrive at slot cadence, not tick cadence.
                if advance_after == 0 {
                    let _ = channels.local.try_send(LocalEvent::AdvanceDecidedSlot {
                        at: super::unix_nanos(),
                    });
                    advance_after = 8;
                } else {
                    advance_after -= 1;
                }
                if built_height > 0 {
                    flush_shares(
                        &mut channels.frames,
                        &mut pending_shares,
                        built_height,
                        &mut dropped,
                    );
                }
            }
            receipt = dispatch_rx.recv(), if dispatch_open => {
                let Some(receipt) = receipt else {
                    dispatch_open = false;
                    continue;
                };
                if let Some(error) = receipt.local.error {
                    if error.contains("local causal import budget exhausted") {
                        import_exhausted = true;
                    }
                    *rejections.entry(error.clone()).or_insert(0) += 1;
                    // Per-event rejections are retryable output, not a stopped owner: the pump
                    // already reports health failures by ending its run. Historical carriers
                    // and transient evidence rejects are expected during a live run, so they
                    // stay diagnostics instead of failing the node.
                    if local_error.as_deref() != Some(error.as_str()) && error_reports < 3 {
                        error_reports += 1;
                        eprintln!("certified node {index} local output rejected: {error}");
                    }
                    local_error = Some(error);
                }
                for share in &receipt.local.build.shares {
                    built_height = built_height.max(share.header.height);
                }
                for message in &receipt.local.carriers {
                    if matches!(message, Message::Vertex(_)) {
                        authored = authored.saturating_add(1);
                    }
                }
                for _ in &receipt.failed_peers {
                    dropped = dropped.saturating_add(1);
                }
            }
        }
    }

    let _ = cancel.send(true);
    let pump = pump_stats.snapshot();
    let mut report = Report {
        index,
        authored,
        imported,
        received,
        rejected,
        dropped,
        bytes_in: bytes_in.load(Ordering::Relaxed),
        bytes_out: bytes_out.load(Ordering::Relaxed),
        applied_tx: 0,
        consumed: 0,
        applications: 0,
        order_root: [0; 32],
        blocked: None,
        certified: 0,
        progress: AgreementProgress::default(),
        head_height: 0,
        head_round: 0,
        pump,
        local_full,
        local_accepted,
        ticks,
        rejections: rejections.into_iter().collect(),
        error: None,
    };
    drop(channels.local);
    drop(channels.frames);
    match pump_task.await {
        Ok((owner, result)) => {
            match result {
                Ok(()) => {
                    let finalizer = owner.finalization().finalizer();
                    report.certified = finalizer.certified_ids().len();
                    report.head_height = finalizer.head().height;
                    report.head_round = finalizer.head().round;
                    report.applied_tx = owner.finalization().execution().applied();
                    report.consumed = owner.finalization().execution().consumed_order().len();
                    report.applications = owner.finalization().execution().applied_slots();
                    report.order_root = owner.finalization().execution().order_root();
                    report.blocked = owner.finalization().execution().blocked().map(
                        |(round, author, payload, id_matches)| {
                            let author = committee
                                .set
                                .validators
                                .iter()
                                .position(|record| record.validator_id == author)
                                .unwrap_or(usize::MAX);
                            (round, author, payload, id_matches)
                        },
                    );
                }
                Err(error) => report.error = Some(error),
            }
            // One durable read per node after the pump ends: the final view, certificate
            // and current-view carrier counts distinguish view divergence from a stalled
            // proposal, vote, aggregate or causal quorum.
            match owner.progress_diagnostics() {
                Ok(progress) => report.progress = progress,
                Err(error) => {
                    if report.error.is_none() {
                        report.error = Some(error);
                    }
                }
            }
        }
        Err(error) => report.error = Some(format!("certified pump stopped: {error}")),
    }
    let _ = dispatcher.await;
    if let Some(error) = &report.error {
        eprintln!("certified node {index}: {error}");
    }
    Ok(report)
}

/// Remembers one distinct signed vertex for a bounded causal import turn.
fn remember_vertex(
    seen: &mut BTreeSet<(u64, Vec<u8>, [u8; 32])>,
    pending: &mut Vec<Vertex>,
    vertex: &Vertex,
) {
    if pending.len() >= MAX_PENDING_VERTICES || seen.len() >= MAX_SEEN_VERTICES {
        return;
    }
    let Ok(id) = vertex.id() else { return };
    let key = (id.round, id.author.clone(), id.digest);
    if !seen.insert(key) {
        return;
    }
    pending.push(vertex.clone());
}

fn requeue_vertices(pending: &mut Vec<Vertex>, vertices: Vec<Vertex>) {
    if vertices.len() > MAX_PENDING_VERTICES {
        return;
    }
    let rest = std::mem::take(pending);
    pending.extend(vertices);
    pending.extend(rest);
    pending.truncate(MAX_PENDING_VERTICES);
}

fn remember_share(shares: &mut VecDeque<Share>, share: &Share) {
    if shares
        .iter()
        .any(|old| old.header.height == share.header.height && old.signer == share.signer)
    {
        return;
    }
    if shares.len() >= MAX_PENDING_SHARES {
        shares.pop_front();
    }
    shares.push_back(share.clone());
}

/// Re-injects peer shares whose exact header this node has already built. Reception
/// is still the pump's decision: an early share is kept for a later turn, never
/// adopted from the wire.
fn flush_shares(
    frames: &mut mpsc::Sender<wire::Frame>,
    shares: &mut VecDeque<Share>,
    built_height: u64,
    dropped: &mut u64,
) {
    let mut deferred = Vec::new();
    for _ in 0..MAX_SHARES_PER_TURN {
        let Some(share) = shares.pop_front() else {
            break;
        };
        if share.header.height > built_height {
            deferred.push(share);
            continue;
        }
        let frame = wire::Frame {
            sent_at_nanos: super::unix_nanos(),
            len: 0,
            message: Message::Share(share),
        };
        if frames.try_send(frame).is_err() {
            *dropped = dropped.saturating_add(1);
            break;
        }
    }
    for share in deferred {
        shares.push_front(share);
    }
}
