//! Opt-in live certified session over the existing peer transport.
//!
//! The legacy loop decides slots with its own commit rules and builds headers from that
//! order. This task keeps the same TCP mesh and the same plain causal vertices, but the
//! durable certified session owns ordering, execution and header production. It is a
//! bounded first live wiring, not a production authority claim:
//!
//! - every node opens a fresh certified session from the same trusted genesis. A live
//!   run refuses to resume a durable session: payload bytes and the owned causal DAG
//!   are volatile here, so offline recovery stays a separate caller-driven path;
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
//! - with `--execute --rpc-port`, client-signed transactions are the only payload source:
//!   the node serves `POST /tx`, takes a bounded batch from its mempool on an authoring
//!   turn, names its digest in a plain causal vertex, and retains the bytes for
//!   retransmission once applied certified ordering requires them. Peers admit the
//!   payload after they apply the same slot, and any holder answers an exact
//!   `PayloadWant`. The request changes who triggers delivery, not the no-acknowledgement
//!   contract. Without `--rpc-port`, payload hashes stay zero and applied slots order
//!   vertices without executing transactions;
//! - no snapshot, epoch transition, pruning or delivery acknowledgement is wired here.
//!   The certified RPC surface accepts submissions only: execution state, account reads
//!   and finality status stay unpublished, so the full legacy router is not mounted.
//!
//! The single-validator path is proven end to end: plain causal rounds decide whenever a
//! majority of authors is held, the initial proposal and view bind, durable votes follow,
//! and the decided slot executes into a header whose share and certificate persist. The
//! multi-validator mesh routes the same evidence over the same links: durable reads reuse a
//! verified replay, refused peer receipts are dropped instead of poisoning the owner, and a
//! single elected publisher owns the shared POL carrier. A bounded three-validator test
//! certifies the first slots on every node. Without `--execute`, payloads stay zero and
//! slots order without executing transactions; with `--execute --rpc-port`, a client-signed
//! transaction submitted over HTTP crosses the same certified path, and every node applies it
//! after the slot that names it is decided. Multi-slot progress is not free at this size: the causal DAG
//! requires a quorum of the previous round's authors, and a three-validator set has no
//! spare author, so every node has to fill every round before the next one is reference
//! ready. The test therefore proves the first decisions, not sustained slot throughput.
//!
//! The owner's causal import budget bounds one run, and both histories stay mutually
//! exclusive on disk: a store holding a legacy chain is refused by the session opener.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
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
use validator::{EpochSchedule, Header, Share, Vertex, VertexId, commit_root};

use super::agreement::AgreementProgress;
use super::agreement::event_pump::{EventPump, LocalEvent, PumpSnapshot};
use super::agreement::output_dispatcher::{self, SharePeer};
use super::agreement::{pacemaker, session};
use super::{Config, Link, LinkTask, credited_genesis};
use crate::chain;
use crate::rpc::{self, RpcCore};

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
    /// Exact applied certified entries; empty when the node did not stop cleanly.
    order: Vec<VertexId>,
    /// Exact headers this node built, keyed by height.
    headers: BTreeMap<u64, Header>,
    blocked: Option<(u64, usize, [u8; 32], bool)>,
    certified: usize,
    progress: AgreementProgress,
    head_height: u64,
    head_round: u64,
    pump: PumpSnapshot,
    local_full: u64,
    local_accepted: u64,
    /// Distinct mempool batches taken from the RPC source.
    taken_batches: usize,
    /// Taken batches a receipt confirmed as named by an authored vertex.
    named_batches: usize,
    /// Round of the vertex that named the last taken batch, if one was named.
    named_round: Option<u64>,
    /// Standalone causal vertices received from peers.
    vertex_frames: usize,
    /// Vertices received inside authenticated carrier exports.
    carrier_vertices: usize,
    /// Distinct vertices queued for a trusted import turn.
    queued_vertices: usize,
    /// Import turns that actually carried vertices.
    drive_turns: u64,
    execution_rejected: Vec<(&'static str, usize)>,
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
        return Err(match failures.first() {
            Some(failure) => format!("no certified node reported a result: {failure}").into(),
            None => "no certified node reported a result".into(),
        });
    }
    if reports.iter().any(|report| report.error.is_some()) {
        // Keep the first concrete node error: a stopped node's reason is the actionable
        // part, and the aggregate message alone hides it.
        let reason = reports
            .iter()
            .find_map(|report| report.error.as_deref())
            .unwrap_or("unknown error");
        return Err(format!("at least one certified node stopped with an error: {reason}").into());
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
    // Certification fixes the entry at every applied index, so comparing the applied
    // prefixes is what separates an ordinary laggard from a fork. It grants no authority:
    // execution still comes only from the node's own certified ordering.
    let relation = order_relation(
        &reports
            .iter()
            .map(|report| (report.index, report.order.as_slice()))
            .collect::<Vec<_>>(),
    );
    match &relation {
        Some(OrderRelation::Identical { len }) => println!(
            "  order:      identical {len} entries on {} nodes",
            reports.len()
        ),
        Some(OrderRelation::Lagging {
            laggard,
            ahead,
            shared,
        }) => println!("  order:      node {laggard} lags node {ahead}: {shared} shared entries"),
        Some(OrderRelation::Fork { index, left, right }) => {
            println!("  order:      forked at entry {index}: nodes {left} and {right} differ")
        }
        None => {}
    }
    if let Some(OrderRelation::Fork { index, left, right }) = relation {
        return Err(format!(
            "certified ordering forked at entry {index}: nodes {left} and {right} applied different entries"
        )
        .into());
    }
    // The same certified entries and payloads must produce the same header. Comparing the
    // highest height every node reached is the strongest execution check this report can
    // make; a differing field is divergence, not lag.
    let headers = header_relation(
        &reports
            .iter()
            .map(|report| (report.index, &report.headers))
            .collect::<Vec<_>>(),
    );
    match &headers {
        HeaderRelation::Identical { height } if *height > 0 => println!(
            "  headers:    identical at height {height} on {} nodes",
            reports.len()
        ),
        HeaderRelation::Divergent {
            height,
            left,
            right,
            field,
        } => println!(
            "  headers:    divergent at height {height}: nodes {left} and {right} disagree on {field}"
        ),
        _ => {}
    }
    if let HeaderRelation::Divergent {
        height,
        left,
        right,
        field,
    } = headers
    {
        return Err(format!(
            "certified headers diverge at height {height}: nodes {left} and {right} disagree on {field}"
        )
        .into());
    }
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

/// How the applied certified orders of a finished run relate to each other.
#[derive(Debug, PartialEq, Eq)]
enum OrderRelation {
    /// Every node applied the same entries.
    Identical { len: usize },
    /// One node stopped before applying entries another node already had: ordinary lag.
    Lagging {
        laggard: usize,
        ahead: usize,
        shared: usize,
    },
    /// Two nodes applied different entries at the same index: not lag, a fork.
    Fork {
        index: usize,
        left: usize,
        right: usize,
    },
}

/// Compares independently applied certified orders, pairwise against the first node.
///
/// Every order is compared with the first one: prefix-consistent orders are transitive, so
/// two later nodes that both match the first also match each other. A differing digest at
/// a shared index is a fork; merely fewer entries is lag. Diagnostic only.
fn order_relation(orders: &[(usize, &[VertexId])]) -> Option<OrderRelation> {
    let (first_node, first) = *orders.first()?;
    let mut shared = first.len();
    let mut shortest = (first_node, first.len());
    let mut longest = (first_node, first.len());
    for (node, order) in orders {
        let common = order.len().min(first.len());
        for index in 0..common {
            if order[index].digest != first[index].digest {
                return Some(OrderRelation::Fork {
                    index,
                    left: first_node,
                    right: *node,
                });
            }
        }
        shared = shared.min(common);
        if order.len() < shortest.1 {
            shortest = (*node, order.len());
        }
        if order.len() > longest.1 {
            longest = (*node, order.len());
        }
    }
    if shortest.1 == longest.1 {
        Some(OrderRelation::Identical { len: longest.1 })
    } else {
        Some(OrderRelation::Lagging {
            laggard: shortest.0,
            ahead: longest.0,
            shared,
        })
    }
}

/// How the built headers of a finished run relate.
#[derive(Debug, PartialEq, Eq)]
enum HeaderRelation {
    /// No node built a header.
    Empty,
    /// Every node that reached the comparable height built the identical header.
    Identical { height: u64 },
    /// Two nodes built different headers at the same height: executed entries diverged.
    Divergent {
        height: u64,
        left: usize,
        right: usize,
        field: &'static str,
    },
}

/// Compares the highest header height every node reached, pairwise against the first node.
///
/// Certification fixes the entry at every applied index and payloads are content-addressed,
/// so the same height must yield the identical header. Heights a node never built are the
/// lag the order comparison already reports, never a divergence. Diagnostic only.
fn header_relation(headers: &[(usize, &BTreeMap<u64, Header>)]) -> HeaderRelation {
    let Some(height) = headers
        .iter()
        .filter_map(|(_, built)| built.keys().next_back().copied())
        .min()
    else {
        return HeaderRelation::Empty;
    };
    let mut first: Option<(usize, &Header)> = None;
    for (node, built) in headers {
        let Some(header) = built.get(&height) else {
            continue;
        };
        match first {
            None => first = Some((*node, header)),
            Some((left, expected)) if expected != header => {
                let field = if header.state_root != expected.state_root {
                    "state root"
                } else if header.dag_root != expected.dag_root {
                    "commit root"
                } else if header.previous != expected.previous {
                    "previous header"
                } else {
                    "applied count"
                };
                return HeaderRelation::Divergent {
                    height,
                    left,
                    right: *node,
                    field,
                };
            }
            Some(_) => {}
        }
    }
    HeaderRelation::Identical { height }
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
        "{prefix}pump:       {} local turns {} (max {}), {} frames {}, {} wakes {}; {} ticks, {} local accepted, {} refused, {} payload wants, {} served, {} early",
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
        p.payload_served,
        p.payload_early
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
    let held = report
        .progress
        .held_by_round
        .iter()
        .rev()
        .take(12)
        .rev()
        .map(|(round, authors)| format!("{round}:{authors}"))
        .collect::<Vec<_>>()
        .join(" ");
    let held = if held.is_empty() {
        String::from("-")
    } else {
        held
    };
    println!(
        "{prefix}availability: {} vertices held (round:authors {held}), {} empty rounds {:?}, next authoring round {} references {}/{} previous-round authors, next decision round {}",
        report.progress.held_vertices,
        report.progress.empty_rounds,
        report.progress.first_empty_rounds,
        report.progress.own_hole,
        report.progress.write_round_authors,
        report.progress.write_round_quorum,
        report.progress.next_round
    );
    println!(
        "{prefix}imports:     {} vertex frames, {} carrier vertices, {} queued distinct, {} drive turns",
        report.vertex_frames, report.carrier_vertices, report.queued_vertices, report.drive_turns
    );
    println!(
        "{prefix}rpc:        {} batches taken, {} named by a vertex at round {}",
        report.taken_batches,
        report.named_batches,
        report
            .named_round
            .map_or_else(|| String::from("none"), |round| round.to_string())
    );
    for (reason, count) in &report.execution_rejected {
        println!("{prefix}execution:  {count}x rejected transaction ({reason})");
    }
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
    // The certified session is the only execution authority, so the RPC surface here is
    // submission-only: a client-signed envelope enters the local mempool and the certified
    // authoring turn names its batch. Reads stay off until certified execution publishes
    // state, because a full router would answer from legacy defaults it never fills.
    let rpc = if config.rpc_port > 0 {
        let target = super::rpc_address(config.rpc_port, index)?;
        let listener = tokio::net::TcpListener::bind(&target)
            .await
            .map_err(|error| format!("node {index} cannot listen for RPC on {target}: {error}"))?;
        let shared = Arc::new(Mutex::new(RpcCore::new(
            index,
            chain_id.clone(),
            &committee.accounts,
            &genesis,
            total,
        )));
        shared
            .lock()
            .expect("rpc lock poisoned")
            .note_state(0, &genesis_state);
        let mut rpc_shutdown = shutdown.clone();
        let app = rpc::submission_router(Arc::clone(&shared));
        tokio::spawn(async move {
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rpc_shutdown.changed().await;
                })
                .await;
            if let Err(error) = served {
                eprintln!("certified node {index} RPC server stopped: {error}");
            }
        });
        Some(shared)
    } else {
        None
    };
    if store
        .has_authenticated_slot_agreement()
        .map_err(|error| error.to_string())?
    {
        // A live run cannot resume durable agreement state: the admitted payload index,
        // the owned causal DAG and the volatile control classification are not recovered,
        // so a resumed node would still decide nothing. Refuse instead of running a
        // degraded session; offline recovery remains an explicit caller-driven path.
        return Err(format!(
            "node {index} cannot resume a durable certified session: payload bytes and owned causal history are volatile; start a fresh store"
        ));
    }
    let mut owner = session::open_at_genesis(
        &store,
        &committee,
        index,
        &genesis,
        genesis_state,
        epoch_schedule,
    )?;
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
    // A run without an RPC source keeps the order-only zero-payload path: payload hashes
    // stay zero and applied slots order vertices without executing transactions.
    let authored_payloads = config.execute && config.rpc_port > 0;
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
    let mut vertex_frames = 0usize;
    let mut carrier_vertices = 0usize;
    let mut queued_vertices = 0usize;
    let mut drive_turns = 0u64;
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
    // The batch taken from the mempool stays here until a naming vertex actually appears in
    // a receipt. Authoring can legitimately decline a free local round, and a taken batch is
    // already marked as batched in the mempool, so dropping it on send would strand the
    // client's transactions in a state the loop cannot see.
    let mut held_batch: Option<tx::batch::Batch> = None;
    let mut taken_batches = 0usize;
    let mut named_batches = 0usize;
    let mut named_round: Option<u64> = None;
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
                        vertex_frames = vertex_frames.saturating_add(1);
                        if remember_vertex(&mut seen, &mut pending, vertex) {
                            queued_vertices = queued_vertices.saturating_add(1);
                        }
                        continue;
                    }
                    Message::AgreementCarrier { vertices, .. } => {
                        for vertex in vertices {
                            carrier_vertices = carrier_vertices.saturating_add(1);
                            if remember_vertex(&mut seen, &mut pending, vertex) {
                                queued_vertices = queued_vertices.saturating_add(1);
                            }
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
                    // Client-signed transactions are the only payload source. The batch is
                    // taken once and retried here until a naming vertex is observed, so a
                    // declined local round does not lose the transaction or reorder it.
                    let pending = match held_batch.clone() {
                        Some(batch) => Some(batch),
                        None => rpc.as_ref().and_then(|rpc| {
                            let batch = rpc
                                .lock()
                                .expect("rpc lock poisoned")
                                .take_batch(config.rpc_batch_max);
                            if batch.is_some() {
                                taken_batches = taken_batches.saturating_add(1);
                            }
                            batch
                        }),
                    };
                    let event = match pending {
                        Some(batch) => {
                            held_batch = Some(batch.clone());
                            LocalEvent::AuthorCausalBatch {
                                vertices: Vec::new(),
                                batch,
                            }
                        }
                        None => LocalEvent::AuthorCausal {
                            payload_hash: [0u8; 32],
                            vertices: Vec::new(),
                        },
                    };
                    match channels.local.try_send(event) {
                        Ok(()) => {
                            local_accepted = local_accepted.saturating_add(1);
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
                        drive_turns = drive_turns.saturating_add(1);
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
                // Only a naming vertex clears the held batch. A peer frame or a maintenance
                // turn can produce a receipt too, so the check is the payload digest on the
                // vertex itself, not the receipt order.
                let named = held_batch.as_ref().is_some_and(|batch| {
                    batch.digest().is_ok_and(|digest| {
                        receipt.local.carriers.iter().any(
                            |message| matches!(message, Message::Vertex(vertex) if vertex.payload_hash == digest),
                        )
                    })
                });
                if named {
                    // Evidence for the frontier question: the round a payload entered the
                    // causal DAG has to be below a leader a slot can still decide.
                    let digest = held_batch.as_ref().and_then(|batch| batch.digest().ok());
                    named_round = receipt.local.carriers.iter().find_map(|message| match message {
                        Message::Vertex(vertex)
                            if digest.is_some_and(|digest| vertex.payload_hash == digest) =>
                        {
                            Some(vertex.round)
                        }
                        _ => None,
                    });
                    held_batch = None;
                    named_batches = named_batches.saturating_add(1);
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
        order: Vec::new(),
        headers: BTreeMap::new(),
        blocked: None,
        certified: 0,
        progress: AgreementProgress::default(),
        head_height: 0,
        head_round: 0,
        pump,
        local_full,
        local_accepted,
        taken_batches,
        named_batches,
        named_round,
        vertex_frames,
        carrier_vertices,
        queued_vertices,
        drive_turns,
        execution_rejected: Vec::new(),
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
                    report.order = owner.finalization().execution().applied_order().to_vec();
                    report.headers = owner.finalization().built_headers().clone();
                    report.execution_rejected = owner
                        .finalization()
                        .execution()
                        .rejected()
                        .iter()
                        .map(|(reason, count)| (*reason, *count))
                        .collect();
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
/// Returns whether the vertex was newly queued.
fn remember_vertex(
    seen: &mut BTreeSet<(u64, Vec<u8>, [u8; 32])>,
    pending: &mut Vec<Vertex>,
    vertex: &Vertex,
) -> bool {
    if pending.len() >= MAX_PENDING_VERTICES || seen.len() >= MAX_SEEN_VERTICES {
        return false;
    }
    let Ok(id) = vertex.id() else { return false };
    let key = (id.round, id.author.clone(), id.digest);
    if !seen.insert(key) {
        return false;
    }
    pending.push(vertex.clone());
    true
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

#[cfg(test)]
mod tests {
    use super::{HeaderRelation, OrderRelation, header_relation, order_relation};
    use std::collections::BTreeMap;
    use validator::{Header, VertexId};

    fn entry(round: u64, digest: u8) -> VertexId {
        VertexId {
            round,
            author: vec![0],
            digest: [digest; 32],
        }
    }

    fn header(height: u64, state_root: u8) -> Header {
        Header {
            chain_id: b"karsa".to_vec(),
            epoch: 0,
            height,
            round: height,
            state_root: [state_root; 32],
            dag_root: [7; 32],
            previous: [8; 32],
            applied: height * 3,
        }
    }

    fn built(headers: &[Header]) -> BTreeMap<u64, Header> {
        headers
            .iter()
            .map(|header| (header.height, header.clone()))
            .collect()
    }

    /// Independent nodes that stop at different moments share their prefix.
    #[test]
    fn a_shorter_applied_order_is_a_laggard_not_a_fork() {
        let first = [entry(1, 1), entry(2, 2), entry(3, 3)];
        let shorter = [entry(1, 1), entry(2, 2)];
        let relation = order_relation(&[(0, &first), (2, &shorter)]).unwrap();
        assert_eq!(
            relation,
            OrderRelation::Lagging {
                laggard: 2,
                ahead: 0,
                shared: 2
            }
        );
    }

    /// Equal lengths with one different digest is divergence, not lag.
    #[test]
    fn a_different_entry_at_a_shared_index_is_a_fork() {
        let first = [entry(1, 1), entry(2, 2)];
        let other = [entry(1, 1), entry(2, 9)];
        assert_eq!(
            order_relation(&[(0, &first), (1, &other)]).unwrap(),
            OrderRelation::Fork {
                index: 1,
                left: 0,
                right: 1
            }
        );
    }

    #[test]
    fn identical_prefixes_compare_as_identical() {
        let first = [entry(1, 1), entry(2, 2)];
        let same = [entry(1, 1), entry(2, 2)];
        let empty: [VertexId; 0] = [];
        assert_eq!(
            order_relation(&[(0, &first), (1, &same), (2, &empty)]).unwrap(),
            OrderRelation::Lagging {
                laggard: 2,
                ahead: 0,
                shared: 0
            }
        );
        assert_eq!(
            order_relation(&[(0, &first), (1, &same)]).unwrap(),
            OrderRelation::Identical { len: 2 }
        );
        assert_eq!(order_relation(&[]), None);
    }

    /// The highest height every node reached is the strongest available header check.
    #[test]
    fn a_lower_header_height_is_compared_at_the_shared_height() {
        let ahead = built(&[header(1, 1), header(2, 2), header(3, 3)]);
        let behind = built(&[header(1, 1), header(2, 2)]);
        assert_eq!(
            header_relation(&[(0, &ahead), (1, &behind)]),
            HeaderRelation::Identical { height: 2 }
        );
    }

    #[test]
    fn a_different_state_root_at_the_same_height_is_divergence() {
        let first = built(&[header(1, 1), header(2, 2)]);
        let other = built(&[header(1, 1), header(2, 9)]);
        assert_eq!(
            header_relation(&[(0, &first), (2, &other)]),
            HeaderRelation::Divergent {
                height: 2,
                left: 0,
                right: 2,
                field: "state root"
            }
        );
        let empty = BTreeMap::new();
        assert_eq!(header_relation(&[(0, &empty)]), HeaderRelation::Empty);
    }
}
