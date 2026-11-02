//! Real sockets between validator nodes on loopback.
//!
//! Every other command in this workspace moves vertices through a deterministic
//! queue. This one puts them on TCP, one listener per node, full mesh, with a
//! length-prefixed frame and nothing else added.
//!
//! # What it measures that the simulator cannot
//!
//! - **Framing.** A stream has no message boundaries, so a vertex can arrive in
//!   two reads. The parser is tested against that; here it runs for real.
//! - **Out-of-order arrival.** The simulator delivers in a fixed order, so a vertex
//!   never arrives before the vertices it references. On a socket it does, and the
//!   DAG rejects it. Those vertices are deferred and retried, and the deferral count
//!   is printed rather than hidden — it is a property of the transport, not a bug.
//! - **Backpressure instead of a drop policy.** Each peer has a bounded queue and
//!   the writer awaits it, so a slow reader slows its sender rather than losing a
//!   vertex. `--slow-ms` delays one node on purpose: with backpressure, a slow
//!   validator costs the whole committee throughput. That is the head-of-line
//!   problem a dissemination design has to answer, and it is cheaper to see it here
//!   than to reason about it.
//!
//! # What it does not measure
//!
//! All nodes are in one process on one machine, so the numbers describe the wire
//! and the runtime, not independent operators. There is no encryption, no
//! handshake, no retransmission, and no peer discovery: the mesh is fixed by
//! `--validators`.

use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use crypto::CryptoErrorKind;
use net::Node;
use net::wire::{self, Frame};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use validator::commit_root;

use crate::chain;

/// Vertices a node will hold while waiting for the ones they reference.
const DEFERRED_LIMIT: usize = 4096;
/// Queue depth per peer, in frames.
const QUEUE: usize = 4096;
/// How long to keep retrying a connection before giving up.
const CONNECT_TRIES: usize = 400;
/// Tick period: the authoring and pacemaker cadence.
const TICK: Duration = Duration::from_millis(2);

/// How a live run is configured.
#[derive(Clone)]
pub struct Config {
    /// Committee size.
    pub validators: usize,
    /// First loopback port; node `i` uses `port_base + i`.
    pub port_base: u16,
    /// Rounds each node authors before the run is allowed to stop.
    pub rounds: u64,
    /// Artificial per-frame delay on node 1, in milliseconds.
    pub slow_ms: u64,
    /// Wall-clock cap on the whole run.
    pub timeout: Duration,
    /// How long to keep the mesh alive after the last node finishes authoring,
    /// so the final rounds can actually propagate before the run is measured.
    pub drain: Duration,
}

/// What one node saw.
struct NodeResult {
    index: usize,
    authored: usize,
    received: usize,
    deferred_max: usize,
    rejected: usize,
    committed: usize,
    bytes_in: u64,
    bytes_out: u64,
    latencies: Vec<u64>,
    commit_root: [u8; 32],
    order: Vec<validator::VertexId>,
}

fn address(port_base: u16, index: usize) -> String {
    format!(
        "127.0.0.1:{}",
        u32::from(port_base) + u32::try_from(index).unwrap_or(0)
    )
}

/// Reads frames from one peer and hands them to the node loop.
async fn read_peer(
    mut stream: TcpStream,
    frames: mpsc::Sender<Frame>,
    bytes_in: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut buffer: Vec<u8> = Vec::with_capacity(64 * 1024);
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        tokio::select! {
            read = stream.read(&mut chunk) => {
                let Ok(read) = read else { break };
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                bytes_in.fetch_add(read as u64, Ordering::Relaxed);
                loop {
                    match wire::take_frame(&mut buffer) {
                        Ok(Some(frame)) => {
                            if frames.send(frame).await.is_err() {
                                return;
                            }
                        }
                        // Not yet: more bytes are on the way.
                        Ok(None) => break,
                        // A peer that sends an unparseable frame is disconnected
                        // rather than trusted to resynchronise.
                        Err(_) => return,
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Writes frames to one peer, awaiting the queue so a slow reader applies
/// backpressure instead of losing data.
async fn write_peer(
    mut stream: TcpStream,
    mut outbound: mpsc::Receiver<Vec<u8>>,
    bytes_out: Arc<AtomicU64>,
) {
    while let Some(bytes) = outbound.recv().await {
        if stream.write_all(&bytes).await.is_err() {
            break;
        }
        bytes_out.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }
    let _ = stream.shutdown().await;
}

/// Retries every deferred vertex after a successful insert.
///
/// Returns how many are still waiting. A vertex whose failure is not
/// `missing_reference` is a bad vertex, not an early one, so it is dropped and
/// counted instead of being retried forever.
fn drain_deferred(node: &mut Node, deferred: &mut Vec<Frame>, rejected: &mut usize) -> usize {
    let mut progressed = true;
    while progressed {
        progressed = false;
        let mut index = 0;
        while index < deferred.len() {
            match node.receive(deferred[index].vertex.clone()) {
                Ok(()) => {
                    deferred.swap_remove(index);
                    progressed = true;
                }
                Err(error) if error.kind() == CryptoErrorKind::MissingReference => index += 1,
                Err(_) => {
                    deferred.swap_remove(index);
                    *rejected += 1;
                }
            }
        }
    }
    deferred.len()
}

async fn node_task(
    index: usize,
    config: &Config,
    started: Instant,
    mut shutdown: watch::Receiver<bool>,
    ready: mpsc::Sender<usize>,
) -> Result<NodeResult, String> {
    let (set, consensus) =
        chain::consensus_set(config.validators).map_err(|error| error.to_string())?;
    let identity = consensus
        .get(index)
        .ok_or("no consensus key for this node")?;
    let mut node = Node::new(set, identity.id.clone(), identity.private_key.clone());

    let listener = TcpListener::bind(address(config.port_base, index))
        .await
        .map_err(|error| format!("node {index} cannot listen: {error}"))?;

    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    let (frames_tx, mut frames_rx) = mpsc::channel(QUEUE);

    // Inbound: accept from every peer.
    {
        let frames_tx = frames_tx.clone();
        let bytes_in = Arc::clone(&bytes_in);
        let mut shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((stream, _)) = accepted else { return };
                        let frames_tx = frames_tx.clone();
                        let bytes_in = Arc::clone(&bytes_in);
                        let shutdown = shutdown.clone();
                        tokio::spawn(async move {
                            read_peer(stream, frames_tx, bytes_in, shutdown).await;
                        });
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
    }

    // Outbound: one link per peer, connected with retries because the nodes start
    // together and a listener may not exist yet.
    let mut outbound: Vec<mpsc::Sender<Vec<u8>>> = Vec::with_capacity(config.validators - 1);
    for peer in 0..config.validators {
        if peer == index {
            continue;
        }
        let target = address(config.port_base, peer);
        let mut attempt = 0usize;
        let stream = loop {
            match TcpStream::connect(&target).await {
                Ok(stream) => break stream,
                Err(error) => {
                    attempt += 1;
                    if attempt >= CONNECT_TRIES {
                        return Err(format!("node {index} cannot reach {target}: {error}"));
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        };
        let (out_tx, out_rx) = mpsc::channel(QUEUE);
        outbound.push(out_tx);
        let bytes_out = Arc::clone(&bytes_out);
        tokio::spawn(async move {
            write_peer(stream, out_rx, bytes_out).await;
        });
    }

    let mut deferred: Vec<Frame> = Vec::new();
    let mut latencies: Vec<u64> = Vec::new();
    let mut received = 0usize;
    let mut deferred_max = 0usize;
    let mut rejected = 0usize;
    let mut announced = false;
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            frame = frames_rx.recv() => {
                let Some(frame) = frame else { break };
                received += 1;
                let now = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                latencies.push(now.saturating_sub(frame.sent_at_nanos));
                if config.slow_ms > 0 && index == 1 {
                    tokio::time::sleep(Duration::from_millis(config.slow_ms)).await;
                }
                match node.receive(frame.vertex.clone()) {
                    Ok(()) => {}
                    Err(error) if error.kind() == CryptoErrorKind::MissingReference => {
                        if deferred.len() < DEFERRED_LIMIT {
                            deferred.push(frame);
                        } else {
                            rejected += 1;
                        }
                    }
                    Err(_) => rejected += 1,
                }
                let waiting = drain_deferred(&mut node, &mut deferred, &mut rejected);
                deferred_max = deferred_max.max(waiting);
            }
            _ = ticker.tick() => {
                if node.round() <= config.rounds {
                    match node.author() {
                        Ok(Some(vertex)) => {
                            let now = u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);
                            let bytes = wire::frame(&vertex, now).map_err(|error| error.to_string())?;
                            for queue in &outbound {
                                // Awaiting is the drop policy: none. A peer that cannot
                                // keep up slows this node instead of losing a vertex.
                                if queue.send(bytes.clone()).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(None) => {}
                        Err(error) => return Err(format!("node {index} cannot author: {error}")),
                    }
                }
                // A commit whose leader history is not fully here yet is a
                // delivery condition, not a failure: the referenced vertex may
                // still be in a peer's queue. Leaving the cursor where it is and
                // retrying on the next tick is what keeps a slow link from
                // killing a validator.
                let step = node.commit();
                match step {
                    Ok(_) => {}
                    Err(error) if error.kind() == CryptoErrorKind::MissingReference => {}
                    Err(error) => {
                        return Err(format!("node {index} cannot commit: {error}"));
                    }
                }
                if !announced && node.round() > config.rounds {
                    announced = true;
                    let _ = ready.send(index).await;
                }
            }
            _ = shutdown.changed() => break,
        }
    }

    Ok(NodeResult {
        index,
        authored: node.authored(),
        received,
        deferred_max,
        rejected,
        committed: node.dag().order().len(),
        bytes_in: bytes_in.load(Ordering::Relaxed),
        bytes_out: bytes_out.load(Ordering::Relaxed),
        latencies,
        commit_root: commit_root(node.dag().order()),
        order: node.dag().order().to_vec(),
    })
}

fn pad(value: &str, width: usize) -> String {
    format!("{value:>width$}")
}

fn left(value: &str, width: usize) -> String {
    format!("{value:<width$}")
}

fn human(bytes: u64) -> String {
    let value = bytes as f64;
    if value >= 1e6 {
        format!("{:.1} MB", value / 1e6)
    } else if value >= 1e3 {
        format!("{:.1} kB", value / 1e3)
    } else {
        format!("{bytes} B")
    }
}

fn percentile(sorted: &[u64], percent: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let index = (sorted.len() - 1) * percent / 100;
    sorted[index]
}

fn millis(nanos: u64) -> String {
    format!("{:.2} ms", nanos as f64 / 1e6)
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    if config.validators < 2 {
        return Err("a live run needs at least two nodes".into());
    }
    if config.validators > 64 {
        return Err("at most 64 nodes: this is a loopback mesh, not a network".into());
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let results = runtime.block_on(async {
        let started = Instant::now();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (ready_tx, mut ready_rx) = mpsc::channel(config.validators);

        let mut tasks = Vec::with_capacity(config.validators);
        for index in 0..config.validators {
            let shutdown_rx = shutdown_rx.clone();
            let ready_tx = ready_tx.clone();
            let config = config.clone();
            tasks.push(tokio::spawn(async move {
                node_task(index, &config, started, shutdown_rx, ready_tx).await
            }));
        }
        drop(ready_tx);

        // Every node announces when it has authored its rounds; then the mesh is
        // kept alive for the drain period, because the last rounds are still on
        // the wire and a root taken at that instant would measure the shutdown
        // rather than the chain.
        let mut announced = 0usize;
        let deadline = tokio::time::sleep(config.timeout);
        tokio::pin!(deadline);
        loop {
            tokio::select! {
                Some(_) = ready_rx.recv() => {
                    announced += 1;
                    if announced == config.validators {
                        break;
                    }
                }
                _ = &mut deadline => break,
            }
        }
        // Measured before the drain, so it is the authoring pace rather than the
        // pace plus a fixed 500 ms wait for the last frames.
        let authoring = started.elapsed();
        tokio::time::sleep(config.drain).await;
        let _ = shutdown_tx.send(true);

        let mut results = Vec::with_capacity(tasks.len());
        for task in tasks {
            match task.await {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(error)) => eprintln!("node failed: {error}"),
                Err(error) => eprintln!("node panicked or was cancelled: {error}"),
            }
        }
        (results, announced, authoring, started.elapsed())
    });

    let (mut results, announced, authoring, elapsed) = results;
    results.sort_by_key(|result| result.index);
    if results.is_empty() {
        return Err("no node reported a result".into());
    }

    println!("== Live sockets between validator nodes ==");
    println!(
        "  {} nodes on 127.0.0.1:{}..={}, full mesh, {} rounds each{}",
        config.validators,
        config.port_base,
        u32::from(config.port_base) + u32::try_from(config.validators - 1).unwrap_or(0),
        config.rounds,
        if config.slow_ms > 0 {
            format!(", node 1 slowed by {} ms per frame", config.slow_ms)
        } else {
            String::new()
        }
    );
    println!(
        "  wall clock: {} ({} of {} nodes finished authoring)",
        millis(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX)),
        announced,
        config.validators
    );
    if announced == config.validators {
        let pace = (config.rounds + 1) as f64 / authoring.as_secs_f64();
        println!(
            "  authoring:  {} for {} rounds per node ({pace:.1} rounds/s, {:.2} ms/round)",
            millis(u64::try_from(authoring.as_nanos()).unwrap_or(u64::MAX)),
            config.rounds + 1,
            authoring.as_secs_f64() * 1e3 / (config.rounds + 1) as f64
        );
    }
    println!();
    println!(
        "  {}  {}  {}  {}  {}  {}  {}  {}",
        left("node", 7),
        pad("authored", 9),
        pad("received", 9),
        pad("deferred", 9),
        pad("rejected", 9),
        pad("committed", 10),
        pad("in", 10),
        pad("out", 10)
    );

    let mut latencies: Vec<u64> = Vec::new();
    let mut bytes_in = 0u64;
    let mut bytes_out = 0u64;
    let mut roots: Vec<[u8; 32]> = Vec::new();
    for result in &results {
        bytes_in += result.bytes_in;
        bytes_out += result.bytes_out;
        roots.push(result.commit_root);
        latencies.extend_from_slice(&result.latencies);
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}",
            left(&format!("val-{}", result.index), 7),
            pad(&result.authored.to_string(), 9),
            pad(&result.received.to_string(), 9),
            pad(&result.deferred_max.to_string(), 9),
            pad(&result.rejected.to_string(), 9),
            pad(&result.committed.to_string(), 10),
            pad(&human(result.bytes_in), 10),
            pad(&human(result.bytes_out), 10)
        );
    }

    latencies.sort_unstable();
    println!();
    println!(
        "  delivery latency  p50 {}  p90 {}  p99 {}  max {}  ({} frames)",
        millis(percentile(&latencies, 50)),
        millis(percentile(&latencies, 90)),
        millis(percentile(&latencies, 99)),
        millis(percentile(&latencies, 100)),
        latencies.len()
    );
    println!(
        "  on the wire       {} in, {} out, {} frames",
        human(bytes_in),
        human(bytes_out),
        results.iter().map(|result| result.received).sum::<usize>()
    );
    let agreed = roots.windows(2).all(|pair| pair[0] == pair[1]);
    println!("  same commit root  {agreed}");
    if !agreed {
        for (index, root) in roots.iter().enumerate() {
            println!("    val-{index} {}", hex::encode(&root[..6]));
        }
        // A root difference is either a different committed *set* or the same set
        // in a different order. Say which one, because they have different causes.
        let reference = &results[0].order;
        for result in &results[1..] {
            let first_order = reference
                .iter()
                .zip(&result.order)
                .position(|(left, right)| left != right);
            let mut left_only: Vec<_> = reference
                .iter()
                .filter(|vertex| !result.order.contains(vertex))
                .collect();
            let mut right_only: Vec<_> = result
                .order
                .iter()
                .filter(|vertex| !reference.contains(vertex))
                .collect();
            left_only.sort_by_key(|vertex| (vertex.round, vertex.author.clone()));
            right_only.sort_by_key(|vertex| (vertex.round, vertex.author.clone()));
            if first_order.is_some() || !left_only.is_empty() || !right_only.is_empty() {
                println!(
                    "    val-0 vs val-{}: first order difference at {:?}, set {} vs {} ({} only in val-0, {} only in val-{})",
                    result.index,
                    first_order,
                    reference.len(),
                    result.order.len(),
                    left_only.len(),
                    right_only.len(),
                    result.index
                );
                for vertex in left_only.iter().take(3) {
                    println!(
                        "      only val-0: round {} {}",
                        vertex.round,
                        String::from_utf8_lossy(&vertex.author)
                    );
                }
                for vertex in right_only.iter().take(3) {
                    println!(
                        "      only val-{}: round {} {}",
                        result.index,
                        vertex.round,
                        String::from_utf8_lossy(&vertex.author)
                    );
                }
                if let Some(position) = first_order {
                    let start = position.saturating_sub(3);
                    let end = (position + 4).min(reference.len().min(result.order.len()));
                    for (index, (left, right)) in reference.iter().zip(&result.order).enumerate() {
                        if index < start || index >= end {
                            continue;
                        }
                        println!(
                            "      [{index}] val-0 round {} {}  |  val-{} round {} {}{}",
                            left.round,
                            String::from_utf8_lossy(&left.author),
                            result.index,
                            right.round,
                            String::from_utf8_lossy(&right.author),
                            if index == position { "  <-- first" } else { "" }
                        );
                    }
                }
            }
        }
    }

    println!();
    println!("  Deferred vertices are not lost data: they arrived before the round they");
    println!("  reference, and the DAG refused them until it could check the rule. Zero");
    println!("  here means the quorum-sized reference rule absorbed the reordering; a");
    println!("  non-zero count is a cost a simulator does not have.");
    if config.slow_ms > 0 {
        println!();
        println!("  The slow node is the point of this run: with backpressure and no drop");
        println!("  policy, its delay propagates to everyone. Payload sharding does not");
        println!("  help here, because consensus vertices are small and every node needs");
        println!("  all of them.");
    }

    if !agreed {
        return Err("nodes did not converge on the same commit root".into());
    }
    Ok(())
}
