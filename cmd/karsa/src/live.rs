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
//! - **Out-of-order arrival.** The simulator delivers in a fixed order; a socket
//!   does not. Insertion is tolerant — the shape rule needs a quorum of distinct
//!   authors, not every edge — so an early vertex is accepted and the gap only
//!   surfaces when a walk needs the missing one. That is why repair scans the held
//!   DAG for dangling references rather than reacting to a rejected insert.
//! - **A drop policy that cannot lose data.** Each peer has a bounded queue. When
//!   it is full the frame is dropped and counted, so one slow reader cannot stall
//!   its sender. Dropping is safe because the reference rule makes the loss
//!   *visible*: the next round's vertices still name the missing id, so the gap sits
//!   in the DAG as a dangling edge, and the node asks a peer for exactly that id.
//!   Nothing is guessed and nothing is lost for good.
//!
//! # What it does not measure
//!
//! All nodes are in one process on one machine, so the numbers describe the wire
//! and the runtime, not independent operators. There is no encryption, no
//! retransmission timer beyond the want sweep, and no peer discovery: the mesh is
//! fixed by `--validators`. A link opens with a hello naming the chain, so two
//! genesis hashes never get as far as exchanging a vertex.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crypto::CryptoErrorKind;
use erasure::Code;
use net::Node;
use net::wire::{self, Message};
use store::Store;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tx::batch::Batch;
use validator::{Step, VertexId, commit_root};

use crate::chain;

/// Ids a node will ask for at once. Beyond this the queue is growing faster than
/// repair can drain it, so the count is reported rather than the memory.
const WANT_LIMIT: usize = 4096;
/// How often an unanswered want is repeated.
const WANT_RETRY: Duration = Duration::from_millis(250);
/// Attempts before a want is abandoned and counted.
const WANT_TRIES: u8 = 8;
/// Control frames a peer may have queued: wants and their answers.
const CONTROL_QUEUE: usize = 256;
/// How long to keep retrying a connection before giving up.
const CONNECT_TRIES: usize = 400;
/// Tick period: the authoring and pacemaker cadence.
const TICK: Duration = Duration::from_millis(2);
/// Ticks between persisted clock samples, about one second at the tick cadence.
///
/// Age-based retention needs a round-to-time map; a second of resolution is far
/// more than pruning days of history needs, and one append per second is cheap.
/// The first sample lands on tick 1 so even a short run leaves an anchor at round
/// zero instead of a store whose history has no known start.
const CLOCK_TICKS: u32 = 500;
/// How often the want sweep runs, in ticks.
const WANT_SWEEP_TICKS: u32 = 25;
/// Ticks the commit cursor must stand still before execution is called caught up.
const QUIET_TICKS: u32 = 50;
/// Balance each demo account starts with in a live run.
///
/// The chain demo funds accounts with a thousand units, which is plenty for a
/// handful of transactions and far too little for a throughput run: at a hundred
/// transactions per batch the fee alone exhausts it within a few rounds and the
/// rest of the run measures rejections instead of execution.
const LIVE_BALANCE: u64 = 1_000_000_000;
/// How long a peer gets to state its chain identity before the link is closed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

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
    /// Frames per peer queue. Small values force drops on purpose, which is the
    /// only way to exercise the repair path on a fast machine.
    pub queue: usize,
    /// Socket send buffer, in bytes. Zero keeps the OS default, which on loopback
    /// is large enough to absorb a whole run — so forcing a drop needs both a small
    /// queue and a small buffer.
    pub send_buffer: usize,
    /// Transactions per authored batch. Zero keeps the data plane empty.
    pub txs: u64,
    /// Extra nodes that store everything and never sign.
    ///
    /// An archive is a role, not a bigger validator: it receives and keeps every
    /// vertex and batch, and produces no vertex of its own. Its presence also makes
    /// the role rule executable rather than a comment in a config file.
    pub archives: usize,
    /// Apply committed batches into an account state and print its root.
    pub execute: bool,
    /// Directory to persist into, one subdirectory per node. Empty keeps everything
    /// in memory, which makes every on-disk figure a model instead of a measurement.
    pub store: PathBuf,
    /// Store one erasure shard per batch instead of the whole payload.
    ///
    /// The code is sized from the committee: `data` shards reconstruct, `n` shards
    /// exist, so one shard per node gives tolerance `n - data` and a per-node
    /// storage of `payload / data`.
    pub shard: bool,
    /// How long to keep the mesh alive after the last node finishes authoring,
    /// so the final rounds and any repair can land before the run is measured.
    pub drain: Duration,
    /// Home directory whose genesis fixes the chain identity.
    ///
    /// The mesh here is still the demo committee, so this does not change who
    /// validates; it changes what the nodes sign over and which chain their hello
    /// announces. Two runs with different genesis hashes refuse each other's links.
    /// `None` keeps the demo identity every other command uses without a home.
    pub home: Option<PathBuf>,
    /// Print where the node's wall time went, one line per stage.
    pub profile: bool,
    /// Sign every batch before the measured window instead of inside the node loop.
    ///
    /// A real client signs before submitting; generating the batch in the validator
    /// would otherwise charge chain throughput for client work.
    pub pre_sign: bool,
    /// Threads used to verify one batch. One keeps the serial path.
    pub verify_threads: usize,
}

/// Wall time spent in the stages the live loop can name.
#[derive(Default, Clone, Copy)]
struct Profile {
    sign: Duration,
    author: Duration,
    commit: Duration,
    verify: Duration,
    state: Duration,
    frame: Duration,
    store: Duration,
}

/// What one node saw.
struct NodeResult {
    index: usize,
    signs: bool,
    authored: usize,
    received: usize,
    dropped: u64,
    wanted: u64,
    repaired: u64,
    served: u64,
    gave_up: u64,
    payloads: usize,
    transactions: usize,
    txs_received: usize,
    payload_bytes: u64,
    missing_payloads: usize,
    applied: usize,
    exec_rejected: usize,
    state_root: Option<[u8; 32]>,
    disk_bytes: u64,
    rejected: usize,
    committed: usize,
    bytes_in: u64,
    bytes_out: u64,
    latencies: Vec<u64>,
    commit_root: [u8; 32],
    order: Vec<VertexId>,
    profile: Profile,
}

fn address(port_base: u16, index: usize) -> String {
    format!(
        "127.0.0.1:{}",
        u32::from(port_base) + u32::try_from(index).unwrap_or(0)
    )
}

/// Renders a vertex author for a diagnostic line.
///
/// The chain runtime authors with 32-byte validator addresses, so this is the same
/// Base58Check form a person sees elsewhere. A short fixture id falls back to text.
fn author_label(author: &[u8]) -> String {
    <[u8; 32]>::try_from(author).map_or_else(
        |_| String::from_utf8_lossy(author).into_owned(),
        |bytes| tx::address::encode(&bytes),
    )
}

/// A short, readable rendering of a chain id for an error message.
fn chain_label(chain_id: &[u8]) -> String {
    let prefix = hex::encode(&chain_id[..chain_id.len().min(6)]);
    if chain_id.len() > 6 {
        format!("{prefix}…")
    } else {
        prefix
    }
}

/// Decides whether a peer's hello describes this chain.
fn check_hello(chain_id: &[u8], hello: &wire::Hello) -> Result<(), String> {
    if hello.protocol != wire::WIRE_PROTOCOL {
        return Err(format!(
            "peer speaks wire protocol {}, this build speaks {}",
            hello.protocol,
            wire::WIRE_PROTOCOL
        ));
    }
    if hello.chain_id != chain_id {
        return Err(format!(
            "peer is on chain {}, this node is on {}",
            chain_label(&hello.chain_id),
            chain_label(chain_id)
        ));
    }
    Ok(())
}

/// Exchanges chain identity before any data frame crosses the link.
///
/// Both sides write first and then read, so neither waits for the other to speak.
/// The genesis hash is the chain's identity (D29); a peer that reports another one
/// is a different chain, and the link is closed before a single vertex is parsed.
/// Bytes that arrived behind the hello stay in `buffer` for [`read_peer`], because a
/// stream has no message boundaries and dropping them would lose the first frame.
async fn handshake(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
    chain_id: &[u8],
) -> Result<(), String> {
    let hello = wire::frame(&Message::Hello(wire::Hello::new(chain_id.to_vec())), 0)
        .map_err(|error| format!("cannot encode the hello: {error}"))?;
    stream
        .write_all(&hello)
        .await
        .map_err(|error| format!("cannot send the hello: {error}"))?;

    let mut chunk = vec![0u8; 4096];
    loop {
        // The first frame on the link has to be the hello; anything else means a
        // peer that skipped the identity check, so there is nothing to buffer for.
        if let Some(frame) = wire::take_frame(buffer)
            .map_err(|error| format!("unreadable frame during the handshake: {error}"))?
        {
            return match frame.message {
                Message::Hello(hello) => check_hello(chain_id, &hello),
                _ => Err("peer sent data before its hello".to_string()),
            };
        }
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("cannot read the hello: {error}"))?;
        if read == 0 {
            return Err("peer closed the link during the handshake".to_string());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Reads frames from one peer and hands them to the node loop.
///
/// `buffer` is what the handshake already read: a frame that arrived in the same
/// segment as the hello is parsed here instead of being thrown away.
async fn read_peer(
    mut stream: TcpStream,
    mut buffer: Vec<u8>,
    frames: mpsc::Sender<wire::Frame>,
    bytes_in: Arc<AtomicU64>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut chunk = vec![0u8; 64 * 1024];
    loop {
        // Drain whatever is already buffered before waiting for more bytes.
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
        tokio::select! {
            read = stream.read(&mut chunk) => {
                let Ok(read) = read else { break };
                if read == 0 {
                    break;
                }
                buffer.extend_from_slice(&chunk[..read]);
                bytes_in.fetch_add(read as u64, Ordering::Relaxed);
            }
            _ = shutdown.changed() => break,
        }
    }
}

/// Writes frames to one peer from two queues, control first.
///
/// One writer, because two tasks writing the same socket would interleave frame
/// bodies. Control frames (a want, and the vertex sent back for one) go first so a
/// repair never sits behind a burst of broadcasts in the same queue — that is how a
/// want ended up dropped and eventually abandoned under load.
async fn write_peer(
    mut stream: TcpStream,
    mut control: mpsc::Receiver<Vec<u8>>,
    mut data: mpsc::Receiver<Vec<u8>>,
    bytes_out: Arc<AtomicU64>,
) {
    loop {
        let bytes = tokio::select! {
            biased;
            Some(bytes) = control.recv() => bytes,
            Some(bytes) = data.recv() => bytes,
            else => break,
        };
        if stream.write_all(&bytes).await.is_err() {
            break;
        }
        bytes_out.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }
    let _ = stream.shutdown().await;
}

/// One peer's two outbound queues.
struct Link {
    control: mpsc::Sender<Vec<u8>>,
    data: mpsc::Sender<Vec<u8>>,
}

/// Queues one frame for every peer, never waiting.
///
/// Waiting here is what made a slow validator everybody's problem: the node loop
/// would block on one full queue and stop authoring and answering for every other
/// peer. Dropping keeps the loop moving, and the want sweep repairs what was
/// dropped.
fn broadcast(links: &[Link], control: bool, bytes: &[u8], dropped: &mut u64) {
    for link in links {
        let queue = if control { &link.control } else { &link.data };
        if queue.try_send(bytes.to_vec()).is_err() {
            *dropped += 1;
        }
    }
}

/// Queues payload on the data plane, awaiting a slot.
///
/// Payload is large and every node has to execute it, so it blocks rather than
/// drops: losing a batch costs more than slowing down for it. The wait is for a
/// queue slot, not for delivery, but it is real — a peer that cannot keep up now
/// costs the sender throughput, which is the trade D22 recorded.
async fn broadcast_payload(links: &[Link], bytes: &[u8]) {
    for link in links {
        if link.data.send(bytes.to_vec()).await.is_err() {
            break;
        }
    }
}

/// One outstanding repair request.
struct Want {
    at: Instant,
    tries: u8,
}

/// The two progress channels a node reports on.
///
/// Grouped so the task signature stays about the node rather than about plumbing.
struct Notify {
    ready: mpsc::Sender<usize>,
    executed: mpsc::Sender<usize>,
}

/// What a validator task needs at startup, grouped so the task signature stays
/// about the node rather than about plumbing.
struct Start {
    started: Instant,
    prebuilt: Option<Vec<Option<Batch>>>,
}

async fn node_task(
    index: usize,
    config: &Config,
    committee: chain::Membership,
    chain_id: Vec<u8>,
    start: Start,
    mut shutdown: watch::Receiver<bool>,
    notify: Notify,
) -> Result<NodeResult, String> {
    let Start {
        started,
        mut prebuilt,
    } = start;
    let set = committee.set.clone();
    // One shard per node: `data` of `n` reconstruct, so the code tolerates
    // `n - data` missing nodes and each node holds `payload / data`.
    let coding =
        Code::new(set.quorum_size(), config.validators).map_err(|error| error.to_string())?;
    let identity = committee
        .consensus
        .get(index)
        .ok_or("no consensus key for this node")?;
    let mut node = Node::with_chain_id_and_epoch_length(
        set,
        committee.epoch_rounds,
        identity.id.clone(),
        identity.private_key.clone(),
        chain_id.clone(),
    );
    let accounts = committee.accounts.clone();
    let store = if config.store.as_os_str().is_empty() {
        None
    } else {
        Some(
            Store::open(config.store.join(format!("val-{index}")))
                .map_err(|error| error.to_string())?,
        )
    };

    let listener = TcpListener::bind(address(config.port_base, index))
        .await
        .map_err(|error| format!("node {index} cannot listen: {error}"))?;

    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    // Both directions use the same depth: the inbound channel is what keeps a
    // reader from acknowledging frames faster than the node loop can judge them,
    // so tuning only one side would leave the other free to absorb the backlog.
    let (frames_tx, mut frames_rx) = mpsc::channel(config.queue.max(1));

    // Inbound: accept from every peer.
    {
        let frames_tx = frames_tx.clone();
        let bytes_in = Arc::clone(&bytes_in);
        let mut shutdown = shutdown.clone();
        let chain_id = chain_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { return };
                        let frames_tx = frames_tx.clone();
                        let bytes_in = Arc::clone(&bytes_in);
                        let shutdown = shutdown.clone();
                        let chain_id = chain_id.clone();
                        tokio::spawn(async move {
                            // The chain identity is settled before any frame is
                            // parsed: a vertex from another chain is not a vertex
                            // this node can ever accept.
                            let mut buffer = Vec::new();
                            match tokio::time::timeout(
                                HANDSHAKE_TIMEOUT,
                                handshake(&mut stream, &mut buffer, &chain_id),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    read_peer(stream, buffer, frames_tx, bytes_in, shutdown).await;
                                }
                                Ok(Err(error)) => {
                                    eprintln!("node {index} refused an inbound peer: {error}");
                                }
                                Err(_) => {
                                    eprintln!("node {index} timed out an inbound handshake");
                                }
                            }
                        });
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
    }

    // Outbound: one link per peer, connected with retries because the nodes start
    // together and a listener may not exist yet. Archives are peers too: what makes
    // an archive an archive is that validators send it everything, not that it
    // participates.
    let total = config.validators + config.archives;
    let mut outbound: Vec<Link> = Vec::with_capacity(total.saturating_sub(1));
    for peer in 0..total {
        if peer == index {
            continue;
        }
        let target = address(config.port_base, peer);
        let mut attempt = 0usize;
        let mut stream = loop {
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
        // The outbound socket carries data one way; the only frame ever read on
        // it is the peer's hello. Anything behind that hello is dropped, which is
        // why the buffer is not handed on.
        let mut trailing = Vec::new();
        match tokio::time::timeout(
            HANDSHAKE_TIMEOUT,
            handshake(&mut stream, &mut trailing, &chain_id),
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
        let (control_tx, control_rx) = mpsc::channel(CONTROL_QUEUE);
        let (data_tx, data_rx) = mpsc::channel(config.queue.max(1));
        outbound.push(Link {
            control: control_tx,
            data: data_tx,
        });
        if config.send_buffer > 0 {
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(config.send_buffer)
                .map_err(|error| format!("node {index} cannot size the socket: {error}"))?;
        }
        let bytes_out = Arc::clone(&bytes_out);
        tokio::spawn(async move {
            write_peer(stream, control_rx, data_rx, bytes_out).await;
        });
    }

    let mut wanted: HashMap<VertexId, Want> = HashMap::new();
    let mut batches: HashMap<[u8; 32], Batch> = HashMap::new();
    let mut state = chain::genesis_state(&accounts).map_err(|error| error.to_string())?;
    for account in &accounts {
        state
            .credit(&account.address, LIVE_BALANCE)
            .map_err(|error| error.to_string())?;
    }
    let mut exec_rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut applied = 0usize;
    let mut applied_cursor = 0usize;
    let mut payload_bytes = 0u64;
    let mut payloads = 0usize;
    let mut txs_received = 0usize;
    let mut latencies: Vec<u64> = Vec::new();
    let mut received = 0usize;
    let mut rejected = 0usize;
    let mut dropped = 0u64;
    let mut wanted_total = 0u64;
    let mut repaired = 0u64;
    let mut served = 0u64;
    let mut gave_up = 0u64;
    let mut ticks: u32 = 0;
    let mut cursor: u64 = 1;
    let mut announced = false;
    let mut profile = Profile::default();
    let mut exec_announced = false;
    let mut last_order = 0usize;
    let mut stable_ticks: u32 = 0;
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    let now = || u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX);

    loop {
        tokio::select! {
            frame = frames_rx.recv() => {
                let Some(frame) = frame else { break };
                received += 1;
                let at = now();
                latencies.push(at.saturating_sub(frame.sent_at_nanos));
                if config.slow_ms > 0 && index == 1 {
                    tokio::time::sleep(Duration::from_millis(config.slow_ms)).await;
                }
                match frame.message {
                    // The handshake consumes the hello before this loop starts; a
                    // second one is a peer breaking the protocol.
                    Message::Hello(_) => rejected += 1,
                    Message::Want(id) => {
                        // Answering is a broadcast: the reply is a vertex, and a
                        // vertex is exactly what the original sender would have
                        // sent. Peers that already have it ignore the duplicate.
                        if let Some(vertex) = node.dag().get(id.round, &id.author) {
                            if let Ok(bytes) = wire::frame(&Message::Vertex(vertex.clone()), now()) {
                                // A repair answer is control traffic: it must not sit
                                // behind the broadcast burst it is repairing.
                                broadcast(&outbound, true, &bytes, &mut dropped);
                                served += 1;
                            }
                        }
                    }
                    Message::Vertex(vertex) => {
                        if let Ok(id) = vertex.id()
                            && wanted.remove(&id).is_some()
                        {
                            repaired += 1;
                        }
                        // Only a vertex this node did not already hold is new, so a
                        // repaired or duplicated frame is not written twice.
                        let known = node.dag().get(vertex.round, &vertex.author).is_some();
                        match node.receive(vertex.clone()) {
                            Ok(()) => {
                                if !known && let Some(store) = &store {
                                    store
                                        .append_vertex(&vertex)
                                        .map_err(|error| error.to_string())?;
                                }
                            }
                            Err(_) => rejected += 1,
                        }
                    }
                    Message::Payload(batch) => {
                        if let Ok(digest) = batch.digest() {
                            payload_bytes += frame.len as u64;
                            txs_received += batch.len();
                            if let std::collections::hash_map::Entry::Vacant(slot) =
                                batches.entry(digest)
                            {
                                if let Some(store) = &store {
                                    put_payload(store, &coding, index, &batch, config.shard)?;
                                }
                                slot.insert(batch);
                                payloads += 1;
                            }
                        }
                    }
                }
            }
            _ = ticker.tick() => {
                ticks = ticks.wrapping_add(1);
                if let Some(store) = &store
                    && ticks % CLOCK_TICKS == 1
                {
                    store
                        .record_clock(node.round(), unix_now())
                        .map_err(|error| error.to_string())?;
                }
                if node.round() <= config.rounds {
                    let round = node.round();
                    let slot = usize::try_from(round).unwrap_or(usize::MAX);
                    let mut sign = Duration::ZERO;
                    let payload = if config.txs == 0 {
                        None
                    } else if let Some(queue) = prebuilt.as_mut() {
                        match queue.get_mut(slot).and_then(Option::take) {
                            Some(batch) => Some(batch),
                            None => {
                                return Err(format!(
                                    "node {index} has no prebuilt batch for round {round}"
                                ));
                            }
                        }
                    } else {
                        let sign_start = Instant::now();
                        let batch = chain::demo_batch(
                            &chain_id,
                            &accounts,
                            index,
                            round,
                            config.txs,
                        )
                        .map_err(|error| error.to_string())?;
                        sign = sign_start.elapsed();
                        Some(batch)
                    };
                    profile.sign += sign;
                    let digest = match &payload {
                        Some(batch) => batch.digest().map_err(|error| error.to_string())?,
                        None => [0u8; 32],
                    };
                    let author_start = Instant::now();
                    let author = node.author_with(digest);
                    profile.author += author_start.elapsed();
                    match author {
                        Ok(Some(vertex)) => {
                            if let Some(store) = &store {
                                let store_start = Instant::now();
                                store
                                    .append_vertex(&vertex)
                                    .map_err(|error| error.to_string())?;
                                if let Some(batch) = &payload {
                                    put_payload(store, &coding, index, batch, config.shard)?;
                                }
                                profile.store += store_start.elapsed();
                            }
                            let frame_start = Instant::now();
                            let bytes = wire::frame(&Message::Vertex(vertex), now())
                                .map_err(|error| error.to_string())?;
                            profile.frame += frame_start.elapsed();
                            broadcast(&outbound, false, &bytes, &mut dropped);
                            if let Some(batch) = payload {
                                let frame_start = Instant::now();
                                let frame = wire::frame(&Message::Payload(batch.clone()), now())
                                    .map_err(|error| error.to_string())?;
                                profile.frame += frame_start.elapsed();
                                batches.insert(digest, batch);
                                broadcast_payload(&outbound, &frame).await;
                            }
                        }
                        Ok(None) => {
                            // The batch was not consumed, so put it back for the
                            // next tick instead of signing it again.
                            if let (Some(queue), Some(batch)) = (prebuilt.as_mut(), payload)
                                && slot < queue.len()
                            {
                                queue[slot] = Some(batch);
                            }
                        }
                        Err(error) => return Err(format!("node {index} cannot author: {error}")),
                    }
                }
                // A commit whose leader history is not fully here yet is a
                // delivery condition, not a failure: the referenced vertex may
                // still be in a peer's queue.
                let commit_start = Instant::now();
                let step = node.commit();
                profile.commit += commit_start.elapsed();
                match step {
                    Ok(step) => {
                        cursor = match step {
                            Step::Advanced { cursor, .. }
                            | Step::Waiting { cursor, .. }
                            | Step::TimedOut { cursor, .. } => cursor,
                        };
                    }
                    Err(error) if error.kind() == CryptoErrorKind::MissingReference => {}
                    Err(error) => {
                        return Err(format!("node {index} cannot commit: {error}"));
                    }
                }
                if config.execute {
                    // Apply in commit order, and stop at the first vertex whose
                    // batch has not arrived: applying past it would put a later
                    // transaction before an earlier one.
                    let order = node.dag().order();
                    while applied_cursor < order.len() {
                        let id = &order[applied_cursor];
                        let Some(vertex) = node.dag().get(id.round, &id.author) else {
                            break;
                        };
                        let Some(batch) = batches.get(&vertex.payload_hash) else {
                            break;
                        };
                        let mut timing = chain::ApplyTiming::default();
                        applied += chain::apply_batch_timed(
                            &mut state,
                            &accounts,
                            batch,
                            &mut exec_rejected,
                            &mut timing,
                            config.verify_threads,
                        );
                        profile.verify += timing.verify;
                        profile.state += timing.state;
                        applied_cursor += 1;
                    }
                }
                if !announced && node.round() > config.rounds {
                    announced = true;
                    let _ = notify.ready.send(index).await;
                }
                // Applying costs real signature verification, so it lags the
                // commit cursor. Report caught-up only once the commit cursor has
                // itself stopped moving for a while: early in the run both cursors
                // are small and "caught up" would be trivially true.
                let order_len = node.dag().order().len();
                if order_len == last_order {
                    stable_ticks = stable_ticks.saturating_add(1);
                } else {
                    stable_ticks = 0;
                    last_order = order_len;
                }
                // With no transactions there is no batch to apply, so an empty
                // `batches` map is not a gap this node is waiting on.
                let execution_caught_up = applied_cursor >= order_len || config.txs == 0;
                if config.execute
                    && !exec_announced
                    && announced
                    && stable_ticks >= QUIET_TICKS
                    && execution_caught_up
                {
                    exec_announced = true;
                    let _ = notify.executed.send(index).await;
                }

                // Ask for every dangling reference, then retry whatever is still
                // outstanding. A gap is visible in the DAG because the next round's
                // vertices name the vertex that never arrived, so this needs no
                // signal from the sender and no guess about who owes us what.
                if ticks % WANT_SWEEP_TICKS == 0 {
                    let mut gaps = node.dag().missing_references();
                    // The cursor walk sees gaps the reference scan cannot: a vertex
                    // nobody held points at is still needed to commit.
                    if let Some(blocking) = node.dag().missing_history(cursor) {
                        gaps.push(blocking);
                    }
                    for id in gaps {
                        if wanted.contains_key(&id) {
                            continue;
                        }
                        if wanted.len() >= WANT_LIMIT {
                            gave_up += 1;
                            continue;
                        }
                        if let Ok(bytes) = wire::frame(&Message::Want(id.clone()), now()) {
                            broadcast(&outbound, true, &bytes, &mut dropped);
                            wanted.insert(
                                id,
                                Want {
                                    at: Instant::now(),
                                    tries: 0,
                                },
                            );
                            wanted_total += 1;
                        }
                    }
                    let retry: Vec<VertexId> = wanted
                        .iter()
                        .filter(|(_, want)| want.at.elapsed() >= WANT_RETRY)
                        .map(|(id, _)| id.clone())
                        .collect();
                    for id in retry {
                        let Some(want) = wanted.get_mut(&id) else { continue };
                        want.at = Instant::now();
                        if want.tries >= WANT_TRIES {
                            wanted.remove(&id);
                            gave_up += 1;
                            continue;
                        }
                        want.tries += 1;
                        if let Ok(bytes) = wire::frame(&Message::Want(id), now()) {
                            broadcast(&outbound, true, &bytes, &mut dropped);
                        }
                    }
                }
            }
            _ = shutdown.changed() => break,
        }
    }

    // A vertex names a batch, so a payload that never arrived is visible without
    // trusting the sender's accounting.
    let mut missing_payloads = 0usize;
    if config.txs > 0 {
        let dag = node.dag();
        let highest = dag.highest_round().unwrap_or(0);
        for round in 0..=highest {
            for validator in &dag.set().validators {
                if let Some(vertex) = dag.get(round, &validator.validator_id)
                    && vertex.payload_hash != [0u8; 32]
                    && !batches.contains_key(&vertex.payload_hash)
                {
                    missing_payloads += 1;
                }
            }
        }
    }
    let transactions: usize = batches.values().map(Batch::len).sum();
    let state_root = if config.execute {
        Some(state.state_root())
    } else {
        None
    };
    let exec_rejected = exec_rejected.values().sum();

    Ok(NodeResult {
        index,
        signs: true,
        authored: node.authored(),
        received,
        dropped,
        wanted: wanted_total,
        repaired,
        served,
        gave_up,
        payloads,
        transactions,
        txs_received,
        payload_bytes,
        missing_payloads,
        applied,
        exec_rejected,
        state_root,
        disk_bytes: store
            .as_ref()
            .map_or(0, |store| directory_bytes(store.path())),
        rejected,
        committed: node.dag().order().len(),
        bytes_in: bytes_in.load(Ordering::Relaxed),
        bytes_out: bytes_out.load(Ordering::Relaxed),
        latencies,
        commit_root: commit_root(node.dag().order()),
        order: node.dag().order().to_vec(),
        profile,
    })
}

/// One archive node: it accepts, stores, and never signs.
///
/// It keeps no DAG and sends nothing, because both are consensus work. What it
/// keeps is the payload every validator broadcasts, which is what makes history
/// outlive the validators' retention window. Duplicate frames are ignored by id, so
/// a repair or a retransmission does not inflate what it holds.
async fn archive_task(
    index: usize,
    config: &Config,
    chain_id: Vec<u8>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<NodeResult, String> {
    let store = if config.store.as_os_str().is_empty() {
        None
    } else {
        Some(
            Store::open(config.store.join(format!("arc-{index}")))
                .map_err(|error| error.to_string())?,
        )
    };

    let listener = TcpListener::bind(address(config.port_base, index))
        .await
        .map_err(|error| format!("archive {index} cannot listen: {error}"))?;

    let bytes_in = Arc::new(AtomicU64::new(0));
    let (frames_tx, mut frames_rx) = mpsc::channel(config.queue.max(1));
    {
        let frames_tx = frames_tx.clone();
        let bytes_in = Arc::clone(&bytes_in);
        let mut shutdown = shutdown.clone();
        let chain_id = chain_id.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { return };
                        let frames_tx = frames_tx.clone();
                        let bytes_in = Arc::clone(&bytes_in);
                        let shutdown = shutdown.clone();
                        let chain_id = chain_id.clone();
                        tokio::spawn(async move {
                            let mut buffer = Vec::new();
                            match tokio::time::timeout(
                                HANDSHAKE_TIMEOUT,
                                handshake(&mut stream, &mut buffer, &chain_id),
                            )
                            .await
                            {
                                Ok(Ok(())) => {
                                    read_peer(stream, buffer, frames_tx, bytes_in, shutdown).await;
                                }
                                Ok(Err(error)) => {
                                    eprintln!("archive {index} refused a peer: {error}");
                                }
                                Err(_) => {
                                    eprintln!("archive {index} timed out a handshake");
                                }
                            }
                        });
                    }
                    _ = shutdown.changed() => return,
                }
            }
        });
    }

    let mut vertices: HashSet<VertexId> = HashSet::new();
    let mut batches: HashSet<[u8; 32]> = HashSet::new();
    let mut received = 0usize;
    let mut payloads = 0usize;
    let mut txs = 0usize;
    let mut payload_bytes = 0u64;
    let mut rejected = 0usize;

    loop {
        tokio::select! {
            frame = frames_rx.recv() => {
                let Some(frame) = frame else { break };
                received += 1;
                match frame.message {
                    Message::Vertex(vertex) => match vertex.id() {
                        Ok(id) => {
                            if vertices.insert(id.clone())
                                && let Some(store) = &store
                            {
                                store
                                    .append_vertex(&vertex)
                                    .map_err(|error| error.to_string())?;
                            }
                        }
                        Err(_) => rejected += 1,
                    },
                    Message::Payload(batch) => {
                        payload_bytes += frame.len as u64;
                        if let Ok(digest) = batch.digest()
                            && batches.insert(digest)
                        {
                            txs += batch.len();
                            payloads += 1;
                            if let Some(store) = &store {
                                store.put_batch(&batch).map_err(|error| error.to_string())?;
                            }
                        }
                    }
                    // An archive decides nothing, so a want is not addressed to it.
                    Message::Want(_) => {}
                    // The accept side consumes the hello before the loop starts.
                    Message::Hello(_) => rejected += 1,
                }
            }
            _ = shutdown.changed() => break,
        }
    }

    Ok(NodeResult {
        index,
        signs: false,
        authored: 0,
        received,
        dropped: 0,
        wanted: 0,
        repaired: 0,
        served: 0,
        gave_up: 0,
        payloads,
        transactions: txs,
        txs_received: txs,
        payload_bytes,
        missing_payloads: 0,
        applied: 0,
        exec_rejected: 0,
        state_root: None,
        disk_bytes: store
            .as_ref()
            .map_or(0, |store| directory_bytes(store.path())),
        rejected,
        committed: 0,
        bytes_in: bytes_in.load(Ordering::Relaxed),
        bytes_out: 0,
        latencies: Vec::new(),
        commit_root: [0u8; 32],
        order: Vec::new(),
        profile: Profile::default(),
    })
}

/// Total bytes of the files directly inside a store directory.
///
/// This is what the node actually wrote, record headers included, so it is the
/// number a disk budget should use rather than a model of one.
fn directory_bytes(path: &std::path::Path) -> u64 {
    let Ok(entries) = std::fs::read_dir(path) else {
        return 0;
    };
    entries
        .filter_map(Result::ok)
        .filter_map(|entry| entry.metadata().ok())
        .filter(|meta| meta.is_file())
        .map(|meta| meta.len())
        .sum()
}

/// Writes one batch to a store, whole or as this node's erasure shard.
///
/// The shard is the same size for every node (`payload / data`), so one directory
/// per node is the whole distribution scheme — which is model B without a data-
/// availability protocol around it.
fn put_payload(
    store: &Store,
    coding: &Code,
    index: usize,
    batch: &Batch,
    shard: bool,
) -> Result<(), String> {
    if !shard {
        return store.put_batch(batch).map_err(|error| error.to_string());
    }
    let payload = batch.encode().map_err(|error| error.to_string())?;
    let encoded = coding.encode(&payload).map_err(|error| error.to_string())?;
    let piece = encoded
        .shards
        .get(index)
        .ok_or("shard index is outside the code")?;
    let digest = batch.digest().map_err(|error| error.to_string())?;
    let slot = u16::try_from(index).map_err(|_| "shard index does not fit u16")?;
    store
        .put_shard(&digest, slot, piece)
        .map_err(|error| error.to_string())
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    if config.validators < 2 {
        return Err("a live run needs at least two nodes".into());
    }
    let total = config.validators + config.archives;
    if total > 64 {
        return Err("at most 64 nodes: this is a loopback mesh, not a network".into());
    }

    // The genesis hash is the chain identity vertices are signed over (D29). An
    // explicit home supplies it; without one the demo identity keeps this run
    // self-contained and does not depend on `~/.karsa`. Membership first: with a
    // home it ensures the genesis and keys exist, so the chain id read below is the
    // hash of the same genesis the committee came from.
    let home = config
        .home
        .clone()
        .map(|path| crate::home::Home::resolve(Some(path)))
        .transpose()?;
    let committee = chain::membership(config.validators, home.as_ref())?;
    let chain_id = match &home {
        Some(home) => chain::chain_id(Some(home))?,
        None => chain::demo_chain_id(),
    };

    let mut prebuilt: Vec<Vec<Option<Batch>>> = if config.pre_sign && config.txs > 0 {
        let rounds = usize::try_from(config.rounds)
            .unwrap_or(usize::MAX)
            .saturating_add(1);
        let mut all = Vec::with_capacity(config.validators);
        for index in 0..config.validators {
            let mut batches = Vec::with_capacity(rounds);
            for round in 0..=config.rounds {
                batches.push(Some(chain::demo_batch(
                    &chain_id,
                    &committee.accounts,
                    index,
                    round,
                    config.txs,
                )?));
            }
            all.push(batches);
        }
        all
    } else {
        Vec::new()
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    let results = runtime.block_on(async {
        let started = Instant::now();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (ready_tx, mut ready_rx) = mpsc::channel(config.validators);
        let (executed_tx, mut executed_rx) = mpsc::channel(config.validators);

        let mut tasks = Vec::with_capacity(total);
        for index in 0..config.validators {
            let shutdown_rx = shutdown_rx.clone();
            let ready_tx = ready_tx.clone();
            let executed_tx = executed_tx.clone();
            let config = config.clone();
            let committee = committee.clone();
            let chain_id = chain_id.clone();
            let prebuilt = if prebuilt.is_empty() {
                None
            } else {
                Some(std::mem::take(&mut prebuilt[index]))
            };
            tasks.push(tokio::spawn(async move {
                node_task(
                    index,
                    &config,
                    committee,
                    chain_id,
                    Start { started, prebuilt },
                    shutdown_rx,
                    Notify {
                        ready: ready_tx,
                        executed: executed_tx,
                    },
                )
                .await
            }));
        }
        // Archives are peers of the mesh with no consensus role: they accept what
        // validators broadcast and keep it.
        for offset in 0..config.archives {
            let index = config.validators + offset;
            let shutdown_rx = shutdown_rx.clone();
            let config = config.clone();
            let chain_id = chain_id.clone();
            tasks.push(tokio::spawn(async move {
                archive_task(index, &config, chain_id, shutdown_rx).await
            }));
        }
        drop(ready_tx);
        drop(executed_tx);

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
        // pace plus a fixed wait for the last frames.
        let authoring = started.elapsed();
        if config.execute {
            // Wait for every node's applied cursor to catch up with its commit
            // cursor; the deadline above still bounds the wait.
            let mut caught = 0usize;
            loop {
                tokio::select! {
                    Some(_) = executed_rx.recv() => {
                        caught += 1;
                        if caught == config.validators {
                            break;
                        }
                    }
                    _ = &mut deadline => break,
                }
            }
        }
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
        "  chain {}: every link opens with it, and a peer on another hash is refused",
        chain_label(&chain_id)
    );
    println!(
        "  {} validators{} on 127.0.0.1:{}..={}, full mesh, {} rounds each{}",
        config.validators,
        if config.archives > 0 {
            format!(" plus {} archives", config.archives)
        } else {
            String::new()
        },
        config.port_base,
        u32::from(config.port_base) + u32::try_from(total - 1).unwrap_or(0),
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
        "  {}  {}  {}  {}  {}  {}  {}  {}  {}",
        left("node", 7),
        pad("authored", 9),
        pad("received", 9),
        pad("dropped", 8),
        pad("repaired", 9),
        pad("rejected", 9),
        pad("committed", 10),
        pad("in", 10),
        pad("out", 10)
    );

    let mut latencies: Vec<u64> = Vec::new();
    let mut bytes_in = 0u64;
    let mut bytes_out = 0u64;
    let mut dropped = 0u64;
    let mut wanted = 0u64;
    let mut repaired = 0u64;
    let mut served = 0u64;
    let mut gave_up = 0u64;
    let mut roots: Vec<[u8; 32]> = Vec::new();
    let mut payload_batches = 0usize;
    let mut payload_txs = 0usize;
    let mut payload_txs_received = 0usize;
    let mut payload_wire = 0u64;
    let mut missing_payloads = 0usize;
    let mut applied = 0usize;
    let mut exec_rejected = 0usize;
    let mut disk_bytes = 0u64;
    let mut disk_bytes_archives = 0u64;
    let mut archive_txs = 0usize;
    let mut validator_txs = 0usize;
    let mut state_roots: Vec<[u8; 32]> = Vec::new();
    for result in &results {
        bytes_in += result.bytes_in;
        bytes_out += result.bytes_out;
        dropped += result.dropped;
        wanted += result.wanted;
        repaired += result.repaired;
        served += result.served;
        gave_up += result.gave_up;
        payload_batches += result.payloads;
        payload_txs += result.transactions;
        payload_txs_received += result.txs_received;
        payload_wire += result.payload_bytes;
        missing_payloads += result.missing_payloads;
        applied += result.applied;
        exec_rejected += result.exec_rejected;
        if result.signs {
            disk_bytes += result.disk_bytes;
            validator_txs += result.transactions;
        } else {
            disk_bytes_archives += result.disk_bytes;
            archive_txs += result.transactions;
        }
        if let Some(root) = result.state_root {
            state_roots.push(root);
        }
        if result.signs {
            roots.push(result.commit_root);
            latencies.extend_from_slice(&result.latencies);
        }
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}  {}",
            left(
                &format!(
                    "{}-{}",
                    if result.signs { "val" } else { "arc" },
                    result.index
                ),
                7
            ),
            pad(&result.authored.to_string(), 9),
            pad(&result.received.to_string(), 9),
            pad(&result.dropped.to_string(), 8),
            pad(&result.repaired.to_string(), 9),
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
    println!(
        "  repair            {dropped} frames dropped, {wanted} wants sent, \
         {repaired} repaired, {served} served, {gave_up} abandoned"
    );
    if config.txs > 0 {
        let per_tx = if payload_txs_received == 0 {
            0.0
        } else {
            payload_wire as f64 / payload_txs_received as f64
        };
        println!(
            "  data plane        {payload_batches} batches, {payload_txs_received} transaction \
             deliveries, {per_tx:.0} B/tx received, {} on the wire, {missing_payloads} named but \
             missing",
            human(payload_wire)
        );
        println!("                    {payload_txs} unique transactions held across all nodes");
    }
    if disk_bytes > 0 {
        let per_tx = if validator_txs == 0 {
            0.0
        } else {
            disk_bytes as f64 / validator_txs as f64
        };
        // At 1k TPS the same record shape costs this much per day.
        let per_day = per_tx * 1_000.0 * 86_400.0 / 1e9;
        let coding = if config.shard {
            let quorum = chain::consensus_set(config.validators)?.0.quorum_size();
            format!(" (one shard per node, {quorum}/{})", config.validators)
        } else {
            String::from(" (full replication)")
        };
        println!(
            "  storage           {} on disk for validators, {per_tx:.0} B per transaction \
             (~{per_day:.1} GB/day at 1k TPS){coding}",
            human(disk_bytes)
        );
        println!("                    vertices and batches only: no snapshot, no pruning here");
        if disk_bytes_archives > 0 {
            let per_tx_archive = if archive_txs == 0 {
                0.0
            } else {
                disk_bytes_archives as f64 / archive_txs as f64
            };
            println!(
                "  archives          {} on disk, {per_tx_archive:.0} B per transaction, kept in full",
                human(disk_bytes_archives)
            );
        }
    }
    if config.shard && !config.store.as_os_str().is_empty() {
        // Coverage is the property that matters for model B: every batch must be
        // reconstructible from shards held across the committee.
        let quorum = chain::consensus_set(config.validators)?.0.quorum_size();
        let mut coverage: HashMap<[u8; 32], usize> = HashMap::new();
        for index in 0..config.validators {
            let store = Store::open(config.store.join(format!("val-{index}")))?;
            for shard in store.shards()? {
                *coverage.entry(shard.digest).or_default() += 1;
            }
        }
        let total = coverage.len();
        let sufficient = coverage.values().filter(|count| **count >= quorum).count();
        println!(
            "  shards            {sufficient} of {total} batches have at least {quorum} shards \
             across the committee"
        );
    }
    if let Some(first) = state_roots.first() {
        let agree = state_roots.iter().all(|root| root == first);
        println!(
            "  execution         {applied} tx applied, {exec_rejected} rejected, state root {} \
             (all nodes agree: {agree})",
            hex::encode(&first[..6])
        );
        if !agree {
            for (index, root) in state_roots.iter().enumerate() {
                println!("    val-{index} {}", hex::encode(&root[..6]));
            }
        }
    }
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
                        author_label(&vertex.author)
                    );
                }
                for vertex in right_only.iter().take(3) {
                    println!(
                        "      only val-{}: round {} {}",
                        result.index,
                        vertex.round,
                        author_label(&vertex.author)
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

    if config.profile {
        let mut profile = Profile::default();
        let mut nodes = 0usize;
        for result in &results {
            if !result.signs {
                continue;
            }
            profile.sign += result.profile.sign;
            profile.author += result.profile.author;
            profile.commit += result.profile.commit;
            profile.verify += result.profile.verify;
            profile.state += result.profile.state;
            profile.frame += result.profile.frame;
            profile.store += result.profile.store;
            nodes += 1;
        }
        let nodes = nodes.max(1) as f64;
        let total = profile.sign
            + profile.author
            + profile.commit
            + profile.verify
            + profile.state
            + profile.frame
            + profile.store;
        let ms = |duration: Duration| duration.as_secs_f64() * 1e3 / nodes;
        let pct = |duration: Duration| {
            if total.is_zero() {
                0.0
            } else {
                duration.as_secs_f64() / total.as_secs_f64() * 100.0
            }
        };
        println!();
        println!("  profile           average per validator, share of named stages");
        for (name, duration) in [
            ("sign batch", profile.sign),
            ("author vertex", profile.author),
            ("commit tick", profile.commit),
            ("verify tx", profile.verify),
            ("apply state", profile.state),
            ("frame payload", profile.frame),
            ("store write", profile.store),
        ] {
            println!(
                "    {:<16} {:>9.2} ms  {:>5.1}%",
                name,
                ms(duration),
                pct(duration)
            );
        }
        println!("    {:<16} {:>9.2} ms", "named total", ms(total));
    }

    println!();
    if dropped > 0 || wanted > 0 {
        println!("  Repair is demand-driven. A gap is found by scanning the held DAG for");
        println!("  references to vertices that never arrived, so the only ids ever");
        println!("  requested are ones a decision actually needs. Nothing is retransmitted");
        println!("  blindly, and a want that itself gets dropped is retried a few times");
        println!("  before it is abandoned and counted.");
    } else {
        println!("  Nothing was dropped, so nothing was repaired. Lower --queue to force");
        println!("  the drop path on a fast machine.");
    }
    if config.slow_ms > 0 {
        println!();
        println!("  The slow node is the point of this run: its queue fills, frames to it");
        println!("  are dropped, and the repair sweep fills the gap. Other nodes keep");
        println!("  authoring at their own pace, which backpressure would not allow.");
    }

    if !agreed {
        return Err("nodes did not converge on the same commit root".into());
    }
    if missing_payloads > 0 {
        return Err(
            format!("{missing_payloads} vertices name a batch this node does not hold").into(),
        );
    }
    if state_roots.len() > 1 && state_roots.iter().any(|root| *root != state_roots[0]) {
        return Err("nodes applied the same commits to different state".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Two connected sockets, the way a node pair sees them.
    async fn linked_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let client = TcpStream::connect(address).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    #[test]
    fn another_wire_protocol_is_refused() {
        let hello = wire::Hello {
            protocol: wire::WIRE_PROTOCOL + 1,
            chain_id: b"chain-a".to_vec(),
        };
        let error = check_hello(b"chain-a", &hello).unwrap_err();
        assert!(error.contains("wire protocol"), "{error}");
    }

    #[tokio::test]
    async fn peers_on_the_same_chain_complete_the_handshake_from_both_sides() {
        let (mut client, mut server) = linked_pair().await;
        let mut client_buffer = Vec::new();
        let mut server_buffer = Vec::new();
        let (client_result, server_result) = tokio::join!(
            handshake(&mut client, &mut client_buffer, b"chain-a"),
            handshake(&mut server, &mut server_buffer, b"chain-a"),
        );
        client_result.unwrap();
        server_result.unwrap();
    }

    #[tokio::test]
    async fn a_peer_on_another_chain_is_refused_by_both_sides() {
        let (mut client, mut server) = linked_pair().await;
        let mut client_buffer = Vec::new();
        let mut server_buffer = Vec::new();
        let (client_result, server_result) = tokio::join!(
            handshake(&mut client, &mut client_buffer, b"chain-a"),
            handshake(&mut server, &mut server_buffer, b"chain-b"),
        );
        let client_error = client_result.unwrap_err();
        let server_error = server_result.unwrap_err();
        assert!(client_error.contains("peer is on chain"), "{client_error}");
        assert!(server_error.contains("peer is on chain"), "{server_error}");
    }

    #[tokio::test]
    async fn a_frame_sent_before_the_hello_is_refused_even_if_it_parses() {
        let (mut client, mut server) = linked_pair().await;
        let want = VertexId {
            round: 3,
            author: b"val-0".to_vec(),
            digest: [1u8; 32],
        };
        let bytes = wire::frame(&Message::Want(want), 0).unwrap();
        client.write_all(&bytes).await.unwrap();

        let mut buffer = Vec::new();
        let error = handshake(&mut server, &mut buffer, b"chain-a")
            .await
            .unwrap_err();
        assert_eq!(error, "peer sent data before its hello");
    }
}
