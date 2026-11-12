//! Real sockets between validator nodes on loopback.
//!
//! Every other command in this workspace moves vertices through a deterministic
//! queue. This one puts them on TCP, one listener per node, full mesh, with a
//! length-prefixed frame. Once a node executes, the same links also carry the
//! certificate shares the finality pipeline produces.
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
//! The default mesh puts all nodes in one process on one machine, so the numbers
//! describe the wire and the runtime, not independent operators. `--node-index`
//! moves one validator into each process, which adds a real scheduler boundary
//! but still leaves every node on the same machine. There is no encryption, no
//! retransmission timer beyond the want sweep, and no peer discovery: the mesh is
//! fixed by `--validators`. A link opens with a hello naming the chain, so two
//! genesis hashes never get as far as exchanging a vertex.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque};
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crypto::CryptoErrorKind;
use crypto::scheme::Ed25519Scheme;
use erasure::Code;
use exec::State;
use net::Node;
use net::wire::{self, Message};
use store::{LiveSnapshot, Store};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch};
use tx::batch::Batch;
use validator::{
    Certificate, CommitFrontier, ControlPayload, FailureDetector, Fence, FenceCertificate,
    Finalizer, Header, NoVoteAttestation, RoundSkip, RoundSkipProof, SetChange, SetSchedule, Step,
    TransitionCertificate, ValidatorSet, VertexId, bitmap_len, commit_root, set_bit,
};

use crate::chain;
use crate::rpc::{self, RpcCore, SharedRpc};

/// Ids a node will ask for at once. Beyond this the queue is growing faster than
/// repair can drain it, so the count is reported rather than the memory.
const WANT_LIMIT: usize = 4096;
/// How often an unanswered want is repeated.
const WANT_RETRY: Duration = Duration::from_millis(250);
/// How long the cursor must sit still before asking for missing voter slots.
///
/// The reference scans cannot see a vote that was broadcast while this node was
/// down and that no later vertex names. Waiting a moment first keeps the slot
/// request out of the ordinary commit path.
const WANT_SLOT_AFTER: Duration = Duration::from_millis(200);
/// Attempts before a want is abandoned and counted.
const WANT_TRIES: u8 = 8;
/// Control frames a peer may have queued: wants and their answers.
const CONTROL_QUEUE: usize = 256;
/// Share frames kept so a reconnected peer can recover a signature that was in
/// flight when the link broke.
///
/// Certificate shares are produced once per height and never retransmitted, so a
/// peer that misses even one height can never certify that height or any above it.
/// The window has to cover a restart, not a single frame: a peer may be away for
/// several seconds while it replays its store. A thousand heights is about fifteen
/// seconds at this committee's certificate rate; a longer outage needs a snapshot
/// resync rather than a replay.
const RECENT_SHARES: usize = 1024;
/// How many of this node's own vertices are replayed once at startup.
///
/// A validator that was killed between authoring a vertex and its broadcast leaves
/// a vote that no peer holds; a want cannot ask for an id nobody knows. Replaying
/// the last own vertices after a restart puts that vote back on the wire. The
/// window covers a few hundred rounds at the observed cadence.
const RECENT_VERTICES: usize = 1024;
/// How long to keep retrying a connection before giving up.
const CONNECT_TRIES: usize = 400;
/// Delay before the first attempt to reconnect a link that dropped.
const RECONNECT_BACKOFF_MIN: Duration = Duration::from_millis(10);
/// Ceiling on the reconnect backoff.
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(1);
/// How long one reconnect attempt may spend connecting and shaking hands.
const RECONNECT_TIMEOUT: Duration = Duration::from_secs(2);
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
/// Wall time one cursor may stand still before a stall is logged.
///
/// Anchors ahead of the cursor keep the pacemaker productive, so a timeout count
/// never fires while the DAG still grows; the cursor's own age is the signal.
const STALL_REPORT_AFTER: Duration = Duration::from_millis(1_500);
/// Window over which a stalled node reports its own committed-entry rate.
///
/// This is the local lambda an operator needs to tell "the chain is moving but
/// this cursor is behind" from "the chain itself has stopped producing commits".
const COMMIT_RATE_WINDOW: Duration = Duration::from_secs(5);
/// Balance each demo account starts with in a live run.
///
/// The chain demo funds accounts with a thousand units, which is plenty for a
/// handful of transactions and far too little for a throughput run: at a hundred
/// transactions per batch the fee alone exhausts it within a few rounds and the
/// rest of the run measures rejections instead of execution.
const LIVE_BALANCE: u64 = 1_000_000_000;
/// How long a peer gets to state its chain identity before the link is closed.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// How long a joining node waits for a peer to accept a snapshot connection.
const SNAPSHOT_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// How long a joining node keeps trying peers while they finish starting up.
const SNAPSHOT_STARTUP_WAIT: Duration = Duration::from_secs(15);
/// How long a joining node waits for the snapshot body.
const SNAPSHOT_READ_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a serving node waits for the node loop to build a snapshot.
const SNAPSHOT_REPLY_TIMEOUT: Duration = Duration::from_secs(20);
/// Per-`applied` states kept so a certified head's state can be served.
const SNAPSHOT_STATES: usize = 256;
/// Ticks between attempts to write a periodic checkpoint.
///
/// Building one clones the state, the committed prefix, and the tail. A head whose
/// floor is not safe to prune must not make that work happen on every 2 ms tick.
const CHECKPOINT_TICKS: u32 = 250;
/// Rounds kept above the certified head when choosing a snapshot floor.
///
/// A vertex at the head's round may still be in flight to the snapshot peer, so
/// keeping a couple of rounds above it lets it travel in the tail.
const SNAPSHOT_FLOOR_MARGIN: u64 = 2;
/// Ticks between rebroadcasts of a partial or adopted set-change certificate.
///
/// The certificate is the durable authorization; repeating it costs one small
/// frame per interval and lets a peer that reconnects catch up.
const SET_CHANGE_TICKS: u32 = 25;
/// Additional rounds a live node may author past its decision cursor while the
/// round-skip experiment is enabled.
///
/// Settling round `r` through an anchor needs rounds `r + 2` and `r + 3`, so a
/// small lead is required. Authoring thousands of rounds ahead is not: those
/// rounds cannot commit before the cursor moves, and they widen the window in
/// which different delivery lets two nodes make different skip decisions. The
/// effective lead is raised above the failure-detector threshold, and the cap
/// is off without `--round-skip` and in closed-loop modes, where the harness
/// owns the round budget.
const AUTHORING_LEAD: u64 = 12;

/// How often an adopted control payload is repeated for a peer that joined late.
///
/// A control payload is named by a vertex, so the vertex reference and its want
/// sweep are the primary repair path; the periodic repeat only covers a peer that
/// missed both halves while it was away.
const CONTROL_REBROADCAST_TICKS: u32 = 1000;

/// Round-based silence is meaningful only after the mesh has finished starting.
///
/// A node that starts a few milliseconds late is many rounds behind, so a tight
/// `--failure-rounds` could otherwise fence a healthy peer before it has had a
/// chance to connect. The grace is wall-clock because startup skew is wall-clock;
/// after it, silence is measured in rounds as before.
const FENCE_STARTUP_GRACE: Duration = Duration::from_secs(1);

/// One checked validator-set change a live run may propose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SetChangeKind {
    /// Append one deterministic validator identity.
    Add,
    /// Remove the last validator identity.
    Remove,
}

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
    /// Run exactly this validator in this process instead of the whole committee.
    ///
    /// `None` keeps the single-process mesh, where every node shares one runtime.
    /// `Some(index)` makes this process one validator: it binds `port_base + index`,
    /// advertises the same chain identity, and serves peers until `timeout` expires
    /// rather than stopping at a local drain.
    pub node_index: Option<usize>,
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
    /// First loopback HTTP port; node `i` serves `rpc_port + i`.
    ///
    /// Zero disables the server. A nonzero port implies `--execute` and turns the
    /// data plane into a mempool: batches come from submitted transactions instead
    /// of [`chain::demo_batch`], and authoring does not stop at `rounds`.
    pub rpc_port: u16,
    /// Most mempool transactions one authored batch may carry.
    pub rpc_batch_max: usize,
    /// First loopback port for snapshot requests; node `i` serves
    /// `snapshot_port + i`. Zero disables the server and the client.
    pub snapshot_port: u16,
    /// Ask a peer for a state snapshot at startup instead of replaying history.
    ///
    /// The joiner still verifies the anchor's quorum certificate. A store with
    /// history is moved forward to a snapshot above its certified head.
    pub sync_from_peers: bool,
    /// Persist a live snapshot every N certified heights. Zero disables it.
    ///
    /// The checkpoint bounds the history a restart has to replay, and each write
    /// prunes the logs below its floor. It needs a store and execution, because
    /// the snapshot carries the state.
    pub checkpoint_every: u64,
    /// Rounds a validator may be silent before the local failure detector reports
    /// it. Zero disables the report.
    ///
    /// The report is a local liveness view, not a consensus input: two nodes with
    /// different delivery may disagree, and a transition that acts on it must be
    /// authorized by the set.
    pub failure_rounds: u64,
    /// One checked set change to propose and authorize at an epoch boundary.
    ///
    /// Every node with the same configuration constructs the same new set and
    /// signs the same descriptor; the old-set quorum travels as partial
    /// certificates and the full certificate is adopted before activation.
    pub change: Option<(SetChangeKind, u64)>,
    /// Collect a quorum fence for a validator the failure detector reports silent.
    ///
    /// The fence is only signed when the node has not decided the fence's round
    /// and the validator is the missing leader of its cursor. It is a liveness
    /// aid, never a state change.
    pub fence_silent: bool,
    /// Build and adopt round-skip proofs when the cursor's leader cannot reach a
    /// quorum from the vertices this node holds.
    ///
    /// The proof partitions the voter set and is verified before it is applied;
    /// it is a liveness aid and is off by default while the dissemination path is
    /// still experimental.
    pub round_skip: bool,
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
    first_author_ms: Option<u64>,
    last_author_ms: Option<u64>,
    complete: bool,
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
    certified_ids: BTreeMap<u64, [u8; 32]>,
    head_height: u64,
    head_round: u64,
    conflicts: usize,
    restored: Option<Restored>,
    snapshot: Option<SnapshotReport>,
    disk_bytes: u64,
    rejected: usize,
    committed: usize,
    bytes_in: u64,
    bytes_out: u64,
    latencies: Vec<u64>,
    commit_root: [u8; 32],
    order: Vec<VertexId>,
    /// Compact summary of the committed entries below `order`, when a snapshot
    /// restored this node from a checkpoint. Empty for a full-history node.
    prefix: CommitFrontier,
    profile: Profile,
}

fn address(port_base: u16, index: usize) -> String {
    format!(
        "127.0.0.1:{}",
        u32::from(port_base) + u32::try_from(index).unwrap_or(0)
    )
}

/// The HTTP address node `index` serves, when the server is enabled.
fn rpc_address(port_base: u16, index: usize) -> Result<String, String> {
    let offset = u32::try_from(index).map_err(|_| "node index does not fit a port offset")?;
    let port = u32::from(port_base)
        .checked_add(offset)
        .filter(|port| *port <= u32::from(u16::MAX))
        .ok_or_else(|| format!("RPC port {} + {index} is outside the u16 range", port_base))?;
    Ok(format!("127.0.0.1:{port}"))
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

/// How one outbound connection ended.
enum LinkEnd {
    /// The socket failed; the peer may still be starting up.
    Broken,
    /// The run is shutting down.
    Shutdown,
    /// Both queues closed, so there is nothing left to send.
    Closed,
}

/// What one outbound link task needs besides the socket and its two queues.
struct LinkTask {
    index: usize,
    target: String,
    chain_id: Vec<u8>,
    bytes_out: Arc<AtomicU64>,
    up: Arc<AtomicBool>,
    /// The most recent share frames this node produced, replayed to a peer that
    /// reconnects so a signature lost at the break cannot wedge its finality.
    recent_shares: Arc<Mutex<VecDeque<Vec<u8>>>>,
    /// The most recent vertex frames this node authored, replayed on reconnect
    /// for the same reason: a vote lost at the break has no repair id to ask for.
    recent_vertices: Arc<Mutex<VecDeque<Vec<u8>>>>,
    send_buffer: usize,
    shutdown: watch::Receiver<bool>,
}

/// Writes frames to one peer from two queues, control first.
///
/// One writer, because two tasks writing the same socket would interleave frame
/// bodies. Control frames (a want, and the vertex sent back for one) go first so a
/// repair never sits behind a burst of broadcasts in the same queue — that is how a
/// want ended up dropped and eventually abandoned under load.
///
/// A dropped link is re-established: a validator that restarts has to receive the
/// mesh's traffic again, and its peers' old sockets died with the previous process.
/// Frames already queued survive the break; the one frame that was mid-write is
/// retried, and the recent shares are replayed so a certificate that lost one
/// signature at the break can still form.
async fn write_peer(
    mut stream: TcpStream,
    mut control: mpsc::Receiver<Vec<u8>>,
    mut data: mpsc::Receiver<Vec<u8>>,
    task: LinkTask,
) {
    let LinkTask {
        index,
        target,
        chain_id,
        bytes_out,
        up,
        recent_shares,
        recent_vertices,
        send_buffer,
        mut shutdown,
    } = task;
    // The frame that was in flight when a socket failed. It is retried on the next
    // connection, because a share lost exactly at the break would leave the peer one
    // signature short of a certificate for that height, and no later share can stand
    // in for it.
    let mut pending = None;
    loop {
        let end = write_connected(
            &mut stream,
            &mut control,
            &mut data,
            &bytes_out,
            &mut pending,
            &mut shutdown,
        )
        .await;
        up.store(false, Ordering::Relaxed);
        let _ = stream.shutdown().await;
        match end {
            LinkEnd::Closed | LinkEnd::Shutdown => return,
            LinkEnd::Broken => {}
        }
        eprintln!("node {index} lost {target}; reconnecting");
        match reconnect(index, &target, &chain_id, send_buffer, &mut shutdown).await {
            Some(fresh) => {
                stream = fresh;
                up.store(true, Ordering::Relaxed);
                resend_recent(&mut stream, &recent_shares, &bytes_out).await;
                resend_recent(&mut stream, &recent_vertices, &bytes_out).await;
                eprintln!("node {index} reconnected {target}");
            }
            None => return,
        }
    }
}

/// Writes the retained share frames to a freshly established link.
async fn resend_recent(
    stream: &mut TcpStream,
    recent: &Mutex<VecDeque<Vec<u8>>>,
    bytes_out: &AtomicU64,
) {
    let frames: Vec<Vec<u8>> = {
        let recent = recent.lock().expect("recent shares lock poisoned");
        recent.iter().cloned().collect()
    };
    for frame in frames {
        if stream.write_all(&frame).await.is_err() {
            return;
        }
        bytes_out.fetch_add(frame.len() as u64, Ordering::Relaxed);
    }
}

/// Keeps the latest frame, dropping the oldest once the window is full.
fn remember_frame(recent: &Mutex<VecDeque<Vec<u8>>>, bytes: &[u8], limit: usize) {
    let mut recent = recent.lock().expect("recent frame lock poisoned");
    if recent.len() == limit {
        recent.pop_front();
    }
    recent.push_back(bytes.to_vec());
}

/// Keeps the latest share frame, dropping the oldest once the window is full.
fn remember_share(recent: &Mutex<VecDeque<Vec<u8>>>, bytes: &[u8]) {
    remember_frame(recent, bytes, RECENT_SHARES);
}

/// Keeps the latest authored-vertex frame for a reconnect replay.
fn remember_vertex(recent: &Mutex<VecDeque<Vec<u8>>>, bytes: &[u8]) {
    remember_frame(recent, bytes, RECENT_VERTICES);
}

/// Writes queued frames until the socket fails, the run ends, or every sender is
/// gone.
async fn write_connected(
    stream: &mut TcpStream,
    control: &mut mpsc::Receiver<Vec<u8>>,
    data: &mut mpsc::Receiver<Vec<u8>>,
    bytes_out: &AtomicU64,
    pending: &mut Option<Vec<u8>>,
    shutdown: &mut watch::Receiver<bool>,
) -> LinkEnd {
    loop {
        let bytes = match pending.take() {
            Some(bytes) => bytes,
            None => tokio::select! {
                biased;
                Some(bytes) = control.recv() => bytes,
                Some(bytes) = data.recv() => bytes,
                _ = shutdown.changed() => return LinkEnd::Shutdown,
                else => return LinkEnd::Closed,
            },
        };
        if stream.write_all(&bytes).await.is_err() {
            *pending = Some(bytes);
            return LinkEnd::Broken;
        }
        bytes_out.fetch_add(bytes.len() as u64, Ordering::Relaxed);
    }
}

/// Re-establishes one outbound link, backing off between attempts.
///
/// The retry is unbounded because a restarted validator may take as long as its
/// operator needs; the run's shutdown signal is what ends it. A refused handshake is
/// reported once and then retried, since a peer that is still starting up may answer
/// abruptly for a moment.
async fn reconnect(
    index: usize,
    target: &str,
    chain_id: &[u8],
    send_buffer: usize,
    shutdown: &mut watch::Receiver<bool>,
) -> Option<TcpStream> {
    let mut delay = RECONNECT_BACKOFF_MIN;
    let mut reported = false;
    loop {
        let attempt = tokio::select! {
            _ = shutdown.changed() => return None,
            result = tokio::time::timeout(RECONNECT_TIMEOUT, TcpStream::connect(target)) => result,
        };
        match attempt {
            Ok(Ok(mut stream)) => {
                let mut trailing = Vec::new();
                let hello = tokio::select! {
                    _ = shutdown.changed() => return None,
                    result = tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        handshake(&mut stream, &mut trailing, chain_id),
                    ) => result,
                };
                match hello {
                    Ok(Ok(())) => {
                        if send_buffer > 0
                            && let Err(error) =
                                socket2::SockRef::from(&stream).set_send_buffer_size(send_buffer)
                        {
                            eprintln!("node {index} cannot size the link to {target}: {error}");
                        }
                        return Some(stream);
                    }
                    Ok(Err(error)) => {
                        if !reported {
                            eprintln!("node {index} cannot rejoin {target}: {error}");
                            reported = true;
                        }
                    }
                    Err(_) => {
                        if !reported {
                            eprintln!("node {index} handshake with {target} timed out");
                            reported = true;
                        }
                    }
                }
            }
            Ok(Err(error)) => {
                if !reported {
                    eprintln!("node {index} cannot reconnect {target}: {error}");
                    reported = true;
                }
            }
            Err(_) => {
                if !reported {
                    eprintln!("node {index} connect to {target} timed out");
                    reported = true;
                }
            }
        }
        tokio::select! {
            _ = shutdown.changed() => return None,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(RECONNECT_BACKOFF_MAX);
    }
}

/// One peer's two outbound queues.
struct Link {
    control: mpsc::Sender<Vec<u8>>,
    data: mpsc::Sender<Vec<u8>>,
    /// Whether the writer currently has a socket for this peer. A link without one
    /// queues what fits but never blocks the node loop.
    up: Arc<AtomicBool>,
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
/// costs the sender throughput, which is the trade D22 recorded. A link that has no
/// socket queues what fits and lets the rest go, so one peer leaving never stops
/// payload reaching the rest.
async fn broadcast_payload(links: &[Link], bytes: &[u8]) {
    for link in links {
        if link.up.load(Ordering::Relaxed) {
            let _ = link.data.send(bytes.to_vec()).await;
        } else {
            // A peer with no live socket cannot drain the queue. Queue the payload
            // if there is room, so a short drop still delivers; if it is full, let
            // it go instead of stalling every live peer behind a link that is down.
            let _ = link.data.try_send(bytes.to_vec());
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

/// The channels that steer one node loop.
struct Signals {
    /// Stop authoring while keeping the mesh and the commit loop alive.
    stop_authoring: watch::Receiver<bool>,
    /// End the loop.
    shutdown: watch::Receiver<bool>,
    /// Progress notifications for the run controller.
    notify: Notify,
}

/// What a validator task needs at startup, grouped so the task signature stays
/// about the node rather than about plumbing.
struct Start {
    started: Instant,
    prebuilt: Option<Vec<Option<Batch>>>,
}

/// What a snapshot join adopted and how long each half took.
#[derive(Debug, Clone, Copy)]
struct SnapshotReport {
    height: u64,
    round: u64,
    floor: Option<u64>,
    order_len: usize,
    applied: usize,
    vertices: usize,
    batches: usize,
    fetch_ms: u64,
    install_ms: u64,
}

/// What a restart rebuilt before the live loop started.
#[derive(Debug, Clone, Copy)]
struct Restored {
    state_root: [u8; 32],
    applied: usize,
    order_len: usize,
    head_height: u64,
    /// Height of the stored snapshot the restart resumed from, when it used one.
    checkpoint: Option<u64>,
}

/// The height a restarted run measures its checkpoint interval from.
///
/// A restored checkpoint is the last anchor a restart resumed from, so the
/// interval continues from it rather than from process start. A store replayed
/// without a checkpoint resumes at its certified head, and a snapshot join
/// resumes at the adopted anchor.
fn resumed_checkpoint_height(restored: Option<&Restored>, certified: Option<u64>) -> u64 {
    match restored {
        Some(restored) => restored.checkpoint.unwrap_or(restored.head_height),
        None => certified.unwrap_or(0),
    }
}

/// The live state a restart rebuilds.
struct Restorable<'a> {
    state: &'a mut State,
    accounts: &'a [chain::Account],
    batches: &'a mut HashMap<[u8; 32], Batch>,
    rejected: &'a mut BTreeMap<&'static str, usize>,
    applied: &'a mut usize,
    applied_cursor: &'a mut usize,
    finalizer: &'a mut Option<Finalizer>,
    /// The RPC surface, when enabled, so a restart can answer `/account` at the
    /// certified head even though the replay may run past it.
    rpc: Option<&'a SharedRpc>,
}

/// The state every live node starts from: the membership's accounts with the
/// harness balance credited.
fn credited_genesis(accounts: &[chain::Account]) -> Result<State, String> {
    let mut state = chain::genesis_state(accounts).map_err(|error| error.to_string())?;
    for account in accounts {
        state
            .credit(&account.address, LIVE_BALANCE)
            .map_err(|error| error.to_string())?;
    }
    Ok(state)
}

/// Replays the stored DAG up to the prefix the latest certificate covers.
///
/// The pacemaker starts at the current cursor, so this is the same decision
/// sequence the original run performed. It stops at the committed prefix named by
/// `head_root`, not at the DAG tip: a header the finalizer builds later names the
/// whole order prefix it covers, so replaying past the certificate would make the
/// first header after restart cover several decisions at once, a header no other
/// validator ever signed. The live loop redoes the decisions above that prefix and
/// records one header per decision.
///
/// The initial boundary is whatever order the node started with: empty for a full
/// replay, and the snapshot's committed prefix for a snapshot restart.
fn replay_to_head(node: &mut Node, head_root: [u8; 32]) -> Result<(), String> {
    let mut boundaries: Vec<(usize, u64)> = vec![(node.dag().order_len(), node.cursor())];
    loop {
        match node.commit_once() {
            Ok(Step::Advanced {
                cursor, anchors, ..
            }) => {
                boundaries.push((node.dag().order_len(), cursor));
                if anchors > 0 {
                    break;
                }
            }
            Ok(Step::Waiting { .. } | Step::TimedOut { .. }) => break,
            Err(error) if error.kind() == CryptoErrorKind::MissingReference => break,
            Err(error) => return Err(format!("cannot rebuild the committed order: {error}")),
        }
    }
    let Some(index) = boundaries
        .iter()
        .rposition(|(len, _)| node.dag().commit_root_at(*len) == Some(head_root))
    else {
        return Err("the certified head does not match any committed prefix".into());
    };
    let (head_len, head_cursor) = boundaries[index];
    if head_len < node.dag().order_len() {
        node.truncate_order(head_len);
        node.set_cursor(head_cursor);
    }
    Ok(())
}

/// Rebuilds a node from its store before the live loop starts.
///
/// The live store keeps every vertex, batch, and certified header, so a restart
/// replays from genesis. A pruned store is refused: its missing prefix carries
/// the committed order, and a header's `dag_root` needs that order to build the
/// next header, so guessing would be worse than failing closed.
fn restore(
    store: &Store,
    node: &mut Node,
    live: &mut Restorable<'_>,
) -> Result<Option<Restored>, String> {
    if let Some(snapshot) = store.live_snapshot().map_err(|error| error.to_string())? {
        return restore_live(store, node, live, snapshot).map(Some);
    }
    let snapshot = store.snapshot().map_err(|error| error.to_string())?;
    let mut vertices = store.vertices().map_err(|error| error.to_string())?;
    let headers = store.headers().map_err(|error| error.to_string())?;
    if vertices.is_empty() && headers.is_empty() {
        return Ok(None);
    }
    let lowest = vertices.iter().map(|vertex| vertex.round).min();
    if snapshot.is_some() || lowest != Some(0) {
        return Err("restart from a pruned store is not supported yet: the committed order prefix is not persisted".into());
    }

    // A transition is installed before any stored vertex or header is replayed:
    // otherwise vertices at the new epoch would be checked against the old set.
    if let Some(transition) = store.set_change().map_err(|error| error.to_string())? {
        node.adopt_set_change(&transition)
            .map_err(|error| format!("stored set change is not authorized: {error}"))?;
        if let Some(finalizer) = live.finalizer.as_mut() {
            finalizer
                .adopt_set_change(&transition)
                .map_err(|error| format!("stored set change cannot be activated: {error}"))?;
        }
    }

    vertices.sort_by(|left, right| {
        left.round
            .cmp(&right.round)
            .then_with(|| left.author.cmp(&right.author))
    });
    for vertex in &vertices {
        node.receive(vertex.clone()).map_err(|error| {
            format!(
                "cannot replay a stored vertex at round {}: {error}",
                vertex.round
            )
        })?;
    }
    if let Some(highest) = node.dag().highest_round() {
        // The top round may be incomplete after an abrupt stop. If this node did
        // not author there, joining it is what lets the committee finish the
        // round; jumping past it would leave a gap the reference rule can never
        // fill.
        let authored_top = node.dag().get(highest, node.id()).is_some();
        node.set_round(if authored_top {
            highest.saturating_add(1)
        } else {
            highest
        });
    }

    // Round skips are decision inputs: replaying the same vertices without them
    // could choose a different order and fail the stored head root.
    let mut control_digests: HashSet<[u8; 32]> = HashSet::new();
    for proof in store.round_skips().map_err(|error| error.to_string())? {
        let payload = ControlPayload::RoundSkip(Box::new(proof.clone()));
        if let Ok(digest) = payload.digest() {
            control_digests.insert(digest);
        }
        // Install the payload before the eager proof so a replay that walks the
        // anchor's causal history still finds it.
        node.add_control(payload)
            .map_err(|error| format!("stored round skip payload is invalid: {error}"))?;
        node.apply_round_skip(proof)
            .map_err(|error| format!("stored round skip is not authorized: {error}"))?;
    }

    let head_root = headers
        .last()
        .map_or_else(|| commit_root(&[]), |record| record.header.dag_root);
    replay_to_head(node, head_root)?;

    for batch in store.batches().map_err(|error| error.to_string())? {
        let digest = batch.digest().map_err(|error| error.to_string())?;
        live.batches.insert(digest, batch);
    }
    let order = node.dag().order().to_vec();
    while *live.applied_cursor < order.len() {
        let id = &order[*live.applied_cursor];
        let Some(vertex) = node.dag().get(id.round, &id.author) else {
            break;
        };
        if vertex.payload_hash == [0u8; 32] || control_digests.contains(&vertex.payload_hash) {
            *live.applied_cursor += 1;
            continue;
        }
        let Some(batch) = live.batches.get(&vertex.payload_hash) else {
            break;
        };
        *live.applied += chain::apply_batch(live.state, live.accounts, batch, live.rejected);
        if let Some(rpc) = live.rpc {
            rpc.lock()
                .expect("rpc lock poisoned")
                .note_state(*live.applied as u64, live.state);
        }
        *live.applied_cursor += 1;
    }

    if let Some(finalizer) = live.finalizer {
        let mut stored = headers;
        stored.sort_by_key(|record| record.header.height);
        for record in stored {
            if record.header.height == 0 {
                continue;
            }
            finalizer
                .adopt_certified(record.header, record.certificate)
                .map_err(|error| format!("cannot adopt a stored header: {error}"))?;
        }
        finalizer.resume_from_head();
    }
    Ok(Some(Restored {
        state_root: live.state.state_root(),
        applied: *live.applied,
        order_len: node.dag().order_len(),
        head_height: live
            .finalizer
            .as_ref()
            .map_or(0, |finalizer| finalizer.head().height),
        checkpoint: None,
    }))
}

/// Resumes a node from the snapshot it joined through.
///
/// The state and committed prefix are adopted as they were verified at join
/// time, then the tail above the floor is replayed and re-committed. The stored
/// certified headers above the anchor advance the header chain; the anchor's own
/// certificate is the trust root.
fn restore_live(
    store: &Store,
    node: &mut Node,
    live: &mut Restorable<'_>,
    snapshot: LiveSnapshot,
) -> Result<Restored, String> {
    let state = State::decode(&snapshot.state)
        .map_err(|error| format!("live snapshot state does not decode: {error}"))?;
    if state.state_root() != snapshot.header.state_root {
        return Err("live snapshot state root does not match its header".into());
    }
    if snapshot.prefix.len().checked_add(snapshot.order.len()) != Some(snapshot.order_len) {
        return Err("live snapshot order length does not match its prefix and tail".into());
    }
    if snapshot
        .prefix
        .root_at(&snapshot.order, snapshot.order.len())
        != Some(snapshot.header.dag_root)
    {
        return Err("live snapshot order does not reproduce its header dag_root".into());
    }
    let anchor_height = snapshot.header.height;
    let finalizer = live
        .finalizer
        .as_mut()
        .ok_or("a live snapshot needs execution (--execute)")?;
    if let Some(transition) = &snapshot.transition {
        node.adopt_set_change(transition)
            .map_err(|error| format!("live snapshot set change is not authorized: {error}"))?;
        finalizer
            .adopt_set_change(transition)
            .map_err(|error| format!("live snapshot set change cannot be activated: {error}"))?;
    }
    finalizer
        .adopt_anchor(
            snapshot.header.clone(),
            &snapshot.certificate,
            snapshot.order_len,
        )
        .map_err(|error| format!("live snapshot anchor is not certified: {error}"))?;
    *live.state = state;
    *live.applied = usize::try_from(snapshot.applied)
        .map_err(|_| format!("{} applied transactions do not fit", snapshot.applied))?;
    *live.applied_cursor = snapshot.order_len;
    node.seed_prefix(snapshot.prefix, snapshot.order);
    if let Some(floor) = snapshot.floor {
        node.set_floor(floor);
    }
    node.set_cursor(snapshot.cursor);
    // The snapshot's fences are installed before the stored tail so the replay
    // uses the same rules the node used when it wrote that tail. A tail vertex
    // that arrived before the fence is inert and cannot be inserted again.
    apply_snapshot_fences(node, Some(store), &snapshot.fences)?;

    let mut vertices = store.vertices().map_err(|error| error.to_string())?;
    vertices.sort_by(|left, right| {
        left.round
            .cmp(&right.round)
            .then_with(|| left.author.cmp(&right.author))
    });
    for vertex in &vertices {
        if inert_under_fences(vertex, &snapshot.fences) {
            continue;
        }
        node.receive(vertex.clone()).map_err(|error| {
            format!(
                "cannot replay a stored tail vertex at round {}: {error}",
                vertex.round
            )
        })?;
    }
    if let Some(highest) = node.dag().highest_round() {
        let authored_top = node.dag().get(highest, node.id()).is_some();
        node.set_round(
            if authored_top {
                highest.saturating_add(1)
            } else {
                highest
            }
            .max(snapshot.cursor),
        );
    } else {
        node.set_round(snapshot.cursor);
    }
    for batch in store.batches().map_err(|error| error.to_string())? {
        let digest = batch.digest().map_err(|error| error.to_string())?;
        live.batches.insert(digest, batch);
    }

    // Round skips above the snapshot floor are decision inputs for the tail
    // replay; the ones below it are already part of the adopted prefix.
    let mut control_digests: HashSet<[u8; 32]> = HashSet::new();
    for proof in store.round_skips().map_err(|error| error.to_string())? {
        let payload = ControlPayload::RoundSkip(Box::new(proof.clone()));
        if let Ok(digest) = payload.digest() {
            control_digests.insert(digest);
        }
        node.add_control(payload)
            .map_err(|error| format!("stored round skip payload is invalid: {error}"))?;
        node.apply_round_skip(proof)
            .map_err(|error| format!("stored round skip is not authorized: {error}"))?;
    }

    // Rebuild the order above the anchor, exactly as the live loop would, and
    // stop at the prefix the latest stored certificate covers. The decisions above
    // it are redone by the live loop so every header covers one decision.
    let mut headers = store.headers().map_err(|error| error.to_string())?;
    headers.sort_by_key(|record| record.header.height);
    let head_root = headers
        .last()
        .map_or(snapshot.header.dag_root, |record| record.header.dag_root);
    replay_to_head(node, head_root)?;

    let base = node.dag().prefix().len();
    let order = node.dag().order().to_vec();
    while *live.applied_cursor < node.dag().order_len() {
        let Some(index) = (*live.applied_cursor).checked_sub(base) else {
            break;
        };
        let Some(id) = order.get(index) else {
            break;
        };
        let Some(vertex) = node.dag().get(id.round, &id.author) else {
            break;
        };
        if vertex.payload_hash == [0u8; 32] || control_digests.contains(&vertex.payload_hash) {
            *live.applied_cursor += 1;
            continue;
        }
        let Some(batch) = live.batches.get(&vertex.payload_hash) else {
            break;
        };
        *live.applied += chain::apply_batch(live.state, live.accounts, batch, live.rejected);
        if let Some(rpc) = live.rpc {
            rpc.lock()
                .expect("rpc lock poisoned")
                .note_state(*live.applied as u64, live.state);
        }
        *live.applied_cursor += 1;
    }

    for record in headers {
        if record.header.height <= anchor_height {
            continue;
        }
        finalizer
            .adopt_certified(record.header, record.certificate)
            .map_err(|error| format!("cannot adopt a stored header: {error}"))?;
    }
    finalizer.resume_from_head();

    Ok(Restored {
        state_root: live.state.state_root(),
        applied: *live.applied,
        order_len: node.dag().order_len(),
        head_height: finalizer.head().height,
        checkpoint: Some(anchor_height),
    })
}

/// Keeps the state at one cumulative applied count for snapshot serving.
fn remember_state(states: &mut VecDeque<(u64, State)>, applied: u64, state: &State) {
    if states.back().is_some_and(|(at, _)| *at == applied) {
        return;
    }
    states.push_back((applied, state.clone()));
    while states.len() > SNAPSHOT_STATES {
        states.pop_front();
    }
}

/// Re-admits the batch of each newly skipped leader.
///
/// A skip records the round without committing its history, so the leader's
/// batch stays out of the execution order. The author's mempool no
/// longer holds those transactions; returning the batch is what keeps them from
/// being stranded. If the same vertex later commits through another anchor, the
/// execution state's sequence rule rejects the recovered copy, so recovery
/// cannot apply a transaction twice.
fn recover_skipped_batches(
    node: &Node,
    batches: &HashMap<[u8; 32], Batch>,
    rpc: Option<&SharedRpc>,
    recovered: &mut usize,
    now: u64,
) -> usize {
    let skipped = node.dag().skipped();
    if *recovered >= skipped.len() {
        return 0;
    }
    let Some(rpc) = rpc else {
        *recovered = skipped.len();
        return 0;
    };
    let floor = node.dag().floor();
    let mut admitted = 0;
    for entry in &skipped[*recovered..] {
        let Some(vertex) = node.dag().get(entry.round, &entry.author) else {
            continue;
        };
        if floor.is_some_and(|floor| entry.round <= floor) {
            continue;
        }
        let Ok(id) = vertex.id() else {
            continue;
        };
        if node.dag().order().contains(&id) {
            // The vertex already committed as history; the execution loop owns
            // its batch.
            continue;
        }
        let Some(batch) = batches.get(&vertex.payload_hash) else {
            continue;
        };
        admitted += rpc
            .lock()
            .expect("rpc lock poisoned")
            .readmit_batch(batch, now);
    }
    *recovered = skipped.len();
    admitted
}

/// The last `limit` vertices this node authored, oldest first.
fn recent_own_vertices(node: &Node, index: usize, limit: usize) -> Vec<validator::Vertex> {
    let Some(record) = node.dag().set().validators.get(index) else {
        return Vec::new();
    };
    let own = record.validator_id.clone();
    let mut held = held_vertices(node);
    held.retain(|vertex| vertex.author == own);
    if held.len() > limit {
        held.drain(..held.len() - limit);
    }
    held
}

/// Every vertex this node still holds, in round and validator order.
fn held_vertices(node: &Node) -> Vec<validator::Vertex> {
    let dag = node.dag();
    let Some(highest) = dag.highest_round() else {
        return Vec::new();
    };
    let mut vertices = Vec::new();
    for round in 0..=highest {
        for record in &dag.set_for_round(round).validators {
            if let Some(vertex) = dag.get(round, &record.validator_id) {
                vertices.push(vertex.clone());
            }
        }
    }
    vertices
}

/// The lowest round a snapshot can drop without losing an uncommitted vertex.
///
/// Mirrors the rule the finality harness uses: a held vertex outside the committed
/// prefix may still be committed later, so it stays above the floor. Round zero is
/// never pruned; when no positive floor is safe the DAG travels whole.
fn snapshot_floor(node: &Node, order: &[VertexId], anchor_round: u64) -> Option<u64> {
    if anchor_round <= SNAPSHOT_FLOOR_MARGIN {
        return None;
    }
    let committed: HashSet<(u64, Vec<u8>)> = order
        .iter()
        .map(|id| (id.round, id.author.clone()))
        .collect();
    let mut floor = anchor_round - SNAPSHOT_FLOOR_MARGIN;
    let dag = node.dag();
    let Some(highest) = dag.highest_round() else {
        return (floor > 0).then_some(floor);
    };
    for round in 0..=highest.min(floor) {
        for record in &dag.set_for_round(round).validators {
            if dag.get(round, &record.validator_id).is_none() {
                continue;
            }
            if !committed.contains(&(round, record.validator_id.clone())) {
                if round == 0 {
                    return None;
                }
                floor = floor.min(round - 1);
            }
        }
    }
    (floor > 0).then_some(floor)
}

/// Builds the checked transition this run is configured to propose.
///
/// Every node computes the same new set from the same base, so the descriptor
/// and the signing payload are identical across the mesh.
fn proposed_change(
    config: &Config,
    set: &ValidatorSet,
    chain_id: &[u8],
) -> Result<Option<(SetChange, ValidatorSet)>, String> {
    let Some((kind, epoch)) = config.change else {
        return Ok(None);
    };
    if epoch <= set.epoch {
        return Err(format!(
            "set-change epoch {epoch} must advance past the current epoch {}",
            set.epoch
        ));
    }
    let next = match kind {
        SetChangeKind::Add => chain::append_validator(set, epoch),
        SetChangeKind::Remove => chain::remove_last_validator(set, epoch),
    }
    .map_err(|error| format!("cannot build the next validator set: {error}"))?;
    let change = SetChange::new(chain_id.to_vec(), set, &next)
        .map_err(|error| format!("the proposed set change is not safe: {error}"))?;
    Ok(Some((change, next)))
}

/// One empty partial certificate for a transition, sized to the old set.
fn empty_change_certificate(
    certificate: &TransitionCertificate,
    set: &ValidatorSet,
) -> TransitionCertificate {
    TransitionCertificate {
        change: certificate.change.clone(),
        new_set: certificate.new_set.clone(),
        signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
        signatures: Vec::new(),
    }
}

/// This node's own share of a proposed transition.
fn own_change_share(
    change: &SetChange,
    next: &ValidatorSet,
    set: &ValidatorSet,
    signer: &[u8],
    private_key: &[u8],
) -> Result<TransitionCertificate, String> {
    let index = set
        .validators
        .iter()
        .position(|record| record.validator_id == signer)
        .ok_or("this node is not in the old validator set")?;
    let payload = change
        .signing_payload()
        .map_err(|error| error.to_string())?;
    let signature = Ed25519Scheme
        .sign(private_key, &payload)
        .map_err(|error| error.to_string())?;
    let mut signer_bitmap = vec![0u8; bitmap_len(set.validators.len())];
    set_bit(&mut signer_bitmap, index);
    Ok(TransitionCertificate {
        change: change.clone(),
        new_set: next.clone(),
        signer_bitmap,
        signatures: vec![signature],
    })
}

/// One empty partial fence, sized to the set that signs it.
fn empty_fence_certificate(certificate: &FenceCertificate, set: &ValidatorSet) -> FenceCertificate {
    FenceCertificate {
        fence: certificate.fence.clone(),
        signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
        signatures: Vec::new(),
    }
}

/// This node's own share of a fence declaration.
fn own_fence_share(
    fence: &Fence,
    set: &ValidatorSet,
    signer: &[u8],
    private_key: &[u8],
) -> Result<FenceCertificate, String> {
    let index = set
        .validators
        .iter()
        .position(|record| record.validator_id == signer)
        .ok_or("this node is not in the fenced set")?;
    let payload = fence.signing_payload().map_err(|error| error.to_string())?;
    let signature = Ed25519Scheme
        .sign(private_key, &payload)
        .map_err(|error| error.to_string())?;
    let mut signer_bitmap = vec![0u8; bitmap_len(set.validators.len())];
    set_bit(&mut signer_bitmap, index);
    Ok(FenceCertificate {
        fence: fence.clone(),
        signer_bitmap,
        signatures: vec![signature],
    })
}

/// Picks the silent validator this node should fence, and the round the fence
/// starts at.
///
/// The round is derived from the failed validator's last observed round, not from
/// this node's cursor. Two survivors whose cursors have diverged still name the
/// same round, so their shares can combine into one certificate. A missing leader
/// needs a fence at or below its own round; a missing voter needs one at or below
/// the voter's round, which `last_round + 1` satisfies in both cases.
fn fence_candidate(node: &Node, silent: &[(Vec<u8>, u64)]) -> Option<(Vec<u8>, u64)> {
    let cursor = node.cursor();
    let lowest = node
        .dag()
        .floor()
        .map_or(1, |floor| floor.saturating_add(1));
    let (validator, last_round, relevant_round) = if node.dag().leader(cursor).is_none() {
        let author = node.dag().leader_author(cursor)?;
        let (validator, last_round) = silent.iter().find(|(validator, last_round)| {
            validator.as_slice() == author
                && *last_round < cursor
                && validator.as_slice() != node.id()
        })?;
        (validator, *last_round, cursor)
    } else {
        let voter_round = cursor.saturating_add(1);
        let voters = node.dag().set_for_round(voter_round);
        let (validator, last_round) = silent.iter().find(|(validator, last_round)| {
            *last_round < voter_round
                && validator.as_slice() != node.id()
                && voters.validator(validator).is_some()
                && node.dag().get(voter_round, validator).is_none()
        })?;
        (validator, *last_round, voter_round)
    };
    let from_round = last_round.saturating_add(1).max(lowest);
    if from_round > relevant_round
        || node
            .dag()
            .set_for_round(from_round)
            .validator(validator)
            .is_none()
    {
        return None;
    }
    Some((validator.clone(), from_round))
}

/// Builds the round-skip proof the cursor's leader allows, if any.
///
/// Every voter this node holds at the voting round is a vote or a non-vote; the
/// rest are missing. A missing voter whose fence covers the voting round is
/// carried as that fence instead. The proof is verified with the same function a
/// receiver uses, so a locally built proof is never weaker than a gossiped one.
fn round_skip_candidate(node: &Node, chain_id: &[u8]) -> Option<RoundSkipProof> {
    let round = node.cursor();
    let leader = node.dag().leader(round)?;
    let leader_id = leader.id().ok()?;
    let voting_round = round.saturating_add(1);
    let voter_set = node.dag().set_for_round(voting_round).clone();
    let mut votes = Vec::new();
    let mut non_votes = Vec::new();
    let mut missing = Vec::new();
    for record in &voter_set.validators {
        match node.dag().get(voting_round, &record.validator_id) {
            Some(vertex) => {
                let id = vertex.id().ok()?;
                if vertex
                    .references
                    .iter()
                    .any(|reference| reference == &leader_id)
                {
                    votes.push(id);
                } else {
                    non_votes.push(id);
                }
            }
            None => missing.push(record.validator_id.clone()),
        }
    }
    let fenced_absent: Vec<FenceCertificate> = node
        .dag()
        .fences()
        .filter(|certificate| {
            certificate.fence.from_round <= voting_round
                && missing
                    .iter()
                    .any(|validator| validator == &certificate.fence.validator_id)
        })
        .cloned()
        .collect();
    missing.retain(|validator| {
        !fenced_absent
            .iter()
            .any(|certificate| &certificate.fence.validator_id == validator)
    });
    let proof = RoundSkipProof {
        attestation: NoVoteAttestation {
            skip: RoundSkip::new(chain_id.to_vec(), leader_id.clone()),
            signer_bitmap: vec![0u8; bitmap_len(voter_set.validators.len())],
            signatures: Vec::new(),
        },
        votes,
        non_votes,
        fenced_absent,
        missing,
    };
    proof
        .verify(
            chain_id,
            &voter_set,
            &leader_id,
            |fence_round| node.dag().set_for_round(fence_round).clone(),
            |id| node.dag().get(id.round, &id.author).cloned(),
        )
        .ok()?;
    Some(proof)
}

/// Whether this node may sign a fence without contradicting its own view.
///
/// The signer promises not to vote for the fenced validator from `from_round`
/// on. That promise is safe exactly when the signer has never seen the validator
/// at or after that round: a vote for it would have required holding its vertex.
/// The signer's own cursor is irrelevant; tying the fence to it is what made two
/// survivors propose different rounds and fail to reach a quorum.
fn may_sign_fence(node: &Node, failures: Option<&FailureDetector>, fence: &Fence) -> bool {
    if fence.validator_id == node.id() {
        // A quorum may declare this node failed; this node does not help.
        return false;
    }
    if node
        .dag()
        .floor()
        .is_some_and(|floor| fence.from_round <= floor)
    {
        return false;
    }
    if node
        .dag()
        .set_for_round(fence.from_round)
        .validator(&fence.validator_id)
        .is_none()
    {
        return false;
    }
    let Some(failures) = failures else {
        return false;
    };
    failures
        .silent()
        .into_iter()
        .any(|(validator, last_round)| {
            validator == fence.validator_id && last_round < fence.from_round
        })
}

/// Why a node cannot serve a snapshot right now.
///
/// A decline is diagnostic, not a consensus statement. The joining node uses it
/// to fail over to another peer instead of waiting for the snapshot timeout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotDecline {
    NoExecution,
    NoCertifiedHead,
    NoCertifiedOrder,
    CoverageOutsideOrder,
    NoSafeFloor,
    StateEvicted { applied: u64 },
    StateRootMismatch,
    StateEncoding,
    BridgeIncomplete { round: u64 },
    PayloadMissing,
    ControlPending,
}

impl std::fmt::Display for SnapshotDecline {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoExecution => write!(formatter, "the node does not execute state"),
            Self::NoCertifiedHead => write!(formatter, "no certified header yet"),
            Self::NoCertifiedOrder => {
                write!(
                    formatter,
                    "the certified head has no committed order length"
                )
            }
            Self::CoverageOutsideOrder => {
                write!(
                    formatter,
                    "the certified coverage is outside the held order"
                )
            }
            Self::NoSafeFloor => write!(formatter, "no floor is safe to prune at"),
            Self::StateEvicted { applied } => {
                write!(
                    formatter,
                    "the state at applied {applied} is no longer retained"
                )
            }
            Self::StateRootMismatch => {
                write!(
                    formatter,
                    "the retained state does not match the certified root"
                )
            }
            Self::StateEncoding => write!(formatter, "the retained state cannot be encoded"),
            Self::BridgeIncomplete { round } => {
                write!(formatter, "a tail reference at round {round} has no bridge")
            }
            Self::PayloadMissing => {
                write!(
                    formatter,
                    "a tail vertex names a batch this node does not hold"
                )
            }
            Self::ControlPending => {
                write!(formatter, "a tail vertex names a pending control payload")
            }
        }
    }
}

/// Rejects a snapshot whose tail is not a closed bridge.
///
/// Every reference above the floor must name a vertex in the tail. A reference
/// at or below the floor is covered only when it is committed at the anchor or
/// already pruned. Every non-empty payload must be a carried batch or a carried
/// round-skip proof; a pending control is not carried yet, so it makes the
/// bridge incomplete instead of pretending the joiner can apply it.
fn check_snapshot_bridge(
    dag: &validator::Dag,
    floor: u64,
    vertices: &[validator::Vertex],
    committed: &HashSet<VertexId>,
    round_skips: &[RoundSkipProof],
    batches: &HashMap<[u8; 32], Batch>,
) -> Result<(), SnapshotDecline> {
    let held: HashSet<VertexId> = vertices
        .iter()
        .filter_map(|vertex| vertex.id().ok())
        .collect();
    let controls: HashSet<[u8; 32]> = round_skips
        .iter()
        .filter_map(|proof| {
            ControlPayload::RoundSkip(Box::new(proof.clone()))
                .digest()
                .ok()
        })
        .collect();
    for vertex in vertices {
        for reference in &vertex.references {
            let covered = if reference.round <= floor {
                dag.floor()
                    .is_some_and(|dag_floor| reference.round <= dag_floor)
                    || committed.contains(reference)
            } else {
                held.contains(reference)
            };
            if !covered {
                return Err(SnapshotDecline::BridgeIncomplete {
                    round: reference.round,
                });
            }
        }
        if vertex.payload_hash == [0u8; 32] || controls.contains(&vertex.payload_hash) {
            continue;
        }
        if dag.control(&vertex.payload_hash).is_some() {
            return Err(SnapshotDecline::ControlPending);
        }
        if !batches.contains_key(&vertex.payload_hash) {
            return Err(SnapshotDecline::PayloadMissing);
        }
    }
    Ok(())
}

/// Builds the snapshot this node can serve right now.
///
/// It is anchored at the certified head, so the receiver has a quorum statement
/// for the state it adopts. The state must still be in the ring; an evicted
/// applied count means this node declines rather than serving a root it cannot
/// reproduce.
fn build_live_snapshot(
    node: &Node,
    finalizer: &Finalizer,
    last_certified: Option<&(Header, Certificate)>,
    states: &VecDeque<(u64, State)>,
    batches: &HashMap<[u8; 32], Batch>,
) -> Result<wire::Snapshot, SnapshotDecline> {
    // The anchor is the latest *certified* header, not the finalizer's built head.
    // Those can differ: a node that built one header and certified another at the
    // same height would otherwise never checkpoint, and its store would grow until
    // the next restart. A certificate is self-contained, so anchoring at it is safe.
    let (header, certificate) = last_certified.ok_or(SnapshotDecline::NoCertifiedHead)?;
    let coverage = finalizer
        .certified_order(header.height)
        .ok_or(SnapshotDecline::NoCertifiedOrder)?;
    let dag = node.dag();
    let base = dag.prefix().len();
    if coverage > dag.order_len() || coverage < base {
        return Err(SnapshotDecline::CoverageOutsideOrder);
    }
    let tail_coverage = coverage - base;
    let committed_tail = &dag.order()[..tail_coverage];
    let proposed =
        snapshot_floor(node, committed_tail, header.round).ok_or(SnapshotDecline::NoSafeFloor)?;
    // The floor only rises: a held prefix below the current floor is already
    // committed, so a candidate that would go backwards cannot drop it again.
    let floor = proposed.max(dag.floor().unwrap_or(0));
    let split = committed_tail
        .iter()
        .position(|id| id.round > floor)
        .unwrap_or(tail_coverage);
    let mut prefix = dag.prefix().clone();
    prefix.extend(&committed_tail[..split]);
    let order = committed_tail[split..].to_vec();
    let state = states
        .iter()
        .rev()
        .find(|(applied, _)| *applied == header.applied)
        .ok_or(SnapshotDecline::StateEvicted {
            applied: header.applied,
        })?
        .1
        .clone();
    if state.state_root() != header.state_root {
        return Err(SnapshotDecline::StateRootMismatch);
    }
    // Only certificates the DAG adopted travel: a partial promise has no quorum
    // and a joiner would have to reject the whole snapshot. A fence below the
    // snapshot floor still travels, because it governs every round above it.
    let fences: Vec<FenceCertificate> = node.dag().fences().cloned().collect();
    let vertices: Vec<validator::Vertex> = held_vertices(node)
        .into_iter()
        .filter(|vertex| vertex.round > floor)
        .filter(|vertex| !inert_under_fences(vertex, &fences))
        .collect();
    let mut seen = HashSet::new();
    let mut tail_batches = Vec::new();
    for vertex in &vertices {
        if vertex.payload_hash == [0u8; 32] || !seen.insert(vertex.payload_hash) {
            continue;
        }
        if let Some(batch) = batches.get(&vertex.payload_hash) {
            tail_batches.push(batch.clone());
        }
    }
    let round_skips: Vec<RoundSkipProof> = node.dag().round_skips().cloned().collect();
    let committed: HashSet<VertexId> = committed_tail.iter().cloned().collect();
    check_snapshot_bridge(dag, floor, &vertices, &committed, &round_skips, batches)?;
    Ok(wire::Snapshot {
        state: state.encode().map_err(|_| SnapshotDecline::StateEncoding)?,
        order,
        order_len: coverage,
        prefix,
        anchor: header.clone(),
        certificate: certificate.clone(),
        transition: node.dag().set_schedule().certificate().cloned(),
        fences,
        cursor: header.round.saturating_add(1),
        floor: Some(floor),
        vertices,
        batches: tail_batches,
        round_skips,
    })
}

/// Reads one message from a stream whose handshake buffer may already hold bytes.
async fn read_one_message(
    stream: &mut TcpStream,
    buffer: &mut Vec<u8>,
) -> Result<wire::Message, String> {
    loop {
        match wire::take_frame(buffer) {
            Ok(Some(frame)) => return Ok(frame.message),
            Ok(None) => {}
            Err(error) => return Err(error.to_string()),
        }
        let mut chunk = [0u8; 64 * 1024];
        let read = stream
            .read(&mut chunk)
            .await
            .map_err(|error| format!("snapshot link read: {error}"))?;
        if read == 0 {
            return Err("peer closed before sending a frame".into());
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Requests one snapshot from a peer's dedicated snapshot port.
async fn fetch_one(target: &str, chain_id: &[u8]) -> Result<wire::Snapshot, String> {
    let mut stream = tokio::time::timeout(SNAPSHOT_CONNECT_TIMEOUT, TcpStream::connect(target))
        .await
        .map_err(|_| format!("connect to {target} timed out"))?
        .map_err(|error| format!("connect to {target}: {error}"))?;
    let mut buffer = Vec::new();
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        handshake(&mut stream, &mut buffer, chain_id),
    )
    .await
    .map_err(|_| format!("handshake with {target} timed out"))?
    .map_err(|error| format!("handshake with {target}: {error}"))?;
    let request =
        wire::frame(&Message::SnapshotWant, unix_nanos()).map_err(|error| error.to_string())?;
    stream
        .write_all(&request)
        .await
        .map_err(|error| format!("snapshot request to {target}: {error}"))?;
    let deadline = tokio::time::Instant::now() + SNAPSHOT_READ_TIMEOUT;
    loop {
        match wire::take_frame(&mut buffer) {
            Ok(Some(frame)) => {
                return match frame.message {
                    Message::Snapshot(snapshot) => Ok(*snapshot),
                    Message::SnapshotDeclined(reason) => {
                        Err(format!("{target} declined the snapshot: {reason}"))
                    }
                    other => Err(format!("{target} answered with {other:?}")),
                };
            }
            Ok(None) => {}
            Err(error) => return Err(error.to_string()),
        }
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return Err(format!("timed out waiting for {target}'s snapshot"));
        }
        let mut chunk = vec![0u8; 64 * 1024];
        let read = tokio::time::timeout(remaining, stream.read(&mut chunk))
            .await
            .map_err(|_| format!("timed out reading {target}'s snapshot"))?
            .map_err(|error| format!("snapshot read from {target}: {error}"))?;
        if read == 0 {
            return Err(format!("{target} closed before sending a snapshot"));
        }
        buffer.extend_from_slice(&chunk[..read]);
    }
}

/// Tries every peer's snapshot port until one answers.
async fn fetch_snapshot(
    port_base: u16,
    index: usize,
    total: usize,
    chain_id: &[u8],
    min_height: u64,
) -> Result<wire::Snapshot, String> {
    let deadline = tokio::time::Instant::now() + SNAPSHOT_STARTUP_WAIT;
    let mut last = String::from("no peers were tried");
    loop {
        for peer in 0..total {
            if peer == index {
                continue;
            }
            let target = rpc_address(port_base, peer)?;
            match fetch_one(&target, chain_id).await {
                // A snapshot at or below what this node already certified would
                // move its trust anchor backwards. Keep looking for one that is
                // ahead, which is what a lagging node needs.
                Ok(snapshot) if snapshot.anchor.height > min_height => {
                    println!(
                        "  node val-{index} snapshot candidate {target}: height {} round {} floor {:?}, committed {}, tail {} vertices / {} batches",
                        snapshot.anchor.height,
                        snapshot.anchor.round,
                        snapshot.floor,
                        snapshot.order_len,
                        snapshot.vertices.len(),
                        snapshot.batches.len()
                    );
                    return Ok(snapshot);
                }
                Ok(snapshot) => {
                    println!(
                        "  node val-{index} snapshot candidate {target}: height {} floor {:?} is not above the stored head {min_height}",
                        snapshot.anchor.height, snapshot.floor
                    );
                    last = format!(
                        "{target}: snapshot height {} is not above the stored head {min_height}",
                        snapshot.anchor.height
                    );
                }
                Err(error) => {
                    println!("  node val-{index} snapshot candidate {target}: {error}");
                    last = format!("{target}: {error}");
                }
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(format!(
                "no peer served a snapshot above height {min_height} ({last})"
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// What a snapshot join adopted.
struct Adopted {
    state: State,
    applied: usize,
    order_len: usize,
    anchor: Header,
    certificate: Certificate,
    floor: Option<u64>,
    vertices: usize,
    batches: usize,
}

/// Whether `vertex` can no longer be inserted once `fences` are installed.
///
/// A node may hold such a vertex when it arrived before the quorum fence did.
/// The fence makes it inert: it cannot become a vote, and a fresh DAG would
/// reject it on insert. Snapshot tails skip it for that reason.
fn inert_under_fences(vertex: &validator::Vertex, fences: &[FenceCertificate]) -> bool {
    fences.iter().any(|certificate| {
        certificate.fence.validator_id == vertex.author
            && vertex.round >= certificate.fence.from_round
    })
}

/// Installs the fences a snapshot carries before any tail vertex is replayed.
///
/// The certificates are checked against the set active at their round and
/// persisted, so a restart does not wait again on a leader the quorum already
/// declared failed. A fence whose round a checkpoint has pruned is still
/// installed: it governs every round above the floor.
fn apply_snapshot_fences(
    node: &mut Node,
    store: Option<&Store>,
    fences: &[FenceCertificate],
) -> Result<(), String> {
    for certificate in fences {
        node.apply_fence(certificate)
            .map_err(|error| format!("snapshot fence is not authorized: {error}"))?;
        if let Some(store) = store {
            store
                .put_fence(certificate)
                .map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

/// Restores the fence shares this node signed before it stopped.
///
/// The signature is the promise: a restart that forgot it could vote for an
/// author it already declared failed. Each stored share is checked against the
/// set active at its round and noted in the DAG; the returned certificates let
/// the live loop keep collecting the quorum and rebroadcast the proposal.
fn load_local_fence_shares(
    node: &mut Node,
    store: &Store,
    chain_id: &[u8],
) -> Result<Vec<FenceCertificate>, String> {
    let mut shares = Vec::new();
    for certificate in store.fence_shares().map_err(|error| error.to_string())? {
        let set = node
            .dag()
            .set_for_round(certificate.fence.from_round)
            .clone();
        certificate
            .check(chain_id, &set)
            .map_err(|error| format!("stored fence share is not authorized: {error}"))?;
        node.note_local_fence(&certificate.fence);
        shares.push(certificate);
    }
    Ok(shares)
}

/// Verifies a received snapshot and starts the node from its anchor.
///
/// Nothing is trusted because it arrived: the state root must match the anchor,
/// the order must reproduce its `dag_root`, and the certificate must carry a
/// quorum for the anchor's epoch before the anchor replaces genesis. The fences
/// are verified separately against the set active at each fence round.
fn adopt_snapshot(
    snapshot: wire::Snapshot,
    node: &mut Node,
    finalizer: &mut Option<Finalizer>,
    batches: &mut HashMap<[u8; 32], Batch>,
    chain_id: &[u8],
    store: Option<&Store>,
) -> Result<Adopted, String> {
    let wire::Snapshot {
        state,
        order,
        order_len,
        prefix,
        anchor,
        certificate,
        transition,
        fences,
        round_skips,
        cursor,
        floor,
        vertices,
        batches: incoming,
    } = snapshot;
    if anchor.chain_id != chain_id {
        return Err("snapshot is anchored on another chain".into());
    }
    let decoded = State::decode(&state)
        .map_err(|error| format!("snapshot state does not decode: {error}"))?;
    if decoded.state_root() != anchor.state_root {
        return Err("snapshot state root does not match the anchor".into());
    }
    if prefix.len().checked_add(order.len()) != Some(order_len) {
        return Err("snapshot order length does not match its prefix and tail".into());
    }
    if prefix.root_at(&order, order.len()) != Some(anchor.dag_root) {
        return Err("snapshot order does not reproduce the anchor dag_root".into());
    }
    let finalizer = finalizer
        .as_mut()
        .ok_or("a snapshot join needs execution (--execute)")?;
    if let Some(transition) = &transition {
        node.adopt_set_change(transition)
            .map_err(|error| format!("snapshot set change is not authorized: {error}"))?;
        finalizer
            .adopt_set_change(transition)
            .map_err(|error| format!("snapshot set change cannot be activated: {error}"))?;
        if let Some(store) = store {
            store
                .put_set_change(transition)
                .map_err(|error| error.to_string())?;
        }
    }
    finalizer
        .adopt_anchor(anchor.clone(), &certificate, order_len)
        .map_err(|error| format!("snapshot anchor is not certified: {error}"))?;
    let stored_order = order.clone();
    let stored_prefix = prefix.clone();
    node.seed_prefix(prefix, order);
    if let Some(floor) = floor {
        node.set_floor(floor);
    }
    node.set_cursor(cursor);
    // Installed before the tail so every replayed vertex is judged by the same
    // rules the live sender applied. A tail vertex that arrived before the
    // fence is inert, and a fresh DAG would reject it on insert.
    apply_snapshot_fences(node, store, &fences)?;
    let vertices: Vec<validator::Vertex> = vertices
        .into_iter()
        .filter(|vertex| !inert_under_fences(vertex, &fences))
        .collect();
    for vertex in &vertices {
        node.receive(vertex.clone())
            .map_err(|error| format!("cannot replay a snapshot tail vertex: {error}"))?;
    }
    // Round skips are decision inputs for the tail. Install them only after the
    // vertices they name are held: a proof is verified against the leader and
    // the voting-round vertices, so a proof that arrived before its evidence
    // would be rejected rather than queued. The proofs are persisted with the
    // rest of the snapshot, after their evidence is on disk.
    let mut verified_skips = Vec::new();
    for proof in round_skips {
        let payload = ControlPayload::RoundSkip(Box::new(proof.clone()));
        node.add_control(payload)
            .map_err(|error| format!("snapshot round skip payload is invalid: {error}"))?;
        node.apply_round_skip(proof.clone())
            .map_err(|error| format!("snapshot round skip is not authorized: {error}"))?;
        verified_skips.push(proof);
    }
    let batch_count = incoming.len();
    if let Some(store) = store {
        store
            .put_header(&anchor, &certificate)
            .map_err(|error| error.to_string())?;
        for vertex in &vertices {
            store
                .append_vertex(vertex)
                .map_err(|error| error.to_string())?;
        }
        for batch in &incoming {
            store.put_batch(batch).map_err(|error| error.to_string())?;
        }
        for proof in &verified_skips {
            store
                .put_round_skip(proof)
                .map_err(|error| error.to_string())?;
        }
        // The live snapshot is the activation point: all records the restart
        // needs are already on disk before this file appears. A crash before
        // the write leaves valid tail records without an adopted snapshot, so
        // the node resumes from its previous anchor and replays them; a crash
        // after it leaves a complete snapshot. Writing it first would make a
        // crash leave a snapshot whose tail was never stored.
        store
            .put_live_snapshot(&store::LiveSnapshot {
                round: anchor.round,
                floor,
                cursor,
                applied: anchor.applied,
                state: state.clone(),
                order: stored_order,
                order_len,
                prefix: stored_prefix,
                header: anchor.clone(),
                certificate: certificate.clone(),
                transition: transition.clone(),
                fences: fences.clone(),
            })
            .map_err(|error| error.to_string())?;
    }
    for batch in incoming {
        if let Ok(digest) = batch.digest() {
            batches.insert(digest, batch);
        }
    }
    let highest = node.dag().highest_round().unwrap_or(anchor.round);
    let authored_top = node.dag().get(highest, node.id()).is_some();
    let round = if authored_top {
        highest.saturating_add(1)
    } else {
        highest
    }
    .max(cursor);
    node.set_round(round);
    let applied = usize::try_from(anchor.applied)
        .map_err(|_| format!("{} applied transactions do not fit", anchor.applied))?;
    Ok(Adopted {
        state: decoded,
        applied,
        order_len,
        anchor,
        certificate,
        floor,
        vertices: vertices.len(),
        batches: batch_count,
    })
}

async fn node_task(
    index: usize,
    config: &Config,
    committee: chain::Membership,
    chain_id: Vec<u8>,
    start: Start,
    signals: Signals,
) -> Result<NodeResult, String> {
    let Signals {
        mut stop_authoring,
        mut shutdown,
        notify,
    } = signals;
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
    let total = config.validators + config.archives;

    let listener = TcpListener::bind(address(config.port_base, index))
        .await
        .map_err(|error| format!("node {index} cannot listen: {error}"))?;

    let bytes_in = Arc::new(AtomicU64::new(0));
    let bytes_out = Arc::new(AtomicU64::new(0));
    // Both directions use the same depth: the inbound channel is what keeps a
    // reader from acknowledging frames faster than the node loop can judge them,
    // so tuning only one side would leave the other free to absorb the backlog.
    // A joiner leaves the mesh running while it fetches a snapshot, so its queue
    // is enlarged to absorb that window without dropping payloads.
    let queue = if config.sync_from_peers {
        config.queue.max(1).saturating_mul(4)
    } else {
        config.queue.max(1)
    };
    let (frames_tx, mut frames_rx) = mpsc::channel(queue);

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

    // The listener is up first so peers can finish their outbound connects and
    // start their own snapshot servers; only then can this node ask for one. The
    // snapshot exchange uses its own port, not the consensus links.
    let sync_started = Instant::now();
    let synced = if config.sync_from_peers {
        if config.snapshot_port == 0 {
            return Err(format!("node {index} cannot sync without --snapshot-port"));
        }
        let stored_head = match &store {
            Some(store) => store
                .headers()
                .map_err(|error| error.to_string())?
                .last()
                .map_or(0, |record| record.header.height),
            None => 0,
        };
        println!(
            "  node val-{index} reseed: --sync-from-peers requested, stored head {stored_head}"
        );
        if stored_head > 0 {
            println!(
                "  node val-{index} has history to height {stored_head}; --sync-from-peers adopts a peer snapshot above it"
            );
        }
        Some(fetch_snapshot(config.snapshot_port, index, total, &chain_id, stored_head).await?)
    } else {
        None
    };
    let fetch_ms = u64::try_from(sync_started.elapsed().as_millis()).unwrap_or(u64::MAX);

    // Outbound: one link per peer, connected with retries because the nodes start
    // together and a listener may not exist yet. Archives are peers too: what makes
    // an archive an archive is that validators send it everything, not that it
    // participates.
    let mut outbound: Vec<Link> = Vec::with_capacity(total.saturating_sub(1));
    let recent_shares: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
    let recent_vertices: Arc<Mutex<VecDeque<Vec<u8>>>> = Arc::new(Mutex::new(VecDeque::new()));
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
        let up = Arc::new(AtomicBool::new(true));
        outbound.push(Link {
            control: control_tx,
            data: data_tx,
            up: Arc::clone(&up),
        });
        if config.send_buffer > 0 {
            socket2::SockRef::from(&stream)
                .set_send_buffer_size(config.send_buffer)
                .map_err(|error| format!("node {index} cannot size the socket: {error}"))?;
        }
        let bytes_out = Arc::clone(&bytes_out);
        let link_target = target.clone();
        let link_chain = chain_id.clone();
        let link_shutdown = shutdown.clone();
        let link_recent = Arc::clone(&recent_shares);
        let link_vertices = Arc::clone(&recent_vertices);
        let send_buffer = config.send_buffer;
        tokio::spawn(async move {
            write_peer(
                stream,
                control_rx,
                data_rx,
                LinkTask {
                    index,
                    target: link_target,
                    chain_id: link_chain,
                    bytes_out,
                    up,
                    recent_shares: link_recent,
                    recent_vertices: link_vertices,
                    send_buffer,
                    shutdown: link_shutdown,
                },
            )
            .await;
        });
    }

    let mut wanted: HashMap<VertexId, Want> = HashMap::new();
    let mut batches: HashMap<[u8; 32], Batch> = HashMap::new();
    let mut state = if let Some(store) = &store {
        match store.genesis_state().map_err(|error| error.to_string())? {
            Some(bytes) => State::decode(&bytes).map_err(|error| error.to_string())?,
            None => {
                let state = credited_genesis(&accounts)?;
                store
                    .put_genesis_state(&state.encode().map_err(|error| error.to_string())?)
                    .map_err(|error| error.to_string())?;
                state
            }
        }
    } else {
        credited_genesis(&accounts)?
    };

    // The store binds the chain and, once finality exists, the exact genesis
    // header. The header matters because a live node credits balances above the
    // membership's genesis; audit and restart must use that same state root.
    let genesis = Header::genesis(
        chain_id.clone(),
        node.dag().epoch_of(0),
        state.state_root(),
        commit_root(&[]),
    );
    let genesis = if let Some(store) = &store {
        if let Ok(hash) = <[u8; 32]>::try_from(chain_id.as_slice()) {
            store
                .bind_genesis(&hash)
                .map_err(|error| error.to_string())?;
        }
        match store.genesis_header().map_err(|error| error.to_string())? {
            Some(stored) => {
                if stored.id().map_err(|error| error.to_string())?
                    != genesis.id().map_err(|error| error.to_string())?
                {
                    return Err(format!(
                        "node {index}'s store was written under another genesis state"
                    ));
                }
                stored
            }
            None => {
                store
                    .put_genesis_header(&genesis)
                    .map_err(|error| error.to_string())?;
                genesis
            }
        }
    } else {
        genesis
    };

    // The HTTP surface shares the node loop's own state. It is created before
    // the finalizer so the same genesis anchor is the initial head, and before
    // restore so the replay can seed the state snapshots a certified header
    // needs.
    let rpc = if config.rpc_port > 0 {
        if !config.execute {
            return Err(format!("node {index}: an RPC server needs execution"));
        }
        let target = rpc_address(config.rpc_port, index)?;
        let listener = TcpListener::bind(&target)
            .await
            .map_err(|error| format!("node {index} cannot listen for RPC on {target}: {error}"))?;
        let shared = Arc::new(Mutex::new(RpcCore::new(
            index,
            chain_id.clone(),
            &accounts,
            &genesis,
            config.validators,
        )));
        let mut rpc_shutdown = shutdown.clone();
        let app = rpc::router(Arc::clone(&shared));
        tokio::spawn(async move {
            let served = axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = rpc_shutdown.changed().await;
                })
                .await;
            if let Err(error) = served {
                eprintln!("node {index} RPC server stopped: {error}");
            }
        });
        println!("  node val-{index} RPC on http://{target}");
        Some(shared)
    } else {
        None
    };

    // A snapshot link is separate from the consensus mesh: the joiner asks, the
    // server answers from the node loop's own state, and nothing is broadcast.
    let (snapshot_tx, mut snapshot_rx) =
        mpsc::channel::<oneshot::Sender<Result<wire::Snapshot, SnapshotDecline>>>(4);
    if config.snapshot_port > 0 {
        let target = rpc_address(config.snapshot_port, index)?;
        let listener = TcpListener::bind(&target)
            .await
            .map_err(|error| format!("node {index} cannot serve snapshots on {target}: {error}"))?;
        println!("  node val-{index} snapshot server on {target}");
        let mut snapshot_shutdown = shutdown.clone();
        let snapshot_chain = chain_id.clone();
        let snapshot_tx = snapshot_tx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let Ok((mut stream, _)) = accepted else { return };
                        let chain = snapshot_chain.clone();
                        let tx = snapshot_tx.clone();
                        tokio::spawn(async move {
                            let mut buffer = Vec::new();
                            let hello = tokio::time::timeout(
                                HANDSHAKE_TIMEOUT,
                                handshake(&mut stream, &mut buffer, &chain),
                            )
                            .await;
                            if !matches!(hello, Ok(Ok(()))) {
                                return;
                            }
                            let Ok(message) = read_one_message(&mut stream, &mut buffer).await else {
                                return;
                            };
                            if message != Message::SnapshotWant {
                                return;
                            }
                            let (reply_tx, reply_rx) = oneshot::channel();
                            if tx.send(reply_tx).await.is_err() {
                                return;
                            }
                            let reply = tokio::time::timeout(SNAPSHOT_REPLY_TIMEOUT, reply_rx).await;
                            let message = match reply {
                                Ok(Ok(Ok(snapshot))) => Message::Snapshot(Box::new(snapshot)),
                                Ok(Ok(Err(reason))) => {
                                    Message::SnapshotDeclined(reason.to_string())
                                }
                                _ => Message::SnapshotDeclined(String::from(
                                    "the node loop did not build a snapshot in time",
                                )),
                            };
                            if let Ok(frame) = wire::frame(&message, unix_nanos()) {
                                let _ = stream.write_all(&frame).await;
                                let _ = stream.flush().await;
                            }
                        });
                    }
                    _ = snapshot_shutdown.changed() => return,
                }
            }
        });
    }

    // A header commits a state root, so finality only exists on a node that
    // executes. The anchor is the genesis header over the same credited state
    // every node starts from, which is what makes the first certificate cross-
    // checkable across the mesh.
    let mut finalizer = if config.execute {
        Some(
            Finalizer::new(
                SetSchedule::single(committee.set.clone()),
                node.dag().epoch_schedule(),
                chain_id.clone(),
                identity.id.clone(),
                identity.private_key.clone(),
                genesis,
                0,
            )
            .map_err(|error| error.to_string())?,
        )
    } else {
        None
    };

    let mut exec_rejected: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut applied = 0usize;
    let mut applied_cursor = 0usize;

    let mut adopted_anchor: Option<(Header, Certificate)> = None;
    let mut snapshot_report = None;
    if let Some(snapshot) = synced {
        let install_started = Instant::now();
        let adopted = adopt_snapshot(
            snapshot,
            &mut node,
            &mut finalizer,
            &mut batches,
            &chain_id,
            store.as_ref(),
        )?;
        let install_ms = u64::try_from(install_started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let state_root = adopted.state.state_root();
        println!(
            "  node val-{index} adopted snapshot height {} round {}, floor {:?}, {} tail \
             vertices, {} batches, state {}",
            adopted.anchor.height,
            adopted.anchor.round,
            adopted.floor,
            adopted.vertices,
            adopted.batches,
            hex::encode(&state_root[..6])
        );
        println!(
            "  node val-{index} snapshot boundary: committed {}, applied {}, tail {} vertices / {} batches, fetched {fetch_ms} ms, verified+installed {install_ms} ms",
            adopted.order_len, adopted.applied, adopted.vertices, adopted.batches
        );
        snapshot_report = Some(SnapshotReport {
            height: adopted.anchor.height,
            round: adopted.anchor.round,
            floor: adopted.floor,
            order_len: adopted.order_len,
            applied: adopted.applied,
            vertices: adopted.vertices,
            batches: adopted.batches,
            fetch_ms,
            install_ms,
        });
        if let Some(store) = &store {
            // A resync moves a store that already has history forward. The data
            // below the adopted floor can no longer be reached by a restart, so
            // dropping it here is what keeps the directory from growing with a
            // history the node has already left behind.
            let pruned = store
                .prune_to_checkpoint(usize::from(config.shard))
                .map_err(|error| error.to_string())?;
            if pruned.vertices > 0 || pruned.headers > 0 {
                println!(
                    "  node val-{index} pruned {} vertices, {} headers, {} batches below the adopted floor",
                    pruned.vertices, pruned.headers, pruned.batches_dropped
                );
            }
        }
        let anchor = adopted.anchor.clone();
        let certificate = adopted.certificate.clone();
        let applied_count = adopted.applied;
        let order_len = adopted.order_len;
        state = adopted.state;
        applied = applied_count;
        applied_cursor = order_len;
        adopted_anchor = Some((anchor, certificate));
    }

    let restore_started = Instant::now();
    let restored = if adopted_anchor.is_some() {
        None
    } else if let Some(store) = &store {
        restore(
            store,
            &mut node,
            &mut Restorable {
                state: &mut state,
                accounts: &accounts,
                batches: &mut batches,
                rejected: &mut exec_rejected,
                applied: &mut applied,
                applied_cursor: &mut applied_cursor,
                finalizer: &mut finalizer,
                rpc: rpc.as_ref(),
            },
        )?
    } else {
        None
    };
    let restore_ms = u64::try_from(restore_started.elapsed().as_millis()).unwrap_or(u64::MAX);
    if let Some(restored) = &restored {
        let entries_per_second = if restore_ms == 0 {
            0.0
        } else {
            restored.order_len as f64 / (restore_ms as f64 / 1e3)
        };
        println!(
            "  node val-{index} replay: {} committed entries in {restore_ms} ms ({entries_per_second:.0} entries/s), applied {}, certified head {}",
            restored.order_len, restored.applied, restored.head_height
        );
    }
    if snapshot_report.is_some() || restored.is_some() {
        let head = finalizer.as_ref().map_or_else(
            || String::from("none"),
            |finalizer| format!("{}/{}", finalizer.head().height, finalizer.head().round),
        );
        println!(
            "  node val-{index} catch-up: committed {}, applied {}, floor {:?}, cursor {}, round {}, certified head {head}",
            node.dag().order_len(),
            applied,
            node.dag().floor(),
            node.cursor(),
            node.round()
        );
    }

    // A restart rebuilds the skipped rounds from the replay. Batches whose
    // leaders were skipped are still in the store but not in the mempool, so
    // re-admit them before the live loop starts.
    let mut recovered_skips = 0usize;
    let recovered = recover_skipped_batches(
        &node,
        &batches,
        rpc.as_ref(),
        &mut recovered_skips,
        unix_now(),
    );
    if recovered > 0 {
        eprintln!("node {index} re-admitted {recovered} transactions from skipped batches");
    }

    // A transition already installed by a snapshot or a restart is rebroadcast
    // so a peer that missed the control frame can still adopt it. Otherwise this
    // node signs the configured proposal and starts collecting the old-set
    // quorum.
    let mut pending_change = node.dag().set_schedule().certificate().cloned();
    let mut set_change_adopted = pending_change.is_some();
    let mut pending_dirty = pending_change.is_some();
    if pending_change.is_none()
        && let Some((change, next)) = proposed_change(config, node.dag().set(), &chain_id)?
    {
        pending_change = Some(own_change_share(
            &change,
            &next,
            node.dag().set(),
            &identity.id,
            &identity.private_key,
        )?);
        pending_dirty = true;
    }

    // Fences are durable: a restart that lost them would wait again on the same
    // failed leaders. The store keeps one entry per validator, up to the DAG's
    // fault budget.
    let mut fences: BTreeMap<Vec<u8>, FenceCertificate> = match &store {
        Some(store) => store
            .fences()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|certificate| (certificate.fence.validator_id.clone(), certificate))
            .collect(),
        None => BTreeMap::new(),
    };
    let mut fence_adopted: BTreeSet<Vec<u8>> = BTreeSet::new();
    for certificate in fences.values() {
        node.apply_fence(certificate)
            .map_err(|error| format!("stored fence is not authorized: {error}"))?;
        fence_adopted.insert(certificate.fence.validator_id.clone());
    }
    let mut fence_dirty = !fences.is_empty();
    // A share this node signed is a promise, not just a pending message. Load it
    // before the live loop authors anything, and seed the pending map so a
    // restart keeps collecting the same quorum and rebroadcasting the proposal.
    if let Some(store) = &store {
        for certificate in load_local_fence_shares(&mut node, store, &chain_id)? {
            let validator = certificate.fence.validator_id.clone();
            let active = node
                .dag()
                .set_for_round(node.round())
                .validator(&validator)
                .is_some();
            if active && !fence_adopted.contains(&validator) && !fences.contains_key(&validator) {
                fences.insert(validator, certificate);
                fence_dirty = true;
            }
        }
    }

    // Round-skip proofs are durable decision inputs. The restore replay already
    // used them; keep them for rebroadcast and for the local builder's dedupe.
    let mut round_skips: BTreeMap<u64, RoundSkipProof> = match &store {
        Some(store) => store
            .round_skips()
            .map_err(|error| error.to_string())?
            .into_iter()
            .map(|proof| (proof.attestation.skip.round(), proof))
            .collect(),
        None => BTreeMap::new(),
    };
    let mut round_skip_dirty = !round_skips.is_empty();

    // Control payloads this node holds, by digest, with the round they target.
    // A vertex that names a control carries no transactions; the execution loop
    // steps over it without waiting for a batch.
    let mut control_payloads: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for proof in round_skips.values() {
        if let Ok(digest) = ControlPayload::RoundSkip(Box::new(proof.clone())).digest() {
            control_payloads.insert(digest, proof.attestation.skip.round());
        }
    }
    // A locally built certificate waits for a vertex to bind it. It is not a
    // decision before that vertex is held.
    let mut pending_control: Option<([u8; 32], RoundSkipProof)> = None;

    let mut failure_epoch = node.dag().set_for_round(node.round()).epoch;
    let mut failures = (config.failure_rounds > 0).then(|| {
        FailureDetector::new(
            node.dag().set_for_round(node.round()),
            config.failure_rounds,
        )
    });
    if let Some(failures) = failures.as_mut() {
        for vertex in held_vertices(&node) {
            failures.observe(vertex.round, &vertex.author);
        }
    }

    let mut last_certified: Option<(Header, Certificate)> = adopted_anchor;
    if last_certified.is_none()
        && let Some(store) = &store
        && let Some(record) = store
            .headers()
            .map_err(|error| error.to_string())?
            .into_iter()
            .next_back()
    {
        last_certified = Some((record.header, record.certificate));
    }

    let mut state_history: VecDeque<(u64, State)> = VecDeque::new();
    if config.snapshot_port > 0 || config.checkpoint_every > 0 {
        remember_state(
            &mut state_history,
            u64::try_from(applied).unwrap_or(u64::MAX),
            &state,
        );
    }

    if let Some(rpc) = &rpc {
        let mut core = rpc.lock().expect("rpc lock poisoned");
        core.note_state(u64::try_from(applied).unwrap_or(u64::MAX), &state);
        if let Some(finalizer) = &finalizer {
            let head = finalizer.head();
            core.note_order_from(node.dag().prefix(), node.dag().order());
            core.note_certified(head, finalizer.certified_order(head.height));
            core.note_certified_heights(finalizer.certified_ids().len());
        }
        core.set_run(
            node.round(),
            node.dag().order_len(),
            u64::try_from(applied).unwrap_or(u64::MAX),
            outbound.len(),
            finalizer.as_ref().map_or(0, Finalizer::conflicts),
            node.skip_counts(),
        );
    }

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
    let mut cursor: u64 = node.cursor();
    let mut cursor_since = Instant::now();
    let mut reported_stall: Option<u64> = None;
    // Local lambda: committed entries over the last few seconds. A frozen cursor
    // with a healthy rate means this node is behind; a frozen cursor with a zero
    // rate means the chain itself stopped producing commits.
    let mut commit_rate: VecDeque<(Instant, usize)> = VecDeque::new();
    // The interval is measured from the checkpoint or head this run resumed at,
    // not from process start: otherwise a restart with a large interval would
    // fire a checkpoint (and now a prune) as soon as the head passed the
    // interval, however little history had been added since the last one.
    let mut last_checkpoint = resumed_checkpoint_height(
        restored.as_ref(),
        last_certified.as_ref().map(|(header, _)| header.height),
    );
    let mut announced = false;
    let mut first_author_ms: Option<u64> = None;
    let mut last_author_ms: Option<u64> = None;
    let mut profile = Profile::default();
    let mut exec_announced = false;
    let mut last_order = 0usize;
    let mut stable_ticks: u32 = 0;
    let mut ticker = tokio::time::interval(TICK);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut authoring_stopped = *stop_authoring.borrow();
    let mut replayed = false;
    let mut reported_silent: BTreeSet<Vec<u8>> = BTreeSet::new();

    // A single-process mesh shares one clock, so a frame's local timestamp is
    // enough. One process per validator does not: each process has its own
    // `Instant` epoch, and subtracting two epochs would measure nothing. Node
    // mode therefore stamps frames on the Unix clock, which every process on
    // this machine shares.
    let absolute_clock = config.node_index.is_some();
    let now = move || {
        if absolute_clock {
            unix_nanos()
        } else {
            u64::try_from(started.elapsed().as_nanos()).unwrap_or(u64::MAX)
        }
    };

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
                    Message::WantSlot { round, author } => {
                        // The requester knows the round and the author from the
                        // set but not the digest. Answer only with a vertex this
                        // node still holds; a pruned round is already covered by
                        // the requester's snapshot or out of scope.
                        if let Some(vertex) = node.dag().get(round, &author) {
                            if let Ok(bytes) = wire::frame(&Message::Vertex(vertex.clone()), now()) {
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
                                if let Some(failures) = failures.as_mut() {
                                    failures.observe(vertex.round, &vertex.author);
                                }
                                // A vertex at or below the floor is already covered by
                                // the state snapshot; storing it would put back history
                                // the checkpoint just pruned.
                                let above_floor = node
                                    .dag()
                                    .floor()
                                    .is_none_or(|floor| vertex.round > floor);
                                if !known && above_floor && let Some(store) = &store {
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
                    Message::Tx(envelope) => {
                        if let Some(rpc) = &rpc {
                            // The receiver re-checks the envelope exactly like a
                            // client submission; a duplicate or stale frame is
                            // simply ignored.
                            rpc.lock()
                                .expect("rpc lock poisoned")
                                .admit_gossip(&envelope, unix_now());
                        } else {
                            rejected += 1;
                        }
                    }
                    Message::Share(share) => {
                        if let Some(finalizer) = finalizer.as_mut() {
                            let certified = finalizer
                                .receive_share(share)
                                .map_err(|error| error.to_string())?;
                            for certified in certified {
                                if last_certified
                                    .as_ref()
                                    .is_none_or(|(current, _)| current.height <= certified.header.height)
                                {
                                    last_certified = Some((
                                        certified.header.clone(),
                                        certified.certificate.clone(),
                                    ));
                                }
                                if let Some(rpc) = &rpc {
                                    let mut core = rpc.lock().expect("rpc lock poisoned");
                                    core.note_order_from(node.dag().prefix(), node.dag().order());
                                    core.note_certified(
                                        &certified.header,
                                        finalizer.certified_order(certified.header.height),
                                    );
                                }
                                if let Some(store) = &store {
                                    store
                                        .put_header(&certified.header, &certified.certificate)
                                        .map_err(|error| error.to_string())?;
                                }
                            }
                        }
                    }
                    // Snapshots travel on their own link, not on the mesh.
                    Message::SnapshotWant | Message::Snapshot(_) | Message::SnapshotDeclined(_) => {
                        rejected += 1
                    }
                    Message::SetChange(certificate) => {
                        if set_change_adopted {
                            let same = pending_change.as_ref().is_some_and(|current| {
                                current.change == certificate.change
                                    && current.new_set == certificate.new_set
                            });
                            if !same {
                                rejected += 1;
                            }
                        } else {
                            let old = node.dag().set().clone();
                            let ready = {
                                let pending = pending_change
                                    .get_or_insert_with(|| empty_change_certificate(&certificate, &old));
                                match pending.merge(&certificate, &old) {
                                    Ok(true) => pending_dirty = true,
                                    Ok(false) => {}
                                    Err(_) => rejected += 1,
                                }
                                pending
                                    .verify(&old)
                                    .ok()
                                    .map(|_| pending.clone())
                            };
                            if let Some(certificate) = ready {
                                let epoch = node.dag().epoch_of(node.round());
                                if epoch >= certificate.change.activation_epoch {
                                    rejected += 1;
                                    eprintln!(
                                        "node {index} refused a set change for epoch {} while at epoch {epoch}",
                                        certificate.change.activation_epoch
                                    );
                                } else {
                                    if let Some(finalizer) = finalizer.as_mut() {
                                        finalizer.adopt_set_change(&certificate).map_err(|error| {
                                            format!(
                                                "cannot install the set change in the finalizer: {error}"
                                            )
                                        })?;
                                    }
                                    let transition = node
                                        .adopt_set_change(&certificate)
                                        .map_err(|error| format!("cannot install the set change: {error}"))?;
                                    if let Some(store) = &store {
                                        store
                                            .put_set_change(&certificate)
                                            .map_err(|error| error.to_string())?;
                                    }
                                    set_change_adopted = true;
                                    pending_change = Some(certificate);
                                    pending_dirty = true;
                                    println!(
                                        "node val-{index} adopted set change at epoch {}: {} -> {} validators ({})",
                                        transition.new_epoch,
                                        transition.old_size,
                                        transition.new_size,
                                        transition.changes()
                                    );
                                }
                            }
                        }
                    }
                    Message::Fence(certificate) => {
                        let validator = certificate.fence.validator_id.clone();
                        let set = node
                            .dag()
                            .set_for_round(certificate.fence.from_round)
                            .clone();
                        if fence_adopted.contains(&validator) {
                            let same = fences
                                .get(&validator)
                                .is_some_and(|current| current.fence == certificate.fence);
                            if !same {
                                rejected += 1;
                            }
                        } else {
                            let ready = if certificate.verify(&chain_id, &set).is_ok() {
                                // A completed certificate needs no local share, and
                                // taking it even when a different partial is pending
                                // is what stops two surviving views from waiting on
                                // each other forever.
                                Some(*certificate)
                            } else {
                                // A later round is signable by every observer that
                                // could sign an earlier one: a signer must have seen
                                // the validator below the fence round. Converging on
                                // the highest proposal is therefore safe and lets
                                // diverged cursors still combine.
                                if fences.get(&validator).is_some_and(|pending| {
                                    certificate.fence.from_round > pending.fence.from_round
                                }) {
                                    fences.remove(&validator);
                                }
                                let pending = fences
                                    .entry(validator.clone())
                                    .or_insert_with(|| empty_fence_certificate(&certificate, &set));
                                if started.elapsed() >= FENCE_STARTUP_GRACE
                                    && may_sign_fence(&node, failures.as_ref(), &certificate.fence)
                                {
                                    let own = own_fence_share(
                                        &certificate.fence,
                                        &set,
                                        &identity.id,
                                        &identity.private_key,
                                    )?;
                                    node.note_local_fence(&certificate.fence);
                                    if let Some(store) = &store {
                                        store
                                            .put_fence_share(&own)
                                            .map_err(|error| error.to_string())?;
                                    }
                                    if pending
                                        .merge(&own, &chain_id, &set)
                                        .is_ok_and(|changed| changed)
                                    {
                                        fence_dirty = true;
                                    }
                                }
                                match pending.merge(&certificate, &chain_id, &set) {
                                    Ok(true) => fence_dirty = true,
                                    Ok(false) => {}
                                    Err(_) => rejected += 1,
                                }
                                pending
                                    .verify(&chain_id, &set)
                                    .ok()
                                    .map(|_| pending.clone())
                            };
                            if let Some(certificate) = ready {
                                match node.apply_fence(&certificate) {
                                    Ok(()) => {
                                        if let Some(store) = &store {
                                            store
                                                .put_fence(&certificate)
                                                .map_err(|error| error.to_string())?;
                                            // The adopted certificate now carries the
                                            // promise; the partial share is no longer
                                            // needed to rebuild a quorum.
                                            store
                                                .clear_fence_share(&validator)
                                                .map_err(|error| error.to_string())?;
                                        }
                                        let name = hex::encode(
                                            &certificate.fence.validator_id
                                                [..certificate.fence.validator_id.len().min(8)],
                                        );
                                        println!(
                                            "node val-{index} fenced {name} from round {}",
                                            certificate.fence.from_round
                                        );
                                        fence_adopted.insert(validator.clone());
                                        fences.insert(validator, certificate);
                                        fence_dirty = true;
                                    }
                                    Err(error) => {
                                        rejected += 1;
                                        eprintln!(
                                            "node {index} refused a fence: {error}"
                                        );
                                    }
                                }
                            }
                        }
                    }
                    Message::Control(payload) => {
                        let round = payload.round();
                        if !round_skips.contains_key(&round)
                            && let Some(proof) = payload.round_skip()
                            && node.dag().check_round_skip(&chain_id, proof).is_ok()
                        {
                            if let Some(store) = &store
                                && let Err(error) = store.put_round_skip(proof)
                            {
                                // A different proof for this round is already
                                // stored; both imply the same skip, so the first
                                // one is enough.
                                eprintln!(
                                    "node {index} kept the stored round skip for round {round}: \
                                     {error}"
                                );
                            }
                            round_skips.insert(round, proof.clone());
                            round_skip_dirty = true;
                        }
                        match node.add_control(*payload) {
                            Ok(digest) => {
                                control_payloads.insert(digest, round);
                            }
                            Err(error) => {
                                rejected += 1;
                                eprintln!(
                                    "node {index} refused a control payload at round {round}: {error}"
                                );
                            }
                        }
                    }
                    // The legacy control frame carries the same evidence. It is
                    // installed as a pending payload, not applied here: only the
                    // vertex that names its digest makes it a decision.
                    Message::RoundSkip(proof) => {
                        let round = proof.attestation.skip.round();
                        if !round_skips.contains_key(&round)
                            && node
                                .dag()
                                .check_round_skip(&chain_id, proof.as_ref())
                                .is_ok()
                        {
                            if let Some(store) = &store
                                && let Err(error) = store.put_round_skip(&proof)
                            {
                                eprintln!(
                                    "node {index} kept the stored round skip for round {round}: \
                                     {error}"
                                );
                            }
                            round_skips.insert(round, (*proof).clone());
                            round_skip_dirty = true;
                        }
                        match node.add_control(ControlPayload::RoundSkip(proof)) {
                            Ok(digest) => {
                                control_payloads.insert(digest, round);
                            }
                            Err(error) => {
                                rejected += 1;
                                eprintln!(
                                    "node {index} refused a round skip at round {round}: {error}"
                                );
                            }
                        }
                    }
                }
            }
            _ = stop_authoring.changed() => {
                authoring_stopped = *stop_authoring.borrow();
            }
            Some(reply) = snapshot_rx.recv() => {
                let built = finalizer.as_ref().map_or(Err(SnapshotDecline::NoExecution), |finalizer| {
                    build_live_snapshot(
                        &node,
                        finalizer,
                        last_certified.as_ref(),
                        &state_history,
                        &batches,
                    )
                });
                let _ = reply.send(built);
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
                // A restarted node puts its own recent vertices back on the wire
                // once. The missing vote may not be referenced by anyone, so the
                // want sweep has no id to ask for; only the author can supply it.
                if !replayed {
                    replayed = true;
                    for vertex in recent_own_vertices(&node, index, RECENT_VERTICES) {
                        let bytes = wire::frame(&Message::Vertex(vertex), now())
                            .map_err(|error| error.to_string())?;
                        broadcast(&outbound, false, &bytes, &mut dropped);
                    }
                }
                // Gossip is drained every tick and sent on the control plane: one
                // small frame per submitted envelope, never re-gossiped on receipt.
                if let Some(rpc) = &rpc {
                    for envelope in rpc.lock().expect("rpc lock poisoned").take_gossip() {
                        let bytes = wire::frame(&Message::Tx(envelope), now())
                            .map_err(|error| error.to_string())?;
                        broadcast(&outbound, true, &bytes, &mut dropped);
                    }
                }
                // A set-change certificate is control traffic, but it must reach
                // every validator that may cross the boundary. Repeating it also
                // repairs a link that reconnected after the first frame.
                if let Some(certificate) = &pending_change
                    && (pending_dirty || ticks % SET_CHANGE_TICKS == 0)
                {
                    let bytes = wire::frame(
                        &Message::SetChange(Box::new(certificate.clone())),
                        now(),
                    )
                    .map_err(|error| error.to_string())?;
                    broadcast(&outbound, true, &bytes, &mut dropped);
                    pending_dirty = false;
                }
                if fence_dirty || ticks % SET_CHANGE_TICKS == 0 {
                    for certificate in fences.values() {
                        let bytes = wire::frame(
                            &Message::Fence(Box::new(certificate.clone())),
                            now(),
                        )
                        .map_err(|error| error.to_string())?;
                        broadcast(&outbound, true, &bytes, &mut dropped);
                    }
                    fence_dirty = false;
                }
                if round_skip_dirty || ticks % CONTROL_REBROADCAST_TICKS == 0 {
                    for proof in round_skips.values() {
                        let payload = ControlPayload::RoundSkip(Box::new(proof.clone()));
                        let bytes = wire::frame(&Message::Control(Box::new(payload)), now())
                            .map_err(|error| error.to_string())?;
                        broadcast(&outbound, true, &bytes, &mut dropped);
                    }
                    round_skip_dirty = false;
                }
                // The lead cap belongs to the round-skip experiment. Without it a
                // live node authors far past the cursor, which widens the window
                // in which delivery differences change a skip decision. The cap
                // must stay above the failure-detector threshold, or a silent
                // validator is never observed far enough behind to be fenced.
                let lead = AUTHORING_LEAD.max(config.failure_rounds.saturating_add(4));
                let within_lead = config.rpc_port == 0
                    || !config.round_skip
                    || node.round() <= node.cursor().saturating_add(lead);
                if !authoring_stopped
                    && within_lead
                    && (config.rpc_port > 0 || node.round() <= config.rounds)
                {
                    let round = node.round();
                    let slot = usize::try_from(round).unwrap_or(usize::MAX);
                    let mut sign = Duration::ZERO;
                    // A locally built certificate waits for a vertex to bind it.
                    // If another node already bound and applied the same proof,
                    // the wait is over and a normal batch can be authored.
                    if pending_control.as_ref().is_some_and(|(_, proof)| {
                        node.dag()
                            .round_skip(proof.attestation.skip.round())
                            .is_some()
                    }) {
                        pending_control = None;
                    }
                    let control_digest = pending_control.as_ref().map(|(digest, _)| *digest);
                    let payload = if control_digest.is_some() {
                        // The binding vertex orders no transactions. The batch
                        // this round would have carried waits for a later round.
                        None
                    } else if config.rpc_port > 0 {
                        // The mempool is the only source in RPC mode: a real client
                        // signs before submitting, and an empty mempool is an empty
                        // batch rather than a synthetic one.
                        rpc.as_ref().and_then(|rpc| {
                            rpc.lock()
                                .expect("rpc lock poisoned")
                                .take_batch(config.rpc_batch_max)
                        })
                    } else if config.txs == 0 {
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
                    let digest = if let Some(digest) = control_digest {
                        digest
                    } else {
                        match &payload {
                            Some(batch) => batch.digest().map_err(|error| error.to_string())?,
                            None => [0u8; 32],
                        }
                    };
                    let author_start = Instant::now();
                    let author = node.author_with(digest);
                    profile.author += author_start.elapsed();
                    match author {
                        Ok(Some(vertex)) => {
                            if let Some(failures) = failures.as_mut() {
                                failures.observe(vertex.round, &vertex.author);
                            }
                            let authored_at = unix_millis();
                            first_author_ms.get_or_insert(authored_at);
                            last_author_ms = Some(authored_at);
                            if payload.is_some()
                                && let Some(rpc) = &rpc
                            {
                                rpc.lock()
                                    .expect("rpc lock poisoned")
                                    .note_authored(
                                        &digest,
                                        vertex.id().map_err(|error| error.to_string())?,
                                    );
                            }
                            if config.rpc_port > 0 && !announced {
                                announced = true;
                                let _ = notify.ready.send(index).await;
                            }
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
                            // The payload goes out before the vertex that binds
                            // it, so a peer that receives the vertex second already
                            // knows the round must wait for this certificate.
                            if control_digest.is_some()
                                && let Some((_, proof)) = pending_control.take()
                            {
                                let control = ControlPayload::RoundSkip(Box::new(proof));
                                let frame = wire::frame(&Message::Control(Box::new(control)), now())
                                    .map_err(|error| error.to_string())?;
                                broadcast(&outbound, true, &frame, &mut dropped);
                            }
                            let frame_start = Instant::now();
                            let bytes = wire::frame(&Message::Vertex(vertex), now())
                                .map_err(|error| error.to_string())?;
                            profile.frame += frame_start.elapsed();
                            remember_vertex(&recent_vertices, &bytes);
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
                            // next tick instead of signing it again. In RPC mode
                            // it goes back to the mempool, in client order.
                            if let Some(batch) = payload {
                                if let Some(rpc) = &rpc {
                                    rpc.lock()
                                        .expect("rpc lock poisoned")
                                        .return_batch(batch);
                                } else if let Some(queue) = prebuilt.as_mut()
                                    && slot < queue.len()
                                {
                                    queue[slot] = Some(batch);
                                }
                            }
                        }
                        Err(error) => return Err(format!("node {index} cannot author: {error}")),
                    }
                }
                // A commit whose leader history is not fully here yet is a
                // delivery condition, not a failure: the referenced vertex may
                // still be in a peer's queue.
                let commit_start = Instant::now();
                loop {
                    match node.commit_once() {
                        Ok(Step::Advanced {
                            from,
                            cursor: next,
                            commits,
                            anchors,
                            ..
                        }) => {
                            if next > cursor {
                                cursor_since = Instant::now();
                                reported_stall = None;
                                let now = Instant::now();
                                while commit_rate
                                    .front()
                                    .is_some_and(|(at, _)| now.duration_since(*at) > COMMIT_RATE_WINDOW)
                                {
                                    commit_rate.pop_front();
                                }
                                if commit_rate
                                    .back()
                                    .is_none_or(|(at, _)| at.elapsed() >= Duration::from_millis(200))
                                {
                                    commit_rate.push_back((now, node.dag().order_len()));
                                }
                            }
                            cursor = next;
                            if commits > 0
                                && let Some(finalizer) = finalizer.as_mut()
                            {
                                finalizer.record_commit(from, node.dag().order_len());
                            }
                            if anchors > 0 {
                                break;
                            }
                        }
                        Ok(Step::Waiting { cursor: next, .. }) => {
                            cursor = next;
                            break;
                        }
                        Ok(Step::TimedOut { cursor: next, .. }) => {
                            cursor = next;
                            break;
                        }
                        Err(error) if error.kind() == CryptoErrorKind::MissingReference => break,
                        Err(error) => {
                            return Err(format!("node {index} cannot commit: {error}"));
                        }
                    }
                }
                profile.commit += commit_start.elapsed();
                // A skip recorded by this commit loop leaves the leader's batch
                // out of the order. Return it to the mempool before the next
                // round can be authored, so its transactions are not stranded.
                let recovered = recover_skipped_batches(
                    &node,
                    &batches,
                    rpc.as_ref(),
                    &mut recovered_skips,
                    unix_now(),
                );
                if recovered > 0 {
                    eprintln!(
                        "node {index} re-admitted {recovered} transactions from a skipped batch"
                    );
                }
                // A frozen cursor is the one condition an operator cannot see
                // from `/status`: rounds and anchors keep advancing while committed
                // entries stop. Anchors ahead reset the pacemaker's stall counter,
                // so this measures the cursor's own age and prints once per round.
                if cursor_since.elapsed() >= STALL_REPORT_AFTER
                    && reported_stall != Some(cursor)
                {
                    reported_stall = Some(cursor);
                    let observed = node.dag().highest_round().unwrap_or(cursor);
                    let missing = node.dag().missing_history(cursor);
                    let detail = missing.map_or_else(
                        || "none".to_string(),
                        |id| {
                            format!(
                                "{} at round {} by {}",
                                hex::encode(&id.digest[..6]),
                                id.round,
                                hex::encode(&id.author[..6])
                            )
                        },
                    );
                    let voters = node.dag().held_voters(cursor).unwrap_or(0);
                    let quorum = node.dag().set().quorum_size();
                    let can_anchor = node.dag().can_still_anchor(cursor).unwrap_or(true);
                    let skip_held = node.dag().round_skip(cursor).is_some();
                    let skip_pending = node.dag().has_pending_control(cursor);
                    let leader_held = node.dag().leader(cursor).is_some();
                    let missing_count = node.dag().missing_references().len();
                    let rate = match (commit_rate.front(), commit_rate.back()) {
                        (Some((first_at, first_len)), Some((last_at, last_len)))
                            if last_at > first_at =>
                        {
                            (*last_len as f64 - *first_len as f64)
                                / last_at.duration_since(*first_at).as_secs_f64()
                        }
                        _ => 0.0,
                    };
                    eprintln!(
                        "node {index} commit stalled at round {cursor} (observed {observed}), missing {detail} (count {missing_count}), rate {rate:.1} committed/s, votes {voters} of quorum {quorum}, can-anchor {can_anchor}, round-skip held {skip_held}, pending {skip_pending}, leader-held {leader_held}"
                    );
                }
                if config.execute {
                    // Apply in commit order, and stop at the first vertex whose
                    // batch has not arrived: applying past it would put a later
                    // transaction before an earlier one.
                    let base = node.dag().prefix().len();
                    let order = node.dag().order();
                    while applied_cursor < node.dag().order_len() {
                        let Some(order_index) = applied_cursor.checked_sub(base) else {
                            break;
                        };
                        let Some(id) = order.get(order_index) else {
                            break;
                        };
                        let Some(vertex) = node.dag().get(id.round, &id.author) else {
                            break;
                        };
                        // A vertex can carry no payload (an empty mempool still has
                        // to author for the DAG to advance), or a control payload
                        // such as a round-skip certificate. Neither changes account
                        // state, so the cursor moves without touching it.
                        if vertex.payload_hash == [0u8; 32]
                            || control_payloads.contains_key(&vertex.payload_hash)
                        {
                            applied_cursor += 1;
                            // A pending header can name this exact prefix, so the
                            // state root has to be captured here rather than only
                            // once at the end of the tick: an all-empty stretch
                            // would otherwise step over its order length.
                            if let Some(finalizer) = finalizer.as_mut() {
                                finalizer.mark_applied(
                                    applied_cursor,
                                    state.state_root(),
                                    u64::try_from(applied).unwrap_or(u64::MAX),
                                );
                            }
                            if let Some(rpc) = &rpc {
                                rpc.lock().expect("rpc lock poisoned").note_state(
                                    u64::try_from(applied).unwrap_or(u64::MAX),
                                    &state,
                                );
                            }
                            continue;
                        }
                        let Some(batch) = batches.get(&vertex.payload_hash) else {
                            break;
                        };
                        let mut timing = chain::ApplyTiming::default();
                        let executed = if let Some(rpc) = &rpc {
                            let mut report = Vec::new();
                            let count = chain::apply_batch_timed_report(
                                &mut state,
                                &accounts,
                                batch,
                                &mut exec_rejected,
                                &mut timing,
                                config.verify_threads,
                                Some(&mut report),
                            );
                            rpc.lock().expect("rpc lock poisoned").note_applied(
                                &vertex.payload_hash,
                                id,
                                applied_cursor,
                                batch,
                                &report,
                            );
                            count
                        } else {
                            chain::apply_batch_timed(
                                &mut state,
                                &accounts,
                                batch,
                                &mut exec_rejected,
                                &mut timing,
                                config.verify_threads,
                            )
                        };
                        applied += executed;
                        profile.verify += timing.verify;
                        profile.state += timing.state;
                        applied_cursor += 1;
                        if let Some(rpc) = &rpc {
                            rpc.lock().expect("rpc lock poisoned").note_state(
                                u64::try_from(applied).unwrap_or(u64::MAX),
                                &state,
                            );
                        }
                        if config.snapshot_port > 0 || config.checkpoint_every > 0 {
                            remember_state(
                                &mut state_history,
                                u64::try_from(applied).unwrap_or(u64::MAX),
                                &state,
                            );
                        }
                        if let Some(finalizer) = finalizer.as_mut() {
                            finalizer.mark_applied(
                                applied_cursor,
                                state.state_root(),
                                u64::try_from(applied).unwrap_or(u64::MAX),
                            );
                        }
                    }
                }
                if let Some(finalizer) = finalizer.as_mut() {
                    finalizer.mark_applied(
                        applied_cursor,
                        state.state_root(),
                        u64::try_from(applied).unwrap_or(u64::MAX),
                    );
                    let build = finalizer
                        .build_ready_with_prefix(
                            node.dag().prefix(),
                            node.dag().order(),
                            now(),
                        )
                        .map_err(|error| error.to_string())?;
                    for share in build.shares {
                        let bytes = wire::frame(&Message::Share(share), now())
                            .map_err(|error| error.to_string())?;
                        remember_share(&recent_shares, &bytes);
                        broadcast(&outbound, false, &bytes, &mut dropped);
                    }
                    for certified in build.certified {
                        if last_certified
                            .as_ref()
                            .is_none_or(|(current, _)| current.height <= certified.header.height)
                        {
                            last_certified = Some((
                                certified.header.clone(),
                                certified.certificate.clone(),
                            ));
                        }
                        if let Some(rpc) = &rpc {
                            let mut core = rpc.lock().expect("rpc lock poisoned");
                            core.note_order_from(node.dag().prefix(), node.dag().order());
                            core.note_certified(
                                &certified.header,
                                finalizer.certified_order(certified.header.height),
                            );
                        }
                        if let Some(store) = &store {
                            store
                                .put_header(&certified.header, &certified.certificate)
                                .map_err(|error| error.to_string())?;
                        }
                    }
                }
                // The active set can change at a set-change boundary. Rebuild the
                // detector's author list from the schedule rather than from the
                // base set, so a removed validator is dropped and a new one is
                // tracked from the epoch it becomes active.
                if let Some(failures) = failures.as_mut() {
                    let active = node.dag().set_for_round(node.round());
                    if active.epoch != failure_epoch {
                        failures.update_set(active);
                        failure_epoch = active.epoch;
                    }
                }
                // The failure detector is a report, not an input to the commit
                // rule. It names validators this node has not seen for longer than
                // the configured threshold; the line is printed once per silence.
                let mut silent = Vec::new();
                if started.elapsed() >= FENCE_STARTUP_GRACE
                    && let Some(failures) = failures.as_ref()
                {
                    silent = failures.silent();
                    for (validator, last_round) in &silent {
                        if reported_silent.insert(validator.clone()) {
                            let name = hex::encode(&validator[..validator.len().min(8)]);
                            let detail = if *last_round == 0 {
                                "never seen".to_string()
                            } else {
                                format!("last seen at round {last_round}")
                            };
                            eprintln!(
                                "node {index} failure detector: {name} silent ({detail}, highest round {})",
                                failures.highest_round()
                            );
                        }
                    }
                    let current: BTreeSet<Vec<u8>> =
                        silent.iter().map(|(validator, _)| validator.clone()).collect();
                    reported_silent.retain(|validator| current.contains(validator));
                }
                // A pending fence for a validator that is visible again is stale:
                // keeping it would block a different proposal and broadcast a
                // failure claim the local evidence no longer supports. Adopted
                // certificates stay; the quorum already declared the failure.
                let stale: Vec<Vec<u8>> = fences
                    .iter()
                    .filter(|(validator, _)| !fence_adopted.contains(*validator))
                    .filter(|(validator, _)| silent.iter().all(|(seen, _)| seen != *validator))
                    .map(|(validator, _)| validator.clone())
                    .collect();
                for validator in stale {
                    fences.remove(&validator);
                    node.clear_local_fence(&validator);
                    if let Some(store) = &store {
                        store
                            .clear_fence_share(&validator)
                            .map_err(|error| error.to_string())?;
                    }
                    fence_dirty = true;
                }
                // A silent leader or missing voter is fenced at the validator's
                // last observed round plus one, so survivors with different
                // cursors still name the same round; the quorum is what authorizes
                // the skip, not this local report.
                if config.fence_silent {
                    let candidates: Vec<(Vec<u8>, u64)> = silent
                        .iter()
                        .filter(|(validator, _)| !fences.contains_key(validator))
                        .cloned()
                        .collect();
                    if let Some((validator, from_round)) = fence_candidate(&node, &candidates) {
                        let set = node.dag().set_for_round(from_round).clone();
                        if fences.len() < set.max_faulty() && set.validator(&validator).is_some() {
                            let fence = Fence::new(chain_id.clone(), from_round, validator.clone());
                            match own_fence_share(
                                &fence,
                                &set,
                                &identity.id,
                                &identity.private_key,
                            ) {
                                Ok(certificate) => {
                                    eprintln!(
                                        "node {index} proposes a fence for round {from_round}"
                                    );
                                    node.note_local_fence(&fence);
                                    if let Some(store) = &store {
                                        store
                                            .put_fence_share(&certificate)
                                            .map_err(|error| error.to_string())?;
                                    }
                                    fences.insert(validator, certificate);
                                    fence_dirty = true;
                                }
                                Err(error) => {
                                    eprintln!("node {index} cannot sign a fence: {error}");
                                }
                            }
                        }
                    }
                }
                // The proof is built from what this node holds: held votes and
                // non-votes, fences covering absent voters, and the rest as
                // missing. It is verified before publication, and only its binding
                // vertex makes it a decision.
                if config.round_skip
                    && pending_control.is_none()
                    && !round_skips.contains_key(&node.cursor())
                    && node
                        .dag()
                        .set_for_round(node.round())
                        .validator(node.id())
                        .is_some()
                    && !node.dag().is_fenced(node.id(), node.round())
                    && let Some(proof) = round_skip_candidate(&node, &chain_id)
                {
                    let round = proof.attestation.skip.round();
                    match node.dag().check_round_skip(&chain_id, &proof) {
                        Ok(check) => {
                            let payload = ControlPayload::RoundSkip(Box::new(proof.clone()));
                            match node.add_control(payload) {
                                Ok(digest) => {
                                    if let Some(store) = &store {
                                        store
                                            .put_round_skip(&proof)
                                            .map_err(|error| error.to_string())?;
                                    }
                                    eprintln!(
                                        "node {index} proved round {round} cannot reach a quorum \
                                         ({} votes, {} non-votes, {} missing)",
                                        check.votes, check.non_votes, check.missing
                                    );
                                    control_payloads.insert(digest, round);
                                    pending_control = Some((digest, proof.clone()));
                                    round_skips.insert(round, proof);
                                    round_skip_dirty = true;
                                }
                                Err(error) => {
                                    eprintln!(
                                        "node {index} cannot queue a round-skip certificate \
                                         at round {round}: {error}"
                                    );
                                }
                            }
                        }
                        Err(error) => {
                            eprintln!(
                                "node {index} built a round skip that did not verify: {error}"
                            );
                        }
                    }
                }
                if let Some(rpc) = &rpc {
                    let mut core = rpc.lock().expect("rpc lock poisoned");
                    core.note_order_from(node.dag().prefix(), node.dag().order());
                    core.note_failures(&silent);
                    core.set_run(
                        node.round(),
                        node.dag().order_len(),
                        u64::try_from(applied).unwrap_or(u64::MAX),
                        outbound.len(),
                        finalizer.as_ref().map_or(0, Finalizer::conflicts),
                        node.skip_counts(),
                    );
                    core.note_certified_heights(
                        finalizer
                            .as_ref()
                            .map_or(0, |finalizer| finalizer.certified_ids().len()),
                    );
                }
                if !announced && config.rpc_port == 0 && node.round() > config.rounds {
                    announced = true;
                    let _ = notify.ready.send(index).await;
                }
                // Applying costs real signature verification, so it lags the
                // commit cursor. Report caught-up only once the commit cursor has
                // itself stopped moving for a while: early in the run both cursors
                // are small and "caught up" would be trivially true.
                let order_len = node.dag().order_len();
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
                    // A vote broadcast while this node was down is invisible to
                    // both scans above when no later vertex names it: the DAG has
                    // no edge to ask about. Once the cursor has been still for a
                    // moment, ask for every missing voter slot of its voting round
                    // by round and author. A peer that still holds one answers
                    // with a vertex, which is the same repair a named want gets.
                    if cursor_since.elapsed() >= WANT_SLOT_AFTER {
                        // The leader slot itself. A restart can resume below a
                        // vertex a later anchor references, and the digest want
                        // for it may already have been abandoned while the links
                        // were still reconnecting.
                        if node.dag().leader(cursor).is_none()
                            && let Some(author) = node.dag().leader_author(cursor)
                            && !node.dag().is_fenced(author, cursor)
                        {
                            let request = Message::WantSlot {
                                round: cursor,
                                author: author.to_vec(),
                            };
                            if let Ok(bytes) = wire::frame(&request, now()) {
                                broadcast(&outbound, true, &bytes, &mut dropped);
                            }
                        }
                        if node.dag().leader(cursor).is_some() {
                            let voting = cursor.saturating_add(1);
                            let voters = node.dag().set_for_round(voting).clone();
                            for record in &voters.validators {
                                if record.validator_id.as_slice() == node.id()
                                    || node.dag().get(voting, &record.validator_id).is_some()
                                    || node.dag().is_fenced(&record.validator_id, voting)
                                {
                                    continue;
                                }
                                let request = Message::WantSlot {
                                    round: voting,
                                    author: record.validator_id.clone(),
                                };
                                if let Ok(bytes) = wire::frame(&request, now()) {
                                    broadcast(&outbound, true, &bytes, &mut dropped);
                                }
                            }
                        }
                    }
                }

                // A checkpoint is a fresh anchor for the next restart. Without
                // one, replay starts at the last snapshot the node adopted and
                // grows with uptime; with one, the tail is at most this interval.
                // A head whose state is no longer retained, or whose order length
                // the finalizer does not know, simply waits for the next one.
                if config.checkpoint_every > 0
                    && ticks % CHECKPOINT_TICKS == 0
                    && let Some(store) = &store
                    && let Some(finalizer) = finalizer.as_ref()
                    && last_certified.as_ref().is_some_and(|(header, _)| {
                        header.height
                            >= last_checkpoint.saturating_add(config.checkpoint_every)
                    })
                    && let Ok(snapshot) = build_live_snapshot(
                        &node,
                        finalizer,
                        last_certified.as_ref(),
                        &state_history,
                        &batches,
                    )
                    && let Some(floor) = snapshot.floor
                {
                    let height = snapshot.anchor.height;
                    store
                        .put_live_snapshot(&store::LiveSnapshot {
                            round: snapshot.anchor.round,
                            floor: Some(floor),
                            cursor: snapshot.cursor,
                            applied: snapshot.anchor.applied,
                            state: snapshot.state,
                            order: snapshot.order,
                            order_len: snapshot.order_len,
                            prefix: snapshot.prefix,
                            header: snapshot.anchor,
                            certificate: snapshot.certificate,
                            transition: snapshot.transition,
                            fences: snapshot.fences,
                        })
                        .map_err(|error| error.to_string())?;
                    // The checkpoint is also the licence to prune: its floor is
                    // the lowest round still reachable by a restart, and its
                    // anchor header is the oldest one an audit still walks.
                    // The running DAG takes the same floor: a late vertex at or
                    // below it must be dropped rather than written back into the
                    // store the checkpoint just pruned.
                    node.set_floor(floor);
                    let pruned = store
                        .prune_to_checkpoint(usize::from(config.shard))
                        .map_err(|error| error.to_string())?;
                    last_checkpoint = height;
                    eprintln!(
                        "node {index} checkpoint at height {height} (pruned {} vertices, {} headers, {} batches, {} bytes)",
                        pruned.vertices, pruned.headers, pruned.batches_dropped, pruned.bytes_freed
                    );
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
        first_author_ms,
        last_author_ms,
        complete: config.rpc_port > 0 || node.round() > config.rounds,
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
        certified_ids: finalizer
            .as_ref()
            .map_or_else(BTreeMap::new, |finalizer| finalizer.certified_ids().clone()),
        head_height: finalizer
            .as_ref()
            .map_or(0, |finalizer| finalizer.head().height),
        head_round: finalizer
            .as_ref()
            .map_or(0, |finalizer| finalizer.head().round),
        conflicts: finalizer
            .as_ref()
            .map_or(0, |finalizer| finalizer.conflicts()),
        restored,
        snapshot: snapshot_report,
        disk_bytes: store
            .as_ref()
            .map_or(0, |store| directory_bytes(store.path())),
        rejected,
        committed: node.dag().order_len(),
        bytes_in: bytes_in.load(Ordering::Relaxed),
        bytes_out: bytes_out.load(Ordering::Relaxed),
        latencies,
        commit_root: node.dag().commit_root(),
        order: node.dag().order().to_vec(),
        prefix: node.dag().prefix().clone(),
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
                    // A slot want is the same repair as a named want.
                    Message::WantSlot { .. } => {}
                    // An archive does not certify; the shares it receives are for
                    // validators to build certificates from.
                    Message::Share(_) => {}
                    // Snapshots need execution state, which an archive does not keep.
                    Message::SnapshotWant | Message::Snapshot(_) | Message::SnapshotDeclined(_) => {}
                    // An archive has no RPC state, so a gossiped envelope has no
                    // record to attach to. It is ignored rather than stored.
                    Message::Tx(_) => {}
                    // An archive has no schedule to activate. The certificate is
                    // stored with the boundary when activation lands.
                    Message::SetChange(_) => {}
                    // An archive does not decide, so a fence has no local effect.
                    Message::Fence(_) => {}
                    // A round skip is a decision input; an archive keeps no DAG.
                    Message::RoundSkip(_) => {}
                    // Control payloads share the round-skip fate here.
                    Message::Control(_) => {}
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
        first_author_ms: None,
        last_author_ms: None,
        complete: false,
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
        certified_ids: BTreeMap::new(),
        head_height: 0,
        head_round: 0,
        conflicts: 0,
        restored: None,
        snapshot: None,
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
        prefix: CommitFrontier::empty(),
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

fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn unix_nanos() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

/// Runs one validator in this process and prints a machine-readable result line.
///
/// The committee is still `config.validators` wide, but this process owns exactly
/// one member. Authoring stops after `config.rounds`; the process then keeps serving
/// peers until `config.timeout` expires, so no listener closes while a slower peer
/// is still committing.
fn run_one_node(
    runtime: tokio::runtime::Runtime,
    config: Config,
    index: usize,
    committee: chain::Membership,
    chain_id: Vec<u8>,
    mut prebuilt: Vec<Vec<Option<Batch>>>,
) -> Result<(), Box<dyn Error>> {
    let validators = config.validators;
    let rounds = config.rounds;
    let txs = config.txs;
    let timeout = config.timeout;
    let execute = config.execute;
    let show_profile = config.profile;
    let rpc_mode = config.rpc_port > 0;
    let drain = config.drain;
    let prebuilt = prebuilt.pop();
    let port = u32::from(config.port_base) + u32::try_from(index).unwrap_or(0);
    let lifetime = millis(u64::try_from(timeout.as_nanos()).unwrap_or(u64::MAX));

    println!("== Live node {index} of {validators} (one process per validator) ==");
    println!(
        "  listening on 127.0.0.1:{port}, {} rounds each, lifetime {lifetime}",
        rounds
    );

    let (result, authoring): (NodeResult, Option<Duration>) = runtime.block_on(async move {
        let started = Instant::now();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (ready_tx, mut ready_rx) = mpsc::channel(1);
        let (executed_tx, mut executed_rx) = mpsc::channel(1);
        let task = tokio::spawn(async move {
            node_task(
                index,
                &config,
                committee,
                chain_id,
                Start { started, prebuilt },
                Signals {
                    stop_authoring: stop_rx,
                    shutdown: shutdown_rx,
                    notify: Notify {
                        ready: ready_tx,
                        executed: executed_tx,
                    },
                },
            )
            .await
        });

        let mut authoring = None;
        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        tokio::select! {
            _ = ready_rx.recv() => {
                authoring = Some(started.elapsed());
            }
            _ = &mut deadline => {}
        }
        if execute {
            tokio::select! {
                _ = executed_rx.recv() => {}
                _ = &mut deadline => {}
            }
        }
        // Stay on the wire until the shared lifetime ends. An early finisher that
        // closed its listener would strand the peers still authoring.
        (&mut deadline).await;
        if rpc_mode {
            // A continuous run has no natural last round. Stop authoring first,
            // then keep the mesh up for the drain so the last rounds still reach
            // peers and commit instead of being cut off mid-flight.
            let _ = stop_tx.send(true);
            tokio::time::sleep(drain).await;
        }
        let _ = shutdown_tx.send(true);
        let result = match task.await {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => return Err(error.into()),
            Err(error) => return Err(format!("node {index} failed: {error}").into()),
        };
        Ok::<_, Box<dyn Error>>((result, authoring))
    })?;

    println!();
    println!(
        "  node val-{index}: authored {}, committed {}, applied {} tx, rejected {}",
        result.authored, result.committed, result.applied, result.exec_rejected
    );

    println!(
        "  finality          {} certified heights, head {}/{}, conflicts {}",
        result.certified_ids.len(),
        result.head_height,
        result.head_round,
        result.conflicts
    );
    if let Some(restored) = &result.restored {
        let checkpoint = restored
            .checkpoint
            .map_or_else(String::new, |height| format!(" (checkpoint {height})"));
        println!(
            "  restored          {} tx applied, order {}, certified head {}, state root {}{checkpoint}",
            restored.applied,
            restored.order_len,
            restored.head_height,
            hex::encode(&restored.state_root[..6])
        );
    }
    if let Some(snapshot) = &result.snapshot {
        println!(
            "  snapshot join     anchor {}/{} floor {:?}, committed {}, applied {}, tail {} vertices / {} batches, fetched {} ms, installed {} ms",
            snapshot.height,
            snapshot.round,
            snapshot.floor,
            snapshot.order_len,
            snapshot.applied,
            snapshot.vertices,
            snapshot.batches,
            snapshot.fetch_ms,
            snapshot.install_ms
        );
    }
    if let Some(authoring) = authoring {
        println!(
            "  finished          authoring after {} (including startup)",
            millis(u64::try_from(authoring.as_nanos()).unwrap_or(u64::MAX))
        );
    }
    match (result.first_author_ms, result.last_author_ms) {
        (Some(first), Some(last)) => {
            let span = last.saturating_sub(first);
            let seconds = span as f64 / 1e3;
            let rounds_per_second = if seconds > 0.0 {
                result.authored as f64 / seconds
            } else {
                0.0
            };
            println!(
                "  authoring window  {span} ms for {} authored rounds ({rounds_per_second:.1} rounds/s), \
                 first vertex {first} ms, last {last} ms (unix)",
                result.authored
            );
        }
        _ => println!("  authoring window  no vertex was authored"),
    }
    let mut latencies = result.latencies.clone();
    latencies.sort_unstable();
    println!(
        "  delivery latency  p50 {}  p90 {}  p99 {}  max {}  ({} frames received here)",
        millis(percentile(&latencies, 50)),
        millis(percentile(&latencies, 90)),
        millis(percentile(&latencies, 99)),
        millis(percentile(&latencies, 100)),
        latencies.len()
    );
    if result.disk_bytes > 0 {
        let per_tx = if result.transactions == 0 {
            0.0
        } else {
            result.disk_bytes as f64 / result.transactions as f64
        };
        println!(
            "  storage           {} on disk for this validator, {per_tx:.0} B per transaction held",
            human(result.disk_bytes)
        );
    }
    if show_profile {
        let total = result.profile.sign
            + result.profile.author
            + result.profile.commit
            + result.profile.verify
            + result.profile.state
            + result.profile.frame
            + result.profile.store;
        let ms = |duration: Duration| duration.as_secs_f64() * 1e3;
        let pct = |duration: Duration| {
            if total.is_zero() {
                0.0
            } else {
                duration.as_secs_f64() / total.as_secs_f64() * 100.0
            }
        };
        println!();
        println!("  profile           this validator, share of named stages");
        for (name, duration) in [
            ("sign batch", result.profile.sign),
            ("author vertex", result.profile.author),
            ("commit tick", result.profile.commit),
            ("verify tx", result.profile.verify),
            ("apply state", result.profile.state),
            ("frame payload", result.profile.frame),
            ("store write", result.profile.store),
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
    let state_root = match &result.state_root {
        Some(root) => hex::encode(root),
        None => String::from("-"),
    };
    println!(
        "  result node={index} validators={validators} rounds={rounds} txs={txs} \
         complete={} authored={} committed={} applied_tx={} rejected={} missing_payloads={} \
         first_author_ms={} last_author_ms={} commit_root={} state_root={state_root} \
         disk_bytes={}",
        u8::from(result.complete),
        result.authored,
        result.committed,
        result.applied,
        result.exec_rejected,
        result.missing_payloads,
        result
            .first_author_ms
            .map_or_else(|| String::from("-"), |value| value.to_string()),
        result
            .last_author_ms
            .map_or_else(|| String::from("-"), |value| value.to_string()),
        hex::encode(result.commit_root),
        result.disk_bytes,
    );

    if !result.complete {
        return Err(format!("node {index} did not finish authoring within {lifetime}").into());
    }
    if result.missing_payloads > 0 {
        return Err(format!(
            "node {index} names {} batches it does not hold",
            result.missing_payloads
        )
        .into());
    }
    if execute && txs > 0 && result.applied < result.committed {
        return Err(format!(
            "node {index} applied {} of {} committed batches before the lifetime ended",
            result.applied, result.committed
        )
        .into());
    }
    Ok(())
}

pub fn run(config: Config) -> Result<(), Box<dyn Error>> {
    if config.validators < 2 {
        return Err("a live run needs at least two nodes".into());
    }
    let total = config.validators + config.archives;
    if total > 64 {
        return Err("at most 64 nodes: this is a loopback mesh, not a network".into());
    }
    if let Some(index) = config.node_index {
        if index >= config.validators {
            return Err(format!(
                "--node-index {index} is outside 0..{} validators",
                config.validators
            )
            .into());
        }
        if config.archives > 0 {
            return Err("--node-index runs one validator per process; --archives must be 0".into());
        }
    }
    if config.rpc_port > 0 {
        if !config.execute {
            return Err(
                "--rpc-port needs --execute: account proofs and finality read state".into(),
            );
        }
        if config.txs > 0 {
            return Err("--rpc-port replaces the demo data plane; leave --txs at 0".into());
        }
        if config.pre_sign {
            return Err(
                "--rpc-port takes batches from the mempool; --pre-sign does not apply".into(),
            );
        }
        if config.rpc_batch_max == 0 {
            return Err("--rpc-batch-max must be at least 1".into());
        }
        // The P2P and HTTP ranges must not overlap, or the second bind fails with
        // an address-in-use that looks like a configuration bug at runtime.
        let p2p_first = u32::from(config.port_base);
        let p2p_last = p2p_first + u32::try_from(total - 1).unwrap_or(0);
        let rpc_first = u32::from(config.rpc_port);
        let rpc_last = rpc_first + u32::try_from(config.validators - 1).unwrap_or(0);
        if rpc_last > u32::from(u16::MAX) {
            return Err(format!(
                "--rpc-port {} plus {} validators exceeds the u16 port range",
                config.rpc_port, config.validators
            )
            .into());
        }
        if rpc_first <= p2p_last && p2p_first <= rpc_last {
            return Err(format!(
                "the RPC range {rpc_first}..={rpc_last} overlaps the peer range {p2p_first}..={p2p_last}"
            )
            .into());
        }
    }
    if config.sync_from_peers {
        if !config.execute {
            return Err("--sync-from-peers needs --execute: the snapshot carries state".into());
        }
        if config.snapshot_port == 0 {
            return Err("--sync-from-peers needs --snapshot-port".into());
        }
        if config.store.as_os_str().is_empty() {
            return Err("--sync-from-peers needs --store: the adopted history is persisted".into());
        }
    }
    if config.checkpoint_every > 0 {
        if !config.execute {
            return Err("--checkpoint-every needs --execute: the snapshot carries state".into());
        }
        if config.store.as_os_str().is_empty() {
            return Err("--checkpoint-every needs --store: the checkpoint is written there".into());
        }
    }
    if config.snapshot_port > 0 {
        let first = u32::from(config.snapshot_port);
        let last = first + u32::try_from(total - 1).unwrap_or(0);
        if last > u32::from(u16::MAX) {
            return Err(format!(
                "--snapshot-port {} plus {total} nodes exceeds the u16 port range",
                config.snapshot_port
            )
            .into());
        }
        let p2p_first = u32::from(config.port_base);
        let p2p_last = p2p_first + u32::try_from(total - 1).unwrap_or(0);
        if first <= p2p_last && p2p_first <= last {
            return Err(format!(
                "the snapshot range {first}..={last} overlaps the peer range {p2p_first}..={p2p_last}"
            )
            .into());
        }
        if config.rpc_port > 0 {
            let rpc_first = u32::from(config.rpc_port);
            let rpc_last = rpc_first + u32::try_from(config.validators - 1).unwrap_or(0);
            if first <= rpc_last && rpc_first <= last {
                return Err(format!(
                    "the snapshot range {first}..={last} overlaps the RPC range {rpc_first}..={rpc_last}"
                )
                .into());
            }
        }
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
        let indices: Vec<usize> = match config.node_index {
            Some(index) => vec![index],
            None => (0..config.validators).collect(),
        };
        let mut all = Vec::with_capacity(indices.len());
        for index in indices {
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

    if let Some(index) = config.node_index {
        return run_one_node(runtime, config, index, committee, chain_id, prebuilt);
    }

    let results = runtime.block_on(async {
        let started = Instant::now();
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let (stop_tx, stop_rx) = watch::channel(false);
        let (ready_tx, mut ready_rx) = mpsc::channel(config.validators);
        let (executed_tx, mut executed_rx) = mpsc::channel(config.validators);

        let mut tasks = Vec::with_capacity(total);
        for index in 0..config.validators {
            let shutdown_rx = shutdown_rx.clone();
            let stop_rx = stop_rx.clone();
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
                    Signals {
                        stop_authoring: stop_rx,
                        shutdown: shutdown_rx,
                        notify: Notify {
                            ready: ready_tx,
                            executed: executed_tx,
                        },
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
        if config.rpc_port > 0 {
            // A continuous run lasts for the configured lifetime, not until a
            // quiet window: the client decides when it is done. Stop authoring
            // first, then drain so the last rounds still commit.
            (&mut deadline).await;
            let _ = stop_tx.send(true);
            tokio::time::sleep(config.drain).await;
        } else {
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
        }
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
    // The same first-vertex-to-last-vertex window the one-process-per-validator
    // report uses, so the two modes can be compared without one charging the
    // last round's commit and apply to the other's numerator.
    let first_author = results
        .iter()
        .filter(|result| result.signs)
        .filter_map(|result| result.first_author_ms)
        .min();
    let last_author = results
        .iter()
        .filter(|result| result.signs)
        .filter_map(|result| result.last_author_ms)
        .max();
    if let (Some(first), Some(last)) = (first_author, last_author) {
        let span = last.saturating_sub(first);
        let authored_txs: u64 = results
            .iter()
            .filter(|result| result.signs)
            .map(|result| result.authored as u64 * config.txs)
            .sum();
        if span > 0 && authored_txs > 0 {
            let tps = authored_txs as f64 * 1e3 / span as f64;
            println!(
                "  authoring window: {span} ms for {authored_txs} authored transactions \
                 ({tps:.0} tx/s, first vertex to last, all nodes)"
            );
        }
    }
    println!();
    println!(
        "  {}  {}  {}  {}  {}  {}  {}  {}  {}  {}  {}",
        left("node", 7),
        pad("authored", 9),
        pad("received", 9),
        pad("dropped", 8),
        pad("repaired", 9),
        pad("rejected", 9),
        pad("committed", 10),
        pad("certified", 10),
        pad("head", 10),
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
    // A node may commit entries beyond the last certified header while another
    // has not received them yet, so the local orders can differ in length at the
    // end of a wall-clock run. Compare the root over the common committed prefix.
    // A snapshot-restored node keeps its prefix compact, so only entries above
    // its own prefix can be recomputed: the common index must clear the longest
    // prefix among the signing nodes.
    let signing: Vec<&NodeResult> = results.iter().filter(|result| result.signs).collect();
    let mut lengths: Vec<usize> = signing.iter().map(|result| result.committed).collect();
    lengths.sort_unstable();
    let shortest = lengths.first().copied().unwrap_or(0);
    let longest = lengths.last().copied().unwrap_or(0);
    let longest_prefix = signing
        .iter()
        .map(|result| result.prefix.len())
        .max()
        .unwrap_or(0);
    let same_length = shortest == longest;
    let comparable = same_length || longest_prefix <= shortest;
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
            roots.push(if same_length {
                result.commit_root
            } else if comparable {
                result
                    .prefix
                    .root_at(&result.order, shortest - result.prefix.len())
                    .unwrap_or([0u8; 32])
            } else {
                result.commit_root
            });
            latencies.extend_from_slice(&result.latencies);
        }
        println!(
            "  {}  {}  {}  {}  {}  {}  {}  {}  {}  {}  {}",
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
            pad(&result.certified_ids.len().to_string(), 10),
            pad(&format!("{}/{}", result.head_height, result.head_round), 10),
            pad(&human(result.bytes_in), 10),
            pad(&human(result.bytes_out), 10)
        );
    }

    let signers: Vec<&NodeResult> = results.iter().filter(|result| result.signs).collect();
    if let Some(first) = signers.first() {
        let common: Vec<u64> = first
            .certified_ids
            .keys()
            .filter(|height| {
                signers
                    .iter()
                    .all(|result| result.certified_ids.contains_key(height))
            })
            .copied()
            .collect();
        let agreed = common.iter().all(|height| {
            signers
                .iter()
                .all(|result| result.certified_ids.get(height) == first.certified_ids.get(height))
        });
        let lowest_head = signers
            .iter()
            .map(|result| result.head_height)
            .min()
            .unwrap_or(0);
        let highest_head = signers
            .iter()
            .map(|result| result.head_height)
            .max()
            .unwrap_or(0);
        let conflicts: usize = signers.iter().map(|result| result.conflicts).sum();
        println!(
            "  finality          {} of {} common certified heights, agreement {}, conflicts {}, \
             heads {}..{}",
            common.len(),
            first.certified_ids.len(),
            agreed,
            conflicts,
            lowest_head,
            highest_head
        );
        if !agreed {
            return Err("validators certified different headers".into());
        }
        if conflicts > 0 {
            return Err(format!("{conflicts} certificate conflicts across the mesh").into());
        }
    }

    let restorations: Vec<&Restored> = signers
        .iter()
        .filter_map(|result| result.restored.as_ref())
        .collect();
    if let Some(first) = restorations.first() {
        let agree = restorations
            .iter()
            .all(|restored| restored.state_root == first.state_root);
        let checkpoint = first.checkpoint.map_or_else(
            || String::from("from history"),
            |height| format!("from checkpoint {height}"),
        );
        println!(
            "  restart           {} tx applied, order {}, certified head {}, state root {} \
             {checkpoint} ({} nodes, all agree: {agree})",
            first.applied,
            first.order_len,
            first.head_height,
            hex::encode(&first.state_root[..6]),
            restorations.len()
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
        println!(
            "                    vertices, batches, and certified headers: no state snapshot \
             and no pruning here"
        );
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
    let agreed = (same_length || comparable) && roots.windows(2).all(|pair| pair[0] == pair[1]);
    if same_length {
        println!("  same commit root  {agreed} at {shortest} committed entries");
    } else {
        println!(
            "  same commit root  {agreed} at {shortest} common committed entries (lengths {shortest}..{longest})"
        );
    }
    if !same_length && !comparable {
        println!(
            "    the common index {shortest} is below a node's pruned prefix {longest_prefix}; roots are not comparable"
        );
    }
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

    #[test]
    fn the_previous_wire_protocol_is_refused() {
        let hello = wire::Hello {
            protocol: wire::WIRE_PROTOCOL - 1,
            chain_id: b"chain-a".to_vec(),
        };
        let error = check_hello(b"chain-a", &hello).unwrap_err();
        assert!(error.contains("wire protocol"), "{error}");
    }

    #[tokio::test]
    async fn a_declined_snapshot_is_an_error_the_caller_can_skip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let chain = b"chain-a".to_vec();
        let server = {
            let chain = chain.clone();
            tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut buffer = Vec::new();
                handshake(&mut stream, &mut buffer, &chain).await.unwrap();
                let want = read_one_message(&mut stream, &mut buffer).await.unwrap();
                assert_eq!(want, Message::SnapshotWant);
                let frame =
                    wire::frame(&Message::SnapshotDeclined(String::from("state evicted")), 1)
                        .unwrap();
                stream.write_all(&frame).await.unwrap();
            })
        };
        let error = fetch_one(&target, &chain).await.unwrap_err();
        assert!(error.contains("declined the snapshot"), "{error}");
        assert!(error.contains("state evicted"), "{error}");
        server.await.unwrap();
    }

    #[test]
    fn a_snapshot_bridge_must_close_every_reference() {
        use validator::{Dag, Vertex};

        fn signed_vertex(
            membership: &chain::Membership,
            chain_id: &[u8],
            author: usize,
            round: u64,
            references: Vec<VertexId>,
            payload_hash: [u8; 32],
        ) -> Vertex {
            let mut vertex = Vertex {
                chain_id: chain_id.to_vec(),
                epoch: membership.set.epoch,
                round,
                author: membership.consensus[author].id.clone(),
                payload_hash,
                references,
                signature: Vec::new(),
            };
            let payload = vertex.signing_payload().unwrap();
            vertex.signature = Ed25519Scheme
                .sign(&membership.consensus[author].private_key, &payload)
                .unwrap();
            vertex
        }

        let membership = chain::membership(4, None).expect("a demo committee");
        let set = membership.set.clone();
        let chain_id = b"karsa-snapshot-bridge".to_vec();
        let mut dag = Dag::with_epoch_length(set.clone(), 2);
        let genesis: Vec<Vertex> = (0..4)
            .map(|author| signed_vertex(&membership, &chain_id, author, 0, Vec::new(), [0u8; 32]))
            .collect();
        for vertex in &genesis {
            dag.insert(vertex.clone()).unwrap();
        }
        let genesis_ids: Vec<VertexId> =
            genesis.iter().map(|vertex| vertex.id().unwrap()).collect();
        let committed: HashSet<VertexId> = genesis_ids.iter().cloned().collect();

        // The shape rule only counts reference authors, so a wrong digest at a
        // real author is accepted into the DAG. The bridge check must catch it.
        let dangling = VertexId {
            round: 0,
            author: genesis_ids[0].author.clone(),
            digest: [7u8; 32],
        };
        let mut references = genesis_ids[..3].to_vec();
        references.push(dangling);
        let tail = signed_vertex(&membership, &chain_id, 1, 1, references, [0u8; 32]);
        dag.insert(tail.clone()).unwrap();
        let error =
            check_snapshot_bridge(&dag, 0, &[tail], &committed, &[], &HashMap::new()).unwrap_err();
        assert_eq!(error, SnapshotDecline::BridgeIncomplete { round: 0 });

        // A payload the sender does not hold is a missing bridge, not an empty
        // tail the joiner can apply.
        let paid = signed_vertex(
            &membership,
            &chain_id,
            2,
            1,
            genesis_ids[..3].to_vec(),
            [9u8; 32],
        );
        dag.insert(paid.clone()).unwrap();
        let error =
            check_snapshot_bridge(&dag, 0, &[paid], &committed, &[], &HashMap::new()).unwrap_err();
        assert_eq!(error, SnapshotDecline::PayloadMissing);
    }

    #[test]
    fn a_snapshot_join_installs_fences_and_drops_inert_tail_vertices() {
        use validator::{CommitFrontier, Vertex};

        fn signed_vertex(
            membership: &chain::Membership,
            chain_id: &[u8],
            author: usize,
            round: u64,
            references: Vec<VertexId>,
        ) -> Vertex {
            let mut vertex = Vertex {
                chain_id: chain_id.to_vec(),
                epoch: membership.set.epoch,
                round,
                author: membership.consensus[author].id.clone(),
                payload_hash: [0u8; 32],
                references,
                signature: Vec::new(),
            };
            let payload = vertex.signing_payload().unwrap();
            vertex.signature = Ed25519Scheme
                .sign(&membership.consensus[author].private_key, &payload)
                .unwrap();
            vertex
        }

        let membership = chain::membership(4, None).expect("a demo committee");
        let set = membership.set.clone();
        let chain_id = b"karsa-snapshot-fence".to_vec();
        let state = State::new();
        let state_root = state.state_root();
        let dag_root = commit_root(&[]);
        let genesis = Header::genesis(chain_id.clone(), set.epoch, state_root, dag_root);
        let anchor = Header {
            chain_id: chain_id.clone(),
            epoch: set.epoch,
            height: 1,
            round: 3,
            state_root,
            dag_root,
            previous: genesis.id().unwrap(),
            applied: 0,
        };
        let mut certificate = Certificate {
            chain_id: chain_id.clone(),
            epoch: anchor.epoch,
            round: anchor.round,
            vertex_id: anchor.id().unwrap().to_vec(),
            validator_set_id: set.id().unwrap().to_vec(),
            signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
            signatures: Vec::new(),
        };
        let payload = certificate.signing_payload().unwrap();
        for index in 0..set.quorum_size() {
            set_bit(&mut certificate.signer_bitmap, index);
            certificate.signatures.push(
                Ed25519Scheme
                    .sign(&membership.consensus[index].private_key, &payload)
                    .unwrap(),
            );
        }

        let fenced = set.validators[0].validator_id.clone();
        let fence = Fence::new(chain_id.clone(), 1, fenced.clone());
        let fence_payload = fence.signing_payload().unwrap();
        let mut fence_certificate = FenceCertificate {
            fence,
            signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
            signatures: Vec::new(),
        };
        for index in 0..set.quorum_size() {
            set_bit(&mut fence_certificate.signer_bitmap, index);
            fence_certificate.signatures.push(
                Ed25519Scheme
                    .sign(&membership.consensus[index].private_key, &fence_payload)
                    .unwrap(),
            );
        }

        let mut vertices: Vec<Vertex> = (0..4)
            .map(|author| signed_vertex(&membership, &chain_id, author, 0, Vec::new()))
            .collect();
        let genesis_ids: Vec<VertexId> =
            vertices.iter().map(|vertex| vertex.id().unwrap()).collect();
        // The fenced author's round-one vertex arrived before the fence. It is
        // not a vote and a fresh DAG cannot insert it, so the join drops it.
        vertices.push(signed_vertex(
            &membership,
            &chain_id,
            0,
            1,
            genesis_ids[..set.quorum_size()].to_vec(),
        ));
        vertices.push(signed_vertex(
            &membership,
            &chain_id,
            1,
            1,
            genesis_ids[..set.quorum_size()].to_vec(),
        ));
        // Two more voting-round vertices that do not reference the leader. They
        // make the round-skip partition exact: one vote, two non-votes, and the
        // fenced author as the absent voter.
        for author in [2, 3] {
            vertices.push(signed_vertex(
                &membership,
                &chain_id,
                author,
                1,
                genesis_ids[1..4].to_vec(),
            ));
        }
        let round_one = |author: usize| {
            vertices
                .iter()
                .find(|vertex| {
                    vertex.round == 1 && vertex.author == set.validators[author].validator_id
                })
                .expect("the voting round holds this author")
                .id()
                .unwrap()
        };
        let skip_proof = RoundSkipProof {
            attestation: NoVoteAttestation {
                skip: RoundSkip::new(chain_id.clone(), genesis_ids[0].clone()),
                signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
                signatures: Vec::new(),
            },
            votes: vec![round_one(1)],
            non_votes: vec![round_one(2), round_one(3)],
            fenced_absent: vec![fence_certificate.clone()],
            missing: Vec::new(),
        };

        let snapshot = wire::Snapshot {
            state: state.encode().unwrap(),
            order: Vec::new(),
            order_len: 0,
            prefix: CommitFrontier::empty(),
            anchor,
            certificate,
            transition: None,
            fences: vec![fence_certificate.clone()],
            round_skips: vec![skip_proof.clone()],
            cursor: 4,
            floor: None,
            vertices,
            batches: Vec::new(),
        };
        let dir = TestDir::new("snapshot-fence");
        let store = Store::open(&dir.0).unwrap();
        let signer = 1;
        let mut node = Node::with_chain_id_and_epoch_length(
            set.clone(),
            0,
            membership.consensus[signer].id.clone(),
            membership.consensus[signer].private_key.clone(),
            chain_id.clone(),
        );
        let mut finalizer = Some(
            Finalizer::new(
                SetSchedule::single(set.clone()),
                node.dag().epoch_schedule(),
                chain_id.clone(),
                membership.consensus[signer].id.clone(),
                membership.consensus[signer].private_key.clone(),
                genesis,
                0,
            )
            .unwrap(),
        );
        let adopted = adopt_snapshot(
            snapshot,
            &mut node,
            &mut finalizer,
            &mut HashMap::new(),
            &chain_id,
            Some(&store),
        )
        .expect("the fenced snapshot must be adopted");

        assert_eq!(adopted.vertices, 7, "four genesis vertices and three votes");
        assert!(node.dag().is_fenced(&fenced, 1));
        assert!(node.dag().is_fenced(&fenced, 99));
        assert!(node.dag().get(1, &fenced).is_none());
        assert!(
            node.dag().get(1, &set.validators[1].validator_id).is_some(),
            "a live author's tail vertex must survive"
        );
        assert_eq!(node.dag().round_skip(0), Some(&skip_proof));
        assert_eq!(store.round_skips().unwrap(), vec![skip_proof.clone()]);
        assert_eq!(store.fences().unwrap(), vec![fence_certificate.clone()]);
        assert_eq!(
            store.live_snapshot().unwrap().unwrap().fences,
            vec![fence_certificate]
        );
    }

    #[test]
    fn a_restarted_node_reloads_its_signed_fence_promise() {
        let membership = chain::membership(4, None).expect("a demo committee");
        let set = membership.set.clone();
        let chain_id = b"karsa-local-fence".to_vec();
        let dir = TestDir::new("local-fence");
        let store = Store::open(&dir.0).unwrap();
        let signer = 1;
        let fence = Fence::new(chain_id.clone(), 4, set.validators[0].validator_id.clone());
        let share = own_fence_share(
            &fence,
            &set,
            &membership.consensus[signer].id,
            &membership.consensus[signer].private_key,
        )
        .unwrap();
        store.put_fence_share(&share).unwrap();

        let mut node = Node::with_chain_id_and_epoch_length(
            set.clone(),
            0,
            membership.consensus[signer].id.clone(),
            membership.consensus[signer].private_key.clone(),
            chain_id.clone(),
        );
        let loaded = load_local_fence_shares(&mut node, &store, &chain_id).unwrap();
        assert_eq!(loaded, vec![share]);
        assert!(
            !node
                .dag()
                .is_locally_fenced(&set.validators[0].validator_id, 3)
        );
        assert!(
            node.dag()
                .is_locally_fenced(&set.validators[0].validator_id, 4)
        );
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

    #[tokio::test]
    async fn a_dropped_link_reconnects_and_keeps_delivering() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap().to_string();
        let chain = b"chain-a".to_vec();
        let (first_read_tx, first_read_rx) = oneshot::channel();

        let server = {
            let chain = chain.clone();
            tokio::spawn(async move {
                // First connection: take one frame, then reset the socket.
                let (mut first, _) = listener.accept().await.unwrap();
                let mut buffer = Vec::new();
                handshake(&mut first, &mut buffer, &chain).await.unwrap();
                let first_frame = read_one_message(&mut first, &mut buffer).await.unwrap();
                socket2::SockRef::from(&first)
                    .set_linger(Some(Duration::ZERO))
                    .unwrap();
                drop(first);
                let _ = first_read_tx.send(());

                // The restarting peer: the retained shares arrive first, then the
                // frame that was in flight when the link broke.
                let (mut second, _) = listener.accept().await.unwrap();
                let mut buffer = Vec::new();
                handshake(&mut second, &mut buffer, &chain).await.unwrap();
                let resent = tokio::time::timeout(
                    Duration::from_secs(5),
                    read_one_message(&mut second, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap();
                let retried = tokio::time::timeout(
                    Duration::from_secs(5),
                    read_one_message(&mut second, &mut buffer),
                )
                .await
                .unwrap()
                .unwrap();
                (first_frame, resent, retried)
            })
        };

        let mut stream = TcpStream::connect(&target).await.unwrap();
        let mut buffer = Vec::new();
        handshake(&mut stream, &mut buffer, &chain).await.unwrap();
        let (control_tx, control_rx) = mpsc::channel(8);
        let (data_tx, data_rx) = mpsc::channel(8);
        let (_shutdown_tx, shutdown_rx) = watch::channel(false);
        let want = |round: u64| {
            wire::frame(
                &Message::Want(VertexId {
                    round,
                    author: b"val-0".to_vec(),
                    digest: [round as u8; 32],
                }),
                0,
            )
            .unwrap()
        };
        let recent = Arc::new(Mutex::new(VecDeque::from([want(99)])));
        let writer = tokio::spawn(write_peer(
            stream,
            control_rx,
            data_rx,
            LinkTask {
                index: 0,
                target,
                chain_id: chain.clone(),
                bytes_out: Arc::new(AtomicU64::new(0)),
                up: Arc::new(AtomicBool::new(true)),
                recent_shares: Arc::clone(&recent),
                recent_vertices: Arc::new(Mutex::new(VecDeque::new())),
                send_buffer: 0,
                shutdown: shutdown_rx,
            },
        ));

        control_tx.send(want(1)).await.unwrap();
        first_read_rx.await.unwrap();
        // The first socket now resets. The next frame can only arrive if the
        // writer keeps the frame that failed and sends it on the new link.
        tokio::time::sleep(Duration::from_millis(100)).await;
        control_tx.send(want(2)).await.unwrap();

        let (first, resent, retried) = server.await.unwrap();
        assert!(matches!(first, Message::Want(_)));
        assert!(
            matches!(&resent, Message::Want(id) if id.round == 99),
            "{resent:?}"
        );
        assert!(
            matches!(&retried, Message::Want(id) if id.round == 2),
            "{retried:?}"
        );
        assert!(!writer.is_finished());
        drop(control_tx);
        drop(data_tx);
    }

    fn node_mode_config(validators: usize, node_index: Option<usize>) -> Config {
        Config {
            validators,
            port_base: 0,
            rounds: 0,
            slow_ms: 0,
            timeout: Duration::from_secs(1),
            queue: 1,
            send_buffer: 0,
            txs: 0,
            archives: 0,
            node_index,
            execute: false,
            store: PathBuf::new(),
            shard: false,
            drain: Duration::ZERO,
            home: None,
            profile: false,
            pre_sign: false,
            verify_threads: 1,
            rpc_port: 0,
            rpc_batch_max: rpc::DEFAULT_BATCH_MAX,
            snapshot_port: 0,
            sync_from_peers: false,
            checkpoint_every: 0,
            failure_rounds: 0,
            change: None,
            fence_silent: false,
            round_skip: false,
        }
    }

    /// Serializes tests that bind a whole loopback mesh.
    ///
    /// Port probing cannot reserve a range: two tests running at once can both
    /// see the same range free and then race to bind it. The integration devnet
    /// is a separate test binary and cargo runs the binaries in turn, so this
    /// lock only has to cover the in-process mesh tests.
    fn mesh_test_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().expect("the mesh test lock is poisoned")
    }

    /// A temp directory removed when the test ends.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new(name: &str) -> Self {
            use std::sync::atomic::{AtomicU64, Ordering};
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let sequence = NEXT.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "karsa-live-{name}-{}-{sequence}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&path);
            std::fs::create_dir_all(&path).expect("test directory");
            Self(path)
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Finds one contiguous port range the mesh can bind.
    fn a_free_port_base(validators: usize) -> u16 {
        for base in (20000u16..50000).step_by(8) {
            let mut probes = Vec::new();
            let mut free = true;
            for offset in 0..validators {
                let Ok(offset) = u16::try_from(offset) else {
                    free = false;
                    break;
                };
                let Ok(listener) = std::net::TcpListener::bind(("127.0.0.1", base + offset)) else {
                    free = false;
                    break;
                };
                probes.push(listener);
            }
            if free {
                drop(probes);
                return base;
            }
        }
        panic!("no free contiguous port range for the live mesh");
    }

    fn mesh_config(dir: &TestDir, port_base: u16, rounds: u64, checkpoint_every: u64) -> Config {
        Config {
            validators: 4,
            port_base,
            rounds,
            slow_ms: 0,
            timeout: Duration::from_secs(30),
            queue: 64,
            send_buffer: 0,
            txs: 0,
            archives: 0,
            node_index: None,
            execute: true,
            store: dir.0.clone(),
            shard: false,
            drain: Duration::from_secs(2),
            home: None,
            profile: false,
            pre_sign: false,
            verify_threads: 1,
            rpc_port: 0,
            rpc_batch_max: rpc::DEFAULT_BATCH_MAX,
            snapshot_port: 0,
            sync_from_peers: false,
            checkpoint_every,
            failure_rounds: 0,
            change: None,
            fence_silent: false,
            round_skip: false,
        }
    }

    #[test]
    fn a_mesh_authorizes_a_set_change_and_crosses_the_boundary() {
        let _mesh = mesh_test_lock();
        let dir = TestDir::new("set-change");
        let home = crate::home::Home::resolve(Some(dir.0.clone())).expect("a test home");
        crate::genesis::run(&home, None, true, Some(2), None).expect("a two-round epoch genesis");

        let mut config = mesh_config(&dir, a_free_port_base(4), 25, 2);
        config.home = Some(dir.0.clone());
        config.change = Some((SetChangeKind::Add, 4));
        let result = run(config);
        assert!(result.is_ok(), "the set-change run failed: {result:?}");

        for index in 0..4 {
            let store = Store::open(dir.0.join(format!("val-{index}"))).unwrap();
            let change = store
                .set_change()
                .unwrap()
                .unwrap_or_else(|| panic!("node {index} did not persist the set change"));
            assert_eq!(change.change.activation_epoch, 4);
            let headers = store.headers().unwrap();
            assert!(
                headers
                    .iter()
                    .any(|entry| entry.header.epoch >= change.change.activation_epoch),
                "node {index} never certified a header after the boundary"
            );
            let snapshot = store
                .live_snapshot()
                .unwrap()
                .unwrap_or_else(|| panic!("node {index} wrote no checkpoint"));
            assert!(
                snapshot.transition.is_some(),
                "node {index} lost the transition from its checkpoint"
            );
        }

        // The restart proposes nothing: it has to recover the transition from
        // the checkpoint and keep certifying above the boundary with the new set.
        let mut restart = mesh_config(&dir, a_free_port_base(4), 8, 0);
        restart.home = Some(dir.0.clone());
        let second = run(restart);
        assert!(second.is_ok(), "the set-change restart failed: {second:?}");

        crate::audit::run(dir.0.join("val-0"), 4, Some(dir.0.clone()))
            .expect("a store with an authorized transition must audit");
    }

    #[test]
    fn a_mesh_restarts_from_a_checkpoint_and_audits() {
        let _mesh = mesh_test_lock();
        let dir = TestDir::new("checkpoint-restart");
        let first = run(mesh_config(&dir, a_free_port_base(4), 30, 2));
        assert!(first.is_ok(), "the first run failed: {first:?}");

        for index in 0..4 {
            let store = Store::open(dir.0.join(format!("val-{index}"))).unwrap();
            let snapshot = store
                .live_snapshot()
                .unwrap()
                .unwrap_or_else(|| panic!("node {index} finished without writing a checkpoint"));
            let floor = snapshot.floor.expect("a checkpoint always has a floor");
            for vertex in store.vertices().unwrap() {
                assert!(
                    vertex.round > floor,
                    "node {index} kept vertex round {} below floor {floor}",
                    vertex.round
                );
            }
            let anchor_headers: Vec<u64> = store
                .headers()
                .unwrap()
                .iter()
                .map(|record| record.header.height)
                .collect();
            assert_eq!(
                anchor_headers.first().copied(),
                Some(snapshot.header.height),
                "the checkpoint anchor is the oldest header on disk"
            );
        }

        // Restart from the same stores. The pruned history cannot be replayed
        // from genesis, so a successful run means restore_live used the
        // checkpoint, and the convergence check inside run means four nodes
        // agreed on the result.
        let second = run(mesh_config(&dir, a_free_port_base(4), 5, 0));
        assert!(second.is_ok(), "the restart failed: {second:?}");

        let store = Store::open(dir.0.join("val-0")).unwrap();
        assert!(
            store.live_snapshot().unwrap().is_some(),
            "the restart must not discard the checkpoint"
        );
        crate::audit::run(dir.0.join("val-0"), 4, None)
            .expect("a checkpoint-pruned store must audit above its anchor");
    }

    #[test]
    fn the_checkpoint_interval_continues_from_the_resumed_head() {
        let restored = Restored {
            state_root: [0; 32],
            applied: 0,
            order_len: 0,
            head_height: 176,
            checkpoint: Some(129),
        };
        assert_eq!(
            resumed_checkpoint_height(Some(&restored), Some(176)),
            129,
            "the interval continues from the checkpoint, not from process start"
        );
        let full_store = Restored {
            checkpoint: None,
            ..restored
        };
        assert_eq!(resumed_checkpoint_height(Some(&full_store), Some(176)), 176);
        assert_eq!(resumed_checkpoint_height(None, Some(42)), 42);
        assert_eq!(resumed_checkpoint_height(None, None), 0);
    }

    #[test]
    fn checkpointing_needs_a_store() {
        let mut config = node_mode_config(2, Some(0));
        config.execute = true;
        config.checkpoint_every = 1;
        let error = run(config).unwrap_err().to_string();
        assert!(
            error.contains("--checkpoint-every needs --store"),
            "{error}"
        );
    }

    #[test]
    fn checkpointing_needs_execution() {
        let mut config = node_mode_config(2, Some(0));
        config.store = PathBuf::from("/tmp/karsa-checkpoint-test");
        config.checkpoint_every = 1;
        let error = run(config).unwrap_err().to_string();
        assert!(
            error.contains("--checkpoint-every needs --execute"),
            "{error}"
        );
    }

    #[test]
    fn one_process_per_validator_refuses_archives() {
        let mut config = node_mode_config(2, Some(0));
        config.archives = 1;
        let error = run(config).unwrap_err().to_string();
        assert!(error.contains("--archives must be 0"), "{error}");
    }

    #[test]
    fn one_process_per_validator_refuses_an_index_outside_the_committee() {
        let error = run(node_mode_config(2, Some(2))).unwrap_err().to_string();
        assert!(error.contains("outside 0..2"), "{error}");
    }
}
