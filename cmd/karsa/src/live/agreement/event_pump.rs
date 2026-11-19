//! Isolated async runtime with opt-in bounded local maintenance, not production integration.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use net::wire::{Frame, Message};
use tokio::sync::{mpsc, watch};
use tx::batch::Batch;
use validator::Build;

use super::{JournaledFinalization, Membership};

/// Local authority, deliberately separate from decoded network messages.
pub enum LocalEvent {
    /// Import bounded trusted causal availability and select one durable nil or positive phase.
    /// When no carrier obligation is authorable, the elected proposer may author its initial
    /// direct-commit proposal and then bind it into the view-0 authorization, or an elected
    /// re-proposal from a retained POL, or one exact `f+1`-supported future view echo may follow.
    /// Network carrier receipt never supplies this availability or applies a slot.
    Drive(Vec<validator::Vertex>),
    /// Explicit trusted phase driving with independently authenticated causal availability.
    Author(Box<super::local_authoring::AuthoringRequest>),
    /// One local pacemaker step; does not sign or apply a certified slot.
    Tick(std::time::Instant),
    /// Bounded retry of selected durable local publications.
    Retry {
        /// Trusted monotonic local time, never a wire timestamp.
        now: std::time::Instant,
        /// At most 64 selected completed local publications; not an unbounded resend queue.
        carriers: Vec<validator::VertexId>,
    },
    /// Authors one plain causal availability vertex at the first ready round.
    ///
    /// Live nodes need a causal DAG before any agreement evidence can be proposed;
    /// this produces the same kind of vertex the legacy loop produces. It is not an
    /// agreement publication: it carries no proposal, vote, aggregate or decision and
    /// authorizes none. The payload digest is local data-plane input, zero meaning no batch.
    AuthorCausal {
        /// Bounded trusted causal availability, imported before selecting the round.
        vertices: Vec<validator::Vertex>,
        /// Local data-plane payload digest; zero names no batch.
        payload_hash: [u8; 32],
    },
    /// Applies the durable decided slot if one exists, then attempts execution from
    /// journaled ordering. An undecided slot is an ordinary no-op, not an error.
    AdvanceDecidedSlot {
        /// Caller-trusted local authoring timestamp.
        at: u64,
    },
    /// Apply the decided slot, then attempt execution from journaled ordering.
    ApplyCertifiedSlot {
        /// Caller-trusted local authoring timestamp.
        at: u64,
    },
    /// Resume payload-blocked execution or initial durable replay without applying a slot.
    BuildReady {
        /// Caller-trusted local authoring timestamp.
        at: u64,
    },
}

/// One attempted response per processed event; volatile and without publication authority.
pub struct PumpOutput {
    /// At most one authenticated durable carrier or control publication per local turn.
    pub carriers: Vec<Message>,
    /// Volatile shares and certificates; grants no pruning or store-publication authority.
    pub build: Build,
    /// Processing error; fatal ownership errors also terminate `run`.
    pub error: Option<String>,
}

/// Bounded ingress compatible with `read_peer`, plus a separate local authority channel.
pub struct PumpChannels {
    /// Decoded network ingress, directly usable by the existing peer reader.
    pub frames: mpsc::Sender<Frame>,
    /// Trusted local authority; must not be derived from arbitrary wire messages.
    pub local: mpsc::Sender<LocalEvent>,
    /// Backpressured volatile responses in processing order, without delivery acknowledgement.
    pub output: mpsc::Receiver<PumpOutput>,
    /// Wall-clock processing cost, sampled by the caller after the pump stops.
    pub stats: Arc<PumpStats>,
}

/// Aggregate pump wall-clock cost, grouped by input kind.
///
/// Diagnostic only. The pump is single-threaded, so these totals say how much of the run the
/// owner spent processing each kind of event. They are not a delivery, freshness or progress
/// statement, and they grant no authority.
#[derive(Debug, Default)]
pub struct PumpStats {
    local_turns: AtomicU64,
    local_nanos: AtomicU64,
    max_local_nanos: AtomicU64,
    frame_turns: AtomicU64,
    frame_nanos: AtomicU64,
    scheduled_turns: AtomicU64,
    scheduled_nanos: AtomicU64,
}

/// Immutable copy of [`PumpStats`].
#[derive(Debug, Clone, Copy, Default)]
pub struct PumpSnapshot {
    /// Local turns processed and their cumulative handling time.
    pub local_turns: u64,
    /// Cumulative nanoseconds spent in local turns.
    pub local_nanos: u64,
    /// Slowest single local turn; one durable action can hold the pump this long.
    pub max_local_nanos: u64,
    /// Peer frames processed and their cumulative handling time.
    pub frame_turns: u64,
    /// Cumulative nanoseconds spent in peer frame handling.
    pub frame_nanos: u64,
    /// Scheduled maintenance wakes processed and their cumulative handling time.
    pub scheduled_turns: u64,
    /// Cumulative nanoseconds spent in scheduled maintenance.
    pub scheduled_nanos: u64,
}

#[derive(Debug, Clone, Copy)]
enum PumpKind {
    Local,
    Frame,
    Scheduled,
}

impl PumpStats {
    fn record(&self, kind: PumpKind, elapsed: std::time::Duration) {
        let nanos = u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX);
        match kind {
            PumpKind::Local => {
                self.local_turns.fetch_add(1, Ordering::Relaxed);
                self.local_nanos.fetch_add(nanos, Ordering::Relaxed);
                self.max_local_nanos.fetch_max(nanos, Ordering::Relaxed);
            }
            PumpKind::Frame => {
                self.frame_turns.fetch_add(1, Ordering::Relaxed);
                self.frame_nanos.fetch_add(nanos, Ordering::Relaxed);
            }
            PumpKind::Scheduled => {
                self.scheduled_turns.fetch_add(1, Ordering::Relaxed);
                self.scheduled_nanos.fetch_add(nanos, Ordering::Relaxed);
            }
        }
    }

    /// Takes one coherent-enough diagnostic sample; counters are read independently.
    pub fn snapshot(&self) -> PumpSnapshot {
        PumpSnapshot {
            local_turns: self.local_turns.load(Ordering::Relaxed),
            local_nanos: self.local_nanos.load(Ordering::Relaxed),
            max_local_nanos: self.max_local_nanos.load(Ordering::Relaxed),
            frame_turns: self.frame_turns.load(Ordering::Relaxed),
            frame_nanos: self.frame_nanos.load(Ordering::Relaxed),
            scheduled_turns: self.scheduled_turns.load(Ordering::Relaxed),
            scheduled_nanos: self.scheduled_nanos.load(Ordering::Relaxed),
        }
    }
}

/// Owns journaled ordering/execution and a digest-validated, bounded payload index.
/// Controls are trusted at construction and cannot be inferred or added by network input.
/// Payload arrival resumes journaled execution using the latest trusted local build time;
/// receipt of agreement evidence never applies a slot. No wire timestamp authorizes signing.
/// Only payload digests referenced by currently applied certified ordering are admitted.
/// Payloads arriving before certified application are rejected and require retransmission.
/// Admitted batches are never evicted: this offline owner's lifetime must fit its limits;
/// it has no pruning authority and does not support unbounded continued operation.
///
/// One event is processed per scheduling turn. Output capacity is reserved before mutation,
/// so ordinary errors do not discard earlier output under backpressure. Ready cancellation
/// and output closure take priority over ingress, with another check before processing.
/// Receiver drop racing after that check can still lose the in-flight or queued volatile
/// output; reservation is not delivery acknowledgement, and execution is not rolled back.
/// Cancellation leaves queued output drainable only while its receiver remains open.
/// Closing ingress with full output requires draining output or cancellation to exit.
/// The owner is returned on exit, including fatal errors, for inspection/reopening.
pub struct EventPump {
    owner: JournaledFinalization,
    membership: Membership,
    controls: BTreeSet<[u8; 32]>,
    batches: BTreeMap<[u8; 32], Batch>,
    payload_bytes: usize,
    max_payload_bytes: usize,
    max_batches: usize,
    build_at: Option<u64>,
    schedule: Option<LocalSchedule>,
    frames: mpsc::Receiver<Frame>,
    local: mpsc::Receiver<LocalEvent>,
    output: mpsc::Sender<PumpOutput>,
    stats: Arc<PumpStats>,
}

/// Caps caller selection and duplicate-check work per scheduled carrier poll.
const CARRIER_PAGE_IDS: usize = 64;

struct LocalSchedule {
    interval: std::time::Duration,
    next: tokio::time::Instant,
    publication_offset: usize,
    retry_controls: bool,
}

impl LocalSchedule {
    fn finish_retry(&mut self, result: &Result<Vec<Message>, String>) {
        // Keep the selected ID while cadence is not due, avoiding phase-locked starvation.
        // Advance on export errors: discovery does not promise current-slot availability.
        if !matches!(result, Ok(messages) if messages.is_empty()) {
            self.publication_offset += 1;
        }
    }

    fn defer(&mut self, now: tokio::time::Instant) {
        // Fixed delay, not interval catch-up: a blocked output never accumulates work.
        self.next = now + self.interval;
    }
}

impl EventPump {
    /// Opts this isolated owner into volatile, fixed-delay local maintenance.
    /// Requires pinned authoring. Each wake ticks once and attempts one nil or positive durable
    /// action, an initial direct-commit proposal with its elected view-0 binding, an elected
    /// re-proposal step from a retained POL, or echoes one exact `f+1`-supported future view
    /// target, or retries one discovered publication. The proposal/view steps use only local
    /// retained causality and durable evidence; they never invent a decision or evidence.
    /// Neither adds a causal import requirement of its own.
    /// Discovery reads at most one 64-ID page per wake under the 4096-event replay cap;
    /// only the first still-current ID is attempted, and IDs whose slot or view has passed
    /// are skipped without a retransmission (they stay durable for explicit export).
    /// Completion or error advances the offset, while a not-yet-due retry retains it. Empty
    /// pages wrap on the next wake. Historical/unavailable publications report errors but
    /// do not pin the cursor.
    /// Idle wakes alternate control-first and carrier-only retry turns. Control retries
    /// include completed nil votes and already-authorized view requests/certificates.
    /// No invented decision/evidence, causal import or slot application is scheduled.
    /// Recovery requires opting in again, including authoring setup.
    /// # Errors
    /// Rejects missing authoring, replacement schedules and intervals outside 10ms..=1 day.
    pub fn enable_scheduling(&mut self, interval: std::time::Duration) -> Result<(), String> {
        self.owner.check_local_authoring()?;
        if self.schedule.is_some() {
            return Err("local pump scheduling is already enabled".into());
        }
        if interval < std::time::Duration::from_millis(10)
            || interval > std::time::Duration::from_secs(86_400)
        {
            return Err("local pump interval must be between 10ms and one day".into());
        }
        self.schedule = Some(LocalSchedule {
            interval,
            next: tokio::time::Instant::now() + interval,
            publication_offset: 0,
            retry_controls: true,
        });
        Ok(())
    }

    pub(super) fn scheduled_turn(
        &mut self,
        now: std::time::Instant,
    ) -> Result<Vec<Message>, String> {
        if self.schedule.is_none() {
            return Err("local pump scheduling is disabled".into());
        }
        let ticked = self.owner.tick_local(now)?;
        if !ticked.is_empty() {
            // A newly authored view request is this turn's publication; the durable
            // retry cadence owns every later copy.
            return Ok(ticked);
        }
        let authored = self.owner.drive_local(Vec::new())?;
        if !authored.is_empty() {
            return Ok(authored);
        }
        let schedule = self
            .schedule
            .as_mut()
            .ok_or("local pump scheduling is disabled")?;
        let controls_first = schedule.retry_controls;
        schedule.retry_controls = !controls_first;
        if controls_first {
            let messages = self.owner.retry_controls_local(now)?;
            if !messages.is_empty() {
                return Ok(messages);
            }
        }
        let offset = self
            .schedule
            .as_ref()
            .ok_or("local pump scheduling is disabled")?
            .publication_offset;
        let page = self.owner.completed_publications(offset)?;
        let page_len = page.len();
        if page_len == 0 {
            if let Some(schedule) = self.schedule.as_mut() {
                schedule.publication_offset = 0;
            }
            return Ok(Vec::new());
        }
        // Retransmitting evidence for a slot or view this node has already left only trains
        // peers to reject it. Skip those IDs; the publication stays durable and explicit
        // export can still select it.
        let mut skipped = 0usize;
        let mut selected = None;
        for id in &page {
            if self.owner.publication_is_current(id)? {
                selected = Some(id.clone());
                break;
            }
            skipped += 1;
        }
        let Some(id) = selected else {
            if let Some(schedule) = self.schedule.as_mut() {
                schedule.publication_offset = if page_len < CARRIER_PAGE_IDS {
                    0
                } else {
                    offset + page_len
                };
            }
            return Ok(Vec::new());
        };
        if let Some(schedule) = self.schedule.as_mut() {
            schedule.publication_offset = offset + skipped;
        }
        let result = self.owner.retry_local(now, std::slice::from_ref(&id));
        if let Some(schedule) = self.schedule.as_mut() {
            schedule.finish_retry(&result);
        }
        result
    }

    /// All channel capacities are identical and nonzero. Payload limits cover batch count
    /// and the sum of retained batches' canonical encoded lengths, not total memory usage
    /// (decoded allocations, channel contents, encoding temporaries and journals are extra).
    /// Exhaustion rejects input without evicting required data; limits bound the offline
    /// lifetime, not a pruning/publication policy.
    pub fn new(
        owner: JournaledFinalization,
        membership: Membership,
        controls: BTreeSet<[u8; 32]>,
        capacity: std::num::NonZeroUsize,
        max_batches: usize,
        max_payload_bytes: usize,
    ) -> (Self, PumpChannels) {
        let (frames_tx, frames) = mpsc::channel(capacity.get());
        let (local_tx, local) = mpsc::channel(capacity.get());
        let (output, output_rx) = mpsc::channel(capacity.get());
        let stats = Arc::new(PumpStats::default());
        (
            Self {
                owner,
                membership,
                controls,
                batches: BTreeMap::new(),
                payload_bytes: 0,
                max_payload_bytes,
                max_batches,
                build_at: None,
                schedule: None,
                frames,
                local,
                output,
                stats: Arc::clone(&stats),
            },
            PumpChannels {
                frames: frames_tx,
                local: local_tx,
                output: output_rx,
                stats,
            },
        )
    }

    /// Runs until cancellation, ingress closure, lost output, or an owner health failure.
    /// Opt-in maintenance shares output reservation and cancellation checks with ingress;
    /// blocked output defers all timer mutation. False watch updates retain the deadline.
    /// Returned errors are fatal; per-event retryable errors travel through the output.
    pub async fn run(
        mut self,
        mut cancel: watch::Receiver<bool>,
    ) -> (JournaledFinalization, Result<(), String>) {
        let mut frames_open = true;
        let mut local_open = true;
        loop {
            if *cancel.borrow() || (!frames_open && !local_open) {
                return (self.owner, Ok(()));
            }
            let permit = tokio::select! {
                biased;
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        return (self.owner, Ok(()));
                    }
                    continue;
                }
                permit = self.output.clone().reserve_owned() => match permit {
                    Ok(permit) => permit,
                    Err(_) => return (self.owner, Err("event pump output closed".into())),
                },
            };
            enum Input {
                Local(Option<LocalEvent>),
                Frame(Option<Frame>),
                Scheduled,
            }
            let deadline = self.schedule.as_ref().map(|schedule| schedule.next);
            let input = tokio::select! {
                biased;
                changed = cancel.changed() => {
                    if changed.is_err() || *cancel.borrow() {
                        return (self.owner, Ok(()));
                    }
                    continue;
                }
                _ = self.output.closed() => {
                    return (self.owner, Err("event pump output closed".into()));
                }
                input = async {
                    tokio::select! {
                        _ = async {
                            match deadline {
                                Some(deadline) => tokio::time::sleep_until(deadline).await,
                                None => std::future::pending::<()>().await,
                            }
                        } => Input::Scheduled,
                        event = self.local.recv(), if local_open => Input::Local(event),
                        frame = self.frames.recv(), if frames_open => Input::Frame(frame),
                    }
                } => input,
            };
            if *cancel.borrow() {
                return (self.owner, Ok(()));
            }
            if self.output.is_closed() {
                return (self.owner, Err("event pump output closed".into()));
            }
            let mut carriers = Vec::new();
            let kind = match &input {
                Input::Local(_) => PumpKind::Local,
                Input::Frame(_) => PumpKind::Frame,
                Input::Scheduled => PumpKind::Scheduled,
            };
            let started = std::time::Instant::now();
            let result = match input {
                Input::Scheduled => {
                    let now = tokio::time::Instant::now();
                    let result = self.scheduled_turn(now.into_std());
                    self.schedule
                        .as_mut()
                        .expect("scheduled wake requires opt-in")
                        .defer(tokio::time::Instant::now());
                    result.map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
                }
                Input::Local(Some(LocalEvent::Drive(vertices))) => {
                    self.owner.drive_local(vertices).map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
                }
                Input::Local(Some(LocalEvent::Author(request))) => {
                    self.owner.author_local(*request).map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
                }
                Input::Local(Some(LocalEvent::Tick(now))) => {
                    self.owner.tick_local(now).map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
                }
                Input::Local(Some(LocalEvent::Retry { now, carriers: ids })) => {
                    self.owner.retry_local(now, &ids).map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
                }
                Input::Local(Some(LocalEvent::AuthorCausal {
                    vertices,
                    payload_hash,
                })) => self
                    .owner
                    .author_causal_local(vertices, payload_hash)
                    .map(|messages| {
                        carriers = messages;
                        Build::default()
                    }),
                Input::Local(Some(LocalEvent::AdvanceDecidedSlot { at })) => {
                    match self.owner.advance_decided_slot() {
                        Ok(true) => self.build(at),
                        Ok(false) => Ok(Build::default()),
                        Err(error) => Err(error),
                    }
                }
                Input::Local(Some(LocalEvent::ApplyCertifiedSlot { at })) => self
                    .owner
                    .advance_certified_slot()
                    .and_then(|()| self.build(at)),
                Input::Local(Some(LocalEvent::BuildReady { at })) => self.build(at),
                Input::Local(None) => {
                    local_open = false;
                    continue;
                }
                Input::Frame(Some(frame)) => self.receive(frame.message),
                Input::Frame(None) => {
                    frames_open = false;
                    continue;
                }
            };
            self.stats.record(kind, started.elapsed());
            let (output, fatal) = match result {
                Ok(build) => (
                    PumpOutput {
                        carriers,
                        build,
                        error: None,
                    },
                    None,
                ),
                Err(error) => {
                    let fatal = self.owner.check_health().err();
                    (
                        PumpOutput {
                            carriers: Vec::new(),
                            build: Build::default(),
                            error: Some(error),
                        },
                        fatal,
                    )
                }
            };
            permit.send(output);
            if let Some(error) = fatal {
                return (self.owner, Err(error));
            }
            tokio::task::yield_now().await;
        }
    }

    fn build(&mut self, at: u64) -> Result<Build, String> {
        self.build_at = Some(at);
        self.owner
            .build_ready(&self.membership, &self.batches, &self.controls, at)
    }

    fn receive(&mut self, message: Message) -> Result<Build, String> {
        match message {
            Message::Payload(batch) => {
                let bytes = batch.encode().map_err(|error| error.to_string())?;
                let hash = batch.digest().map_err(|error| error.to_string())?;
                if hash == [0; 32] || self.controls.contains(&hash) {
                    return Err("payload conflicts with trusted control classification".into());
                }
                if !self
                    .owner
                    .finalization()
                    .execution()
                    .snapshot()
                    .vertices()
                    .iter()
                    .any(|vertex| vertex.payload_hash == hash)
                {
                    return Err("payload is not required by applied certified ordering; retransmit after certified application".into());
                }
                if !self.batches.contains_key(&hash) {
                    let size = self
                        .payload_bytes
                        .checked_add(bytes.len())
                        .ok_or("payload index size overflow")?;
                    if self.batches.len() >= self.max_batches || size > self.max_payload_bytes {
                        return Err("event pump payload index full".into());
                    }
                    self.batches.insert(hash, batch);
                    self.payload_bytes = size;
                }
                // Resume only work already authorized with a trusted local timestamp.
                // A wire timestamp never supplies local header-authoring time.
                match self.build_at {
                    Some(at) => self.build(at),
                    None => Ok(Build::default()),
                }
            }
            Message::Share(share) => Ok(Build {
                shares: Vec::new(),
                certified: self.owner.receive_share(&self.membership, share)?,
            }),
            message @ (Message::AgreementCarrier { .. }
            | Message::AgreementNilVote(_)
            | Message::AgreementViewRequest(_)
            | Message::AgreementViewCertificate(_)) => {
                self.owner.receive_agreement_message(message)?;
                Ok(Build::default())
            }
            _ => Err("message is not isolated agreement input".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delayed_schedule_defers_without_catch_up_or_cursor_reset() {
        let start = tokio::time::Instant::now();
        let interval = std::time::Duration::from_secs(1);
        let mut schedule = LocalSchedule {
            interval,
            next: start + interval,
            publication_offset: 63,
            retry_controls: true,
        };
        let after_backpressure = start + interval * 100;
        schedule.defer(after_backpressure);
        assert_eq!(schedule.next, after_backpressure + interval);
        assert_eq!(schedule.publication_offset, 63);
        schedule.defer(after_backpressure + interval);
        assert_eq!(schedule.next, after_backpressure + interval * 2);
        for _ in 0..100 {
            schedule.finish_retry(&Ok(Vec::new()));
        }
        assert_eq!(
            schedule.publication_offset, 63,
            "not-due retries retain the selected publication"
        );
        schedule.finish_retry(&Ok(vec![Message::WantSlot {
            round: 1,
            author: vec![1],
        }]));
        assert_eq!(schedule.publication_offset, 64);
        schedule.finish_retry(&Err("unavailable historical publication".into()));
        assert_eq!(
            schedule.publication_offset, 65,
            "errors cannot pin discovery forever"
        );
    }
}
