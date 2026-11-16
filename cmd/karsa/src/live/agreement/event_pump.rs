//! Isolated async runtime with explicit local driving; not connected to the production node.

use std::collections::{BTreeMap, BTreeSet};

use net::wire::{Frame, Message};
use tokio::sync::{mpsc, watch};
use tx::batch::Batch;
use validator::Build;

use super::{JournaledFinalization, Membership};

/// Local authority, deliberately separate from decoded network messages.
pub enum LocalEvent {
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
    /// At most one authenticated durable carrier export per local request.
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
    frames: mpsc::Receiver<Frame>,
    local: mpsc::Receiver<LocalEvent>,
    output: mpsc::Sender<PumpOutput>,
}

impl EventPump {
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
                frames,
                local,
                output,
            },
            PumpChannels {
                frames: frames_tx,
                local: local_tx,
                output: output_rx,
            },
        )
    }

    /// Runs until cancellation, ingress closure, lost output, or an owner health failure.
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
            }
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
            let result = match input {
                Input::Local(Some(LocalEvent::Author(request))) => {
                    self.owner.author_local(*request).map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
                }
                Input::Local(Some(LocalEvent::Tick(now))) => {
                    self.owner.tick_local(now).map(|()| Build::default())
                }
                Input::Local(Some(LocalEvent::Retry { now, carriers: ids })) => {
                    self.owner.retry_local(now, &ids).map(|messages| {
                        carriers = messages;
                        Build::default()
                    })
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
