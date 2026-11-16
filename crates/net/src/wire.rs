//! Frames for a validator-to-validator byte stream.
//!
//! A TCP stream is a sequence of bytes, not of messages. Something has to say
//! where one frame ends and the next begins, and it has to be able to say "not
//! yet" when a read lands in the middle of a frame — so this type is a parser over
//! an accumulator, not a function over a complete buffer.
//!
//! ```text
//! u32 body length || u64 sent-at nanos || u8 kind || payload
//! ```
//!
//! Twenty kinds share a link:
//!
//! - [`Message::Hello`] is the first frame on a link and names the chain.
//! - [`Message::Vertex`] is the broadcast.
//! - [`Message::Want`] asks a peer for one vertex by id.
//! - [`Message::WantSlot`] asks a peer for the vertex one author made in one
//!   round, for a vote that was broadcast while this node was down.
//! - [`Message::Payload`] carries the batch a vertex names, on the data plane.
//! - [`Message::Control`] carries a control payload a vertex names, on the same
//!   causal plane as a batch.
//! - [`Message::Share`] carries one validator's signature over a header.
//! - [`Message::SnapshotWant`] and [`Message::Snapshot`] are a snapshot link.
//! - [`Message::Tx`] gossips one signed envelope so every node can track it.
//! - [`Message::SetChange`] carries a transition certificate authorized by the
//!   old set.
//! - [`Message::Fence`] carries a quorum statement that one validator failed.
//! - [`Message::RoundSkip`] carries evidence that a leader round cannot reach a
//!   vote quorum.
//! - [`Message::Floor`] reports how much history a validator has pruned, so a
//!   peer can tell when a want can no longer be served.
//! - [`Message::SnapshotRelease`] tells a snapshot server that the joiner has
//!   installed the snapshot, so its floor no longer needs to stay pinned.
//!
//! - [`Message::AgreementCarrier`] carries opaque agreement data and supporting vertices.
//! - [`Message::AgreementViewRequest`], [`Message::AgreementViewCertificate`], and
//!   [`Message::AgreementNilVote`] carry bounded opaque agreement envelopes;
//!   authentication and semantic validation belong to the consumer.
//!
//! The hello exists because a vertex is only meaningful on one chain: the chain id
//! is part of what a validator signs, so a peer on another genesis would produce
//! vertices this node can only reject. Exchanging the identity first turns that
//! from per-frame waste into one refused connection.
//!
//! [`Message::Want`] is what makes a bounded queue safe. A peer that cannot keep up
//! may have a frame dropped, and a dropped vertex is never "lost" to the protocol:
//! the reference rule makes it *visible* — the next round's vertices name it, the
//! receiver cannot check the shape rule, and it asks for exactly that id. Repair is
//! driven by the rule the DAG already enforces, not by guessing which authors
//! should have authored.
//!
//! The length field excludes itself. The timestamp is transport metadata, not part
//! of any signature. A frame longer than [`MAX_FRAME`] is rejected rather than
//! buffered: without a cap, one peer would choose how much a node allocates.

use crypto::encoding::{Decoder, Encoder};
use crypto::{CryptoError, CryptoErrorKind};
use tx::batch::Batch;
use validator::{
    Certificate, CommitFrontier, ControlPayload, FenceCertificate, Header, RoundSkipProof, Share,
    TransitionCertificate, Vertex, VertexId,
};

/// Largest body this parser will accept.
///
/// An Ed25519 vertex with full references at a hundred validators is a few
/// kilobytes; a post-quantum one with a SLH-DSA signature is under 128 kB. Sixteen
/// megabytes is far above both and still bounded.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Bytes in front of the payload: length, timestamp, and kind.
const HEADER: usize = 4 + 8 + 1;

const KIND_VERTEX: u8 = 1;
const KIND_WANT: u8 = 2;
const KIND_PAYLOAD: u8 = 3;
const KIND_HELLO: u8 = 4;
const KIND_SHARE: u8 = 5;
const KIND_SNAPSHOT_WANT: u8 = 6;
const KIND_SNAPSHOT: u8 = 7;
const KIND_TX: u8 = 8;
const KIND_SET_CHANGE: u8 = 9;
const KIND_FENCE: u8 = 10;
const KIND_ROUND_SKIP: u8 = 11;
const KIND_CONTROL: u8 = 12;
const KIND_WANT_SLOT: u8 = 13;
const KIND_SNAPSHOT_DECLINED: u8 = 14;
const KIND_FLOOR: u8 = 15;
const KIND_SNAPSHOT_RELEASE: u8 = 16;
const KIND_AGREEMENT_CARRIER: u8 = 17;
const KIND_AGREEMENT_VIEW_REQUEST: u8 = 18;
const KIND_AGREEMENT_VIEW_CERTIFICATE: u8 = 19;
const KIND_AGREEMENT_NIL_VOTE: u8 = 20;

// Matches the slot-decision codec's maximum validator roster; bytes remain capped separately.
const MAX_AGREEMENT_VIEW_REQUESTS: usize = 4096;

/// Maximum opaque agreement envelope length.
pub const MAX_AGREEMENT_ENVELOPE: usize = 1024 * 1024;
/// Maximum agreement payload length, excluding transport timestamp and kind.
pub const MAX_AGREEMENT_PAYLOAD: usize = 2 * 1024 * 1024;
/// Maximum vertices in one agreement carrier.
pub const MAX_AGREEMENT_VERTICES: usize = 4096;
/// Maximum total vertex references in one agreement carrier.
pub const MAX_AGREEMENT_EDGES: usize = 65536;

/// The framing and message layout this build speaks.
///
/// A peer that answers with another number is not necessarily hostile; it may be a
/// different build. The link is closed rather than parsed optimistically, because
/// the next frame kind could mean something else there.
pub const WIRE_PROTOCOL: u16 = 18;

/// The first frame on every link: which chain the sender is on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Framing version the sender speaks.
    pub protocol: u16,
    /// The sender's genesis hash, which is the chain's identity.
    pub chain_id: Vec<u8>,
}

impl Hello {
    /// A hello for `chain_id` speaking [`WIRE_PROTOCOL`].
    #[must_use]
    pub fn new(chain_id: Vec<u8>) -> Self {
        Self {
            protocol: WIRE_PROTOCOL,
            chain_id,
        }
    }
}

/// A state snapshot a joining node can adopt instead of replaying from genesis.
///
/// The anchor is the certified header the state belongs to. Its certificate is
/// carried so the receiver can check the quorum rather than trust the sender.
/// The committed order is split: `prefix` summarizes the entries at or below the
/// floor, whose vertices travel only above it, and `order` is the retained tail.
/// `order_len` is the total, which is what the anchor's `dag_root` commits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    /// Encoded `exec::State` at the anchor.
    pub state: Vec<u8>,
    /// Committed order tail above the compact prefix.
    pub order: Vec<VertexId>,
    /// Total committed entries the anchor covers.
    pub order_len: usize,
    /// Peaks of the committed order at or below the floor.
    pub prefix: CommitFrontier,
    /// The certified header the snapshot is anchored at.
    pub anchor: Header,
    /// Quorum certificate over the anchor.
    pub certificate: Certificate,
    /// Authorized set change that applies above the anchor, if any.
    pub transition: Option<TransitionCertificate>,
    /// Quorum fences adopted by the sender, including those below its floor.
    ///
    /// A joiner that lost a fence would wait again on a leader the quorum
    /// already declared failed, so the certificates travel with the state they
    /// apply to. Each is verified against the set active at its round.
    pub fences: Vec<FenceCertificate>,
    /// Round-skip proofs the sender adopted, including those below its floor.
    ///
    /// A tail vertex can name a control payload whose digest is not a batch.
    /// Carrying the proofs with the state gives the joiner the same decision
    /// inputs the sender used, instead of relying on a live rebroadcast that may
    /// already be gone. Each is verified against the set and the vertices the
    /// joiner holds.
    pub round_skips: Vec<RoundSkipProof>,
    /// Decision round the joiner resumes from.
    pub cursor: u64,
    /// Rounds at or below this are covered by `state` and are not transferred.
    pub floor: Option<u64>,
    /// Vertices above the floor.
    pub vertices: Vec<Vertex>,
    /// Batches named by those vertices.
    pub batches: Vec<Batch>,
}

/// What a frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// The opening frame, naming the chain.
    Hello(Hello),
    /// A broadcast vertex.
    Vertex(Vertex),
    /// A request for one vertex, named by id.
    Want(VertexId),
    /// A request for the vertex one author authored in one round.
    ///
    /// The missing-reference scan cannot find a vote that was broadcast while
    /// this node was down and is not named by any later reference; the requester
    /// knows only the round and the author from the set.
    WantSlot {
        /// Round the requested vertex must be in.
        round: u64,
        /// Validator that authored the requested vertex.
        author: Vec<u8>,
    },
    /// A batch a vertex names, sent on the data plane.
    Payload(Batch),
    /// A protocol payload a vertex names, carrying the same causal weight as a
    /// batch.
    ///
    /// The first such payload is a round-skip certificate. The frame is the data
    /// plane for that payload; the vertex that names its digest is what gives it
    /// a position in the DAG.
    Control(Box<ControlPayload>),
    /// One validator's signature over one header.
    Share(Share),
    /// A request for a state snapshot, sent on a dedicated snapshot link.
    SnapshotWant,
    /// A state snapshot response.
    Snapshot(Box<Snapshot>),
    /// The peer cannot serve a snapshot right now, with the reason.
    ///
    /// A joining node uses this to fail over to another peer instead of waiting
    /// for the snapshot read timeout. The reason is diagnostic, not trusted.
    SnapshotDeclined(String),
    /// The joiner installed a snapshot and no longer needs its floor pinned.
    ///
    /// The floor is the one the adopted snapshot reported. A server keeps the
    /// pin for a short grace window after this frame, because another joiner may
    /// still be installing the same snapshot.
    SnapshotRelease {
        /// Floor of the snapshot the joiner adopted.
        floor: u64,
    },
    /// One encoded transaction envelope, gossiped so a peer can track it.
    ///
    /// The frame carries the canonical envelope, not a decoded transaction:
    /// the receiver re-checks the chain, policy, and signature before it is
    /// admitted, so a gossiped frame has the same trust as a client submission.
    Tx(Vec<u8>),
    /// A validator-set transition certificate signed by the old-set quorum.
    ///
    /// The certificate carries the new set and is verified against the old set
    /// the receiver already holds; activation is a separate step.
    SetChange(Box<TransitionCertificate>),
    /// One validator's pruning floor, gossiped so peers can see what history it
    /// can still serve.
    ///
    /// A floor of `Some(r)` means every round at or below `r` has been pruned by
    /// the sender: a want for a vertex there cannot be answered. The value is
    /// diagnostic until a consumer acts on it, so the receiver records it per
    /// peer rather than trusting it for any safety decision. The sender names
    /// itself because the link handshake identifies the chain, not the identity.
    Floor {
        /// Validator that owns this floor, as the sender reports it.
        validator: Vec<u8>,
        /// Highest pruned round, or `None` before the first checkpoint.
        floor: Option<u64>,
    },
    /// A quorum declaration that one validator is failed from a round onward.
    Fence(Box<FenceCertificate>),
    /// Evidence that a leader round cannot reach a vote quorum.
    ///
    /// The proof partitions the voter set into held votes, held non-votes,
    /// promises, fenced absent voters, and missing voters. A receiver verifies
    /// it against its own DAG and rebroadcasts it, so a node that missed the
    /// original frame can still adopt the same decision.
    RoundSkip(Box<RoundSkipProof>),
    /// Opaque view request; not authenticated by this codec.
    AgreementViewRequest(Vec<u8>),
    /// Nonempty collection of opaque view requests; not authenticated by this codec.
    AgreementViewCertificate(Vec<Vec<u8>>),
    /// Opaque nil vote; not authenticated by this codec.
    AgreementNilVote(Vec<u8>),
    /// Opaque agreement data and supporting vertices, without authentication or activation.
    AgreementCarrier {
        /// Uninterpreted agreement envelope.
        envelope: Vec<u8>,
        /// Supporting vertices; signatures are not checked by this codec.
        vertices: Vec<Vertex>,
    },
}

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Nanoseconds since the sender's mesh started, as the sender saw them.
    pub sent_at_nanos: u64,
    /// Bytes this frame occupied on the wire, length prefix included.
    pub len: usize,
    /// What the frame carries.
    pub message: Message,
}

fn truncated(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::TruncatedInput, detail)
}

fn invalid(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::InvalidVertex, detail)
}

fn encode_id(id: &VertexId) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = Encoder::with_capacity(48);
    encoder.put_u64(id.round);
    encoder.put_bytes(&id.author)?;
    // `put_bytes`, not `put_raw`: the decoder reads a length prefix.
    encoder.put_bytes(&id.digest)?;
    Ok(encoder.finish())
}

fn decode_id(decoder: &mut Decoder<'_>) -> Result<VertexId, CryptoError> {
    let round = decoder.read_u64()?;
    let author = decoder.read_bytes()?.to_vec();
    let digest: [u8; 32] = decoder
        .read_bytes()?
        .try_into()
        .map_err(|_| truncated("vertex id digest is not 32 bytes"))?;
    Ok(VertexId {
        round,
        author,
        digest,
    })
}

fn encode_share(share: &Share) -> Result<Vec<u8>, CryptoError> {
    let header = share.header.encode()?;
    let signer = u32::try_from(share.signer).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "share signer does not fit a u32",
        )
    })?;
    let mut encoder = Encoder::with_capacity(header.len() + share.signature.len() + 24);
    encoder.put_bytes(&header)?;
    encoder.put_u32(signer);
    encoder.put_bytes(&share.signature)?;
    encoder.put_u64(share.at);
    Ok(encoder.finish())
}

fn decode_share(payload: &[u8]) -> Result<Share, CryptoError> {
    let mut decoder = Decoder::new(payload);
    let header = Header::decode(decoder.read_bytes()?)?;
    let signer = decoder.read_u32()? as usize;
    let signature = decoder.read_bytes()?.to_vec();
    let at = decoder.read_u64()?;
    decoder.finish()?;
    Ok(Share {
        header,
        signer,
        signature,
        at,
    })
}

fn count(value: usize, what: &str) -> Result<u32, CryptoError> {
    u32::try_from(value).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{what} count does not fit a u32"),
        )
    })
}

fn agreement_bound(value: usize, cap: usize, what: &str) -> Result<(), CryptoError> {
    if value > cap {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("agreement {what} exceeds the {cap} cap"),
        ));
    }
    Ok(())
}

fn agreement_size_add(size: &mut usize, extra: usize) -> Result<(), CryptoError> {
    *size = size.checked_add(extra).ok_or_else(|| {
        CryptoError::new(CryptoErrorKind::FieldTooLong, "agreement size overflows")
    })?;
    agreement_bound(*size, MAX_AGREEMENT_PAYLOAD, "payload")
}

fn encode_view_certificate(items: &[Vec<u8>]) -> Result<Vec<u8>, CryptoError> {
    agreement_bound(
        items.len(),
        MAX_AGREEMENT_VIEW_REQUESTS,
        "view request count",
    )?;
    if items.is_empty() {
        return Err(invalid("empty agreement view certificate"));
    }
    let mut size = 4usize;
    for item in items {
        agreement_bound(item.len(), MAX_AGREEMENT_ENVELOPE, "envelope")?;
        size = size.checked_add(4 + item.len()).ok_or_else(|| {
            CryptoError::new(CryptoErrorKind::FieldTooLong, "agreement size overflows")
        })?;
        agreement_bound(size, MAX_AGREEMENT_ENVELOPE, "view certificate payload")?;
    }
    let mut encoder = Encoder::with_capacity(size);
    encoder.put_u32(count(items.len(), "agreement view request")?);
    for item in items {
        encoder.put_bytes(item)?;
    }
    Ok(encoder.finish())
}

fn decode_view_certificate(payload: &[u8]) -> Result<Message, CryptoError> {
    agreement_bound(
        payload.len(),
        MAX_AGREEMENT_ENVELOPE,
        "view certificate payload",
    )?;
    let mut decoder = Decoder::new(payload);
    let count = decoder.read_u32()? as usize;
    agreement_bound(count, MAX_AGREEMENT_VIEW_REQUESTS, "view request count")?;
    if count == 0 {
        return Err(invalid("empty agreement view certificate"));
    }
    // Validate the entire structure before allocating any envelopes or the collection.
    for _ in 0..count {
        agreement_bound(
            decoder.read_bytes()?.len(),
            MAX_AGREEMENT_ENVELOPE,
            "envelope",
        )?;
    }
    decoder.finish()?;
    let mut decoder = Decoder::new(payload);
    decoder.read_u32()?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        items.push(decoder.read_bytes()?.to_vec());
    }
    decoder.finish()?;
    Ok(Message::AgreementViewCertificate(items))
}

fn encode_agreement(envelope: &[u8], vertices: &[Vertex]) -> Result<Vec<u8>, CryptoError> {
    agreement_bound(envelope.len(), MAX_AGREEMENT_ENVELOPE, "envelope")?;
    agreement_bound(vertices.len(), MAX_AGREEMENT_VERTICES, "vertex count")?;
    let mut size = 8 + envelope.len();
    let mut edges = 0;
    // Preflight the canonical vertex layout before allocating encoded vertices.
    for vertex in vertices {
        edges += vertex.references.len();
        agreement_bound(edges, MAX_AGREEMENT_EDGES, "edge count")?;
        agreement_size_add(&mut size, 4 + 70)?;
        for field in [&vertex.chain_id, &vertex.author, &vertex.signature] {
            agreement_size_add(&mut size, field.len())?;
        }
        for reference in &vertex.references {
            agreement_size_add(&mut size, 48)?;
            agreement_size_add(&mut size, reference.author.len())?;
        }
    }
    let mut encoder = Encoder::with_capacity(size);
    encoder.put_bytes(envelope)?;
    encoder.put_u32(count(vertices.len(), "agreement vertex")?);
    for vertex in vertices {
        encoder.put_bytes(&vertex.encode()?)?;
    }
    Ok(encoder.finish())
}

fn decode_agreement(payload: &[u8]) -> Result<Message, CryptoError> {
    agreement_bound(payload.len(), MAX_AGREEMENT_PAYLOAD, "payload")?;
    let mut decoder = Decoder::new(payload);
    let envelope = decoder.read_bytes()?;
    agreement_bound(envelope.len(), MAX_AGREEMENT_ENVELOPE, "envelope")?;
    let count = decoder.read_u32()? as usize;
    agreement_bound(count, MAX_AGREEMENT_VERTICES, "vertex count")?;
    let mut vertices = Vec::new();
    let mut edges = 0usize;
    for _ in 0..count {
        let bytes = decoder.read_bytes()?;
        // Inspect the reference count before the vertex decoder allocates references.
        let mut header = Decoder::new(bytes);
        header.read_u16()?;
        header.read_bytes()?;
        header.read_u64()?;
        header.read_u64()?;
        header.read_bytes()?;
        header.read_bytes()?;
        edges = edges
            .checked_add(header.read_u32()? as usize)
            .ok_or_else(|| {
                CryptoError::new(
                    CryptoErrorKind::FieldTooLong,
                    "agreement edge count overflows",
                )
            })?;
        agreement_bound(edges, MAX_AGREEMENT_EDGES, "edge count")?;
        vertices.push(Vertex::decode(bytes)?);
    }
    decoder.finish()?;
    Ok(Message::AgreementCarrier {
        envelope: envelope.to_vec(),
        vertices,
    })
}

fn encode_snapshot(snapshot: &Snapshot) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = Encoder::with_capacity(64 + snapshot.state.len());
    encoder.put_bytes(&snapshot.state)?;
    encoder.put_u64(
        u64::try_from(snapshot.order_len)
            .map_err(|_| invalid("snapshot order length does not fit a u64".to_string()))?,
    );
    encoder.put_u64(
        u64::try_from(snapshot.prefix.len())
            .map_err(|_| invalid("snapshot prefix length does not fit a u64".to_string()))?,
    );
    encoder.put_u32(
        u32::try_from(snapshot.prefix.peaks().len())
            .map_err(|_| invalid("snapshot peak count does not fit a u32".to_string()))?,
    );
    for peak in snapshot.prefix.peaks() {
        encoder.put_bytes(peak)?;
    }
    encoder.put_u32(count(snapshot.order.len(), "order")?);
    for id in &snapshot.order {
        encoder.put_bytes(&encode_id(id)?)?;
    }
    encoder.put_bytes(&snapshot.anchor.encode()?)?;
    encoder.put_bytes(&snapshot.certificate.encode()?)?;
    match &snapshot.transition {
        None => encoder.put_u8(0),
        Some(transition) => {
            encoder.put_u8(1);
            encoder.put_bytes(&transition.encode()?)?;
        }
    }
    encoder.put_u32(count(snapshot.fences.len(), "fence")?);
    for certificate in &snapshot.fences {
        encoder.put_bytes(&certificate.encode()?)?;
    }
    encoder.put_u32(count(snapshot.round_skips.len(), "round skip")?);
    for proof in &snapshot.round_skips {
        encoder.put_bytes(&proof.encode()?)?;
    }
    encoder.put_u64(snapshot.cursor);
    match snapshot.floor {
        None => encoder.put_u8(0),
        Some(floor) => {
            encoder.put_u8(1);
            encoder.put_u64(floor);
        }
    }
    encoder.put_u32(count(snapshot.vertices.len(), "vertex")?);
    for vertex in &snapshot.vertices {
        encoder.put_bytes(&vertex.encode()?)?;
    }
    encoder.put_u32(count(snapshot.batches.len(), "batch")?);
    for batch in &snapshot.batches {
        encoder.put_bytes(&batch.encode()?)?;
    }
    Ok(encoder.finish())
}
fn decode_snapshot(payload: &[u8]) -> Result<Snapshot, CryptoError> {
    let mut decoder = Decoder::new(payload);
    let state = decoder.read_bytes()?.to_vec();
    let order_len = usize::try_from(decoder.read_u64()?)
        .map_err(|_| invalid("snapshot order length does not fit this host".to_string()))?;
    let prefix_len = usize::try_from(decoder.read_u64()?)
        .map_err(|_| invalid("snapshot prefix length does not fit this host".to_string()))?;
    let peak_count = decoder.read_u32()? as usize;
    if peak_count > payload.len() {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{peak_count} peaks exceed the frame"),
        ));
    }
    let mut peaks = Vec::with_capacity(peak_count.min(64));
    for _ in 0..peak_count {
        let peak: [u8; 32] = decoder
            .read_bytes()?
            .try_into()
            .map_err(|_| invalid("snapshot peak is not 32 bytes".to_string()))?;
        peaks.push(peak);
    }
    let prefix = CommitFrontier::from_peaks(prefix_len, peaks)?;
    let order_count = decoder.read_u32()? as usize;
    if order_count > MAX_FRAME {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{order_count} order entries exceed the frame cap"),
        ));
    }
    let mut order = Vec::with_capacity(order_count.min(1024));
    for _ in 0..order_count {
        order.push(decode_id(&mut Decoder::new(decoder.read_bytes()?))?);
    }
    if prefix.len().checked_add(order.len()) != Some(order_len) {
        return Err(invalid(
            "snapshot order length does not match its prefix and tail".to_string(),
        ));
    }
    let anchor = Header::decode(decoder.read_bytes()?)?;
    let certificate = Certificate::decode(decoder.read_bytes()?)?;
    let transition = match decoder.read_u8()? {
        0 => None,
        1 => Some(TransitionCertificate::decode(decoder.read_bytes()?)?),
        other => return Err(invalid(format!("unknown snapshot transition flag {other}"))),
    };
    let fence_count = decoder.read_u32()? as usize;
    if fence_count > MAX_FRAME {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{fence_count} fences exceed the frame cap"),
        ));
    }
    let mut fences = Vec::with_capacity(fence_count.min(64));
    for _ in 0..fence_count {
        fences.push(FenceCertificate::decode(decoder.read_bytes()?)?);
    }
    let skip_count = decoder.read_u32()? as usize;
    if skip_count > MAX_FRAME {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{skip_count} round skips exceed the frame cap"),
        ));
    }
    let mut round_skips = Vec::with_capacity(skip_count.min(64));
    for _ in 0..skip_count {
        round_skips.push(RoundSkipProof::decode(decoder.read_bytes()?)?);
    }
    let cursor = decoder.read_u64()?;
    let floor = match decoder.read_u8()? {
        0 => None,
        1 => Some(decoder.read_u64()?),
        other => return Err(invalid(format!("unknown snapshot floor flag {other}"))),
    };
    let vertex_count = decoder.read_u32()? as usize;
    if vertex_count > MAX_FRAME {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{vertex_count} vertices exceed the frame cap"),
        ));
    }
    let mut vertices = Vec::with_capacity(vertex_count.min(1024));
    for _ in 0..vertex_count {
        vertices.push(Vertex::decode(decoder.read_bytes()?)?);
    }
    let batch_count = decoder.read_u32()? as usize;
    if batch_count > MAX_FRAME {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{batch_count} batches exceed the frame cap"),
        ));
    }
    let mut batches = Vec::with_capacity(batch_count.min(1024));
    for _ in 0..batch_count {
        batches.push(Batch::decode(decoder.read_bytes()?)?);
    }
    decoder.finish()?;
    Ok(Snapshot {
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
        batches,
    })
}

/// Encodes one message into a length-prefixed frame.
///
/// # Errors
///
/// Propagates the vertex encoding, and [`CryptoErrorKind::FieldTooLong`] when the
/// body does not fit the length field.
pub fn frame(message: &Message, sent_at_nanos: u64) -> Result<Vec<u8>, CryptoError> {
    let (kind, payload) = match message {
        Message::Hello(hello) => {
            let mut encoder = Encoder::with_capacity(2 + 4 + hello.chain_id.len());
            encoder.put_u16(hello.protocol);
            encoder.put_bytes(&hello.chain_id)?;
            (KIND_HELLO, encoder.finish())
        }
        Message::Vertex(vertex) => (KIND_VERTEX, vertex.encode()?),
        Message::Want(id) => (KIND_WANT, encode_id(id)?),
        Message::WantSlot { round, author } => {
            let mut encoder = Encoder::with_capacity(8 + 4 + author.len());
            encoder.put_u64(*round);
            encoder.put_bytes(author)?;
            (KIND_WANT_SLOT, encoder.finish())
        }
        Message::Payload(batch) => (KIND_PAYLOAD, batch.encode()?),
        Message::Control(payload) => (KIND_CONTROL, payload.encode()?),
        Message::Share(share) => (KIND_SHARE, encode_share(share)?),
        Message::SnapshotWant => (KIND_SNAPSHOT_WANT, Vec::new()),
        Message::Snapshot(snapshot) => (KIND_SNAPSHOT, encode_snapshot(snapshot)?),
        Message::SnapshotDeclined(reason) => {
            let mut encoder = Encoder::with_capacity(4 + reason.len());
            encoder.put_bytes(reason.as_bytes())?;
            (KIND_SNAPSHOT_DECLINED, encoder.finish())
        }
        Message::SnapshotRelease { floor } => {
            let mut encoder = Encoder::with_capacity(8);
            encoder.put_u64(*floor);
            (KIND_SNAPSHOT_RELEASE, encoder.finish())
        }
        Message::Tx(envelope) => (KIND_TX, {
            let mut encoder = Encoder::with_capacity(4 + envelope.len());
            encoder.put_bytes(envelope)?;
            encoder.finish()
        }),
        Message::SetChange(certificate) => (KIND_SET_CHANGE, certificate.encode()?),
        Message::Floor { validator, floor } => {
            let mut encoder = Encoder::with_capacity(4 + validator.len() + 9);
            encoder.put_bytes(validator)?;
            match floor {
                None => encoder.put_u8(0),
                Some(floor) => {
                    encoder.put_u8(1);
                    encoder.put_u64(*floor);
                }
            }
            (KIND_FLOOR, encoder.finish())
        }
        Message::AgreementViewRequest(envelope) | Message::AgreementNilVote(envelope) => {
            agreement_bound(envelope.len(), MAX_AGREEMENT_ENVELOPE, "envelope")?;
            let kind = if matches!(message, Message::AgreementViewRequest(_)) {
                KIND_AGREEMENT_VIEW_REQUEST
            } else {
                KIND_AGREEMENT_NIL_VOTE
            };
            (kind, envelope.clone())
        }
        Message::AgreementViewCertificate(items) => (
            KIND_AGREEMENT_VIEW_CERTIFICATE,
            encode_view_certificate(items)?,
        ),
        Message::Fence(certificate) => (KIND_FENCE, certificate.encode()?),
        Message::RoundSkip(proof) => (KIND_ROUND_SKIP, proof.encode()?),
        Message::AgreementCarrier { envelope, vertices } => (
            KIND_AGREEMENT_CARRIER,
            encode_agreement(envelope, vertices)?,
        ),
    };
    let length = u32::try_from(8 + 1 + payload.len()).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "frame does not fit a u32 length",
        )
    })?;
    let mut bytes = Vec::with_capacity(HEADER + payload.len());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&sent_at_nanos.to_le_bytes());
    bytes.push(kind);
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

/// Takes one complete frame off the front of `buffer`, if there is one.
///
/// Returns `Ok(None)` and leaves `buffer` untouched when fewer bytes have arrived
/// than the frame needs. That is an ordinary event on a stream, not an error; the
/// caller reads more and asks again.
///
/// # Errors
///
/// [`CryptoErrorKind::TruncatedInput`] when a complete frame is shorter than its
/// own header, [`CryptoErrorKind::FieldTooLong`] when the declared length exceeds
/// [`MAX_FRAME`], [`CryptoErrorKind::InvalidVertex`] for an unknown kind, and
/// anything the payload codecs report.
pub fn take_frame(buffer: &mut Vec<u8>) -> Result<Option<Frame>, CryptoError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let body_len = u32::from_le_bytes([buffer[0], buffer[1], buffer[2], buffer[3]]) as usize;
    if body_len > MAX_FRAME {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("frame of {body_len} bytes exceeds the {MAX_FRAME}-byte cap"),
        ));
    }
    let total = 4usize
        .checked_add(body_len)
        .ok_or_else(|| truncated("frame length overflows"))?;
    if body_len >= HEADER - 4 && buffer.len() >= HEADER {
        let cap = match buffer[HEADER - 1] {
            KIND_AGREEMENT_CARRIER => Some(MAX_AGREEMENT_PAYLOAD),
            KIND_AGREEMENT_VIEW_REQUEST
            | KIND_AGREEMENT_VIEW_CERTIFICATE
            | KIND_AGREEMENT_NIL_VOTE => Some(MAX_AGREEMENT_ENVELOPE),
            _ => None,
        };
        if let Some(cap) = cap {
            agreement_bound(body_len - (HEADER - 4), cap, "payload")?;
        }
    }
    if buffer.len() < total {
        return Ok(None);
    }
    if body_len < HEADER - 4 {
        return Err(truncated("frame is shorter than its own header"));
    }
    let mut sent_at_nanos = [0u8; 8];
    sent_at_nanos.copy_from_slice(&buffer[4..12]);
    let kind = buffer[12];
    let payload = &buffer[HEADER..total];
    let message = match kind {
        KIND_HELLO => {
            let mut decoder = Decoder::new(payload);
            let protocol = decoder.read_u16()?;
            let chain_id = decoder.read_bytes()?.to_vec();
            decoder.finish()?;
            Message::Hello(Hello { protocol, chain_id })
        }
        KIND_VERTEX => Message::Vertex(Vertex::decode(payload)?),
        KIND_WANT => Message::Want(decode_id(&mut Decoder::new(payload))?),
        KIND_WANT_SLOT => {
            let mut decoder = Decoder::new(payload);
            let round = decoder.read_u64()?;
            let author = decoder.read_bytes()?.to_vec();
            decoder.finish()?;
            Message::WantSlot { round, author }
        }
        KIND_PAYLOAD => Message::Payload(Batch::decode(payload)?),
        KIND_CONTROL => Message::Control(Box::new(ControlPayload::decode(payload)?)),
        KIND_SHARE => Message::Share(decode_share(payload)?),
        KIND_SNAPSHOT_WANT => {
            if !payload.is_empty() {
                return Err(CryptoError::new(
                    CryptoErrorKind::TrailingBytes,
                    "a snapshot request carries no payload",
                ));
            }
            Message::SnapshotWant
        }
        KIND_SNAPSHOT => Message::Snapshot(Box::new(decode_snapshot(payload)?)),
        KIND_SNAPSHOT_DECLINED => {
            let mut decoder = Decoder::new(payload);
            let reason = String::from_utf8(decoder.read_bytes()?.to_vec())
                .map_err(|_| invalid("snapshot decline reason is not UTF-8".to_string()))?;
            decoder.finish()?;
            Message::SnapshotDeclined(reason)
        }
        KIND_SNAPSHOT_RELEASE => {
            let mut decoder = Decoder::new(payload);
            let floor = decoder.read_u64()?;
            decoder.finish()?;
            Message::SnapshotRelease { floor }
        }
        KIND_TX => {
            let mut decoder = Decoder::new(payload);
            let envelope = decoder.read_bytes()?.to_vec();
            decoder.finish()?;
            Message::Tx(envelope)
        }
        KIND_SET_CHANGE => Message::SetChange(Box::new(TransitionCertificate::decode(payload)?)),
        KIND_FLOOR => {
            let mut decoder = Decoder::new(payload);
            let validator = decoder.read_bytes()?.to_vec();
            let floor = match decoder.read_u8()? {
                0 => None,
                1 => Some(decoder.read_u64()?),
                other => return Err(invalid(format!("unknown floor flag {other}"))),
            };
            decoder.finish()?;
            Message::Floor { validator, floor }
        }
        KIND_FENCE => Message::Fence(Box::new(FenceCertificate::decode(payload)?)),
        KIND_ROUND_SKIP => Message::RoundSkip(Box::new(RoundSkipProof::decode(payload)?)),
        KIND_AGREEMENT_CARRIER => decode_agreement(payload)?,
        KIND_AGREEMENT_VIEW_REQUEST => Message::AgreementViewRequest(payload.to_vec()),
        KIND_AGREEMENT_VIEW_CERTIFICATE => decode_view_certificate(payload)?,
        KIND_AGREEMENT_NIL_VOTE => Message::AgreementNilVote(payload.to_vec()),
        other => return Err(invalid(format!("unknown frame kind {other}"))),
    };
    buffer.drain(..total);
    Ok(Some(Frame {
        sent_at_nanos: u64::from_le_bytes(sent_at_nanos),
        len: total,
        message,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::registry::ALG_ED25519;
    use validator::{
        Fence, FenceCertificate, NO_EXPIRY, NoVoteAttestation, RoundSkip, SetChange, ValidatorKey,
        ValidatorRecord, ValidatorSet,
    };

    fn vertex(round: u64) -> Vertex {
        // Signatures are not checked by the codec, so a placeholder is enough here.
        Vertex {
            chain_id: b"karsa-wire-1".to_vec(),
            epoch: 1,
            round,
            author: b"val-0".to_vec(),
            payload_hash: [round as u8; 32],
            references: Vec::new(),
            signature: vec![9u8; 64],
        }
    }

    fn want(round: u64) -> VertexId {
        VertexId {
            round,
            author: b"val-2".to_vec(),
            digest: [round as u8; 32],
        }
    }

    fn opaque_frame(kind: u8, payload: &[u8]) -> Vec<u8> {
        let mut bytes = agreement_frame(payload);
        bytes[HEADER - 1] = kind;
        bytes
    }

    #[test]
    fn opaque_agreement_messages_round_trip_fragmented() {
        for message in [
            Message::AgreementViewRequest(vec![0, 255, 7]),
            Message::AgreementViewCertificate(vec![vec![0, 255], vec![], vec![7]]),
            Message::AgreementNilVote(vec![0, 255, 7]),
        ] {
            let bytes = frame(&message, 42).unwrap();
            let mut buffer = Vec::new();
            for byte in &bytes[..bytes.len() - 1] {
                buffer.push(*byte);
                let before = buffer.clone();
                assert_eq!(take_frame(&mut buffer).unwrap(), None);
                assert_eq!(buffer, before);
            }
            buffer.push(*bytes.last().unwrap());
            let decoded = take_frame(&mut buffer).unwrap().unwrap();
            assert_eq!(decoded.message, message);
            assert_eq!(decoded.sent_at_nanos, 42);
            assert_eq!(decoded.len, bytes.len());
            assert!(buffer.is_empty());
        }
    }

    #[test]
    fn opaque_agreement_envelope_bounds_and_raw_layout() {
        for (kind, make) in [
            (
                KIND_AGREEMENT_VIEW_REQUEST,
                Message::AgreementViewRequest as fn(Vec<u8>) -> Message,
            ),
            (KIND_AGREEMENT_NIL_VOTE, Message::AgreementNilVote),
        ] {
            for len in [0, MAX_AGREEMENT_ENVELOPE] {
                let message = make(vec![255; len]);
                let mut bytes = frame(&message, 0).unwrap();
                assert_eq!(bytes.len(), HEADER + len);
                assert_eq!(bytes[12], kind);
                assert_eq!(take_frame(&mut bytes).unwrap().unwrap().message, message);
            }
            let oversized = vec![0; MAX_AGREEMENT_ENVELOPE + 1];
            assert_eq!(
                frame(&make(oversized.clone()), 0).unwrap_err().kind(),
                CryptoErrorKind::FieldTooLong
            );
            assert_eq!(
                take_frame(&mut opaque_frame(kind, &oversized))
                    .unwrap_err()
                    .kind(),
                CryptoErrorKind::FieldTooLong
            );
        }
    }

    #[test]
    fn view_certificate_size_and_count_bounds() {
        for items in [
            vec![vec![0; MAX_AGREEMENT_ENVELOPE - 8]],
            vec![vec![]; MAX_AGREEMENT_VIEW_REQUESTS],
        ] {
            let message = Message::AgreementViewCertificate(items);
            let mut bytes = frame(&message, 0).unwrap();
            assert_eq!(take_frame(&mut bytes).unwrap().unwrap().message, message);
        }
        for items in [
            vec![],
            vec![vec![]; MAX_AGREEMENT_VIEW_REQUESTS + 1],
            vec![vec![0; MAX_AGREEMENT_ENVELOPE - 7]],
            vec![vec![0; MAX_AGREEMENT_ENVELOPE + 1]],
            vec![vec![0; MAX_AGREEMENT_ENVELOPE / 2]; 2],
        ] {
            assert!(frame(&Message::AgreementViewCertificate(items), 0).is_err());
        }
        for count in [0, (MAX_AGREEMENT_VIEW_REQUESTS + 1) as u32, u32::MAX] {
            assert!(
                take_frame(&mut opaque_frame(
                    KIND_AGREEMENT_VIEW_CERTIFICATE,
                    &count.to_le_bytes()
                ))
                .is_err()
            );
        }
        let oversized = vec![0; MAX_AGREEMENT_ENVELOPE + 1];
        assert_eq!(
            decode_view_certificate(&oversized).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
    }

    #[test]
    fn view_certificate_above_1024_entries_fits_the_byte_budget() {
        let message = Message::AgreementViewCertificate(vec![vec![7; 256]; 1025]);
        let mut bytes = frame(&message, 0).unwrap();
        assert_eq!(take_frame(&mut bytes).unwrap().unwrap().message, message);
        assert!(bytes.is_empty());
    }

    #[test]
    fn view_certificate_malformed_and_trailing_are_rejected() {
        let payload = encode_view_certificate(&[vec![0, 255], vec![7]]).unwrap();
        assert_eq!(&payload[..4], &2u32.to_le_bytes());
        for end in 0..payload.len() {
            assert!(
                take_frame(&mut opaque_frame(
                    KIND_AGREEMENT_VIEW_CERTIFICATE,
                    &payload[..end]
                ))
                .is_err()
            );
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert_eq!(
            take_frame(&mut opaque_frame(
                KIND_AGREEMENT_VIEW_CERTIFICATE,
                &trailing
            ))
            .unwrap_err()
            .kind(),
            CryptoErrorKind::TrailingBytes
        );
        let mut malformed = payload;
        malformed[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(
            take_frame(&mut opaque_frame(
                KIND_AGREEMENT_VIEW_CERTIFICATE,
                &malformed
            ))
            .is_err()
        );
    }

    #[test]
    fn opaque_agreement_caps_reject_at_header_and_kind() {
        for kind in [
            KIND_AGREEMENT_VIEW_REQUEST,
            KIND_AGREEMENT_VIEW_CERTIFICATE,
            KIND_AGREEMENT_NIL_VOTE,
        ] {
            for extra in [0, 1] {
                let mut prefix = ((9 + MAX_AGREEMENT_ENVELOPE + extra) as u32)
                    .to_le_bytes()
                    .to_vec();
                prefix.extend_from_slice(&0u64.to_le_bytes());
                assert_eq!(take_frame(&mut prefix).unwrap(), None);
                prefix.push(kind);
                let before = prefix.clone();
                if extra == 0 {
                    assert_eq!(take_frame(&mut prefix).unwrap(), None);
                } else {
                    assert_eq!(
                        take_frame(&mut prefix).unwrap_err().kind(),
                        CryptoErrorKind::FieldTooLong
                    );
                }
                assert_eq!(prefix, before);
            }
        }
    }

    fn agreement_frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&(9 + payload.len() as u32).to_le_bytes());
        bytes.extend_from_slice(&42u64.to_le_bytes());
        bytes.push(KIND_AGREEMENT_CARRIER);
        bytes.extend_from_slice(payload);
        bytes
    }

    #[test]
    fn an_agreement_carrier_round_trips_fragmented() {
        let message = Message::AgreementCarrier {
            envelope: vec![0, 255, 7],
            vertices: vec![vertex(1), vertex(2)],
        };
        let bytes = frame(&message, 42).unwrap();
        let mut buffer = Vec::new();
        for byte in &bytes[..bytes.len() - 1] {
            buffer.push(*byte);
            let before = buffer.clone();
            assert_eq!(take_frame(&mut buffer).unwrap(), None);
            assert_eq!(buffer, before);
        }
        buffer.push(*bytes.last().unwrap());
        let decoded = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(decoded.message, message);
        assert_eq!(decoded.sent_at_nanos, 42);
        assert_eq!(decoded.len, bytes.len());
        assert!(buffer.is_empty());
    }

    #[test]
    fn agreement_malformed_and_trailing_bytes_are_rejected() {
        let payload = encode_agreement(b"opaque", &[vertex(1)]).unwrap();
        for end in 0..payload.len() {
            assert!(take_frame(&mut agreement_frame(&payload[..end])).is_err());
        }
        let mut trailing = payload.clone();
        trailing.push(0);
        assert_eq!(
            take_frame(&mut agreement_frame(&trailing))
                .unwrap_err()
                .kind(),
            CryptoErrorKind::TrailingBytes
        );
        let mut malformed = payload;
        // Envelope length prefix, envelope, and vertex count precede vertex length.
        let version_offset = 4 + b"opaque".len() + 4 + 4;
        malformed[version_offset..version_offset + 2].copy_from_slice(&u16::MAX.to_le_bytes());
        assert!(take_frame(&mut agreement_frame(&malformed)).is_err());
    }

    #[test]
    fn agreement_envelope_and_vertex_caps_apply_in_both_directions() {
        let envelope = vec![0; MAX_AGREEMENT_ENVELOPE];
        assert!(encode_agreement(&envelope, &[]).is_ok());
        let oversized = vec![0; MAX_AGREEMENT_ENVELOPE + 1];
        assert_eq!(
            encode_agreement(&oversized, &[]).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        let mut payload = ((oversized.len()) as u32).to_le_bytes().to_vec();
        payload.extend_from_slice(&oversized);
        payload.extend_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            decode_agreement(&payload).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert!(encode_agreement(&[], &vec![vertex(1); MAX_AGREEMENT_VERTICES]).is_ok());
        assert_eq!(
            encode_agreement(&[], &vec![vertex(1); MAX_AGREEMENT_VERTICES + 1])
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
        let mut encoder = Encoder::with_capacity(8);
        encoder.put_bytes(&[]).unwrap();
        encoder.put_u32((MAX_AGREEMENT_VERTICES + 1) as u32);
        assert_eq!(
            decode_agreement(&encoder.finish()).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
    }

    #[test]
    fn agreement_size_and_edge_preflight_are_bounded() {
        let mut large = vertex(1);
        large.signature = vec![0; MAX_AGREEMENT_PAYLOAD];
        assert_eq!(
            encode_agreement(&[], &[large]).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        let mut many_edges = vertex(1);
        many_edges.references = vec![want(1); MAX_AGREEMENT_EDGES + 1];
        assert_eq!(
            encode_agreement(&[], &[many_edges]).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        let mut encoded = vertex(1).encode().unwrap();
        let count_offset = 2 + 4 + b"karsa-wire-1".len() + 16 + 4 + b"val-0".len() + 36;
        encoded[count_offset..count_offset + 4]
            .copy_from_slice(&((MAX_AGREEMENT_EDGES + 1) as u32).to_le_bytes());
        let mut encoder = Encoder::with_capacity(encoded.len() + 12);
        encoder.put_bytes(&[]).unwrap();
        encoder.put_u32(1);
        encoder.put_bytes(&encoded).unwrap();
        assert_eq!(
            decode_agreement(&encoder.finish()).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
    }

    #[test]
    fn agreement_cumulative_edge_count_rejects_u32_max() {
        let mut first = vertex(1);
        first.references.push(want(1));
        let mut second = vertex(2).encode().unwrap();
        let count_offset = 2 + 4 + b"karsa-wire-1".len() + 16 + 4 + b"val-0".len() + 36;
        second[count_offset..count_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        let mut encoder = Encoder::new();
        encoder.put_bytes(&[]).unwrap();
        encoder.put_u32(2);
        encoder.put_bytes(&first.encode().unwrap()).unwrap();
        encoder.put_bytes(&second).unwrap();
        assert_eq!(
            decode_agreement(&encoder.finish()).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
    }

    #[test]
    fn oversized_agreement_is_rejected_from_header_and_kind_only() {
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&((9 + MAX_AGREEMENT_PAYLOAD + 1) as u32).to_le_bytes());
        prefix.extend_from_slice(&0u64.to_le_bytes());
        assert_eq!(take_frame(&mut prefix).unwrap(), None);
        prefix.push(KIND_AGREEMENT_CARRIER);
        let before = prefix.clone();
        assert_eq!(
            take_frame(&mut prefix).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert_eq!(prefix, before);
        prefix[12] = KIND_VERTEX;
        assert_eq!(take_frame(&mut prefix).unwrap(), None);
    }

    #[test]
    fn a_hello_names_the_chain_and_the_protocol() {
        let hello = Hello::new(vec![7u8; 32]);
        let mut buffer = frame(&Message::Hello(hello.clone()), 1).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Hello(hello));
        assert_eq!(frame.sent_at_nanos, 1);
    }

    #[test]
    fn a_hello_with_trailing_bytes_is_refused_rather_than_guessed() {
        let mut payload = Vec::new();
        let mut encoder = Encoder::with_capacity(64);
        encoder.put_u16(WIRE_PROTOCOL);
        encoder.put_bytes(&[3u8; 32]).unwrap();
        payload.extend_from_slice(encoder.as_slice());
        payload.push(0xff);

        let body = 8 + 1 + payload.len();
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&u32::try_from(body).unwrap().to_le_bytes());
        buffer.extend_from_slice(&0u64.to_le_bytes());
        buffer.push(KIND_HELLO);
        buffer.extend_from_slice(&payload);

        assert!(matches!(
            take_frame(&mut buffer),
            Err(error) if error.kind() == CryptoErrorKind::TrailingBytes
        ));
    }

    #[test]
    fn a_vertex_frame_round_trips_through_an_accumulator() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&frame(&Message::Vertex(vertex(1)), 42).unwrap());
        buffer.extend_from_slice(&frame(&Message::Vertex(vertex(2)), 43).unwrap());

        let first = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(first.sent_at_nanos, 42);
        assert_eq!(first.message, Message::Vertex(vertex(1)));

        let second = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(second.message, Message::Vertex(vertex(2)));
        assert!(buffer.is_empty());

        assert_eq!(take_frame(&mut buffer).unwrap(), None);
    }

    #[test]
    fn a_want_frame_round_trips() {
        let mut buffer = frame(&Message::Want(want(7)), 11).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Want(want(7)));
    }

    #[test]
    fn a_want_slot_frame_round_trips() {
        let request = Message::WantSlot {
            round: 91,
            author: b"val-2".to_vec(),
        };
        let mut buffer = frame(&request, 12).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, request);
    }

    #[test]
    fn a_payload_frame_round_trips() {
        let batch = tx::batch::Batch::new(vec![tx::envelope::Transaction {
            protocol_version: tx::envelope::PROTOCOL_VERSION_V1,
            chain_id: b"karsa-wire-1".to_vec(),
            sender: b"alice".to_vec(),
            sequence: 1,
            fee: 1,
            expiration: 100,
            policy_version: 1,
            payload: vec![1, 2, 3],
            authorization: Vec::new(),
        }]);
        let mut buffer = frame(&Message::Payload(batch.clone()), 5).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Payload(batch));
    }

    #[test]
    fn a_transaction_frame_round_trips() {
        let envelope = vec![7u8, 8, 9, 10];
        let mut buffer = frame(&Message::Tx(envelope.clone()), 6).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Tx(envelope));
    }

    #[test]
    fn a_snapshot_frame_round_trips() {
        let batch = tx::batch::Batch::new(vec![tx::envelope::Transaction {
            protocol_version: tx::envelope::PROTOCOL_VERSION_V1,
            chain_id: b"karsa-wire-1".to_vec(),
            sender: b"alice".to_vec(),
            sequence: 1,
            fee: 1,
            expiration: 100,
            policy_version: 1,
            payload: vec![1, 2, 3],
            authorization: Vec::new(),
        }]);
        let anchor = Header {
            chain_id: b"karsa-wire-1".to_vec(),
            epoch: 1,
            height: 4,
            round: 4,
            state_root: [3; 32],
            dag_root: [4; 32],
            previous: [5; 32],
            applied: 2,
        };
        let snapshot = Snapshot {
            state: b"encoded state".to_vec(),
            order: vec![want(1), want(2)],
            order_len: 2,
            prefix: CommitFrontier::empty(),
            anchor: anchor.clone(),
            certificate: Certificate {
                chain_id: anchor.chain_id.clone(),
                epoch: anchor.epoch,
                round: anchor.round,
                vertex_id: anchor.id().unwrap().to_vec(),
                validator_set_id: b"set".to_vec(),
                signer_bitmap: vec![0b1],
                signatures: vec![vec![9u8; 64]],
            },
            transition: Some(transition_certificate()),
            fences: vec![fence_certificate()],
            round_skips: vec![round_skip_proof()],
            cursor: 5,
            floor: Some(2),
            vertices: vec![vertex(4)],
            batches: vec![batch],
        };
        let mut buffer = frame(&Message::Snapshot(Box::new(snapshot.clone())), 13).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Snapshot(Box::new(snapshot)));
        assert_eq!(frame.sent_at_nanos, 13);
    }

    #[test]
    fn a_snapshot_decline_round_trips() {
        let reason = String::from("the state at applied 7 is no longer retained");
        let mut buffer = frame(&Message::SnapshotDeclined(reason.clone()), 14).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::SnapshotDeclined(reason));
        assert_eq!(frame.sent_at_nanos, 14);
    }

    fn transition_certificate() -> TransitionCertificate {
        let set = |epoch: u64, count: usize| ValidatorSet {
            epoch,
            validators: (0..count)
                .map(|index| ValidatorRecord {
                    validator_id: format!("val-{index}").into_bytes(),
                    keys: vec![ValidatorKey {
                        key_id: format!("val-{index}-k0").into_bytes(),
                        algorithm_id: ALG_ED25519,
                        public_key: vec![u8::try_from(index + 1).unwrap(); 32],
                        activation_epoch: 0,
                        retirement_epoch: NO_EXPIRY,
                    }],
                })
                .collect(),
        };
        let old = set(1, 1);
        let new = set(2, 2);
        let change = SetChange::new(b"karsa-wire-1".to_vec(), &old, &new).unwrap();
        TransitionCertificate {
            change,
            new_set: new,
            signer_bitmap: vec![0b1],
            signatures: vec![vec![9u8; 64]],
        }
    }

    #[test]
    fn a_set_change_frame_round_trips() {
        let certificate = transition_certificate();
        let mut buffer = frame(&Message::SetChange(Box::new(certificate.clone())), 17).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::SetChange(Box::new(certificate)));
        assert_eq!(frame.sent_at_nanos, 17);
    }

    fn fence_certificate() -> FenceCertificate {
        FenceCertificate {
            fence: Fence::new(b"karsa-wire-1".to_vec(), 7, b"val-0".to_vec()),
            signer_bitmap: vec![0b1],
            signatures: vec![vec![9u8; 64]],
        }
    }

    #[test]
    fn a_fence_frame_round_trips() {
        let certificate = fence_certificate();
        let mut buffer = frame(&Message::Fence(Box::new(certificate.clone())), 18).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Fence(Box::new(certificate)));
        assert_eq!(frame.sent_at_nanos, 18);
    }

    fn round_skip_proof() -> validator::RoundSkipProof {
        let leader = want(7);
        let mut vote = want(8);
        vote.round = 8;
        let mut non_vote = want(9);
        non_vote.round = 8;
        validator::RoundSkipProof {
            attestation: NoVoteAttestation {
                skip: RoundSkip::new(b"karsa-wire-1".to_vec(), leader),
                signer_bitmap: vec![0b1],
                signatures: vec![vec![9u8; 64]],
            },
            votes: vec![vote],
            non_votes: vec![non_vote],
            fenced_absent: vec![fence_certificate()],
            missing: vec![b"val-2".to_vec()],
        }
    }

    #[test]
    fn a_round_skip_frame_round_trips() {
        let proof = round_skip_proof();
        let mut buffer = frame(&Message::RoundSkip(Box::new(proof.clone())), 19).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::RoundSkip(Box::new(proof)));
        assert_eq!(frame.sent_at_nanos, 19);
    }

    #[test]
    fn a_snapshot_release_frame_round_trips() {
        let message = Message::SnapshotRelease { floor: 4_096 };
        let mut buffer = frame(&message, 22).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, message);
        assert_eq!(frame.sent_at_nanos, 22);
    }

    #[test]
    fn a_floor_frame_round_trips() {
        for floor in [None, Some(0), Some(4_096)] {
            let message = Message::Floor {
                validator: b"val-1".to_vec(),
                floor,
            };
            let mut buffer = frame(&message, 21).unwrap();
            let frame = take_frame(&mut buffer).unwrap().unwrap();
            assert_eq!(frame.message, message);
            assert_eq!(frame.sent_at_nanos, 21);
        }
    }

    #[test]
    fn a_control_payload_frame_round_trips() {
        let payload = ControlPayload::RoundSkip(Box::new(round_skip_proof()));
        let mut buffer = frame(&Message::Control(Box::new(payload.clone())), 20).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::Control(Box::new(payload)));
        assert_eq!(frame.sent_at_nanos, 20);
    }

    #[test]
    fn a_snapshot_request_round_trips_without_a_payload() {
        let mut buffer = frame(&Message::SnapshotWant, 3).unwrap();
        let frame = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(frame.message, Message::SnapshotWant);
    }

    #[test]
    fn both_kinds_share_one_stream() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&frame(&Message::Want(want(3)), 1).unwrap());
        buffer.extend_from_slice(&frame(&Message::Vertex(vertex(4)), 2).unwrap());

        assert!(matches!(
            take_frame(&mut buffer).unwrap().unwrap().message,
            Message::Want(_)
        ));
        assert!(matches!(
            take_frame(&mut buffer).unwrap().unwrap().message,
            Message::Vertex(_)
        ));
    }

    #[test]
    fn a_partial_frame_is_not_an_error_and_is_not_consumed() {
        let bytes = frame(&Message::Vertex(vertex(3)), 7).unwrap();
        let mut buffer = bytes[..bytes.len() - 5].to_vec();
        let before = buffer.len();

        assert_eq!(take_frame(&mut buffer).unwrap(), None);
        assert_eq!(buffer.len(), before, "an incomplete frame is left alone");

        buffer.extend_from_slice(&bytes[bytes.len() - 5..]);
        assert_eq!(
            take_frame(&mut buffer).unwrap().unwrap().message,
            Message::Vertex(vertex(3))
        );
    }

    #[test]
    fn a_length_beyond_the_cap_is_refused_before_allocating() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&(MAX_FRAME as u32 + 1).to_le_bytes());
        assert!(matches!(
            take_frame(&mut buffer),
            Err(error) if error.kind() == CryptoErrorKind::FieldTooLong
        ));
    }

    #[test]
    fn a_body_shorter_than_the_header_is_refused() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&3u32.to_le_bytes());
        buffer.extend_from_slice(&[0u8; 3]);
        assert!(matches!(
            take_frame(&mut buffer),
            Err(error) if error.kind() == CryptoErrorKind::TruncatedInput
        ));
    }

    #[test]
    fn an_unknown_kind_is_refused_rather_than_guessed() {
        let mut bytes = frame(&Message::Vertex(vertex(1)), 0).unwrap();
        bytes[12] = 0x7f;
        let mut buffer = bytes;
        assert!(matches!(
            take_frame(&mut buffer),
            Err(error) if error.kind() == CryptoErrorKind::InvalidVertex
        ));
    }
}
