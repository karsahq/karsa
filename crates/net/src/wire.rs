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
//! Ten kinds share a link:
//!
//! - [`Message::Hello`] is the first frame on a link and names the chain.
//! - [`Message::Vertex`] is the broadcast.
//! - [`Message::Want`] asks a peer for one vertex by id.
//! - [`Message::Payload`] carries the batch a vertex names, on the data plane.
//! - [`Message::Share`] carries one validator's signature over a header.
//! - [`Message::SnapshotWant`] and [`Message::Snapshot`] are a snapshot link.
//! - [`Message::Tx`] gossips one signed envelope so every node can track it.
//! - [`Message::SetChange`] carries a transition certificate authorized by the
//!   old set.
//! - [`Message::Fence`] carries a quorum statement that one validator failed.
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
    Certificate, CommitFrontier, FenceCertificate, Header, Share, TransitionCertificate, Vertex,
    VertexId,
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

/// The framing and message layout this build speaks.
///
/// A peer that answers with another number is not necessarily hostile; it may be a
/// different build. The link is closed rather than parsed optimistically, because
/// the next frame kind could mean something else there.
pub const WIRE_PROTOCOL: u16 = 9;

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
    /// A batch a vertex names, sent on the data plane.
    Payload(Batch),
    /// One validator's signature over one header.
    Share(Share),
    /// A request for a state snapshot, sent on a dedicated snapshot link.
    SnapshotWant,
    /// A state snapshot response.
    Snapshot(Box<Snapshot>),
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
    /// A quorum declaration that one validator is failed from a round onward.
    Fence(Box<FenceCertificate>),
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
        Message::Payload(batch) => (KIND_PAYLOAD, batch.encode()?),
        Message::Share(share) => (KIND_SHARE, encode_share(share)?),
        Message::SnapshotWant => (KIND_SNAPSHOT_WANT, Vec::new()),
        Message::Snapshot(snapshot) => (KIND_SNAPSHOT, encode_snapshot(snapshot)?),
        Message::Tx(envelope) => (KIND_TX, {
            let mut encoder = Encoder::with_capacity(4 + envelope.len());
            encoder.put_bytes(envelope)?;
            encoder.finish()
        }),
        Message::SetChange(certificate) => (KIND_SET_CHANGE, certificate.encode()?),
        Message::Fence(certificate) => (KIND_FENCE, certificate.encode()?),
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
        KIND_PAYLOAD => Message::Payload(Batch::decode(payload)?),
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
        KIND_TX => {
            let mut decoder = Decoder::new(payload);
            let envelope = decoder.read_bytes()?.to_vec();
            decoder.finish()?;
            Message::Tx(envelope)
        }
        KIND_SET_CHANGE => Message::SetChange(Box::new(TransitionCertificate::decode(payload)?)),
        KIND_FENCE => Message::Fence(Box::new(FenceCertificate::decode(payload)?)),
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
        Fence, FenceCertificate, NO_EXPIRY, SetChange, ValidatorKey, ValidatorRecord, ValidatorSet,
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
