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
//! Two kinds share a link:
//!
//! - [`Message::Vertex`] is the broadcast.
//! - [`Message::Want`] asks a peer for one vertex by id.
//! - [`Message::Payload`] carries the batch a vertex names, on the data plane.
//!
//! The second kind is what makes a bounded queue safe. A peer that cannot keep up
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
use validator::{Vertex, VertexId};

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

/// What a frame carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A broadcast vertex.
    Vertex(Vertex),
    /// A request for one vertex, named by id.
    Want(VertexId),
    /// A batch a vertex names, sent on the data plane.
    Payload(Batch),
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

/// Encodes one message into a length-prefixed frame.
///
/// # Errors
///
/// Propagates the vertex encoding, and [`CryptoErrorKind::FieldTooLong`] when the
/// body does not fit the length field.
pub fn frame(message: &Message, sent_at_nanos: u64) -> Result<Vec<u8>, CryptoError> {
    let (kind, payload) = match message {
        Message::Vertex(vertex) => (KIND_VERTEX, vertex.encode()?),
        Message::Want(id) => (KIND_WANT, encode_id(id)?),
        Message::Payload(batch) => (KIND_PAYLOAD, batch.encode()?),
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
        KIND_VERTEX => Message::Vertex(Vertex::decode(payload)?),
        KIND_WANT => Message::Want(decode_id(&mut Decoder::new(payload))?),
        KIND_PAYLOAD => Message::Payload(Batch::decode(payload)?),
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
