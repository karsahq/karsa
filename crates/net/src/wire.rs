//! Vertex framing for a byte stream.
//!
//! A TCP stream is a sequence of bytes, not of messages. Something has to say
//! where one vertex ends and the next begins, and it has to be able to say
//! "not yet" when a read lands in the middle of a frame — so this type is a
//! parser over an accumulator, not a function over a complete buffer.
//!
//! ```text
//! u32 body length || u64 sent-at nanos || canonical vertex bytes
//! ```
//!
//! The length field excludes itself. The timestamp is transport metadata, not part
//! of the vertex: it never enters a signature, and a node that receives an old
//! timestamp learns nothing that a hash could not also tell it.
//!
//! A frame longer than [`MAX_FRAME`] is rejected rather than buffered. Without a
//! cap, one peer can make a node allocate whatever number it puts in four bytes.

use crypto::{CryptoError, CryptoErrorKind};
use validator::Vertex;

/// Largest body this parser will accept.
///
/// An Ed25519 vertex with full references at a hundred validators is a few
/// kilobytes; a post-quantum one with a SLH-DSA signature is under 128 kB. Sixteen
/// megabytes is far above both and still bounded.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

/// Bytes of transport metadata in front of the vertex.
const HEADER: usize = 4 + 8;

/// One decoded frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    /// Milliseconds since the sender's mesh started, as the sender saw them.
    pub sent_at_nanos: u64,
    /// The vertex itself.
    pub vertex: Vertex,
}

fn truncated(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::TruncatedInput, detail)
}

/// Encodes one vertex into a length-prefixed frame.
///
/// # Errors
///
/// Propagates the vertex encoding, and [`CryptoErrorKind::FieldTooLong`] when the
/// body does not fit the length field.
pub fn frame(vertex: &Vertex, sent_at_nanos: u64) -> Result<Vec<u8>, CryptoError> {
    let body = vertex.encode()?;
    let length = u32::try_from(HEADER - 4 + body.len()).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "frame does not fit a u32 length",
        )
    })?;
    let mut bytes = Vec::with_capacity(HEADER + body.len());
    bytes.extend_from_slice(&length.to_le_bytes());
    bytes.extend_from_slice(&sent_at_nanos.to_le_bytes());
    bytes.extend_from_slice(&body);
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
/// [`MAX_FRAME`], and anything [`Vertex::decode`] reports for the body.
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
    sent_at_nanos.copy_from_slice(&buffer[4..HEADER]);
    let vertex = Vertex::decode(&buffer[HEADER..total])?;
    buffer.drain(..total);
    Ok(Some(Frame {
        sent_at_nanos: u64::from_le_bytes(sent_at_nanos),
        vertex,
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

    #[test]
    fn a_frame_round_trips_through_an_accumulator() {
        let mut buffer = Vec::new();
        buffer.extend_from_slice(&frame(&vertex(1), 42).unwrap());
        buffer.extend_from_slice(&frame(&vertex(2), 43).unwrap());

        let first = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(first.sent_at_nanos, 42);
        assert_eq!(first.vertex, vertex(1));

        let second = take_frame(&mut buffer).unwrap().unwrap();
        assert_eq!(second.vertex, vertex(2));
        assert!(buffer.is_empty());

        assert_eq!(take_frame(&mut buffer).unwrap(), None);
    }

    #[test]
    fn a_partial_frame_is_not_an_error_and_is_not_consumed() {
        let bytes = frame(&vertex(3), 7).unwrap();
        let mut buffer = bytes[..bytes.len() - 5].to_vec();
        let before = buffer.len();

        assert_eq!(take_frame(&mut buffer).unwrap(), None);
        assert_eq!(buffer.len(), before, "an incomplete frame is left alone");

        buffer.extend_from_slice(&bytes[bytes.len() - 5..]);
        assert_eq!(take_frame(&mut buffer).unwrap().unwrap().vertex, vertex(3));
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
}
