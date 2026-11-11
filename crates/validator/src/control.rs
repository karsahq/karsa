//! Control payloads a vertex can carry besides a transaction batch.
//!
//! `Vertex::payload_hash` is part of the signed payload and the DAG treats it as
//! opaque, so a vertex can name any canonical payload. A batch is the data-plane
//! default; a control payload is protocol evidence that needs the same causal
//! position as a batch, because a decision made from it must be replayable from
//! the DAG rather than from a control frame that a peer may have missed.
//!
//! The first control payload is a round-skip certificate. Carrying it in a
//! vertex makes the skip a fact of the DAG: the payload is applied only when the
//! vertex that names it is held, so a node that is missing either half waits
//! instead of deciding the round through an anchor.

use crypto::encoding::{Decoder, Encoder};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::round_skip::RoundSkipProof;

/// Canonical control payload version.
pub const CONTROL_PAYLOAD_VERSION_V1: u16 = 1;

/// Domain tag hashed in front of a canonical control payload.
///
/// A batch hash is the untagged SHA-256 of the batch encoding; the tag keeps a
/// control digest from colliding with one.
pub const CONTROL_PAYLOAD_DOMAIN: &[u8] = b"KARSA/DAG/CONTROL/v1";

const KIND_ROUND_SKIP: u8 = 1;

/// A protocol payload a vertex can bind with its `payload_hash`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlPayload {
    /// Evidence that the leader of one round cannot reach a vote quorum.
    RoundSkip(Box<RoundSkipProof>),
}

impl ControlPayload {
    /// The leader round this payload decides.
    #[must_use]
    pub fn round(&self) -> u64 {
        match self {
            Self::RoundSkip(proof) => proof.attestation.skip.round(),
        }
    }

    /// The round-skip proof, when this payload is one.
    #[must_use]
    pub fn round_skip(&self) -> Option<&RoundSkipProof> {
        match self {
            Self::RoundSkip(proof) => Some(proof),
        }
    }

    /// Writes the canonical payload encoding.
    ///
    /// # Errors
    ///
    /// Every error from [`RoundSkipProof::encode`].
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        match self {
            Self::RoundSkip(proof) => {
                let proof = proof.encode()?;
                let mut encoder = Encoder::with_capacity(3 + 4 + proof.len());
                encoder.put_u16(CONTROL_PAYLOAD_VERSION_V1);
                encoder.put_u8(KIND_ROUND_SKIP);
                encoder.put_bytes(&proof)?;
                Ok(encoder.finish())
            }
        }
    }

    /// Reads a canonical payload encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`], [`CryptoErrorKind::TrailingBytes`],
    /// or [`CryptoErrorKind::MalformedCertificate`] for a bad buffer, unknown
    /// version, or unknown kind, plus every error from
    /// [`RoundSkipProof::decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != CONTROL_PAYLOAD_VERSION_V1 {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedCertificate,
                format!("unsupported control payload version {version}"),
            ));
        }
        let kind = decoder.read_u8()?;
        let payload = match kind {
            KIND_ROUND_SKIP => {
                Self::RoundSkip(Box::new(RoundSkipProof::decode(decoder.read_bytes()?)?))
            }
            other => {
                return Err(CryptoError::new(
                    CryptoErrorKind::MalformedCertificate,
                    format!("unknown control payload kind {other}"),
                ));
            }
        };
        decoder.finish()?;
        Ok(payload)
    }

    /// Content digest named by [`crate::Vertex::payload_hash`].
    ///
    /// # Errors
    ///
    /// Propagates [`ControlPayload::encode`].
    pub fn digest(&self) -> Result<[u8; 32], CryptoError> {
        let body = self.encode()?;
        let mut encoder = Encoder::with_capacity(CONTROL_PAYLOAD_DOMAIN.len() + body.len() + 8);
        encoder.put_bytes(CONTROL_PAYLOAD_DOMAIN)?;
        encoder.put_raw(&body);
        Ok(Sha256::digest(encoder.finish()).into())
    }
}

#[cfg(test)]
mod tests {
    use crypto::CryptoErrorKind;

    use super::*;
    use crate::round_skip::{NoVoteAttestation, RoundSkip};
    use crate::vertex::VertexId;

    fn proof() -> RoundSkipProof {
        RoundSkipProof {
            attestation: NoVoteAttestation {
                skip: RoundSkip::new(
                    b"karsa-control-1".to_vec(),
                    VertexId {
                        round: 7,
                        author: b"val-0".to_vec(),
                        digest: [3; 32],
                    },
                ),
                signer_bitmap: vec![0b1],
                signatures: vec![vec![9u8; 64]],
            },
            votes: Vec::new(),
            non_votes: vec![VertexId {
                round: 8,
                author: b"val-1".to_vec(),
                digest: [4; 32],
            }],
            fenced_absent: Vec::new(),
            missing: vec![b"val-2".to_vec()],
        }
    }

    #[test]
    fn a_control_payload_roundtrips() {
        let payload = ControlPayload::RoundSkip(Box::new(proof()));
        let encoded = payload.encode().unwrap();
        assert_eq!(ControlPayload::decode(&encoded).unwrap(), payload);
        assert_eq!(payload.round(), 7);
        assert_eq!(payload.round_skip(), Some(&proof()));
    }

    #[test]
    fn a_control_digest_is_domain_separated_from_the_batch_style_hash() {
        let payload = ControlPayload::RoundSkip(Box::new(proof()));
        let encoded = payload.encode().unwrap();
        let digest = payload.digest().unwrap();
        let untagged: [u8; 32] = Sha256::digest(&encoded).into();
        assert_ne!(digest, untagged);
        assert_eq!(digest, payload.digest().unwrap());
    }

    #[test]
    fn an_unknown_kind_is_refused() {
        let payload = ControlPayload::RoundSkip(Box::new(proof()));
        let mut encoded = payload.encode().unwrap();
        // version (2 bytes) followed by the kind byte.
        encoded[2] = 9;
        assert!(matches!(
            ControlPayload::decode(&encoded),
            Err(error) if error.kind() == CryptoErrorKind::MalformedCertificate
        ));
    }

    #[test]
    fn trailing_bytes_are_refused() {
        let payload = ControlPayload::RoundSkip(Box::new(proof()));
        let mut encoded = payload.encode().unwrap();
        encoded.push(0xff);
        assert!(matches!(
            ControlPayload::decode(&encoded),
            Err(error) if error.kind() == CryptoErrorKind::TrailingBytes
        ));
    }
}
