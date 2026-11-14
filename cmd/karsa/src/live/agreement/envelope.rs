//! Inactive complete carrier representation; construction and decoding are not authentication.

use super::PendingIntent;
use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use validator::{
    SlotAgreementProof, SlotAgreementViewLineage, SlotAgreementVotePayload, ValidatorSet, VertexId,
};

/// One MiB including framing, consistent with the existing evidence codec bound.
pub const MAX_ENVELOPE_BYTES: usize = MAX_FIELD_LEN;
const MAX_AUTHOR_BYTES: usize = 1024;
const VERSION: u16 = 1;

/// Complete owned evidence. Access through an envelope is immutable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierPayload {
    /// Individual nonnil prevote or precommit, including its prerequisite.
    Vote(SlotAgreementVotePayload),
    /// Complete lineage whose last entry contains the selected, actual POL carrier.
    Pol(SlotAgreementViewLineage),
    /// Complete final evidence, not decision-application authority.
    Final(SlotAgreementProof),
}

/// Immutable evidence and claimed actual carrier association, never send authorization.
///
/// The digest is the existing protocol payload digest, NOT a hash of this wrapper.
/// `VertexId.digest` identifies the vertex, not its payload. Only authenticated DAG
/// inspection can check that the vertex's payload_hash equals this payload digest,
/// verify signatures/ancestry/proposal semantics, or establish causal readiness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CarrierEnvelope {
    carrier: VertexId,
    payload: CarrierPayload,
    payload_digest: [u8; 32],
}

fn invalid(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

fn bound(len: usize, max: usize) -> Result<(), CryptoError> {
    if len > max {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "carrier envelope exceeds bound",
        ));
    }
    Ok(())
}

impl CarrierEnvelope {
    fn checked(
        carrier: VertexId,
        payload: CarrierPayload,
        payload_digest: [u8; 32],
        set: &ValidatorSet,
    ) -> Result<Self, CryptoError> {
        bound(carrier.author.len(), MAX_AUTHOR_BYTES)?;
        let actual = match &payload {
            CarrierPayload::Vote(vote) => {
                if carrier.author != vote.signature.validator_id {
                    return Err(invalid("vote carrier author differs from signer"));
                }
                vote.digest(set)?
            }
            CarrierPayload::Pol(lineage) => {
                let index = lineage
                    .entries
                    .len()
                    .checked_sub(1)
                    .ok_or_else(|| invalid("empty POL lineage"))?;
                let pol = lineage.entries[index]
                    .pol
                    .as_ref()
                    .ok_or_else(|| invalid("selected entry lacks POL"))?;
                if pol.carrier != carrier {
                    return Err(invalid("selected POL carrier association mismatch"));
                }
                lineage.pol_digest(index, set)?
            }
            CarrierPayload::Final(proof) => proof.digest(set)?,
        };
        if actual != payload_digest {
            return Err(invalid("carrier payload digest mismatch"));
        }
        let envelope = Self {
            carrier,
            payload,
            payload_digest,
        };
        // Check aggregate framing as well as the nested codec's bounds.
        envelope.encode(set)?;
        Ok(envelope)
    }

    /// Returns the claimed actual carrier; it has not been authenticated here.
    pub fn carrier(&self) -> &VertexId {
        &self.carrier
    }

    /// Returns full immutable evidence, including every retained witness and lineage entry.
    pub fn payload(&self) -> &CarrierPayload {
        &self.payload
    }

    /// Returns the exact existing protocol payload digest.
    pub fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// Encodes inactive transport/storage bytes with no embedded validator-set authority.
    ///
    /// Layout: u16 version, u8 kind (0 vote, 1 POL, 2 final), u64 round,
    /// length-prefixed author, vertex digest, payload digest, length-prefixed body.
    /// Integers and byte fields follow the existing crypto codec conventions.
    /// # Errors
    /// Rejects nested codec errors and aggregate/identifier bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        bound(self.carrier.author.len(), MAX_AUTHOR_BYTES)?;
        let (tag, body) = match &self.payload {
            CarrierPayload::Vote(p) => (0, p.encode(set)?),
            CarrierPayload::Pol(p) => (1, p.encode(set)?),
            CarrierPayload::Final(p) => (2, p.encode(set)?),
        };
        // Fixed framing: version + kind + round + two length prefixes + two digests.
        bound(
            83 + self.carrier.author.len() + body.len(),
            MAX_ENVELOPE_BYTES,
        )?;
        let mut e = Encoder::new();
        e.put_u16(VERSION);
        e.put_u8(tag);
        e.put_u64(self.carrier.round);
        e.put_bytes(&self.carrier.author)?;
        e.put_raw(&self.carrier.digest);
        e.put_raw(&self.payload_digest);
        e.put_bytes(&body)?;
        Ok(e.finish())
    }

    /// Decodes complete evidence against a caller-pinned set, without authenticating it.
    /// # Errors
    /// Rejects all outer lengths/trailing bytes before nested decode, unknown tags or
    /// versions, malformed bodies, digest mismatch and selected-carrier mismatch.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        bound(bytes.len(), MAX_ENVELOPE_BYTES)?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != VERSION {
            return Err(invalid("unknown carrier envelope version"));
        }
        let tag = d.read_u8()?;
        if tag > 2 {
            return Err(invalid("unknown carrier envelope kind"));
        }
        let round = d.read_u64()?;
        let author = d.read_bytes()?;
        bound(author.len(), MAX_AUTHOR_BYTES)?;
        let mut digest = [0; 32];
        for byte in &mut digest {
            *byte = d.read_u8()?;
        }
        let mut payload_digest = [0; 32];
        for byte in &mut payload_digest {
            *byte = d.read_u8()?;
        }
        let body = d.read_bytes()?;
        d.finish()?;
        let payload = match tag {
            0 => CarrierPayload::Vote(SlotAgreementVotePayload::decode(body, set)?),
            1 => CarrierPayload::Pol(SlotAgreementViewLineage::decode(body, set)?),
            2 => CarrierPayload::Final(SlotAgreementProof::decode(body, set)?),
            _ => unreachable!("kind preflighted"),
        };
        Self::checked(
            VertexId {
                round,
                author: author.to_vec(),
                digest,
            },
            payload,
            payload_digest,
            set,
        )
    }
}

impl PendingIntent {
    /// Binds owned complete evidence to a supplied actual carrier ID.
    /// This checks construction consistency only, not authentication, readiness,
    /// carrier payload_hash, signing, publication or application authority.
    /// # Errors
    /// Rejects nil, stale/untrusted intent digests, vote-author mismatch and codec bounds.
    pub fn into_envelope(
        self,
        carrier: VertexId,
        set: &ValidatorSet,
    ) -> Result<CarrierEnvelope, CryptoError> {
        let (payload, digest) = match self {
            Self::UnsupportedNil { .. } => return Err(invalid("nil carrier is unsupported")),
            Self::Vote { payload, digest } => (CarrierPayload::Vote(payload), digest),
            Self::Pol { candidate, digest } => {
                if candidate.digest() != digest {
                    return Err(invalid("POL intent digest mismatch"));
                }
                (
                    CarrierPayload::Pol(candidate.bind_carrier(carrier.clone())),
                    digest,
                )
            }
            Self::FinalProof { proof, digest } => (CarrierPayload::Final(proof), digest),
        };
        CarrierEnvelope::checked(carrier, payload, digest, set)
    }
}
