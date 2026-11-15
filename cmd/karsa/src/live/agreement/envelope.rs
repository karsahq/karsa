//! Inactive carrier representation; construction and decoding are not authentication.
//!
//! Version 2 retains full vote lineage; version 1 is deliberately rejected.
//! No migration, network activation, or storage integration is provided.

use super::PendingIntent;
use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use validator::{
    Dag, SlotAgreementBinding, SlotAgreementProof, SlotAgreementViewLineage,
    SlotAgreementVotePayload, SlotAgreementVoteWitness, SlotProposalEnvelope, ValidatorSet,
    VertexId,
};

/// One MiB including framing, consistent with the existing evidence codec bound.
pub const MAX_ENVELOPE_BYTES: usize = MAX_FIELD_LEN;
const MAX_AUTHOR_BYTES: usize = 1024;
const VERSION: u16 = 2;

/// Owned, self-contained payload evidence, immutable through an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CarrierPayload {
    /// Plain proposal, without elected-view authority.
    Proposal(SlotProposalEnvelope),
    /// Complete elected-view authorization lineage.
    View(SlotAgreementViewLineage),
    /// Individual nonnil prevote or precommit, including its prerequisite.
    Vote {
        /// Existing protocol vote, still the sole payload-digest authority.
        payload: SlotAgreementVotePayload,
        /// Complete retained lineage used by unified DAG inspection.
        lineage: SlotAgreementViewLineage,
    },
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

// version + kind + round + author/body length prefixes + two fixed digests.
const ENVELOPE_FRAMING_BYTES: usize = 83;

fn preflight_body_len(author_len: usize, body_len: usize) -> Result<(), CryptoError> {
    bound(author_len, MAX_AUTHOR_BYTES)?;
    bound(
        ENVELOPE_FRAMING_BYTES
            .saturating_add(author_len)
            .saturating_add(body_len),
        MAX_ENVELOPE_BYTES,
    )
}

impl CarrierEnvelope {
    /// Reconstructs typed publication evidence with canonical codec validation.
    /// This does not authenticate the vertex or authorize publication.
    pub(super) fn from_publication(
        carrier: VertexId,
        payload: CarrierPayload,
        payload_digest: [u8; 32],
        set: &ValidatorSet,
    ) -> Result<Self, CryptoError> {
        let envelope = Self::checked(carrier, payload, payload_digest, set)?;
        Self::decode(&envelope.encode(set)?, set)
    }

    /// Preflights vote framing without inventing an unknown carrier digest.
    pub(super) fn preflight_vote(
        author: &[u8],
        payload: &SlotAgreementVotePayload,
        lineage: &SlotAgreementViewLineage,
        set: &ValidatorSet,
    ) -> Result<(), CryptoError> {
        bound(author.len(), MAX_AUTHOR_BYTES)?;
        let lineage = lineage.encode(set)?;
        let vote = payload.encode(set)?;
        bound(
            91 + author.len() + lineage.len() + vote.len(),
            MAX_ENVELOPE_BYTES,
        )
    }

    /// Preflights exact aggregate framing without a dummy carrier or binding.
    pub(super) fn preflight_aggregate(
        author: &[u8],
        intent: &PendingIntent,
        set: &ValidatorSet,
    ) -> Result<(), CryptoError> {
        bound(author.len(), MAX_AUTHOR_BYTES)?;
        let len = match intent {
            PendingIntent::Pol { candidate, .. } => candidate.bound_lineage_len(author, set)?,
            PendingIntent::FinalProof { proof, .. } => proof.encode(set)?.len(),
            _ => return Err(invalid("expected aggregate candidate")),
        };
        preflight_body_len(author.len(), len)
    }

    /// Preflights proposal/view framing before any carrier signing.
    pub(super) fn preflight_local(author: &[u8], body_len: usize) -> Result<(), CryptoError> {
        preflight_body_len(author.len(), body_len)
    }

    /// Converts owned evidence into a closed request, without asserting authentication.
    /// The receiving session must reauthenticate against its own pinned binding and DAG.
    pub(super) fn into_request(
        self,
        vertices: Vec<validator::Vertex>,
    ) -> Result<store::AuthenticatedSlotAgreementRequest, CryptoError> {
        use store::AuthenticatedSlotAgreementRequest;
        Ok(match self.payload {
            CarrierPayload::Proposal(proposal) => {
                AuthenticatedSlotAgreementRequest::ObserveProposal {
                    proposal,
                    carrier: self.carrier,
                    vertices,
                }
            }
            CarrierPayload::View(lineage) => {
                AuthenticatedSlotAgreementRequest::Propose { lineage, vertices }
            }
            CarrierPayload::Vote { payload, lineage } => {
                AuthenticatedSlotAgreementRequest::ObserveVote {
                    lineage,
                    witness: SlotAgreementVoteWitness {
                        payload,
                        carrier: self.carrier,
                    },
                    vertices,
                }
            }
            CarrierPayload::Pol(lineage) => {
                AuthenticatedSlotAgreementRequest::ObservePrevote { lineage, vertices }
            }
            CarrierPayload::Final(proof) => AuthenticatedSlotAgreementRequest::ObservePrecommit {
                proof,
                carrier: self.carrier,
                vertices,
            },
        })
    }

    fn checked(
        carrier: VertexId,
        payload: CarrierPayload,
        payload_digest: [u8; 32],
        set: &ValidatorSet,
    ) -> Result<Self, CryptoError> {
        bound(carrier.author.len(), MAX_AUTHOR_BYTES)?;
        let actual = match &payload {
            CarrierPayload::Proposal(proposal) => proposal.digest()?,
            CarrierPayload::View(lineage) => {
                let index = lineage
                    .entries
                    .len()
                    .checked_sub(1)
                    .ok_or_else(|| invalid("empty view lineage"))?;
                if lineage.entries[index].view_carrier != carrier {
                    return Err(invalid("selected view carrier association mismatch"));
                }
                lineage.view_digest(index)?
            }
            CarrierPayload::Vote {
                payload: vote,
                lineage,
            } => {
                if vote.vote.phase == validator::slot_agreement::AgreementPhase::Precommit
                    && lineage
                        .entries
                        .last()
                        .is_none_or(|entry| entry.pol.is_none())
                {
                    return Err(invalid("precommit requires selected POL"));
                }
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

    /// Returns immutable payload evidence, including full retained vote lineage.
    pub fn payload(&self) -> &CarrierPayload {
        &self.payload
    }

    /// Returns the exact existing protocol payload digest.
    pub fn payload_digest(&self) -> [u8; 32] {
        self.payload_digest
    }

    /// Authenticates evidence against the current DAG and a caller-trusted binding.
    ///
    /// Uses only retained lineage. Success is an inspection result for this DAG borrow,
    /// not authority to persist, sign, publish, or apply a decision. This is inactive.
    /// # Errors
    /// Rejects all unified DAG inspection errors, including incorrect lineage,
    /// carriers, payload hashes, ancestry, signatures or binding.
    pub fn inspect(&self, dag: &Dag, binding: &SlotAgreementBinding) -> Result<(), CryptoError> {
        match &self.payload {
            CarrierPayload::Proposal(proposal) => dag
                .inspect_slot_bound_proposal(proposal, &self.carrier, binding)
                .map(|_| ()),
            CarrierPayload::View(lineage) => dag
                .inspect_slot_agreement_view_lineage(lineage, binding)
                .map(|_| ()),
            CarrierPayload::Vote { payload, lineage } => dag.inspect_slot_agreement_vote(
                lineage,
                &SlotAgreementVoteWitness {
                    payload: payload.clone(),
                    carrier: self.carrier.clone(),
                },
                binding,
            ),
            CarrierPayload::Pol(lineage) => dag
                .inspect_slot_agreement_view_lineage(lineage, binding)
                .map(|_| ()),
            CarrierPayload::Final(proof) => dag
                .inspect_slot_agreement_proof(proof, &self.carrier, binding)
                .map(|_| ()),
        }
    }

    /// Encodes inactive transport/storage bytes with no embedded validator-set authority.
    ///
    /// Layout: u16 version, u8 kind (0 vote, 1 POL, 2 final, 3 proposal, 4 view), u64 round,
    /// length-prefixed author, vertex digest, payload digest, length-prefixed body.
    /// Integers and byte fields follow the existing crypto codec conventions.
    /// # Errors
    /// Rejects nested codec errors and aggregate/identifier bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        bound(self.carrier.author.len(), MAX_AUTHOR_BYTES)?;
        let (tag, body) = match &self.payload {
            CarrierPayload::Vote { payload, lineage } => {
                let lineage = lineage.encode(set)?;
                let vote = payload.encode(set)?;
                bound(
                    91 + self.carrier.author.len() + lineage.len() + vote.len(),
                    MAX_ENVELOPE_BYTES,
                )?;
                let mut body = Encoder::new();
                body.put_bytes(&lineage)?;
                body.put_bytes(&vote)?;
                (0, body.finish())
            }
            CarrierPayload::Proposal(p) => (3, p.encode()?),
            CarrierPayload::View(p) => (4, p.encode(set)?),
            CarrierPayload::Pol(p) => (1, p.encode(set)?),
            CarrierPayload::Final(p) => (2, p.encode(set)?),
        };
        // Fixed framing: version + kind + round + two length prefixes + two digests.
        preflight_body_len(self.carrier.author.len(), body.len())?;
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

    /// Decodes payload evidence against a caller-pinned set, without authenticating it.
    /// Vote bodies contain length-prefixed full lineage followed by the vote codec.
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
        if tag > 4 {
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
            0 => {
                // Preflight both nested lengths and trailing bytes before nested decoding.
                let mut body = Decoder::new(body);
                let lineage = body.read_bytes()?;
                let vote = body.read_bytes()?;
                body.finish()?;
                CarrierPayload::Vote {
                    lineage: SlotAgreementViewLineage::decode(lineage, set)?,
                    payload: SlotAgreementVotePayload::decode(vote, set)?,
                }
            }
            1 => CarrierPayload::Pol(SlotAgreementViewLineage::decode(body, set)?),
            3 => CarrierPayload::Proposal(SlotProposalEnvelope::decode(body)?),
            4 => CarrierPayload::View(SlotAgreementViewLineage::decode(body, set)?),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_framing_accepts_exact_limit_and_rejects_one_byte_over() {
        for author_len in [0, 1, MAX_AUTHOR_BYTES] {
            let author = vec![0; author_len];
            let body_len = MAX_ENVELOPE_BYTES - ENVELOPE_FRAMING_BYTES - author_len;
            let body = vec![0; body_len];
            let mut encoded = Encoder::new();
            encoded.put_u16(VERSION);
            encoded.put_u8(1);
            encoded.put_u64(6);
            encoded.put_bytes(&author).unwrap();
            encoded.put_raw(&[0; 32]);
            encoded.put_raw(&[0; 32]);
            encoded.put_bytes(&body).unwrap();
            assert_eq!(encoded.len(), MAX_ENVELOPE_BYTES);
            assert!(preflight_body_len(author_len, body_len - 1).is_ok());
            assert!(preflight_body_len(author_len, body_len).is_ok());
            assert!(preflight_body_len(author_len, body_len + 1).is_err());
        }
        assert!(preflight_body_len(MAX_AUTHOR_BYTES + 1, 0).is_err());
        assert!(preflight_body_len(1, usize::MAX).is_err());
    }
}

impl PendingIntent {
    /// Binds owned payload evidence to a supplied actual carrier ID.
    /// Votes carry their exact original lineage; no external reconstruction is accepted.
    /// This checks construction consistency only, not authentication, readiness,
    /// carrier payload_hash, signing, publication or application authority.
    /// # Errors
    /// Rejects nil, stale/untrusted
    /// intent digests, vote-author mismatch, incomplete precommit lineage and codec bounds.
    pub fn into_envelope(
        self,
        carrier: VertexId,
        set: &ValidatorSet,
    ) -> Result<CarrierEnvelope, CryptoError> {
        let (payload, digest) = match self {
            Self::UnsupportedNil { .. } => return Err(invalid("nil carrier is unsupported")),
            Self::Vote {
                payload,
                digest,
                lineage,
            } => (CarrierPayload::Vote { payload, lineage }, digest),
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
