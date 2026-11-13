//! Inactive slot certificate payloads and trusted checkpoint carrier bindings.
//!
//! This codec does not verify signatures, evidence, continuity, or DAG ancestry,
//! and does not activate a protocol path. A DAG inspector must separately check
//! the predecessor certificate carrier in the proposal's causal cone and bind
//! the QC carrier to this payload and the proposal carrier's causal ancestry.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::slot_decision::{SlotDecisionCertificate, SlotDecisionTip};
use crate::slot_proposal::SlotProposal;
use crate::vertex::VertexId;

/// Canonical slot certificate payload encoding version.
pub const SLOT_CERTIFICATE_PAYLOAD_VERSION_V1: u16 = 1;
/// Domain hashed before the canonical slot certificate payload encoding.
pub const SLOT_CERTIFICATE_PAYLOAD_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_CERTIFICATE_PAYLOAD/v1";

// Match the identifier budget used by slot proposals.
const MAX_AUTHOR_BYTES: usize = 1024;

/// An inactive proposal, its carrier identifier, and a certificate for its exact decision.
///
/// The total canonical encoding is bounded by `MAX_FIELD_LEN` (1 MiB).
/// Equality of the nested decisions is a codec invariant, not verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotCertificatePayload {
    /// Proposal whose evidence requires independent validation.
    pub proposal: SlotProposal,
    /// DAG vertex carrying the proposal; ancestry requires independent validation.
    pub proposal_carrier: VertexId,
    /// Certificate with the exact same decision as the proposal.
    pub certificate: SlotDecisionCertificate,
}

fn check_bound(value: usize, limit: usize) -> Result<(), CryptoError> {
    if value > limit {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "slot certificate payload exceeds encoding bound",
        ));
    }
    Ok(())
}

fn malformed(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

impl SlotCertificatePayload {
    fn check_decision(&self) -> Result<(), CryptoError> {
        if self.proposal.decision != self.certificate.decision {
            return Err(malformed("slot certificate proposal decision mismatch"));
        }
        Ok(())
    }

    /// Encodes version, proposal bytes, carrier round/author/digest, then certificate bytes.
    ///
    /// Nested bodies, author, and digest are length-prefixed. No signatures are verified.
    ///
    /// # Errors
    /// Rejects unequal decisions, oversized bodies or authors, and nested codec errors.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        self.check_decision()?;
        check_bound(self.proposal_carrier.author.len(), MAX_AUTHOR_BYTES)?;
        let proposal = self.proposal.encode()?;
        let certificate = self.certificate.encode()?;
        let size = 2
            + 4
            + proposal.len()
            + 8
            + 4
            + self.proposal_carrier.author.len()
            + 4
            + 32
            + 4
            + certificate.len();
        check_bound(size, MAX_FIELD_LEN)?;
        let mut e = Encoder::with_capacity(size);
        e.put_u16(SLOT_CERTIFICATE_PAYLOAD_VERSION_V1);
        e.put_bytes(&proposal)?;
        e.put_u64(self.proposal_carrier.round);
        e.put_bytes(&self.proposal_carrier.author)?;
        e.put_bytes(&self.proposal_carrier.digest)?;
        e.put_bytes(&certificate)?;
        Ok(e.finish())
    }

    /// Decodes a bounded canonical payload without authenticating any of its contents.
    ///
    /// # Errors
    /// Rejects unequal decisions, oversized bodies/fields/authors, unknown versions,
    /// malformed digests, truncation, trailing bytes, and nested codec errors.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_bound(bytes.len(), MAX_FIELD_LEN)?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != SLOT_CERTIFICATE_PAYLOAD_VERSION_V1 {
            return Err(malformed("unsupported slot certificate payload version"));
        }
        let proposal = SlotProposal::decode(d.read_bytes()?)?;
        let round = d.read_u64()?;
        let author = d.read_bytes()?;
        check_bound(author.len(), MAX_AUTHOR_BYTES)?;
        let digest = d
            .read_bytes()?
            .try_into()
            .map_err(|_| malformed("expected a 32-byte proposal carrier digest"))?;
        let certificate = SlotDecisionCertificate::decode(d.read_bytes()?)?;
        d.finish()?;
        let payload = Self {
            proposal,
            proposal_carrier: VertexId {
                round,
                author: author.to_vec(),
                digest,
            },
            certificate,
        };
        payload.check_decision()?;
        Ok(payload)
    }

    /// Hashes the length-prefixed domain followed by the raw canonical encoding.
    ///
    /// Includes proposal evidence, carrier, and certificate signatures. This digest
    /// is not a signing payload or authorization.
    ///
    /// # Errors
    /// Propagates [`Self::encode`] errors, including unequal decisions.
    pub fn digest(&self) -> Result<[u8; 32], CryptoError> {
        let body = self.encode()?;
        let mut e = Encoder::with_capacity(4 + SLOT_CERTIFICATE_PAYLOAD_DOMAIN.len() + body.len());
        e.put_bytes(SLOT_CERTIFICATE_PAYLOAD_DOMAIN)?;
        e.put_raw(&body);
        Ok(Sha256::digest(e.finish()).into())
    }
}

/// Read-only association of a trusted decision tip with its prior certificate carrier.
///
/// This is inactive bootstrap state, not authenticated restoration or an update API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDecisionBinding {
    tip: SlotDecisionTip,
    carrier: Option<VertexId>,
}

impl SlotDecisionBinding {
    /// Constructs a binding from TRUSTED activation checkpoint values.
    ///
    /// The caller must establish trust in both values and their association. This
    /// constructor neither authenticates a checkpoint nor updates an existing tip.
    /// `None` is allowed ONLY when the caller's trusted activation checkpoint has
    /// no prior certificate carrier; it must not be used to omit a known carrier.
    /// No DAG membership, ancestry, or round relationship is checked here.
    ///
    /// # Errors
    /// Rejects a carrier author longer than 1024 bytes, if a carrier is present.
    pub fn from_checkpoint(
        tip: SlotDecisionTip,
        carrier: Option<VertexId>,
    ) -> Result<Self, CryptoError> {
        if let Some(carrier) = &carrier {
            check_bound(carrier.author.len(), MAX_AUTHOR_BYTES)?;
        }
        Ok(Self { tip, carrier })
    }

    // Only the owned application wrapper installs an already validated successor.
    pub(crate) fn replace_validated(&mut self, tip: SlotDecisionTip, carrier: VertexId) {
        self.tip = tip;
        self.carrier = Some(carrier);
    }

    /// Returns the current decision tip.
    pub fn tip(&self) -> &SlotDecisionTip {
        &self.tip
    }

    /// Returns the current certificate carrier, or the trusted checkpoint predecessor.
    pub fn carrier(&self) -> Option<&VertexId> {
        self.carrier.as_ref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{ValidatorSet, ValidatorSignature};
    use crate::slot_decision::{SlotDecision, SlotOutcome};

    fn payload() -> SlotCertificatePayload {
        // Deliberately unauthenticated and semantically invalid: this is only a codec.
        let decision = SlotDecision {
            chain_id: b"test".to_vec(),
            validator_set_id: [1; 32],
            epoch: 2,
            round: 7,
            previous: [2; 32],
            before_len: 9,
            before_root: [3; 32],
            after_len: 0,
            after_root: [4; 32],
            outcome: SlotOutcome::Skip {
                leader_author: Vec::new(),
            },
        };
        SlotCertificatePayload {
            proposal: SlotProposal {
                decision: decision.clone(),
                voters: Vec::new(),
            },
            proposal_carrier: VertexId {
                round: 8,
                author: b"carrier".to_vec(),
                digest: [5; 32],
            },
            certificate: SlotDecisionCertificate {
                decision,
                signatures: vec![ValidatorSignature {
                    validator_id: b"unknown".to_vec(),
                    key_id: Vec::new(),
                    signature: vec![0],
                }],
            },
        }
    }

    // Bypass the outer codec to exercise hostile wire data.
    fn raw(p: &SlotCertificatePayload, digest: &[u8]) -> Vec<u8> {
        let mut e = Encoder::new();
        e.put_u16(SLOT_CERTIFICATE_PAYLOAD_VERSION_V1);
        e.put_bytes(&p.proposal.encode().unwrap()).unwrap();
        e.put_u64(p.proposal_carrier.round);
        e.put_bytes(&p.proposal_carrier.author).unwrap();
        e.put_bytes(digest).unwrap();
        e.put_bytes(&p.certificate.encode().unwrap()).unwrap();
        e.finish()
    }

    #[test]
    fn canonical_roundtrip_and_domain_digest_without_verification() {
        let p = payload();
        let bytes = p.encode().unwrap();
        assert_eq!(bytes, raw(&p, &p.proposal_carrier.digest));
        assert_eq!(SlotCertificatePayload::decode(&bytes).unwrap(), p);
        let mut e = Encoder::new();
        e.put_bytes(b"KARSA/DAG/SLOT_CERTIFICATE_PAYLOAD/v1")
            .unwrap();
        e.put_raw(&bytes);
        let expected: [u8; 32] = Sha256::digest(e.finish()).into();
        assert_eq!(p.digest().unwrap(), expected);
        let mut empty = p;
        empty.certificate.signatures.clear();
        assert_eq!(
            SlotCertificatePayload::decode(&empty.encode().unwrap()).unwrap(),
            empty
        );
    }

    #[test]
    fn digest_covers_carrier_signatures_and_proposal() {
        let p = payload();
        let expected = p.digest().unwrap();
        for field in 0..6 {
            let mut changed = p.clone();
            match field {
                0 => changed.proposal_carrier.round += 1,
                1 => changed.proposal_carrier.author.push(0),
                2 => changed.proposal_carrier.digest[0] ^= 1,
                3 => changed.certificate.signatures[0].signature.push(1),
                4 => changed.certificate.signatures[0].validator_id.push(1),
                _ => changed
                    .proposal
                    .voters
                    .push(changed.proposal_carrier.clone()),
            }
            assert_ne!(changed.digest().unwrap(), expected, "field {field}");
        }
    }

    #[test]
    fn exact_decision_context_mismatch_rejected_everywhere() {
        for field in 0..11 {
            let mut p = payload();
            let d = &mut p.certificate.decision;
            match field {
                0 => d.chain_id.push(1),
                1 => d.validator_set_id[0] ^= 1,
                2 => d.epoch += 1,
                3 => d.round += 1,
                4 => d.previous[0] ^= 1,
                5 => d.before_len += 1,
                6 => d.before_root[0] ^= 1,
                7 => d.after_len += 1,
                8 => d.after_root[0] ^= 1,
                9 => {
                    d.outcome = SlotOutcome::Skip {
                        leader_author: vec![1],
                    }
                }
                _ => {
                    d.outcome = SlotOutcome::Commit {
                        leader: p.proposal_carrier.clone(),
                    }
                }
            }
            assert_eq!(
                p.encode().unwrap_err().kind(),
                CryptoErrorKind::MalformedCertificate
            );
            assert!(p.digest().is_err());
            assert_eq!(
                SlotCertificatePayload::decode(&raw(&p, &[5; 32]))
                    .unwrap_err()
                    .kind(),
                CryptoErrorKind::MalformedCertificate,
                "field {field}"
            );
        }
    }

    #[test]
    fn malformed_wire_is_rejected() {
        let p = payload();
        let bytes = p.encode().unwrap();
        for end in 0..bytes.len() {
            assert!(
                SlotCertificatePayload::decode(&bytes[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            SlotCertificatePayload::decode(&trailing)
                .unwrap_err()
                .kind(),
            CryptoErrorKind::TrailingBytes
        );
        for version in [0u16, 2, u16::MAX] {
            let mut bad = bytes.clone();
            bad[..2].copy_from_slice(&version.to_le_bytes());
            assert!(SlotCertificatePayload::decode(&bad).is_err());
        }
        for len in [0, 31, 33] {
            assert_eq!(
                SlotCertificatePayload::decode(&raw(&p, &vec![0; len]))
                    .unwrap_err()
                    .kind(),
                CryptoErrorKind::MalformedCertificate
            );
        }
        let mut oversized_field = bytes;
        oversized_field[2..6].copy_from_slice(&((MAX_FIELD_LEN + 1) as u32).to_le_bytes());
        assert_eq!(
            SlotCertificatePayload::decode(&oversized_field)
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
    }

    #[test]
    fn author_and_combined_total_bounds() {
        let mut p = payload();
        p.proposal_carrier.author = vec![0; MAX_AUTHOR_BYTES];
        assert_eq!(
            SlotCertificatePayload::decode(&p.encode().unwrap()).unwrap(),
            p
        );
        p.proposal_carrier.author.push(0);
        assert_eq!(
            p.encode().unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert!(p.digest().is_err());
        assert_eq!(
            SlotCertificatePayload::decode(&raw(&p, &[5; 32]))
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
        p = payload();
        // Each nested codec fits; their combined envelope exceeds the outer budget.
        p.proposal.voters = (0..600)
            .map(|round| VertexId {
                round,
                author: vec![0; MAX_AUTHOR_BYTES],
                digest: [0; 32],
            })
            .collect();
        p.certificate.signatures[0].signature = vec![0; 600_000];
        assert!(p.proposal.encode().is_ok());
        assert!(p.certificate.encode().is_ok());
        assert_eq!(
            p.encode().unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert!(p.digest().is_err());
        assert_eq!(
            SlotCertificatePayload::decode(&raw(&p, &[5; 32]))
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert_eq!(
            SlotCertificatePayload::decode(&vec![0; MAX_FIELD_LEN + 1])
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
    }

    fn tip() -> SlotDecisionTip {
        SlotDecisionTip::from_checkpoint(
            b"test".to_vec(),
            &ValidatorSet {
                epoch: 2,
                validators: vec![crate::schedule::ValidatorRecord {
                    validator_id: b"validator".to_vec(),
                    keys: vec![crate::schedule::ValidatorKey {
                        key_id: b"key".to_vec(),
                        algorithm_id: crypto::registry::ALG_ED25519,
                        public_key: crypto::scheme::Ed25519Scheme::public_key_from_seed(&[1; 32])
                            .unwrap()
                            .to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: crate::schedule::NO_EXPIRY,
                    }],
                }],
            },
            7,
            [0; 32],
            0,
            [0; 32],
        )
        .unwrap()
    }

    #[test]
    fn binding_trusted_bootstrap_getters_and_carrier_bound() {
        let tip = tip();
        let absent = SlotDecisionBinding::from_checkpoint(tip.clone(), None).unwrap();
        assert_eq!(absent.tip(), &tip);
        assert_eq!(absent.carrier(), None);
        let mut carrier = payload().proposal_carrier;
        for len in [0, MAX_AUTHOR_BYTES] {
            carrier.author = vec![0; len];
            let binding =
                SlotDecisionBinding::from_checkpoint(tip.clone(), Some(carrier.clone())).unwrap();
            assert_eq!(binding.tip(), &tip);
            assert_eq!(binding.carrier(), Some(&carrier));
        }
        carrier.author.push(0);
        assert_eq!(
            SlotDecisionBinding::from_checkpoint(tip, Some(carrier))
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
    }
}
