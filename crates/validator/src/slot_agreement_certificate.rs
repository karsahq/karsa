//! Inactive final agreement QC carriers, distinct from legacy slot certificates.
//!
//! This slice does not prove intermediate prevote/POL causal carriers and is not
//! sufficient for activation. Decoding authenticates neither checkpoints nor evidence.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::slot_agreement::{AgreementPhase, AgreementQc, AgreementValue};
use crate::{SlotDecisionTip, SlotProposal, ValidatorSet, VertexId};

/// Version of the independent final agreement carrier codec.
pub const SLOT_AGREEMENT_CERTIFICATE_VERSION_V1: u16 = 1;
/// Independent payload-binding domain, not an agreement vote signing domain.
pub const SLOT_AGREEMENT_CERTIFICATE_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_AGREEMENT_CERTIFICATE/v1";
const FINAL_QC: u8 = 0;
const MAX_AUTHOR: usize = 1024;

fn invalid(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

fn bound(size: usize, limit: usize) -> Result<(), CryptoError> {
    if size > limit {
        return Err(invalid("agreement certificate exceeds encoding bound"));
    }
    Ok(())
}

/// Bounded proposal evidence and a final nonnil precommit QC for its exact decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementCertificatePayload {
    /// Direct-rule evidence, independently checked by the DAG inspector.
    pub proposal: SlotProposal,
    /// Exact signed vertex carrying the proposal digest.
    pub proposal_carrier: VertexId,
    /// Agreement-domain signatures; never a legacy decision certificate.
    pub certificate: AgreementQc,
}

impl SlotAgreementCertificatePayload {
    fn check_final(&self) -> Result<(), CryptoError> {
        if self.certificate.vote.phase != AgreementPhase::Precommit
            || self.certificate.vote.value
                != AgreementValue::Decision(self.proposal.decision.clone())
        {
            return Err(invalid("expected final agreement QC for exact proposal"));
        }
        Ok(())
    }

    /// Encodes canonical bounded storage bytes without verifying signatures or ancestry.
    ///
    /// # Errors
    /// Rejects nonfinal/mismatched statements, nested codec errors and size bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        self.check_final()?;
        bound(self.proposal_carrier.author.len(), MAX_AUTHOR)?;
        let proposal = self.proposal.encode()?;
        let certificate = self.certificate.encode(set)?;
        let size = 3
            + 4
            + proposal.len()
            + 8
            + 4
            + self.proposal_carrier.author.len()
            + 4
            + 32
            + 4
            + certificate.len();
        bound(size, MAX_FIELD_LEN)?;
        let mut e = Encoder::with_capacity(size);
        e.put_u16(SLOT_AGREEMENT_CERTIFICATE_VERSION_V1);
        e.put_u8(FINAL_QC);
        e.put_bytes(&proposal)?;
        e.put_u64(self.proposal_carrier.round);
        e.put_bytes(&self.proposal_carrier.author)?;
        e.put_bytes(&self.proposal_carrier.digest)?;
        e.put_bytes(&certificate)?;
        Ok(e.finish())
    }

    /// Decodes untrusted canonical bytes, preflighting the outer envelope before allocation.
    ///
    /// # Errors
    /// Rejects unknown tags/versions, bounds, truncation, trailing bytes and nested errors.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        bound(bytes.len(), MAX_FIELD_LEN)?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != SLOT_AGREEMENT_CERTIFICATE_VERSION_V1 || d.read_u8()? != FINAL_QC {
            return Err(invalid("unknown agreement certificate version or kind"));
        }
        let proposal = d.read_bytes()?;
        let round = d.read_u64()?;
        let author = d.read_bytes()?;
        bound(author.len(), MAX_AUTHOR)?;
        let digest = d
            .read_bytes()?
            .try_into()
            .map_err(|_| invalid("expected 32-byte proposal carrier digest"))?;
        let certificate = d.read_bytes()?;
        d.finish()?;
        let payload = Self {
            proposal: SlotProposal::decode(proposal)?,
            proposal_carrier: VertexId {
                round,
                author: author.to_vec(),
                digest,
            },
            certificate: AgreementQc::decode(certificate, set)?,
        };
        payload.check_final()?;
        Ok(payload)
    }

    /// Hashes the length-prefixed independent domain followed by canonical storage bytes.
    ///
    /// # Errors
    /// Propagates encoding errors; no cryptographic evidence verification is performed.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        let body = self.encode(set)?;
        let mut e =
            Encoder::with_capacity(4 + SLOT_AGREEMENT_CERTIFICATE_DOMAIN.len() + body.len());
        e.put_bytes(SLOT_AGREEMENT_CERTIFICATE_DOMAIN)?;
        e.put_raw(&body);
        Ok(Sha256::digest(e.finish()).into())
    }
}

/// Read-only trusted agreement checkpoint association, with no application/update API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementBinding {
    tip: SlotDecisionTip,
    carrier: Option<VertexId>,
}

impl SlotAgreementBinding {
    /// Imports TRUSTED checkpoint values; does not authenticate their association.
    /// `None` is only valid if the trusted checkpoint has no predecessor carrier;
    /// callers must not use it to omit a known predecessor.
    ///
    /// # Errors
    /// Rejects predecessor authors longer than 1024 bytes.
    pub fn from_checkpoint(
        tip: SlotDecisionTip,
        carrier: Option<VertexId>,
    ) -> Result<Self, CryptoError> {
        if let Some(carrier) = &carrier {
            bound(carrier.author.len(), MAX_AUTHOR)?;
        }
        Ok(Self { tip, carrier })
    }

    /// Trusted fixed-slot context, never advanced through a legacy QC conversion.
    pub fn tip(&self) -> &SlotDecisionTip {
        &self.tip
    }

    /// Trusted predecessor QC carrier, if the checkpoint has one.
    pub fn carrier(&self) -> Option<&VertexId> {
        self.carrier.as_ref()
    }
}
