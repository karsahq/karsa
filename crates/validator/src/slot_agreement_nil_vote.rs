//! Carrier-free, structurally checked nil votes; only explicit verification authenticates them.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};

use crate::slot_agreement::{AgreementQc, AgreementValue, AgreementVote};
use crate::{SlotDecisionTip, ValidatorSet, ValidatorSignature};

const VERSION: u16 = 1;
const NIL_VOTE: u8 = 0;
const MAX_ID: usize = 1024;

fn invalid(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

/// One immutable nil statement and signature, with no proposal or DAG carrier.
///
/// Construction and decoding check structure only, not signature authenticity or
/// checkpoint trust. Call [`Self::verify`] with the exact trusted slot context.
/// Nil is abstention, never a decision to skip, and this message is not a quorum.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementNilVote {
    vote: AgreementVote,
    signature: ValidatorSignature,
}

impl SlotAgreementNilVote {
    // Exact nil vote + one-signature QC + version/kind/length envelope size.
    // Check before cloning anything into the existing owned QC codec.
    fn preflight(&self) -> Result<(), CryptoError> {
        if self.vote.value != AgreementValue::Nil {
            return Err(invalid("expected exactly nil agreement vote"));
        }
        if self.signature.validator_id.len() > MAX_ID || self.signature.key_id.len() > MAX_ID {
            return Err(invalid("nil vote signer identifier exceeds bound"));
        }
        let mut size = 179usize;
        for len in [
            self.vote.context.chain_id().len(),
            self.signature.validator_id.len(),
            self.signature.key_id.len(),
            self.signature.signature.len(),
        ] {
            size = size
                .checked_add(len)
                .ok_or_else(|| invalid("nil vote size overflow"))?;
        }
        if size > MAX_FIELD_LEN {
            return Err(invalid("nil vote exceeds one MiB"));
        }
        Ok(())
    }

    /// Checks structure and codec bounds without authenticating the signature.
    ///
    /// # Errors
    /// Rejects every decision (including Skip), invalid set context and codec bounds.
    pub fn new(
        vote: AgreementVote,
        signature: ValidatorSignature,
        set: &ValidatorSet,
    ) -> Result<Self, CryptoError> {
        let message = Self { vote, signature };
        message.preflight()?;
        message.vote.signing_payload(set)?;
        Ok(message)
    }

    /// Borrows the exact immutable nil statement.
    pub fn vote(&self) -> &AgreementVote {
        &self.vote
    }

    /// Borrows the untrusted signature; presence does not imply authentication.
    pub fn signature(&self) -> &ValidatorSignature {
        &self.signature
    }

    /// Encodes a canonical bounded nil-message envelope, not a signing payload.
    ///
    /// # Errors
    /// Rejects invalid set context or nested/total codec bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        self.preflight()?;
        let qc = AgreementQc {
            vote: self.vote.clone(),
            signatures: vec![self.signature.clone()],
        }
        .encode(set)?;
        let mut e = Encoder::with_capacity(7 + qc.len());
        e.put_u16(VERSION);
        e.put_u8(NIL_VOTE);
        e.put_bytes(&qc)?;
        Ok(e.finish())
    }

    /// Decodes structural evidence only; authenticates neither signer nor checkpoint.
    ///
    /// # Errors
    /// Rejects unknown versions/kinds, malformed/truncated/trailing bytes, bounds,
    /// decisions, and anything other than exactly one signature.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(invalid("nil vote exceeds one MiB"));
        }
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != VERSION || d.read_u8()? != NIL_VOTE {
            return Err(invalid("unknown nil vote version or kind"));
        }
        let qc_bytes = d.read_bytes()?;
        d.finish()?;
        // Reject counts before the QC decoder allocates owned votes/signatures.
        let mut scan = Decoder::new(qc_bytes);
        if scan.read_u16()? != 1 || scan.read_u8()? != 2 {
            return Err(invalid("expected agreement QC body"));
        }
        scan.read_bytes()?;
        if scan.read_u32()? != 1 {
            return Err(invalid("expected exactly one nil vote signature"));
        }
        let mut qc = AgreementQc::decode(qc_bytes, set)?;
        let signature = qc
            .signatures
            .pop()
            .ok_or_else(|| invalid("missing nil vote signature"))?;
        Self::new(qc.vote, signature, set)
    }

    /// Authenticates one signature over the existing agreement VOTE signing payload.
    /// No quorum, carrier, proposal, or slot decision is established.
    ///
    /// # Errors
    /// Rejects any pinned-context mismatch, invalid set, unknown/inactive key,
    /// invalid signature, or codec bounds.
    pub fn verify(&self, context: &SlotDecisionTip, set: &ValidatorSet) -> Result<(), CryptoError> {
        if self.vote.context != *context {
            return Err(invalid("nil vote pinned context mismatch"));
        }
        self.preflight()?;
        set.verify_signatures(
            &self.vote.signing_payload(set)?,
            context.epoch(),
            std::slice::from_ref(&self.signature),
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "slot_agreement_nil_vote_tests.rs"]
mod tests;
