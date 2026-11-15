//! Inactive, inert authenticated advisory requests, never promises or remote sync completion.
//!
//! A signature states only advisory support/request for the target view. It makes no
//! timer claim or signing-floor promise, has no reducer side effects, and must never
//! be counted as a promise. This is not a certificate, entry, vote, or authorization.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};

use crate::slot_agreement::AgreementView;
use crate::{SlotDecisionTip, ValidatorSet, ValidatorSignature};

/// Independent domain for advisory view requests, not agreement votes or promises.
pub const SLOT_AGREEMENT_VIEW_REQUEST_DOMAIN: &[u8] = b"KARSA/SLOT_AGREEMENT/VIEW_REQUEST/v1";
const VERSION: u16 = 1;
const MAX_ID: usize = 1024;
// Version, chain prefix, three prefixed digests, four u64s, three signature prefixes.
const FIXED_SIZE: usize = 2 + 4 + 3 * 36 + 4 * 8 + 3 * 4;

fn invalid(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

fn id<'a>(d: &mut Decoder<'a>) -> Result<&'a [u8], CryptoError> {
    let bytes = d.read_bytes()?;
    if bytes.is_empty() || bytes.len() > MAX_ID {
        return Err(invalid("invalid view request identifier length"));
    }
    Ok(bytes)
}

fn digest(d: &mut Decoder<'_>) -> Result<[u8; 32], CryptoError> {
    d.read_bytes()?
        .try_into()
        .map_err(|_| invalid("invalid view request digest length"))
}

/// Immutable advisory support/request for a target view, with no protocol effects.
///
/// Construction and decoding validate structure only. Explicit verification authenticates
/// one active member, not a quorum or checkpoint. No timer expiry, signing-floor promise,
/// remote sync completion, or reducer transition follows; never count this as a promise.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementViewRequest {
    context: SlotDecisionTip,
    target_view: AgreementView,
    signature: ValidatorSignature,
}

impl SlotAgreementViewRequest {
    fn preflight(&self) -> Result<usize, CryptoError> {
        for id in [&self.signature.validator_id, &self.signature.key_id] {
            if id.is_empty() || id.len() > MAX_ID {
                return Err(invalid("invalid view request signer identifier length"));
            }
        }
        if self.signature.signature.is_empty() {
            return Err(invalid("empty view request signature"));
        }
        let mut size = FIXED_SIZE;
        for len in [
            self.context.chain_id().len(),
            self.signature.validator_id.len(),
            self.signature.key_id.len(),
            self.signature.signature.len(),
        ] {
            size = size
                .checked_add(len)
                .ok_or_else(|| invalid("view request size overflow"))?;
        }
        if size > MAX_FIELD_LEN {
            return Err(invalid("view request exceeds one MiB"));
        }
        Ok(size)
    }

    /// Checks signature shape, bounds, positive target and full fixed-set context, not authenticity.
    ///
    /// # Errors
    /// Rejects empty/oversized signer or key IDs, empty signatures, bounds or invalid context/target.
    pub fn new(
        context: SlotDecisionTip,
        target_view: AgreementView,
        signature: ValidatorSignature,
        set: &ValidatorSet,
    ) -> Result<Self, CryptoError> {
        let request = Self {
            context,
            target_view,
            signature,
        };
        request.preflight()?;
        Self::signing_payload(&request.context, target_view, set)?;
        Ok(request)
    }

    /// Borrows the complete immutable, not necessarily trusted context.
    pub fn context(&self) -> &SlotDecisionTip {
        &self.context
    }

    /// Returns the advisory target, independent of any timer or signing floor.
    pub fn target_view(&self) -> AgreementView {
        self.target_view
    }

    /// Borrows the structurally checked but not necessarily authentic signature.
    pub fn signature(&self) -> &ValidatorSignature {
        &self.signature
    }

    /// Returns independent-domain bytes for advisory support/request only.
    ///
    /// # Errors
    /// Rejects zero targets and contexts not exactly bound to the supplied valid set.
    pub fn signing_payload(
        context: &SlotDecisionTip,
        target_view: AgreementView,
        set: &ValidatorSet,
    ) -> Result<Vec<u8>, CryptoError> {
        let c = context;
        let checked = SlotDecisionTip::from_checkpoint(
            c.chain_id().to_vec(),
            set,
            c.next_round(),
            *c.previous_id(),
            c.order_len(),
            *c.order_root(),
        )?;
        if checked != *c || target_view.0 == 0 {
            return Err(invalid("view request context mismatch or zero target"));
        }
        let mut e = Encoder::new();
        e.put_bytes(SLOT_AGREEMENT_VIEW_REQUEST_DOMAIN)?;
        e.put_bytes(c.chain_id())?;
        e.put_raw(c.set_id());
        e.put_u64(c.epoch());
        e.put_u64(c.next_round());
        e.put_raw(c.previous_id());
        e.put_u64(c.order_len());
        e.put_raw(c.order_root());
        e.put_u64(target_view.0);
        Ok(e.finish())
    }

    /// Encodes a bounded versioned canonical body, distinct from the signing payload.
    ///
    /// # Errors
    /// Rejects structural, context, target or total-size errors.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        let size = self.preflight()?;
        Self::signing_payload(&self.context, self.target_view, set)?;
        let c = &self.context;
        let mut e = Encoder::with_capacity(size);
        e.put_u16(VERSION);
        e.put_bytes(c.chain_id())?;
        e.put_bytes(c.set_id())?;
        e.put_u64(c.epoch());
        e.put_u64(c.next_round());
        e.put_bytes(c.previous_id())?;
        e.put_u64(c.order_len());
        e.put_bytes(c.order_root())?;
        e.put_u64(self.target_view.0);
        e.put_bytes(&self.signature.validator_id)?;
        e.put_bytes(&self.signature.key_id)?;
        e.put_bytes(&self.signature.signature)?;
        debug_assert_eq!(e.len(), size);
        Ok(e.finish())
    }

    /// Decodes structural evidence only, without authenticating signer or checkpoint.
    ///
    /// # Errors
    /// Rejects unknown versions, malformed/truncated/trailing bytes, bounds and invalid context/target.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(invalid("view request exceeds one MiB"));
        }
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != VERSION {
            return Err(invalid("unknown view request version"));
        }
        let chain = d.read_bytes()?;
        if chain.len() > MAX_ID {
            return Err(invalid("view request chain exceeds bound"));
        }
        let set_id = digest(&mut d)?;
        let epoch = d.read_u64()?;
        let slot = d.read_u64()?;
        let previous = digest(&mut d)?;
        let len = d.read_u64()?;
        let root = digest(&mut d)?;
        let target = AgreementView(d.read_u64()?);
        let signer = id(&mut d)?;
        let key = id(&mut d)?;
        let signature = d.read_bytes()?;
        d.finish()?;
        let context =
            SlotDecisionTip::from_checkpoint(chain.to_vec(), set, slot, previous, len, root)?;
        if *context.set_id() != set_id || context.epoch() != epoch {
            return Err(invalid("view request set or epoch mismatch"));
        }
        Self::new(
            context,
            target,
            ValidatorSignature {
                validator_id: signer.to_vec(),
                key_id: key.to_vec(),
                signature: signature.to_vec(),
            },
            set,
        )
    }

    /// Authenticates one active member against the exact trusted full context; remains inert.
    ///
    /// # Errors
    /// Rejects pinned-context/set mismatch, invalid structure, unknown/inactive keys or bad signatures.
    pub fn verify(&self, context: &SlotDecisionTip, set: &ValidatorSet) -> Result<(), CryptoError> {
        if self.context != *context {
            return Err(invalid("view request pinned context mismatch"));
        }
        self.preflight()?;
        let payload = Self::signing_payload(context, self.target_view, set)?;
        set.verify_signatures(
            &payload,
            context.epoch(),
            std::slice::from_ref(&self.signature),
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "slot_agreement_view_request_tests.rs"]
mod tests;
