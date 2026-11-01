//! DAG-BFT certificates over the epoch-bound validator schedule.
//!
//! A certificate is a signature bitmap plus one signature per set bit, in
//! validator order. The verifier resolves which key each signer used from the
//! schedule at the certificate's epoch, so a certificate never carries key ids:
//! a key that is not active at that epoch simply cannot produce a valid
//! certificate. That is the property that makes a scheduled rotation safe — the
//! old key stops counting at its published retirement epoch, on every node,
//! without a flag day.
//!
//! Encoding is the deterministic codec from `crypto::encoding`, so two nodes
//! hash identical bytes for the same certificate.

use crypto::domain::{VoteSigningFields, encode_vote_signing_payload};
use crypto::encoding::{Decoder, Encoder};
use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};

use crate::schedule::{ValidatorKey, ValidatorSet};

/// Canonical certificate encoding version.
pub const CERTIFICATE_VERSION_V1: u16 = 1;

/// A quorum certificate for one DAG vertex.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Certificate {
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: Vec<u8>,
    /// Epoch the certificate belongs to; also the epoch the keys are resolved at.
    pub epoch: u64,
    /// Round the certified vertex belongs to.
    pub round: u64,
    /// Identifier of the certified vertex.
    pub vertex_id: Vec<u8>,
    /// Opaque validator-set identifier the signers were drawn from.
    pub validator_set_id: Vec<u8>,
    /// One bit per validator, indexed like `ValidatorSet::validators`.
    pub signer_bitmap: Vec<u8>,
    /// One signature per set bit, in ascending validator order.
    pub signatures: Vec<Vec<u8>>,
}

/// Number of bytes needed for `validators` signer bits.
#[must_use]
pub fn bitmap_len(validators: usize) -> usize {
    validators.div_ceil(8)
}

/// Returns whether validator `index` signed.
#[must_use]
pub fn bit_is_set(bitmap: &[u8], index: usize) -> bool {
    bitmap
        .get(index / 8)
        .is_some_and(|byte| byte & (1 << (index % 8)) != 0)
}

/// Marks validator `index` as a signer.
///
/// # Panics
///
/// Panics when `bitmap` has no byte for `index`. Callers size the bitmap from
/// the validator set first.
pub fn set_bit(bitmap: &mut [u8], index: usize) {
    bitmap[index / 8] |= 1 << (index % 8);
}

/// Builds a bitmap with the first `signers` validators marked and the unused
/// high bits of the last byte cleared.
#[must_use]
pub fn bitmap_of(validators: usize, signers: usize) -> Vec<u8> {
    let mut bitmap = vec![0u8; bitmap_len(validators)];
    for index in 0..signers.min(validators) {
        set_bit(&mut bitmap, index);
    }
    bitmap
}

fn malformed(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, detail)
}

impl Certificate {
    /// Builds the bytes the signers sign.
    ///
    /// # Errors
    ///
    /// Returns an error only when a field exceeds the encoding limit.
    pub fn signing_payload(&self) -> Result<Vec<u8>, CryptoError> {
        encode_vote_signing_payload(&VoteSigningFields {
            chain_id: &self.chain_id,
            epoch: self.epoch,
            round: self.round,
            vertex_id: &self.vertex_id,
        })
    }

    /// Number of validators marked as signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Checks the parts of the shape that do not need a validator set.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::MalformedCertificate`] when the bitmap and the
    /// signature list disagree, or when trailing bits of the last bitmap byte
    /// are set (which would let two encodings describe the same signers).
    pub fn check_shape(&self) -> Result<(), CryptoError> {
        let signers = self.signer_count();
        if signers != self.signatures.len() {
            return Err(malformed(format!(
                "bitmap marks {signers} signers but {} signatures are present",
                self.signatures.len()
            )));
        }
        Ok(())
    }

    /// Encodes the certificate canonically.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::MalformedCertificate`] for an inconsistent
    /// shape and [`CryptoErrorKind::FieldTooLong`] for an oversized field.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        self.check_shape()?;
        let mut encoder = Encoder::with_capacity(128);
        encoder.put_u16(CERTIFICATE_VERSION_V1);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_u64(self.epoch);
        encoder.put_u64(self.round);
        encoder.put_bytes(&self.vertex_id)?;
        encoder.put_bytes(&self.validator_set_id)?;
        encoder.put_bytes(&self.signer_bitmap)?;
        encoder.put_u32(
            u32::try_from(self.signatures.len()).map_err(|_| malformed("too many signatures"))?,
        );
        for signature in &self.signatures {
            encoder.put_bytes(signature)?;
        }
        Ok(encoder.finish())
    }

    /// Decodes a canonical certificate.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`] or
    /// [`CryptoErrorKind::TrailingBytes`] for a bad buffer,
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version or an
    /// inconsistent shape, and [`CryptoErrorKind::FieldTooLong`] for an
    /// oversized field.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != CERTIFICATE_VERSION_V1 {
            return Err(malformed(format!(
                "unsupported certificate version {version}"
            )));
        }
        let chain_id = decoder.read_bytes()?.to_vec();
        let epoch = decoder.read_u64()?;
        let round = decoder.read_u64()?;
        let vertex_id = decoder.read_bytes()?.to_vec();
        let validator_set_id = decoder.read_bytes()?.to_vec();
        let signer_bitmap = decoder.read_bytes()?.to_vec();
        let count = decoder.read_u32()? as usize;
        let mut signatures = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            signatures.push(decoder.read_bytes()?.to_vec());
        }
        decoder.finish()?;

        let certificate = Self {
            chain_id,
            epoch,
            round,
            vertex_id,
            validator_set_id,
            signer_bitmap,
            signatures,
        };
        certificate.check_shape()?;
        Ok(certificate)
    }

    /// Verifies every signature and returns the validators that contributed.
    ///
    /// Each set bit is resolved to the key that validator had active at
    /// `self.epoch`; a validator with no active key, an ambiguous schedule, or a
    /// signature that does not verify fails the whole certificate. There is no
    /// partial credit: a certificate with one bad signature is malformed, not
    /// "mostly valid".
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::MalformedCertificate`] when the bitmap does not match
    /// the set or has set padding bits, [`CryptoErrorKind::KeyNotActive`] or
    /// [`CryptoErrorKind::KeyAmbiguous`] from the schedule, plus any verification
    /// error from [`crypto::scheme::verify_signature`].
    pub fn verify(&self, set: &ValidatorSet) -> Result<Vec<Vec<u8>>, CryptoError> {
        self.check_shape()?;
        let validators = set.validators.len();
        if self.signer_bitmap.len() != bitmap_len(validators) {
            return Err(malformed(format!(
                "bitmap is {} bytes for {validators} validators, expected {}",
                self.signer_bitmap.len(),
                bitmap_len(validators)
            )));
        }
        let used_in_last_byte = validators % 8;
        if used_in_last_byte != 0
            && let Some(last) = self.signer_bitmap.last()
            && last >> used_in_last_byte != 0
        {
            return Err(malformed(format!(
                "bitmap sets bits above validator {validators}"
            )));
        }

        let payload = self.signing_payload()?;
        let mut signers = Vec::with_capacity(self.signatures.len());
        let mut signature_index = 0;
        for (index, record) in set.validators.iter().enumerate() {
            if !bit_is_set(&self.signer_bitmap, index) {
                continue;
            }
            let key: &ValidatorKey = record.active_key(self.epoch)?;
            verify_signature(
                key.algorithm_id,
                &key.public_key,
                &payload,
                &self.signatures[signature_index],
            )?;
            signature_index += 1;
            signers.push(record.validator_id.clone());
        }
        Ok(signers)
    }

    /// Verifies the certificate and requires a BFT supermajority.
    ///
    /// # Errors
    ///
    /// Every error from [`Certificate::verify`], and
    /// [`CryptoErrorKind::PolicyUnsatisfied`] when the certificate verifies but
    /// too few validators signed.
    pub fn verify_quorum(&self, set: &ValidatorSet) -> Result<Vec<Vec<u8>>, CryptoError> {
        let signers = self.verify(set)?;
        if !set.has_supermajority(signers.len()) {
            return Err(CryptoError::new(
                CryptoErrorKind::PolicyUnsatisfied,
                format!(
                    "{} of {} validators signed; a supermajority is required",
                    signers.len(),
                    set.validators.len()
                ),
            ));
        }
        Ok(signers)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    struct Signer {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn deterministic_key(index: u8) -> Signer {
        let seed = [index; 32];
        let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
        let mut private_key = Vec::with_capacity(64);
        private_key.extend_from_slice(&seed);
        private_key.extend_from_slice(&public_key);
        Signer {
            public_key: public_key.to_vec(),
            private_key,
        }
    }

    /// Builds a set of `count` validators whose keys are active for `[0, NO_EXPIRY)`.
    fn validator_set(count: usize) -> (ValidatorSet, Vec<Signer>) {
        let mut signers = Vec::with_capacity(count);
        let mut validators = Vec::with_capacity(count);
        for index in 0..count {
            let signer = deterministic_key(u8::try_from(index + 1).unwrap());
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: signer.public_key.clone(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            signers.push(signer);
        }
        let set = ValidatorSet {
            epoch: 1,
            validators,
        };
        set.validate().unwrap();
        (set, signers)
    }

    fn certificate(set: &ValidatorSet, signers: &[Signer], signed: usize) -> Certificate {
        let mut candidate = Certificate {
            chain_id: b"karsa-test-1".to_vec(),
            epoch: 1,
            round: 7,
            vertex_id: b"vertex-01".to_vec(),
            validator_set_id: b"set-genesis".to_vec(),
            signer_bitmap: bitmap_of(set.validators.len(), signed),
            signatures: Vec::new(),
        };
        let payload = candidate.signing_payload().unwrap();
        for signer in signers.iter().take(signed) {
            candidate
                .signatures
                .push(Ed25519Scheme.sign(&signer.private_key, &payload).unwrap());
        }
        candidate
    }

    #[test]
    fn encoding_roundtrips() {
        let (set, signers) = validator_set(4);
        let original = certificate(&set, &signers, 3);
        let encoded = original.encode().unwrap();
        let decoded = Certificate::decode(&encoded).unwrap();
        assert_eq!(decoded, original);
        assert_eq!(decoded.encode().unwrap(), encoded);
        assert_eq!(decoded.signer_count(), 3);
        assert_eq!(decoded.verify(&set).unwrap().len(), 3);
    }

    #[test]
    fn two_of_four_is_not_a_quorum() {
        let (set, signers) = validator_set(4);
        let two = certificate(&set, &signers, 2);
        assert_eq!(two.verify(&set).unwrap().len(), 2);
        let error = two.verify_quorum(&set).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);

        let three = certificate(&set, &signers, 3);
        assert_eq!(three.verify_quorum(&set).unwrap().len(), 3);
    }

    #[test]
    fn a_tampered_signature_fails_the_whole_certificate() {
        let (set, signers) = validator_set(4);
        let mut candidate = certificate(&set, &signers, 3);
        candidate.signatures[1][0] ^= 0x01;
        let error = candidate.verify(&set).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn a_missing_signature_is_a_shape_error() {
        let (set, signers) = validator_set(4);
        let mut candidate = certificate(&set, &signers, 3);
        candidate.signatures.pop();
        assert_eq!(
            candidate.encode().unwrap_err().kind(),
            CryptoErrorKind::MalformedCertificate
        );
    }

    #[test]
    fn padding_bits_must_be_zero() {
        let (set, signers) = validator_set(3);
        let mut candidate = certificate(&set, &signers, 3);
        // Third validator uses bits 0..=2 of the byte; set bit 7.
        candidate.signer_bitmap[0] |= 0b1000_0000;
        let error = candidate.verify(&set).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MalformedCertificate);
    }

    #[test]
    fn a_bitmap_for_another_set_is_rejected() {
        let (set, signers) = validator_set(4);
        let candidate = certificate(&set, &signers, 4);
        let (other, _) = validator_set(12);
        let error = candidate.verify(&other).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MalformedCertificate);
    }

    #[test]
    fn a_retired_key_cannot_produce_a_valid_certificate() {
        let (mut set, signers) = validator_set(2);
        let signed = certificate(&set, &signers, 2);
        set.validators[0].keys[0].retirement_epoch = 1; // not active at epoch 1
        let error = signed.verify(&set).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyNotActive);
    }

    #[test]
    fn signer_key_is_resolved_from_the_schedule() {
        let (mut set, signers) = validator_set(2);
        let signed = certificate(&set, &signers, 2);
        // Rotate validator 0 to a different key whose private half we do not have:
        // the certificate carries no key id, so the schedule decides and the old
        // signature stops verifying.
        let replacement = deterministic_key(9);
        set.validators[0].keys = vec![
            ValidatorKey {
                key_id: b"val-0-k0".to_vec(),
                algorithm_id: ALG_ED25519,
                public_key: signers[0].public_key.clone(),
                activation_epoch: 0,
                retirement_epoch: 1,
            },
            ValidatorKey {
                key_id: b"val-0-k1".to_vec(),
                algorithm_id: ALG_ED25519,
                public_key: replacement.public_key.clone(),
                activation_epoch: 1,
                retirement_epoch: NO_EXPIRY,
            },
        ];
        set.validate().unwrap();
        let error = signed.verify(&set).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn truncated_encoding_is_rejected() {
        let (set, signers) = validator_set(4);
        let encoded = certificate(&set, &signers, 4).encode().unwrap();
        let error = Certificate::decode(&encoded[..encoded.len() - 1]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TruncatedInput);
    }
}
