//! Quorum-authorized validator fences.
//!
//! A fence is a statement by a quorum that one validator is failed from a round
//! onward. It is not a local timeout: every signature is checked against the set
//! active at the fenced round, and the certificate is what lets a pacemaker skip
//! rounds that only the failed validator could have led. A node that holds no
//! fence keeps waiting, which is the safe default; a node that holds one may
//! skip, and the quorum's honest signers would not have signed if they had voted
//! for the fenced leader.
//!
//! At most `f` validators may be fenced for one set. A certificate that would
//! exceed the fault budget is refused, because a larger fence would be a
//! statement the fault model cannot support.

use std::collections::BTreeMap;
use std::fmt;

use crypto::domain::{FenceSigningFields, encode_fence_signing_payload};
use crypto::encoding::{Decoder, Encoder};
use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};

use crate::certificate::{bit_is_set, bitmap_len, set_bit};
use crate::schedule::{ValidatorKey, ValidatorRecord, ValidatorSet};

/// Canonical fence descriptor version.
pub const FENCE_VERSION_V1: u16 = 1;

/// The signed content of one fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fence {
    /// Chain identifier.
    pub chain_id: Vec<u8>,
    /// First round at which the validator is considered failed.
    pub from_round: u64,
    /// Validator declared failed.
    pub validator_id: Vec<u8>,
}

impl Fence {
    /// Creates a fence descriptor.
    #[must_use]
    pub fn new(chain_id: impl Into<Vec<u8>>, from_round: u64, validator_id: Vec<u8>) -> Self {
        Self {
            chain_id: chain_id.into(),
            from_round,
            validator_id,
        }
    }

    /// The bytes a quorum signs.
    ///
    /// # Errors
    ///
    /// [`FenceError::Encoding`] when a field exceeds the encoding limit.
    pub fn signing_payload(&self) -> Result<Vec<u8>, FenceError> {
        encode_fence_signing_payload(&FenceSigningFields {
            chain_id: &self.chain_id,
            from_round: self.from_round,
            validator_id: &self.validator_id,
        })
        .map_err(FenceError::Encoding)
    }

    /// Writes the canonical descriptor encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::FieldTooLong`] when a field exceeds the encoding limit.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder =
            Encoder::with_capacity(32 + self.chain_id.len() + self.validator_id.len());
        encoder.put_u16(FENCE_VERSION_V1);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_u64(self.from_round);
        encoder.put_bytes(&self.validator_id)?;
        Ok(encoder.finish())
    }

    /// Reads a canonical descriptor encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`] or
    /// [`CryptoErrorKind::TrailingBytes`] for a bad buffer, and
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != FENCE_VERSION_V1 {
            return Err(codec(format!("unsupported fence version {version}")));
        }
        let chain_id = decoder.read_bytes()?.to_vec();
        let from_round = decoder.read_u64()?;
        let validator_id = decoder.read_bytes()?.to_vec();
        decoder.finish()?;
        Ok(Self {
            chain_id,
            from_round,
            validator_id,
        })
    }
}

/// A fence signed by a quorum of the set active at its round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FenceCertificate {
    /// The signed fence.
    pub fence: Fence,
    /// Bitmap of validators that signed, in set order.
    pub signer_bitmap: Vec<u8>,
    /// One signature per set bit.
    pub signatures: Vec<Vec<u8>>,
}

impl FenceCertificate {
    /// Number of validators marked as signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Verifies the chain, shape, and every present signature, without requiring
    /// a quorum.
    ///
    /// # Errors
    ///
    /// [`FenceError::Mismatch`] for another chain or a validator outside the set,
    /// [`FenceError::Malformed`] for an inconsistent bitmap, and
    /// [`FenceError::Signer`] for a key that cannot be resolved or a signature
    /// that does not verify.
    pub fn check(&self, chain_id: &[u8], set: &ValidatorSet) -> Result<(), FenceError> {
        if self.fence.chain_id != chain_id {
            return Err(FenceError::Mismatch(
                "the fence belongs to another chain".to_string(),
            ));
        }
        if set
            .validators
            .iter()
            .all(|record| record.validator_id != self.fence.validator_id)
        {
            return Err(FenceError::Mismatch(
                "the fenced validator is not in the set".to_string(),
            ));
        }
        self.check_shape(set)?;
        let payload = self.fence.signing_payload()?;
        for (_, key, signature) in self.resolve_signers(set)? {
            verify_signature(key.algorithm_id, &key.public_key, &payload, signature)
                .map_err(FenceError::Signer)?;
        }
        Ok(())
    }

    /// Verifies the certificate and requires a supermajority of the set.
    ///
    /// # Errors
    ///
    /// Every error from [`Self::check`], plus [`FenceError::NoQuorum`] when the
    /// valid signatures are too few.
    pub fn verify(&self, chain_id: &[u8], set: &ValidatorSet) -> Result<(), FenceError> {
        self.check(chain_id, set)?;
        if !set.has_supermajority(self.signer_count()) {
            return Err(FenceError::NoQuorum {
                signers: self.signer_count(),
                required: set.quorum_size(),
            });
        }
        Ok(())
    }

    /// Adds the signatures in `other` to this partial certificate.
    ///
    /// Both sides must describe the same fence. A signer already present is kept.
    /// Returns whether anything was added.
    ///
    /// # Errors
    ///
    /// [`FenceError::Mismatch`] when the certificates describe different fences,
    /// plus every error from [`Self::check`].
    pub fn merge(
        &mut self,
        other: &Self,
        chain_id: &[u8],
        set: &ValidatorSet,
    ) -> Result<bool, FenceError> {
        if self.fence != other.fence {
            return Err(FenceError::Mismatch(
                "the certificates describe different fences".to_string(),
            ));
        }
        self.check(chain_id, set)?;
        other.check(chain_id, set)?;

        let mut merged: BTreeMap<usize, Vec<u8>> = self
            .shares(set)
            .into_iter()
            .map(|(index, signature)| (index, signature.to_vec()))
            .collect();
        let mut changed = false;
        for (index, signature) in other.shares(set) {
            if let std::collections::btree_map::Entry::Vacant(slot) = merged.entry(index) {
                slot.insert(signature.to_vec());
                changed = true;
            }
        }
        if !changed {
            return Ok(false);
        }

        let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::with_capacity(merged.len());
        for (index, signature) in merged {
            set_bit(&mut bitmap, index);
            signatures.push(signature);
        }
        self.signer_bitmap = bitmap;
        self.signatures = signatures;
        Ok(true)
    }

    /// Writes the canonical certificate encoding.
    ///
    /// # Errors
    ///
    /// Every error from [`Fence::encode`], plus
    /// [`CryptoErrorKind::FieldTooLong`] for an oversized signature count.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let fence = self.fence.encode()?;
        let mut encoder = Encoder::with_capacity(fence.len() + self.signer_bitmap.len() + 64);
        encoder.put_bytes(&fence)?;
        encoder.put_bytes(&self.signer_bitmap)?;
        encoder.put_u32(count_field(self.signatures.len(), "signatures")?);
        for signature in &self.signatures {
            encoder.put_bytes(signature)?;
        }
        Ok(encoder.finish())
    }

    /// Reads a canonical certificate encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`] or
    /// [`CryptoErrorKind::TrailingBytes`] for a bad buffer,
    /// [`CryptoErrorKind::MalformedCertificate`] for an inconsistent bitmap and
    /// signature list, plus every error from [`Fence::decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let fence = Fence::decode(decoder.read_bytes()?)?;
        let signer_bitmap = decoder.read_bytes()?.to_vec();
        let signature_count = decoder.read_u32()? as usize;
        if signature_count > bytes.len() / 4 {
            return Err(codec(format!(
                "{signature_count} signatures exceed the {} byte payload",
                bytes.len()
            )));
        }
        let mut signatures = Vec::with_capacity(signature_count.min(1024));
        for _ in 0..signature_count {
            signatures.push(decoder.read_bytes()?.to_vec());
        }
        decoder.finish()?;
        let certificate = Self {
            fence,
            signer_bitmap,
            signatures,
        };
        if certificate.signer_count() != certificate.signatures.len() {
            return Err(codec(format!(
                "bitmap marks {} signers but {} signatures are present",
                certificate.signer_count(),
                certificate.signatures.len()
            )));
        }
        Ok(certificate)
    }

    fn check_shape(&self, set: &ValidatorSet) -> Result<(), FenceError> {
        let signers = self.signer_count();
        if signers != self.signatures.len() {
            return Err(malformed(format!(
                "bitmap marks {signers} signers but {} signatures are present",
                self.signatures.len()
            )));
        }
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
        Ok(())
    }

    fn resolve_signers<'a>(
        &'a self,
        set: &'a ValidatorSet,
    ) -> Result<Vec<SignedEntry<'a>>, FenceError> {
        let mut signers = Vec::with_capacity(self.signatures.len());
        let mut signature_index = 0;
        for (index, record) in set.validators.iter().enumerate() {
            if !bit_is_set(&self.signer_bitmap, index) {
                continue;
            }
            let key = record.active_key(set.epoch).map_err(FenceError::Signer)?;
            let signature = self.signatures.get(signature_index).ok_or_else(|| {
                malformed(format!(
                    "bitmap marks {} signers but only {} signatures are present",
                    self.signer_count(),
                    self.signatures.len()
                ))
            })?;
            signature_index += 1;
            signers.push((record, key, signature.as_slice()));
        }
        Ok(signers)
    }

    fn shares<'a>(&'a self, set: &'a ValidatorSet) -> Vec<(usize, &'a [u8])> {
        let mut shares = Vec::with_capacity(self.signatures.len());
        let mut signature_index = 0;
        for (index, _) in set.validators.iter().enumerate() {
            if !bit_is_set(&self.signer_bitmap, index) {
                continue;
            }
            let Some(signature) = self.signatures.get(signature_index) else {
                break;
            };
            shares.push((index, signature.as_slice()));
            signature_index += 1;
        }
        shares
    }
}

/// One resolved signer: record, active key, and signature bytes.
type SignedEntry<'a> = (&'a ValidatorRecord, &'a ValidatorKey, &'a [u8]);

/// A fence certificate or descriptor that does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FenceError {
    /// A field could not be encoded.
    Encoding(CryptoError),
    /// A signer's key could not be resolved or its signature did not verify.
    Signer(CryptoError),
    /// The bitmap or signature list is inconsistent.
    Malformed(String),
    /// The certificate does not describe this chain or this set.
    Mismatch(String),
    /// Fewer than a supermajority signed.
    NoQuorum {
        /// Distinct validators that signed.
        signers: usize,
        /// Smallest signer count that is a supermajority.
        required: usize,
    },
    /// The fence would exceed the set's fault budget.
    TooMany {
        /// Fences already installed.
        count: usize,
        /// Largest supportable fence count.
        limit: usize,
    },
}

impl fmt::Display for FenceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(f, "fence encoding: {error}"),
            Self::Signer(error) => write!(f, "fence signer: {error}"),
            Self::Malformed(detail) => write!(f, "malformed fence certificate: {detail}"),
            Self::Mismatch(detail) => write!(f, "fence mismatch: {detail}"),
            Self::NoQuorum { signers, required } => {
                write!(f, "{signers} validators signed; {required} required")
            }
            Self::TooMany { count, limit } => {
                write!(f, "{count} fences exceed the fault budget {limit}")
            }
        }
    }
}

impl std::error::Error for FenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(error) | Self::Signer(error) => Some(error),
            Self::Malformed(_)
            | Self::Mismatch(_)
            | Self::NoQuorum { .. }
            | Self::TooMany { .. } => None,
        }
    }
}

fn malformed(detail: impl Into<String>) -> FenceError {
    FenceError::Malformed(detail.into())
}

fn codec(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, detail)
}

fn count_field(count: usize, what: &str) -> Result<u32, CryptoError> {
    u32::try_from(count).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{what} count does not fit a u32"),
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const CHAIN: &[u8] = b"karsa-fence-1";

    struct Signer {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn signer(index: usize) -> Signer {
        let seed = [u8::try_from(index + 1).expect("fewer than 255 signers"); 32];
        let public_key = Ed25519Scheme::public_key_from_seed(&seed).expect("a seed is a key");
        let mut private_key = seed.to_vec();
        private_key.extend_from_slice(&public_key);
        Signer {
            public_key: public_key.to_vec(),
            private_key,
        }
    }

    fn fixture(count: usize) -> (ValidatorSet, Vec<Signer>) {
        let signers: Vec<Signer> = (0..count).map(signer).collect();
        let validators = signers
            .iter()
            .enumerate()
            .map(|(index, signer)| ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: signer.public_key.clone(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect();
        let set = ValidatorSet {
            epoch: 1,
            validators,
        };
        set.validate().expect("the fixture set is valid");
        (set, signers)
    }

    fn certificate(
        fence: Fence,
        set: &ValidatorSet,
        signers: &[Signer],
        signed: usize,
    ) -> FenceCertificate {
        let payload = fence
            .signing_payload()
            .expect("the fixture payload encodes");
        let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::with_capacity(signed);
        for (index, signer) in signers.iter().take(signed).enumerate() {
            set_bit(&mut bitmap, index);
            signatures.push(
                Ed25519Scheme
                    .sign(&signer.private_key, &payload)
                    .expect("the fixture key signs"),
            );
        }
        FenceCertificate {
            fence,
            signer_bitmap: bitmap,
            signatures,
        }
    }

    #[test]
    fn a_quorum_fence_verifies() {
        let (set, signers) = fixture(4);
        let fence = Fence::new(CHAIN.to_vec(), 7, b"val-0".to_vec());
        let certificate = certificate(fence, &set, &signers, 3);
        certificate
            .verify(CHAIN, &set)
            .expect("three of four is a quorum");
    }

    #[test]
    fn fewer_than_a_quorum_is_rejected() {
        let (set, signers) = fixture(4);
        let fence = Fence::new(CHAIN.to_vec(), 7, b"val-0".to_vec());
        let certificate = certificate(fence, &set, &signers, 2);
        let error = certificate.verify(CHAIN, &set).unwrap_err();
        assert!(matches!(
            error,
            FenceError::NoQuorum {
                signers: 2,
                required: 3
            }
        ));
    }

    #[test]
    fn a_fence_for_another_chain_or_another_set_is_rejected() {
        let (set, signers) = fixture(4);
        let fence = Fence::new(CHAIN.to_vec(), 7, b"val-0".to_vec());
        let first = certificate(fence, &set, &signers, 3);
        assert!(matches!(
            first.verify(b"another-chain", &set),
            Err(FenceError::Mismatch(_))
        ));

        let fence = Fence::new(CHAIN.to_vec(), 7, b"not-in-set".to_vec());
        let second = certificate(fence, &set, &signers, 3);
        assert!(matches!(
            second.verify(CHAIN, &set),
            Err(FenceError::Mismatch(_))
        ));
    }

    #[test]
    fn partial_fences_merge_until_the_quorum_is_reached() {
        let (set, signers) = fixture(4);
        let fence = Fence::new(CHAIN.to_vec(), 7, b"val-0".to_vec());
        let payload = fence.signing_payload().unwrap();
        let partial = || FenceCertificate {
            fence: fence.clone(),
            signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
            signatures: Vec::new(),
        };
        let share = |index: usize| {
            let mut certificate = partial();
            set_bit(&mut certificate.signer_bitmap, index);
            certificate.signatures.push(
                Ed25519Scheme
                    .sign(&signers[index].private_key, &payload)
                    .unwrap(),
            );
            certificate
        };

        let mut merged = partial();
        assert!(merged.merge(&share(0), CHAIN, &set).unwrap());
        assert!(merged.merge(&share(1), CHAIN, &set).unwrap());
        assert!(!merged.merge(&share(0), CHAIN, &set).unwrap());
        assert!(matches!(
            merged.verify(CHAIN, &set),
            Err(FenceError::NoQuorum { signers: 2, .. })
        ));
        assert!(merged.merge(&share(2), CHAIN, &set).unwrap());
        merged
            .verify(CHAIN, &set)
            .expect("three of four is a quorum");
    }

    #[test]
    fn a_fence_certificate_roundtrips() {
        let (set, signers) = fixture(4);
        let fence = Fence::new(CHAIN.to_vec(), 7, b"val-0".to_vec());
        let certificate = certificate(fence, &set, &signers, 3);
        let encoded = certificate.encode().unwrap();
        let decoded = FenceCertificate::decode(&encoded).unwrap();
        assert_eq!(decoded, certificate);
        decoded.verify(CHAIN, &set).unwrap();
    }
}
