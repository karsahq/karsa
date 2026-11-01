//! Signature schemes behind a narrow interface.
//!
//! The interface follows `docs/architecture.md` §4.3: an algorithm id,
//! public-key validation, and verification. The production path uses static
//! dispatch in [`verify_signature`] rather than trait objects, so the hot path
//! has no vtable lookup.

use curve25519_dalek::edwards::CompressedEdwardsY;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey, verify_batch};
use rand_core::OsRng;

use crate::encoding::MAX_FIELD_LEN;
use crate::error::{CryptoError, CryptoErrorKind};
use crate::registry::{self, ALG_ED25519, AlgorithmSpec};

/// Ed25519 seed length, per RFC 8032.
pub const ED25519_SEED_SIZE: usize = 32;
/// Ed25519 public-key length.
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;
/// Ed25519 private-key length in the Karsa encoding: seed followed by public key.
pub const ED25519_PRIVATE_KEY_SIZE: usize = 64;
/// Ed25519 signature length.
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// The per-algorithm interface for verification.
///
/// Implementations must be deterministic: the same key, message, and signature
/// always produce the same outcome and the same error kind.
pub trait SignatureScheme {
    /// Returns the registry id of this scheme.
    fn algorithm_id(&self) -> u16;

    /// Checks that `public_key` has the canonical encoding for this algorithm.
    ///
    /// # Errors
    ///
    /// Returns an encoding error when the key is the wrong length.
    fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CryptoError>;

    /// Verifies one signature.
    ///
    /// # Errors
    ///
    /// Returns a malformed-input error for a wrong-length key or signature, and
    /// [`CryptoErrorKind::InvalidSignature`] when a well-formed signature does
    /// not verify.
    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError>;
}

/// Ed25519 (RFC 8032) wired into the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct Ed25519Scheme;

impl Ed25519Scheme {
    /// Derives the public key for a 32-byte seed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::MalformedPrivateKey`] when the seed is the
    /// wrong length.
    pub fn public_key_from_seed(seed: &[u8]) -> Result<[u8; ED25519_PUBLIC_KEY_SIZE], CryptoError> {
        let key_seed = copy_seed(seed)?;
        let key = SigningKey::from_bytes(&key_seed);
        Ok(key.verifying_key().to_bytes())
    }

    /// Produces a signature from Karsa's 64-byte `seed || public_key` encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::MalformedPrivateKey`] when the key is the wrong
    /// length or its public half does not match the seed. The mismatch check
    /// exists because `ed25519-dalek` ignores the public half: signing with a
    /// mismatched pair would produce a signature that verifies under a different
    /// key than the caller expects.
    pub fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedPrivateKey,
                format!(
                    "want {ED25519_PRIVATE_KEY_SIZE} bytes, got {}",
                    private_key.len()
                ),
            ));
        }
        let key_seed = copy_seed(&private_key[..ED25519_SEED_SIZE])?;
        let key = SigningKey::from_bytes(&key_seed);
        let derived = key.verifying_key().to_bytes();
        if private_key[ED25519_SEED_SIZE..] != derived {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedPrivateKey,
                "public half does not match the seed",
            ));
        }
        Ok(key.sign(message).to_bytes().to_vec())
    }

    /// Generates a fresh key pair from the operating system CSPRNG.
    ///
    /// Returns the 32-byte public key and the 64-byte `seed || public_key`
    /// private key used by the rest of the crate.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::EntropyFailure`] when the OS randomness source
    /// fails.
    pub fn generate_keypair() -> Result<
        (
            [u8; ED25519_PUBLIC_KEY_SIZE],
            [u8; ED25519_PRIVATE_KEY_SIZE],
        ),
        CryptoError,
    > {
        let key = SigningKey::generate(&mut OsRng);
        let public_key = key.verifying_key().to_bytes();
        let mut private_key = [0u8; ED25519_PRIVATE_KEY_SIZE];
        private_key[..ED25519_SEED_SIZE].copy_from_slice(&key.to_bytes());
        private_key[ED25519_SEED_SIZE..].copy_from_slice(&public_key);
        Ok((public_key, private_key))
    }
}

impl SignatureScheme for Ed25519Scheme {
    fn algorithm_id(&self) -> u16 {
        ALG_ED25519
    }

    fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CryptoError> {
        parse_public_key(public_key).map(|_| ())
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        let key = parse_public_key(public_key)?;
        let signature = parse_signature(signature)?;

        // `verify_strict` rejects small-order components and non-canonical
        // encodings, matching what the V implementation and OpenSSL do.
        key.verify_strict(message, &signature).map_err(|_| {
            CryptoError::new(
                CryptoErrorKind::InvalidSignature,
                "ed25519: signature does not verify",
            )
        })
    }
}

/// Parses a canonical Ed25519 public key.
///
/// A point of small order is rejected as malformed rather than merely invalid:
/// such a key can never produce a signature that `verify_strict` accepts, and
/// accepting one into a set would weaken batch verification, whose equation does
/// not test small-order public keys the way single-signature verification does.
fn parse_public_key(public_key: &[u8]) -> Result<VerifyingKey, CryptoError> {
    if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            format!(
                "ed25519: want {ED25519_PUBLIC_KEY_SIZE} bytes, got {}",
                public_key.len()
            ),
        ));
    }
    let mut key_bytes = [0u8; ED25519_PUBLIC_KEY_SIZE];
    key_bytes.copy_from_slice(public_key);
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            "ed25519: public key is not a canonical point",
        )
    })?;
    if key.is_weak() {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            "ed25519: public key is a small-order point",
        ));
    }
    Ok(key)
}

fn parse_signature(signature: &[u8]) -> Result<Signature, CryptoError> {
    if signature.len() != ED25519_SIGNATURE_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedSignature,
            format!(
                "ed25519: want {ED25519_SIGNATURE_SIZE} bytes, got {}",
                signature.len()
            ),
        ));
    }
    let mut signature_bytes = [0u8; ED25519_SIGNATURE_SIZE];
    signature_bytes.copy_from_slice(signature);
    Ok(Signature::from_bytes(&signature_bytes))
}

/// Returns whether the signature's `R` is unusable.
///
/// `verify_strict` rejects a small-order `R`; the batch equation does not, so a
/// batch verifier has to check it explicitly or it would accept a signature the
/// single-signature path rejects. A `R` that does not decompress also fails.
fn has_unusable_r(signature: &Signature) -> bool {
    CompressedEdwardsY(*signature.r_bytes())
        .decompress()
        .is_none_or(|point| point.is_small_order())
}

/// One signature in a batch.
#[derive(Debug, Clone, Copy)]
pub struct Ed25519BatchEntry<'a> {
    /// Canonical 32-byte public key.
    pub public_key: &'a [u8],
    /// The message this signature covers.
    pub message: &'a [u8],
    /// The 64-byte signature.
    pub signature: &'a [u8],
}

/// Verifies many Ed25519 signatures with one multi-scalar multiplication.
///
/// The accept/reject decision is the same as verifying each entry with
/// [`Ed25519Scheme`]: canonical and non-small-order public keys, canonical `s`, a
/// usable `R`, and a valid equation. The batch randomness is derived from a
/// transcript over the inputs, not from the operating system, so two nodes
/// checking the same certificate reach the same verdict.
///
/// An empty batch verifies vacuously.
///
/// # Errors
///
/// Returns a malformed-input error for a wrong-length key or signature, and
/// [`CryptoErrorKind::InvalidSignature`] when any entry does not verify. The
/// error does not say which entry failed, because the batch equation cannot
/// attribute a failure.
pub fn verify_ed25519_batch(entries: &[Ed25519BatchEntry<'_>]) -> Result<(), CryptoError> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut keys = Vec::with_capacity(entries.len());
    let mut signatures = Vec::with_capacity(entries.len());
    let mut messages = Vec::with_capacity(entries.len());
    for entry in entries {
        let key = parse_public_key(entry.public_key)?;
        let signature = parse_signature(entry.signature)?;
        if has_unusable_r(&signature) {
            return Err(CryptoError::new(
                CryptoErrorKind::InvalidSignature,
                "ed25519: signature R is a small-order point",
            ));
        }
        keys.push(key);
        signatures.push(signature);
        messages.push(entry.message);
    }
    verify_batch(&messages, &signatures, &keys).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::InvalidSignature,
            "ed25519: batch does not verify",
        )
    })
}

fn copy_seed(seed: &[u8]) -> Result<[u8; ED25519_SEED_SIZE], CryptoError> {
    if seed.len() != ED25519_SEED_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            format!(
                "ed25519: seed must be {ED25519_SEED_SIZE} bytes, got {}",
                seed.len()
            ),
        ));
    }
    let mut key_seed = [0u8; ED25519_SEED_SIZE];
    key_seed.copy_from_slice(seed);
    Ok(key_seed)
}

/// The canonical consensus-critical verification entry point.
///
/// Resolves the registry entry and checks the canonical sizes before any
/// expensive work, then dispatches statically per algorithm.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::UnknownAlgorithm`] for an unknown id,
/// [`CryptoErrorKind::UnsupportedAlgorithm`] for a non-signature or unimplemented
/// algorithm, [`CryptoErrorKind::AlgorithmNotEnabled`] for a gated one, a
/// malformed-input error for a wrong-length key or signature, and
/// [`CryptoErrorKind::InvalidSignature`] when verification fails.
pub fn verify_signature(
    algorithm_id: u16,
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    let spec = registry::require_signature_algorithm(algorithm_id)?;
    check_sizes(spec, public_key, signature)?;
    if message.len() > MAX_FIELD_LEN {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("message of {} bytes exceeds {MAX_FIELD_LEN}", message.len()),
        ));
    }
    match algorithm_id {
        ALG_ED25519 => Ed25519Scheme.verify(public_key, message, signature),
        #[cfg(feature = "pq-openssl")]
        registry::ALG_ML_DSA_65 => crate::ml_dsa::verify(public_key, message, signature),
        #[cfg(feature = "pq-slh")]
        registry::ALG_SLH_DSA_SHA2_128S => crate::slh_dsa::verify(public_key, message, signature),
        _ => Err(CryptoError::new(
            CryptoErrorKind::UnsupportedAlgorithm,
            format!("no verifier wired for algorithm id 0x{algorithm_id:04x}"),
        )),
    }
}

fn check_sizes(
    spec: &AlgorithmSpec,
    public_key: &[u8],
    signature: &[u8],
) -> Result<(), CryptoError> {
    if public_key.len() != spec.public_key_size {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            format!(
                "{}: want {} bytes, got {}",
                spec.name,
                spec.public_key_size,
                public_key.len()
            ),
        ));
    }
    if signature.len() != spec.signature_size {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedSignature,
            format!(
                "{}: want {} bytes, got {}",
                spec.name,
                spec.signature_size,
                signature.len()
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Vector {
        seed: &'static str,
        public_key: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    // RFC 8032 §7.1. These are the same three vectors the V prototype uses.
    const RFC8032: [Vector; 3] = [
        Vector {
            seed: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            public_key: "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            message: "",
            signature: "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
                        b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        },
        Vector {
            seed: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            public_key: "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            message: "72",
            signature: "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
                        085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        },
        Vector {
            seed: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
            public_key: "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
            message: "af82",
            signature: "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac\
                        18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
        },
    ];

    fn decode_hex(input: &str) -> Vec<u8> {
        assert!(input.len().is_multiple_of(2), "odd-length hex");
        (0..input.len() / 2)
            .map(|index| {
                u8::from_str_radix(&input[index * 2..index * 2 + 2], 16).expect("valid hex")
            })
            .collect()
    }

    fn private_key(seed: &[u8]) -> Vec<u8> {
        let public_key = Ed25519Scheme::public_key_from_seed(seed).unwrap();
        let mut key = seed.to_vec();
        key.extend_from_slice(&public_key);
        key
    }

    #[test]
    fn rfc8032_public_key_derivation() {
        for vector in &RFC8032 {
            let derived = Ed25519Scheme::public_key_from_seed(&decode_hex(vector.seed)).unwrap();
            assert_eq!(derived.to_vec(), decode_hex(vector.public_key));
        }
    }

    #[test]
    fn rfc8032_signature_verification() {
        for vector in &RFC8032 {
            let public_key = decode_hex(vector.public_key);
            let message = decode_hex(vector.message);
            let signature = decode_hex(vector.signature);
            verify_signature(ALG_ED25519, &public_key, &message, &signature)
                .unwrap_or_else(|error| panic!("vector rejected: {error}"));
        }
    }

    #[test]
    fn rfc8032_signing_is_deterministic() {
        let vector = &RFC8032[0];
        let key = private_key(&decode_hex(vector.seed));
        let signature = Ed25519Scheme
            .sign(&key, &decode_hex(vector.message))
            .unwrap();
        assert_eq!(signature, decode_hex(vector.signature));
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let vector = &RFC8032[2];
        let public_key = decode_hex(vector.public_key);
        let message = decode_hex(vector.message);
        let mut signature = decode_hex(vector.signature);
        signature[10] ^= 0x01;

        let error = verify_signature(ALG_ED25519, &public_key, &message, &signature).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn wrong_message_is_rejected() {
        let vector = &RFC8032[2];
        let public_key = decode_hex(vector.public_key);
        let signature = decode_hex(vector.signature);

        let error = verify_signature(ALG_ED25519, &public_key, b"a different message", &signature)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn malformed_public_key_is_rejected_before_verification() {
        let error = verify_signature(ALG_ED25519, &[0u8; 31], b"hello", &[0u8; 64]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MalformedPublicKey);
    }

    #[test]
    fn malformed_signature_length_is_rejected() {
        let public_key = decode_hex(RFC8032[0].public_key);
        let error = verify_signature(ALG_ED25519, &public_key, b"hello", &[0u8; 63]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MalformedSignature);
    }

    #[test]
    fn ml_dsa_verification_follows_the_registry_status() {
        // Zero bytes are never a valid ML-DSA key, so an enabled build must fail
        // as malformed input rather than accept anything.
        let result = verify_signature(
            registry::ALG_ML_DSA_65,
            &vec![0u8; 1952],
            b"hello",
            &vec![0u8; 3309],
        );
        if registry::ml_dsa_enabled() {
            let kind = result.unwrap_err().kind();
            assert!(
                matches!(
                    kind,
                    CryptoErrorKind::InvalidSignature
                        | CryptoErrorKind::MalformedPublicKey
                        | CryptoErrorKind::BackendFailure
                ),
                "unexpected error kind {kind:?}"
            );
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                CryptoErrorKind::AlgorithmNotEnabled
            );
        }
    }

    #[test]
    fn unknown_algorithm_fails_closed() {
        let error = verify_signature(0x9999, b"key", b"message", b"signature").unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::UnknownAlgorithm);
    }

    #[test]
    fn mismatched_public_half_is_rejected() {
        let key = private_key(&decode_hex(RFC8032[0].seed));
        let mut broken = key.clone();
        broken[40] ^= 0xff;
        let error = Ed25519Scheme.sign(&broken, b"hello").unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::MalformedPrivateKey);
    }

    #[test]
    fn key_generation_roundtrips() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let signature = Ed25519Scheme.sign(&private_key, b"generated").unwrap();
        verify_signature(ALG_ED25519, &public_key, b"generated", &signature).unwrap();
        assert_eq!(&private_key[ED25519_SEED_SIZE..], &public_key);
    }
}
