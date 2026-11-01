//! SLH-DSA-SHA2-128s (FIPS 205) through the pure-Rust `slh-dsa` crate.
//!
//! Compiled only with the `pq-slh` feature. Unlike [`crate::ml_dsa`] this backend
//! needs no system library: the hash-based construction is implemented in Rust,
//! so the build stays portable and the verifier is available on any target the
//! crate supports.
//!
//! The protocol always signs and verifies with an empty context, because domain
//! separation is carried inside the signed payload. The context-aware entry
//! points exist so published ACVP vectors, which use an explicit context, can be
//! checked against the same backend.
//!
//! Costs are not symmetric. SLH-DSA-SHA2-128s is the *small-signature* variant:
//! verification is milliseconds, signing is hundreds of milliseconds, and every
//! signature is 7,856 bytes. It is registered for crypto-agility, not because it
//! is a sensible default for the consensus hot path.

use rand_core::{OsRng, RngCore};
use slh_dsa::signature::Keypair;
use slh_dsa::{Sha2_128s, Signature, SigningKey, VerifyingKey};

use crate::error::{CryptoError, CryptoErrorKind};
use crate::registry::ALG_SLH_DSA_SHA2_128S;
use crate::scheme::SignatureScheme;

/// Bytes of one FIPS 205 `n` value at the 128-s security level.
const N: usize = 16;
/// Seed material for key generation: `SK.seed ‖ SK.prf ‖ PK.seed`.
pub const SLH_DSA_SHA2_128S_SEED_SIZE: usize = 3 * N;
/// Canonical SLH-DSA-SHA2-128s public-key length: `PK.seed ‖ PK.root`.
pub const SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE: usize = 2 * N;
/// Canonical private-key length: `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root`.
pub const SLH_DSA_SHA2_128S_PRIVATE_KEY_SIZE: usize = 4 * N;
/// Canonical signature length.
pub const SLH_DSA_SHA2_128S_SIGNATURE_SIZE: usize = 7856;
/// FIPS 205 limit on the context string.
pub const MAX_CONTEXT_LEN: usize = 255;

fn backend_error(detail: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::BackendFailure, detail)
}

fn check_context(context: &[u8]) -> Result<(), CryptoError> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!(
                "slh-dsa-sha2-128s: context of {} bytes exceeds {MAX_CONTEXT_LEN}",
                context.len()
            ),
        ));
    }
    Ok(())
}

fn import_public_key(public_key: &[u8]) -> Result<VerifyingKey<Sha2_128s>, CryptoError> {
    VerifyingKey::<Sha2_128s>::try_from(public_key).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            "slh-dsa-sha2-128s: cannot import public key",
        )
    })
}

fn import_private_key(private_key: &[u8]) -> Result<SigningKey<Sha2_128s>, CryptoError> {
    SigningKey::<Sha2_128s>::try_from(private_key).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            "slh-dsa-sha2-128s: cannot import private key",
        )
    })
}

/// Builds a signing key from `SK.seed ‖ SK.prf ‖ PK.seed`, the three `n`-byte
/// values FIPS 205 §9.1 key generation consumes.
///
/// Lengths are checked here because the crate's seed constructors panic on a
/// slice of the wrong size.
fn key_from_seed(seed: &[u8]) -> Result<SigningKey<Sha2_128s>, CryptoError> {
    if seed.len() != SLH_DSA_SHA2_128S_SEED_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            format!(
                "slh-dsa-sha2-128s: seed must be {SLH_DSA_SHA2_128S_SEED_SIZE} bytes, got {}",
                seed.len()
            ),
        ));
    }
    let (sk_seed, rest) = seed.split_at(N);
    let (sk_prf, pk_seed) = rest.split_at(N);
    Ok(SigningKey::<Sha2_128s>::slh_keygen_internal(
        sk_seed, sk_prf, pk_seed,
    ))
}

/// Derives the public key for 96 bytes of FIPS 205 seed material.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::MalformedPrivateKey`] for a wrong-length seed.
pub fn public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    Ok(key_from_seed(seed)?.verifying_key().to_vec())
}

/// Generates a key pair from the operating system CSPRNG.
///
/// Returns `(public_key, private_key)` in canonical FIPS 205 encodings.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::BackendFailure`] when the derived key has an
/// unexpected size.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut seed = [0u8; SLH_DSA_SHA2_128S_SEED_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed);
    let key = key_from_seed(&seed)?;
    let public_key = key.verifying_key().to_vec();
    let private_key = key.to_vec();
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE
        || private_key.len() != SLH_DSA_SHA2_128S_PRIVATE_KEY_SIZE
    {
        return Err(backend_error("slh-dsa-sha2-128s: unexpected key length"));
    }
    Ok((public_key, private_key))
}

/// Signs with an explicit FIPS 205 context string.
///
/// Signing is deterministic: the FIPS 205 randomizer is derived from the key and
/// the message, so the same inputs always produce the same signature.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::MalformedPrivateKey`] for a wrong-length key,
/// [`CryptoErrorKind::FieldTooLong`] for an oversized context, and
/// [`CryptoErrorKind::BackendFailure`] when the backend rejects the request.
pub fn sign_with_context(
    private_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_context(context)?;
    if private_key.len() != SLH_DSA_SHA2_128S_PRIVATE_KEY_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            format!(
                "slh-dsa-sha2-128s: want {SLH_DSA_SHA2_128S_PRIVATE_KEY_SIZE} bytes, got {}",
                private_key.len()
            ),
        ));
    }
    let key = import_private_key(private_key)?;
    let signature = key
        .try_sign_with_context(message, context, None)
        .map_err(|_| backend_error("slh-dsa-sha2-128s: signing failed"))?;
    let encoded = signature.to_vec();
    if encoded.len() != SLH_DSA_SHA2_128S_SIGNATURE_SIZE {
        return Err(backend_error(
            "slh-dsa-sha2-128s: unexpected signature length",
        ));
    }
    Ok(encoded)
}

/// Verifies with an explicit FIPS 205 context string.
///
/// # Errors
///
/// Returns a malformed-input error for a wrong-length key or signature, a field
/// error for an oversized context, and [`CryptoErrorKind::InvalidSignature`]
/// when a well-formed signature does not verify.
pub fn verify_with_context(
    public_key: &[u8],
    message: &[u8],
    signature: &[u8],
    context: &[u8],
) -> Result<(), CryptoError> {
    check_context(context)?;
    if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            format!(
                "slh-dsa-sha2-128s: want {SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE} bytes, got {}",
                public_key.len()
            ),
        ));
    }
    if signature.len() != SLH_DSA_SHA2_128S_SIGNATURE_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedSignature,
            format!(
                "slh-dsa-sha2-128s: want {SLH_DSA_SHA2_128S_SIGNATURE_SIZE} bytes, got {}",
                signature.len()
            ),
        ));
    }

    let key = import_public_key(public_key)?;
    let parsed = Signature::<Sha2_128s>::try_from(signature).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedSignature,
            "slh-dsa-sha2-128s: cannot import signature",
        )
    })?;
    key.try_verify_with_context(message, context, &parsed)
        .map_err(|_| {
            CryptoError::new(
                CryptoErrorKind::InvalidSignature,
                "slh-dsa-sha2-128s: signature does not verify",
            )
        })
}

/// SLH-DSA-SHA2-128s wired into the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct SlhDsaSha2_128sScheme;

impl SignatureScheme for SlhDsaSha2_128sScheme {
    fn algorithm_id(&self) -> u16 {
        ALG_SLH_DSA_SHA2_128S
    }

    fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CryptoError> {
        if public_key.len() != SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedPublicKey,
                format!(
                    "slh-dsa-sha2-128s: want {SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE} bytes, got {}",
                    public_key.len()
                ),
            ));
        }
        Ok(())
    }

    fn verify(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), CryptoError> {
        verify_with_context(public_key, message, signature, &[])
    }
}

/// Verifies one SLH-DSA-SHA2-128s signature through the canonical entry point.
///
/// # Errors
///
/// Propagates [`verify_with_context`] errors with an empty context.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), CryptoError> {
    verify_with_context(public_key, message, signature, &[])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry;
    use crate::scheme::verify_signature;

    // Signing this parameter set costs hundreds of milliseconds, so the tests
    // share one key pair and one signature per message where possible.
    fn keypair() -> (Vec<u8>, Vec<u8>) {
        generate_keypair().expect("key generation")
    }

    #[test]
    fn sizes_match_the_registry() {
        let spec = registry::lookup(ALG_SLH_DSA_SHA2_128S).unwrap();
        assert_eq!(spec.public_key_size, SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE);
        assert_eq!(spec.signature_size, SLH_DSA_SHA2_128S_SIGNATURE_SIZE);
    }

    #[test]
    fn roundtrip_and_context_binding() {
        let (public_key, private_key) = keypair();
        assert_eq!(public_key.len(), SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE);
        assert_eq!(private_key.len(), SLH_DSA_SHA2_128S_PRIVATE_KEY_SIZE);

        let message = b"slh-dsa roundtrip";
        let signature = sign_with_context(&private_key, message, &[]).unwrap();
        assert_eq!(signature.len(), SLH_DSA_SHA2_128S_SIGNATURE_SIZE);
        verify_with_context(&public_key, message, &signature, &[]).unwrap();

        let error = verify_with_context(&public_key, message, &signature, b"ctx").unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn signing_is_deterministic() {
        let (_, private_key) = keypair();
        let message = b"deterministic";
        let first = sign_with_context(&private_key, message, &[]).unwrap();
        let second = sign_with_context(&private_key, message, &[]).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (public_key, private_key) = keypair();
        let message = b"slh-dsa tamper";
        let mut signature = sign_with_context(&private_key, message, &[]).unwrap();
        signature[SLH_DSA_SHA2_128S_SIGNATURE_SIZE - 1] ^= 0x01;

        let error = verify_with_context(&public_key, message, &signature, &[]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn oversized_context_is_rejected() {
        let oversized = vec![0u8; MAX_CONTEXT_LEN + 1];
        let error = verify_with_context(
            &[0u8; SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE],
            b"m",
            &[0u8; SLH_DSA_SHA2_128S_SIGNATURE_SIZE],
            &oversized,
        )
        .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::FieldTooLong);
    }

    #[test]
    fn seed_derivation_is_deterministic() {
        let seed = [7u8; SLH_DSA_SHA2_128S_SEED_SIZE];
        let first = public_key_from_seed(&seed).unwrap();
        let second = public_key_from_seed(&seed).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn public_path_follows_the_registry_status() {
        let (public_key, private_key) = keypair();
        let message = b"public path";
        let signature = sign_with_context(&private_key, message, &[]).unwrap();

        let result = verify_signature(ALG_SLH_DSA_SHA2_128S, &public_key, message, &signature);
        if registry::slh_dsa_enabled() {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                CryptoErrorKind::AlgorithmNotEnabled
            );
        }
    }

    #[test]
    fn zero_bytes_never_verify() {
        let result = verify_with_context(
            &[0u8; SLH_DSA_SHA2_128S_PUBLIC_KEY_SIZE],
            b"hello",
            &[0u8; SLH_DSA_SHA2_128S_SIGNATURE_SIZE],
            &[],
        );
        assert!(result.is_err(), "an all-zero signature must not verify");
    }
}
