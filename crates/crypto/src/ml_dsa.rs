//! ML-DSA-65 (FIPS 204) through OpenSSL 3.5+.
//!
//! Compiled only with the `pq-openssl` feature, and **requires OpenSSL 3.5 or
//! newer at build time**; the `openssl` crate does not expose the seed-based key
//! derivation or the context string on older versions.
//!
//! The protocol always signs and verifies with an empty context, because domain
//! separation is carried inside the signed payload. The context-aware entry
//! points exist so published ACVP vectors, which use a 32-byte context, can be
//! checked against the same backend.

use openssl::md_ctx::MdCtx;
use openssl::pkey::{KeyType, PKey, Private, Public};
use rand_core::{OsRng, RngCore};

use crate::error::{CryptoError, CryptoErrorKind};
use crate::registry::ALG_ML_DSA_65;
use crate::scheme::SignatureScheme;

/// FIPS 204 seed length used by the key-generation interface.
pub const ML_DSA_65_SEED_SIZE: usize = 32;
/// Canonical ML-DSA-65 public-key length.
pub const ML_DSA_65_PUBLIC_KEY_SIZE: usize = 1952;
/// Canonical ML-DSA-65 private-key length.
pub const ML_DSA_65_PRIVATE_KEY_SIZE: usize = 4032;
/// Canonical ML-DSA-65 signature length.
pub const ML_DSA_65_SIGNATURE_SIZE: usize = 3309;
/// FIPS 204 limit on the context string.
pub const MAX_CONTEXT_LEN: usize = 255;

fn backend_error(detail: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::BackendFailure, detail)
}

fn check_context(context: &[u8]) -> Result<(), CryptoError> {
    if context.len() > MAX_CONTEXT_LEN {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!(
                "ml-dsa-65: context of {} bytes exceeds {MAX_CONTEXT_LEN}",
                context.len()
            ),
        ));
    }
    Ok(())
}

fn import_public_key(public_key: &[u8]) -> Result<PKey<Public>, CryptoError> {
    PKey::public_key_from_raw_bytes_ex(None, KeyType::ML_DSA_65, None, public_key).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            "ml-dsa-65: cannot import public key",
        )
    })
}

fn import_private_key(private_key: &[u8]) -> Result<PKey<Private>, CryptoError> {
    PKey::private_key_from_raw_bytes_ex(None, KeyType::ML_DSA_65, None, private_key).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            "ml-dsa-65: cannot import private key",
        )
    })
}

fn key_from_seed(seed: &[u8]) -> Result<PKey<Private>, CryptoError> {
    if seed.len() != ML_DSA_65_SEED_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            format!(
                "ml-dsa-65: seed must be {ML_DSA_65_SEED_SIZE} bytes, got {}",
                seed.len()
            ),
        ));
    }
    PKey::private_key_from_seed(None, KeyType::ML_DSA_65, None, seed)
        .map_err(|_| backend_error("ml-dsa-65: cannot derive a key from the seed"))
}

/// Derives the public key for a 32-byte FIPS 204 seed.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::MalformedPrivateKey`] for a wrong-length seed and
/// [`CryptoErrorKind::BackendFailure`] when OpenSSL rejects it.
pub fn public_key_from_seed(seed: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let key = key_from_seed(seed)?;
    let public_key = key
        .raw_public_key()
        .map_err(|_| backend_error("ml-dsa-65: cannot export the public key"))?;
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(backend_error("ml-dsa-65: unexpected public key length"));
    }
    Ok(public_key)
}

/// Generates a key pair from the operating system CSPRNG.
///
/// Returns `(public_key, private_key)` in canonical FIPS 204 encodings.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::BackendFailure`] when OpenSSL fails.
pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
    let mut seed = [0u8; ML_DSA_65_SEED_SIZE];
    let mut rng = OsRng;
    rng.fill_bytes(&mut seed);
    let key = key_from_seed(&seed)?;
    let public_key = key
        .raw_public_key()
        .map_err(|_| backend_error("ml-dsa-65: cannot export the public key"))?;
    let private_key = key
        .raw_private_key()
        .map_err(|_| backend_error("ml-dsa-65: cannot export the private key"))?;
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE
        || private_key.len() != ML_DSA_65_PRIVATE_KEY_SIZE
    {
        return Err(backend_error("ml-dsa-65: unexpected key length"));
    }
    Ok((public_key, private_key))
}

/// Signs with an explicit FIPS 204 context string.
///
/// # Errors
///
/// Returns a malformed-key error for a wrong-length key, a field error for an
/// oversized context, and [`CryptoErrorKind::BackendFailure`] when OpenSSL fails.
pub fn sign_with_context(
    private_key: &[u8],
    message: &[u8],
    context: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    check_context(context)?;
    if private_key.len() != ML_DSA_65_PRIVATE_KEY_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPrivateKey,
            format!(
                "ml-dsa-65: want {ML_DSA_65_PRIVATE_KEY_SIZE} bytes, got {}",
                private_key.len()
            ),
        ));
    }
    let key = import_private_key(private_key)?;
    let mut md_ctx =
        MdCtx::new().map_err(|_| backend_error("ml-dsa-65: cannot allocate digest context"))?;
    {
        let pkey_ctx = md_ctx
            .digest_sign_init(None, &key)
            .map_err(|_| backend_error("ml-dsa-65: sign init failed"))?;
        if !context.is_empty() {
            pkey_ctx
                .set_context_string(context)
                .map_err(|_| backend_error("ml-dsa-65: cannot set context string"))?;
        }
    }
    let mut signature = Vec::new();
    md_ctx
        .digest_sign_to_vec(message, &mut signature)
        .map_err(|_| backend_error("ml-dsa-65: signing failed"))?;
    if signature.len() != ML_DSA_65_SIGNATURE_SIZE {
        return Err(backend_error("ml-dsa-65: unexpected signature length"));
    }
    Ok(signature)
}

/// Verifies with an explicit FIPS 204 context string.
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
    if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedPublicKey,
            format!(
                "ml-dsa-65: want {ML_DSA_65_PUBLIC_KEY_SIZE} bytes, got {}",
                public_key.len()
            ),
        ));
    }
    if signature.len() != ML_DSA_65_SIGNATURE_SIZE {
        return Err(CryptoError::new(
            CryptoErrorKind::MalformedSignature,
            format!(
                "ml-dsa-65: want {ML_DSA_65_SIGNATURE_SIZE} bytes, got {}",
                signature.len()
            ),
        ));
    }

    let key = import_public_key(public_key)?;
    let mut md_ctx =
        MdCtx::new().map_err(|_| backend_error("ml-dsa-65: cannot allocate digest context"))?;
    {
        let pkey_ctx = md_ctx
            .digest_verify_init(None, &key)
            .map_err(|_| backend_error("ml-dsa-65: verify init failed"))?;
        if !context.is_empty() {
            pkey_ctx
                .set_context_string(context)
                .map_err(|_| backend_error("ml-dsa-65: cannot set context string"))?;
        }
    }
    // `openssl`'s `digest_verify` maps `EVP_DigestVerify`'s 0 result to an error
    // through `cvt`, so an invalid signature arrives as `Err`. Key import and
    // verify-init already succeeded at this point, so any result other than a
    // clean `true` means "did not verify" — the same mapping the V prototype and
    // libsodium make.
    let valid = md_ctx.digest_verify(message, signature);
    match valid {
        Ok(true) => Ok(()),
        Ok(false) | Err(_) => Err(CryptoError::new(
            CryptoErrorKind::InvalidSignature,
            "ml-dsa-65: signature does not verify",
        )),
    }
}

/// ML-DSA-65 wired into the registry.
#[derive(Debug, Clone, Copy, Default)]
pub struct MlDsa65Scheme;

impl SignatureScheme for MlDsa65Scheme {
    fn algorithm_id(&self) -> u16 {
        ALG_ML_DSA_65
    }

    fn validate_public_key(&self, public_key: &[u8]) -> Result<(), CryptoError> {
        if public_key.len() != ML_DSA_65_PUBLIC_KEY_SIZE {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedPublicKey,
                format!(
                    "ml-dsa-65: want {ML_DSA_65_PUBLIC_KEY_SIZE} bytes, got {}",
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

/// Verifies one ML-DSA-65 signature through the canonical entry point.
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

    fn keypair() -> (Vec<u8>, Vec<u8>) {
        generate_keypair().expect("key generation")
    }

    #[test]
    fn sizes_match_the_registry() {
        let spec = registry::lookup(ALG_ML_DSA_65).unwrap();
        assert_eq!(spec.public_key_size, ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(spec.signature_size, ML_DSA_65_SIGNATURE_SIZE);
    }

    #[test]
    fn roundtrip_with_an_empty_context() {
        let (public_key, private_key) = keypair();
        assert_eq!(public_key.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
        assert_eq!(private_key.len(), ML_DSA_65_PRIVATE_KEY_SIZE);

        let message = b"ml-dsa roundtrip";
        let signature = sign_with_context(&private_key, message, &[]).unwrap();
        assert_eq!(signature.len(), ML_DSA_65_SIGNATURE_SIZE);
        verify_with_context(&public_key, message, &signature, &[]).unwrap();
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let (public_key, private_key) = keypair();
        let message = b"ml-dsa tamper";
        let mut signature = sign_with_context(&private_key, message, &[]).unwrap();
        signature[100] ^= 0x01;

        let error = verify_with_context(&public_key, message, &signature, &[]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn context_string_is_bound_to_the_signature() {
        let (public_key, private_key) = keypair();
        let message = b"context binding";
        let signature = sign_with_context(&private_key, message, &[]).unwrap();

        verify_with_context(&public_key, message, &signature, &[]).unwrap();
        let error = verify_with_context(&public_key, message, &signature, b"ctx").unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn oversized_context_is_rejected() {
        let oversized = vec![0u8; MAX_CONTEXT_LEN + 1];
        let error = verify_with_context(
            &[0u8; ML_DSA_65_PUBLIC_KEY_SIZE],
            b"m",
            &[0u8; ML_DSA_65_SIGNATURE_SIZE],
            &oversized,
        )
        .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::FieldTooLong);
    }

    #[test]
    fn seed_derivation_is_deterministic() {
        let seed = [7u8; ML_DSA_65_SEED_SIZE];
        let first = public_key_from_seed(&seed).unwrap();
        let second = public_key_from_seed(&seed).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), ML_DSA_65_PUBLIC_KEY_SIZE);
    }

    #[test]
    fn public_path_follows_the_registry_status() {
        let (public_key, private_key) = keypair();
        let message = b"public path";
        let signature = sign_with_context(&private_key, message, &[]).unwrap();

        let result = verify_signature(ALG_ML_DSA_65, &public_key, message, &signature);
        if registry::ml_dsa_enabled() {
            result.unwrap();
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                CryptoErrorKind::AlgorithmNotEnabled
            );
        }
    }
}
