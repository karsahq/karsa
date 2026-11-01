//! The algorithm registry: the single source of truth for which algorithms
//! exist and which of them may be used.
//!
//! Unknown identifiers are absent from [`REGISTRY`] on purpose. Absence is what
//! makes an unknown algorithm fail closed.

use crate::error::{CryptoError, CryptoErrorKind};

/// Ed25519 (RFC 8032), enabled at genesis.
pub const ALG_ED25519: u16 = 0x0001;
/// ML-DSA-65 (FIPS 204), registered and activation gated.
pub const ALG_ML_DSA_65: u16 = 0x0101;
/// SLH-DSA-SHA2-128s (FIPS 205), registered and activation gated.
pub const ALG_SLH_DSA_SHA2_128S: u16 = 0x0102;
/// ML-KEM-768 (FIPS 203), a key-encapsulation algorithm, not a signature.
pub const ALG_ML_KEM_768: u16 = 0x0201;

/// Separates digital signatures from key-establishment algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmKind {
    /// Produces and verifies signatures.
    Signature,
    /// Establishes a shared key. Never authorizes a transaction.
    KeyEncapsulation,
}

/// The lifecycle state of a registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AlgorithmStatus {
    /// Usable in consensus-critical contexts.
    Enabled,
    /// Registered and encodable, but every use is rejected.
    ActivationGated,
    /// Decodable for historical verification, rejected for new authorizations.
    Deprecated,
}

/// One immutable registry entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgorithmSpec {
    /// The numeric protocol identifier.
    pub id: u16,
    /// The display name, for example `ML-DSA-65`.
    pub name: &'static str,
    /// The specification reference, for example `FIPS 204`.
    pub specification: &'static str,
    /// Whether this algorithm signs or establishes keys.
    pub kind: AlgorithmKind,
    /// The lifecycle state.
    pub status: AlgorithmStatus,
    /// Canonical public-key encoding size, in bytes.
    pub public_key_size: usize,
    /// Canonical signature size, in bytes; `0` for key encapsulation.
    pub signature_size: usize,
}

#[cfg(all(feature = "pq-testnet", not(feature = "pq-openssl")))]
compile_error!(
    "the `pq-testnet` feature requires `pq-openssl`: activation needs an implementation"
);

// Activation requires both the implementation feature and the testnet switch.
#[cfg(all(feature = "pq-testnet", feature = "pq-openssl"))]
const ML_DSA_65_STATUS: AlgorithmStatus = AlgorithmStatus::Enabled;
#[cfg(not(all(feature = "pq-testnet", feature = "pq-openssl")))]
const ML_DSA_65_STATUS: AlgorithmStatus = AlgorithmStatus::ActivationGated;

/// The frozen registry.
pub const REGISTRY: [AlgorithmSpec; 4] = [
    AlgorithmSpec {
        id: ALG_ED25519,
        name: "Ed25519",
        specification: "RFC 8032",
        kind: AlgorithmKind::Signature,
        status: AlgorithmStatus::Enabled,
        public_key_size: 32,
        signature_size: 64,
    },
    AlgorithmSpec {
        id: ALG_ML_DSA_65,
        name: "ML-DSA-65",
        specification: "FIPS 204",
        kind: AlgorithmKind::Signature,
        status: ML_DSA_65_STATUS,
        public_key_size: 1952,
        signature_size: 3309,
    },
    AlgorithmSpec {
        id: ALG_SLH_DSA_SHA2_128S,
        name: "SLH-DSA-SHA2-128s",
        specification: "FIPS 205",
        kind: AlgorithmKind::Signature,
        status: AlgorithmStatus::ActivationGated,
        public_key_size: 32,
        signature_size: 7856,
    },
    AlgorithmSpec {
        id: ALG_ML_KEM_768,
        name: "ML-KEM-768",
        specification: "FIPS 203",
        kind: AlgorithmKind::KeyEncapsulation,
        status: AlgorithmStatus::ActivationGated,
        public_key_size: 1184,
        signature_size: 0,
    },
];

/// Returns whether ML-DSA-65 may be used for authorization in this build.
#[must_use]
pub const fn ml_dsa_enabled() -> bool {
    matches!(ML_DSA_65_STATUS, AlgorithmStatus::Enabled)
}

/// Returns the registry entry for `id`.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::UnknownAlgorithm`] when `id` is absent from the
/// registry. That is the fail-closed behaviour the protocol requires.
pub fn lookup(id: u16) -> Result<&'static AlgorithmSpec, CryptoError> {
    REGISTRY.iter().find(|spec| spec.id == id).ok_or_else(|| {
        CryptoError::new(
            CryptoErrorKind::UnknownAlgorithm,
            format!("algorithm id 0x{id:04x}"),
        )
    })
}

/// Returns the entry for `id` only when it is a signature algorithm that is
/// currently enabled.
///
/// # Errors
///
/// Returns [`CryptoErrorKind::UnknownAlgorithm`] for an unknown id,
/// [`CryptoErrorKind::UnsupportedAlgorithm`] for a key-encapsulation algorithm,
/// and [`CryptoErrorKind::AlgorithmNotEnabled`] for a gated or deprecated one.
pub fn require_signature_algorithm(id: u16) -> Result<&'static AlgorithmSpec, CryptoError> {
    let spec = lookup(id)?;
    if spec.kind != AlgorithmKind::Signature {
        return Err(CryptoError::new(
            CryptoErrorKind::UnsupportedAlgorithm,
            format!("{} is not a signature algorithm", spec.name),
        ));
    }
    if spec.status != AlgorithmStatus::Enabled {
        return Err(CryptoError::new(
            CryptoErrorKind::AlgorithmNotEnabled,
            format!("{} is {:?}", spec.name, spec.status),
        ));
    }
    Ok(spec)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_algorithm_fails_closed() {
        let error = lookup(0x9999).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::UnknownAlgorithm);
    }

    #[test]
    fn key_encapsulation_is_not_a_signature_algorithm() {
        let error = require_signature_algorithm(ALG_ML_KEM_768).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::UnsupportedAlgorithm);
    }

    #[test]
    fn ml_dsa_status_follows_the_features() {
        let expected = cfg!(all(feature = "pq-testnet", feature = "pq-openssl"));
        assert_eq!(ml_dsa_enabled(), expected);

        let result = require_signature_algorithm(ALG_ML_DSA_65);
        if expected {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                result.unwrap_err().kind(),
                CryptoErrorKind::AlgorithmNotEnabled
            );
        }
    }

    #[test]
    fn enabled_algorithm_exposes_registry_sizes() {
        let spec = require_signature_algorithm(ALG_ED25519).unwrap();
        assert_eq!(spec.public_key_size, 32);
        assert_eq!(spec.signature_size, 64);
    }

    #[test]
    fn registry_ids_are_unique() {
        for (index, spec) in REGISTRY.iter().enumerate() {
            for other in &REGISTRY[index + 1..] {
                assert_ne!(spec.id, other.id, "duplicate id 0x{:04x}", spec.id);
            }
        }
    }

    #[test]
    fn registry_entries_have_a_specification() {
        for spec in &REGISTRY {
            assert!(!spec.specification.is_empty(), "{} has no spec", spec.name);
            assert!(spec.public_key_size > 0, "{} has no key size", spec.name);
        }
    }
}
