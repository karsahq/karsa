//! The closed error taxonomy shared by every crypto operation.
//!
//! The numeric values are protocol constants. They mirror the codes frozen in
//! `docs/crypto-registry.md` §7, so a Rust node and a V node report the
//! same failure for the same input.

use std::error::Error;
use std::fmt;

/// The closed set of reasons a crypto operation may fail.
///
/// Variants are ordered so that [`CryptoErrorKind::code`] equals the protocol
/// error code. Reordering variants is a protocol change, not a refactor.
///
/// This enum is deliberately *not* `#[non_exhaustive]`: it is a stable ontology
/// that consensus-critical callers must match exhaustively.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum CryptoErrorKind {
    /// The algorithm id is absent from the registry.
    UnknownAlgorithm = 0,
    /// The algorithm is registered but has the wrong kind for this use.
    UnsupportedAlgorithm = 1,
    /// The algorithm is gated or deprecated.
    AlgorithmNotEnabled = 2,
    /// A public key had the wrong length or an invalid encoding.
    MalformedPublicKey = 3,
    /// A private key or seed had the wrong length.
    MalformedPrivateKey = 4,
    /// A signature had the wrong length or a non-canonical encoding.
    MalformedSignature = 5,
    /// A well-formed signature did not verify.
    InvalidSignature = 6,
    /// An authorization named a key the account has not registered.
    UnknownKey = 7,
    /// A key is retired or revoked.
    KeyNotActive = 8,
    /// A key is outside its validity window.
    KeyOutOfWindow = 9,
    /// An authorization's algorithm differs from the key's algorithm.
    AlgorithmMismatch = 10,
    /// The same key authorized twice.
    DuplicateAuthorization = 11,
    /// The policy condition was not met.
    PolicyUnsatisfied = 12,
    /// A field exceeded the protocol limit.
    FieldTooLong = 13,
    /// An authorization list exceeded the protocol limit.
    TooManyAuthorizations = 14,
    /// The operating system randomness source failed.
    EntropyFailure = 15,
    /// Input ended in the middle of a field.
    TruncatedInput = 16,
    /// Input continued after the last field.
    TrailingBytes = 17,
    /// The selected crypto backend reported a failure.
    BackendFailure = 18,
    /// A signature came from a validator that is not in the set.
    UnknownValidator = 19,
    /// A validator has more than one active key at an epoch.
    KeyAmbiguous = 20,
    /// A validator key schedule has invalid or overlapping intervals.
    InvalidKeySchedule = 21,
    /// A key id appears twice on one validator.
    DuplicateKeyId = 22,
    /// A validator id appears twice in a set.
    DuplicateValidatorId = 23,
    /// A certificate's shape is inconsistent: bitmap, padding, or signature
    /// count do not agree with each other or with the validator set.
    MalformedCertificate = 24,
    /// A vertex references a vertex this node does not have.
    MissingReference = 25,
    /// A vertex does not carry the references its round requires.
    InvalidVertex = 26,
    /// A header does not extend the header this node already trusts.
    HeaderMismatch = 27,
}

impl CryptoErrorKind {
    /// Returns the numeric protocol code.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Returns the snake_case name used in logs and on the wire.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UnknownAlgorithm => "unknown_algorithm",
            Self::UnsupportedAlgorithm => "unsupported_algorithm",
            Self::AlgorithmNotEnabled => "algorithm_not_enabled",
            Self::MalformedPublicKey => "malformed_public_key",
            Self::MalformedPrivateKey => "malformed_private_key",
            Self::MalformedSignature => "malformed_signature",
            Self::InvalidSignature => "invalid_signature",
            Self::UnknownKey => "unknown_key",
            Self::KeyNotActive => "key_not_active",
            Self::KeyOutOfWindow => "key_out_of_window",
            Self::AlgorithmMismatch => "algorithm_mismatch",
            Self::DuplicateAuthorization => "duplicate_authorization",
            Self::PolicyUnsatisfied => "policy_unsatisfied",
            Self::FieldTooLong => "field_too_long",
            Self::TooManyAuthorizations => "too_many_authorizations",
            Self::EntropyFailure => "entropy_failure",
            Self::TruncatedInput => "truncated_input",
            Self::TrailingBytes => "trailing_bytes",
            Self::BackendFailure => "backend_failure",
            Self::UnknownValidator => "unknown_validator",
            Self::KeyAmbiguous => "key_ambiguous",
            Self::InvalidKeySchedule => "invalid_key_schedule",
            Self::DuplicateKeyId => "duplicate_key_id",
            Self::DuplicateValidatorId => "duplicate_validator_id",
            Self::MalformedCertificate => "malformed_certificate",
            Self::MissingReference => "missing_reference",
            Self::InvalidVertex => "invalid_vertex",
            Self::HeaderMismatch => "header_mismatch",
        }
    }
}

impl fmt::Display for CryptoErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A crypto failure with a protocol code and a human-readable detail.
///
/// `detail` must be deterministic: it may contain lengths and identifiers, but
/// never timings, randomness, or host state, because consensus-critical callers
/// compare outcomes across nodes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoError {
    kind: CryptoErrorKind,
    detail: String,
}

impl CryptoError {
    /// Creates an error.
    #[must_use]
    pub fn new(kind: CryptoErrorKind, detail: impl Into<String>) -> Self {
        Self {
            kind,
            detail: detail.into(),
        }
    }

    /// Returns the protocol error kind.
    #[must_use]
    pub const fn kind(&self) -> CryptoErrorKind {
        self.kind
    }

    /// Returns the protocol error code.
    #[must_use]
    pub const fn code(&self) -> u16 {
        self.kind.code()
    }

    /// Returns the human-readable detail.
    #[must_use]
    pub fn detail(&self) -> &str {
        &self.detail
    }
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.detail.is_empty() {
            write!(f, "crypto: {}", self.kind)
        } else {
            write!(f, "crypto: {}: {}", self.kind, self.detail)
        }
    }
}

impl Error for CryptoError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_match_the_frozen_protocol_table() {
        assert_eq!(CryptoErrorKind::UnknownAlgorithm.code(), 0);
        assert_eq!(CryptoErrorKind::InvalidSignature.code(), 6);
        assert_eq!(CryptoErrorKind::FieldTooLong.code(), 13);
        assert_eq!(CryptoErrorKind::BackendFailure.code(), 18);
        assert_eq!(CryptoErrorKind::DuplicateValidatorId.code(), 23);
        assert_eq!(CryptoErrorKind::MalformedCertificate.code(), 24);
        assert_eq!(CryptoErrorKind::MissingReference.code(), 25);
        assert_eq!(CryptoErrorKind::InvalidVertex.code(), 26);
        assert_eq!(CryptoErrorKind::HeaderMismatch.code(), 27);
    }

    #[test]
    fn display_reads_like_the_v_prototype() {
        let error = CryptoError::new(CryptoErrorKind::InvalidSignature, "does not verify");
        assert_eq!(
            error.to_string(),
            "crypto: invalid_signature: does not verify"
        );

        let bare = CryptoError::new(CryptoErrorKind::TrailingBytes, "");
        assert_eq!(bare.to_string(), "crypto: trailing_bytes");
    }
}
