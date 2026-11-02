//! Karsa's crypto-agile protocol core.
//!
//! The crate started as a port of the V prototype, which has since been removed.
//! The byte-for-byte vectors that implementation produced are embedded in the
//! tests here:
//!
//! - [`registry`] freezes algorithm identifiers, statuses, and canonical sizes.
//! - [`encoding`] is the deterministic little-endian, length-prefixed codec.
//! - [`domain`] builds the domain-separated payloads that get signed.
//! - [`merkle`] is the Merkle tree and leaf commitment used for state and commit
//!   roots.
//! - [`CryptoError`] is the closed error taxonomy shared by all of them.
//!
//! The normative specification is `docs/crypto-registry.md`. Where this
//! crate and that document disagree, the document wins and the crate is a bug.

mod error;

pub mod domain;
pub mod encoding;
pub mod merkle;
#[cfg(feature = "pq-openssl")]
pub mod ml_dsa;
pub mod registry;
pub mod scheme;
#[cfg(feature = "pq-slh")]
pub mod slh_dsa;

pub use error::{CryptoError, CryptoErrorKind};
