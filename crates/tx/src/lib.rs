//! Karsa transaction envelope and authorization policy.
//!
//! Ports the V prototype's transaction and policy modules. The normative
//! encoding is `docs/crypto-registry.md` §5 and §6.

pub mod address;
pub mod batch;
pub mod envelope;
pub mod policy;
