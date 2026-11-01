//! Epoch-bound validator key schedule.
//!
//! Ports the V prototype's validator module. Consensus keys are separate from
//! account keys and bound to an epoch interval, which is what makes a PQ
//! migration safe: a new key can be registered while the old one still signs, and
//! the switch happens at a published epoch rather than by ad hoc node behaviour.

mod schedule;

pub use schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet, ValidatorSignature};
