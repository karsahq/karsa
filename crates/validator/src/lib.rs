//! Epoch-bound validator key schedule.
//!
//! Ports the V prototype's validator module. Consensus keys are separate from
//! account keys and bound to an epoch interval, which is what makes a PQ
//! migration safe: a new key can be registered while the old one still signs, and
//! the switch happens at a published epoch rather than by ad hoc node behaviour.

mod address;
mod certificate;
mod dag;
mod finality;
mod frontier;
mod header;
mod pacemaker;
mod schedule;
mod set_change;
mod vertex;

pub use address::validator_address;
pub use certificate::{
    CERTIFICATE_VERSION_V1, Certificate, bit_is_set, bitmap_len, bitmap_of, set_bit,
};
pub use dag::{CommitProof, Dag, Decision, SkippedRound, commit_leaf, commit_root};
pub use finality::{Build, Certified, Finalizer, Share, VALIDATOR_SET_ID, signing_payload};
pub use frontier::CommitFrontier;
pub use header::{HEADER_VERSION_V1, Header, HeaderChain};
pub use pacemaker::{Pacemaker, PacemakerConfig, Step};
pub use schedule::{
    EpochSchedule, NO_EXPIRY, ValidatorKey, ValidatorRecord, ValidatorSet, ValidatorSignature,
};
pub use set_change::{SetSchedule, Transition, check_transition, min_intersection};
pub use vertex::{VERTEX_VERSION_V1, Vertex, VertexId, tally_votes};
