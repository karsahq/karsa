//! Epoch-bound validator key schedule.
//!
//! Ports the V prototype's validator module. Consensus keys are separate from
//! account keys and bound to an epoch interval, which is what makes a PQ
//! migration safe: a new key can be registered while the old one still signs, and
//! the switch happens at a published epoch rather than by ad hoc node behaviour.

mod address;
mod certificate;
mod control;
mod dag;
mod failure;
mod fence;
mod finality;
mod frontier;
mod header;
mod pacemaker;
mod round_skip;
mod schedule;
mod set_change;
pub mod slot_agreement;
mod slot_agreement_certificate;
mod slot_agreement_phase;
mod slot_agreement_proof;
mod slot_agreement_view;
pub use slot_agreement_proof::{
    SLOT_AGREEMENT_PROOF_DOMAIN, SLOT_AGREEMENT_PROOF_MAX_BYTES, SLOT_AGREEMENT_PROOF_MAX_ENTRIES,
    SlotAgreementProof, SlotAgreementProofEntry, SlotAgreementProofPol, SlotAgreementViewLineage,
};
pub use slot_agreement_view::{
    SLOT_AGREEMENT_VIEW_DOMAIN, SlotAgreementPreviousPol, SlotAgreementViewProposal,
    slot_agreement_view_proposer,
};
mod slot_certificate;
mod slot_decision;
mod slot_proposal;
mod vertex;

pub use address::validator_address;
pub use certificate::{
    CERTIFICATE_VERSION_V1, Certificate, bit_is_set, bitmap_len, bitmap_of, set_bit,
};
pub use control::{CONTROL_PAYLOAD_DOMAIN, CONTROL_PAYLOAD_VERSION_V1, ControlPayload};
pub use dag::{
    AnchorSkip, CertifiedDag, CommitProof, Dag, Decision, PreparedSlotApplication, SkippedRound,
    SlotApplicationResult, commit_leaf, commit_root,
};
pub use failure::FailureDetector;
pub use fence::{FENCE_VERSION_V1, Fence, FenceCertificate, FenceError};
pub use finality::{Build, Certified, Finalizer, Share, VALIDATOR_SET_ID, signing_payload};
pub use frontier::CommitFrontier;
pub use header::{HEADER_VERSION_V1, Header, HeaderChain};
pub use pacemaker::{Pacemaker, PacemakerConfig, SkipCounts, Step};
pub use round_skip::{
    NO_VOTE_ATTESTATION_VERSION_V1, NoVoteAttestation, ROUND_SKIP_PROOF_VERSION_V1,
    ROUND_SKIP_VERSION_V1, RoundSkip, RoundSkipCheck, RoundSkipError, RoundSkipProof,
};
pub use schedule::{
    EpochSchedule, NO_EXPIRY, VALIDATOR_SET_VERSION_V1, ValidatorKey, ValidatorRecord,
    ValidatorSet, ValidatorSignature,
};
pub use set_change::{
    SET_CHANGE_VERSION_V1, SetChange, SetChangeError, SetSchedule,
    TRANSITION_CERTIFICATE_VERSION_V1, Transition, TransitionCertificate, check_transition,
    min_intersection,
};
pub use slot_agreement_certificate::{
    SLOT_AGREEMENT_CERTIFICATE_DOMAIN, SLOT_AGREEMENT_CERTIFICATE_VERSION_V1, SlotAgreementBinding,
    SlotAgreementCertificatePayload,
};
pub use slot_agreement_phase::{
    SLOT_AGREEMENT_PHASE_DOMAIN, SLOT_AGREEMENT_PHASE_VERSION_V1, SLOT_AGREEMENT_PHASE_WORK_BUDGET,
    SlotAgreementPhaseChain, SlotAgreementPrevotePayload, SlotAgreementStrongPhaseChain,
    SlotAgreementStrongPrevotePayload, SlotAgreementVotePayload, SlotAgreementVoteWitness,
};
pub use slot_certificate::{
    SLOT_CERTIFICATE_PAYLOAD_DOMAIN, SLOT_CERTIFICATE_PAYLOAD_VERSION_V1, SlotCertificatePayload,
    SlotDecisionBinding,
};
pub use slot_decision::{
    SLOT_DECISION_ID_DOMAIN, SLOT_DECISION_SIGNING_DOMAIN, SLOT_DECISION_VERSION_V1, SlotDecision,
    SlotDecisionCertificate, SlotDecisionTip, SlotOutcome,
};
pub use slot_proposal::{SLOT_PROPOSAL_DOMAIN, SLOT_PROPOSAL_VERSION_V1, SlotProposal};
pub use vertex::{VERTEX_VERSION_V1, Vertex, VertexId, tally_votes};
