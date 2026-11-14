//! Inactive durable signing boundary. No carrier authoring or transport is authorized here.

use crypto::registry::{self, ALG_ED25519};
use crypto::scheme::{Ed25519Scheme, verify_signature};
use store::{
    AuthenticatedSlotAgreementBootstrap, AuthenticatedSlotAgreementRequest,
    SlotAgreementCarrierCandidate, SlotAgreementDriver, SlotAgreementDriverOutput, Store,
    StoreError,
};
use validator::slot_agreement::AgreementValue;

pub use crate::chain::Membership;
use validator::{SlotAgreementVotePayload, ValidatorSet, ValidatorSignature, VertexId};

/// Carrier intent whose dependencies still require causal-readiness inspection.
#[derive(Debug)]
pub enum PendingIntent {
    /// A durable local vote, not yet causally ready for a carrier.
    Vote {
        /// Exact signed statement and authenticated prerequisite.
        payload: SlotAgreementVotePayload,
        /// Existing vote-carrier payload digest.
        digest: [u8; 32],
    },
    /// Authenticated prevote quorum awaiting a real carrier.
    Pol {
        /// Carrier-free POL evidence.
        candidate: validator::SlotAgreementPolCandidate,
        /// Existing POL digest.
        digest: [u8; 32],
    },
    /// Final evidence, not decision-application authority.
    FinalProof {
        /// Complete proof awaiting a real final carrier.
        proof: validator::SlotAgreementProof,
        /// Existing final proof digest.
        digest: [u8; 32],
    },
}

/// No live activation exists until pre-sign causal readiness and transport are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Signing boundary available, but live carrier authoring remains disabled.
    DisabledMissingCausalReadinessAndTransport,
    /// No further signing: older unreleased output cannot be enumerated.
    RecoveryRequiredHistoricalIntentsUnavailable,
}

/// Exclusive driver owner; retained intents are process-local, not a recoverable outbox.
pub struct Adapter {
    driver: SlotAgreementDriver,
    set: ValidatorSet,
    validator_id: Vec<u8>,
    key_id: Vec<u8>,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    pending: Vec<PendingIntent>,
    readiness: Readiness,
}

impl Adapter {
    /// Validates the pinned active key before creating a WAL. Never called by live startup.
    pub fn begin(
        store: &Store,
        bootstrap: AuthenticatedSlotAgreementBootstrap,
        membership: &Membership,
        index: usize,
    ) -> Result<Self, String> {
        let private_key = membership_key(&bootstrap, membership, index)?;
        let key = checked_key(&bootstrap, &private_key)?;
        let set = bootstrap.agreement.set.clone();
        let validator_id = bootstrap.agreement.local_validator.clone();
        let session = store
            .begin_authenticated_slot_agreement(bootstrap)
            .map_err(|e| e.to_string())?;
        Ok(Self {
            driver: SlotAgreementDriver::new(session),
            set,
            validator_id,
            key_id: key.0,
            public_key: key.1,
            private_key,
            pending: Vec::new(),
            readiness: Readiness::DisabledMissingCausalReadinessAndTransport,
        })
    }

    /// Only an empty recovered session can accept requests: latest output cannot recover history.
    pub fn recover(
        store: &Store,
        bootstrap: AuthenticatedSlotAgreementBootstrap,
        membership: &Membership,
        index: usize,
    ) -> Result<Self, String> {
        let private_key = membership_key(&bootstrap, membership, index)?;
        let key = checked_key(&bootstrap, &private_key)?;
        let set = bootstrap.agreement.set.clone();
        let validator_id = bootstrap.agreement.local_validator.clone();
        let session = store
            .recover_authenticated_slot_agreement(bootstrap)
            .map_err(|e| e.to_string())?;
        let readiness = if session.sequence() == 0 {
            Readiness::DisabledMissingCausalReadinessAndTransport
        } else {
            Readiness::RecoveryRequiredHistoricalIntentsUnavailable
        };
        Ok(Self {
            driver: SlotAgreementDriver::new(session),
            set,
            validator_id,
            key_id: key.0,
            public_key: key.1,
            private_key,
            pending: Vec::new(),
            readiness,
        })
    }

    /// Returns the activation/recovery barrier, never transport authorization.
    pub fn readiness(&self) -> Readiness {
        self.readiness
    }

    /// Retained across later observations; reading never signs or releases anything.
    pub fn pending(&self) -> &[PendingIntent] {
        &self.pending
    }

    /// Accepts only the closed authenticated request vocabulary; signs only immediate durable output.
    /// Any driver/output failure requires recovery, even when persistence may have succeeded.
    pub fn apply(&mut self, request: AuthenticatedSlotAgreementRequest) -> Result<(), String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("recovery cannot enumerate historical unreleased intents".into());
        }
        // Pin the exact prerequisite from this authenticated request, never a cached transition.
        let prerequisite: Option<VertexId> = match &request {
            AuthenticatedSlotAgreementRequest::Propose { lineage, .. } => {
                lineage.entries.last().map(|e| e.view_carrier.clone())
            }
            AuthenticatedSlotAgreementRequest::ObservePrevote { lineage, .. } => lineage
                .entries
                .last()
                .and_then(|e| e.pol.as_ref())
                .map(|p| p.carrier.clone()),
            _ => None,
        };
        let sequence = self
            .driver
            .sequence()
            .checked_add(1)
            .ok_or("agreement sequence exhausted")?;
        let result = self.driver.apply(sequence, request);
        self.consume_durable_result(result, prerequisite)
    }

    fn consume_durable_result(
        &mut self,
        result: Result<SlotAgreementDriverOutput, StoreError>,
        prerequisite: Option<VertexId>,
    ) -> Result<(), String> {
        let output = match result {
            Ok(output) => output,
            Err(error) => {
                self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
                return Err(error.to_string());
            }
        };
        // A post-durability encoding/signing failure must also block continued operation.
        self.readiness = Readiness::RecoveryRequiredHistoricalIntentsUnavailable;
        if let Some(vote) = output.transition.and_then(|t| t.vote) {
            if matches!(vote.value, AgreementValue::Nil) {
                return Err("nil vote carriers are unsupported; no signature produced".into());
            }

            let prerequisite =
                prerequisite.ok_or("durable vote has no authenticated request prerequisite")?;
            let bytes = vote.signing_payload(&self.set).map_err(|e| e.to_string())?;
            let signature = Ed25519Scheme
                .sign(&self.private_key, &bytes)
                .map_err(|e| e.to_string())?;
            verify_signature(ALG_ED25519, &self.public_key, &bytes, &signature)
                .map_err(|e| e.to_string())?;
            let payload = SlotAgreementVotePayload {
                vote,
                signature: ValidatorSignature {
                    validator_id: self.validator_id.clone(),
                    key_id: self.key_id.clone(),
                    signature,
                },
                prerequisite,
            };
            payload
                .verify(&payload.vote.context, &self.set)
                .map_err(|e| e.to_string())?;
            let digest = payload.digest(&self.set).map_err(|e| e.to_string())?;
            self.pending.push(PendingIntent::Vote { payload, digest });
        }
        for candidate in output.candidates {
            let intent = match candidate {
                SlotAgreementCarrierCandidate::PendingPol(candidate) => {
                    let digest = candidate.digest();
                    PendingIntent::Pol { candidate, digest }
                }
                SlotAgreementCarrierCandidate::PendingFinalProof(proof) => {
                    let digest = proof.digest(&self.set).map_err(|e| e.to_string())?;
                    PendingIntent::FinalProof { proof, digest }
                }
            };
            let duplicate = self.pending.iter().any(|old| match (old, &intent) {
                (PendingIntent::Pol { digest: a, .. }, PendingIntent::Pol { digest: b, .. })
                | (
                    PendingIntent::FinalProof { digest: a, .. },
                    PendingIntent::FinalProof { digest: b, .. },
                ) => a == b,
                _ => false,
            });
            if !duplicate {
                self.pending.push(intent);
            }
        }
        self.readiness = Readiness::DisabledMissingCausalReadinessAndTransport;
        Ok(())
    }
}

fn membership_key(
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    membership: &Membership,
    index: usize,
) -> Result<Vec<u8>, String> {
    let identity = membership
        .consensus
        .get(index)
        .ok_or("no consensus key for this node")?;
    if membership.set != bootstrap.agreement.set
        || identity.id != bootstrap.agreement.local_validator
    {
        return Err("membership differs from pinned agreement identity or set".into());
    }
    Ok(identity.private_key.clone())
}

fn checked_key(
    bootstrap: &AuthenticatedSlotAgreementBootstrap,
    private: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let agreement = &bootstrap.agreement;
    let validator = agreement
        .set
        .validator(&agreement.local_validator)
        .ok_or("local validator absent from pinned set")?;
    let key = validator
        .active_key(agreement.context.epoch())
        .map_err(|e| e.to_string())?;
    registry::require_signature_algorithm(key.algorithm_id).map_err(|e| e.to_string())?;
    if key.algorithm_id != ALG_ED25519 {
        return Err("live adapter supports only Ed25519 private keys".into());
    }
    if private.len() != 64 {
        return Err("invalid Ed25519 private key length".into());
    }
    let derived = Ed25519Scheme::public_key_from_seed(&private[..32]).map_err(|e| e.to_string())?;
    if private[32..] != derived || key.public_key != derived {
        return Err("private key does not match pinned active public key".into());
    }
    Ok((key.key_id.clone(), key.public_key.clone()))
}

/// The legacy node must not run on an authenticated signing root (including staged generations).
pub(super) fn disabled_guard(store: &Store) -> Result<(), String> {
    store.slot_decision_locks().map(|_| ()).map_err(|e| {
        format!("live agreement adapter is disabled; legacy root signing check failed: {e}")
    })
}

#[cfg(test)]
mod tests;
