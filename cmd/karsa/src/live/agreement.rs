//! Inactive durable signing boundary. No carrier authoring or transport is authorized here.

use crypto::registry::{self, ALG_ED25519};
use crypto::scheme::{Ed25519Scheme, verify_signature};
use store::{AgreementSigningIntent, AgreementSigningPrerequisite};
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
    /// Durable nil obligation retained without a signature or fabricated carrier.
    UnsupportedNil {
        /// Full original immutable signing context.
        intent: AgreementSigningIntent,
    },
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

/// Failure to extract carrier ancestry prerequisites from an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrerequisiteExtractionError {
    /// Nil has no supported carrier representation.
    UnsupportedNil,
    /// An externally constructed final intent lacks its selected POL.
    MissingSelectedPol,
}

impl std::fmt::Display for PrerequisiteExtractionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::UnsupportedNil => "nil carrier prerequisites are unsupported",
            Self::MissingSelectedPol => "final intent lacks selected POL",
        })
    }
}

impl std::error::Error for PrerequisiteExtractionError {}

impl PendingIntent {
    /// Extracts sorted, unique direct prerequisite IDs for a future ancestry check.
    /// This is not authentication, readiness, signing or publication authorization:
    /// externally constructed intents remain untrusted, including their digests.
    /// Nested evidence still requires unified DAG inspection.
    ///
    /// # Errors
    /// Rejects nil votes/obligations and final evidence without a selected POL.
    pub fn prerequisite_carriers(&self) -> Result<Vec<VertexId>, PrerequisiteExtractionError> {
        let mut ids = match self {
            Self::UnsupportedNil { .. } => return Err(PrerequisiteExtractionError::UnsupportedNil),
            Self::Vote { payload, .. } => {
                if payload.vote.value == AgreementValue::Nil {
                    return Err(PrerequisiteExtractionError::UnsupportedNil);
                }
                vec![payload.prerequisite.clone()]
            }
            Self::Pol { candidate, .. } => candidate.prerequisite_carriers(),
            Self::FinalProof { proof, .. } => {
                let pol = proof
                    .entries
                    .last()
                    .and_then(|entry| entry.pol.as_ref())
                    .ok_or(PrerequisiteExtractionError::MissingSelectedPol)?;
                let mut ids = vec![pol.carrier.clone()];
                ids.extend(proof.votes.iter().map(|w| w.carrier.clone()));
                ids
            }
        };
        ids.sort_by(|a, b| (a.round, &a.author, a.digest).cmp(&(b.round, &b.author, b.digest)));
        ids.dedup();
        Ok(ids)
    }
}

/// No live activation exists until pre-sign causal readiness and transport are implemented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Readiness {
    /// Signing boundary available, but live carrier authoring remains disabled.
    DisabledMissingCausalReadinessAndTransport,
    /// A driver or reconstruction failure requires a fresh durable recovery.
    RecoveryRequiredHistoricalIntentsUnavailable,
}

/// Exclusive driver owner reconstructing historical obligations, never ready-to-send output.
pub struct Adapter {
    driver: SlotAgreementDriver,
    set: ValidatorSet,
    validator_id: Vec<u8>,
    key_id: Vec<u8>,
    public_key: Vec<u8>,
    private_key: Vec<u8>,
    pending: Vec<PendingIntent>,
    history: Vec<AgreementSigningIntent>,
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
            history: Vec::new(),
            readiness: Readiness::DisabledMissingCausalReadinessAndTransport,
        })
    }

    /// Reconstructs full durable signing history; repeated recovery may sign identical bytes.
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
        let mut adapter = Self {
            driver: SlotAgreementDriver::new(session),
            set,
            validator_id,
            key_id: key.0,
            public_key: key.1,
            private_key,
            pending: Vec::new(),
            history: Vec::new(),
            readiness: Readiness::RecoveryRequiredHistoricalIntentsUnavailable,
        };
        let output = adapter.driver.output();
        adapter.consume_durable_result(output, None)?;
        Ok(adapter)
    }

    /// Returns the activation/recovery barrier, never transport authorization.
    pub fn readiness(&self) -> Readiness {
        self.readiness
    }

    /// Original contexts and stable IDs retained across slots, including unsupported nil.
    /// No acknowledgement or removal is supported; this is not send authorization.
    pub fn signing_history(&self) -> &[AgreementSigningIntent] {
        &self.history
    }

    /// Retained across later observations; reading never signs or releases anything.
    pub fn pending(&self) -> &[PendingIntent] {
        &self.pending
    }

    /// Accepts only authenticated requests and reconstructs the durable signing outbox.
    /// Any driver/output failure requires recovery, even when persistence may have succeeded.
    pub fn apply(&mut self, request: AuthenticatedSlotAgreementRequest) -> Result<(), String> {
        if self.readiness == Readiness::RecoveryRequiredHistoricalIntentsUnavailable {
            return Err("agreement owner requires recovery before further signing".into());
        }
        let sequence = self
            .driver
            .sequence()
            .checked_add(1)
            .ok_or("agreement sequence exhausted")?;
        let result = self.driver.apply(sequence, request);
        self.consume_durable_result(result, None)
    }

    fn consume_durable_result(
        &mut self,
        result: Result<SlotAgreementDriverOutput, StoreError>,
        _prerequisite: Option<VertexId>,
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
        let history = self.driver.signing_outbox().map_err(|e| e.to_string())?;
        // Validate every historical identity before producing any signature. Nil is an
        // unsupported obligation, not a reason to discard valid nonnil history.
        for intent in &history {
            if intent.agreement.set != self.set
                || intent.agreement.local_validator != self.validator_id
                || intent.vote.context != intent.agreement.context
            {
                return Err("historical signing identity or context mismatch".into());
            }
            let bootstrap = AuthenticatedSlotAgreementBootstrap {
                agreement: intent.agreement.clone(),
                predecessor: None,
                order: Vec::new(),
                vertices: Vec::new(),
            };
            let key = checked_key(&bootstrap, &self.private_key)?;
            if key != (self.key_id.clone(), self.public_key.clone()) {
                return Err("historical active key mismatch".into());
            }
            match (&intent.prerequisite, &intent.vote.value) {
                (AgreementSigningPrerequisite::UnsupportedNil, AgreementValue::Nil) => {}
                (AgreementSigningPrerequisite::Carrier(_), AgreementValue::Nil)
                | (AgreementSigningPrerequisite::UnsupportedNil, _) => {
                    return Err("historical prerequisite mismatch".into());
                }
                (AgreementSigningPrerequisite::Carrier(_), _) => {
                    intent
                        .vote
                        .signing_payload(&intent.agreement.set)
                        .map_err(|e| e.to_string())?;
                }
            }
        }
        for intent in history {
            if self.history.iter().any(|old| old.id == intent.id) {
                continue;
            }
            let pending = match &intent.prerequisite {
                AgreementSigningPrerequisite::UnsupportedNil => PendingIntent::UnsupportedNil {
                    intent: intent.clone(),
                },
                AgreementSigningPrerequisite::Carrier(prerequisite) => {
                    let set = &intent.agreement.set;
                    let bytes = intent
                        .vote
                        .signing_payload(set)
                        .map_err(|e| e.to_string())?;
                    let signature = Ed25519Scheme
                        .sign(&self.private_key, &bytes)
                        .map_err(|e| e.to_string())?;
                    verify_signature(ALG_ED25519, &self.public_key, &bytes, &signature)
                        .map_err(|e| e.to_string())?;
                    let payload = SlotAgreementVotePayload {
                        vote: intent.vote.clone(),
                        signature: ValidatorSignature {
                            validator_id: intent.agreement.local_validator.clone(),
                            key_id: self.key_id.clone(),
                            signature,
                        },
                        prerequisite: prerequisite.clone(),
                    };
                    payload
                        .verify(&intent.agreement.context, set)
                        .map_err(|e| e.to_string())?;
                    let digest = payload.digest(set).map_err(|e| e.to_string())?;
                    PendingIntent::Vote { payload, digest }
                }
            };
            self.pending.push(pending);
            self.history.push(intent);
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
