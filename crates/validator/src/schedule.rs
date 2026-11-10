//! The validator key schedule, quorum-safe signature counting, and the epoch
//! rules around them.
//!
//! `activation_epoch` is inclusive and `retirement_epoch` is exclusive, so a key
//! is active for `[activation, retirement)`. [`NO_EXPIRY`] means no planned
//! retirement.

use std::collections::HashSet;

use crypto::domain::DOMAIN_VALIDATOR_SET_V1;
use crypto::encoding::Encoder;
use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

/// Sentinel for a key with no planned retirement.
///
/// Same sentinel as `tx::policy::NO_EXPIRY`; it is repeated here so this crate
/// does not depend on the transaction crate.
pub const NO_EXPIRY: u64 = u64::MAX;

/// One consensus key with its activation interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorKey {
    /// Caller-visible key identifier.
    pub key_id: Vec<u8>,
    /// Registry algorithm id of the key.
    pub algorithm_id: u16,
    /// Canonical public-key encoding.
    pub public_key: Vec<u8>,
    /// First epoch at which the key may sign (inclusive).
    pub activation_epoch: u64,
    /// First epoch at which it may no longer sign (exclusive).
    pub retirement_epoch: u64,
}

impl ValidatorKey {
    /// Returns whether the key may sign at `epoch`.
    #[must_use]
    pub fn is_active(&self, epoch: u64) -> bool {
        epoch >= self.activation_epoch && epoch < self.retirement_epoch
    }
}

/// One validator identity and every key it has registered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// Validator identifier, stable across key rotations.
    pub validator_id: Vec<u8>,
    /// Registered consensus keys.
    pub keys: Vec<ValidatorKey>,
}

impl ValidatorRecord {
    fn find_key(&self, key_id: &[u8]) -> Option<&ValidatorKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }

    /// Returns the single key that may sign at `epoch`.
    ///
    /// Zero or two active keys is an error, never a silent pick: an ambiguous
    /// schedule would let two key epochs vote as one validator.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::KeyNotActive`] when no key is active,
    /// [`CryptoErrorKind::KeyAmbiguous`] when more than one is.
    pub fn active_key(&self, epoch: u64) -> Result<&ValidatorKey, CryptoError> {
        let mut active = self.keys.iter().filter(|key| key.is_active(epoch));
        let first = active.next().ok_or_else(|| {
            CryptoError::new(
                CryptoErrorKind::KeyNotActive,
                format!("validator has no active key at epoch {epoch}"),
            )
        })?;
        if active.next().is_some() {
            return Err(CryptoError::new(
                CryptoErrorKind::KeyAmbiguous,
                format!("validator has more than one active key at epoch {epoch}"),
            ));
        }
        Ok(first)
    }

    /// Checks that key intervals are ordered and never overlap, and that key ids
    /// are unique.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::DuplicateKeyId`] for a repeated id, and
    /// [`CryptoErrorKind::InvalidKeySchedule`] for an invalid or overlapping
    /// interval.
    pub fn validate_schedule(&self) -> Result<(), CryptoError> {
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for key in &self.keys {
            if !seen.insert(key.key_id.as_slice()) {
                return Err(CryptoError::new(
                    CryptoErrorKind::DuplicateKeyId,
                    "duplicate key id on validator",
                ));
            }
        }

        let mut keys: Vec<&ValidatorKey> = self.keys.iter().collect();
        keys.sort_by_key(|key| key.activation_epoch);
        for (index, key) in keys.iter().enumerate() {
            if key.activation_epoch >= key.retirement_epoch {
                return Err(CryptoError::new(
                    CryptoErrorKind::InvalidKeySchedule,
                    format!(
                        "activation {} must precede retirement {}",
                        key.activation_epoch, key.retirement_epoch
                    ),
                ));
            }
            if let Some(next) = keys.get(index + 1)
                && key.retirement_epoch > next.activation_epoch
            {
                return Err(CryptoError::new(
                    CryptoErrorKind::InvalidKeySchedule,
                    format!("key intervals overlap at epoch {}", next.activation_epoch),
                ));
            }
        }
        Ok(())
    }
}

/// Maps rounds to epochs.
///
/// A key rotation is not a validator-set change: the identities stay fixed and only
/// their active keys move. That is why quorum intersection survives the boundary —
/// intersection is over validator ids, not over keys — and why no round has to be
/// re-decided when the algorithm changes.
///
/// The mapping is a function of the round alone, so every node derives the same
/// epoch for the same round without trusting the message that carries it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EpochSchedule {
    /// Epoch that round 0 belongs to.
    pub base: u64,
    /// Rounds per epoch, or `None` when the whole DAG is one epoch.
    pub rounds_per_epoch: Option<u64>,
}

impl EpochSchedule {
    /// A schedule in which every round is in `epoch`.
    #[must_use]
    pub fn single(epoch: u64) -> Self {
        Self {
            base: epoch,
            rounds_per_epoch: None,
        }
    }

    /// A schedule that advances one epoch every `rounds_per_epoch` rounds.
    ///
    /// A zero length is treated as "one epoch", because a span of zero rounds is
    /// not a schedule.
    #[must_use]
    pub fn advancing(base: u64, rounds_per_epoch: u64) -> Self {
        Self {
            base,
            rounds_per_epoch: Some(rounds_per_epoch).filter(|length| *length > 0),
        }
    }

    /// The epoch `round` belongs to.
    #[must_use]
    pub fn epoch_of(&self, round: u64) -> u64 {
        match self.rounds_per_epoch {
            Some(length) => self.base + round / length,
            None => self.base,
        }
    }
}

/// One signature presented for a consensus message.
///
/// Both `validator_id` and `key_id` are explicit, so a verifier never has to guess
/// which key produced the signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSignature {
    /// Validator that signed.
    pub validator_id: Vec<u8>,
    /// Key that signed.
    pub key_id: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

fn count_field(count: usize, name: &str) -> Result<u32, CryptoError> {
    u32::try_from(count).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{count} {name} do not fit a u32"),
        )
    })
}

/// The validator set as seen at one epoch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorSet {
    /// Epoch this set describes.
    pub epoch: u64,
    /// Validator records.
    pub validators: Vec<ValidatorRecord>,
}

impl ValidatorSet {
    /// Checks unique validator ids and every record's schedule.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::DuplicateValidatorId`] for a repeated id, plus any
    /// error from [`ValidatorRecord::validate_schedule`].
    pub fn validate(&self) -> Result<(), CryptoError> {
        let mut seen: HashSet<&[u8]> = HashSet::new();
        for record in &self.validators {
            if !seen.insert(record.validator_id.as_slice()) {
                return Err(CryptoError::new(
                    CryptoErrorKind::DuplicateValidatorId,
                    "duplicate validator id in set",
                ));
            }
            record.validate_schedule()?;
        }
        Ok(())
    }

    /// A content identifier for this set at its epoch.
    ///
    /// The digest covers the epoch, the validator order, every validator id, and
    /// every key schedule. Order is part of the identity because a certificate
    /// bitmap is indexed by it; two sets with the same members in a different
    /// order therefore have different identifiers.
    ///
    /// This does not validate the set. Call [`ValidatorSet::validate`] before
    /// treating an identifier as a statement about a usable set.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::FieldTooLong`] when a field or count exceeds the
    /// canonical encoding limit.
    pub fn id(&self) -> Result<[u8; 32], CryptoError> {
        let mut encoder = Encoder::with_capacity(64 + self.validators.len() * 64);
        encoder.put_bytes(DOMAIN_VALIDATOR_SET_V1.as_bytes())?;
        encoder.put_u64(self.epoch);
        encoder.put_u32(count_field(self.validators.len(), "validators")?);
        for record in &self.validators {
            encoder.put_bytes(&record.validator_id)?;
            encoder.put_u32(count_field(record.keys.len(), "keys")?);
            for key in &record.keys {
                encoder.put_bytes(&key.key_id)?;
                encoder.put_u16(key.algorithm_id);
                encoder.put_bytes(&key.public_key)?;
                encoder.put_u64(key.activation_epoch);
                encoder.put_u64(key.retirement_epoch);
            }
        }
        Ok(Sha256::digest(encoder.finish()).into())
    }

    /// Returns the record for `validator_id`.
    #[must_use]
    pub fn validator(&self, validator_id: &[u8]) -> Option<&ValidatorRecord> {
        self.validators
            .iter()
            .find(|record| record.validator_id == validator_id)
    }

    /// Verifies consensus signatures at `epoch` and returns the validator ids
    /// that contributed.
    ///
    /// Each validator is counted once even when two of its keys sign, which is the
    /// rule that stops a rotation from becoming extra voting power. A duplicate
    /// signature is ignored rather than rejected.
    ///
    /// Exactly one key per validator is active at any epoch (`active_key` enforces
    /// it), so a rotation switches keys at a boundary rather than overlapping. An
    /// overlapping window would need every active key to sign, and a vertex carries
    /// one signature; until that changes, the switch is atomic.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::UnknownValidator`] for an unregistered validator,
    /// [`CryptoErrorKind::UnknownKey`] for an unregistered key,
    /// [`CryptoErrorKind::KeyNotActive`] for a key outside its epoch window, plus
    /// any signature verification error.
    pub fn verify_signatures(
        &self,
        message: &[u8],
        epoch: u64,
        signatures: &[ValidatorSignature],
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let mut counted: Vec<Vec<u8>> = Vec::new();
        for entry in signatures {
            let record = self.validator(&entry.validator_id).ok_or_else(|| {
                CryptoError::new(
                    CryptoErrorKind::UnknownValidator,
                    "signature from an unregistered validator",
                )
            })?;
            let key = record.find_key(&entry.key_id).ok_or_else(|| {
                CryptoError::new(
                    CryptoErrorKind::UnknownKey,
                    "signature names a key the validator has not registered",
                )
            })?;
            if !key.is_active(epoch) {
                return Err(CryptoError::new(
                    CryptoErrorKind::KeyNotActive,
                    format!("key is not active at epoch {epoch}"),
                ));
            }
            verify_signature(key.algorithm_id, &key.public_key, message, &entry.signature)?;
            if !counted.contains(&entry.validator_id) {
                counted.push(entry.validator_id.clone());
            }
        }
        Ok(counted)
    }

    /// Returns whether `signer_count` exceeds two thirds of the set, the usual BFT
    /// certificate threshold.
    #[must_use]
    pub fn has_supermajority(&self, signer_count: usize) -> bool {
        signer_count.saturating_mul(3) > self.validators.len().saturating_mul(2)
    }

    /// Smallest signer count that is a supermajority of the set.
    ///
    /// This is the number of distinct previous-round authors a vertex must
    /// reference, and the number of votes a leader needs to commit.
    #[must_use]
    pub fn quorum_size(&self) -> usize {
        self.validators.len() * 2 / 3 + 1
    }

    /// Largest number of validators that may be faulty while the quorum still
    /// intersects every other quorum.
    ///
    /// A node that holds more than this many votes for a leader has seen enough
    /// that no supermajority of non-votes can still exist in the round.
    #[must_use]
    pub fn max_faulty(&self) -> usize {
        self.validators.len().saturating_sub(self.quorum_size())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::domain::{VoteSigningFields, encode_vote_signing_payload};
    use crypto::registry::ALG_ED25519;
    #[cfg(feature = "pq-openssl")]
    use crypto::registry::{ALG_ML_DSA_65, ml_dsa_enabled};
    use crypto::scheme::Ed25519Scheme;

    fn vote_message() -> Vec<u8> {
        encode_vote_signing_payload(&VoteSigningFields {
            chain_id: b"karsa-testnet-1",
            epoch: 9,
            round: 7,
            vertex_id: b"vertex-abc",
        })
        .unwrap()
    }

    fn dummy_key(key_id: &[u8], activation: u64, retirement: u64) -> ValidatorKey {
        ValidatorKey {
            key_id: key_id.to_vec(),
            algorithm_id: ALG_ED25519,
            public_key: vec![0u8; 32],
            activation_epoch: activation,
            retirement_epoch: retirement,
        }
    }

    fn make_ed25519_key(
        key_id: &[u8],
        activation: u64,
        retirement: u64,
    ) -> (ValidatorKey, [u8; 64]) {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        (
            ValidatorKey {
                key_id: key_id.to_vec(),
                algorithm_id: ALG_ED25519,
                public_key: public_key.to_vec(),
                activation_epoch: activation,
                retirement_epoch: retirement,
            },
            private_key,
        )
    }

    fn signed_vote(
        validator_id: &[u8],
        key: &ValidatorKey,
        private_key: &[u8],
        message: &[u8],
    ) -> ValidatorSignature {
        ValidatorSignature {
            validator_id: validator_id.to_vec(),
            key_id: key.key_id.clone(),
            signature: Ed25519Scheme.sign(private_key, message).unwrap(),
        }
    }

    fn single_validator_set(key: ValidatorKey) -> ValidatorSet {
        ValidatorSet {
            epoch: 5,
            validators: vec![ValidatorRecord {
                validator_id: b"v1".to_vec(),
                keys: vec![key],
            }],
        }
    }

    #[test]
    fn key_is_active_on_a_half_open_interval() {
        let key = dummy_key(b"k1", 10, 20);
        assert!(!key.is_active(9), "must not be active before activation");
        assert!(key.is_active(10), "activation epoch is inclusive");
        assert!(key.is_active(19), "must be active before retirement");
        assert!(!key.is_active(20), "retirement epoch is exclusive");
    }

    #[test]
    fn rotation_switches_the_active_key() {
        let first = dummy_key(b"ed-1", 0, 10);
        let second = dummy_key(b"pq-1", 10, NO_EXPIRY);
        let record = ValidatorRecord {
            validator_id: b"v1".to_vec(),
            keys: vec![first, second],
        };
        record.validate_schedule().unwrap();

        assert_eq!(record.active_key(9).unwrap().key_id, b"ed-1");
        assert_eq!(record.active_key(10).unwrap().key_id, b"pq-1");
    }

    #[test]
    fn overlapping_keys_are_rejected() {
        let record = ValidatorRecord {
            validator_id: b"v1".to_vec(),
            keys: vec![dummy_key(b"k1", 0, 15), dummy_key(b"k2", 10, NO_EXPIRY)],
        };
        let error = record.validate_schedule().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn retirement_before_activation_is_rejected() {
        let record = ValidatorRecord {
            validator_id: b"v1".to_vec(),
            keys: vec![dummy_key(b"k1", 20, 10)],
        };
        let error = record.validate_schedule().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn duplicate_key_id_is_rejected() {
        let record = ValidatorRecord {
            validator_id: b"v1".to_vec(),
            keys: vec![dummy_key(b"same", 0, 10), dummy_key(b"same", 10, NO_EXPIRY)],
        };
        let error = record.validate_schedule().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::DuplicateKeyId);
    }

    #[test]
    fn duplicate_validator_id_is_rejected() {
        let record = ValidatorRecord {
            validator_id: b"v1".to_vec(),
            keys: Vec::new(),
        };
        let set = ValidatorSet {
            epoch: 1,
            validators: vec![record.clone(), record],
        };
        let error = set.validate().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::DuplicateValidatorId);
    }

    #[test]
    fn validator_without_an_active_key_is_rejected() {
        let record = ValidatorRecord {
            validator_id: b"v1".to_vec(),
            keys: vec![dummy_key(b"k1", 0, 10)],
        };
        let error = record.active_key(10).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyNotActive);
    }

    #[test]
    fn verify_signatures_accepts_an_active_key() {
        let message = vote_message();
        let (key, private_key) = make_ed25519_key(b"k1", 0, NO_EXPIRY);
        let set = single_validator_set(key.clone());

        let signers = set
            .verify_signatures(
                &message,
                5,
                &[signed_vote(b"v1", &key, &private_key, &message)],
            )
            .unwrap();
        assert_eq!(signers, vec![b"v1".to_vec()]);
    }

    #[test]
    fn verify_signatures_rejects_a_retired_key() {
        let message = vote_message();
        let (key, private_key) = make_ed25519_key(b"k1", 0, 10);
        let set = single_validator_set(key.clone());

        let error = set
            .verify_signatures(
                &message,
                10,
                &[signed_vote(b"v1", &key, &private_key, &message)],
            )
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyNotActive);
    }

    #[test]
    fn verify_signatures_rejects_a_not_yet_active_key() {
        let message = vote_message();
        let (key, private_key) = make_ed25519_key(b"k1", 10, NO_EXPIRY);
        let set = single_validator_set(key.clone());

        let error = set
            .verify_signatures(
                &message,
                9,
                &[signed_vote(b"v1", &key, &private_key, &message)],
            )
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyNotActive);
    }

    #[test]
    fn two_keys_of_one_validator_count_once() {
        let message = vote_message();
        let (old_key, old_private) = make_ed25519_key(b"old", 0, NO_EXPIRY);
        let (new_key, new_private) = make_ed25519_key(b"new", 0, NO_EXPIRY);
        // Deliberately overlapping: validation would reject this schedule, but a
        // verifier still must not count one validator twice.
        let set = ValidatorSet {
            epoch: 5,
            validators: vec![ValidatorRecord {
                validator_id: b"v1".to_vec(),
                keys: vec![old_key.clone(), new_key.clone()],
            }],
        };

        let signers = set
            .verify_signatures(
                &message,
                5,
                &[
                    signed_vote(b"v1", &old_key, &old_private, &message),
                    signed_vote(b"v1", &new_key, &new_private, &message),
                ],
            )
            .unwrap();
        assert_eq!(signers.len(), 1, "one validator was counted twice");
    }

    #[test]
    fn unknown_validator_is_rejected() {
        let message = vote_message();
        let (key, private_key) = make_ed25519_key(b"k1", 0, NO_EXPIRY);
        let set = single_validator_set(key.clone());

        let error = set
            .verify_signatures(
                &message,
                5,
                &[signed_vote(b"v2", &key, &private_key, &message)],
            )
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::UnknownValidator);
    }

    #[test]
    fn supermajority_threshold() {
        let four = ValidatorSet {
            epoch: 1,
            validators: (0..4)
                .map(|index| ValidatorRecord {
                    validator_id: format!("v{index}").into_bytes(),
                    keys: Vec::new(),
                })
                .collect(),
        };
        assert!(!four.has_supermajority(2), "2 of 4 is not a supermajority");
        assert!(four.has_supermajority(3), "3 of 4 is a supermajority");

        let seven = ValidatorSet {
            epoch: 1,
            validators: (0..7)
                .map(|index| ValidatorRecord {
                    validator_id: format!("w{index}").into_bytes(),
                    keys: Vec::new(),
                })
                .collect(),
        };
        assert!(!seven.has_supermajority(4), "4 of 7 is not a supermajority");
        assert!(seven.has_supermajority(5), "5 of 7 is a supermajority");
    }

    #[test]
    #[cfg(feature = "pq-openssl")]
    fn ml_dsa_validator_key_roundtrip() {
        if !ml_dsa_enabled() {
            return;
        }
        let message = vote_message();
        let (public_key, private_key) = crypto::ml_dsa::generate_keypair().unwrap();
        let key = ValidatorKey {
            key_id: b"pq-1".to_vec(),
            algorithm_id: ALG_ML_DSA_65,
            public_key,
            activation_epoch: 100,
            retirement_epoch: NO_EXPIRY,
        };
        let set = ValidatorSet {
            epoch: 100,
            validators: vec![ValidatorRecord {
                validator_id: b"v1".to_vec(),
                keys: vec![key.clone()],
            }],
        };
        let signature = crypto::ml_dsa::sign_with_context(&private_key, &message, &[]).unwrap();
        let entry = ValidatorSignature {
            validator_id: b"v1".to_vec(),
            key_id: b"pq-1".to_vec(),
            signature,
        };
        let signers = set.verify_signatures(&message, 100, &[entry]).unwrap();
        assert_eq!(signers, vec![b"v1".to_vec()]);
    }

    #[test]
    fn a_set_id_binds_the_epoch_order_members_and_keys() {
        let record = |id: &[u8], key_id: &[u8]| ValidatorRecord {
            validator_id: id.to_vec(),
            keys: vec![dummy_key(key_id, 0, NO_EXPIRY)],
        };
        let set = ValidatorSet {
            epoch: 5,
            validators: vec![record(b"v1", b"v1-k0"), record(b"v2", b"v2-k0")],
        };
        let id = set.id().unwrap();
        assert_eq!(id, set.clone().id().unwrap(), "the identifier is stable");

        let mut later = set.clone();
        later.epoch = 6;
        assert_ne!(id, later.id().unwrap(), "the epoch is bound");

        let mut reordered = set.clone();
        reordered.validators.swap(0, 1);
        assert_ne!(id, reordered.id().unwrap(), "the signer order is bound");

        let mut rekeyed = set.clone();
        rekeyed.validators[0].keys[0].public_key = vec![7u8; 32];
        assert_ne!(id, rekeyed.id().unwrap(), "the key material is bound");
    }
}
