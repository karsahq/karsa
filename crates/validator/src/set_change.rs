//! Checked validator-set transitions and the certificate that authorizes them.
//!
//! A key rotation keeps the validator identities and moves only their active
//! keys. A set change moves identities, which is a different safety problem: an
//! old quorum and a new quorum can decide conflicting prefixes unless they
//! still overlap by more than the fault budget. [`check_transition`] checks that
//! condition, [`SetChange`] names the checked boundary, and
//! [`TransitionCertificate`] carries a quorum of the old set over that
//! descriptor. Activating the new set in the DAG and the finalizer is a separate
//! step; this module decides only whether the change is authorized.
//!
//! The first implementation is deliberately conservative: exactly one identity
//! is added or removed per epoch, and the new set must keep the old fault
//! budget. A later version can allow more changes if it keeps both the
//! intersection and the fault-budget checks.

use std::collections::HashSet;
use std::fmt;

use crypto::domain::{
    DOMAIN_SET_TRANSITION_V1, SetChangeSigningFields, encode_set_change_signing_payload,
};
use crypto::encoding::{Decoder, Encoder};
use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::certificate::{bit_is_set, bitmap_len};
use crate::schedule::{EpochSchedule, ValidatorKey, ValidatorRecord, ValidatorSet};

/// Canonical set-change descriptor version.
pub const SET_CHANGE_VERSION_V1: u16 = 1;
/// Canonical transition-certificate version.
pub const TRANSITION_CERTIFICATE_VERSION_V1: u16 = 1;

/// The arithmetic of one checked transition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transition {
    /// Epoch the old set is active.
    pub old_epoch: u64,
    /// Epoch the new set becomes active.
    pub new_epoch: u64,
    /// Validators in the old set.
    pub old_size: usize,
    /// Validators in the new set.
    pub new_size: usize,
    /// Validator ids present in both sets.
    pub shared: usize,
    /// Old quorum size.
    pub old_quorum: usize,
    /// New quorum size.
    pub new_quorum: usize,
    /// Smallest possible intersection of an old and a new quorum.
    pub min_intersection: usize,
    /// Fault budget the old set is designed for.
    pub fault_budget: usize,
    /// Fault budget the new set is designed for.
    pub new_fault_budget: usize,
}

impl Transition {
    /// Number of identities added or removed.
    #[must_use]
    pub fn changes(&self) -> usize {
        self.old_size + self.new_size - 2 * self.shared
    }
}

/// The signed descriptor of one checked validator-set transition.
///
/// The descriptor names the old and new sets by content id, the epoch the new
/// set activates, and a digest of the transition itself. A
/// [`TransitionCertificate`] is a quorum of old-set signatures over
/// [`SetChange::signing_payload`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetChange {
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: Vec<u8>,
    /// Content identifier of the set whose quorum signs the change.
    pub old_set_id: [u8; 32],
    /// Content identifier of the set that becomes active.
    pub new_set_id: [u8; 32],
    /// First epoch at which the new set is active.
    pub activation_epoch: u64,
    /// Domain-separated identifier of this transition.
    pub transition_hash: [u8; 32],
}

impl SetChange {
    /// Builds the descriptor for a checked transition.
    ///
    /// # Errors
    ///
    /// [`SetChangeError::Transition`] when [`check_transition`] rejects the
    /// transition, and [`SetChangeError::Encoding`] when a set identifier cannot
    /// be encoded.
    pub fn new(
        chain_id: impl Into<Vec<u8>>,
        old: &ValidatorSet,
        new: &ValidatorSet,
    ) -> Result<Self, SetChangeError> {
        check_transition(old, new).map_err(SetChangeError::Transition)?;
        let old_set_id = old.id().map_err(SetChangeError::Encoding)?;
        let new_set_id = new.id().map_err(SetChangeError::Encoding)?;
        let activation_epoch = new.epoch;
        let transition_hash = transition_hash(&old_set_id, &new_set_id, activation_epoch)
            .map_err(SetChangeError::Encoding)?;
        Ok(Self {
            chain_id: chain_id.into(),
            old_set_id,
            new_set_id,
            activation_epoch,
            transition_hash,
        })
    }

    /// The bytes an old-set quorum signs.
    ///
    /// # Errors
    ///
    /// [`SetChangeError::Encoding`] when a field exceeds the encoding limit.
    pub fn signing_payload(&self) -> Result<Vec<u8>, SetChangeError> {
        encode_set_change_signing_payload(&SetChangeSigningFields {
            chain_id: &self.chain_id,
            old_set_id: &self.old_set_id,
            new_set_id: &self.new_set_id,
            activation_epoch: self.activation_epoch,
            transition_hash: &self.transition_hash,
        })
        .map_err(SetChangeError::Encoding)
    }

    /// Writes the canonical descriptor encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::FieldTooLong`] when a field exceeds the encoding limit.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder = Encoder::with_capacity(128 + self.chain_id.len());
        encoder.put_u16(SET_CHANGE_VERSION_V1);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_bytes(&self.old_set_id)?;
        encoder.put_bytes(&self.new_set_id)?;
        encoder.put_u64(self.activation_epoch);
        encoder.put_bytes(&self.transition_hash)?;
        Ok(encoder.finish())
    }

    /// Reads a canonical descriptor encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`] or
    /// [`CryptoErrorKind::TrailingBytes`] for a bad buffer,
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version, and
    /// [`CryptoErrorKind::FieldTooLong`] for an oversized field.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != SET_CHANGE_VERSION_V1 {
            return Err(codec(format!("unsupported set-change version {version}")));
        }
        let chain_id = decoder.read_bytes()?.to_vec();
        let old_set_id = read_digest(&mut decoder, "old set id")?;
        let new_set_id = read_digest(&mut decoder, "new set id")?;
        let activation_epoch = decoder.read_u64()?;
        let transition_hash = read_digest(&mut decoder, "transition hash")?;
        decoder.finish()?;
        Ok(Self {
            chain_id,
            old_set_id,
            new_set_id,
            activation_epoch,
            transition_hash,
        })
    }

    /// Checks that the descriptor names exactly the supplied old and new sets.
    fn check_against(&self, old: &ValidatorSet, new: &ValidatorSet) -> Result<(), SetChangeError> {
        let old_set_id = old.id().map_err(SetChangeError::Encoding)?;
        let new_set_id = new.id().map_err(SetChangeError::Encoding)?;
        if self.old_set_id != old_set_id {
            return Err(mismatch("the certificate names a different old set"));
        }
        if self.new_set_id != new_set_id {
            return Err(mismatch("the certificate names a different new set"));
        }
        if self.activation_epoch != new.epoch {
            return Err(mismatch(format!(
                "activation epoch {} does not match the new set epoch {}",
                self.activation_epoch, new.epoch
            )));
        }
        let expected = transition_hash(&old_set_id, &new_set_id, self.activation_epoch)
            .map_err(SetChangeError::Encoding)?;
        if self.transition_hash != expected {
            return Err(mismatch("the transition hash does not match its fields"));
        }
        Ok(())
    }
}

/// A validator-set change signed by a quorum of the old set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransitionCertificate {
    /// The signed transition descriptor.
    pub change: SetChange,
    /// The set that becomes active at [`SetChange::activation_epoch`].
    pub new_set: ValidatorSet,
    /// Bitmap of old-set validators that signed, indexed like a finality
    /// certificate.
    pub signer_bitmap: Vec<u8>,
    /// One signature per set bit, in old-set order.
    pub signatures: Vec<Vec<u8>>,
}

impl TransitionCertificate {
    /// Number of old-set validators marked as signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Verifies the old-set quorum and the checked transition.
    ///
    /// The certificate is self-contained apart from the old set: the verifier
    /// already holds the set that is active when the change is made. The new set
    /// travels with the certificate and its content id is covered by the
    /// signatures.
    ///
    /// # Errors
    ///
    /// [`SetChangeError::Mismatch`] when the descriptor does not name the
    /// supplied sets, [`SetChangeError::Malformed`] when the bitmap and the
    /// signature list disagree, [`SetChangeError::Transition`] when
    /// [`check_transition`] rejects the change, [`SetChangeError::NoQuorum`]
    /// when fewer than a supermajority of the old set signed, and
    /// [`SetChangeError::Signer`] when a key cannot be resolved or a signature
    /// does not verify.
    pub fn verify(&self, old: &ValidatorSet) -> Result<Transition, SetChangeError> {
        self.change.check_against(old, &self.new_set)?;
        self.check_shape(old)?;
        let transition =
            check_transition(old, &self.new_set).map_err(SetChangeError::Transition)?;
        let signers = self.resolve_signers(old)?;
        if !old.has_supermajority(signers.len()) {
            return Err(SetChangeError::NoQuorum {
                signers: signers.len(),
                required: old.quorum_size(),
            });
        }

        let payload = self.change.signing_payload()?;
        for (_, key, signature) in signers {
            verify_signature(key.algorithm_id, &key.public_key, &payload, signature)
                .map_err(SetChangeError::Signer)?;
        }
        Ok(transition)
    }

    /// Writes the canonical certificate encoding.
    ///
    /// # Errors
    ///
    /// Every error from [`SetChange::encode`] or [`ValidatorSet::encode`], plus
    /// [`CryptoErrorKind::FieldTooLong`] for an oversized signature count.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let change = self.change.encode()?;
        let new_set = self.new_set.encode()?;
        let mut encoder =
            Encoder::with_capacity(change.len() + new_set.len() + self.signer_bitmap.len() + 64);
        encoder.put_u16(TRANSITION_CERTIFICATE_VERSION_V1);
        encoder.put_bytes(&change)?;
        encoder.put_bytes(&new_set)?;
        encoder.put_bytes(&self.signer_bitmap)?;
        encoder.put_u32(count_field(self.signatures.len(), "signatures")?);
        for signature in &self.signatures {
            encoder.put_bytes(signature)?;
        }
        Ok(encoder.finish())
    }

    /// Reads a canonical certificate encoding.
    ///
    /// The bitmap is checked against the signature count, but not against the
    /// old set: the old set is not part of this object. [`Self::verify`] does
    /// the remaining shape and quorum checks.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`] or
    /// [`CryptoErrorKind::TrailingBytes`] for a bad buffer,
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version or an
    /// inconsistent bitmap and signature list, plus every error from
    /// [`SetChange::decode`] or [`ValidatorSet::decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != TRANSITION_CERTIFICATE_VERSION_V1 {
            return Err(codec(format!(
                "unsupported transition-certificate version {version}"
            )));
        }
        let change = SetChange::decode(decoder.read_bytes()?)?;
        let new_set = ValidatorSet::decode(decoder.read_bytes()?)?;
        let signer_bitmap = decoder.read_bytes()?.to_vec();
        let signature_count = decoder.read_u32()? as usize;
        // Each signature has at least its four-byte length prefix.
        if signature_count > bytes.len() / 4 {
            return Err(codec(format!(
                "{signature_count} signatures exceed the {} byte payload",
                bytes.len()
            )));
        }
        let mut signatures = Vec::with_capacity(signature_count.min(1024));
        for _ in 0..signature_count {
            signatures.push(decoder.read_bytes()?.to_vec());
        }
        decoder.finish()?;

        let certificate = Self {
            change,
            new_set,
            signer_bitmap,
            signatures,
        };
        if certificate.signer_count() != certificate.signatures.len() {
            return Err(codec(format!(
                "bitmap marks {} signers but {} signatures are present",
                certificate.signer_count(),
                certificate.signatures.len()
            )));
        }
        Ok(certificate)
    }

    /// Checks the bitmap and signature count against the old set.
    fn check_shape(&self, old: &ValidatorSet) -> Result<(), SetChangeError> {
        let signers = self.signer_count();
        if signers != self.signatures.len() {
            return Err(malformed(format!(
                "bitmap marks {signers} signers but {} signatures are present",
                self.signatures.len()
            )));
        }

        let validators = old.validators.len();
        if self.signer_bitmap.len() != bitmap_len(validators) {
            return Err(malformed(format!(
                "bitmap is {} bytes for {validators} validators, expected {}",
                self.signer_bitmap.len(),
                bitmap_len(validators)
            )));
        }

        let used_in_last_byte = validators % 8;
        if used_in_last_byte != 0
            && let Some(last) = self.signer_bitmap.last()
            && last >> used_in_last_byte != 0
        {
            return Err(malformed(format!(
                "bitmap sets bits above validator {validators}"
            )));
        }
        Ok(())
    }

    /// Resolves each marked signer to the key active at the old set's epoch.
    fn resolve_signers<'a>(
        &'a self,
        old: &'a ValidatorSet,
    ) -> Result<Vec<SignedEntry<'a>>, SetChangeError> {
        let mut signers = Vec::with_capacity(self.signatures.len());
        let mut signature_index = 0;
        for (index, record) in old.validators.iter().enumerate() {
            if !bit_is_set(&self.signer_bitmap, index) {
                continue;
            }
            let key = record
                .active_key(old.epoch)
                .map_err(SetChangeError::Signer)?;
            let signature = self.signatures.get(signature_index).ok_or_else(|| {
                malformed(format!(
                    "bitmap marks {} signers but only {} signatures are present",
                    self.signer_count(),
                    self.signatures.len()
                ))
            })?;
            signature_index += 1;
            signers.push((record, key, signature.as_slice()));
        }
        Ok(signers)
    }
}

/// One resolved old-set signer: record, active key, and signature bytes.
type SignedEntry<'a> = (&'a ValidatorRecord, &'a ValidatorKey, &'a [u8]);

/// A transition certificate or descriptor that does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetChangeError {
    /// A set identifier or signing payload could not be encoded.
    Encoding(CryptoError),
    /// The transition failed the checked boundary rules.
    Transition(CryptoError),
    /// A signer's key could not be resolved or its signature did not verify.
    Signer(CryptoError),
    /// The certificate's bitmap or signature list is inconsistent.
    Malformed(String),
    /// The certificate does not describe the supplied sets.
    Mismatch(String),
    /// Fewer than a supermajority of the old set signed.
    NoQuorum {
        /// Distinct old-set validators that signed.
        signers: usize,
        /// Smallest signer count that is a supermajority.
        required: usize,
    },
}

impl fmt::Display for SetChangeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(f, "set change encoding: {error}"),
            Self::Transition(error) => write!(f, "set change transition: {error}"),
            Self::Signer(error) => write!(f, "set change signer: {error}"),
            Self::Malformed(detail) => write!(f, "malformed set-change certificate: {detail}"),
            Self::Mismatch(detail) => write!(f, "set-change mismatch: {detail}"),
            Self::NoQuorum { signers, required } => {
                write!(
                    f,
                    "{signers} old-set validators signed; {required} required"
                )
            }
        }
    }
}

impl std::error::Error for SetChangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(error) | Self::Transition(error) | Self::Signer(error) => Some(error),
            Self::Malformed(_) | Self::Mismatch(_) | Self::NoQuorum { .. } => None,
        }
    }
}

/// The set active at each epoch.
///
/// The prototype holds at most one transition. `SetSchedule::single` is the
/// unchanged one-set case; `SetSchedule::with_change` adds a checked transition
/// at `change_epoch`. Callers that do not need a transition keep using the
/// existing constructors.
#[derive(Debug, Clone)]
pub struct SetSchedule {
    base: ValidatorSet,
    change: Option<Change>,
}

#[derive(Debug, Clone)]
struct Change {
    epoch: u64,
    set: ValidatorSet,
    transition: Transition,
}

impl SetSchedule {
    /// A schedule with one set for every epoch.
    #[must_use]
    pub fn single(set: ValidatorSet) -> Self {
        Self {
            base: set,
            change: None,
        }
    }

    /// A schedule with one checked transition at `change_epoch`.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::InvalidKeySchedule`] when `change_epoch` does not
    /// name the new set's epoch, plus every error from [`check_transition`].
    pub fn with_change(
        base: ValidatorSet,
        change_epoch: u64,
        next: ValidatorSet,
    ) -> Result<Self, CryptoError> {
        if change_epoch != next.epoch {
            return Err(invalid(format!(
                "change epoch {change_epoch} does not match the new set epoch {}",
                next.epoch
            )));
        }
        let transition = check_transition(&base, &next)?;
        Ok(Self {
            base,
            change: Some(Change {
                epoch: change_epoch,
                set: next,
                transition,
            }),
        })
    }

    /// The set that is active before any transition.
    #[must_use]
    pub fn base(&self) -> &ValidatorSet {
        &self.base
    }

    /// The epoch the transition activates, if there is one.
    #[must_use]
    pub fn change_epoch(&self) -> Option<u64> {
        self.change.as_ref().map(|change| change.epoch)
    }

    /// The checked transition, if there is one.
    #[must_use]
    pub fn transition(&self) -> Option<&Transition> {
        self.change.as_ref().map(|change| &change.transition)
    }

    /// The largest set in the schedule.
    ///
    /// A mesh has to keep a channel and a key for every validator that can be
    /// active in either set, not only for the set that is active now.
    #[must_use]
    pub fn mesh_size(&self) -> usize {
        self.change
            .as_ref()
            .map_or(self.base.validators.len(), |change| {
                self.base.validators.len().max(change.set.validators.len())
            })
    }

    /// The set active at `epoch`.
    #[must_use]
    pub fn set_for_epoch(&self, epoch: u64) -> &ValidatorSet {
        match &self.change {
            Some(change) if epoch >= change.epoch => &change.set,
            _ => &self.base,
        }
    }

    /// The set active at `round`, using the DAG's epoch schedule.
    #[must_use]
    pub fn set_for_round(&self, schedule: &EpochSchedule, round: u64) -> &ValidatorSet {
        self.set_for_epoch(schedule.epoch_of(round))
    }
}

/// Smallest number of validators that any old quorum and any new quorum share.
///
/// With quorum sizes `old_quorum` and `new_quorum` drawn from sets whose union
/// has `old_size + new_size - shared` members, the smallest possible
/// intersection is the sum of the quorum sizes minus the union size. It
/// saturates at zero when the sets are disjoint.
#[must_use]
pub fn min_intersection(
    old_size: usize,
    new_size: usize,
    shared: usize,
    old_quorum: usize,
    new_quorum: usize,
) -> usize {
    let union = old_size.saturating_add(new_size).saturating_sub(shared);
    old_quorum.saturating_add(new_quorum).saturating_sub(union)
}

/// Checks a transition from `old` to `new`.
///
/// The rule is deliberately conservative:
///
/// - exactly one identity is added or removed;
/// - the new set keeps at least the old fault budget
///   (`new.max_faulty() >= old.max_faulty()`);
/// - any old quorum and any new quorum intersect in more than the old fault
///   budget, so at least one validator honest in both sets is in both.
///
/// The first two rules are a prototype policy. A later version can allow more
/// changes if it keeps the intersection and fault-budget checks.
///
/// # Errors
///
/// [`CryptoErrorKind::InvalidKeySchedule`] for a malformed set, a
/// non-advancing epoch, or a change count other than one;
/// [`CryptoErrorKind::PolicyUnsatisfied`] when the new set loses fault
/// tolerance or the quorum intersection is too small.
pub fn check_transition(old: &ValidatorSet, new: &ValidatorSet) -> Result<Transition, CryptoError> {
    old.validate()?;
    new.validate()?;
    if new.epoch <= old.epoch {
        return Err(invalid(format!(
            "new set epoch {} must advance past old epoch {}",
            new.epoch, old.epoch
        )));
    }

    let old_ids: HashSet<&[u8]> = old
        .validators
        .iter()
        .map(|record| record.validator_id.as_slice())
        .collect();
    let new_ids: HashSet<&[u8]> = new
        .validators
        .iter()
        .map(|record| record.validator_id.as_slice())
        .collect();
    let shared = old_ids.intersection(&new_ids).count();
    let changes = old.validators.len() + new.validators.len() - 2 * shared;
    if changes != 1 {
        return Err(invalid(format!(
            "a transition must add or remove exactly one validator, not {changes}"
        )));
    }

    let old_quorum = old.quorum_size();
    let new_quorum = new.quorum_size();
    let intersection = min_intersection(
        old.validators.len(),
        new.validators.len(),
        shared,
        old_quorum,
        new_quorum,
    );
    let fault_budget = old.max_faulty();
    let new_fault_budget = new.max_faulty();

    if new_fault_budget < fault_budget {
        return Err(policy(format!(
            "new set tolerates {new_fault_budget} faults, below the old {fault_budget}"
        )));
    }
    if intersection <= fault_budget {
        return Err(policy(format!(
            "old and new quorums intersect in at least {intersection}, not more than the \
             {fault_budget} fault budget"
        )));
    }

    Ok(Transition {
        old_epoch: old.epoch,
        new_epoch: new.epoch,
        old_size: old.validators.len(),
        new_size: new.validators.len(),
        shared,
        old_quorum,
        new_quorum,
        min_intersection: intersection,
        fault_budget,
        new_fault_budget,
    })
}

fn read_digest(decoder: &mut Decoder<'_>, what: &str) -> Result<[u8; 32], CryptoError> {
    let bytes = decoder.read_bytes()?;
    <[u8; 32]>::try_from(bytes).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::TruncatedInput,
            format!("{what} is {} bytes, expected 32", bytes.len()),
        )
    })
}

fn count_field(count: usize, what: &str) -> Result<u32, CryptoError> {
    u32::try_from(count).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{what} count does not fit a u32"),
        )
    })
}

fn codec(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, detail)
}

fn transition_hash(
    old_set_id: &[u8; 32],
    new_set_id: &[u8; 32],
    activation_epoch: u64,
) -> Result<[u8; 32], CryptoError> {
    let mut encoder = Encoder::with_capacity(80);
    encoder.put_bytes(DOMAIN_SET_TRANSITION_V1.as_bytes())?;
    encoder.put_bytes(old_set_id)?;
    encoder.put_bytes(new_set_id)?;
    encoder.put_u64(activation_epoch);
    Ok(Sha256::digest(encoder.finish()).into())
}

fn malformed(detail: impl Into<String>) -> SetChangeError {
    SetChangeError::Malformed(detail.into())
}

fn mismatch(detail: impl Into<String>) -> SetChangeError {
    SetChangeError::Mismatch(detail.into())
}

fn invalid(detail: String) -> CryptoError {
    CryptoError::new(CryptoErrorKind::InvalidKeySchedule, detail)
}

fn policy(detail: String) -> CryptoError {
    CryptoError::new(CryptoErrorKind::PolicyUnsatisfied, detail)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::certificate::bitmap_of;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    fn ids(count: usize) -> Vec<String> {
        (0..count).map(|index| format!("val-{index}")).collect()
    }

    fn set(epoch: u64, ids: &[String]) -> ValidatorSet {
        let validators = ids
            .iter()
            .map(|id| ValidatorRecord {
                validator_id: id.as_bytes().to_vec(),
                keys: vec![ValidatorKey {
                    key_id: format!("{id}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: vec![0u8; 32],
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect();
        let set = ValidatorSet { epoch, validators };
        set.validate().expect("the fixture set is valid");
        set
    }

    #[test]
    fn adding_one_validator_is_safe_at_launch_sizes() {
        for count in [4, 10, 20, 30] {
            let old = set(1, &ids(count));
            let new = set(2, &ids(count + 1));
            let transition = check_transition(&old, &new).expect("one addition is safe");
            assert_eq!(transition.changes(), 1);
            assert!(transition.min_intersection > transition.fault_budget);
            assert!(transition.new_fault_budget >= transition.fault_budget);
        }
    }

    #[test]
    fn removing_one_validator_is_safe_when_the_fault_budget_holds() {
        for count in [5, 11, 20, 30] {
            let old = set(1, &ids(count));
            let new = set(2, &ids(count - 1));
            let transition = check_transition(&old, &new).expect("the shrunken set is safe");
            assert_eq!(transition.changes(), 1);
            assert!(transition.min_intersection > transition.fault_budget);
            assert!(transition.new_fault_budget >= transition.fault_budget);
        }
    }

    #[test]
    fn removing_from_ten_lowers_the_fault_budget_and_is_rejected() {
        let old = set(1, &ids(10));
        let new = set(2, &ids(9));
        let error = check_transition(&old, &new).expect_err("nine validators cannot keep f=3");
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn a_replacement_is_two_changes_and_is_rejected() {
        let old = set(1, &ids(10));
        let mut new_ids = ids(10);
        new_ids[0] = "new-validator".to_string();
        let new = set(2, &new_ids);
        let error = check_transition(&old, &new).expect_err("a replacement is two changes");
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn a_non_advancing_epoch_is_rejected() {
        let old = set(2, &ids(10));
        let new = set(2, &ids(11));
        let error = check_transition(&old, &new).expect_err("the epoch must advance");
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn the_quorum_arithmetic_matches_the_formula() {
        let old = set(1, &ids(10));
        let new = set(2, &ids(11));
        let transition = check_transition(&old, &new).expect("10 to 11 is safe");
        assert_eq!(transition.old_quorum, 7);
        assert_eq!(transition.new_quorum, 8);
        assert_eq!(transition.shared, 10);
        assert_eq!(transition.min_intersection, 4);
        assert_eq!(transition.fault_budget, 3);
        assert_eq!(transition.new_fault_budget, 3);
    }

    #[test]
    fn a_single_schedule_returns_the_base_set() {
        let base = set(1, &ids(10));
        let schedule = SetSchedule::single(base.clone());
        assert!(schedule.change_epoch().is_none());
        assert!(schedule.transition().is_none());
        assert_eq!(schedule.set_for_epoch(1), &base);
        assert_eq!(schedule.set_for_epoch(99), &base);
    }

    #[test]
    fn a_change_activates_at_the_epoch_boundary() {
        let base = set(1, &ids(4));
        let next = set(2, &ids(5));
        let schedule = SetSchedule::with_change(base.clone(), 2, next.clone()).unwrap();
        assert_eq!(schedule.change_epoch(), Some(2));
        assert_eq!(schedule.set_for_epoch(1), &base);
        assert_eq!(schedule.set_for_epoch(2), &next);

        let epoch_schedule = crate::schedule::EpochSchedule::advancing(1, 2);
        assert_eq!(schedule.set_for_round(&epoch_schedule, 1), &base);
        assert_eq!(schedule.set_for_round(&epoch_schedule, 2), &next);
        assert_eq!(schedule.transition().unwrap().changes(), 1);
    }

    #[test]
    fn a_change_epoch_must_match_the_new_set_epoch() {
        let base = set(1, &ids(4));
        let next = set(3, &ids(5));
        let error = SetSchedule::with_change(base, 2, next).expect_err("the epochs must agree");
        assert_eq!(error.kind(), CryptoErrorKind::InvalidKeySchedule);
    }

    #[test]
    fn an_unsafe_change_is_rejected_before_it_is_scheduled() {
        let base = set(1, &ids(10));
        let next = set(2, &ids(9));
        let error = SetSchedule::with_change(base, 2, next).expect_err("f must not drop");
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn the_intersection_formula_shows_an_unsafe_shrink() {
        // Ten to eight is two removals, which the prototype rejects before this
        // arithmetic. The formula still shows why the boundary matters: a
        // seven-of-ten quorum and a six-of-eight quorum share at least three
        // validators, which is not more than f=3.
        let old_quorum = 10 * 2 / 3 + 1;
        let new_quorum = 8 * 2 / 3 + 1;
        assert_eq!(min_intersection(10, 8, 8, old_quorum, new_quorum), 3);
    }

    const CHAIN: &[u8] = b"karsa-set-change-1";

    struct Signer {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn signer(index: usize) -> Signer {
        let seed = [u8::try_from(index + 1).expect("the fixture has fewer than 255 signers"); 32];
        let public_key = Ed25519Scheme::public_key_from_seed(&seed).expect("a seed is a key");
        let mut private_key = seed.to_vec();
        private_key.extend_from_slice(&public_key);
        Signer {
            public_key: public_key.to_vec(),
            private_key,
        }
    }

    fn signed_record(index: usize, signer: &Signer) -> ValidatorRecord {
        ValidatorRecord {
            validator_id: format!("val-{index}").into_bytes(),
            keys: vec![ValidatorKey {
                key_id: format!("val-{index}-k0").into_bytes(),
                algorithm_id: ALG_ED25519,
                public_key: signer.public_key.clone(),
                activation_epoch: 0,
                retirement_epoch: NO_EXPIRY,
            }],
        }
    }

    fn signed_set(epoch: u64, signers: &[Signer]) -> ValidatorSet {
        ValidatorSet {
            epoch,
            validators: signers
                .iter()
                .enumerate()
                .map(|(index, signer)| signed_record(index, signer))
                .collect(),
        }
    }

    fn fixture(old_count: usize, new_count: usize) -> (ValidatorSet, ValidatorSet, Vec<Signer>) {
        let count = old_count.max(new_count);
        let signers: Vec<Signer> = (0..count).map(signer).collect();
        let old = signed_set(1, &signers[..old_count]);
        let new = signed_set(2, &signers[..new_count]);
        (old, new, signers)
    }

    fn propose(old: &ValidatorSet, new: &ValidatorSet) -> SetChange {
        SetChange::new(CHAIN.to_vec(), old, new).expect("the fixture transition is safe")
    }

    fn certificate(
        change: SetChange,
        new: ValidatorSet,
        old_count: usize,
        signers: &[Signer],
        signed: usize,
    ) -> TransitionCertificate {
        let payload = change
            .signing_payload()
            .expect("the fixture payload is encodable");
        TransitionCertificate {
            change,
            new_set: new,
            signer_bitmap: bitmap_of(old_count, signed),
            signatures: signers
                .iter()
                .take(signed)
                .map(|signer| {
                    Ed25519Scheme
                        .sign(&signer.private_key, &payload)
                        .expect("the fixture key signs")
                })
                .collect(),
        }
    }

    #[test]
    fn a_transition_certificate_roundtrips() {
        let (old, new, signers) = fixture(4, 5);
        let change = propose(&old, &new);
        let encoded_change = change.encode().unwrap();
        assert_eq!(SetChange::decode(&encoded_change).unwrap(), change);

        let certificate = certificate(change, new, 4, &signers, 3);
        let encoded = certificate.encode().unwrap();
        let decoded = TransitionCertificate::decode(&encoded).unwrap();
        assert_eq!(decoded, certificate);
        assert_eq!(
            decoded.verify(&old).unwrap(),
            certificate.verify(&old).unwrap()
        );
    }

    #[test]
    fn a_quorum_of_the_old_set_certifies_the_transition() {
        let (old, new, signers) = fixture(4, 5);
        let certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        let transition = certificate
            .verify(&old)
            .expect("three of four old validators are a quorum");
        assert_eq!(transition.old_epoch, 1);
        assert_eq!(transition.new_epoch, 2);
        assert_eq!(transition.old_size, 4);
        assert_eq!(transition.new_size, 5);
        assert_eq!(transition.shared, 4);
        assert_eq!(transition.old_quorum, 3);
        assert_eq!(transition.new_quorum, 4);
        assert_eq!(transition.min_intersection, 2);
        assert_eq!(transition.fault_budget, 1);
        assert_eq!(transition.new_fault_budget, 1);
        assert!(transition.min_intersection > transition.fault_budget);
    }

    #[test]
    fn a_removal_is_certified_by_the_old_quorum() {
        let (old, new, signers) = fixture(5, 4);
        assert_eq!(old.quorum_size(), 4);
        let certificate = certificate(propose(&old, &new), new, 5, &signers, 4);
        let transition = certificate
            .verify(&old)
            .expect("four of five old validators are a quorum");
        assert_eq!(transition.new_size, 4);
        assert_eq!(transition.min_intersection, 2);
        assert!(transition.min_intersection > transition.fault_budget);
    }

    #[test]
    fn fewer_than_a_quorum_of_the_old_set_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let certificate = certificate(propose(&old, &new), new, 4, &signers, 2);
        let error = certificate
            .verify(&old)
            .expect_err("two of four is not a quorum");
        assert!(
            matches!(
                error,
                SetChangeError::NoQuorum {
                    signers: 2,
                    required: 3
                }
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let mut certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        certificate.signatures[0][0] ^= 0xff;
        let error = certificate
            .verify(&old)
            .expect_err("a changed signature must not verify");
        assert!(
            matches!(
                error,
                SetChangeError::Signer(ref error)
                    if error.kind() == CryptoErrorKind::InvalidSignature
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_signature_for_another_chain_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let mut certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        certificate.change.chain_id = b"karsa-other-chain".to_vec();
        let error = certificate
            .verify(&old)
            .expect_err("the signatures cover the original chain id");
        assert!(
            matches!(
                error,
                SetChangeError::Signer(ref error)
                    if error.kind() == CryptoErrorKind::InvalidSignature
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_certificate_for_a_different_old_set_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        let mut other_old = old.clone();
        other_old.validators[0].keys[0].public_key = vec![9u8; 32];
        let error = certificate
            .verify(&other_old)
            .expect_err("the old set id is bound");
        assert!(
            matches!(error, SetChangeError::Mismatch(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_certificate_for_a_different_new_set_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let mut certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        certificate.new_set.validators[4].keys[0].public_key = vec![9u8; 32];
        let error = certificate
            .verify(&old)
            .expect_err("the new set id is bound");
        assert!(
            matches!(error, SetChangeError::Mismatch(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_activation_epoch_that_does_not_match_the_new_set_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let mut certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        certificate.change.activation_epoch = 3;
        let error = certificate
            .verify(&old)
            .expect_err("the activation epoch is signed");
        assert!(
            matches!(error, SetChangeError::Mismatch(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn a_malformed_bitmap_is_rejected() {
        let (old, new, signers) = fixture(4, 5);
        let mut certificate = certificate(propose(&old, &new), new, 4, &signers, 3);
        certificate.signatures.pop();
        let error = certificate
            .verify(&old)
            .expect_err("the bitmap marks one more signer than the list holds");
        assert!(
            matches!(error, SetChangeError::Malformed(_)),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn an_unsafe_transition_cannot_be_proposed() {
        let (old, new, _signers) = fixture(10, 9);
        let error = SetChange::new(CHAIN.to_vec(), &old, &new)
            .expect_err("nine validators cannot keep the old fault budget");
        assert!(
            matches!(
                error,
                SetChangeError::Transition(ref error)
                    if error.kind() == CryptoErrorKind::PolicyUnsatisfied
            ),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn duplicate_validator_identities_are_rejected() {
        let (old, new, _signers) = fixture(4, 5);
        let mut duplicate = new;
        duplicate.validators.push(duplicate.validators[0].clone());
        let error = SetChange::new(CHAIN.to_vec(), &old, &duplicate)
            .expect_err("a set cannot contain one identity twice");
        assert!(
            matches!(
                error,
                SetChangeError::Transition(ref error)
                    if error.kind() == CryptoErrorKind::DuplicateValidatorId
            ),
            "unexpected error: {error}"
        );
    }
}
