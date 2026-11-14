//! Inactive, fixed-validator-set slot-decision protocol primitives.
//!
//! This phase-one safety kernel is not integrated with live consensus. It provides
//! no unlock rule or liveness guarantee. Verification checks authorization and
//! structural effects, not semantic evidence, causal validity, elected leadership,
//! previous-decision continuity, or application correctness; callers must check those.

use std::collections::HashSet;

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::{ValidatorSet, ValidatorSignature, VertexId};

/// Canonical descriptor and certificate version.
pub const SLOT_DECISION_VERSION_V1: u16 = 1;
/// Domain for signer-independent decision identifiers.
pub const SLOT_DECISION_ID_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_DECISION/ID/v1";
/// Distinct domain for quorum signatures over decisions.
pub const SLOT_DECISION_SIGNING_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_DECISION/SIGN/v1";

// Bound total parsing/allocation work as well as individual canonical fields.
const MAX_CERTIFICATE_BYTES: usize = MAX_FIELD_LEN;
const MAX_SIGNATURES: usize = 4096;
const MAX_VALIDATORS: usize = 4096;
const MAX_DECISION_BYTES: usize = 64 * 1024;
const MAX_ID_BYTES: usize = 1024;

/// The mutually exclusive structural outcome of one slot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotOutcome {
    /// Commit this leader, possibly already committed as an ancestor (no frontier growth).
    /// Contents and ancestry require caller validation.
    Commit {
        /// Committed leader identifier.
        leader: VertexId,
    },
    /// Preserve the frontier for this leader; the cause requires caller validation.
    Skip {
        /// Skipped leader's validator identifier.
        leader_author: Vec<u8>,
    },
}

/// Signer-independent slot statement for an inactive fixed-set protocol.
///
/// Canonical bodies are limited to 64 KiB; chain and identity fields to 1024 bytes.
/// These bounds apply to encoding, decoding, hashing, signing, and validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDecision {
    /// Chain identifier.
    pub chain_id: Vec<u8>,
    /// Content identifier of the fixed validator set.
    pub validator_set_id: [u8; 32],
    /// Epoch of that set.
    pub epoch: u64,
    /// Decided slot round.
    pub round: u64,
    /// Previous decision identifier; continuity is checked by the caller.
    pub previous: [u8; 32],
    /// Frontier length before the decision.
    pub before_len: u64,
    /// Frontier root before the decision.
    pub before_root: [u8; 32],
    /// Frontier length after the decision.
    pub after_len: u64,
    /// Frontier root after the decision.
    pub after_root: [u8; 32],
    /// Structural slot effect.
    pub outcome: SlotOutcome,
}

fn malformed(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

fn digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], CryptoError> {
    decoder
        .read_bytes()?
        .try_into()
        .map_err(|_| malformed("expected a 32-byte digest"))
}

fn version(decoder: &mut Decoder<'_>) -> Result<(), CryptoError> {
    if decoder.read_u16()? != SLOT_DECISION_VERSION_V1 {
        return Err(malformed("unsupported slot decision version"));
    }
    Ok(())
}

impl SlotDecision {
    /// Encodes the canonical version-one body without signers.
    ///
    /// # Errors
    /// Returns encoding errors for oversized fields.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        check_id(&self.chain_id)?;
        match &self.outcome {
            SlotOutcome::Commit { leader } => check_id(&leader.author)?,
            SlotOutcome::Skip { leader_author } => check_id(leader_author)?,
        }
        let mut e = Encoder::new();
        e.put_u16(SLOT_DECISION_VERSION_V1);
        e.put_bytes(&self.chain_id)?;
        e.put_bytes(&self.validator_set_id)?;
        e.put_u64(self.epoch);
        e.put_u64(self.round);
        e.put_bytes(&self.previous)?;
        e.put_u64(self.before_len);
        e.put_bytes(&self.before_root)?;
        e.put_u64(self.after_len);
        e.put_bytes(&self.after_root)?;
        match &self.outcome {
            SlotOutcome::Commit { leader } => {
                e.put_u8(1);
                e.put_u64(leader.round);
                e.put_bytes(&leader.author)?;
                e.put_bytes(&leader.digest)?;
            }
            SlotOutcome::Skip { leader_author } => {
                e.put_u8(2);
                e.put_bytes(leader_author)?;
            }
        }
        check_decision_size(e.len())?;
        Ok(e.finish())
    }

    /// Decodes a canonical body without performing semantic validation.
    ///
    /// # Errors
    /// Rejects malformed lengths, truncation, trailing bytes, and unknown versions or tags.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_decision_size(bytes.len())?;
        let mut d = Decoder::new(bytes);
        version(&mut d)?;
        let chain_id = read_id(&mut d)?;
        let validator_set_id = digest(&mut d)?;
        let epoch = d.read_u64()?;
        let round = d.read_u64()?;
        let previous = digest(&mut d)?;
        let before_len = d.read_u64()?;
        let before_root = digest(&mut d)?;
        let after_len = d.read_u64()?;
        let after_root = digest(&mut d)?;
        let outcome = match d.read_u8()? {
            1 => SlotOutcome::Commit {
                leader: VertexId {
                    round: d.read_u64()?,
                    author: read_id(&mut d)?,
                    digest: digest(&mut d)?,
                },
            },
            2 => SlotOutcome::Skip {
                leader_author: read_id(&mut d)?,
            },
            _ => return Err(malformed("unknown slot outcome")),
        };
        d.finish()?;
        Ok(Self {
            chain_id,
            validator_set_id,
            epoch,
            round,
            previous,
            before_len,
            before_root,
            after_len,
            after_root,
            outcome,
        })
    }

    fn tagged_body(&self, domain: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut e = Encoder::new();
        e.put_bytes(domain)?;
        e.put_raw(&self.encode()?);
        Ok(e.finish())
    }

    /// Hashes the domain-separated body, independent of any certificate or signer subset.
    ///
    /// # Errors
    /// Propagates canonical encoding errors.
    pub fn id(&self) -> Result<[u8; 32], CryptoError> {
        Ok(Sha256::digest(self.tagged_body(SLOT_DECISION_ID_DOMAIN)?).into())
    }

    /// Builds canonical signing bytes in a domain distinct from the identifier domain.
    ///
    /// # Errors
    /// Propagates canonical encoding errors.
    pub fn signing_payload(&self) -> Result<Vec<u8>, CryptoError> {
        self.tagged_body(SLOT_DECISION_SIGNING_DOMAIN)
    }

    /// Checks fixed-set binding, safe quorum intersection, membership, and structural effects.
    ///
    /// The caller must validate the elected leader, evidence, continuity, and application.
    /// This does not unlock a vote or provide a live protocol.
    ///
    /// # Errors
    /// Returns set validation/encoding errors or rejects a mismatched set/epoch,
    /// unsafe intersection, nonmember leader, or inconsistent frontier effect.
    pub fn validate(&self, set: &ValidatorSet) -> Result<(), CryptoError> {
        self.encode()?;
        validate_slot_set(set)?;
        if self.validator_set_id != set.id()? || self.epoch != set.epoch {
            return Err(malformed("slot decision set or epoch mismatch"));
        }
        let author = match &self.outcome {
            SlotOutcome::Commit { leader } => {
                if leader.round != self.round
                    || self.after_len < self.before_len
                    || (self.after_len == self.before_len && self.after_root != self.before_root)
                {
                    return Err(malformed(
                        "commit must not shrink or change an unchanged frontier in the leader round",
                    ));
                }
                &leader.author
            }
            SlotOutcome::Skip { leader_author } => {
                if self.before_len != self.after_len || self.before_root != self.after_root {
                    return Err(malformed("skip must preserve the frontier"));
                }
                leader_author
            }
        };
        if set.validator(author).is_none() {
            return Err(CryptoError::new(
                CryptoErrorKind::UnknownValidator,
                "slot leader is not a member",
            ));
        }
        Ok(())
    }
}

/// Quorum authorization of an inactive fixed-set slot statement, not semantic evidence.
///
/// Supports at most 4096 validators/signatures and a one-MiB certificate. Callers
/// should check [`Self::encode`] with the intended signature sizes before signing:
/// a valid body does not guarantee that the resulting quorum fits the wire budget.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDecisionCertificate {
    /// Signer-independent statement.
    pub decision: SlotDecision,
    /// Explicit validator/key signatures over the decision signing payload.
    pub signatures: Vec<ValidatorSignature>,
}

impl SlotDecisionCertificate {
    /// Verifies chain binding, structural validity, distinct signers, and quorum signatures.
    ///
    /// Does not validate evidence, cause, application effects, or elected leadership,
    /// and supplies no unlock/liveness rule or live integration.
    ///
    /// # Errors
    /// Propagates decision and signature errors; rejects duplicates and missing quorum.
    pub fn verify(&self, chain_id: &[u8], set: &ValidatorSet) -> Result<(), CryptoError> {
        // Apply the same wire budget to in-memory certificates before cryptographic work.
        self.encode()?;
        if self.decision.chain_id != chain_id {
            return Err(malformed("slot decision chain mismatch"));
        }
        self.decision.validate(set)?;
        let mut seen = HashSet::new();
        for signature in &self.signatures {
            if !seen.insert(signature.validator_id.as_slice()) {
                return Err(malformed("duplicate slot decision signer"));
            }
        }
        let signers = set.verify_signatures(
            &self.decision.signing_payload()?,
            self.decision.epoch,
            &self.signatures,
        )?;
        if signers.len() < set.quorum_size() {
            return Err(malformed("slot decision has no quorum"));
        }
        Ok(())
    }

    /// Encodes a version-one certificate, bounded to one MiB and 4096 signatures.
    ///
    /// # Errors
    /// Returns field/total-size encoding errors or rejects an excessive signature count.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        if self.signatures.len() > MAX_SIGNATURES {
            return Err(malformed("too many slot decision signatures"));
        }
        let mut e = Encoder::new();
        e.put_u16(SLOT_DECISION_VERSION_V1);
        e.put_bytes(&self.decision.encode()?)?;
        e.put_u32(self.signatures.len() as u32);
        for signature in &self.signatures {
            check_id(&signature.validator_id)?;
            check_id(&signature.key_id)?;
            e.put_bytes(&signature.validator_id)?;
            e.put_bytes(&signature.key_id)?;
            e.put_bytes(&signature.signature)?;
            check_size(e.len())?;
        }
        check_size(e.len())?;
        Ok(e.finish())
    }

    /// Decodes a bounded certificate; authorization requires a separate `verify` call.
    ///
    /// # Errors
    /// Rejects oversized input/counts, malformed fields, unknown versions, and trailing bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_size(bytes.len())?;
        let mut d = Decoder::new(bytes);
        version(&mut d)?;
        let decision = SlotDecision::decode(d.read_bytes()?)?;
        let count = d.read_u32()? as usize;
        if count > MAX_SIGNATURES || count > d.remaining() / 12 {
            return Err(malformed("invalid slot decision signature count"));
        }
        let mut signatures = Vec::with_capacity(count);
        for _ in 0..count {
            signatures.push(ValidatorSignature {
                validator_id: read_id(&mut d)?,
                key_id: read_id(&mut d)?,
                signature: d.read_bytes()?.to_vec(),
            });
        }
        d.finish()?;
        Ok(Self {
            decision,
            signatures,
        })
    }
}

/// Inactive continuity tracker for quorum-authorized, fixed-set slot decisions.
///
/// This is not a DAG mutation or final live application. Authorization and structural
/// continuity do not establish causal binding or semantic correctness of effects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotDecisionTip {
    chain_id: Vec<u8>,
    set_id: [u8; 32],
    epoch: u64,
    next_round: u64,
    previous_id: [u8; 32],
    order_len: u64,
    order_root: [u8; 32],
}

impl SlotDecisionTip {
    /// Initializes from trusted bootstrap values and validates the fixed validator set.
    ///
    /// Despite the name, this neither authenticates a checkpoint nor implements secure
    /// restoration: the caller must establish trust in every supplied bootstrap value.
    ///
    /// # Errors
    /// Returns chain-size, validator-set validation, or set-identifier encoding errors.
    pub fn from_checkpoint(
        chain_id: Vec<u8>,
        set: &ValidatorSet,
        next_round: u64,
        previous: [u8; 32],
        order_len: u64,
        root: [u8; 32],
    ) -> Result<Self, CryptoError> {
        check_id(&chain_id)?;
        validate_slot_set(set)?;
        Ok(Self {
            chain_id,
            set_id: set.id()?,
            epoch: set.epoch,
            next_round,
            previous_id: previous,
            order_len,
            order_root: root,
        })
    }

    /// Advances structural continuity after verifying quorum authorization.
    ///
    /// Before calling, the caller must validate elected leadership, semantic effects,
    /// evidence, and causal binding. This is not final live application and provides
    /// no unlock or liveness rule. Even an unchanged frontier advances the decision chain.
    /// All checks and ID computation finish before any state changes.
    ///
    /// # Errors
    /// Propagates certificate/encoding errors and rejects pinned-set, round, predecessor,
    /// or before-frontier mismatches and round overflow. Every failure leaves the tip unchanged.
    pub fn advance_authorized(
        &mut self,
        cert: &SlotDecisionCertificate,
        set: &ValidatorSet,
    ) -> Result<(), CryptoError> {
        cert.verify(&self.chain_id, set)?;
        self.advance_inspected(&cert.decision)
    }

    // The caller must fully inspect authorization, causal binding, and effects first.
    pub(crate) fn advance_inspected(&mut self, d: &SlotDecision) -> Result<(), CryptoError> {
        if d.validator_set_id != self.set_id || d.epoch != self.epoch {
            return Err(malformed("slot tip pinned set or epoch mismatch"));
        }
        if d.round != self.next_round
            || d.previous != self.previous_id
            || d.before_len != self.order_len
            || d.before_root != self.order_root
        {
            return Err(malformed("slot tip continuity mismatch"));
        }
        let next_round = self
            .next_round
            .checked_add(1)
            .ok_or_else(|| malformed("slot tip round overflow"))?;
        let previous_id = d.id()?;
        self.next_round = next_round;
        self.previous_id = previous_id;
        self.order_len = d.after_len;
        self.order_root = d.after_root;
        Ok(())
    }

    /// Pinned chain identifier.
    #[must_use]
    pub fn chain_id(&self) -> &[u8] {
        &self.chain_id
    }
    /// Pinned validator-set identifier.
    #[must_use]
    pub fn set_id(&self) -> &[u8; 32] {
        &self.set_id
    }
    /// Pinned validator-set epoch.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
    /// Next expected decision round.
    #[must_use]
    pub fn next_round(&self) -> u64 {
        self.next_round
    }
    /// Most recently accepted decision ID, or trusted bootstrap predecessor.
    #[must_use]
    pub fn previous_id(&self) -> &[u8; 32] {
        &self.previous_id
    }
    /// Current authorized order length.
    #[must_use]
    pub fn order_len(&self) -> u64 {
        self.order_len
    }
    /// Current authorized order root.
    #[must_use]
    pub fn order_root(&self) -> &[u8; 32] {
        &self.order_root
    }
}

fn validate_slot_set(set: &ValidatorSet) -> Result<(), CryptoError> {
    let n = set.validators.len();
    if n > MAX_VALIDATORS {
        return Err(malformed("slot validator set exceeds 4096 members"));
    }
    set.validate()?;
    let mut active_keys = HashSet::new();
    for record in &set.validators {
        check_id(&record.validator_id)?;
        for key in &record.keys {
            check_id(&key.key_id)?;
            if key.is_active(set.epoch)
                && !active_keys.insert((key.algorithm_id, key.public_key.as_slice()))
            {
                return Err(malformed("duplicate active slot verification key"));
            }
        }
    }
    let q = set.quorum_size();
    if n == 0 || q > n || q.saturating_mul(2).saturating_sub(n) <= set.max_faulty() {
        return Err(malformed("unsafe slot decision quorum intersection"));
    }
    Ok(())
}

fn check_id(bytes: &[u8]) -> Result<(), CryptoError> {
    if bytes.len() > MAX_ID_BYTES {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "slot chain or identity exceeds 1024 bytes",
        ));
    }
    Ok(())
}

fn read_id(decoder: &mut Decoder<'_>) -> Result<Vec<u8>, CryptoError> {
    let bytes = decoder.read_bytes()?;
    check_id(bytes)?;
    Ok(bytes.to_vec())
}

fn check_decision_size(size: usize) -> Result<(), CryptoError> {
    if size > MAX_DECISION_BYTES {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "slot decision exceeds 64 KiB",
        ));
    }
    Ok(())
}

fn check_size(size: usize) -> Result<(), CryptoError> {
    if size > MAX_CERTIFICATE_BYTES {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "slot certificate exceeds size limit",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    fn fixture() -> (ValidatorSet, Vec<Vec<u8>>, SlotDecision) {
        let mut keys = Vec::new();
        let validators = (0..4u8)
            .map(|i| {
                let seed = [i + 1; 32];
                let public = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
                keys.push([seed.as_slice(), public.as_slice()].concat());
                ValidatorRecord {
                    validator_id: vec![i],
                    keys: vec![ValidatorKey {
                        key_id: vec![i],
                        algorithm_id: ALG_ED25519,
                        public_key: public.to_vec(),
                        activation_epoch: 0,
                        retirement_epoch: NO_EXPIRY,
                    }],
                }
            })
            .collect();
        let set = ValidatorSet {
            epoch: 2,
            validators,
        };
        let decision = SlotDecision {
            chain_id: b"slot-test".to_vec(),
            validator_set_id: set.id().unwrap(),
            epoch: 2,
            round: 7,
            previous: [1; 32],
            before_len: 3,
            before_root: [2; 32],
            after_len: 4,
            after_root: [3; 32],
            outcome: SlotOutcome::Commit {
                leader: VertexId {
                    round: 7,
                    author: vec![0],
                    digest: [4; 32],
                },
            },
        };
        (set, keys, decision)
    }

    fn certificate(
        decision: SlotDecision,
        keys: &[Vec<u8>],
        indices: &[usize],
    ) -> SlotDecisionCertificate {
        let payload = decision.signing_payload().unwrap();
        let signatures = indices
            .iter()
            .map(|&i| ValidatorSignature {
                validator_id: vec![i as u8],
                key_id: vec![i as u8],
                signature: Ed25519Scheme.sign(&keys[i], &payload).unwrap(),
            })
            .collect();
        SlotDecisionCertificate {
            decision,
            signatures,
        }
    }

    fn skip(mut d: SlotDecision) -> SlotDecision {
        d.after_len = d.before_len;
        d.after_root = d.before_root;
        d.outcome = SlotOutcome::Skip {
            leader_author: vec![0],
        };
        d
    }

    fn tip(set: &ValidatorSet, d: &SlotDecision) -> SlotDecisionTip {
        SlotDecisionTip::from_checkpoint(
            d.chain_id.clone(),
            set,
            d.round,
            d.previous,
            d.before_len,
            d.before_root,
        )
        .unwrap()
    }

    #[test]
    fn slot_decision_tip_skip_chain_and_signer_independence() {
        let (set, keys, d) = fixture();
        let mut d = skip(d);
        let mut a = tip(&set, &d);
        let mut b = a.clone();
        assert_eq!(a.chain_id(), d.chain_id);
        assert_eq!(a.set_id(), &d.validator_set_id);
        assert_eq!(a.epoch(), set.epoch);
        for _ in 0..3 {
            a.advance_authorized(&certificate(d.clone(), &keys, &[0, 1, 2]), &set)
                .unwrap();
            b.advance_authorized(&certificate(d.clone(), &keys, &[1, 2, 3]), &set)
                .unwrap();
            assert_eq!(a, b);
            assert_eq!(a.next_round(), d.round + 1);
            assert_eq!(a.previous_id(), &d.id().unwrap());
            assert_eq!(a.order_len(), d.before_len);
            assert_eq!(a.order_root(), &d.before_root);
            d.previous = d.id().unwrap();
            d.round += 1;
        }
        // A subsequent growth decision uses the same unchanged frontier.
        d.after_len += 1;
        d.after_root = [9; 32];
        d.outcome = SlotOutcome::Commit {
            leader: VertexId {
                round: d.round,
                author: vec![0],
                digest: [8; 32],
            },
        };
        a.advance_authorized(&certificate(d.clone(), &keys, &[0, 1, 2]), &set)
            .unwrap();
        assert_eq!(a.order_len(), d.after_len);
        assert_eq!(a.order_root(), &d.after_root);
    }

    #[test]
    fn slot_decision_tip_rejects_conflict_and_continuity_errors_atomically() {
        let (set, keys, d) = fixture();
        let initial = tip(&set, &d);
        for field in 0..6 {
            let mut bad = d.clone();
            match field {
                0 => {
                    bad.round += 1;
                    if let SlotOutcome::Commit { leader } = &mut bad.outcome {
                        leader.round += 1;
                    }
                }
                1 => bad.previous[0] ^= 1,
                2 => bad.before_len -= 1,
                3 => bad.before_root[0] ^= 1,
                4 => bad.chain_id.push(0),
                _ => bad.validator_set_id[0] ^= 1,
            }
            let mut t = initial.clone();
            assert!(
                t.advance_authorized(&certificate(bad, &keys, &[0, 1, 2]), &set)
                    .is_err()
            );
            assert_eq!(t, initial, "field {field}");
        }
        let mut other = set.clone();
        other.epoch += 1;
        let mut changed = d.clone();
        changed.epoch = other.epoch;
        changed.validator_set_id = other.id().unwrap();
        let c = certificate(changed, &keys, &[0, 1, 2]);
        c.verify(b"slot-test", &other).unwrap();
        let mut t = initial.clone();
        assert!(t.advance_authorized(&c, &other).is_err());
        assert_eq!(t, initial);
        let mut reordered = set.clone();
        reordered.validators.swap(0, 1);
        let mut changed = d.clone();
        changed.validator_set_id = reordered.id().unwrap();
        assert!(
            t.advance_authorized(&certificate(changed, &keys, &[0, 1, 2]), &reordered)
                .is_err()
        );
        assert_eq!(t, initial);
        let mut invalid = certificate(d.clone(), &keys, &[0, 1, 2]);
        invalid.signatures[0].signature[0] ^= 1;
        assert!(t.advance_authorized(&invalid, &set).is_err());
        assert_eq!(t, initial);
        t.advance_authorized(&certificate(d.clone(), &keys, &[0, 1, 2]), &set)
            .unwrap();
        let accepted = t.clone();
        for same_slot in [d.clone(), skip(d)] {
            assert!(
                t.advance_authorized(&certificate(same_slot, &keys, &[1, 2, 3]), &set)
                    .is_err()
            );
            assert_eq!(t, accepted);
        }
    }

    #[test]
    fn slot_decision_tip_bootstrap_and_overflow() {
        let (set, keys, d) = fixture();
        let mut end = skip(d.clone());
        end.round = u64::MAX;
        let mut t = tip(&set, &end);
        let original = t.clone();
        assert!(
            t.advance_authorized(&certificate(end, &keys, &[0, 1, 2]), &set)
                .is_err()
        );
        assert_eq!(t, original);
        assert!(
            SlotDecisionTip::from_checkpoint(
                vec![0; MAX_ID_BYTES + 1],
                &set,
                0,
                [0; 32],
                0,
                [0; 32]
            )
            .is_err()
        );
        let empty = ValidatorSet {
            epoch: 2,
            validators: vec![],
        };
        assert!(SlotDecisionTip::from_checkpoint(vec![], &empty, 0, [0; 32], 0, [0; 32]).is_err());
        let mut duplicate = set.clone();
        duplicate.validators[1].keys[0].public_key =
            duplicate.validators[0].keys[0].public_key.clone();
        assert!(
            SlotDecisionTip::from_checkpoint(vec![], &duplicate, 0, [0; 32], 0, [0; 32]).is_err()
        );
    }

    #[test]
    fn slot_decision_roundtrips_and_signer_independent_ids() {
        let (set, keys, d) = fixture();
        for d in [d.clone(), skip(d)] {
            let a = certificate(d.clone(), &keys, &[0, 1, 2]);
            let b = certificate(d.clone(), &keys, &[1, 2, 3]);
            a.verify(b"slot-test", &set).unwrap();
            b.verify(b"slot-test", &set).unwrap();
            assert_ne!(a.encode().unwrap(), b.encode().unwrap());
            assert_eq!(a.decision.id().unwrap(), b.decision.id().unwrap());
            assert_eq!(SlotDecision::decode(&d.encode().unwrap()).unwrap(), d);
            assert_eq!(
                SlotDecisionCertificate::decode(&a.encode().unwrap()).unwrap(),
                a
            );
        }
    }

    #[test]
    fn slot_decision_malformed_encodings() {
        let (_, keys, d) = fixture();
        let bytes = d.encode().unwrap();
        for end in 0..bytes.len() {
            assert!(SlotDecision::decode(&bytes[..end]).is_err());
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(SlotDecision::decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[0] = 2;
        assert!(SlotDecision::decode(&bad).is_err());
        let mut bad = bytes.clone();
        bad[bytes.len() - 50] = 9;
        assert!(SlotDecision::decode(&bad).is_err());
        let mut bad = bytes;
        bad[15..19].copy_from_slice(&31u32.to_le_bytes());
        assert!(SlotDecision::decode(&bad).is_err());
        let c = certificate(d, &keys, &[0, 1, 2]).encode().unwrap();
        for end in 0..c.len() {
            assert!(SlotDecisionCertificate::decode(&c[..end]).is_err());
        }
        let mut bad = c.clone();
        bad.push(0);
        assert!(SlotDecisionCertificate::decode(&bad).is_err());
        let mut bad = c.clone();
        bad[0] = 2;
        assert!(SlotDecisionCertificate::decode(&bad).is_err());
        let body_len = u32::from_le_bytes(c[2..6].try_into().unwrap()) as usize;
        let mut bad = c;
        bad[6 + body_len..10 + body_len].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(SlotDecisionCertificate::decode(&bad).is_err());
        assert!(SlotDecisionCertificate::decode(&vec![0; MAX_CERTIFICATE_BYTES + 1]).is_err());
    }

    #[test]
    fn slot_decision_chain_set_epoch_and_domain_tampering() {
        let (set, keys, d) = fixture();
        let c = certificate(d, &keys, &[0, 1, 2]);
        assert!(c.verify(b"other", &set).is_err());
        for field in 0..8 {
            let mut bad = c.clone();
            match field {
                0 => bad.decision.chain_id.push(0),
                1 => bad.decision.validator_set_id[0] ^= 1,
                2 => bad.decision.epoch += 1,
                3 => bad.decision.previous[0] ^= 1,
                4 => bad.decision.before_root[0] ^= 1,
                5 => bad.decision.after_root[0] ^= 1,
                6 => {
                    bad.decision.before_len += 1;
                    bad.decision.after_len += 1;
                }
                _ => {
                    bad.decision.round += 1;
                    if let SlotOutcome::Commit { leader } = &mut bad.decision.outcome {
                        leader.round += 1;
                    }
                }
            }
            assert!(
                bad.verify(&bad.decision.chain_id, &set).is_err(),
                "field {field}"
            );
        }
        for payload in [
            c.decision.encode().unwrap(),
            c.decision.tagged_body(SLOT_DECISION_ID_DOMAIN).unwrap(),
            c.decision.id().unwrap().to_vec(),
        ] {
            let mut bad = c.clone();
            for (i, signature) in bad.signatures.iter_mut().enumerate() {
                signature.signature = Ed25519Scheme.sign(&keys[i], &payload).unwrap();
            }
            assert!(bad.verify(b"slot-test", &set).is_err());
        }
    }

    #[test]
    fn slot_decision_conflicting_commit_skip_certificates_do_not_share_signatures() {
        let (set, keys, d) = fixture();
        let commit = certificate(d.clone(), &keys, &[0, 1, 2]);
        let skipped = certificate(skip(d), &keys, &[1, 2, 3]);
        // A stateless verifier cannot reject separately signed equivocation;
        // honest signer discipline/locking belongs to the caller, not this primitive.
        commit.verify(b"slot-test", &set).unwrap();
        skipped.verify(b"slot-test", &set).unwrap();
        assert_ne!(
            commit.decision.id().unwrap(),
            skipped.decision.id().unwrap()
        );
        let forged = SlotDecisionCertificate {
            decision: skipped.decision,
            signatures: commit.signatures,
        };
        assert!(forged.verify(b"slot-test", &set).is_err());
    }

    #[test]
    fn slot_decision_no_quorum_duplicate_and_invalid_signers() {
        let (set, keys, d) = fixture();
        for indices in [&[][..], &[0, 1][..], &[0, 0, 1][..], &[0, 1, 2, 2][..]] {
            assert!(
                certificate(d.clone(), &keys, indices)
                    .verify(b"slot-test", &set)
                    .is_err()
            );
        }
        let mut c = certificate(d, &keys, &[0, 1, 2]);
        c.signatures[0].signature[0] ^= 1;
        assert!(c.verify(b"slot-test", &set).is_err());
    }

    #[test]
    fn slot_decision_rejects_relabeled_reused_active_key_signature() {
        let (mut set, keys, mut d) = fixture();
        set.validators[1].keys[0].public_key = set.validators[0].keys[0].public_key.clone();
        d.validator_set_id = set.id().unwrap();
        let mut c = certificate(d, &keys, &[0, 2, 3]);
        let mut relabeled = c.signatures[0].clone();
        relabeled.validator_id = vec![1];
        relabeled.key_id = vec![1];
        c.signatures = vec![c.signatures[0].clone(), relabeled, c.signatures[1].clone()];
        // Without key uniqueness these are three accepted identities from two keys.
        assert_eq!(
            set.verify_signatures(&c.decision.signing_payload().unwrap(), 2, &c.signatures)
                .unwrap()
                .len(),
            3
        );
        assert!(c.verify(b"slot-test", &set).is_err());
        assert!(c.decision.validate(&set).is_err());
        // Sharing retired key material is not sharing a current voting key.
        let mut historical = set.validators[0].keys[0].clone();
        historical.key_id = vec![99];
        historical.retirement_epoch = 1;
        set.validators[1].keys[0].public_key = Ed25519Scheme::public_key_from_seed(&[2; 32])
            .unwrap()
            .to_vec();
        set.validators[1].keys[0].activation_epoch = 1;
        set.validators[1].keys.push(historical);
        c.decision.validator_set_id = set.id().unwrap();
        c.decision.validate(&set).unwrap();
    }

    #[test]
    fn slot_decision_consistent_resource_bounds() {
        let (set, keys, d) = fixture();
        for outcome in [d.outcome.clone(), skip(d.clone()).outcome] {
            let mut large = d.clone();
            large.outcome = outcome;
            large.chain_id = vec![1; MAX_ID_BYTES];
            match &mut large.outcome {
                SlotOutcome::Commit { leader } => leader.author = vec![2; MAX_ID_BYTES],
                SlotOutcome::Skip { leader_author } => *leader_author = vec![2; MAX_ID_BYTES],
            }
            let encoded = large.encode().unwrap();
            assert_eq!(SlotDecision::decode(&encoded).unwrap(), large);
            large.chain_id.push(1);
            assert!(large.encode().is_err());
            assert!(large.id().is_err());
            assert!(large.signing_payload().is_err());
            assert!(large.validate(&set).is_err());
            let mut e = Encoder::new();
            e.put_u16(SLOT_DECISION_VERSION_V1);
            e.put_bytes(&large.chain_id).unwrap();
            assert!(SlotDecision::decode(&e.finish()).is_err());
            large.chain_id.clear();
            match &mut large.outcome {
                SlotOutcome::Commit { leader } => leader.author.push(2),
                SlotOutcome::Skip { leader_author } => leader_author.push(2),
            }
            assert!(large.encode().is_err());
            assert!(large.id().is_err());
            assert!(large.signing_payload().is_err());
            assert!(large.validate(&set).is_err());
        }
        assert!(SlotDecision::decode(&vec![0; MAX_DECISION_BYTES + 1]).is_err());
        let mut c = certificate(d.clone(), &keys, &[0, 1, 2]);
        c.signatures
            .resize(MAX_SIGNATURES + 1, c.signatures[0].clone());
        assert!(c.encode().is_err());
        assert!(c.verify(b"slot-test", &set).is_err());
        c.signatures.truncate(3);
        c.signatures[0].key_id = vec![0; MAX_ID_BYTES + 1];
        assert!(c.encode().is_err());
        assert!(c.verify(b"slot-test", &set).is_err());
        c.signatures[0].key_id = vec![0];
        c.signatures[0].signature = vec![0; MAX_CERTIFICATE_BYTES];
        assert!(c.encode().is_err());
        assert!(c.verify(b"slot-test", &set).is_err());
        let mut oversized = set.clone();
        oversized
            .validators
            .resize(MAX_VALIDATORS + 1, set.validators[0].clone());
        assert!(d.validate(&oversized).is_err());
    }

    #[test]
    fn slot_decision_membership_effects_and_set_validity() {
        let (set, _, d) = fixture();
        d.validate(&set).unwrap();
        let s = skip(d.clone());
        s.validate(&set).unwrap();
        let mut bad = d.clone();
        bad.after_len = bad.before_len;
        assert!(bad.validate(&set).is_err());
        bad.after_root = bad.before_root;
        bad.validate(&set).unwrap();
        let (_, keys, _) = fixture();
        let no_growth = certificate(bad.clone(), &keys, &[0, 1, 2]);
        no_growth.verify(b"slot-test", &set).unwrap();
        assert_eq!(SlotDecision::decode(&bad.encode().unwrap()).unwrap(), bad);
        bad.after_len = bad.before_len - 1;
        assert!(bad.validate(&set).is_err());
        for outcome in [
            SlotOutcome::Commit {
                leader: VertexId {
                    round: 8,
                    author: vec![0],
                    digest: [0; 32],
                },
            },
            SlotOutcome::Commit {
                leader: VertexId {
                    round: 7,
                    author: vec![9],
                    digest: [0; 32],
                },
            },
            SlotOutcome::Skip {
                leader_author: vec![9],
            },
        ] {
            let mut bad = if matches!(outcome, SlotOutcome::Skip { .. }) {
                s.clone()
            } else {
                d.clone()
            };
            bad.outcome = outcome;
            assert!(bad.validate(&set).is_err());
        }
        let mut bad = s.clone();
        bad.after_len += 1;
        assert!(bad.validate(&set).is_err());
        let mut bad = s;
        bad.after_root[0] ^= 1;
        assert!(bad.validate(&set).is_err());
        let mut invalid = set.clone();
        invalid.validators.push(invalid.validators[0].clone());
        assert!(d.validate(&invalid).is_err());
        let empty = ValidatorSet {
            epoch: 2,
            validators: vec![],
        };
        let mut bad = d;
        bad.validator_set_id = empty.id().unwrap();
        assert!(bad.validate(&empty).is_err());
        for n in 1..=4 {
            let mut subset = set.clone();
            subset.validators.truncate(n);
            let mut good = bad.clone();
            good.validator_set_id = subset.id().unwrap();
            good.validate(&subset).unwrap();
            assert!(2 * subset.quorum_size() - n > subset.max_faulty());
        }
    }
}
