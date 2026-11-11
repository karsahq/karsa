//! Quorum evidence that a leader round can never reach a vote quorum.
//!
//! A round can stall for a reason the DAG alone cannot settle: the leader is
//! held, some next-round vertices are missing, and the missing validators may or
//! may not have voted. The direct rule only skips observed non-votes, and the
//! fence rule only frees a leader when every missing voter is fenced. This module
//! adds the third form of evidence: a *round-skip proof* that accounts for every
//! voter.
//!
//! A [`RoundSkip`] names the leader vertex being abandoned. Each signer of a
//! [`NoVoteAttestation`] states that it did not vote for that leader and will
//! not: a validator that already authored a voting vertex must refuse to sign
//! ([`RoundSkip::may_sign`]). [`RoundSkipProof`] partitions the voter set into
//! five disjoint classes:
//!
//! - `votes`: held voting-round vertices that reference the leader;
//! - `non_votes`: held voting-round vertices that do not;
//! - `attestation`: validators without a held voting-round vertex that promise
//!   not to vote;
//! - `fenced_absent`: absent validators covered by a quorum fence;
//! - `missing`: validators with no evidence at all.
//!
//! Every voter must appear in exactly one class. The proof is admissible only
//! when even the unproven voters cannot reach a quorum:
//!
//! ```text
//! votes + fenced_absent + missing + faulty_attesters < quorum_size
//! ```
//!
//! A missing voter can contribute at most one vote, so listing it is enough; the
//! arithmetic never needs to know whether it actually voted. A fenced-absent
//! voter is counted the same way, because its vertex may have arrived before the
//! fence. The fault budget is charged only when an attestation is present: a
//! signer without a held vertex could break its promise, and at most `f` can.
//!
//! Verification resolves every listed vertex through a caller-supplied lookup
//! and treats an unresolvable id as [`RoundSkipError::MissingEvidence`]. A node
//! that holds less history therefore waits for the same vertex instead of
//! accepting a weaker proof. The signing rule is the safety-critical half and
//! lives at the signer, not at the verifier.

use std::collections::BTreeSet;
use std::fmt;

use crypto::domain::{RoundSkipSigningFields, encode_round_skip_signing_payload};
use crypto::encoding::{Decoder, Encoder};
use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};

use crate::certificate::{bit_is_set, bitmap_len, set_bit};
use crate::fence::{FenceCertificate, FenceError};
use crate::schedule::{ValidatorKey, ValidatorRecord, ValidatorSet};
use crate::vertex::{Vertex, VertexId};

/// Canonical round-skip descriptor version.
pub const ROUND_SKIP_VERSION_V1: u16 = 1;
/// Canonical no-vote-attestation version.
pub const NO_VOTE_ATTESTATION_VERSION_V1: u16 = 1;
/// Canonical round-skip-proof version.
pub const ROUND_SKIP_PROOF_VERSION_V1: u16 = 1;

/// The leader slot a no-vote attestation refuses.
///
/// The descriptor pins the exact leader vertex, not only the round: a leader can
/// equivocate inside one round, and an attestation for one digest must not be
/// replayed for another.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundSkip {
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: Vec<u8>,
    /// Leader vertex the signers refuse to vote for.
    pub leader: VertexId,
}

impl RoundSkip {
    /// Creates a descriptor for one leader vertex.
    #[must_use]
    pub fn new(chain_id: impl Into<Vec<u8>>, leader: VertexId) -> Self {
        Self {
            chain_id: chain_id.into(),
            leader,
        }
    }

    /// The leader round being abandoned.
    #[must_use]
    pub fn round(&self) -> u64 {
        self.leader.round
    }

    /// The round whose vertices vote for this leader.
    #[must_use]
    pub fn voting_round(&self) -> u64 {
        self.leader.round.saturating_add(1)
    }

    /// The bytes a signer of the attestation covers.
    ///
    /// # Errors
    ///
    /// [`RoundSkipError::Encoding`] when a field exceeds the encoding limit.
    pub fn signing_payload(&self) -> Result<Vec<u8>, RoundSkipError> {
        encode_round_skip_signing_payload(&RoundSkipSigningFields {
            chain_id: &self.chain_id,
            round: self.leader.round,
            leader_author: &self.leader.author,
            leader_digest: &self.leader.digest,
        })
        .map_err(RoundSkipError::Encoding)
    }

    /// Whether a validator that authored `voting_vertex` may sign this skip.
    ///
    /// `voting_vertex` is the vertex this validator authored in
    /// [`Self::voting_round`], if any. A validator that has not authored one may
    /// sign, but the signature is a promise to author only a non-vote or nothing
    /// for the rest of that round. A validator that authored a vote must not sign:
    /// its vote already exists, so the statement would be false. A validator that
    /// authored a non-vote may sign, because the one-vertex-per-round rule means
    /// it cannot vote later.
    #[must_use]
    pub fn may_sign(&self, voting_vertex: Option<&Vertex>) -> bool {
        match voting_vertex {
            None => true,
            Some(vertex) => {
                vertex.round == self.voting_round()
                    && !vertex
                        .references
                        .iter()
                        .any(|reference| reference == &self.leader)
            }
        }
    }

    /// Writes the canonical descriptor encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::FieldTooLong`] when a field exceeds the encoding limit.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder =
            Encoder::with_capacity(32 + self.chain_id.len() + self.leader.author.len());
        encoder.put_u16(ROUND_SKIP_VERSION_V1);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_u64(self.leader.round);
        encoder.put_bytes(&self.leader.author)?;
        encoder.put_bytes(&self.leader.digest)?;
        Ok(encoder.finish())
    }

    /// Reads a canonical descriptor encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`] or
    /// [`CryptoErrorKind::TrailingBytes`] for a bad buffer, and
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != ROUND_SKIP_VERSION_V1 {
            return Err(codec(format!("unsupported round-skip version {version}")));
        }
        let chain_id = decoder.read_bytes()?.to_vec();
        let round = decoder.read_u64()?;
        let author = decoder.read_bytes()?.to_vec();
        let digest = read_digest(&mut decoder)?;
        decoder.finish()?;
        Ok(Self {
            chain_id,
            leader: VertexId {
                round,
                author,
                digest,
            },
        })
    }
}

/// A set of validators stating that they did not and will not vote for a leader.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoVoteAttestation {
    /// The leader slot the signers refuse.
    pub skip: RoundSkip,
    /// Bitmap of validators that signed, in set order.
    pub signer_bitmap: Vec<u8>,
    /// One signature per set bit.
    pub signatures: Vec<Vec<u8>>,
}

impl NoVoteAttestation {
    /// Number of validators marked as signers.
    #[must_use]
    pub fn signer_count(&self) -> usize {
        self.signer_bitmap
            .iter()
            .map(|byte| byte.count_ones() as usize)
            .sum()
    }

    /// Verifies the chain, the named leader, the shape, and every present
    /// signature, without requiring a quorum.
    ///
    /// `set` must be the voter set for [`RoundSkip::voting_round`]; the signer
    /// keys are resolved at that set's epoch.
    ///
    /// # Errors
    ///
    /// [`RoundSkipError::Mismatch`] for another chain or leader,
    /// [`RoundSkipError::Malformed`] for an inconsistent bitmap, and
    /// [`RoundSkipError::Signer`] for a key that cannot be resolved or a
    /// signature that does not verify.
    pub fn check(
        &self,
        chain_id: &[u8],
        set: &ValidatorSet,
        leader: &VertexId,
    ) -> Result<(), RoundSkipError> {
        if self.skip.chain_id != chain_id {
            return Err(RoundSkipError::Mismatch(
                "the attestation belongs to another chain".to_string(),
            ));
        }
        if &self.skip.leader != leader {
            return Err(RoundSkipError::Mismatch(
                "the attestation names another leader vertex".to_string(),
            ));
        }
        self.check_shape(set)?;
        let payload = self.skip.signing_payload()?;
        for (_, key, signature) in self.resolve_signers(set)? {
            verify_signature(key.algorithm_id, &key.public_key, &payload, signature)
                .map_err(RoundSkipError::Signer)?;
        }
        Ok(())
    }

    /// Verifies the attestation and requires a supermajority of the voter set.
    ///
    /// A quorum of no-vote signatures is by itself enough to prove that no vote
    /// quorum can exist: at most `f` signers may break their promise and at most
    /// `n - quorum` validators did not sign, so at most `2f` votes exist and
    /// `2f < quorum`.
    ///
    /// # Errors
    ///
    /// Every error from [`Self::check`], plus [`RoundSkipError::NoQuorum`] when
    /// the valid signatures are too few.
    pub fn verify(
        &self,
        chain_id: &[u8],
        set: &ValidatorSet,
        leader: &VertexId,
    ) -> Result<(), RoundSkipError> {
        self.check(chain_id, set, leader)?;
        if !set.has_supermajority(self.signer_count()) {
            return Err(RoundSkipError::NoQuorum {
                signers: self.signer_count(),
                required: set.quorum_size(),
            });
        }
        Ok(())
    }

    /// Adds the signatures in `other` to this partial attestation.
    ///
    /// Both sides must describe the same skip. A signer already present is kept.
    /// Returns whether anything was added.
    ///
    /// # Errors
    ///
    /// [`RoundSkipError::Mismatch`] when the attestations describe different
    /// skips, plus every error from [`Self::check`].
    pub fn merge(
        &mut self,
        other: &Self,
        chain_id: &[u8],
        set: &ValidatorSet,
        leader: &VertexId,
    ) -> Result<bool, RoundSkipError> {
        if self.skip != other.skip {
            return Err(RoundSkipError::Mismatch(
                "the attestations describe different skips".to_string(),
            ));
        }
        self.check(chain_id, set, leader)?;
        other.check(chain_id, set, leader)?;

        let mut merged: Vec<(usize, Vec<u8>)> = self
            .shares(set)
            .into_iter()
            .map(|(index, signature)| (index, signature.to_vec()))
            .collect();
        let mut changed = false;
        for (index, signature) in other.shares(set) {
            if merged.iter().any(|(present, _)| *present == index) {
                continue;
            }
            merged.push((index, signature.to_vec()));
            changed = true;
        }
        if !changed {
            return Ok(false);
        }
        merged.sort_unstable_by_key(|(index, _)| *index);

        let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::with_capacity(merged.len());
        for (index, signature) in merged {
            set_bit(&mut bitmap, index);
            signatures.push(signature);
        }
        self.signer_bitmap = bitmap;
        self.signatures = signatures;
        Ok(true)
    }

    /// Writes the canonical attestation encoding.
    ///
    /// # Errors
    ///
    /// Every error from [`RoundSkip::encode`], plus
    /// [`CryptoErrorKind::FieldTooLong`] for an oversized signature count.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let skip = self.skip.encode()?;
        let mut encoder = Encoder::with_capacity(skip.len() + self.signer_bitmap.len() + 64);
        encoder.put_u16(NO_VOTE_ATTESTATION_VERSION_V1);
        encoder.put_bytes(&skip)?;
        encoder.put_bytes(&self.signer_bitmap)?;
        encoder.put_u32(count_field(self.signatures.len(), "signatures")?);
        for signature in &self.signatures {
            encoder.put_bytes(signature)?;
        }
        Ok(encoder.finish())
    }

    /// Reads a canonical attestation encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`], [`CryptoErrorKind::TrailingBytes`],
    /// or [`CryptoErrorKind::MalformedCertificate`] for a bad buffer or an
    /// inconsistent bitmap and signature list, plus every error from
    /// [`RoundSkip::decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != NO_VOTE_ATTESTATION_VERSION_V1 {
            return Err(codec(format!(
                "unsupported no-vote attestation version {version}"
            )));
        }
        let skip = RoundSkip::decode(decoder.read_bytes()?)?;
        let signer_bitmap = decoder.read_bytes()?.to_vec();
        let signature_count = decoder.read_u32()? as usize;
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
        let attestation = Self {
            skip,
            signer_bitmap,
            signatures,
        };
        if attestation.signer_count() != attestation.signatures.len() {
            return Err(codec(format!(
                "bitmap marks {} signers but {} signatures are present",
                attestation.signer_count(),
                attestation.signatures.len()
            )));
        }
        Ok(attestation)
    }

    fn check_shape(&self, set: &ValidatorSet) -> Result<(), RoundSkipError> {
        let signers = self.signer_count();
        if signers != self.signatures.len() {
            return Err(malformed(format!(
                "bitmap marks {signers} signers but {} signatures are present",
                self.signatures.len()
            )));
        }
        let validators = set.validators.len();
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

    fn resolve_signers<'a>(
        &'a self,
        set: &'a ValidatorSet,
    ) -> Result<Vec<SignedEntry<'a>>, RoundSkipError> {
        let mut signers = Vec::with_capacity(self.signatures.len());
        let mut signature_index = 0;
        for (index, record) in set.validators.iter().enumerate() {
            if !bit_is_set(&self.signer_bitmap, index) {
                continue;
            }
            let key = record
                .active_key(set.epoch)
                .map_err(RoundSkipError::Signer)?;
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

    fn shares<'a>(&'a self, set: &'a ValidatorSet) -> Vec<(usize, &'a [u8])> {
        let mut shares = Vec::with_capacity(self.signatures.len());
        let mut signature_index = 0;
        for (index, _) in set.validators.iter().enumerate() {
            if !bit_is_set(&self.signer_bitmap, index) {
                continue;
            }
            let Some(signature) = self.signatures.get(signature_index) else {
                break;
            };
            shares.push((index, signature.as_slice()));
            signature_index += 1;
        }
        shares
    }
}

/// One resolved signer: record, active key, and signature bytes.
type SignedEntry<'a> = (&'a ValidatorRecord, &'a ValidatorKey, &'a [u8]);

/// A partition of the voter set that proves a leader round cannot commit.
///
/// Every validator in the set active at the voting round is accounted for
/// exactly once: a held vote, a held non-vote, an attestation signer, a fenced
/// absent voter, or an explicit missing voter. The proof is admissible when the
/// votes plus the unproven voters stay below the quorum:
///
/// ```text
/// votes + fenced_absent + missing + (faulty attesters) < quorum
/// ```
///
/// The fault budget is charged only when an attestation is present. A missing
/// voter contributes at most one vote, so listing it is enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoundSkipProof {
    /// No-vote promises from validators without a held voting-round vertex. A
    /// partial attestation is valid evidence here; coverage of the whole voter
    /// set is what makes the proof admissible.
    pub attestation: NoVoteAttestation,
    /// Held voting-round vertices that reference the leader.
    pub votes: Vec<VertexId>,
    /// Held voting-round vertices that do not reference the leader.
    pub non_votes: Vec<VertexId>,
    /// Fences covering absent voters at the voting round.
    pub fenced_absent: Vec<FenceCertificate>,
    /// Validators with no evidence. Each is counted as one potential vote.
    pub missing: Vec<Vec<u8>>,
}

impl RoundSkipProof {
    /// Verifies the proof against the voter set active at the voting round.
    ///
    /// `set_for_round` resolves the set a fence was signed against: a fence may
    /// start before an epoch boundary, so its keys come from the set active at
    /// its own round, not from the voter set. `resolve` returns the vertex a
    /// listed id names, if this node holds it; a proof whose evidence is not yet
    /// held is reported as [`RoundSkipError::MissingEvidence`] so the caller can
    /// repair instead of accepting a weaker proof.
    ///
    /// # Errors
    ///
    /// [`RoundSkipError::Mismatch`] for another chain or leader, a fence that
    /// does not cover the voting round, or a listed vertex with the wrong round
    /// or vote status; [`RoundSkipError::Fence`] for an invalid fence;
    /// [`RoundSkipError::Signer`] for an invalid attestation or vertex signature;
    /// [`RoundSkipError::MissingEvidence`] for an unheld listed vertex;
    /// [`RoundSkipError::NotCovered`] or [`RoundSkipError::Overlap`] when the
    /// partition is not exact; and [`RoundSkipError::TooManyVotes`] when the bound
    /// is not below the quorum.
    pub fn verify<F, R>(
        &self,
        chain_id: &[u8],
        voter_set: &ValidatorSet,
        leader: &VertexId,
        set_for_round: F,
        resolve: R,
    ) -> Result<RoundSkipCheck, RoundSkipError>
    where
        F: Fn(u64) -> ValidatorSet,
        R: Fn(&VertexId) -> Option<Vertex>,
    {
        self.attestation.check(chain_id, voter_set, leader)?;
        let voting_round = leader.round.saturating_add(1);

        let mut covered: BTreeSet<Vec<u8>> = BTreeSet::new();
        for (index, record) in voter_set.validators.iter().enumerate() {
            if bit_is_set(&self.attestation.signer_bitmap, index) {
                covered.insert(record.validator_id.clone());
            }
        }

        for vote in &self.votes {
            let author = check_vertex(vote, true, voter_set, leader, voting_round, &resolve)?;
            if !covered.insert(author.clone()) {
                return Err(RoundSkipError::Overlap(author));
            }
        }
        for non_vote in &self.non_votes {
            let author = check_vertex(non_vote, false, voter_set, leader, voting_round, &resolve)?;
            if !covered.insert(author.clone()) {
                return Err(RoundSkipError::Overlap(author));
            }
        }

        if self.fenced_absent.len() > voter_set.max_faulty() {
            return Err(RoundSkipError::TooManyFences {
                count: self.fenced_absent.len(),
                limit: voter_set.max_faulty(),
            });
        }
        for certificate in &self.fenced_absent {
            if certificate.fence.from_round > voting_round {
                return Err(RoundSkipError::Mismatch(format!(
                    "a fence starts at round {} after the voting round {voting_round}",
                    certificate.fence.from_round
                )));
            }
            if voter_set
                .validator(&certificate.fence.validator_id)
                .is_none()
            {
                return Err(RoundSkipError::Mismatch(
                    "a fenced validator is outside the voter set".to_string(),
                ));
            }
            certificate
                .verify(chain_id, &set_for_round(certificate.fence.from_round))
                .map_err(RoundSkipError::Fence)?;
            if !covered.insert(certificate.fence.validator_id.clone()) {
                return Err(RoundSkipError::Overlap(
                    certificate.fence.validator_id.clone(),
                ));
            }
        }

        for validator in &self.missing {
            if voter_set.validator(validator).is_none() {
                return Err(RoundSkipError::Mismatch(
                    "a missing validator is outside the voter set".to_string(),
                ));
            }
            if !covered.insert(validator.clone()) {
                return Err(RoundSkipError::Overlap(validator.clone()));
            }
        }

        for record in &voter_set.validators {
            if !covered.contains(&record.validator_id) {
                return Err(RoundSkipError::NotCovered(record.validator_id.clone()));
            }
        }

        let attester_liars = if self.attestation.signer_count() > 0 {
            voter_set.max_faulty()
        } else {
            0
        };
        let possible_votes = self
            .votes
            .len()
            .saturating_add(self.fenced_absent.len())
            .saturating_add(self.missing.len())
            .saturating_add(attester_liars);
        let quorum = voter_set.quorum_size();
        if possible_votes >= quorum {
            return Err(RoundSkipError::TooManyVotes {
                possible: possible_votes,
                quorum,
            });
        }
        Ok(RoundSkipCheck {
            attested: self.attestation.signer_count(),
            votes: self.votes.len(),
            non_votes: self.non_votes.len(),
            fenced_absent: self.fenced_absent.len(),
            missing: self.missing.len(),
            possible_votes,
            quorum,
        })
    }

    /// Writes the canonical proof encoding.
    ///
    /// # Errors
    ///
    /// Every error from [`NoVoteAttestation::encode`] or
    /// [`FenceCertificate::encode`], plus [`CryptoErrorKind::FieldTooLong`] for
    /// an oversized list count.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let attestation = self.attestation.encode()?;
        let mut encoder = Encoder::with_capacity(
            attestation.len()
                + (self.votes.len() + self.non_votes.len()) * 48
                + self.fenced_absent.len() * 128
                + self.missing.len() * 16,
        );
        encoder.put_u16(ROUND_SKIP_PROOF_VERSION_V1);
        encoder.put_bytes(&attestation)?;
        put_vertices(&mut encoder, &self.votes)?;
        put_vertices(&mut encoder, &self.non_votes)?;
        encoder.put_u32(count_field(self.fenced_absent.len(), "fences")?);
        for certificate in &self.fenced_absent {
            encoder.put_bytes(&certificate.encode()?)?;
        }
        encoder.put_u32(count_field(self.missing.len(), "missing")?);
        for validator in &self.missing {
            encoder.put_bytes(validator)?;
        }
        Ok(encoder.finish())
    }

    /// Reads a canonical proof encoding.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::TruncatedInput`], [`CryptoErrorKind::TrailingBytes`],
    /// or [`CryptoErrorKind::MalformedCertificate`] for a bad buffer, plus every
    /// error from [`NoVoteAttestation::decode`] or [`FenceCertificate::decode`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != ROUND_SKIP_PROOF_VERSION_V1 {
            return Err(codec(format!(
                "unsupported round-skip proof version {version}"
            )));
        }
        let attestation = NoVoteAttestation::decode(decoder.read_bytes()?)?;
        let votes = read_vertices(&mut decoder, bytes.len())?;
        let non_votes = read_vertices(&mut decoder, bytes.len())?;
        let fence_count = decoder.read_u32()? as usize;
        if fence_count > bytes.len() / 4 {
            return Err(codec(format!(
                "{fence_count} fences exceed the {} byte payload",
                bytes.len()
            )));
        }
        let mut fenced_absent = Vec::with_capacity(fence_count.min(1024));
        for _ in 0..fence_count {
            fenced_absent.push(FenceCertificate::decode(decoder.read_bytes()?)?);
        }
        let missing_count = decoder.read_u32()? as usize;
        if missing_count > bytes.len() / 4 {
            return Err(codec(format!(
                "{missing_count} missing validators exceed the {} byte payload",
                bytes.len()
            )));
        }
        let mut missing = Vec::with_capacity(missing_count.min(1024));
        for _ in 0..missing_count {
            missing.push(decoder.read_bytes()?.to_vec());
        }
        decoder.finish()?;
        Ok(Self {
            attestation,
            votes,
            non_votes,
            fenced_absent,
            missing,
        })
    }
}

/// How much evidence a verified proof used.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RoundSkipCheck {
    /// Validators that signed the no-vote attestation.
    pub attested: usize,
    /// Held votes listed by the proof.
    pub votes: usize,
    /// Held non-votes listed by the proof.
    pub non_votes: usize,
    /// Absent voters covered by a fence.
    pub fenced_absent: usize,
    /// Voters with no evidence, each counted as one potential vote.
    pub missing: usize,
    /// Upper bound on votes after the fault budget is charged.
    pub possible_votes: usize,
    /// Votes needed to commit the leader.
    pub quorum: usize,
}

/// A round-skip descriptor, attestation, or proof that does not verify.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoundSkipError {
    /// A field could not be encoded or a vertex id could not be recomputed.
    Encoding(CryptoError),
    /// A signer's key could not be resolved or its signature did not verify.
    Signer(CryptoError),
    /// A carried fence certificate does not verify.
    Fence(FenceError),
    /// The bitmap, signature list, or vertex list is inconsistent.
    Malformed(String),
    /// The evidence does not describe this chain, this leader, or this round.
    Mismatch(String),
    /// A listed evidence vertex is not held by this node.
    MissingEvidence(VertexId),
    /// Fewer than a supermajority signed a standalone attestation.
    NoQuorum {
        /// Distinct validators that signed.
        signers: usize,
        /// Smallest signer count that is a supermajority.
        required: usize,
    },
    /// A voter is in none of the evidence classes.
    NotCovered(Vec<u8>),
    /// A voter is in more than one evidence class.
    Overlap(Vec<u8>),
    /// Even the unproven voters cannot be ruled out below the quorum.
    TooManyVotes {
        /// Upper bound on the votes that could exist.
        possible: usize,
        /// Votes needed to commit the leader.
        quorum: usize,
    },
    /// More absent voters are fenced than the set's fault budget allows.
    TooManyFences {
        /// Fences present in the proof.
        count: usize,
        /// Largest supportable fence count.
        limit: usize,
    },
}

impl fmt::Display for RoundSkipError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encoding(error) => write!(f, "round-skip encoding: {error}"),
            Self::Signer(error) => write!(f, "round-skip signer: {error}"),
            Self::Fence(error) => write!(f, "round-skip fence: {error}"),
            Self::Malformed(detail) => write!(f, "malformed round-skip evidence: {detail}"),
            Self::Mismatch(detail) => write!(f, "round-skip mismatch: {detail}"),
            Self::MissingEvidence(id) => write!(
                f,
                "round-skip evidence vertex {} at round {} is not held",
                hex(&id.author),
                id.round
            ),
            Self::NoQuorum { signers, required } => {
                write!(f, "{signers} validators signed; {required} required")
            }
            Self::NotCovered(validator) => {
                write!(
                    f,
                    "validator {} is not covered by the proof",
                    hex(validator)
                )
            }
            Self::Overlap(validator) => {
                write!(
                    f,
                    "validator {} appears in two evidence classes",
                    hex(validator)
                )
            }
            Self::TooManyVotes { possible, quorum } => {
                write!(
                    f,
                    "{possible} possible votes are not below the quorum {quorum}"
                )
            }
            Self::TooManyFences { count, limit } => {
                write!(
                    f,
                    "{count} fenced absent voters exceed the fault budget {limit}"
                )
            }
        }
    }
}

impl std::error::Error for RoundSkipError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Encoding(error) | Self::Signer(error) => Some(error),
            Self::Fence(error) => Some(error),
            Self::Malformed(_)
            | Self::Mismatch(_)
            | Self::MissingEvidence(_)
            | Self::NoQuorum { .. }
            | Self::NotCovered(_)
            | Self::Overlap(_)
            | Self::TooManyVotes { .. }
            | Self::TooManyFences { .. } => None,
        }
    }
}

fn check_vertex<R>(
    id: &VertexId,
    should_vote: bool,
    voter_set: &ValidatorSet,
    leader: &VertexId,
    voting_round: u64,
    resolve: &R,
) -> Result<Vec<u8>, RoundSkipError>
where
    R: Fn(&VertexId) -> Option<Vertex>,
{
    let vertex = resolve(id).ok_or_else(|| RoundSkipError::MissingEvidence(id.clone()))?;
    if vertex.id().map_err(RoundSkipError::Encoding)? != *id {
        return Err(RoundSkipError::Mismatch(
            "a listed vertex does not hash to its id".to_string(),
        ));
    }
    if vertex.round != voting_round {
        return Err(RoundSkipError::Mismatch(format!(
            "a listed vertex is at round {}, not {voting_round}",
            vertex.round
        )));
    }
    if voter_set.validator(&vertex.author).is_none() {
        return Err(RoundSkipError::Mismatch(
            "a listed vertex belongs to a validator outside the voter set".to_string(),
        ));
    }
    vertex
        .verify(voter_set, voter_set.epoch)
        .map_err(RoundSkipError::Signer)?;
    let votes = vertex
        .references
        .iter()
        .any(|reference| reference == leader);
    if votes != should_vote {
        return Err(RoundSkipError::Mismatch(format!(
            "a listed {} vertex has the opposite vote status",
            if should_vote { "vote" } else { "non-vote" }
        )));
    }
    Ok(vertex.author)
}

fn put_vertices(encoder: &mut Encoder, vertices: &[VertexId]) -> Result<(), CryptoError> {
    encoder.put_u32(count_field(vertices.len(), "vertices")?);
    for vertex in vertices {
        encoder.put_u64(vertex.round);
        encoder.put_bytes(&vertex.author)?;
        encoder.put_bytes(&vertex.digest)?;
    }
    Ok(())
}

fn read_vertices(
    decoder: &mut Decoder<'_>,
    payload_len: usize,
) -> Result<Vec<VertexId>, CryptoError> {
    let count = decoder.read_u32()? as usize;
    if count > payload_len / 4 {
        return Err(codec(format!(
            "{count} vertices exceed the {payload_len} byte payload"
        )));
    }
    let mut vertices = Vec::with_capacity(count.min(1024));
    for _ in 0..count {
        let round = decoder.read_u64()?;
        let author = decoder.read_bytes()?.to_vec();
        let digest = read_digest(decoder)?;
        vertices.push(VertexId {
            round,
            author,
            digest,
        });
    }
    Ok(vertices)
}

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

fn malformed(detail: impl Into<String>) -> RoundSkipError {
    RoundSkipError::Malformed(detail.into())
}

fn codec(detail: impl Into<String>) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, detail)
}

fn count_field(count: usize, what: &str) -> Result<u32, CryptoError> {
    u32::try_from(count).map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            format!("{what} count does not fit a u32"),
        )
    })
}

fn read_digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], CryptoError> {
    let bytes = decoder.read_bytes()?;
    bytes
        .try_into()
        .map_err(|_| codec(format!("digest of {} bytes, expected 32", bytes.len())))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use crate::fence::Fence;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const CHAIN: &[u8] = b"karsa-round-skip-1";
    const LEADER_ROUND: u64 = 73;
    const EPOCH: u64 = 1;

    struct Signer {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn signer(index: usize) -> Signer {
        let seed = [u8::try_from(index + 1).expect("fewer than 255 signers"); 32];
        let public_key = Ed25519Scheme::public_key_from_seed(&seed).expect("a seed is a key");
        let mut private_key = seed.to_vec();
        private_key.extend_from_slice(&public_key);
        Signer {
            public_key: public_key.to_vec(),
            private_key,
        }
    }

    fn fixture(count: usize) -> (ValidatorSet, Vec<Signer>) {
        let signers: Vec<Signer> = (0..count).map(signer).collect();
        let validators = signers
            .iter()
            .enumerate()
            .map(|(index, signer)| ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: signer.public_key.clone(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            })
            .collect();
        let set = ValidatorSet {
            epoch: EPOCH,
            validators,
        };
        set.validate().expect("the fixture set is valid");
        (set, signers)
    }

    fn leader() -> VertexId {
        VertexId {
            round: LEADER_ROUND,
            author: b"val-3".to_vec(),
            digest: [7u8; 32],
        }
    }

    fn skip() -> RoundSkip {
        RoundSkip::new(CHAIN.to_vec(), leader())
    }

    fn vertex(
        set: &ValidatorSet,
        signers: &[Signer],
        author: usize,
        round: u64,
        references: Vec<VertexId>,
    ) -> Vertex {
        let mut vertex = Vertex {
            chain_id: CHAIN.to_vec(),
            epoch: set.epoch,
            round,
            author: format!("val-{author}").into_bytes(),
            payload_hash: [u8::try_from(author + 1).expect("fewer than 255 authors"); 32],
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload().unwrap();
        vertex.signature = Ed25519Scheme
            .sign(&signers[author].private_key, &payload)
            .unwrap();
        vertex
    }

    fn vote_vertex(set: &ValidatorSet, signers: &[Signer], author: usize) -> Vertex {
        vertex(set, signers, author, LEADER_ROUND + 1, vec![leader()])
    }

    fn non_vote_vertex(set: &ValidatorSet, signers: &[Signer], author: usize) -> Vertex {
        vertex(set, signers, author, LEADER_ROUND + 1, Vec::new())
    }

    fn attestation(set: &ValidatorSet, signers: &[Signer], signed: &[usize]) -> NoVoteAttestation {
        let skip = skip();
        let payload = skip.signing_payload().unwrap();
        let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::with_capacity(signed.len());
        for index in signed {
            set_bit(&mut bitmap, *index);
            signatures.push(
                Ed25519Scheme
                    .sign(&signers[*index].private_key, &payload)
                    .expect("the fixture key signs"),
            );
        }
        NoVoteAttestation {
            skip,
            signer_bitmap: bitmap,
            signatures,
        }
    }

    fn fence(
        set: &ValidatorSet,
        signers: &[Signer],
        from_round: u64,
        validator: &[u8],
    ) -> FenceCertificate {
        let fence = Fence::new(CHAIN.to_vec(), from_round, validator.to_vec());
        let payload = fence.signing_payload().unwrap();
        let mut bitmap = vec![0u8; bitmap_len(set.validators.len())];
        let mut signatures = Vec::with_capacity(set.quorum_size());
        for (index, signer) in signers
            .iter()
            .enumerate()
            .filter(|(index, _)| set.validators[*index].validator_id != validator)
            .take(set.quorum_size())
        {
            set_bit(&mut bitmap, index);
            signatures.push(
                Ed25519Scheme
                    .sign(&signer.private_key, &payload)
                    .expect("the fixture key signs"),
            );
        }
        FenceCertificate {
            fence,
            signer_bitmap: bitmap,
            signatures,
        }
    }

    struct Fixture {
        set: ValidatorSet,
        signers: Vec<Signer>,
        vertices: Vec<Vertex>,
    }

    impl Fixture {
        fn new(count: usize) -> Self {
            let (set, signers) = fixture(count);
            let vertices = signers
                .iter()
                .enumerate()
                .map(|(index, _)| vote_vertex(&set, &signers, index))
                .collect();
            Self {
                set,
                signers,
                vertices,
            }
        }

        fn replace(&mut self, vertex: Vertex) {
            let author = &vertex.author;
            let slot = self
                .vertices
                .iter_mut()
                .find(|held| held.author == *author)
                .expect("every fixture author has a slot");
            *slot = vertex;
        }

        fn forget(&mut self, index: usize) {
            self.vertices.remove(index);
        }

        fn make_non_vote(&mut self, index: usize) {
            let vertex = non_vote_vertex(&self.set, &self.signers, index);
            self.replace(vertex);
        }

        fn lookup(&self) -> HashMap<VertexId, Vertex> {
            self.vertices
                .iter()
                .map(|vertex| (vertex.id().unwrap(), vertex.clone()))
                .collect()
        }

        fn proof(
            &self,
            id: &[usize],
            votes: &[usize],
            non_votes: &[usize],
            applied: &[FenceCertificate],
            missing: &[usize],
        ) -> RoundSkipProof {
            let held = self.lookup();
            let ids = |indices: &[usize]| -> Vec<VertexId> {
                indices
                    .iter()
                    .map(|index| {
                        let id = self.vertices[*index].id().unwrap();
                        assert!(held.contains_key(&id));
                        id
                    })
                    .collect()
            };
            RoundSkipProof {
                attestation: attestation(&self.set, &self.signers, id),
                votes: ids(votes),
                non_votes: ids(non_votes),
                fenced_absent: applied.to_vec(),
                missing: missing
                    .iter()
                    .map(|index| self.set.validators[*index].validator_id.clone())
                    .collect(),
            }
        }

        fn verify(&self, proof: &RoundSkipProof) -> Result<RoundSkipCheck, RoundSkipError> {
            let held = self.lookup();
            proof.verify(
                CHAIN,
                &self.set,
                &leader(),
                |_| self.set.clone(),
                |id| held.get(id).cloned(),
            )
        }
    }

    #[test]
    fn a_quorum_no_vote_attestation_verifies() {
        let (set, signers) = fixture(5);
        // A supermajority of five is four.
        let attestation = attestation(&set, &signers, &[0, 1, 2, 3]);
        attestation
            .verify(CHAIN, &set, &leader())
            .expect("four of five is a quorum");
    }

    #[test]
    fn fewer_than_a_quorum_is_rejected() {
        let (set, signers) = fixture(5);
        let attestation = attestation(&set, &signers, &[0, 1, 2]);
        let error = attestation.verify(CHAIN, &set, &leader()).unwrap_err();
        assert!(matches!(
            error,
            RoundSkipError::NoQuorum {
                signers: 3,
                required: 4
            }
        ));
    }

    #[test]
    fn an_attestation_for_another_chain_or_leader_is_rejected() {
        let (set, signers) = fixture(5);
        let attestation = attestation(&set, &signers, &[0, 1, 2, 3]);
        assert!(matches!(
            attestation.verify(b"another-chain", &set, &leader()),
            Err(RoundSkipError::Mismatch(_))
        ));

        let mut other_leader = leader();
        other_leader.digest = [8u8; 32];
        assert!(matches!(
            attestation.verify(CHAIN, &set, &other_leader),
            Err(RoundSkipError::Mismatch(_))
        ));
    }

    #[test]
    fn partial_attestations_merge_until_the_quorum_is_reached() {
        let (set, signers) = fixture(5);
        let payload = skip().signing_payload().unwrap();
        let share = |index: usize| {
            let mut partial = NoVoteAttestation {
                skip: skip(),
                signer_bitmap: vec![0u8; bitmap_len(set.validators.len())],
                signatures: Vec::new(),
            };
            set_bit(&mut partial.signer_bitmap, index);
            partial.signatures.push(
                Ed25519Scheme
                    .sign(&signers[index].private_key, &payload)
                    .unwrap(),
            );
            partial
        };

        let mut merged = share(0);
        assert!(merged.merge(&share(1), CHAIN, &set, &leader()).unwrap());
        assert!(merged.merge(&share(2), CHAIN, &set, &leader()).unwrap());
        assert!(!merged.merge(&share(0), CHAIN, &set, &leader()).unwrap());
        assert!(matches!(
            merged.verify(CHAIN, &set, &leader()),
            Err(RoundSkipError::NoQuorum { signers: 3, .. })
        ));
        assert!(merged.merge(&share(3), CHAIN, &set, &leader()).unwrap());
        merged
            .verify(CHAIN, &set, &leader())
            .expect("four of five is a quorum");
    }

    #[test]
    fn an_attestation_roundtrips() {
        let (set, signers) = fixture(5);
        let attestation = attestation(&set, &signers, &[0, 1, 2, 3]);
        let encoded = attestation.encode().unwrap();
        let decoded = NoVoteAttestation::decode(&encoded).unwrap();
        assert_eq!(decoded, attestation);
        decoded.verify(CHAIN, &set, &leader()).unwrap();
    }

    #[test]
    fn a_validator_that_already_voted_may_not_sign() {
        let mut fixture = Fixture::new(2);
        let skip = RoundSkip::new(CHAIN.to_vec(), leader());
        let voting = fixture.vertices[0].clone();
        assert!(!skip.may_sign(Some(&voting)));

        fixture.replace(non_vote_vertex(&fixture.set, &fixture.signers, 0));
        assert!(skip.may_sign(Some(&fixture.vertices[0])));

        // A validator that has not authored its voting vertex yet may sign, but
        // the signature becomes its promise not to vote.
        assert!(skip.may_sign(None));
    }

    #[test]
    fn a_covered_proof_counts_a_missing_voter_as_a_potential_vote() {
        let mut fixture = Fixture::new(5);
        // Two votes, two held non-votes, and one voter with no vertex. The held
        // non-votes are evidence, so no fault budget is charged; the missing
        // voter is one possible vote and the bound is 2 + 1 < 4.
        fixture.replace(non_vote_vertex(&fixture.set, &fixture.signers, 0));
        fixture.replace(non_vote_vertex(&fixture.set, &fixture.signers, 1));
        fixture.forget(4);
        let proof = fixture.proof(&[], &[2, 3], &[0, 1], &[], &[4]);
        let check = fixture
            .verify(&proof)
            .expect("the round cannot reach a quorum");
        assert_eq!(
            check,
            RoundSkipCheck {
                attested: 0,
                votes: 2,
                non_votes: 2,
                fenced_absent: 0,
                missing: 1,
                possible_votes: 3,
                quorum: 4,
            }
        );
    }

    #[test]
    fn an_attestation_is_charged_the_fault_budget() {
        let fixture = Fixture::new(5);
        // Three votes plus two promises: without the fault budget the bound is
        // 3 < 4, but a lying signer could reach the quorum of four.
        let proof = fixture.proof(&[0, 1], &[2, 3, 4], &[], &[], &[]);
        let error = fixture.verify(&proof).unwrap_err();
        assert!(matches!(
            error,
            RoundSkipError::TooManyVotes {
                possible: 4,
                quorum: 4
            }
        ));
    }

    #[test]
    fn a_proof_with_an_uncovered_voter_is_rejected() {
        let mut fixture = Fixture::new(5);
        fixture.make_non_vote(0);
        fixture.make_non_vote(1);
        let proof = fixture.proof(&[], &[2, 3], &[0, 1], &[], &[]);
        let error = fixture.verify(&proof).unwrap_err();
        assert_eq!(error, RoundSkipError::NotCovered(b"val-4".to_vec()));
    }

    #[test]
    fn a_voter_cannot_be_both_attesting_and_voting() {
        let fixture = Fixture::new(5);
        // val-2 signs the attestation and is also listed as a vote.
        let proof = fixture.proof(&[0, 1, 2], &[2, 3], &[], &[], &[4]);
        let error = fixture.verify(&proof).unwrap_err();
        assert_eq!(error, RoundSkipError::Overlap(b"val-2".to_vec()));
    }

    #[test]
    fn too_many_unproven_voters_are_rejected() {
        let mut fixture = Fixture::new(5);
        fixture.make_non_vote(0);
        // Two votes plus two missing voters reach the quorum of four.
        let proof = fixture.proof(&[], &[2, 3], &[0], &[], &[1, 4]);
        let error = fixture.verify(&proof).unwrap_err();
        assert!(matches!(
            error,
            RoundSkipError::TooManyVotes {
                possible: 4,
                quorum: 4
            }
        ));
    }

    #[test]
    fn a_listed_vertex_must_be_held_and_have_the_claimed_status() {
        let mut fixture = Fixture::new(5);
        for index in [0, 1, 3, 4] {
            fixture.make_non_vote(index);
        }
        // val-2 is listed as a vote and the other four as non-votes.
        let proof = fixture.proof(&[], &[2], &[0, 1, 3, 4], &[], &[]);
        let mut broken = proof.clone();
        broken.non_votes.push(fixture.vertices[2].id().unwrap());
        let error = fixture.verify(&broken).unwrap_err();
        assert!(matches!(error, RoundSkipError::Mismatch(_)));

        // A listed id this node does not hold is repair work, not a skip.
        let mut absent = proof;
        absent.votes[0].digest = [9u8; 32];
        assert!(matches!(
            fixture.verify(&absent),
            Err(RoundSkipError::MissingEvidence(_))
        ));
    }

    #[test]
    fn a_fence_that_starts_after_the_voting_round_does_not_cover_it() {
        let fixture = Fixture::new(5);
        let mut proof = fixture.proof(&[], &[2, 3], &[0, 1], &[], &[]);
        let validator = fixture.set.validators[4].validator_id.clone();
        proof.fenced_absent.push(fence(
            &fixture.set,
            &fixture.signers,
            LEADER_ROUND + 2,
            &validator,
        ));
        let error = fixture.verify(&proof).unwrap_err();
        assert!(matches!(error, RoundSkipError::Mismatch(_)));
    }

    #[test]
    fn a_proof_roundtrips() {
        let mut fixture = Fixture::new(5);
        fixture.replace(non_vote_vertex(&fixture.set, &fixture.signers, 0));
        fixture.replace(non_vote_vertex(&fixture.set, &fixture.signers, 1));
        fixture.forget(4);
        let proof = fixture.proof(&[], &[2, 3], &[0, 1], &[], &[4]);
        let encoded = proof.encode().unwrap();
        let decoded = RoundSkipProof::decode(&encoded).unwrap();
        assert_eq!(decoded, proof);
        fixture
            .verify(&decoded)
            .expect("the decoded proof still verifies");
    }
}
