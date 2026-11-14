//! Inactive, nonnil proposal → prevote QC → precommit QC carrier evidence.
//!
//! Aggregate and individual-vote APIs are separate; neither proves POL-backed
//! view proposals. These inactive inspectors must not be used to activate agreement.
//! Proposal authorization (including any view leader policy) remains a trusted
//! caller responsibility; DAG authorship does not establish that policy.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::slot_agreement::{AgreementPhase, AgreementQc, AgreementValue, AgreementVote};
use crate::{SlotDecisionTip, SlotProposal, ValidatorSet, ValidatorSignature, VertexId};

/// Independent canonical phase-chain storage version.
pub const SLOT_AGREEMENT_PHASE_VERSION_V1: u16 = 1;
/// Domain for phase-chain payload hashes, never used for vote signatures.
pub const SLOT_AGREEMENT_PHASE_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_AGREEMENT_PHASE/v1";
const PREVOTE: u8 = 0;
const FINAL: u8 = 1;
const MAX_AUTHOR: usize = 1024;
const VOTE: u8 = 2;
const STRONG_PREVOTE: u8 = 3;
const STRONG_FINAL: u8 = 4;
const MAX_WITNESSES: usize = 4096;
/// Total reference/vertex visits allowed across all strong-inspector cone walks.
/// Repeated visits, including shared ancestors across witnesses, consume work.
/// Exhaustion rejects evidence; it never truncates or trusts an unchecked cone.
pub const SLOT_AGREEMENT_PHASE_WORK_BUDGET: usize = 100_000;

pub(crate) fn invalid(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

fn bound(size: usize) -> Result<(), CryptoError> {
    if size > MAX_FIELD_LEN {
        return Err(invalid("agreement phase payload exceeds one MiB"));
    }
    Ok(())
}

/// Exact direct proposal evidence and its nonnil prevote quorum.
///
/// This is a distinct payload, not a legacy/final certificate. Its signed DAG
/// carrier must follow the proposal carrier. It does not claim vote-carrier proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementPrevotePayload {
    /// Direct-rule proposal and exact signed carrier.
    pub proposal: crate::SlotProposal,
    /// Carrier binding the direct proposal digest (not a view proposal).
    pub proposal_carrier: VertexId,
    /// Nonnil prevote QC for that exact decision and fixed-slot context.
    pub certificate: AgreementQc,
}

impl SlotAgreementPrevotePayload {
    fn check(&self) -> Result<(), CryptoError> {
        if self.certificate.vote.phase != AgreementPhase::Prevote
            || self.certificate.vote.value
                != AgreementValue::Decision(self.proposal.decision.clone())
            || self.proposal_carrier.author.len() > MAX_AUTHOR
        {
            return Err(invalid(
                "expected bounded nonnil prevote QC for exact proposal",
            ));
        }
        Ok(())
    }

    /// Encodes bounded canonical bytes; authenticates neither evidence nor context.
    ///
    /// # Errors
    /// Rejects wrong phase, nil/mismatched decisions and nested or total bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        self.check()?;
        let proposal = self.proposal.encode()?;
        let certificate = self.certificate.encode(set)?;
        let size = 3
            + 4
            + proposal.len()
            + 8
            + 4
            + self.proposal_carrier.author.len()
            + 36
            + 4
            + certificate.len();
        bound(size)?;
        let mut e = Encoder::with_capacity(size);
        e.put_u16(SLOT_AGREEMENT_PHASE_VERSION_V1);
        e.put_u8(PREVOTE);
        e.put_bytes(&proposal)?;
        e.put_u64(self.proposal_carrier.round);
        e.put_bytes(&self.proposal_carrier.author)?;
        e.put_bytes(&self.proposal_carrier.digest)?;
        e.put_bytes(&certificate)?;
        Ok(e.finish())
    }

    /// Decodes untrusted canonical evidence without authenticating signatures.
    ///
    /// # Errors
    /// Rejects unknown tags, bounds, truncation, trailing bytes and nested errors.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        bound(bytes.len())?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != SLOT_AGREEMENT_PHASE_VERSION_V1 || d.read_u8()? != PREVOTE {
            return Err(invalid("unknown agreement phase version or kind"));
        }
        let proposal = d.read_bytes()?;
        let round = d.read_u64()?;
        let author = d.read_bytes()?;
        if author.len() > MAX_AUTHOR {
            return Err(invalid("agreement phase carrier author exceeds bound"));
        }
        let digest = d
            .read_bytes()?
            .try_into()
            .map_err(|_| invalid("expected 32-byte phase carrier digest"))?;
        let certificate = d.read_bytes()?;
        d.finish()?;
        let p = Self {
            proposal: SlotProposal::decode(proposal)?,
            proposal_carrier: VertexId {
                round,
                author: author.to_vec(),
                digest,
            },
            certificate: AgreementQc::decode(certificate, set)?,
        };
        p.check()?;
        Ok(p)
    }

    /// Hashes canonical bytes in the independent phase domain.
    ///
    /// # Errors
    /// Propagates encoding errors; no signature verification is performed.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        digest(&self.encode(set)?)
    }
}

/// Fixed-depth evidence for proposal → prevote QC → final precommit QC.
///
/// The final carrier binds this complete body; the intermediate carrier binds
/// `prevote.digest(set)`. There are exactly three named carriers, no arbitrary
/// control list and no recursive proof objects. Nested QCs each cap signers at 4096.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementPhaseChain {
    /// Intermediate proposal/prevote payload.
    pub prevote: SlotAgreementPrevotePayload,
    /// Exact retained signed carrier binding the intermediate payload.
    pub prevote_carrier: VertexId,
    /// Same-context, same-view, same-value final precommit quorum.
    pub certificate: AgreementQc,
}

impl SlotAgreementPhaseChain {
    fn check(&self) -> Result<(), CryptoError> {
        check_chain(&self.prevote, &self.prevote_carrier, &self.certificate)
    }

    /// Encodes at most one MiB of canonical, unauthenticated phase evidence.
    ///
    /// # Errors
    /// Rejects semantic statement mismatches, nested errors and aggregate bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        self.check()?;
        let prevote = self.prevote.encode(set)?;
        let certificate = self.certificate.encode(set)?;
        let size = 3
            + 4
            + prevote.len()
            + 8
            + 4
            + self.prevote_carrier.author.len()
            + 36
            + 4
            + certificate.len();
        bound(size)?;
        let mut e = Encoder::with_capacity(size);
        e.put_u16(SLOT_AGREEMENT_PHASE_VERSION_V1);
        e.put_u8(FINAL);
        e.put_bytes(&prevote)?;
        e.put_u64(self.prevote_carrier.round);
        e.put_bytes(&self.prevote_carrier.author)?;
        e.put_bytes(&self.prevote_carrier.digest)?;
        e.put_bytes(&certificate)?;
        Ok(e.finish())
    }

    /// Decodes untrusted evidence, preflighting the entire outer envelope first.
    ///
    /// # Errors
    /// Rejects malformed/noncanonical bodies, bounds, tags and statement mismatches.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        bound(bytes.len())?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != SLOT_AGREEMENT_PHASE_VERSION_V1 || d.read_u8()? != FINAL {
            return Err(invalid("unknown agreement phase version or kind"));
        }
        let prevote = d.read_bytes()?;
        let round = d.read_u64()?;
        let author = d.read_bytes()?;
        if author.len() > MAX_AUTHOR {
            return Err(invalid("agreement phase carrier author exceeds bound"));
        }
        let digest = d
            .read_bytes()?
            .try_into()
            .map_err(|_| invalid("expected 32-byte phase carrier digest"))?;
        let certificate = d.read_bytes()?;
        d.finish()?;
        let p = Self {
            prevote: SlotAgreementPrevotePayload::decode(prevote, set)?,
            prevote_carrier: VertexId {
                round,
                author: author.to_vec(),
                digest,
            },
            certificate: AgreementQc::decode(certificate, set)?,
        };
        p.check()?;
        Ok(p)
    }

    /// Hashes the complete final body, including exact intermediate evidence/carrier.
    ///
    /// # Errors
    /// Propagates encoding errors; does not authenticate any signatures.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        digest(&self.encode(set)?)
    }
}

/// One nonnil agreement signature and its exact causal prerequisite.
///
/// Prevotes reference the direct proposal carrier; precommits reference the strong
/// prevote-QC carrier. This payload does not authorize a proposer or prove a POL.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementVotePayload {
    /// Complete signed statement, including fixed-slot context, phase and view.
    pub vote: AgreementVote,
    /// Exactly one validator signature over `vote.signing_payload(set)`.
    pub signature: ValidatorSignature,
    /// Exact earlier carrier required by this phase.
    pub prerequisite: VertexId,
}

impl SlotAgreementVotePayload {
    /// Encodes canonical storage bytes, not vote signing bytes.
    ///
    /// # Errors
    /// Rejects nil, malformed statements/identifiers and total size over one MiB.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        if matches!(self.vote.value, AgreementValue::Nil) {
            return Err(invalid("individual carrier requires nonnil vote"));
        }
        // Bound opaque signature bytes before cloning the single-signature QC body.
        if self.signature.validator_id.len() > MAX_AUTHOR
            || self.signature.key_id.len() > MAX_AUTHOR
        {
            return Err(invalid("individual vote identifier exceeds bound"));
        }
        bound(self.signature.signature.len())?;
        let qc = AgreementQc {
            vote: self.vote.clone(),
            signatures: vec![self.signature.clone()],
        }
        .encode(set)?;
        let mut e = start(VOTE);
        put_id(&mut e, &self.prerequisite)?;
        put_bounded(&mut e, &qc)?;
        Ok(e.finish())
    }

    /// Decodes one canonical, unauthenticated vote carrier payload.
    ///
    /// # Errors
    /// Rejects bounds, unknown tags, nil, extra signatures and malformed bodies.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        let mut d = decoder(bytes, VOTE)?;
        let prerequisite = read_id(&mut d)?;
        let qc = d.read_bytes()?;
        d.finish()?;
        let mut qc = AgreementQc::decode(qc, set)?;
        if qc.signatures.len() != 1 || matches!(qc.vote.value, AgreementValue::Nil) {
            return Err(invalid("individual carrier requires one nonnil signature"));
        }
        Ok(Self {
            vote: qc.vote,
            signature: qc.signatures.remove(0),
            prerequisite,
        })
    }

    /// Authenticates one nonnil statement against a pinned context and set.
    ///
    /// # Errors
    /// Rejects bounds, context mismatch, unknown/inactive signer or bad signature.
    pub fn verify(&self, context: &SlotDecisionTip, set: &ValidatorSet) -> Result<(), CryptoError> {
        self.encode(set)?;
        if self.vote.context != *context {
            return Err(invalid("individual vote context mismatch"));
        }
        set.verify_signatures(
            &self.vote.signing_payload(set)?,
            context.epoch(),
            std::slice::from_ref(&self.signature),
        )?;
        Ok(())
    }

    /// Hashes the complete vote payload in the independently tagged phase domain.
    ///
    /// # Errors
    /// Propagates encoding errors; does not authenticate the statement.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        digest(&self.encode(set)?)
    }
}

/// An exact signed DAG carrier and the individual vote payload it must bind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementVoteWitness {
    /// Complete single-signature payload, compared byte-for-byte with the QC entry.
    pub payload: SlotAgreementVotePayload,
    /// Retained DAG carrier; its author must equal the signature's validator ID.
    pub carrier: VertexId,
}

/// Separate prevote-QC payload binding every individual prevote carrier.
///
/// Its digest is not the aggregate prevote digest. Witnesses are in strictly
/// increasing validator-ID order, one per QC signature (at most 4096).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementStrongPrevotePayload {
    /// Direct proposal evidence and nonnil prevote QC.
    pub aggregate: SlotAgreementPrevotePayload,
    /// Exact individual prevotes; each prerequisite is the direct proposal carrier.
    pub votes: Vec<SlotAgreementVoteWitness>,
}

impl SlotAgreementStrongPrevotePayload {
    /// Encodes the separate strong prevote body, including ordered vote witnesses.
    ///
    /// # Errors
    /// Rejects witness/signature/statement mismatch, bounds and nested errors.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        check_witnesses(
            &self.votes,
            &self.aggregate.certificate,
            &self.aggregate.proposal_carrier,
        )?;
        let body = self.aggregate.encode(set)?;
        let mut e = start(STRONG_PREVOTE);
        put_bounded(&mut e, &body)?;
        put_witnesses(&mut e, &self.votes, set)?;
        Ok(e.finish())
    }

    /// Decodes bounded canonical evidence without authenticating signatures.
    ///
    /// # Errors
    /// Rejects outer bounds before nested allocation, noncanonical lists and mismatches.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        let mut d = decoder(bytes, STRONG_PREVOTE)?;
        let body = d.read_bytes()?;
        let mut scan = d.clone();
        scan_witnesses(&mut scan)?;
        scan.finish()?;
        let p = Self {
            aggregate: SlotAgreementPrevotePayload::decode(body, set)?,
            votes: read_witnesses(&mut d, set)?,
        };
        d.finish()?;
        check_witnesses(
            &p.votes,
            &p.aggregate.certificate,
            &p.aggregate.proposal_carrier,
        )?;
        Ok(p)
    }

    /// Hashes the strong prevote body; never substitutes an aggregate carrier hash.
    ///
    /// # Errors
    /// Propagates canonical encoding errors.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        digest(&self.encode(set)?)
    }
}

/// Fixed-depth individual-vote chain, without POL or view-proposer authorization.
///
/// The prevote carrier binds `prevote.digest(set)` before any precommit vote is
/// carried. The final carrier binds this full body after all precommit carriers.
/// No payload references its own carrier, so neither phase introduces hash cycles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementStrongPhaseChain {
    /// Strong prevote payload with exact individual prevote witnesses.
    pub prevote: SlotAgreementStrongPrevotePayload,
    /// Exact strong prevote-QC carrier, prerequisite of all precommit witnesses.
    pub prevote_carrier: VertexId,
    /// Same-view/context/value final precommit quorum.
    pub certificate: AgreementQc,
    /// Ordered individual precommits, exactly matching all final QC signatures.
    pub votes: Vec<SlotAgreementVoteWitness>,
}

impl SlotAgreementStrongPhaseChain {
    /// Encodes a canonical strong final body with an aggregate one-MiB limit.
    ///
    /// # Errors
    /// Rejects phase/view/context/value mismatch, witness mismatch and size/count bounds.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        check_chain(
            &self.prevote.aggregate,
            &self.prevote_carrier,
            &self.certificate,
        )?;
        check_witnesses(&self.votes, &self.certificate, &self.prevote_carrier)?;
        let prevote = self.prevote.encode(set)?;
        let certificate = self.certificate.encode(set)?;
        let mut e = start(STRONG_FINAL);
        put_bounded(&mut e, &prevote)?;
        put_id(&mut e, &self.prevote_carrier)?;
        put_bounded(&mut e, &certificate)?;
        put_witnesses(&mut e, &self.votes, set)?;
        Ok(e.finish())
    }

    /// Decodes a bounded strong final body; decoding never establishes DAG causality.
    ///
    /// # Errors
    /// Rejects malformed envelopes, witness counts/order, mismatches and nested errors.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        let mut d = decoder(bytes, STRONG_FINAL)?;
        let prevote = d.read_bytes()?;
        let prevote_carrier = read_id(&mut d)?;
        let certificate = d.read_bytes()?;
        let mut scan = d.clone();
        scan_witnesses(&mut scan)?;
        scan.finish()?;
        let p = Self {
            prevote: SlotAgreementStrongPrevotePayload::decode(prevote, set)?,
            prevote_carrier,
            certificate: AgreementQc::decode(certificate, set)?,
            votes: read_witnesses(&mut d, set)?,
        };
        d.finish()?;
        p.encode(set)?;
        Ok(p)
    }

    /// Hashes the complete stronger final payload, not the aggregate final bytes.
    ///
    /// # Errors
    /// Propagates canonical encoding errors.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        digest(&self.encode(set)?)
    }
}

fn check_chain(
    prevote: &SlotAgreementPrevotePayload,
    carrier: &VertexId,
    certificate: &AgreementQc,
) -> Result<(), CryptoError> {
    let a = &prevote.certificate.vote;
    let b = &certificate.vote;
    if a.phase != AgreementPhase::Prevote
        || b.phase != AgreementPhase::Precommit
        || a.context != b.context
        || a.view != b.view
        || a.value != b.value
        || a.value != AgreementValue::Decision(prevote.proposal.decision.clone())
    {
        return Err(invalid(
            "agreement phase, view, context or decision mismatch",
        ));
    }
    if carrier.author.len() > MAX_AUTHOR {
        return Err(invalid("agreement phase carrier author exceeds bound"));
    }
    Ok(())
}

fn start(kind: u8) -> Encoder {
    let mut e = Encoder::new();
    e.put_u16(SLOT_AGREEMENT_PHASE_VERSION_V1);
    e.put_u8(kind);
    e
}

fn decoder(bytes: &[u8], kind: u8) -> Result<Decoder<'_>, CryptoError> {
    bound(bytes.len())?;
    let mut d = Decoder::new(bytes);
    if d.read_u16()? != SLOT_AGREEMENT_PHASE_VERSION_V1 || d.read_u8()? != kind {
        return Err(invalid("unknown agreement phase version or kind"));
    }
    Ok(d)
}

fn put_bounded(e: &mut Encoder, bytes: &[u8]) -> Result<(), CryptoError> {
    bound(
        e.len()
            .checked_add(4)
            .and_then(|n| n.checked_add(bytes.len()))
            .ok_or_else(|| invalid("agreement phase size overflow"))?,
    )?;
    e.put_bytes(bytes)
}

pub(crate) fn put_id(e: &mut Encoder, id: &VertexId) -> Result<(), CryptoError> {
    if id.author.len() > MAX_AUTHOR {
        return Err(invalid("agreement phase carrier author exceeds bound"));
    }
    bound(e.len() + 8)?;
    e.put_u64(id.round);
    put_bounded(e, &id.author)?;
    put_bounded(e, &id.digest)
}

pub(crate) fn read_id(d: &mut Decoder<'_>) -> Result<VertexId, CryptoError> {
    let round = d.read_u64()?;
    let author = d.read_bytes()?;
    if author.len() > MAX_AUTHOR {
        return Err(invalid("agreement phase carrier author exceeds bound"));
    }
    let digest = d
        .read_bytes()?
        .try_into()
        .map_err(|_| invalid("expected 32-byte phase carrier digest"))?;
    Ok(VertexId {
        round,
        author: author.to_vec(),
        digest,
    })
}

pub(crate) fn check_witnesses(
    votes: &[SlotAgreementVoteWitness],
    qc: &AgreementQc,
    prerequisite: &VertexId,
) -> Result<(), CryptoError> {
    if votes.len() > MAX_WITNESSES || votes.len() != qc.signatures.len() {
        return Err(invalid("individual vote witness count mismatch or bound"));
    }
    let mut previous: Option<&[u8]> = None;
    for (w, signature) in votes.iter().zip(&qc.signatures) {
        let id = signature.validator_id.as_slice();
        if previous.is_some_and(|p| p >= id)
            || w.payload.vote != qc.vote
            || w.payload.signature != *signature
            || w.carrier.author != signature.validator_id
            || w.payload.prerequisite != *prerequisite
            || prerequisite.round >= w.carrier.round
        {
            return Err(invalid(
                "individual vote witness statement, signature, author or prerequisite mismatch",
            ));
        }
        previous = Some(id);
    }
    Ok(())
}

pub(crate) fn put_witnesses(
    e: &mut Encoder,
    votes: &[SlotAgreementVoteWitness],
    set: &ValidatorSet,
) -> Result<(), CryptoError> {
    if votes.len() > MAX_WITNESSES {
        return Err(invalid("too many individual vote witnesses"));
    }
    bound(e.len() + 4)?;
    e.put_u32(u32::try_from(votes.len()).map_err(|_| invalid("witness count overflow"))?);
    for w in votes {
        put_id(e, &w.carrier)?;
        put_bounded(e, &w.payload.encode(set)?)?;
    }
    Ok(())
}

fn witness_count(d: &mut Decoder<'_>) -> Result<usize, CryptoError> {
    let count = usize::try_from(d.read_u32()?).map_err(|_| invalid("witness count overflow"))?;
    // Each witness has an ID (at least 48 bytes) and a length-prefixed payload.
    if count > MAX_WITNESSES || count > d.remaining() / 52 {
        return Err(invalid(
            "individual vote witness count exceeds bound or remaining bytes",
        ));
    }
    Ok(count)
}

pub(crate) fn scan_witnesses(d: &mut Decoder<'_>) -> Result<(), CryptoError> {
    let count = witness_count(d)?;
    for _ in 0..count {
        read_id(d)?;
        d.read_bytes()?;
    }
    Ok(())
}

pub(crate) fn read_witnesses(
    d: &mut Decoder<'_>,
    set: &ValidatorSet,
) -> Result<Vec<SlotAgreementVoteWitness>, CryptoError> {
    let count = witness_count(d)?;
    let mut votes = Vec::with_capacity(count);
    for _ in 0..count {
        let carrier = read_id(d)?;
        let payload = SlotAgreementVotePayload::decode(d.read_bytes()?, set)?;
        votes.push(SlotAgreementVoteWitness { payload, carrier });
    }
    Ok(votes)
}

fn digest(body: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut e = Encoder::new();
    e.put_bytes(SLOT_AGREEMENT_PHASE_DOMAIN)?;
    e.put_raw(body);
    Ok(Sha256::digest(e.finish()).into())
}
