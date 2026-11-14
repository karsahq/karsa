//! Inactive flat, view-authorized agreement evidence. This does not certify local
//! lock/WAL execution or timeout validity and cannot authorize application.
use crate::slot_agreement::{AgreementPhase, AgreementQc, AgreementValue, AgreementView};
use crate::slot_agreement_phase::{
    check_witnesses, invalid, put_id, put_witnesses, read_id, read_witnesses, scan_witnesses,
};
use crate::{SlotAgreementVoteWitness, SlotProposal, ValidatorSet, VertexId};
use crypto::CryptoError;
use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use sha2::{Digest, Sha256};

/// Maximum number of nonrecursive lineage entries.
pub const SLOT_AGREEMENT_PROOF_MAX_ENTRIES: usize = 16;
/// Maximum total canonical proof bytes.
pub const SLOT_AGREEMENT_PROOF_MAX_BYTES: usize = MAX_FIELD_LEN;
/// Domain independent of all legacy view and phase payloads.
pub const SLOT_AGREEMENT_PROOF_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_AGREEMENT_PROOF/v1";

/// Strong prevote evidence bound to one authenticated view proposal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementProofPol {
    /// Complete phase quorum statement and signatures.
    pub certificate: AgreementQc,
    /// Exact individual signed vote carriers in canonical identity order.
    pub votes: Vec<SlotAgreementVoteWitness>,
    /// Exact signed carrier binding this evidence.
    pub carrier: VertexId,
}
/// One complete direct proposal and its view authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementProofEntry {
    /// Complete direct-rule evidence.
    pub proposal: SlotProposal,
    /// Exact plain direct-proposal carrier.
    pub proposal_carrier: VertexId,
    /// Agreement view, independent of DAG round.
    pub view: AgreementView,
    /// Exact authenticated elected-proposer carrier.
    pub view_carrier: VertexId,
    /// Strictly earlier entry; all entries must be reachable from the last.
    pub previous_pol: Option<usize>,
    /// Optional strong prevote evidence for this entry.
    pub pol: Option<SlotAgreementProofPol>,
}
/// Final evidence selects the last entry; no payload contains a recursive proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementProof {
    /// Connected flat lineage; the last entry is selected.
    pub entries: Vec<SlotAgreementProofEntry>,
    /// Complete phase quorum statement and signatures.
    pub certificate: AgreementQc,
    /// Exact individual signed vote carriers in canonical identity order.
    pub votes: Vec<SlotAgreementVoteWitness>,
}
fn hash(kind: u8, bytes: &[u8]) -> Result<[u8; 32], CryptoError> {
    let mut e = Encoder::new();
    e.put_bytes(SLOT_AGREEMENT_PROOF_DOMAIN)?;
    e.put_u8(kind);
    e.put_raw(bytes);
    Ok(Sha256::digest(e.finish()).into())
}
impl SlotAgreementProof {
    /// Hashes view authorization using the shared lineage representation.
    pub fn view_digest(&self, index: usize) -> Result<[u8; 32], CryptoError> {
        Lineage(&self.entries).view_digest(index)
    }
    /// Hashes authenticated POL evidence using the shared lineage representation.
    pub fn pol_digest(&self, index: usize, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        Lineage(&self.entries).pol_digest(index, set)
    }
    fn check(&self) -> Result<(), CryptoError> {
        Lineage(&self.entries).check()?;
        let last = self
            .entries
            .last()
            .ok_or_else(|| invalid("empty lineage"))?;
        let final_vote = &self.certificate.vote;
        if self
            .entries
            .iter()
            .filter_map(|p| p.pol.as_ref())
            .any(|pol| pol.certificate.vote.context != final_vote.context)
        {
            return Err(invalid("POL context mismatch"));
        }
        let pol = last
            .pol
            .as_ref()
            .ok_or_else(|| invalid("selected entry lacks POL"))?;
        if final_vote.phase != AgreementPhase::Precommit
            || final_vote.view != last.view
            || final_vote.value != pol.certificate.vote.value
        {
            return Err(invalid("final statement mismatch"));
        }
        check_witnesses(&self.votes, &self.certificate, &pol.carrier)
    }
    /// Encodes the complete bounded envelope without authenticating signatures.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        self.check()?;
        let mut e = Encoder::new();
        e.put_u16(1);
        Lineage(&self.entries).encode_into(&mut e, set)?;
        e.put_bytes(&self.certificate.encode(set)?)?;
        put_witnesses(&mut e, &self.votes, set)?;
        if e.len() > MAX_FIELD_LEN {
            return Err(invalid("proof exceeds one MiB"));
        }
        Ok(e.finish())
    }
    /// Decodes a flat envelope, checking all outer lengths before nested decoding.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(invalid("proof exceeds one MiB"));
        }
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != 1 {
            return Err(invalid("unknown proof version"));
        }
        let raw = scan_entries(&mut d, bytes)?;
        let qc = d.read_bytes()?;
        let start = d.remaining();
        scan_witnesses(&mut d)?;
        d.finish()?;
        let votes = read_witnesses(&mut Decoder::new(&bytes[bytes.len() - start..]), set)?;
        let entries = decode_entries(raw, set)?;
        let proof = Self {
            entries,
            certificate: AgreementQc::decode(qc, set)?,
            votes,
        };
        proof.check()?;
        Ok(proof)
    }
    /// Final carrier digest; only this final payload includes the full lineage.
    pub fn digest(&self, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        hash(2, &self.encode(set)?)
    }
}

/// Bounded authenticated view prefix, independent of a final precommit QC.
/// Inspection is read-only and does not establish local durability or signing authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotAgreementViewLineage {
    /// Connected lineage selecting the last view; that view need not have a POL.
    pub entries: Vec<SlotAgreementProofEntry>,
}
impl SlotAgreementViewLineage {
    /// Hashes the same view authorization as the full proof, without a final QC.
    pub fn view_digest(&self, index: usize) -> Result<[u8; 32], CryptoError> {
        Lineage(&self.entries).view_digest(index)
    }
    /// Hashes the same POL authorization as the full proof.
    pub fn pol_digest(&self, index: usize, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        Lineage(&self.entries).pol_digest(index, set)
    }
    /// Encodes bounded canonical evidence without authenticating it.
    pub fn encode(&self, set: &ValidatorSet) -> Result<Vec<u8>, CryptoError> {
        let lineage = Lineage(&self.entries);
        lineage.check()?;
        let mut e = Encoder::new();
        e.put_u16(1);
        lineage.encode_into(&mut e, set)?;
        Ok(e.finish())
    }
    /// Preflights the entire envelope before decoding nested evidence.
    pub fn decode(bytes: &[u8], set: &ValidatorSet) -> Result<Self, CryptoError> {
        if bytes.len() > MAX_FIELD_LEN {
            return Err(invalid("lineage exceeds one MiB"));
        }
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != 1 {
            return Err(invalid("unknown lineage version"));
        }
        let raw = scan_entries(&mut d, bytes)?;
        d.finish()?;
        let entries = decode_entries(raw, set)?;
        Lineage(&entries).check()?;
        Ok(Self { entries })
    }
}
pub(crate) struct Lineage<'a>(pub(crate) &'a [SlotAgreementProofEntry]);
impl Lineage<'_> {
    fn entry(&self, index: usize) -> Result<&SlotAgreementProofEntry, CryptoError> {
        self.0
            .get(index)
            .ok_or_else(|| invalid("invalid lineage index"))
    }
    /// Hashes only view authorization, including the exact earlier POL carrier.
    pub fn view_digest(&self, index: usize) -> Result<[u8; 32], CryptoError> {
        let p = self.entry(index)?;
        let mut e = Encoder::new();
        e.put_u64(p.view.0);
        e.put_bytes(&p.proposal.encode()?)?;
        put_id(&mut e, &p.proposal_carrier)?;
        match p.previous_pol {
            None => e.put_u8(0),
            Some(i) => {
                if i >= index {
                    return Err(invalid("POL index must be strictly earlier"));
                }
                let prior = self.entry(i)?;
                let pol = prior
                    .pol
                    .as_ref()
                    .ok_or_else(|| invalid("missing earlier POL"))?;
                e.put_u8(1);
                e.put_u32(i as u32);
                put_id(&mut e, &pol.carrier)?;
            }
        }
        hash(0, &e.finish())
    }
    /// Hashes the exact view carrier, QC and individual prevote witnesses.
    pub fn pol_digest(&self, index: usize, set: &ValidatorSet) -> Result<[u8; 32], CryptoError> {
        let p = self.entry(index)?;
        let pol = p.pol.as_ref().ok_or_else(|| invalid("missing POL"))?;
        let mut e = Encoder::new();
        e.put_u64(p.view.0);
        put_id(&mut e, &p.view_carrier)?;
        e.put_raw(&self.view_digest(index)?);
        e.put_bytes(&pol.certificate.encode(set)?)?;
        put_witnesses(&mut e, &pol.votes, set)?;
        hash(1, &e.finish())
    }
    fn check(&self) -> Result<(), CryptoError> {
        if self.0.is_empty() || self.0.len() > SLOT_AGREEMENT_PROOF_MAX_ENTRIES {
            return Err(invalid("lineage entry bound"));
        }
        let last = self.0.last().ok_or_else(|| invalid("empty lineage"))?;
        for (i, p) in self.0.iter().enumerate() {
            // A single-parent connected lineage has exactly this canonical shape.
            if p.previous_pol != i.checked_sub(1) || p.proposal.decision != last.proposal.decision {
                return Err(invalid("unused, forward or mismatched lineage entry"));
            }
            if let Some(prior) = p.previous_pol
                && self.0[prior].view >= p.view
            {
                return Err(invalid("POL view is not earlier"));
            }
            if let Some(pol) = &p.pol {
                let v = &pol.certificate.vote;
                if v.phase != AgreementPhase::Prevote
                    || v.view != p.view
                    || v.value != AgreementValue::Decision(p.proposal.decision.clone())
                {
                    return Err(invalid("POL statement mismatch"));
                }
                check_witnesses(&pol.votes, &pol.certificate, &p.view_carrier)?;
            } else if i + 1 < self.0.len() {
                return Err(invalid("referenced entry lacks POL"));
            }
        }
        Ok(())
    }
    fn encode_into(&self, e: &mut Encoder, set: &ValidatorSet) -> Result<(), CryptoError> {
        e.put_u32(self.0.len() as u32);
        for p in self.0 {
            e.put_bytes(&p.proposal.encode()?)?;
            put_id(e, &p.proposal_carrier)?;
            e.put_u64(p.view.0);
            put_id(e, &p.view_carrier)?;
            match p.previous_pol {
                None => e.put_u8(0),
                Some(i) => {
                    e.put_u8(1);
                    e.put_u32(i as u32);
                }
            }
            match &p.pol {
                None => e.put_u8(0),
                Some(pol) => {
                    e.put_u8(1);
                    e.put_bytes(&pol.certificate.encode(set)?)?;
                    put_id(e, &pol.carrier)?;
                    put_witnesses(e, &pol.votes, set)?;
                }
            }
            if e.len() > MAX_FIELD_LEN {
                return Err(invalid("proof exceeds one MiB"));
            }
        }
        Ok(())
    }
}
type RawEntry<'a> = (
    &'a [u8],
    VertexId,
    AgreementView,
    VertexId,
    Option<usize>,
    Option<(&'a [u8], VertexId, &'a [u8])>,
);
fn scan_entries<'a>(
    d: &mut Decoder<'a>,
    bytes: &'a [u8],
) -> Result<Vec<RawEntry<'a>>, CryptoError> {
    let n = d.read_u32()? as usize;
    if n == 0 || n > SLOT_AGREEMENT_PROOF_MAX_ENTRIES {
        return Err(invalid("lineage entry bound"));
    }
    let mut raw = Vec::with_capacity(n);
    for _ in 0..n {
        let proposal = d.read_bytes()?;
        let plain = read_id(d)?;
        let view = AgreementView(d.read_u64()?);
        let carrier = read_id(d)?;
        let prior = match d.read_u8()? {
            0 => None,
            1 => Some(d.read_u32()? as usize),
            _ => return Err(invalid("invalid prior tag")),
        };
        let pol = match d.read_u8()? {
            0 => None,
            1 => {
                let qc = d.read_bytes()?;
                let id = read_id(d)?;
                let start = d.remaining();
                scan_witnesses(d)?;
                let end = d.remaining();
                Some((qc, id, &bytes[bytes.len() - start..bytes.len() - end]))
            }
            _ => return Err(invalid("invalid POL tag")),
        };
        raw.push((proposal, plain, view, carrier, prior, pol));
    }
    Ok(raw)
}
fn decode_entries(
    raw: Vec<RawEntry<'_>>,
    set: &ValidatorSet,
) -> Result<Vec<SlotAgreementProofEntry>, CryptoError> {
    let mut entries = Vec::with_capacity(raw.len());
    for (proposal, proposal_carrier, view, view_carrier, previous_pol, pol) in raw {
        let pol = pol
            .map(|(qc, carrier, w)| {
                Ok::<_, CryptoError>(SlotAgreementProofPol {
                    certificate: AgreementQc::decode(qc, set)?,
                    carrier,
                    votes: read_witnesses(&mut Decoder::new(w), set)?,
                })
            })
            .transpose()?;
        entries.push(SlotAgreementProofEntry {
            proposal: SlotProposal::decode(proposal)?,
            proposal_carrier,
            view,
            view_carrier,
            previous_pol,
            pol,
        });
    }
    Ok(entries)
}
