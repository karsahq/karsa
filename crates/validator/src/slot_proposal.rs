//! Inactive fixed-set proposals carrying explicit evidence for direct slot rules.
//!
//! This payload is not signable authorization and does not activate a protocol path.
//! Voter identifiers name signed DAG vertices: votes or nonvotes must be inferred
//! from their signed references, not asserted by this codec. Before locking or
//! signing a decision, the proposer must validate DAG causal binding, evidence
//! (including signatures, membership, distinct authors, rounds, and thresholds),
//! the evidence rule, and decision/frontier continuity. Legacy V1 proposals support
//! only direct evidence; the unified envelope adds explicit indirect-positive
//! evidence. Fence evidence is unsupported. Codecs perform no semantic validation.

use crypto::encoding::{Decoder, Encoder, MAX_FIELD_LEN};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::slot_decision::SlotDecision;
use crate::vertex::VertexId;

/// Canonical slot proposal encoding version.
pub const SLOT_PROPOSAL_VERSION_V1: u16 = 1;
/// Domain hashed before the canonical slot proposal body.
pub const SLOT_PROPOSAL_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_PROPOSAL/v1";

// Bound work and allocation independently of individual length-prefixed fields.
const MAX_VOTERS: usize = 4096;
const MAX_AUTHOR_BYTES: usize = 1024;

/// An inactive direct-rule proposal, not authorization to lock or sign a decision.
///
/// The entire encoding is bounded by `MAX_FIELD_LEN` (1 MiB), with at most
/// 4096 voters and 1024 bytes per voter author. Voters must be strictly ordered
/// lexicographically by `(round, author, digest)`; codecs never sort them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotProposal {
    /// Structural decision requiring caller validation before locking or signing.
    pub decision: SlotDecision,
    /// Explicit vote/nonvote evidence, resolved against signed DAG references.
    pub voters: Vec<VertexId>,
}

/// Independent indirect-positive proposal encoding version.
pub const SLOT_PROPOSAL_VERSION_V2: u16 = 2;
/// Domain for explicit indirect-positive proposal evidence.
pub const SLOT_PROPOSAL_INDIRECT_DOMAIN: &[u8] = b"KARSA/DAG/SLOT_PROPOSAL/v2";

/// Explicit evidence kind; indirect evidence admits only a positive commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SlotProposalEvidence {
    /// Exact signed direct vote or nonvote vertices.
    Direct {
        /// Canonically ordered signed vote/nonvote identities.
        voters: Vec<VertexId>,
    },
    /// Later elected anchor and exact signed vertices voting for it.
    IndirectCommit {
        /// Exact later elected leader identity.
        anchor: VertexId,
        /// Canonically ordered signed votes explicitly referencing the anchor.
        support: Vec<VertexId>,
    },
}

/// Versioned proposal used by unified agreement lineage and application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotProposalEnvelope {
    /// Exact decision context and deterministic target effect.
    pub decision: SlotDecision,
    /// Explicit direct or indirect-positive evidence.
    pub evidence: SlotProposalEvidence,
}

impl From<SlotProposal> for SlotProposalEnvelope {
    fn from(proposal: SlotProposal) -> Self {
        Self {
            decision: proposal.decision,
            evidence: SlotProposalEvidence::Direct {
                voters: proposal.voters,
            },
        }
    }
}

impl SlotProposalEnvelope {
    /// Encodes direct proposals byte-for-byte as V1, and indirect evidence as V2.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        match &self.evidence {
            SlotProposalEvidence::Direct { voters } => encode_parts(&self.decision, voters),
            SlotProposalEvidence::IndirectCommit { anchor, support } => {
                // Reuse the bounded canonical identity-list codec, without overloading
                // its semantics: the V2 body explicitly separates anchor and support.
                let body = encode_parts(&self.decision, support)?;
                check_bound(anchor.author.len(), MAX_AUTHOR_BYTES)?;
                check_bound(
                    2 + 8 + 4 + anchor.author.len() + 4 + 32 + 4 + body.len(),
                    MAX_FIELD_LEN,
                )?;
                let mut e = Encoder::new();
                e.put_u16(SLOT_PROPOSAL_VERSION_V2);
                e.put_u64(anchor.round);
                e.put_bytes(&anchor.author)?;
                e.put_bytes(&anchor.digest)?;
                e.put_bytes(&body)?;
                Ok(e.finish())
            }
        }
    }

    /// Decodes an explicitly versioned bounded proposal, without authentication.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_bound(bytes.len(), MAX_FIELD_LEN)?;
        let mut d = Decoder::new(bytes);
        match d.read_u16()? {
            SLOT_PROPOSAL_VERSION_V1 => Ok(SlotProposal::decode(bytes)?.into()),
            SLOT_PROPOSAL_VERSION_V2 => {
                let round = d.read_u64()?;
                let author = d.read_bytes()?;
                check_bound(author.len(), MAX_AUTHOR_BYTES)?;
                let digest = d
                    .read_bytes()?
                    .try_into()
                    .map_err(|_| malformed("expected a 32-byte anchor digest"))?;
                let body = SlotProposal::decode(d.read_bytes()?)?;
                d.finish()?;
                Ok(Self {
                    decision: body.decision,
                    evidence: SlotProposalEvidence::IndirectCommit {
                        anchor: VertexId {
                            round,
                            author: author.to_vec(),
                            digest,
                        },
                        support: body.voters,
                    },
                })
            }
            _ => Err(malformed("unsupported slot proposal envelope version")),
        }
    }

    /// Hashes direct bytes in the unchanged V1 domain, or indirect bytes in V2.
    pub fn digest(&self) -> Result<[u8; 32], CryptoError> {
        let domain = match self.evidence {
            SlotProposalEvidence::Direct { .. } => SLOT_PROPOSAL_DOMAIN,
            SlotProposalEvidence::IndirectCommit { .. } => SLOT_PROPOSAL_INDIRECT_DOMAIN,
        };
        let mut e = Encoder::new();
        e.put_bytes(domain)?;
        e.put_raw(&self.encode()?);
        Ok(Sha256::digest(e.finish()).into())
    }
}

fn check_bound(value: usize, limit: usize) -> Result<(), CryptoError> {
    if value > limit {
        return Err(CryptoError::new(
            CryptoErrorKind::FieldTooLong,
            "slot proposal exceeds encoding bound",
        ));
    }
    Ok(())
}

fn malformed(message: &str) -> CryptoError {
    CryptoError::new(CryptoErrorKind::MalformedCertificate, message)
}

fn check_order(previous: &VertexId, next: &VertexId) -> Result<(), CryptoError> {
    if (previous.round, &previous.author, &previous.digest)
        >= (next.round, &next.author, &next.digest)
    {
        return Err(malformed("slot proposal voters are not strictly ordered"));
    }
    Ok(())
}

fn encode_parts(decision: &SlotDecision, voters: &[VertexId]) -> Result<Vec<u8>, CryptoError> {
    check_bound(voters.len(), MAX_VOTERS)?;
    let decision = decision.encode()?;
    let mut size = 2 + 4 + decision.len() + 4;
    for (index, voter) in voters.iter().enumerate() {
        check_bound(voter.author.len(), MAX_AUTHOR_BYTES)?;
        if index > 0 {
            check_order(&voters[index - 1], voter)?;
        }
        size += 8 + 4 + voter.author.len() + 4 + 32;
        check_bound(size, MAX_FIELD_LEN)?;
    }
    check_bound(size, MAX_FIELD_LEN)?;
    let mut e = Encoder::with_capacity(size);
    e.put_u16(SLOT_PROPOSAL_VERSION_V1);
    e.put_bytes(&decision)?;
    e.put_u32(voters.len() as u32);
    for voter in voters {
        e.put_u64(voter.round);
        e.put_bytes(&voter.author)?;
        e.put_bytes(&voter.digest)?;
    }
    Ok(e.finish())
}

impl SlotProposal {
    /// Encodes version, length-prefixed decision, count, then voter identifiers.
    ///
    /// Each identifier contains a round, length-prefixed author and 32-byte digest.
    ///
    /// # Errors
    /// Rejects oversized bodies, fields or counts, noncanonical voter ordering,
    /// and any structural encoding error from [`SlotDecision::encode`].
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        encode_parts(&self.decision, &self.voters)
    }

    /// Decodes a canonical proposal without validating decision or evidence semantics.
    ///
    /// # Errors
    /// Rejects oversized bodies, authors or counts, unknown versions, malformed
    /// digests, duplicate/reordered voters, truncation, and trailing bytes, and
    /// propagates structural [`SlotDecision::decode`] errors.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        check_bound(bytes.len(), MAX_FIELD_LEN)?;
        let mut d = Decoder::new(bytes);
        if d.read_u16()? != SLOT_PROPOSAL_VERSION_V1 {
            return Err(malformed("unsupported slot proposal version"));
        }
        let decision = SlotDecision::decode(d.read_bytes()?)?;
        let count = d.read_u32()? as usize;
        check_bound(count, MAX_VOTERS)?;
        let mut voters = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let round = d.read_u64()?;
            let author = d.read_bytes()?;
            check_bound(author.len(), MAX_AUTHOR_BYTES)?;
            let digest = d
                .read_bytes()?
                .try_into()
                .map_err(|_| malformed("expected a 32-byte voter digest"))?;
            let voter = VertexId {
                round,
                author: author.to_vec(),
                digest,
            };
            if let Some(previous) = voters.last() {
                check_order(previous, &voter)?;
            }
            voters.push(voter);
        }
        d.finish()?;
        Ok(Self { decision, voters })
    }

    /// Hashes the length-prefixed domain followed by the raw canonical encoding.
    ///
    /// This content digest is not a signing payload or authorization.
    ///
    /// # Errors
    /// Propagates [`Self::encode`] errors.
    pub fn digest(&self) -> Result<[u8; 32], CryptoError> {
        let body = self.encode()?;
        let mut e = Encoder::with_capacity(4 + SLOT_PROPOSAL_DOMAIN.len() + body.len());
        e.put_bytes(SLOT_PROPOSAL_DOMAIN)?;
        e.put_raw(&body);
        Ok(Sha256::digest(e.finish()).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::slot_decision::SlotOutcome;

    fn proposal() -> SlotProposal {
        SlotProposal {
            // Deliberately structural only: no valid set, DAG, or continuity proof.
            decision: SlotDecision {
                chain_id: Vec::new(),
                validator_set_id: [0; 32],
                epoch: 0,
                round: 7,
                previous: [0; 32],
                before_len: 9,
                before_root: [1; 32],
                after_len: 0,
                after_root: [2; 32],
                outcome: SlotOutcome::Skip {
                    leader_author: Vec::new(),
                },
            },
            voters: vec![
                VertexId {
                    round: 8,
                    author: b"a".to_vec(),
                    digest: [1; 32],
                },
                VertexId {
                    round: 8,
                    author: b"b".to_vec(),
                    digest: [2; 32],
                },
            ],
        }
    }

    // Bypass the encoder's canonical checks to exercise hostile wire inputs.
    fn raw(p: &SlotProposal, count: u32) -> Vec<u8> {
        let mut e = Encoder::new();
        e.put_u16(SLOT_PROPOSAL_VERSION_V1);
        e.put_bytes(&p.decision.encode().unwrap()).unwrap();
        e.put_u32(count);
        for voter in &p.voters {
            e.put_u64(voter.round);
            e.put_bytes(&voter.author).unwrap();
            e.put_bytes(&voter.digest).unwrap();
        }
        e.finish()
    }

    #[test]
    fn envelope_preserves_v1_and_distinguishes_bounded_v2() {
        let legacy = proposal();
        let direct: SlotProposalEnvelope = legacy.clone().into();
        assert_eq!(direct.encode().unwrap(), legacy.encode().unwrap());
        assert_eq!(direct.digest().unwrap(), legacy.digest().unwrap());
        assert_eq!(
            SlotProposalEnvelope::decode(&legacy.encode().unwrap()).unwrap(),
            direct
        );
        let mut indirect = SlotProposalEnvelope {
            decision: legacy.decision,
            evidence: SlotProposalEvidence::IndirectCommit {
                anchor: legacy.voters[0].clone(),
                support: legacy.voters,
            },
        };
        let bytes = indirect.encode().unwrap();
        assert_eq!(SlotProposalEnvelope::decode(&bytes).unwrap(), indirect);
        assert!(SlotProposal::decode(&bytes).is_err());
        let mut e = Encoder::new();
        e.put_bytes(SLOT_PROPOSAL_INDIRECT_DOMAIN).unwrap();
        e.put_raw(&bytes);
        let digest: [u8; 32] = Sha256::digest(e.finish()).into();
        assert_eq!(indirect.digest().unwrap(), digest);
        for end in 0..bytes.len() {
            assert!(
                SlotProposalEnvelope::decode(&bytes[..end]).is_err(),
                "prefix {end}"
            );
        }
        let mut bad = bytes.clone();
        bad.push(0);
        assert!(SlotProposalEnvelope::decode(&bad).is_err());
        bad = bytes.clone();
        bad[..2].copy_from_slice(&3u16.to_le_bytes());
        assert!(SlotProposalEnvelope::decode(&bad).is_err());
        let SlotProposalEvidence::IndirectCommit { support, .. } = &mut indirect.evidence else {
            unreachable!()
        };
        support.reverse();
        assert!(indirect.encode().is_err());
        let SlotProposalEvidence::IndirectCommit { anchor, .. } = &mut indirect.evidence else {
            unreachable!()
        };
        anchor.author = vec![0; MAX_AUTHOR_BYTES + 1];
        assert!(indirect.encode().is_err());
    }

    #[test]
    fn structural_roundtrip_and_domain_digest() {
        let mut p = proposal();
        let bytes = p.encode().unwrap();
        assert_eq!(SlotProposal::decode(&bytes).unwrap(), p);
        let mut e = Encoder::new();
        e.put_bytes(SLOT_PROPOSAL_DOMAIN).unwrap();
        e.put_raw(&bytes);
        let expected: [u8; 32] = Sha256::digest(e.finish()).into();
        assert_eq!(p.digest().unwrap(), expected);
        p.voters[1].digest[0] ^= 1;
        assert_ne!(p.digest().unwrap(), expected);
        p.voters.clear();
        assert_eq!(SlotProposal::decode(&p.encode().unwrap()).unwrap(), p);
    }

    #[test]
    fn duplicate_and_reordered_voters_are_rejected() {
        for duplicate in [false, true] {
            let mut p = proposal();
            if duplicate {
                p.voters[1] = p.voters[0].clone();
            } else {
                p.voters.swap(0, 1);
            }
            assert_eq!(
                p.encode().unwrap_err().kind(),
                CryptoErrorKind::MalformedCertificate
            );
            assert!(p.digest().is_err());
            assert_eq!(
                SlotProposal::decode(&raw(&p, 2)).unwrap_err().kind(),
                CryptoErrorKind::MalformedCertificate
            );
        }
    }

    #[test]
    fn ordering_uses_round_then_author_then_digest() {
        let mut p = proposal();
        p.voters[1].author = p.voters[0].author.clone();
        assert!(p.encode().is_ok());
        p.voters[1].digest = [0; 32];
        assert!(p.encode().is_err());
        p.voters[1].round += 1;
        assert!(p.encode().is_ok());
    }

    #[test]
    fn truncation_trailing_version_and_digest_length_are_rejected() {
        let bytes = proposal().encode().unwrap();
        for end in 0..bytes.len() {
            assert!(SlotProposal::decode(&bytes[..end]).is_err(), "prefix {end}");
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            SlotProposal::decode(&trailing).unwrap_err().kind(),
            CryptoErrorKind::TrailingBytes
        );
        let mut version = bytes.clone();
        version[..2].copy_from_slice(&2u16.to_le_bytes());
        assert!(SlotProposal::decode(&version).is_err());
        let mut malformed = bytes;
        let digest_prefix = malformed.len() - 32 - 4;
        malformed[digest_prefix..digest_prefix + 4].copy_from_slice(&31u32.to_le_bytes());
        assert_eq!(
            SlotProposal::decode(&malformed).unwrap_err().kind(),
            CryptoErrorKind::MalformedCertificate
        );
    }

    #[test]
    fn author_count_and_total_limits_apply_both_ways() {
        let mut p = proposal();
        p.voters[0].author = vec![0; MAX_AUTHOR_BYTES];
        assert!(p.encode().is_ok());
        p.voters[0].author.push(0);
        assert_eq!(
            p.encode().unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert_eq!(
            SlotProposal::decode(&raw(&p, 2)).unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        p.voters = (0..MAX_VOTERS)
            .map(|round| VertexId {
                round: round as u64,
                author: Vec::new(),
                digest: [0; 32],
            })
            .collect();
        assert_eq!(SlotProposal::decode(&p.encode().unwrap()).unwrap(), p);
        p.voters.push(VertexId {
            round: MAX_VOTERS as u64,
            author: Vec::new(),
            digest: [0; 32],
        });
        assert!(p.encode().is_err());
        assert_eq!(
            SlotProposal::decode(&raw(&proposal(), u32::MAX))
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
        p.voters.pop();
        for voter in &mut p.voters {
            voter.author = vec![0; MAX_AUTHOR_BYTES];
        }
        assert_eq!(
            p.encode().unwrap_err().kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert_eq!(
            SlotProposal::decode(&raw(&p, MAX_VOTERS as u32))
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
        assert_eq!(
            SlotProposal::decode(&vec![0; MAX_FIELD_LEN + 1])
                .unwrap_err()
                .kind(),
            CryptoErrorKind::FieldTooLong
        );
    }
}
