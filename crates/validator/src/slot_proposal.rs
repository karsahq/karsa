//! Inactive fixed-set proposals carrying explicit evidence for direct slot rules.
//!
//! This payload is not signable authorization and does not activate a protocol path.
//! Voter identifiers name signed DAG vertices: votes or nonvotes must be inferred
//! from their signed references, not asserted by this codec. Before locking or
//! signing a decision, the proposer must validate DAG causal binding, evidence
//! (including signatures, membership, distinct authors, rounds, and thresholds),
//! the direct rule, and decision/frontier continuity. Fence and indirect rules
//! are not supported. Encoding and decoding perform no semantic validation.

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

impl SlotProposal {
    /// Encodes version, length-prefixed decision, count, then voter identifiers.
    ///
    /// Each identifier contains a round, length-prefixed author and 32-byte digest.
    ///
    /// # Errors
    /// Rejects oversized bodies, fields or counts, noncanonical voter ordering,
    /// and any structural encoding error from [`SlotDecision::encode`].
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        check_bound(self.voters.len(), MAX_VOTERS)?;
        let decision = self.decision.encode()?;
        let mut size = 2 + 4 + decision.len() + 4;
        for (index, voter) in self.voters.iter().enumerate() {
            check_bound(voter.author.len(), MAX_AUTHOR_BYTES)?;
            if index > 0 {
                check_order(&self.voters[index - 1], voter)?;
            }
            size += 8 + 4 + voter.author.len() + 4 + 32;
            check_bound(size, MAX_FIELD_LEN)?;
        }
        check_bound(size, MAX_FIELD_LEN)?;
        let mut e = Encoder::with_capacity(size);
        e.put_u16(SLOT_PROPOSAL_VERSION_V1);
        e.put_bytes(&decision)?;
        e.put_u32(self.voters.len() as u32);
        for voter in &self.voters {
            e.put_u64(voter.round);
            e.put_bytes(&voter.author)?;
            e.put_bytes(&voter.digest)?;
        }
        Ok(e.finish())
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
