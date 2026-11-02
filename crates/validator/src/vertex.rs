//! DAG vertices: one signature per block, votes expressed as references.
//!
//! This is the uncertified counterpart of [`crate::Certificate`]. A certificate
//! carries one signature per validator, so a round of `n` certificates costs
//! `n²` signatures. A vertex carries only its author's signature, and a vote for
//! a leader is the presence of that leader in `references`, so a round of `n`
//! vertices costs `n` signatures.
//!
//! The trade is portability, not correctness: a certificate can be handed to a
//! light client and verified offline, while a vertex vote only means something
//! against the DAG it references.

use crypto::domain::{VertexRefFields, VertexSigningFields, encode_vertex_signing_payload};
use crypto::encoding::{Decoder, Encoder};
use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::schedule::{EpochSchedule, ValidatorSet};

/// Canonical vertex encoding version.
pub const VERTEX_VERSION_V1: u16 = 1;

/// Content-addressed identifier of a vertex.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct VertexId {
    /// Round the vertex belongs to.
    pub round: u64,
    /// Validator that authored it.
    pub author: Vec<u8>,
    /// SHA-256 of its signed payload.
    pub digest: [u8; 32],
}

/// One DAG vertex: an author, a reference list, and one signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Vertex {
    /// Chain identifier.
    pub chain_id: Vec<u8>,
    /// Epoch the vertex belongs to.
    pub epoch: u64,
    /// Round the vertex belongs to.
    pub round: u64,
    /// Authoring validator.
    pub author: Vec<u8>,
    /// Digest of the transaction batch the vertex orders.
    pub payload_hash: [u8; 32],
    /// Vertices this one references; a leader reference is a vote.
    pub references: Vec<VertexId>,
    /// The author's signature over [`Vertex::signing_payload`].
    pub signature: Vec<u8>,
}

impl VertexId {
    fn as_fields(&self) -> VertexRefFields<'_> {
        VertexRefFields {
            round: self.round,
            author: &self.author,
            digest: &self.digest,
        }
    }
}

impl Vertex {
    fn reference_fields(&self) -> Vec<VertexRefFields<'_>> {
        self.references.iter().map(VertexId::as_fields).collect()
    }

    /// Builds the bytes the author signs.
    ///
    /// # Errors
    ///
    /// Returns an error only when a field exceeds the encoding limit.
    pub fn signing_payload(&self) -> Result<Vec<u8>, CryptoError> {
        let references = self.reference_fields();
        encode_vertex_signing_payload(&VertexSigningFields {
            chain_id: &self.chain_id,
            epoch: self.epoch,
            round: self.round,
            author: &self.author,
            payload_hash: &self.payload_hash,
            references: &references,
        })
    }

    /// Content-addressed id: SHA-256 of the signed payload.
    ///
    /// The signature is deliberately outside the digest, so the id names what the
    /// author committed to rather than a particular encoding of the signature.
    ///
    /// # Errors
    ///
    /// Propagates [`Vertex::signing_payload`] errors.
    pub fn id(&self) -> Result<VertexId, CryptoError> {
        let digest: [u8; 32] = Sha256::digest(self.signing_payload()?).into();
        Ok(VertexId {
            round: self.round,
            author: self.author.clone(),
            digest,
        })
    }

    /// Encodes the vertex canonically, signature included.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::FieldTooLong`] for an oversized field.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder = Encoder::with_capacity(128 + self.references.len() * 48);
        encoder.put_u16(VERTEX_VERSION_V1);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_u64(self.epoch);
        encoder.put_u64(self.round);
        encoder.put_bytes(&self.author)?;
        encoder.put_bytes(&self.payload_hash)?;
        encoder.put_u32(
            u32::try_from(self.references.len()).map_err(|_| {
                CryptoError::new(CryptoErrorKind::FieldTooLong, "too many references")
            })?,
        );
        for reference in &self.references {
            encoder.put_u64(reference.round);
            encoder.put_bytes(&reference.author)?;
            encoder.put_bytes(&reference.digest)?;
        }
        encoder.put_bytes(&self.signature)?;
        Ok(encoder.finish())
    }

    /// Decodes a canonical vertex.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`],
    /// [`CryptoErrorKind::TrailingBytes`], or
    /// [`CryptoErrorKind::MalformedCertificate`] for an unknown version.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let version = decoder.read_u16()?;
        if version != VERTEX_VERSION_V1 {
            return Err(CryptoError::new(
                CryptoErrorKind::MalformedCertificate,
                format!("unsupported vertex version {version}"),
            ));
        }
        let chain_id = decoder.read_bytes()?.to_vec();
        let epoch = decoder.read_u64()?;
        let round = decoder.read_u64()?;
        let author = decoder.read_bytes()?.to_vec();
        let payload_hash = read_digest(&mut decoder)?;
        let count = decoder.read_u32()? as usize;
        let mut references = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let round = decoder.read_u64()?;
            let author = decoder.read_bytes()?.to_vec();
            let digest = read_digest(&mut decoder)?;
            references.push(VertexId {
                round,
                author,
                digest,
            });
        }
        let signature = decoder.read_bytes()?.to_vec();
        decoder.finish()?;
        Ok(Self {
            chain_id,
            epoch,
            round,
            author,
            payload_hash,
            references,
            signature,
        })
    }

    /// Verifies the author's signature against the schedule.
    ///
    /// The author's key is resolved from the schedule at `epoch`, so a vertex
    /// never names a key: a rotated-out key cannot sign, and a key that is not
    /// active yet cannot vote early.
    ///
    /// `epoch` is passed in rather than read from the vertex on purpose. A vertex
    /// that declared its own epoch could name an epoch in which a retired key was
    /// still active and keep signing with it. The caller derives the epoch from the
    /// round, which every node computes the same way.
    ///
    /// # Errors
    ///
    /// [`CryptoErrorKind::UnknownValidator`] for an author outside the set,
    /// [`CryptoErrorKind::KeyOutOfWindow`] when the vertex claims another epoch,
    /// [`CryptoErrorKind::KeyNotActive`] or [`CryptoErrorKind::KeyAmbiguous`] from
    /// the schedule, plus any verification error from
    /// [`crypto::scheme::verify_signature`].
    pub fn verify(&self, set: &ValidatorSet, epoch: u64) -> Result<(), CryptoError> {
        if self.epoch != epoch {
            return Err(CryptoError::new(
                CryptoErrorKind::KeyOutOfWindow,
                format!(
                    "vertex claims epoch {} but round maps to {epoch}",
                    self.epoch
                ),
            ));
        }
        let record = set.validator(&self.author).ok_or_else(|| {
            CryptoError::new(
                CryptoErrorKind::UnknownValidator,
                "vertex from an unregistered validator",
            )
        })?;
        let key = record.active_key(epoch)?;
        let payload = self.signing_payload()?;
        verify_signature(key.algorithm_id, &key.public_key, &payload, &self.signature)
    }
}

fn read_digest(decoder: &mut Decoder<'_>) -> Result<[u8; 32], CryptoError> {
    let bytes = decoder.read_bytes()?;
    let digest: [u8; 32] = bytes.try_into().map_err(|_| {
        CryptoError::new(
            CryptoErrorKind::MalformedCertificate,
            format!("digest of {} bytes, expected 32", bytes.len()),
        )
    })?;
    Ok(digest)
}

/// Counts the distinct validators that voted for `leader`.
///
/// A vote is a vertex in the round after the leader that references it. Every
/// candidate must verify, and an author that appears twice counts once — the same
/// rule the certificate path applies, so one validator can never become two votes.
///
/// # Errors
///
/// Propagates [`Vertex::verify`]; a candidate from another round is ignored
/// rather than rejected, because it is not a vote for this leader.
pub fn tally_votes(
    set: &ValidatorSet,
    leader: &VertexId,
    candidates: &[Vertex],
    schedule: &EpochSchedule,
) -> Result<Vec<Vec<u8>>, CryptoError> {
    let voting_round = leader.round + 1;
    let mut voters: Vec<Vec<u8>> = Vec::new();
    for candidate in candidates.iter().filter(|v| v.round == voting_round) {
        // Each voter is checked at the epoch its own round belongs to. The round
        // that votes for a leader can be the first round of the next epoch, so
        // using the leader's epoch would reject a legitimate vote at the boundary.
        candidate.verify(set, schedule.epoch_of(candidate.round))?;
        if !candidate.references.iter().any(|r| r == leader) {
            continue;
        }
        if !voters.contains(&candidate.author) {
            voters.push(candidate.author.clone());
        }
    }
    Ok(voters)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schedule::{NO_EXPIRY, ValidatorKey, ValidatorRecord};
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    const EPOCH: u64 = 1;

    struct Signer {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
    }

    fn deterministic_key(index: u8) -> Signer {
        let seed = [index; 32];
        let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
        let mut private_key = Vec::with_capacity(64);
        private_key.extend_from_slice(&seed);
        private_key.extend_from_slice(&public_key);
        Signer {
            public_key: public_key.to_vec(),
            private_key,
        }
    }

    fn validator_set(count: usize) -> (ValidatorSet, Vec<Signer>) {
        let mut signers = Vec::with_capacity(count);
        let mut validators = Vec::with_capacity(count);
        for index in 0..count {
            let signer = deterministic_key(u8::try_from(index + 1).unwrap());
            validators.push(ValidatorRecord {
                validator_id: format!("val-{index}").into_bytes(),
                keys: vec![ValidatorKey {
                    key_id: format!("val-{index}-k0").into_bytes(),
                    algorithm_id: ALG_ED25519,
                    public_key: signer.public_key.clone(),
                    activation_epoch: 0,
                    retirement_epoch: NO_EXPIRY,
                }],
            });
            signers.push(signer);
        }
        let set = ValidatorSet {
            epoch: EPOCH,
            validators,
        };
        set.validate().unwrap();
        (set, signers)
    }

    fn vertex(author: usize, round: u64, references: Vec<VertexId>, signers: &[Signer]) -> Vertex {
        let mut vertex = Vertex {
            chain_id: b"karsa-test-1".to_vec(),
            epoch: EPOCH,
            round,
            author: format!("val-{author}").into_bytes(),
            payload_hash: [u8::try_from(author).unwrap(); 32],
            references,
            signature: Vec::new(),
        };
        let payload = vertex.signing_payload().unwrap();
        vertex.signature = Ed25519Scheme
            .sign(&signers[author].private_key, &payload)
            .unwrap();
        vertex
    }

    #[test]
    fn a_vertex_verifies_and_roundtrips() {
        let (set, signers) = validator_set(4);
        let leader = vertex(0, 7, Vec::new(), &signers);
        let leader_id = leader.id().unwrap();
        let vote = vertex(1, 8, vec![leader_id], &signers);

        vote.verify(&set, EPOCH).unwrap();
        let encoded = vote.encode().unwrap();
        let decoded = Vertex::decode(&encoded).unwrap();
        assert_eq!(decoded, vote);
        assert_eq!(decoded.id().unwrap(), vote.id().unwrap());
    }

    #[test]
    fn the_signature_covers_the_reference_list() {
        let (set, signers) = validator_set(4);
        let a = vertex(0, 7, Vec::new(), &signers);
        let b = vertex(1, 7, Vec::new(), &signers);
        let mut vote = vertex(2, 8, vec![a.id().unwrap()], &signers);
        vote.verify(&set, EPOCH).unwrap();

        // Re-point the reference at a different leader: the old signature must die.
        vote.references = vec![b.id().unwrap()];
        let error = vote.verify(&set, EPOCH).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn a_full_round_votes_once_per_validator() {
        let (set, signers) = validator_set(4);
        let leader = vertex(0, 7, Vec::new(), &signers);
        let leader_id = leader.id().unwrap();

        // Three distinct voters, plus a duplicate vote from val-1 and a vertex from
        // the wrong round that must be ignored.
        let candidates = vec![
            vertex(1, 8, vec![leader_id.clone()], &signers),
            vertex(2, 8, vec![leader_id.clone()], &signers),
            vertex(3, 8, vec![leader_id.clone()], &signers),
            vertex(1, 8, vec![leader_id.clone()], &signers),
            vertex(2, 9, vec![leader_id.clone()], &signers),
        ];
        let voters =
            tally_votes(&set, &leader_id, &candidates, &EpochSchedule::single(EPOCH)).unwrap();
        assert_eq!(voters.len(), 3);
        assert!(set.has_supermajority(voters.len()));
    }

    #[test]
    fn a_vertex_that_does_not_reference_the_leader_is_not_a_vote() {
        let (set, signers) = validator_set(4);
        let leader = vertex(0, 7, Vec::new(), &signers);
        let other = vertex(3, 7, Vec::new(), &signers);
        let leader_id = leader.id().unwrap();

        let candidates = vec![
            vertex(1, 8, vec![leader_id.clone()], &signers),
            vertex(2, 8, vec![other.id().unwrap()], &signers),
        ];
        let voters =
            tally_votes(&set, &leader_id, &candidates, &EpochSchedule::single(EPOCH)).unwrap();
        assert_eq!(voters, vec![b"val-1".to_vec()]);
    }

    #[test]
    fn a_retired_key_cannot_vote() {
        let (mut set, signers) = validator_set(3);
        let leader = vertex(0, 7, Vec::new(), &signers);
        let leader_id = leader.id().unwrap();
        let vote = vertex(1, 8, vec![leader_id.clone()], &signers);

        set.validators[1].keys[0].retirement_epoch = EPOCH;
        let error = vote.verify(&set, EPOCH).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyNotActive);
    }

    #[test]
    fn an_unregistered_author_is_rejected() {
        let (set, signers) = validator_set(2);
        let mut vote = vertex(0, 7, Vec::new(), &signers);
        vote.author = b"val-9".to_vec();
        let error = vote.verify(&set, EPOCH).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::UnknownValidator);
    }

    #[test]
    fn a_vertex_from_another_epoch_is_rejected() {
        let (set, signers) = validator_set(2);
        let mut vote = vertex(0, 7, Vec::new(), &signers);
        vote.epoch = EPOCH + 1;
        let error = vote.verify(&set, EPOCH).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyOutOfWindow);
    }
}
