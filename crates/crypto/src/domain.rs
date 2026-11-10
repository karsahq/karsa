//! Domain-separated signing payloads.
//!
//! Every signed message begins with a length-prefixed ASCII domain tag, so a
//! signature produced for one protocol purpose cannot authorize another. See
//! `docs/crypto-registry.md` §4.

use crate::encoding::Encoder;
use crate::error::CryptoError;

/// Account transaction payload domain.
pub const DOMAIN_TX_V1: &str = "KARSA/TX/v1";
/// DAG-BFT vote payload domain.
pub const DOMAIN_DAG_VOTE_V1: &str = "KARSA/DAG/VOTE/v1";
/// DAG-BFT proposal payload domain.
pub const DOMAIN_DAG_PROPOSE_V1: &str = "KARSA/DAG/PROPOSE/v1";
/// IBC client payload domain.
pub const DOMAIN_IBC_CLIENT_V1: &str = "KARSA/IBC/CLIENT/v1";
/// Validator key registration payload domain.
pub const DOMAIN_VALIDATOR_KEY_V1: &str = "KARSA/VALIDATOR/KEY/v1";
/// Validator-set identifier domain: binds a set's epoch, order, and keys.
pub const DOMAIN_VALIDATOR_SET_V1: &str = "KARSA/VALIDATOR/SET/v1";
/// Validator-set transition descriptor domain.
pub const DOMAIN_SET_CHANGE_V1: &str = "KARSA/SET/CHANGE/v1";
/// Validator-set transition identifier domain.
pub const DOMAIN_SET_TRANSITION_V1: &str = "KARSA/SET/TRANSITION/v1";
/// Validator-failure fence declaration domain.
pub const DOMAIN_FENCE_V1: &str = "KARSA/SET/FENCE/v1";
/// DAG vertex payload domain: one signature per vertex.
pub const DOMAIN_VERTEX_V1: &str = "KARSA/DAG/VERTEX/v1";
/// Committed-state header domain: the object a finality certificate names.
pub const DOMAIN_HEADER_V1: &str = "KARSA/HEADER/v1";

/// The values a transaction signature authorizes.
///
/// The envelope's authorization list is excluded: a signature cannot cover
/// itself. `payload_hash` is the digest of the payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TxSigningFields<'a> {
    /// Envelope protocol version.
    pub protocol_version: u16,
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: &'a [u8],
    /// Sender account identifier.
    pub sender: &'a [u8],
    /// Strictly increasing per-sender sequence.
    pub sequence: u64,
    /// Fee committed by the signature.
    pub fee: u64,
    /// Expiration timestamp.
    pub expiration: u64,
    /// Account policy version the signature was made under.
    pub policy_version: u64,
    /// Digest of the payload.
    pub payload_hash: &'a [u8],
}

/// The signed content of a DAG-BFT vote.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VoteSigningFields<'a> {
    /// Chain identifier.
    pub chain_id: &'a [u8],
    /// Epoch the vote belongs to.
    pub epoch: u64,
    /// Round the vote belongs to.
    pub round: u64,
    /// Identifier of the vertex being voted for.
    pub vertex_id: &'a [u8],
}

/// The signed content of a DAG-BFT proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProposeSigningFields<'a> {
    /// Chain identifier.
    pub chain_id: &'a [u8],
    /// Epoch the proposal belongs to.
    pub epoch: u64,
    /// Round the proposal belongs to.
    pub round: u64,
    /// Digest of the proposal.
    pub proposal_hash: &'a [u8],
}

/// The values a validator key registration authorizes.
///
/// Registration is authorized by a key the validator already has, so a new key
/// cannot be enrolled by anyone who merely knows the validator id. The signed
/// fields cover every part of the new key, which is what stops a relay from
/// swapping the public key or the activation epoch in transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRegistrationSigningFields<'a> {
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: &'a [u8],
    /// Validator the new key belongs to.
    pub validator_id: &'a [u8],
    /// Identifier of the new key.
    pub key_id: &'a [u8],
    /// Registry algorithm id of the new key.
    pub algorithm_id: u16,
    /// Canonical public-key encoding of the new key.
    pub public_key: &'a [u8],
    /// First epoch the new key may sign (inclusive).
    pub activation_epoch: u64,
    /// First epoch the new key may no longer sign (exclusive).
    pub retirement_epoch: u64,
    /// Epoch the authorizing key claims at signing time.
    pub signed_at_epoch: u64,
}

/// The signed content of a validator-set change.
///
/// The transition itself is identified by `transition_hash`; the other fields
/// let a verifier find the old set and check which set becomes active, when.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetChangeSigningFields<'a> {
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: &'a [u8],
    /// Content identifier of the set that signs the change.
    pub old_set_id: &'a [u8],
    /// Content identifier of the set that becomes active.
    pub new_set_id: &'a [u8],
    /// First epoch at which the new set is active.
    pub activation_epoch: u64,
    /// Domain-separated identifier of the transition.
    pub transition_hash: &'a [u8],
}

/// The signed content of a validator-failure fence.
///
/// A fence is a quorum statement that `validator_id` is failed from
/// `from_round` onward. It is scoped to the chain and the round whose set
/// resolves the signing keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FenceSigningFields<'a> {
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: &'a [u8],
    /// First round at which the validator is considered failed.
    pub from_round: u64,
    /// Validator declared failed.
    pub validator_id: &'a [u8],
}

/// A reference to another vertex, as it appears inside a signed vertex payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VertexRefFields<'a> {
    /// Round of the referenced vertex.
    pub round: u64,
    /// Author of the referenced vertex.
    pub author: &'a [u8],
    /// Digest of the referenced vertex's signed payload.
    pub digest: &'a [u8],
}

/// The signed content of a DAG vertex.
///
/// One vertex carries one signature, from its author. A vote for a leader is the
/// presence of that leader in `references`, which is why an uncertified DAG needs
/// `n` signatures per round rather than `n²`: there is no separate certificate
/// object to sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VertexSigningFields<'a> {
    /// Chain identifier.
    pub chain_id: &'a [u8],
    /// Epoch the vertex belongs to.
    pub epoch: u64,
    /// Round the vertex belongs to.
    pub round: u64,
    /// Validator that authored the vertex.
    pub author: &'a [u8],
    /// Digest of the transaction batch this vertex orders.
    pub payload_hash: &'a [u8],
    /// Vertices this one references.
    pub references: &'a [VertexRefFields<'a>],
}

/// The committed state a header names.
///
/// A header is not signed directly. It is identified by the hash of this payload,
/// and a finality certificate is a quorum signature over that identifier. The
/// domain tag is what keeps a header identifier from colliding with a vertex
/// identifier, so a certificate over one can never be read as a certificate over
/// the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeaderFields<'a> {
    /// Chain identifier.
    pub chain_id: &'a [u8],
    /// Epoch the header was produced in.
    pub epoch: u64,
    /// Monotone height, starting at 0 for the genesis header.
    pub height: u64,
    /// DAG round whose commits this header covers.
    pub round: u64,
    /// Merkle root of the account state.
    pub state_root: &'a [u8],
    /// Merkle root over the committed vertices, in commit order.
    pub dag_root: &'a [u8],
    /// Identifier of the previous header, all zero at genesis.
    pub previous: &'a [u8],
    /// Cumulative number of transactions applied at this height.
    pub applied: u64,
}

/// Prefixes an already-canonical body with a length-prefixed domain tag.
fn wrap_domain(domain: &str, body: &[u8]) -> Result<Vec<u8>, CryptoError> {
    let mut encoder = Encoder::with_capacity(domain.len() + body.len() + 8);
    encoder.put_bytes(domain.as_bytes())?;
    encoder.put_raw(body);
    Ok(encoder.finish())
}

/// Builds the bytes a transaction signature covers.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_tx_signing_payload(fields: &TxSigningFields<'_>) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(128);
    body.put_u16(fields.protocol_version);
    body.put_bytes(fields.chain_id)?;
    body.put_bytes(fields.sender)?;
    body.put_u64(fields.sequence);
    body.put_u64(fields.fee);
    body.put_u64(fields.expiration);
    body.put_u64(fields.policy_version);
    body.put_bytes(fields.payload_hash)?;
    wrap_domain(DOMAIN_TX_V1, body.as_slice())
}

/// Builds the bytes a DAG-BFT vote signature covers.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_vote_signing_payload(fields: &VoteSigningFields<'_>) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(64);
    body.put_bytes(fields.chain_id)?;
    body.put_u64(fields.epoch);
    body.put_u64(fields.round);
    body.put_bytes(fields.vertex_id)?;
    wrap_domain(DOMAIN_DAG_VOTE_V1, body.as_slice())
}

/// Builds the bytes a DAG-BFT proposal signature covers.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_propose_signing_payload(
    fields: &ProposeSigningFields<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(64);
    body.put_bytes(fields.chain_id)?;
    body.put_u64(fields.epoch);
    body.put_u64(fields.round);
    body.put_bytes(fields.proposal_hash)?;
    wrap_domain(DOMAIN_DAG_PROPOSE_V1, body.as_slice())
}

/// Builds the bytes a validator key registration signature covers.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_key_registration_payload(
    fields: &KeyRegistrationSigningFields<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(128);
    body.put_bytes(fields.chain_id)?;
    body.put_bytes(fields.validator_id)?;
    body.put_bytes(fields.key_id)?;
    body.put_u16(fields.algorithm_id);
    body.put_bytes(fields.public_key)?;
    body.put_u64(fields.activation_epoch);
    body.put_u64(fields.retirement_epoch);
    body.put_u64(fields.signed_at_epoch);
    wrap_domain(DOMAIN_VALIDATOR_KEY_V1, body.as_slice())
}

/// Builds the bytes an old-set quorum signs to authorize a validator-set change.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_set_change_signing_payload(
    fields: &SetChangeSigningFields<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(128);
    body.put_bytes(fields.chain_id)?;
    body.put_bytes(fields.old_set_id)?;
    body.put_bytes(fields.new_set_id)?;
    body.put_u64(fields.activation_epoch);
    body.put_bytes(fields.transition_hash)?;
    wrap_domain(DOMAIN_SET_CHANGE_V1, body.as_slice())
}

/// Builds the bytes a fence quorum signs.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_fence_signing_payload(
    fields: &FenceSigningFields<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(64 + fields.validator_id.len());
    body.put_bytes(fields.chain_id)?;
    body.put_u64(fields.from_round);
    body.put_bytes(fields.validator_id)?;
    wrap_domain(DOMAIN_FENCE_V1, body.as_slice())
}

/// Builds the bytes a DAG vertex signature covers.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_vertex_signing_payload(
    fields: &VertexSigningFields<'_>,
) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(128 + fields.references.len() * 48);
    body.put_bytes(fields.chain_id)?;
    body.put_u64(fields.epoch);
    body.put_u64(fields.round);
    body.put_bytes(fields.author)?;
    body.put_bytes(fields.payload_hash)?;
    let count = u32::try_from(fields.references.len()).map_err(|_| {
        crate::error::CryptoError::new(
            crate::error::CryptoErrorKind::FieldTooLong,
            "too many vertex references",
        )
    })?;
    body.put_u32(count);
    for reference in fields.references {
        body.put_u64(reference.round);
        body.put_bytes(reference.author)?;
        body.put_bytes(reference.digest)?;
    }
    wrap_domain(DOMAIN_VERTEX_V1, body.as_slice())
}

/// Builds the bytes whose hash identifies a committed-state header.
///
/// # Errors
///
/// Returns an error only when a field exceeds the encoding limit.
pub fn encode_header_payload(fields: &HeaderFields<'_>) -> Result<Vec<u8>, CryptoError> {
    let mut body = Encoder::with_capacity(96 + fields.chain_id.len());
    body.put_bytes(fields.chain_id)?;
    body.put_u64(fields.epoch);
    body.put_u64(fields.height);
    body.put_u64(fields.round);
    body.put_bytes(fields.state_root)?;
    body.put_bytes(fields.dag_root)?;
    body.put_bytes(fields.previous)?;
    body.put_u64(fields.applied);
    wrap_domain(DOMAIN_HEADER_V1, body.as_slice())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PAYLOAD_HASH: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    fn tx_fields(chain_id: &[u8]) -> TxSigningFields<'_> {
        TxSigningFields {
            protocol_version: 1,
            chain_id,
            sender: b"acct_alice",
            sequence: 7,
            fee: 1000,
            expiration: 1_900_000_000,
            policy_version: 1,
            payload_hash: &PAYLOAD_HASH,
        }
    }

    fn to_hex(bytes: &[u8]) -> String {
        use std::fmt::Write as _;
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            write!(out, "{byte:02x}").expect("writing to a String cannot fail");
        }
        out
    }

    #[test]
    fn payload_starts_with_the_domain_tag() {
        let encoded = encode_tx_signing_payload(&tx_fields(b"karsa-testnet-1")).unwrap();
        let tag_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize;
        assert_eq!(tag_len, DOMAIN_TX_V1.len());
        assert_eq!(&encoded[4..4 + tag_len], DOMAIN_TX_V1.as_bytes());
    }

    #[test]
    fn each_purpose_has_a_distinct_domain_tag() {
        let tags = [
            DOMAIN_TX_V1,
            DOMAIN_DAG_VOTE_V1,
            DOMAIN_DAG_PROPOSE_V1,
            DOMAIN_IBC_CLIENT_V1,
            DOMAIN_VALIDATOR_KEY_V1,
            DOMAIN_VALIDATOR_SET_V1,
            DOMAIN_SET_CHANGE_V1,
            DOMAIN_SET_TRANSITION_V1,
            DOMAIN_FENCE_V1,
            DOMAIN_VERTEX_V1,
        ];
        for (index, tag) in tags.iter().enumerate() {
            for other in &tags[index + 1..] {
                assert_ne!(tag, other);
            }
        }
    }

    #[test]
    fn key_registration_binds_every_field() {
        let fields = KeyRegistrationSigningFields {
            chain_id: b"karsa-testnet-1",
            validator_id: b"val-1",
            key_id: b"val-1-next",
            algorithm_id: 0x0001,
            public_key: &PAYLOAD_HASH,
            activation_epoch: 4,
            retirement_epoch: u64::MAX,
            signed_at_epoch: 3,
        };
        let encoded = encode_key_registration_payload(&fields).unwrap();
        let tag_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize;
        assert_eq!(&encoded[4..4 + tag_len], DOMAIN_VALIDATOR_KEY_V1.as_bytes());

        let renamed = encode_key_registration_payload(&KeyRegistrationSigningFields {
            key_id: b"val-1-other",
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, renamed);

        let rescheduled = encode_key_registration_payload(&KeyRegistrationSigningFields {
            activation_epoch: 5,
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, rescheduled);
    }

    #[test]
    fn a_set_change_payload_binds_every_activation_field() {
        let fields = SetChangeSigningFields {
            chain_id: b"karsa-testnet-1",
            old_set_id: &[1u8; 32],
            new_set_id: &[2u8; 32],
            activation_epoch: 9,
            transition_hash: &[3u8; 32],
        };
        let encoded = encode_set_change_signing_payload(&fields).unwrap();
        let tag_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize;
        assert_eq!(&encoded[4..4 + tag_len], DOMAIN_SET_CHANGE_V1.as_bytes());

        let other_epoch = encode_set_change_signing_payload(&SetChangeSigningFields {
            activation_epoch: 10,
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, other_epoch);

        let other_set = encode_set_change_signing_payload(&SetChangeSigningFields {
            new_set_id: &[4u8; 32],
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, other_set);
    }

    #[test]
    fn a_fence_payload_binds_the_round_and_the_validator() {
        let fields = FenceSigningFields {
            chain_id: b"karsa-testnet-1",
            from_round: 77,
            validator_id: b"val-3",
        };
        let encoded = encode_fence_signing_payload(&fields).unwrap();
        let tag_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize;
        assert_eq!(&encoded[4..4 + tag_len], DOMAIN_FENCE_V1.as_bytes());

        let other_round = encode_fence_signing_payload(&FenceSigningFields {
            from_round: 78,
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, other_round);

        let other_validator = encode_fence_signing_payload(&FenceSigningFields {
            validator_id: b"val-2",
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, other_validator);
    }

    #[test]
    fn a_vertex_payload_binds_its_references() {
        let parent = VertexRefFields {
            round: 6,
            author: b"val-0",
            digest: &PAYLOAD_HASH,
        };
        let fields = VertexSigningFields {
            chain_id: b"karsa-test-1",
            epoch: 1,
            round: 7,
            author: b"val-1",
            payload_hash: &PAYLOAD_HASH,
            references: std::slice::from_ref(&parent),
        };
        let encoded = encode_vertex_signing_payload(&fields).unwrap();
        let tag_len = u32::from_le_bytes(encoded[0..4].try_into().unwrap()) as usize;
        assert_eq!(&encoded[4..4 + tag_len], DOMAIN_VERTEX_V1.as_bytes());

        let other_parent = VertexRefFields {
            round: 6,
            author: b"val-2",
            ..parent
        };
        let repointed = encode_vertex_signing_payload(&VertexSigningFields {
            references: std::slice::from_ref(&other_parent),
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, repointed);

        let no_parent = encode_vertex_signing_payload(&VertexSigningFields {
            references: &[],
            ..fields
        })
        .unwrap();
        assert_ne!(encoded, no_parent);
    }

    #[test]
    fn chain_id_changes_the_signed_payload() {
        let on_a = encode_tx_signing_payload(&tx_fields(b"karsa-testnet-1")).unwrap();
        let on_b = encode_tx_signing_payload(&tx_fields(b"karsa-testnet-2")).unwrap();
        assert_ne!(on_a, on_b);
    }

    #[test]
    fn matches_the_v_implementation_byte_for_byte() {
        let encoded = encode_tx_signing_payload(&tx_fields(b"karsa-testnet-1")).unwrap();
        assert_eq!(
            to_hex(&encoded),
            "0b0000004b415253412f54582f763101000f0000006b617273612d746573746e65742d310a0000\
             00616363745f616c6963650700000000000000e80300000000000000b33f7100000000010000\
             000000000020000000000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c\
             1d1e1f"
        );

        let vote = encode_vote_signing_payload(&VoteSigningFields {
            chain_id: b"karsa-testnet-1",
            epoch: 9,
            round: 7,
            vertex_id: b"vertex-abc",
        })
        .unwrap();
        assert_eq!(
            to_hex(&vote),
            "110000004b415253412f4441472f564f54452f76310f0000006b617273612d746573746e6574\
             2d31090000000000000007000000000000000a0000007665727465782d616263"
        );
    }
}
