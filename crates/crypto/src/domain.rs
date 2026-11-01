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
        ];
        for (index, tag) in tags.iter().enumerate() {
            for other in &tags[index + 1..] {
                assert_ne!(tag, other);
            }
        }
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
