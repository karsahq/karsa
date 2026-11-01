//! The versioned, algorithm-aware transaction envelope.
//!
//! The authorization list is not part of the signed content: a signature cannot
//! cover itself. The signature covers the fields that affect execution and replay
//! protection. See `docs/crypto-registry.md` §5.

use crypto::domain::{TxSigningFields, encode_tx_signing_payload};
use crypto::encoding::{Decoder, Encoder};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::policy::{AuthPolicy, Authorization};

/// The only envelope version this crate encodes.
pub const PROTOCOL_VERSION_V1: u16 = 1;

/// The bound on the authorization list, so a decode cannot allocate without
/// limit from hostile input.
pub const MAX_AUTHORIZATIONS: usize = 32;

/// A transaction envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Envelope version.
    pub protocol_version: u16,
    /// Chain identifier, which prevents cross-chain replay.
    pub chain_id: Vec<u8>,
    /// Sender account identifier.
    pub sender: Vec<u8>,
    /// Strictly increasing per-sender sequence.
    pub sequence: u64,
    /// Fee committed by the signature.
    pub fee: u64,
    /// Expiration timestamp.
    pub expiration: u64,
    /// Account policy version the signature was made under.
    pub policy_version: u64,
    /// Opaque payload bytes.
    pub payload: Vec<u8>,
    /// Presented authorizations.
    pub authorization: Vec<Authorization>,
}

impl Transaction {
    /// Returns the SHA-256 digest of the payload.
    #[must_use]
    pub fn payload_hash(&self) -> [u8; 32] {
        Sha256::digest(&self.payload).into()
    }

    /// Builds the bytes a transaction signature covers.
    ///
    /// # Errors
    ///
    /// Returns an encoding error only when a field exceeds the protocol limit.
    pub fn signing_payload(&self) -> Result<Vec<u8>, CryptoError> {
        let payload_hash = self.payload_hash();
        encode_tx_signing_payload(&TxSigningFields {
            protocol_version: self.protocol_version,
            chain_id: &self.chain_id,
            sender: &self.sender,
            sequence: self.sequence,
            fee: self.fee,
            expiration: self.expiration,
            policy_version: self.policy_version,
            payload_hash: &payload_hash,
        })
    }

    /// Evaluates the account policy against this transaction at `now`.
    ///
    /// # Errors
    ///
    /// Propagates [`AuthPolicy::authorize`] errors.
    pub fn verify(&self, policy: &AuthPolicy, now: u64) -> Result<Vec<Vec<u8>>, CryptoError> {
        let message = self.signing_payload()?;
        policy.authorize(&message, &self.authorization, now)
    }

    /// Writes the canonical envelope encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TooManyAuthorizations`] above
    /// [`MAX_AUTHORIZATIONS`], and a field error for oversized fields.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        if self.authorization.len() > MAX_AUTHORIZATIONS {
            return Err(CryptoError::new(
                CryptoErrorKind::TooManyAuthorizations,
                format!(
                    "{} authorizations exceed {MAX_AUTHORIZATIONS}",
                    self.authorization.len()
                ),
            ));
        }
        let count = u32::try_from(self.authorization.len()).map_err(|_| {
            CryptoError::new(
                CryptoErrorKind::TooManyAuthorizations,
                "authorization count does not fit a u32",
            )
        })?;

        let mut encoder = Encoder::with_capacity(256);
        encoder.put_u16(self.protocol_version);
        encoder.put_bytes(&self.chain_id)?;
        encoder.put_bytes(&self.sender)?;
        encoder.put_u64(self.sequence);
        encoder.put_u64(self.fee);
        encoder.put_u64(self.expiration);
        encoder.put_u64(self.policy_version);
        encoder.put_bytes(&self.payload)?;
        encoder.put_u32(count);
        for authorization in &self.authorization {
            encoder.put_u16(authorization.algorithm_id);
            encoder.put_bytes(&authorization.key_id)?;
            encoder.put_bytes(&authorization.signature)?;
        }
        Ok(encoder.finish())
    }

    /// Parses a canonical envelope. Truncated input, trailing bytes, and
    /// oversized lists are rejected; nothing is repaired or ignored.
    ///
    /// # Errors
    ///
    /// Returns an encoding error for malformed input and
    /// [`CryptoErrorKind::TooManyAuthorizations`] for an oversized list.
    pub fn decode(data: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(data);
        let protocol_version = decoder.read_u16()?;
        let chain_id = decoder.read_bytes()?.to_vec();
        let sender = decoder.read_bytes()?.to_vec();
        let sequence = decoder.read_u64()?;
        let fee = decoder.read_u64()?;
        let expiration = decoder.read_u64()?;
        let policy_version = decoder.read_u64()?;
        let payload = decoder.read_bytes()?.to_vec();
        let count = decoder.read_u32()? as usize;
        if count > MAX_AUTHORIZATIONS {
            return Err(CryptoError::new(
                CryptoErrorKind::TooManyAuthorizations,
                format!("{count} authorizations exceed {MAX_AUTHORIZATIONS}"),
            ));
        }
        let mut authorization = Vec::with_capacity(count);
        for _ in 0..count {
            authorization.push(Authorization {
                algorithm_id: decoder.read_u16()?,
                key_id: decoder.read_bytes()?.to_vec(),
                signature: decoder.read_bytes()?.to_vec(),
            });
        }
        decoder.finish()?;
        Ok(Self {
            protocol_version,
            chain_id,
            sender,
            sequence,
            fee,
            expiration,
            policy_version,
            payload,
            authorization,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{AuthKey, AuthPolicyKind, KeyStatus, NO_EXPIRY};
    use crypto::encoding::Encoder;
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    fn sample(chain_id: &[u8], sequence: u64) -> Transaction {
        Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: chain_id.to_vec(),
            sender: b"acct_alice".to_vec(),
            sequence,
            fee: 10,
            expiration: 1000,
            policy_version: 1,
            payload: b"hello".to_vec(),
            authorization: Vec::new(),
        }
    }

    fn policy_for(public_key: &[u8]) -> AuthPolicy {
        AuthPolicy {
            kind: AuthPolicyKind::Single,
            threshold: 0,
            policy_nonce: 1,
            keys: vec![AuthKey {
                key_id: b"k1".to_vec(),
                algorithm_id: ALG_ED25519,
                public_key: public_key.to_vec(),
                weight: 1,
                status: KeyStatus::Active,
                valid_from: 0,
                valid_until: NO_EXPIRY,
            }],
        }
    }

    fn signed(chain_id: &[u8], sequence: u64) -> (Transaction, Vec<u8>) {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let mut tx = sample(chain_id, sequence);
        let signature = Ed25519Scheme
            .sign(&private_key, &tx.signing_payload().unwrap())
            .unwrap();
        tx.authorization.push(Authorization {
            algorithm_id: ALG_ED25519,
            key_id: b"k1".to_vec(),
            signature,
        });
        (tx, public_key.to_vec())
    }

    #[test]
    fn envelope_roundtrip() {
        let (tx, _) = signed(b"karsa-testnet-1", 3);
        let encoded = tx.encode().unwrap();
        let decoded = Transaction::decode(&encoded).unwrap();
        assert_eq!(decoded, tx);
        assert_eq!(decoded.encode().unwrap(), encoded);
    }

    #[test]
    fn signed_transaction_verifies() {
        let (tx, public_key) = signed(b"karsa-testnet-1", 3);
        let used = tx.verify(&policy_for(&public_key), 100).unwrap();
        assert_eq!(used, vec![b"k1".to_vec()]);
    }

    #[test]
    fn tampered_sequence_is_rejected() {
        let (tx, public_key) = signed(b"karsa-testnet-1", 3);
        let mut tampered = tx.clone();
        tampered.sequence = 4;
        let error = tampered.verify(&policy_for(&public_key), 100).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn cross_chain_replay_is_rejected() {
        let (tx, public_key) = signed(b"karsa-testnet-1", 3);
        let mut replayed = tx.clone();
        replayed.chain_id = b"karsa-testnet-2".to_vec();
        let error = replayed.verify(&policy_for(&public_key), 100).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::InvalidSignature);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let (tx, _) = signed(b"karsa-testnet-1", 3);
        let mut encoded = tx.encode().unwrap();
        encoded.push(0);
        let error = Transaction::decode(&encoded).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TrailingBytes);
    }

    #[test]
    fn truncated_envelope_is_rejected() {
        let (tx, _) = signed(b"karsa-testnet-1", 3);
        let encoded = tx.encode().unwrap();
        let error = Transaction::decode(&encoded[..encoded.len() - 1]).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TruncatedInput);
    }

    #[test]
    fn encode_rejects_too_many_authorizations() {
        let mut tx = sample(b"karsa-testnet-1", 1);
        for index in 0..=MAX_AUTHORIZATIONS {
            tx.authorization.push(Authorization {
                algorithm_id: ALG_ED25519,
                key_id: format!("k{index}").into_bytes(),
                signature: vec![0u8; 64],
            });
        }
        let error = tx.encode().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TooManyAuthorizations);
    }

    #[test]
    fn decode_rejects_an_oversized_authorization_count() {
        let mut encoder = Encoder::with_capacity(64);
        encoder.put_u16(PROTOCOL_VERSION_V1);
        encoder.put_bytes(b"karsa-testnet-1").unwrap();
        encoder.put_bytes(b"acct_alice").unwrap();
        encoder.put_u64(1);
        encoder.put_u64(1);
        encoder.put_u64(2);
        encoder.put_u64(1);
        encoder.put_bytes(b"p").unwrap();
        encoder.put_u32(u32::try_from(MAX_AUTHORIZATIONS).unwrap() + 1);
        let data = encoder.finish();

        let error = Transaction::decode(&data).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TooManyAuthorizations);
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
    fn matches_the_v_implementation_byte_for_byte() {
        // Same fixed seed, fields, and payload as the V prototype's envelope dump
        // (the generator was removed with that prototype; the expected bytes are
        // below).
        let seed = [0x42u8; 32];
        let public_key = Ed25519Scheme::public_key_from_seed(&seed).unwrap();
        let mut private_key = seed.to_vec();
        private_key.extend_from_slice(&public_key);

        let mut tx = Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: b"karsa-testnet-1".to_vec(),
            sender: b"acct_alice".to_vec(),
            sequence: 3,
            fee: 10,
            expiration: 1000,
            policy_version: 1,
            payload: b"hello".to_vec(),
            authorization: Vec::new(),
        };
        let signature = Ed25519Scheme
            .sign(&private_key, &tx.signing_payload().unwrap())
            .unwrap();
        tx.authorization.push(Authorization {
            algorithm_id: ALG_ED25519,
            key_id: b"k1".to_vec(),
            signature,
        });

        assert_eq!(
            to_hex(&tx.encode().unwrap()),
            "01000f0000006b617273612d746573746e65742d310a000000616363745f616c696365\
             03000000000000000a00000000000000e8030000000000000100000000000000050000\
             0068656c6c6f010000000100020000006b3140000000d86a3e20adb533539fc9885e37\
             e0d21005ef0282e66aaeff9be220f0e72ff535ef2bd5ba32558c5116c5e9fa29b71e5cd8\
             8cd1d683c61391e9489d75db6a730b"
        );
    }
}
