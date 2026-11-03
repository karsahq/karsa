//! A validator's identity as an address.
//!
//! A validator is not a name a node chooses; it is the key schedule that chain
//! genesis agreed on. The address commits to that *genesis* schedule, so a later
//! key rotation authorized by the active key does not move the validator's
//! identity, its votes, or its history. The same principle as an account address
//! (D32): a commitment to creation, not to the current key set.
//!
//! The preimage excludes `key_id` and `retirement_epoch`. `key_id` is a label and
//! is already excluded from account addresses for the same reason; retirement is
//! schedule state that a rotation may change. Algorithm, public key, and activation
//! epoch are the facts that decide when this validator could sign.

use crypto::CryptoError;
use crypto::encoding::Encoder;
use sha2::{Digest, Sha256};

use crate::schedule::ValidatorKey;

/// Domain tag, so this hash can never be confused with an account address or a
/// genesis hash over similar bytes.
pub const DOMAIN: &[u8] = b"KARSA/VALIDATOR/v1";

/// Derives the validator address from its genesis key schedule.
///
/// Keys are sorted by `(algorithm, public_key, activation_epoch)`, so the order in
/// a file is not part of the identity. Two validators with identical genesis
/// schedules have the same address, which is a duplicate genesis must refuse.
///
/// # Errors
///
/// [`crypto::CryptoErrorKind::FieldTooLong`] when a public key does not fit the
/// encoder's length prefix, which a registry-sized key never does.
pub fn validator_address(keys: &[ValidatorKey]) -> Result<[u8; 32], CryptoError> {
    let mut encoder = Encoder::with_capacity(DOMAIN.len() + 8 + keys.len() * 48);
    // A fixed constant, not a length-prefixed field.
    encoder.put_raw(DOMAIN);

    let mut keys: Vec<&ValidatorKey> = keys.iter().collect();
    keys.sort_by(|left, right| {
        left.algorithm_id
            .cmp(&right.algorithm_id)
            .then_with(|| left.public_key.cmp(&right.public_key))
            .then_with(|| left.activation_epoch.cmp(&right.activation_epoch))
    });
    encoder.put_u32(u32::try_from(keys.len()).map_err(|_| {
        CryptoError::new(
            crypto::CryptoErrorKind::FieldTooLong,
            "validator has more keys than a u32 can count",
        )
    })?);
    for key in keys {
        encoder.put_u16(key.algorithm_id);
        encoder.put_u64(key.activation_epoch);
        encoder.put_bytes(&key.public_key)?;
    }

    Ok(Sha256::digest(encoder.as_slice()).into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::registry::ALG_ED25519;
    use crypto::scheme::Ed25519Scheme;

    fn key(seed: u8, activation: u64) -> ValidatorKey {
        let public_key = Ed25519Scheme::public_key_from_seed(&[seed; 32])
            .unwrap()
            .to_vec();
        ValidatorKey {
            key_id: format!("key-{seed}").into_bytes(),
            algorithm_id: ALG_ED25519,
            public_key,
            activation_epoch: activation,
            retirement_epoch: crate::schedule::NO_EXPIRY,
        }
    }

    #[test]
    fn key_order_does_not_change_the_address() {
        let left = vec![key(1, 0), key(2, 10)];
        let right = vec![key(2, 10), key(1, 0)];
        assert_eq!(
            validator_address(&left).unwrap(),
            validator_address(&right).unwrap()
        );
    }

    #[test]
    fn labels_and_retirement_do_not_move_the_address() {
        let original = vec![key(1, 0)];
        let mut renamed = original.clone();
        renamed[0].key_id = b"different-label".to_vec();
        renamed[0].retirement_epoch = 500;
        assert_eq!(
            validator_address(&original).unwrap(),
            validator_address(&renamed).unwrap()
        );
    }

    #[test]
    fn changing_a_public_key_or_activation_changes_the_address() {
        let base = validator_address(&[key(1, 0)]).unwrap();
        assert_ne!(base, validator_address(&[key(2, 0)]).unwrap());
        assert_ne!(base, validator_address(&[key(1, 1)]).unwrap());
    }

    #[test]
    fn the_encoding_is_stable() {
        // A golden vector: changing the preimage moves every validator identity.
        let address = validator_address(&[key(1, 0)]).unwrap();
        let hex: String = address.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(
            hex,
            "0400601c39bf002cb13e43876964235f775658d718a9ce125a574d5158c65134"
        );
    }
}
