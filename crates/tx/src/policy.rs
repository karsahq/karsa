//! Account authorization policy.
//!
//! The policy decides who may authorize a message: one key, every active key
//! (AND), or a weighted threshold. There is deliberately no OR policy: an OR over
//! a classical and a post-quantum key authorizes with the weakest component and
//! must not be described as hybrid protection.

use crypto::scheme::verify_signature;
use crypto::{CryptoError, CryptoErrorKind};

/// Sentinel for a key that never expires.
pub const NO_EXPIRY: u64 = u64::MAX;

/// The policy shape, mirroring `SINGLE` / `AND` / `THRESHOLD` in the spec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthPolicyKind {
    /// Exactly one authorization must be present and verify.
    Single,
    /// Every active, in-window key must authorize.
    All,
    /// The summed weight of distinct authorized keys must reach the threshold.
    Threshold,
}

/// The lifecycle state of one authorization key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// May authorize.
    Active,
    /// Retired; rejected for new authorizations.
    Retired,
    /// Revoked; rejected for new authorizations.
    Revoked,
}

/// One public key registered on an account.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthKey {
    /// Caller-visible key identifier.
    pub key_id: Vec<u8>,
    /// Registry algorithm id of the key.
    pub algorithm_id: u16,
    /// Canonical public-key encoding.
    pub public_key: Vec<u8>,
    /// Weight, used only by [`AuthPolicyKind::Threshold`].
    pub weight: u16,
    /// Lifecycle state.
    pub status: KeyStatus,
    /// First epoch or timestamp at which the key may authorize (inclusive).
    pub valid_from: u64,
    /// First epoch or timestamp at which it may no longer authorize (exclusive).
    pub valid_until: u64,
}

impl AuthKey {
    /// Returns whether the key may authorize at `now`.
    #[must_use]
    pub fn is_usable(&self, now: u64) -> bool {
        self.status == KeyStatus::Active && now >= self.valid_from && now < self.valid_until
    }
}

/// One signature presented with a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Authorization {
    /// Registry algorithm id the signature was produced with.
    pub algorithm_id: u16,
    /// Key that produced the signature.
    pub key_id: Vec<u8>,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// The account-side authorization rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthPolicy {
    /// Policy shape.
    pub kind: AuthPolicyKind,
    /// Minimum summed weight for [`AuthPolicyKind::Threshold`].
    pub threshold: u16,
    /// Account-side rotation counter.
    pub policy_nonce: u64,
    /// Registered keys.
    pub keys: Vec<AuthKey>,
}

impl AuthPolicy {
    fn find_key(&self, key_id: &[u8]) -> Option<&AuthKey> {
        self.keys.iter().find(|key| key.key_id == key_id)
    }

    /// Checks one authorization and returns the key id it used.
    ///
    /// The order is part of the determinism contract: unknown key, algorithm
    /// binding, lifecycle, validity window, then the signature itself.
    fn verify_one(
        &self,
        authorization: &Authorization,
        message: &[u8],
        now: u64,
    ) -> Result<Vec<u8>, CryptoError> {
        let key = self.find_key(&authorization.key_id).ok_or_else(|| {
            CryptoError::new(
                CryptoErrorKind::UnknownKey,
                "authorization references an unregistered key",
            )
        })?;
        if authorization.algorithm_id != key.algorithm_id {
            return Err(CryptoError::new(
                CryptoErrorKind::AlgorithmMismatch,
                format!(
                    "authorization algorithm 0x{:04x} does not match key 0x{:04x}",
                    authorization.algorithm_id, key.algorithm_id
                ),
            ));
        }
        if key.status != KeyStatus::Active {
            return Err(CryptoError::new(
                CryptoErrorKind::KeyNotActive,
                format!("key status is {:?}", key.status),
            ));
        }
        if now < key.valid_from || now >= key.valid_until {
            return Err(CryptoError::new(
                CryptoErrorKind::KeyOutOfWindow,
                "key is outside its validity window",
            ));
        }
        verify_signature(
            key.algorithm_id,
            &key.public_key,
            message,
            &authorization.signature,
        )?;
        Ok(key.key_id.clone())
    }

    /// Evaluates the policy against the signed message.
    ///
    /// Returns the ids of the keys that contributed, so callers can emit a
    /// deterministic audit event. A duplicate authorization for the same key is
    /// an error, which also stops a threshold policy from counting one key twice.
    ///
    /// # Errors
    ///
    /// Returns the first failure from `verify_one`, then
    /// [`CryptoErrorKind::DuplicateAuthorization`] or
    /// [`CryptoErrorKind::PolicyUnsatisfied`].
    pub fn authorize(
        &self,
        message: &[u8],
        authorizations: &[Authorization],
        now: u64,
    ) -> Result<Vec<Vec<u8>>, CryptoError> {
        let mut used: Vec<Vec<u8>> = Vec::new();
        for authorization in authorizations {
            let key_id = self.verify_one(authorization, message, now)?;
            if used.contains(&key_id) {
                return Err(CryptoError::new(
                    CryptoErrorKind::DuplicateAuthorization,
                    "the same key authorized twice",
                ));
            }
            used.push(key_id);
        }

        match self.kind {
            AuthPolicyKind::Single => {
                if authorizations.len() != 1 {
                    return Err(CryptoError::new(
                        CryptoErrorKind::PolicyUnsatisfied,
                        format!(
                            "single policy needs exactly one authorization, got {}",
                            authorizations.len()
                        ),
                    ));
                }
            }
            AuthPolicyKind::All => {
                let mut active = 0usize;
                for key in &self.keys {
                    if key.is_usable(now) {
                        active += 1;
                        if !used.contains(&key.key_id) {
                            return Err(CryptoError::new(
                                CryptoErrorKind::PolicyUnsatisfied,
                                "AND policy requires every active key to authorize",
                            ));
                        }
                    }
                }
                if active == 0 {
                    return Err(CryptoError::new(
                        CryptoErrorKind::PolicyUnsatisfied,
                        "AND policy has no active key",
                    ));
                }
            }
            AuthPolicyKind::Threshold => {
                if self.threshold == 0 {
                    return Err(CryptoError::new(
                        CryptoErrorKind::PolicyUnsatisfied,
                        "threshold policy must have a non-zero threshold",
                    ));
                }
                let mut total: u32 = 0;
                for authorization in authorizations {
                    if let Some(key) = self.find_key(&authorization.key_id) {
                        total += u32::from(key.weight);
                    }
                }
                if total < u32::from(self.threshold) {
                    return Err(CryptoError::new(
                        CryptoErrorKind::PolicyUnsatisfied,
                        format!("threshold {} not met, total weight {total}", self.threshold),
                    ));
                }
            }
        }

        Ok(used)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::registry::{ALG_ED25519, ALG_ML_DSA_65};
    use crypto::scheme::Ed25519Scheme;

    const MESSAGE: &[u8] = b"authorize me";

    fn active_key(key_id: &[u8], public_key: Vec<u8>) -> AuthKey {
        AuthKey {
            key_id: key_id.to_vec(),
            algorithm_id: ALG_ED25519,
            public_key,
            weight: 1,
            status: KeyStatus::Active,
            valid_from: 0,
            valid_until: NO_EXPIRY,
        }
    }

    fn ed25519_authorization(key_id: &[u8], private_key: &[u8]) -> Authorization {
        Authorization {
            algorithm_id: ALG_ED25519,
            key_id: key_id.to_vec(),
            signature: Ed25519Scheme.sign(private_key, MESSAGE).unwrap(),
        }
    }

    fn policy(kind: AuthPolicyKind, keys: Vec<AuthKey>) -> AuthPolicy {
        AuthPolicy {
            kind,
            threshold: 0,
            policy_nonce: 1,
            keys,
        }
    }

    #[test]
    fn single_accepts_one_signature() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = policy(
            AuthPolicyKind::Single,
            vec![active_key(b"k1", public_key.to_vec())],
        );
        let used = policy
            .authorize(MESSAGE, &[ed25519_authorization(b"k1", &private_key)], 100)
            .unwrap();
        assert_eq!(used, vec![b"k1".to_vec()]);
    }

    #[test]
    fn single_rejects_two_authorizations() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let (other_public, other_private) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = policy(
            AuthPolicyKind::Single,
            vec![
                active_key(b"k1", public_key.to_vec()),
                active_key(b"k2", other_public.to_vec()),
            ],
        );
        let error = policy
            .authorize(
                MESSAGE,
                &[
                    ed25519_authorization(b"k1", &private_key),
                    ed25519_authorization(b"k2", &other_private),
                ],
                100,
            )
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn all_requires_every_active_key() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let (other_public, other_private) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = policy(
            AuthPolicyKind::All,
            vec![
                active_key(b"k1", public_key.to_vec()),
                active_key(b"k2", other_public.to_vec()),
            ],
        );

        let both = policy
            .authorize(
                MESSAGE,
                &[
                    ed25519_authorization(b"k1", &private_key),
                    ed25519_authorization(b"k2", &other_private),
                ],
                100,
            )
            .unwrap();
        assert_eq!(both.len(), 2);

        let error = policy
            .authorize(MESSAGE, &[ed25519_authorization(b"k1", &private_key)], 100)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn all_without_active_keys_is_unsatisfied() {
        let policy = policy(AuthPolicyKind::All, Vec::new());
        let error = policy.authorize(MESSAGE, &[], 100).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn threshold_counts_weight() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let (other_public, other_private) = Ed25519Scheme::generate_keypair().unwrap();
        let mut heavy = active_key(b"k2", other_public.to_vec());
        heavy.weight = 2;

        let policy = AuthPolicy {
            kind: AuthPolicyKind::Threshold,
            threshold: 2,
            policy_nonce: 1,
            keys: vec![active_key(b"k1", public_key.to_vec()), heavy],
        };

        // One key with weight 2 meets the threshold.
        let used = policy
            .authorize(
                MESSAGE,
                &[ed25519_authorization(b"k2", &other_private)],
                100,
            )
            .unwrap();
        assert_eq!(used, vec![b"k2".to_vec()]);

        // One key with weight 1 does not.
        let error = policy
            .authorize(MESSAGE, &[ed25519_authorization(b"k1", &private_key)], 100)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn threshold_zero_is_rejected() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = AuthPolicy {
            kind: AuthPolicyKind::Threshold,
            threshold: 0,
            policy_nonce: 1,
            keys: vec![active_key(b"k1", public_key.to_vec())],
        };
        let error = policy
            .authorize(MESSAGE, &[ed25519_authorization(b"k1", &private_key)], 100)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::PolicyUnsatisfied);
    }

    #[test]
    fn duplicate_authorization_is_rejected() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = policy(
            AuthPolicyKind::Single,
            vec![active_key(b"k1", public_key.to_vec())],
        );
        let authorization = ed25519_authorization(b"k1", &private_key);
        let error = policy
            .authorize(MESSAGE, &[authorization.clone(), authorization], 100)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::DuplicateAuthorization);
    }

    #[test]
    fn expired_key_is_rejected() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let mut key = active_key(b"k1", public_key.to_vec());
        key.valid_until = 500;
        let policy = policy(AuthPolicyKind::Single, vec![key]);
        let error = policy
            .authorize(MESSAGE, &[ed25519_authorization(b"k1", &private_key)], 1000)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyOutOfWindow);
    }

    #[test]
    fn retired_key_is_rejected() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let mut key = active_key(b"k1", public_key.to_vec());
        key.status = KeyStatus::Retired;
        let policy = policy(AuthPolicyKind::Single, vec![key]);
        let error = policy
            .authorize(MESSAGE, &[ed25519_authorization(b"k1", &private_key)], 100)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::KeyNotActive);
    }

    #[test]
    fn unknown_key_is_rejected() {
        let (_, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = policy(AuthPolicyKind::Single, Vec::new());
        let error = policy
            .authorize(
                MESSAGE,
                &[ed25519_authorization(b"missing", &private_key)],
                100,
            )
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::UnknownKey);
    }

    #[test]
    fn algorithm_mismatch_is_rejected() {
        let (public_key, private_key) = Ed25519Scheme::generate_keypair().unwrap();
        let policy = policy(
            AuthPolicyKind::Single,
            vec![active_key(b"k1", public_key.to_vec())],
        );
        let mut authorization = ed25519_authorization(b"k1", &private_key);
        authorization.algorithm_id = ALG_ML_DSA_65;
        let error = policy
            .authorize(MESSAGE, &[authorization], 100)
            .unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::AlgorithmMismatch);
    }

    #[test]
    fn ml_dsa_key_fails_closed() {
        // Zero bytes are not a valid ML-DSA key or signature. Whether the failure
        // is "not enabled" or "did not verify" depends on the build features, but
        // it must never be accepted.
        let policy = policy(
            AuthPolicyKind::Single,
            vec![AuthKey {
                key_id: b"pq1".to_vec(),
                algorithm_id: ALG_ML_DSA_65,
                public_key: vec![0u8; 1952],
                weight: 1,
                status: KeyStatus::Active,
                valid_from: 0,
                valid_until: NO_EXPIRY,
            }],
        );
        let authorization = Authorization {
            algorithm_id: ALG_ML_DSA_65,
            key_id: b"pq1".to_vec(),
            signature: vec![0u8; 3309],
        };
        let error = policy
            .authorize(MESSAGE, &[authorization], 100)
            .unwrap_err();
        if crypto::registry::ml_dsa_enabled() {
            assert!(
                matches!(
                    error.kind(),
                    CryptoErrorKind::InvalidSignature
                        | CryptoErrorKind::MalformedPublicKey
                        | CryptoErrorKind::BackendFailure
                ),
                "unexpected error kind {:?}",
                error.kind()
            );
        } else {
            assert_eq!(error.kind(), CryptoErrorKind::AlgorithmNotEnabled);
        }
    }
}
