//! A batch of transactions: the unit a vertex names by digest.
//!
//! Ordering and payload travel separately. A vertex carries only a batch digest,
//! so consensus messages stay small and identical to their measured sizes, while
//! the batch itself moves once through a data plane. That is the Narwhal split,
//! and it is the reason a 331 KB certificate problem does not reappear here.
//!
//! A batch is encoded canonically so that two nodes that build the same batch
//! compute the same digest, and therefore the same vertex payload hash.

use crypto::encoding::{Decoder, Encoder};
use crypto::{CryptoError, CryptoErrorKind};
use sha2::{Digest, Sha256};

use crate::envelope::Transaction;

/// The bound on the number of transactions in one batch.
///
/// This is a decode limit, not a target: it stops hostile input from making a
/// decoder allocate without bound.
pub const MAX_BATCH_TRANSACTIONS: usize = 4096;

/// One ordered list of transactions.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Batch {
    /// Transactions, in the order they will be executed.
    pub transactions: Vec<Transaction>,
}

impl Batch {
    /// Creates a batch from an ordered list.
    #[must_use]
    pub fn new(transactions: Vec<Transaction>) -> Self {
        Self { transactions }
    }

    /// Number of transactions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.transactions.len()
    }

    /// Whether the batch holds no transaction.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.transactions.is_empty()
    }

    /// Writes the canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::FieldTooLong`] above
    /// [`MAX_BATCH_TRANSACTIONS`], and propagates transaction encoding errors.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        if self.transactions.len() > MAX_BATCH_TRANSACTIONS {
            return Err(CryptoError::new(
                CryptoErrorKind::FieldTooLong,
                format!(
                    "{} transactions exceed {MAX_BATCH_TRANSACTIONS}",
                    self.transactions.len()
                ),
            ));
        }
        let count = u32::try_from(self.transactions.len()).map_err(|_| {
            CryptoError::new(
                CryptoErrorKind::FieldTooLong,
                "transaction count does not fit a u32",
            )
        })?;

        let mut encoder = Encoder::with_capacity(8 + self.transactions.len() * 256);
        encoder.put_u32(count);
        for transaction in &self.transactions {
            encoder.put_bytes(&transaction.encode()?)?;
        }
        Ok(encoder.finish())
    }

    /// Reads a canonical encoding.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`],
    /// [`CryptoErrorKind::TrailingBytes`], [`CryptoErrorKind::FieldTooLong`], or a
    /// transaction decode error.
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let count = decoder.read_u32()? as usize;
        if count > MAX_BATCH_TRANSACTIONS {
            return Err(CryptoError::new(
                CryptoErrorKind::FieldTooLong,
                format!("{count} transactions exceed {MAX_BATCH_TRANSACTIONS}"),
            ));
        }
        let mut transactions = Vec::with_capacity(count.min(64));
        for _ in 0..count {
            transactions.push(Transaction::decode(decoder.read_bytes()?)?);
        }
        decoder.finish()?;
        Ok(Self { transactions })
    }

    /// The content address of the batch: SHA-256 of its canonical encoding.
    ///
    /// # Errors
    ///
    /// Propagates [`Batch::encode`].
    pub fn digest(&self) -> Result<[u8; 32], CryptoError> {
        Ok(Sha256::digest(self.encode()?).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::PROTOCOL_VERSION_V1;

    fn transaction(sequence: u64, payload: &[u8]) -> Transaction {
        Transaction {
            protocol_version: PROTOCOL_VERSION_V1,
            chain_id: b"karsa-batch-1".to_vec(),
            sender: b"alice".to_vec(),
            sequence,
            fee: 1,
            expiration: 100,
            policy_version: 1,
            payload: payload.to_vec(),
            authorization: Vec::new(),
        }
    }

    #[test]
    fn a_batch_roundtrips() {
        let batch = Batch::new(vec![transaction(1, b"one"), transaction(2, b"two")]);
        let encoded = batch.encode().unwrap();
        assert_eq!(Batch::decode(&encoded).unwrap(), batch);
    }

    #[test]
    fn an_empty_batch_roundtrips() {
        let encoded = Batch::default().encode().unwrap();
        assert_eq!(Batch::decode(&encoded).unwrap(), Batch::default());
    }

    #[test]
    fn the_digest_covers_order() {
        let first = Batch::new(vec![transaction(1, b"one"), transaction(2, b"two")]);
        let swapped = Batch::new(vec![transaction(2, b"two"), transaction(1, b"one")]);
        assert_ne!(first.digest().unwrap(), swapped.digest().unwrap());
    }

    #[test]
    fn the_digest_is_stable_across_decoding() {
        let batch = Batch::new(vec![transaction(7, b"payload")]);
        let decoded = Batch::decode(&batch.encode().unwrap()).unwrap();
        assert_eq!(decoded.digest().unwrap(), batch.digest().unwrap());
    }

    #[test]
    fn a_batch_with_a_broken_transaction_does_not_decode() {
        let batch = Batch::new(vec![transaction(1, b"one")]);
        let mut encoded = batch.encode().unwrap();
        encoded.pop();
        assert!(Batch::decode(&encoded).is_err());
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = Batch::default().encode().unwrap();
        encoded.push(0);
        let error = Batch::decode(&encoded).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TrailingBytes);
    }
}
