//! A `Transfer` payload: the only application message this experiment executes.
//!
//! The envelope deliberately carries an opaque `payload`, so the transfer format
//! lives here rather than in `tx`. It is canonical for the same reason everything
//! else is: two nodes must hash the same bytes from the same transfer.

use crypto::CryptoError;
use crypto::encoding::{Decoder, Encoder};

/// A value transfer from the envelope's sender to `to`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transfer {
    /// Recipient account identifier.
    pub to: Vec<u8>,
    /// Amount moved, in the smallest unit.
    pub amount: u64,
}

impl Transfer {
    /// Creates a transfer.
    #[must_use]
    pub fn new(to: impl Into<Vec<u8>>, amount: u64) -> Self {
        Self {
            to: to.into(),
            amount,
        }
    }

    /// Writes the canonical payload encoding.
    ///
    /// # Errors
    ///
    /// Returns a field error when the recipient identifier is too long.
    pub fn encode(&self) -> Result<Vec<u8>, CryptoError> {
        let mut encoder = Encoder::with_capacity(16 + self.to.len());
        encoder.put_bytes(&self.to)?;
        encoder.put_u64(self.amount);
        Ok(encoder.finish())
    }

    /// Reads a canonical payload encoding.
    ///
    /// # Errors
    ///
    /// Returns [`crypto::CryptoErrorKind::TruncatedInput`] or
    /// [`crypto::CryptoErrorKind::TrailingBytes`].
    pub fn decode(bytes: &[u8]) -> Result<Self, CryptoError> {
        let mut decoder = Decoder::new(bytes);
        let to = decoder.read_bytes()?.to_vec();
        let amount = decoder.read_u64()?;
        decoder.finish()?;
        Ok(Self { to, amount })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::CryptoErrorKind;

    #[test]
    fn a_transfer_roundtrips() {
        let transfer = Transfer::new(b"bob".to_vec(), 250);
        let encoded = transfer.encode().unwrap();
        assert_eq!(Transfer::decode(&encoded).unwrap(), transfer);
    }

    #[test]
    fn a_truncated_transfer_does_not_decode() {
        let mut encoded = Transfer::new(b"bob".to_vec(), 250).encode().unwrap();
        encoded.pop();
        assert_eq!(
            Transfer::decode(&encoded).unwrap_err().kind(),
            CryptoErrorKind::TruncatedInput
        );
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoded = Transfer::new(b"bob".to_vec(), 250).encode().unwrap();
        encoded.push(0);
        assert_eq!(
            Transfer::decode(&encoded).unwrap_err().kind(),
            CryptoErrorKind::TrailingBytes
        );
    }
}
