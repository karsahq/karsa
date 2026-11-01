//! Deterministic canonical encoding.
//!
//! Fixed-width little-endian integers and length-prefixed byte fields, as
//! specified in `docs/crypto-registry.md` §3. Two different values
//! never encode to the same bytes, and a decoder rejects truncated input,
//! trailing bytes, and oversized fields instead of repairing them.

use crate::error::{CryptoError, CryptoErrorKind};

/// The largest single length-prefixed field, in bytes (1 MiB).
pub const MAX_FIELD_LEN: usize = 1 << 20;

/// Writes the canonical encoding.
#[derive(Debug, Default, Clone)]
pub struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    /// Creates an empty encoder.
    #[must_use]
    pub const fn new() -> Self {
        Self { buf: Vec::new() }
    }

    /// Creates an empty encoder with room for `capacity` bytes.
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            buf: Vec::with_capacity(capacity),
        }
    }

    /// Appends one byte.
    pub fn put_u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    /// Appends a `u16` in little-endian order.
    pub fn put_u16(&mut self, value: u16) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a `u32` in little-endian order.
    pub fn put_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a `u64` in little-endian order.
    pub fn put_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    /// Appends a `u32` length prefix followed by the bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::FieldTooLong`] when `data` exceeds
    /// [`MAX_FIELD_LEN`]. The check also makes the `u32` cast lossless.
    pub fn put_bytes(&mut self, data: &[u8]) -> Result<(), CryptoError> {
        if data.len() > MAX_FIELD_LEN {
            return Err(CryptoError::new(
                CryptoErrorKind::FieldTooLong,
                format!("field of {} bytes exceeds {MAX_FIELD_LEN}", data.len()),
            ));
        }
        let len = u32::try_from(data.len()).map_err(|_| {
            CryptoError::new(
                CryptoErrorKind::FieldTooLong,
                format!("field of {} bytes does not fit a u32", data.len()),
            )
        })?;
        self.put_u32(len);
        self.buf.extend_from_slice(data);
        Ok(())
    }

    /// Appends bytes with no length prefix.
    ///
    /// Use this only for an already-canonical body, as [`crate::domain`] does
    /// when it prefixes a domain tag.
    pub fn put_raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Returns the encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    /// Returns the bytes written so far without consuming the encoder.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    /// Returns the number of bytes written so far.
    #[must_use]
    pub fn len(&self) -> usize {
        self.buf.len()
    }

    /// Returns whether nothing has been written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// Reads the canonical encoding. Every read is bounds-checked.
#[derive(Debug, Clone)]
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    /// Prepares a decoder over `buf`. The buffer is not copied.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], CryptoError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| CryptoError::new(CryptoErrorKind::TruncatedInput, "length overflow"))?;
        if end > self.buf.len() {
            return Err(CryptoError::new(
                CryptoErrorKind::TruncatedInput,
                format!(
                    "need {len} bytes at offset {}, have {}",
                    self.pos,
                    self.buf.len() - self.pos
                ),
            ));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Reads one byte.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`] when the buffer ends.
    pub fn read_u8(&mut self) -> Result<u8, CryptoError> {
        Ok(self.take(1)?[0])
    }

    /// Reads a little-endian `u16`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`] when the buffer ends.
    pub fn read_u16(&mut self) -> Result<u16, CryptoError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Reads a little-endian `u32`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`] when the buffer ends.
    pub fn read_u32(&mut self) -> Result<u32, CryptoError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Reads a little-endian `u64`.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TruncatedInput`] when the buffer ends.
    pub fn read_u64(&mut self) -> Result<u64, CryptoError> {
        let bytes = self.take(8)?;
        let mut array = [0u8; 8];
        array.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(array))
    }

    /// Reads a length-prefixed byte field.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::FieldTooLong`] when the claimed length exceeds
    /// [`MAX_FIELD_LEN`], and [`CryptoErrorKind::TruncatedInput`] when the bytes
    /// are not present.
    pub fn read_bytes(&mut self) -> Result<&'a [u8], CryptoError> {
        let len = self.read_u32()? as usize;
        if len > MAX_FIELD_LEN {
            return Err(CryptoError::new(
                CryptoErrorKind::FieldTooLong,
                format!("field claims {len} bytes, limit is {MAX_FIELD_LEN}"),
            ));
        }
        self.take(len)
    }

    /// Returns how many bytes are unread.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Checks that the whole buffer was consumed.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoErrorKind::TrailingBytes`] when input remains. Trailing
    /// bytes are never ignored: they would let two distinct inputs share a parse.
    pub fn finish(self) -> Result<(), CryptoError> {
        if self.pos != self.buf.len() {
            return Err(CryptoError::new(
                CryptoErrorKind::TrailingBytes,
                format!(
                    "{} bytes left after offset {}",
                    self.buf.len() - self.pos,
                    self.pos
                ),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_prefix_disambiguates_concatenation() {
        let mut a = Encoder::new();
        a.put_bytes(b"ab").unwrap();
        a.put_bytes(b"c").unwrap();

        let mut b = Encoder::new();
        b.put_bytes(b"a").unwrap();
        b.put_bytes(b"bc").unwrap();

        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn integers_roundtrip_as_little_endian() {
        let mut encoder = Encoder::new();
        encoder.put_u16(0x1234);
        encoder.put_u32(0x7abc_def1);
        encoder.put_u64(0x0102_0304_0506_0708);
        let data = encoder.finish();

        assert_eq!(data.len(), 14);
        assert_eq!(&data[0..2], &[0x34, 0x12]);
        assert_eq!(&data[2..6], &[0xf1, 0xde, 0xbc, 0x7a]);

        let mut decoder = Decoder::new(&data);
        assert_eq!(decoder.read_u16().unwrap(), 0x1234);
        assert_eq!(decoder.read_u32().unwrap(), 0x7abc_def1);
        assert_eq!(decoder.read_u64().unwrap(), 0x0102_0304_0506_0708);
        decoder.finish().unwrap();
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut encoder = Encoder::new();
        encoder.put_u32(4); // claims four payload bytes, provides none
        let data = encoder.finish();

        let mut decoder = Decoder::new(&data);
        let error = decoder.read_bytes().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TruncatedInput);
    }

    #[test]
    fn trailing_bytes_are_rejected() {
        let mut encoder = Encoder::new();
        encoder.put_u16(1);
        let mut data = encoder.finish();
        data.push(0);

        let mut decoder = Decoder::new(&data);
        decoder.read_u16().unwrap();
        let error = decoder.finish().unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::TrailingBytes);
    }

    #[test]
    fn oversized_field_is_rejected() {
        let oversized = vec![0u8; MAX_FIELD_LEN + 1];
        let mut encoder = Encoder::new();
        let error = encoder.put_bytes(&oversized).unwrap_err();
        assert_eq!(error.kind(), CryptoErrorKind::FieldTooLong);
    }
}
