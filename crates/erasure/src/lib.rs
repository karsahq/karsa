//! Reed-Solomon erasure coding over GF(2^8).
//!
//! Erasure coding is how a node stores or sends `1/n` of a payload instead of all
//! of it. The payload is split into `data` shards; `total - data` parity shards are
//! derived from them; and any `data` of the `total` shards reconstruct the whole
//! payload. Losing up to `total - data` shards is therefore free, which is what
//! makes a slow or absent node stop mattering to data availability.
//!
//! # The code
//!
//! Non-systematic Vandermonde over GF(2^8): the `data` input shards are the
//! coefficients of a polynomial, and shard `j` is that polynomial evaluated at the
//! field element `j`. Any `data` points determine the polynomial, so any `data`
//! shards decode. No shard equals its input slice, which costs nothing here because
//! nothing reads a shard directly.
//!
//! `total` is capped at 256, the number of distinct evaluation points in the field.
//! That is above any committee size this experiment considers, and the cap is
//! enforced rather than assumed.
//!
//! # What this is not
//!
//! GF(2^8) limits shard-count to 256 and is measurably slower than the SIMD
//! GF(2^16) implementations used in production testbeds. It is chosen here because
//! it is small enough to read, test, and trust, and because correctness of the
//! reconstruction path matters more than throughput at this stage.

use std::error::Error;
use std::fmt;

/// Primitive polynomial `x^8 + x^4 + x^3 + x^2 + 1`.
const POLYNOMIAL: u16 = 0x11d;
/// Order of the multiplicative group.
const ORDER: usize = 255;

/// Why an erasure operation could not be performed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErasureError {
    /// `data` shards must be at least one.
    NoDataShards,
    /// `total` must be greater than `data`.
    NoParity,
    /// `total` must not exceed the 256 points the field provides.
    TooManyShards,
    /// Fewer shards than `data` were supplied, or their indices repeat.
    NotEnoughShards,
    /// The shards supplied have inconsistent lengths.
    RaggedShards,
    /// A shard index is outside `0..total`.
    IndexOutOfRange,
}

impl fmt::Display for ErasureError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NoDataShards => "at least one data shard is required",
            Self::NoParity => "total must exceed data so that a shard can be lost",
            Self::TooManyShards => "GF(2^8) provides at most 256 distinct shards",
            Self::NotEnoughShards => "not enough distinct shards to reconstruct",
            Self::RaggedShards => "shards have inconsistent lengths",
            Self::IndexOutOfRange => "shard index is outside the code",
        })
    }
}

impl Error for ErasureError {}

/// A Reed-Solomon code with `data` input shards and `total` output shards.
#[derive(Debug, Clone)]
pub struct Code {
    data: usize,
    total: usize,
    exp: [u8; ORDER * 2],
    log: [u8; 256],
}

impl Code {
    /// Builds a code that tolerates `total - data` lost shards.
    ///
    /// # Errors
    ///
    /// [`ErasureError::NoDataShards`], [`ErasureError::NoParity`], or
    /// [`ErasureError::TooManyShards`].
    pub fn new(data: usize, total: usize) -> Result<Self, ErasureError> {
        if data == 0 {
            return Err(ErasureError::NoDataShards);
        }
        if total <= data {
            return Err(ErasureError::NoParity);
        }
        if total > 256 {
            return Err(ErasureError::TooManyShards);
        }

        let mut exp = [0u8; ORDER * 2];
        let mut log = [0u8; 256];
        let mut value: u16 = 1;
        for power in 0..ORDER {
            exp[power] = u8::try_from(value).expect("value stays below 256");
            log[usize::from(exp[power])] = u8::try_from(power).expect("power stays below 255");
            value <<= 1;
            if value & 0x100 != 0 {
                value ^= POLYNOMIAL;
            }
        }
        // Doubling the table removes the modulo from every addition.
        for power in ORDER..ORDER * 2 {
            exp[power] = exp[power - ORDER];
        }

        Ok(Self {
            data,
            total,
            exp,
            log,
        })
    }

    /// Number of input shards.
    #[must_use]
    pub fn data(&self) -> usize {
        self.data
    }

    /// Number of output shards.
    #[must_use]
    pub fn total(&self) -> usize {
        self.total
    }

    /// How many shards may be lost.
    #[must_use]
    pub fn tolerance(&self) -> usize {
        self.total - self.data
    }

    /// Size of one shard for a payload of `bytes`.
    #[must_use]
    pub fn shard_len(&self, bytes: usize) -> usize {
        bytes.div_ceil(self.data)
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 {
            return 0;
        }
        let sum = usize::from(self.log[usize::from(a)]) + usize::from(self.log[usize::from(b)]);
        self.exp[sum]
    }

    /// Precomputes `value * scalar` for every value, so the inner loop is one
    /// table lookup instead of a log, an add, and an exponent lookup.
    fn mul_table(&self, scalar: u8) -> [u8; 256] {
        let mut table = [0u8; 256];
        if scalar == 0 {
            return table;
        }
        for value in 1..256u16 {
            table[usize::from(value)] = self.mul(u8::try_from(value).expect("below 256"), scalar);
        }
        table
    }

    fn inv(&self, a: u8) -> u8 {
        debug_assert!(a != 0, "zero has no inverse");
        self.exp[ORDER - usize::from(self.log[usize::from(a)])]
    }

    /// Splits `payload` into `data` padded input shards.
    fn input_shards(&self, payload: &[u8]) -> (Vec<Vec<u8>>, usize) {
        let shard_len = self.shard_len(payload.len()).max(1);
        let mut shards = vec![vec![0u8; shard_len]; self.data];
        for (index, byte) in payload.iter().enumerate() {
            shards[index / shard_len][index % shard_len] = *byte;
        }
        (shards, payload.len())
    }

    /// Encodes `payload` into `total` shards.
    ///
    /// The original length is needed to trim the padding on the way back, so it is
    /// returned with the shards rather than guessed.
    ///
    /// # Errors
    ///
    /// Propagates shard-construction errors; this implementation cannot fail after
    /// construction.
    pub fn encode(&self, payload: &[u8]) -> Result<Encoded, ErasureError> {
        let (inputs, length) = self.input_shards(payload);
        let shard_len = inputs.first().map_or(0, Vec::len);

        // Shard j is the polynomial with the input shards as coefficients,
        // evaluated at the field element j.
        let mut shards = Vec::with_capacity(self.total);
        for point in 0..self.total {
            let x = u8::try_from(point).expect("total is at most 256");
            let table = self.mul_table(x);
            let mut shard = vec![0u8; shard_len];
            // Horner: start from the highest coefficient.
            for coefficient in inputs.iter().rev() {
                for (target, source) in shard.iter_mut().zip(coefficient.iter()) {
                    *target = table[usize::from(*target)] ^ *source;
                }
            }
            shards.push(shard);
        }

        Ok(Encoded { shards, length })
    }

    /// Reconstructs the payload from any `data` distinct shards.
    ///
    /// # Errors
    ///
    /// [`ErasureError::NotEnoughShards`], [`ErasureError::IndexOutOfRange`], or
    /// [`ErasureError::RaggedShards`].
    pub fn decode(
        &self,
        shards: &[(usize, &[u8])],
        length: usize,
    ) -> Result<Vec<u8>, ErasureError> {
        if shards.len() < self.data {
            return Err(ErasureError::NotEnoughShards);
        }
        let shard_len = shards.first().map_or(0, |(_, bytes)| bytes.len());
        if shards.iter().any(|(_, bytes)| bytes.len() != shard_len) {
            return Err(ErasureError::RaggedShards);
        }

        // Take exactly `data` shards and invert the Vandermonde they form.
        let chosen = &shards[..self.data];
        let mut seen = [false; 256];
        for (index, _) in chosen {
            if *index >= self.total {
                return Err(ErasureError::IndexOutOfRange);
            }
            if seen[*index] {
                return Err(ErasureError::NotEnoughShards);
            }
            seen[*index] = true;
        }

        // Each chosen shard index gives one row `[1, x, x², …]` of the Vandermonde
        // matrix; the identity on the right turns the inversion into a solver.
        let mut matrix: Vec<Vec<u8>> = chosen
            .iter()
            .map(|(index, _)| {
                let x = u8::try_from(*index).expect("index is below 256");
                let mut row = vec![0u8; self.data * 2];
                let mut power = 1u8;
                for cell in row.iter_mut().take(self.data) {
                    *cell = power;
                    power = self.mul(power, x);
                }
                row
            })
            .collect();
        for (row_index, row) in matrix.iter_mut().enumerate() {
            row[self.data + row_index] = 1;
        }

        self.invert(&mut matrix);

        let mut recovered = vec![vec![0u8; shard_len]; self.data];
        for (coefficient_index, target) in recovered.iter_mut().enumerate() {
            for (source_index, (_, bytes)) in chosen.iter().enumerate() {
                let factor = matrix[coefficient_index][self.data + source_index];
                let table = self.mul_table(factor);
                for (out, byte) in target.iter_mut().zip(bytes.iter()) {
                    *out ^= table[usize::from(*byte)];
                }
            }
        }

        let mut payload = Vec::with_capacity(length);
        for shard in &recovered {
            payload.extend_from_slice(shard);
        }
        payload.truncate(length);
        Ok(payload)
    }

    /// Gauss-Jordan inversion of the left half, applied to the right half.
    fn invert(&self, matrix: &mut [Vec<u8>]) {
        let size = self.data;
        for pivot in 0..size {
            if matrix[pivot][pivot] == 0 {
                // A Vandermonde over distinct points is always invertible, so this
                // can only happen if the caller supplied duplicate indices, which
                // the caller rejects first.
                continue;
            }
            let scale = self.inv(matrix[pivot][pivot]);
            for value in matrix[pivot].iter_mut() {
                *value = self.mul(*value, scale);
            }
            // The pivot row is read while other rows are written, so it is copied
            // out rather than borrowed alongside them.
            let pivot_row = matrix[pivot].clone();
            for (row_index, row) in matrix.iter_mut().enumerate() {
                if row_index == pivot {
                    continue;
                }
                let factor = row[pivot];
                if factor == 0 {
                    continue;
                }
                for (value, source) in row.iter_mut().zip(pivot_row.iter()) {
                    *value ^= self.mul(factor, *source);
                }
            }
        }
    }
}

/// Encoded shards plus the length of the original payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Encoded {
    /// `total` shards, each the same length.
    pub shards: Vec<Vec<u8>>,
    /// Length of the payload before padding.
    pub length: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(bytes: usize) -> Vec<u8> {
        (0..bytes)
            .map(|index| u8::try_from(index % 251).expect("below 251"))
            .collect()
    }

    #[test]
    fn a_payload_roundtrips_through_every_shard_count() {
        let bytes = payload(1_000);
        for (data, total) in [(1, 2), (2, 3), (4, 6), (10, 16), (16, 24)] {
            let code = Code::new(data, total).unwrap();
            let encoded = code.encode(&bytes).unwrap();
            assert_eq!(encoded.shards.len(), total);
            let all: Vec<(usize, &[u8])> = encoded
                .shards
                .iter()
                .enumerate()
                .map(|(index, shard)| (index, shard.as_slice()))
                .collect();
            assert_eq!(
                code.decode(&all, encoded.length).unwrap(),
                bytes,
                "{data}/{total} did not roundtrip"
            );
        }
    }

    #[test]
    fn any_data_shards_reconstruct() {
        let bytes = payload(777);
        let code = Code::new(4, 6).unwrap();
        let encoded = code.encode(&bytes).unwrap();

        // Every 4-subset of the 6 shards must decode.
        for a in 0..6 {
            for b in (a + 1)..6 {
                for c in (b + 1)..6 {
                    for d in (c + 1)..6 {
                        let subset = [
                            (a, encoded.shards[a].as_slice()),
                            (b, encoded.shards[b].as_slice()),
                            (c, encoded.shards[c].as_slice()),
                            (d, encoded.shards[d].as_slice()),
                        ];
                        assert_eq!(
                            code.decode(&subset, encoded.length).unwrap(),
                            bytes,
                            "subset {a}{b}{c}{d} failed"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn a_payload_survives_losing_the_parity_shards() {
        let bytes = payload(500);
        let code = Code::new(3, 5).unwrap();
        let encoded = code.encode(&bytes).unwrap();
        let inputs: Vec<(usize, &[u8])> = encoded.shards[..3]
            .iter()
            .enumerate()
            .map(|(index, shard)| (index, shard.as_slice()))
            .collect();
        assert_eq!(code.decode(&inputs, encoded.length).unwrap(), bytes);
    }

    #[test]
    fn a_payload_survives_losing_the_data_shards() {
        let bytes = payload(500);
        // 2 of 4: the two parity shards alone must reconstruct the payload.
        let code = Code::new(2, 4).unwrap();
        let encoded = code.encode(&bytes).unwrap();
        let parity: Vec<(usize, &[u8])> = encoded.shards[2..]
            .iter()
            .enumerate()
            .map(|(offset, shard)| (offset + 2, shard.as_slice()))
            .collect();
        assert_eq!(code.decode(&parity, encoded.length).unwrap(), bytes);
    }

    #[test]
    fn too_few_shards_are_refused() {
        let code = Code::new(4, 6).unwrap();
        let encoded = code.encode(&payload(100)).unwrap();
        let two: Vec<(usize, &[u8])> = encoded.shards[..2]
            .iter()
            .enumerate()
            .map(|(index, shard)| (index, shard.as_slice()))
            .collect();
        assert_eq!(
            code.decode(&two, encoded.length),
            Err(ErasureError::NotEnoughShards)
        );
    }

    #[test]
    fn duplicate_indices_are_refused() {
        let code = Code::new(2, 4).unwrap();
        let encoded = code.encode(&payload(64)).unwrap();
        let duplicated = [
            (1, encoded.shards[1].as_slice()),
            (1, encoded.shards[1].as_slice()),
        ];
        assert_eq!(
            code.decode(&duplicated, encoded.length),
            Err(ErasureError::NotEnoughShards)
        );
    }

    #[test]
    fn degenerate_codes_are_refused() {
        assert_eq!(Code::new(0, 4).unwrap_err(), ErasureError::NoDataShards);
        assert_eq!(Code::new(4, 4).unwrap_err(), ErasureError::NoParity);
        assert_eq!(Code::new(4, 257).unwrap_err(), ErasureError::TooManyShards);
    }

    #[test]
    fn an_empty_payload_roundtrips() {
        let code = Code::new(2, 4).unwrap();
        let encoded = code.encode(&[]).unwrap();
        let all: Vec<(usize, &[u8])> = encoded
            .shards
            .iter()
            .enumerate()
            .map(|(index, shard)| (index, shard.as_slice()))
            .collect();
        assert_eq!(code.decode(&all, 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn the_overhead_is_total_over_data() {
        let code = Code::new(32, 48).unwrap();
        let bytes = payload(10_000);
        let encoded = code.encode(&bytes).unwrap();
        let wire: usize = encoded.shards.iter().map(Vec::len).sum();
        let expected = bytes.len().div_ceil(32) * 48;
        assert_eq!(wire, expected, "shards carry padding, as they must");
        assert_eq!(code.tolerance(), 16);
    }
}
