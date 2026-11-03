//! How an account address is written for people.
//!
//! The identity is the 32 bytes `AuthPolicy::address` derives; this module only
//! changes how those bytes are typed, copied, and compared. Base58Check is used
//! deliberately rather than a Cosmos-style `chain1...` string or an EVM `0x...`:
//!
//! - There is no word prefix, so an address does not claim to be another chain's.
//! - A two-byte version identifies this chain and is chosen so addresses begin
//!   with `K`, which is recognisable without reading the whole string.
//! - Four checksum bytes catch the mistyped or truncated copy that happens when
//!   someone pastes an address into an explorer.
//! - Base58 excludes `0`, `O`, `I`, and `l`, so the characters most often confused
//!   by eye cannot appear at all.
//!
//! ```text
//! base58( version[2] || address[32] || sha256(sha256(version || address))[..4] )
//! ```
//!
//! The text is display only. State keys, the wire, and the genesis hash all use
//! the 32 bytes it decodes to, so changing this format does not move an account.

use sha2::{Digest, Sha256};

/// Version bytes for this chain's account addresses.
///
/// Two bytes, and these two in particular, because a one-byte version lets the
/// first character drift with the payload. This pair keeps every address starting
/// with `K` while remaining a plain Base58Check payload: version, address,
/// checksum.
pub const VERSION: [u8; 2] = [0x02, 0x1a];

/// Base58 alphabet: Bitcoin's, without `0`, `O`, `I`, and `l`.
const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Why a string is not an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// The string is empty.
    Empty,
    /// A character is outside the base58 alphabet.
    BadCharacter(char),
    /// The checksum does not match the payload.
    BadChecksum,
    /// The version bytes belong to another chain.
    WrongVersion([u8; 2]),
    /// The decoded payload is not a 32-byte address.
    WrongLength(usize),
}

impl std::fmt::Display for AddressError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(formatter, "address is empty"),
            Self::BadCharacter(character) => {
                write!(
                    formatter,
                    "character {character} is outside the base58 alphabet"
                )
            }
            Self::BadChecksum => write!(formatter, "checksum does not match"),
            Self::WrongVersion(version) => write!(
                formatter,
                "version is {:02x}{:02x}, this chain uses {:02x}{:02x}",
                version[0], version[1], VERSION[0], VERSION[1]
            ),
            Self::WrongLength(length) => {
                write!(formatter, "address payload is {length} bytes, expected 32")
            }
        }
    }
}

impl std::error::Error for AddressError {}

/// Encodes 32 bytes as a `K...` Base58Check string.
#[must_use]
pub fn encode(bytes: &[u8; 32]) -> String {
    encode_payload(VERSION, bytes)
}

/// Decodes an address, checking base58, checksum, version, and length.
///
/// # Errors
///
/// Every [`AddressError`]: empty input, a character outside the alphabet, a bad
/// checksum, another chain's version bytes, or a payload that is not 32 bytes.
pub fn decode(text: &str) -> Result<[u8; 32], AddressError> {
    if text.is_empty() {
        return Err(AddressError::Empty);
    }
    let bytes = base58_decode(text)?;
    if bytes.len() < 6 {
        return Err(AddressError::WrongLength(bytes.len().saturating_sub(2)));
    }
    let (payload, check) = bytes.split_at(bytes.len() - 4);
    if checksum(payload) != check {
        return Err(AddressError::BadChecksum);
    }
    if payload.len() != VERSION.len() + 32 {
        return Err(AddressError::WrongLength(
            payload.len().saturating_sub(VERSION.len()),
        ));
    }
    if payload[0] != VERSION[0] || payload[1] != VERSION[1] {
        return Err(AddressError::WrongVersion([payload[0], payload[1]]));
    }
    <[u8; 32]>::try_from(&payload[VERSION.len()..])
        .map_err(|_| AddressError::WrongLength(payload.len() - VERSION.len()))
}

fn encode_payload(version: [u8; 2], data: &[u8]) -> String {
    let mut payload = Vec::with_capacity(version.len() + data.len() + 4);
    payload.extend_from_slice(&version);
    payload.extend_from_slice(data);
    let check = checksum(&payload);
    payload.extend_from_slice(&check);
    base58_encode(&payload)
}

/// Base58Check's double-SHA-256 checksum, truncated to four bytes.
fn checksum(payload: &[u8]) -> [u8; 4] {
    let first = Sha256::digest(payload);
    let second = Sha256::digest(first);
    [second[0], second[1], second[2], second[3]]
}

fn base58_encode(input: &[u8]) -> String {
    let zeros = input.iter().take_while(|byte| **byte == 0).count();
    // Little-endian base58 digits.
    let mut digits: Vec<u8> = Vec::new();
    for byte in &input[zeros..] {
        let mut carry = u32::from(*byte);
        for digit in &mut digits {
            carry += u32::from(*digit) << 8;
            *digit = u8::try_from(carry % 58).unwrap_or(0);
            carry /= 58;
        }
        while carry > 0 {
            digits.push(u8::try_from(carry % 58).unwrap_or(0));
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    for _ in 0..zeros {
        out.push('1');
    }
    for digit in digits.iter().rev() {
        out.push(char::from(ALPHABET[usize::from(*digit)]));
    }
    out
}

fn base58_decode(text: &str) -> Result<Vec<u8>, AddressError> {
    let zeros = text.bytes().take_while(|byte| *byte == b'1').count();
    // Little-endian bytes.
    let mut bytes: Vec<u8> = Vec::new();
    for character in text.chars() {
        let byte = character as u8;
        let Some(index) = ALPHABET.iter().position(|candidate| *candidate == byte) else {
            return Err(AddressError::BadCharacter(character));
        };
        let mut carry = u32::try_from(index).unwrap_or(0);
        for slot in &mut bytes {
            carry += u32::from(*slot) * 58;
            *slot = u8::try_from(carry & 0xff).unwrap_or(0);
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push(u8::try_from(carry & 0xff).unwrap_or(0));
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; zeros];
    out.extend(bytes.iter().rev());
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The address of the template account's policy, from an independent encoder.
    const TEMPLATE: [u8; 32] = [
        0xe9, 0x4f, 0x1b, 0x9f, 0x07, 0x29, 0x8a, 0xa1, 0xf8, 0x0d, 0x62, 0x08, 0x59, 0x71, 0x50,
        0xb1, 0x77, 0xb2, 0xcd, 0xad, 0xd9, 0x8c, 0xaf, 0xd4, 0xbd, 0x32, 0x51, 0x5b, 0xe6, 0x30,
        0x1a, 0x50,
    ];

    #[test]
    fn a_thirty_two_byte_address_round_trips() {
        for seed in [0u8, 1, 0x5a, 0xff] {
            let bytes = [seed; 32];
            let text = encode(&bytes);
            assert!(text.starts_with('K'), "{text}");
            assert_eq!(decode(&text).unwrap(), bytes);
        }
    }

    #[test]
    fn the_encoding_is_pinned_to_a_known_vector() {
        assert_eq!(
            encode(&TEMPLATE),
            "K4aFUZMDDimgetMW8Vm3QsKAKCZ8jLGGziZ7bndkskcAYmLuVPx"
        );
    }

    #[test]
    fn every_address_starts_with_k() {
        // The version bytes are chosen so the first character does not drift with
        // the payload, which is what makes `K...` a usable visual cue.
        for byte in 0..=255u8 {
            let bytes = [byte; 32];
            assert!(encode(&bytes).starts_with('K'), "{byte}");
        }
    }

    #[test]
    fn another_chains_version_is_refused() {
        let text = encode_payload([0x02, 0x1b], &TEMPLATE);
        assert!(matches!(
            decode(&text),
            Err(AddressError::WrongVersion([0x02, 0x1b]))
        ));
    }

    #[test]
    fn a_single_wrong_character_breaks_the_checksum() {
        let mut characters: Vec<char> = encode(&TEMPLATE).chars().collect();
        let last = characters.len() - 1;
        characters[last] = if characters[last] == 'q' { 'r' } else { 'q' };
        let text: String = characters.into_iter().collect();
        assert!(matches!(decode(&text), Err(AddressError::BadChecksum)));
    }

    #[test]
    fn a_payload_that_is_not_thirty_two_bytes_is_refused() {
        let text = encode_payload(VERSION, &[1u8; 31]);
        assert!(matches!(decode(&text), Err(AddressError::WrongLength(31))));
    }

    #[test]
    fn a_character_outside_the_alphabet_is_refused() {
        let mut text = encode(&TEMPLATE);
        text.push('0');
        assert!(matches!(
            decode(&text),
            Err(AddressError::BadCharacter('0'))
        ));
    }

    #[test]
    fn an_empty_string_is_refused() {
        assert_eq!(decode(""), Err(AddressError::Empty));
    }
}
