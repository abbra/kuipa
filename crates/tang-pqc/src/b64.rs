//! Unpadded base64url (RFC 4648 §5), as required by JOSE (RFC 7515 §2).
//!
//! Decoding is strict: no padding, no whitespace, and no non-zero trailing
//! bits, so every value has exactly one accepted encoding.

use crate::error::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Length of the unpadded encoding of `n` bytes.
/// Length of the encoding of `n` bytes.
#[must_use]
pub const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Encode into `out`, which must be exactly [`encoded_len`] bytes.  Lets
/// secrets be encoded straight into a wiping buffer.
/// Encode into `out`, which must be exactly [`encoded_len`] bytes.
///
/// # Panics
///
/// If `out` has the wrong length.
pub fn encode_into(data: &[u8], out: &mut [u8]) {
    assert_eq!(out.len(), encoded_len(data.len()), "base64url output size");
    let mut pos = 0;
    for chunk in data.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |acc, (i, &b)| acc | u32::from(b) << (16 - 8 * i));
        for i in 0..=chunk.len() {
            out[pos] = ALPHABET[(n >> (18 - 6 * i)) as usize & 63];
            pos += 1;
        }
    }
}

/// Encode.
#[must_use]
#[allow(clippy::missing_panics_doc)] // the alphabet is ASCII
pub fn encode(data: &[u8]) -> String {
    let mut out = vec![0u8; encoded_len(data.len())];
    encode_into(data, &mut out);
    String::from_utf8(out).expect("base64url alphabet is ASCII")
}

fn value(c: u8) -> Option<u32> {
    let v = match c {
        b'A'..=b'Z' => c - b'A',
        b'a'..=b'z' => c - b'a' + 26,
        b'0'..=b'9' => c - b'0' + 52,
        b'-' => 62,
        b'_' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decode strictly.
///
/// # Errors
///
/// [`Error::Malformed`] for anything but canonical unpadded base64url.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let malformed = || Error::Malformed("base64url");
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(malformed());
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let n = chunk.iter().enumerate().try_fold(0u32, |acc, (i, &c)| {
            value(c).map(|v| acc | v << (18 - 6 * i))
        });
        let n = n.ok_or_else(malformed)?;
        let produced = chunk.len() - 1;
        // Bits below the last full output byte must be zero (canonical form).
        if n & ((1 << (24 - 8 * produced)) - 1) != 0 {
            return Err(malformed());
        }
        out.extend_from_slice(&n.to_be_bytes()[1..=produced]);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 4648 §10 vectors, unpadded.
    #[test]
    fn rfc4648_vectors() {
        for (plain, enc) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(encode(plain.as_bytes()), enc);
            assert_eq!(decode(enc).unwrap(), plain.as_bytes());
        }
    }

    #[test]
    fn encoded_len_matches() {
        for n in 0..10 {
            assert_eq!(encode(&vec![0xa5; n]).len(), encoded_len(n));
        }
    }

    #[test]
    fn url_alphabet_and_round_trip() {
        assert_eq!(encode(&[0xfb, 0xff]), "-_8");
        let all: Vec<u8> = (0..=255).collect();
        assert_eq!(decode(&encode(&all)).unwrap(), all);
    }

    #[test]
    fn rejects_non_canonical() {
        // padding, impossible length, non-zero trailing bits, standard
        // alphabet, whitespace
        for bad in ["Zg==", "Z", "Zh", "Zm+v", "Zm/v", "Zm 9v"] {
            assert!(decode(bad).is_err(), "{bad}");
        }
    }
}
