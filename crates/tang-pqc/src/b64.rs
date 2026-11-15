//! Unpadded base64url (RFC 4648 §5), as required by JOSE (RFC 7515 §2).
//!
//! Decoding is strict: no padding, no whitespace, and no non-zero trailing
//! bits, so every value has exactly one accepted encoding.

use crate::error::{Error, Result};

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Length of the unpadded encoding of `n` bytes.
#[must_use]
pub(crate) const fn encoded_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// Encode into `out`, which must be exactly [`encoded_len`] bytes.  Lets
/// secrets be encoded straight into a wiping buffer.
///
/// # Panics
///
/// If `out` has the wrong length.
pub(crate) fn encode_into(data: &[u8], out: &mut [u8]) {
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
///
/// # Panics
///
/// Never: the output is ASCII by construction.
#[must_use]
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

/// Decode strictly into exactly `N` bytes.
///
/// # Errors
///
/// [`Error::Malformed`] as for [`decode`], or when the length is not `N`.
pub fn decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    decode(text)?
        .try_into()
        .map_err(|_| Error::Malformed("base64url"))
}

/// `#[serde(with = "tang_pqc::b64::bytes")]`: a byte string, or anything
/// that converts to and from one (`[u8; N]`, `Vec<u8>`), as a base64url
/// string.
pub mod bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer, de::Error};

    /// Serialize as an unpadded base64url string.
    ///
    /// # Errors
    ///
    /// Whatever `s` fails with.
    pub fn serialize<T: AsRef<[u8]>, S: Serializer>(v: &T, s: S) -> Result<S::Ok, S::Error> {
        super::encode(v.as_ref()).serialize(s)
    }

    /// Deserialize strictly from a base64url string.
    ///
    /// # Errors
    ///
    /// Not canonical base64url, or the length the target refuses.
    pub fn deserialize<'de, T, D>(d: D) -> Result<T, D::Error>
    where
        T: TryFrom<Vec<u8>>,
        D: Deserializer<'de>,
    {
        let bytes = super::decode(&String::deserialize(d)?).map_err(D::Error::custom)?;
        T::try_from(bytes).map_err(|_| D::Error::custom("wrong length"))
    }
}

/// `#[serde(with = "tang_pqc::b64::bytes_vec")]`: a list of byte strings as
/// a list of base64url strings.
pub mod bytes_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Serialize as a list of unpadded base64url strings.
    ///
    /// # Errors
    ///
    /// Whatever `s` fails with.
    pub fn serialize<S: Serializer>(v: &[Vec<u8>], s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(v.iter().map(|b| super::encode(b)))
    }

    /// Deserialize strictly from a list of base64url strings.
    ///
    /// # Errors
    ///
    /// Any entry that is not canonical base64url.
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<Vec<u8>>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|t| super::decode(t).map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_helpers_use_base64url_strings() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct S {
            #[serde(with = "super::bytes")]
            fixed: [u8; 3],
            #[serde(with = "super::bytes")]
            var: Vec<u8>,
            #[serde(with = "super::bytes_vec")]
            many: Vec<Vec<u8>>,
        }
        let s = S {
            fixed: *b"foo",
            var: vec![0xfb, 0xff],
            many: vec![b"f".to_vec(), vec![]],
        };
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, r#"{"fixed":"Zm9v","var":"-_8","many":["Zg",""]}"#);
        assert_eq!(serde_json::from_str::<S>(&json).unwrap(), s);
        for bad in [
            r#"{"fixed":"Zm9","var":"","many":[]}"#,
            r#"{"fixed":"Zm9v","var":"Zg==","many":[]}"#,
        ] {
            assert!(serde_json::from_str::<S>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn decode_array_checks_the_length() {
        assert_eq!(decode_array::<3>("Zm9v").unwrap(), *b"foo");
        assert!(decode_array::<2>("Zm9v").is_err());
        assert!(decode_array::<3>("Zm9").is_err());
    }

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
