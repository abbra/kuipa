//! The subset of JWK (RFC 7517) used here: `"kty": "AKP"` keys as defined by
//! RFC 9964 (ML-DSA) and draft-ietf-jose-pqc-kem (ML-KEM).

use native_ossl::util::SecretBuf;
use serde::{Deserialize, Serialize};

use crate::b64;
use crate::error::{Error, Result};
use crate::primitives;

/// The RFC 9964 "Algorithm Key Pair" key type.
pub(crate) const KTY_AKP: &str = "AKP";

/// A JWK as it appears on the wire.  Members of other key types (`crv`, `x`,
/// …) are ignored, so classic Tang keys can share a JWK Set with these.
#[derive(Debug, Default, Serialize, Deserialize)]
pub(crate) struct Jwk {
    pub(crate) kty: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) alg: Option<String>,
    #[serde(rename = "pub", skip_serializing_if = "Option::is_none")]
    pub(crate) public: Option<String>,
    /// Only ever parsed: private JWKs are written by [`write_private_akp`]
    /// so that the seed never sits in an ordinary `String`.
    #[serde(rename = "priv", default, skip_serializing)]
    pub(crate) private: Option<SecretText>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) key_ops: Option<Vec<String>>,
    /// Members this crate does not interpret (e.g. an application role).
    #[serde(flatten)]
    pub(crate) extra: serde_json::Map<String, serde_json::Value>,
}

impl Jwk {
    pub(crate) fn akp(alg: &str, public: &[u8], key_ops: &[&str]) -> Self {
        Self {
            kty: KTY_AKP.into(),
            alg: Some(alg.into()),
            public: Some(b64::encode(public)),
            private: None,
            key_ops: Some(key_ops.iter().map(|&op| op.into()).collect()),
            extra: serde_json::Map::new(),
        }
    }

    /// The `alg` of an AKP key, or `None` for any other key type.
    pub(crate) fn akp_alg(&self) -> Option<&str> {
        (self.kty == KTY_AKP)
            .then_some(self.alg.as_deref())
            .flatten()
    }

    /// The key states itself usable for `op`: `key_ops` is present and
    /// allows it.  Absent `key_ops` allows nothing — an AKP key always
    /// carries one (RFC 9964 §4), and a key without a stated purpose must
    /// not silently serve every role in an advertisement.
    pub(crate) fn states(&self, op: &str) -> bool {
        self.key_ops
            .as_ref()
            .is_some_and(|ops| ops.iter().any(|o| o == op))
    }

    pub(crate) fn public_bytes(&self) -> Result<Vec<u8>> {
        b64::decode(
            self.public
                .as_deref()
                .ok_or(Error::Malformed("JWK: missing pub"))?,
        )
    }

    #[cfg(test)]
    pub(crate) fn to_json(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("JWK serialisation cannot fail")
    }

    pub(crate) fn from_json(json: &[u8]) -> Result<Self> {
        serde_json::from_slice(json).map_err(|_| Error::Malformed("JWK"))
    }
}

/// A JSON string holding secret material; wiped with `OPENSSL_cleanse` on drop.
#[derive(Default, Deserialize)]
#[serde(transparent)]
pub(crate) struct SecretText(String);

impl SecretText {
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Drop for SecretText {
    fn drop(&mut self) {
        drop(SecretBuf::new(std::mem::take(&mut self.0).into_bytes()));
    }
}

impl std::fmt::Debug for SecretText {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretText(..)")
    }
}

/// Serialise a private AKP JWK directly into a wiping buffer:
/// `{"kty":"AKP","alg":…,"pub":…,"key_ops":[…],"priv":…}`.
pub(crate) fn write_private_akp(
    alg: &str,
    public: &[u8],
    key_ops: &[&str],
    seed: &[u8],
) -> SecretBuf {
    let ops = key_ops
        .iter()
        .map(|op| format!("\"{op}\""))
        .collect::<Vec<_>>()
        .join(",");
    let head = format!(
        r#"{{"kty":"{KTY_AKP}","alg":"{alg}","pub":"{}","key_ops":[{ops}],"priv":""#,
        b64::encode(public)
    );
    let tail = b"\"}";
    let seed_len = b64::encoded_len(seed.len());
    let mut out = SecretBuf::with_len(head.len() + seed_len + tail.len());
    let buf = out.as_mut_slice();
    let (h, rest) = buf.split_at_mut(head.len());
    let (s, t) = rest.split_at_mut(seed_len);
    h.copy_from_slice(head.as_bytes());
    b64::encode_into(seed, s);
    t.copy_from_slice(tail);
    out
}

/// RFC 7638 SHA-256 thumbprint of an AKP key: the hash of
/// `{"alg":…,"kty":"AKP","pub":…}` with members in lexicographic order and
/// no whitespace (RFC 9964 §6).
pub(crate) fn akp_thumbprint(alg: &str, public: &[u8]) -> Result<[u8; 32]> {
    let canonical = format!(
        r#"{{"alg":"{alg}","kty":"{KTY_AKP}","pub":"{}"}}"#,
        b64::encode(public)
    );
    primitives::sha256(&[canonical.as_bytes()])
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    /// Our hand-built canonical form equals a generic RFC 7638 serialisation.
    #[test]
    fn thumbprint_matches_generic_rfc7638() {
        let public = [0x5au8; 1312];
        let encoded = b64::encode(&public);
        let members = BTreeMap::from([("alg", "ML-DSA-44"), ("kty", "AKP"), ("pub", &encoded)]);
        let generic = primitives::sha256(&[serde_json::to_string(&members).unwrap().as_bytes()]);
        assert_eq!(
            akp_thumbprint("ML-DSA-44", &public).unwrap(),
            generic.unwrap()
        );
    }

    #[test]
    fn private_writer_produces_valid_jwk_without_leaking_priv_on_reserialise() {
        let json = write_private_akp("ML-DSA-44", &[1, 2, 3], &["sign", "verify"], &[9; 32]);
        let jwk = Jwk::from_json(json.as_ref()).unwrap();
        assert_eq!(jwk.akp_alg(), Some("ML-DSA-44"));
        assert_eq!(
            jwk.key_ops.as_deref(),
            Some(&["sign".into(), "verify".into()][..])
        );
        let seed = b64::decode(jwk.private.as_ref().unwrap().as_str()).unwrap();
        assert_eq!(seed, [9; 32]);
        // Serialising a parsed private JWK never emits `priv`.
        let public_only: serde_json::Value = serde_json::from_slice(&jwk.to_json()).unwrap();
        assert!(public_only.get("priv").is_none());
    }

    #[test]
    fn foreign_key_types_are_tolerated() {
        let ec =
            br#"{"kty":"EC","crv":"P-521","alg":"ECMR","key_ops":["deriveKey"],"x":"AA","y":"AA"}"#;
        let jwk = Jwk::from_json(ec).unwrap();
        assert_eq!(jwk.akp_alg(), None);
    }
}
