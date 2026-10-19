//! Building blocks shared by this crate's protocol and by protocols built on
//! top of it: labelled HKDF, transcript hashing and single-use AES-256-GCM.
//!
//! ML-KEM encapsulation and decapsulation are methods on
//! [`ExchangeKey`](crate::ExchangeKey) and
//! [`ExchangeKeyPair`](crate::ExchangeKeyPair).

use std::ffi::CStr;

use native_ossl::cipher::{AeadDecryptCtx, AeadEncryptCtx, CipherAlg};
use native_ossl::digest::DigestAlg;
use native_ossl::kdf::HkdfBuilder;
use native_ossl::pkey::{DecapCtx, EncapCtx, Pkey, Private, Public};
use native_ossl::util::SecretBuf;

use crate::error::{Error, Result};

/// A protocol's domain-separation label.
///
/// The label is the HKDF salt of every derivation in the protocol, and
/// prefixes every HKDF `info`, so keys derived for one protocol can never be
/// confused with keys derived for another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Domain(&'static str);

impl Default for Domain {
    fn default() -> Self {
        Self::TANG
    }
}

impl Domain {
    /// The Tang escrow protocol of this crate.
    pub const TANG: Self = Self("tang-pqc/v1");

    /// A protocol label such as `"ipa-ku-enroll/v1 escrow"`.
    #[must_use]
    pub const fn new(label: &'static str) -> Self {
        Self(label)
    }

    /// The label.
    #[must_use]
    pub const fn label(self) -> &'static str {
        self.0
    }

    /// `HKDF-<hash>(salt = label, ikm = ‖ikm, info = label ‖ " " ‖ purpose ‖ ‖info)`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn hkdf(
        self,
        hash: &CStr,
        ikm: &[&[u8]],
        purpose: &str,
        info: &[&[u8]],
        out: &mut [u8],
    ) -> Result<()> {
        let mut key = SecretBuf::with_len(ikm.iter().map(|p| p.len()).sum());
        let mut offset = 0;
        for part in ikm {
            key.as_mut_slice()[offset..offset + part.len()].copy_from_slice(part);
            offset += part.len();
        }
        let mut full_info = Vec::with_capacity(64);
        full_info.extend_from_slice(self.0.as_bytes());
        full_info.push(b' ');
        full_info.extend_from_slice(purpose.as_bytes());
        for part in info {
            full_info.extend_from_slice(part);
        }
        let md = DigestAlg::fetch(hash, None)?;
        HkdfBuilder::new(&md)
            .key(key.as_ref())
            .salt(self.0.as_bytes())
            .info(&full_info)
            .derive(out)?;
        Ok(())
    }

    /// A 32-byte key from [`hkdf`](Self::hkdf), held in a [`SecretBuf`].
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn derive_key(
        self,
        hash: &CStr,
        ikm: &[&[u8]],
        purpose: &str,
        info: &[&[u8]],
    ) -> Result<SecretBuf> {
        let mut key = SecretBuf::with_len(32);
        self.hkdf(hash, ikm, purpose, info, key.as_mut_slice())?;
        Ok(key)
    }
}

/// AES-256-GCM tag length.
pub const TAG_LEN: usize = 16;

/// `hash` over the concatenation of `parts`.
///
/// # Errors
///
/// An OpenSSL error.
pub fn digest(hash: &CStr, parts: &[&[u8]]) -> Result<Vec<u8>> {
    let alg = DigestAlg::fetch(hash, None)?;
    let mut ctx = alg.new_context()?;
    for part in parts {
        ctx.update(part)?;
    }
    let mut out = vec![0u8; alg.output_len()];
    let n = ctx.finish(&mut out)?;
    out.truncate(n);
    Ok(out)
}

/// SHA-256 over the concatenation of `parts`.
///
/// # Errors
///
/// An OpenSSL error.
pub fn sha256(parts: &[&[u8]]) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest(c"SHA2-256", parts)?);
    Ok(out)
}

fn aes_256_gcm() -> Result<CipherAlg> {
    Ok(CipherAlg::fetch(c"AES-256-GCM", None)?)
}

/// The fixed GCM nonce.  Safe because every key is single-use: each one is
/// derived from a fresh ML-KEM encapsulation.
const NONCE: [u8; 12] = [0; 12];

/// AES-256-GCM encryption under a **single-use** 32-byte key; returns
/// `ct ‖ tag`.  The nonce is fixed, so never encrypt twice under one key.
///
/// # Errors
///
/// [`Error::Malformed`] for a key that is not 32 bytes, or an OpenSSL error.
pub fn seal(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if key.len() != 32 {
        return Err(Error::Malformed("AES-256-GCM key"));
    }
    let mut ctx = AeadEncryptCtx::new(&aes_256_gcm()?, key, &NONCE, None)?;
    let mut out = vec![0u8; plaintext.len() + TAG_LEN];
    let n = ctx.update(plaintext, &mut out)?;
    let n = n + ctx.finalize(&mut out[n..])?;
    ctx.tag(&mut out[n..n + TAG_LEN])?;
    out.truncate(n + TAG_LEN);
    Ok(out)
}

/// Inverse of [`seal`].
///
/// # Errors
///
/// [`Error::RecoveryFailed`] if the ciphertext is truncated or does not
/// authenticate.
pub fn open(key: &[u8], sealed: &[u8]) -> Result<SecretBuf> {
    if key.len() != 32 {
        return Err(Error::Malformed("AES-256-GCM key"));
    }
    let split = sealed
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::RecoveryFailed)?;
    let (ciphertext, tag) = sealed.split_at(split);
    let mut ctx = AeadDecryptCtx::new(&aes_256_gcm()?, key, &NONCE, None)?;
    let mut out = SecretBuf::with_len(ciphertext.len());
    let n = ctx.update(ciphertext, out.as_mut_slice())?;
    ctx.set_tag(tag)?;
    ctx.finalize(&mut out.as_mut_slice()[n..])
        .map_err(|_| Error::RecoveryFailed)?;
    Ok(out)
}

/// ML-KEM encapsulation; returns `(ciphertext, shared secret)`.
pub(crate) fn encapsulate(key: &Pkey<Public>) -> Result<(Vec<u8>, SecretBuf)> {
    let r = EncapCtx::new(key)?.encapsulate()?;
    Ok((r.wrapped_key, SecretBuf::new(r.shared_secret)))
}

/// ML-KEM decapsulation (with FIPS 203 implicit rejection).
pub(crate) fn decapsulate(key: &Pkey<Private>, ciphertext: &[u8]) -> Result<SecretBuf> {
    Ok(SecretBuf::new(DecapCtx::new(key)?.decapsulate(ciphertext)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip() {
        let key = [9u8; 32];
        let sealed = seal(&key, b"thirty-two bytes of shared secret").unwrap();
        assert_eq!(
            open(&key, &sealed).unwrap().as_ref(),
            b"thirty-two bytes of shared secret"
        );

        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(matches!(open(&key, &bad), Err(Error::RecoveryFailed)));
        assert!(matches!(
            open(&[8u8; 32], &sealed),
            Err(Error::RecoveryFailed)
        ));
        assert!(seal(&[0u8; 16], b"x").is_err());
    }

    #[test]
    fn domains_separate_derivations() {
        let a = Domain::TANG
            .derive_key(c"SHA2-256", &[b"ikm"], "key", &[b"x"])
            .unwrap();
        let b = Domain::new("other/v1")
            .derive_key(c"SHA2-256", &[b"ikm"], "key", &[b"x"])
            .unwrap();
        let c = Domain::TANG
            .derive_key(c"SHA2-256", &[b"ikm"], "response", &[b"x"])
            .unwrap();
        assert_ne!(a.as_ref(), b.as_ref());
        assert_ne!(a.as_ref(), c.as_ref());
    }
}
