//! The FIPS 204 message representative μ and the blinding salt.
//!
//! FIPS 204 Algorithm 7, step 6 defines
//!
//! ```text
//! tr = SHAKE256(pk, 64)
//! μ  = SHAKE256(tr || M', 64),   M' = 0x00 || len(ctx) || ctx || M
//! ```
//!
//! and explicitly allows μ to be computed outside the module that holds the
//! secret key.  This crate sets `M = salt || message`, which turns μ into a
//! hiding and binding commitment to `message`.

use native_ossl::digest::DigestAlg;
use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;

use crate::error::{Error, Result};

/// Length of μ and of `tr` in bytes.
pub const MU_LEN: usize = 64;

/// Length of the blinding salt in bytes.
pub const SALT_LEN: usize = 32;

/// FIPS 204 domain-separator byte for pure (non-prehash) ML-DSA.
const PURE_ML_DSA: u8 = 0x00;

/// An ML-DSA context string (FIPS 204 `ctx`, at most 255 bytes).
///
/// The context is folded into μ by the requester and must be supplied again
/// by every verifier.  The signer never sees it, so it provides domain
/// separation for verifiers but is **not** something the signer can enforce.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct Context(Vec<u8>);

impl Context {
    /// Maximum context length allowed by FIPS 204.
    pub const MAX_LEN: usize = 255;

    /// Create a context string.
    ///
    /// # Errors
    ///
    /// [`Error::ContextTooLong`] if `bytes` is longer than 255 bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self> {
        let bytes = bytes.into();
        if bytes.len() > Self::MAX_LEN {
            return Err(Error::ContextTooLong(bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// The raw context bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn len_byte(&self) -> u8 {
        u8::try_from(self.0.len()).expect("length checked in Context::new")
    }
}

impl TryFrom<&[u8]> for Context {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::new(bytes)
    }
}

/// Per-request blinding randomness.  Secret until the signature is finalised;
/// [`SecretBuf`] wipes it with `OPENSSL_cleanse` on drop.
pub(crate) struct Salt(SecretBuf);

impl Salt {
    pub(crate) fn random() -> Result<Self> {
        let mut salt = SecretBuf::with_len(SALT_LEN);
        Rand::fill_private(salt.as_mut_slice())?;
        Ok(Self(salt))
    }

    pub(crate) fn from_bytes(bytes: [u8; SALT_LEN]) -> Self {
        Self(SecretBuf::from_slice(&bytes))
    }

    /// Always exactly [`SALT_LEN`] bytes.
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

/// SHAKE256 over the concatenation of `parts`, squeezed to 64 bytes.
fn shake256_64(parts: &[&[u8]]) -> Result<[u8; MU_LEN]> {
    let mut ctx = DigestAlg::fetch(c"SHAKE256", None)?.new_context()?;
    for part in parts {
        ctx.update(part)?;
    }
    let mut out = [0u8; MU_LEN];
    ctx.finish_xof(&mut out)?;
    Ok(out)
}

/// `tr = SHAKE256(pk, 64)` — FIPS 204 Algorithm 7, step 6.
pub(crate) fn public_key_hash(encoded_pk: &[u8]) -> Result<[u8; MU_LEN]> {
    shake256_64(&[encoded_pk])
}

/// `μ = SHAKE256(tr || 0x00 || len(ctx) || ctx || salt || message, 64)`.
pub(crate) fn message_representative(
    tr: &[u8; MU_LEN],
    context: &Context,
    salt: &[u8],
    message: &[u8],
) -> Result<[u8; MU_LEN]> {
    shake256_64(&[
        tr,
        &[PURE_ML_DSA, context.len_byte()],
        context.as_bytes(),
        salt,
        message,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_length_limit() {
        assert!(Context::new(vec![0u8; 255]).is_ok());
        assert!(matches!(
            Context::new(vec![0u8; 256]),
            Err(Error::ContextTooLong(256))
        ));
    }

    #[test]
    fn salts_are_fresh() {
        let a = Salt::random().unwrap();
        let b = Salt::random().unwrap();
        assert_ne!(a.as_bytes(), b.as_bytes());
    }
}
