//! The two-move blind signing protocol.
//!
//! ```text
//!   Requester (knows message)                    Signer (holds sk)
//!   ─────────────────────────                    ─────────────────
//!   salt ←$ {0,1}^256
//!   μ = SHAKE256(tr ‖ 0 ‖ |ctx| ‖ ctx ‖ salt ‖ m)
//!                         ── BlindRequest(μ) ──▶
//!                                                σ = ML-DSA.Sign(sk, μ)   [external μ]
//!                         ◀── BlindResponse(σ) ──
//!   check ML-DSA.Verify(pk, μ, σ)
//!   output (salt, σ)
//! ```
//!
//! Anyone verifies `(salt, σ)` on `m` as an ordinary ML-DSA signature on the
//! message `salt ‖ m` with context `ctx`.

use std::fmt;

use crate::error::{Error, Result};
use crate::keys::VerifyingKey;
use crate::mu::{self, Context, Salt, MU_LEN, SALT_LEN};
use crate::params::ParameterSet;

// ── Messages on the wire ────────────────────────────────────────────────────

/// Requester → signer: the blinded message, i.e. μ (64 bytes).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BlindRequest {
    mu: [u8; MU_LEN],
}

impl BlindRequest {
    /// Encoded length in bytes.
    pub const LEN: usize = MU_LEN;

    /// The 64-byte encoding (μ).
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; MU_LEN] {
        &self.mu
    }

    /// Decode a request received from the network.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `bytes` is exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mu = bytes.try_into().map_err(|_| Error::InvalidLength {
            what: "blind request",
            expected: MU_LEN,
            actual: bytes.len(),
        })?;
        Ok(Self { mu })
    }
}

impl TryFrom<&[u8]> for BlindRequest {
    type Error = Error;

    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_bytes(bytes)
    }
}

impl fmt::Debug for BlindRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindRequest").finish_non_exhaustive()
    }
}

/// Signer → requester: a raw ML-DSA signature on μ.
///
/// It is untrusted until [`PendingSignature::finalize`] has verified it.
#[derive(Clone, PartialEq, Eq)]
pub struct BlindResponse(Box<[u8]>);

impl BlindResponse {
    /// The encoded signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<Vec<u8>> for BlindResponse {
    fn from(bytes: Vec<u8>) -> Self {
        Self(bytes.into_boxed_slice())
    }
}

impl From<&[u8]> for BlindResponse {
    fn from(bytes: &[u8]) -> Self {
        Self(bytes.into())
    }
}

impl fmt::Debug for BlindResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BlindResponse").field(&self.0.len()).finish()
    }
}

// ── Requester ───────────────────────────────────────────────────────────────

/// The party that wants a message signed without revealing it.
#[derive(Clone, Debug)]
pub struct Requester {
    key: VerifyingKey,
    context: Context,
}

impl Requester {
    /// A requester for signatures under `key` with the empty context string.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        Self::with_context(key, Context::default())
    }

    /// A requester for signatures under `key` with an explicit context string.
    #[must_use]
    pub fn with_context(key: VerifyingKey, context: Context) -> Self {
        Self { key, context }
    }

    /// The signer's public key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.key
    }

    /// The context string folded into μ.
    #[must_use]
    pub fn context(&self) -> &Context {
        &self.context
    }

    /// Blind `message`: produce the request to send and the state to keep.
    ///
    /// A fresh 256-bit salt is drawn from OpenSSL's private DRBG for every
    /// call, so blinding the same message twice yields unrelated requests.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// the signer's parameter set (the signature could not be verified), or
    /// an OpenSSL error if randomness or hashing fails.
    pub fn blind(&self, message: &[u8]) -> Result<(BlindRequest, PendingSignature)> {
        self.key.parameter_set().ensure_allowed()?;
        self.blind_with_salt(message, Salt::random()?)
    }

    /// Rebuild the pending state of an earlier [`blind`](Self::blind) of
    /// `message` from its saved [`salt`](PendingSignature::salt), e.g. when
    /// the request and the response are handled by separate runs of a
    /// tool.  Gives the same request as the original call.
    ///
    /// The salt hides the message from the signer: keep it secret until the
    /// signature is finalised, and never choose it other than with
    /// [`blind`](Self::blind).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] unless `salt` is 32 bytes, or as
    /// [`blind`](Self::blind).
    pub fn resume(&self, message: &[u8], salt: &[u8]) -> Result<PendingSignature> {
        self.key.parameter_set().ensure_allowed()?;
        let salt: [u8; SALT_LEN] = salt.try_into().map_err(|_| Error::InvalidLength {
            what: "blinding salt",
            expected: SALT_LEN,
            actual: salt.len(),
        })?;
        Ok(self.blind_with_salt(message, Salt::from_bytes(salt))?.1)
    }

    pub(crate) fn blind_with_salt(
        &self,
        message: &[u8],
        salt: Salt,
    ) -> Result<(BlindRequest, PendingSignature)> {
        let mu =
            mu::message_representative(self.key.tr(), &self.context, salt.as_bytes(), message)?;
        let pending = PendingSignature {
            key: self.key.clone(),
            salt,
            mu,
        };
        Ok((BlindRequest { mu }, pending))
    }
}

/// Requester state between sending a [`BlindRequest`] and receiving the
/// [`BlindResponse`].
///
/// Holds the secret salt; it is wiped when this value is dropped.
#[must_use = "a pending signature must be finalized with the signer's response"]
pub struct PendingSignature {
    key: VerifyingKey,
    salt: Salt,
    mu: [u8; MU_LEN],
}

impl PendingSignature {
    /// The secret blinding salt, to save the state for
    /// [`Requester::resume`].
    #[must_use]
    pub fn salt(&self) -> &[u8] {
        self.salt.as_bytes()
    }

    /// The request this state belongs to (e.g. to resend it).
    #[must_use]
    pub fn request(&self) -> BlindRequest {
        BlindRequest { mu: self.mu }
    }

    /// Check the signer's response and produce the final signature.
    ///
    /// The response is verified against μ with the signer's public key, so a
    /// faulty or malicious signer cannot hand out a signature that later fails
    /// to verify.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] or [`Error::InvalidSignature`] if the
    /// response is not a valid ML-DSA signature on this request.
    pub fn finalize(self, response: &BlindResponse) -> Result<BlindSignature> {
        self.key.parameter_set().ensure_allowed()?;
        let sig = response.as_bytes();
        self.key.check_signature_len(sig)?;
        self.key.verify_mu(&self.mu, sig)?;
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(self.salt.as_bytes());
        Ok(BlindSignature {
            salt,
            signature: sig.into(),
        })
    }
}

impl fmt::Debug for PendingSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingSignature")
            .field("key", &self.key)
            .finish_non_exhaustive()
    }
}

// ── Final signature ─────────────────────────────────────────────────────────

/// A finalised blind signature: the salt and a standard ML-DSA signature.
///
/// The ML-DSA signature is valid for the message
/// [`signed_message(m)`](Self::signed_message) `= salt ‖ m`, so any FIPS 204
/// implementation can verify it without knowing about this crate.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct BlindSignature {
    salt: [u8; SALT_LEN],
    signature: Box<[u8]>,
}

impl BlindSignature {
    /// Length of the salt prefix in bytes.
    pub const SALT_LEN: usize = SALT_LEN;

    /// The blinding salt, now public.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// The raw FIPS 204 ML-DSA signature.
    #[must_use]
    pub fn ml_dsa_signature(&self) -> &[u8] {
        &self.signature
    }

    /// The exact message a stock ML-DSA verifier must be given: `salt ‖ message`.
    #[must_use]
    pub fn signed_message(&self, message: &[u8]) -> Vec<u8> {
        [&self.salt[..], message].concat()
    }

    /// Encode as `salt ‖ ml_dsa_signature`.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        [&self.salt[..], &self.signature].concat()
    }

    /// Decode `salt ‖ ml_dsa_signature` for the given parameter set.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] if the length does not match `parameter_set`.
    pub fn from_bytes(parameter_set: ParameterSet, bytes: &[u8]) -> Result<Self> {
        let expected = SALT_LEN + parameter_set.signature_len();
        match bytes.split_first_chunk::<SALT_LEN>() {
            Some((salt, signature)) if bytes.len() == expected => Ok(Self {
                salt: *salt,
                signature: signature.into(),
            }),
            _ => Err(Error::InvalidLength {
                what: "blind signature",
                expected,
                actual: bytes.len(),
            }),
        }
    }
}

impl fmt::Debug for BlindSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BlindSignature")
            .field("len", &(SALT_LEN + self.signature.len()))
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn resumed_state_finalises() {
        let sk = crate::SigningKey::generate(ParameterSet::MlDsa44).unwrap();
        let requester = Requester::new(sk.verifying_key().clone());
        let (request, pending) = requester.blind(b"m").unwrap();
        let salt = pending.salt().to_vec();
        drop(pending);
        let resumed = requester.resume(b"m", &salt).unwrap();
        assert_eq!(resumed.request(), request);
        let signature = resumed.finalize(&sk.blind_sign(&request).unwrap()).unwrap();
        sk.verifying_key()
            .verify(&Context::default(), b"m", &signature)
            .unwrap();
        assert!(requester.resume(b"m", &salt[1..]).is_err());
        // Another message under the same salt is another request.
        assert_ne!(requester.resume(b"n", &salt).unwrap().request(), request);
    }

    use super::*;
    use crate::keys::SigningKey;

    #[test]
    fn same_salt_gives_same_request() {
        let sk = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
        let requester = Requester::new(sk.verifying_key().clone());
        let (a, _) = requester
            .blind_with_salt(b"m", Salt::from_bytes([7; SALT_LEN]))
            .unwrap();
        let (b, _) = requester
            .blind_with_salt(b"m", Salt::from_bytes([7; SALT_LEN]))
            .unwrap();
        let (c, _) = requester
            .blind_with_salt(b"m", Salt::from_bytes([8; SALT_LEN]))
            .unwrap();
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn signature_encoding_round_trip() {
        let sk = SigningKey::generate(ParameterSet::MlDsa44).unwrap();
        let requester = Requester::new(sk.verifying_key().clone());
        let (req, pending) = requester.blind(b"msg").unwrap();
        let sig = pending.finalize(&sk.blind_sign(&req).unwrap()).unwrap();
        let decoded = BlindSignature::from_bytes(ParameterSet::MlDsa44, &sig.to_bytes()).unwrap();
        assert_eq!(sig, decoded);
        assert!(BlindSignature::from_bytes(ParameterSet::MlDsa65, &sig.to_bytes()).is_err());
    }
}
