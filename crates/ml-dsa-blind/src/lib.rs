//! Blind (message-hiding) signing with **unmodified** FIPS 204 ML-DSA.
//!
//! A requester obtains an ML-DSA signature on a message the signer never
//! sees.  The signer runs stock OpenSSL ML-DSA signing, and the result is an
//! ordinary ML-DSA signature that any FIPS 204 implementation verifies.
//!
//! # How it works
//!
//! FIPS 204 (Algorithm 7, step 6) lets the message representative
//! `μ = SHAKE256(tr ‖ M′, 64)` be computed outside the module that holds
//! the key.  OpenSSL exposes this as the `"mu"` signature parameter.  The
//! requester computes μ over `M = salt ‖ message` with a fresh 256-bit salt
//! and sends only μ.  Because the salt is secret, μ is a hiding commitment to
//! the message.  The signer signs μ and the requester publishes
//! `(salt, σ)`.  See [`protocol`] for the message flow and `DESIGN.md` for
//! the security analysis.
//!
//! # What you get, and what you don't
//!
//! * **Message hiding.** The signer learns nothing about the message.
//! * **Unforgeability.** Each request yields exactly one signature, so a
//!   requester that made `q` requests cannot produce `q + 1` valid
//!   signatures.  This reduces to the EUF-CMA security of ML-DSA.
//! * **Standard output.** The signature is plain ML-DSA on `salt ‖ message`.
//! * **No unlinkability.** The signer sees the exact signature bytes it
//!   returns.  ML-DSA is strongly unforgeable, so the requester cannot
//!   re-randomise them, and the signer can recognise the signature when it is
//!   shown later.  No scheme with an unmodified ML-DSA signer *and* an
//!   unmodified ML-DSA verifier can avoid this; `DESIGN.md` explains why and
//!   describes the zero-knowledge upgrade that keeps this signer unchanged.
//!
//! # Example
//!
//! ```
//! use ml_dsa_blind::{BlindRequest, Context, ParameterSet, Requester, SigningKey};
//!
//! # fn main() -> Result<(), ml_dsa_blind::Error> {
//! // Signer: a dedicated ML-DSA key.
//! let signing_key = SigningKey::generate(ParameterSet::MlDsa65)?;
//! let public_key = signing_key.verifying_key().clone();
//!
//! // Requester: blind the message, send 64 bytes.
//! let ctx = Context::new(b"example/v1".to_vec())?;
//! let requester = Requester::with_context(public_key.clone(), ctx.clone());
//! let (request, pending) = requester.blind(b"a secret ballot")?;
//! let wire: &[u8] = request.as_bytes();
//!
//! // Signer: sign μ without seeing the message.
//! let response = signing_key.blind_sign(&BlindRequest::from_bytes(wire)?)?;
//!
//! // Requester: check and unblind.
//! let signature = pending.finalize(&response)?;
//!
//! // Anyone: verify.
//! public_key.verify(&ctx, b"a secret ballot", &signature)?;
//! # Ok(())
//! # }
//! ```

pub mod error;
mod keys;
mod mu;
mod params;
pub mod protocol;

pub use error::{Error, Result};
pub use keys::{SigningKey, VerifyingKey};
pub use mu::{Context, MU_LEN, SALT_LEN};
pub use params::ParameterSet;
pub use protocol::{BlindRequest, BlindResponse, BlindSignature, PendingSignature, Requester};
