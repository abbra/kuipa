//! ML-DSA key wrappers and the two OpenSSL calls the protocol relies on:
//! external-μ signing and external-μ verification.

use std::fmt;
use std::sync::Arc;

use native_ossl::params::{ParamBuilder, Params};
use native_ossl::pkey::{KeygenCtx, MessageSigner, MessageVerifier, Pkey, Private, Public, SigAlg};
use native_ossl::pkey_builder::RawKeyBuilder;
use native_ossl::pkey_params;

use crate::error::{Error, Result};
use crate::mu::{self, Context, MU_LEN};
use crate::params::ParameterSet;
use crate::protocol::{BlindRequest, BlindResponse, BlindSignature};

/// OpenSSL `OSSL_SIGNATURE_PARAM_MU`: the input to sign/verify is μ itself.
const PARAM_MU: &std::ffi::CStr = c"mu";

fn external_mu_params() -> Result<Params<'static>> {
    Ok(ParamBuilder::new()?.push_int(PARAM_MU, 1)?.build()?)
}

// ── VerifyingKey ────────────────────────────────────────────────────────────

/// An ML-DSA public key.
///
/// Cheap to clone (reference counted).  Besides the OpenSSL key it caches the
/// FIPS 204 encoding and `tr = SHAKE256(pk, 64)`, which requesters need to
/// compute μ.
#[derive(Clone)]
pub struct VerifyingKey(Arc<VerifyingKeyInner>);

struct VerifyingKeyInner {
    pkey: Pkey<Public>,
    sig_alg: SigAlg,
    parameter_set: ParameterSet,
    encoded: Box<[u8]>,
    tr: [u8; MU_LEN],
}

impl VerifyingKey {
    /// Wrap an OpenSSL ML-DSA public key.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedKey`] if `pkey` is not an ML-DSA key.
    pub fn from_pkey(pkey: Pkey<Public>) -> Result<Self> {
        let parameter_set = ParameterSet::of(&pkey).ok_or(Error::UnsupportedKey)?;
        let exported = pkey.export()?;
        let encoded: Box<[u8]> = exported.get_octet_string(pkey_params::PUB_KEY)?.into();
        if encoded.len() != parameter_set.public_key_len() {
            return Err(Error::InvalidLength {
                what: "ML-DSA public key",
                expected: parameter_set.public_key_len(),
                actual: encoded.len(),
            });
        }
        let tr = mu::public_key_hash(&encoded)?;
        let sig_alg = SigAlg::fetch(parameter_set.algorithm_name(), None)?;
        Ok(Self(Arc::new(VerifyingKeyInner {
            pkey,
            sig_alg,
            parameter_set,
            encoded,
            tr,
        })))
    }

    /// Decode a raw FIPS 204 public key encoding.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidLength`] for a wrong-sized encoding, or an OpenSSL error
    /// if the key fails to import.
    pub fn from_bytes(parameter_set: ParameterSet, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != parameter_set.public_key_len() {
            return Err(Error::InvalidLength {
                what: "ML-DSA public key",
                expected: parameter_set.public_key_len(),
                actual: bytes.len(),
            });
        }
        let pkey = RawKeyBuilder::new(parameter_set.algorithm_name())
            .pub_key(bytes)
            .build_public()?;
        Self::from_pkey(pkey)
    }

    /// Decode a DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error for malformed input, [`Error::UnsupportedKey`] for a
    /// non-ML-DSA key.
    pub fn from_der(der: &[u8]) -> Result<Self> {
        Self::from_pkey(Pkey::<Public>::from_der(der)?)
    }

    /// Decode a PEM `PUBLIC KEY`.
    ///
    /// # Errors
    ///
    /// As for [`from_der`](Self::from_der).
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Self::from_pkey(Pkey::<Public>::from_pem(pem)?)
    }

    /// Encode as DER `SubjectPublicKeyInfo`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if encoding fails.
    pub fn to_der(&self) -> Result<Vec<u8>> {
        Ok(self.0.pkey.public_key_to_der()?)
    }

    /// Encode as PEM `PUBLIC KEY`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if encoding fails.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.0.pkey.to_pem()?)
    }

    /// The raw FIPS 204 public key encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0.encoded
    }

    /// The ML-DSA parameter set of this key.
    #[must_use]
    pub fn parameter_set(&self) -> ParameterSet {
        self.0.parameter_set
    }

    /// The underlying OpenSSL key, e.g. for verifying with plain OpenSSL.
    #[must_use]
    pub fn pkey(&self) -> &Pkey<Public> {
        &self.0.pkey
    }

    /// Verify a finalised blind signature on `message`.
    ///
    /// This is ordinary FIPS 204 ML-DSA verification of
    /// [`signature.signed_message(message)`](BlindSignature::signed_message)
    /// under `context`.  It is implemented through OpenSSL's external-μ
    /// interface so that `message` does not have to be copied to prepend the
    /// salt; the result is identical to a pure ML-DSA verify.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`] if the signature does not verify, or
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// this key's parameter set.
    pub fn verify(
        &self,
        context: &Context,
        message: &[u8],
        signature: &BlindSignature,
    ) -> Result<()> {
        self.0.parameter_set.ensure_allowed()?;
        self.check_signature_len(signature.ml_dsa_signature())?;
        let mu = mu::message_representative(&self.0.tr, context, signature.salt(), message)?;
        self.verify_mu(&mu, signature.ml_dsa_signature())
    }

    pub(crate) fn tr(&self) -> &[u8; MU_LEN] {
        &self.0.tr
    }

    pub(crate) fn check_signature_len(&self, sig: &[u8]) -> Result<()> {
        let expected = self.0.parameter_set.signature_len();
        if sig.len() == expected {
            Ok(())
        } else {
            Err(Error::InvalidLength {
                what: "ML-DSA signature",
                expected,
                actual: sig.len(),
            })
        }
    }

    /// FIPS 204 `ML-DSA.Verify_internal` with an externally supplied μ.
    pub(crate) fn verify_mu(&self, mu: &[u8; MU_LEN], sig: &[u8]) -> Result<()> {
        self.0.parameter_set.ensure_allowed()?;
        let params = external_mu_params()?;
        let mut verifier = MessageVerifier::new(&self.0.pkey, &self.0.sig_alg, Some(&params))?;
        if verifier.verify(mu, sig)? {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }
}

impl PartialEq for VerifyingKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.encoded == other.0.encoded
    }
}

impl Eq for VerifyingKey {}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("parameter_set", &self.0.parameter_set)
            .finish_non_exhaustive()
    }
}

// ── SigningKey ──────────────────────────────────────────────────────────────

/// An ML-DSA private key used by the blind signer.
///
/// **Use a dedicated key.**  The signer cannot see what it signs, so a key
/// that answers blind requests will sign *any* message the requester chooses,
/// including messages that some other protocol would accept.  Never share a
/// blind-signing key with certificates, code signing, or any other use.
pub struct SigningKey {
    pkey: Pkey<Private>,
    verifying_key: VerifyingKey,
}

impl SigningKey {
    /// Generate a fresh key pair with OpenSSL.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// `parameter_set`, or an OpenSSL error if key generation fails.
    pub fn generate(parameter_set: ParameterSet) -> Result<Self> {
        parameter_set.ensure_allowed()?;
        let pkey = KeygenCtx::new(parameter_set.algorithm_name())?.generate()?;
        Self::from_pkey(pkey)
    }

    /// Generate a key pair with the first parameter set in
    /// [`ParameterSet::PREFERENCE`] that the system crypto policy allows.
    ///
    /// # Errors
    ///
    /// [`Error::NoAllowedParameterSet`] if the policy allows none.
    pub fn generate_preferred() -> Result<Self> {
        Self::generate(ParameterSet::preferred()?)
    }

    /// Wrap an OpenSSL ML-DSA private key (e.g. one held by a provider or HSM).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedKey`] if `pkey` is not an ML-DSA key.
    pub fn from_pkey(pkey: Pkey<Private>) -> Result<Self> {
        let verifying_key = VerifyingKey::from_pkey(Pkey::<Public>::from(pkey.clone()))?;
        Ok(Self {
            pkey,
            verifying_key,
        })
    }

    /// Decode a DER PKCS#8 `PrivateKeyInfo`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error for malformed input, [`Error::UnsupportedKey`] for a
    /// non-ML-DSA key.
    pub fn from_pkcs8_der(der: &[u8]) -> Result<Self> {
        Self::from_pkey(Pkey::<Private>::from_der(der)?)
    }

    /// Decode a PEM `PRIVATE KEY`.
    ///
    /// # Errors
    ///
    /// As for [`from_pkcs8_der`](Self::from_pkcs8_der).
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Self::from_pkey(Pkey::<Private>::from_pem(pem)?)
    }

    /// Encode as DER PKCS#8.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if encoding fails.
    pub fn to_pkcs8_der(&self) -> Result<Vec<u8>> {
        Ok(self.pkey.to_pkcs8_der()?)
    }

    /// Encode as PEM `PRIVATE KEY`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if encoding fails.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.pkey.to_pem()?)
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// The underlying OpenSSL key.
    #[must_use]
    pub fn pkey(&self) -> &Pkey<Private> {
        &self.pkey
    }

    /// Answer a blind signing request.
    ///
    /// This is unmodified FIPS 204 `ML-DSA.Sign` (hedged, with OpenSSL's DRBG
    /// supplying `rnd`) on the externally computed μ carried by `request`.
    /// The signer learns nothing about the message beyond the fact that a
    /// request was made.
    ///
    /// Authorising the requester (rate limiting, payment, eligibility) is the
    /// caller's job and must happen before calling this.
    ///
    /// Two fault-attack countermeasures are built in:
    ///
    /// * **Hedged signing only.** OpenSSL's `deterministic` mode is never
    ///   enabled, so signing the same μ twice uses fresh randomness.  The
    ///   requester chooses μ freely, and repeated deterministic signatures
    ///   are what differential fault attacks on Dilithium need.
    /// * **Verify before release.** Each signature is checked against μ
    ///   before it leaves the signer, so a faulty computation, which can
    ///   leak key material, is never handed to the requester.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// this key's parameter set, [`Error::SigningFault`] if the fresh
    /// signature does not verify, or an OpenSSL error if signing fails.
    pub fn blind_sign(&self, request: &BlindRequest) -> Result<BlindResponse> {
        self.verifying_key.parameter_set().ensure_allowed()?;
        let params = external_mu_params()?;
        let mut signer =
            MessageSigner::new(&self.pkey, &self.verifying_key.0.sig_alg, Some(&params))?;
        let mut sig = vec![0u8; self.verifying_key.parameter_set().signature_len()];
        let written = signer.sign(request.as_bytes(), Some(&mut sig))?;
        sig.truncate(written);
        match self.verifying_key.verify_mu(request.as_bytes(), &sig) {
            Ok(()) => Ok(BlindResponse::from(sig)),
            Err(Error::InvalidSignature) => Err(Error::SigningFault),
            Err(e) => Err(e),
        }
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("parameter_set", &self.verifying_key.parameter_set())
            .finish_non_exhaustive()
    }
}
