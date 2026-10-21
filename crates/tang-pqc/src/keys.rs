//! Server keys: ML-KEM exchange keys and ML-DSA advertisement signing keys,
//! with their JOSE representations (`"kty": "AKP"`, RFC 9964).

use std::ffi::CStr;
use std::fmt;
use std::str::FromStr;

use native_ossl::params::{ParamBuilder, Params};
use native_ossl::pkey::{KeygenCtx, MessageSigner, MessageVerifier, Pkey, Private, Public};
use native_ossl::pkey_builder::RawKeyBuilder;
use native_ossl::pkey_params;
use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;

use crate::alg::{KemAlg, SignatureAlg};
use crate::b64;
use crate::error::{Error, Result};
use crate::jwk::{Jwk, SecretText, akp_thumbprint, write_private_akp};
use crate::primitives;

/// Tang's `key_ops` for advertised signing and exchange keys.
pub(crate) const OP_VERIFY: &str = "verify";
pub(crate) const OP_SIGN: &str = "sign";
pub(crate) const OP_DERIVE_KEY: &str = "deriveKey";

fn raw_public_key(pkey: &Pkey<Public>, expected_len: usize) -> Result<Box<[u8]>> {
    let exported = pkey.export()?;
    let raw = exported.get_octet_string(pkey_params::PUB_KEY)?;
    if raw.len() == expected_len {
        Ok(raw.into())
    } else {
        Err(Error::UnsupportedKey)
    }
}

/// The FIPS 203/204 seed of a private key, if OpenSSL retained it.
///
/// Only used for keys wrapped with `from_pkey`; keys created by this crate
/// keep their own seed.  See `keygen_from_seed` on wiping the exported copy.
fn exported_seed(pkey: &Pkey<Private>, len: usize) -> Result<SecretBuf> {
    let exported = pkey.export()?;
    // ML-DSA and ML-KEM share the OpenSSL parameter name "seed".
    match exported.get_octet_string(pkey_params::ML_DSA_SEED) {
        Ok(seed) if seed.len() == len => Ok(SecretBuf::from_slice(seed)),
        _ => Err(Error::SeedUnavailable),
    }
}

/// A fresh seed from OpenSSL's private DRBG.
fn random_seed(len: usize) -> Result<SecretBuf> {
    let mut seed = SecretBuf::with_len(len);
    Rand::fill_private(seed.as_mut_slice())?;
    Ok(seed)
}

/// FIPS 203 / FIPS 204 key generation from a given seed.
///
/// Runs OpenSSL's normal key generation (including its pairwise consistency
/// test) with the seed as a keygen parameter.
///
/// The keygen parameter must be an `OCTET_STRING`, so the builder copies the
/// seed; native-ossl cleanses that copy on drop with OpenSSL 4.0+
/// (`OSSL_PARAM_clear_free`).  With older OpenSSL it is freed unwiped.
fn keygen_from_seed(alg: &CStr, seed: &SecretBuf) -> Result<Pkey<Private>> {
    let params = ParamBuilder::new()?
        .push_octet_slice(pkey_params::ML_DSA_SEED, seed.as_ref())?
        .build()?;
    let mut ctx = KeygenCtx::new(alg)?;
    ctx.set_params(&params)?;
    Ok(ctx.generate()?)
}

/// Parse a private AKP JWK into `(algorithm, jwk, seed)`.
fn parse_private_jwk<A>(
    json: &[u8],
    alg_from_name: fn(&str) -> Option<A>,
) -> Result<(A, Jwk, SecretBuf)> {
    let jwk = Jwk::from_json(json)?;
    let alg = jwk
        .akp_alg()
        .and_then(alg_from_name)
        .ok_or(Error::UnsupportedKey)?;
    let seed = SecretBuf::new(b64::decode(
        jwk.private
            .as_ref()
            .map(SecretText::as_str)
            .ok_or(Error::Malformed("JWK: missing priv"))?,
    )?);
    Ok((alg, jwk, seed))
}

/// Any `pub` member must match the key regenerated from the seed.
fn check_public_matches(jwk: &Jwk, actual: &[u8]) -> Result<()> {
    if jwk.public.is_some() && jwk.public_bytes()? != actual {
        return Err(Error::Malformed("JWK: pub does not match priv"));
    }
    Ok(())
}

// ── Thumbprint ──────────────────────────────────────────────────────────────

/// RFC 7638 JWK thumbprint (SHA-256) of an AKP key.
///
/// Used as the Tang `kid` of exchange keys and the Clevis `thp` of signing
/// keys.  Displayed and parsed as unpadded base64url, like Clevis.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Thumbprint([u8; 32]);

impl Thumbprint {
    fn of_akp(alg: &str, public: &[u8]) -> Result<Self> {
        Ok(Self(akp_thumbprint(alg, public)?))
    }

    /// The 32 raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Wrap 32 raw bytes.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl fmt::Display for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&b64::encode(&self.0))
    }
}

impl fmt::Debug for Thumbprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Thumbprint({self})")
    }
}

impl FromStr for Thumbprint {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let bytes = b64::decode(s).map_err(|_| Error::Malformed("thumbprint"))?;
        Ok(Self(
            bytes
                .try_into()
                .map_err(|_| Error::Malformed("thumbprint"))?,
        ))
    }
}

// ── Exchange keys (ML-KEM) ──────────────────────────────────────────────────

/// A server's public ML-KEM encapsulation key, as found in an advertisement.
#[derive(Clone)]
pub struct ExchangeKey {
    alg: KemAlg,
    pkey: Pkey<Public>,
    encoded: Box<[u8]>,
    kid: Thumbprint,
}

impl ExchangeKey {
    pub(crate) fn from_pkey(pkey: Pkey<Public>) -> Result<Self> {
        let alg = KemAlg::of(&pkey).ok_or(Error::UnsupportedKey)?;
        let encoded = raw_public_key(&pkey, alg.encapsulation_key_len())?;
        let kid = Thumbprint::of_akp(alg.jose_name(), &encoded)?;
        Ok(Self {
            alg,
            pkey,
            encoded,
            kid,
        })
    }

    /// Decode a raw FIPS 203 encapsulation key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a wrong length, or an OpenSSL error if the key
    /// is rejected (FIPS 203 encapsulation key check).
    pub fn from_bytes(alg: KemAlg, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != alg.encapsulation_key_len() {
            return Err(Error::Malformed("ML-KEM encapsulation key"));
        }
        Self::from_pkey(
            RawKeyBuilder::new(alg.name())
                .pub_key(bytes)
                .build_public()?,
        )
    }

    pub(crate) fn from_jwk(jwk: &Jwk, alg: KemAlg) -> Result<Self> {
        Self::from_bytes(alg, &jwk.public_bytes()?)
    }

    pub(crate) fn to_jwk(&self) -> Jwk {
        Jwk::akp(self.alg.jose_name(), &self.encoded, &[OP_DERIVE_KEY])
    }

    /// The KEM algorithm.
    #[must_use]
    pub fn alg(&self) -> KemAlg {
        self.alg
    }

    /// The key id (RFC 7638 thumbprint).
    #[must_use]
    pub fn kid(&self) -> &Thumbprint {
        &self.kid
    }

    /// The raw FIPS 203 encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// ML-KEM encapsulation to this key; returns `(ciphertext, shared secret)`.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// the KEM, or an OpenSSL error.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, SecretBuf)> {
        self.alg.ensure_allowed()?;
        primitives::encapsulate(&self.pkey)
    }

    /// The public AKP JWK (`key_ops: ["deriveKey"]`).
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // serialising plain strings cannot fail
    pub fn to_jwk_json(&self) -> String {
        serde_json::to_string(&self.to_jwk()).expect("JWK serialisation cannot fail")
    }

    /// Parse a public AKP JWK.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid JSON or a key that does not allow
    /// `deriveKey`, [`Error::UnsupportedKey`] for other algorithms.
    pub fn from_jwk_json(json: &[u8]) -> Result<Self> {
        let jwk = Jwk::from_json(json)?;
        let alg = jwk
            .akp_alg()
            .and_then(KemAlg::from_jose_name)
            .ok_or(Error::UnsupportedKey)?;
        if !jwk.states(OP_DERIVE_KEY) {
            return Err(Error::Malformed("JWK: key_ops"));
        }
        Self::from_jwk(&jwk, alg)
    }
}

impl PartialEq for ExchangeKey {
    fn eq(&self, other: &Self) -> bool {
        self.alg == other.alg && self.encoded == other.encoded
    }
}

impl Eq for ExchangeKey {}

impl fmt::Debug for ExchangeKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeKey")
            .field("alg", &self.alg)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// A server's ML-KEM key pair.
pub struct ExchangeKeyPair {
    pkey: Pkey<Private>,
    public: ExchangeKey,
    /// FIPS 203 seed `d ‖ z`, kept for JWK export (`None` for wrapped keys).
    seed: Option<SecretBuf>,
}

impl ExchangeKeyPair {
    /// Generate a fresh key pair.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// `alg`, or an OpenSSL error if key generation fails.
    pub fn generate(alg: KemAlg) -> Result<Self> {
        alg.ensure_allowed()?;
        Self::from_seed(alg, random_seed(KemAlg::SEED_LEN)?)
    }

    /// Generate a key pair with the first KEM in [`KemAlg::PREFERENCE`] that
    /// the system crypto policy allows.
    ///
    /// # Errors
    ///
    /// [`Error::NoAllowedAlgorithm`] if the policy allows none.
    pub fn generate_preferred() -> Result<Self> {
        Self::generate(KemAlg::preferred()?)
    }

    fn from_seed(alg: KemAlg, seed: SecretBuf) -> Result<Self> {
        let mut pair = Self::from_pkey(keygen_from_seed(alg.name(), &seed)?)?;
        pair.seed = Some(seed);
        Ok(pair)
    }

    /// Wrap an OpenSSL ML-KEM private key.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedKey`] if it is not ML-KEM-768 or ML-KEM-1024.
    pub fn from_pkey(pkey: Pkey<Private>) -> Result<Self> {
        let public = ExchangeKey::from_pkey(Pkey::<Public>::from(pkey.clone()))?;
        Ok(Self {
            pkey,
            public,
            seed: None,
        })
    }

    /// Load a private JWK (`"kty": "AKP"`, `priv` = 64-byte FIPS 203 seed
    /// `d ‖ z`).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid JSON, a wrong seed length, or a `pub`
    /// that does not match the seed; [`Error::UnsupportedKey`] for other
    /// algorithms.
    pub fn from_jwk(json: &[u8]) -> Result<Self> {
        let (alg, jwk, seed) = parse_private_jwk(json, KemAlg::from_jose_name)?;
        if seed.len() != KemAlg::SEED_LEN {
            return Err(Error::Malformed("JWK: ML-KEM seed must be 64 bytes"));
        }
        let pair = Self::from_seed(alg, seed)?;
        check_public_matches(&jwk, pair.public.as_bytes())?;
        Ok(pair)
    }

    /// Store as a private JWK, like the files in Tang's key directory.
    ///
    /// # Errors
    ///
    /// [`Error::SeedUnavailable`] if the seed is unknown (e.g. a key wrapped
    /// with [`from_pkey`](Self::from_pkey) that was imported in expanded form).
    pub fn to_jwk(&self) -> Result<SecretBuf> {
        let exported;
        let seed = if let Some(seed) = &self.seed {
            seed
        } else {
            exported = exported_seed(&self.pkey, KemAlg::SEED_LEN)?;
            &exported
        };
        Ok(write_private_akp(
            self.public.alg.jose_name(),
            &self.public.encoded,
            &[OP_DERIVE_KEY],
            seed.as_ref(),
        ))
    }

    /// Load from a PEM `PRIVATE KEY`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error for malformed input, [`Error::UnsupportedKey`] for a
    /// non-ML-KEM key.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Self::from_pkey(Pkey::<Private>::from_pem(pem)?)
    }

    /// Store as a PEM `PRIVATE KEY`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if encoding fails.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.pkey.to_pem()?)
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> &ExchangeKey {
        &self.public
    }

    /// ML-KEM decapsulation (FIPS 203, with implicit rejection: a modified
    /// ciphertext yields an unrelated pseudorandom secret).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a ciphertext of the wrong length,
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// the KEM, or an OpenSSL error.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecretBuf> {
        self.public.alg.ensure_allowed()?;
        if ciphertext.len() != self.public.alg.ciphertext_len() {
            return Err(Error::Malformed("ML-KEM ciphertext"));
        }
        primitives::decapsulate(&self.pkey, ciphertext)
    }
}

impl fmt::Debug for ExchangeKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ExchangeKeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

// ── Advertisement signing keys (ML-DSA) ─────────────────────────────────────

/// A server's public ML-DSA advertisement signing key.
#[derive(Clone)]
pub struct VerifyingKey {
    alg: SignatureAlg,
    pkey: Pkey<Public>,
    encoded: Box<[u8]>,
    thumbprint: Thumbprint,
}

impl VerifyingKey {
    fn from_pkey(pkey: Pkey<Public>) -> Result<Self> {
        let alg = SignatureAlg::of(&pkey).ok_or(Error::UnsupportedKey)?;
        let encoded = raw_public_key(&pkey, alg.public_key_len())?;
        let thumbprint = Thumbprint::of_akp(alg.jose_name(), &encoded)?;
        Ok(Self {
            alg,
            pkey,
            encoded,
            thumbprint,
        })
    }

    /// Decode a raw FIPS 204 public key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a wrong length, or an OpenSSL error.
    pub fn from_bytes(alg: SignatureAlg, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != alg.public_key_len() {
            return Err(Error::Malformed("ML-DSA public key"));
        }
        Self::from_pkey(
            RawKeyBuilder::new(alg.name())
                .pub_key(bytes)
                .build_public()?,
        )
    }

    pub(crate) fn from_jwk(jwk: &Jwk, alg: SignatureAlg) -> Result<Self> {
        Self::from_bytes(alg, &jwk.public_bytes()?)
    }

    pub(crate) fn to_jwk(&self) -> Jwk {
        Jwk::akp(self.alg.jose_name(), &self.encoded, &[OP_VERIFY])
    }

    /// The signature algorithm.
    #[must_use]
    pub fn alg(&self) -> SignatureAlg {
        self.alg
    }

    /// The key thumbprint clients pin (Clevis `thp`).
    #[must_use]
    pub fn thumbprint(&self) -> &Thumbprint {
        &self.thumbprint
    }

    /// The raw FIPS 204 encoding.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// Pure ML-DSA verification with the empty context, as RFC 9964 requires
    /// for JWS.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSignature`], or [`Error::DisabledBySystemPolicy`] if
    /// the system crypto policy disables the algorithm.
    pub fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        self.verify_with_context(message, b"", signature)
    }

    /// Pure ML-DSA verification with a FIPS 204 context string (at most 255
    /// bytes), for domain separation from JWS signatures by the same key.
    ///
    /// # Errors
    ///
    /// As for [`verify`](Self::verify); [`Error::Malformed`] for a context
    /// longer than 255 bytes.
    pub fn verify_with_context(
        &self,
        message: &[u8],
        context: &[u8],
        signature: &[u8],
    ) -> Result<()> {
        self.alg.ensure_allowed()?;
        if signature.len() != self.alg.signature_len() {
            return Err(Error::InvalidSignature);
        }
        let alg = native_ossl::pkey::SigAlg::fetch(self.alg.name(), None)?;
        let params = context_params(context)?;
        let mut verifier = MessageVerifier::new(&self.pkey, &alg, params.as_ref())?;
        if verifier.verify(message, signature)? {
            Ok(())
        } else {
            Err(Error::InvalidSignature)
        }
    }

    /// The public AKP JWK (`key_ops: ["verify"]`).
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // serialising plain strings cannot fail
    pub fn to_jwk_json(&self) -> String {
        serde_json::to_string(&self.to_jwk()).expect("JWK serialisation cannot fail")
    }

    /// Parse a public AKP JWK.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid JSON or a key that does not allow
    /// `verify`, [`Error::UnsupportedKey`] for other algorithms.
    pub fn from_jwk_json(json: &[u8]) -> Result<Self> {
        let jwk = Jwk::from_json(json)?;
        let alg = jwk
            .akp_alg()
            .and_then(SignatureAlg::from_jose_name)
            .ok_or(Error::UnsupportedKey)?;
        if !jwk.states(OP_VERIFY) {
            return Err(Error::Malformed("JWK: key_ops"));
        }
        Self::from_jwk(&jwk, alg)
    }
}

/// `OSSL_SIGNATURE_PARAM_CONTEXT_STRING`, or no parameters for the empty
/// context.
fn context_params(context: &[u8]) -> Result<Option<Params<'static>>> {
    if context.len() > 255 {
        return Err(Error::Malformed("ML-DSA context longer than 255 bytes"));
    }
    if context.is_empty() {
        return Ok(None);
    }
    Ok(Some(
        ParamBuilder::new()?
            .push_octet_slice(pkey_params::CONTEXT_STRING, context)?
            .build()?,
    ))
}

impl fmt::Debug for VerifyingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifyingKey")
            .field("alg", &self.alg)
            .field("thumbprint", &self.thumbprint)
            .finish_non_exhaustive()
    }
}

/// A server's ML-DSA advertisement signing key.
pub struct SigningKey {
    pkey: Pkey<Private>,
    public: VerifyingKey,
    /// FIPS 204 seed ξ, kept for JWK export (`None` for wrapped keys).
    seed: Option<SecretBuf>,
}

impl SigningKey {
    /// Generate a fresh key pair.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// `alg`, or an OpenSSL error if key generation fails.
    pub fn generate(alg: SignatureAlg) -> Result<Self> {
        alg.ensure_allowed()?;
        Self::from_seed(alg, random_seed(SignatureAlg::SEED_LEN)?)
    }

    /// Generate a key pair with the first algorithm in
    /// [`SignatureAlg::PREFERENCE`] that the system crypto policy allows.
    ///
    /// # Errors
    ///
    /// [`Error::NoAllowedAlgorithm`] if the policy allows none.
    pub fn generate_preferred() -> Result<Self> {
        Self::generate(SignatureAlg::preferred()?)
    }

    fn from_seed(alg: SignatureAlg, seed: SecretBuf) -> Result<Self> {
        let mut key = Self::from_pkey(keygen_from_seed(alg.name(), &seed)?)?;
        key.seed = Some(seed);
        Ok(key)
    }

    /// Wrap an OpenSSL ML-DSA private key (e.g. one held in an HSM).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedKey`] if it is not an ML-DSA key.
    pub fn from_pkey(pkey: Pkey<Private>) -> Result<Self> {
        let public = VerifyingKey::from_pkey(Pkey::<Public>::from(pkey.clone()))?;
        Ok(Self {
            pkey,
            public,
            seed: None,
        })
    }

    /// Load a private JWK (RFC 9964: `"kty": "AKP"`, `priv` = 32-byte seed).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid JSON, a wrong seed length, or a `pub`
    /// that does not match the seed; [`Error::UnsupportedKey`] for other
    /// algorithms.
    pub fn from_jwk(json: &[u8]) -> Result<Self> {
        let (alg, jwk, seed) = parse_private_jwk(json, SignatureAlg::from_jose_name)?;
        if seed.len() != SignatureAlg::SEED_LEN {
            return Err(Error::Malformed("JWK: ML-DSA seed must be 32 bytes"));
        }
        let key = Self::from_seed(alg, seed)?;
        check_public_matches(&jwk, key.public.as_bytes())?;
        Ok(key)
    }

    /// Store as a private JWK (RFC 9964 seed form), like the files in Tang's
    /// key directory.
    ///
    /// # Errors
    ///
    /// [`Error::SeedUnavailable`] if the seed is unknown (e.g. a key wrapped
    /// with [`from_pkey`](Self::from_pkey) that was imported in expanded form).
    pub fn to_jwk(&self) -> Result<SecretBuf> {
        let exported;
        let seed = if let Some(seed) = &self.seed {
            seed
        } else {
            exported = exported_seed(&self.pkey, SignatureAlg::SEED_LEN)?;
            &exported
        };
        Ok(write_private_akp(
            self.public.alg.jose_name(),
            &self.public.encoded,
            &[OP_SIGN, OP_VERIFY],
            seed.as_ref(),
        ))
    }

    /// Load from a PEM `PRIVATE KEY`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error for malformed input, [`Error::UnsupportedKey`] for a
    /// non-ML-DSA key.
    pub fn from_pem(pem: &[u8]) -> Result<Self> {
        Self::from_pkey(Pkey::<Private>::from_pem(pem)?)
    }

    /// Store as a PEM `PRIVATE KEY`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error if encoding fails.
    pub fn to_pem(&self) -> Result<Vec<u8>> {
        Ok(self.pkey.to_pem()?)
    }

    /// The public half.
    #[must_use]
    pub fn public(&self) -> &VerifyingKey {
        &self.public
    }

    /// Pure ML-DSA signing with the empty context, as RFC 9964 requires for
    /// JWS.  Hedged: OpenSSL draws fresh randomness for every signature.
    ///
    /// # Errors
    ///
    /// [`Error::DisabledBySystemPolicy`] if the system crypto policy disables
    /// the algorithm, or an OpenSSL error.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>> {
        self.sign_with_context(message, b"")
    }

    /// Pure ML-DSA signing with a FIPS 204 context string (at most 255
    /// bytes).
    ///
    /// # Errors
    ///
    /// As for [`sign`](Self::sign); [`Error::Malformed`] for a context longer
    /// than 255 bytes.
    pub fn sign_with_context(&self, message: &[u8], context: &[u8]) -> Result<Vec<u8>> {
        self.public.alg.ensure_allowed()?;
        let alg = native_ossl::pkey::SigAlg::fetch(self.public.alg.name(), None)?;
        let params = context_params(context)?;
        let mut signer = MessageSigner::new(&self.pkey, &alg, params.as_ref())?;
        let mut sig = vec![0u8; self.public.alg.signature_len()];
        let n = signer.sign(message, Some(&mut sig))?;
        sig.truncate(n);
        Ok(sig)
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn thumbprint_base64url_round_trip() {
        let k = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let kid = *k.public().kid();
        assert_eq!(kid.to_string().len(), 43);
        assert_eq!(kid.to_string().parse::<Thumbprint>().unwrap(), kid);
        assert!("abcd".parse::<Thumbprint>().is_err());
    }

    #[test]
    fn keys_reload_from_pem() {
        let k = ExchangeKeyPair::generate(KemAlg::MlKem1024).unwrap();
        let k2 = ExchangeKeyPair::from_pem(&k.to_pem().unwrap()).unwrap();
        assert_eq!(k.public().kid(), k2.public().kid());

        let s = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let s2 = SigningKey::from_pem(&s.to_pem().unwrap()).unwrap();
        assert_eq!(s.public().thumbprint(), s2.public().thumbprint());
        let sig = s.sign(b"adv").unwrap();
        s2.public().verify(b"adv", &sig).unwrap();
        assert!(s2.public().verify(b"adw", &sig).is_err());
    }

    #[test]
    fn signature_contexts_separate_domains() {
        let s = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let sig = s.sign_with_context(b"m", b"ctx").unwrap();
        s.public().verify_with_context(b"m", b"ctx", &sig).unwrap();
        assert!(s.public().verify(b"m", &sig).is_err());
        assert!(
            s.public()
                .verify_with_context(b"m", b"other", &sig)
                .is_err()
        );
        assert!(s.sign_with_context(b"m", &[0; 256]).is_err());
    }

    #[test]
    fn public_jwk_json_round_trip() {
        let s = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let v = VerifyingKey::from_jwk_json(s.public().to_jwk_json().as_bytes()).unwrap();
        assert_eq!(v.thumbprint(), s.public().thumbprint());
        let k = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let e = ExchangeKey::from_jwk_json(k.public().to_jwk_json().as_bytes()).unwrap();
        assert_eq!(e.kid(), k.public().kid());
        assert!(ExchangeKey::from_jwk_json(s.public().to_jwk_json().as_bytes()).is_err());
        let (ct, ss) = e.encapsulate().unwrap();
        assert_eq!(k.decapsulate(&ct).unwrap().as_ref(), ss.as_ref());
        assert!(k.decapsulate(&ct[1..]).is_err());
    }

    #[test]
    fn private_jwk_round_trip() {
        for alg in SignatureAlg::ALL {
            let s = SigningKey::generate(alg).unwrap();
            let s2 = SigningKey::from_jwk(s.to_jwk().unwrap().as_ref()).unwrap();
            assert_eq!(s.public().thumbprint(), s2.public().thumbprint());
            s2.public().verify(b"m", &s.sign(b"m").unwrap()).unwrap();
        }
        for alg in KemAlg::ALL {
            let k = ExchangeKeyPair::generate(alg).unwrap();
            let k2 = ExchangeKeyPair::from_jwk(k.to_jwk().unwrap().as_ref()).unwrap();
            assert_eq!(k.public().kid(), k2.public().kid());
        }
    }

    #[test]
    fn private_jwk_shape() {
        let s = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let v: serde_json::Value = serde_json::from_slice(s.to_jwk().unwrap().as_ref()).unwrap();
        assert_eq!(v["kty"], "AKP");
        assert_eq!(v["alg"], "ML-DSA-44");
        assert_eq!(b64::decode(v["priv"].as_str().unwrap()).unwrap().len(), 32);
        assert_eq!(b64::decode(v["pub"].as_str().unwrap()).unwrap().len(), 1312);

        let k = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let v: serde_json::Value = serde_json::from_slice(k.to_jwk().unwrap().as_ref()).unwrap();
        assert_eq!(v["alg"], "ML-KEM-768");
        assert_eq!(b64::decode(v["priv"].as_str().unwrap()).unwrap().len(), 64);
    }

    #[test]
    fn private_jwk_rejects_mismatched_pub_and_bad_seed() {
        let a = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let b = SigningKey::generate(SignatureAlg::MlDsa44).unwrap();
        let mut v: serde_json::Value =
            serde_json::from_slice(a.to_jwk().unwrap().as_ref()).unwrap();
        v["pub"] = b64::encode(b.public().as_bytes()).into();
        assert!(matches!(
            SigningKey::from_jwk(v.to_string().as_bytes()),
            Err(Error::Malformed(_))
        ));
        v["priv"] = b64::encode(&[0u8; 31]).into();
        assert!(SigningKey::from_jwk(v.to_string().as_bytes()).is_err());

        // An ML-KEM JWK is not a signing key.
        let kem = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        assert!(matches!(
            SigningKey::from_jwk(kem.to_jwk().unwrap().as_ref()),
            Err(Error::UnsupportedKey)
        ));
    }

    #[test]
    fn kinds_are_not_interchangeable() {
        let kem = KeygenCtx::new(c"ML-KEM-768").unwrap().generate().unwrap();
        let dsa = KeygenCtx::new(c"ML-DSA-44").unwrap().generate().unwrap();
        assert!(matches!(
            SigningKey::from_pkey(kem),
            Err(Error::UnsupportedKey)
        ));
        assert!(matches!(
            ExchangeKeyPair::from_pkey(dsa),
            Err(Error::UnsupportedKey)
        ));
    }
}
