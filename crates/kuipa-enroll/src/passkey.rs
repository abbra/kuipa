//! Passkeys as a seal factor (§7.6.5): CTAP assertions verified against a
//! user's IPA passkeys (`ipaPassKey`), with kuipad as the relying party.
//!
//! Borrowed from ahdapa's WebAuthn verifier (`src/auth/passkey.rs`) and
//! adapted to CTAP-level assertions.  The client is `kuipa`, which talks to
//! the authenticator through libfido2 as SSSD's `passkey_child` does, so
//! the authenticator signs `authenticatorData ‖ clientDataHash` with the
//! request's own hash as `clientDataHash`: there is no browser and no
//! `clientDataJSON`, hence no origin to check.  The RP ID is the one the
//! realm's passkeys are registered under, the IPA domain.
//!
//! The classical algorithms every FreeIPA and SSSD version registers
//! (ES256, EdDSA, RS256) are accepted, and so are ES384 and the
//! post-quantum ML-DSA-44, ML-DSA-65 and ML-DSA-87 (FIPS 204) that SSSD
//! registers when built against a libfido2 supporting them.  IPA stores
//! the public key as SPKI, so the algorithm follows from the key: each key
//! type has exactly one signature algorithm.
//!
//! IPA keeps no signature counter, so none is checked, as SSSD checks
//! none: a cloned authenticator is not detected.

use native_ossl::digest::DigestAlg;
use native_ossl::pkey::{Pkey, Public, SignInit, Verifier};
use native_ossl::pkey_params;
use serde::{Deserialize, Serialize};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{SignatureAlg, VerifyingKey, b64, primitives};

use crate::error::{Error, Result};

const ASSERTION_MAGIC: [u8; 4] = *b"IPPA";

// authenticatorData flag bits (WebAuthn §6.1).
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// `rpIdHash(32) flags(1) signCount(4)`: the shortest authenticatorData.
const AUTH_DATA_MIN: usize = 37;

/// WebAuthn §7.1 step 22: credential IDs longer than this are refused.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// SPKI prefixes of the two NIST curves FreeIPA passkeys use: the
/// `AlgorithmIdentifier` `id-ecPublicKey` with the named curve, and the
/// BIT STRING header of an uncompressed point.
const P256_SPKI_PREFIX: &[u8] = &[
    0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
    0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04,
];
const P384_SPKI_PREFIX: &[u8] = &[
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04,
];

/// A passkey's signature algorithm, as COSE (RFC 9053, RFC 9964) names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA with P-256 and SHA-256.
    Es256,
    /// ECDSA with P-384 and SHA-384.
    Es384,
    /// Ed25519.
    EdDsa,
    /// RSASSA-PKCS1-v1_5 with SHA-256.
    Rs256,
    /// Pure ML-DSA with the empty context.
    MlDsa(SignatureAlg),
}

impl Algorithm {
    /// Every algorithm, the post-quantum ones last.
    pub const ALL: [Self; 7] = [
        Self::Es256,
        Self::Es384,
        Self::EdDsa,
        Self::Rs256,
        Self::MlDsa(SignatureAlg::MlDsa44),
        Self::MlDsa(SignatureAlg::MlDsa65),
        Self::MlDsa(SignatureAlg::MlDsa87),
    ];

    /// The algorithm of a COSE identifier, if it is one of these.
    #[must_use]
    pub fn from_cose(cose: i64) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.cose() == cose)
    }

    /// The algorithm [`name`](Self::name) names.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|a| a.name() == name)
    }

    /// The COSE algorithm identifier.
    #[must_use]
    pub const fn cose(self) -> i64 {
        match self {
            Self::Es256 => -7,
            Self::Es384 => -35,
            Self::EdDsa => -8,
            Self::Rs256 => -257,
            Self::MlDsa(SignatureAlg::MlDsa44) => -48,
            Self::MlDsa(SignatureAlg::MlDsa65) => -49,
            Self::MlDsa(SignatureAlg::MlDsa87) => -50,
        }
    }

    /// The name SSSD's `passkey_child --type` and `ipa user-add-passkey
    /// --cose-type` use.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Es256 => "es256",
            Self::Es384 => "es384",
            Self::EdDsa => "eddsa",
            Self::Rs256 => "rs256",
            Self::MlDsa(SignatureAlg::MlDsa44) => "mldsa44",
            Self::MlDsa(SignatureAlg::MlDsa65) => "mldsa65",
            Self::MlDsa(SignatureAlg::MlDsa87) => "mldsa87",
        }
    }

    /// Whether this is a post-quantum algorithm.
    #[must_use]
    pub const fn is_post_quantum(self) -> bool {
        matches!(self, Self::MlDsa(_))
    }
}

/// One of a user's IPA passkeys: its credential ID and public key.
#[derive(Clone)]
pub struct PasskeyKey {
    credential_id: Vec<u8>,
    alg: Algorithm,
    key: Pkey<Public>,
}

impl std::fmt::Debug for PasskeyKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PasskeyKey")
            .field("credential_id", &b64::encode(&self.credential_id))
            .field("alg", &self.alg)
            .finish_non_exhaustive()
    }
}

impl PasskeyKey {
    /// Parse an `ipaPassKey` value, `passkey:<credential id>,<public
    /// key>[,<user id>]`: the credential ID in base64, the public key as
    /// the base64 body of a PEM `PUBLIC KEY` block (SPKI).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], or [`Error::Passkey`] for a key of an
    /// unsupported algorithm.
    pub fn from_ipa(value: &str) -> Result<Self> {
        let rest = value
            .strip_prefix("passkey:")
            .ok_or(Error::Malformed("passkey mapping"))?;
        let mut parts = rest.splitn(3, ',');
        let id = std_b64_decode(parts.next().unwrap_or_default())
            .ok_or(Error::Malformed("passkey credential id"))?;
        let spki = std_b64_decode(parts.next().unwrap_or_default())
            .ok_or(Error::Malformed("passkey public key"))?;
        Self::from_spki(id, &spki)
    }

    /// A passkey from its credential ID and SPKI public key.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], or [`Error::Passkey`] for a key of an
    /// unsupported algorithm.
    pub fn from_spki(credential_id: Vec<u8>, spki: &[u8]) -> Result<Self> {
        if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(Error::Malformed("passkey credential id"));
        }
        let key = Pkey::<Public>::from_der(spki).map_err(|_| Error::Malformed("passkey key"))?;
        let alg = if key.is_a(c"EC") {
            // The DER as OpenSSL writes it names the curve.
            let der = key.public_key_to_der()?;
            if der.len() == 91 && der.starts_with(P256_SPKI_PREFIX) {
                Algorithm::Es256
            } else if der.len() == 120 && der.starts_with(P384_SPKI_PREFIX) {
                Algorithm::Es384
            } else {
                return Err(Error::Passkey(
                    "an EC passkey on a curve other than P-256 or P-384",
                ));
            }
        } else if key.is_a(c"ED25519") {
            Algorithm::EdDsa
        } else if key.is_a(c"RSA") {
            if key.bits() < 2048 {
                return Err(Error::Passkey("an RSA passkey shorter than 2048 bits"));
            }
            Algorithm::Rs256
        } else if let Some(alg) = SignatureAlg::ALL.into_iter().find(|a| key.is_a(a.name())) {
            Algorithm::MlDsa(alg)
        } else {
            return Err(Error::Passkey("a passkey of an unsupported algorithm"));
        };
        Ok(Self {
            credential_id,
            alg,
            key,
        })
    }

    /// The credential ID.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The signature algorithm.
    #[must_use]
    pub fn alg(&self) -> Algorithm {
        self.alg
    }

    /// Verify `signature` over `data`, as the passkey's algorithm signs.
    fn verify_signature(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let bad = || Error::Passkey("the assertion's signature does not verify");
        if let Algorithm::MlDsa(alg) = self.alg {
            let raw = self.key.export()?;
            let raw = raw.get_octet_string(pkey_params::PUB_KEY)?;
            return VerifyingKey::from_bytes(alg, raw)?
                .verify(data, signature)
                .map_err(|_| bad());
        }
        let digest = match self.alg {
            Algorithm::Es256 | Algorithm::Rs256 => {
                Some(DigestAlg::fetch(primitives::SHA256, None)?)
            }
            Algorithm::Es384 => Some(DigestAlg::fetch(primitives::SHA384, None)?),
            // Ed25519 is one-shot, without a separate digest.
            Algorithm::EdDsa | Algorithm::MlDsa(_) => None,
        };
        // ECDSA signatures are DER, as WebAuthn and CTAP give them; RSA
        // uses PKCS#1 v1.5, OpenSSL's default padding.
        let mut verifier = Verifier::new(&self.key, &SignInit::new(digest.as_ref(), None))?;
        if verifier.verify_oneshot(data, signature).unwrap_or(false) {
            Ok(())
        } else {
            Err(bad())
        }
    }
}

/// The standard base64 (RFC 4648 §4, padded) IPA stores passkeys in.
fn std_b64_decode(s: &str) -> Option<Vec<u8>> {
    if s.is_empty() || s.contains(['-', '_']) {
        return None;
    }
    let url: String = s
        .trim_end_matches('=')
        .chars()
        .map(|c| match c {
            '+' => '-',
            '/' => '_',
            c => c,
        })
        .collect();
    b64::decode(&url).ok()
}

/// What an assertion was checked for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Verified {
    /// The passkey's algorithm.
    pub alg: Algorithm,
    /// Whether the authenticator verified the user (PIN or biometrics).
    pub user_verified: bool,
}

/// A CTAP assertion (`authenticatorGetAssertion`): which credential signed,
/// the raw authenticator data and the signature over `authData ‖
/// clientDataHash`.  `IPPA credential_id authenticator_data signature`.
#[derive(Clone, PartialEq, Eq)]
pub struct Assertion {
    /// The credential's ID.
    pub credential_id: Vec<u8>,
    /// The raw authenticator data (not CBOR-wrapped).
    pub authenticator_data: Vec<u8>,
    /// The signature.
    pub signature: Vec<u8>,
}

impl std::fmt::Debug for Assertion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Assertion")
            .field("credential_id", &b64::encode(&self.credential_id))
            .finish_non_exhaustive()
    }
}

impl Assertion {
    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(ASSERTION_MAGIC)
            .bytes(&self.credential_id)
            .bytes(&self.authenticator_data)
            .bytes(&self.signature)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, ASSERTION_MAGIC, "passkey assertion")?;
        let a = Self {
            credential_id: r.bytes()?.to_vec(),
            authenticator_data: r.bytes()?.to_vec(),
            signature: r.bytes()?.to_vec(),
        };
        r.finish()?;
        Ok(a)
    }

    /// Verify against `keys`, a user's passkeys (WebAuthn §7.2 steps 5,
    /// 15-21, without the client data): the credential must be one of
    /// them, the authenticator data for `rp_id` with the user present and,
    /// when `user_verification` is required, verified, and the signature
    /// made over `client_data_hash`.
    ///
    /// # Errors
    ///
    /// [`Error::Passkey`] naming what failed.
    pub fn verify(
        &self,
        keys: &[PasskeyKey],
        rp_id: &str,
        client_data_hash: &[u8; 32],
        user_verification: bool,
    ) -> Result<Verified> {
        let key = keys
            .iter()
            .find(|k| k.credential_id == self.credential_id)
            .ok_or(Error::Passkey(
                "the assertion is from none of the user's passkeys",
            ))?;
        let auth_data = &self.authenticator_data;
        if auth_data.len() < AUTH_DATA_MIN {
            return Err(Error::Malformed("passkey authenticator data"));
        }
        if auth_data[..32] != primitives::sha256(&[rp_id.as_bytes()])?[..] {
            return Err(Error::Passkey("the assertion is for another relying party"));
        }
        let flags = auth_data[32];
        if flags & FLAG_UP == 0 {
            return Err(Error::Passkey("the user was not present"));
        }
        let user_verified = flags & FLAG_UV != 0;
        if user_verification && !user_verified {
            return Err(Error::Passkey("the authenticator did not verify the user"));
        }
        let mut signed = Vec::with_capacity(auth_data.len() + client_data_hash.len());
        signed.extend_from_slice(auth_data);
        signed.extend_from_slice(client_data_hash);
        key.verify_signature(&signed, &self.signature)?;
        Ok(Verified {
            alg: key.alg,
            user_verified,
        })
    }
}

/// A user's passkeys as the directory holds them: the `ipaPassKey`
/// values, and whether the realm requires user verification
/// (`ipa passkeyconfig`, `ipaRequireUserVerification`).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct UserPasskeys {
    /// The `ipaPassKey` values.
    pub values: Vec<String>,
    /// Whether every assertion must verify the user.
    pub user_verification: bool,
}

impl UserPasskeys {
    /// The passkeys this build can verify; others (a key type a newer IPA
    /// accepts) are skipped.
    #[must_use]
    pub fn keys(&self) -> Vec<PasskeyKey> {
        self.values
            .iter()
            .filter_map(|v| PasskeyKey::from_ipa(v).ok())
            .collect()
    }
}

/// What a client needs to ask its authenticator for an assertion: the RP
/// ID, whether to verify the user, and the credential IDs to allow
/// (base64url), its user's passkeys.  The answer to the seal operation
/// `passkeys`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyInfo {
    /// The relying party ID: the IPA domain.
    pub rp_id: String,
    /// Whether the assertion must verify the user.
    pub user_verification: bool,
    /// The credential IDs, base64url, with their algorithms.
    pub credentials: Vec<PasskeyCredential>,
}

/// One of a user's passkeys, as a client sees it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasskeyCredential {
    /// The credential ID, base64url.
    pub id: String,
    /// Its algorithm ([`Algorithm::name`]).
    pub alg: String,
}

impl PasskeyInfo {
    /// The info for `passkeys` under relying party `rp_id`.
    #[must_use]
    pub fn of(rp_id: &str, passkeys: &UserPasskeys) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            user_verification: passkeys.user_verification,
            credentials: passkeys
                .keys()
                .iter()
                .map(|k| PasskeyCredential {
                    id: b64::encode(&k.credential_id),
                    alg: k.alg.name().to_owned(),
                })
                .collect(),
        }
    }

    /// The credential IDs to allow.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn credential_ids(&self) -> Result<Vec<Vec<u8>>> {
        self.credentials
            .iter()
            .map(|c| b64::decode(&c.id).map_err(Error::from))
            .collect()
    }
}

/// A software authenticator, for tests of the passkey factor and of
/// passkey-wrapped device keys: one credential of a given algorithm, with
/// an `hmac-secret` stand-in.
#[cfg(any(test, feature = "testing"))]
pub mod soft {
    use native_ossl::params::ParamBuilder;
    use native_ossl::pkey::{KeygenCtx, Private, Signer};
    use native_ossl::rand::Rand;
    use tang_pqc::SigningKey;

    use super::{
        Algorithm, Assertion, DigestAlg, FLAG_UP, FLAG_UV, Pkey, Public, SignInit, b64, primitives,
    };

    /// One credential: its ID, key and `hmac-secret` key.
    pub struct SoftAuthenticator {
        id: Vec<u8>,
        alg: Algorithm,
        classic: Option<Pkey<Private>>,
        ml_dsa: Option<SigningKey>,
        cred_random: [u8; 32],
    }

    fn keygen(name: &std::ffi::CStr, group: Option<&std::ffi::CStr>) -> Pkey<Private> {
        let mut kg = KeygenCtx::new(name).expect("keygen");
        if let Some(group) = group {
            let params = ParamBuilder::new()
                .and_then(|b| b.push_utf8_string(c"group", group))
                .and_then(ParamBuilder::build)
                .expect("EC group");
            kg.set_params(&params).expect("EC group");
        }
        kg.generate().expect("keygen")
    }

    impl SoftAuthenticator {
        /// A new credential of `alg`.
        ///
        /// # Panics
        ///
        /// If OpenSSL cannot make the key.
        #[must_use]
        pub fn new(alg: Algorithm) -> Self {
            let (classic, ml_dsa) = match alg {
                Algorithm::Es256 => (Some(keygen(c"EC", Some(c"P-256"))), None),
                Algorithm::Es384 => (Some(keygen(c"EC", Some(c"P-384"))), None),
                Algorithm::EdDsa => (Some(keygen(c"ED25519", None)), None),
                Algorithm::Rs256 => (Some(keygen(c"RSA", None)), None),
                Algorithm::MlDsa(a) => (None, Some(SigningKey::generate(a).expect("ML-DSA"))),
            };
            let mut id = vec![0u8; 32];
            let mut cred_random = [0u8; 32];
            Rand::fill(&mut id).expect("random");
            Rand::fill(&mut cred_random).expect("random");
            Self {
                id,
                alg,
                classic,
                ml_dsa,
                cred_random,
            }
        }

        /// One credential of every algorithm.
        #[must_use]
        pub fn all() -> Vec<Self> {
            Algorithm::ALL.into_iter().map(Self::new).collect()
        }

        /// The credential as JSON, its private key (PEM) included, for a
        /// software key kept in a file.
        ///
        /// # Panics
        ///
        /// If OpenSSL cannot write the key.
        #[must_use]
        pub fn to_json(&self) -> serde_json::Value {
            let pem = match (&self.classic, &self.ml_dsa) {
                (Some(k), _) => k.to_pem().expect("PEM"),
                (None, Some(k)) => k.to_pem().expect("PEM"),
                (None, None) => unreachable!("a credential has a key"),
            };
            serde_json::json!({
                "id": b64::encode(&self.id),
                "alg": self.alg.cose(),
                "key": String::from_utf8_lossy(&pem),
                "cred_random": b64::encode(&self.cred_random),
            })
        }

        /// A credential [`to_json`](Self::to_json) wrote.
        #[must_use]
        pub fn from_json(v: &serde_json::Value) -> Option<Self> {
            let alg = Algorithm::from_cose(v.get("alg")?.as_i64()?)?;
            let pem = v.get("key")?.as_str()?.as_bytes();
            let (classic, ml_dsa) = match alg {
                Algorithm::MlDsa(_) => (None, Some(SigningKey::from_pem(pem).ok()?)),
                _ => (Some(Pkey::<Private>::from_pem(pem).ok()?), None),
            };
            Some(Self {
                id: b64::decode(v.get("id")?.as_str()?).ok()?,
                alg,
                classic,
                ml_dsa,
                cred_random: b64::decode(v.get("cred_random")?.as_str()?)
                    .ok()?
                    .try_into()
                    .ok()?,
            })
        }

        /// The credential ID.
        #[must_use]
        pub fn id(&self) -> &[u8] {
            &self.id
        }

        /// The algorithm.
        #[must_use]
        pub fn alg(&self) -> Algorithm {
            self.alg
        }

        fn spki(&self) -> Vec<u8> {
            if let Some(k) = &self.classic {
                return Pkey::<Public>::from(k.clone())
                    .public_key_to_der()
                    .expect("SPKI");
            }
            let public = self.ml_dsa.as_ref().expect("a key").public();
            native_ossl::pkey_builder::RawKeyBuilder::new(public.alg().name())
                .pub_key(public.as_bytes())
                .build_public()
                .and_then(|k| k.public_key_to_der())
                .expect("SPKI")
        }

        /// The `ipaPassKey` value IPA would store for the credential.
        #[must_use]
        pub fn ipa_value(&self) -> String {
            let std = |b: &[u8]| {
                let mut s = b64::encode(b).replace('-', "+").replace('_', "/");
                while !s.len().is_multiple_of(4) {
                    s.push('=');
                }
                s
            };
            format!("passkey:{},{}", std(&self.id), std(&self.spki()))
        }

        /// An assertion for `rp_id` over `client_data_hash`, with the
        /// authenticator data `flags` (`0x01` user present, `0x04`
        /// verified).
        ///
        /// # Panics
        ///
        /// If OpenSSL cannot sign.
        #[must_use]
        pub fn assert_with(
            &self,
            rp_id: &str,
            client_data_hash: &[u8; 32],
            flags: u8,
        ) -> Assertion {
            let mut auth_data = primitives::sha256(&[rp_id.as_bytes()])
                .expect("SHA-256")
                .to_vec();
            auth_data.push(flags);
            auth_data.extend_from_slice(&7u32.to_be_bytes());
            let mut signed = auth_data.clone();
            signed.extend_from_slice(client_data_hash);
            let signature = if let Some(k) = &self.ml_dsa {
                k.sign(&signed).expect("ML-DSA")
            } else {
                let digest = match self.alg {
                    Algorithm::Es256 | Algorithm::Rs256 => Some(primitives::SHA256),
                    Algorithm::Es384 => Some(primitives::SHA384),
                    Algorithm::EdDsa | Algorithm::MlDsa(_) => None,
                }
                .map(|h| DigestAlg::fetch(h, None).expect("digest"));
                Signer::new(
                    self.classic.as_ref().expect("a key"),
                    &SignInit::new(digest.as_ref(), None),
                )
                .and_then(|mut s| s.sign_oneshot(&signed))
                .expect("signature")
            };
            Assertion {
                credential_id: self.id.clone(),
                authenticator_data: auth_data,
                signature,
            }
        }

        /// An assertion for `rp_id` over `client_data_hash`, the user
        /// present and verified.
        #[must_use]
        pub fn assert(&self, rp_id: &str, client_data_hash: &[u8; 32]) -> Assertion {
            self.assert_with(rp_id, client_data_hash, FLAG_UP | FLAG_UV)
        }

        /// The `hmac-secret` output for `salt`: a stand-in for
        /// `HMAC-SHA-256(CredRandom, salt)`, the same for the same salt.
        ///
        /// # Panics
        ///
        /// If OpenSSL cannot hash.
        #[must_use]
        pub fn hmac_secret(&self, salt: &[u8; 32]) -> [u8; 32] {
            primitives::sha256(&[&self.cred_random, salt]).expect("SHA-256")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::soft::SoftAuthenticator;
    use super::*;

    const RP_ID: &str = "example.test";

    fn keys_of(auths: &[SoftAuthenticator]) -> Vec<PasskeyKey> {
        auths
            .iter()
            .map(|a| PasskeyKey::from_ipa(&a.ipa_value()).unwrap())
            .collect()
    }

    #[test]
    fn every_algorithm_verifies_from_its_ipa_mapping() {
        let auths = SoftAuthenticator::all();
        let keys = keys_of(&auths);
        let cdh = [9u8; 32];
        for a in &auths {
            let got = a
                .assert(RP_ID, &cdh)
                .verify(&keys, RP_ID, &cdh, true)
                .unwrap();
            assert_eq!(got.alg, a.alg());
            assert!(got.user_verified);
            assert_eq!(
                got.alg.is_post_quantum(),
                matches!(a.alg(), Algorithm::MlDsa(_))
            );
        }
    }

    #[test]
    fn a_signature_over_another_challenge_fails() {
        let auths = SoftAuthenticator::all();
        let keys = keys_of(&auths);
        for a in &auths {
            let err = a
                .assert(RP_ID, &[1u8; 32])
                .verify(&keys, RP_ID, &[2u8; 32], false)
                .unwrap_err();
            assert!(err.to_string().contains("does not verify"), "{err}");
        }
    }

    #[test]
    fn the_relying_party_presence_and_verification_are_checked() {
        let a = SoftAuthenticator::new(Algorithm::Es256);
        let keys = keys_of(std::slice::from_ref(&a));
        let cdh = [3u8; 32];
        let err = a
            .assert_with("other.test", &cdh, FLAG_UP | FLAG_UV)
            .verify(&keys, RP_ID, &cdh, false)
            .unwrap_err();
        assert!(err.to_string().contains("another relying party"), "{err}");
        let err = a
            .assert_with(RP_ID, &cdh, FLAG_UV)
            .verify(&keys, RP_ID, &cdh, false)
            .unwrap_err();
        assert!(err.to_string().contains("not present"), "{err}");
        let unverified = a.assert_with(RP_ID, &cdh, FLAG_UP);
        assert!(unverified.verify(&keys, RP_ID, &cdh, true).is_err());
        assert!(
            !unverified
                .verify(&keys, RP_ID, &cdh, false)
                .unwrap()
                .user_verified
        );
    }

    #[test]
    fn another_users_passkey_is_refused() {
        let mine = SoftAuthenticator::new(Algorithm::MlDsa(SignatureAlg::MlDsa65));
        let theirs = SoftAuthenticator::new(Algorithm::EdDsa);
        let cdh = [4u8; 32];
        let err = theirs
            .assert(RP_ID, &cdh)
            .verify(&keys_of(&[mine]), RP_ID, &cdh, false)
            .unwrap_err();
        assert!(err.to_string().contains("none of the user's"), "{err}");
    }

    #[test]
    fn assertions_round_trip_and_mappings_are_strict() {
        let a = SoftAuthenticator::new(Algorithm::Rs256);
        let assertion = a.assert(RP_ID, &[5u8; 32]);
        assert_eq!(
            Assertion::from_bytes(&assertion.to_bytes()).unwrap(),
            assertion
        );
        let value = a.ipa_value();
        assert!(PasskeyKey::from_ipa(&format!("{value},dXNlcg==")).is_ok());
        assert!(PasskeyKey::from_ipa(value.trim_start_matches("passkey:")).is_err());
        assert!(PasskeyKey::from_ipa("passkey:,AAAA").is_err());
        assert!(PasskeyKey::from_ipa("passkey:AAAA,notakey").is_err());
    }

    #[test]
    fn soft_credentials_survive_a_file() {
        let cdh = [6u8; 32];
        for a in SoftAuthenticator::all() {
            let back = SoftAuthenticator::from_json(&a.to_json()).unwrap();
            assert_eq!(back.id(), a.id());
            assert_eq!(back.hmac_secret(&cdh), a.hmac_secret(&cdh));
            let keys = [PasskeyKey::from_ipa(&a.ipa_value()).unwrap()];
            back.assert(RP_ID, &cdh)
                .verify(&keys, RP_ID, &cdh, true)
                .unwrap();
        }
        assert_eq!(
            Algorithm::from_name("mldsa44").map(Algorithm::cose),
            Some(-48)
        );
    }

    #[test]
    fn info_lists_the_keys_this_build_verifies() {
        let a = SoftAuthenticator::new(Algorithm::MlDsa(SignatureAlg::MlDsa87));
        let passkeys = UserPasskeys {
            values: vec![a.ipa_value(), "passkey:AAAA,garbage".to_owned()],
            user_verification: true,
        };
        let info = PasskeyInfo::of(RP_ID, &passkeys);
        assert_eq!(info.credentials.len(), 1);
        assert_eq!(info.credentials[0].alg, "mldsa87");
        assert_eq!(info.credential_ids().unwrap(), vec![a.id().to_vec()]);
        assert!(info.user_verification);
    }
}
