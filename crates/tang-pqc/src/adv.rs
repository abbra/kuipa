//! Signed server advertisements (the Tang `GET /adv` payload).
//!
//! As in Tang, the advertisement is a JWS in General JSON Serialization
//! (RFC 7515 §7.2.1) whose payload is a JWK Set.  Each signature has the
//! protected header `{"alg":"ML-DSA-…","cty":"jwk-set+json"}` and is an
//! RFC 9964 ML-DSA signature (pure, empty context) over
//! `BASE64URL(header) ‖ "." ‖ BASE64URL(payload)`.
//!
//! Signing keys are AKP JWKs with `key_ops: ["verify"]`, and exchange keys
//! are AKP JWKs with `key_ops: ["deriveKey"]`.  Keys of other types (e.g. a
//! classic Tang `ES512`/`ECMR` pair) may share the set and are ignored.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::alg::{KemAlg, SignatureAlg};
use crate::b64;
use crate::error::{Error, Result};
use crate::jwk::{Jwk, akp_thumbprint};
use crate::keys::{ExchangeKey, OP_DERIVE_KEY, OP_VERIFY, SigningKey, Thumbprint, VerifyingKey};
use crate::policy::{Policy, unix_seconds};

/// JWS `cty` used by Tang for advertisements.
const CTY_JWK_SET: &str = "jwk-set+json";

/// Most bytes of an accepted advertisement (the JSON document).  Real ones
/// are a few KiB: a handful of ML-DSA/ML-KEM keys and signatures.  A larger
/// one is either broken or hostile, and parsing it — let alone verifying a
/// signature per JWS `signatures` entry — costs CPU and memory before the
/// pinned key's signature rejects it.
pub const MAX_ADVERTISEMENT_BYTES: usize = 256 * 1024;

/// Most JWS signatures in one advertisement.  Real servers emit one to a
/// handful (one per current signing key).
const MAX_SIGNATURES: usize = 16;

/// Most keys in one advertisement's JWK Set.
const MAX_KEYS: usize = 256;

#[derive(Serialize, Deserialize)]
struct JwkSet {
    keys: Vec<Jwk>,
    /// Extension members (RFC 7517 §5 allows them; unknown ones are ignored).
    #[serde(flatten)]
    extra: Map<String, Value>,
}

#[derive(Serialize, Deserialize)]
struct ProtectedHeader {
    alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cty: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    /// Issued-at and expiry (Unix seconds), JWT claims replicated as header
    /// parameters (RFC 7519 §5.3) so the signature covers them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    iat: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exp: Option<u64>,
}

/// Validity period of a signed advertisement, in Unix seconds.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Lifetime {
    pub(crate) iat: u64,
    pub(crate) exp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct JwsSignature {
    protected: String,
    signature: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct GeneralJws {
    payload: String,
    signatures: Vec<JwsSignature>,
}

/// A verified advertisement: the server's signing keys and exchange keys.
///
/// The only way to obtain one is [`SignedAdvertisement::verify`], so holding
/// an `Advertisement` means its signature was checked against a trusted key.
#[derive(Clone, Debug)]
pub struct Advertisement {
    signing_keys: Vec<VerifyingKey>,
    /// Exchange keys without extension members (plain Tang keys).
    exchange_keys: Vec<ExchangeKey>,
    /// Exchange keys with extension members, and those members.
    tagged_keys: Vec<(ExchangeKey, Map<String, Value>)>,
    members: Map<String, Value>,
    trusted: Thumbprint,
}

impl Advertisement {
    /// The server's advertisement signing keys.
    #[must_use]
    pub fn signing_keys(&self) -> &[VerifyingKey] {
        &self.signing_keys
    }

    /// The exchange keys offered for new bindings.
    ///
    /// Only keys without extension members are listed, so a key published
    /// for another role (see [`AdvertisementBuilder::exchange_key_with`]) is
    /// never picked by a plain Tang client.
    #[must_use]
    pub fn exchange_keys(&self) -> &[ExchangeKey] {
        &self.exchange_keys
    }

    /// The exchange keys whose JWK has the string member `member` equal to
    /// `value`, in advertisement order.
    pub fn exchange_keys_where<'a>(
        &'a self,
        member: &'a str,
        value: &'a str,
    ) -> impl Iterator<Item = &'a ExchangeKey> + 'a {
        self.tagged_keys
            .iter()
            .filter(move |(_, m)| m.get(member).and_then(Value::as_str) == Some(value))
            .map(|(k, _)| k)
    }

    /// A signed extension member of the JWK Set.
    #[must_use]
    pub fn member(&self, name: &str) -> Option<&Value> {
        self.members.get(name)
    }

    /// The signing key this advertisement was verified against.
    #[must_use]
    pub fn trusted_thumbprint(&self) -> &Thumbprint {
        &self.trusted
    }

    /// The exchange key with id `kid`, if advertised (with or without
    /// extension members).
    #[must_use]
    pub fn exchange_key(&self, kid: &Thumbprint) -> Option<&ExchangeKey> {
        self.exchange_keys
            .iter()
            .chain(self.tagged_keys.iter().map(|(k, _)| k))
            .find(|k| k.kid() == kid)
    }
}

/// The ML-DSA algorithm of an advertised signing key, if it is one.
fn signing_alg(jwk: &Jwk) -> Option<SignatureAlg> {
    jwk.akp_alg()
        .and_then(SignatureAlg::from_jose_name)
        .filter(|_| jwk.states(OP_VERIFY))
}

/// The ML-KEM algorithm of an advertised exchange key, if it is one.
fn exchange_alg(jwk: &Jwk) -> Option<KemAlg> {
    jwk.akp_alg()
        .and_then(KemAlg::from_jose_name)
        .filter(|_| jwk.states(OP_DERIVE_KEY))
}

/// An advertisement as served at `GET /adv`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAdvertisement {
    jws: GeneralJws,
}

impl SignedAdvertisement {
    pub(crate) fn sign(
        signing: &[&SigningKey],
        exchange: &[&ExchangeKey],
        lifetime: Option<Lifetime>,
    ) -> Result<Self> {
        let mut builder = AdvertisementBuilder::new(signing);
        for key in exchange {
            builder = builder.exchange_key(key);
        }
        if let Some(l) = lifetime {
            builder = builder.validity(l.iat, l.exp);
        }
        builder.sign()
    }

    fn sign_key_set(
        signing: &[&SigningKey],
        set: &JwkSet,
        lifetime: Option<Lifetime>,
    ) -> Result<Self> {
        let payload =
            b64::encode(&serde_json::to_vec(set).expect("JWK Set serialisation cannot fail"));
        let signatures = signing
            .iter()
            .map(|k| {
                let header = ProtectedHeader {
                    alg: k.public().alg().jose_name().into(),
                    cty: Some(CTY_JWK_SET.into()),
                    crit: None,
                    iat: lifetime.map(|l| l.iat),
                    exp: lifetime.map(|l| l.exp),
                };
                let protected = b64::encode(
                    &serde_json::to_vec(&header).expect("header serialisation cannot fail"),
                );
                let signature = k.sign(format!("{protected}.{payload}").as_bytes())?;
                Ok(JwsSignature {
                    protected,
                    signature: b64::encode(&signature),
                })
            })
            .collect::<Result<_>>()?;
        Ok(Self {
            jws: GeneralJws {
                payload,
                signatures,
            },
        })
    }

    fn key_set(&self) -> Result<JwkSet> {
        let payload = b64::decode(&self.jws.payload)?;
        if payload.len() > MAX_ADVERTISEMENT_BYTES {
            return Err(Error::Malformed("advertisement JWK Set too large"));
        }
        let set: JwkSet = serde_json::from_slice(&payload)
            .map_err(|_| Error::Malformed("advertisement JWK Set"))?;
        if set.keys.len() > MAX_KEYS {
            return Err(Error::Malformed("advertisement JWK Set has too many keys"));
        }
        Ok(set)
    }

    /// The protected header of `sig` if it verifies under `key`.  Signatures
    /// with an unexpected `alg` or `cty`, or with critical header parameters
    /// we do not understand, never verify.
    fn signed_by(&self, key: &VerifyingKey, sig: &JwsSignature) -> Option<ProtectedHeader> {
        let header: ProtectedHeader =
            serde_json::from_slice(&b64::decode(&sig.protected).ok()?).ok()?;
        if header.crit.is_some()
            || header.alg != key.alg().jose_name()
            || header.cty.as_deref() != Some(CTY_JWK_SET)
        {
            return None;
        }
        let signature = b64::decode(&sig.signature).ok()?;
        let input = format!("{}.{}", sig.protected, self.jws.payload);
        key.verify(input.as_bytes(), &signature).ok()?;
        Some(header)
    }

    /// Verify against a pinned signing key thumbprint (Clevis `thp`) under
    /// the default [`Policy`].
    ///
    /// # Errors
    ///
    /// As for [`verify_at`](Self::verify_at).
    pub fn verify(&self, trusted: &Thumbprint) -> Result<Advertisement> {
        self.verify_with(trusted, &Policy::default())
    }

    /// Verify against a pinned signing key thumbprint under `policy`.
    ///
    /// # Errors
    ///
    /// As for [`verify_at`](Self::verify_at).
    pub fn verify_with(&self, trusted: &Thumbprint, policy: &Policy) -> Result<Advertisement> {
        self.verify_at(trusted, policy, SystemTime::now())
    }

    /// Verify against a pinned signing key thumbprint under `policy`, as of
    /// time `now`.
    ///
    /// * The trusted key must be in the JWK Set with `key_ops` allowing
    ///   `verify`, and its algorithm must be allowed by the policy.
    /// * One of the JWS signatures must verify under it, and that
    ///   signature's protected `iat`/`exp` must satisfy the policy.
    /// * Exchange keys whose KEM the policy, or the system crypto policy,
    ///   does not allow are dropped.
    ///
    /// Signatures by other keys are ignored.
    ///
    /// # Errors
    ///
    /// * [`Error::UntrustedAdvertisement`]: the trusted key is absent.
    /// * [`Error::Policy`]: its algorithm or the validity period is not
    ///   allowed.
    /// * [`Error::DisabledBySystemPolicy`]: the system crypto policy disables
    ///   its algorithm.
    /// * [`Error::InvalidSignature`]: no signature by it verifies.
    /// * [`Error::StaleAdvertisement`]: it is expired or not yet valid.
    /// * [`Error::Malformed`]: the advertisement cannot be parsed.
    pub fn verify_at(
        &self,
        trusted: &Thumbprint,
        policy: &Policy,
        now: SystemTime,
    ) -> Result<Advertisement> {
        let set = self.key_set()?;
        let (jwk, alg) = set
            .keys
            .iter()
            .filter_map(|j| Some((j, signing_alg(j)?)))
            .find(|(j, alg)| {
                j.public_bytes()
                    .and_then(|p| akp_thumbprint(alg.jose_name(), &p))
                    .is_ok_and(|t| t == *trusted.as_bytes())
            })
            .ok_or(Error::UntrustedAdvertisement)?;
        if !policy.allows_signature(alg) {
            return Err(Error::Policy("signing algorithm not allowed"));
        }
        alg.ensure_allowed()?;
        let key = VerifyingKey::from_jwk(jwk, alg)?;

        // Accept if any valid signature by the trusted key is also fresh;
        // otherwise report why the valid ones were not.
        let now = unix_seconds(now);
        let mut outcome = Err(Error::InvalidSignature);
        for header in self
            .jws
            .signatures
            .iter()
            .filter_map(|s| self.signed_by(&key, s))
        {
            outcome = policy.check_freshness(header.iat, header.exp, now);
            if outcome.is_ok() {
                break;
            }
        }
        outcome?;

        // Only now import the rest of the (authenticated) key set.
        let signing_keys = set
            .keys
            .iter()
            .filter_map(|j| Some(VerifyingKey::from_jwk(j, signing_alg(j)?)))
            .collect::<Result<_>>()?;
        let mut exchange_keys = Vec::new();
        let mut tagged_keys = Vec::new();
        for (jwk, alg) in set
            .keys
            .into_iter()
            .filter_map(|j| {
                let alg = exchange_alg(&j)?;
                Some((j, alg))
            })
            .filter(|(_, alg)| policy.allows_kem(*alg))
        {
            if !alg.allowed_by_system()? {
                continue;
            }
            let key = ExchangeKey::from_jwk(&jwk, alg)?;
            if jwk.extra.is_empty() {
                exchange_keys.push(key);
            } else {
                tagged_keys.push((key, jwk.extra));
            }
        }
        Ok(Advertisement {
            signing_keys,
            exchange_keys,
            tagged_keys,
            members: set.extra,
            trusted: *trusted,
        })
    }

    /// Thumbprints of the ML-DSA signing keys listed in the advertisement.
    ///
    /// **Unverified.** Use only to show the user what to confirm out of band
    /// before trusting one (Clevis' trust-on-first-use prompt), then call
    /// [`verify`](Self::verify).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an unparsable advertisement.
    pub fn advertised_signing_keys(&self) -> Result<Vec<Thumbprint>> {
        self.key_set()?
            .keys
            .iter()
            .filter_map(|j| {
                let alg = signing_alg(j)?;
                Some(
                    j.public_bytes()
                        .and_then(|p| akp_thumbprint(alg.jose_name(), &p))
                        .map(Thumbprint::from_bytes),
                )
            })
            .collect()
    }

    /// An extension member of the JWK Set, **unverified**.
    ///
    /// For protocols whose trust in the signing key comes from a member
    /// itself (for example a delegation signed by a pinned anchor): read the
    /// member, establish the signing key from it, then call
    /// [`verify`](Self::verify) and use only the verified [`Advertisement`].
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an unparsable advertisement.
    pub fn unverified_member(&self, name: &str) -> Result<Option<Value>> {
        Ok(self.key_set()?.extra.remove(name))
    }

    /// Serialise as JWS General JSON.
    #[must_use]
    #[allow(clippy::missing_panics_doc)] // serialising plain strings cannot fail
    pub fn to_json(&self) -> String {
        serde_json::to_string(&self.jws).expect("JWS serialisation cannot fail")
    }

    /// Parse JWS General JSON.  Does not verify anything.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for invalid JSON, or an oversized document.
    pub fn from_json(json: &[u8]) -> Result<Self> {
        if json.len() > MAX_ADVERTISEMENT_BYTES {
            return Err(Error::Malformed("advertisement too large"));
        }
        let jws: GeneralJws =
            serde_json::from_slice(json).map_err(|_| Error::Malformed("advertisement"))?;
        if jws.signatures.len() > MAX_SIGNATURES {
            return Err(Error::Malformed("advertisement has too many signatures"));
        }
        Ok(Self { jws })
    }
}

/// Builds and signs an advertisement, optionally with extension members.
///
/// Extension members are covered by the signatures. Plain Tang clients
/// ignore them, and [`Advertisement::exchange_keys`] never returns a key
/// that carries one.
#[must_use]
pub struct AdvertisementBuilder<'a> {
    signing: &'a [&'a SigningKey],
    keys: Vec<Jwk>,
    members: Map<String, Value>,
    lifetime: Option<Lifetime>,
}

impl<'a> AdvertisementBuilder<'a> {
    /// Sign with every key in `signing`.
    pub fn new(signing: &'a [&'a SigningKey]) -> Self {
        Self {
            signing,
            keys: signing.iter().map(|k| k.public().to_jwk()).collect(),
            members: Map::new(),
            lifetime: None,
        }
    }

    /// Advertise an exchange key for plain Tang bindings.
    pub fn exchange_key(mut self, key: &ExchangeKey) -> Self {
        self.keys.push(key.to_jwk());
        self
    }

    /// Advertise an exchange key with an extension member, e.g. a role:
    /// `exchange_key_with(key, "ipa_use", "escrow")`.
    pub fn exchange_key_with(mut self, key: &ExchangeKey, member: &str, value: &str) -> Self {
        let mut jwk = key.to_jwk();
        jwk.extra.insert(member.into(), value.into());
        self.keys.push(jwk);
        self
    }

    /// Add a signed extension member to the JWK Set.  The name `keys` is
    /// reserved and ignored.
    pub fn member(mut self, name: &str, value: Value) -> Self {
        if name != "keys" {
            self.members.insert(name.into(), value);
        }
        self
    }

    /// Issued-at and expiry, in Unix seconds.
    pub fn validity(mut self, iat: u64, exp: u64) -> Self {
        self.lifetime = Some(Lifetime { iat, exp });
        self
    }

    /// Sign.
    ///
    /// # Errors
    ///
    /// [`Error::NoExchangeKey`] without signing keys, or a signing error.
    pub fn sign(self) -> Result<SignedAdvertisement> {
        if self.signing.is_empty() {
            return Err(Error::NoExchangeKey);
        }
        let set = JwkSet {
            keys: self.keys,
            extra: self.members,
        };
        SignedAdvertisement::sign_key_set(self.signing, &set, self.lifetime)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use serde_json::{Value, json};

    use super::*;
    use crate::keys::ExchangeKeyPair;

    const DAY: u64 = 24 * 3600;

    fn now() -> u64 {
        unix_seconds(SystemTime::now())
    }

    fn fresh() -> Lifetime {
        let now = now();
        Lifetime {
            iat: now,
            exp: now + DAY,
        }
    }

    fn adv_with(
        sig: SignatureAlg,
        kem: KemAlg,
        lifetime: Option<Lifetime>,
    ) -> (SignedAdvertisement, Thumbprint) {
        let signing = SigningKey::generate(sig).unwrap();
        let thp = *signing.public().thumbprint();
        let exchange = ExchangeKeyPair::generate(kem).unwrap();
        let adv = SignedAdvertisement::sign(&[&signing], &[exchange.public()], lifetime).unwrap();
        (adv, thp)
    }

    fn server_adv() -> (SignedAdvertisement, Thumbprint) {
        adv_with(SignatureAlg::MlDsa65, KemAlg::MlKem768, Some(fresh()))
    }

    fn payload_json(adv: &SignedAdvertisement) -> Value {
        serde_json::from_slice(&b64::decode(&adv.jws.payload).unwrap()).unwrap()
    }

    fn header_json(adv: &SignedAdvertisement) -> Value {
        serde_json::from_slice(&b64::decode(&adv.jws.signatures[0].protected).unwrap()).unwrap()
    }

    fn with_payload(adv: &SignedAdvertisement, payload: &Value) -> SignedAdvertisement {
        let mut forged = adv.clone();
        forged.jws.payload = b64::encode(payload.to_string().as_bytes());
        forged
    }

    #[test]
    fn shape_matches_tang() {
        let (adv, thp) = server_adv();
        let header = header_json(&adv);
        assert_eq!(header["alg"], "ML-DSA-65");
        assert_eq!(header["cty"], "jwk-set+json");
        let (iat, exp) = (
            header["iat"].as_u64().unwrap(),
            header["exp"].as_u64().unwrap(),
        );
        assert_eq!(exp - iat, DAY);

        let keys = &payload_json(&adv)["keys"];
        assert_eq!(keys[0]["kty"], "AKP");
        assert_eq!(keys[0]["alg"], "ML-DSA-65");
        assert_eq!(keys[0]["key_ops"], json!(["verify"]));
        assert_eq!(keys[1]["alg"], "ML-KEM-768");
        assert_eq!(keys[1]["key_ops"], json!(["deriveKey"]));
        assert!(keys[0].get("priv").is_none() && keys[1].get("priv").is_none());

        assert_eq!(adv.advertised_signing_keys().unwrap(), vec![thp]);
        let parsed = SignedAdvertisement::from_json(adv.to_json().as_bytes()).unwrap();
        assert_eq!(parsed, adv);
        parsed.verify(&thp).unwrap();
    }

    /// A network attacker swaps the exchange key but keeps the real signing
    /// key and signature: the signature no longer covers the payload.
    #[test]
    fn substituted_exchange_key_is_rejected() {
        let (adv, thp) = server_adv();
        let attacker = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let mut payload = payload_json(&adv);
        payload["keys"][1]["pub"] = b64::encode(attacker.public().as_bytes()).into();
        let forged = with_payload(&adv, &payload);
        assert!(matches!(forged.verify(&thp), Err(Error::InvalidSignature)));
    }

    /// Dropping the trusted key from the set is detected before any
    /// signature is looked at.
    #[test]
    fn missing_trusted_key_is_untrusted() {
        let (adv, thp) = server_adv();
        let mut payload = payload_json(&adv);
        payload["keys"].as_array_mut().unwrap().remove(0);
        let forged = with_payload(&adv, &payload);
        assert!(matches!(
            forged.verify(&thp),
            Err(Error::UntrustedAdvertisement)
        ));

        let stranger = *SigningKey::generate(SignatureAlg::MlDsa65)
            .unwrap()
            .public()
            .thumbprint();
        assert!(matches!(
            adv.verify(&stranger),
            Err(Error::UntrustedAdvertisement)
        ));
    }

    #[test]
    fn header_alg_crit_and_lifetime_are_enforced() {
        let (adv, thp) = server_adv();
        let mut extended = header_json(&adv);
        extended["exp"] = (extended["exp"].as_u64().unwrap() + DAY).into();
        let headers = [
            json!({"alg": "ML-DSA-44", "cty": "jwk-set+json"}),
            json!({"alg": "ML-DSA-65", "cty": "jwk-set+json", "crit": ["x"], "x": 1}),
            json!({"alg": "ML-DSA-65"}),
            json!({"alg": "ML-DSA-65", "cty": "other+json"}),
            // Extending the signed lifetime invalidates the signature.
            extended,
        ];
        for header in headers {
            let mut forged = adv.clone();
            forged.jws.signatures[0].protected = b64::encode(header.to_string().as_bytes());
            assert!(matches!(forged.verify(&thp), Err(Error::InvalidSignature)));
        }
    }

    #[test]
    fn oversized_advertisements_are_rejected_before_parsing() {
        let (adv, _) = server_adv();
        // Too many signatures: rejected at parse, before any verification.
        let mut flooded = adv.clone();
        let one = flooded.jws.signatures[0].clone();
        flooded.jws.signatures = vec![one; MAX_SIGNATURES + 1];
        assert!(matches!(
            SignedAdvertisement::from_json(flooded.to_json().as_bytes()),
            Err(Error::Malformed(_))
        ));
        // Too many bytes: rejected at parse.
        let huge = format!("{}{}", " ".repeat(MAX_ADVERTISEMENT_BYTES), "]");
        assert!(matches!(
            SignedAdvertisement::from_json(huge.as_bytes()),
            Err(Error::Malformed(_))
        ));
        // A normal one still parses.
        assert!(SignedAdvertisement::from_json(adv.to_json().as_bytes()).is_ok());
    }

    #[test]
    fn too_many_keys_or_payload_bytes_are_rejected() {
        let (adv, thp) = server_adv();
        // A payload with too many keys fails at the key-set decode, before
        // signature verification can burn CPU on each one.
        let mut payload = payload_json(&adv);
        let filler = json!({"kty": "oct", "k": ""});
        payload["keys"] = Value::Array(std::iter::repeat_n(filler, MAX_KEYS + 1).collect());
        let forged = with_payload(&adv, &payload);
        assert!(matches!(forged.verify(&thp), Err(Error::Malformed(_))));
        // A payload larger than the cap fails likewise.
        let mut big = payload_json(&adv);
        big["keys"][0]["x"] = Value::String("A".repeat(MAX_ADVERTISEMENT_BYTES));
        let forged = with_payload(&adv, &big);
        assert!(matches!(forged.verify(&thp), Err(Error::Malformed(_))));
    }

    /// Replaying an old, validly signed advertisement fails once it expires.
    #[test]
    fn expired_advertisement_is_stale() {
        let (adv, thp) = server_adv();
        let policy = Policy::default();
        let later = SystemTime::now() + Duration::from_secs(DAY + 10 * 60);
        assert!(matches!(
            adv.verify_at(&thp, &policy, later),
            Err(Error::StaleAdvertisement)
        ));
        let earlier = SystemTime::now() - Duration::from_secs(3600);
        assert!(matches!(
            adv.verify_at(&thp, &policy, earlier),
            Err(Error::StaleAdvertisement)
        ));
    }

    #[test]
    fn unexpiring_advertisement_needs_explicit_opt_in() {
        let (adv, thp) = adv_with(SignatureAlg::MlDsa65, KemAlg::MlKem768, None);
        assert!(matches!(adv.verify(&thp), Err(Error::Policy(_))));
        adv.verify_with(&thp, &Policy::default().allow_unexpiring())
            .unwrap();
    }

    #[test]
    fn overlong_validity_is_rejected() {
        let now = now();
        let lifetime = Some(Lifetime {
            iat: now,
            exp: now + 90 * DAY,
        });
        let (adv, thp) = adv_with(SignatureAlg::MlDsa65, KemAlg::MlKem768, lifetime);
        assert!(matches!(adv.verify(&thp), Err(Error::Policy(_))));
    }

    #[test]
    fn policy_restricts_algorithms() {
        // ML-DSA-44 is below the default policy.
        let (adv, thp) = adv_with(SignatureAlg::MlDsa44, KemAlg::MlKem768, Some(fresh()));
        assert!(matches!(adv.verify(&thp), Err(Error::Policy(_))));
        let permissive = Policy::default().with_signature_algs(&SignatureAlg::ALL);
        adv.verify_with(&thp, &permissive).unwrap();

        // CNSA 2.0 drops ML-KEM-768 exchange keys, leaving nothing to bind to.
        let (adv, thp) = adv_with(SignatureAlg::MlDsa87, KemAlg::MlKem768, Some(fresh()));
        let verified = adv.verify_with(&thp, &Policy::cnsa2()).unwrap();
        assert_eq!(verified.exchange_keys().len(), 0);
        assert!(matches!(
            verified.provision(None),
            Err(Error::NoExchangeKey)
        ));
    }

    #[test]
    fn key_ops_restrict_roles() {
        let (adv, thp) = server_adv();
        // A signing key that is not allowed to verify cannot be trusted.
        let mut payload = payload_json(&adv);
        payload["keys"][0]["key_ops"] = json!(["deriveKey"]);
        assert!(matches!(
            with_payload(&adv, &payload).verify(&thp),
            Err(Error::UntrustedAdvertisement)
        ));
    }

    fn classic_keys() -> Vec<Jwk> {
        serde_json::from_slice(
            br#"[
            {"kty":"EC","crv":"P-521","alg":"ES512","key_ops":["verify"],"x":"AA","y":"AA"},
            {"kty":"EC","crv":"P-521","alg":"ECMR","key_ops":["deriveKey"],"x":"AA","y":"AA"}
        ]"#,
        )
        .unwrap()
    }

    /// A hybrid server can publish classic Tang keys (ES512/ECMR) in the same
    /// JWK Set; they are ignored, and the PQ keys still verify and work.
    #[test]
    fn classic_tang_keys_are_ignored() {
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let thp = *signing.public().thumbprint();
        let exchange = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let mut keys = classic_keys();
        keys.push(signing.public().to_jwk());
        keys.push(exchange.public().to_jwk());
        let adv = SignedAdvertisement::sign_key_set(
            &[&signing],
            &JwkSet {
                keys,
                extra: Map::new(),
            },
            Some(fresh()),
        )
        .unwrap();

        assert_eq!(adv.advertised_signing_keys().unwrap(), vec![thp]);
        let verified = adv.verify(&thp).unwrap();
        assert_eq!(verified.signing_keys().len(), 1);
        assert_eq!(verified.exchange_keys().len(), 1);
        assert_eq!(verified.exchange_keys()[0].kid(), exchange.public().kid());
    }

    /// Downgrade: an advertisement offering only classic exchange keys never
    /// yields a binding, so a client cannot be pushed back to ECMR.
    #[test]
    fn classic_only_exchange_keys_cannot_be_bound() {
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let thp = *signing.public().thumbprint();
        let mut keys = classic_keys();
        keys.push(signing.public().to_jwk());
        let adv = SignedAdvertisement::sign_key_set(
            &[&signing],
            &JwkSet {
                keys,
                extra: Map::new(),
            },
            Some(fresh()),
        )
        .unwrap();
        let verified = adv.verify(&thp).unwrap();
        assert!(matches!(
            verified.provision(None),
            Err(Error::NoExchangeKey)
        ));
    }
}
