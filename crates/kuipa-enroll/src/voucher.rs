//! Enrollment vouchers (§9): `auth_type` 3.
//!
//! A voucher is an ML-DSA signature, under a voucher key the realm
//! publishes, on
//!
//! ```text
//! m = "IPVM" ‖ realm ‖ fqdn ‖ hostgroup ‖ not_before ‖ not_after ‖ lease ‖ binding
//! ```
//!
//! `lease` (`DESIGN-ci.md` §1) is how long the host the voucher creates
//! lives from its join, in seconds, 0 for no lease; the realm caps it
//! ([`VoucherSettings`]).
//!
//! made blind (`ml-dsa-blind`): the issuer signs `μ` and never sees `m`;
//! the result is an ordinary signature on `salt ‖ m` with context
//! [`SIGN_CONTEXT`], which the IPA server checks with the public key only.
//! `binding` is [`binding`]`(ek_e)` of the ephemeral key the host will join
//! with, or empty for a bearer voucher.  It is hashed with `ek_e`'s KEM
//! suite hash: SHA-256 for ML-KEM-768, SHA-384 for ML-KEM-1024 (CNSA 2.0).  A voucher creates one host: the
//! server refuses an existing FQDN and records the spent salt.
//!
//! ```text
//! ipa-ku-voucher1:<base64url(voucher)>
//! ```

use native_ossl::util::SecretBuf;
use tang_pqc::primitives;
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{SignatureAlg, Thumbprint, VerifyingKey, b64};

use crate::error::{Error, Result};

/// ML-DSA context of voucher signatures.
pub const SIGN_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 voucher";

/// The role of voucher keys in the advertisement.
pub const ROLE_VOUCHER: &str = "voucher";

/// Length of the blinding salt.
pub const SALT_LEN: usize = 32;

const PREFIX: &str = "ipa-ku-voucher1:";
const MESSAGE_MAGIC: [u8; 4] = *b"IPVM";

/// The realm's voucher settings (`ipaKUVouchers` on
/// `cn=vouchers,cn=kuipa,cn=etc`).
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct VoucherSettings {
    /// The longest lease, in seconds; [`DEFAULT_MAX_LEASE`] when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_lease: Option<u64>,
}

impl VoucherSettings {
    /// The longest lease a voucher may give its host.
    #[must_use]
    pub fn max_lease(&self) -> u64 {
        self.max_lease.unwrap_or(DEFAULT_MAX_LEASE)
    }
}

/// The longest lease when the realm sets none: 7 days.
pub const DEFAULT_MAX_LEASE: u64 = 7 * 86_400;
const VOUCHER_MAGIC: [u8; 4] = *b"IPVO";
const BINDING_LABEL: &[u8] = b"ipa-ku-enroll/v1 voucher binding";

/// What a voucher allows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claims {
    /// The realm.
    pub realm: String,
    /// The host to create.
    pub fqdn: String,
    /// The host group to add it to; empty for none.
    pub hostgroup: String,
    /// Unix seconds.
    pub not_before: u64,
    /// Unix seconds.
    pub not_after: u64,
    /// How long the host lives from its join, in seconds; 0 for no lease.
    pub lease: u64,
    /// [`binding`] of the host's ephemeral key (32 or 48 bytes), or empty.
    pub binding: Vec<u8>,
}

impl Claims {
    /// The signed message `m`.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        let mut w = Writer::new(MESSAGE_MAGIC);
        self.put(&mut w);
        w.finish()
    }

    fn put(&self, w: &mut Writer) {
        w.str(&self.realm)
            .str(&self.fqdn)
            .str(&self.hostgroup)
            .u64(self.not_before)
            .u64(self.not_after)
            .u64(self.lease)
            .bytes(&self.binding);
    }

    fn get(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            realm: r.str()?.to_owned(),
            fqdn: r.str()?.to_owned(),
            hostgroup: r.str()?.to_owned(),
            not_before: r.u64()?,
            not_after: r.u64()?,
            lease: r.u64()?,
            binding: match r.bytes()? {
                b if b.is_empty() || is_binding_len(b.len()) => b.to_vec(),
                _ => return Err(Error::Malformed("voucher binding")),
            },
        })
    }

    /// Whether it binds an ephemeral key.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        !self.binding.is_empty()
    }
}

/// Whether `len` is a [`binding`]'s length: a KEM suite hash's, SHA-256
/// or SHA-384.
#[must_use]
pub fn is_binding_len(len: usize) -> bool {
    tang_pqc::KemAlg::ALL
        .into_iter()
        .any(|a| primitives::digest_len(a.hash()) == Some(len))
}

/// The binding of an ephemeral encapsulation key (its raw bytes): its
/// KEM's suite hash, named by the key's length.
///
/// # Errors
///
/// [`Error::Malformed`] for a key of no ML-KEM set, or an OpenSSL error.
pub fn binding(ephemeral_key: &[u8]) -> Result<Vec<u8>> {
    let alg = tang_pqc::KemAlg::ALL
        .into_iter()
        .find(|a| a.encapsulation_key_len() == ephemeral_key.len())
        .ok_or(Error::Malformed("ephemeral key"))?;
    Ok(primitives::digest(
        alg.hash(),
        &[BINDING_LABEL, ephemeral_key],
    )?)
}

/// A voucher: claims, the voucher key and the unblinded signature.
#[derive(Clone, PartialEq, Eq)]
pub struct Voucher {
    key: Thumbprint,
    claims: Claims,
    salt: [u8; SALT_LEN],
    signature: Box<[u8]>,
}

impl std::fmt::Debug for Voucher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Voucher")
            .field("key", &self.key)
            .field("claims", &self.claims)
            .finish_non_exhaustive()
    }
}

impl Voucher {
    /// Assemble from the unblinded `salt ‖ signature` under `key`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a short signature.
    pub fn new(key: &Thumbprint, claims: Claims, salted_signature: &[u8]) -> Result<Self> {
        let (salt, signature) = salted_signature
            .split_first_chunk::<SALT_LEN>()
            .ok_or(Error::Malformed("voucher signature"))?;
        Ok(Self {
            key: *key,
            claims,
            salt: *salt,
            signature: signature.into(),
        })
    }

    /// The voucher key it is signed under.
    #[must_use]
    pub fn key(&self) -> &Thumbprint {
        &self.key
    }

    /// What it allows.
    #[must_use]
    pub fn claims(&self) -> &Claims {
        &self.claims
    }

    /// The salt, recorded as spent.
    #[must_use]
    pub fn salt(&self) -> &[u8; SALT_LEN] {
        &self.salt
    }

    /// Encode as text.  An unbound voucher is a bearer credential.
    #[must_use]
    pub fn encode(&self) -> SecretBuf {
        let mut w = Writer::new(VOUCHER_MAGIC);
        w.u8(1).fixed(self.key.as_bytes());
        self.claims.put(&mut w);
        w.fixed(&self.salt).bytes(&self.signature);
        SecretBuf::new(format!("{PREFIX}{}", b64::encode(&w.finish())).into_bytes())
    }

    /// Parse the text form.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn parse(text: &[u8]) -> Result<Self> {
        let malformed = || Error::Malformed("voucher");
        let text = std::str::from_utf8(text).map_err(|_| malformed())?.trim();
        let body = text.strip_prefix(PREFIX).ok_or_else(malformed)?;
        let bytes = b64::decode(body).map_err(|_| malformed())?;
        let mut r = Reader::new(&bytes, VOUCHER_MAGIC, "voucher")?;
        if r.u8()? != 1 {
            return Err(malformed());
        }
        let voucher = Self {
            key: Thumbprint::from_bytes(r.fixed()?),
            claims: Claims::get(&mut r)?,
            salt: r.fixed()?,
            signature: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(voucher)
    }

    /// Check it under `key` for a join of `fqdn` in `realm` with an
    /// ephemeral key whose [`binding`] is `ephemeral` at time `now`.
    ///
    /// # Errors
    ///
    /// [`Error::Refused`] for a bad signature, another key, realm or host,
    /// another ephemeral key, or outside its validity.  The lease is the
    /// caller's to cap.
    pub fn verify(
        &self,
        key: &VerifyingKey,
        realm: &str,
        fqdn: &str,
        ephemeral: &[u8],
        now: u64,
    ) -> Result<&Claims> {
        let c = &self.claims;
        let signed = [&self.salt[..], &c.message()].concat();
        if key.thumbprint() != &self.key
            || c.realm != realm
            || !c.fqdn.eq_ignore_ascii_case(fqdn)
            || (c.is_bound() && c.binding != ephemeral)
            || now < c.not_before
            || now > c.not_after
            || key
                .verify_with_context(&signed, SIGN_CONTEXT, &self.signature)
                .is_err()
        {
            return Err(Error::Refused);
        }
        Ok(c)
    }
}

/// The ML-DSA parameter set name of a voucher key, for `ml-dsa-blind`.
#[must_use]
pub fn alg_name(alg: SignatureAlg) -> &'static str {
    match alg {
        SignatureAlg::MlDsa44 => "ML-DSA-44",
        SignatureAlg::MlDsa65 => "ML-DSA-65",
        SignatureAlg::MlDsa87 => "ML-DSA-87",
    }
}

#[cfg(test)]
mod tests {
    use tang_pqc::{ExchangeKeyPair, KemAlg, SigningKey};

    use super::*;

    fn ek_of(alg: KemAlg) -> Vec<u8> {
        ExchangeKeyPair::generate(alg)
            .unwrap()
            .public()
            .as_bytes()
            .to_vec()
    }

    fn claims(binding: Vec<u8>) -> Claims {
        Claims {
            realm: "EXAMPLE.TEST".into(),
            fqdn: "web1.example.test".into(),
            hostgroup: "webservers".into(),
            not_before: 100,
            not_after: 200,
            lease: 0,
            binding,
        }
    }

    /// A voucher signed directly: what unblinding yields.
    fn voucher(key: &SigningKey, claims: Claims) -> Voucher {
        let salt = [7u8; SALT_LEN];
        let signed = [&salt[..], &claims.message()].concat();
        let sig = key.sign_with_context(&signed, SIGN_CONTEXT).unwrap();
        Voucher::new(
            key.public().thumbprint(),
            claims,
            &[&salt[..], &sig].concat(),
        )
        .unwrap()
    }

    #[test]
    fn round_trip_and_checks() {
        let key = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let ek = binding(&ek_of(KemAlg::MlKem768)).unwrap();
        assert_eq!(ek.len(), primitives::SHA256_LEN);
        // An ML-KEM-1024 key (CNSA 2.0) is bound with SHA-384, and a key
        // of no ML-KEM set is no key.
        let cnsa = binding(&ek_of(KemAlg::MlKem1024)).unwrap();
        assert_eq!(cnsa.len(), primitives::SHA384_LEN);
        assert!(binding(b"ephemeral").is_err());
        let v = voucher(&key, claims(Vec::new()));
        let v = Voucher::parse(v.encode().as_ref()).unwrap();
        let k = key.public();
        assert!(
            v.verify(k, "EXAMPLE.TEST", "WEB1.example.test", &ek, 150)
                .is_ok()
        );
        assert!(
            v.verify(k, "OTHER.TEST", "web1.example.test", &ek, 150)
                .is_err()
        );
        assert!(
            v.verify(k, "EXAMPLE.TEST", "web2.example.test", &ek, 150)
                .is_err()
        );
        assert!(
            v.verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 99)
                .is_err()
        );
        assert!(
            v.verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 201)
                .is_err()
        );
        let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        assert!(
            v.verify(
                other.public(),
                "EXAMPLE.TEST",
                "web1.example.test",
                &ek,
                150
            )
            .is_err()
        );

        // A bound voucher works with its ephemeral key only.
        let bound = voucher(&key, claims(ek.clone()));
        assert!(
            bound
                .verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 150)
                .is_ok()
        );
        let wrong = binding(&ek_of(KemAlg::MlKem768)).unwrap();
        assert!(
            bound
                .verify(k, "EXAMPLE.TEST", "web1.example.test", &wrong, 150)
                .is_err()
        );

        // Tampered claims do not verify.
        let mut forged = v.clone();
        forged.claims.hostgroup = "admins".into();
        assert!(
            forged
                .verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 150)
                .is_err()
        );
        assert!(Voucher::parse(b"ipa-ku-voucher1:AAAA").is_err());

        // A lease is signed and kept through the text form.
        let leased = |lease| {
            let c = Claims {
                lease,
                ..claims(Vec::new())
            };
            Voucher::parse(voucher(&key, c).encode().as_ref()).unwrap()
        };
        let four_hours = leased(4 * 3600);
        assert_eq!(four_hours.claims().lease, 4 * 3600);
        assert!(
            four_hours
                .verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 150)
                .is_ok()
        );
        let mut longer = four_hours.clone();
        longer.claims.lease = DEFAULT_MAX_LEASE;
        assert!(
            longer
                .verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 150)
                .is_err(),
            "the lease is signed"
        );
    }
}
