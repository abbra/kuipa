//! Enrollment vouchers (§9): `auth_type` 3.
//!
//! A voucher is an ML-DSA signature, under a voucher key the realm
//! publishes, on
//!
//! ```text
//! m = "IPVM" ‖ realm ‖ fqdn ‖ hostgroup ‖ not_before ‖ not_after ‖ binding
//! ```
//!
//! made blind (`ml-dsa-blind`): the issuer signs `μ` and never sees `m`;
//! the result is an ordinary signature on `salt ‖ m` with context
//! [`SIGN_CONTEXT`], which the IPA server checks with the public key only.
//! `binding` is [`binding`]`(ek_e)` of the ephemeral key the host will join
//! with, or zeros for a bearer voucher.  A voucher creates one host: the
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
    /// [`binding`] of the host's ephemeral key, or zeros.
    pub binding: [u8; 32],
}

impl Claims {
    /// The signed message `m`.
    #[must_use]
    pub fn message(&self) -> Vec<u8> {
        Writer::new(MESSAGE_MAGIC)
            .str(&self.realm)
            .str(&self.fqdn)
            .str(&self.hostgroup)
            .u64(self.not_before)
            .u64(self.not_after)
            .fixed(&self.binding)
            .finish()
    }

    fn put(&self, w: &mut Writer) {
        w.str(&self.realm)
            .str(&self.fqdn)
            .str(&self.hostgroup)
            .u64(self.not_before)
            .u64(self.not_after)
            .fixed(&self.binding);
    }

    fn get(r: &mut Reader) -> Result<Self> {
        Ok(Self {
            realm: r.str()?.to_owned(),
            fqdn: r.str()?.to_owned(),
            hostgroup: r.str()?.to_owned(),
            not_before: r.u64()?,
            not_after: r.u64()?,
            binding: r.fixed()?,
        })
    }

    /// Whether it binds an ephemeral key.
    #[must_use]
    pub fn is_bound(&self) -> bool {
        self.binding != [0; 32]
    }
}

/// The binding of an ephemeral encapsulation key (its raw bytes).
///
/// # Errors
///
/// An OpenSSL error.
pub fn binding(ephemeral_key: &[u8]) -> Result<[u8; 32]> {
    Ok(primitives::sha256(&[BINDING_LABEL, ephemeral_key])?)
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
    /// another ephemeral key, or outside its validity.
    pub fn verify(
        &self,
        key: &VerifyingKey,
        realm: &str,
        fqdn: &str,
        ephemeral: &[u8; 32],
        now: u64,
    ) -> Result<&Claims> {
        let c = &self.claims;
        let signed = [&self.salt[..], &c.message()].concat();
        if key.thumbprint() != &self.key
            || c.realm != realm
            || !c.fqdn.eq_ignore_ascii_case(fqdn)
            || (c.is_bound() && &c.binding != ephemeral)
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
    use tang_pqc::SigningKey;

    use super::*;

    fn claims(binding: [u8; 32]) -> Claims {
        Claims {
            realm: "EXAMPLE.TEST".into(),
            fqdn: "web1.example.test".into(),
            hostgroup: "webservers".into(),
            not_before: 100,
            not_after: 200,
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
        let ek = binding(b"ephemeral").unwrap();
        let v = voucher(&key, claims([0; 32]));
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
        let bound = voucher(&key, claims(ek));
        assert!(
            bound
                .verify(k, "EXAMPLE.TEST", "web1.example.test", &ek, 150)
                .is_ok()
        );
        let wrong = binding(b"other").unwrap();
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
    }
}
