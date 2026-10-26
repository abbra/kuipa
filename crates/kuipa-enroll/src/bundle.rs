//! Offline enrollment bundles (§8).
//!
//! ```text
//! B   = mode ‖ alg ‖ realm ‖ fqdn ‖ id ‖ iat ‖ not_after ‖ recipient_thp ‖ signer_thp
//! A:  (ct, ss) = Encaps(ek_m);  k = HKDF(ss, "bundle" ‖ H(B ‖ H(ct)))
//! B:  ct = ε;                   k = HKDF(S,  "bundle-secret" ‖ H(B ‖ H(ct)))
//! sealed = GCM_k(enrollment)    (signed-only: the enrollment in the clear)
//! sig = ML-DSA(server key, everything above ‖ delegation ‖ server key,
//!              ctx = "ipa-ku-enroll/v1 bundle")
//! ```
//!
//! The delegation's claim names the server key by thumbprint; the bundle
//! carries the key itself.

use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;
use tang_pqc::primitives;
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{ExchangeKey, ExchangeKeyPair, KemAlg, Policy, Thumbprint, VerifyingKey};

use crate::delegation::{Delegation, VerifiedDelegation};
use crate::enrollment::Secret;
use crate::error::{Error, Result};
use crate::join::DOMAIN;
use crate::keytab::Principal;
use crate::payload::Enrollment;
use crate::realm::ServerKeys;

const MAGIC: [u8; 4] = *b"IPOB";
const HEADER_MAGIC: [u8; 4] = *b"IPOH";

/// ML-DSA context of bundle signatures, separating them from JWS
/// signatures (empty context) by the same key.
pub const SIGNATURE_CONTEXT: &[u8] = b"ipa-ku-enroll/v1 bundle";

/// How a bundle is opened (§8.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    /// A: encrypted to an ML-KEM key the target generated.
    MachineKey,
    /// B: encrypted under a secret delivered by a second channel.
    Secret,
    /// C: signed only; requires an explicit opt-in to create and open.
    SignedOnly,
}

impl Mode {
    const fn id(self) -> u8 {
        match self {
            Self::MachineKey => 1,
            Self::Secret => 2,
            Self::SignedOnly => 3,
        }
    }

    fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::MachineKey),
            2 => Ok(Self::Secret),
            3 => Ok(Self::SignedOnly),
            _ => Err(Error::Malformed("bundle mode")),
        }
    }
}

/// Who a new bundle is for.
#[derive(Clone, Copy, Debug)]
pub enum Recipient<'a> {
    /// Mode A: the target's public key.
    MachineKey(&'a ExchangeKey),
    /// Mode B: a fresh secret, returned by [`Bundle::create`].
    Secret,
    /// Mode C.
    SignedOnly,
}

/// What opens a bundle.
#[derive(Clone, Copy)]
pub enum Opener<'a> {
    /// Mode A: the target's private key.
    MachineKey(&'a ExchangeKeyPair),
    /// Mode B: the secret from the enrollment string.
    Secret(&'a [u8]),
    /// Mode C, explicitly accepted as insecure.
    InsecureSignedOnly,
}

/// The staging parameters an administrator sends in a stage request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StageParams {
    /// Bundle mode.
    pub mode: Mode,
    /// Mode A: the target's public key.
    pub recipient: Option<ExchangeKey>,
    /// When the staged keys expire (Unix seconds).
    pub not_after: u64,
}

const PARAMS_MAGIC: [u8; 4] = *b"IPSX";

impl StageParams {
    /// Encode as the `extra` part of a stage request.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let (alg, key) = self
            .recipient
            .as_ref()
            .map_or((0, &[][..]), |k| (k.alg().id(), k.as_bytes()));
        Writer::new(PARAMS_MAGIC)
            .u8(self.mode.id())
            .u8(alg)
            .bytes(key)
            .u64(self.not_after)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for a mode A request without a key or a
    /// key without mode A.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, PARAMS_MAGIC, "stage parameters")?;
        let mode = Mode::from_id(r.u8()?)?;
        let alg = r.u8()?;
        let key = r.bytes()?;
        let not_after = r.u64()?;
        r.finish()?;
        let recipient = match (mode, key.is_empty()) {
            (Mode::MachineKey, false) => Some(ExchangeKey::from_bytes(KemAlg::from_id(alg)?, key)?),
            (Mode::MachineKey, true) | (_, false) => {
                return Err(Error::Malformed("stage parameters"));
            }
            (_, true) => None,
        };
        Ok(Self {
            mode,
            recipient,
            not_after,
        })
    }
}

/// An offline enrollment bundle.
#[derive(Clone, PartialEq, Eq)]
pub struct Bundle {
    mode: Mode,
    alg: KemAlg,
    realm: String,
    fqdn: String,
    id: [u8; 16],
    iat: u64,
    not_after: u64,
    recipient: [u8; 32],
    signer: [u8; 32],
    ciphertext: Box<[u8]>,
    sealed: Box<[u8]>,
    delegation: Box<[u8]>,
    /// The server signing key (JWK JSON).
    signer_key: Box<[u8]>,
    signature: Box<[u8]>,
}

impl std::fmt::Debug for Bundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Bundle")
            .field("mode", &self.mode)
            .field("realm", &self.realm)
            .field("fqdn", &self.fqdn)
            .field("not_after", &self.not_after)
            .finish_non_exhaustive()
    }
}

impl Bundle {
    /// Build and sign a bundle carrying `enrollment` for `fqdn`.
    ///
    /// Returns the bundle and, in mode B, the secret that opens it.
    ///
    /// # Errors
    ///
    /// [`Error::Expired`] if `not_after` is not after `iat` or lies beyond
    /// the server's `delegation`, or a crypto error.
    pub fn create(
        keys: &ServerKeys,
        delegation: &Delegation,
        alg: KemAlg,
        recipient: Recipient<'_>,
        enrollment: &Enrollment,
        iat: u64,
        not_after: u64,
    ) -> Result<(Self, Option<Secret>)> {
        if not_after <= iat || not_after > delegation.expires_unverified()? {
            return Err(Error::Expired);
        }
        let mut id = [0u8; 16];
        Rand::fill(&mut id)?;
        let fqdn = enrollment
            .keytab
            .principal()
            .components()
            .get(1)
            .cloned()
            .ok_or(Error::Malformed("host principal"))?;
        let (mode, recipient_thp, alg) = match recipient {
            Recipient::MachineKey(k) => (Mode::MachineKey, *k.kid().as_bytes(), k.alg()),
            Recipient::Secret => (Mode::Secret, [0; 32], alg),
            Recipient::SignedOnly => (Mode::SignedOnly, [0; 32], alg),
        };
        let mut bundle = Self {
            mode,
            alg,
            realm: enrollment.config.realm.clone(),
            fqdn,
            id,
            iat,
            not_after,
            recipient: recipient_thp,
            signer: *keys.signing.public().thumbprint().as_bytes(),
            ciphertext: Box::default(),
            sealed: Box::default(),
            delegation: delegation.to_json().into_bytes().into(),
            signer_key: keys.signing.public().to_jwk_json().into_bytes().into(),
            signature: Box::default(),
        };
        let payload = enrollment.to_bytes()?;
        let mut secret = None;
        bundle.sealed = match recipient {
            Recipient::MachineKey(k) => {
                let (ct, ss) = k.encapsulate()?;
                bundle.ciphertext = ct.into();
                let key = bundle.key(ss.as_ref(), "bundle")?;
                primitives::seal(key.as_ref(), payload.as_ref())?.into()
            }
            Recipient::Secret => {
                let mut s = SecretBuf::with_len(32);
                Rand::fill_private(s.as_mut_slice())?;
                let key = bundle.key(s.as_ref(), "bundle-secret")?;
                secret = Some(Secret::new(tang_pqc::b64::encode(s.as_ref()).as_bytes()));
                primitives::seal(key.as_ref(), payload.as_ref())?.into()
            }
            Recipient::SignedOnly => payload.as_ref().into(),
        };
        bundle.signature = keys
            .signing
            .sign_with_context(&bundle.signed_part(), SIGNATURE_CONTEXT)?
            .into();
        Ok((bundle, secret))
    }

    fn header(&self) -> Writer {
        let mut w = Writer::new(HEADER_MAGIC);
        w.u8(self.mode.id())
            .u8(self.alg.id())
            .str(&self.realm)
            .str(&self.fqdn)
            .fixed(&self.id)
            .u64(self.iat)
            .u64(self.not_after)
            .fixed(&self.recipient)
            .fixed(&self.signer);
        w
    }

    fn key(&self, ikm: &[u8], purpose: &str) -> Result<SecretBuf> {
        let hash = self.alg.hash();
        let t = primitives::digest(
            hash,
            &[
                &self.header().finish(),
                &primitives::digest(hash, &[&self.ciphertext])?,
            ],
        )?;
        Ok(DOMAIN.derive_key(hash, &[ikm], purpose, &[&t])?)
    }

    fn signed_part(&self) -> Vec<u8> {
        let mut w = Writer::new(MAGIC);
        w.fixed(&self.header().finish()[5..])
            .bytes(&self.ciphertext)
            .bytes(&self.sealed)
            .bytes(&self.delegation)
            .bytes(&self.signer_key);
        w.finish()
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = self.signed_part();
        out.extend_from_slice(
            &u32::try_from(self.signature.len())
                .unwrap_or(0)
                .to_be_bytes(),
        );
        out.extend_from_slice(&self.signature);
        out
    }

    /// Decode.  Does not verify anything.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, MAGIC, "bundle")?;
        let mode = Mode::from_id(r.u8()?)?;
        let alg = KemAlg::from_id(r.u8()?)?;
        let bundle = Self {
            mode,
            alg,
            realm: r.str()?.to_owned(),
            fqdn: r.str()?.to_owned(),
            id: r.fixed()?,
            iat: r.u64()?,
            not_after: r.u64()?,
            recipient: r.fixed()?,
            signer: r.fixed()?,
            ciphertext: r.bytes()?.into(),
            sealed: r.bytes()?.into(),
            delegation: r.bytes()?.into(),
            signer_key: r.bytes()?.into(),
            signature: r.bytes()?.into(),
        };
        r.finish()?;
        let ct_len = if mode == Mode::MachineKey {
            alg.ciphertext_len()
        } else {
            0
        };
        if bundle.ciphertext.len() != ct_len {
            return Err(Error::Malformed("bundle ciphertext"));
        }
        Ok(bundle)
    }

    /// The mode.
    #[must_use]
    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// The host the bundle enrolls.
    #[must_use]
    pub fn fqdn(&self) -> &str {
        &self.fqdn
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// When the staged keys expire (Unix seconds).
    #[must_use]
    pub fn not_after(&self) -> u64 {
        self.not_after
    }

    /// Verify the delegation (at the bundle's `iat`, §8.4) and the bundle
    /// signature.
    ///
    /// # Errors
    ///
    /// [`Error::UntrustedAnchor`], [`Error::Expired`] (delegation not valid
    /// at `iat`, or `not_after` outside it), [`Error::WrongRealm`],
    /// [`Error::Mismatch`] (signed by another key than the delegated one),
    /// or [`Error::Crypto`] for a bad signature.
    pub fn verify(self, anchors: &[Thumbprint], policy: &Policy) -> Result<VerifiedBundle> {
        let delegation =
            Delegation::from_json(&self.delegation)?.verify_at(anchors, policy, self.iat)?;
        if delegation.realm != self.realm {
            return Err(Error::WrongRealm);
        }
        let key = VerifyingKey::from_jwk_json(&self.signer_key)?;
        if key.thumbprint() != &delegation.key || delegation.key.as_bytes() != &self.signer {
            return Err(Error::Mismatch("bundle signer"));
        }
        if !policy.allows_signature(key.alg()) {
            return Err(Error::Crypto(tang_pqc::Error::Policy(
                "server signing algorithm not allowed",
            )));
        }
        if self.not_after <= self.iat || self.not_after > delegation.exp {
            return Err(Error::Expired);
        }
        key.verify_with_context(&self.signed_part(), SIGNATURE_CONTEXT, &self.signature)?;
        Ok(VerifiedBundle {
            bundle: self,
            delegation,
        })
    }
}

/// A bundle whose signature chain verified.
#[derive(Debug)]
pub struct VerifiedBundle {
    bundle: Bundle,
    delegation: VerifiedDelegation,
}

impl VerifiedBundle {
    /// The bundle.
    #[must_use]
    pub fn bundle(&self) -> &Bundle {
        &self.bundle
    }

    /// The successions followed from a pinned anchor to the one whose
    /// proof was accepted, as `(old, new)` (§4.7).
    #[must_use]
    pub fn succeeded(&self) -> &[(tang_pqc::Thumbprint, tang_pqc::Thumbprint)] {
        &self.delegation.succeeded
    }

    /// The server that staged it.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.delegation.server
    }

    /// Open with `opener`, and check the enrollment is for the bundle's
    /// host and realm.
    ///
    /// # Errors
    ///
    /// * [`Error::WrongRecipient`]: another key or secret, or a mode
    ///   mismatch.
    /// * [`Error::Insecure`]: a signed-only bundle without
    ///   [`Opener::InsecureSignedOnly`].
    /// * [`Error::Mismatch`]: the enrollment is for another principal.
    pub fn open(&self, opener: Opener<'_>) -> Result<Enrollment> {
        let b = &self.bundle;
        let payload = match (b.mode, opener) {
            (Mode::MachineKey, Opener::MachineKey(k)) => {
                if k.public().kid().as_bytes() != &b.recipient || k.public().alg() != b.alg {
                    return Err(Error::WrongRecipient);
                }
                let ss = k.decapsulate(&b.ciphertext)?;
                let key = b.key(ss.as_ref(), "bundle")?;
                primitives::open(key.as_ref(), &b.sealed).map_err(|_| Error::WrongRecipient)?
            }
            (Mode::Secret, Opener::Secret(s)) => {
                let s = SecretBuf::new(
                    tang_pqc::b64::decode(
                        std::str::from_utf8(s).map_err(|_| Error::WrongRecipient)?,
                    )
                    .map_err(|_| Error::WrongRecipient)?,
                );
                let key = b.key(s.as_ref(), "bundle-secret")?;
                primitives::open(key.as_ref(), &b.sealed).map_err(|_| Error::WrongRecipient)?
            }
            (Mode::SignedOnly, Opener::InsecureSignedOnly) => SecretBuf::from_slice(&b.sealed),
            (Mode::SignedOnly, _) => return Err(Error::Insecure("a signed-only bundle")),
            _ => return Err(Error::WrongRecipient),
        };
        let enrollment = Enrollment::from_bytes(payload.as_ref())?;
        if enrollment.keytab.principal() != &Principal::host(&b.fqdn, &b.realm)
            || enrollment.config.realm != b.realm
        {
            return Err(Error::Mismatch("bundle principal"));
        }
        Ok(enrollment)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::RealmConfig;
    use crate::payload::tests::keytab;
    use crate::realm::tests::{now, test_realm};

    fn enrollment() -> Enrollment {
        Enrollment {
            config: RealmConfig {
                realm: "EXAMPLE.TEST".into(),
                domain: "example.test".into(),
                basedn: "dc=example,dc=test".into(),
                issuer: "ipa1.example.test".into(),
                servers: Vec::new(),
            },
            keytab: keytab("web1.example.test", 1),
            ca_certs: vec![b"ca".to_vec()],
            pkinit_anchors: Vec::new(),
            anchors: Vec::new(),
            heads: Vec::new(),
            epoch_seq: 0,
            epoch_head: [0; 48],
        }
    }

    /// Sizes for DESIGN §4.3 and §8: a 1.5 KB CA certificate, also used as
    /// the PKINIT anchor; `cargo test -p kuipa-enroll measure_sizes --
    /// --ignored --nocapture`.
    #[test]
    #[ignore = "measurement"]
    fn measure_sizes() {
        use crate::realm::{RealmInfo, ServerKeys};
        use tang_pqc::{SignatureAlg, SigningKey};
        let ca = vec![0x30; 1500];
        for (kem, sig) in [
            (KemAlg::MlKem768, SignatureAlg::MlDsa65),
            (KemAlg::MlKem1024, SignatureAlg::MlDsa87),
        ] {
            let anchor = SigningKey::generate(sig).unwrap();
            let signing = SigningKey::generate(sig).unwrap();
            let delegation = Delegation::issue(
                &anchor,
                "EXAMPLE.TEST",
                "ipa1.example.test",
                signing.public(),
                now(),
                now() + 86400,
            )
            .unwrap();
            let keys = ServerKeys {
                signing,
                join: vec![ExchangeKeyPair::generate(kem).unwrap()],
                escrow: vec![ExchangeKeyPair::generate(kem).unwrap()],
                trust: Vec::new(),
                vouchers: Vec::new(),
                retired: Vec::new(),
            };
            let info = RealmInfo {
                realm: "EXAMPLE.TEST".into(),
                domain: "example.test".into(),
                basedn: "dc=example,dc=test".into(),
                server: "ipa1.example.test".into(),
                servers: vec!["ipa1.example.test".into(), "ipa2.example.test".into()],
                ca_certs: vec![ca.clone()],
                pkinit_anchors: vec![ca.clone()],
                anchors: vec![*anchor.public().thumbprint()],
                heads: Vec::new(),
                trusts: Vec::new(),
                kdc_proxy: None,
            };
            let adv = keys
                .advertisement(&info, &delegation, now(), now() + 3600, None)
                .unwrap()
                .to_json();
            let machine = ExchangeKeyPair::generate(kem).unwrap();
            let e = Enrollment {
                ca_certs: vec![ca.clone()],
                pkinit_anchors: vec![ca.clone()],
                ..enrollment()
            };
            let (bundle, _) = Bundle::create(
                &keys,
                &delegation,
                kem,
                Recipient::MachineKey(machine.public()),
                &e,
                now(),
                now() + 3600,
            )
            .unwrap();
            println!(
                "{kem:?} + {sig:?}: advertisement {} bytes, delegation {} bytes, bundle {} bytes",
                adv.len(),
                delegation.to_json().len(),
                bundle.to_bytes().len()
            );
        }
    }

    #[test]
    fn mode_a_only_opens_with_the_machine_key() {
        let t = test_realm("ipa1.example.test");
        let anchors = [*t.anchor.public().thumbprint()];
        let machine = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let other = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let (bundle, secret) = Bundle::create(
            &t.keys,
            &t.delegation,
            KemAlg::MlKem768,
            Recipient::MachineKey(machine.public()),
            &enrollment(),
            now(),
            now() + 3600,
        )
        .unwrap();
        assert!(secret.is_none());
        let v = Bundle::from_bytes(&bundle.to_bytes())
            .unwrap()
            .verify(&anchors, &Policy::default())
            .unwrap();
        assert_eq!(v.server(), "ipa1.example.test");
        let e = v.open(Opener::MachineKey(&machine)).unwrap();
        assert_eq!(e.keytab.kvno(), Some(1));
        assert!(matches!(
            v.open(Opener::MachineKey(&other)),
            Err(Error::WrongRecipient)
        ));
        assert!(matches!(
            v.open(Opener::Secret(b"x")),
            Err(Error::WrongRecipient)
        ));
    }

    #[test]
    fn mode_b_and_c() {
        let t = test_realm("ipa1.example.test");
        let anchors = [*t.anchor.public().thumbprint()];
        let (bundle, secret) = Bundle::create(
            &t.keys,
            &t.delegation,
            KemAlg::MlKem768,
            Recipient::Secret,
            &enrollment(),
            now(),
            now() + 3600,
        )
        .unwrap();
        let secret = secret.unwrap();
        let v = bundle.verify(&anchors, &Policy::default()).unwrap();
        v.open(Opener::Secret(secret.as_bytes())).unwrap();
        let wrong = tang_pqc::b64::encode(&[0u8; 32]);
        assert!(v.open(Opener::Secret(wrong.as_bytes())).is_err());

        let (bundle, _) = Bundle::create(
            &t.keys,
            &t.delegation,
            KemAlg::MlKem768,
            Recipient::SignedOnly,
            &enrollment(),
            now(),
            now() + 3600,
        )
        .unwrap();
        let v = bundle.verify(&anchors, &Policy::default()).unwrap();
        assert!(matches!(
            v.open(Opener::Secret(secret.as_bytes())),
            Err(Error::Insecure(_))
        ));
        v.open(Opener::InsecureSignedOnly).unwrap();
    }

    #[test]
    fn verification_failures() {
        let t = test_realm("ipa1.example.test");
        let anchors = [*t.anchor.public().thumbprint()];
        let make = |iat, not_after| {
            Bundle::create(
                &t.keys,
                &t.delegation,
                KemAlg::MlKem768,
                Recipient::SignedOnly,
                &enrollment(),
                iat,
                not_after,
            )
        };
        // Outliving the delegation is refused at creation.
        assert!(matches!(
            make(now(), now() + 2 * 86400),
            Err(Error::Expired)
        ));
        let (bundle, _) = make(now(), now() + 60).unwrap();

        // Any modification breaks the signature.
        let mut bytes = bundle.to_bytes();
        let i = bytes.len() / 2;
        bytes[i] ^= 1;
        assert!(
            Bundle::from_bytes(&bytes)
                .and_then(|b| b.verify(&anchors, &Policy::default()))
                .is_err()
        );

        // Wrong anchor.
        let stranger = test_realm("x");
        assert!(matches!(
            bundle.clone().verify(
                &[*stranger.anchor.public().thumbprint()],
                &Policy::default()
            ),
            Err(Error::UntrustedAnchor)
        ));

        // The delegation is checked at iat, not now: an old bundle with a
        // still-valid not_after verifies even though the clock moved on.
        bundle.verify(&anchors, &Policy::default()).unwrap();
    }

    #[test]
    fn stage_params_round_trip() {
        let k = ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap();
        let p = StageParams {
            mode: Mode::MachineKey,
            recipient: Some(k.public().clone()),
            not_after: 42,
        };
        assert_eq!(StageParams::from_bytes(&p.to_bytes()).unwrap(), p);
        let p = StageParams {
            mode: Mode::Secret,
            recipient: None,
            not_after: 42,
        };
        assert_eq!(StageParams::from_bytes(&p.to_bytes()).unwrap(), p);
        let bad = StageParams {
            mode: Mode::MachineKey,
            recipient: None,
            not_after: 1,
        };
        assert!(StageParams::from_bytes(&bad.to_bytes()).is_err());
    }
}
