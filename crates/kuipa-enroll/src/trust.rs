//! Establishing a trust between two IPA realms (§17.4).
//!
//! Realm B's administrator issues an invitation; an A server, for A's
//! administrator, sends B a trust request sealed to B's trust key:
//!
//! ```text
//! invitation = ipa-ku-trust1:<REALM-B>:<B anchor>:<one-time secret>
//! (ct, ss)     = Encaps(ek_trust)            (dk_e, ek_e) = KeyGen()
//! T  = H(alg ‖ kid ‖ B signer ‖ realm B ‖ realm A ‖ H(ct) ‖ H(ek_e))
//! k  = HKDF(ss, "req" ‖ T)
//!      ── TrustRequest(alg, kid, realm B, realm A, ct, ek_e,
//!            GCM_k(secret, A's realm, A's delegation, A's server key,
//!                  ML-DSA(A's server key, T, "ipa-ku-trust/v1 request"))) ──▶
//! (ct_e, ss_e) = Encaps(ek_e)                T' = H(T ‖ H(ct_e))
//! k' = HKDF(ss ‖ ss_e, "rsp" ‖ T')           trust secret = HKDF(ss ‖ ss_e, "trust-secret" ‖ T')
//!      ◀── TrustResponse(ct_e, GCM_k'(B's realm)) ──
//! ```
//!
//! The invitation's secret authorises the request; A's delegation, checked
//! against the anchors A sends and binding the signing key that signed `T`,
//! shows that a server of A made it.  Both sides derive the same trust
//! secret, which neither chose alone, for the cross-realm Kerberos keys
//! (FreeIPA's `trust-add --trust_secret`).  All derivations use their own
//! protocol domain, so nothing here can be taken for a join.

use native_ossl::util::SecretBuf;
use tang_pqc::primitives::{self, Domain};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{ExchangeKey, ExchangeKeyPair, KemAlg, SigningKey, Thumbprint, b64};

use crate::delegation::Delegation;
use crate::enrollment::Secret;
use crate::error::{Error, Result};
use crate::realm::{TrustedRealm, VerifiedRealm};

/// Domain of all trust derivations.
pub const DOMAIN: Domain = Domain::new("ipa-ku-trust/v1");

/// ML-DSA context of the initiating server's signature over `T`.
pub(crate) const SIGN_CONTEXT: &[u8] = b"ipa-ku-trust/v1 request";

const PREFIX: &str = "ipa-ku-trust1";
const SECRET_LABEL: &[u8] = b"ipa-ku-trust/v1 invitation";

/// A trust invitation:
/// `ipa-ku-trust1:<REALM>:<anchor thumbprint>:<one-time secret>`.
#[derive(Debug)]
pub struct Invitation {
    realm: String,
    anchor: Thumbprint,
    secret: Secret,
}

impl Invitation {
    /// A new invitation to `realm`, pinning its `anchor`, with a fresh
    /// 256-bit secret.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn new(realm: &str, anchor: Thumbprint) -> Result<Self> {
        let mut s = SecretBuf::with_len(32);
        native_ossl::rand::Rand::fill_private(s.as_mut_slice())?;
        Ok(Self {
            realm: realm.into(),
            anchor,
            secret: Secret::new(b64::encode(s.as_ref()).as_bytes()),
        })
    }

    /// Parse.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn parse(text: &[u8]) -> Result<Self> {
        let malformed = || Error::Malformed("trust invitation");
        let text = std::str::from_utf8(text).map_err(|_| malformed())?.trim();
        let mut parts = text.splitn(4, ':');
        let (Some(PREFIX), Some(realm), Some(anchor), Some(secret)) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(malformed());
        };
        if realm.is_empty() || secret.is_empty() {
            return Err(malformed());
        }
        Ok(Self {
            realm: realm.into(),
            anchor: anchor.parse().map_err(|_| malformed())?,
            secret: Secret::new(secret.as_bytes()),
        })
    }

    /// Encode.
    #[must_use]
    pub fn encode(&self) -> SecretBuf {
        let mut s = format!("{PREFIX}:{}:{}:", self.realm, self.anchor).into_bytes();
        s.extend_from_slice(self.secret.as_bytes());
        SecretBuf::new(s)
    }

    /// The inviting realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// Its anchor, to verify its advertisement with.
    #[must_use]
    pub fn anchor(&self) -> &Thumbprint {
        &self.anchor
    }

    /// What the inviting realm stores: a hash of the secret.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn secret_hash(&self) -> Result<InvitationHash> {
        secret_hash(self.secret.as_bytes())
    }
}

/// The stored form of an invitation secret: SHA-384 under every policy,
/// as no key decides it and a stored hash must outlive a policy change.
pub type InvitationHash = [u8; primitives::SHA384_LEN];

pub(crate) fn secret_hash(secret: &[u8]) -> Result<InvitationHash> {
    Ok(primitives::sha384(&[SECRET_LABEL, secret])?)
}

/// Encode a realm's description: `realm ‖ domain ‖ n[server] ‖ n[anchor]`.
fn put_realm(w: &mut Writer, r: &TrustedRealm) -> Result<()> {
    let count = |n: usize| u8::try_from(n).map_err(|_| Error::Malformed("too many entries"));
    w.str(&r.realm).str(&r.domain).u8(count(r.servers.len())?);
    for s in &r.servers {
        w.str(s);
    }
    w.u8(count(r.anchors.len())?);
    for a in &r.anchors {
        w.fixed(a.as_bytes());
    }
    Ok(())
}

fn get_realm(r: &mut Reader) -> Result<TrustedRealm> {
    let realm = r.str()?.to_owned();
    let domain = r.str()?.to_owned();
    let servers = (0..r.u8()?)
        .map(|_| r.str().map(str::to_owned))
        .collect::<Result<_, _>>()?;
    let anchors = (0..r.u8()?)
        .map(|_| r.fixed().map(Thumbprint::from_bytes))
        .collect::<Result<_, _>>()?;
    Ok(TrustedRealm {
        realm,
        domain,
        servers,
        anchors,
        // The wire form carries no heads: they arrive with the
        // partner's first refresh, from its advertisement
        // (DESIGN-claim-logs.md §3).
        heads: Vec::new(),
    })
}

/// A trust request (`POST /ipa/ku/trust/{kid}`).
#[derive(Clone, PartialEq, Eq)]
pub struct TrustRequest {
    alg: KemAlg,
    kid: Thumbprint,
    realm: String,
    initiator: String,
    ciphertext: Box<[u8]>,
    ephemeral_key: Box<[u8]>,
    sealed: Box<[u8]>,
}

impl std::fmt::Debug for TrustRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustRequest")
            .field("kid", &self.kid)
            .field("realm", &self.realm)
            .field("initiator", &self.initiator)
            .finish_non_exhaustive()
    }
}

const REQUEST_MAGIC: [u8; 4] = *b"IPTQ";
const BODY_MAGIC: [u8; 4] = *b"IPTB";
const RESPONSE_MAGIC: [u8; 4] = *b"IPTS";
const PAYLOAD_MAGIC: [u8; 4] = *b"IPTP";

impl TrustRequest {
    /// The trust key it is sealed to.
    #[must_use]
    pub fn kid(&self) -> &Thumbprint {
        &self.kid
    }

    /// The realm asked to trust.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The realm asking.
    #[must_use]
    pub fn initiator(&self) -> &str {
        &self.initiator
    }

    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(REQUEST_MAGIC)
            .u8(1)
            .u8(self.alg.id())
            .fixed(self.kid.as_bytes())
            .str(&self.realm)
            .str(&self.initiator)
            .bytes(&self.ciphertext)
            .bytes(&self.ephemeral_key)
            .bytes(&self.sealed)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, REQUEST_MAGIC, "trust request")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("trust request version"));
        }
        let alg = KemAlg::from_id(r.u8()?)?;
        let request = Self {
            alg,
            kid: Thumbprint::from_bytes(r.fixed()?),
            realm: r.str()?.into(),
            initiator: r.str()?.into(),
            ciphertext: r.bytes_exact(alg.ciphertext_len())?.into(),
            ephemeral_key: r.bytes_exact(alg.encapsulation_key_len())?.into(),
            sealed: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(request)
    }

    pub(crate) fn alg(&self) -> KemAlg {
        self.alg
    }

    pub(crate) fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// `T`; `signer` is the asked realm's server signing key.
    pub(crate) fn transcript(&self, signer: &Thumbprint) -> Result<Vec<u8>> {
        let hash = self.alg.hash();
        let fields = Writer::new(*b"IPTT")
            .u8(self.alg.id())
            .fixed(self.kid.as_bytes())
            .fixed(signer.as_bytes())
            .str(&self.realm)
            .str(&self.initiator)
            .fixed(&primitives::digest(hash, &[&self.ciphertext])?)
            .fixed(&primitives::digest(hash, &[&self.ephemeral_key])?)
            .finish();
        Ok(primitives::digest(hash, &[&fields])?)
    }

    pub(crate) fn open(&self, ss: &[u8], t: &[u8]) -> Result<TrustBody> {
        let k = DOMAIN.derive_key(self.alg.hash(), &[ss], "req", &[t])?;
        let plain = primitives::open(k.as_ref(), &self.sealed).map_err(|_| Error::Refused)?;
        let mut r = Reader::new(plain.as_ref(), BODY_MAGIC, "trust request body")?;
        let body = TrustBody {
            secret: SecretBuf::from_slice(r.bytes()?),
            partner: get_realm(&mut r)?,
            delegation: Delegation::from_json(r.bytes()?)?,
            signer_key: r.str()?.to_owned(),
            signature: r.bytes()?.to_vec(),
        };
        r.finish()?;
        Ok(body)
    }

    /// Answer with `own` realm's description, and return the trust secret.
    pub(crate) fn respond(
        &self,
        ss: &[u8],
        t: &[u8],
        own: &TrustedRealm,
    ) -> Result<(TrustResponse, SecretBuf)> {
        // Importing runs the FIPS 203 encapsulation-key check.
        let ephemeral = ExchangeKey::from_bytes(self.alg, &self.ephemeral_key)?;
        let (ct_e, ss_e) = ephemeral.encapsulate()?;
        let (k, secret) = response_keys(self.alg, ss, ss_e.as_ref(), t, &ct_e)?;
        let mut w = Writer::new(PAYLOAD_MAGIC);
        put_realm(&mut w, own)?;
        let response = TrustResponse {
            sealed: primitives::seal(k.as_ref(), &w.finish())?.into(),
            ciphertext: ct_e.into(),
        };
        Ok((response, secret))
    }
}

/// The opened request body.
pub(crate) struct TrustBody {
    pub(crate) secret: SecretBuf,
    pub(crate) partner: TrustedRealm,
    pub(crate) delegation: Delegation,
    pub(crate) signer_key: String,
    pub(crate) signature: Vec<u8>,
}

/// `k'` and the trust secret.
fn response_keys(
    alg: KemAlg,
    ss: &[u8],
    ss_e: &[u8],
    t: &[u8],
    ct_e: &[u8],
) -> Result<(SecretBuf, SecretBuf)> {
    let hash = alg.hash();
    let t2 = primitives::digest(hash, &[t, &primitives::digest(hash, &[ct_e])?])?;
    Ok((
        DOMAIN.derive_key(hash, &[ss, ss_e], "rsp", &[&t2])?,
        DOMAIN.derive_key(hash, &[ss, ss_e], "trust-secret", &[&t2])?,
    ))
}

/// The answer to a trust request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustResponse {
    ciphertext: Box<[u8]>,
    sealed: Box<[u8]>,
}

impl TrustResponse {
    /// Encode.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        Writer::new(RESPONSE_MAGIC)
            .u8(1)
            .bytes(&self.ciphertext)
            .bytes(&self.sealed)
            .finish()
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, RESPONSE_MAGIC, "trust response")?;
        if r.u8()? != 1 {
            return Err(Error::Malformed("trust response version"));
        }
        let response = Self {
            ciphertext: r.bytes()?.into(),
            sealed: r.bytes()?.into(),
        };
        r.finish()?;
        Ok(response)
    }
}

/// What the initiating side keeps until the response arrives.
pub struct PendingTrust {
    alg: KemAlg,
    ss: SecretBuf,
    t: Vec<u8>,
    ephemeral: ExchangeKeyPair,
    realm: String,
    anchor: Thumbprint,
    own: TrustedRealm,
}

/// The trust, as the initiating side ends up with it.
pub struct Established {
    /// The other realm, as it describes itself.
    pub partner: TrustedRealm,
    /// The shared trust secret (32 bytes).
    pub secret: SecretBuf,
}

/// The trust secret as the text FreeIPA's `trust-add --trust_secret` takes
/// (base64url), the same on both sides.
#[must_use]
pub fn secret_text(secret: &SecretBuf) -> SecretBuf {
    SecretBuf::new(b64::encode(secret.as_ref()).into_bytes())
}

/// Build the trust request to the realm whose verified advertisement is
/// `adv` (verified with the invitation's anchor), describing this realm as
/// `own` and proving a server of it with that server's `delegation` and
/// `signing` key.
///
/// # Errors
///
/// [`Error::WrongRealm`] if `adv` is not the inviting realm's,
/// [`Error::Missing`] without a trust key, or a crypto error.
pub fn request(
    adv: &VerifiedRealm,
    invitation: &Invitation,
    own: &TrustedRealm,
    delegation: &Delegation,
    signing: &SigningKey,
) -> Result<(TrustRequest, PendingTrust)> {
    if adv.info().realm != invitation.realm {
        return Err(Error::WrongRealm);
    }
    let key = adv.trust_key()?;
    let (ct, ss) = key.encapsulate()?;
    let ephemeral = ExchangeKeyPair::generate(key.alg())?;
    let mut request = TrustRequest {
        alg: key.alg(),
        kid: *key.kid(),
        realm: invitation.realm.clone(),
        initiator: own.realm.clone(),
        ciphertext: ct.into(),
        ephemeral_key: ephemeral.public().as_bytes().into(),
        sealed: Box::default(),
    };
    let t = request.transcript(adv.signer())?;
    let signature = signing.sign_with_context(&t, SIGN_CONTEXT)?;
    let mut w = Writer::new(BODY_MAGIC);
    w.bytes(invitation.secret.as_bytes());
    put_realm(&mut w, own)?;
    w.bytes(delegation.to_json().as_bytes())
        .str(&signing.public().to_jwk_json())
        .bytes(&signature);
    let body = SecretBuf::new(w.finish());
    let k = DOMAIN.derive_key(key.alg().hash(), &[ss.as_ref()], "req", &[&t])?;
    request.sealed = primitives::seal(k.as_ref(), body.as_ref())?.into();
    let pending = PendingTrust {
        alg: key.alg(),
        ss,
        t,
        ephemeral,
        realm: invitation.realm.clone(),
        anchor: invitation.anchor,
        own: own.clone(),
    };
    Ok((request, pending))
}

impl std::fmt::Debug for Established {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Established")
            .field("partner", &self.partner)
            .finish_non_exhaustive()
    }
}

impl PendingTrust {
    /// Open the response and derive the trust secret.
    ///
    /// # Errors
    ///
    /// [`Error::BadResponse`] for a response to another request, or
    /// [`Error::Mismatch`] if the other realm's description is not the
    /// invited realm's or does not include the invitation's anchor.
    pub fn finish(self, response: &TrustResponse) -> Result<Established> {
        let ss_e = self
            .ephemeral
            .decapsulate(&response.ciphertext)
            .map_err(|_| Error::BadResponse)?;
        let (k, secret) = response_keys(
            self.alg,
            self.ss.as_ref(),
            ss_e.as_ref(),
            &self.t,
            &response.ciphertext,
        )?;
        let plain =
            primitives::open(k.as_ref(), &response.sealed).map_err(|_| Error::BadResponse)?;
        let mut r = Reader::new(plain.as_ref(), PAYLOAD_MAGIC, "trust response payload")?;
        let partner = get_realm(&mut r)?;
        r.finish()?;
        if partner.realm != self.realm || !partner.anchors.contains(&self.anchor) {
            return Err(Error::Mismatch("trusted realm"));
        }
        partner.validate_for(&self.own.realm, &self.own.anchors)?;
        Ok(Established { partner, secret })
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::Mutex;
    use std::time::SystemTime;

    use tang_pqc::{ExchangeKeyPair, Policy, SignatureAlg, SignedAdvertisement, unix_seconds};

    use super::*;
    use crate::EnrollServer;
    use crate::escrow::BindingHash;
    use crate::keytab::{Enctype, Keytab, Principal};
    use crate::realm::{RealmInfo, ServerKeys};
    use crate::server::{Directory, DirectoryError, Staged};

    fn now() -> u64 {
        unix_seconds(SystemTime::now())
    }

    /// A directory that only keeps invitations and trusts.
    #[derive(Default)]
    struct Trusts {
        invitations: Mutex<HashMap<[u8; 48], u64>>,
        recorded: Mutex<Vec<(TrustedRealm, Vec<u8>)>>,
    }

    impl Directory for Trusts {
        fn join_with_otp(
            &self,
            _: &str,
            _: &[u8],
            _: &[Enctype],
        ) -> Result<Keytab, DirectoryError> {
            unreachable!()
        }
        fn join_with_gss(
            &self,
            _: &str,
            _: &[u8],
            _: &[u8; 32],
            _: &[Enctype],
        ) -> Result<(Keytab, crate::join::KerberosBinding), DirectoryError> {
            unreachable!()
        }
        fn rekey_with_gss(
            &self,
            _: &str,
            _: &[u8],
            _: &[u8; 32],
            _: &[Enctype],
        ) -> Result<(Keytab, crate::join::KerberosBinding), DirectoryError> {
            unreachable!()
        }
        fn stage_with_gss(
            &self,
            _: &str,
            _: &[u8],
            _: &[u8; 32],
            _: &[Enctype],
            _: &Staged,
        ) -> Result<(Keytab, crate::join::KerberosBinding), DirectoryError> {
            unreachable!()
        }
        fn register_escrow(&self, _: &Principal, _: &[BindingHash]) -> Result<(), DirectoryError> {
            unreachable!()
        }
        fn escrow_allowed(
            &self,
            _: &Principal,
            _: crate::escrow::Kind,
            _: &BindingHash,
        ) -> Result<bool, DirectoryError> {
            unreachable!()
        }
        fn ca_certificates(&self) -> Result<Vec<Vec<u8>>, DirectoryError> {
            unreachable!()
        }
        fn servers(&self) -> Result<Vec<String>, DirectoryError> {
            unreachable!()
        }
        fn add_trust_invitation(
            &self,
            hash: &[u8; 48],
            not_after: u64,
        ) -> Result<(), DirectoryError> {
            self.invitations.lock().unwrap().insert(*hash, not_after);
            Ok(())
        }
        fn consume_trust_invitation(&self, hash: &[u8; 48]) -> Result<(), DirectoryError> {
            match self.invitations.lock().unwrap().remove(hash) {
                Some(not_after) if not_after > now() => Ok(()),
                _ => Err("unknown, used or expired invitation".into()),
            }
        }
        fn record_trust(
            &self,
            partner: &TrustedRealm,
            secret: &[u8],
        ) -> Result<(), DirectoryError> {
            self.recorded
                .lock()
                .unwrap()
                .push((partner.clone(), secret.to_vec()));
            Ok(())
        }
    }

    struct Realm {
        server: EnrollServer,
        anchor: SigningKey,
        signing: SigningKey,
    }

    fn realm(name: &str) -> Realm {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let fqdn = format!("ipa1.{}", name.to_ascii_lowercase());
        let delegation = Delegation::issue(
            &anchor,
            name,
            &fqdn,
            signing.public(),
            now() - 60,
            now() + 86400,
        )
        .unwrap();
        let info = RealmInfo {
            realm: name.into(),
            domain: name.to_ascii_lowercase(),
            basedn: "dc=test".into(),
            server: fqdn.clone(),
            servers: vec![fqdn],
            ca_certs: vec![b"ca".to_vec()],
            pkinit_anchors: vec![b"pkinit".to_vec()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
        };
        let copy = SigningKey::from_jwk(signing.to_jwk().unwrap().as_ref()).unwrap();
        let keys = ServerKeys {
            signing: copy,
            join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            trust: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
            vouchers: Vec::new(),
            retired: Vec::new(),
        };
        Realm {
            server: EnrollServer::new(keys, info, delegation),
            anchor,
            signing,
        }
    }

    fn verified(r: &Realm, anchor: &Thumbprint) -> VerifiedRealm {
        let json = r.server.advertisement(&[*anchor]).unwrap().to_json();
        VerifiedRealm::verify(
            &SignedAdvertisement::from_json(json.as_bytes()).unwrap(),
            &r.server.info().realm,
            &[*anchor],
            &Policy::default(),
            SystemTime::now(),
        )
        .unwrap()
    }

    #[test]
    fn invitation_round_trip() {
        let anchor = Thumbprint::from_bytes([3; 32]);
        let inv = Invitation::new("B.TEST", anchor).unwrap();
        let back = Invitation::parse(inv.encode().as_ref()).unwrap();
        assert_eq!(back.realm(), "B.TEST");
        assert_eq!(back.anchor(), &anchor);
        assert_eq!(back.secret_hash().unwrap(), inv.secret_hash().unwrap());
        for bad in [
            "ipa-ku1:B:x:y",
            "ipa-ku-trust1:B.TEST:notathumbprint:s",
            "ipa-ku-trust1::a:",
        ] {
            assert!(Invitation::parse(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn establish_a_trust() {
        let (a, b) = (realm("A.TEST"), realm("B.TEST"));
        let dir = Trusts::default();
        let b_anchor = *b.anchor.public().thumbprint();
        let inv = Invitation::new("B.TEST", b_anchor).unwrap();
        dir.add_trust_invitation(&inv.secret_hash().unwrap(), now() + 3600)
            .unwrap();

        let adv = verified(&b, &b_anchor);
        let (req, pending) = request(
            &adv,
            &inv,
            &a.server.as_partner(),
            &a.server.delegation(),
            &a.signing,
        )
        .unwrap();
        let req = TrustRequest::from_bytes(&req.to_bytes()).unwrap();
        let response = b.server.establish_trust(&req, &dir).unwrap();
        let est = pending
            .finish(&TrustResponse::from_bytes(&response.to_bytes()).unwrap())
            .unwrap();

        // Both sides hold the same secret, and each the other's description.
        assert_eq!(est.partner.realm, "B.TEST");
        assert_eq!(est.partner.anchors, [b_anchor]);
        let recorded = dir.recorded.lock().unwrap();
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].0.realm, "A.TEST");
        assert_eq!(recorded[0].0.anchors, [*a.anchor.public().thumbprint()]);
        assert_eq!(recorded[0].1, est.secret.as_ref());
        assert_eq!(secret_text(&est.secret).as_ref().len(), 43);
        drop(recorded);

        // The invitation is used up.
        assert!(b.server.establish_trust(&req, &dir).is_err());
    }

    #[test]
    fn refused_trust_requests() {
        let (a, b) = (realm("A.TEST"), realm("B.TEST"));
        let dir = Trusts::default();
        let b_anchor = *b.anchor.public().thumbprint();
        let adv = verified(&b, &b_anchor);
        let attempt = |inv: &Invitation, signing: &SigningKey| {
            let (req, _) = request(
                &adv,
                inv,
                &a.server.as_partner(),
                &a.server.delegation(),
                signing,
            )
            .unwrap();
            b.server.establish_trust(&req, &dir)
        };
        // An invitation B never issued.
        let unknown = Invitation::new("B.TEST", b_anchor).unwrap();
        assert!(attempt(&unknown, &a.signing).is_err());
        // A valid invitation, but signed by a key A's delegation does not
        // name.
        let inv = Invitation::new("B.TEST", b_anchor).unwrap();
        dir.add_trust_invitation(&inv.secret_hash().unwrap(), now() + 3600)
            .unwrap();
        let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        assert!(attempt(&inv, &stranger).is_err());
        assert!(dir.recorded.lock().unwrap().is_empty());
        // A tampered request does not open.
        let inv = Invitation::new("B.TEST", b_anchor).unwrap();
        dir.add_trust_invitation(&inv.secret_hash().unwrap(), now() + 3600)
            .unwrap();
        let (req, _) = request(
            &adv,
            &inv,
            &a.server.as_partner(),
            &a.server.delegation(),
            &a.signing,
        )
        .unwrap();
        let mut bytes = req.to_bytes();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        let tampered = TrustRequest::from_bytes(&bytes).unwrap();
        assert!(b.server.establish_trust(&tampered, &dir).is_err());
        // An advertisement of another realm is not the invited one.
        let other = Invitation::new("C.TEST", b_anchor).unwrap();
        assert!(matches!(
            request(
                &adv,
                &other,
                &a.server.as_partner(),
                &a.server.delegation(),
                &a.signing
            ),
            Err(Error::WrongRealm)
        ));
    }
}
