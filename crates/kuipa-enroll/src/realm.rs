//! The realm advertisement (§4.3): a `tang-pqc` advertisement signed by a
//! server key, carrying that server's delegation and the realm metadata.
//!
//! Verification runs in three steps: verify the delegation against the
//! pinned anchors, use the delegated key's thumbprint to verify the
//! advertisement, then read only the verified members.

use std::time::SystemTime;

use serde::{Deserialize, Serialize};
use tang_pqc::{
    Advertisement, AdvertisementBuilder, ExchangeKey, ExchangeKeyPair, Policy, SignedAdvertisement,
    SigningKey, Thumbprint, VerifyingKey, b64, unix_seconds,
};

use crate::delegation::Claim;
use crate::delegation::{Delegation, HeadPin, HeadProof, VerifiedDelegation};
use crate::error::{Error, Result};

/// JWK member naming a key's role.
pub const ROLE_MEMBER: &str = "ipa_use";
/// Role of join (and rekey and stage) keys.
pub const ROLE_JOIN: &str = "join";
/// Role of sealed-keytab escrow keys.
pub const ROLE_ESCROW: &str = "escrow";
/// Role of the keys trust requests from other realms are sealed to (§17.4).
pub const ROLE_TRUST: &str = "trust";

const MEMBER_IPA: &str = "ipa";
const MEMBER_DELEGATION: &str = "delegation";
/// Voucher keys (§9): signature keys, so a signed member rather than JWK
/// Set entries, which Tang takes for advertisement signers.
const MEMBER_VOUCHERS: &str = "kuipa_vouchers";

/// The head of this server's anchor epoch log (§4.8): what any host
/// that has looked before must see extended.
const MEMBER_EPOCH: &str = "epoch";

/// Realm metadata published by every server (§4.3, `"ipa"` member).
///
/// It carries certificates, not just their hashes: a host that is not
/// enrolled yet needs the PKINIT anchors for FAST armour (anonymous
/// PKINIT) before an administrator using an external IdP or a passkey can
/// `kinit`, and the IPA CA lets it verify the server's TLS certificate as
/// soon as the advertisement is verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmInfo {
    /// Kerberos realm.
    pub realm: String,
    /// DNS domain.
    pub domain: String,
    /// LDAP base DN.
    pub basedn: String,
    /// This server's FQDN.
    pub server: String,
    /// The realm's servers (KDCs), for a bootstrap `krb5.conf`.
    pub servers: Vec<String>,
    /// The IPA CA chain (DER), each a CA certificate
    /// ([`check_ca`](crate::certs::check_ca)).
    pub ca_certs: Vec<Vec<u8>>,
    /// The PKINIT trust anchors (DER) clients need for anonymous PKINIT,
    /// each a CA certificate.
    pub pkinit_anchors: Vec<Vec<u8>>,
    /// Current realm anchors.
    pub anchors: Vec<Thumbprint>,
    /// The anchors' current vouch heads (§4.9), when this server knows
    /// them: what a client pins instead of — or beside — the
    /// thumbprint, to check a delegation with no signature.
    pub heads: Vec<HeadPin>,
    /// Realms this realm trusts, with the anchors it vouches for (§17).
    pub trusts: Vec<TrustedRealm>,
    /// This realm's KDC proxies, when its KDCs are not reachable
    /// directly: what a trusting realm's hosts use to reach them.
    pub kdc_proxy: Option<KdcProxy>,
}

/// How a realm's KDCs are reached when they are not reachable directly:
/// MS-KKDCP proxies (FreeIPA's `/KdcProxy`) over HTTPS.  A host's
/// `krb5.conf` then lists the proxy URLs as the realm's `kdc`s.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KdcProxy {
    /// The proxy URLs, `https://<host>[:<port>][/<path>]`, in order.
    pub urls: Vec<String>,
    /// What authenticates the proxies' TLS certificates.
    pub ca: ProxyCa,
}

/// The certificates a host trusts for a KDC proxy's TLS server (krb5's
/// `http_anchors`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProxyCa {
    /// The realm's own IPA CA, from its verified advertisement: a proxy
    /// on the IPA servers themselves.
    #[default]
    Realm,
    /// The system's trust store: a front end with a public certificate.
    System,
}

impl ProxyCa {
    /// The wire and configuration name.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Realm => "realm",
            Self::System => "system",
        }
    }
}

impl std::str::FromStr for ProxyCa {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        match s {
            "realm" => Ok(Self::Realm),
            "system" => Ok(Self::System),
            _ => Err(Error::Malformed("KDC proxy CA")),
        }
    }
}

/// At most this many proxy URLs per realm.
const MAX_KDC_PROXIES: usize = 16;

impl KdcProxy {
    /// Check that there are one to 16 URLs, each safe in generated
    /// Kerberos configuration ([`is_safe_proxy_url`]).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn validate(&self) -> Result<()> {
        if (1..=MAX_KDC_PROXIES).contains(&self.urls.len())
            && self.urls.iter().all(|u| is_safe_proxy_url(u))
        {
            Ok(())
        } else {
            Err(Error::Malformed("KDC proxy"))
        }
    }
}

/// Whether `url` is safe as a KDC proxy in generated Kerberos
/// configuration: `https://`, a host name that is [safe](is_safe_name),
/// an optional port, and a path of ASCII letters, digits, `.`, `-`, `_`,
/// `~` and `/` only — nothing that could end the `kdc` value or start
/// another relation.
#[must_use]
pub fn is_safe_proxy_url(url: &str) -> bool {
    let Some(rest) = url.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = rest.find('/').map_or((rest, ""), |i| rest.split_at(i));
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    url.len() <= 512
        && is_safe_name(host)
        && port.is_none_or(|p| {
            p.bytes().all(|b| b.is_ascii_digit()) && p.parse::<u16>().is_ok_and(|p| p > 0)
        })
        && path
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'~' | b'/'))
}

#[derive(Serialize, Deserialize)]
struct KdcProxyJson {
    urls: Vec<String>,
    /// Absent for the default, the realm's own CA.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ca: Option<String>,
}

impl From<&KdcProxy> for KdcProxyJson {
    fn from(p: &KdcProxy) -> Self {
        Self {
            urls: p.urls.clone(),
            ca: (p.ca != ProxyCa::Realm).then(|| p.ca.as_str().to_owned()),
        }
    }
}

impl KdcProxyJson {
    fn parse(self) -> Option<KdcProxy> {
        Some(KdcProxy {
            ca: self.ca.map_or(Ok(ProxyCa::Realm), |c| c.parse()).ok()?,
            urls: self.urls,
        })
    }
}

/// A trusted realm, as the advertising realm vouches for it (§17): where
/// to find its servers and which of its anchors to pin, for that realm
/// only.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedRealm {
    /// Its Kerberos realm.
    pub realm: String,
    /// Its DNS domain.
    pub domain: String,
    /// Some of its servers, to fetch its advertisement from.
    pub servers: Vec<String>,
    /// Its anchors.
    pub anchors: Vec<Thumbprint>,
    /// Its anchors' current vouch heads (DESIGN-claim-logs.md §3),
    /// aligned with `anchors` and in its advertisement's `heads` form:
    /// what a host of this realm pins for that realm next to its
    /// anchors, so its next refresh verifies with no signature.
    /// Empty where unknown (an older partner, or none of its anchors
    /// vouched yet).
    pub heads: Vec<HeadPin>,
    /// The KDC proxies this realm's hosts use for it, when its KDCs are
    /// not reachable directly.  `None`: its KDCs, or the proxies its
    /// own advertisement names.
    pub kdc_proxy: Option<KdcProxy>,
}

impl TrustedRealm {
    /// The JSON form, as in the advertisement's `trusts`.
    ///
    /// # Panics
    ///
    /// Never: the form has only strings.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(&TrustJson::from(self)).expect("serialisable")
    }

    /// Parse the JSON form.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_json(json: &[u8]) -> Result<Self> {
        serde_json::from_slice::<TrustJson>(json)
            .ok()
            .and_then(TrustJson::parse)
            .ok_or(Error::Malformed("trusted realm"))
    }

    /// Check that it is clearly separate from the realm `own` with `anchors`:
    /// safe names, another realm, with servers, and with anchors of its own.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn validate_for(&self, own: &str, anchors: &[Thumbprint]) -> Result<()> {
        let names = [&self.realm, &self.domain].into_iter().chain(&self.servers);
        if !names.into_iter().all(|n| is_safe_name(n))
            || self.realm.eq_ignore_ascii_case(own)
            || self.anchors.is_empty()
            || self.servers.is_empty()
            || self.anchors.iter().any(|a| anchors.contains(a))
            || self
                .kdc_proxy
                .as_ref()
                .is_some_and(|p| p.validate().is_err())
        {
            return Err(Error::Malformed("trusted realm"));
        }
        Ok(())
    }

    /// The heads a client should pin for this realm's anchors
    /// (DESIGN-claim-logs.md §3): only those for anchors it lists, at
    /// most one each, whatever order the wire carried.
    #[must_use]
    pub fn pins(&self) -> Vec<HeadPin> {
        self.anchors
            .iter()
            .filter_map(|a| self.heads.iter().find(|h| &h.anchor == a))
            .copied()
            .collect()
    }
}

#[derive(Serialize, Deserialize)]
struct TrustJson {
    realm: String,
    domain: String,
    servers: Vec<String>,
    anchors: Vec<String>,
    /// Absent in older advertisements: the realm's partners carried no
    /// heads (DESIGN-claim-logs.md §3).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    heads: Vec<serde_json::Value>,
    /// Absent when its KDCs are reached directly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdc_proxy: Option<KdcProxyJson>,
}

impl From<&TrustedRealm> for TrustJson {
    fn from(t: &TrustedRealm) -> Self {
        Self {
            realm: t.realm.clone(),
            domain: t.domain.clone(),
            servers: t.servers.clone(),
            anchors: t.anchors.iter().map(ToString::to_string).collect(),
            heads: t.heads.iter().map(HeadPin::to_json).collect(),
            kdc_proxy: t.kdc_proxy.as_ref().map(KdcProxyJson::from),
        }
    }
}

impl TrustJson {
    fn parse(self) -> Option<TrustedRealm> {
        Some(TrustedRealm {
            anchors: parse_anchors(&self.anchors)?,
            heads: self
                .heads
                .iter()
                .map(HeadPin::from_json)
                .collect::<Result<_>>()
                .ok()?,
            kdc_proxy: match self.kdc_proxy {
                Some(p) => Some(p.parse().filter(|p| p.validate().is_ok())?),
                None => None,
            },
            realm: self.realm,
            domain: self.domain,
            servers: self.servers,
        })
    }
}

/// Whether `name` is safe as a realm, domain or host name in generated
/// Kerberos configuration and file names: 1–253 characters of ASCII
/// letters, digits, `.`, `-` and `_`, not starting with `.` or `-`.
#[must_use]
pub fn is_safe_name(name: &str) -> bool {
    (1..=253).contains(&name.len())
        && !name.starts_with(['.', '-'])
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
}

#[derive(Serialize, Deserialize)]
struct InfoJson {
    realm: String,
    domain: String,
    basedn: String,
    server: String,
    servers: Vec<String>,
    ca_certs: Vec<String>,
    pkinit_anchors: Vec<String>,
    anchors: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    heads: Vec<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    trusts: Vec<TrustJson>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdc_proxy: Option<KdcProxyJson>,
}

fn parse_anchors(items: &[String]) -> Option<Vec<Thumbprint>> {
    items.iter().map(|a| a.parse().ok()).collect()
}

fn decode_all(items: &[String]) -> Option<Vec<Vec<u8>>> {
    items.iter().map(|c| b64::decode(c).ok()).collect()
}

impl RealmInfo {
    fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(InfoJson {
            realm: self.realm.clone(),
            domain: self.domain.clone(),
            basedn: self.basedn.clone(),
            server: self.server.clone(),
            servers: self.servers.clone(),
            ca_certs: self.ca_certs.iter().map(|c| b64::encode(c)).collect(),
            pkinit_anchors: self.pkinit_anchors.iter().map(|c| b64::encode(c)).collect(),
            anchors: self.anchors.iter().map(ToString::to_string).collect(),
            heads: self.heads.iter().map(HeadPin::to_json).collect(),
            trusts: self.trusts.iter().map(TrustJson::from).collect(),
            kdc_proxy: self.kdc_proxy.as_ref().map(KdcProxyJson::from),
        })
        .expect("serialisable")
    }

    /// Check the names, certificates and trusted realms: every name must be
    /// safe for generated configuration ([`is_safe_name`]), every CA
    /// certificate and PKINIT anchor a CA certificate
    /// ([`certs::check_ca`](crate::certs::check_ca)), and every trusted
    /// realm clearly separate — not this realm, not listed twice, with
    /// servers, and with anchors of its own, none of them this realm's.
    /// KDC proxies, this realm's and its trusted realms', must be
    /// [valid](KdcProxy::validate).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for names and trusted realms, [`Error::NotCa`]
    /// for certificates.
    pub fn validate(&self) -> Result<()> {
        let names = [&self.realm, &self.domain, &self.server]
            .into_iter()
            .chain(&self.servers);
        if !names.into_iter().all(|n| is_safe_name(n)) {
            return Err(Error::Malformed("realm info names"));
        }
        if let Some(p) = &self.kdc_proxy {
            p.validate()?;
        }
        for (list, certs) in [
            ("CA certificate", &self.ca_certs),
            ("PKINIT anchor", &self.pkinit_anchors),
        ] {
            for (i, cert) in certs.iter().enumerate() {
                crate::certs::check_ca(cert).map_err(|what| Error::NotCa {
                    list,
                    entry: i + 1,
                    what,
                })?;
            }
        }
        for (i, t) in self.trusts.iter().enumerate() {
            t.validate_for(&self.realm, &self.anchors)?;
            if self.trusts[..i]
                .iter()
                .any(|o| o.realm.eq_ignore_ascii_case(&t.realm))
            {
                return Err(Error::Malformed("trusted realm"));
            }
        }
        Ok(())
    }

    /// Parse and [`validate`](Self::validate).
    fn from_value(value: &serde_json::Value) -> Result<Self> {
        let malformed = || Error::Malformed("realm info");
        let j = InfoJson::deserialize(value).map_err(|_| malformed())?;
        let trusts = j
            .trusts
            .into_iter()
            .map(TrustJson::parse)
            .collect::<Option<_>>()
            .ok_or_else(malformed)?;
        let kdc_proxy = match j.kdc_proxy {
            Some(p) => Some(p.parse().ok_or_else(malformed)?),
            None => None,
        };
        let info = Self {
            kdc_proxy,
            ca_certs: decode_all(&j.ca_certs).ok_or_else(malformed)?,
            pkinit_anchors: decode_all(&j.pkinit_anchors).ok_or_else(malformed)?,
            anchors: parse_anchors(&j.anchors).ok_or_else(malformed)?,
            heads: j
                .heads
                .iter()
                .map(HeadPin::from_json)
                .collect::<Result<_>>()
                .map_err(|_| malformed())?,
            trusts,
            realm: j.realm,
            domain: j.domain,
            basedn: j.basedn,
            server: j.server,
            servers: j.servers,
        };
        info.validate()?;
        Ok(info)
    }
}

/// One server's keys (§4.1).
#[derive(Debug)]
pub struct ServerKeys {
    /// The server signing key.
    pub signing: SigningKey,
    /// Advertised join keys; the first is offered to new clients.
    pub join: Vec<ExchangeKeyPair>,
    /// Advertised escrow keys.
    pub escrow: Vec<ExchangeKeyPair>,
    /// Advertised trust keys (§17.4); none if this server does not accept
    /// trust requests.
    pub trust: Vec<ExchangeKeyPair>,
    /// Voucher keys (§9), public only: the issuer holds the private keys.
    pub vouchers: Vec<VerifyingKey>,
    /// Rotated-out keys of either role: still answered, no longer advertised.
    pub retired: Vec<ExchangeKeyPair>,
}

impl ServerKeys {
    /// Sign this server's advertisement carrying `delegation`, valid from
    /// `iat` to `exp`.
    ///
    /// # Errors
    ///
    /// A signing error.
    pub fn advertisement(
        &self,
        info: &RealmInfo,
        delegation: &Delegation,
        iat: u64,
        exp: u64,
        epoch: Option<(u64, crate::epoch::EpochHead)>,
    ) -> Result<SignedAdvertisement> {
        let signing = [&self.signing];
        let mut builder = AdvertisementBuilder::new(&signing);
        for k in &self.join {
            builder = builder.exchange_key_with(k.public(), ROLE_MEMBER, ROLE_JOIN);
        }
        for k in &self.escrow {
            builder = builder.exchange_key_with(k.public(), ROLE_MEMBER, ROLE_ESCROW);
        }
        for k in &self.trust {
            builder = builder.exchange_key_with(k.public(), ROLE_MEMBER, ROLE_TRUST);
        }
        if !self.vouchers.is_empty() {
            let keys = self
                .vouchers
                .iter()
                .map(|k| {
                    let mut jwk: serde_json::Value = serde_json::from_str(&k.to_jwk_json())
                        .map_err(|_| Error::Malformed("voucher key"))?;
                    jwk[ROLE_MEMBER] = crate::voucher::ROLE_VOUCHER.into();
                    Ok(jwk)
                })
                .collect::<Result<Vec<_>>>()?;
            builder = builder.member(MEMBER_VOUCHERS, keys.into());
        }
        if let Some((seq, head)) = epoch {
            builder = builder.member(
                MEMBER_EPOCH,
                serde_json::json!({ "seq": seq, "head": b64::encode(&head) }),
            );
        }
        Ok(builder
            .member(MEMBER_IPA, info.to_value())
            .member(MEMBER_DELEGATION, delegation.to_value())
            .validity(iat, exp)
            .sign()?)
    }

    /// A join key by id, advertised or retired.
    #[must_use]
    pub fn join_key(&self, kid: &Thumbprint) -> Option<&ExchangeKeyPair> {
        self.join
            .iter()
            .chain(&self.retired)
            .find(|k| k.public().kid() == kid)
    }

    /// An escrow key by id, advertised or retired.
    #[must_use]
    pub fn escrow_key(&self, kid: &Thumbprint) -> Option<&ExchangeKeyPair> {
        self.escrow
            .iter()
            .chain(&self.retired)
            .find(|k| k.public().kid() == kid)
    }

    /// A trust key by id, advertised or retired.
    #[must_use]
    pub fn trust_key(&self, kid: &Thumbprint) -> Option<&ExchangeKeyPair> {
        self.trust
            .iter()
            .chain(&self.retired)
            .find(|k| k.public().kid() == kid)
    }
}

/// The deployment a client was told to join, through channels other than
/// the enrollment string and the advertisement (§4.6): the servers named
/// with `--server`, found in DNS or stored at enrollment, and the DNS
/// domain when one was given or used for discovery.  An advertisement
/// names its realm, domain and servers itself, and verifying it only shows
/// that an anchor the client trusts vouches for them; this is what they
/// must also agree with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Deployment {
    /// The servers the client was told to use.
    pub servers: Vec<String>,
    /// The realm's DNS domain, if the client knows it independently.
    pub domain: Option<String>,
}

impl Deployment {
    /// Servers only, no domain.
    #[must_use]
    pub fn servers(servers: &[String]) -> Self {
        Self {
            servers: servers.to_vec(),
            domain: None,
        }
    }

    /// Whether `name` is one of the servers.
    #[must_use]
    pub fn has_server(&self, name: &str) -> bool {
        self.servers.iter().any(|s| same_name(s, name))
    }
}

/// DNS names compare without case and without a trailing dot.
fn same_name(a: &str, b: &str) -> bool {
    a.trim_end_matches('.')
        .eq_ignore_ascii_case(b.trim_end_matches('.'))
}

/// A verified advertisement of one server of a realm.
#[derive(Clone, Debug)]
pub struct VerifiedRealm {
    info: RealmInfo,
    delegation: VerifiedDelegation,
    /// The head proofs the advertisement's delegation carried, parsed
    /// (each still needs a pinned window to check against — §2).
    head_proofs: Vec<HeadProof>,
    /// The heads the delegation proved **by signature** at verification
    /// time (`Delegation::verified_heads`): the only heads a reader may
    /// pin from this advertisement (DESIGN-claim-logs.md §4).
    proved_heads: Vec<HeadPin>,
    /// The server's claim the delegation carries: what head proofs are
    /// checked against (§2 gate).
    claim: Claim,
    adv: Advertisement,
    /// The signed advertisement as served, to keep without fetching it
    /// again (it verifies again wherever it is read back).
    signed: SignedAdvertisement,
    epoch: Option<(u64, crate::epoch::EpochHead)>,
}

impl VerifiedRealm {
    /// Verify `adv` as an advertisement of a server of `realm`, whose
    /// delegation is signed by one of `anchors`, as of `now`.
    ///
    /// Which server the client connected to is not checked: every key in
    /// the exchange belongs to the delegated server (§4.6).
    ///
    /// # Errors
    ///
    /// * [`Error::Missing`]: no delegation member.
    /// * [`Error::UntrustedAnchor`] / [`Error::Expired`]: from the
    ///   delegation.
    /// * [`Error::WrongRealm`]: the delegation is for another realm.
    /// * [`Error::Mismatch`]: the realm metadata names another realm or
    ///   server than the delegation.
    /// * [`Error::Crypto`]: the advertisement itself does not verify.
    pub fn verify(
        adv: &SignedAdvertisement,
        realm: &str,
        anchors: &[Thumbprint],
        policy: &Policy,
        now: SystemTime,
    ) -> Result<Self> {
        Self::verify_with_heads(adv, realm, anchors, &[], &[], policy, now)
    }

    /// [`verify`](Self::verify) with the client's pinned vouch heads
    /// (§4.9) and the claims their logs retired, as the client learned
    /// them: a delegation that carries a head proof for one of them, for a
    /// claim not retired, is accepted with no signature.  The heads do not
    /// replace the pins:
    /// an expired or absent head falls back to the signature proofs the
    /// advertisement also carries or the client asks for again.
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify).
    pub fn verify_with_heads(
        adv: &SignedAdvertisement,
        realm: &str,
        anchors: &[Thumbprint],
        heads: &[HeadPin],
        retired: &[crate::merkle::Hash],
        policy: &Policy,
        now: SystemTime,
    ) -> Result<Self> {
        let parsed = Delegation::from_value(
            adv.unverified_member(MEMBER_DELEGATION)?
                .ok_or(Error::Missing("delegation"))?,
        )?;
        let proved_heads = parsed.verified_heads(policy, unix_seconds(now));
        let head_proofs = parsed.head_proofs();
        let claim = parsed.claim()?;
        let delegation =
            parsed.verify_at_with_heads(anchors, heads, retired, policy, unix_seconds(now))?;
        if delegation.realm != realm {
            return Err(Error::WrongRealm);
        }
        let signed = adv.clone();
        let adv = adv.verify_at(&delegation.key, policy, now)?;
        let info =
            RealmInfo::from_value(adv.member(MEMBER_IPA).ok_or(Error::Missing("realm info"))?)?;
        if info.realm != delegation.realm || info.server != delegation.server {
            return Err(Error::Mismatch("server identity"));
        }
        // The epoch head is advisory here: a server with no epoch log yet
        // names none, and a mismatch with what the client stored is the flow's
        // discovery, not a reason to reject this advertisement.
        let epoch = adv.member(MEMBER_EPOCH).and_then(|v| {
            let seq = v.get("seq")?.as_u64()?;
            let head = b64::decode(v.get("head")?.as_str()?).ok()?;
            crate::epoch::EpochHead::try_from(head.as_slice())
                .ok()
                .filter(|_| seq > 0)
                .map(|h| (seq, h))
        });
        Ok(Self {
            info,
            delegation,
            head_proofs,
            proved_heads,
            claim,
            adv,
            signed,
            epoch,
        })
    }

    /// The realm metadata.
    #[must_use]
    pub fn info(&self) -> &RealmInfo {
        &self.info
    }

    /// The delegated server's FQDN: the identity to use for the rest of
    /// the exchange.
    #[must_use]
    pub fn server(&self) -> &str {
        &self.delegation.server
    }

    /// The server signing key, as the verified advertisement carries it:
    /// what its transparency-log heads and receipts verify with.
    #[must_use]
    pub fn signing_key(&self) -> Option<&VerifyingKey> {
        self.adv
            .signing_keys()
            .iter()
            .find(|k| k.thumbprint() == self.signer())
    }

    /// Thumbprint of the server signing key.
    #[must_use]
    pub fn signer(&self) -> &Thumbprint {
        &self.delegation.key
    }

    /// The pinned anchor whose signature on the delegation was accepted.
    #[must_use]
    pub fn anchor(&self) -> &Thumbprint {
        &self.delegation.anchor
    }

    /// Every pinned anchor whose own proof of the delegation checked,
    /// [`anchor`](Self::anchor) first: one advertisement can carry a
    /// client's whole quorum (DESIGN §4.4).
    #[must_use]
    pub fn proven_by(&self) -> &[crate::delegation::ProvenBy] {
        &self.delegation.proven_by
    }

    /// The pinned anchor whose **head** proved the delegation, if one did
    /// (§4.9): `None` when a signature was checked.  A frozen pin
    /// demands one of these (DESIGN-claim-logs.md §2).
    #[must_use]
    pub fn head_anchor(&self) -> Option<Thumbprint> {
        self.delegation.head_anchor
    }

    /// The head proofs this advertisement carried, for a frozen pin's
    /// §2 gate: each frozen anchor must have one that checks against
    /// its pinned window ([`HeadPin::check`]).
    #[must_use]
    pub fn head_proofs(&self) -> &[HeadProof] {
        &self.head_proofs
    }

    /// The heads this advertisement proved by signature: the only heads
    /// a reader may pin from it (DESIGN-claim-logs.md §4).
    #[must_use]
    pub fn proved_heads(&self) -> &[HeadPin] {
        &self.proved_heads
    }

    /// The server's claim this advertisement delegates: the claim head
    /// proofs prove ([`HeadPin::check`] takes it).
    #[must_use]
    pub fn claim(&self) -> &Claim {
        &self.claim
    }

    /// When the accepted anchor's vouch expires (Unix seconds).
    /// `u64::MAX` when a pinned head proved the claim instead (§4.9):
    /// a head proof has no lifetime.
    #[must_use]
    pub fn vouched_until(&self) -> u64 {
        self.delegation.vouched_until
    }

    /// The successions followed from a pinned anchor to the accepted one,
    /// as `(old, new)`; empty if the accepted anchor is pinned (§4.7).
    #[must_use]
    pub fn succeeded(&self) -> &[(Thumbprint, Thumbprint)] {
        &self.delegation.succeeded
    }

    /// The head of the server's anchor epoch log, if it named one
    /// (§4.8).
    #[must_use]
    pub fn epoch(&self) -> Option<(u64, crate::epoch::EpochHead)> {
        self.epoch
    }

    /// When the delegation's claim expires (Unix seconds).
    #[must_use]
    pub fn delegation_expires(&self) -> u64 {
        self.delegation.exp
    }

    /// The join key to use.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] if none is advertised (or the policy allows none).
    pub fn join_key(&self) -> Result<&ExchangeKey> {
        self.adv
            .exchange_keys_where(ROLE_MEMBER, ROLE_JOIN)
            .next()
            .ok_or(Error::Missing("join key"))
    }

    /// The escrow key to bind sealed keytabs to.
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] if none is advertised.
    pub fn escrow_key(&self) -> Result<&ExchangeKey> {
        self.adv
            .exchange_keys_where(ROLE_MEMBER, ROLE_ESCROW)
            .next()
            .ok_or(Error::Missing("escrow key"))
    }

    /// The voucher keys the realm accepts (§9).
    #[must_use]
    pub fn voucher_keys(&self) -> Vec<VerifyingKey> {
        let Some(serde_json::Value::Array(keys)) = self.adv.member(MEMBER_VOUCHERS) else {
            return Vec::new();
        };
        keys.iter()
            .filter(|k| k[ROLE_MEMBER] == crate::voucher::ROLE_VOUCHER)
            .filter_map(|k| VerifyingKey::from_jwk_json(k.to_string().as_bytes()).ok())
            .collect()
    }

    /// The key to seal a trust request to (§17.4).
    ///
    /// # Errors
    ///
    /// [`Error::Missing`] if none is advertised.
    pub fn trust_key(&self) -> Result<&ExchangeKey> {
        self.adv
            .exchange_keys_where(ROLE_MEMBER, ROLE_TRUST)
            .next()
            .ok_or(Error::Missing("trust key"))
    }

    /// The underlying `tang-pqc` advertisement.
    #[must_use]
    pub fn advertisement(&self) -> &Advertisement {
        &self.adv
    }

    /// The signed advertisement this was verified from, as served: to keep
    /// it, for verifying again later, without fetching it again.
    #[must_use]
    pub fn signed(&self) -> &SignedAdvertisement {
        &self.signed
    }

    /// Require every certificate to be one the advertisement lists, and at
    /// least one.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`].
    pub fn check_ca_certs(&self, certs: &[Vec<u8>]) -> Result<()> {
        if certs.is_empty() || certs.iter().any(|c| !self.info.ca_certs.contains(c)) {
            return Err(Error::Mismatch("CA chain"));
        }
        Ok(())
    }

    /// Require every anchor an enrollment tells this host to pin to be one
    /// the verified advertisement vouches for: advertised by the realm, or
    /// reached from a pinned anchor through proven successions.  An
    /// enrollment carries the server's own choice of anchors; without this
    /// check, any server still holding the realm's join key could pin the
    /// host to anchors of its own (§4.8's frozen-server threat).
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] for an anchor the advertisement does not vouch
    /// for.
    pub fn check_anchors(&self, anchors: &[Thumbprint]) -> Result<()> {
        // The anchors this advertisement makes believable: the realm's
        // advertised set, plus every succession end the delegation proved
        // on the way to it (old pinned ends included, so a rotation in
        // flight still verifies).
        let mut believed: Vec<Thumbprint> = self.info.anchors.clone();
        believed.extend(self.delegation.succeeded.iter().flat_map(|(a, b)| [a, b]));
        believed.push(*self.anchor());
        if anchors.is_empty() || anchors.iter().any(|a| !believed.contains(a)) {
            return Err(Error::Mismatch("anchors"));
        }
        Ok(())
    }

    /// Require an enrollment's epoch watermark to agree with what this
    /// advertisement showed: either the server named no log at all, or the
    /// watermark is the one it advertised.  The enrollment's value must
    /// never replace the client's own verified chain knowledge (§4.8).
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] when the server named an epoch and the
    /// enrollment carries a different one.
    pub fn check_epoch(&self, epoch: (u64, crate::epoch::EpochHead)) -> Result<()> {
        if self.epoch.is_some_and(|e| e != epoch) {
            return Err(Error::Mismatch("anchor epoch"));
        }
        Ok(())
    }

    /// Check that this advertisement describes `deployment` (§4.6): the
    /// delegated server is one of its servers and lists itself among the
    /// realm's servers, and the domain is the one the client knows, if it
    /// knows one.  The realm was already checked by [`Self::verify`].
    ///
    /// # Errors
    ///
    /// [`Error::Deployment`], naming what was expected and what is
    /// advertised.
    pub fn check_deployment(&self, deployment: &Deployment) -> Result<()> {
        let server = self.server();
        if !deployment.has_server(server) {
            return Err(Error::Deployment(format!(
                "the advertisement is for server {server}, which is not one of the servers to use ({})",
                deployment.servers.join(", ")
            )));
        }
        if !self.info.servers.iter().any(|s| same_name(s, server)) {
            return Err(Error::Deployment(format!(
                "server {server} is not among the servers its advertisement lists ({})",
                self.info.servers.join(", ")
            )));
        }
        if let Some(domain) = &deployment.domain
            && !same_name(domain, &self.info.domain)
        {
            return Err(Error::Deployment(format!(
                "the advertisement is for domain {}, not {domain}",
                self.info.domain
            )));
        }
        Ok(())
    }

    /// The KDCs to use before enrollment: this server first, then the
    /// other advertised servers that are also in `deployment`, so secrets
    /// sent to a KDC (a password, an OTP) only go to hosts the client was
    /// told to use.
    #[must_use]
    pub fn kdcs_within<'a>(&'a self, deployment: &Deployment) -> Vec<&'a str> {
        let server = self.server();
        let mut kdcs = vec![server];
        kdcs.extend(
            self.info
                .servers
                .iter()
                .map(String::as_str)
                .filter(|s| !same_name(s, server) && deployment.has_server(s)),
        );
        kdcs
    }

    /// A `krb5.conf` for bootstrapping Kerberos before enrollment (§5.4),
    /// with the KDCs of [`Self::kdcs_within`] `deployment`: see
    /// [`krb5_conf`].
    #[must_use]
    pub fn krb5_conf(&self, pkinit_anchors_file: &str, deployment: &Deployment) -> String {
        krb5_conf(
            &self.info.realm,
            &self.info.domain,
            &self.kdcs_within(deployment),
            pkinit_anchors_file,
        )
    }
}

/// A minimal `krb5.conf` for `realm`: `kdcs` in order (duplicates
/// dropped, the first is the primary), no DNS lookups, and
/// `pkinit_anchors_file` (PEM) for anonymous PKINIT armour.
#[must_use]
pub fn krb5_conf(realm: &str, domain: &str, kdcs: &[&str], pkinit_anchors_file: &str) -> String {
    let lines = [
        "# Generated by kuipa from verified realm data.",
        "[libdefaults]",
        &format!("    default_realm = {realm}"),
        "    dns_lookup_realm = false",
        "    dns_lookup_kdc = false",
        "    rdns = false",
        "    dns_canonicalize_hostname = false",
        "    udp_preference_limit = 0",
        "",
    ]
    .join("\n");
    lines + "\n" + &krb5_realm_section(realm, domain, kdcs, pkinit_anchors_file)
}

/// The `[realms]` and `[domain_realm]` sections for one realm, without
/// `[libdefaults]`: as a `krb5.conf.d` snippet for a trusted realm (§17),
/// its `pkinit_anchors` apply to that realm's KDCs only.
#[must_use]
pub fn krb5_realm_section(
    realm: &str,
    domain: &str,
    kdcs: &[&str],
    pkinit_anchors_file: &str,
) -> String {
    let mut unique: Vec<&str> = Vec::new();
    for k in kdcs {
        if !unique.contains(k) {
            unique.push(k);
        }
    }
    let mut relations: Vec<String> = unique.iter().map(|k| format!("kdc = {k}:88")).collect();
    if let Some(primary) = unique.first() {
        relations.push(format!("master_kdc = {primary}:88"));
    }
    realm_section(realm, domain, relations, pkinit_anchors_file)
}

/// [`krb5_realm_section`] for a realm whose KDCs are reached through
/// `proxy`: each URL is a `kdc`, and the proxies' TLS certificates are
/// checked against `ca_file` (the realm's IPA CA, PEM) for
/// [`ProxyCa::Realm`], or the system trust store for
/// [`ProxyCa::System`].  MIT Kerberos only: Heimdal does not speak
/// MS-KKDCP.  A URL that is not safe in generated configuration
/// ([`is_safe_proxy_url`]) is left out rather than interpolated.
#[must_use]
pub fn krb5_proxied_realm_section(
    realm: &str,
    domain: &str,
    proxy: &KdcProxy,
    ca_file: &str,
    pkinit_anchors_file: &str,
) -> String {
    let mut unique: Vec<&str> = Vec::new();
    for u in &proxy.urls {
        if is_safe_proxy_url(u) && !unique.contains(&u.as_str()) {
            unique.push(u);
        }
    }
    let mut relations: Vec<String> = unique.iter().map(|u| format!("kdc = {u}")).collect();
    if proxy.ca == ProxyCa::Realm {
        relations.push(format!("http_anchors = FILE:{ca_file}"));
    }
    realm_section(realm, domain, relations, pkinit_anchors_file)
}

fn realm_section(
    realm: &str,
    domain: &str,
    relations: Vec<String>,
    pkinit_anchors_file: &str,
) -> String {
    let mut lines = vec!["[realms]".to_owned(), format!("    {realm} = {{")];
    lines.extend(relations.into_iter().map(|r| format!("        {r}")));
    lines.extend([
        format!("        pkinit_anchors = FILE:{pkinit_anchors_file}"),
        format!("        pkinit_pool = FILE:{pkinit_anchors_file}"),
        "    }".into(),
        String::new(),
        "[domain_realm]".into(),
        format!("    .{domain} = {realm}"),
        format!("    {domain} = {realm}"),
        String::new(),
    ]);
    lines.join("\n")
}

#[cfg(test)]
pub(crate) mod tests {
    use tang_pqc::{KemAlg, SignatureAlg};

    use super::*;
    use crate::delegation::{SignedVouch, VOUCH_VALIDITY};
    use crate::server::EnrollServer;

    pub(crate) struct TestRealm {
        pub anchor: SigningKey,
        pub keys: ServerKeys,
        pub delegation: Delegation,
        pub info: RealmInfo,
        pub ca: Vec<u8>,
    }

    pub(crate) fn now() -> u64 {
        unix_seconds(SystemTime::now())
    }

    pub(crate) fn test_realm(server: &str) -> TestRealm {
        let anchor = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        server_of(anchor, server)
    }

    pub(crate) fn server_of(anchor: SigningKey, server: &str) -> TestRealm {
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let delegation = Delegation::issue(
            &anchor,
            "EXAMPLE.TEST",
            server,
            signing.public(),
            now() - 60,
            now() + 86400,
        )
        .unwrap();
        let ca = include_bytes!("../tests/data/ipa-ca.der").to_vec();
        let info = RealmInfo {
            realm: "EXAMPLE.TEST".into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            server: server.into(),
            servers: vec![server.into()],
            ca_certs: vec![ca.clone()],
            pkinit_anchors: vec![include_bytes!("../tests/data/pkinit-ca.der").to_vec()],
            anchors: vec![*anchor.public().thumbprint()],
            heads: Vec::new(),
            trusts: Vec::new(),
            kdc_proxy: None,
        };
        TestRealm {
            anchor,
            delegation,
            keys: ServerKeys {
                signing,
                join: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
                escrow: vec![ExchangeKeyPair::generate(KemAlg::MlKem768).unwrap()],
                trust: Vec::new(),
                vouchers: Vec::new(),
                retired: Vec::new(),
            },
            info,
            ca,
        }
    }

    impl TestRealm {
        pub(crate) fn signed(&self) -> SignedAdvertisement {
            self.keys
                .advertisement(&self.info, &self.delegation, now() - 10, now() + 3600, None)
                .unwrap()
        }
    }

    fn trusted(realm: &str, anchor: Thumbprint) -> TrustedRealm {
        TrustedRealm {
            realm: realm.into(),
            domain: realm.to_ascii_lowercase(),
            servers: vec![format!("ipa1.{}", realm.to_ascii_lowercase())],
            anchors: vec![anchor],
            heads: Vec::new(),
            kdc_proxy: None,
        }
    }

    #[test]
    fn trusted_realms_are_separate_realms() {
        let mut t = test_realm("ipa1.example.test");
        let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        t.info.trusts = vec![trusted("B.TEST", *other.public().thumbprint())];
        let back = RealmInfo::from_value(&t.info.to_value()).unwrap();
        assert_eq!(back, t.info);

        let own = *t.anchor.public().thumbprint();
        let refused = [
            // The advertising realm itself, in any case.
            vec![trusted("example.test", *other.public().thumbprint())],
            // Listed twice.
            vec![
                trusted("B.TEST", *other.public().thumbprint()),
                trusted("b.test", *other.public().thumbprint()),
            ],
            // Sharing an anchor with the advertising realm.
            vec![trusted("B.TEST", own)],
            // Names that would inject into krb5.conf or escape a path.
            vec![TrustedRealm {
                realm: "B.TEST\n[libdefaults]".into(),
                ..trusted("B.TEST", *other.public().thumbprint())
            }],
            vec![TrustedRealm {
                servers: vec!["../etc".into()],
                ..trusted("B.TEST", *other.public().thumbprint())
            }],
        ];
        for trusts in refused {
            let info = RealmInfo {
                trusts,
                realm: "EXAMPLE.TEST".into(),
                ..t.info.clone()
            };
            assert!(RealmInfo::from_value(&info.to_value()).is_err(), "{info:?}");
        }
        assert!(is_safe_name("ipa1.b-c_d.test"));
        for bad in ["", ".x", "-x", "a b", "a/b", "a}b", "a=b"] {
            assert!(!is_safe_name(bad), "{bad:?}");
        }
    }

    fn verified(t: &TestRealm) -> VerifiedRealm {
        VerifiedRealm::verify(
            &t.signed(),
            "EXAMPLE.TEST",
            &[*t.anchor.public().thumbprint()],
            &Policy::default(),
            SystemTime::now(),
        )
        .unwrap()
    }

    #[test]
    fn enrollment_anchors_must_be_vouched_for() {
        let t = test_realm("ipa1.example.test");
        let v = verified(&t);
        let own = *t.anchor.public().thumbprint();
        // The realm's advertised anchors, and the proof's own ends, pass.
        v.check_anchors(&[own]).unwrap();
        // A pinned anchor the client does not have does not: the
        // enrollment cannot introduce trust the advertisement did not
        // vouch for.
        let stranger = *SigningKey::generate(SignatureAlg::MlDsa65)
            .unwrap()
            .public()
            .thumbprint();
        assert!(matches!(
            v.check_anchors(&[stranger]),
            Err(Error::Mismatch(_))
        ));
        // Nor may a stranger ride along beside a real one.
        assert!(matches!(
            v.check_anchors(&[own, stranger]),
            Err(Error::Mismatch(_))
        ));
        // Empty is no choice at all.
        assert!(matches!(v.check_anchors(&[]), Err(Error::Mismatch(_))));
    }

    #[test]
    fn enrollment_epoch_must_match_the_advertisement() {
        let t = test_realm("ipa1.example.test");
        let v = verified(&t);
        // This advertisement named no log: any watermark stands (a server
        // with no epoch log yet names none, §4.8).
        v.check_epoch((7, [1; 48])).unwrap();
        // One that names a log demands the same watermark.
        let e = (3, [2; 48]);
        // Re-sign with an epoch member, as the server's advertisement does.
        let set = t
            .keys
            .advertisement(&t.info, &t.delegation, now() - 10, now() + 3600, Some(e))
            .unwrap();
        let v = VerifiedRealm::verify(
            &set,
            "EXAMPLE.TEST",
            &[*t.anchor.public().thumbprint()],
            &Policy::default(),
            SystemTime::now(),
        )
        .unwrap();
        v.check_epoch(e).unwrap();
        assert!(matches!(
            v.check_epoch((4, [2; 48])),
            Err(Error::Mismatch(_))
        ));
        assert!(matches!(
            v.check_epoch((3, [3; 48])),
            Err(Error::Mismatch(_))
        ));
    }

    #[test]
    fn advertisement_must_describe_the_deployment() {
        let mut t = test_realm("ipa1.example.test");
        t.info.servers = vec!["ipa1.example.test".into(), "ipa2.example.test".into()];
        let v = verified(&t);
        let deployment = |servers: &[&str], domain: Option<&str>| Deployment {
            servers: servers.iter().map(|s| (*s).to_owned()).collect(),
            domain: domain.map(str::to_owned),
        };

        // Names compare without case or a trailing dot; the domain is
        // checked only when the client knows one.
        for ok in [
            deployment(&["ipa1.example.test"], None),
            deployment(&["IPA1.Example.Test."], Some("Example.Test")),
            deployment(
                &["ipa2.example.test", "ipa1.example.test"],
                Some("example.test"),
            ),
        ] {
            v.check_deployment(&ok).unwrap();
        }
        for (bad, why) in [
            (
                deployment(&["ipa2.example.test"], None),
                "not one of the servers to use",
            ),
            (deployment(&[], None), "not one of the servers to use"),
            (
                deployment(&["ipa1.example.test"], Some("other.test")),
                "not other.test",
            ),
        ] {
            let e = v.check_deployment(&bad).unwrap_err();
            assert!(matches!(e, Error::Deployment(_)), "{e}");
            assert!(e.to_string().contains(why), "{e}");
        }

        // A server that does not list itself among the realm's servers.
        t.info.servers = vec!["ipa2.example.test".into()];
        let e = verified(&t)
            .check_deployment(&deployment(&["ipa1.example.test"], None))
            .unwrap_err();
        assert!(e.to_string().contains("not among the servers"), "{e}");
    }

    #[test]
    fn kdcs_are_narrowed_to_the_deployment() {
        let mut t = test_realm("ipa1.example.test");
        t.info.servers = vec![
            "ipa1.example.test".into(),
            "ipa2.example.test".into(),
            "kdc.elsewhere.test".into(),
        ];
        let v = verified(&t);
        let d = Deployment::servers(&["ipa1.example.test".into(), "IPA2.example.test".into()]);
        assert_eq!(
            v.kdcs_within(&d),
            ["ipa1.example.test", "ipa2.example.test"]
        );
        let conf = v.krb5_conf("/p.pem", &d);
        assert!(conf.contains("kdc = ipa2.example.test:88"));
        assert!(!conf.contains("elsewhere"), "{conf}");
        let conf = v.krb5_conf(
            "/p.pem",
            &Deployment::servers(&["ipa1.example.test".into()]),
        );
        assert!(!conf.contains("ipa2"), "{conf}");
    }

    #[test]
    fn realm_section_has_no_defaults() {
        let s = krb5_realm_section("B.TEST", "b.test", &["k1", "k2", "k1"], "/p.pem");
        assert!(!s.contains("[libdefaults]"));
        assert!(s.contains("B.TEST = {"));
        assert_eq!(s.lines().filter(|l| l.trim() == "kdc = k1:88").count(), 1);
        assert!(s.contains("pkinit_anchors = FILE:/p.pem"));
        assert!(s.contains(".b.test = B.TEST"));
    }

    #[test]
    fn verify_realm_advertisement() {
        let t = test_realm("ipa1.example.test");
        let json = t.signed().to_json();
        let adv = SignedAdvertisement::from_json(json.as_bytes()).unwrap();
        let anchors = [*t.anchor.public().thumbprint()];
        let v = VerifiedRealm::verify(
            &adv,
            "EXAMPLE.TEST",
            &anchors,
            &Policy::default(),
            SystemTime::now(),
        )
        .unwrap();
        assert_eq!(v.server(), "ipa1.example.test");
        assert_eq!(v.join_key().unwrap().kid(), t.keys.join[0].public().kid());
        assert_eq!(
            v.escrow_key().unwrap().kid(),
            t.keys.escrow[0].public().kid()
        );
        assert!(
            v.advertisement().exchange_keys().is_empty(),
            "no plain Tang keys"
        );
        v.check_ca_certs(std::slice::from_ref(&t.ca)).unwrap();
        assert!(v.check_ca_certs(&[b"other".to_vec()]).is_err());
        assert!(v.check_ca_certs(&[]).is_err());
        let conf = v.krb5_conf(
            "/tmp/anchors.pem",
            &Deployment::servers(&["ipa1.example.test".into()]),
        );
        assert!(conf.contains("default_realm = EXAMPLE.TEST"));
        assert!(conf.contains("        kdc = ipa1.example.test:88\n"));
        assert!(conf.contains("pkinit_anchors = FILE:/tmp/anchors.pem"));
        assert_eq!(
            v.info().pkinit_anchors,
            vec![include_bytes!("../tests/data/pkinit-ca.der").to_vec()]
        );

        assert!(matches!(
            VerifiedRealm::verify(
                &adv,
                "OTHER.TEST",
                &anchors,
                &Policy::default(),
                SystemTime::now()
            ),
            Err(Error::WrongRealm)
        ));
        let stranger = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        assert!(matches!(
            VerifiedRealm::verify(
                &adv,
                "EXAMPLE.TEST",
                &[*stranger.public().thumbprint()],
                &Policy::default(),
                SystemTime::now()
            ),
            Err(Error::UntrustedAnchor)
        ));
    }

    #[test]
    fn delegation_must_match_signer_and_info() {
        // A server signing with a key that is not the delegated one.
        let mut t = test_realm("ipa1.example.test");
        t.keys.signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let anchors = [*t.anchor.public().thumbprint()];
        assert!(matches!(
            VerifiedRealm::verify(
                &t.signed(),
                "EXAMPLE.TEST",
                &anchors,
                &Policy::default(),
                SystemTime::now()
            ),
            Err(Error::Crypto(_))
        ));

        // Realm info naming another server than the delegation.
        let mut t = test_realm("ipa1.example.test");
        t.info.server = "ipa2.example.test".into();
        let anchors = [*t.anchor.public().thumbprint()];
        assert!(matches!(
            VerifiedRealm::verify(
                &t.signed(),
                "EXAMPLE.TEST",
                &anchors,
                &Policy::default(),
                SystemTime::now()
            ),
            Err(Error::Mismatch(_))
        ));
    }

    #[test]
    fn advertised_certificates_must_be_ca_certificates() {
        // What a host would write into ca.crt or its PKINIT anchors: a
        // blob that is no certificate, and an end-entity certificate.
        let leaf = synta_certificate::pem_to_der(include_bytes!("../tests/data/mtc-demo-leaf.pem"));
        for bad in [b"IPA CA (DER)".to_vec(), leaf[0].clone()] {
            for pkinit in [false, true] {
                let mut t = test_realm("ipa1.example.test");
                if pkinit {
                    t.info.pkinit_anchors.push(bad.clone());
                } else {
                    t.info.ca_certs.push(bad.clone());
                }
                let anchors = [*t.anchor.public().thumbprint()];
                assert!(matches!(
                    VerifiedRealm::verify(
                        &t.signed(),
                        "EXAMPLE.TEST",
                        &anchors,
                        &Policy::default(),
                        SystemTime::now()
                    ),
                    Err(Error::NotCa { entry: 2, .. })
                ));
            }
        }

        // A Merkle Tree CA is one, though it is unsigned.
        let mut t = test_realm("ipa1.example.test");
        let mtc = synta_certificate::pem_to_der(include_bytes!("../tests/data/mtc-demo-ca.pem"));
        t.info.ca_certs.push(mtc[0].clone());
        assert!(verified(&t).info().ca_certs.contains(&mtc[0]));
    }

    #[test]
    fn kdc_proxy_urls_are_safe_in_krb5_conf() {
        for ok in [
            "https://ipa1.b.test/KdcProxy",
            "https://id.fedoraproject.org/KdcProxy",
            "https://kdc.b.test:8443/KdcProxy",
            "https://kdc.b.test",
            "https://kdc.b.test/a/b~c_d.e-f/",
        ] {
            assert!(is_safe_proxy_url(ok), "{ok}");
        }
        for bad in [
            "http://ipa1.b.test/KdcProxy",
            "ipa1.b.test/KdcProxy",
            "https://",
            "https:///KdcProxy",
            "https://ipa1.b.test:/KdcProxy",
            "https://ipa1.b.test:0/KdcProxy",
            "https://ipa1.b.test:65536/KdcProxy",
            "https://ipa1.b.test:+443/KdcProxy",
            "https://user@ipa1.b.test/KdcProxy",
            "https://ipa1.b.test/KdcProxy?x=1",
            "https://ipa1.b.test/Kdc Proxy",
            "https://ipa1.b.test/KdcProxy\n    }",
            "https://ipa1.b.test/KdcProxy}",
            "https://-b.test/KdcProxy",
        ] {
            assert!(!is_safe_proxy_url(bad), "{bad}");
        }
        let long = format!("https://b.test/{}", "a".repeat(500));
        assert!(!is_safe_proxy_url(&long));
    }

    #[test]
    fn kdc_proxies_round_trip_and_are_checked() {
        let mut t = test_realm("ipa1.example.test");
        let other = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let proxy = |ca, urls: &[&str]| KdcProxy {
            urls: urls.iter().map(|u| (*u).to_owned()).collect(),
            ca,
        };
        let b = TrustedRealm {
            kdc_proxy: Some(proxy(ProxyCa::Realm, &["https://ipa1.b.test/KdcProxy"])),
            ..trusted("B.TEST", *other.public().thumbprint())
        };
        // The default CA is no member at all; another one is named.
        let json = b.to_json();
        assert!(json.contains(r#""kdc_proxy":{"urls":["https://ipa1.b.test/KdcProxy"]}"#));
        assert_eq!(TrustedRealm::from_json(json.as_bytes()).unwrap(), b);
        t.info.trusts = vec![b.clone()];
        t.info.kdc_proxy = Some(proxy(
            ProxyCa::System,
            &["https://id.example.test/KdcProxy"],
        ));
        let value = t.info.to_value();
        assert_eq!(value["kdc_proxy"]["ca"], "system");
        assert_eq!(RealmInfo::from_value(&value).unwrap(), t.info);
        // An unknown CA, an unsafe URL or no URL at all is refused, in
        // the realm's own entry or a trusted realm's.
        let mut unknown = value.clone();
        unknown["kdc_proxy"]["ca"] = "anything".into();
        assert!(RealmInfo::from_value(&unknown).is_err());
        for bad in [
            proxy(ProxyCa::Realm, &[]),
            proxy(ProxyCa::Realm, &["https://b.test/KdcProxy\n[libdefaults]"]),
        ] {
            let own = RealmInfo {
                kdc_proxy: Some(bad.clone()),
                ..t.info.clone()
            };
            assert!(RealmInfo::from_value(&own.to_value()).is_err(), "{bad:?}");
            let theirs = RealmInfo {
                trusts: vec![TrustedRealm {
                    kdc_proxy: Some(bad.clone()),
                    ..b.clone()
                }],
                ..t.info.clone()
            };
            assert!(
                RealmInfo::from_value(&theirs.to_value()).is_err(),
                "{bad:?}"
            );
        }
        // An advertisement without proxies is what it was before them.
        t.info.trusts = vec![trusted("B.TEST", *other.public().thumbprint())];
        t.info.kdc_proxy = None;
        assert!(!t.info.to_value().to_string().contains("kdc_proxy"));
    }

    #[test]
    fn proxied_realm_section() {
        let proxy = KdcProxy {
            urls: vec![
                "https://ipa1.b.test/KdcProxy".into(),
                "https://ipa2.b.test/KdcProxy".into(),
                "https://ipa1.b.test/KdcProxy".into(),
            ],
            ca: ProxyCa::Realm,
        };
        let s = krb5_proxied_realm_section("B.TEST", "b.test", &proxy, "/ca.crt", "/p.pem");
        assert!(!s.contains("[libdefaults]"));
        assert_eq!(
            s.lines()
                .filter(|l| l.trim().starts_with("kdc = "))
                .map(str::trim)
                .collect::<Vec<_>>(),
            [
                "kdc = https://ipa1.b.test/KdcProxy",
                "kdc = https://ipa2.b.test/KdcProxy"
            ]
        );
        assert!(!s.contains("master_kdc"), "{s}");
        assert!(s.contains("http_anchors = FILE:/ca.crt"), "{s}");
        assert!(s.contains("pkinit_anchors = FILE:/p.pem"), "{s}");
        assert!(s.contains(".b.test = B.TEST"), "{s}");
        // A public front end: the system's trust store, so no anchors.
        let public = KdcProxy {
            ca: ProxyCa::System,
            ..proxy
        };
        let s = krb5_proxied_realm_section("B.TEST", "b.test", &public, "/ca.crt", "/p.pem");
        assert!(!s.contains("http_anchors"), "{s}");
    }

    #[test]
    fn trusted_realm_heads_round_trip() {
        let a = *test_realm("ipa1.example.test").anchor.public().thumbprint();
        let head = HeadPin {
            anchor: a,
            size: 3,
            root: crate::merkle::test_hash(7),
        };
        let t = TrustedRealm {
            realm: "B.TEST".into(),
            domain: "b.test".into(),
            servers: vec!["ipa1.b.test".into()],
            anchors: vec![a],
            heads: vec![head],
            kdc_proxy: None,
        };
        assert_eq!(TrustedRealm::from_json(t.to_json().as_bytes()).unwrap(), t);
        // pins(): the head for an anchor it lists, none for one it
        // does not (DESIGN-claim-logs.md §3).
        assert_eq!(t.pins(), vec![head]);
        let stranger = TrustedRealm {
            anchors: vec![Thumbprint::from_bytes([9; 32])],
            heads: vec![head],
            ..t.clone()
        };
        assert_eq!(stranger.pins(), Vec::<HeadPin>::new());

        // A partner without heads (an older one) parses to none, and
        // the JSON form of one without heads carries no member.
        let bare = TrustedRealm {
            heads: Vec::new(),
            ..t
        };
        let json = bare.to_json();
        assert!(!json.contains("heads"));
        assert_eq!(TrustedRealm::from_json(json.as_bytes()).unwrap(), bare);

        // validate_for still separates the realms: a head is a fact
        // about an anchor, not a new way to share one.
        assert!(bare.validate_for("EXAMPLE.TEST", &[a]).is_err());
    }

    #[test]
    fn as_partner_carries_the_heads() {
        // The partner form fills heads from the server's published
        // vouches, aligned with its anchors (DESIGN-claim-logs.md §3).
        let t = test_realm("ipa1.example.test");
        let a = *t.anchor.public().thumbprint();
        let signing = SigningKey::generate(SignatureAlg::MlDsa65).unwrap();
        let server = EnrollServer::new(
            ServerKeys {
                signing,
                join: Vec::new(),
                escrow: Vec::new(),
                trust: Vec::new(),
                vouchers: Vec::new(),
                retired: Vec::new(),
            },
            t.info.clone(),
            t.delegation.clone(),
        );
        assert_eq!(server.as_partner().heads, Vec::<HeadPin>::new());
        let vouch = SignedVouch::issue(
            &t.anchor,
            "EXAMPLE.TEST",
            [t.delegation
                .claim()
                .unwrap()
                .leaf(crate::merkle::TreeHash::Sha256)
                .unwrap()],
            now() - 60,
            now() + VOUCH_VALIDITY,
            None,
        )
        .unwrap();
        let mut vouches = std::collections::HashMap::new();
        vouches.insert(a, vouch);
        server.publish(t.delegation.clone(), vec![a], vouches);
        let heads = server.as_partner().heads;
        assert_eq!(heads.len(), 1);
        assert_eq!(heads[0].anchor, a);
        assert_eq!(heads[0].size, 1);
    }
}
