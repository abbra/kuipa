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

use crate::delegation::{Delegation, VerifiedDelegation};
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
    /// The IPA CA chain (DER).
    pub ca_certs: Vec<Vec<u8>>,
    /// The PKINIT trust anchors (DER) clients need for anonymous PKINIT.
    pub pkinit_anchors: Vec<Vec<u8>>,
    /// Current realm anchors.
    pub anchors: Vec<Thumbprint>,
    /// Realms this realm trusts, with the anchors it vouches for (§17).
    pub trusts: Vec<TrustedRealm>,
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
        {
            return Err(Error::Malformed("trusted realm"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
struct TrustJson {
    realm: String,
    domain: String,
    servers: Vec<String>,
    anchors: Vec<String>,
}

impl From<&TrustedRealm> for TrustJson {
    fn from(t: &TrustedRealm) -> Self {
        Self {
            realm: t.realm.clone(),
            domain: t.domain.clone(),
            servers: t.servers.clone(),
            anchors: t.anchors.iter().map(ToString::to_string).collect(),
        }
    }
}

impl TrustJson {
    fn parse(self) -> Option<TrustedRealm> {
        Some(TrustedRealm {
            anchors: parse_anchors(&self.anchors)?,
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
    trusts: Vec<TrustJson>,
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
            trusts: self.trusts.iter().map(TrustJson::from).collect(),
        })
        .expect("serialisable")
    }

    /// Check the names and trusted realms: every name must be safe for
    /// generated configuration ([`is_safe_name`]), and every trusted realm
    /// clearly separate — not this realm, not listed twice, with servers,
    /// and with anchors of its own, none of them this realm's.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn validate(&self) -> Result<()> {
        let names = [&self.realm, &self.domain, &self.server]
            .into_iter()
            .chain(&self.servers);
        if !names.into_iter().all(|n| is_safe_name(n)) {
            return Err(Error::Malformed("realm info names"));
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
        let info = Self {
            ca_certs: decode_all(&j.ca_certs).ok_or_else(malformed)?,
            pkinit_anchors: decode_all(&j.pkinit_anchors).ok_or_else(malformed)?,
            anchors: parse_anchors(&j.anchors).ok_or_else(malformed)?,
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
        epoch: Option<(u64, [u8; 32])>,
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
    adv: Advertisement,
    epoch: Option<(u64, [u8; 32])>,
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
        let delegation = Delegation::from_value(
            adv.unverified_member(MEMBER_DELEGATION)?
                .ok_or(Error::Missing("delegation"))?,
        )?
        .verify_at(anchors, policy, unix_seconds(now))?;
        if delegation.realm != realm {
            return Err(Error::WrongRealm);
        }
        let adv = adv.verify_at(&delegation.key, policy, now)?;
        let info =
            RealmInfo::from_value(adv.member(MEMBER_IPA).ok_or(Error::Missing("realm info"))?)?;
        if info.realm != delegation.realm || info.server != delegation.server {
            return Err(Error::Mismatch("server identity"));
        }
        // The epoch head is advisory here: an older server names none,
        // and a mismatch with what the client stored is the flow's
        // discovery, not a reason to reject this advertisement.
        let epoch = adv.member(MEMBER_EPOCH).and_then(|v| {
            let seq = v.get("seq")?.as_u64()?;
            let head = b64::decode(v.get("head")?.as_str()?).ok()?;
            <[u8; 32]>::try_from(head.as_slice())
                .ok()
                .filter(|_| seq > 0)
                .map(|h| (seq, h))
        });
        Ok(Self {
            info,
            delegation,
            adv,
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

    /// When the accepted anchor's vouch expires (Unix seconds).
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
    pub fn epoch(&self) -> Option<(u64, [u8; 32])> {
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
    let mut lines = vec!["[realms]".to_owned(), format!("    {realm} = {{")];
    lines.extend(unique.iter().map(|k| format!("        kdc = {k}:88")));
    if let Some(primary) = unique.first() {
        lines.push(format!("        master_kdc = {primary}:88"));
    }
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
        let ca = b"not really a certificate".to_vec();
        let info = RealmInfo {
            realm: "EXAMPLE.TEST".into(),
            domain: "example.test".into(),
            basedn: "dc=example,dc=test".into(),
            server: server.into(),
            servers: vec![server.into()],
            ca_certs: vec![ca.clone()],
            pkinit_anchors: vec![b"pkinit anchor".to_vec()],
            anchors: vec![*anchor.public().thumbprint()],
            trusts: Vec::new(),
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
        assert_eq!(v.info().pkinit_anchors, vec![b"pkinit anchor".to_vec()]);

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
}
