//! Daemon configuration (`/etc/ipa/kuipad.json`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::realm::{KdcProxy, ProxyCa, RealmInfo, TrustedRealm};
use serde::Deserialize;
use tang_pqc::Thumbprint;

use crate::directory;

/// Default configuration path.
pub const DEFAULT_PATH: &str = "/etc/ipa/kuipad.json";

/// The configuration file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Kerberos realm.
    pub realm: String,
    /// DNS domain.
    pub domain: String,
    /// LDAP base DN.
    pub basedn: String,
    /// This server's FQDN.
    pub server: String,
    /// LDAPI URI.
    pub ldap_uri: String,
    /// The daemon's principal.
    pub principal: String,
    /// The daemon's GSS-API service name (`ipa-ku@<fqdn>`).
    pub service: String,
    /// The daemon's keytab.
    pub keytab: String,
    /// PEM file with the IPA CA chain.
    pub ca_file: String,
    /// PEM file with the PKINIT trust anchors clients need (§4.3).
    #[serde(default = "default_pkinit_anchors_file")]
    pub pkinit_anchors_file: String,
    /// Key directory.
    #[serde(default = "default_key_dir")]
    pub key_dir: PathBuf,
    /// Peers to exchange anchors with (FQDNs), in addition to the IPA
    /// servers found in LDAP (§4.2).
    #[serde(default)]
    pub peers: Vec<String>,
    /// Find peers among the IPA servers in LDAP (`cn=masters`).
    #[serde(default = "default_true")]
    pub discover_peers: bool,
    /// Base URLs of peers by FQDN, instead of `https://<fqdn>`.
    #[serde(default)]
    pub peer_endpoints: BTreeMap<String, String>,
    /// Seconds between anchor exchange rounds.
    #[serde(default = "default_peer_interval")]
    pub peer_interval: u64,
    /// Whether this server holds an anchor and vouches for claims (§4.2);
    /// a realm needs at least one anchor server.
    #[serde(default = "default_true")]
    pub anchor: bool,
    /// Least seconds between vouches that only add claims.
    #[serde(default = "default_peer_interval")]
    pub vouch_interval: u64,
    /// Rate limits (§5.1).
    #[serde(default)]
    pub rate_limit: crate::limit::Limits,
    /// Trusted realms to advertise, with their anchors (§17).
    #[serde(default)]
    pub trusts: Vec<TrustConfig>,
    /// This realm's KDC proxies, advertised for realms that trust it,
    /// when its KDCs are not reachable from their hosts.
    #[serde(default)]
    pub kdc_proxy: Option<KdcProxyConfig>,
    /// Allowed enctypes, strongest first.
    #[serde(default = "default_enctypes")]
    pub enctypes: Vec<i32>,
    /// Listen address when not socket-activated (`unix:/path` or `host:port`).
    #[serde(default = "default_listen")]
    pub listen: String,
    /// The `keys` operation's handlers (§18.5); absent disables it.
    #[serde(default)]
    pub keys: Option<KeysConfig>,
    /// Seconds between published transparency-log heads
    /// (`DESIGN-tlog.md` §5): a head covers what was logged before its
    /// period began, so watching it grow tells how many events a period
    /// had, not when each happened.  Zero publishes every event at once.
    #[serde(default = "default_tlog_head_interval")]
    pub tlog_head_interval: u64,
    /// Months of transparency-log openings kept (`DESIGN-tlog.md` §5):
    /// older events can no longer be looked up or said to be about anyone.
    #[serde(default = "default_tlog_retention_months")]
    pub tlog_retention_months: u32,
}

fn default_tlog_head_interval() -> u64 {
    crate::ledger::HEAD_INTERVAL.as_secs()
}

fn default_tlog_retention_months() -> u32 {
    crate::ledger::RETENTION_MONTHS
}

fn default_key_dir() -> PathBuf {
    "/var/lib/ipa/ku".into()
}

fn default_pkinit_anchors_file() -> String {
    "/var/lib/ipa-client/pki/kdc-ca-bundle.pem".into()
}

fn default_enctypes() -> Vec<i32> {
    Enctype::DEFAULT.iter().map(|e| e.0).collect()
}

/// One trusted realm.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustConfig {
    /// Its Kerberos realm.
    pub realm: String,
    /// Its DNS domain.
    pub domain: String,
    /// Servers to fetch its advertisement from.
    pub servers: Vec<String>,
    /// Its anchors (base64url thumbprints), from its trust invitation.
    pub anchors: Vec<String>,
    /// The KDC proxies this realm's hosts use for it; absent, its KDCs
    /// are reached directly (or through the proxies it advertises).
    #[serde(default)]
    pub kdc_proxy: Option<KdcProxyConfig>,
}

impl TrustConfig {
    /// As advertised, with no heads: configuration cannot know the
    /// partner's; the trust refresh fills them from its advertisement
    /// (DESIGN-claim-logs.md §3).
    fn trusted_realm(&self) -> Result<TrustedRealm, Error> {
        Ok(TrustedRealm {
            realm: self.realm.clone(),
            domain: self.domain.clone(),
            servers: self.servers.clone(),
            anchors: self
                .anchors
                .iter()
                .map(|a| a.parse())
                .collect::<Result<_, _>>()?,
            heads: Vec::new(),
            kdc_proxy: self
                .kdc_proxy
                .as_ref()
                .map(KdcProxyConfig::to_proxy)
                .transpose()?,
        })
    }
}

/// A realm's KDC proxies (MS-KKDCP, FreeIPA's `/KdcProxy`).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdcProxyConfig {
    /// The proxy URLs, `https://<host>[:<port>][/<path>]`.
    pub urls: Vec<String>,
    /// What authenticates their TLS certificates: `"realm"` (default),
    /// the realm's IPA CA, or `"system"`, the system trust store.
    #[serde(default)]
    pub ca: Option<String>,
}

impl KdcProxyConfig {
    fn to_proxy(&self) -> Result<KdcProxy, Error> {
        let proxy = KdcProxy {
            urls: self.urls.clone(),
            ca: self.ca.as_deref().map_or(Ok(ProxyCa::Realm), str::parse)?,
        };
        proxy.validate()?;
        Ok(proxy)
    }
}

/// The `keys` operation's configuration (§18.5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeysConfig {
    /// Whether the operation is served; default true when the section is
    /// present.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// A handler per namespace, keyed by its label (`dm`, `ra`, `ca`,
    /// `ca_wrapped`, `lwca-store`).
    pub handlers: BTreeMap<String, HandlerConfig>,
}

/// One namespace's handler.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandlerConfig {
    /// The executable.
    pub command: String,
    /// The user to run it as (`root`, `pkiuser`); absent keeps the
    /// daemon's own user.
    #[serde(default)]
    pub runas: Option<String>,
}

fn default_true() -> bool {
    true
}

fn default_peer_interval() -> u64 {
    60
}

fn default_listen() -> String {
    "unix:/run/ipa/kuipad.sock".into()
}

/// Errors loading the configuration.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

impl Config {
    /// Read and parse.
    ///
    /// # Errors
    ///
    /// I/O or parse errors.
    pub fn load(path: &str) -> Result<Self, Error> {
        Ok(serde_json::from_slice(&std::fs::read(path)?)?)
    }

    /// The `keys` operation's handler table (§18.5), or `None` when the
    /// section is absent or disabled.
    ///
    /// # Errors
    ///
    /// A namespace label that is not one of §18.1's.
    pub fn keys_service(&self) -> Result<Option<Arc<crate::keys::Keys>>, Error> {
        let Some(cfg) = &self.keys else {
            return Ok(None);
        };
        if !cfg.enabled {
            return Ok(None);
        }
        let mut handlers = Vec::new();
        for (label, handler) in &cfg.handlers {
            let namespace = match label.as_str() {
                "dm" => kuipa_enroll::keys::Namespace::Dm,
                "ra" => kuipa_enroll::keys::Namespace::Ra,
                "ca" => kuipa_enroll::keys::Namespace::Ca,
                "ca_wrapped" => kuipa_enroll::keys::Namespace::CaWrapped,
                "lwca-store" => kuipa_enroll::keys::Namespace::LwcaStore,
                _ => return Err(format!("unknown keys namespace: {label}").into()),
            };
            handlers.push((
                namespace,
                crate::keys::Handler {
                    command: handler.command.clone().into(),
                    runas: handler.runas.clone(),
                },
            ));
        }
        Ok(Some(Arc::new(crate::keys::Keys::new(handlers))))
    }

    /// The realm metadata this server publishes, listing `servers` and,
    /// until the anchor exchange has run, only this server's own `anchor`
    /// (none without the anchor role).
    ///
    /// # Errors
    ///
    /// Unreadable or empty certificate files, or a malformed trusted
    /// realm.
    pub fn realm_info(
        &self,
        servers: Vec<String>,
        anchor: Option<Thumbprint>,
    ) -> Result<RealmInfo, Error> {
        let read = |path: &str| -> Result<Vec<Vec<u8>>, Error> {
            let certs = synta_certificate::pem_to_der(&std::fs::read(path)?);
            if certs.is_empty() {
                return Err(format!("no certificates in {path}").into());
            }
            Ok(certs)
        };
        let info = RealmInfo {
            realm: self.realm.clone(),
            domain: self.domain.clone(),
            basedn: self.basedn.clone(),
            server: self.server.clone(),
            servers,
            ca_certs: read(&self.ca_file)?,
            pkinit_anchors: read(&self.pkinit_anchors_file)?,
            anchors: anchor.into_iter().collect(),
            heads: Vec::new(),
            trusts: self
                .trusts
                .iter()
                .map(TrustConfig::trusted_realm)
                .collect::<Result<_, Error>>()?,
            kdc_proxy: self
                .kdc_proxy
                .as_ref()
                .map(KdcProxyConfig::to_proxy)
                .transpose()?,
        };
        info.validate()?;
        Ok(info)
    }

    /// The configured trusted realms.
    ///
    /// # Errors
    ///
    /// A malformed anchor or KDC proxy.
    pub fn trusted_realms(&self) -> Result<Vec<TrustedRealm>, Error> {
        self.trusts.iter().map(TrustConfig::trusted_realm).collect()
    }

    /// The directory side of the configuration.
    #[must_use]
    pub fn directory(&self) -> directory::Config {
        directory::Config {
            ldap_uri: self.ldap_uri.clone(),
            basedn: self.basedn.clone(),
            realm: self.realm.clone(),
            principal: self.principal.clone(),
            service: self.service.clone(),
            keytab: self.keytab.clone(),
            ca_file: self.ca_file.clone(),
            enctypes: self.enctypes.iter().copied().map(Enctype).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn trust(kdc_proxy: &str) -> Result<TrustedRealm, Error> {
        let anchor = Thumbprint::from_bytes([7; 32]);
        let json = format!(
            r#"{{"realm": "B.TEST", "domain": "b.test", "servers": ["ipa1.b.test"],
                "anchors": ["{anchor}"]{kdc_proxy}}}"#
        );
        serde_json::from_str::<TrustConfig>(&json)?.trusted_realm()
    }

    #[test]
    fn trusted_realm_kdc_proxies() {
        assert_eq!(trust("").unwrap().kdc_proxy, None);
        let t = trust(r#", "kdc_proxy": {"urls": ["https://ipa1.b.test/KdcProxy"]}"#).unwrap();
        assert_eq!(
            t.kdc_proxy,
            Some(KdcProxy {
                urls: vec!["https://ipa1.b.test/KdcProxy".into()],
                ca: ProxyCa::Realm,
            })
        );
        let t = trust(r#", "kdc_proxy": {"urls": ["https://id.b.test/KdcProxy"], "ca": "system"}"#)
            .unwrap();
        assert_eq!(t.kdc_proxy.unwrap().ca, ProxyCa::System);
        for bad in [
            r#", "kdc_proxy": {"urls": ["https://id.b.test/KdcProxy"], "ca": "public"}"#,
            r#", "kdc_proxy": {"urls": ["http://id.b.test/KdcProxy"]}"#,
            r#", "kdc_proxy": {"urls": []}"#,
            r#", "kdc_proxy": {"url": "https://id.b.test/KdcProxy"}"#,
        ] {
            assert!(trust(bad).is_err(), "{bad}");
        }
    }
}
