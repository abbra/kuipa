//! Daemon configuration (`/etc/ipa/kuipad.json`).

use std::collections::BTreeMap;
use std::path::PathBuf;

use kuipa_enroll::keytab::Enctype;
use kuipa_enroll::realm::{RealmInfo, TrustedRealm};
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
    /// Allowed enctypes, strongest first.
    #[serde(default = "default_enctypes")]
    pub enctypes: Vec<i32>,
    /// Listen address when not socket-activated (`unix:/path` or `host:port`).
    #[serde(default = "default_listen")]
    pub listen: String,
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
            trusts: self
                .trusts
                .iter()
                .map(|t| {
                    Ok(TrustedRealm {
                        realm: t.realm.clone(),
                        domain: t.domain.clone(),
                        servers: t.servers.clone(),
                        anchors: t
                            .anchors
                            .iter()
                            .map(|a| a.parse())
                            .collect::<Result<_, _>>()?,
                    })
                })
                .collect::<Result<_, Error>>()?,
        };
        info.validate()?;
        Ok(info)
    }

    /// The configured trusted realms.
    ///
    /// # Errors
    ///
    /// A malformed anchor.
    pub fn trusted_realms(&self) -> Result<Vec<TrustedRealm>, Error> {
        self.trusts
            .iter()
            .map(|t| {
                Ok(TrustedRealm {
                    realm: t.realm.clone(),
                    domain: t.domain.clone(),
                    servers: t.servers.clone(),
                    anchors: t
                        .anchors
                        .iter()
                        .map(|a| a.parse())
                        .collect::<Result<_, _>>()?,
                })
            })
            .collect()
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
