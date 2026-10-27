//! IPA server discovery through DNS SRV records (§4.6): `_ldap._tcp.<domain>`,
//! which FreeIPA publishes for every server.
//!
//! Lookups go through `hickory-resolver` (as in akamu), with the system
//! configuration or, with `KUIPA_DNS`, one given nameserver: plain DNS
//! (`<address:port>`; UDP first, TCP when an answer is truncated), DNS over
//! TLS (`dot://<host>[:853]`, RFC 7858) or DNS over HTTPS
//! (`doh://<host>[:443][/path]`, RFC 8484; the path defaults to
//! `/dns-query`).  A `doh://` or `dot://` host that is a name, not an
//! address, is resolved through the system configuration.  `DoT` and `DoH`
//! server certificates are verified against the system roots, or, with
//! `KUIPA_DNS_CA=<path>`, that file's PEM certificates.  DNS is not
//! trusted for anything but naming candidates: every server must still
//! present an advertisement that verifies against a pinned anchor, and
//! names that are not safe host names are dropped.

use std::net::SocketAddr;
use std::sync::Arc;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use kuipa_enroll::realm::is_safe_name;
use kuipa_enroll::tls::server_verifier;

use crate::paths::Error;

/// One SRV record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Srv {
    /// Lower is preferred.
    pub priority: u16,
    /// Higher is preferred among equal priorities.
    pub weight: u16,
    /// Port.
    pub port: u16,
    /// Target host name, without the trailing dot.
    pub target: String,
}

/// The default `DoT` and `DoH` ports.
const DOT_PORT: u16 = 853;
const DOH_PORT: u16 = 443;

/// The `DoH` query path hickory uses when none is given.
const DOH_PATH: &str = "/dns-query";

/// The nameserver `KUIPA_DNS` names: plain, `DoT` (RFC 7858) or `DoH`
/// (RFC 8484).  See the module documentation.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Nameserver {
    /// Plain DNS: UDP, then TCP on truncation.
    Plain(SocketAddr),
    /// DNS over TLS: the address, and the name the server's certificate
    /// must be valid for.
    Dot { addr: SocketAddr, name: String },
    /// DNS over HTTPS: the address, the TLS server name, and the URI path.
    Doh {
        addr: SocketAddr,
        name: String,
        path: String,
    },
}

/// `host[:port]` with `port` as the default; an IPv6 address in brackets.
fn split_host_port(value: &str, default: u16) -> (String, u16) {
    if let Some(rest) = value.strip_prefix('[')
        && let Some((host, tail)) = rest.split_once(']')
    {
        let port = tail
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default);
        return (host.to_owned(), port);
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => match port.parse() {
            Ok(port) => (host.to_owned(), port),
            Err(_) => (value.to_owned(), default),
        },
        _ => (value.to_owned(), default),
    }
}

impl Nameserver {
    /// Parse a `KUIPA_DNS` value; `resolve` gives the addresses of a
    /// `doh://` or `dot://` host that is a name.
    fn parse(value: &str, resolve: &dyn Fn(&str) -> Option<SocketAddr>) -> Result<Self, Error> {
        let bad = |what: &str| format!("KUIPA_DNS={value:?}: {what}");
        if let Some(rest) = value.strip_prefix("dot://") {
            let (host, port) = split_host_port(rest, DOT_PORT);
            let addr = resolve(&host).ok_or_else(|| bad("not resolvable to an address"))?;
            let addr = SocketAddr::new(addr.ip(), port);
            return Ok(Self::Dot { addr, name: host });
        }
        if let Some(rest) = value.strip_prefix("doh://") {
            let (authority, path) = match rest.split_once('/') {
                Some((authority, path)) => (authority, format!("/{path}")),
                None => (rest, DOH_PATH.to_owned()),
            };
            let (host, port) = split_host_port(authority, DOH_PORT);
            let addr = resolve(&host).ok_or_else(|| bad("not resolvable to an address"))?;
            let addr = SocketAddr::new(addr.ip(), port);
            return Ok(Self::Doh {
                addr,
                name: host,
                path,
            });
        }
        if value.contains("://") {
            return Err(bad("expected dot://, doh:// or a plain address:port").into());
        }
        Ok(Self::Plain(
            value.parse().map_err(|_| bad("is not an address:port"))?,
        ))
    }

    /// The connection configurations to try, in order.
    fn connections(&self) -> Vec<ConnectionConfig> {
        match self {
            Self::Plain(addr) => {
                let mut udp = ConnectionConfig::udp();
                udp.port = addr.port();
                let mut tcp = ConnectionConfig::tcp();
                tcp.port = addr.port();
                vec![udp, tcp]
            }
            Self::Dot { addr, name } => {
                let mut tls = ConnectionConfig::tls(Arc::from(name.as_str()));
                tls.port = addr.port();
                vec![tls]
            }
            Self::Doh { addr, name, path } => {
                let mut https = ConnectionConfig::https(
                    Arc::from(name.as_str()),
                    Some(Arc::from(path.as_str())),
                );
                https.port = addr.port();
                vec![https]
            }
        }
    }
}

/// A resolver for `nameservers`, or the system's.
fn resolver(nameservers: Option<&Nameservers>) -> Result<TokioResolver, Error> {
    let Some(nameservers) = nameservers else {
        return Ok(Resolver::builder_tokio()?.build()?);
    };
    if nameservers.secure() {
        let Nameservers::Secure(list) = nameservers else {
            unreachable!("secure nameservers");
        };
        return tls_resolver(list);
    }
    let servers = nameservers
        .plain()
        .iter()
        .map(|addr| {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            NameServerConfig::new(addr.ip(), false, vec![udp, tcp])
        })
        .collect();
    Ok(fast_fail(Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    )))
}

/// A resolver with `DoT` or `DoH` `nameservers`: certificates verified against
/// `KUIPA_DNS_CA`'s PEM certificates (Merkle Tree CAs included) if set,
/// the system roots otherwise.
fn tls_resolver(nameservers: &[Nameserver]) -> Result<TokioResolver, Error> {
    let servers = nameservers
        .iter()
        .map(|ns| NameServerConfig::new(ns.addr().ip(), false, ns.connections()))
        .collect();
    let mut builder = Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    );
    if std::env::var_os("KUIPA_DNS_CA").is_some() {
        builder = builder.with_tls_config(tls_config()?);
    }
    Ok(fast_fail(builder))
}

/// The nameservers a lookup uses: the system's (`None`), or the one
/// `KUIPA_DNS` names.
#[derive(Debug)]
enum Nameservers {
    /// Plain DNS to one address.
    Plain(Vec<SocketAddr>),
    /// `DoT` or `DoH`.
    Secure(Vec<Nameserver>),
}

impl Nameservers {
    /// Whether any nameserver is `DoT` or `DoH`.
    fn secure(&self) -> bool {
        matches!(self, Self::Secure(_))
    }

    /// The plain nameservers, empty for `DoT`/`DoH`.
    fn plain(&self) -> &[SocketAddr] {
        match self {
            Self::Plain(addrs) => addrs,
            Self::Secure(_) => &[],
        }
    }
}

/// Apply the fast-fail options for a configured nameserver (tests, the
/// playground): one attempt with a short timeout.
fn fast_fail(builder: hickory_resolver::ResolverBuilder<TokioRuntimeProvider>) -> TokioResolver {
    builder
        .with_options({
            let mut opts = hickory_resolver::config::ResolverOpts::default();
            opts.timeout = std::time::Duration::from_secs(2);
            opts.attempts = 1;
            opts
        })
        .build()
        .expect("resolver options")
}

impl Nameserver {
    /// The server's address.
    fn addr(&self) -> SocketAddr {
        match self {
            Self::Plain(addr) | Self::Dot { addr, .. } | Self::Doh { addr, .. } => *addr,
        }
    }
}

/// The TLS configuration for `DoT` and `DoH`: the OpenSSL-backed provider the
/// rest of kuipa installs, verifying against `KUIPA_DNS_CA`'s
/// certificates, Merkle Tree CAs included.
fn tls_config() -> Result<rustls::ClientConfig, Error> {
    let path = std::env::var("KUIPA_DNS_CA").map_err(|_| "KUIPA_DNS_CA is not set".to_string())?;
    let pem = std::fs::read(&path).map_err(|e| format!("KUIPA_DNS_CA={path:?}: {e}"))?;
    let mut cas = Vec::new();
    for der in synta_certificate::pem_to_der(&pem) {
        cas.push(der);
    }
    if cas.is_empty() {
        return Err(format!("KUIPA_DNS_CA={path:?}: no PEM certificates").into());
    }
    let verifier = server_verifier(&cas).map_err(|e| format!("KUIPA_DNS_CA={path:?}: {e}"))?;
    Ok(rustls_native_ossl::client_config_builder()
        .map_err(|e| format!("TLS for DNS: {e}"))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_no_client_auth())
}

/// The nameserver from `KUIPA_DNS`, if set.
fn configured() -> Result<Option<Nameservers>, Error> {
    match std::env::var("KUIPA_DNS") {
        Ok(value) => Ok(Some(matched_nameservers(&value)?)),
        Err(_) => Ok(None),
    }
}

/// `KUIPA_DNS` as [`Nameservers`]: a `doh://` or `dot://` name resolves
/// through the system configuration, but never circularly through itself.
fn matched_nameservers(value: &str) -> Result<Nameservers, Error> {
    if value.starts_with("dot://") || value.starts_with("doh://") {
        let ns = Nameserver::parse(value, &|host| {
            // Resolve a server *name* (not address) through the system
            // resolver only: if the system configuration itself needs the
            // SRV records being looked up, that is the deployment's knot
            // to untangle, not ours.
            std::net::ToSocketAddrs::to_socket_addrs(&(host, 0))
                .ok()?
                .find(|_| true)
        })?;
        return Ok(Nameservers::Secure(vec![ns]));
    }
    if value.contains("://") {
        return Err(format!(
            "KUIPA_DNS={value:?}: expected dot://, doh:// or a plain address:port"
        )
        .into());
    }
    Ok(Nameservers::Plain(vec![value.parse().map_err(|_| {
        format!("KUIPA_DNS={value:?} is not an address:port")
    })?]))
}

/// The SRV records for `name`; an empty list when there are none.
fn lookup(name: &str, nameservers: Option<&Nameservers>) -> Result<Vec<Srv>, Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let resolver = resolver(nameservers)?;
        tracing::debug!("DNS SRV lookup for {name}");
        let lookup = match resolver.srv_lookup(name).await {
            Ok(lookup) => lookup,
            Err(e) if e.is_no_records_found() => return Ok(Vec::new()),
            Err(e) => return Err(format!("DNS lookup for {name}: {e}").into()),
        };
        let records: Vec<Srv> = lookup
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                RData::SRV(srv) => Some(Srv {
                    priority: srv.priority,
                    weight: srv.weight,
                    port: srv.port,
                    target: srv.target.to_utf8().trim_end_matches('.').to_owned(),
                }),
                _ => None,
            })
            .collect();
        tracing::debug!("DNS: {} SRV record(s) for {name}", records.len());
        Ok(records)
    })
}

/// The SRV records for `name`, from `KUIPA_DNS` or the system resolvers.
///
/// # Errors
///
/// A failed lookup.
pub fn srv(name: &str) -> Result<Vec<Srv>, Error> {
    lookup(name, configured()?.as_ref())
}

/// The IPA servers of `domain` from `_ldap._tcp.<domain>`, by priority,
/// then weight (highest first); unsafe names are dropped.
///
/// # Errors
///
/// A failed lookup, or no usable records.
pub fn ipa_servers(domain: &str) -> Result<Vec<String>, Error> {
    servers(domain, configured()?.as_ref())
}

/// [`ipa_servers`], asking `nameservers`.
///
/// # Errors
///
/// A failed lookup, or no usable records.
pub fn ipa_servers_from(domain: &str, nameservers: &[SocketAddr]) -> Result<Vec<String>, Error> {
    servers(domain, Some(&Nameservers::Plain(nameservers.to_vec())))
}

fn servers(domain: &str, nameservers: Option<&Nameservers>) -> Result<Vec<String>, Error> {
    let name = format!("_ldap._tcp.{}.", domain.trim_end_matches('.'));
    let mut records = lookup(&name, nameservers)?;
    records.sort_by(|a, b| (a.priority, b.weight).cmp(&(b.priority, a.weight)));
    let mut servers: Vec<String> = Vec::new();
    for r in records {
        let target = r.target.to_ascii_lowercase();
        if is_safe_name(&target) && !servers.contains(&target) {
            servers.push(target);
        }
    }
    if servers.is_empty() {
        return Err(format!("no IPA servers in DNS ({name} has no usable SRV records)").into());
    }
    Ok(servers)
}

/// The DNS domain of a host name (everything after the first label).
#[must_use]
pub fn domain_of(fqdn: &str) -> Option<&str> {
    fqdn.split_once('.')
        .map(|(_, d)| d)
        .filter(|d| !d.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn domains() {
        assert_eq!(domain_of("web1.example.test"), Some("example.test"));
        assert_eq!(domain_of("web1"), None);
        assert_eq!(domain_of("web1."), None);
    }

    fn resolve_local(host: &str) -> Option<SocketAddr> {
        if host == "dns.example.test" {
            Some(SocketAddr::new(IpAddr::from([127, 0, 0, 1]), 0))
        } else if let Ok(addr) = host.parse::<std::net::IpAddr>() {
            Some(SocketAddr::new(addr, 0))
        } else {
            None
        }
    }

    #[test]
    fn plain_nameserver() {
        let ns = Nameserver::parse("192.0.2.1:53", &|_| None).unwrap();
        assert_eq!(ns, Nameserver::Plain("192.0.2.1:53".parse().unwrap()));
        assert!(Nameserver::parse("192.0.2.1", &|_| None).is_err());
    }

    #[test]
    fn dot_nameserver() {
        let ns = Nameserver::parse("dot://dns.example.test", &resolve_local).unwrap();
        assert_eq!(
            ns,
            Nameserver::Dot {
                addr: "127.0.0.1:853".parse().unwrap(),
                name: "dns.example.test".to_owned()
            }
        );
        let ns = Nameserver::parse("dot://[2001:db8::1]:853", &resolve_local).unwrap();
        assert_eq!(
            ns,
            Nameserver::Dot {
                addr: SocketAddr::new(
                    IpAddr::from([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]),
                    853
                ),
                name: "2001:db8::1".to_owned()
            }
        );
        assert!(Nameserver::parse("dot://nowhere.test", &resolve_local).is_err());
    }

    #[test]
    fn doh_nameserver() {
        let ns = Nameserver::parse("doh://dns.example.test", &resolve_local).unwrap();
        assert_eq!(
            ns,
            Nameserver::Doh {
                addr: "127.0.0.1:443".parse().unwrap(),
                name: "dns.example.test".to_owned(),
                path: DOH_PATH.to_owned()
            }
        );
        let ns = Nameserver::parse("doh://dns.example.test:8443/resolve", &resolve_local).unwrap();
        assert_eq!(
            ns,
            Nameserver::Doh {
                addr: "127.0.0.1:8443".parse().unwrap(),
                name: "dns.example.test".to_owned(),
                path: "/resolve".to_owned()
            }
        );
    }

    #[test]
    fn unknown_scheme_rejected() {
        assert!(Nameserver::parse("https://dns.example.test", &resolve_local).is_err());
        assert!(Nameserver::parse("quic://dns.example.test", &resolve_local).is_err());
    }

    #[test]
    fn host_port_splitting() {
        assert_eq!(split_host_port("host", 53), ("host".to_owned(), 53));
        assert_eq!(split_host_port("host:5353", 53), ("host".to_owned(), 5353));
        assert_eq!(
            split_host_port("[2001:db8::1]", 853),
            ("2001:db8::1".to_owned(), 853)
        );
        assert_eq!(
            split_host_port("[2001:db8::1]:5353", 853),
            ("2001:db8::1".to_owned(), 5353)
        );
        // A bare IPv6 address (no brackets) reads as a host.
        assert_eq!(
            split_host_port("2001:db8::1", 853),
            ("2001:db8::1".to_owned(), 853)
        );
    }
}
