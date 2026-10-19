//! IPA server discovery through DNS SRV records (§4.6): `_ldap._tcp.<domain>`,
//! which FreeIPA publishes for every server.
//!
//! Lookups go through `hickory-resolver` (as in akamu), with the system
//! configuration or, with `KUIPA_DNS=<address:port>`, one given
//! nameserver; UDP first, TCP when an answer is truncated.  DNS is not
//! trusted for anything but naming candidates: every server must still
//! present an advertisement that verifies against a pinned anchor, and
//! names that are not safe host names are dropped.

use std::net::SocketAddr;

use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolverConfig, ResolverOpts};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::proto::rr::RData;
use hickory_resolver::{Resolver, TokioResolver};
use kuipa_enroll::realm::is_safe_name;

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

/// A resolver for `nameservers` (UDP and TCP), or the system's.
fn resolver(nameservers: Option<&[SocketAddr]>) -> Result<TokioResolver, Error> {
    let Some(nameservers) = nameservers else {
        return Ok(Resolver::builder_tokio()?.build()?);
    };
    let servers = nameservers
        .iter()
        .map(|addr| {
            let mut udp = ConnectionConfig::udp();
            udp.port = addr.port();
            let mut tcp = ConnectionConfig::tcp();
            tcp.port = addr.port();
            NameServerConfig::new(addr.ip(), false, vec![udp, tcp])
        })
        .collect();
    Ok(Resolver::builder_with_config(
        ResolverConfig::from_name_servers(servers),
        TokioRuntimeProvider::default(),
    )
    .with_options({
        // One given nameserver (tests, the playground): fail fast.
        let mut opts = ResolverOpts::default();
        opts.timeout = std::time::Duration::from_secs(2);
        opts.attempts = 1;
        opts
    })
    .build()?)
}

/// The nameserver from `KUIPA_DNS`, if set.
fn configured() -> Result<Option<Vec<SocketAddr>>, Error> {
    match std::env::var("KUIPA_DNS") {
        Ok(addr) => {
            Ok(Some(vec![addr.parse().map_err(|_| {
                format!("KUIPA_DNS={addr:?} is not an address:port")
            })?]))
        }
        Err(_) => Ok(None),
    }
}

/// The SRV records for `name`; an empty list when there are none.
fn lookup(name: &str, nameservers: Option<&[SocketAddr]>) -> Result<Vec<Srv>, Error> {
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
    lookup(name, configured()?.as_deref())
}

/// The IPA servers of `domain` from `_ldap._tcp.<domain>`, by priority,
/// then weight (highest first); unsafe names are dropped.
///
/// # Errors
///
/// A failed lookup, or no usable records.
pub fn ipa_servers(domain: &str) -> Result<Vec<String>, Error> {
    servers(domain, configured()?.as_deref())
}

/// [`ipa_servers`], asking `nameservers`.
///
/// # Errors
///
/// A failed lookup, or no usable records.
pub fn ipa_servers_from(domain: &str, nameservers: &[SocketAddr]) -> Result<Vec<String>, Error> {
    servers(domain, Some(nameservers))
}

fn servers(domain: &str, nameservers: Option<&[SocketAddr]>) -> Result<Vec<String>, Error> {
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

    #[test]
    fn domains() {
        assert_eq!(domain_of("web1.example.test"), Some("example.test"));
        assert_eq!(domain_of("web1"), None);
        assert_eq!(domain_of("web1."), None);
    }
}
