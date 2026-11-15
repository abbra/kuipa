//! The `keys` operation (§18): a Kerberos-authenticated fetch of a named
//! secret from a server, the transport that replaces FreeIPA's Custodia.
//!
//! The operation data is `IPKG` and the answer `IPKR` (§14):
//!
//! ```text
//! IPKG  namespace(1) nickname alg_arg(1)
//! IPKR  value
//! ```
//!
//! The namespace is one of the four Custodia namespaces (`dm`, `ra`, `ca`,
//! `ca_wrapped`) or the sealed lightweight-CA artifact store
//! (`lwca-store`, §18.3); the nickname is opaque bytes with a length
//! bound, and `alg_arg` names a wrap algorithm for `ca_wrapped` only.
//! The value is the handler's output, verbatim.

use crate::error::{Error, Result};
use crate::keytab::Principal;
use tang_pqc::wire::{Reader, Writer};

const FETCH_MAGIC: [u8; 4] = *b"IPKG";
const ANSWER_MAGIC: [u8; 4] = *b"IPKR";

/// Largest nickname accepted (§18.2: a bounded, opaque string).
pub(crate) const MAX_NICKNAME: usize = 255;

/// Largest value a handler may answer with (§11.3's body limit bounds the
/// sealed form; this bounds the plaintext the daemon will hold).
pub const MAX_VALUE: usize = 512 * 1024;

/// The namespaces a `keys` fetch can name (§18.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Namespace {
    /// `dm/DMHash`: the Directory Manager password hash.
    Dm = 1,
    /// `ra/ipaCert`: the RA agent key and certificate (PKCS#12).
    Ra,
    /// `ca/<nickname>`: a CA or KRA subsystem key and certificate
    /// (PKCS#12).
    Ca,
    /// `ca_wrapped/<nickname>`: a lightweight-CA key wrapped by the CA
    /// signing key (`PKIArchiveOptions`).
    CaWrapped,
    /// The sealed lightweight-CA artifact store (§18.3).
    LwcaStore,
    /// `akamu/<name>`: the Akamu RA agent key and certificate (PEM), one
    /// secret, fetched like `ra` by a replica that is becoming a CA server.
    Akamu,
}

impl Namespace {
    /// Every namespace, in wire-id order.
    pub const ALL: [Self; 6] = [
        Self::Dm,
        Self::Ra,
        Self::Ca,
        Self::CaWrapped,
        Self::LwcaStore,
        Self::Akamu,
    ];

    /// Its wire id (§14).
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// From its wire id.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for any other value.
    pub fn from_id(id: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|n| n.id() == id)
            .ok_or(Error::Malformed("namespace"))
    }

    /// Its name, as FreeIPA's key names use it (`dm/DMHash` and so on).
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Dm => "dm",
            Self::Ra => "ra",
            Self::Ca => "ca",
            Self::CaWrapped => "ca_wrapped",
            Self::LwcaStore => "lwca-store",
            Self::Akamu => "akamu",
        }
    }
}

impl std::fmt::Display for Namespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.label())
    }
}

impl std::str::FromStr for Namespace {
    type Err = Error;

    /// By [`label`](Namespace::label); `lwca` also names the lightweight-CA
    /// store.
    fn from_str(s: &str) -> Result<Self> {
        if s == "lwca" {
            return Ok(Self::LwcaStore);
        }
        Self::ALL
            .into_iter()
            .find(|n| n.label() == s)
            .ok_or(Error::Malformed("namespace"))
    }
}

/// The wrap algorithm a `ca_wrapped` fetch asks for (§18.3): an
/// allowlist, not a pass-through of Dogtag's OIDs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum WrapAlg {
    /// AES-256-CBC with PKCS#11 padding (`2.16.840.1.101.3.4.1.42`).
    Aes256CbcPad = 1,
    /// AES-256 key wrap (`2.16.840.1.101.3.4.1.45`), where Dogtag
    /// supports it.
    Aes256Wrap,
}

impl WrapAlg {
    /// Every algorithm, in wire-selector order.
    pub const ALL: [Self; 2] = [Self::Aes256CbcPad, Self::Aes256Wrap];

    /// Its wire selector (§14).
    #[must_use]
    pub const fn id(self) -> u8 {
        self as u8
    }

    /// From its wire selector.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for any other value.
    pub fn from_id(id: u8) -> Result<Self> {
        Self::ALL
            .into_iter()
            .find(|a| a.id() == id)
            .ok_or(Error::Malformed("wrap algorithm"))
    }

    /// The OID Dogtag's `pki ca-authority-key-export --algorithm` takes.
    #[must_use]
    pub const fn oid(self) -> &'static str {
        match self {
            Self::Aes256CbcPad => "2.16.840.1.101.3.4.1.42",
            Self::Aes256Wrap => "2.16.840.1.101.3.4.1.45",
        }
    }

    /// The algorithm a caller may spell in `kuipa keys fetch`, if any.
    #[must_use]
    pub fn from_label(label: &str) -> Option<Self> {
        match label {
            "aes-256-cbc-pad" => Some(Self::Aes256CbcPad),
            "aes-256-wrap" => Some(Self::Aes256Wrap),
            _ => None,
        }
    }
}

/// `IPKG`: a fetch of one named secret (§18.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysFetch {
    /// The namespace.
    pub namespace: Namespace,
    /// The nickname inside it (empty where the namespace has one secret).
    pub nickname: String,
    /// The wrap algorithm, for `ca_wrapped` only.
    pub alg: Option<WrapAlg>,
}

impl KeysFetch {
    /// Encode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a nickname over [`MAX_NICKNAME`] bytes, or
    /// a wrap algorithm outside `ca_wrapped`.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.nickname.len() > MAX_NICKNAME {
            return Err(Error::Malformed("nickname"));
        }
        let alg = self.alg.map_or(0, WrapAlg::id);
        if self.alg.is_some() && self.namespace != Namespace::CaWrapped {
            return Err(Error::Malformed("wrap algorithm outside ca_wrapped"));
        }
        Ok(Writer::new(FETCH_MAGIC)
            .u8(self.namespace.id())
            .str(&self.nickname)
            .u8(alg)
            .finish())
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, FETCH_MAGIC, "keys fetch")?;
        let namespace = Namespace::from_id(r.u8()?)?;
        let nickname = r.str()?.to_owned();
        if nickname.len() > MAX_NICKNAME {
            return Err(Error::Malformed("nickname"));
        }
        let alg = r.u8()?;
        r.finish()?;
        let alg = if alg == 0 {
            None
        } else {
            Some(WrapAlg::from_id(alg)?)
        };
        if alg.is_some() && namespace != Namespace::CaWrapped {
            return Err(Error::Malformed("wrap algorithm outside ca_wrapped"));
        }
        Ok(Self {
            namespace,
            nickname,
            alg,
        })
    }
}

/// `IPKR`: the fetch's answer, the handler's value verbatim (§18.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysAnswer {
    /// The value.
    pub value: Vec<u8>,
}

impl KeysAnswer {
    /// Encode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a value over [`MAX_VALUE`].
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        if self.value.len() > MAX_VALUE {
            return Err(Error::Malformed("value"));
        }
        Ok(Writer::new(ANSWER_MAGIC).bytes(&self.value).finish())
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, ANSWER_MAGIC, "keys answer")?;
        let value = r.bytes()?.to_vec();
        if value.len() > MAX_VALUE {
            return Err(Error::Malformed("value"));
        }
        r.finish()?;
        Ok(Self { value })
    }
}

/// Which principals may fetch which namespace, checked by the server
/// before any handler runs (§18.2).  A host must be in the server list
/// (`cn=masters`); `dogtag/<fqdn>` must be a CA server's service.
///
/// The check returns the refusal reason for the daemon's log; the client
/// only ever sees an empty `403`, as for every other refusal.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysPolicy {
    /// The realms' server FQDNs allowed to fetch as `host/<fqdn>`
    /// (the `cn=masters` list).
    pub servers: Vec<String>,
    /// The FQDNs allowed to fetch as `dogtag/<fqdn>` (the servers with
    /// the CA role).
    pub ca_servers: Vec<String>,
}

impl KeysPolicy {
    /// May `principal` fetch `namespace`?
    #[must_use]
    pub fn check(&self, principal: &Principal, namespace: Namespace) -> Option<String> {
        let parts = principal.components();
        let (service, fqdn) = match parts {
            [service, fqdn] => (service.as_str(), fqdn.as_str()),
            _ => return Some("not a host or server principal".into()),
        };
        let in_masters = self.servers.iter().any(|s| s.eq_ignore_ascii_case(fqdn));
        let is_ca = self.ca_servers.iter().any(|s| s.eq_ignore_ascii_case(fqdn));
        match (service, namespace) {
            ("host", Namespace::Dm | Namespace::Ra | Namespace::Ca | Namespace::Akamu)
                if in_masters =>
            {
                None
            }
            ("host", Namespace::CaWrapped | Namespace::LwcaStore) if in_masters && is_ca => None,
            ("dogtag", Namespace::CaWrapped | Namespace::LwcaStore) if is_ca => None,
            ("dogtag", _) => Some(format!("dogtag/ may not fetch {}", namespace.label())),
            ("host", _) if !in_masters => Some(format!("{fqdn} is not in the server list")),
            ("host", Namespace::CaWrapped | Namespace::LwcaStore) => {
                Some(format!("{fqdn} is not a CA server"))
            }
            _ => Some("principal may not fetch".into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn namespaces_round_trip_by_id_and_name() {
        for n in Namespace::ALL {
            assert_eq!(Namespace::from_id(n.id()).unwrap(), n);
            assert_eq!(n.to_string().parse::<Namespace>().unwrap(), n);
        }
        assert_eq!(Namespace::Dm.id(), 1);
        assert_eq!(Namespace::Akamu.id(), 6);
        assert_eq!("lwca".parse::<Namespace>().unwrap(), Namespace::LwcaStore);
        assert!("nope".parse::<Namespace>().is_err());
        assert!(Namespace::from_id(0).is_err() && Namespace::from_id(7).is_err());
        for a in WrapAlg::ALL {
            assert_eq!(WrapAlg::from_id(a.id()).unwrap(), a);
        }
        assert_eq!(WrapAlg::Aes256Wrap.id(), 2);
    }
}
