//! Kerberos principals, host keys and the MIT keytab file format (version
//! 0x0502, as written by `ipa-getkeytab` and read by libkrb5).

use std::fmt;
use std::str::FromStr;

use native_ossl::util::SecretBuf;

use crate::error::{Error, Result};

/// A Kerberos principal name: components and realm.
///
/// Parsed from and displayed as `comp/comp@REALM`.  Escaped characters are
/// not supported; FreeIPA host and service principals never need them.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Principal {
    components: Vec<String>,
    realm: String,
}

impl Principal {
    /// `host/<fqdn>@<realm>`.
    #[must_use]
    pub fn host(fqdn: &str, realm: &str) -> Self {
        Self {
            components: vec!["host".into(), fqdn.into()],
            realm: realm.into(),
        }
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The name components.
    #[must_use]
    pub fn components(&self) -> &[String] {
        &self.components
    }

    /// `KRB5_NT_SRV_HST` (3) for two-component service names, otherwise
    /// `KRB5_NT_PRINCIPAL` (1).
    fn name_type(&self) -> u32 {
        if self.components.len() == 2 { 3 } else { 1 }
    }
}

impl FromStr for Principal {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let malformed = || Error::Malformed("principal");
        if s.contains('\\') {
            return Err(malformed());
        }
        let (name, realm) = s.rsplit_once('@').ok_or_else(malformed)?;
        let components: Vec<String> = name.split('/').map(str::to_owned).collect();
        if realm.is_empty() || components.iter().any(String::is_empty) {
            return Err(malformed());
        }
        Ok(Self {
            components,
            realm: realm.into(),
        })
    }
}

impl fmt::Display for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.components.join("/"), self.realm)
    }
}

impl fmt::Debug for Principal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Principal({self})")
    }
}

/// A Kerberos encryption type number (RFC 3961 registry).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Enctype(pub i32);

impl Enctype {
    /// `aes128-cts-hmac-sha1-96`.
    pub const AES128_CTS_HMAC_SHA1_96: Self = Self(17);
    /// `aes256-cts-hmac-sha1-96`.
    pub const AES256_CTS_HMAC_SHA1_96: Self = Self(18);
    /// `aes128-cts-hmac-sha256-128` (RFC 8009).
    pub const AES128_CTS_HMAC_SHA256_128: Self = Self(19);
    /// `aes256-cts-hmac-sha384-192` (RFC 8009).
    pub const AES256_CTS_HMAC_SHA384_192: Self = Self(20);

    /// What clients propose by default: the AES enctypes, strongest first.
    pub const DEFAULT: [Self; 4] = [
        Self::AES256_CTS_HMAC_SHA384_192,
        Self::AES128_CTS_HMAC_SHA256_128,
        Self::AES256_CTS_HMAC_SHA1_96,
        Self::AES128_CTS_HMAC_SHA1_96,
    ];
}

/// One long-term key of a principal.
pub struct KeytabEntry {
    /// Key version number.
    pub kvno: u32,
    /// Encryption type.
    pub enctype: Enctype,
    /// Key bytes, wiped on drop.
    pub key: SecretBuf,
    /// When the key was written (Unix seconds, as in MIT keytabs).
    pub timestamp: u32,
}

impl fmt::Debug for KeytabEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeytabEntry")
            .field("kvno", &self.kvno)
            .field("enctype", &self.enctype)
            .finish_non_exhaustive()
    }
}

/// The keys of one principal.
#[derive(Debug)]
pub struct Keytab {
    principal: Principal,
    entries: Vec<KeytabEntry>,
}

const VERSION: [u8; 2] = [0x05, 0x02];

impl Keytab {
    /// A keytab for `principal`.
    #[must_use]
    pub fn new(principal: Principal, entries: Vec<KeytabEntry>) -> Self {
        Self { principal, entries }
    }

    /// The principal.
    #[must_use]
    pub fn principal(&self) -> &Principal {
        &self.principal
    }

    /// The keys.
    #[must_use]
    pub fn entries(&self) -> &[KeytabEntry] {
        &self.entries
    }

    /// The highest key version number, if there are keys.
    #[must_use]
    pub fn kvno(&self) -> Option<u32> {
        self.entries.iter().map(|e| e.kvno).max()
    }

    /// Keep only entries whose kvno satisfies `keep`.
    pub fn retain_kvno(&mut self, keep: impl Fn(u32) -> bool) {
        self.entries.retain(|e| keep(e.kvno));
    }

    /// Add the entries of `other` (same principal) that this keytab lacks.
    ///
    /// # Errors
    ///
    /// [`Error::Mismatch`] for a different principal.
    pub fn merge(&mut self, other: Self) -> Result<()> {
        if other.principal != self.principal {
            return Err(Error::Mismatch("keytab principal"));
        }
        for entry in other.entries {
            if !self
                .entries
                .iter()
                .any(|e| e.kvno == entry.kvno && e.enctype == entry.enctype)
            {
                self.entries.push(entry);
            }
        }
        Ok(())
    }

    fn record_len(&self, key_len: usize) -> usize {
        let name: usize = 2
            + 2
            + self.principal.realm.len()
            + self
                .principal
                .components
                .iter()
                .map(|c| 2 + c.len())
                .sum::<usize>();
        // name ‖ name_type ‖ timestamp ‖ vno8 ‖ enctype ‖ key ‖ vno32
        name + 4 + 4 + 1 + 2 + 2 + key_len + 4
    }

    /// Encode as an MIT keytab file.  The result is wiped on drop.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] if a name or key is too long for the format.
    pub fn to_mit(&self) -> Result<SecretBuf> {
        let total = 2 + self
            .entries
            .iter()
            .map(|e| 4 + self.record_len(e.key.len()))
            .sum::<usize>();
        let mut out = SecretBuf::with_len(total);
        let mut w = Cursor {
            buf: out.as_mut_slice(),
            pos: 0,
        };
        w.put(&VERSION);
        for e in &self.entries {
            let len = i32::try_from(self.record_len(e.key.len()))
                .map_err(|_| Error::Malformed("keytab entry"))?;
            w.put(&len.to_be_bytes());
            w.u16(self.principal.components.len())?;
            w.counted(self.principal.realm.as_bytes())?;
            for c in &self.principal.components {
                w.counted(c.as_bytes())?;
            }
            w.put(&self.principal.name_type().to_be_bytes());
            w.put(&e.timestamp.to_be_bytes());
            w.put(&[u8::try_from(e.kvno).unwrap_or(0)]);
            w.u16(usize::try_from(e.enctype.0).map_err(|_| Error::Malformed("enctype"))?)?;
            w.counted(e.key.as_ref())?;
            w.put(&e.kvno.to_be_bytes());
        }
        debug_assert_eq!(w.pos, total);
        Ok(out)
    }

    /// Decode an MIT keytab file holding the keys of a single principal.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for anything but a version 0x0502 keytab, and
    /// [`Error::Mismatch`] if it holds keys of several principals.
    pub fn from_mit(bytes: &[u8]) -> Result<Self> {
        let mut r = Parser { buf: bytes };
        if r.take(2)? != VERSION {
            return Err(Error::Malformed("keytab version"));
        }
        let mut principal: Option<Principal> = None;
        let mut entries = Vec::new();
        while !r.buf.is_empty() {
            let size = i32::from_be_bytes(r.fixed()?);
            let Ok(size) = usize::try_from(size) else {
                // A hole left by a deleted entry.
                r.take(size.unsigned_abs() as usize)?;
                continue;
            };
            let mut e = Parser { buf: r.take(size)? };
            let count = usize::from(u16::from_be_bytes(e.fixed()?));
            let realm = e.string()?;
            let components = (0..count).map(|_| e.string()).collect::<Result<_>>()?;
            let this = Principal { components, realm };
            let _name_type: [u8; 4] = e.fixed()?;
            let timestamp = u32::from_be_bytes(e.fixed()?);
            let vno8 = e.fixed::<1>()?[0];
            let enctype = Enctype(i32::from(u16::from_be_bytes(e.fixed()?)));
            let key = SecretBuf::from_slice(e.counted()?);
            let kvno = match e.buf.len() {
                n if n >= 4 => match u32::from_be_bytes(e.fixed()?) {
                    0 => u32::from(vno8),
                    v => v,
                },
                _ => u32::from(vno8),
            };
            match &principal {
                Some(p) if *p != this => return Err(Error::Mismatch("keytab principal")),
                Some(_) => {}
                None => principal = Some(this),
            }
            entries.push(KeytabEntry {
                kvno,
                enctype,
                key,
                timestamp,
            });
        }
        Ok(Self {
            principal: principal.ok_or(Error::Missing("keytab entries"))?,
            entries,
        })
    }
}

struct Cursor<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl Cursor<'_> {
    fn put(&mut self, bytes: &[u8]) {
        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(bytes);
        self.pos += bytes.len();
    }

    fn u16(&mut self, v: usize) -> Result<()> {
        let v = u16::try_from(v).map_err(|_| Error::Malformed("keytab field"))?;
        self.put(&v.to_be_bytes());
        Ok(())
    }

    fn counted(&mut self, bytes: &[u8]) -> Result<()> {
        self.u16(bytes.len())?;
        self.put(bytes);
        Ok(())
    }
}

struct Parser<'a> {
    buf: &'a [u8],
}

impl<'a> Parser<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.buf.len() < n {
            return Err(Error::Malformed("keytab"));
        }
        let (head, tail) = self.buf.split_at(n);
        self.buf = tail;
        Ok(head)
    }

    fn fixed<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn counted(&mut self) -> Result<&'a [u8]> {
        let n = usize::from(u16::from_be_bytes(self.fixed()?));
        self.take(n)
    }

    fn string(&mut self) -> Result<String> {
        String::from_utf8(self.counted()?.to_vec()).map_err(|_| Error::Malformed("keytab name"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Keytab {
        let p: Principal = "host/a.example.test@EXAMPLE.TEST".parse().unwrap();
        Keytab::new(
            p,
            vec![
                KeytabEntry {
                    kvno: 2,
                    enctype: Enctype::AES256_CTS_HMAC_SHA1_96,
                    key: SecretBuf::from_slice(&[7; 32]),
                    timestamp: 1_800_000_000,
                },
                KeytabEntry {
                    kvno: 300,
                    enctype: Enctype::AES128_CTS_HMAC_SHA1_96,
                    key: SecretBuf::from_slice(&[8; 16]),
                    timestamp: 1_800_000_001,
                },
            ],
        )
    }

    #[test]
    fn principal_parse_and_display() {
        let p: Principal = "host/a.example.test@EXAMPLE.TEST".parse().unwrap();
        assert_eq!(p.components(), ["host", "a.example.test"]);
        assert_eq!(p.realm(), "EXAMPLE.TEST");
        assert_eq!(p.to_string(), "host/a.example.test@EXAMPLE.TEST");
        assert_eq!(p, Principal::host("a.example.test", "EXAMPLE.TEST"));
        for bad in ["host/a", "@R", "host//a@R", "a\\/b@R", "host/a@"] {
            assert!(bad.parse::<Principal>().is_err(), "{bad}");
        }
    }

    #[test]
    fn mit_round_trip() {
        let kt = sample();
        let bytes = kt.to_mit().unwrap();
        assert_eq!(&bytes.as_ref()[..2], &[5, 2]);
        let back = Keytab::from_mit(bytes.as_ref()).unwrap();
        assert_eq!(back.principal(), kt.principal());
        assert_eq!(back.entries().len(), 2);
        assert_eq!(back.entries()[1].kvno, 300, "32-bit kvno survives");
        assert_eq!(back.entries()[0].key.as_ref(), &[7; 32]);
        assert_eq!(back.kvno(), Some(300));
    }

    #[test]
    fn holes_are_skipped_and_garbage_rejected() {
        let bytes = sample().to_mit().unwrap();
        let mut with_hole = bytes.as_ref()[..2].to_vec();
        with_hole.extend_from_slice(&(-3i32).to_be_bytes());
        with_hole.extend_from_slice(&[0, 0, 0]);
        with_hole.extend_from_slice(&bytes.as_ref()[2..]);
        assert_eq!(Keytab::from_mit(&with_hole).unwrap().entries().len(), 2);

        assert!(Keytab::from_mit(&bytes.as_ref()[..bytes.len() - 1]).is_err());
        assert!(Keytab::from_mit(&[5, 1]).is_err());
        assert!(Keytab::from_mit(&[5, 2]).is_err(), "no entries");
    }

    #[test]
    fn merge_keeps_unique_keys() {
        let mut a = sample();
        let b = sample();
        a.merge(b).unwrap();
        assert_eq!(a.entries().len(), 2);
        a.retain_kvno(|v| v > 2);
        assert_eq!(a.entries().len(), 1);
        let other = Keytab::new(Principal::host("b", "R"), Vec::new());
        assert!(a.merge(other).is_err());
    }
}
