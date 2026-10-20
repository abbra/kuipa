//! What a successful join, rekey or bundle delivers to the host (§5.5,
//! §8.4): its keys, the CA chain, the anchors and the realm configuration.

use native_ossl::util::SecretBuf;
use tang_pqc::Thumbprint;
use tang_pqc::wire::{Reader, Writer};

use crate::error::{Error, Result};
use crate::keytab::Keytab;

const MAGIC: [u8; 4] = *b"IPJP";

/// The realm configuration a host needs, beyond its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealmConfig {
    /// Kerberos realm.
    pub realm: String,
    /// DNS domain.
    pub domain: String,
    /// LDAP base DN.
    pub basedn: String,
    /// The server that issued the keys: list it first until replication
    /// catches up (§4.6).
    pub issuer: String,
    /// Other servers known to the issuer.
    pub servers: Vec<String>,
}

/// An enrollment: everything the host installs.
#[derive(Debug)]
pub struct Enrollment {
    /// Realm configuration.
    pub config: RealmConfig,
    /// The host's keys.
    pub keytab: Keytab,
    /// The IPA CA chain (DER).
    pub ca_certs: Vec<Vec<u8>>,
    /// The PKINIT trust anchors (DER).
    pub pkinit_anchors: Vec<Vec<u8>>,
    /// The current realm anchors.
    pub anchors: Vec<Thumbprint>,
    /// The sequence number of the issuing server's anchor epoch log
    /// (§4.8); `0` when it kept none.
    pub epoch_seq: u64,
    /// The hash of that last entry, for the host's watermark; zero when
    /// there is none.
    pub epoch_head: [u8; 32],
}

fn count(n: usize) -> Result<u8> {
    u8::try_from(n).map_err(|_| Error::Malformed("enrollment: too many items"))
}

impl Enrollment {
    /// Encode.  The keys go last, so the buffer holding them is written once
    /// and wiped on drop.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for more than 255 items in a list.
    pub fn to_bytes(&self) -> Result<SecretBuf> {
        let mut w = Writer::new(MAGIC);
        let c = &self.config;
        w.str(&c.realm).str(&c.domain).str(&c.basedn).str(&c.issuer);
        w.u8(count(c.servers.len())?);
        for s in &c.servers {
            w.str(s);
        }
        w.u8(count(self.ca_certs.len())?);
        for cert in &self.ca_certs {
            w.bytes(cert);
        }
        w.u8(count(self.pkinit_anchors.len())?);
        for cert in &self.pkinit_anchors {
            w.bytes(cert);
        }
        w.u8(count(self.anchors.len())?);
        for a in &self.anchors {
            w.fixed(a.as_bytes());
        }
        w.u64(self.epoch_seq).fixed(&self.epoch_head);
        w.bytes(self.keytab.to_mit()?.as_ref());
        Ok(SecretBuf::new(w.finish()))
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, MAGIC, "enrollment")?;
        let realm = r.str()?.to_owned();
        let domain = r.str()?.to_owned();
        let basedn = r.str()?.to_owned();
        let issuer = r.str()?.to_owned();
        let servers = (0..r.u8()?)
            .map(|_| r.str().map(str::to_owned))
            .collect::<Result<_, _>>()?;
        let ca_certs = (0..r.u8()?)
            .map(|_| r.bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let pkinit_anchors = (0..r.u8()?)
            .map(|_| r.bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let anchors = (0..r.u8()?)
            .map(|_| r.fixed().map(Thumbprint::from_bytes))
            .collect::<Result<_, _>>()?;
        let (epoch_seq, epoch_head) = (r.u64()?, r.fixed()?);
        let keytab = Keytab::from_mit(r.bytes()?)?;
        r.finish()?;
        if keytab.principal().realm() != realm {
            return Err(Error::Mismatch("keytab realm"));
        }
        Ok(Self {
            config: RealmConfig {
                realm,
                domain,
                basedn,
                issuer,
                servers,
            },
            keytab,
            ca_certs,
            pkinit_anchors,
            anchors,
            epoch_seq,
            epoch_head,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::keytab::{Enctype, KeytabEntry, Principal};

    pub(crate) fn keytab(fqdn: &str, kvno: u32) -> Keytab {
        Keytab::new(
            Principal::host(fqdn, "EXAMPLE.TEST"),
            vec![KeytabEntry {
                kvno,
                enctype: Enctype::AES256_CTS_HMAC_SHA1_96,
                key: SecretBuf::from_slice(&[u8::try_from(kvno).unwrap(); 32]),
                timestamp: 1,
            }],
        )
    }

    #[test]
    fn round_trip() {
        let e = Enrollment {
            config: RealmConfig {
                realm: "EXAMPLE.TEST".into(),
                domain: "example.test".into(),
                basedn: "dc=example,dc=test".into(),
                issuer: "ipa1.example.test".into(),
                servers: vec!["ipa2.example.test".into()],
            },
            keytab: keytab("a.example.test", 1),
            ca_certs: vec![b"ca".to_vec()],
            pkinit_anchors: vec![b"pkinit".to_vec()],
            anchors: vec![Thumbprint::from_bytes([1; 32])],
            epoch_seq: 7,
            epoch_head: [9; 32],
        };
        let bytes = e.to_bytes().unwrap();
        let back = Enrollment::from_bytes(bytes.as_ref()).unwrap();
        assert_eq!(back.config, e.config);
        assert_eq!(back.ca_certs, e.ca_certs);
        assert_eq!(back.pkinit_anchors, e.pkinit_anchors);
        assert_eq!(back.anchors, e.anchors);
        assert_eq!((back.epoch_seq, back.epoch_head), (7, [9; 32]));
        assert_eq!(back.keytab.kvno(), Some(1));
        assert!(Enrollment::from_bytes(&bytes.as_ref()[..bytes.len() - 1]).is_err());
    }
}
