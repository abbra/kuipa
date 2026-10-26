//! What a successful join, rekey or bundle delivers to the host (§5.5,
//! §8.4): its keys, the CA chain, the anchors and the realm configuration;
//! and what a pins refresh delivers (§4.5): the anchors alone.

use native_ossl::util::SecretBuf;
use tang_pqc::Thumbprint;
use tang_pqc::wire::{Reader, Writer};

use crate::error::{Error, Result};
use crate::keytab::Keytab;
use crate::merkle::Hash;

const MAGIC: [u8; 4] = *b"IPJP";
const PINS_MAGIC: [u8; 4] = *b"IPPN";

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
    /// The anchors' current vouch heads (§4.9), aligned with `anchors`:
    /// `None` where the issuing server knew no head for the anchor.
    /// Clients pin them next to the thumbprints, and check a delegation
    /// against a head with no signature at all.
    pub heads: Vec<Option<(u64, Hash)>>,
    /// The sequence number of the issuing server's anchor epoch log
    /// (§4.8); `0` when it kept none.
    pub epoch_seq: u64,
    /// The hash of that last entry, for the host's watermark; zero when
    /// there is none.
    pub epoch_head: crate::epoch::EpochHead,
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
        write_anchors(&mut w, &self.anchors, &self.heads)?;
        w.u64(self.epoch_seq).fixed(&self.epoch_head);
        w.bytes(self.keytab.to_mit()?.as_ref());
        Ok(SecretBuf::new(w.finish()))
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for a realm, domain, issuer or server
    /// name that is not safe to put in generated configuration and file
    /// names (see [`crate::realm::is_safe_name`]).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, MAGIC, "enrollment")?;
        let realm = r.str()?.to_owned();
        let domain = r.str()?.to_owned();
        let basedn = r.str()?.to_owned();
        let issuer = r.str()?.to_owned();
        let servers: Vec<String> = (0..r.u8()?)
            .map(|_| r.str().map(str::to_owned))
            .collect::<Result<_, _>>()?;
        let ca_certs = (0..r.u8()?)
            .map(|_| r.bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let pkinit_anchors = (0..r.u8()?)
            .map(|_| r.bytes().map(<[u8]>::to_vec))
            .collect::<Result<_, _>>()?;
        let (anchors, heads) = read_anchors(&mut r)?;
        let (epoch_seq, epoch_head) = (r.u64()?, r.fixed()?);
        let keytab = Keytab::from_mit(r.bytes()?)?;
        r.finish()?;
        if keytab.principal().realm() != realm {
            return Err(Error::Mismatch("keytab realm"));
        }
        let safe = |n: &str| crate::realm::is_safe_name(n);
        if !safe(&realm) || !safe(&domain) || !safe(&issuer) || servers.iter().any(|s| !safe(s)) {
            return Err(Error::Malformed("enrollment: unsafe name"));
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
            heads,
            epoch_seq,
            epoch_head,
        })
    }
}

/// The anchors with their heads, aligned: a count, then per anchor its
/// thumbprint and its head `(size, root)`, the root length prefixed (its
/// length names its hash); an absent head is a zero size and an empty root.
fn write_anchors(
    w: &mut Writer,
    anchors: &[Thumbprint],
    heads: &[Option<(u64, Hash)>],
) -> Result<()> {
    if heads.len() != anchors.len() {
        return Err(Error::Malformed("heads do not match anchors"));
    }
    w.u8(count(anchors.len())?);
    for (a, head) in anchors.iter().zip(heads) {
        w.fixed(a.as_bytes());
        match head {
            Some((size, root)) => {
                w.u64(*size).bytes(root);
            }
            None => {
                w.u64(0).bytes(&[]);
            }
        }
    }
    Ok(())
}

/// Anchors with their vouch heads, aligned: what an enrollment and a pins
/// refresh deliver.
pub(crate) type AnchorHeads = (Vec<Thumbprint>, Vec<Option<(u64, Hash)>>);

/// The anchors and heads [`write_anchors`] wrote.
fn read_anchors(r: &mut Reader<'_>) -> Result<AnchorHeads> {
    let n = r.u8()?;
    let mut anchors = Vec::with_capacity(n as usize);
    let mut heads = Vec::with_capacity(n as usize);
    for _ in 0..n {
        anchors.push(Thumbprint::from_bytes(r.fixed()?));
        let size = r.u64()?;
        let root = r.bytes()?;
        heads.push(if size == 0 {
            None
        } else {
            Some((size, Hash::from_slice(root)?))
        });
    }
    Ok((anchors, heads))
}

/// What a pins refresh answers (`POST /ipa/ku/pins/{kid}`, §4.5): the
/// realm's current anchors and their vouch heads, as a rekey delivers them
/// but with no keys and no anchor epoch: the watermark moves only through
/// the verified chain (§4.8).  The answer is bound to the host's
/// Kerberos session like a rekey's, so a host may update its pins from it
/// (§4.7) without rotating its keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinsAnswer {
    /// The realm.
    pub realm: String,
    /// The server that answered: its claim log backs the heads.
    pub issuer: String,
    /// The current realm anchors.
    pub anchors: Vec<Thumbprint>,
    /// Their current vouch heads, aligned with `anchors`.
    pub heads: Vec<Option<(u64, Hash)>>,
}

impl PinsAnswer {
    /// `IPPN ‖ 1 ‖ realm ‖ issuer ‖ anchors and heads`.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for heads that do not match the anchors, or
    /// more than 255 anchors.
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut w = Writer::new(PINS_MAGIC);
        w.str(&self.realm).str(&self.issuer);
        write_anchors(&mut w, &self.anchors, &self.heads)?;
        Ok(w.finish())
    }

    /// Decode.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`], also for an unsafe realm or issuer name.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let mut r = Reader::new(bytes, PINS_MAGIC, "pins")?;
        let realm = r.str()?.to_owned();
        let issuer = r.str()?.to_owned();
        let (anchors, heads) = read_anchors(&mut r)?;
        r.finish()?;
        if !crate::realm::is_safe_name(&realm) || !crate::realm::is_safe_name(&issuer) {
            return Err(Error::Malformed("pins: unsafe name"));
        }
        Ok(Self {
            realm,
            issuer,
            anchors,
            heads,
        })
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn pins_answers_round_trip_and_keep_heads_aligned() {
        let a = Thumbprint::from_bytes([1; 32]);
        let b = Thumbprint::from_bytes([2; 32]);
        let answer = PinsAnswer {
            realm: "EXAMPLE.TEST".into(),
            issuer: "ipa1.example.test".into(),
            anchors: vec![a, b],
            heads: vec![Some((3, crate::merkle::test_hash(3))), None],
        };
        assert_eq!(
            PinsAnswer::from_bytes(&answer.to_bytes().unwrap()).unwrap(),
            answer
        );
        let misaligned = PinsAnswer {
            heads: vec![None],
            ..answer.clone()
        };
        assert!(misaligned.to_bytes().is_err());
        let unsafe_issuer = PinsAnswer {
            issuer: "ipa1/../x".into(),
            ..answer
        };
        assert!(PinsAnswer::from_bytes(&unsafe_issuer.to_bytes().unwrap()).is_err());
    }
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
            anchors: vec![
                Thumbprint::from_bytes([1; 32]),
                Thumbprint::from_bytes([2; 32]),
            ],
            heads: vec![Some((3, Hash::from_slice(&[4; 48]).unwrap())), None],
            epoch_seq: 7,
            epoch_head: [9; 48],
        };
        let bytes = e.to_bytes().unwrap();
        let back = Enrollment::from_bytes(bytes.as_ref()).unwrap();
        assert_eq!(back.config, e.config);
        assert_eq!(back.ca_certs, e.ca_certs);
        assert_eq!(back.pkinit_anchors, e.pkinit_anchors);
        assert_eq!(back.anchors, e.anchors);
        assert_eq!((back.epoch_seq, back.epoch_head), (7, [9; 48]));
        assert_eq!(back.keytab.kvno(), Some(1));
        assert!(Enrollment::from_bytes(&bytes.as_ref()[..bytes.len() - 1]).is_err());
    }
}
