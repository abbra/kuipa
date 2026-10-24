//! The enrollment string an administrator hands to a host (§4.4):
//!
//! ```text
//! ipa-ku1:<REALM>:<anchor thumbprint>:<expiry>[:<secret>]
//! ipa-ku2:<REALM>:<anchor thumbprint>:<expiry>:<size>:<root>[:<secret>]
//! ```
//!
//! The expiry is in Unix seconds; a host refuses the string after it (with
//! [`CLOCK_SKEW`]).  It has the integrity of the channel that delivers the
//! string, as the thumbprint does: whoever could change it could change the
//! thumbprint instead.  It bounds how long a string that leaked, or lingers
//! in an old image, can pin an anchor that may have been rotated or stolen
//! since.
//!
//! A version 2 string also pins the anchor's **vouch head** (§4.9): the
//! claim log's `(size, root)` at issue time, which lets the host check a
//! delegation's inclusion proof with no signature at all.
//!
//! The secret is an OTP for an online join, or the bundle secret `S` for an
//! offline mode B bundle.  It is the last field and may itself contain `:`.

use native_ossl::util::SecretBuf;
use tang_pqc::Thumbprint;

use crate::delegation::{CLOCK_SKEW, HeadPin};
use crate::error::{Error, Result};
use crate::merkle::Hash;
use tang_pqc::b64;

const PREFIX: &str = "ipa-ku1";
const PREFIX_HEAD: &str = "ipa-ku2";

/// A parsed enrollment string.
#[derive(Debug)]
pub struct EnrollmentString {
    realm: String,
    anchor: Thumbprint,
    exp: u64,
    head: Option<(u64, Hash)>,
    secret: Option<Secret>,
}

/// A secret read from an enrollment string: wiped on drop, never printed.
pub struct Secret(SecretBuf);

impl Secret {
    /// Wrap secret bytes.
    #[must_use]
    pub fn new(bytes: &[u8]) -> Self {
        Self(SecretBuf::from_slice(bytes))
    }

    /// The secret bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl std::fmt::Debug for Secret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Secret(..)")
    }
}

impl EnrollmentString {
    /// A string for `realm` and `anchor`, valid until `exp` (Unix
    /// seconds), with an optional secret.
    #[must_use]
    pub fn new(realm: &str, anchor: Thumbprint, exp: u64, secret: Option<Secret>) -> Self {
        Self::with_head(realm, anchor, None, exp, secret)
    }

    /// A version 2 string, additionally pinning the anchor's vouch head
    /// (§4.9): `(size, root)` of its claim log.
    #[must_use]
    pub fn with_head(
        realm: &str,
        anchor: Thumbprint,
        head: Option<(u64, Hash)>,
        exp: u64,
        secret: Option<Secret>,
    ) -> Self {
        Self {
            realm: realm.into(),
            anchor,
            head,
            exp,
            secret,
        }
    }

    /// Parse, ignoring surrounding whitespace (a trailing newline from
    /// standard input, for example).
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for anything but
    /// `ipa-ku1:REALM:thp:exp[:secret]` or
    /// `ipa-ku2:REALM:thp:exp:size:root[:secret]`.
    pub fn parse(text: &[u8]) -> Result<Self> {
        let malformed = || Error::Malformed("enrollment string");
        let text = std::str::from_utf8(text).map_err(|_| malformed())?.trim();
        let (prefix, rest) = text.split_once(':').ok_or_else(malformed)?;
        let v2 = match prefix {
            PREFIX => false,
            PREFIX_HEAD => true,
            _ => return Err(malformed()),
        };
        // The prefix is split off already: realm, anchor, expiry, then —
        // v2 only — size and root, then the secret, which may contain `:`
        // and is the last field, however many `:` it holds.
        let mut fields = rest.splitn(if v2 { 6 } else { 4 }, ':');
        let realm = fields
            .next()
            .filter(|r| !r.is_empty())
            .ok_or_else(malformed)?;
        let anchor = fields
            .next()
            .ok_or_else(malformed)?
            .parse()
            .map_err(|_| malformed())?;
        let exp = fields
            .next()
            .filter(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()))
            .and_then(|e| e.parse().ok())
            .ok_or_else(malformed)?;
        let head = if v2 {
            let size = fields
                .next()
                .filter(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|s| s.parse().ok())
                .filter(|s| *s > 0)
                .ok_or_else(malformed)?;
            let root = fields
                .next()
                .and_then(|r| b64::decode(r).ok())
                .and_then(|r| Hash::from_slice(&r).ok())
                .ok_or_else(malformed)?;
            Some((size, root))
        } else {
            None
        };
        let secret = match fields.next() {
            None => None,
            Some("") => return Err(malformed()),
            Some(s) => Some(Secret::new(s.as_bytes())),
        };
        Ok(Self {
            realm: realm.into(),
            anchor,
            head,
            exp,
            secret,
        })
    }

    /// Encode; the result holds the secret, so it is wiped on drop.
    #[must_use]
    pub fn encode(&self) -> SecretBuf {
        let head = format!(
            "{}:{}:{}:{}",
            if self.head.is_some() {
                PREFIX_HEAD
            } else {
                PREFIX
            },
            self.realm,
            self.anchor,
            self.exp
        );
        let head = self.head.as_ref().map_or(head.clone(), |(size, root)| {
            format!("{head}:{size}:{}", b64::encode(root))
        });
        let secret = self.secret.as_ref().map_or(&[][..], Secret::as_bytes);
        let extra = if secret.is_empty() {
            0
        } else {
            1 + secret.len()
        };
        let mut out = SecretBuf::with_len(head.len() + extra);
        let buf = out.as_mut_slice();
        buf[..head.len()].copy_from_slice(head.as_bytes());
        if extra > 0 {
            buf[head.len()] = b':';
            buf[head.len() + 1..].copy_from_slice(secret);
        }
        out
    }

    /// The realm.
    #[must_use]
    pub fn realm(&self) -> &str {
        &self.realm
    }

    /// The pinned realm anchor.
    #[must_use]
    pub fn anchor(&self) -> &Thumbprint {
        &self.anchor
    }

    /// The pinned vouch head (§4.9), for a version 2 string.
    #[must_use]
    pub fn head(&self) -> Option<HeadPin> {
        self.head.map(|(size, root)| HeadPin {
            anchor: self.anchor,
            size,
            root,
        })
    }

    /// When it expires (Unix seconds).
    #[must_use]
    pub fn exp(&self) -> u64 {
        self.exp
    }

    /// Whether it may still be used at `now` (Unix seconds).
    ///
    /// # Errors
    ///
    /// [`Error::Expired`] past its expiry, with [`CLOCK_SKEW`].
    pub fn check_valid(&self, now: u64) -> Result<()> {
        if now > self.exp.saturating_add(CLOCK_SKEW) {
            return Err(Error::Expired);
        }
        Ok(())
    }

    /// The OTP or bundle secret, if present.
    #[must_use]
    pub fn secret(&self) -> Option<&Secret> {
        self.secret.as_ref()
    }

    /// Take the secret out, leaving none.
    pub fn take_secret(&mut self) -> Option<Secret> {
        self.secret.take()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn thp() -> Thumbprint {
        Thumbprint::from_bytes([3; 32])
    }

    #[test]
    fn round_trip_with_and_without_secret() {
        let s = EnrollmentString::new("EXAMPLE.TEST", thp(), 1800, Some(Secret::new(b"a:b c")));
        let enc = s.encode();
        assert!(
            enc.as_ref()
                .starts_with(format!("ipa-ku1:EXAMPLE.TEST:{}:1800:", thp()).as_bytes())
        );
        let back = EnrollmentString::parse(enc.as_ref()).unwrap();
        assert_eq!(back.realm(), "EXAMPLE.TEST");
        assert_eq!(back.anchor(), &thp());
        assert_eq!(back.exp(), 1800);
        assert_eq!(back.secret().unwrap().as_bytes(), b"a:b c");

        let s = EnrollmentString::new("EXAMPLE.TEST", thp(), 1800, None);
        let mut line = s.encode().as_ref().to_vec();
        line.push(b'\n');
        assert!(EnrollmentString::parse(&line).unwrap().secret().is_none());
    }

    #[test]
    fn round_trip_with_a_head() {
        // A SHA-384 root: the string carries either length.
        let root = Hash::from_slice(&[7; 48]).unwrap();
        let s = EnrollmentString::with_head(
            "EXAMPLE.TEST",
            thp(),
            Some((12, root)),
            1800,
            Some(Secret::new(b"a:b c")),
        );
        let enc = s.encode();
        assert!(
            enc.as_ref().starts_with(
                format!(
                    "ipa-ku2:EXAMPLE.TEST:{}:1800:12:{}:",
                    thp(),
                    b64::encode(&root)
                )
                .as_bytes()
            )
        );
        let back = EnrollmentString::parse(enc.as_ref()).unwrap();
        let head = back.head().unwrap();
        assert_eq!(head.anchor, thp());
        assert_eq!(head.size, 12);
        assert_eq!(head.root, root);
        assert_eq!(back.secret().unwrap().as_bytes(), b"a:b c");

        // Without a secret, and v1 still parses with no head.
        let s = EnrollmentString::with_head("R", thp(), Some((1, root)), 10, None);
        assert!(
            EnrollmentString::parse(s.encode().as_ref())
                .unwrap()
                .head()
                .is_some()
        );
        let v1 = EnrollmentString::new("R", thp(), 10, None);
        assert!(
            EnrollmentString::parse(v1.encode().as_ref())
                .unwrap()
                .head()
                .is_none()
        );
    }

    #[test]
    fn expires() {
        let s = EnrollmentString::new("R", thp(), 1000, None);
        assert!(s.check_valid(1000).is_ok());
        assert!(s.check_valid(1000 + CLOCK_SKEW).is_ok());
        assert!(matches!(
            s.check_valid(1001 + CLOCK_SKEW),
            Err(Error::Expired)
        ));
    }

    #[test]
    fn rejects_malformed() {
        let t = thp().to_string();
        for bad in [
            format!("ipa-ku2:R:{t}:1"),
            format!("ipa-ku1::{t}:1"),
            "ipa-ku1:R:short:1".into(),
            format!("ipa-ku1:R:{t}:1:"),
            "ipa-ku1:R".into(),
            // The expiry is mandatory, decimal, and comes before the secret.
            format!("ipa-ku1:R:{t}"),
            format!("ipa-ku1:R:{t}:"),
            format!("ipa-ku1:R:{t}:Secret123"),
            format!("ipa-ku1:R:{t}:+5"),
            format!("ipa-ku1:R:{t}:99999999999999999999999"),
            // A v2 string needs a decimal size and a 32-byte root.
            format!("ipa-ku2:R:{t}:1:0:{}", b64::encode(&[0; 32])),
            format!("ipa-ku2:R:{t}:1:x:{}", b64::encode(&[0; 32])),
            format!("ipa-ku2:R:{t}:1:2:short"),
            format!("ipa-ku2:R:{t}:1:2:"),
        ] {
            assert!(EnrollmentString::parse(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(format!("{:?}", Secret::new(b"x")).contains(".."));
    }
}
