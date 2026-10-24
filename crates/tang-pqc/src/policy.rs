//! Client-side acceptance policy for advertisements.

use std::time::{Duration, SystemTime};

use crate::alg::{KemAlg, SignatureAlg};
use crate::error::{Error, Result};

/// What a client accepts from an advertisement.
///
/// The policy is the client's defence against downgrade (a server or network
/// attacker offering weaker or classic-only keys) and against replay of old,
/// validly signed advertisements.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    kems: Vec<KemAlg>,
    signature_algs: Vec<SignatureAlg>,
    max_validity: Duration,
    clock_skew: Duration,
    require_expiry: bool,
}

impl Default for Policy {
    /// ML-KEM-768/1024, ML-DSA-44/65/87, expiry required, at most 30 days of
    /// validity, 5 minutes of clock skew.
    ///
    /// ML-DSA-44 is accepted because transparency-log witnesses and CA
    /// cosigners use it (C2SP tlog-witness, Chrome's quantum-resistant root
    /// policy); new signing keys still prefer ML-DSA-65
    /// ([`SignatureAlg::PREFERENCE`]).
    fn default() -> Self {
        Self {
            kems: KemAlg::ALL.to_vec(),
            signature_algs: SignatureAlg::ALL.to_vec(),
            max_validity: Duration::from_secs(30 * 24 * 3600),
            clock_skew: Duration::from_secs(5 * 60),
            require_expiry: true,
        }
    }
}

impl Policy {
    /// CNSA 2.0: ML-KEM-1024 and ML-DSA-87 only.
    #[must_use]
    pub fn cnsa2() -> Self {
        Self {
            kems: vec![KemAlg::MlKem1024],
            signature_algs: vec![SignatureAlg::MlDsa87],
            ..Self::default()
        }
    }

    /// The default policy narrowed to what the system crypto policy allows,
    /// so a CNSA 2.0 system policy yields [`cnsa2`](Self::cnsa2).
    ///
    /// # Errors
    ///
    /// [`Error::SystemPolicy`] if OpenSSL's configuration cannot be read, or
    /// [`Error::NoAllowedAlgorithm`] if it allows no ML-KEM or no ML-DSA.
    pub fn from_system() -> Result<Self> {
        let mut kems = Vec::new();
        for alg in KemAlg::ALL {
            if alg.allowed_by_system()? {
                kems.push(alg);
            }
        }
        let mut signature_algs = Vec::new();
        for alg in SignatureAlg::ALL {
            if alg.allowed_by_system()? {
                signature_algs.push(alg);
            }
        }
        if kems.is_empty() {
            return Err(Error::NoAllowedAlgorithm("ML-KEM"));
        }
        if signature_algs.is_empty() {
            return Err(Error::NoAllowedAlgorithm("ML-DSA"));
        }
        Ok(Self {
            kems,
            signature_algs,
            ..Self::default()
        })
    }

    /// Accept only these KEMs for new bindings.
    #[must_use]
    pub fn with_kems(mut self, kems: &[KemAlg]) -> Self {
        self.kems = kems.to_vec();
        self
    }

    /// Accept only these algorithms for the trusted signing key.
    #[must_use]
    pub fn with_signature_algs(mut self, algs: &[SignatureAlg]) -> Self {
        self.signature_algs = algs.to_vec();
        self
    }

    /// Reject advertisements whose `exp − iat` exceeds `max`.
    #[must_use]
    pub fn with_max_validity(mut self, max: Duration) -> Self {
        self.max_validity = max;
        self
    }

    /// Tolerated difference between client and server clocks.
    #[must_use]
    pub fn with_clock_skew(mut self, skew: Duration) -> Self {
        self.clock_skew = skew;
        self
    }

    /// Accept advertisements without `iat`/`exp`, which can be replayed
    /// forever.  Only for servers that cannot be upgraded yet.
    #[must_use]
    pub fn allow_unexpiring(mut self) -> Self {
        self.require_expiry = false;
        self
    }

    /// Does the policy allow this KEM?
    #[must_use]
    pub fn allows_kem(&self, alg: KemAlg) -> bool {
        self.kems.contains(&alg)
    }

    /// Does the policy allow this signature algorithm?
    #[must_use]
    pub fn allows_signature(&self, alg: SignatureAlg) -> bool {
        self.signature_algs.contains(&alg)
    }

    /// Check a signed `iat`/`exp` pair (Unix seconds) against `now`.
    /// Check a validity period `iat`/`exp` (Unix seconds) against `now`:
    /// both or neither must be present, the period must not exceed the
    /// maximum validity, and `now` must fall inside it, within the clock
    /// skew.
    ///
    /// # Errors
    ///
    /// [`Error::StaleAdvertisement`], [`Error::Policy`] or [`Error::Malformed`].
    pub fn check_freshness(&self, iat: Option<u64>, exp: Option<u64>, now: u64) -> Result<()> {
        let (iat, exp) = match (iat, exp) {
            (Some(iat), Some(exp)) => (iat, exp),
            (None, None) if !self.require_expiry => return Ok(()),
            (None, None) => return Err(Error::Policy("advertisement has no expiry")),
            _ => {
                return Err(Error::Malformed(
                    "advertisement: iat and exp must come together",
                ));
            }
        };
        if exp <= iat {
            return Err(Error::Malformed("advertisement: exp not after iat"));
        }
        if exp - iat > self.max_validity.as_secs() {
            return Err(Error::Policy("advertisement validity period too long"));
        }
        let skew = self.clock_skew.as_secs();
        if now > exp.saturating_add(skew) || iat > now.saturating_add(skew) {
            return Err(Error::StaleAdvertisement);
        }
        Ok(())
    }
}

/// Seconds since the Unix epoch (0 for earlier times).
/// Seconds since the Unix epoch (0 before it).
#[must_use]
pub fn unix_seconds(t: SystemTime) -> u64 {
    t.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u64 = 24 * 3600;

    #[test]
    fn freshness_window() {
        let p = Policy::default();
        let now = 1_800_000_000;
        p.check_freshness(Some(now - DAY), Some(now + DAY), now)
            .unwrap();
        // Within skew on both ends.
        p.check_freshness(Some(now + 60), Some(now + DAY), now)
            .unwrap();
        p.check_freshness(Some(now - DAY), Some(now - 60), now)
            .unwrap();
        // Expired, not yet valid.
        assert!(matches!(
            p.check_freshness(Some(now - 2 * DAY), Some(now - DAY), now),
            Err(Error::StaleAdvertisement)
        ));
        assert!(matches!(
            p.check_freshness(Some(now + DAY), Some(now + 2 * DAY), now),
            Err(Error::StaleAdvertisement)
        ));
        // Too long, inverted, half-present, missing.
        assert!(matches!(
            p.check_freshness(Some(now), Some(now + 31 * DAY), now),
            Err(Error::Policy(_))
        ));
        assert!(p.check_freshness(Some(now), Some(now), now).is_err());
        assert!(p.check_freshness(Some(now), None, now).is_err());
        assert!(matches!(
            p.check_freshness(None, None, now),
            Err(Error::Policy(_))
        ));
        p.clone()
            .allow_unexpiring()
            .check_freshness(None, None, now)
            .unwrap();
    }

    #[test]
    fn cnsa2_is_strict() {
        let p = Policy::cnsa2();
        assert!(p.allows_kem(KemAlg::MlKem1024) && !p.allows_kem(KemAlg::MlKem768));
        assert!(p.allows_signature(SignatureAlg::MlDsa87));
        assert!(!p.allows_signature(SignatureAlg::MlDsa65));
        assert!(!p.allows_signature(SignatureAlg::MlDsa44));
        assert!(Policy::default().allows_signature(SignatureAlg::MlDsa44));
    }
}
