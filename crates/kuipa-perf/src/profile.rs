//! Benchmark profiles: the sizes a run measures, and which CA it uses.
//!
//! Selected with `KUIPA_BENCH_PROFILE=smoke|production|pqproduction|large`;
//! production is the default.  Profiles are *fixture sizes* — benches scale
//! around them (a scaling bench still sweeps its own parameter axis).

use std::str::FromStr;

use serde_json::{Value, json};

/// Which certificate authority the fixture realm carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CaKind {
    /// RSA-2048 CA, SHA-256 signed — what most deployments still ship.
    Rsa2048,
    /// EC P-256 CA, SHA-256 signed — the common modern choice.
    EcP256,
    /// ML-DSA-65 CA — post-quantum, the `pqproduction` profile.
    MlDsa65,
}

impl CaKind {
    /// The name as it appears in result metadata.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Rsa2048 => "rsa2048",
            Self::EcP256 => "ec-p256",
            Self::MlDsa65 => "ml-dsa-65",
        }
    }
}

/// A named set of fixture sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProfileKind {
    /// The smallest sizes, for a quick run.
    Smoke,
    /// What a typical deployment looks like.
    Production,
    /// `Production` with an ML-DSA-65 CA.
    PqProduction,
    /// A deep realm, for scaling.
    Large,
}

impl ProfileKind {
    /// The name `KUIPA_BENCH_PROFILE` and the result metadata use.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Smoke => "smoke",
            Self::Production => "production",
            Self::PqProduction => "pqproduction",
            Self::Large => "large",
        }
    }
}

impl FromStr for ProfileKind {
    type Err = String;

    fn from_str(name: &str) -> Result<Self, String> {
        [
            Self::Smoke,
            Self::Production,
            Self::PqProduction,
            Self::Large,
        ]
        .into_iter()
        .find(|k| k.name() == name)
        .ok_or_else(|| format!("unknown profile '{name}'"))
    }
}

/// The sizes a benchmark run works at.
#[derive(Clone, Debug)]
pub struct Profile {
    /// Which profile this is.
    pub kind: ProfileKind,
    /// Enroll servers in the fixture realm.
    pub servers: usize,
    /// CA certificates the advertisement carries (and a client checks).
    pub ca_certs: usize,
    /// `ca_certificates()` entries per directory lookup.
    pub dir_cas: usize,
    /// Keytab entries per host principal.
    pub keytab_entries: usize,
    /// Servers an escrow seals across.
    pub escrow_servers: usize,
    /// Claims an anchor vouches for (merkle leaves).
    pub leaves: usize,
    /// Servers whose delegations attest each other.
    pub attested: usize,
    /// The certificate authority this profile uses.
    pub ca: CaKind,
}

impl Profile {
    /// The sizes of `kind`.
    #[must_use]
    pub fn new(kind: ProfileKind) -> Self {
        let (servers, ca_certs, dir_cas, keytab_entries, leaves, attested) = match kind {
            ProfileKind::Smoke => (2, 1, 1, 1, 3, 1),
            ProfileKind::Large => (8, 4, 4, 6, 64, 7),
            ProfileKind::Production | ProfileKind::PqProduction => (4, 1, 2, 4, 8, 3),
        };
        Self {
            kind,
            servers,
            ca_certs,
            dir_cas,
            keytab_entries,
            escrow_servers: servers,
            leaves,
            attested,
            ca: if kind == ProfileKind::PqProduction {
                CaKind::MlDsa65
            } else {
                CaKind::EcP256
            },
        }
    }

    /// The profile named by `name`, or `None` if unknown.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        name.parse().ok().map(Self::new)
    }

    /// The profile named by `KUIPA_BENCH_PROFILE`, or `production`.
    ///
    /// # Panics
    ///
    /// If `KUIPA_BENCH_PROFILE` names an unknown profile.
    #[must_use]
    pub fn from_env() -> Self {
        let raw = std::env::var("KUIPA_BENCH_PROFILE").unwrap_or_default();
        if raw.is_empty() {
            return Self::new(ProfileKind::Production);
        }
        Self::new(
            raw.parse()
                .unwrap_or_else(|e| panic!("KUIPA_BENCH_PROFILE: {e}")),
        )
    }

    /// A profile with `ca_certs` CA certificates, in the advertisement and
    /// in the directory's answer.
    #[must_use]
    pub fn with_ca_certs(mut self, ca_certs: usize) -> Self {
        self.ca_certs = ca_certs;
        self.dir_cas = ca_certs;
        self
    }

    /// A profile whose escrow seals across `servers` servers.  Escrow slots
    /// are the advertisement's servers, so this sizes the realm too: every
    /// server has to be attested by its peers to verify, hence `attested`.
    #[must_use]
    pub fn with_escrow_servers(mut self, servers: usize) -> Self {
        self.escrow_servers = servers;
        self.servers = servers;
        self.attested = servers.saturating_sub(1);
        self
    }

    /// Sizes to sweep, each a multiple of `base`: `smoke` stays shallow and
    /// `large` goes deep, so one bench file serves both.
    #[must_use]
    pub fn sweep(&self, base: usize) -> Vec<usize> {
        let mults: &[usize] = match self.kind {
            ProfileKind::Smoke => &[1, 4],
            ProfileKind::Large => &[1, 4, 16, 64],
            _ => &[1, 4, 16],
        };
        mults.iter().map(|m| base * m).collect()
    }

    /// Metadata recorded with the run's results.
    #[must_use]
    pub fn metadata(&self) -> Value {
        json!({
            "profile": self.kind.name(),
            "ca": self.ca.name(),
            "servers": self.servers,
            "ca_certs": self.ca_certs,
            "dir_cas": self.dir_cas,
            "keytab_entries": self.keytab_entries,
            "escrow_servers": self.escrow_servers,
            "leaves": self.leaves,
            "attested": self.attested,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CaKind, Profile};

    #[test]
    fn production_defaults_to_ec() {
        let p = Profile::named("production").expect("production");
        assert_eq!(p.ca, CaKind::EcP256);
        assert!(p.servers >= 2);
    }

    #[test]
    fn pqproduction_selects_ml_dsa() {
        assert_eq!(
            Profile::named("pqproduction").expect("pqproduction").ca,
            CaKind::MlDsa65
        );
    }

    #[test]
    fn unknown_profile_is_none() {
        assert!(Profile::named("nope").is_none());
    }

    #[test]
    fn metadata_has_every_size() {
        let m = Profile::named("smoke").expect("smoke").metadata();
        for key in [
            "profile",
            "ca",
            "servers",
            "ca_certs",
            "keytab_entries",
            "escrow_servers",
            "leaves",
        ] {
            assert!(m.get(key).is_some(), "missing {key}");
        }
    }
}
