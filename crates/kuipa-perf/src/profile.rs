//! Benchmark profiles: the sizes a run measures, and which CA it uses.
//!
//! Selected with `KUIPA_BENCH_PROFILE=smoke|production|pqproduction|large`;
//! production is the default.  Profiles are *fixture sizes* — benches scale
//! around them (a scaling bench still sweeps its own parameter axis).

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

/// The sizes a benchmark run works at.
#[derive(Clone, Debug)]
pub struct Profile {
    /// The profile name (`smoke`, `production`, …).
    pub name: String,
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
    /// The base sizes shared by `production` and `pqproduction`.
    #[must_use]
    fn base(name: &str) -> Self {
        match name {
            "smoke" => Self {
                name: name.into(),
                servers: 2,
                ca_certs: 1,
                dir_cas: 1,
                keytab_entries: 1,
                escrow_servers: 2,
                leaves: 3,
                attested: 1,
                ca: CaKind::EcP256,
            },
            "large" => Self {
                name: name.into(),
                servers: 8,
                ca_certs: 4,
                dir_cas: 4,
                keytab_entries: 6,
                escrow_servers: 8,
                leaves: 64,
                attested: 7,
                ca: CaKind::EcP256,
            },
            _ => Self {
                name: name.into(),
                servers: 4,
                ca_certs: 1,
                dir_cas: 2,
                keytab_entries: 4,
                escrow_servers: 4,
                leaves: 8,
                attested: 3,
                ca: CaKind::EcP256,
            },
        }
    }

    /// The profile named by `name`, or `None` if unknown.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        let mut p = match name {
            "smoke" | "production" | "pqproduction" | "large" => Self::base(name),
            _ => return None,
        };
        if name == "pqproduction" {
            p.ca = CaKind::MlDsa65;
        }
        Some(p)
    }

    /// The profile named by `KUIPA_BENCH_PROFILE`, or `production`.
    ///
    /// # Panics
    ///
    /// If `KUIPA_BENCH_PROFILE` names an unknown profile.
    #[must_use]
    pub fn from_env() -> Self {
        let raw = std::env::var("KUIPA_BENCH_PROFILE").unwrap_or_default();
        let name = if raw.is_empty() {
            "production"
        } else {
            raw.as_str()
        };
        Self::named(name).unwrap_or_else(|| panic!("unknown KUIPA_BENCH_PROFILE '{name}'"))
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

    /// A profile whose anchors vouch for `leaves` claims.
    #[must_use]
    pub fn with_leaves(mut self, leaves: usize) -> Self {
        self.leaves = leaves;
        self
    }

    /// Sizes to sweep, each a multiple of `base`: `smoke` stays shallow and
    /// `large` goes deep, so one bench file serves both.
    #[must_use]
    pub fn sweep(&self, base: usize) -> Vec<usize> {
        let mults: &[usize] = match self.name.as_str() {
            "smoke" => &[1, 4],
            "large" => &[1, 4, 16, 64],
            _ => &[1, 4, 16],
        };
        mults.iter().map(|m| base * m).collect()
    }

    /// Metadata recorded with the run's results.
    #[must_use]
    pub fn metadata(&self) -> Value {
        json!({
            "profile": self.name,
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
