//! Benchmark fixtures for kuipa: deterministic synthesis, profile sizes,
//! real CA certificates, and an in-memory directory.
//!
//! This is a dev-dependency of the crates under test; their `benches/`
//! targets build realms, keytabs, and requests from here and time only the
//! library call.

pub mod certs;
pub mod dir;
pub mod ledger;
pub mod prng;
pub mod profile;
pub mod realm;

pub use certs::chain;
pub use dir::{ADMIN, BenchDirectory, HOST, REALM, fake_binding, gss_token};
pub use ledger::{Ledger, ledger as anchor_ledger};
pub use prng::SplitMix64;
pub use profile::{CaKind, Profile};
pub use realm::{DOMAIN, Realm, now, server_name};
