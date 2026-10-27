//! kuipa: post-quantum enrollment and keytab protection for FreeIPA.
//!
//! This crate implements the protocol of `docs/DESIGN.md` without doing any
//! I/O: messages, key schedules and verification on the client side, and on
//! the server side a state machine ([`EnrollServer`]) that delegates every
//! directory operation to a [`Directory`] implemented over LDAP and GSSAPI.
//!
//! * [`delegation`], [`anchors`]: server delegations and the anchor
//!   exchange between servers (§4.2).
//! * [`realm`]: realm advertisements and their verification (§4).
//! * [`join`]: join, rekey and stage requests (§5, §6).
//! * [`bundle`]: offline enrollment bundles (§8).
//! * [`escrow`]: sealed keytabs (§7).
//! * [`seal`], [`passkey`]: user seals and the passkey factor (§7.6).
//! * [`shards`]: recovery shards, an N-of-M paper key with error correction
//!   (`docs/DESIGN-recovery.md` §2.1).
//! * [`sign`]: Kerberos-bound signing statements (`docs/DESIGN-sign.md`).
//! * [`tlog`]: typed transparency logs with tombstones and witness
//!   cosignatures (`docs/DESIGN-tlog.md`).

pub mod anchors;
pub mod bundle;
pub mod certs;
pub mod delegation;
pub mod enrollment;
pub mod epoch;
pub mod error;
pub mod escrow;
pub mod join;
pub mod keys;
pub mod keytab;
pub mod merkle;
pub mod passkey;
pub mod payload;
pub mod realm;
pub mod seal;
pub mod server;
pub mod shards;
pub mod sign;
pub mod tlog;
#[cfg(feature = "tls")]
pub mod tls;
pub mod trust;
pub mod voucher;

pub use error::{Error, Result};
pub use server::{Directory, EnrollServer};
