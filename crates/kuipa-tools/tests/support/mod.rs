//! Shared test support (also used by the playground example): test
//! certificates, an ephemeral MIT realm, and a directory backed by it.

#![allow(dead_code)]

pub(crate) mod certs;
pub(crate) mod directory;
pub(crate) mod dns;
pub(crate) mod kdc;
