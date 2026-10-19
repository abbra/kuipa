//! Shared test support (also used by the playground example): test
//! certificates, an ephemeral MIT realm, and a directory backed by it.

#![allow(dead_code)]

pub mod certs;
pub mod directory;
pub mod dns;
pub mod kdc;
