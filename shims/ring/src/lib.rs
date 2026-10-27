//! The `ring` 0.17 API backed by OpenSSL, so DNS-over-TLS and DNS-over-HTTPS
//! (hickory's `tls-ring`/`https-ring` features, and rustls's `ring` feature)
//! verify and encrypt through the system OpenSSL instead of building ring's
//! vendored `BoringSSL` — the same choice `shims/rand` and `rustls-native-ossl`
//! make for the rest of the workspace.
//!
//! Patched in for `ring` in the workspace `Cargo.toml`.  The implementation
//! is `ring-native-ossl`, from the same native-ossl project as
//! `rustls-native-ossl`; this shim only binds it to the name and version
//! consumers require.

pub use ring_native_ossl::*;
