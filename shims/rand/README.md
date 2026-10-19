# rand (shim)

A replacement for the part of the `rand` 0.10 API that `hickory` uses:
DNS query IDs, source ports, randomised name case and start-up jitter.
Every value comes from OpenSSL's DRBG (`RAND_bytes`), through
[`native-ossl`](https://crates.io/crates/native-ossl). As a result, no
RustCrypto generator is linked into kuipa.

The workspace `Cargo.toml` patches it in for `rand`, through
`[patch.crates-io]`. The `deps` CI job checks that no RustCrypto crate
reappears.

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
