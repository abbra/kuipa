# tang-pqc

Post-quantum key escrow in the style of Tang/Clevis, built only from
standard primitives in OpenSSL (via
[`native-ossl`](https://crates.io/crates/native-ossl)).

* **ML-KEM** (FIPS 203) replaces the P-521 McCallum-Relyea exchange.
* **ML-DSA** (FIPS 204) replaces ES512 for signing advertisements.
  * As in Tang, the advertisement is a JWS over a JWK Set.
  * Keys use the RFC 9964 `AKP` key type, and clients pin RFC 7638 `thp`
    thumbprints.
  * Server keys are stored as seed-form private JWKs.
  * ML-KEM keys follow `draft-ietf-jose-pqc-kem` (provisional).

Recovering the key needs both the stored binding metadata and the server.
The server is stateless and never learns the key. Unlike McCallum-Relyea,
the server sees one of two key shares during recovery and can link repeated
recoveries of the same volume. Network observers can't: the stored
ciphertext travels sealed to the server. [DESIGN.md](DESIGN.md) covers the
details and the trade-offs.

## Example

```rust
// server
let signing = SigningKey::generate(SignatureAlg::MlDsa65)?;
let thp = *signing.public().thumbprint();
let server = Server::new(&[signing], vec![ExchangeKeyPair::generate(KemAlg::MlKem768)?])?;

// clevis encrypt
let (binding, key) = server.advertisement().verify(&thp)?.provision(None)?;

// clevis decrypt
let (request, pending) = binding.recovery_request(server.exchange_key(binding.kid())?)?;
let key_again = pending.finish(&server.recover(&request)?)?;
```

Run the example with `cargo run -p tang-pqc --example escrow [768|1024]`.
Requires OpenSSL ≥ 3.5.

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
