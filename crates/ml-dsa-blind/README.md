# ml-dsa-blind

Blind (message-hiding) signing with **unmodified FIPS 204 ML-DSA**, built on
OpenSSL through [`native-ossl`](https://crates.io/crates/native-ossl).

* The signer runs stock OpenSSL ML-DSA in external-μ mode and sees only a
  64-byte value.
* The result is an ordinary ML-DSA signature on `salt ‖ message`:

  ```sh
  openssl pkeyutl -verify -pubin -inkey pk.pem -rawin -in signed-message.bin -sigfile sig.bin
  ```

* It provides message hiding and one-more unforgeability. It does **not**
  provide unlinkability, which no scheme with both a stock ML-DSA signer and
  a stock ML-DSA verifier can offer. See [DESIGN.md](DESIGN.md) for the
  argument and the zero-knowledge upgrade path that keeps the signer
  unchanged.

## Example

```rust
let signing_key = SigningKey::generate(ParameterSet::MlDsa65)?;
let requester = Requester::new(signing_key.verifying_key().clone());

let (request, pending) = requester.blind(b"message")?;   // send request (64 B)
let response = signing_key.blind_sign(&request)?;        // signer, blind
let signature = pending.finalize(&response)?;            // verify + unblind

signing_key.verifying_key().verify(&Context::default(), b"message", &signature)?;
```

Use a **dedicated** key for blind signing: the signer cannot see what it signs.

Requires OpenSSL ≥ 3.5 (ML-DSA with the `mu` parameter). Run the demo with
`cargo run -p ml-dsa-blind --example demo -- <dir>`.

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
