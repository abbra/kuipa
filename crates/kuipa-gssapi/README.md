# kuipa-gssapi

Safe Rust bindings to the MIT Kerberos GSSAPI library, as kuipa uses it.

* Accepting and initiating security contexts, including one-message
  contexts with channel bindings
* Server credentials from a keytab, and S4U2Self and S4U2Proxy
  credentials
* Pseudo-random function (PRF) output from an established context
* An in-process, FAST-armoured password `kinit`
* Per-thread credential caches

```rust
let cred = kuipa_gssapi::GssServerCred::acquire("HTTP", "/etc/httpd/http.keytab")?;
match kuipa_gssapi::accept_token(&cred, &token, None)? {
    kuipa_gssapi::AcceptStep::Complete { out_token, principal } => { /* authenticated */ }
    kuipa_gssapi::AcceptStep::Continue { out_token, ctx } => { /* send out_token back */ }
}
```

## Requirements

You need the MIT Kerberos development files: `krb5-devel` on Fedora, or
`libkrb5-dev` on Debian and Ubuntu. The build script finds the library
through pkg-config.

## License

This crate is part of [kuipa](../../README.md). It is derived from the
GSSAPI bindings of the ahdapa project (`ahdapa-gssapi`). It is licensed
under the GNU General Public License v3.0 or later. See
[LICENSE](LICENSE).
