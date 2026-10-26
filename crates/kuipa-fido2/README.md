# kuipa-fido2

A thin, safe wrapper around libfido2 for kuipa's passkeys (DESIGN.md
§7.6.5): the client talks to the authenticator at the CTAP level, as
SSSD's `passkey_child` does, with no browser in between.

* List the authenticators attached to the host
* Get an assertion over a raw `clientDataHash`, from an allow list of
  credentials, with the `hmac-secret` extension when asked
* Make a credential with `hmac-secret`, trying COSE algorithms in turn

Every algorithm the installed libfido2 knows works: ES256, ES384, EdDSA
and RS256, and the post-quantum ML-DSA-44, ML-DSA-65 and ML-DSA-87 with a
libfido2 built with ML-DSA support.  The calls block, waiting for a touch.

## Requirements

`libfido2-devel` on Fedora.

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
