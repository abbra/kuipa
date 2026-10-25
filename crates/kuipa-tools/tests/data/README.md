# Test data

`ipa-ca.der` and `pkinit-ca.der` are self-signed EC P-256 CA certificates
made with `openssl req -x509` for `O=EXAMPLE.TEST`; their private keys were
discarded, so they stand in for an IPA CA and a PKINIT anchor and can issue
nothing.  The same files are in `kuipa-enroll/tests/data`.

`mtc-demo-ca.pem` is the unsigned (RFC 9925) Merkle Tree CA certificate,
CA ID 32473.1, of the IETF plants WG demo corpus
(<https://github.com/ietf-plants-wg/merkle-tree-certs>, `plants-06`), as in
`kuipa-enroll/tests/data`; the playground advertises it in a CA chain.
