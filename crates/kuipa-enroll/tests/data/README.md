# Test data

`mtc-demo-ca.pem` and `mtc-demo-leaf.pem` come from the test corpus of the
IETF plants WG Merkle Tree Certificates demo
(<https://github.com/ietf-plants-wg/merkle-tree-certs>, draft-05,
`demo-bin generate`), as Akāmu's interop tests carry them
(`tests/fixtures/mtc_demo/ca_cert.pem` and `cert_0_0.pem`).  The first is
the demo's unsigned (RFC 9925) Merkle Tree CA certificate; the second a
certificate that CA issued, with an `MTCProof` in place of a signature.
Both use the experimental OIDs under 1.3.6.1.4.1.44363.47.

`ipa-ca.der` and `pkinit-ca.der` (also under `kuipa-tools/tests/data`) are
self-signed EC P-256 CA certificates made with `openssl req -x509` for
`O=EXAMPLE.TEST`; their private keys were discarded, so they stand in for
an IPA CA and a PKINIT anchor and can issue nothing.
