# Blind signing with unmodified ML-DSA — design

## 1. Goal and constraints

* The signer runs **standard FIPS 204 ML-DSA** exactly as shipped in OpenSSL
  (default or FIPS provider, or an HSM behind a provider). No changes to key
  generation, signing, or the signature format.
* The signer must not learn the message it signs.
* The output should be verifiable by standard ML-DSA verifiers wherever
  possible.

## 2. Classic blind signatures and why ML-DSA resists them

A blind signature scheme (Chaum) has two security properties:

1. **One-more unforgeability.** After `q` signing sessions the user cannot
   output `q + 1` valid message/signature pairs.
2. **Blindness.** The signer cannot tell which session produced a given
   message/signature pair. This covers both *message hiding* and
   *unlinkability*.

Blind RSA (RFC 9474) uses the multiplicative homomorphism of RSA. Lattice
Fiat–Shamir schemes have no such homomorphism. ML-DSA computes
`c̃ = H(μ ‖ w1)` inside the signer, and its rejection sampling depends on the
secret key. Every known lattice blind signature scheme therefore changes the
signing algorithm, for example by adding interactive masking, extra
rejection rounds, or a different key structure. That rules them out here.

### 2.1 Impossibility of unlinkability with an unmodified signer *and* verifier

Suppose the final signature `σ*` on message `m*` must pass the standard
`ML-DSA.Verify(pk, m*, σ*)`, and the signer only runs standard
`ML-DSA.Sign` on inputs of the user's choice. The signer can log every
signature it outputs. Then:

* If `σ*` is one of the logged signatures, the signer links the session
  directly.
* If not, the user produced a new valid pair `(m*, σ*)`. If `m*` was signed
  in some session, the user has produced a new signature on an
  already-signed message, which breaks **strong** unforgeability (ML-DSA is
  SUF-CMA). If `m*` was never signed, the user has broken EUF-CMA.

So unlinkability with an unmodified ML-DSA signer and verifier would break
ML-DSA. **At least one side has to change, or unlinkability has to be given
up.** This crate keeps both sides standard and provides message hiding.
§6 describes the upgrade that adds unlinkability while keeping the *signer*
unchanged.

## 3. The construction

FIPS 204 Algorithm 7 (`ML-DSA.Sign_internal`) begins with

```
tr = H(pk, 64)
μ  = H(tr ‖ M′, 64)          (H = SHAKE256)
```

FIPS 204 §6.2 and OpenSSL (`OSSL_SIGNATURE_PARAM_MU`, `EVP_MD-ML-DSA-MU`)
allow μ to be computed **outside** the cryptographic module, with the
module signing μ directly. The protocol builds on this.

**Public parameters:** signer public key `pk`, optional context string
`ctx` (≤ 255 bytes).

```
Requester(pk, ctx, m)                               Signer(sk)
salt ←$ {0,1}^256         (OpenSSL private DRBG)
tr   = SHAKE256(pk, 64)
μ    = SHAKE256(tr ‖ 0x00 ‖ |ctx| ‖ ctx ‖ salt ‖ m, 64)
                       ───────── μ (64 B) ─────────▶
                                                    authorise the request
                                                    σ = ML-DSA.Sign(sk, μ)   [OpenSSL, mu=1]
                       ◀──────── σ ────────────────
require ML-DSA.Verify(pk, μ, σ)   [OpenSSL, mu=1]
output  (salt, σ)
```

**Verification.** `(salt, σ)` is a valid blind signature on `m` iff
`ML-DSA.Verify(pk, salt ‖ m, σ, ctx)` holds. This is pure ML-DSA, because
`0x00 ‖ |ctx| ‖ ctx ‖ (salt ‖ m)` is exactly `M′` for the message
`salt ‖ m`. Any FIPS 204 verifier accepts it, including
`openssl pkeyutl -verify -rawin`.

**Wire sizes**

| set       | request | response | final signature |
|-----------|---------|----------|-----------------|
| ML-DSA-44 | 64      | 2420     | 32 + 2420       |
| ML-DSA-65 | 64      | 3309     | 32 + 3309       |
| ML-DSA-87 | 64      | 4627     | 32 + 4627       |

## 4. Security analysis

**Message hiding.** The signer sees only
`μ = SHAKE256(tr ‖ … ‖ salt ‖ m)` with a fresh, uniformly random 256-bit
salt. In the random-oracle model μ is uniformly distributed and independent
of `m`, whatever the entropy of `m`. The salt is what makes this work: with
`salt` omitted, low-entropy messages such as a "yes/no" vote could be found by
brute force. The salt is kept in an `OPENSSL_cleanse`-on-drop `SecretBuf`
until finalisation.

**One-more unforgeability.** The signer is a signing oracle on chosen μ, so
this reduces to EUF-CMA of `ML-DSA.Sign_internal`. ML-DSA's Fiat–Shamir
proof treats μ as the message, so this is the standard notion. To output
`q + 1` distinct valid `(m, salt, σ)` after `q` queries, the user needs
either:

* a signature on a μ that was never queried, which is a forgery; or
* two `(salt, m)` inputs with the same μ, which is a 512-bit SHAKE256
  collision.

**Malicious signer.** The requester verifies σ against μ before accepting
it, so a faulty or malicious signer cannot hand out an unusable signature.
The signer can still deny service.

**Fault attacks on the signer.** The requester chooses μ freely and can
repeat it, which is the setting differential fault attacks on Dilithium-style
signing exploit. Two countermeasures are built in:

* **Hedged signing only.** OpenSSL's `deterministic` parameter is never set,
  so every signature uses fresh randomness `rnd`, even for a repeated μ.
  The test `signing_is_hedged` pins this.
* **Verify before release.** `blind_sign` verifies each signature against μ
  before returning it. A faulty computation, whose output can leak key
  material, is withheld as `Error::SigningFault`. The cost is one
  verification, a fraction of the signing time.

**Unlinkability: not provided** (§2.1). The final σ is byte-identical to the
response, and the test `signer_can_link_final_signature_to_its_response`
asserts this.

## 5. Operational requirements

* **Dedicated key.** The signer will sign any message chosen by any
  authorised requester. Never reuse a blind-signing key for certificates,
  code signing, tokens of another protocol, and so on. Bound to the plain
  `ML-DSA.Sign` API, an attacker could obtain a signature on any message
  `X`: compute `μ_X` and submit it.
* **Context is not enforced.** `ctx` is folded into μ by the requester and
  the signer cannot check it. It separates domains *for verifiers* only.
  Public metadata (key epoch, token type) has to be expressed by using
  separate keys, as with RFC 9474 tokens.
* **Authorisation is outside the crate.** Rate limiting, payment, and
  eligibility checks must happen before `SigningKey::blind_sign`, because
  each call mints exactly one signature.
* **FIPS.** External-μ signing is an approved mode in FIPS 204. The OpenSSL
  FIPS provider's indicator stays "approved". The SHAKE256 computation of μ
  on the requester side uses the default provider and is not a
  key-dependent operation.

* **System crypto policy.** The crate enforces the system-wide policy
  (Fedora/RHEL crypto-policies), because OpenSSL does not do it for us:
  * **OpenSSL doesn't enforce it here.** crypto-policies reaches OpenSSL
    only as the `SignatureAlgorithms` list of the `system_default` SSL
    configuration, which libssl applies to TLS handshakes. `EVP_PKEY_sign`
    ignores it; an ML-DSA-44 signature succeeded under a policy listing only
    `mldsa87`.
  * **How it's read.** native-ossl's `system_policy::SystemPolicy` reads the
    list with OpenSSL's own configuration loader (`OPENSSL_CONF`, or
    `OPENSSLDIR/openssl.cnf`), once per process. A parameter set is allowed
    when the list contains `mldsa44`/`mldsa65`/`mldsa87`. No configuration
    or no list means no restriction, as for TLS. An unreadable configuration
    fails closed.
  * **Where it's enforced.** Key generation, `blind_sign`,
    `Requester::blind`, `PendingSignature::finalize` and
    `VerifyingKey::verify` refuse a disabled parameter set with
    `Error::DisabledBySystemPolicy`. Keys can still be loaded, so they can
    be inspected and rotated.
  * **Fallback.** Where the library chooses,
    `ParameterSet::preferred()` and `SigningKey::generate_preferred()` take
    the first allowed set in the order ML-DSA-65, ML-DSA-87, ML-DSA-44.
    Under a CNSA 2.0-style policy that is ML-DSA-87.
  * **Changing the policy.** Signatures under a disabled parameter set stop
    verifying when the policy changes. Rotate the blind-signing key to an
    allowed parameter set first.

## 6. Upgrade path to full blindness (signer unchanged)

The generic construction of Fischlin (CRYPTO 2006), as used for lattices by
del Pino–Katsumata (CRYPTO 2022) and Beullens et al. (CCS 2023), keeps the
signer exactly as it is here:

1. The requester commits `com = μ`. μ is already a hiding and binding
   commitment to `m` with opening `salt`.
2. The signer returns `σ = ML-DSA.Sign(sk, com)`. **This is the current
   `SigningKey::blind_sign`.**
3. The requester outputs a **NIZK proof of knowledge** of `(salt, σ)` such
   that `ML-DSA.Verify_internal(pk, SHAKE256(tr ‖ … ‖ salt ‖ m), σ) = 1`.

The verifier checks the proof instead of an ML-DSA signature. This restores
unlinkability, and the signer and its OpenSSL or HSM key handling remain
unchanged. Only `PendingSignature::finalize` and `VerifyingKey::verify` would
need a ZK variant.

The cost is the proof system. The statement includes:

* about 10 Keccak-f[1600] permutations (μ, `c̃ = H(μ ‖ w1)`, and
  `SampleInBall`);
* one linear map over `Z_q`, `A·z − c·t1·2^d`, which is cheap because
  `A` and `t1` are public;
* `HighBits`/`UseHint` decompositions and an `‖z‖∞` range check over
  1024–1792 coefficients.

Practical candidates are LaBRADOR/LNP-style lattice proofs (tens of KB)
and VOLE-in-the-head or Ligero-style proofs, such as Longfellow-zk for
hash-heavy circuits (hundreds of KB). Both are substantial independent
implementations. They are deliberately out of scope for this crate, whose
types are shaped so that such a module can be added without touching the
signer.

## 7. Implementation notes

* All cryptography goes through OpenSSL via `native-ossl`:
  * SHAKE256 for `tr` and μ;
  * `EVP_PKEY_sign_message_init` with `mu=1` for signing;
  * `EVP_PKEY_verify_message_init` with `mu=1` for verifying;
  * `RAND_priv_bytes` for the salt.
* `VerifyingKey::verify` uses the external-μ verify path so that the
  message is streamed into SHAKE256 rather than copied to prepend the salt.
  It is equivalent to pure ML-DSA verification of `salt ‖ m`, and the tests
  check that against OpenSSL's pure-mode verifier.
* The tests cross-check the crate's μ against OpenSSL's own `ML-DSA-MU`
  digest for all parameter sets and for empty and 255-byte contexts, where
  OpenSSL provides that digest (OpenSSL 3.5 does not; the crate itself
  needs only the `mu` signing parameter, which 3.5 has). Without it, the
  pure-mode verification above still checks μ indirectly.

## 8. Uses in kuipa

* **Vouchers** (`docs/DESIGN.md` §9). A provisioner blinds a
  voucher message naming realm, host and host group; the issuer signs the
  64-byte μ with a dedicated voucher key (§5) and counts it against a
  quota. One-more unforgeability makes that count exact, and message hiding
  keeps the issuer from learning which hosts it admits. The realm verifies
  vouchers as ordinary ML-DSA signatures on `salt ‖ m`, with the context
  `ipa-ku-enroll/v1 voucher`. The missing unlinkability (§2.1) does not
  matter there: the voucher names its host anyway.
* **Not for Tang.** The signer sees the signature it returns, so a blind
  signature cannot serve as a key the server must not learn. `tang-pqc`
  uses ML-KEM instead and documents what that costs (`tang-pqc` DESIGN §2,
  §5).
