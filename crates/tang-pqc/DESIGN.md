# tang-pqc — post-quantum Tang/Clevis key escrow

## 1. What Tang does today

Tang binds a key to the presence of a network server. A Clevis-encrypted
volume unlocks automatically only while it can reach its Tang server. The
McCallum-Relyea (MR) exchange over P-521 provides this:

| Phase     | Client                                       | Server       |
|-----------|----------------------------------------------|--------------|
| setup     |                                              | `S = s·G`, signed advertisement (ES512) |
| provision | `c ←$`, `K = c·S`, store `C = c·G`           | —            |
| recover   | `e ←$`, send `X = C + e·G`                   | `Y = s·X`    |
|           | `K = Y − e·S`                                |              |

Properties:

* **P1, two-factor:** recovering `K` needs the metadata `C` and the server key `s`.
* **P2, server blindness:** the server never learns `K`. Each `X` is uniformly
  random, so the server learns nothing during recovery.
* **P3, unlinkability:** recoveries of the same volume look unrelated.
* **P4, stateless server:** no per-client database.
* **P5, authenticated setup:** advertisements are signed, and clients pin a
  signing-key thumbprint (`thp`).

A quantum attacker breaks MR completely. With the disk alone it can compute
`s` from `S` (or `c` from `C`) and recover `K`. Stolen disks are long-lived,
so this is a *harvest-now-decrypt-later* problem: the threat applies to
volumes provisioned today.

## 2. Why MR has no drop-in post-quantum replacement

MR is an *oblivious PRF*, and it relies on the group structure of EC points
for blinding. Standard PQC primitives lack that structure:

* **ML-DSA blind signing** (`crates/ml-dsa-blind`): the signer sees the
  signature it produces. A signature used as `K` would therefore be known
  to the server, which loses P2. The crate hides the *message* from the
  signer, not the signature, so it serves kuipa's vouchers (`docs/DESIGN.md`
  §9) but cannot replace MR.
* **ML-KEM ciphertext blinding:** FIPS 203 decapsulation re-encrypts the
  plaintext and rejects any modified ciphertext. Dropping that check (raw
  K-PKE) turns the server into a lattice decryption oracle, which leaks the
  secret key.
* **Post-quantum OPRFs** from lattices or isogenies would keep P1–P5, but
  none is standardised or available in OpenSSL.

This design therefore uses **standard ML-KEM and ML-DSA only**, keeps P1,
P4, P5 and post-quantum confidentiality, and weakens P2 and P3 in specific,
documented ways (§5).

## 3. Protocol

**Primitives:** all from OpenSSL via `native-ossl`:

* ML-KEM-768 or ML-KEM-1024 (FIPS 203);
* ML-DSA-65 or -87 (FIPS 204); ML-DSA-44 only if the client policy allows
  it;
* HKDF (RFC 5869) with the suite hash `H`;
* AES-256-GCM;
* `RAND_priv_bytes`.

`H` is SHA-256 with ML-KEM-768 and SHA-384 with ML-KEM-1024 (CNSA 2.0).
Thumbprints are always SHA-256 (RFC 7638, as Clevis uses). `‖` is
concatenation.

### 3.1 Server keys and advertisement

All keys are JOSE `"kty": "AKP"` keys (RFC 9964; §7 has the details).

* **Signing keys:** one or more ML-DSA keys. `thp` is the RFC 7638
  thumbprint of the key.
* **Exchange keys:** one or more ML-KEM key pairs `(ek, dk)`. `kid` is the
  RFC 7638 thumbprint of `ek`.
* **Advertisement:** as in Tang, a JWS in General JSON Serialization.
  * The payload is a JWK Set holding the signing keys
    (`key_ops: ["verify"]`) and the exchange keys
    (`key_ops: ["deriveKey"]`).
  * There is one signature per signing key, with protected header
    `{"alg":"ML-DSA-…","cty":"jwk-set+json","iat":…,"exp":…}`.
  * `iat`/`exp` are JWT claims replicated as header parameters
    (RFC 7519 §5.3), so the signature covers them. Classic Clevis ignores
    header members it does not know.
  * The server re-signs once half the validity has passed (default 7 days,
    `Server::with_validity`), so clients always see at least half the
    lifetime left.
  * Each signature is pure ML-DSA with an empty context, as RFC 9964
    requires.

**Client trust check.**

* The trusted `thp` must belong to an ML-DSA key in the set whose `key_ops`
  allow `verify`.
* A signature whose header `alg` matches that key must verify over
  `protected ‖ "." ‖ payload`.
* Signatures with `crit` are ignored.
* The client `Policy` must be satisfied:
  * the trusted key's algorithm is allowed (default ML-DSA-65/87;
    `Policy::cnsa2()` allows only ML-DSA-87);
  * the signature carries `iat`/`exp`, the advertisement is current within
    the allowed clock skew (default 5 minutes), and `exp − iat` is at most
    the maximum validity (default 30 days). `allow_unexpiring()` exists only
    for servers that cannot be upgraded.
* Exchange keys whose KEM the policy does not allow are dropped, and
  non-AKP keys (classic `ECMR`) are never used. A downgraded advertisement
  therefore yields `NoExchangeKey`, never a classic binding.
* The other keys are imported only after the signature check. A verified
  `Advertisement` value can only come from this check.

### 3.2 Provisioning (Clevis `encrypt`, works offline once the advertisement is trusted)

```
(ct, ss)      = ML-KEM.Encaps(ek_kid)
r            ←$ {0,1}^256
K ‖ confirm   = HKDF-H(salt="tang-pqc/v1", ikm = ss ‖ r,
                       info = "tang-pqc/v1 key" ‖ alg ‖ kid ‖ thp ‖ H(ct), L = 64)
store Binding = (alg, kid, thp, ct, r, confirm); use K; forget ss
```

Every stored field except `confirm` is bound into the derivation, including
the trust anchor `thp`. Editing any of them on disk produces a clean
`RecoveryFailed`.

**Rebinding.** `Binding::rebind` takes a freshly verified advertisement and
returns a new key and binding. The client installs them by adding the new
LUKS keyslot and token first and then removing the old ones, so a crash
never leaves the volume locked. `rebind` refuses an advertisement verified
under a different `thp`, and it moves the binding to the current exchange
key after rotation. It serves `clevis luks regen` and policy migrations.

**Static bindings are the baseline.** A client *may* also rebind after
every unlock, but the security analysis never assumes it does. The client
is an unreliable narrator: it may crash before rebinding, boot from
read-only media, be restored from a header backup, or simply skip the step,
and a stateless server cannot tell the difference. Every property in §4 and
§5 holds for a binding that is used for the whole life of the volume.

### 3.3 Recovery (Clevis `decrypt`)

```
Client                                              Server
           ── GET /key/{kid} ──▶
           ◀── ek_kid (public JWK) ──
require thumbprint(ek_kid) == kid
(ct_t, ss_t)  = ML-KEM.Encaps(ek_kid)
k_req ‖ k_rsp = HKDF(ss_t, "tang-pqc/v1 transport" ‖ alg ‖ kid ‖ H(ct_t), L = 64)
           ── RecoveryRequest(alg, kid, ct_t, AES-256-GCM_k_req(ct)) ──▶
                                                    ss_t = ML-KEM.Decaps(dk_kid, ct_t)
                                                    ct   = Open_k_req(...)   (else refuse)
                                                    ss   = ML-KEM.Decaps(dk_kid, ct)
           ◀── RecoveryResponse(AES-256-GCM_k_rsp(ss)) ──
ss = Open_k_rsp(...)
K ‖ confirm' = HKDF(ss ‖ r, ...);  require confirm' == confirm  (constant time)
```

**Sealed request.** The binding's ciphertext `ct` never appears on the
wire. Each attempt carries a fresh transport encapsulation `ct_t`, so a
static binding produces unrelated-looking requests. Both directions are
encrypted under keys derived from `ss_t`, which only the client and the
holder of `dk_kid` know.

**Obtaining `ek_kid`.** The binding stores only the thumbprint `kid`. The
client fetches the key from `GET /key/{kid}` (`Server::exchange_key`,
`ExchangeKey::to_jwk_json`/`from_jwk_json`); `recovery_request` checks the
thumbprint, which authenticates the key without a signature check or a
clock. That matters in early boot, where the clock may be wrong. The server
answers for retired keys too, which are no longer advertised. A key taken
from a verified advertisement works as well. Storing `ek` next to the
binding avoids the round trip where space is not tight: kuipa's sealed
keytabs do that. In a LUKS2 token it would add 1184–1568 bytes per server
(§3.4).

**No client ephemeral key.** An earlier version encrypted the response to a
fresh client ML-KEM key. It adds no forward secrecy: whoever later obtains `dk_kid` computes
`ss = Decaps(dk_kid, ct)` from the ciphertext alone. The response key
derived from `ss_t` gives the same protection for one encapsulation instead
of a key generation, an encapsulation and a decapsulation, and shrinks the
response from 1149–1629 bytes to 57.

A zero GCM nonce is safe: `k_req` and `k_rsp` are distinct and each is used
once, since both come from a fresh encapsulation.

### 3.4 Sizes (bytes, measured by `examples/escrow.rs`)

| suite                    | `/adv` (JWS JSON) | binding | `/key` (JWK) | request | response |
|--------------------------|-------------------|---------|--------------|---------|----------|
| ML-KEM-768 + ML-DSA-65   | 10332             | 1226    | 1644         | 2238    | 57       |
| ML-KEM-1024 + ML-DSA-87  | 13912             | 1706    | 2157         | 3198    | 57       |

(The compression and LUKS2 figures below exclude the 45-byte `iat`/`exp`
header; it does not change the conclusions.)

The advertisement is about 1.6 times the size of the raw keys plus
signatures (6445 and 8787 bytes). The keys are base64url-encoded twice:
once as JWK `pub` members, and again inside the JWS payload. That is a
factor of about 1.78 for the keys.

**Compression inside the JWS is not worth it.**

* ML-DSA and ML-KEM public keys are packed coefficients plus a seed and are
  effectively random. Deflate and xz make the raw keys slightly larger.
  Compression only recovers base64's redundancy.
* JWS defines no `zip` header (RFC 7515; `zip` exists only for JWE in
  RFC 7516). A compressed payload would break standard RFC 9964
  verification.
* RFC 7797 unencoded payloads (`"b64": false`) remove only the outer encoding
  (10287 → 8881). They need `crit`, which Tang does not use and JOSE
  libraries support unevenly.

**Compress the transport instead.** HTTP `Content-Encoding` needs no format
change (bytes):

| suite                    | as served | gzip -9 | brotli -q 11 |
|--------------------------|-----------|---------|--------------|
| ML-KEM-768 + ML-DSA-65   | 10287     | 7725    | 7507         |
| ML-KEM-1024 + ML-DSA-87  | 13867     | 10409   | 10125        |

**Store the binding, never the advertisement.** Clevis's classic Tang pin
embeds the advertised JWK Set in the JWE it keeps in the LUKS2 token,
base64url-encoded once more. That does not scale to post-quantum keys:

* With the default 16 KiB LUKS2 metadata area, `cryptsetup token import`
  accepts a token of about 11 000 bytes and rejects one of 12 000. This was
  measured with cryptsetup on a scratch image.
* The embedded JWK Set alone would be about 5.8 KB (ML-KEM-768) or 7.6 KB
  (ML-KEM-1024) per server. An `sss` policy over two Tang servers would not
  fit.
* `--luks2-metadata-size` raises the limit only at `luksFormat` time, so it
  does not help existing volumes.

The binding (1226 or 1706 bytes) plus `url` and `thp` is everything
recovery and `clevis luks regen` need, so that is all the pin stores (§6).

## 4. Security analysis

**P1, two-factor.** `K = HKDF(ss ‖ r, …)`.

* *Disk only* (`ct`, `r`, `confirm`, `ek`): getting `ss` means breaking
  ML-KEM IND-CCA2, which is post-quantum. `confirm` is an HKDF output and
  reveals nothing about `ss`, a 256-bit uniform value, so it gives no
  offline test.
* *Server only* (`dk`, logs of `ss`): `r` is a uniform 256-bit secret that
  never leaves the client. In the random-oracle model for HKDF, `K` is
  independent of everything the server knows.
* *Both:* recovery succeeds. This is the intended behaviour, identical to MR.

**Recorded traffic.** A passive attacker sees `kid`, `ct_t`, the sealed
`ct` and the sealed `ss`. Opening either needs `ss_t`, that is, the server's
`dk` (ML-KEM IND-CCA2). Even with `ss`, the attacker still needs `r` from
the disk. The attacker never sees `ct`, so it cannot replay it to the server
to obtain `ss`, and it cannot link recoveries of a static binding by their
content (`static_binding_requests_are_unlinkable_on_the_wire`).

**Active network attacker.**

* Forged advertisement: rejected, since ML-DSA is EUF-CMA and the `thp` is
  pinned. The unit tests in `adv.rs` cover:
  * exchange-key substitution;
  * removing the trusted key;
  * a header `alg` that doesn't match the key;
  * unknown `crit` parameters;
  * `key_ops` that don't allow the key's role.
* Replayed advertisement: rejected once expired. Without an expiry, an old
  validly signed advertisement could bind clients to a retired, or later
  compromised, exchange key. Tang has this weakness; see
  `expired_advertisement_is_stale` and `advertisements_expire_and_refresh`.
  Extending `exp` invalidates the signature.
* Downgrade: weaker suites and classic-only key sets are refused by policy
  (`policy_restricts_algorithms`, `classic_only_exchange_keys_cannot_be_bound`).
* Substituted exchange key at `GET /key/{kid}`: rejected, since the
  thumbprint must equal the binding's `kid` (`Error::KeyMismatch`).
* Tampered recovery request: refused by the server, because the sealed
  `ct` does not open (`requests_need_the_right_key_and_are_authenticated`).
  A replayed request yields a response only the original client can open.
* Tampered or replayed recovery response: rejected. The response key is
  unique to this request's `ct_t`, and `confirm` catches anything else.
  `confirm` also authenticates the server: only the holder of `dk_kid` can
  return the right `ss`. See `responses_are_bound_to_their_request`.
* What remains: denial of service, and querying the server with a stolen
  binding. Both are the same as in MR.

**Malformed inputs.**

* Ciphertext lengths are checked before decapsulation, for `ct_t` on
  decoding and for the sealed `ct` after opening it.
* Keys from `GET /key/{kid}` go through the FIPS 203 encapsulation-key
  check on import.
* A modified `ct` decapsulates to a pseudorandom `ss` (implicit rejection),
  and `confirm` turns that into a clean `RecoveryFailed`.

**Fault attacks and side channels.** `POST /rec` is a decapsulation oracle
reachable from the network. ML-KEM's IND-CCA2 security covers the
mathematics, so the realistic risk is a side channel in the
re-encryption check. Run decapsulation in the FIPS provider or an HSM, and
rate-limit per `kid` and per source. MR has the same exposure: the server
computes `s·X` for arbitrary `X`.

**Key material in memory.**

* Seeds and derived keys live in `SecretBuf`s, which `OPENSSL_cleanse` on
  drop.
* Private JWKs are written straight into a `SecretBuf`, and a parsed `priv`
  string is cleansed when dropped.
* Keys generated or loaded by this crate keep their own seed, so OpenSSL is
  never asked to export it.
* The seed handed to OpenSSL key generation, and the `exported_seed`
  fallback for wrapped keys, pass through `OSSL_PARAM` arrays. native-ossl
  frees them with `OSSL_PARAM_clear_free` on OpenSSL 4.0 and later; with
  older OpenSSL those copies are freed without wiping.

**FIPS.** Every algorithm used is approved. Seeded key generation goes
through OpenSSL's normal keygen, including its pairwise consistency test,
not through key import. The server's decapsulation key
and ML-DSA signing key can live in the OpenSSL FIPS provider or in an HSM;
the types accept any provider-backed `Pkey`.

## 5. Differences from McCallum-Relyea (read before deploying)

| property | MR | tang-pqc |
|---|---|---|
| P1 two-factor | ✓ | ✓ |
| P2 server learns nothing | ✓ | **server learns `ss`**, one of two 256-bit shares, during each recovery |
| P3 unlinkable recoveries | ✓ | unlinkable for network observers apart from `kid`, timing and source address; **linkable by the server**, which sees the same `ct` each time |
| P4 stateless server | ✓ | ✓ |
| P5 signed advertisement | ES512 | ML-DSA |
| quantum-safe disk-at-rest | ✗ | ✓ |

What the P2 and P3 gaps mean in practice:

* **P2.** A *malicious* Tang server that logs `ss` and later steals the disk
  metadata can recover `K`. Under MR, an honest-but-logging server that
  later steals the disk can also recover `K`, because it holds `s`. The
  P2 gap therefore matters only against a server that is honest when keys
  are rotated and deleted but not during recoveries. Rotating keys and
  deleting retired keys retires the logged `ss` values only if the logs are
  deleted too.
* **P2 lasts as long as the binding.** With static bindings (§3.2), a logged
  `ss` stays usable until the exchange key is retired *and* every binding
  on it is regenerated. Mitigations that do not depend on the client:
  * **`sss`.** Splitting the key across two or more independent tang-pqc
    servers (Clevis `sss`), or across tang-pqc and `tpm2`, means one
    server's log is never enough.
  * **The hybrid transition (§6).** Adding an MR share restores classical
    P2: a logged `ss` without the MR share is not enough.
  * **Key rotation with log hygiene.** Rotate exchange keys, regenerate
    bindings, delete retired keys and any logs of the period.

  A client that does rebind after unlocking retires its logged `ss` early,
  but an *old copy* of the header, such as a backup, still opens with it.
* **P3, server side.** The server sees the same `ct` on every unlock of a
  static binding, so it can count unlocks per volume and correlate them
  with source addresses. Only a post-quantum OPRF would remove that (§2).
* **P3, network side.** The sealed request hides `ct`, so observers see
  only `kid`, timing and addresses. To hide those as well, run Tang on a
  trusted management network (common practice already) or wrap recovery in
  TLS (the pin's `https` URLs, §6).

## 6. Deployment and migration

* **HTTP mapping** (same endpoints as Tang):
  * `GET /adv`: `SignedAdvertisement::to_json()`, served as
    `application/jose+json` like Tang. Honour `Accept-Encoding` and send it
    with `Content-Encoding: br` or `gzip`, which saves 25–27% (§3.4). Tang or
    a fronting proxy can do this. The Clevis side should request
    compression, e.g. `curl --compressed`.
  * `GET /adv/{thp}` (optional, as in Tang): the advertisement also signed
    by signing key `thp` when that key is retired, so a client that pinned
    it can follow a rotation. `Server` keeps no retired signing keys and
    does not serve it; kuipad does (`docs/DESIGN.md` §11.5).
  * `GET /key/{kid}`: `Server::exchange_key(kid)?.to_jwk_json()`, the
    public ML-KEM JWK, served as `application/jwk+json`, for advertised and
    retired keys alike. It is a new endpoint; Tang has no equivalent.
  * `POST /rec/{kid}`: binary request and response bodies
    (`application/vnd.tang-pqc.rec-req` and `application/vnd.tang-pqc.rec-rsp`).
    `kid` is the base64url thumbprint, as in Tang.
* **Key storage:** one private JWK file per key, as in Tang's
  `/var/db/tang`, written with `to_jwk()` and read with `from_jwk()`.
  * The files hold only the seed form (`priv`) that RFC 9964 mandates. A key
    imported without its seed (e.g. an expanded PKCS#8 key from an HSM
    export) cannot be written as a JWK; use PEM or keep it in the provider.
  * Rotation works like `tangd-rotate-keys`: generate new keys, then pass
    the old exchange keys to `Server::with_retired_keys`. Retired keys are
    hidden: still answered, no longer advertised. After
    `clevis luks regen`, delete them.
* **Mixed servers:** the JWK Set may also carry a classic Tang
  `ES512`/`ECMR` pair. Older Clevis clients select only `ECMR` keys and
  ignore the AKP keys; this crate ignores non-AKP keys. One server can
  therefore serve classic and post-quantum clients side by side during
  migration. Each kind of client verifies only the signatures it
  understands.
* **Clevis pin:** implemented as `crates/tang-pqc-clevis`, one binary that
  is the `tang-pqc` command and, linked as `clevis-encrypt-tang-pqc` /
  `clevis-decrypt-tang-pqc`, the Clevis pin `tang-pqc`
  (`docs/DESIGN.md` §10.7).
  * **Configuration:** `{"url": …, "thp": …}`, plus `adv` (an advertisement
    file, for offline provisioning) and `ca` (a PEM file to verify an
    `https` server). `thp` is required: there is no trust on first use.
  * **Encrypt:** fetch `URL/adv`, verify it against `thp` (falling back to
    `URL/adv/{thp}` after a rotation), provision a binding, and write a
    compact JWE: `"alg": "dir"`, `"enc": "A256GCM"`, `K` as the content key,
    and the protected header as AAD. The header's `clevis.tang-pqc` holds
    `url`, `thp`, the binding (base64url) and `ca` if set, about 2.5 KB. The
    advertisement is **not** embedded, unlike the classic Tang pin (see §3.4
    for the LUKS2 size limit).
  * **Decrypt:** fetch `URL/key/{kid}`, send the sealed request to
    `URL/rec/{kid}` (§3.3), and decrypt. Because the header is AAD, a
    changed URL, thumbprint or binding fails to decrypt.
  * **`clevis luks regen`** passes the old pin object back; the pin ignores
    the `binding` member and provisions afresh against the stored `thp`.
    The pin does not rebind after unlocking (§3.2).
  * **Offline provisioning** (`"adv": file`) reads the advertisement from a
    file and still does not store it. The file must be unexpired, so fetch
    it shortly before use.
  * **Boot:** `contrib/clevis/install.sh` installs the binary, the pin links
    and the dracut module `60clevis-pin-tang-pqc`, which also carries the
    crypto-policy files so the initramfs enforces the same policy (§6.1).
* **Hybrid transition:** combine with classical MR by setting
  `ikm = ss ‖ K_MR ‖ r`, so the key is safe if *either* system holds. This
  is the client-independent fix for P2 (§5): a server that logs `ss` still
  lacks `K_MR`, and MR keeps the server blind to it. It should be one
  combined pin whose token stores `C = c·G` and the thumbprint of the
  server's MR key, not the advertisement (the LUKS2 size limit, §3.4).
  Keeping `S` off the disk is no protection in itself, since `/adv` serves
  it to anyone: against a quantum attacker `K_MR` adds nothing, and the
  ML-KEM share alone keeps the disk safe at rest. That needs P-521 point
  addition and multiplication in Rust (`EC_POINT_add`/`EC_POINT_mul`, not
  exposed by `native-ossl` today), so it is not implemented yet.
* **OpenSSL hybrid KEMs** (`X25519MLKEM768`, `SecP384r1MLKEM1024`) were
  evaluated and not adopted.
  * They work for keygen, encapsulation and decapsulation through
    native-ossl, and their concatenated shared secret would be safe here,
    since HKDF binds the full hybrid ciphertext and key thumbprint.
  * But they have no PKCS#8/SPKI encoders and no JOSE registration, and their
    private keys export only in an OpenSSL-specific expanded form (2432 bytes
    for `X25519MLKEM768`).
  * That contradicts the seed-only JOSE key files. A protocol-level hybrid
    (a separate standard X25519 or P-384 JWK next to the ML-KEM key, with
    both secrets in the HKDF input) keeps standard key formats.
* **Algorithm choice:** ML-KEM-768 + ML-DSA-65 by default. Use
  ML-KEM-1024 + ML-DSA-87 for CNSA 2.0 or category-5 requirements.
  ML-KEM-512 is deliberately not offered: bindings live as long as the
  volume does.

### 6.1 System crypto policy

The system-wide policy (Fedora/RHEL crypto-policies) is a ceiling for both
client and server. The application's `Policy` can only narrow it further.

* **Why the crate enforces it.** crypto-policies reaches OpenSSL only as the
  `SignatureAlgorithms` and `Groups` lists of the `system_default` SSL
  configuration. libssl applies them to TLS; EVP signing and encapsulation
  ignore them, as tested (an ML-DSA-44 signature succeeds under a policy
  listing only `mldsa87`).
* **How it's read.** native-ossl's `system_policy::SystemPolicy` reads the
  lists with OpenSSL's own configuration loader (`OPENSSL_CONF` or
  `OPENSSLDIR/openssl.cnf`, full `.include` support), once per process. No
  configuration or no list means no restriction, matching TLS. A
  configuration that exists but cannot be loaded fails closed
  (`Error::SystemPolicy`).
* **Mapping.**
  * ML-DSA-*n* is allowed when `SignatureAlgorithms` contains `mldsa<n>`.
  * ML-KEM-*n* is allowed when any allowed group, pure or hybrid, contains
    it (`X25519MLKEM768`, `SecP384r1MLKEM1024`, `mlkem1024`, …).
    crypto-policies' DEFAULT lists only hybrid ML-KEM groups, and `NO-PQ`
    removes all of them.
* **Enforcement.** The checks sit at the primitive level, so every path
  is covered:
  * key generation, advertisement signing and verification, provisioning,
    `Binding::recovery_request` and `Server::recover` refuse a disabled
    algorithm (`Error::DisabledBySystemPolicy`);
  * keys can still be loaded, so they can be inspected and rotated.
* **Fallback where the library chooses.**
  * `SignatureAlg::preferred()` / `SigningKey::generate_preferred()` pick
    ML-DSA-65, else ML-DSA-87.
  * `KemAlg::preferred()` / `ExchangeKeyPair::generate_preferred()` pick
    ML-KEM-768, else ML-KEM-1024.
  * A server holding keys of several strengths signs its advertisement only
    with allowed signing keys and advertises only allowed exchange keys.
  * Clients drop disallowed exchange keys and provision with what remains.
  * Under a CNSA 2.0-style policy everything moves to ML-DSA-87 +
    ML-KEM-1024. Under `NO-PQ` nothing is allowed (`NoAllowedAlgorithm`).
* **Changing the policy locks out bindings that use a now-disabled KEM.**
  Both client and server then refuse to recover them, and the volume falls
  back to its other unlock methods. Before tightening the policy:
  1. add exchange keys of the new strength to the server;
  2. rebind every client (`Binding::rebind` moves a binding to the first
     advertised key);
  3. switch the policy;
  4. retire the old keys.

  `tests/system_policy.rs` exercises CNSA 2.0-style and `NO-PQ` policies end
  to end, each in a child process with its own `OPENSSL_CONF`.

## 7. Wire formats

### 7.1 Advertisement and server keys: JOSE

The JOSE parts follow two specifications:

* **ML-DSA:** RFC 9964.
* **ML-KEM:** `draft-ietf-jose-pqc-kem` (-05 as of December 2025), which is
  provisional until it is published.

```json
{"payload": "<b64url JWK Set>",
 "signatures": [{"protected": "<b64url {\"alg\":\"ML-DSA-65\",\"cty\":\"jwk-set+json\"}>",
                 "signature": "<b64url ML-DSA signature>"}]}

JWK Set:
{"keys": [
  {"kty":"AKP","alg":"ML-DSA-65","pub":"<b64url 1952 B>","key_ops":["verify"]},
  {"kty":"AKP","alg":"ML-KEM-768","pub":"<b64url 1184 B>","key_ops":["deriveKey"]}]}
```

Details:

* **Thumbprints:** RFC 7638 SHA-256 over `{"alg":…,"kty":"AKP","pub":…}`
  (RFC 9964 §6), shown as unpadded base64url. ML-KEM keys use the same
  members.
* **Private JWKs:**
  * ML-DSA: `priv` is the 32-byte FIPS 204 seed ξ.
  * ML-KEM: `priv` is the 64-byte FIPS 203 seed `d ‖ z`.
  * Expanded private keys are never written.
  * On load, a `pub` member must match the key regenerated from the seed.
* **Draft discrepancy:** `draft-ietf-jose-pqc-kem-05` says the ML-KEM
  `priv` is "the 32-byte seed". FIPS 203 `ML-KEM.KeyGen_internal` takes two
  32-byte seeds `(d, z)`, and OpenSSL and the LAMPS ML-KEM X.509 work use
  the 64-byte `d ‖ z`. A 32-byte value cannot reproduce a FIPS 203 key pair.
  This crate uses 64 bytes; the draft text should be raised with the JOSE
  WG.
* **Verification:** independent tooling can check advertisements. The
  thumbprints can be recomputed generically, and the stock `openssl` CLI
  verifies the JWS signatures as pure ML-DSA over `protected.payload` with
  no context.

### 7.2 Binding and recovery messages: binary

Tang has no JOSE structure for these: it uses bare JWKs for `/rec`, and
Clevis keeps its own LUKS2 token JSON. Each message is
`magic(4) ‖ version(1)=1 ‖ fields`. A variable-length field is encoded as a
`u32` big-endian length followed by the bytes. KEM ids are `0x01`
ML-KEM-768 and `0x02` ML-KEM-1024. `kid` and `thp` are the raw 32-byte
thumbprints. `sealed_ct` is the binding's ciphertext plus a 16-byte GCM
tag.

```
TQBD  alg(1) kid(32) thp(32) ct r(32) confirm(32)              binding
TQRQ  alg(1) kid(32) ct_t sealed_ct                            recovery request
TQRS  sealed_ss(48)                                            recovery response
```

A Clevis pin can wrap the binding in its token JSON as base64url.

## 8. Extension points for protocols built on tang-pqc

kuipa (`crates/kuipa-enroll`) builds enrollment and keytab escrow on this
crate. The Tang protocol above is unchanged by these extensions: its
derivations are the `Domain::TANG` case, byte for byte.

* **Protocol domains** (`primitives::Domain`): a label that is the HKDF salt
  and prefixes every HKDF `info` as `label ‖ " " ‖ purpose ‖ parts`. Tang
  uses `tang-pqc/v1` with purposes `key` and `transport`; other protocols
  pick their own label, so their keys can never coincide with Tang's.
* **Binding context** (`BindingContext`): a domain plus application data
  mixed into the binding key after `H(ct)` (kuipa: the principal whose
  keytab is protected). It is not stored in the binding, so it is supplied
  again with `Binding::from_bytes_with`; a different context yields a
  different key. `Advertisement::provision_with` creates bindings under a
  context, `rebind` keeps it, and `Binding::ciphertext_hash` gives a public
  identifier for server-side registration.
* **Answering recovery requests directly**, for servers that hold their own
  keys and authorise requests themselves: `RecoveryRequest::open(key,
  domain)` opens the sealed request, `OpenedRequest::ciphertext_hash`
  identifies the binding for the authorisation check, and
  `OpenedRequest::respond` answers. `RecoveryRequest::respond` does both
  steps, and `Server::recover` is the Tang case. A request sealed in
  another domain does not open. Opening costs a decapsulation before the
  check, so rate-limit before it.
* **Recovery with a stored key:** `Binding::recovery_request` takes the
  exchange key, so a protocol can keep it next to the binding (`Binding::alg`
  and `kid` identify it) instead of fetching `GET /key/{kid}`.
* **Advertisement extensions** (`AdvertisementBuilder`):
  * `member(name, value)` adds a signed JWK Set member (RFC 7517 §5);
    `Advertisement::member` reads it after verification, and
    `SignedAdvertisement::unverified_member` before, for protocols whose
    signing key is itself named by a member;
  * `exchange_key_with(key, member, value)` tags an exchange key with a
    role; `Advertisement::exchange_keys_where` selects by role, and
    `exchange_keys` (what plain Tang clients use) never returns a tagged
    key.
* **Key operations:** `ExchangeKey::encapsulate`,
  `ExchangeKeyPair::decapsulate` (length-checked, policy-checked), and public
  JWK JSON for both key types.
* **ML-DSA contexts:** `SigningKey::sign_with_context` and
  `VerifyingKey::verify_with_context` (FIPS 204 context strings up to 255
  bytes), so one key can sign JWS (empty context, RFC 9964) and other
  structures without either signature verifying as the other.
* **Public building blocks:** `primitives::{seal, open, digest, sha256}`
  (single-use AES-256-GCM), `wire` (the binary message codec of §7.2, with
  `u64` and string fields), `b64`, and `Policy::check_freshness` and
  `unix_seconds`.

`tests/extensions.rs` covers these: role-tagged keys invisible to plain
Tang, signed members, binding context (domain and info), and the default
context matching Tang.
