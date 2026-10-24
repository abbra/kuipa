# kuipa — post-quantum FreeIPA enrollment and keytab protection

This document describes the protocol and its implementation in this
workspace. the local CI guide (`docs/src/development/local-ci.md`) covers CI and the interactive
playground. §19 lists what is implemented, what is tested
where, and what is not built yet.

## 1. Goal and scope

A FreeIPA client's identity is its keytab: the long-term Kerberos keys of
`host/<fqdn>@REALM`. kuipa protects that keytab with standard
post-quantum primitives at four points:

1. **Enrollment:** authenticate the realm, authorise the join, and deliver
   the keytab, the CA chain and the realm configuration to the host.
2. **Rekey:** rotate the host keys with forward secrecy.
3. **At rest:** optionally seal the keytab so that a copy of the disk is
   useless without the IPA servers.
4. **Offline enrollment:** stage the host and its keys in advance, and let
   the host enroll from a sealed, signed bundle with no network access.

Constraints:

* Only FIPS 203 ML-KEM, FIPS 204 ML-DSA, HKDF, AES-256-GCM and SHA-2, all
  from OpenSSL (≥ 3.5) through `native-ossl`. Server keys can live in the
  FIPS provider or an HSM.
* No change to Kerberos, the KDC, or the LDAP extended operations that
  create keys: kuipa changes how secrets *travel* and are *stored*, not how
  they are made.
* The system crypto policy (Fedora/RHEL crypto-policies) is a ceiling for
  every algorithm (`tang-pqc` DESIGN §6.1).
* No single point of trust among the servers: each holds its own anchor,
  and the servers vouch for each other through an exchange authenticated
  with their Kerberos keys (§4.2).

Out of scope: PKINIT itself, FAST armour, and ML-DSA certificates from the
IPA CA. Custodia's job moves onto kuipa's envelope (§18).

## 2. Enrollment in FreeIPA today

References are to the FreeIPA tree at f15a4acd2.

**OTP enrollment** (`ipa host-add --random`, then `ipa-client-install -w`):

1. `ipaclient/install/client.py:get_ca_certs`: with no preexisting
   `/etc/ipa/ca.crt`, the CA certificate is downloaded **over plain HTTP**
   (the interactive prompt calls this "INSECURE"; unattended installs accept
   it silently).
2. `client/ipa-join.c:join_ldap` binds over LDAPS as
   `fqdn=<host>,cn=computers,cn=accounts,<suffix>` with the OTP and calls the
   join extended operation (`2.16.840.1.113730.3.8.10.3`).
3. `ipa-join` runs `ipa-getkeytab -D <hostdn> -w <otp>`, which binds again and
   calls `KEYTAB_GET` (`…10.5`) with server-side key generation.
4. `ipa-pwd-extop:store_new_keys` → `remove_user_password` deletes
   `userPassword` when keys are first stored: that makes the OTP one-time.

The OTP is passed to both tools in `argv`, readable through `/proc` while
they run.

**Administrator enrollment** (`-p admin`): `ipa-client-install` writes a
temporary `krb5.conf`, runs `kinit` with the admin password, fetches the CA
from LDAP unverified, calls `host_join` over JSON-RPC and runs
`ipa-getkeytab` with the admin ticket.

**Exposure:**

| step | protected by | recorded now, quantum later | active quantum attacker at install time |
|---|---|---|---|
| CA certificate | nothing (OTP) / unverified TLS (admin) | — | substitutes the CA (a classical attacker can too) |
| OTP | TLS key exchange | learns the OTP if the exchange was classical | forges the server certificate and enrolls as the host |
| admin password (`kinit`) | password-derived keys or classical armour | offline guessing of the password | — |
| keytab | TLS key exchange | **learns the host's long-term keys** if the exchange was classical | as above |
| keytab on disk | file mode 0600 | — | — |

Hybrid ML-KEM TLS groups fix the recorded-traffic rows only where every hop
negotiates them, and fix nothing about trust in the CA. Kerberos after
enrollment is symmetric (AES) and remains sound; rotation by the host
inherits the old key's protection without forward secrecy (§6).

## 3. Architecture

```
          enrollment string: realm + anchor thumbprint (+ OTP or bundle secret)
                                     │ out of band
                                     ▼
 host                                                         IPA server
 kuipa enroll ─── GET  /ipa/ku/adv?anchor=… ─────────────▶ httpd ─▶ kuipad
               ◀── realm advertisement (ML-DSA JWS) ──────           (Unix socket,
               ─── POST /ipa/ku/join/{kid} ───────────────▶            socket-activated)
               ◀── keytab + CA chain + config, sealed ────                 │ LDAPI, GSSAPI
                                                                           ▼
 kuipa rotate-keys ── POST /ipa/ku/rekey/{kid} ──────────▶        389-ds: bind, join,
 kuipa-unseal ─────── POST /ipa/ku/rec/{kid} ────────────▶        KEYTAB_GET, attributes
 kuipa protect ────── POST /ipa/ku/register/{kid} ───────▶
 (administrator) ───── POST /ipa/ku/stage/{kid} ──────────▶
 clevis (tang-pqc) ─── GET/POST /ipa/ku/tang/… ───────────▶        Tang keys only (§11.5)

 provisioner ◀── blinded μ / σ, out of band ──▶ voucher issuer (kuipa-voucher, §9)
 other IPA servers ◀── POST /ipa/ku/peer/sync (agirru gossip, Kerberos) ──▶ kuipad
```

### 3.1 Workspace

One Cargo workspace (root `Cargo.toml`: Rust 1.89, edition 2024 except
for the two borrowed FFI crates and `ml-dsa-blind`, which stay on 2021,
shared lints with `unsafe_code` forbidden by default) holds eight crates.
Each depends only on crates in rows above it:

| layer | crate (`crates/`) | role | workspace dependencies |
|---|---|---|---|
| cryptographic building blocks, no IPA knowledge | `tang-pqc` | ML-KEM/ML-DSA Tang escrow: advertisements, keys, bindings, sealed recovery, plus protocol domains, binding context, advertisement extensions and public primitives for protocols built on it (§15) | — |
| | `ml-dsa-blind` | blind (message-hiding) signing with stock FIPS 204 ML-DSA through OpenSSL's external μ, for vouchers (§9) | — |
| | `tang-pqc-clevis` | the `tang-pqc` binary: a client for any post-quantum Tang server and the Clevis pin `tang-pqc` (§10.7) | `tang-pqc` |
| IPA protocol | `kuipa-enroll` | the protocol, without I/O or `unsafe`: delegations and the anchor exchange state, realm advertisements, join/rekey/stage, vouchers, trust establishment, bundles, sealed keytabs and escrow, MIT keytabs, `Directory` and `EnrollServer` | `tang-pqc` |
| system bindings | `kuipa-gssapi` | GSSAPI bindings (from ahdapa-gssapi) | — |
| | `kuipa-ldap` | OpenLDAP bindings (from ahdapa-ldap), with extended operations | `kuipa-gssapi` |
| programs | `kuipad` | the server daemon: axum router, LDAPI/GSSAPI `Directory`, key store, anchor exchange, the general post-quantum Tang service (§11) | `kuipa-enroll`, `tang-pqc`, `kuipa-gssapi`, `kuipa-ldap` |
| | `kuipa-tools` | `kuipa`, `kuipa-unseal` and `kuipa-voucher` (§10), and the `kuipa-playground` example behind `local-ci.sh interactive` | `kuipa-enroll`, `tang-pqc`, `ml-dsa-blind`, `kuipa-gssapi`; tests also `kuipad`, `tang-pqc-clevis` |

All crates are licensed GPL-3.0-or-later. `kuipa-gssapi` and
`kuipa-ldap` are derived from ahdapa's bindings. Three crates are
usable outside FreeIPA: `tang-pqc` and `tang-pqc-clevis` serve and unlock
any post-quantum Tang binding, and `ml-dsa-blind` is a general
blind-signing library.

Outside `crates/`:

* `shims/rand` replaces `rand` (through `[patch.crates-io]`) with
  OpenSSL's generator for hickory, so no RustCrypto crate is linked (the
  `deps` CI job enforces it).
* `contrib/` holds the systemd units, the httpd snippet, a daemon
  configuration example and a gssproxy example; `contrib/clevis/` the pin's
  installer and dracut module; `contrib/ci/` the local CI and playground
  script (the local CI guide (`docs/src/development/local-ci.md`));
  `docs/man/` the man pages (scdoc sources, one per program).

All cryptography is OpenSSL (≥ 3.5) through `native-ossl`; TLS uses rustls
with the `rustls-native-ossl` provider.

### 3.2 Executables

| executable | crate | runs on | as |
|---|---|---|---|
| `kuipad` | `kuipad` | IPA servers | socket-activated service behind httpd (§11) |
| `kuipa` | `kuipa-tools` | hosts | root, from `ipa-client-install`, an administrator or a unit (§10.1) |
| `/usr/libexec/kuipa-unseal` | `kuipa-tools` | hosts with a sealed keytab or file | `init_t` at boot, `gssproxy_t` as keytab loader (§10.5) |
| `kuipa-voucher` | `kuipa-tools` | the voucher issuer's and the provisioner's machines | their users (§10.6) |
| `tang-pqc`, linked as `clevis-{en,de}crypt-tang-pqc` | `tang-pqc-clevis` | any Clevis client, initramfs included | the Clevis pin or a command (§10.7) |

The host-side programs are split only where SELinux needs different domains
(SELinux picks a domain by executable file type, not by arguments; FreeIPA
already uses one executable per confined domain, e.g. the Custodia helpers):

* **`kuipa`** runs as root from `ipa-client-install`, an administrator or a
  systemd unit. It writes `/etc/krb5.keytab` and `/etc/ipa`, and uses
  Kerberos; interactive use stays unconfined, like `ipa-join`.
* **`/usr/libexec/kuipa-unseal`** is started only by `init_t` (boot) and by
  `gssproxy_t` (keytab loader). Its domain, `kuipa_unseal_t`, may read the
  sealed keytabs and files, the client state, anchors and CA, connect to the
  IPA servers' HTTP port, run `systemd-creds`, and write
  `/run/ipa/krb5.keytab`, `/run/ipa/kuipa/` (§7.5) or an inherited memfd.
  It has no Kerberos client rights and cannot write `/etc`; `gssproxy_t`
  gains only the right to transition into it.

## 4. Keys, anchors and the realm advertisement

### 4.1 Keys

| key | type | where | role |
|---|---|---|---|
| anchor | ML-DSA-65 (ML-DSA-87 under CNSA 2.0) | every server, its own | vouches for its own server's claim and every claim it trusts; clients pin anchor thumbprints |
| server signing key | ML-DSA, same set | every server | signs that server's advertisement and bundles |
| join keys | ML-KEM-768 (ML-KEM-1024 under CNSA 2.0) | every server | join, rekey and stage requests |
| escrow keys | ML-KEM, same set | every server | sealed-keytab bindings |
| trust keys | ML-KEM, same set | every server | trust requests from other realms (§17.4) |
| voucher keys | ML-DSA | the voucher issuer; servers hold the public key | enrollment vouchers (§9) |
| Tang signing and exchange keys | ML-DSA and ML-KEM | any server that serves Tang | the general post-quantum Tang service (§11.5), nothing else |
| `ipa-ku/<fqdn>` Kerberos key | the realm's enctypes | every server's keytab | the daemon's GSS-API identity: accepts client tokens, authenticates anchor exchange syncs |

There is no realm-wide anchor and no anchor server: every server creates
its own anchor at installation, and no private key ever leaves the server
that made it. Join and escrow keys are distinct keys with distinct
protocol domains, and never Tang keys; trust keys likewise. Private keys
are seed-form JWKs in the daemon's key directory (§11.2); public keys need
no confidentiality. Join, escrow and trust keys rotate with
`kuipad rotate-keys`: the retired key is no longer advertised but
is still answered, so requests made against the previous advertisement,
and sealed keytabs bound to it, keep working until `prune-keys` deletes it
(§11.2).

### 4.2 Delegations and the anchor exchange

A server's **claim** names its realm, its FQDN, its own anchor and the
thumbprint of its signing key, with a validity period (90 days by
default, at most 400):

```
IPDC ‖ 1 ‖ realm ‖ server ‖ anchor(32) ‖ key(32) ‖ iat ‖ exp      about 100 bytes
```

The server renews it at two thirds of its lifetime, or when its signing
key changes. Claims are not signed by themselves. Each anchor
**vouches** for a set of claims with one ML-DSA signature over a Merkle
tree of them, the way a Merkle Tree Certificates log signs its tree
(built and proven with `synta-mtc`; RFC 9162 hashing: SHA-256 over
`0x00 ‖ claim` for leaves and
`0x01 ‖ left ‖ right` for nodes, leaves sorted):

```
IPVH ‖ 1 ‖ realm ‖ anchor(32) ‖ iat ‖ exp ‖ size ‖ root(32)       signed, context "ipa-ku-enroll/v1 vouch"
```

A vouch lasts 7 days (at most 31 are accepted). The anchor vouches again
at half life and whenever the set of claims it vouches for changes, at
most once per round. A **proof** that anchor T vouched for a claim is T's
public key, the signed vouch and the claim's inclusion path (log₂ of the
number of claims hashes). A **delegation** is a claim with proofs:

How proofs can skip the signature and the key entirely — a
pre-distributed **vouch head** checked like an MTC landmark — is
designed in §4.9.

```json
{"claim": "<b64url IPDC>",
 "proofs": [{"anchor": {<anchor public key>}, "vouch": "<b64url IPVH>",
             "signature": "<b64url>", "index": 3, "path": ["<b64url hash>", …]}],
 "successions": [{"from": {<old anchor public key>}, "statement": "<b64url IPAR>",
                  "signature": "<b64url>"}]}
```

A verifier accepts the first proof whose anchor is pinned and allowed by
its `Policy`, whose signature and inclusion path verify, and whose vouch is
valid; then the claim must be valid too (300 s of clock skew for both).
`successions`, present only after an anchor rotation, lead from rotated
anchors to current ones (§4.7).
Vouch signatures use a non-empty ML-DSA context, so they never verify as a
JWS or bundle signature by the same key.

Servers exchange anchor keys, claims and vouches with **agirru** (push-pull
anti-entropy gossip, `agirru-engine` 0.1.2) over `POST /ipa/ku/peer/sync`:

* **Members** are the IPA servers in `cn=masters,cn=ipa,cn=etc,<basedn>`
  (re-read every five rounds) plus the configured `peers`; only members are
  gossiped with and trusted. A master without kuipa answers `404` and is
  retried with each round.
* **Server identities.** Every IPA server holds the key of its own
  Kerberos service principal `ipa-ku/<fqdn>@REALM` in the daemon's keytab
  (`keytab` and `principal` in the configuration). The same key serves both
  directions: as an acceptor, it decrypts tickets that clients and peers
  obtain for this server; as an initiator, it gets this server a TGT from
  which it obtains tickets for its peers. Servers address one another
  through GSS-API by host-based service name, `ipa-ku@<fqdn>` (`service@host`,
  `GSS_C_NT_HOSTBASED_SERVICE`), which the Kerberos library maps to the
  peer's principal `ipa-ku/<fqdn>@REALM`; only that peer's key can accept
  the resulting token. Below, `<sender>` and `<receiver>` are the FQDNs of
  the two servers in a sync.
* **Every sync request is Kerberos-authenticated.** It carries the
  sender's own delegation (its claim with its own anchor's proof), the agirru
  envelope, and a GSS-API token that the sender, initiating with its own
  `ipa-ku/<sender>@REALM` key, creates for the service name
  `ipa-ku@<receiver>`; the token's channel binding is
  `SHA-256("ipa-ku-enroll/v1 peer" ‖ sender ‖ receiver ‖ delegation ‖
  envelope)` (§14). The receiver accepts the token with its own
  `ipa-ku/<receiver>@REALM` key, requires the initiator to be exactly
  `ipa-ku/<sender>@REALM`, the sender to be a member, the request to be
  addressed to itself, and the delegation to be the sender's own and proven
  by the anchor it names; any failure is `403`. The sender's claim is then
  **attested**: Kerberos proves that `<sender>` presented that anchor.
* **State** (`AnchorState`): anchor keys (keyed by thumbprint), claims
  (keyed by leaf hash) and one vouch per anchor, with its leaves. Keys and
  claims never change; a vouch is replaced by the same anchor's newer one
  (signed `iat`, strictly increasing per anchor; ties by content), so no
  causal tags are needed. Inbound entries are checked before merging: keys
  against the policy, claims and vouches against the realm and the time,
  vouches against their anchor's key (received or known) and their leaves
  against the signed root; vouches by the receiver's own anchor are
  discarded (it is their only source), and so are claims of non-members.
  Expired entries, claims no vouch has covered for an hour, vouches by
  anchors no claim names and keys nothing refers to are dropped. The state
  is persisted in `peers.state`.
* **Trust** (`Trust::compute`), recomputed after every change: a server
  trusts its own claim and every attested claim. It then trusts a claim of
  server S that S's own anchor vouches for and that an anchor already
  trusted for a *different* server vouches for, repeating until nothing
  changes; a newer trusted claim of S replaces an older one, and one anchor
  is trusted for at most one server.
* **Each anchor vouches for every claim its server trusts**, its own
  included: one vouch per anchor. Trust therefore spreads across servers
  that never talk directly: if A and B sync, and B and C sync, A trusts C
  through B's vouch and then vouches for C itself.
* **Publishing:** the server's claim with a proof from every trusted
  anchor, and the trusted anchors (its own first), go to the `EnrollServer`
  and to `delegation.json`. A renewed claim replaces the previous one once
  it has as many proofs, or when the previous proofs have less than a
  quarter of a vouch's lifetime left.
* **Size** (measured, ML-DSA-65; `measure_exchange_sizes`):

  | servers | exchange state | delta after one claim renewal | advertised delegation |
  |---|---|---|---|
  | 10 | 65 KB | 38 KB | 7.6 KB |
  | 60 | 489 KB | 321 KB | 7.7 KB |

  Per server, the state holds an anchor key (2.7 KB as JWK), a claim
  (about 100 bytes) and a vouch (a 3.3 KB signature and 32 bytes per
  vouched claim): it grows with the number of servers, plus 32 bytes per
  pair. A renewal costs one new vouch per anchor, batched per round, so
  short-lived claims stay cheap.

* **Anchor role.** A server configured with `"anchor": false` holds no
  anchor: it makes claims without one (its claim's anchor field is all
  zeros), never vouches, and is trusted through the Kerberos attestation of
  the servers it syncs with, whose anchors vouch for it. A realm needs at
  least one anchor server; clients pin anchor servers' thumbprints only.
  With 6 anchors among 60 servers the state is 55 KB and a renewal's delta
  32 KB (against 489 KB and 321 KB with 60 anchors).
* **Re-vouching.** A vouch that would only add claims waits until the
  previous one is `vouch_interval` seconds old (default 60), so a burst of
  new or renewed claims costs one vouch per anchor; a vouch that drops a
  claim (a removed server, the anchor's own renewal) is made at once. Vouch
  `iat`s of one anchor strictly increase, so the newest always wins.

Adding a server needs no administrator step: its daemon generates an
anchor, its `ipa-ku/<fqdn>` key authenticates it to the members it syncs
with, and within a few rounds every anchor vouches for its claim and every
server lists its anchor. Removing a server (`ipa server-del`) removes it
from `cn=masters`: every server stops trusting it, drops its claim from its
next vouch, and drops its anchor from the anchor lists. Its existing proofs
stop verifying when the vouches they come from expire, within 7 days.

### 4.3 The realm advertisement

`GET /ipa/ku/adv` returns a `tang-pqc` advertisement (General JWS over a JWK
Set) signed by the server signing key, valid for 7 days and re-signed at
half life. The JWK Set carries two extension members:

```json
{"keys": [
   {"kty":"AKP","alg":"ML-DSA-65","pub":"…","key_ops":["verify"]},
   {"kty":"AKP","alg":"ML-KEM-768","pub":"…","key_ops":["deriveKey"],"ipa_use":"join"},
   {"kty":"AKP","alg":"ML-KEM-768","pub":"…","key_ops":["deriveKey"],"ipa_use":"escrow"}],
 "ipa": {"realm":"EXAMPLE.TEST", "domain":"example.test", "basedn":"dc=example,dc=test",
         "server":"ipa1.example.test",
         "servers":["ipa1.example.test","ipa2.example.test"],
         "ca_certs":["<b64url DER>"],
         "pkinit_anchors":["<b64url DER>"],
         "anchors":["<b64url thumbprint>", …],
         "heads":[{"anchor":"<b64url thumbprint>","size":12,"root":"<b64url hash>"}, …]},
 "delegation": {"claim":"…","proofs":[<one proof>]}}
```

`anchors` lists the trusted anchors, the server's own first. The
`delegation` carries **one** proof: the client names the anchors it pins as
`?anchor=<thumbprint>` (repeated, in order of preference, at most 16 used),
and the server includes the proof of the first of them that vouches for its
claim, or else its own anchor's. The size of an advertisement
therefore does not grow with the number of servers. The server keeps one
signed advertisement per chosen proof, re-signed at half life and
discarded when the exchange publishes.

The `ipa` member carries certificates, not hashes: before enrollment the
advertisement is the only authenticated source of the PKINIT anchors an
armoured `kinit` needs (§5.4), and its CA authenticates the server's TLS
certificate from the join onwards (§10.3).

**Verification** (`VerifiedRealm::verify`):

1. Read the `delegation` member (unverified) and verify it against the
   pinned anchors as of now. Its realm must be the expected one.
2. Verify the advertisement against the delegated key's thumbprint with the
   `tang-pqc` checks (freshness, policy, `key_ops`, non-AKP keys ignored).
3. Read `ipa` from the verified set; its realm and server must equal the
   delegation's.
4. Use keys by `ipa_use` only. Keys without it are plain Tang keys and are
   never used for kuipa; keys with another value are ignored.

The delegation's `server` is the server's identity for the rest of the
exchange (Kerberos target, configuration). It is not compared with the name
the client connected to, so DNS aliases and load balancers work: every key
in the exchange belongs to the delegated server.

**Size** (measured, `measure_sizes`, with a 1.5 KB CA certificate that is
also the PKINIT anchor): 28.2 KB for ML-KEM-768 + ML-DSA-65, 36.0 KB for
ML-KEM-1024 + ML-DSA-87, of which the one-proof delegation is 7.5 / 10.1 KB
(base64 inside base64 JSON; a path hash more per doubling of the realm),
plus 44 bytes per listed anchor. It is fetched once per join, rekey or
check. The vouch-head proofs of §4.9 would make the delegation member a
few hundred bytes.

### 4.4 The enrollment string

```
ipa-ku1:<REALM>:<anchor thumbprint>:<expiry>[:<secret>]
```

The anchor thumbprint is 43 base64url characters: the anchor of the server
that issued the string. The expiry is in Unix seconds; the host refuses the
string after it (300 s of clock skew), before sending anything.
The string may also carry the anchor's current **vouch head**, which
lets the host check the delegation without any signature at all
(§4.9): `ipa-ku2:<REALM>:<anchor>:<expiry>:<size>:<root>[:<secret>]`.
`kuipad enrollment-string [--days N]` prints the string without a
secret (7 days by default, at most 400), to append `:<OTP>` to. The secret
is an OTP for an online join, or the bundle secret `S` of a mode B bundle
(§8.2), and is the last field (it may contain `:`). Realm and servers are
public, so the thumbprint is the only thing that must reach the host
authentically, and it travels with the OTP. DNS cannot carry it (DNSSEC is
classical).

The expiry is mandatory and is protected only by the channel that delivers
the string, exactly as the thumbprint is: whoever can change the expiry can
change the thumbprint to their own anchor instead, which is worse. No
signature or MAC can do better. The host could only check one with a key it
reaches through the thumbprint itself, so the check would be circular, and
the thief of an old anchor could re-sign a later expiry anyway. What the
expiry bounds is stale delivery through honest channels: a string left in
an image, a kickstart file or a wiki page after the anchor it names was
rotated (§4.7) or stolen. A stolen anchor can vouch for impostors forever;
an expired string makes an honest host refuse them.

Enrollments without a secret in the string (a user's password, a ticket, a
voucher) and `realm-info` can take `--realm R` instead: the advertisement is
then verified against the anchors pre-provisioned in `/etc/ipa/ku-anchors`
(an image, configuration management). Listing two or more changes what the
host demands: the claim must be provable by two distinct listed anchors,
each asked for its own proof (`?anchor=`, §4.3), and pins that resolve
through a succession to the same current key count once. That is the
second anchor's purpose: a realm whose anchors exchanged (§4.3) answers
for both, a host vouched by a single key — a stolen one included —
answers with one, and the theft surfaces as a refusal (§4.7, §13). A
realm with one anchor server is pinned with exactly one anchor; a second
pin there only breaks enrollment. Enrolled hosts' stored lists (§4.5)
meet the same rule on rekeys and checks. Such pins
should carry an expiry for the same reason (`<thumbprint> <expiry>` per
line, §10.2); lists written from server responses carry none, since every
rekey refreshes them. There is still no trust on first use: without a
pinned anchor the client would talk to a server nobody vouched for.

An enrollment string together with `--realm` (`ipa-client-install -r`) is
a cross-check: the string must be for that realm, compared exactly as
Kerberos does, or `kuipa` stops before contacting a server. The realm,
like the servers and the domain (§4.6), then comes from a channel other
than the string.

### 4.5 Anchor lists on enrolled hosts

Every join and rekey response carries the trusted anchors, authenticated
inside the sealed payload; clients store them in `/etc/ipa/ku-anchors` and
pin all of them for later rekeys, checks, unsealing and bundles. A host
therefore keeps working as servers come and go, as long as one anchor it
stores still signs: each rekey refreshes the list. A replaced anchor (a
server reinstalled with a new one) is handled like a new server.

### 4.6 Servers and failover

An enrollment string names a realm, never a server. Every server accepts
it once the exchange has run: the string's anchor vouches for every server's
delegation, and every authenticator is realm-wide state (OTPs and staging
on replicated host entries, Kerberos tickets for each server's own
`ipa-ku/<server>` principal, bundles verifiable through any anchor the
host pins).

The client tries the servers it is given (`--server`, else the stored
list) in order. Without either, it looks them up in DNS: `_ldap._tcp.<domain>`
SRV records, which FreeIPA publishes for every server, for `--domain` or
else the domain of `--hostname` or of the host name, ordered by priority
and then weight (highest first), through `hickory-resolver` with the system
configuration (`KUIPA_DNS=<address:port>` names one nameserver instead).
DNS only names candidates: names that are not safe host names are dropped,
and every server must still present an advertisement that verifies against
a pinned anchor.

Verifying an advertisement only shows that an anchor the client trusts
vouches for what it says, and it names its realm, domain and servers
itself. A forged or misdirected enrollment string brings its own anchor,
so every advertisement must also describe the deployment the client was
told about through other channels: the servers to use (`--server`, the
DNS SRV targets, or the stored list on an enrolled host) and, when given
or used for the DNS lookup, the domain. Before any request is built:

* the delegated server must be one of those servers, and among the
  servers its own advertisement lists;
* the advertised domain must be the client's, compared without case;
* the realm is already checked by the verification itself, against the
  string's realm, which `--realm` cross-checks (§4.4).

A mismatch stops with exit 1 (needs an administrator), naming what was
expected and what was advertised. It does not fail over to the next
server: it is either an attack or a misconfiguration, and failing over
would hide both. Before enrollment, the KDCs for the armoured AS
exchanges of password and OTP joins (§5.3) and in `realm-info`'s
`krb5.conf` (§5.4) are the delegated server and those advertised servers
that are also among the servers to use, so a password or an OTP-derived
exchange only reaches hosts the client was told to use. After enrollment
the stored server list and `krb5.conf` hold every advertised server: they
come from the authenticated response (§5.5).

These checks are not authentication. An attacker who delivers the string
and is on the path to the named servers can repeat the expected names;
the string must still reach the host authentically (§13). What they add is
that the enrollment must match the deployment the administrator described
independently, which catches stale, mis-delivered or foreign strings and
anchors, and keeps secrets away from hosts outside that deployment.

A server whose
advertisement cannot be fetched or does not verify (expired delegation, a
server the pinned anchor does not vouch for yet, an impostor) is skipped.
Creating keys is not idempotent across servers — two servers could accept
the same OTP before replication — so:

| situation | client action |
|---|---|
| connection failure, `502`/`503`/`404`, `429` (rate limited), advertisement fetch or verification fails | try the next server |
| request sent, then no answer (timeout, dropped connection) | retry the **same** server once with a fresh request; if that also fails, stop: "outcome unknown on `<server>`; do not retry elsewhere" (exit 1) |
| the advertisement verifies but describes another deployment | stop: needs an administrator (exit 1), before anything is sent |
| `403` | stop: refused (exit 1) |
| no server usable | exit 75 (retry later) |

After a join the issuing server comes first in the stored server list and in
the generated `krb5.conf`, until replication catches up.

Lockout counters (`krbLoginFailedCount`) are not replicated, so across N
servers an attacker gets about N times the per-server OTP guess limit — as
today, and harmless for `--random` OTPs.

### 4.7 Anchor rotation

`kuipad rotate-anchor [--days N]` replaces a server's anchor:

1. It generates a new anchor.
2. The current one signs a **succession** to it, valid for N days (default
   400, the longest a string or image pin may live):

   ```
   IPAR ‖ 1 ‖ realm ‖ old(32) ‖ new(32) ‖ iat ‖ exp     signed by old, context "ipa-ku-enroll/v1 succession"
   ```

3. It stores the signed succession, with the old anchor's public key, as
   `succession-<old>.json`.
4. Only then does it replace `anchor.jwk`. The old private key is gone; it
   signed exactly one statement.

After a restart the server's next claim names the new anchor. Its peers
admit that claim through the usual Kerberos attestation (§4.2), switch to
the new anchor and drop the old one, its vouch and its key. The server puts
its successions into the anchor exchange each round. They are
self-authenticating, gossiped like vouches (one per old anchor, the newest
wins) and dropped when they expire. Every server's delegation carries the
successions it knows.

**Clients.** `Delegation::verify_at` first tries the pinned anchors. If no
proof is by one of them, it follows the successions it carries from the
pinned set: each must check under its embedded key for the claim's realm at
the time, at most four hops, no cycles. It then accepts a proof by an anchor
it reached. `GET adv?anchor=…` returns, for a client that pins only rotated
anchors, the shortest chain from the first of them that leads to a proof.
Bundles carry every succession, since their reader is unknown.

**Pins.** Successions are followed in memory only and never written to
`/etc/ipa/ku-anchors`. Pins change only through join and rekey responses,
and rekey responses are bound to the Kerberos session (§5.1), which a
holder of a stolen anchor cannot imitate. An enrolled host therefore moves
to the new anchor, and drops the old one, at its next rekey
(`kuipa-rotate.timer`, monthly). `kuipa check` reports a server that
verified only through a succession.

**Limits.**

* A succession is a hand-over, not a revocation. Whoever stole the old
  anchor's key before the rotation can still vouch with it, and sign a
  conflicting succession.
* Two known anchors are what make a stolen one visible (§4.4). A host
  that pins only that anchor cannot tell its thief from the realm; a
  realm with one anchor server can offer no second proof, so keep at
  least two anchor servers, or pin only one and keep watching what
  the realm serves (§4.8).
* Flows with a Kerberos root (§5.3) are still protected.
* Anchor-only flows are bounded by the expiry of the string or pin they
  start from (§4.4): `--ldap-otp`, vouchers, bundles, and `--use-ccache`
  with IdP or passkey tickets.
* There is no revocation list.

### 4.8 The anchor epoch log

§4.4 notices a replaced anchor only when two anchors are known at the
same moment. This needs only one known anchor and two *lookings*: the
realm keeps an append-only record of its anchor history, and a host
remembers what it last saw.

**The log.** Entry `n` states the realm's anchor set and the
succession proofs behind it, and is signed by the current anchors'
keys; each signature carries its key, as a `Proof` does. Entries are
numbered from 1. They are canonical — the anchor and succession lists
sorted and deduplicated — so the same state produces the same bytes,
the same hash, the same entry on every server. Each entry names the
head of the entry before it — `0…0` for the first — so entries bind to
each other, not to a number line. Each anchor server
mints the next entry when the anchors it trusts or the proofs it has
change — but only once the state the entry would carry has stood
unchanged for a full exchange round, so servers that learn of a change
at different moments extend the same entry, not divergent ones neither
can rejoin — and exchanges the log with the other servers over the
anchor exchange, under the same channel binding as the rest of it. Two
servers that reach the same state by different paths therefore
converge on one log instead of forking it: an entry records state,
not a path. The log is not part of the CRDT state; each server
keeps it as its own record.

**Publishing.** Every realm advertisement names the head of the log:
`(n, H(entry n bytes))`. `GET /ipa/ku/anchor-log?from=n` answers
publicly with the entries after `n`, at most `MAX_EPOCH_FETCH` of
them. A host follows a longer log page by page: it asks `from=` its
last verified entry and advances to the advertised head.

**Watermark.** A host that verifies a realm stores that pair as an
`epoch <n> <hash>` line in `/etc/ipa/ku-anchors`, next to the pins.
Enrollment, rekey and `kuipa check` consult it and move it forward
only after a verified continuation.

**Belief.** A fetched continuation is verified from the pins alone:
every entry must continue the numbering and be signed by a *proven*
key — a pinned one, or the new end of a succession the entries list
whose old end is proven, at most `MAX_SUCCESSION_HOPS` deep, with
those succession signatures checked but not their expiry: a
historical record stays a record. Every entry's `prev` must be the
head of the entry before it, so a fetched page binds to a head the
host already knows; and an anchor listed by an entry that verified so
far becomes proven itself for the entries after it — an anchor added
behind a signature already believed is believed with the chain.
That is §4.2's rule transplanted.
The fetched log's end must equal the advertised head. A host with a
watermark refuses a server whose advertisement carries no log at all.

**What a host sees.**

| the server's head against the watermark | the host's response |
|---|---|
| a lower `n` | refused: this server has been left behind; its anchor key may have been replaced elsewhere |
| the same `n`, same hash | fine |
| the same `n`, other hash | refused: the log has forked |
| a higher `n` | the continuation must verify and end at the advertised head; the watermark moves |
| no watermark yet | stored from the advertisement, under §4.4's rule |

`check` reports this per server; join and rekey stop. A temporary
disagreement between servers during a rotation heals by the next
exchange round, because entries are derived from state and identical
entries merge their signatures.

**Merging on the servers.** An exchange carries a bounded tail window of
the log, not all of it. Entries both servers hold merge signature sets.
A window is adopted when it vouches for itself — contiguous numbering,
each entry signed by an anchor it names, each committing to its
predecessor — and continues our log at our own head; a window that
leaves a gap the server fills by fetching the peer's public anchor log.
If the two disagree on a statement at a sequence both hold, the log has
forked: neither server appends further until an operator reconciles
them.

**Limits.**

* A thief holding the old key can extend the log — it can sign its
  own succession into the new key — exactly the case §4.4 already
  cannot distinguish. What the log catches is the *stale* server:
  one still built on what the realm left behind, and a log that
  contradicts another server's.
* A host that never looks again notices nothing; the watermark is
  only as fresh as the last verification.
* Nothing here revokes; §4.7's limits stand.

### 4.9 Vouch heads

§4.2's proof is an MTC certificate in all but shape, and carries the
cost of one: measured (`measure_sizes`), the advertisement's delegation
member is 7.5 KB with ML-DSA-65 and 10.1 KB with ML-DSA-87, of which
the anchor JWK (2.7 KB) and the ML-DSA signature (3.3 KB raw, 4.4 KB
base64url) are almost everything; the exchange state is 55 KB (60
servers, 6 anchors) to 489 KB (60 anchors), and one claim renewal
gossips 32–321 KB of deltas, most of it the same JWKs and signatures
repeated per anchor and per round. A certificate whose proof can skip
the signature and the key would make the advertisement delegation a few
hundred bytes and the exchange deltas mostly leaf lists. The Merkle
Tree Certificates drafts call the mechanism that allows this a
**landmark**: draft-ietf-plants-merkle-tree-certs §6.4 and §7.4 — a
pre-distributed tree checkpoint a relying party holds, against which an
inclusion proof verifies with no signature at all. `synta-mtc` (already
a dependency, for the tree hashing) implements landmark publication,
distribution and trusted-subtree verification. This section is kuipa's
use of it, and it is implemented: vouches are claim logs, pins carry
heads, and a head-pinned client is served a proof with no signature,
no anchor key and no vouch on the wire (§18.1).

#### 4.9.1 What the anchor signs today, and what a head is

An anchor's vouch is a **claim log**: an
append-only sequence of leaves, one per claim the anchor vouches for,
numbered from 1, with the same RFC 9162 hashing as today (the MTC
draft's leaf and node prefixing is identical to what `merkle.rs` already
does through `synta-mtc`). The anchor still signs, but what it signs is
a **head**:

```
IPVH  version 2: realm anchor(32) iat exp size(u64) root(32)
```

— the same fields as the v1 vouch statement, over the claim log
instead of a re-sorted tree. The **vouch head** is `(anchor thumbprint,
size, root)`. Re-vouching keeps the previous log's order and appends
the new claims, so every prefix of the log is the tree an earlier
vouch signed: a head pinned at any prefix keeps verifying, with the
inclusion path recomputed inside that prefix. A vouch that must *drop*
a claim (a removed server) restarts the log, so no old prefix stays
valid — a pinned head must not prove a claim the realm dropped.

#### 4.9.2 The wire: a proof that skips the signature

A **head proof** replaces today's `Proof` where the client holds the
head, in the delegation's `head_proofs` member:

```json
{"head_proofs": [{"anchor": "<thumbprint>", "index": 3, "size": 12,
                  "path": ["<b64url hash>", …]}]}
```

The `proofs` member stays (§4.3) for a client that pins the anchor but
no head. A head proof is accepted only against a pin that carries a
head for that anchor (§4.9.4) — the thumbprint alone is not enough,
since there is no signature to check. The client names its pinned
heads as repeated `?head=<anchor>.<size>.<root>` parameters next to
`?anchor=`; the server answers a head proof when one of its vouches
makes the pinned prefix, else today's signature proof — a stale head
is a silent fallback, not an error. The two-pin quorum (§4.4) works
unchanged on head proofs: two pinned heads by distinct anchors must
both prove the claim, and a thief holding one key alone cannot mint a
matching head, so the impostor still surfaces as a refusal.

**What it saves.** A head proof is the path (32 bytes per level, six
levels at 60 anchors) plus a thumbprint: under 300 bytes against 7.5
KB, and the `anchors` and `claim` members they make redundant shrink
the delegation member to a few hundred bytes, advertisement to about
21 KB (ML-DSA-65) — with no signature to make, the proof needs no
freshness of its own.

#### 4.9.3 Servers: the gossip is leaves

On the servers nothing structural changes — `AnchorState`, agirru
anti-entropy, the Kerberos-authenticated syncs and the trust
computation stay as they are. The `IPSV` entry keeps carrying the
whole leaf list, in log order: a re-vouch that only appends keeps the
previous log and adds to it, one that must drop a claim starts a new
log, and the newest vouch of an anchor always carries its current
log — so a peer that receives one can check and serve any prefix of
it. A server that wants a leaf older than the vouch it holds fetches
the pages it needs from the peer's public claim log (§4.9.5), as it
fetches a missing anchor-log window today (§4.8). The anchor
re-signs on the same schedule and cadence (§4.2).

A delegation served to a head-pinned client carries its head proof
only, not the signature; the signature stays in the exchange and in
delegations served to clients without heads. This is the size win on
the wire between servers as well: per anchor per round the delta
becomes the head (about 100 bytes) and the appended leaves (32 bytes
per claim), with the 2.7 KB JWK and 3.3 KB signature sent only when
the anchor itself changes — measured exchange sizes, minus the
per-anchor signature cost per round: the state keeps one key, one
current head and its signature per anchor, plus the claims.

#### 4.9.4 How a head reaches a host

Every channel that carries a pin today carries the head next to it,
because a pin and a head are the same kind of fact — an administrator's
assertion about an anchor, delivered out of band, and only as fresh as
its channel:

| channel | today | with a head |
|---|---|---|
| enrollment string (§4.4) | `ipa-ku1:REALM:<anchor>:<expiry>` | `ipa-ku2:REALM:<anchor>:<expiry>:<size>:<root>` (`kuipad enrollment-string --head`; a v1 string pins the anchor alone, as today) |
| `/etc/ipa/ku-anchors` (§4.5) | `<thumbprint> [<expiry>]` | `<thumbprint> [<expiry> [<size> <root>]]`, refreshed inside every sealed join and rekey response, as pins are |
| sealed response payload (§5.5) | `anchors[]` (thumbprints) | `anchors[]` with each one's current head |
| image pins (§4.4, `--realm`) | thumbprints + expiry | thumbprints + expiry + head |

A host that has verified a realm keeps the head it used, and replaces
it only from a verified advertisement or sealed response — never from
the delegation member itself, which is untrusted input: **the head is
part of the pin, not of the proof**. An expired head is refused like an
expired pin (the string's expiry bounds it); a head whose `exp` has
passed makes the client fall back to a signature proof, which the
server serves as today. A head may also be pinned *behind* a
succession (§4.7): the succession chain carries heads as it carries
keys, and a client whose pinned head is for a rotated anchor follows
the chain and takes the current anchor's head from the advertisement's
`anchors` member — verified, as the whole `ipa` member is, by the
delegated key's signature.

Heads in pins carry the same guarantee MTC gives a pre-distributed
landmark: the tree a head names cannot change behind it, so any
inclusion proof that checks against it was fixed when the head was
pinned. A host that never looks again trusts exactly the claims that
were in the tree when its pin was written — the stale-pin property
§4.4's expiry already bounds.

#### 4.9.5 Publishing heads publicly

`GET /ipa/ku/anchor-log` (§4.8) also answers the anchors' current
heads, and `GET /ipa/ku/claim-log/{anchor}?from=<index>` serves pages
of one anchor's claim log — the same pagination and public,
unauthenticated access as the epoch log, for a server that must fill a
gap or a verifier that wants to audit what a head covered. Leaves are
content-addressed claims (their hash is the leaf), so pages are
verifiable against any head that follows them: a page's last leaf at
index `i`, hashed with the page's path structure, must reproduce the
root of a head at size ≥ `i` — the MTC subtree proof (`synta-mtc`
`verify_subtree_inclusion_proof`). The epoch log (§4.8) and the claim
logs stay separate records: the epoch log records anchor *history*;
claim logs record what each anchor *vouched for*.

#### 4.9.6 What this does not change

* **No global log, no new quorum.** The claim log is per anchor, and
  trust still comes from the exchange (§4.2): a claim enters a tree
  only through the anchor's own server or the gossip. There is no CT
  monitor, no third-party witness, no new party to run.
* **Threat model.** A head is a weaker pin than a key: it binds the
  tree, not the key that signs it. But a client that holds only a
  thumbprint today trusts *every* signature that key makes, forever,
  with no freshness; a client that holds a head trusts exactly the
  leaves under it, and nothing an impostor signs later. Head proofs
  are strictly stronger than the pins they extend, for the same
  channel. The two-anchor rule (§4.4) and the Kerberos binding
  (§5.1) apply unchanged and are what binds a head proof to a live
  server.
* **Backwards and forwards.** Old clients ignore the new members; new
  clients fall back to signature proofs wherever no head is pinned.
  There is no deployment yet, so both forms ship in one version and
  the prefix bump (`ipa-ku2`) is free; the v1 form stays only as long
  as tests and the playground exercise it.
* **Anchor rotation** (§4.7) is untouched: heads follow successions,
  and a rotated anchor's claim log simply stops growing; its
  successor's tree starts fresh.

## 5. Join protocol

### 5.1 Key schedule

`alg` is the KEM; `H` and HKDF use SHA-256 with ML-KEM-768 and SHA-384 with
ML-KEM-1024. Every derivation uses a protocol domain (`tang-pqc`
`primitives::Domain`): HKDF salt = the label, info = `label ‖ " " ‖ purpose ‖
parts`. The join domain is `ipa-ku-enroll/v1`. Every AES-256-GCM key
encrypts exactly one message, so the nonce is fixed at zero.

```
Client (advertisement verified: kid, ek_kid, signer thumbprint thp)    Server (dk_kid)
(ct, ss)     = ML-KEM.Encaps(ek_kid)
(dk_e, ek_e) = ML-KEM.KeyGen()
T  = H(op ‖ alg ‖ kid ‖ thp ‖ realm ‖ fqdn ‖ auth_type ‖ enctypes ‖ H(ct) ‖ H(ek_e))
     op = "join" | "rekey" | "stage", fixed by the endpoint
cb = HKDF(ss, "cb", T)                     GSS-API channel binding (32 bytes)
k  = HKDF(ss, "req", T)
     ── Request(alg, kid, realm, fqdn, auth_type, enctypes, ct, ek_e, GCM_k(body)) ──▶
                                                ss = ML-KEM.Decaps(dk_kid, ct)
                                                recompute T, k, cb; open body; authorise
                                                (ct_e, ss_e) = ML-KEM.Encaps(ek_e)
                                                k' = HKDF(ss ‖ ss_e [‖ kb], "rsp", H(T ‖ H(ct_e)))
     ◀── Response(ct_e, GCM_k'(payload)) ──
ss_e = ML-KEM.Decaps(dk_e, ct_e); open; check principal and CA chain

kb = GSS_Pseudo_random(ctx, GSS_C_PRF_KEY_FULL, "ipa-ku-enroll/v1 rsp" ‖ cb, 32)
     for auth_type Kerberos only; ctx is the authenticator's GSS-API context
```

* `ss` authenticates the server implicitly: only the holder of `dk_kid`, a
  key whose server a pinned anchor vouched for, can open the request or
  derive `k'`.
* `ss_e` gives the response forward secrecy: a later compromise of `dk_kid`
  does not reveal it without `dk_e`, which only ever existed in client
  memory.
* `kb` authenticates the server a second time, independently of the
  anchors. The authenticator is one Kerberos V5 token (the krb5 mechanism
  itself, no SPNEGO and no mutual authentication, so one message
  establishes both contexts), and RFC 4401's pseudo-random function derives
  `kb` from its session key or subkey. Only the holder of the
  `ipa-ku/<server>` key the ticket was issued for can recover that key. A
  server whose anchor proof verified but that cannot accept the ticket (a
  stolen anchor, an impostor) cannot produce a response the client can
  open. Defeating both means stealing an anchor *and* a server's Kerberos
  key, i.e. compromising a server, which exposes the realm's keys anyway.
  The client refuses to seal a Kerberos request without `kb`, and the
  server to answer one without it.
* `T` binds every cleartext field and the endpoint: a modified field, or the
  request replayed at another endpoint, does not open.
* Ciphertext lengths are checked before decapsulation, `ek_e` passes the
  FIPS 203 encapsulation-key check, and a modified `ct` decapsulates to an
  unrelated secret (implicit rejection).

Every failure after decapsulation is the same empty `403`; the reason goes
to the server log only. Before decapsulation or any LDAP work, requests are
rate-limited with token buckets per host FQDN (joins, rekeys, staging; the
principal for recovery, the realm for trust requests; none for
registrations and vault operations, which are only ever Kerberos-
authenticated, so there is nothing to guess, and whose many users on one
host must not share that host's allowance) and per client address, which httpd passes as the last `X-Forwarded-For` entry: by default
a burst of 10 and 2 a minute per host, a burst of 60 and 30 a minute per
address (`rate_limit`, §11.1). An exceeded limit is an empty `429`, which
the client treats like an unreachable server.

### 5.2 Request body

The sealed body is `auth_type ‖ registrations ‖ extra ‖ authenticator`:

* `registrations`: escrow binding hashes to register (§7.2), at most 255;
  stored for joins and rekeys only.
* `extra`: the staging parameters for `stage` (§8.3), empty otherwise.
* `authenticator`: depends on `auth_type` (§5.3).

### 5.3 Authenticators

| `auth_type` | authenticator | allowed for | server check (§11.4) |
|---|---|---|---|
| 1 OTP | the OTP | join | simple bind as the host entry over LDAPI with the OTP, then join and `KEYTAB_GET` on that connection |
| 2 Kerberos | Kerberos V5 initial token for `ipa-ku@<server>` with channel binding `cb`; its context yields `kb` (§5.1) | join, rekey, stage | accept with the same `cb` and derive `kb`; act as the authenticated principal through S4U2Self + S4U2Proxy to LDAP |
| 3 voucher | reserved for §9 | — | refused |
| 4 | none: was a user's password sealed to the server | — | malformed |

How the client gets its Kerberos ticket decides whether `kb` gives the
realm's Kerberos keys as a second, independent root (§5.1):

| client | Kerberos credential | `kb` independent of the anchor? |
|---|---|---|
| OTP join (default) | armoured AS exchange as `host/<fqdn>` with the OTP, which FreeIPA's `host-add --random` also sets as the host's temporary Kerberos key; then a **rekey** as the host itself, which replaces that key | yes: the AS reply is encrypted in the OTP-derived key |
| `--principal` password join | armoured AS exchange as the user, straight for `ipa-ku/<server>`; the password answers a plain realm, and whatever else the KDC asks for — a token value, a PIN, a RADIUS or IdP answer, a passkey PIN — is asked for on the terminal, inside the armour; then a Kerberos join | yes for plain password users (the reply is encrypted in the user's key); no for password+OTP, RADIUS, IdP and passkey users, whose reply key comes from the armour |
| `--use-ccache` | the caller's ticket (§5.4) | as above, by how it was obtained |
| rekey, stage, `check`, `protect` | the host keytab | yes |
| `protect --keytab` / `--file` (registration, §7.5) | the keytab being protected, or the one a file is sealed with | yes |
| `--ldap-otp` (auth type 1), voucher, bundle | none | no: the anchor alone |

* **Armoured AS exchanges** (`kuipa-gssapi::ticket`) run in
  process with their own configuration: the advertisement's KDCs and PKINIT
  anchors in a private temporary `krb5.conf`, anonymous PKINIT armour in a
  memory ccache, FAST required, no fallback to an unarmoured exchange (which
  would expose the password or OTP to offline guessing by a passive
  attacker). The service ticket is asked for directly in the AS exchange, so
  no TGS exchange, realm lookup or `KRB5_CONFIG` change is needed. The
  password never leaves the host. Its residual exposure is the one every IPA
  `kinit` has: a recorded exchange allows offline guessing once the
  classical PKINIT key exchange of the armour falls. A `--random` OTP is not
  guessable that way.
* **Pre-authentication** inside those exchanges follows the KDC, as `kinit`
  does: libkrb5's responder is asked once per round which methods the realm
  offers, and each is answered — `passkey` by answering nothing, which hands
  the FIDO2 PIN and device presence to the installed plugin and the
  prompter; `otp` by showing the token the KDC named and asking for its
  value, and for a separate PIN when the token asks; `radius`, `idp`,
  `pkinit` and any method kuipa does not know by showing its challenge and
  asking for an answer.  A password is not answered there: libkrb5 needs the
  long-term password to build the FAST encrypted challenge, and takes it
  from the secret `--password-file` or standard input brought, else asks for
  it through kuipa's prompter, echo off.  A password never stands in for a
  passwordless method the realm offered, so a user with a token authenticates
  with the token.  FAST carries every question and answer, so an impostor's
  KDC cannot collect them either.  With no terminal to ask on, a realm that
  needs more than the secret given is refused with that reason;
  `--use-ccache` (§5.4) is how such a user enrolls from a script.
* **OTP:** a fake KDC (one named by an impostor's advertisement) could only
  answer the host's AS exchange by knowing the OTP-derived key, and learns
  nothing to guess from. The client never falls back to the LDAP-checked
  OTP on its own, since a fake KDC could force that; `--ldap-otp` chooses it
  explicitly, for hosts whose OTP sets no Kerberos key. On the first rekey
  with an OTP-derived key the daemon deletes the host's `userPassword`, so
  the OTP is spent for both paths.
* **LDAP-checked OTP** (`--ldap-otp`): the same LDAP operations as
  `ipa-join` and `ipa-getkeytab`, so lockout, password policy, `enrolledBy`
  and the one-time behaviour are unchanged. Sealed under `ss`, the OTP
  cannot be guessed offline from a recording, but a server with a stolen
  anchor learns it.
* **Kerberos:** for any user with a ticket, including external IdP and
  passkeys (§5.4). The channel binding ties the token to this KEM exchange,
  so a token lifted from one request is useless in another. The existing
  ACIs decide, applied to the caller's identity.
* Rekey accepts only the host itself; stage accepts only callers the
  directory authorises to stage.
* The client proposes enctypes (default: aes256-sha384, aes128-sha256,
  aes256-sha1, aes128-sha1); the server keeps those the realm allows.

Admin-free enrollment (OTP, bundle) is preferred: it never puts an
administrator's credential on the host.

### 5.4 Kerberos before enrollment

A host that is not enrolled has no Kerberos configuration, and external-IdP
or passkey authentication needs FAST armour, i.e. anonymous PKINIT, which
needs the KDC's PKINIT anchors. `kuipa realm-info --server … --krb5-dir DIR`
verifies the advertisement and writes, from it:

* `DIR/krb5.conf`: the realm, as KDCs this server first and then the
  other advertised servers that are among the servers to use (§4.6), no
  DNS lookups, `pkinit_anchors` and `pkinit_pool` pointing at:
* `DIR/pkinit-anchors.pem`, and `DIR/ca.crt`.

`ipa-client-install` then sets `KRB5_CONFIG` and a temporary `KRB5CCNAME`,
runs `kinit -n` (armour) and `kinit -T <armour> admin`, and calls
`kuipa enroll --use-ccache`. Password and OTP joins do the same in process
(§5.3), so they need no Kerberos configuration and no `kinit` on the host.

### 5.5 Response payload

```
realm, domain, basedn, issuer, servers[]       → configuration; issuer listed first
ca_certs[] (DER)                               → /etc/ipa/ca.crt; each must be in the advertisement
pkinit_anchors[] (DER)                         → PKINIT anchors for the generated krb5.conf
anchors[] (thumbprints) with heads[]           → /etc/ipa/ku-anchors (§4.9.4)
keytab (MIT 0x0502)                            → /etc/krb5.keytab; principal must be host/<fqdn>@REALM
```

The keytab is encoded last, so the buffer holding the keys is written once
and wiped on drop.

### 5.6 Keys are created before the client confirms

The server stores the keys, consuming the OTP, before the client has
written the keytab, exactly as `ipa-join` does. A failed install needs a new
OTP. A two-phase join would need a variant of the keytab extended operation
that keeps `userPassword` until a commit, i.e. a 389-ds change, which kuipa
avoids.

## 6. Rekey

With `ipa-getkeytab` each new key is protected by a session key derived from
the previous one, so whoever obtains an old key and recorded the rotation
gets the new key.

`POST /ipa/ku/rekey/{kid}` is the join exchange with a Kerberos
authenticator made from the host's own keytab; the server accepts only the
host's principal and generates new keys through `KEYTAB_GET`. The response
is wrapped under `ss ‖ ss_e`, so a recording plus the old host key is not
enough: the new key needs `dk_e`.

`kuipa rotate-keys` installs the new keys together with the previous kvno
(as `ipa-getkeytab` does) and, when the keytab is protected, reseals it and
re-registers fresh escrow bindings in the same request (§7.2).

## 7. Keytab protection

### 7.1 Sealed keytab

```
DEK ←$ 32 bytes                                   fresh on every seal
V = machine vault of (host/<fqdn>@REALM, keytab)                       §7.6.8
for each reachable server i with an escrow key:
    (B_i, K_i, t_i) = tang-pqc provision to server i's escrow key,
                      domain "ipa-ku-enroll/v1 escrow", info = "host/<fqdn>@REALM",
                      committed to IPCV(principal, V)
    W_i = GCM_{K_i}(DEK)
/etc/ipa/krb5.keytab.sealed = IPSK(principal, [(server_i, B_i, ek_i, t_i, W_i)], GCM_DEK(MIT keytab))
```

Each slot keeps server `i`'s public escrow key `ek_i` beside its binding,
so unsealing seals its recovery request to it without fetching anything
first; the binding's `kid` authenticates it.

Any one server can unseal. The bindings and `DEK` are created *before* the
rekey that produces the keys they protect (`Sealer::prepare`), so the
registrations travel in that same authenticated request; the keytab is
sealed once the response arrives (`Sealer::seal`).

### 7.2 Registration and recovery

Tang servers are stateless; for a host keytab that would let a stolen disk
unlock for as long as any server answers. The IPA server holds per-host
state, so escrow uses it:

* **Registration:** each binding's `H(ct)` (SHA-256) is sent in a join or
  rekey body and stored in `ipaKUEscrowBinding` on the host entry, replacing
  the previous set. Other keytabs and files register in a request of their
  own (§7.5).
* **Recovery:** `POST /ipa/ku/rec/{kid}` carries the unified request of
  §7.6.5: the principal, the vault (for host and service escrow, the
  machine vault derived from the principal and the kind, §7.6.8), the
  slot's commitment `t_i`, and a `tang-pqc` recovery request, whose binding
  ciphertext is sealed to the escrow key (`tang-pqc` DESIGN §3.3). The
  server opens it in the escrow domain and **checks the commitment** to
  `IPCV(principal, vault)`, so a binding cannot be presented under another
  principal or vault than it was made for, even where it is registered.
  It then answers only for an enabled entry of the principal
  (`nsAccountLock` not true) whose bindings registered for that kind
  (`ipaKUEscrowBinding` for keytabs, `ipaKUEscrowFileBinding` for files,
  §7.5) include the opened `H(ct)`. The principal is also bound into
  `K_i`. Before commitments, that client-side binding was all that stopped
  a principal on whose entry someone registered the same binding hash.
* **Revocation:** deleting the host, locking it (`nsAccountLock`), or
  clearing the attribute stops unsealing at once. `ipa host-disable` and
  `ipa service-disable` today only remove keys and certificates: the entry
  stays unlocked, a principal without keys may still authenticate with
  PKINIT, and its sealed files keep opening. The lock is the right signal
  (`ipa-kdb` refuses every ticket for a locked entry, PKINIT included), so
  FreeIPA's disable commands must set `nsAccountLock` (TODO); kuipad does
  not infer "disabled" from missing keys. A fresh seal (every `rotate-keys`) retires the old
  bindings, so an old disk image stops working too.

The server learns `ss` and can link recoveries; that is irrelevant here, as
it holds the host's keys and knows who asks.

### 7.3 File mode (implemented)

* `kuipa protect` rekeys with sealing, test-unseals through a server and
  compares the result with the new keys, and only then replaces
  `/etc/krb5.keytab` with a symlink to `/run/ipa/krb5.keytab` (tmpfs).
* `kuipa-unseal.service` runs `kuipa-unseal` after the network is up and
  before SSSD, gssproxy and certmonger; it writes `/run/ipa/krb5.keytab`
  (0600). Without a reachable server it exits 75 and the unit retries; the
  host boots without its Kerberos identity meanwhile.
* `kuipa-unseal` has no Kerberos rights and never rebinds; rebinding
  happens at every `rotate-keys` (monthly timer, §12).
* `kuipa unprotect` writes a plain keytab back and removes the sealed file.

| attacker has | plain keytab | sealed keytab |
|---|---|---|
| disk image or backup, no access to the realm's servers | host identity | nothing |
| disk image + server access, host enabled | host identity | host identity (as with Tang) |
| the same after `ipa host-disable` (keys removed, entry locked once FreeIPA sets `nsAccountLock`) | nothing (keys gone) | nothing |
| an image from before the last rotation, host enabled | that kvno's keys | nothing (binding no longer registered) |
| root on the running host | host identity | host identity |

### 7.4 gssproxy as the holder (implemented; gssproxy change merged)

GSS-API services that run through gssproxy never see keytabs. If gssproxy
itself unseals, the keytab never touches a filesystem. This needs no change
to MIT Kerberos — `MEMORY:` keytabs are stock, and a keytab in a memfd can be
read through `FILE:/proc/self/fd/N` and copied in — but it needed gssproxy to
learn:

1. a per-service `keytab_loader = /usr/libexec/kuipa-unseal --memfd`: run
   the loader with a memfd as fd 3, import the keytab into
   `cred_store = keytab:MEMORY:<name>`, close the memfd;
2. re-run the loader on `SIGHUP` and swap the keytab atomically;
3. retry a failing loader with backoff;
4. keep keytab memory out of core dumps.

All four landed in
[gssapi/gssproxy#135](https://github.com/gssapi/gssproxy/pull/135) (merged
2026-10-21, not in a release yet): a loader that fails or runs over five
minutes is retried from 5 s up to 10 min while the keys loaded before stay
in use, services sharing a `MEMORY:` keytab must name the same loader, and
gssproxy makes itself non-dumpable (`PR_SET_DUMPABLE`) while any loader is
configured.

`kuipa-unseal --memfd` implements the loader side. GSS-API
consumers (NFS, `mod_auth_gssapi`, sshd, `GSS_USE_PROXY=yes` applications)
fit directly. SSSD's `ldap_child` and `krb5_child`, certmonger and
`kinit -k` scripts read the keytab with libkrb5 and stay on file mode until
they move to GSS-API through gssproxy. Service principals therefore come
first; `host/<fqdn>` follows SSSD.

IPA servers' own keytabs stay plain: binding them to peer replicas would make
a full-realm cold start depend on a non-network unlocker.

### 7.5 Other keytabs and any file (implemented)

The same sealing protects a service's or a user's keytab, and any file:

```
kuipa protect --keytab /etc/httpd/http.keytab     sealed for HTTP/web1.example.test@REALM
kuipa protect --file /etc/app/secret.conf          sealed for host/<fqdn>@REALM
kuipa protect --file F --keytab K                  sealed for K's principal
```

* **Format.** A keytab is sealed as `IPSK`, byte for byte as it is on disk
  (`Sealer::seal_mit`); any other file as `IPSF`, the same layout with the
  file's contents in place of the keytab. The binding context is the
  principal in both, so `K_i` is bound to it as for the host keytab.
* **Two binding sets per entry.** A principal's keytab bindings
  (`ipaKUEscrowBinding`) are *replaced* by each seal, as for the host. File
  bindings (`ipaKUEscrowFileBinding`) are *added*, and a seal retires only
  the bindings of the seal it replaces: several files can be sealed for one
  principal, and a host rekey (which replaces the host's keytab set) leaves
  the files sealed for the host openable. Recovery accepts a binding from
  either set.
* **Registration.** `POST /ipa/ku/register/{kid}` is the join protocol with
  operation `register` and a Kerberos authenticator: the request body carries
  the new bindings and, as operation data, `IPRP(principal, kind, retire[])`;
  the response payload `IPRA(principal)` acknowledges. The caller must be
  `principal` itself, so its ticket comes from the keytab being protected,
  or, for a file, from the keytab it is sealed with (the host keytab by
  default). As with a rekey, `kb` authenticates the server's answer with the
  realm's Kerberos keys as well as the anchor. The daemon finds the entry
  as `fqdn=<fqdn>` for `host/<fqdn>`, otherwise by `krbPrincipalName` or
  `krbCanonicalName` under `cn=accounts`: hosts, services and users alike.
* **No rekey.** kuipad does not rotate other principals' keys, and copies of
  a service keytab on other machines (a cluster) must keep working. Keys the
  plain file held before protection stay valid until rotated: rotate them
  with `ipa-getkeytab -k <path>` (which writes through the symlink to the
  unsealed copy), then `kuipa protect --keytab <path>` again to reseal.
  Protecting an already-protected path always reseals what is there now and
  retires the previous seal.
* **On disk.** `kuipa protect` registers, seals into `<path>.sealed`
  (0600), test-unseals through a server and compares, writes the unsealed
  copy to `/run/ipa/kuipa/<escaped path>` (tmpfs; the name as `systemd-escape
  --path` writes it) with the original mode, owner and group, and only then
  replaces `<path>` with a symlink to it. The entry is recorded in
  `state.json` (contents, path, principal, the authenticating keytab, mode,
  owner, group).
* **At boot** `kuipa-unseal --all` (the unit's command) unseals the host
  keytab if protected and every recorded keytab and file; one failure does
  not stop the others, and any for want of a server makes it exit 75. A
  service that reads a protected path orders itself after
  `kuipa-unseal.service`. For gssproxy, `kuipa-unseal --sealed <path>.sealed
  --memfd` is the per-service loader of §7.4.
* **Undo.** `kuipa unprotect --keytab P` / `--file P` puts the plaintext
  back with its mode and owner, then retires its bindings with the same
  keytab (the keytab set cleared, or the file's bindings removed). Without a
  reachable server the plaintext is still restored and the result says the
  bindings remain registered. `kuipa leave` restores every protected path
  without contacting a server.

| attacker has | plain service keytab or file | sealed |
|---|---|---|
| disk image or backup, no access to the realm's servers | its contents | nothing |
| disk image + server access, principal enabled | its contents | its contents |
| the same after the principal is locked (`nsAccountLock`; see §7.2 for `service-disable`) | its contents (keys valid until rotated) | nothing |
| an image from before the last reseal or `unprotect` | that version | nothing (binding retired) |
| root on the running host | its contents | its contents |

### 7.6 User vaults (being implemented)

A user seals their own files with `kuipa seal`, without root, so that a copy opens only under
a policy the user chose within limits the realm sets. The realm's servers
hold the rule for releasing a key share, never the data: this is
client-side encryption with server-mediated key release, not a store of
secrets like FreeIPA's KRA-backed `ipa vault-*`.

#### 7.6.1 Goals and non-goals

A sealed file must not open:

* from a **copy at rest** (backup, disk image, copied home directory,
  stolen laptop) without the factors its vault's policy names;
* for **another user of the host** who can read the sealed file;
* once the owner is **disabled or deleted**, or the vault or the device is
  **revoked**, on any host, from then on.

Out of scope: **root on the running host** while a file is open or a
session is unlocked (root can read process memory and the kernel keyring),
and anything already released: limits govern the *release* of a key share,
never what a client does with it afterwards.

#### 7.6.2 Vaults, policies and devices

A **vault** is an entry in a central container,
`cn=<vault id>,cn=vaults,cn=kuipa,cn=etc,<suffix>`, owned by one user
(`ipaKUVaultOwner`). The vault id is 16 random bytes in hex, chosen by the
server at creation. The entry holds:

| attribute | content |
|---|---|
| `ipaKUVaultOwner` | the owner's principal |
| `ipaKUVaultName` | the owner's label (unique per owner) |
| `ipaKUVaultPolicy` | JSON, below |
| `ipaKUVaultDevice` | one value per registered device key, below |
| `ipaKUVaultSessionKey` | offline sessions only: the current epoch's session key, sealed to each server's escrow key (§7.6.6) |
| `ipaKUVaultState` | `enabled` or `revoked` |

The **policy**:

| field | meaning | enforced |
|---|---|---|
| `factors.device` | `none`, or the least device-key level: `any`, `hardware-wrapped`, `hardware-bound` | by the server: the answer is encrypted to a registered device key of that level, and the file's device share needs it (§7.6.4) |
| `factors.ticket` | an unlock needs a ticket naming the owner as client: one from the owner's login (PAM through SSSD, `kinit`) or obtained for them by the host through protocol transition and S4U2Proxy (sshd on Fedora and RHEL after a public-key login), which then attests the host's vouch, not the owner's credentials | by the server |
| `ticket.delegation` | `allow` (the default), `refuse` (only tickets from the owner's own credentials), or `via` a list of services a delegated ticket may have passed through (e.g. only `host/devvm1.example.test`) | by the server, from the PAC's S4U delegation info |
| `factors.passkey` | an unlock needs a passkey assertion from any of the owner's IPA passkeys (`ipaPassKey`): managing a user's passkeys in IPA manages their vault access too | by the server |
| `not_after` | no unlock after this time | by the server |
| `max_unlocks` | releases over the vault's life | by the server, approximately across replicas (§7.6.7) |
| `sessions.reauth` | the longest re-authentication session, or off | by the server (§7.6.6) |
| `sessions.offline` | the longest offline session and the key epoch, or off (the default) | release by the server; the session's end only by the client (§7.6.6) |
| `sealing` | `offline` (the default: commitment only, no network) or `registered` (implemented: after sealing, the client registers the file's binding hashes with the vault operation `register`, kept in `ipaKUVaultBinding` and left out of descriptors, at most 4096; a server releases a file's share only while its hash is registered; `kuipa seal reseal` retires the old file's hashes and `kuipa seal retire` retires a file's, so every copy of it stops opening) | by the server |

A policy needs **at least one factor besides the server share** (any
non-empty combination of `device`, `ticket`, `passkey`): a copy plus network
access alone never opens a file. That is what makes a user vault stronger
than host escrow (§7.5), whose files open without a human.

**Realm limits** (`cn=vault-limits,cn=kuipa,cn=etc`, set by administrators,
later per group): the furthest `not_after`, the largest `max_unlocks`,
vaults per user, devices per vault, the longest sessions, whether offline
sessions are allowed at all (by default they are not: an administrator
opts the realm in), and the factor shapes allowed (for example: `ticket`
alone not allowed). Users create and change their own vaults (self-service)
within these limits; the server refuses a policy outside them.

A **device** is an ML-KEM key pair of the owner; its public half is
registered in the vault:

```
ipaKUVaultDevice = { "id": thumbprint(dpk), "label", "dpk": <ML-KEM public key>,
                     "level": "any" | "hardware-wrapped" | "hardware-bound",
                     "type": "file" | "passkey" | "pkcs11" | "pkcs11-wrapped",
                     "attestation": <summary>, "added": <time> }
```

| type | where the decapsulation key is | highest level |
|---|---|---|
| `file` | `device.key` in the user's kuipa directory: `IPDK(kdf, iterations, salt, GCM_k(private JWK))` with `k = PBKDF2-HMAC-SHA-512(passphrase, salt)`, 600 000 iterations (native-ossl exports no encrypted PKCS#8 for ML-KEM keys, so the format is kuipa's own) | `any` |
| `passkey` | a key file encrypted under the FIDO2 `hmac-secret` (WebAuthn PRF) output of a passkey; every use needs a touch or PIN | `hardware-wrapped` |
| `pkcs11-wrapped` | a key file wrapped by an AES key on a PKCS#11 token (`CKM_AES_KEY_WRAP_KWP`); RSA or EC wrapping is refused (harvest-now-decrypt-later) | `hardware-wrapped` |
| `pkcs11` | an ML-KEM key generated on a PKCS#11 3.2 token (`CKM_ML_KEM`), non-extractable, used by `pkcs11:` URI through OpenSSL's pkcs11-provider (implemented: kuipa loads the provider into its own library context with a configuration written to the user's runtime directory, passes the PIN as the URI's `pin-value`, and decapsulates on the token; the host remembers the module and URI in `device.pkcs11`; tested with kryoptic) | `hardware-bound` |

No attestation is verified yet, so every device is registered at `any`.
A session cannot cache a token's key (it never leaves the token), so
opening during a session still asks for the PIN. A type sets the highest
level a device can have; the server grants it only
when the registration's attestation verifies, and records `any` otherwise.
A software token behind PKCS#11 (SoftHSM), or a passkey without
attestation, is an `any` device. That is also the unattended case: a token
whose PIN a job holds works without a human, at level `any`.

The levels say what an attestation can prove, and no more:

* **`hardware-bound`**: the attestation (the token vendor's key attestation,
  checked against roots an administrator configures) covers the ML-KEM key
  itself and its non-extractability, so no other copy exists.
* **`hardware-wrapped`**: the attestation covers the *wrapping* key only:
  for a passkey, its WebAuthn attestation checked against the FIDO Metadata
  Service, made over a challenge `H(dpk)`; for an AES-wrapped key, the
  token's attestation of the AES key. Nothing proves the ML-KEM key was
  never copied before it was wrapped.
* **`any`**: nothing is attested. A passphrase cannot be proven, so the
  server never learns whether a file key has one.

A device registration needs the owner's ticket. It carries no proof of
possession of `dpk`: registering a key one does not hold only gives away
one's own files' device shares.

#### 7.6.3 The vault descriptor

Sealing is offline, so the client keeps a **descriptor** of each vault:
id, owner, policy, devices, the realm's escrow keys, and the current
session-key epoch. The server signs it with its advertisement signing key
(ML-DSA, context `ipa-ku-enroll/v1 vault descriptor`); the client verifies
it against the pinned anchors through the delegation, as an advertisement
(§4.2). Without a signature, whoever could write the cache could add a
device key, and every file sealed afterwards would carry a device share for
it. A descriptor is refreshed at every online vault operation. Sealing is
refused after the vault's `not_after`, and with a descriptor older than a
realm limit (default 30 days), so a revoked device or vault stops receiving
new files within that time even on a host that stays offline.

#### 7.6.4 Sealed file format

```
A, B ←$ 32 bytes each                      server share, device share
DEK = HKDF(A ‖ B, "ipa-ku-enroll/v1 vault dek" ‖ V ‖ P)    (with factors.device = none: B is empty)
ctx = BindingContext("ipa-ku-enroll/v1 vault", P ‖ V)
for each server i:   (B_i, ss_i) = tang-pqc provision to ek_i under ctx
                     K_i = binding key (ss_i, r_i, ctx);  W_i = GCM_{K_i}(A)
                     t_i = HMAC(HKDF(ss_i, "commit"), "vault" ‖ P ‖ V)
for each device j:   (c_j, s_j) = ML-KEM.Encaps(dpk_j)
                     L_j = HKDF(s_j, "ipa-ku-enroll/v1 vault device" ‖ V ‖ id_j);  U_j = GCM_{L_j}(B)
IPUF = P ‖ V ‖ [(server_i, B_i, ek_i, t_i, W_i)] ‖ [(id_j, c_j, U_j)] ‖ GCM_DEK(file)
```

* **Two shares.** The server share `A` comes back only through a server,
  under policy. The device share `B` needs a registered device's
  decapsulation key. With `factors.device`, neither alone opens the file,
  and in particular the realm's administrators, who can reach the escrow
  keys, cannot read a user's files without the user's device.
* **Any registered device.** The file has one slot per device registered
  when it was sealed; a device added later opens only files sealed or
  resealed after it (`kuipa seal reseal`).
* **The commitment `t_i`** ties the binding to `(P, V)` in a way the server
  can check (§7.6.5). Without it the server sees only the binding's
  ciphertext, and a client could present someone else's binding under a
  vault whose policy it satisfies, receive `ss_i`, and derive `K_i` from
  the context stored in the file.
* **Session-mode files** (§7.6.6), when built, replace the per-server
  slots by one slot sealed to the vault's epoch-`e` session key, in a
  format of their own.

#### 7.6.5 Unlock and the unified recovery request

One recovery request serves user vaults and the host and service escrow of
§7.2 and §7.5, which become **machine vaults** with a fixed policy (§7.6.8):

```
IPEQ = P ‖ V ‖ t_i ‖ tang-pqc RecoveryRequest ‖ device id (or none)
       ‖ [GSS-API token, cb = H(the fields above)]
       ‖ [WebAuthn assertion, challenge = H(the fields above)]
       ‖ [session token]
```

The server:

1. opens the tang-pqc request with its escrow key, in the escrow domain;
2. checks the **commitment**: recomputes
   `HMAC(HKDF(ss, "commit"), "vault" ‖ P ‖ V)` and compares it with `t_i`
   in constant time (`tang_pqc::OpenedRequest::verify_commitment`, a new
   extension point that does not change the Tang wire format);
3. looks up vault `V` and checks owner `P`, `ipaKUVaultState`, the owner's
   `nsAccountLock`, `not_after`, the unlock count, `sealing = registered`
   bindings, and the factors: the ticket (accepted with `cb`, caller must
   be `P`), the assertion (verified against `ipaPassKey`, ML-DSA or the
   classical algorithms the realm allows), or a valid session token;
   kuipad acts as the relying party here;
4. answers with `ss`, encrypted to the named device's `dpk` when
   `factors.device` is set (a fresh ML-KEM encapsulation to `dpk`, then
   GCM under a key derived from it and the request hash), else under the
   tang-pqc transport key alone.

Encrypting the answer to `dpk` makes the device factor the server's to
enforce: only a registered device of the required level can read the
answer, revoking a device takes effect at the next unlock, and the
device's level, checked at registration, decides whether it qualifies.
The device share `B` is the part that keeps the server's operators out.

#### 7.6.6 Sessions

The policy enables either kind, both or neither. Offline sessions are off
unless both the vault's policy and the realm limits turn them on: they are
the one place where a limit stops being the server's to enforce.

* **Re-authentication session** (implemented). The owner starts one with
  the vault operation `unlock` (`kuipa seal unlock`), authenticated by
  their ticket, naming a registered device. The server answers with a
  **session token** `IPST(V, owner, device, not_after)`, `not_after` at most
  `sessions.reauth` ahead and never past the vault's own end, signed with
  its advertisement signing key under its delegation (context
  `ipa-ku-enroll/v1 vault session`), so any server checks it against its
  anchors. An unlock request carrying the token is accepted in place of the
  ticket and passkey factors, for the named device only, while the policy
  still allows sessions. Every open still reaches a server, so the
  session's end, the counts, revocation and the audit stay the server's.
  Sessions need `factors.device`: the answer is encrypted to the device, so
  a token is useless without the device key, and a policy without the
  device factor cannot have sessions (a token alone would open the vault).
  The client keeps the token **and the unwrapped device key** in the
  user's runtime directory (`$XDG_RUNTIME_DIR/kuipa/sessions/<vault>`:
  tmpfs, the user's own, 0600, gone at logout) until the session ends or
  `kuipa seal lock`, so a session spares the passphrase as well as the
  ticket; the key never touches a disk unwrapped.
* **Offline session** (implemented). A vault whose policy has
  `sessions.offline` (and which the realm limits allow; both off by
  default) has a **session key** per epoch: an ML-KEM pair `(vk_e, dk_e)`
  made by a server. Each epoch's public half goes into the descriptor;
  `dk_e`'s private JWK is stored in `ipaKUVaultSessionKey` (one JSON value
  per epoch), sealed to every server's escrow key: each kuipad publishes
  its current escrow public key on its `cn=masters` entry
  (`ipaKUServerEscrowKey`), and a server that can open an epoch key seals
  it to every published key without a slot, at every vault operation, so a
  replica that joins later can release older epochs once any server has
  seen the vault. A server starts epoch `e+1` when `sessions.epoch`
  (default 30 days) has passed since epoch `e` began. Session-mode files
  (`kuipa seal file --session`, `IPUS`) seal `A` to `vk_e` in place of the
  per-server slots, with the device slots as usual. The vault operation
  `unlock` with `offline`, authenticated by the owner's ticket and
  counted as one unlock, releases every epoch's key so far, encrypted to
  the device (`IPEK`); the client keeps them with the unwrapped device key
  in the user's runtime directory until the session ends (at most
  `sessions.offline`) or `kuipa seal lock`, and opens session-mode files
  without any server meanwhile.
  **Once released, `dk_e` can be kept**: the timeout is the client's
  courtesy, not a guarantee, and the server no longer sees individual
  opens. A new epoch starts every policy period; files sealed in an earlier
  epoch need a release of that epoch's key, so an old leak does not open
  new files. A vault without offline sessions has no session key, no
  `ipaKUVaultSessionKey`, and no session-mode files.

**Passkeys without a browser.** The client is `kuipa`, not a browser, so it
talks to the authenticator through libfido2 at the CTAP level, as SSSD's
`passkey_child` does for passkey logins: the challenge is the CTAP
`clientDataHash`, set to the request hash directly, with no
`clientDataJSON` around it, and the RP ID is the one the realm's passkeys
are registered under (the IPA domain, as `ipa passkeyconfig` and SSSD use
it), with user verification as that configuration requires. The same
libfido2 calls give the `hmac-secret` output for passkey-wrapped device
keys.

**Delegated tickets.** A ticket from S4U2Proxy is as good as the host that
obtained it: whoever holds that host's keys can obtain one for any user its
delegation rules cover. The realm's delegation rules decide which hosts may
act for users towards `ipa-ku/<server>`; a host whose keytab is sealed
(§7.3) cannot be cloned from a snapshot to mint them. Forwarding a
ticket-granting ticket (`ssh -K`) is not the intended path: it puts an
unrestricted credential on the host. The KDC records the delegation in the
ticket's PAC: the S4U delegation info lists the services the ticket passed
through to get here. kuipad reads it from the accepted context's PAC and
applies `ticket.delegation`: with `refuse`, any delegation info refuses the
ticket; with `via`, every transited service must be on the list. A ticket whose delegation the directory cannot tell (no PAC, or a
directory that does not read it yet: kuipad until the PAC work lands) is
accepted only under `allow`.

#### 7.6.7 Counting unlocks (implemented)

`max_unlocks` is a grow-only counter per vault and server, kept on the
vault entry: `ipaKUVaultUnlocks` holds one value `<server> <count>` per
server, and each server replaces only its own value (delete the old, add
the new, in one modify), so 389-ds's multi-master replication merges the
values of different servers without conflict and the total is their sum.
Every release is counted, with or without a limit, so `kuipa seal show`
reports it. A server refuses once the sum reaches the limit. The overshoot
is bounded by the releases other servers make within one replication
delay. Expiry, revocation, the factors and the device checks are exact;
the count is the only approximate limit. (An earlier draft carried the
counter in the anchor exchange's gossip; per-server LDAP values give the
same convergence without extending that state.)

#### 7.6.8 Machine vaults: host and service escrow on the same path (implemented)

Host and service keytabs and files sealed for machines (§7.1, §7.5) keep
their behaviour, but their bindings carry the commitment and their recovery
uses the request of §7.6.5:

* `V` is derived, the first 16 bytes of `SHA-256("ipa-ku-enroll/v1
  machine vault" ‖ kind ‖ P)`, and has no entry; its policy
  is fixed: server share only, `sealing = registered` (each seal's binding
  registered, as `ipaKUEscrowBinding` and `ipaKUEscrowFileBinding` are
  today, so an old image stops opening), no sessions, no count.
* Every binding carries the commitment, so the server's check no longer
  rests on the registration alone.
* A TPM-protected machine key, when the TPM factor (§7.1) is built, is a
  machine vault with `factors.device = hardware-bound`.

#### 7.6.9 Client

Users run `kuipa seal` with their own ticket (`KRB5CCNAME`); nothing
needs root. The realm comes from the host's world-readable files:
`/var/lib/ipa-client/ku/realm.json` (realm, FQDN, servers, written beside
the root-only state), `/etc/ipa/ku-anchors` and `/etc/ipa/ca.crt`.
Per-user state lives in `$KUIPA_USER_DIR`, else `$XDG_DATA_HOME/kuipa`,
else `~/.local/share/kuipa` (0700, files 0600): `device.key`,
`vaults/<name>.vault` (the last signed descriptor of each vault) and
`servers.json` (each server's signed advertisement with when it was
fetched, re-verified as of then when sealing offline, and used no longer
than the descriptor's age limit). A ticket is sent with every unlock when
one is available; vaults that do not ask for it ignore it.

```
kuipa seal create VAULT [--expires D] [--max-unlocks N]
                        [--require device=LEVEL,ticket,passkey]
                        [--ticket-delegation allow|refuse | --ticket-via SERVICE…]
                        [--sessions reauth=T,offline=T/EPOCH] [--sealing registered]
kuipa seal device add VAULT (--passphrase | --passkey | --pkcs11 URI | --pkcs11-wrap URI)
kuipa seal device remove VAULT ID
kuipa seal file VAULT FILE [--out F.sealed] [--session]      offline by default
kuipa seal open F.sealed --out F|- [--force] [--passphrase-file F]
kuipa seal unlock VAULT [--offline] | lock VAULT              sessions
kuipa seal reseal VAULT F.sealed…                             new devices, new epoch
kuipa seal list | show VAULT | revoke VAULT
```

`open --out -` follows `kuipa-unseal`'s rules (§10.5): standard output
only when it is not a terminal, unless `--force`.

#### 7.6.10 What each attacker gets

| attacker has | file sealed with `device` | `ticket` or `passkey` only |
|---|---|---|
| a copy of the sealed file, network access | nothing | nothing |
| the copy and the owner's device key file, network access | nothing without the device's passphrase, touch or token | — |
| the copy and the owner's password | nothing (no device) | the file, from anywhere, unless `passkey` is required too |
| the realm's escrow keys (an IPA administrator) | nothing (no device share) | the file |
| a released offline-session key | that epoch's session-mode files, for as long as it keeps the key | — |
| any of the above after the vault, device or owner is revoked or disabled | nothing new (released keys stay released) | nothing new |
| root on the running host during a session | the open files and the session key | the same |

#### 7.6.11 Work this needs

* `tang-pqc`: `OpenedRequest::verify_commitment` and a client-side
  `Binding::commitment` (extension points, §8 of its DESIGN).
* `kuipa-enroll`: the `IPUF` format, the unified `IPEQ`, encrypted
  answers, session tokens, signed descriptors; machine vaults replacing the
  escrow check of §7.2.
* `kuipad`: the vault container and limits, vault and device operations
  (Kerberos-authenticated, as the registration of §7.5), the recovery
  checks, the counter in the anchor exchange's CRDT, and relying-party
  verification of passkey assertions and FIDO MDS attestation copied from
  ahdapa (`src/auth/passkey.rs`, `src/auth/fido_mds.rs`) into a kuipa
  crate, adapted to CTAP-level assertions (a raw `clientDataHash`, not a
  browser's `clientDataJSON`). ahdapa has no client side: there the browser
  is the client.
* `kuipa`: `kuipa seal`; device key types: PBES2 PKCS#8 files (OpenSSL),
  PKCS#11 through pkcs11-provider, and a borrowed libfido2 FFI crate for
  `hmac-secret` and assertions (against the libfido2 from abbra/pqc for
  ML-DSA passkeys).
* FreeIPA: schema and ACIs for the container, `vault-limits`, and a
  framework front end for administrators (list, revoke, set limits).

#### 7.6.12 Decisions

Settled with the design: the threat model of §7.6.1; factors configurable
per vault, any non-empty combination besides the server share; offline
sealing with a server-checked commitment, `registered` sealing as a policy
option; device levels `any` / `hardware-wrapped` / `hardware-bound`, with
file (PBKDF2 everywhere, for FIPS), passkey-wrapped, PKCS#11-wrapped and
PKCS#11-native keys; files sealed to every registered device; both session
kinds as separate policy options, offline sessions off by default in each
vault and in the realm limits; delegated tickets allowed by default,
refusable or limited to the services they passed through
(`ticket.delegation`); the unlock counter as per-server values on the vault entry
(replicated by 389-ds; the earlier choice was the anchor exchange's CRDT);
re-authentication sessions that also keep the unwrapped device key in the
user's runtime directory; self-service within realm limits; vault entries in a
central container; passkeys as both an unlock factor (any of the owner's)
and a key wrapper; ahdapa's relying-party code copied into kuipa; one
recovery path for user and machine vaults; the command named `kuipa seal`
(the server object stays a vault, distinct from `ipa vault-*`);
offline-session keys sealed per server in the vault entry; descriptors
older than 30 days (a realm limit) refused for sealing.

## 8. Offline enrollment

### 8.1 Flow

1. **Staging** (online, administrator): the server creates the host's keys
   and packs everything the host needs into a signed **bundle**.
2. **Opening** (offline, host): the host verifies the bundle against a
   pinned anchor, opens it and installs the enrollment.
3. **First contact** (online, later): the host rekeys with the staged keys
   and the deferred installer steps run.

### 8.2 Recipient modes

| mode | opened with | bundle in transit | use for |
|---|---|---|---|
| A, machine key (default) | an ML-KEM key the host generated (`kuipa prepare`) | safe on any channel | hosts that can report a key first |
| B, secret | a 256-bit secret `S` generated by the server, carried in the enrollment string | safe while the two channels stay apart | images and clouds without a per-host key |
| C, signed only | nothing | as safe as a copied keytab | lab use; must be explicitly accepted when opening |

In mode A the public key must reach the administrator authentically, or an
attacker substitutes their own. `S` is server-generated and never a
password, so there is no offline guessing.

### 8.3 Staging

A stage request is the join exchange at `stage/{kid}` with an
administrator's Kerberos authenticator and the staging parameters
(`IPSX(mode, recipient ek_m, not_after)`) in `extra`. The directory checks
the caller, creates keys (staging again replaces them, so at most one bundle
is live per host), and records:

* `krbPrincipalExpiration = not_after`: `ipa-kdb` maps it to the KDC entry,
  so the staged keys stop working on schedule without client cooperation;
* `ipaKUStaged = {"not_after", "recipient"}`.

The server then builds the bundle:

```
header = IPOH(mode, alg, realm, fqdn, id(16), iat, not_after, recipient_thp, signer_thp)
A: (ct, ss) = ML-KEM.Encaps(ek_m);  k = HKDF(ss, "bundle",        H(header ‖ H(ct)))
B: ct = empty;                      k = HKDF(S,  "bundle-secret", H(header ‖ H(ct)))
sealed = GCM_k(payload)             (C: the payload in the clear)
sig = ML-DSA(server signing key, IPOB(header fields, ct, sealed, delegation),
             context "ipa-ku-enroll/v1 bundle")
```

The payload is the join payload (§5.5). The signature covers the
ciphertext, so tampering is rejected before decapsulation; its non-empty
context keeps bundle signatures apart from the same key's JWS signatures.
The bundle carries the staging server's delegation with its own anchor's
signature only, so the host must pin that anchor: a mode B enrollment
string names it, and the realm's anchor list includes it. Staging refuses a
`not_after` beyond the delegation. The stage response carries the bundle
and, in mode B, `S`, wrapped under `ss ‖ ss_e`.

### 8.4 Opening

`kuipa enroll --bundle FILE`:

1. Verify the delegation **as of the bundle's `iat`** (an offline host's
   clock is not trusted), check it names the bundle's signer and realm, that
   `not_after` lies inside it, and the signature.
2. Refuse a bundle for another host (`--hostname`), and refuse one whose
   `not_after` has passed (exit 1: stage the host again). The KDC enforces
   the real expiry regardless of the host clock.
3. Open with the machine key, `S`, or (signed-only, explicitly) nothing;
   check the principal and realm; install as for an online join.
4. Delete the machine key, and write the pending file listing the deferred
   steps: `rotate-keys`, `kinit`, `ca-certs`, `dns-update`, `ssh-keys`,
   `host-certificate`, `time-sync`, `automount`.

### 8.5 First contact

`kuipa complete` (run by `ipa-client-complete.service`) rekeys with the
staged keys. The server's rekey clears `ipaKUStaged` and
`krbPrincipalExpiration` and logs the first contact. On success the pending
file is removed and the remaining steps are reported for
`ipa-client-install`. A refusal exits 1 (an administrator must act); any
other failure, such as no reachable server or staged keys not replicated
yet, exits 75 so the unit retries.

| attacker | mode A | mode B | mode C |
|---|---|---|---|
| copies the bundle | nothing | nothing without `S` | the host identity until first contact or `not_after` |
| also has `dk_m` (before deletion) / `S` | host identity until first contact or `not_after` | same | — |
| records it, quantum later | nothing | nothing | — |
| forges or modifies it | needs a delegated server key | same | same |
| replays an old bundle after re-staging | keys replaced, refused by the KDC | same | same |
| moves the offline clock back | the KDC still enforces `not_after` | same | same |

Someone holding the staged keys can rekey before the real host; the real
host's rekey then fails, and the server log shows the unexpected first
contact. A short `not_after` keeps the window small.

**Size** (measured): 17.9 KB (ML-KEM-768 + ML-DSA-65) and 23.2 KB
(ML-KEM-1024 + ML-DSA-87) with a 1.5 KB CA, mostly the delegation, the
server's signing key and the signature. Both proofs stop verifying when
their vouch expires, but a bundle is checked at its own `iat` (§8.4), so
it stays usable until its `not_after`. Both exceed a 16 KB cloud user-data limit; deliver bundles by
config drive, ISO or object storage, and keep the enrollment string in
user-data.

## 9. Vouchers

For bulk provisioning a voucher replaces the OTP (`auth_type` 3). Three
roles take part, and blind signing earns its place only when the issuer is
a different party than the provisioner (otherwise plain ML-DSA signatures
would do the same):

* the **issuer** holds a dedicated ML-DSA voucher key and a quota;
* the **provisioner** decides which hosts may join, in which host group;
* the **host** joins with the voucher.

A voucher is an ML-DSA signature, with context `ipa-ku-enroll/v1 voucher`,
on `salt ‖ m`:

```text
m = "IPVM" ‖ realm ‖ fqdn ‖ hostgroup ‖ not_before ‖ not_after ‖ binding
binding = SHA-256("ipa-ku-enroll/v1 voucher binding" ‖ ek_e)  or zeros
```

The provisioner blinds `m` with `ml-dsa-blind` (`μ = SHAKE256(tr ‖ 0 ‖
|ctx| ‖ ctx ‖ salt ‖ m)` with a fresh secret salt) and sends the issuer
the 64-byte `μ`; the issuer signs it with stock OpenSSL ML-DSA in
external-μ mode, never seeing realm, host or group, and counts it against
its quota before signing — one-more unforgeability makes that count exact.
The provisioner checks the answer against `μ` and keeps `(salt, σ)`: an
ordinary ML-DSA signature that any FIPS 204 verifier checks.

The realm accepts vouchers under the public keys in its key directory
(`add-voucher-key`, §11.2) and lists them in the advertisement's signed
`kuipa_vouchers` member, each JWK with `ipa_use: "voucher"`. They are a
member rather than JWK Set entries because Tang takes every signature key
in the set for an advertisement signer. A key per epoch is retired by
deleting its file.

The server opens the join request as for an OTP join, then verifies the
voucher with the public key only: the key is one it accepts, the realm and
FQDN are the request's, now is within `not_before`…`not_after`, and a
non-zero `binding` matches the request's `ek_e`. The directory then, as
the daemon, adds the host entry with the spent salt in `ipaKUVoucherSpent`
(refusing a spent salt and, by the add itself, an existing FQDN), adds it to
the host group, and creates the keys. A voucher therefore creates one host
once. A bound voucher is useless to anyone without the host's ephemeral
private key, which `kuipa voucher-key` makes on the host before the
voucher is requested; an unbound voucher is a bearer credential until used.

Tools: `kuipa-voucher` (§10.6) for the issuer and the provisioner;
`kuipa voucher-key` and `kuipa enroll --voucher-file F [--ephemeral-key
F]` on the host (§10.1). The text form is `ipa-ku-voucher1:<base64url(IPVO)>`.

## 10. Client: `kuipa` and `kuipa-unseal`

### 10.1 Commands

Commands are user tasks; protocol steps (advertisements, failover,
rebinding, resealing, anchor refresh) happen inside them.

| command | does |
|---|---|
| `prepare [--new] [--hostname H]` | create (idempotently; `--new` replaces) the mode A machine key; print its thumbprint, the public-key file and the administrator's staging command |
| `enroll [--server S… \| --domain D] [--hostname H] [--enrollment-file F]` | online join with the OTP from the enrollment string, as the host's temporary Kerberos key (§5.3) |
| `enroll … --ldap-otp` | online join with the OTP checked by an LDAP bind on the server: the anchor alone authenticates the server |
| `enroll … --principal P [--password-file F]` | online join with `P`'s password, through an armoured `kinit` on the host (§5.3) |
| `enroll … --realm R (--principal P \| --use-ccache \| --voucher-file F)` | as above, verified against the pre-provisioned `/etc/ipa/ku-anchors` instead of an enrollment string (§4.4) |
| `enroll … --use-ccache` | online join with the ticket in `KRB5CCNAME` |
| `enroll … --voucher-file F [--ephemeral-key F]` | online join with a voucher (§9), with the ephemeral key it is bound to |
| `voucher-key --out F` | make the ephemeral key to bind a voucher to; print its binding (§9) |
| `enroll --bundle F [--enrollment-file F] [--hostname H] [--insecure-signed-only]` | offline enrollment (§8.4) |
| `realm-info --server S… --krb5-dir D [--realm R]` | Kerberos configuration for enrolling with a ticket (§5.4) |
| `complete` | finish an offline enrollment (§8.5) |
| `rotate-keys` | new host keys (§6), resealing when protected |
| `protect` / `unprotect` | seal / unseal the host keytab, file mode (§7.3) |
| `protect` / `unprotect --keytab F` | the same for another keytab (a service's or a user's), sealed for its own principal; `protect` again reseals (§7.5) |
| `protect` / `unprotect --file F [--keytab K]` | the same for any file, sealed for `K`'s principal (default: the host) (§7.5) |
| `trusted-realms` | install, refresh and remove the trusted realms the host's realm advertises: their anchors, PKINIT anchors, CA and `krb5.conf.d` snippets (§17.3) |
| `status` | local state: realm, principal, kvno, servers, anchors, trusted realms, protection and the other protected keytabs and files, pending steps, which ML-KEM sets the system policy allows |
| `check [--server S]` | for each server: advertisement and delegation (warns under 14 days, and when only a succession of rotated anchors verifies it, §4.7), a `kinit` with the host keys, and a test unseal when protected and of every other protected keytab and file; each problem with the fix |
| `advertisement [--server S… \| --domain D] [--enrollment-file F \| --realm R]` | for each server: its verified advertisement — realm, domain, KDCs, signing key and which anchor proves it, delegation and vouch lifetimes, join/escrow keys, CA and PKINIT anchors, the anchors vouched for each trusted realm — and the anchor log behind its head: every entry with its landmark head and successions (§4.8).  Then a per-key index of those same facts, derived without a second fetch: for every anchor or signing key these servers name, whether this host pins it, which servers' claims it proves, which servers call it a current anchor and at which log sequences, which trusted realm's anchors it is, and what it replaces or is replaced by (§4.2, §4.6, §4.7); reads and verifies, writes nothing |
| `seal create|policy|device add|device remove|file|open|reseal|show|list|revoke` | a user's own vaults, as that user with their ticket (§7.6.9); `open --out -` writes only the plaintext to standard output and nothing else, as `kuipa-unseal` does |
| `leave` | remove what kuipa installed besides the keytab (sealed file, anchors, generated Kerberos files, machine key, state); a sealed keytab is first written back in plain form for `ipa-join --unenroll`, and so is every other protected keytab and file |

Common rules:

* Secrets never come from argv. The enrollment string comes from
  `--enrollment-file`, `KUIPA_ENROLLMENT_FILE` or standard input; the
  password from `--password-file` or standard input. From a pipe the
  enrollment string is the first line and the password the next; on a
  terminal each is prompted for, the password without echo. An empty value
  is an error, never an empty secret. With `--realm` alone no enrollment
  string is read, and an OTP join needs one; with `--realm` and an
  enrollment file (`--enrollment-file` or `KUIPA_ENROLLMENT_FILE`), the
  string must be for that realm (§4.4). An expired enrollment string, or `--realm` with only expired pins, is refused
  before anything is sent.
* Commands that talk to servers use `--server`, else the stored server
  list, else DNS SRV records (§4.6).
* `--json` prints a JSON object; otherwise a readable rendering of it.
* Exit status: 0 success; 75 retry later; 1 needs an administrator, or any
  other error; 2 usage. `check` exits 1 when it finds problems.

### 10.2 Files and environment

| path (under `KUIPA_ROOT`, default `/`) | content |
|---|---|
| `etc/krb5.keytab` | the host keytab (a symlink to `run/ipa/krb5.keytab` when protected) |
| `etc/ipa/ca.crt` | the IPA CA chain |
| `etc/ipa/ku-anchors` | pinned anchors of the host's realm, one per line; a line may add the pin's expiry, `<thumbprint> <unix seconds>`, after which it is ignored, and the anchor's vouch head, `<size> <root>` (§4.9.4); lines written from server responses carry the head and no expiry |
| `etc/ipa/ku-anchors.d/<REALM>`, `var/lib/ipa-client/ku/trusts/<REALM>/`, `etc/krb5.conf.d/kuipa_trust_<REALM>` | a trusted realm's anchors, PKINIT anchors and CA, and Kerberos configuration (§17.3) |
| `etc/ipa/krb5.keytab.sealed` | the sealed keytab |
| `run/ipa/krb5.keytab` | the unsealed keytab in file mode |
| `<path>.sealed`, `run/ipa/kuipa/<escaped path>` | another protected keytab or file, sealed and unsealed; `<path>` is a symlink to the latter (§7.5) |
| `var/lib/ipa-client/ku/state.json` | realm, FQDN, servers (issuer first), protection, other protected keytabs and files |
| `var/lib/ipa-client/ku/realm.json` | realm, FQDN and servers again, world-readable, for users' `kuipa seal` |
| `var/lib/ipa-client/ku/krb5.conf`, `pkinit-anchors.pem` | Kerberos configuration generated from the enrollment |
| `var/lib/ipa-client/ku/recipient.jwk`, `recipient.pub.jwk` | the mode A machine key |
| `var/lib/ipa-client/ku/pending.json` | deferred steps after offline enrollment |

All private files are written atomically with mode 0600.

| variable | effect |
|---|---|
| `KUIPA_ROOT` | root for all paths above |
| `KUIPA_ENROLLMENT_FILE` | default enrollment-string file |
| `KUIPA_ENDPOINTS` | `fqdn=target,…`: reach a server at a URL or `unix:/path` instead of `https://<fqdn>/` |
| `KUIPA_DNS` | `address:port` of the one nameserver to ask for SRV records, instead of the system configuration |
| `KUIPA_KDC` | the one KDC (as `krb5.conf` names it, e.g. a Unix socket) for the armoured exchanges of password and OTP joins, instead of the advertised servers (tests, local use) |
| `KUIPA_TRACE` | `tracing` filter directives (`debug`, `kuipa_tools=trace,kuipa_gssapi=debug`, …) for the trace of §10.4; overrides `--verbose` and `--trace` |
| `KRB5_CONFIG`, `KRB5CCNAME` | used as given; with no `KRB5_CONFIG`, `kuipa` uses `/etc/krb5.conf` followed by the generated `krb5.conf`, so a host whose system configuration does not know the realm can still rotate and check |

### 10.3 Transport

HTTP is `reqwest` (blocking) over rustls with the `rustls-native-ossl`
provider, installed process-wide. `GET adv` names the pinned anchors as
`?anchor=` parameters (§4.3). On first contact it accepts any TLS
certificate (handshake signatures are still checked); once the advertisement
verifies, the join is sent over a new connection that verifies the server
against the advertised CA, and every later operation verifies against the
installed CA (`OsslServerCertVerifier`). Plain `http://` and `unix:` targets
are accepted for tests and local use.

### 10.4 Tracing

`kuipa` and `kuipa-unseal` trace what they request and retrieve on
standard error (standard output keeps the result), through `tracing` and
`tracing-subscriber` as in akamu and ahdapa:

* `--verbose`: each step — every HTTP request (method, URL, size) and its
  answer (status, size, time); each advertisement verified or rejected (the
  server, its realm, the signing key, the anchor whose delegation signature
  was accepted, days left); failover decisions; each join, rekey or stage
  request (operation, host, realm, authentication, join key) and what came
  back (principal, kvno, enctypes, CA certificates, anchors, issuer); GSS-API
  tokens (target and size); escrow recoveries; bundles; trusted realms; every
  file written or removed (path, size, mode).
* `--trace`: also the details — endpoints and their TLS mode, and the full
  contents of advertisements and enrollments (servers, key ids, anchors,
  trusted realms).
* `KUIPA_TRACE`: filter directives instead of either flag.

OTPs, passwords, keys and GSS-API tokens are never traced, only their sizes
and thumbprints; the flow tests capture a full trace of an OTP and a
password enrollment and check that neither secret appears.

### 10.5 `kuipa-unseal`

Unseals through the first server that answers for a registered binding, and
writes the MIT keytab to `/run/ipa/krb5.keytab` (default) or to fd 3
(`--memfd`, the gssproxy loader protocol). `--all` (boot) unseals the host
keytab if protected and every other protected keytab and file into its
unsealed copy; `--sealed S` unseals one sealed keytab or file to `--out F`,
to standard output with `--out -`, to fd 3 with `--memfd`, or to its
unsealed copy if `kuipa protect` recorded it (§7.5). `--out -` writes the
plaintext and nothing else (traces go to standard error) and refuses a
terminal unless `--force`. Any other `--out` is written atomically, so it
must be a regular file or not exist yet, and not under `/dev`: renaming
over `/dev/stdout` would replace the link. Both are checked before a server
is contacted. Exit 0, 75 (no server could unseal) or 1.

### 10.6 `kuipa-voucher`

| command | role | does |
|---|---|---|
| `keygen --key F [--alg ml-dsa-65]` | issuer | write the voucher key (PKCS#8 PEM, 0600); print its public JWK |
| `quota --quota F --limit N` | issuer | set how many vouchers may be issued, keeping the count |
| `sign --key F --quota F` | issuer | count, then sign the blinded request on standard input; print the response |
| `request --public JWK --realm R --fqdn H [--hostgroup G] [--days N] [--binding B] --state F` | provisioner | blind a voucher valid for `N` days (default 7); keep the salt in `F` (0600); print the request |
| `finish --state F` | provisioner | check and unblind the response on standard input; print the voucher |
| `show` | anyone | print the claims of the voucher on standard input |

Requests and responses are base64url text (87 and about 4.4 KB), so any
channel will do.

### 10.7 `tang-pqc` and the Clevis pin

`crates/tang-pqc-clevis` is a client for any post-quantum Tang server (the
daemon's, §11.5, or another `tang-pqc` server) and the Clevis pin
`tang-pqc`. It is one binary: as `tang-pqc` it takes commands, and linked
as `clevis-encrypt-tang-pqc` / `clevis-decrypt-tang-pqc` it is the pin, so
`clevis encrypt`, `clevis decrypt` and `clevis luks bind/unlock/regen` use
it like the `tang` pin.

| command | does |
|---|---|
| `tang-pqc adv URL [--ca F]` | list the signing-key thumbprints `URL` advertises, to choose `thp` |
| `tang-pqc encrypt CONFIG < IN > JWE`, `clevis encrypt tang-pqc CONFIG` | fetch `URL/adv`, verify it against `thp` (falling back to `URL/adv/{thp}` after a rotation), provision a binding, and encrypt `IN` as a compact JWE |
| `tang-pqc decrypt < JWE > OUT`, `clevis decrypt` | fetch the binding's exchange key at `URL/key/{kid}`, recover the key with a sealed request to `URL/rec/{kid}`, and decrypt |

* **Configuration:** `url` (required), `thp` (required: there is no trust
  on first use; without it `encrypt` fails and names the advertised keys),
  `adv` (an advertisement file, for offline provisioning), `ca` (a PEM file
  to verify an `https` server; without it any certificate is accepted, as
  the advertisement is verified and the exchange needs no transport
  security). Other members are ignored, so `clevis luks regen` can pass the
  old header's pin object back.
* **JWE:** `"alg": "dir"`, `"enc": "A256GCM"`, the binding's 32-byte key as
  the content key, a random 96-bit IV, and the protected header as AAD. The
  header's `clevis.tang-pqc` holds `url`, `thp`, the binding (base64url)
  and `ca` if set: about 2.5 KB in all, well within a LUKS2 token. Any JWE
  library decrypts it given the key.
* **Boot:** `contrib/clevis/install.sh` installs the binary, the two pin
  links and a dracut module (`60clevis-pin-tang-pqc`: the pin, `clevis` and
  `network`, plus the crypto-policy files, so the initramfs applies the same
  algorithm policy).

## 11. Server: `kuipad`

### 11.1 Deployment

The daemon is socket-activated on `/run/ipa/kuipad.sock` (`listenfd`;
otherwise it binds its configured `listen` address) and reached through
httpd: `ProxyPass "/ipa/ku/" "unix:/run/ipa/kuipad.sock|http://localhost/ipa/ku/"`.
`contrib/` has the units and the httpd snippet. Configuration is
`/etc/ipa/kuipad.json`: realm, domain, base DN, server FQDN, LDAPI URI,
the daemon's principal (`ipa-ku/<fqdn>`), its GSS service name and keytab,
the CA file, the PKINIT anchors file, the key directory and the allowed
enctypes; for the anchor exchange, `peers` (FQDNs beyond those in LDAP),
`discover_peers` (default true), `peer_endpoints` (base URLs by FQDN
instead of `https://<fqdn>`) and `peer_interval` (seconds between rounds,
default 60, at least 5), `anchor` (default true: whether this server holds
an anchor, §4.2) and `vouch_interval` (seconds, default 60); `rate_limit`
(`{"per_host": {"burst", "per_minute"}, "per_source": {…}}`, §5.1, which
relies on httpd's `X-Forwarded-For`); `trusts` lists trusted realms
configured by hand (§17.2), next to those recorded by establishing a trust
(§17.4). At start
it reads its server list from
`cn=masters,cn=ipa,cn=etc` (falling back to itself), loads or issues its
delegation, and starts the exchange (§4.2) next to the HTTP server.

Peers' TLS certificates are verified against the IPA CA. The exchange's
initiator credential (`ipa-ku/<fqdn>` from the keytab) and the LDAP service
connection each use their own `MEMORY:` ccache, one thread at a time.

### 11.2 Key store

```
/var/lib/ipa/ku/anchor.jwk         this server's anchor (seed JWK)
/var/lib/ipa/ku/signing.jwk        server ML-DSA key (seed JWK)
/var/lib/ipa/ku/join-<kid>.jwk     join keys
/var/lib/ipa/ku/escrow-<kid>.jwk   escrow keys
/var/lib/ipa/ku/trust-<kid>.jwk    trust keys (§17.4)
/var/lib/ipa/ku/voucher-<thp>.jwk  accepted voucher keys, public (§9)
/var/lib/ipa/ku/.<name>.jwk        retired keys: still answered, not advertised
/var/lib/ipa/ku/tang/<thp>.jwk     Tang keys, laid out like Tang's key directory (§11.5)
/var/lib/ipa/ku/delegation.json    the advertised delegation: the claim with every trusted anchor's proof
/var/lib/ipa/ku/peers.state        the anchor exchange state (IPAS)
/var/lib/ipa/ku/succession-<thp>.json  a rotated anchor's signed succession (§4.7)
```

Files are written atomically with mode 0600; keys are never overwritten,
except `anchor.jwk` by `rotate-anchor`, which deletes the old anchor once it
has signed its succession.
Commands:

| command | does |
|---|---|
| `serve` | the daemon |
| `generate-keys` | create the anchor (unless `anchor` is false), signing, join, escrow and trust keys; print the anchor thumbprint |
| `anchor` | print the anchor thumbprint |
| `enrollment-string [--days 7] [--head]` | print `ipa-ku1:REALM:<anchor>:<expiry>` (with `--head`: `ipa-ku2`, also pinning the anchor's vouch head, §4.9), valid that many days (at most 400), to append `:<OTP>` to (§4.4) |
| `rotate-anchor [--days 400]` | replace the anchor: the old one signs a succession to the new one, valid that many days, and is deleted (§4.7); print the new thumbprint |
| `rotate-keys [--join] [--escrow] [--trust] [--signing]` | retire the chosen keys (default: join, escrow and trust) and create new ones; a retired key keeps answering, with its retirement time as the file's mtime |
| `prune-keys [--join-days 14] [--escrow-days 400]` | delete retired join and trust keys, and escrow keys, retired longer ago than that, and expired successions |
| `add-voucher-key --file JWK` | accept vouchers under a voucher key (§9) |
| `trust-invitation [--days 7]` | issue an invitation for another realm (§17.4) |
| `tang-keygen` | create Tang keys (a signing and an exchange key), which turns the Tang service on; print the thumbprint clients pin (§11.5) |
| `tang-rotate` | retire the Tang keys and create new ones; print the new thumbprint |
| `tang-thp` | print the current Tang thumbprints |
| `establish-trust --invitation-file F --server S…` | establish the trust the invitation offers (§17.4) |

The daemon reads its keys at start: restart it after `rotate-keys`,
`rotate-anchor`, `prune-keys`, `add-voucher-key` and the Tang commands. A rotated signing key needs a new
delegation, which the next exchange round issues and vouches for.

### 11.3 HTTP

| method | path | request → response |
|---|---|---|
| GET | `/ipa/ku/adv` | → advertisement (`application/jose+json`) |
| POST | `/ipa/ku/join/{kid}` | `IPJQ` → `IPJS` |
| POST | `/ipa/ku/rekey/{kid}` | `IPJQ` → `IPJS` |
| POST | `/ipa/ku/stage/{kid}` | `IPSQ` → `IPJS` (payload `IPSP`) |
| POST | `/ipa/ku/register/{kid}` | `IPJQ` (operation data `IPRP`) → `IPJS` (payload `IPRA`) (§7.5) |
| POST | `/ipa/ku/keys/{kid}` | `IPJQ` (operation data `IPKG`) → `IPJS` (payload `IPKR`) (§18) |
| POST | `/ipa/ku/vault/{kid}` | `IPJQ` (operation data: a JSON vault operation) → `IPJS` (payload `IPVR`) (§7.6) |
| POST | `/ipa/ku/rec/{kid}` | `IPEQ` → `TQRS`, or `IPVA` when the request names a device (§7.6.5) |
| POST | `/ipa/ku/peer/sync` | `IPPS` → agirru envelope (CBOR); servers only (§4.2) |
| GET | `/ipa/ku/anchor-log?from=n` | → epoch-log entries and the anchors' current vouch heads (§4.8, §4.9) |
| GET | `/ipa/ku/claim-log/{anchor}?from=i` | → one anchor's claim-log page (§4.9.5) |
| POST | `/ipa/ku/trust/{kid}` | `IPTQ` → `IPTS` (§17.4) |
| GET | `/ipa/ku/tang/adv`, `/ipa/ku/tang/adv/{thp}` | → Tang advertisement (`application/jose+json`) (§11.5) |
| GET | `/ipa/ku/tang/key/{kid}` | → Tang exchange key (`application/jwk+json`) (§11.5) |
| POST | `/ipa/ku/tang/rec/{kid}` | `TQRQ` → `TQRS` (§11.5) |

Bodies are limited to 1 MiB (64 KiB before §18; a CA or KRA subsystem
PKCS#12 and a wrapped ML-DSA key fit, §18); the path `kid` must match the
request's.
Refusals are empty `403`s with the reason logged, rate-limited requests
empty `429`s (§5.1); blocking LDAP and GSS work
runs on tokio's blocking pool.

### 11.4 Directory over LDAPI and GSSAPI

`LdapDirectory` implements the protocol's `Directory` trait:

| operation | LDAP |
|---|---|
| OTP join (`--ldap-otp`) | simple bind as `fqdn=<fqdn>,cn=computers,cn=accounts,<suffix>`; join extended operation (returns the principal); `KEYTAB_GET` with server-side generation on the same connection |
| Kerberos join | accept the token with `cb`; S4U2Self as the caller, SASL GSSAPI bind with that credential (S4U2Proxy to `ldap/`); join and `KEYTAB_GET` |
| rekey | as Kerberos join, caller must be `host/<fqdn>`; then, as the daemon, delete `ipaKUStaged` and `krbPrincipalExpiration` if staged, and `userPassword` if present (first contact with the OTP as Kerberos key) |
| stage | as the caller: join, `KEYTAB_GET`, replace `ipaKUStaged` and `krbPrincipalExpiration` |
| escrow | as the daemon, on the principal's entry (a host's by FQDN, others by `krbPrincipalName`/`krbCanonicalName` under `cn=accounts`): replace `ipaKUEscrowBinding`; read it and `ipaKUEscrowFileBinding` with `nsAccountLock` |
| vaults (§7.6) | accept the owner's token with `cb`; as the daemon: one entry `cn=<vault id>` under `cn=vaults,cn=kuipa,cn=etc` (`objectClass: ipaKUVault`, owner, name, policy JSON, one JSON value per device, state, `ipaKUVaultUnlocks` per server, `ipaKUVaultSessionKey` per epoch); each server's escrow public key as `ipaKUServerEscrowKey` on its `cn=masters` entry; searched one level by `ipaKUVaultOwner`; limits from `ipaKUVaultLimits` (JSON) on `cn=vault-limits,cn=kuipa,cn=etc`, defaults when absent; the owner's lock from `nsAccountLock` on their entry. Names are unique per owner as checked before the add; two servers creating the same name at once can both succeed |
| registration (§7.5) | accept the token with `cb`, caller must be the principal; as the daemon: replace `ipaKUEscrowBinding`, or delete each retired value of `ipaKUEscrowFileBinding` (an absent one is no error) and add the new ones |
| voucher join | as the daemon, after the voucher verified: search `ipaKUVoucherSpent` for the salt; add the host entry (as `host-add` lays it out) with it; add it as `member` of `cn=<group>,cn=hostgroups,cn=accounts`; `KEYTAB_GET` |
| trust invitation | as the daemon: add `ipaKUTrustInvitation: <hex SHA-256 of the secret> <not after>` to `cn=trusts,cn=kuipa,cn=etc,<suffix>`; using it deletes that exact value, which only one server can do |
| record a trust | as the daemon: add `krbtgt/<B>@<A>` and `krbtgt/<A>@<B>` under `cn=<A>,cn=kerberos,<suffix>` and give them keys from the trust secret with `KEYTAB_GET` and a password (as `ipa-getkeytab -P`); store the partner as JSON in `ipaKUTrustedRealm` |
| servers | as the daemon: the `cn` of the entries under `cn=masters,cn=ipa,cn=etc` |
| peer sync | accept the sync's token with the daemon's acceptor credential; return the initiator |

`KEYTAB_GET` encodes `GetKeytabControl` (explicit tags, `freeipa/asn1`) with
synta and reads the reply from the response control. The daemon's acceptor
credential uses a private `MEMORY:` ccache for its initiator half, so it
never depends on the service's default ccache.

### 11.5 Post-quantum Tang

The daemon is also a general post-quantum Tang server (`tang-pqc`), for
Clevis-style bindings such as disk unlocking, at the Tang URL
`https://<server>/ipa/ku/tang`. It shares nothing with enrollment except
the process: its own keys, none of the realm's state, and `tang-pqc`'s own
protocol domain. A server serves Tang once it has Tang keys
(`tang-keygen`); without them the endpoints answer `404`.

* **Keys** are kept as Tang keeps them: `<key_dir>/tang/<thumbprint>.jwk`
  per seed-form JWK, signing (ML-DSA) and exchange (ML-KEM) alike, with a
  leading `.` for a retired key. Clients pin a signing key's thumbprint
  (`tang-thp`).
* **`GET adv`** returns the advertisement signed by every current signing
  key, re-signed at half its validity. The advertisement holds only plain
  Tang keys: no `ipa_use` role, so the enrollment client never picks them,
  and the enrollment advertisement never lists them.
* **`GET adv/{thp}`** also signs with signing key `thp` when that key is
  retired, so a client that pinned it can verify and bind to the new keys
  after `tang-rotate` (as Tang's `/adv/{thp}`); a key the server never had
  is a `404`.
* **`GET key/{kid}`** returns the public exchange key `kid`, current or
  retired, as a JWK; clients seal their recovery requests to it, and the
  binding's `kid` authenticates it. An unknown key is a `404`.
* **`POST rec/{kid}`** answers with any current or retired exchange key.
  The answers are `200`, `404` for an unknown key, `400` for a request that
  does not parse, does not match the path or does not open under the key, and `429` when the client
  address is over its per-source limit (§5.1). There is no per-host limit,
  since a recovery names no host.
* **Rotation**, as `tangd-rotate-keys`: `tang-rotate` retires every current
  key and creates new ones. Retired exchange keys are never pruned
  automatically: delete their `.`-files once every client has rebound
  (`clevis luks regen`).

Like Tang, the service is stateless: anyone holding a binding can recover
its key, so it belongs where Tang would be deployed, on a network that
should be able to unlock. Sealed host keytabs do **not** use it: they use
the escrow exchange (§7.2), which checks the host and its registered
bindings.

## 12. Deployment units

| unit | runs |
|---|---|
| `kuipad.socket` / `.service` | the daemon |
| `kuipa-unseal.service` | `kuipa-unseal` at boot, before SSSD, gssproxy and certmonger; retries on 75 |
| `ipa-client-complete.service` | `kuipa complete` while a pending file exists; retries on 75 |
| `kuipa-rotate.timer` / `.service` | `kuipa rotate-keys` monthly (also rebinds a sealed keytab) |

## 13. Security analysis

Assumptions: ML-KEM is IND-CCA2 and ML-DSA SUF-CMA, both post-quantum; HKDF
behaves as a random oracle; the enrollment string reaches the host
authentically.

| attacker | outcome |
|---|---|
| records all traffic, quantum later | nothing: OTPs, passwords and keytabs are under `ss`/`ss_e`; the advertisement is public |
| active network attacker, classical or quantum | cannot impersonate a server without a delegation signed by a pinned anchor; can block enrollment |
| delivers a forged or misdirected enrollment string, with an anchor of its own | its advertisements verify, but must name the realm (`--realm`), domain (`--domain`, or the one used for DNS) and servers (`--server` or DNS) the host was given independently, before any request or secret leaves the host; KDCs for the armoured exchange are limited to those servers (§4.6); not stopped if it also controls those channels or the path to the named servers |
| replays a recorded request | OTP consumed; Kerberos tokens bound to `cb` and the replay cache; the response is for an `ek_e` the attacker lacks |
| guesses an OTP or password | online only, one guess per request, LDAP lockout per server |
| compromises a join key later | opens recorded requests (consumed OTPs of `--ldap-otp` joins, expired tokens), not responses; passwords are never in them |
| records a password or OTP join | the armoured AS exchange allows offline guessing once its classical PKINIT key exchange falls, as for any IPA `kinit`; harmless for `--random` OTPs |
| compromises a server signing key | impersonates that server to new clients until its delegation lapses |
| compromises one server's anchor | can sign delegations for any server name, to clients that pin it, but cannot answer a Kerberos-bound request (§5.1): OTP, password, ticket and every enrolled host's operations stay safe; `--ldap-otp`, voucher, bundle and IdP/passkey `--use-ccache` joins are exposed until the strings and pins naming that anchor expire (§4.4); a client that knows two of the realm's anchors asks each for its own proof and refuses a server that only one can give (§4.4), so the impostor passes only where the host knows that anchor alone; rotate it (§4.7) and remove nothing else |
| knows two anchors and one of them was stolen | refuses every server that cannot produce two proofs from distinct anchors: the thief holding the stolen key is skipped like a bad advertisement, and enrollment goes to the server the other anchor vouches for, or stops at exit 75 when none can (§4.4, §4.6) |
| obtains a server's `ipa-ku/<fqdn>` Kerberos key | can get an anchor of its choice trusted for that member's name; needs the realm's Kerberos keys, which also protect every host key in LDAP |
| sends syncs without a member's `kuipa` key | refused (`403`); forged or replayed entries fail their signatures or lose to newer ones |
| strips kuipa or blocks `/ipa/ku/` | enrollment fails; `kuipa` never falls back to classical enrollment |
| old host key + recorded rekey | nothing (§6) |
| redirects to another genuine server | harmless (§4.3) |
| stolen disk | §7.3 |
| staged bundle copied or raced | §8.5 |

Clock: advertisements and delegations expire, so online clients need a
roughly correct clock (`ipa-client-install` syncs time before joining);
offline bundles are checked at their `iat` and bounded by the KDC.

The anchor exchange rests on the members' Kerberos keys. They are
symmetric, so recorded syncs reveal nothing to a quantum attacker; an
attacker who could forge them would already hold the realm's Kerberos
keys, through which every host key in LDAP is exposed too. A removed
server's claim drops out of every vouch at the next round, and its
existing proofs stop verifying when the vouches they come from expire
(7 days).

Still classical: TLS server authentication (an RSA IPA CA, now reached
authentically), PKINIT and its anonymous armour, DNSSEC. Custodia is
replaced by §18.

FIPS: every primitive is approved; HKDF over `ss ‖ ss_e` is an SP 800-56C
rev. 2 derivation over two approved KEM secrets.

## 14. Wire formats

`magic(4) ‖ version(1)=1 ‖ fields`; variable fields are a big-endian `u32`
length and the bytes; strings UTF-8; lists a `u8` count. KEM ids: `0x01`
ML-KEM-768, `0x02` ML-KEM-1024. Thumbprints are 32 raw bytes.

```
IPJQ  alg kid(32) realm fqdn auth_type(1) n(1) [enctype(i32)] ct ek_e sealed   join, rekey request
IPSQ  same fields                                                                stage request
IPRB  auth_type(1) n(1) [registration(32)] extra authenticator                  sealed request body
IPJS  ct_e sealed                                                                response
IPJP  realm domain basedn issuer n[server] n[ca_cert] n[pkinit_anchor]
      n[anchor(32)] epoch_seq(u64) epoch_head(32) keytab                   enrollment payload
IPSX  mode(1) alg(1) ek_m not_after(u64)                                         staging parameters
IPSP  bundle secret                                                              stage result
IPOB  mode(1) alg(1) realm fqdn id(16) iat(u64) not_after(u64) recipient(32)
      signer(32) ct sealed delegation(JSON) signer_key(JWK) signature            offline bundle
IPSK  principal n(1) [server binding(TQBD) ek commitment(32) wrapped] sealed     sealed keytab
IPSF  same fields                                                                sealed file
IPCV  principal vault(16)                                                        what a binding commits to (commitment input, never sent)
IPEQ  principal vault(16) commitment(32) recovery(TQRQ) device session ticket     escrow request (device: empty or a 32-byte thumbprint; session: empty or IPST; ticket: empty or a GSS-API token)
IPUF  principal vault(16) n(1) [server binding(TQBD) ek commitment(32) wrapped]
      m(1) [device(32) ct wrapped] sealed                                        file sealed to a user vault
IPVD  body(JSON) delegation(JSON) signer_key(JWK) signature                      vault descriptor (signed: IPVD without the signature)
IPVR  n(u64) [descriptor(IPVD)] session                                          vault operation answer (session: empty or IPST)
IPST  signed(IPST: vault(16) owner device(32) not_after(u64) delegation signer_key) signature   re-authentication session token
IPSS  token(IPST) device_key(private JWK) n(u64) [epoch(u64) private JWK]       a client's session file in its runtime directory (never sent)
IPDK  kdf(1) iterations(u64) salt(16) sealed                                    a user's device key file (never sent)
IPUS  principal vault(16) epoch(u64) ct_e wrapped_A m(1) [device(32) ct wrapped] sealed   file sealed for offline sessions
IPEK  ct sealed(IPEK n(u64) [epoch(u64) private JWK])                          session keys released to a device
IPVA  ct sealed                                                                  recovery answer encrypted to a device
IPRP  principal kind(1) n(1) [retire(32)]                                        registration parameters
IPRA  principal                                                                  registration answer
IPKG  namespace(1) nickname alg_arg(1)                                           keys operation data (§18.2)
      (namespace: 1 dm, 2 ra, 3 ca, 4 ca_wrapped, 5 lwca-store; alg_arg: a wrap
       algorithm selector for ca_wrapped, 0 none; nickname: a string)
IPKR  value                                                                      keys answer (the handler's JSON)
IPPS  sender receiver delegation(JSON) envelope token                           peer sync request
IPDC  realm server anchor(32) key(32) iat(u64) exp(u64)                          claim
IPVH  realm anchor(32) iat(u64) exp(u64) size(u64) root(32)                      vouch (signed)
IPSV  vouch(IPVH) signature n(u64) [leaf(32)]                                    signed vouch with leaves
IPVH  version 2 (§4.9): the same fields, over the append-only claim log          vouch head (claim log)
IPSV  version 2 (§4.9): vouch(IPVH) signature n(u64) [leaf(32)]                  signed head, with the whole claim log in order: appending keeps the previous log, a drop restarts it
IPAR  realm old(32) new(32) iat(u64) exp(u64)                                    anchor succession (signed by old)
IPSR  old_key(JWK) succession(IPAR) signature                                    signed succession (gossip form)
IPAE  realm seq(u64) prev(32) n(u64)[anchor(32)] m(u64)[signed-succession]  anchor epoch entry (signed bytes; `head` is `SHA-256` of them under a domain-separation context; `prev` is the previous entry's head, `0…0` for the first)
IEPS  entry(IPAE) signature n(u64) [key(JWK) signature]                    signed anchor epoch entry
IPAS  n(u64) [tag(1) value]                                                      exchange state (1 key, 2 claim, 3 vouch, 4 succession)
IPVM  realm fqdn hostgroup not_before(u64) not_after(u64) binding(32)          voucher message (no version)
IPVO  key(32) realm fqdn hostgroup not_before(u64) not_after(u64) binding(32)
      salt(32) signature                                                         voucher
IPTQ  alg kid(32) realm initiator ct ek_e sealed                                trust request
IPTT  alg kid(32) signer(32) realm initiator H(ct) H(ek_e)                      trust transcript input (no version)
IPTB  secret realm domain n[server] n[anchor(32)] delegation(JSON)
      signer_key(JWK) signature                                                  sealed trust request body (no version)
IPTS  ct_e sealed                                                                trust response
IPTP  realm domain n[server] n[anchor(32)]                                       sealed trust response payload (no version)
IPLF  kind(2) time(u64) index(32) body                                          typed log leaf (DESIGN-tlog.md §1)
IPLT  target(u64) reason                                                        tombstone body (DESIGN-tlog.md §2)
IPLH  log(32) size(u64) root(32) time(u64)                                      log head (signed, DESIGN-tlog.md §3)
IPLC  time(u64) head(IPLH)                                                      what a witness cosigns (never sent)
IPLS  head(IPLH) signature n(1) [witness(32) time(u64) signature]                signed log head with cosignatures
```

`ct` is empty in bundle modes B and C, `recipient` all zeros outside mode A,
`secret` empty outside mode B. The bundle signature covers `IPOB` up to and
including the signer key. The `IPPS` token's channel binding is
`SHA-256("ipa-ku-enroll/v1 peer" ‖ IPPS(sender, receiver, delegation,
envelope))`, without version or token; the response is agirru's `Envelope`
(CBOR) whose state is an `IPAS` byte string. `TQBD`, `TQRQ` and `TQRS` are `tang-pqc`'s binding,
recovery request and response.

## 15. What kuipa uses from `tang-pqc`

| tang-pqc | used for |
|---|---|
| `AdvertisementBuilder` (`exchange_key_with`, `member`, `validity`), `Advertisement::{exchange_keys_where, member}`, `SignedAdvertisement::unverified_member` | the realm advertisement and its roles |
| `primitives::Domain` (labelled HKDF), `seal`/`open`, `digest` | every derivation and encryption |
| `ExchangeKey::encapsulate`, `ExchangeKeyPair::decapsulate` | the KEM steps |
| `SigningKey::sign_with_context`, `VerifyingKey::verify_with_context` | bundle and vouch signatures |
| `BindingContext`, `provision_committed`, `Binding::{from_bytes_with, ciphertext_hash, recovery_request}`, `RecoveryRequest::open`, `OpenedRequest::{verify_commitment, ciphertext_hash, respond}` | sealed keytabs and files, escrow, vaults |
| `Policy`, `wire`, `b64`, seed JWKs, thumbprints, system-policy checks | throughout |

`tang-pqc`'s own DESIGN.md §8 describes these extension points.

## 16. Out of scope and open questions

* **PKINIT and FAST armour** stay classical until PQ PKINIT exists; the host
  keys kuipa protects are symmetric.
* **ML-DSA certificates** from the IPA CA would make TLS server
  authentication post-quantum; kuipa's CA pinning works for any algorithm.
* **Custodia's JOSE message layer** has no post-quantum standard to move
  to (`draft-ietf-jose-pqc-kem` is still moving); §18 replaces the whole
  daemon on kuipa's envelope instead of waiting for one.
* **Anchor exchange scale:** the state grows linearly with the number of
  anchors; with every server an anchor, 60 servers make 489 KB of state and
  321 KB of deltas per renewal round. Large realms should give the anchor
  role to a few servers (6 of 60: 55 KB and 32 KB, §4.2).
* **Merkle Tree Certificates:** vouches are tree heads over claims, with
  the same hashing and inclusion proofs as MTC. §4.9 designs the use of
  pre-distributed tree heads ("landmarks"): pins carry a vouch head, and
  a client that holds one checks a delegation's inclusion proof against
  it, with no signature and no anchor key on the wire, through
  `synta-mtc`'s landmark and trusted-subtree machinery.
  The services built on that exchange — head windows (a pin that keeps
  every head it verified, with a consistency check against the public
  claim log), frozen-trust pins, cross-realm heads, the signed vouch in
  the public claim log, and the `kuipa-audit` and `kuipa-mirror` tools
  — are designed in `DESIGN-claim-logs.md`.
* **The daemon's identity:** its own `ipa-ku/<server>` principal with a
  delegation rule to `ldap/<server>` (as implemented) versus `HTTP/<server>`
  through gssproxy. Acting for callers uses protocol transition; S4U2Proxy
  with the caller's evidence ticket would be stricter.
* **Staging SSH host keys and certificates** before first contact: rejected
  for SSH keys (generated off the host); the host certificate stays a
  deferred step.
* **Hybrid KEM:** if required, a separate standard X25519/P-384 key whose
  secret is appended to the HKDF input.
* **`draft-ietf-jose-pqc-kem`** may still change the ML-KEM JWK form (the
  64-byte seed question, `tang-pqc` DESIGN §7.1).

## 17. Trusted IPA realms

Before a host of realm A accepts users of a trusted IPA realm B, it needs
B's KDCs and B's PKINIT CA chain: anonymous PKINIT armour from B's KDC
(`WELLKNOWN/ANONYMOUS@B`), and PKINIT for B's users, verify B's KDC
certificate against that chain. Today the chain would come from DNS, an
administrator copying files, or trust on first use. The realm
advertisement provides it authenticated, with strict separation between
the realms.

### 17.1 Domain separation

* **Every signed object names its realm**, and every verifier checks it
  against the realm it expects: delegations, advertisements (`ipa.realm`),
  join transcripts, exchange entries. The anchor exchange accepts only its
  own realm's entries and only `ipa-ku/<fqdn>@OWN-REALM` initiators, so
  cross-realm tickets never take part in it, even once a trust exists.
* **Anchors are pinned per realm.** The host's own anchors stay in
  `/etc/ipa/ku-anchors`; a trusted realm's go to
  `/etc/ipa/ku-anchors.d/<REALM>` and verify objects of that realm only. A
  compromised anchor of B can impersonate B's servers, never A's.
* **No shared anchors.** A trust entry that names the advertising realm,
  repeats a realm, or lists one of the advertising realm's anchors is
  refused, by the server when it loads its configuration and by every
  client when it parses the advertisement (`RealmInfo::validate`). A client
  also refuses a trusted realm whose anchors overlap with the ones it pins
  for its own realm.
* **Kerberos configuration is per realm.** B's PKINIT anchors appear only
  in B's `[realms]` section, so a certificate from B's CA is never
  accepted for A's KDC, and A's chain does not vouch for B's KDC.
* **Safe names.** Realm, domain and server names that end up in generated
  configuration or file names must consist of ASCII letters, digits, `.`,
  `-` and `_` (`is_safe_name`); otherwise the advertisement is refused.

### 17.2 The `trusts` member

A's servers list the realms A trusts in the `ipa` member of their
advertisement:

```json
"trusts": [{"realm":"B.TEST", "domain":"b.test",
            "servers":["ipa1.b.test"], "anchors":["<b64url thumbprint>"]}]
```

The member is part of A's signed advertisement, so a host that verifies A
learns which of B's anchors A vouches for, and for which realm. The daemon
reads it from its configuration (`trusts`, §11.1) and can replace it at
run time (`EnrollServer::publish_trusts`); in FreeIPA it would come from
the trust objects in LDAP.

### 17.3 `kuipa trusted-realms`

On an enrolled host, this command makes the installed trusted realms match
what the host's own realm advertises:

1. Verify an advertisement of the host's realm with its own anchors (over
   TLS verified with the installed IPA CA) and read `trusts`.
2. For each listed realm B, fetch B's advertisement from the listed servers
   and verify it with the anchors A vouches for, as realm B. As on first
   contact, TLS to B accepts any certificate for this request: the
   advertisement authenticates B.
3. Install, for B only:

   ```
   /etc/ipa/ku-anchors.d/B.TEST                         B's anchors (written last: marks B installed)
   /var/lib/ipa-client/ku/trusts/B.TEST/pkinit-anchors.pem  B's PKINIT anchors
   /var/lib/ipa-client/ku/trusts/B.TEST/ca.crt          B's IPA CA
   /etc/krb5.conf.d/kuipa_trust_B_TEST                 B's [realms] and [domain_realm] sections
   ```

   The snippet has no `[libdefaults]`; it names B's servers as KDCs (the
   answering one first) and sets `pkinit_anchors` and `pkinit_pool` to B's
   chain. MIT's `includedir` reads only file names of letters, digits, `-`
   and `_`, hence the name.
4. Remove realms that are installed but no longer listed.

A realm that cannot be fetched or verified keeps its last verified files.
The command then exits 75 after applying everything else; it never falls
back to unverified sources. `kuipa status` lists the installed realms, and
`kuipa leave` removes them. Run it after enrollment and periodically (for
example with `kuipa-rotate.timer`); until it has installed B, the host
has no configuration that would accept B's users over FAST.

### 17.4 Establishing the trust

The trust itself — the cross-realm `krbtgt` keys from a shared secret, and
each realm's anchors in the other's `trusts` — is set up with the same
machinery, B inviting and a server of A answering:

```text
B: kuipad trust-invitation   →  ipa-ku-trust1:<REALM-B>:<B anchor>:<one-time secret>
A: kuipad establish-trust --invitation-file F --server <B server>…

(ct, ss)     = Encaps(ek_trust)            (dk_e, ek_e) = KeyGen()
T  = H("IPTT" ‖ alg ‖ kid ‖ B signer ‖ realm B ‖ realm A ‖ H(ct) ‖ H(ek_e))
k  = HKDF(ss, "req" ‖ T)
     ── POST /ipa/ku/trust/{kid}: IPTQ(alg, kid, realm B, realm A, ct, ek_e,
          GCM_k(secret, A's realm, A's delegation, A's server key,
                ML-DSA(A's server key, T, "ipa-ku-trust/v1 request"))) ──▶
(ct_e, ss_e) = Encaps(ek_e)                T' = H(T ‖ H(ct_e))
k' = HKDF(ss ‖ ss_e, "rsp" ‖ T')           trust secret = HKDF(ss ‖ ss_e, "trust-secret" ‖ T')
     ◀── IPTS(ct_e, GCM_k'(B's realm)) ──
```

* **Invitation.** It carries B's realm, an anchor of B and a 256-bit
  one-time secret, and travels out of band like an enrollment string. B
  stores a hash of the secret with an expiry (default 7 days). A's server
  fetches B's advertisement from the given servers and verifies it with the
  invitation's anchor.
* **Request.** It goes to one of B's trust keys (`ipa_use: "trust"`), in its
  own protocol domain `ipa-ku-trust/v1`, so nothing in it can be taken for a
  join. B uses up the invitation, then checks:
  * A's description: safe names, another realm, servers, and anchors of
    its own;
  * A's delegation, verified with the anchors A sends, names realm A;
  * the signing key sent is the one A's delegation delegates to, and it
    signed `T`.
  The request thus comes from a server of A, holding the invitation.
* **Trust secret.** Both sides derive it from both encapsulations, so
  neither chooses it alone. Each directory records the partner and creates
  `krbtgt/<B>@<A>` and `krbtgt/<A>@<B>` with keys from its base64url text,
  as `trust-add --trust_secret` would (§11.4). A directory that cannot
  record trusts leaves it to the administrator: `establish-trust` then
  prints the secret and the `trusts` entry to configure. A answers only if
  B's description includes the invitation's anchor.
* **Upkeep.** Every server publishes its configured trusts and the recorded
  ones. Every ten exchange rounds it fetches each recorded partner's
  advertisement, verified with the anchors on record, and records the
  partner's current servers and anchors, which B vouches for. A partner it
  cannot reach keeps its last description. Removing the trust removes it
  from `trusts`, and every host removes B at its next `kuipa
  trusted-realms`.

Limits: AD trusts are not covered (AD runs no kuipa); cross-realm PKINIT
and the cross-realm `krbtgt` keys stay what Kerberos makes them — kuipa
authenticates the PKINIT chains and protects the trust secret in transit,
not PKINIT itself. The invitation needs an authentic out-of-band channel,
like an enrollment string.

## 18. Secrets transport: replacing FreeIPA's Custodia

FreeIPA moves its most sensitive material — CA and KRA subsystem PKCS#12
bundles, the RA agent key, the Directory Manager password hash and
Dogtag's wrapped lightweight-CA keys — through its embedded Custodia
daemon: a JWS (`RS256`) inside a JWE (`RSA-OAEP`, `A256CBC-HS512`),
client public keys in a self-writable LDAP tree (`cn=custodia`), fetched
as `GET /ipa/keys/<name>` over TLS through httpd and SPNEGO. All of it is
classical, and the JWE layer has no post-quantum standard to move to
(§16). This section designs the same job on kuipa's envelope: FreeIPA's
own design for adopting it is `doc/designs/kuipa-secrets-transport.md` in
the FreeIPA tree, which this section stays in sync with.

### 18.1 What is being replaced

Custodia's `IPASecStore` stores nothing: it dispatches four key names to
handler executables that export or import against a live subsystem. The
namespaces, each with a fixed producer and consumer:

| namespace | export | import | when |
|---|---|---|---|
| `dm/DMHash` | `nsslapd-rootpw` from `cn=config` over LDAPI | the promoting replica writes its own `cn=config` | end of `ipa-replica-install` |
| `ra/ipaCert` | the RA agent key and certificate as PKCS#12 | a clone or non-CA replica | replica promotion, CA topology repair |
| `ca/<nickname>` | a subsystem certificate and key from Dogtag's NSS database as PKCS#12 | a CA or KRA clone, one nickname at a time | `ipa-ca-install`, `ipa-kra-install` |
| `ca_wrapped/<nickname>` | a lightweight-CA key wrapped by the CA signing key (PKIArchiveOptions) | nobody: Dogtag itself consumes it | runtime, on CA clones missing a LWCA key |

The `KEYS` service entry (`cn=masters`), the audit log and
`ipa-custodia-check` complete the surface. The trust root it needs — the
LDAP public-key directory that a promoting replica must poll until its
keys replicate (`_wait_keys`) — disappears entirely: kuipa's callers
authenticate with Kerberos tickets the KDC already knows.

### 18.2 The `keys` operation

`Operation::Keys` (a sibling of `register`, §7.5) carries a fetch from a
host that is already enrolled:

* **Endpoint.** `POST /ipa/ku/keys/{kid}`, request `IPJQ` with operation
  data `IPKG`, response `IPJS` (payload `IPKR`, §14).
* **Authenticator.** Kerberos, as `register`: the caller's ticket inside
  the sealed body, channel-bound (`cb`), the response authenticated by
  the realm's Kerberos keys as well as the anchor (`kb`). The caller is
  `host/<fqdn>` (install-time fetches) or `dogtag/<fqdn>` (lightweight-CA
  retrieval, as today).
* **Operation data** (`IPKG`): namespace (one of `dm`, `ra`, `ca`,
  `ca_wrapped`), nickname, and for `ca_wrapped` a wrap-algorithm
  argument validated against an allowlist. No string parsing of the key
  name: the namespace is an enum, the nickname opaque bytes with a
  length bound.
* **Policy** (static, in `kuipad.json`, §18.5): the daemon checks the
  caller's principal against the namespace's allowed shape and against
  the server list in `cn=masters,cn=ipa,cn=etc`, the way Ahdapa admits
  gossip peers by IPA topology: a host not in `cn=masters` — a locked or
  removed server, or an unenrolled impostor — is refused before any
  handler runs. `dogtag/<fqdn>` additionally requires the peer's
  `cn=CA,cn=<fqdn>,cn=masters` entry, so a non-CA server cannot ask for
  wrapped CA keys.
* **Handler execution.** Direct runas spawn on tokio's blocking pool, as
  Custodia does today: the daemon execs the same four handler executables
  (`ipa-custodia-dmldap`, `ipa-custodia-pki-tomcat`,
  `ipa-custodia-pki-tomcat-wrapped`, `ipa-custodia-ra-agent`) with
  `--export -`, capturing stdout, each under the SELinux domain its file
  type already selects (root for `dmldap` and `ra-agent`, `pkiuser` for
  the NSS handlers). Import is the same spawn with `--import -` and the
  value on stdin. `ca_wrapped` stays export-only.
* **Response.** The handler's JSON value, sealed in the envelope. The
  body limit (§11.3) is 1 MiB, enough for a CA or KRA subsystem PKCS#12
  and ML-DSA-sized wrapped keys; Custodia's 10 MiB limit was never
  needed.
* **Audit.** One structured line per request: caller principal,
  namespace, nickname, allowed or refused, reason — the parity
  `/var/log/ipa-custodia.audit.log` needs.

### 18.3 Sealed lightweight-CA keys (replacing `ca_wrapped` storage)

The wrapped-CA-key flow moves from per-request live export to a sealed
artifact replicated in LDAP, unsealed by a key-recovery request. This
removes the live-master dependency (any replica serves the fetch) and,
with an ML-DSA CA, fixes what Custodia cannot do at all: Dogtag's
`KeyWrapAlgorithm.RSA` cannot wrap an ML-DSA-87 private key (the RSA
wrap of the session key needs an RSA public key; the CA signing key is
ML-DSA), so `ca_wrapped` is impossible against a post-quantum CA without
new Dogtag work.

* **Artifact.** When Dogtag creates or rotates a lightweight CA's key,
  the wrapped PKIArchiveOptions and the certificate are sealed as a
  machine-vault file (§7.6.8): server share under the escrow keys, sealed
  to `dogtag/<server>` as the recovery principal, `sealing = registered`
  bindings, policy fixed as for host keytabs. The artifact name is the
  LWCA nickname under a `cn=lwca,cn=kuipa,cn=etc` container.
* **Producer.** The `keys` operation with namespace `lwca-store`: the
  CA's Dogtag instance asks through the same `keys` operation (the
  dogtag principal it already runs the retriever as), the daemon
  seals what the handler exported. Dogtag's ML-KEM archival
  (`CryptoUtil.encapsulateMLKEM`) already produces a wrapped form the
  artifact can carry; its import side still needs the matching ML-KEM
  unwrap, which is Dogtag-side work either way.
* **Consumer.** `ipa-pki-retrieve-key` becomes `kuipa keys fetch
  lwca/<nickname> --json` under the hood: unseal the artifact (a
  recovery request naming the machine vault, §7.6.5) and print the JSON
  Dogtag's `ExternalProcessKeyRetriever` expects (`certificate` and
  `wrapped_key`, base64 PKIArchiveOptions). Dogtag itself does not
  change: the retriever's contract — executable, arguments, JSON on
  stdout, nonzero exit retried on the next host — is untouched.
* **Wrap algorithm.** Inside the artifact, the session key Dogtag wraps
  with is no longer bound to AES-128-CBC or DES-EDE3-CBC
  (`2.16.840.1.101.3.4.1.2`, `1.2.840.113549.3.7`): the allowlist names
  AES-256 variants (AES-256-CBC-PAD, and AES key wrap where Dogtag
  supports it), and any RSA-key-wrap of the session key is refused for
  ML-DSA CAs because it is structurally impossible. The artifact's own
  protection is kuipa's ML-KEM escrow seal, so the wrap is defense in
  depth, not the carrier of the post-quantum property.

### 18.4 Client and CLI

`kuipa keys fetch <namespace>/<nickname> [--alg A] [--out F]` writes
the handler's value to standard output, or to `F`.  Importing what was
fetched (as `fetch_key(store=True)` does today) stays with the caller:
the FreeIPA integration runs its handler itself. Callers that cannot
link Rust (`ipa-pki-retrieve-key`, FreeIPA's Python installers) shell
out to `kuipa keys fetch`, as they shell out to `ipa-getkeytab` today.
The ticket comes from the caller's
keytab (`/etc/krb5.keytab` for hosts, `/etc/pki/pki-tomcat/dogtag.keytab`
for the retriever), the anchor list and CA from `/etc/ipa`.

### 18.5 Configuration

`kuipad.json` gains a `keys` object:

```json
{
  "keys": {
    "enabled": true,
    "handlers": {
      "dm":      {"command": "/usr/libexec/ipa/custodia/ipa-custodia-dmldap", "runas": "root"},
      "ra":      {"command": "/usr/libexec/ipa/custodia/ipa-custodia-ra-agent", "runas": "root"},
      "ca":      {"command": "/usr/libexec/ipa/custodia/ipa-custodia-pki-tomcat", "runas": "pkiuser"},
      "ca_wrapped": {"command": "/usr/libexec/ipa/custodia/ipa-custodia-pki-tomcat-wrapped", "runas": "pkiuser"},
      "lwca-store": {"command": "/usr/libexec/ipa/custodia/ipa-custodia-pki-tomcat-wrapped", "runas": "pkiuser"}
    },
    "lwca": {"container": "cn=lwca,cn=kuipa,cn=etc"}
  }
}
```

The four handlers keep their names and SELinux labels (they are FreeIPA
files); the daemon only replaces Custodia's forking HTTP server, its
KEM/JOSE message layer and its LDAP public-key directory. The policy —
which principal may ask for which namespace — is static in the daemon
(`host/*` in `cn=masters` for `dm`, `ra`, `ca`; `dogtag/*` or `host/*`
for `ca_wrapped` and `lwca-store`), checked against the server list and
CA role in `cn=masters` before any handler runs. Nothing is
LDAP-configurable: the four flows have no runtime policy to change, and
a static table is the smallest surface to audit.

### 18.6 What stays out

* **Dogtag's internal wrap** stays what Dogtag ships. The artifact seal
  (ML-KEM escrow) governs the secret at rest and in transit; Dogtag's
  PKIArchiveOptions wrap is access control by the CA signing key, only
  breakable by someone who already holds the CA, which is circular.
* **TLS** stays classical until FreeIPA's PQ TLS lands — irrelevant to
  payload confidentiality, which the envelope provides.
* **The `simple` store, PUT/DELETE and container operations** are not
  ported: FreeIPA never used them (`allowed_keytypes = kem`, and
  `IPASecStore.list` raises `NotImplementedError`).
* **HSM deployments** do not fetch CA or wrapped keys through this path
  (as with Custodia today); `dm` and `ra` still flow.

## 19. Implementation status and tests

### 19.1 Status

| area | state |
|---|---|
| protocol library (`kuipa-enroll`): delegations, anchor exchange state and trust, advertisement, join/rekey/stage, OTP/password/Kerberos/voucher authenticators, payload, bundles A/B/C, sealed keytab, escrow, MIT keytab, trust establishment | implemented, tested |
| client (`kuipa`, `kuipa-unseal`): every command of §10.1, failover, DNS SRV discovery, prompts, file mode | implemented, tested over HTTP, against a stub DNS server and against a real KDC |
| daemon (`kuipad`): router, key store and rotation, rate limiting, commands, `KEYTAB_GET` codec | implemented, tested (router, limiter, key store, codec) |
| anchor exchange (agirru gossip, Kerberos-authenticated syncs, claims, Merkle-tree vouches, anchor role, batched re-vouching, renewal, publishing) | implemented, tested with two servers against a real KDC |
| daemon `LdapDirectory` against 389-ds | implemented, **not yet run against a FreeIPA server** |
| trusted realms: `trusts` member and its validation, `kuipa trusted-realms`, per-realm anchors, PKINIT anchors and `krb5.conf.d` snippets (§17.1–§17.3) | implemented, tested against two real KDCs |
| establishing a trust: invitation, trust request, trust secret, cross-realm keys, partner refresh (§17.4) | implemented, tested against two real KDCs; the LDAP side **not yet run against FreeIPA** |
| units, httpd snippet, config example | provided (`contrib/`) |
| Tamarin model of the core exchange (pins and advertisement verification, join/rekey key schedule, OTP and Kerberos authenticators, sealed-keytab escrow): secrecy, server authentication, rekey forward secrecy, offline resistance, and the §13 attacks for a mis-delivered string and a stolen anchor | provided and proved (`contrib/tamarin/kuipa.spthy`, `tamarin-prover --prove`) |
| vouch heads: claim logs, head proofs in advertisements and delegations, `?head=` selection with signature fallback, heads in pins and sealed responses, `ipa-ku2` strings, public claim logs (§4.9) | implemented, tested (claim logs and head proofs, tampering and stale heads, HTTP flows with a head-pinned client, pin-file round trips, KDC exchange) |
| claim-log services: head windows with consistency-checked refresh, frozen-trust pins, cross-realm heads, the signed vouch in claim-log pages, `kuipa-audit`, `kuipa-mirror` (DESIGN-claim-logs.md) | implemented, tested (window merge and consistency rules, frozen refusals — every frozen anchor by its own head, trust install of a partner's heads *only where a signature proves them*, claim-log pages with their vouch, the audit's coverage states and split views over HTTP with the served head's signature checked, the mirror's sync/serve/no-route and cached head proofs with pages cached only under proved heads, expired pins trusted no more than absent ones, corrupt pin files refusing, the whole window travelling on `?head=`, fetch caps on oversized trees, playground session steps) |
| vouchers (§9): `ml-dsa-blind` issuing, `kuipa-voucher`, bound and bearer vouchers, voucher joins | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| secrets transport (§18): the `keys` operation, handler execution with runas, `kuipa keys fetch`, the `cn=masters` and CA-role policy, a promotion scenario in the playground | implemented, tested; the LDAP policy check **not yet run against a FreeIPA server**; sealed lightweight-CA artifacts (§18.3) designed |
| TPM factor for sealed keytabs, `prepare --tpm` | designed |
| post-quantum Tang service (§11.5): `adv`, `adv/{thp}`, `key/{kid}`, `rec/{kid}`, Tang-style key directory and rotation | implemented, tested over HTTP |
| `tang-pqc` client and Clevis pin (§10.7), installer, dracut module | implemented, tested as a command and through the pin's names over HTTP; **not yet run under `clevis` itself, with LUKS2, or in an initramfs** |
| user vaults, unified recovery (§7.6) | designed |
| gssproxy holder (§7.4) | `kuipa-unseal --memfd` implemented; the gssproxy change merged as gssapi/gssproxy#135, **awaiting an upstream release** |
| FreeIPA integration (schema `ipaKUEscrowBinding`, `ipaKUEscrowFileBinding`, `ipaKUStaged`, `ipaKUVoucherSpent`, `ipaKUTrustInvitation`, `ipaKUTrustedRealm` and the `cn=trusts,cn=kuipa,cn=etc` entry; ACIs letting the daemon add hosts, host-group members and cross-realm `krbtgt` principals and write their keys; framework commands, installers, `ipa-client-install` options) | designed |

### 19.2 Tests

| suite | covers |
|---|---|
| `crates/tang-pqc` unit and `tests/{escrow,extensions,system_policy}.rs` | Tang escrow, sealed recovery requests (no binding ciphertext on the wire, fresh requests for a static binding, wrong key, tampering), the extension points (domains, contexts, opening requests, roles, signed members), crypto-policy enforcement |
| `kuipa-enroll` unit tests | trust establishment between two in-memory realms (same secret on both sides, single-use invitations, foreign signer, tampering, wrong realm), vouchers (encoding, realm, host, validity, binding, tampering, key), Merkle trees (synta-mtc's roots and inclusion proofs against an independent RFC 9162 reference, for every leaf of trees of 1–33 leaves, and tampered paths), delegations (one vouch covering several claims, proofs per anchor and selection, vouch expiry, tampering, policy), successions (one and two hops, expiry, wrong realm, forged statements and keys, cycles, the hop limit, chains kept by selection, the JSON shape without them), the anchor exchange (trust from Kerberos attestation spreading through vouches, untrusted and removed servers, renewal, an anchor rotated and succeeded, merge/delta/admission/encoding, linear growth, the sync message and attestation), the anchor epoch log (canonical entries, the numbering rule, an entry that does not commit to the entry before it, gaps and forks against a watermark, proven and self-asserted signers, trust carried forward through the chain, a forged continuation, the wire), realm verification, trusted-realm validation (own realm, duplicates, shared anchors, unsafe names) and the realm-section generator, enrollment strings (expiry mandatory, decimal, before the secret; expired strings refused), MIT keytabs, payloads, bundles (all modes, wrong recipient, tampering, `iat` checks) |
| `crates/kuipa-enroll/tests/end_to_end.rs` | every flow against an in-memory directory, with two servers that have exchanged anchors and a client pinning one: OTP join on either server, wrong OTP / wrong server, endpoint and response binding, field tampering, Kerberos join and rekey with channel bindings and the Kerberos binding (an impostor's response does not open), auth type 4 refused, staging modes A/B and first contact, staging authorisation, sealed keytab with registration, failover, revocation and rebinding, a sealed file registered by a service principal (reseal retires the old bindings, another principal's ticket and the rekey endpoint refused), bindings opening only under the principal and vault they commit to, a user vault through its whole life (policies refused, descriptors signed and verified against the anchors, sealing to a device, opening with device and ticket; refused without the device, with another device, with another user's ticket, without a ticket, with a delegated ticket the policy refuses or does not list, with a device below the policy's level, under another user's vault, after the device is removed, the owner locked or the vault revoked), the `krb5.conf` generator |
| `kuipad` unit tests | `KEYTAB_GET` DER against a hand encoding (with and without a password), `GeneralizedTime`, the key store (generation, rotation, retired keys still loaded, pruning by age, anchor rotation leaving a succession and no trace of the old key), the Tang key directory (generation, rotation, `adv/{thp}` with a retired key, recovery with a retired key), the rate limiter (bursts, refill, per-source limits, idle buckets dropped, `X-Forwarded-For`), `?anchor=` parsing, the anchor epoch merge (a continuing window adopted and both signature sets kept, a shorter window only adds signatures, a different statement at a shared sequence is a fork, a window naming another head is a fork, a gap is fetched not assumed, the sync window is a bounded recent tail) |
| `crates/ml-dsa-blind` | blind signing (results verify as stock ML-DSA, μ against OpenSSL's `ML-DSA-MU`, requests hide the message, bad responses, resumed state), crypto-policy enforcement |
| `crates/kuipa-tools/tests/cli.rs` | the `kuipa` binary: `--realm` with an enrollment string for another realm (or another case) is an error before any server is contacted; with the same realm the join goes ahead; no help text, rendered result, or error message cites a DESIGN section; labels are plain when output is captured or `$NO_COLOR` is set, emphasised when `$CLICOLOR_FORCE` asks for colour; `status` shows the pinned head windows and freezes, and a corrupt pin file refuses (naming the file) rather than reading as nothing pinned; `kuipa-unseal` refuses `--out /dev/stdout` and a symlink target before reading anything, and accepts `--out -` to a pipe, and stripping the emphasis gives byte-for-byte the plain rows |
| `crates/kuipa-tools/tests/flows.rs` | the client flows against the daemon's router over HTTP: OTP enrollment with failover (and its trace: the steps are there, the OTP is not), refusal and retry-later exits, OTP guessing stopped by the per-host limit (`429`, exit 75), wrong anchor, a stolen anchor: two pinned anchors demand two distinct proofs, so the single-vouched server is skipped and the exchange-vouched one serves the join, alone it stops at exit 75 naming the reason, and one pinned anchor takes it (§4.4), the anchor epoch watermark: a proper rotation moves it forward through the public anchor log, a log longer than one page is followed to the advertised head, and one pinned anchor refuses both a server whose log stops behind it (naming both sequences) and a log forked at it (§4.8), the LDAP-checked OTP, `realm-info` (its KDCs limited to the servers to use), pre-provisioned pins (one is enough; a second unrelated one makes the host refuse the realm), a string naming a rotated anchor verified through the succession, expired strings refused, offline bundles; advertisements for another server or domain than the deployment's refused (needs an administrator) without failing over, before any request, armoured kinit or `realm-info` file; the post-quantum Tang service with `tang-pqc`'s client (provision against the pinned thumbprint, recovery through `key/{kid}`, Tang's error statuses, rotation: the old binding still opens (its retired key still served at `key/{kid}`) and `adv/{old}` lets the old pin verify the new keys; no keys, no service), and the pin against it: encrypt and decrypt, a header pointing elsewhere refused, encryption with the old pin after a rotation |
| `crates/kuipa-tools/tests/flows.rs` (claim-log services) | DESIGN-claim-logs.md over the daemon's router: an expired pin is trusted no more than an absent one, a corrupt pin file errors rather than reading as empty, a partner head no signature proves is not pinned (§3), a frozen pin refuses a claim its own head does not prove — naming the freeze — and two frozen anchors must each prove the claim by head (§2), the whole window travels on `?head=` so a claim under only the newest head is proven (§1.4), an enrollment head nothing signed is not pinned and one a signature proves is (§4), an advertised tree larger than the fetch bound is refused with the window kept (§1.3), `kuipa-audit` coverage (current, stale, restarted, unsigned head as split) and `split-view` over two servers with forked logs, `kuipa-mirror` serving cached advertisement, claim-log pages, anchor-log heads and head-proof answers with no authenticated route |
| `crates/tang-pqc-clevis` unit and `tests/pin.rs` | the binary as `tang-pqc` and as `clevis-encrypt-tang-pqc` / `clevis-decrypt-tang-pqc` against a `tang-pqc` server: `--summary`, `adv`, refusal without or with a wrong `thp` (naming the advertised keys), round trips, fresh bindings per encryption, tampered header or ciphertext refused, the `regen` configuration, usage exits; configuration parsing, foreign JWEs |
| `crates/kuipa-tools/tests/dns.rs` | SRV discovery against a stub DNS server over UDP and TCP (truncated answers): priority and weight order, unsafe and duplicate names dropped, no records, no answer |
| `crates/kuipa-tools/tests/voucher.rs` | against a real MIT KDC: issuer key and quota, blinded request (64 bytes), unblinding, the voucher key in the advertisement; a bearer voucher creates its host in its host group once and not another host; a bound voucher needs its ephemeral key; an unknown voucher key is refused; the quota runs out |
| `crates/kuipa-tools/tests/trust.rs` | against two real MIT KDCs, realms A and B: B invites A and A's server establishes the trust over HTTP (both directories record it, the invitation is single use, A publishes B refreshed from B's advertisement); a host of A installs B from A's `trusts` (B's anchors apart from A's, B's chain, a `krb5.conf.d` snippet without `[libdefaults]`), gets anonymous-PKINIT armour from B's KDC, and gets none without B's chain or with A's chain instead; with the cross-realm keys the establishment created in both KDCs, a user of B logs in with that armour and gets a ticket for the A host; refresh, an unreachable B keeping its files, a trust entry with A's own anchor refused, removal, `leave` |
| `crates/kuipa-tools/tests/kdc.rs` | against a real MIT KDC with PKINIT, two servers running the router and the anchor exchange: both converge to both anchors and claims proven by both anchors; the two anchor logs converge to the same head and `check` moves the host's watermark to it (§4.8); GSS-API channel bindings, OTP join → `rotate-keys` → `check`, `protect` → unseal → `unprotect`, a user's own vault with her ticket (`kuipa seal`'s create, device add with a passphrase key, seal offline from the stored descriptor and advertisements, open; refused with a wrong or missing passphrase, with another user's ticket, after revocation), a service keytab and a file protected with registration (mode kept, reseal retiring the old seal, a host rekey leaving them openable, `kuipa-unseal --all`, `check`, `unprotect` retiring the bindings), one-message krb5 contexts deriving the same PRF output on both sides, the OTP as a temporary Kerberos key → armoured AS exchange → rekey (and the OTP spent after it), admin-ticket join, armoured password joins (wrong and right password), `realm-info` anchors → anonymous PKINIT (and its failure without them) → armoured `kinit` → `--use-ccache` join, staging → bundle → `complete`; an OTP join through ipa2 alone with ipa1's anchor pinned, storing both anchors; syncs with another server's token or no valid token refused |

`contrib/ci/local-ci.sh` runs these as CI jobs (the real-KDC tests as
`kdc-test`, failing rather than skipping when the KDC tools are missing),
plus formatting, clippy (including the MSRV lint), documentation, workflow
lint, the dependency policy (`deps`: no RustCrypto crates) and an opt-in
MSRV build. `local-ci.sh interactive` runs a realm with
two servers that exchange their anchors, and a trusted realm `B.TEST`
with its own KDC, for manual use. See the local CI guide (`docs/src/development/local-ci.md`).
