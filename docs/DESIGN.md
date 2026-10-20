# kuipa — post-quantum FreeIPA enrollment and keytab protection

This document describes the protocol and its implementation in this
workspace. [local-ci.md](local-ci.md) covers CI and the interactive
playground. §18 lists what is implemented, what is tested
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

Out of scope: PKINIT itself, FAST armour, ML-DSA certificates from the IPA
CA, and Custodia (§16).

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

One Cargo workspace (root `Cargo.toml`: Rust 1.88, edition 2024 except
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
  script ([local-ci.md](local-ci.md)).

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
         "anchors":["<b64url thumbprint>", …]},
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
check.

### 4.4 The enrollment string

```
ipa-ku1:<REALM>:<anchor thumbprint>:<expiry>[:<secret>]
```

The anchor thumbprint is 43 base64url characters: the anchor of the server
that issued the string. The expiry is in Unix seconds; the host refuses the
string after it (300 s of clock skew), before sending anything.
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
principal for recovery, the realm for trust requests) and per client
address, which httpd passes as the last `X-Forwarded-For` entry: by default
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
| `--principal` password join | armoured AS exchange as the user with the password, straight for `ipa-ku/<server>`; then a Kerberos join | yes for plain password users (the reply is encrypted in the user's key); no for password+OTP, RADIUS, IdP and passkey users, whose reply key comes from the armour |
| `--use-ccache` | the caller's ticket (§5.4) | as above, by how it was obtained |
| rekey, stage, `check`, `protect` | the host keytab | yes |
| `protect --keytab` / `--file` (registration, §7.5) | the keytab being protected, or the one a file is sealed with | yes |
| `--ldap-otp` (auth type 1), voucher, bundle | none | no: the anchor alone |

* **Armoured AS exchanges** (`kuipa-gssapi::password_ticket`) run in
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
anchors[] (thumbprints)                        → /etc/ipa/ku-anchors
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
for each reachable server i with an escrow key:
    (B_i, K_i) = tang-pqc provision to server i's escrow key,
                 domain "ipa-ku-enroll/v1 escrow", info = "host/<fqdn>@REALM"
    W_i = GCM_{K_i}(DEK)
/etc/ipa/krb5.keytab.sealed = IPSK(principal, [(server_i, B_i, ek_i, W_i)], GCM_DEK(MIT keytab))
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
* **Recovery:** `POST /ipa/ku/rec/{kid}` carries the principal and a
  `tang-pqc` recovery request, whose binding ciphertext is sealed to the
  escrow key (`tang-pqc` DESIGN §3.3). The server opens it in the escrow
  domain, then answers only for an enabled entry of the principal
  (`nsAccountLock` not true) whose registered bindings, in either set
  (§7.5), include the opened `H(ct)`. The principal
  is also bound into `K_i`, so naming another principal yields a wrong key.
* **Revocation:** disabling or deleting the host, or clearing the attribute,
  stops unsealing at once. A fresh seal (every `rotate-keys`) retires the old
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
| the same after `ipa host-disable` | nothing (keys gone) | nothing |
| an image from before the last rotation, host enabled | that kvno's keys | nothing (binding no longer registered) |
| root on the running host | host identity | host identity |

### 7.4 gssproxy as the holder (designed; needs a gssproxy change)

GSS-API services that run through gssproxy never see keytabs. If gssproxy
itself unseals, the keytab never touches a filesystem. This needs no change
to MIT Kerberos — `MEMORY:` keytabs are stock, and a keytab in a memfd can be
read through `FILE:/proc/self/fd/N` and copied in — but it needs gssproxy to
learn:

1. a per-service `keytab_loader = /usr/libexec/kuipa-unseal --memfd`: run
   the loader with a memfd as fd 3, import the keytab into
   `cred_store = keytab:MEMORY:<name>`, close the memfd;
2. re-run the loader on `SIGHUP` and swap the keytab atomically;
3. retry a failing loader with backoff;
4. keep keytab memory out of core dumps.

`kuipa-unseal --memfd` already implements the loader side. GSS-API
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
| the same after the principal is disabled (`nsAccountLock`) | its contents (keys valid until rotated) | nothing |
| an image from before the last reseal or `unprotect` | that version | nothing (binding retired) |
| root on the running host | its contents | its contents |

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
| `etc/ipa/ku-anchors` | pinned anchors of the host's realm, one per line; a pre-provisioned line may add its expiry, `<thumbprint> <unix seconds>`, after which it is ignored (§4.4) |
| `etc/ipa/ku-anchors.d/<REALM>`, `var/lib/ipa-client/ku/trusts/<REALM>/`, `etc/krb5.conf.d/kuipa_trust_<REALM>` | a trusted realm's anchors, PKINIT anchors and CA, and Kerberos configuration (§17.3) |
| `etc/ipa/krb5.keytab.sealed` | the sealed keytab |
| `run/ipa/krb5.keytab` | the unsealed keytab in file mode |
| `<path>.sealed`, `run/ipa/kuipa/<escaped path>` | another protected keytab or file, sealed and unsealed; `<path>` is a symlink to the latter (§7.5) |
| `var/lib/ipa-client/ku/state.json` | realm, FQDN, servers (issuer first), protection, other protected keytabs and files |
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
to fd 3 with `--memfd`, or to its unsealed copy if `kuipa protect` recorded
it (§7.5). Exit 0, 75 (no server could unseal) or 1.

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
| `enrollment-string [--days 7]` | print `ipa-ku1:REALM:<anchor>:<expiry>`, valid that many days (at most 400), to append `:<OTP>` to (§4.4) |
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
| POST | `/ipa/ku/rec/{kid}` | `IPEQ` → `TQRS` |
| POST | `/ipa/ku/peer/sync` | `IPPS` → agirru envelope (CBOR); servers only (§4.2) |
| POST | `/ipa/ku/trust/{kid}` | `IPTQ` → `IPTS` (§17.4) |
| GET | `/ipa/ku/tang/adv`, `/ipa/ku/tang/adv/{thp}` | → Tang advertisement (`application/jose+json`) (§11.5) |
| GET | `/ipa/ku/tang/key/{kid}` | → Tang exchange key (`application/jwk+json`) (§11.5) |
| POST | `/ipa/ku/tang/rec/{kid}` | `TQRQ` → `TQRS` (§11.5) |

Bodies are limited to 64 KiB; the path `kid` must match the request's.
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
authentically), PKINIT and its anonymous armour, Custodia (which escrows
CA storage keys in non-HSM deployments), DNSSEC.

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
IPSK  principal n(1) [server binding(TQBD) ek wrapped] sealed                    sealed keytab
IPEQ  principal recovery(TQRQ)                                                   escrow request
IPPS  sender receiver delegation(JSON) envelope token                           peer sync request
IPDC  realm server anchor(32) key(32) iat(u64) exp(u64)                          claim
IPVH  realm anchor(32) iat(u64) exp(u64) size(u64) root(32)                      vouch (signed)
IPSV  vouch(IPVH) signature n(u64) [leaf(32)]                                    signed vouch with leaves
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
| `BindingContext`, `provision_with`, `Binding::{from_bytes_with, ciphertext_hash, recovery_request}`, `RecoveryRequest::open`, `OpenedRequest::{ciphertext_hash, respond}` | sealed keytabs and escrow |
| `Policy`, `wire`, `b64`, seed JWKs, thumbprints, system-policy checks | throughout |

`tang-pqc`'s own DESIGN.md §8 describes these extension points.

## 16. Out of scope and open questions

* **PKINIT and FAST armour** stay classical until PQ PKINIT exists; the host
  keys kuipa protects are symmetric.
* **ML-DSA certificates** from the IPA CA would make TLS server
  authentication post-quantum; kuipa's CA pinning works for any algorithm.
* **Custodia** should gain an ML-KEM key exchange; kuipa does not depend on
  it.
* **Anchor exchange scale:** the state grows linearly with the number of
  anchors; with every server an anchor, 60 servers make 489 KB of state and
  321 KB of deltas per renewal round. Large realms should give the anchor
  role to a few servers (6 of 60: 55 KB and 32 KB, §4.2).
* **Merkle Tree Certificates:** vouches are tree heads over claims, with
  the same hashing and inclusion proofs as MTC. Anchors issued as MTC
  certificates, or pre-distributed tree heads ("landmarks") that let a
  client skip the signature check, can build on this; `synta-mtc`, which
  already builds the trees, has both.
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

## 18. Implementation status and tests

### 18.1 Status

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
| vouchers (§9): `ml-dsa-blind` issuing, `kuipa-voucher`, bound and bearer vouchers, voucher joins | implemented, tested against a real KDC; the LDAP side **not yet run against FreeIPA** |
| TPM factor for sealed keytabs, `prepare --tpm` | designed |
| post-quantum Tang service (§11.5): `adv`, `adv/{thp}`, `key/{kid}`, `rec/{kid}`, Tang-style key directory and rotation | implemented, tested over HTTP |
| `tang-pqc` client and Clevis pin (§10.7), installer, dracut module | implemented, tested as a command and through the pin's names over HTTP; **not yet run under `clevis` itself, with LUKS2, or in an initramfs** |
| gssproxy holder (§7.4) | `kuipa-unseal --memfd` implemented; needs the gssproxy change |
| FreeIPA integration (schema `ipaKUEscrowBinding`, `ipaKUEscrowFileBinding`, `ipaKUStaged`, `ipaKUVoucherSpent`, `ipaKUTrustInvitation`, `ipaKUTrustedRealm` and the `cn=trusts,cn=kuipa,cn=etc` entry; ACIs letting the daemon add hosts, host-group members and cross-realm `krbtgt` principals and write their keys; framework commands, installers, `ipa-client-install` options) | designed |

### 18.2 Tests

| suite | covers |
|---|---|
| `crates/tang-pqc` unit and `tests/{escrow,extensions,system_policy}.rs` | Tang escrow, sealed recovery requests (no binding ciphertext on the wire, fresh requests for a static binding, wrong key, tampering), the extension points (domains, contexts, opening requests, roles, signed members), crypto-policy enforcement |
| `kuipa-enroll` unit tests | trust establishment between two in-memory realms (same secret on both sides, single-use invitations, foreign signer, tampering, wrong realm), vouchers (encoding, realm, host, validity, binding, tampering, key), Merkle trees (synta-mtc's roots and inclusion proofs against an independent RFC 9162 reference, for every leaf of trees of 1–33 leaves, and tampered paths), delegations (one vouch covering several claims, proofs per anchor and selection, vouch expiry, tampering, policy), successions (one and two hops, expiry, wrong realm, forged statements and keys, cycles, the hop limit, chains kept by selection, the JSON shape without them), the anchor exchange (trust from Kerberos attestation spreading through vouches, untrusted and removed servers, renewal, an anchor rotated and succeeded, merge/delta/admission/encoding, linear growth, the sync message and attestation), the anchor epoch log (canonical entries, the numbering rule, an entry that does not commit to the entry before it, gaps and forks against a watermark, proven and self-asserted signers, trust carried forward through the chain, a forged continuation, the wire), realm verification, trusted-realm validation (own realm, duplicates, shared anchors, unsafe names) and the realm-section generator, enrollment strings (expiry mandatory, decimal, before the secret; expired strings refused), MIT keytabs, payloads, bundles (all modes, wrong recipient, tampering, `iat` checks) |
| `crates/kuipa-enroll/tests/end_to_end.rs` | every flow against an in-memory directory, with two servers that have exchanged anchors and a client pinning one: OTP join on either server, wrong OTP / wrong server, endpoint and response binding, field tampering, Kerberos join and rekey with channel bindings and the Kerberos binding (an impostor's response does not open), auth type 4 refused, staging modes A/B and first contact, staging authorisation, sealed keytab with registration, failover, revocation and rebinding, a sealed file registered by a service principal (reseal retires the old bindings, another principal's ticket and the rekey endpoint refused), the `krb5.conf` generator |
| `kuipad` unit tests | `KEYTAB_GET` DER against a hand encoding (with and without a password), `GeneralizedTime`, the key store (generation, rotation, retired keys still loaded, pruning by age, anchor rotation leaving a succession and no trace of the old key), the Tang key directory (generation, rotation, `adv/{thp}` with a retired key, recovery with a retired key), the rate limiter (bursts, refill, per-source limits, idle buckets dropped, `X-Forwarded-For`), `?anchor=` parsing, the anchor epoch merge (a continuing window adopted and both signature sets kept, a shorter window only adds signatures, a different statement at a shared sequence is a fork, a window naming another head is a fork, a gap is fetched not assumed, the sync window is a bounded recent tail) |
| `crates/ml-dsa-blind` | blind signing (results verify as stock ML-DSA, μ against OpenSSL's `ML-DSA-MU`, requests hide the message, bad responses, resumed state), crypto-policy enforcement |
| `crates/kuipa-tools/tests/cli.rs` | the `kuipa` binary: `--realm` with an enrollment string for another realm (or another case) is an error before any server is contacted; with the same realm the join goes ahead; no help text, rendered result, or error message cites a DESIGN section; labels are plain when output is captured or `$NO_COLOR` is set, emphasised when `$CLICOLOR_FORCE` asks for colour, and stripping the emphasis gives byte-for-byte the plain rows |
| `crates/kuipa-tools/tests/flows.rs` | the client flows against the daemon's router over HTTP: OTP enrollment with failover (and its trace: the steps are there, the OTP is not), refusal and retry-later exits, OTP guessing stopped by the per-host limit (`429`, exit 75), wrong anchor, a stolen anchor: two pinned anchors demand two distinct proofs, so the single-vouched server is skipped and the exchange-vouched one serves the join, alone it stops at exit 75 naming the reason, and one pinned anchor takes it (§4.4), the anchor epoch watermark: a proper rotation moves it forward through the public anchor log, a log longer than one page is followed to the advertised head, and one pinned anchor refuses both a server whose log stops behind it (naming both sequences) and a log forked at it (§4.8), the LDAP-checked OTP, `realm-info` (its KDCs limited to the servers to use), pre-provisioned pins (one is enough; a second unrelated one makes the host refuse the realm), a string naming a rotated anchor verified through the succession, expired strings refused, offline bundles; advertisements for another server or domain than the deployment's refused (needs an administrator) without failing over, before any request, armoured kinit or `realm-info` file; the post-quantum Tang service with `tang-pqc`'s client (provision against the pinned thumbprint, recovery through `key/{kid}`, Tang's error statuses, rotation: the old binding still opens (its retired key still served at `key/{kid}`) and `adv/{old}` lets the old pin verify the new keys; no keys, no service), and the pin against it: encrypt and decrypt, a header pointing elsewhere refused, encryption with the old pin after a rotation |
| `crates/tang-pqc-clevis` unit and `tests/pin.rs` | the binary as `tang-pqc` and as `clevis-encrypt-tang-pqc` / `clevis-decrypt-tang-pqc` against a `tang-pqc` server: `--summary`, `adv`, refusal without or with a wrong `thp` (naming the advertised keys), round trips, fresh bindings per encryption, tampered header or ciphertext refused, the `regen` configuration, usage exits; configuration parsing, foreign JWEs |
| `crates/kuipa-tools/tests/dns.rs` | SRV discovery against a stub DNS server over UDP and TCP (truncated answers): priority and weight order, unsafe and duplicate names dropped, no records, no answer |
| `crates/kuipa-tools/tests/voucher.rs` | against a real MIT KDC: issuer key and quota, blinded request (64 bytes), unblinding, the voucher key in the advertisement; a bearer voucher creates its host in its host group once and not another host; a bound voucher needs its ephemeral key; an unknown voucher key is refused; the quota runs out |
| `crates/kuipa-tools/tests/trust.rs` | against two real MIT KDCs, realms A and B: B invites A and A's server establishes the trust over HTTP (both directories record it, the invitation is single use, A publishes B refreshed from B's advertisement); a host of A installs B from A's `trusts` (B's anchors apart from A's, B's chain, a `krb5.conf.d` snippet without `[libdefaults]`), gets anonymous-PKINIT armour from B's KDC, and gets none without B's chain or with A's chain instead; with the cross-realm keys the establishment created in both KDCs, a user of B logs in with that armour and gets a ticket for the A host; refresh, an unreachable B keeping its files, a trust entry with A's own anchor refused, removal, `leave` |
| `crates/kuipa-tools/tests/kdc.rs` | against a real MIT KDC with PKINIT, two servers running the router and the anchor exchange: both converge to both anchors and claims proven by both anchors; the two anchor logs converge to the same head and `check` moves the host's watermark to it (§4.8); GSS-API channel bindings, OTP join → `rotate-keys` → `check`, `protect` → unseal → `unprotect`, a service keytab and a file protected with registration (mode kept, reseal retiring the old seal, a host rekey leaving them openable, `kuipa-unseal --all`, `check`, `unprotect` retiring the bindings), one-message krb5 contexts deriving the same PRF output on both sides, the OTP as a temporary Kerberos key → armoured AS exchange → rekey (and the OTP spent after it), admin-ticket join, armoured password joins (wrong and right password), `realm-info` anchors → anonymous PKINIT (and its failure without them) → armoured `kinit` → `--use-ccache` join, staging → bundle → `complete`; an OTP join through ipa2 alone with ipa1's anchor pinned, storing both anchors; syncs with another server's token or no valid token refused |

`contrib/ci/local-ci.sh` runs these as CI jobs (the real-KDC tests as
`kdc-test`, failing rather than skipping when the KDC tools are missing),
plus formatting, clippy (including the MSRV lint), documentation, workflow
lint, the dependency policy (`deps`: no RustCrypto crates) and an opt-in
MSRV build. `local-ci.sh interactive` runs a realm with
two servers that exchange their anchors, and a trusted realm `B.TEST`
with its own KDC, for manual use. See [local-ci.md](local-ci.md).
