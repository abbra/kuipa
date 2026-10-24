# A traced session in the playground

This session runs in the interactive playground (`contrib/ci/local-ci.sh
interactive`, see [Local CI and the playground](../development/local-ci.md)). Host `web1` enrolls in
`EXAMPLE.TEST`. It then installs the trusted realm `B.TEST`, a user of
`B.TEST` logs in on it, and that user gets a ticket for `web1` across the
trust. With tracing on, every request, answer, decision and file write
appears on standard error (see the design's
[tracing](../reference/design.md#104-tracing) section); the command's
result follows on standard output.

The same flow, with many more steps, runs scripted in
`./contrib/ci/local-ci.sh playground-test`, which writes a report to
`kuipa-playground-report/`: every step's output and trace, plus an
animated terminal capture of each section of the session. This page
follows that session's sixteen sections; the traced steps below quote
it, so what you read here is what CI saw, minus the playground's
throwaway paths and thumbprints.

Thumbprints, ports, timings and paths differ in every playground. Times
print as calendar dates in UTC, everywhere a tool reports one to a
person; `--json` keeps raw Unix seconds for scripts.

## 1. Turn tracing on

```
[kuipa web1] kuipa $ export KUIPA_TRACE=kuipa_tools=trace,kuipa_gssapi=debug
```

`KUIPA_TRACE` takes `tracing` filter directives. This one shows every
detail from the client tools and debug messages from the GSS-API
bindings. `--verbose` and `--trace` on a single command give the same
without the variable. Traces never contain secrets (OTPs, passwords,
keys, GSS-API tokens), only their sizes and thumbprints.

## 2. Enroll with an OTP: `pq_enroll web1`

`pq_enroll web1` runs `kuipa enroll --server ipa1.example.test --server
ipa2.example.test --hostname web1.example.test` with web1's enrollment
string, `ipa-ku1:EXAMPLE.TEST:<anchor>:<expiry>:<OTP>`, as `ipa host-add
--random` would print it ([The enrollment string](../reference/design.md#44-the-enrollment-string)). The string expires a day after the
playground starts. As `host-add` does, the playground also made the OTP the
host's temporary Kerberos key ([Authenticators](../reference/design.md#53-authenticators)).

### Fetch and verify the realm advertisement

```
   0.004182272s TRACE endpoint server="ipa1.example.test" base=http://127.0.0.1:42923/ipa/ku/ tls="none"
   0.005410270s DEBUG GET http://127.0.0.1:42923/ipa/ku/adv?anchor=pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ (0 bytes) server=ipa1.example.test
   0.012204903s DEBUG 200 OK: 24535 bytes in 6 ms server=ipa1.example.test
```

* The client tries the servers in the order given, ipa1 first.
  `KUIPA_ENDPOINTS` maps the name to a local port over plain HTTP, hence
  `tls="none"`. On a real host this is `https://ipa1.example.test/ipa/ku/`,
  and on first contact TLS accepts any certificate: the host has no CA yet,
  and the advertisement, not TLS, authenticates the server ([Transport](../reference/design.md#103-transport)).
* `?anchor=pjLV…` names the anchor pinned by the enrollment string: ipa1's
  own anchor, since ipa1 issued the string. The server answers with an
  advertisement whose delegation carries that anchor's proof ([The realm advertisement](../reference/design.md#43-the-realm-advertisement)).
* About 25 KB: ML-DSA-65 signatures and keys, base64-encoded inside JSON,
  plus the CA certificate and the PKINIT anchors.

```
   0.017085387s DEBUG advertisement verified: ipa1.example.test of EXAMPLE.TEST, signed by 0hznLdS2gMlbsHVPD5MjxvyQqox9Sw6wAp8a8mNgLbg, delegation by anchor pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ (claim: 89 days left, vouch: 7 days left) server=ipa1.example.test
```

Verification ([The realm advertisement](../reference/design.md#43-the-realm-advertisement)) runs in three steps:

1. The delegation's claim names realm `EXAMPLE.TEST`, server
   `ipa1.example.test` and its signing key, and is valid now. Its proof by
   the pinned anchor `pjLV…` verifies: the anchor's signature over its
   vouch, and the claim's inclusion path in the vouched Merkle tree.
2. The advertisement is signed by the server signing key `0hzn…` that the
   claim names.
3. Its realm information matches the claim.

"claim: 89 days left, vouch: 7 days left": claims last 90 days, and each
server renews its own at two thirds of the lifetime; a vouch lasts 7 days,
and each anchor vouches again at half life or whenever the claims it
trusts change ([Delegations and the anchor exchange](../reference/design.md#42-delegations-and-the-anchor-exchange)).

```
   0.017132035s TRACE advertisement contents server=ipa1.example.test domain=example.test servers=["ipa1.example.test", "ipa2.example.test"] join_key=4zRtyVcF9IQNUKBEAcIzyjFTHc9O584n-0PydLfSS-0 escrow_key=KkVcqIPOzuFGEZKNRHQyV0hnHFi8bVWS1UBm2tL6kgc ca_certs=1 pkinit_anchors=1 anchors=["pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ", "WdR5rAyr1-fDWTwzIRofwxAsBo_PtvKCw0aOVufgkOk"] trusts=["B.TEST"]
```

What the verified advertisement provides:

* **`join_key`**: the ML-KEM-768 key the join request is sealed to.
* **`escrow_key`**: the key for sealed keytabs ([Keytab protection](../reference/design.md#7-keytab-protection)).
* **`ca_certs`, `pkinit_anchors`**: the IPA CA and the KDC's PKINIT chain,
  authenticated here before enrollment.
* **`anchors`**: the realm's trusted anchors. There are two because ipa1
  (`pjLV…`) and ipa2 (`WdR5…`) each have their own anchor and exchanged
  them over Kerberos-authenticated syncs before the shell started ([Delegations and the anchor exchange](../reference/design.md#42-delegations-and-the-anchor-exchange)).
  ipa1's own comes first.
* **`trusts`**: the trusted realms, here `B.TEST` ([Trusted IPA realms](../reference/design.md#17-trusted-ipa-realms)).

```
   0.017159105s DEBUG TLS from now on verified against the advertised IPA CA server=ipa1.example.test
   0.017188350s TRACE endpoint server="ipa1.example.test" base=http://127.0.0.1:42923/ipa/ku/ tls="none"
```

The join request goes over a new connection that verifies the server's TLS
certificate against the CA the advertisement just authenticated. Over the
playground's plain HTTP there is nothing to verify, so the second endpoint
also says `tls="none"`; on a real host it says `verified against the IPA
CA`.

### The join exchange

```
   0.015325549s DEBUG armoured AS exchange as host/web1.example.test@EXAMPLE.TEST for ipa-ku/ipa1.example.test@EXAMPLE.TEST
   0.036719841s DEBUG GSS-API token for ipa-ku/ipa1.example.test@EXAMPLE.TEST, bound to the exchange (896 bytes)
   0.036798669s DEBUG Rekey request for web1.example.test in EXAMPLE.TEST with Kerberos authentication, to join key lVyDC-Zmyo2dVYZmkz8KnQb-wFiWV3EDQIwQkVMBEf0 server=ipa1.example.test
   0.036887707s DEBUG POST http://127.0.0.1:42809/ipa/ku/rekey/lVyDC-Zmyo2dVYZmkz8KnQb-wFiWV3EDQIwQkVMBEf0 (3304 bytes) server=ipa1.example.test
```

1. **A ticket with the OTP.** The client writes the advertisement's KDCs
   and PKINIT anchors into a private `krb5.conf`. It gets anonymous PKINIT
   armour, then a ticket as `host/web1` for `ipa-ku/ipa1`, with the OTP as
   the key, in a FAST exchange ([Authenticators](../reference/design.md#53-authenticators)). The OTP never leaves the host. A
   fake KDC could only answer by knowing the OTP-derived key.
2. **One Kerberos token.** The token for that ticket is a single Kerberos
   V5 message bound to this KEM exchange by `cb`. Both ends derive the same
   32 bytes `kb` from its session key ([Key schedule](../reference/design.md#51-key-schedule)), and only the real
   `ipa-ku/ipa1` can.
3. **A rekey as the host itself.** The OTP-derived key already makes the
   host a Kerberos principal, so the request is a rekey, which accepts only
   the host itself. The client encapsulates to the join key and seals the
   token under the shared secret `ss`. It sends a fresh ephemeral ML-KEM key
   for the response.

Most of the 3304 bytes are the ML-KEM-768 ciphertext (1088), the
ephemeral key (1184) and the token (896). The transcript binds every clear
field and the operation, so the request cannot be replayed at another
endpoint.

```
   0.060626237s DEBUG 200 OK: 2245 bytes in 23 ms server=ipa1.example.test
   0.055947180s DEBUG received keys for host/web1.example.test@EXAMPLE.TEST (kvno 2, enctypes [20, 19]), 1 CA certificate(s), 2 anchor(s), issuer ipa1.example.test server=ipa1.example.test
   0.055974381s TRACE enrollment contents server=ipa1.example.test realm=EXAMPLE.TEST domain=example.test servers=["ipa1.example.test", "ipa2.example.test"] pkinit_anchors=1
```

* **The server's side:** it decapsulated and accepted the token as
  `host/web1` with the same `cb`. It had new keys created, which replace
  the OTP-derived key, and deleted the host's `userPassword`, so the OTP is
  spent for both paths ([Directory over LDAPI and GSSAPI](../reference/design.md#114-directory-over-ldapi-and-gssapi)).
* **The response:** an encapsulation to the client's ephemeral key and the
  payload, sealed under a key derived from both KEM secrets and `kb`.
  Recording it and later breaking the join key reveals nothing. A server
  whose anchor verified but that cannot accept the ticket cannot produce it
  ([Key schedule](../reference/design.md#51-key-schedule)).
* **What it holds:**
  * **The keytab:** the host's new keys. The client proposed four enctypes;
    the KDC allowed `aes256-cts-hmac-sha384-192` (20) and
    `aes128-cts-hmac-sha256-128` (19). kvno 2: the OTP-derived key was
    kvno 1, and the rekey had the KDC generate new keys, standing in for
    `KEYTAB_GET`.
  * **The CA chain:** installed only because it matches the advertisement
    ([Response payload](../reference/design.md#55-response-payload)).
  * **The anchors:** both of the realm's, which the host pins from now on
    ([Anchor lists on enrolled hosts](../reference/design.md#45-anchor-lists-on-enrolled-hosts)).
  * **The realm configuration:** realm, domain and servers; the issuer comes
    first.

### What is installed

```
   0.057300294s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/etc/krb5.keytab (174 bytes, mode 600)
   0.057381346s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/etc/ipa/ca.crt (566 bytes, mode 644)
   0.057431771s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/etc/ipa/ku-anchors (111 bytes, mode 644)
   0.057503786s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/pkinit-anchors.pem (566 bytes, mode 644)
   0.057572916s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/krb5.conf (686 bytes, mode 644)
   0.057624633s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/state.json (149 bytes, mode 600)
```

Each host in the playground has its own root (`KUIPA_ROOT`); on a real
host these paths start at `/` ([Files and environment](../reference/files.md)). Every file is written atomically:

| file | contents |
|---|---|
| `etc/krb5.keytab` | the host keys (mode 0600) |
| `etc/ipa/ca.crt` | the IPA CA, now authentic, for TLS from here on |
| `etc/ipa/ku-anchors` | the realm's two anchors |
| `var/lib/ipa-client/ku/pkinit-anchors.pem` and `krb5.conf` | a Kerberos configuration generated from verified data, used when the system has none for the realm |
| `var/lib/ipa-client/ku/state.json` | realm, host name and the servers, issuer first |

```
Enrolled host/web1.example.test@EXAMPLE.TEST in EXAMPLE.TEST: its keys, the realm's anchors, CA and Kerberos configuration all taken from ipa1.example.test's verified advertisement.
principal: host/web1.example.test@EXAMPLE.TEST
kvno: 2
issuer: ipa1.example.test
realm: EXAMPLE.TEST
IPA servers: ipa1.example.test, ipa2.example.test
domain: example.test
LDAP base: dc=example,dc=test
  installed here:
    host keys: /tmp/kuipa-playground-222664/hosts/web1/etc/krb5.keytab
    IPA CA: /tmp/kuipa-playground-222664/hosts/web1/etc/ipa/ca.crt
    pinned anchors: /tmp/kuipa-playground-222664/hosts/web1/etc/ipa/ku-anchors
    PKINIT anchors: /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/pkinit-anchors.pem
    Kerberos configuration: /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/krb5.conf
    state: /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/state.json
```

The command's result, on standard output: what was enrolled, which server
issued it, and which file on this host holds each part. `--json` prints the
same values as one JSON object.

`kuipa status` then names the same subject in its own words — the
anchors the host pinned, each with the head window it holds over that
anchor's claim log, and where every file lives:

```
What kuipa has installed for host/web1.example.test@EXAMPLE.TEST (state file: …/state.json)
                         principal: host/web1.example.test@EXAMPLE.TEST
                              kvno: 2
                             realm: EXAMPLE.TEST
                       IPA servers: ipa1.example.test, ipa2.example.test
               anchors pinned here: UXKR…xg, nGpA…Ho
                       head window: UXKR…xg: 2 leaves
                       head window: nGpA…Ho: 2 leaves
          trusted realms installed: none
                    keytab held by: none
```

## 3. Rekey and check: `kuipa rotate-keys`, `kuipa check`

New host keys, authenticated by the keytab itself rather than any OTP —
a request only the enrolled host can send:

```
New host keys, issued by ipa1.example.test:
principal: host/web1.example.test@EXAMPLE.TEST
     kvno: 3
   issuer: ipa1.example.test
```

`kuipa check` then verifies every server's advertisement against the
pinned anchors, and that a `kinit` with the current keys succeeds — its
`servers:` block lists one row per server, `advertisement verified` with
`delegation: 89 days left`, and ends in `problems: none`. With both
servers unreachable (the session's last section) the same command lists
each as `server unreachable`, names the exact request that failed, and
exits non-zero.

## 4. Keytab protection: `kuipa protect`, `kuipa-unseal`

```
The keytab is sealed on disk: opening it needs one of the realm's servers, as at boot.
Keys reissued before sealing, issued by ipa1.example.test:
principal: host/web1.example.test@EXAMPLE.TEST
     kvno: 4
   issuer: ipa1.example.test
sealed as: …/etc/ipa/krb5.keytab.sealed
```

`kuipa protect` reissues the keys first (a sealed copy of a keytab must
not hold keys the plain one still has), then seals the keytab to the
advertisement's escrow keys. `kuipa-unseal` is what the boot unit runs:
its trace shows the escrow recovery — `POST /ipa/ku/rec/<escrow key
thumbprint>`, one request, the key back under ML-KEM — and it writes
the plain keytab to `run/ipa/krb5.keytab` (tmpfs). `kuipa check` with
the sealed keytab, then `kuipa unprotect`, round the section off.

## 5. Protecting any file: `kuipa protect --file`

Any file seals the same way, for the principal of a keytab (the host's
by default). Its bindings are registered with that principal's own
ticket, so a host rekey leaves them in place:

```
/tmp/…/etc/app/secret.conf is sealed on disk: opening it needs one of the realm's servers, as at boot.
                     holds: file
   bindings registered for: host/web1.example.test@EXAMPLE.TEST
             registered by: ipa1.example.test
servers that can unseal it: ipa1.example.test, ipa2.example.test
                 sealed as: …/etc/app/secret.conf.sealed
     unsealed copy (tmpfs): …/run/ipa/kuipa/tmp-…-secret.conf
```

After a rekey (which changes only the keytab's bindings), `kuipa-unseal
--all` recovers both the keytab and the file, `cat` reads the secret
through the tmpfs symlink, and `kuipa-unseal --sealed … --out -` prints
only the plaintext — traces stay on standard error. `--out /dev/stdout`
is refused, since replacing that symlink would replace the link.
`kuipa unprotect --file` retires the bindings: no copy of the sealed
file opens any more.

## 6. Sealing your own files: `kuipa seal`

A user's vaults, run as the user with their ticket (`pq_admin_kinit`
here). A vault is created with the factors its opens need — this one a
registered device under a passphrase plus the ticket:

```
Vault personal (admin@EXAMPLE.TEST), enabled:
               id: 39942eb30c05fd03877c5d4fdd9cd79d
    opening needs: a registered device (any) and your Kerberos ticket
          expires: 2027-11-27 12:21:03 UTC
   unlocks so far: 0
delegated tickets: allow
          devices: none
     described by: ipa1.example.test
```

The vault's expiry prints as a UTC date, not a Unix counter — a person
decides with the calendar. Adding this host's device key lists it under
`devices:` with its thumbprint; sealing and opening a file round-trips
(`token=playground-user` back on standard output), and a wrong
passphrase is refused: `kuipa seal: wrong passphrase`.

Each of those steps went into the transparency log of the server that
handled it. `kuipa tlog watch personal` checks every server's log for
the vault. The first watch lists the history and only records where
each log stands:

```
        ok  ipa1.example.test #0 at 2026-10-24 12:30:16 UTC: create
        ok  ipa1.example.test #1 at 2026-10-24 12:30:16 UTC: add-device device L_LxP5xhTXsQXtHSYqZqQIyZBjoFUtliO4nZOqL0UMk
        ok  ipa1.example.test #2 at 2026-10-24 12:30:16 UTC: release device L_LxP5xhTXsQXtHSYqZqQIyZBjoFUtliO4nZOqL0UMk
  baseline  ipa1.example.test: first watch, history not flagged
Vault personal: 0 unexpected.
```

ipa2 handled nothing for this vault, so its log is empty and the watch
has nothing to list from it. A second device registered from another
data directory (`KUIPA_USER_DIR=…/admin-laptop`) is not in the vault
description this host stored, so the next watch flags it and exits 1:

```
UNEXPECTED  ipa1.example.test #3 at 2026-10-24 12:30:17 UTC: add-device device hjrpLcMII4mUXrCDd8os2VrTEeXa1rwbAERAd0yzhjo (a device the stored descriptor does not list)
Vault personal: 1 unexpected.
```

`kuipa seal show personal` stores the current description, which
accepts the device. The next watch is clean, and the next open shows up
as one more `release`.

A second vault allows hour-long sessions and ten unlocks
(`--session-hours 1 --max-unlocks 10`, shown as `unlocks allowed: 10`
and `longest session (seconds): 3600`). One unlock — passphrase and
ticket, once — starts it:

```
Session started: files open on this host without the passphrase or a ticket until 2026-10-23 13:21:05 UTC, or `kuipa seal lock`.
```

Until that date, opens need neither the passphrase nor a ticket;
`kuipa seal lock` ends the session early, and `kuipa seal show` then
counts `unlocks so far: 1`.

Offline sessions (`travel`, `--offline-hours 2`) go further: the
device's unlock releases the vault's session key to this host, so files
sealed `--session` open with every server down:

```
Offline session started: files sealed with --session open on this host without any server until 2026-10-23 14:21:05 UTC, or `kuipa seal lock`.
```

With both servers unreachable the boarding pass still opens; the
session's end is the date above, not a server's decision (see
[Sealing your own files](../user/sealing.md) for what that costs).
`kuipa seal revoke personal` ends the section: the vault prints
`revoked`, and no server opens its files any more.

## 7. Failover: `pq_enroll web2` with ipa1 down

With ipa1 unreachable, web2 enrolls through ipa2 — `issuer:
ipa2.example.test` — because every server presents an advertisement
ipa1's anchor vouches for. Enrolled, web2 must keep verifying ipa2 with
the anchors it pinned, not the one anchor of the enrollment string it
was issued, whose server is the one that is down. `kuipa advertisement
--server ipa2.example.test` shows the whole verified view: the signing
key, the pinned anchor that proves the claim, `its delegation: 89 days
left`, the join and escrow keys, and the anchor log index — every key
these servers named, and what it belongs to.

## 8. Password and ticket enrollment: `pq_password web3`, `pq_bootstrap`

web3 enrolls with the administrator's password, through an armoured
kinit on the host (the `ipa-client-install -p admin -w` habit); web4
with an existing ticket, after `pq_bootstrap` did what
`ipa-client-install` does before one: `kuipa realm-info` writes a
Kerberos configuration from the verified advertisement, anonymous
PKINIT armour is obtained with the advertised anchors, and the armoured
`kinit` follows. Both end in the same enrolled summary as web1.

## 9. Offline enrollment: `pq_offline web5`, `kuipa complete`

web5 prepares a machine key (`kuipa prepare`), the administrator stages
it (`ipa host-add --pq-stage --pq-recipient=…`, stood in for by
`kuipa-playground stage`), and web5 enrolls from the sealed, signed
bundle without talking to a server. The staged enrollment reports the
bundle's own deadline — the row the host writes to decide when to
finish:

```
  staged, to finish at first contact (`kuipa complete`) for "web5.example.test":
    the staged bundle is usable until: 2026-10-24 12:36:12 UTC
  deferred steps:
    rotate-keys
    kinit
    ca-certs
    dns-update
    ssh-keys
    host-certificate
    time-sync
    automount
```

At first contact — once a server is reachable — `kuipa complete`
replaces the staged keys with keys from the KDC (`kvno: 3`) and lists
what is left for `ipa-client-install` on the host.

## 10. Voucher enrollment: `pq_voucher web6 --bound`

web6 has no host entry and no OTP: it enrolls with a voucher the issuer
signed blindly, bound to the host's ephemeral key. The voucher's claims
print as JSON — `kuipa-voucher show` output, machine-readable, so its
`not_after` stays Unix seconds — and the enrollment that follows is the
same summary again. Vouchers are for fleets; see
[Cloud virtual machines](cloud.md).

## 11. Auditing the claim logs: `kuipa-audit`

`kuipa-audit coverage` reads the realm's public claim logs and checks
what the pinned heads cover: for each anchor, the pinned head (`2
leaves, root …`) beside the served head, and a `state` — `current` when
the server's log extends the pinned one. `kuipa-audit split-view`
compares servers: `no disagreements: every server answers the same
heads`.

The claim log itself, decoded, ends with the vouch's expiry as a date:

```
server         http://127.0.0.1:36995
anchor         UXKR…xg
leaves         2
root           6GMRG29mLohvnvJUvLXqa37xBXTV9WOPjXiXPm2_EUg
vouch expires  2026-10-30 12:21:03 UTC
leaf count     2
     1  jw2GNV1__uSEVfz7jRqxpLrBmk1-Zwm-vnwXNY0J7kY
     2  gEaI7JGPeHkYPUMDGjp7KqY0jo1EoPW4UmKggsH6nH8
```

An auditor deciding whether to trust a log reasons in calendar time;
see [Auditing and mirroring](../realm/audit.md).

## 12. A keyless mirror: `kuipa-mirror`

`kuipa-mirror` syncs the public endpoints of one server and serves them
read-only. The claim-log answer above came from the mirror, not ipa1:
a head-pinned client verifies the proof with no signature and no key on
the mirror. When the origin is unreachable past a vouch's expiry, the
mirror's head proofs stop verifying for new verifications — the
clients' own clocks decide, and the mirror cannot lie about it.

## 13. The trusted realm: `pq_trust`, `pq_trusted_kinit`, `pq_trusted`

web1 installs the realm its realm trusts, `B.TEST`, verified through
EXAMPLE.TEST's advertisement:

```
Realms EXAMPLE.TEST trusts, each verified through the servers it advertises and installed on this host:

                         realm: B.TEST
                what kuipa did: installed
              verified through: ipa1.b.test
           krb5.conf.d snippet: …/etc/krb5.conf.d/kuipa_trust_B_TEST
anchors, PKINIT anchors and CA: …/var/lib/ipa-client/ku/trusts/B.TEST
```

Then plain MIT Kerberos, on configuration kuipa installed: `kinit -n`
gets anonymous-PKINIT armour from B's KDC — the client accepts B's KDC
certificate only because the snippet points `pkinit_anchors` at the
chain kuipa installed from B's verified advertisement — and an armoured
`kinit` logs `alice@B.TEST` in. With her TGT, B's KDC issues the
cross-realm ticket, EXAMPLE.TEST's accepts it, and `kvno` returns a
ticket for web1:

```
host/web1.example.test@EXAMPLE.TEST: kvno = 5
```

The ticket and the configuration stay in `$KUIPA_ROOT/trusted-login`;
`pq_trusted CMD…` runs a command with them. `klist` there shows the
path: her TGT, the cross-realm ticket, and the service ticket from
EXAMPLE.TEST's KDC.

## 14. Post-quantum Tang: `tang-pqc`

ipa1 also serves post-quantum Tang: a secret encrypted with the
tang-pqc pin (`echo "a secret" | tang-pqc encrypt "$(pq_tang)"`) is
recovered with ipa1's help — `tang-pqc decrypt` prints `a secret`
back. The same escrow machinery as the keytab, on a public pin.

## 15. Replica promotion: `kuipa keys fetch`

web7 imitates a promoting replica: it fetches the material promotion
delivers — the DM password hash, the RA agent key, the CA subsystem
keys — through the keys operation, sealed under ML-KEM. The server
checks `cn=masters` first, so the sequence teaches who may ask:

```
$ kuipa keys fetch dm/DMHash
kuipa keys: ipa1.example.test refused the request
$ kuipa-playground masters --add web7.example.test
web7.example.test joined cn=masters (promotion)
$ kuipa keys fetch dm/DMHash --out …/promotion/dmhash && cat …/promotion/dmhash
{"dmhash":"{SSHA512}playground-dm-hash"}
```

An unknown nickname is refused; the wrapped CA keys need the CA role
(`kuipa-playground masters --ca`, standing in for `ipa-ca-install`)
before `pq_promote` fetches the whole set. A removed server
(`ipa-server-del`) is refused again.

## 16. Failure is reported: `kuipa check` with both servers down

```
    ipa1.example.test: server unreachable: error sending request for url (http://127.0.0.1:9/ipa/ku/adv?anchor=…&head=…)
    ipa2.example.test: server unreachable: error sending request for url (http://127.0.0.1:9/ipa/ku/adv?anchor=…&head=…)
```

With both servers unreachable the health check fails and says why: each
server's row names the request that failed, down to the anchors and
heads it asked for. `pq_up` restores them.
