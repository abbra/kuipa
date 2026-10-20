# A traced session in the playground

This session runs in the interactive playground (`contrib/ci/local-ci.sh
interactive`, see [Local CI and the playground](../development/local-ci.md)). Host `web1` enrolls in
`EXAMPLE.TEST`. It then installs the trusted realm `B.TEST`, a user of
`B.TEST` logs in on it, and that user gets a ticket for `web1` across the
trust. With tracing on, every request, answer, decision and file write
appears on standard error (see the design's
[tracing](../reference/design.md#104-tracing) section); the command's
result follows on standard output.

Thumbprints, ports, timings and paths differ in every playground.

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

## 3. Install the trusted realm: `pq_trust`

`pq_trust` runs [`kuipa trusted-realms`](../reference/design.md#173-kuipa-trusted-realms).

```
   0.003737495s TRACE endpoint server="ipa1.example.test" base=http://127.0.0.1:42923/ipa/ku/ tls="none"
   0.004667063s DEBUG GET http://127.0.0.1:42923/ipa/ku/adv?anchor=pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ&anchor=WdR5rAyr1-fDWTwzIRofwxAsBo_PtvKCw0aOVufgkOk (0 bytes) server=ipa1.example.test
   0.010315741s DEBUG 200 OK: 24535 bytes in 5 ms server=ipa1.example.test
   0.017710863s DEBUG advertisement verified: ipa1.example.test of EXAMPLE.TEST, signed by 0hznLdS2gMlbsHVPD5MjxvyQqox9Sw6wAp8a8mNgLbg, delegation by anchor pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ (claim: 89 days left, vouch: 7 days left) server=ipa1.example.test
   0.017780233s TRACE advertisement contents server=ipa1.example.test domain=example.test servers=["ipa1.example.test", "ipa2.example.test"] join_key=4zRtyVcF9IQNUKBEAcIzyjFTHc9O584n-0PydLfSS-0 escrow_key=KkVcqIPOzuFGEZKNRHQyV0hnHFi8bVWS1UBm2tL6kgc ca_certs=1 pkinit_anchors=1 anchors=["pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ", "WdR5rAyr1-fDWTwzIRofwxAsBo_PtvKCw0aOVufgkOk"] trusts=["B.TEST"]
   0.018293728s DEBUG EXAMPLE.TEST lists trusted realms ["B.TEST"]; installed here: []
```

The host is enrolled now, so this time:

* **Anchors:** it pins both stored anchors and names both in `?anchor=`.
  The server returns the proof of the first one that vouches for its
  claim.
* **TLS:** on a real host, TLS is verified against the installed IPA CA.
* **The list:** its own realm's verified advertisement is the authority.
  It lists `B.TEST`, and nothing is installed yet.

```
   0.018382676s TRACE endpoint server="ipa1.b.test" base=http://127.0.0.1:34839/ipa/ku/ tls="none"
   0.018922290s DEBUG GET http://127.0.0.1:34839/ipa/ku/adv?anchor=LkmLRj-3-YW4cWTvKRoQuM4DDw9U3tfzU7VU5ZMtfu8 (0 bytes) server=ipa1.b.test
   0.027127104s DEBUG 200 OK: 24139 bytes in 8 ms server=ipa1.b.test
   0.033559656s DEBUG advertisement verified: ipa1.b.test of B.TEST, signed by fLz6i5i9mSUtHn6F6wv35Dolqq9BT8Bh5xa1TxPn2MQ, delegation by anchor LkmLRj-3-YW4cWTvKRoQuM4DDw9U3tfzU7VU5ZMtfu8 (claim: 89 days left, vouch: 6 days left) server=ipa1.b.test
   0.033605412s TRACE advertisement contents server=ipa1.b.test domain=b.test servers=["ipa1.b.test"] join_key=FdC8v6oADZUlVaf_8pkSVgZFeRzUfIyF30ZnBwQSwmc escrow_key=qTGI8evWNJnd1E10pcBrgpVrj-3EDQaPTuiZSdW37is ca_certs=1 pkinit_anchors=1 anchors=["LkmLRj-3-YW4cWTvKRoQuM4DDw9U3tfzU7VU5ZMtfu8"] trusts=[]
```

* **Where B is fetched from:** the server listed in EXAMPLE.TEST's `trusts`
  entry for B, `ipa1.b.test`.
* **Which anchor it pins:** `LkmL…`, the anchor EXAMPLE.TEST vouches for.
  That anchor verifies objects of realm `B.TEST` only, and B's advertisement
  must claim that realm. B's anchors never join the host's own list, and a
  trust entry sharing an anchor with the host's realm is refused ([Domain separation](../reference/design.md#171-domain-separation)).
* **TLS to B:** it accepts any certificate, as on first contact; the
  advertisement authenticates B.
* **What B provides:** its domain, KDCs, CA and PKINIT chain. B's own
  `trusts` is empty, because the playground's trust is listed on the
  EXAMPLE.TEST side only.

```
   0.034000625s DEBUG installing B.TEST: 1 PKINIT anchor(s), 1 CA certificate(s), KDCs ["ipa1.b.test"]
   0.034233152s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/trusts/B.TEST/pkinit-anchors.pem (566 bytes, mode 644)
   0.034293976s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/trusts/B.TEST/ca.crt (566 bytes, mode 644)
   0.034373505s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/etc/krb5.conf.d/kuipa_trust_B_TEST (492 bytes, mode 644)
   0.034417077s DEBUG wrote /tmp/kuipa-playground-222664/hosts/web1/etc/ipa/ku-anchors.d/B.TEST (122 bytes, mode 644)
```

B's files, for B only:

* **The PKINIT chain and the CA.**
* **A `krb5.conf.d` snippet** with B's `[realms]` and `[domain_realm]`
  sections and no `[libdefaults]`. Its `pkinit_anchors` therefore apply to
  B's KDCs and nothing else. The file name has no dots because MIT's
  `includedir` skips such names.
* **B's anchors, written last.** Their presence marks B as installed, so an
  interrupted run never leaves a half-installed realm that looks complete.

If B cannot be reached or verified on a later run, the host keeps these
files and the command exits 75. If EXAMPLE.TEST stops listing B, the next
run removes them.

```
Realms EXAMPLE.TEST trusts, each verified through the servers it advertises and installed on this host:

realm: B.TEST
what kuipa did: installed
verified through: ipa1.b.test
krb5.conf.d snippet: /tmp/kuipa-playground-222664/hosts/web1/etc/krb5.conf.d/kuipa_trust_B_TEST
anchors, PKINIT anchors and CA: /tmp/kuipa-playground-222664/hosts/web1/var/lib/ipa-client/ku/trusts/B.TEST
```

## 4. Log in a user of the trusted realm: `pq_trusted_kinit alice`

```
[kuipa web1] kuipa $ pq_trusted_kinit alice
anonymous PKINIT armour from B.TEST's KDC, with the PKINIT chain kuipa installed
alice@B.TEST logged in through the armoured exchange; try: pq_trusted kvno host/web1.example.test
```

This step is plain MIT Kerberos; kuipa is not involved, so there are no kuipa
traces (use `KRB5_TRACE=/dev/stderr` to see the Kerberos side):

1. The bare name `alice` is taken as `alice@B.TEST`.
2. `kinit -n @B.TEST` gets anonymous-PKINIT armour from B's KDC. The
   configuration is the host's plus the installed snippet, with B's KDC
   pointed at its Unix socket. The client accepts B's KDC certificate only
   because the snippet points `pkinit_anchors` at the chain kuipa installed
   from B's verified advertisement. Without that chain, or with
   EXAMPLE.TEST's chain instead, there is no armour (the trust test checks
   both).
3. `kinit -T <armour> alice@B.TEST` runs the password exchange inside that
   FAST channel.

The ticket and the configuration stay in `$KUIPA_ROOT/trusted-login`;
`pq_trusted CMD…` runs a command with them.

## 5. Use the trust: `pq_trusted kvno host/web1.example.test`

```
[kuipa web1] kuipa $ pq_trusted kvno host/web1.example.test
host/web1.example.test@EXAMPLE.TEST: kvno = 2
```

alice, a user of `B.TEST`, gets a ticket for the host that just enrolled
in `EXAMPLE.TEST`:

1. With her TGT, B's KDC issues the cross-realm ticket
   `krbtgt/EXAMPLE.TEST@B.TEST`.
2. EXAMPLE.TEST's KDC accepts it and issues `host/web1.example.test`.

kvno 2 is the key from step 2, now in web1's keytab. The playground
created the cross-realm keys in both KDCs from a random shared secret,
standing in for FreeIPA's `trust-add --trust_secret`; establishing the
trust through kuipa is designed in [Establishing the trust](../reference/design.md#174-establishing-the-trust).

## 6. Two credential caches

```
[kuipa web1] kuipa $ klist
klist: No credentials cache found (filename: /tmp/kuipa-playground-222664/admin.ccache)
[kuipa web1] kuipa $ pq_trusted klist
Ticket cache: FILE:/tmp/kuipa-playground-222664/hosts/web1/trusted-login/user.ccache
Default principal: alice@B.TEST

Valid starting       Expires              Service principal
18.10.2026 20.35.04  18.10.2026 21.35.04  krbtgt/B.TEST@B.TEST
18.10.2026 20.35.04  18.10.2026 21.35.04  krbtgt/EXAMPLE.TEST@B.TEST
18.10.2026 20.35.04  18.10.2026 21.35.04  host/web1.example.test@EXAMPLE.TEST
```

* **The shell's own cache:** `KRB5CCNAME` points at the playground
  administrator's cache. It stays empty until a helper such as
  `pq_bootstrap` or `pq_offline` obtains an admin ticket.
* **alice's cache:** `pq_trusted klist` lists it, showing the path of
  step 5:
  * **`krbtgt/B.TEST@B.TEST`:** her TGT from the armoured login.
  * **`krbtgt/EXAMPLE.TEST@B.TEST`:** the cross-realm ticket.
  * **`host/web1.example.test@EXAMPLE.TEST`:** the service ticket from
    EXAMPLE.TEST's KDC.
