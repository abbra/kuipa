# What kuipa protects

This chapter is for anyone deciding whether, and where, to rely on kuipa.
It states what each attacker gets, in plain words. The full analysis, with
its assumptions, is in the design's
[security analysis](reference/design.md#13-security-analysis), and in its
tables for [a sealed host keytab](reference/design.md#73-file-mode-implemented),
[other sealed keytabs and files](reference/design.md#75-other-keytabs-and-any-file-implemented)
and [users' vaults](reference/design.md#7610-what-each-attacker-gets).

Assumptions throughout: ML-KEM and ML-DSA are as strong as their standards
claim, including against quantum computers, and the enrollment string (or
the pinned anchors) reaches the host through a channel you trust.

## Traffic

| attacker | gets |
|---|---|
| records every enrollment and rotation now, has a quantum computer later | nothing: keytabs, OTPs and passwords travel under ML-KEM |
| controls the network during enrollment (classical or quantum) | can stop it, cannot impersonate the realm: a server must show a delegation from an anchor the host pins |
| replays a recorded request | nothing: one-time passwords are spent, tickets are bound to the exchange, answers go to a key only the host has |
| guesses an OTP or password | one guess per request online, limited per host and per address, and by IPA's lockout |

`kuipa` never falls back to classical enrollment: if the post-quantum path
is blocked, enrollment fails.

## A server's keys

| attacker | gets |
|---|---|
| a server's signing key | can impersonate that server to new hosts until its delegation lapses (90 days by default, at most 400) |
| one server's anchor | can vouch for impostor servers, but cannot answer Kerberos-bound requests: hosts that rotate, OTP, password and ticket joins stay safe. Exposed until rotation: vouchers, bundles and `--ldap-otp` joins pinning only that anchor. Hosts that pin two anchors refuse the impostor. Rotate the anchor (`kuipad rotate-anchor`) |
| a server's `ipa-ku/<server>` Kerberos key | can get an anchor of its choice trusted, but that key is as sensitive as the realm's other Kerberos keys |

## Copies of disks, snapshots and backups

| attacker has | plain keytab or file | sealed |
|---|---|---|
| a copy, no access to the realm's servers | everything | nothing |
| a copy, network access, host still enabled | everything | everything: the servers answer the host's copy |
| the same, after the host is deleted (or its entry locked) | everything (until keys are rotated) | nothing |
| a copy from before the last key rotation or reseal | that version | nothing |
| root on the running host | everything | everything |

Sealing protects copies taken *out of* reach of your servers. A recent
snapshot restored *inside* your network still opens while the host is
enabled. Delete hosts you retire, and rotate keys on the timer. Binding
keytabs to the machine's TPM, which closes the gap, is planned.

`ipa host-disable` today removes keys but does not lock the entry, so
sealed *files* of a disabled host still open. Delete the host, or lock it,
to retire them.

## Users' vaults

| attacker has | file sealed with a device | ticket only |
|---|---|---|
| a copy of the sealed file, network access | nothing | nothing |
| the copy and the user's device key file, without its passphrase or token PIN | nothing | — |
| the copy and the user's password | nothing | **the file**: require a device too |
| the realm's servers and their keys (an IPA administrator) | nothing: the device share is missing | the file |
| anything, after the vault, the device or the user is revoked or disabled | nothing new | nothing new |
| a released offline-session key | that epoch's session files, for as long as it keeps the key | — |
| root on the user's machine while a file is open or a session is unlocked | the open files and the session's keys | the same |

## Algorithms and the crypto policy

kuipa has no algorithm setting of its own: the system crypto policy
(`update-crypto-policies`) decides. It decides which ML-KEM and ML-DSA
parameter sets servers make and hosts accept, and from those follows
every hash a signature covers:

| policy | signing keys | KEM | trees, logs, indexes, signing batches | digests `kuipa sign` makes |
|---|---|---|---|---|
| `DEFAULT`, or any policy that allows ML-DSA-65 | ML-DSA-65 (ML-DSA-44 accepted from witnesses) | ML-KEM-768 | SHA-256 | SHA-256 |
| a CNSA 2.0 policy | ML-DSA-87 only | ML-KEM-1024 | SHA-384 | SHA-384 |

Under CNSA 2.0 nothing that a signature covers rests on SHA-256, SHA-3
or SHAKE, which CNSA does not approve as general-purpose hashes. The
exceptions are where a standard prescribes its own hash, as ML-DSA and
ML-KEM do internally. A server refuses a SHA-256 digest to sign, and
hosts refuse a head, receipt or statement whose hashes do not match the
category of the key that signed it.

**Changing the policy** on a server moves it to new keys of the new
category. A server's transparency log is tied to its hash, so the
server starts a new log with a new id. The old log stays in
`/var/lib/ipa/ku/tlog/` and keeps verifying under the old key. Witnesses
and `kuipa tlog watch` see a new log, not a rewritten one.

The rest follows the same way. What belongs to an ML-KEM exchange is
hashed with that KEM's hash: a sealed file's bindings and keys, machine
vault ids, the voucher binding. That is SHA-256 for ML-KEM-768, so files
sealed under the default policy still open, and SHA-384 for ML-KEM-1024.
What no key decides is SHA-384 under every policy: the anchor epoch
chain, trust invitations, and the binding that authenticates anchor
exchanges.

Key thumbprints stay SHA-256 under every policy. They are RFC 7638's
names for keys, as Clevis computes them, and every pin and enrollment
string uses them.

## What still uses classical cryptography

kuipa protects what travels and rests between hosts and the realm's
servers. It does not replace the cryptography of FreeIPA's own components.
These may still use classical cryptography and might be attacked by a
cryptographically relevant quantum computer (CRQC):

* **The IPA CA and TLS.** The IPA CA issues classical (RSA) certificates,
  so TLS server authentication to IPA servers is classical. kuipa does not
  depend on it to authenticate the realm: a host verifies the servers
  through its anchors and reaches the CA's certificate authentically.
  But other clients of IPA's TLS services do depend on it.
* **Kerberos PKINIT.** PKINIT, and the anonymous PKINIT armour that
  protects password and OTP `kinit`, use classical key exchange and
  certificates. Password and OTP logins through such an armoured `kinit`
  can be guessed offline once a CRQC breaks the armour's key exchange, as
  for any FreeIPA `kinit`. Random one-time passwords are not guessable
  that way.
* **Custodia**, which FreeIPA uses to move CA and other secrets between
  replicas.
* **DNSSEC**, which belongs to the DNS infrastructure rather than to
  FreeIPA or kuipa.

Moving FreeIPA's components (the CA, Kerberos PKINIT, Custodia) to
post-quantum cryptography is a separate effort, in progress alongside
kuipa. As each component moves, this list shrinks; kuipa's protections do
not depend on it.

## Clocks

Advertisements and delegations expire, so hosts need a roughly correct
clock to enroll online. Offline bundles are checked at the time they were
issued, and the KDC enforces their expiry whatever the host's clock says.
