# What kuipa protects

This chapter is for anyone deciding whether, and where, to rely on kuipa.
It states what each attacker gets, in plain words. The full analysis, with
its assumptions, is in the design's security analysis (§13) and the
tables of §7.3, §7.5 and §7.6.10.

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

## What still uses classical cryptography

kuipa does not replace these. They may use classical cryptography and
might be attacked by a cryptographically relevant quantum computer (CRQC):

* TLS server authentication (the IPA CA is RSA; kuipa reaches it
  authentically, but TLS itself is not post-quantum);
* PKINIT and the anonymous PKINIT armour used for password and OTP
  `kinit`;
* DNSSEC;
* Custodia.

Password and OTP logins through an armoured `kinit` can be guessed offline
once a CRQC breaks the classical key exchange of that armour, as for any
FreeIPA `kinit`. Random one-time passwords are not guessable that way.

## Clocks

Advertisements and delegations expire, so hosts need a roughly correct
clock to enroll online. Offline bundles are checked at the time they were
issued, and the KDC enforces their expiry whatever the host's clock says.
