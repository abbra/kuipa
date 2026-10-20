# Letting hosts join

How a host proves it may join decides what an administrator hands it. This
chapter covers each way, from the realm's side; the host's side is in
[Enrolling a host](../host/enroll.md).

| the host has | the administrator provides | the realm checks |
|---|---|---|
| an enrollment string with an OTP | `ipa host-add --random`, then `kuipad enrollment-string` | the OTP, as FreeIPA does today |
| a user's password | nothing: the user has one | the user's right to join hosts (FreeIPA's access controls) |
| a Kerberos ticket | nothing | the same, for the ticket's principal |
| a voucher | a voucher key, and an issuer with a quota | the voucher's signature, hostname and expiry; it is single use |
| a staged bundle | a staging step before the host exists | the bundle's signature and expiry, then a first contact |

## Enrollment strings

An enrollment string tells a host which anchor to trust, until when, and
(for an OTP join) its one-time password:

```sh
ipa host-add web1.example.test --random        # prints the OTP
kuipad enrollment-string --days 1              # ipa-ku1:EXAMPLE.TEST:<anchor>:<expiry>
```

Append `:<OTP>` and hand the string to whoever enrolls `web1`, through a
channel you trust: it is what the host authenticates the realm with.

* **Keep strings short-lived.** `--days 1` is plenty for interactive
  installs; the most is 400. The expiry is what makes an old string (left
  in a wiki or a kickstart file) useless after you rotate or lose an
  anchor.
* **The OTP should also be the host's temporary Kerberos key**, so the
  host authenticates the join with Kerberos and the realm's answer is bound
  to the realm's keys. Making `ipa host-add --random` set that key is part
  of the pending FreeIPA integration (the playground does it). Until then,
  enroll with `kuipa enroll --ldap-otp`, which checks the OTP with an LDAP
  bind: it works on a stock server, but only the anchor authenticates the
  server, and the server learns the OTP.

## Pinned anchors for images

For hosts built from images or by configuration management, pin the realm
instead of shipping strings:

```text
# /etc/ipa/ku-anchors: thumbprint and expiry (Unix seconds), one per line
pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ 1798761600
Qx3l…                                       1798761600
```

Hosts then enroll with `--realm EXAMPLE.TEST` and a password, a ticket or
a voucher. Pin **two** anchors from different servers: a host that knows
two demands that both vouch for a server, so one stolen anchor cannot
impersonate the realm to it. In a realm with a single anchor server, pin
exactly one.

## Vouchers

Vouchers let something else (an autoscaler, an image pipeline) decide
which hosts join, without being able to join more than you allowed:

```sh
# The issuer, once: a key and a quota.
kuipa-voucher keygen --key voucher.key > voucher.pub.jwk
kuipa-voucher quota --quota quota.json --limit 500

# Each IPA server accepts vouchers under that key.
kuipad add-voucher-key --file voucher.pub.jwk
systemctl restart kuipad
```

The provisioner then requests a voucher per host, blinded so the issuer
never sees which, and the host enrolls with it. A voucher creates one host,
once, in the host group it names, and refuses a hostname that already
exists. The full workflow, including binding vouchers to the instance, is
in [Cloud virtual machines](../scenarios/cloud.md#join-instances-from-an-autoscaler-with-vouchers).

To stop accepting a voucher key, delete its `voucher-<thp>.jwk` file from
`/var/lib/ipa/ku` and restart `kuipad`.

## Staged hosts and bundles

An administrator can stage a host before it ever reaches the network: the
server creates its keys and packs them into a signed, sealed **bundle**.
The host opens the bundle offline and finishes at first contact.

* **mode A**: sealed to a key the host made (`kuipa prepare` prints it);
* **mode B**: sealed under a secret carried in the enrollment string,
  so the bundle and the string can travel separately;
* **mode C**: signed only, for labs.

The staged keys expire at the time you choose, enforced by the KDC. The
`ipa host-add --pq-stage` command that stages a host is part of the
pending FreeIPA integration; the playground's `pq_offline` helper stages
with an administrator's ticket the way it will.
