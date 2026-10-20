# Day-to-day host care

## Is the host healthy?

```sh
kuipa status         # what the host knows, from its files: no network
kuipa check          # every server, the delegations, a kinit with the keys
kuipa check --server ipa2.example.test
```

`status` shows the realm, the host principal and its key version, the
servers, the pinned anchors, installed trusted realms, how the keytab is
held, other protected keytabs and files, and which ML-KEM variants the
system crypto policy allows.

`check` contacts each server and reports problems with the action that
fixes each one:

* a delegation expiring within 14 days, or an anchor's vouch within 48
  hours (the servers renew them; if they do not, their anchor exchange is
  stuck);
* a server verified only through a rotated anchor: run `kuipa
  rotate-keys` to refresh the pins;
* no ticket with the host keys: rotate or re-enroll;
* a sealed keytab or file no server would open.

It exits 1 when it finds a problem, so it fits monitoring.

## Rotating keys

```sh
systemctl enable --now kuipa-rotate.timer        # monthly
kuipa rotate-keys                                # now
```

Rotation gets new keys over the protected exchange, authenticated by the
current ones, keeps the previous key version so existing tickets stay
valid, refreshes the pinned anchors and the server list, and reseals the
keytab if it is protected.

## Trusted realms

```sh
kuipa trusted-realms
```

installs the realms the host's realm trusts: their anchors
(`/etc/ipa/ku-anchors.d/<REALM>`), PKINIT anchors and CA
(`/var/lib/ipa-client/ku/trusts/<REALM>/`) and a Kerberos snippet
(`/etc/krb5.conf.d/kuipa_trust_<REALM>`), each verified through the host's
own realm. It removes realms no longer trusted. A realm it cannot reach
keeps its last verified files, and the command exits 75. Run it after
enrollment and periodically.

## Leaving the realm

```sh
kuipa leave
```

removes what kuipa installed besides the keytab: anchors, generated
Kerberos files, trusted realms, the machine key, the state. A sealed
keytab, and every other protected keytab and file, is first written back
in plain form, so `ipa-join --unenroll` (or `ipa-client-install
--uninstall`) can finish the job.

## Trying things without touching the system

Every path `kuipa` uses hangs off `$KUIPA_ROOT` (default `/`):

```sh
KUIPA_ROOT=/tmp/h kuipa prepare --hostname web1.example.test
```
