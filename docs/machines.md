# kuipa on cloud virtual machines

Cloud machines come and go, are cloned from images, snapshotted, and run
where the people responsible for them cannot touch the hardware. This guide
walks through what kuipa does for them, use case by use case: joining a
realm from an image or an autoscaler, keeping keytabs and secrets useless
in snapshots, unlocking data volumes, and cleaning up when an instance
goes away.

Each use case says how far along it is:

* **available**: implemented and tested in this repository;
* **needs FreeIPA**: implemented here, but the administrator's side waits
  for the FreeIPA integration (schema, framework commands; see
  [TODO.md](../TODO.md));
* **planned**: designed in [DESIGN.md](DESIGN.md), not implemented yet.

Throughout, the realm is `EXAMPLE.TEST` with servers `ipa1` and `ipa2`, and
the instances live in a cloud network that can reach them over HTTPS.

## Before you start: what the network must allow

kuipa talks to the IPA servers over HTTPS (`/ipa/ku/…`), at enrollment, at
every key rotation and, for protected keytabs and files, **at every boot**.
So:

* allow outbound HTTPS from instances to every IPA server, and Kerberos
  (88) as for any IPA client;
* put a replica in each region or zone that runs instances, so that booting
  does not depend on a WAN link: `kuipa-unseal` tries every server in turn
  and, when none answers, exits 75 and systemd retries every 30 seconds;
  the instance boots meanwhile, without its Kerberos identity.

## Use cases

### Bake the realm's trust into an image

**available**

Every enrollment starts by verifying the realm against an anchor the host
already trusts. For images, pin the realm's anchors in the image instead of
handing each instance an enrollment string:

```
# /etc/ipa/ku-anchors in the image: one anchor per line, with an expiry
pjLVUZeo5CYHWwNIxNTa1uAyFIRS9Z6NVW7X2h_qgOQ 1798761600
Qx3l…                                       1798761600
```

* Instances then enroll with `--realm EXAMPLE.TEST` and a voucher, a
  password or a ticket, and verify the servers against these pins.
* With two anchors pinned, an instance demands that both vouch for a
  server, so a single stolen anchor cannot impersonate the realm to it.
* Give the pins an expiry. An image outlives the anchors it was built
  with; when the anchor rotates, an expired pin makes an old image refuse
  to enroll instead of trusting a retired key. Rebuild images before the
  pins expire.

### Join instances from an autoscaler with vouchers

**available** (the host and voucher tools); **needs FreeIPA** for adding
the voucher key to a production realm

An autoscaling group needs each new instance to join the realm without an
administrator. A **voucher** is a single-use, signed permission for one
hostname to join, optionally into a host group. Two roles keep each other
honest:

* the **issuer** (for example the security team) holds a voucher key and a
  quota: how many vouchers it will ever sign;
* the **provisioner** (the autoscaler) decides which instances join, and
  asks the issuer to sign. Signing is *blind*: the issuer never sees which
  hostname or group a voucher is for, only that it spent one of its quota.

```sh
# issuer, once
kuipa-voucher keygen --key voucher.key            # give the public JWK to the IPA admins
kuipa-voucher quota --quota quota.json --limit 500

# provisioner, per instance
kuipa-voucher request --public "$JWK" --realm EXAMPLE.TEST \
    --fqdn web-17.example.test --hostgroup webservers --days 1 --state web-17.state > req
#   … the issuer runs:  kuipa-voucher sign --key voucher.key --quota quota.json < req > rsp
kuipa-voucher finish --state web-17.state < rsp > web-17.voucher

# the instance, from cloud-init
kuipa enroll --realm EXAMPLE.TEST --voucher-file /run/web-17.voucher \
             --hostname web-17.example.test
```

What this buys you:

* a compromised autoscaler can join at most the issuer's remaining quota of
  hosts, and every voucher names one hostname and expires (`--days`);
* a voucher creates its host once: it cannot be replayed, and it cannot
  take over a host that already exists;
* the issuer's records reveal nothing about your fleet's names.

**User-data is readable.** Anyone allowed to read the instance's metadata
can read a voucher placed in user-data, and an unbound voucher works for
whoever uses it first. Two ways to close that:

* **bind the voucher to the instance**: the instance runs
  `kuipa voucher-key --out /run/kuipa-ephemeral.jwk` first and reports the
  printed binding to the provisioner, which passes it as `--binding`; the
  voucher then works only with that instance's ephemeral key
  (`kuipa enroll … --ephemeral-key /run/kuipa-ephemeral.jwk`);
* or keep unbound vouchers short-lived (`--days 1`, or less) and delete them
  from user-data after the join.

A **replacement instance with the same hostname** cannot join with a new
voucher while the old host entry exists: delete the old entry first
(`ipa host-del`), typically from the termination hook below.

### Pre-stage instances that boot without network access to IPA

**available** on the host; **needs FreeIPA** for staging (`ipa host-add
--pq-stage`)

Some instances can't reach the IPA servers when they first boot (a private
subnet brought up later, an air-gapped build), or you want the join to be
decided entirely ahead of time. An administrator **stages** the host: the
server creates its keys and packs everything into a signed **bundle**,
which the instance opens offline:

```sh
kuipa enroll --bundle /run/web-17.bundle --enrollment-file /run/web-17.string \
             --hostname web-17.example.test
```

The bundle is sealed so that it is safe to put in user-data or an image:

* **mode B (for clouds)**: the bundle opens with a secret that travels
  separately, in the enrollment string. Put the bundle in user-data and the
  string in your cloud's secret manager: someone who sees only one of the
  two learns nothing;
* **mode A**: the instance first makes a key (`kuipa prepare`) and reports
  it; the bundle is sealed to that key and safe on any channel. Suits
  instances that can report a key before they need to join.

The staged keys expire at a time the administrator chose, enforced by the
KDC whatever the instance's clock says. When the instance first reaches a
server, `ipa-client-complete.service` replaces the staged keys with fresh
ones (`kuipa complete`) and retries until it can.

### Keep the host keytab useless in snapshots and images

**available**

A snapshot or an image of a running instance contains its host keytab:
whoever restores it elsewhere has the host's identity. `kuipa protect`
seals the keytab so a copy needs the realm's servers to open:

```sh
kuipa protect
systemctl enable kuipa-unseal.service kuipa-rotate.timer
```

* `/etc/krb5.keytab` becomes a link to `/run/ipa/krb5.keytab` (memory
  only), filled at every boot by `kuipa-unseal` through any IPA server.
* `kuipa-rotate.timer` rotates the host keys monthly and reseals. **A
  snapshot from before the last rotation no longer opens**, even inside
  your network: its sealed copy's bindings are retired.
* Deleting the host (`ipa host-del`) stops every copy from opening at
  once. `ipa host-disable` removes the host's keys, so an unsealed copy
  holds only dead keys.

**Know the limit in a cloud.** Sealing protects against a snapshot taken
*out of* reach of your IPA servers: an exported image, a leaked backup, a
disk in another account. Someone who can restore a recent snapshot as a new
instance *inside* your network, while the host is still enabled, gets the
host's identity, just as the original instance would. Rotation narrows the
window to a month at most; disabling hosts on termination closes it for
deleted instances. Binding the keytab to the instance's virtual TPM closes
it fully and is planned (below).

### Protect service keytabs on the instance

**available**

Web servers, NFS servers and other services have keytabs of their own,
just as exposed in a snapshot. Seal each one for its own principal:

```sh
kuipa protect --keytab /etc/httpd/http.keytab
```

* The keytab becomes a link to a memory-only copy, refilled at boot by the
  same `kuipa-unseal.service`; mode and owner are kept, so the service reads
  it as before.
* Order the service after unsealing, with a drop-in:

  ```ini
  # /etc/systemd/system/httpd.service.d/kuipa.conf
  [Unit]
  After=kuipa-unseal.service
  Wants=kuipa-unseal.service
  ```

* kuipa does not rotate a service's keys (other instances may share them).
  Rotate them with `ipa-getkeytab -k /etc/httpd/http.keytab` and run
  `kuipa protect --keytab /etc/httpd/http.keytab` again to reseal; the old
  sealed copy stops opening.

**gssproxy**: services that go through gssproxy (NFS, `mod_auth_gssapi`)
can get their keytab straight into gssproxy's memory, never on any
filesystem, once gssproxy's `keytab_loader` lands
([gssapi/gssproxy#135](https://github.com/gssapi/gssproxy/pull/135),
**planned** until then):

```ini
[service/nfs-server]
  mechs = krb5
  cred_store = keytab:MEMORY:nfs-server
  keytab_loader = /usr/libexec/kuipa-unseal --sealed /etc/nfs.keytab.sealed --memfd
  cred_usage = accept
```

### Deliver application secrets with the instance

**available**

Database passwords, API tokens and TLS private keys deployed with an
instance end up in its snapshots too. Seal them for the host:

```sh
kuipa protect --file /etc/app/db.conf
kuipa protect --file /etc/pki/tls/private/app.key --keytab /etc/httpd/http.keytab
```

* The first is sealed for the host principal; the second for the web
  service's principal, so deleting either principal stops it opening.
  Disabling (`ipa host-disable`, `ipa service-disable`) removes keys but
  does not stop sealed files opening yet: use `host-del`, or see the note
  under termination below.
* Changed the secret? Write the new contents through the link and run
  `kuipa protect --file …` again: the old sealed copy is retired.
* A one-off read, for a script: `kuipa-unseal --sealed /etc/app/db.conf.sealed
  --out - | app-migrate --config /dev/stdin`.

How this compares with a cloud secret manager: it works the same on every
cloud and on premises, uses post-quantum cryptography end to end, needs no
cloud IAM role on the instance, and is revoked by disabling the host or
service in IPA. It does not replace a secret manager for secrets that many
machines share; it protects what one machine holds.

### Encrypt data volumes that unlock only inside your network

**available**

Attach an encrypted data volume and have it unlock automatically, but only
where the IPA servers answer. kuipad doubles as a post-quantum Tang server,
and the `tang-pqc` Clevis pin binds LUKS volumes to it:

```sh
tang-pqc adv https://ipa1.example.test/ipa/ku/tang     # note a signing-key thumbprint
clevis luks bind -d /dev/nvme1n1 sss '{"t":1,"pins":{"tang-pqc":[
    {"url":"https://ipa1.example.test/ipa/ku/tang","thp":"<thp1>"},
    {"url":"https://ipa2.example.test/ipa/ku/tang","thp":"<thp2>"}]}}'
```

* With `t: 1`, either server unlocks it; the volume unlocks at boot from
  the initramfs (install the pin's dracut module with
  `contrib/clevis/install.sh`) or with `clevis luks unlock`.
* A volume detached and attached in another account, or a disk snapshot
  copied out, does not unlock.
* Tang is stateless by design: anyone holding the volume and network access
  to a Tang server can unlock it. Use it for volumes that should unlock
  anywhere in your network, and the keytab-style protection above for
  identities.

### Clean up when an instance is terminated

**available** in IPA today

Add a termination hook (an autoscaling lifecycle hook, a cloud function on
the instance-terminated event) that removes the host from IPA:

```sh
ipa host-del web-17.example.test --updatedns
```

* Its keys stop working at once, and every sealed keytab and file of that
  host stops opening, including in snapshots and images.
* The hostname is free for a replacement to join with a new voucher.
* If you'd rather keep the entry for audit, `ipa host-disable` removes its
  keys, so sealed keytabs open to dead keys, and it blocks a voucher join
  under the same name. Sealed *files* of a disabled host still open today:
  kuipad checks the entry's `nsAccountLock`, which `host-disable` does not
  set. Until that is fixed, delete the host to retire its files.

### Bind identities to the instance's virtual TPM

**planned**

Clouds offer a virtual TPM per instance (shielded or trusted-launch VMs,
NitroTPM). With the planned TPM factor, a sealed keytab or file opens only
with both an IPA server and *this instance's* vTPM. A snapshot restored as
a new instance, even inside your network, gets a different vTPM and cannot
open it. This closes the gap described under snapshots above.

### Your own secrets on a cloud development VM

**planned** (`kuipa seal`, see [sealing.md](sealing.md))

Users of a shared development or bastion VM can seal their own files with
`kuipa seal`, without root. On a cloud VM:

* there is no USB, so a passkey on your desk cannot reach the VM; use a
  vault that requires your **ticket** (forward it over SSH with GSSAPI
  delegation, `ssh -K`) together with a **device** key file on the VM;
* a VM snapshot then holds only sealed files and a passphrase-protected key
  file; neither opens without you;
* a re-authentication session saves you from typing the passphrase for
  every file during a working day.

## Summary

| you want to | use | status |
|---|---|---|
| ship the realm's trust in an image | pinned anchors in `/etc/ipa/ku-anchors` | available |
| join instances from an autoscaler | vouchers, bound to the instance where possible | available; voucher keys need FreeIPA |
| join without network access at first boot | staged bundles (mode B for clouds) | needs FreeIPA |
| keep the host identity out of snapshots | `kuipa protect`, monthly rotation | available |
| protect service keytabs | `kuipa protect --keytab` | available |
| keep service keytabs off every filesystem | gssproxy `keytab_loader` | planned (upstream PR) |
| deliver application secrets | `kuipa protect --file` | available |
| encrypt data volumes | Clevis `tang-pqc` pin against kuipad | available |
| invalidate a terminated instance | `ipa host-del` in a termination hook | available |
| defeat snapshot restores inside the network | vTPM factor | planned |
| let users seal their own files | `kuipa seal` | planned |
