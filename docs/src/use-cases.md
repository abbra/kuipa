# What kuipa is for

kuipa protects the secrets a FreeIPA realm hands out: host keys, service
keys, users' files. It also records what the realm does with them, so
people can check. Everything is post-quantum. A recording of today's
traffic, or a copy of today's disk, stays useless to a quantum computer
later.

This page lists every use case kuipa targets, grouped by who it is for.
Each one has a short "why", a status, and a link to the chapter that
shows how.

| status | meaning |
|---|---|
| **works** | built and tested; kuipa as a whole is still a research prototype |
| **partly** | the main path works; the chapter says what is missing |
| **planned** | designed or proposed, not built yet |
| **research** | needs cryptography that is still being worked out |

"Works" means kuipa does it, tested against a real Kerberos KDC. It
does not mean a FreeIPA release does it yet. kuipa has not run against
a real FreeIPA server, and the FreeIPA side (its LDAP schema, access
controls, `ipa` commands and installer options) is still to be written.
The open work, use case by use case, is in `TODO.md` at the top of the
source tree.

## At a glance

| use case | for | status |
|---|---|---|
| [Join hosts to the realm safely](#join-hosts-to-the-realm-safely) | realm admins | works |
| [Join cloud instances from images and autoscalers](#join-cloud-instances-from-images-and-autoscalers) | cloud operators | works |
| [Prepare hosts that join without a network](#prepare-hosts-that-join-without-a-network) | realm admins | works |
| [Rotate host keys automatically](#rotate-host-keys-automatically) | host admins | works |
| [Keep keytabs useless in backups and snapshots](#keep-keytabs-useless-in-backups-and-snapshots) | host admins | works |
| [Seal any file to a host](#seal-any-file-to-a-host) | host admins | works |
| [Unlock encrypted disks with a post-quantum Tang](#unlock-encrypted-disks-with-a-post-quantum-tang) | host admins | works, not yet tested with real Clevis and LUKS |
| [Deliver CA bundles without trusting DNS or TLS](#deliver-ca-bundles-without-trusting-dns-or-tls) | realm admins, host admins | partly |
| [Give CI runners short-lived identities](#give-ci-runners-short-lived-identities) | platform teams | works |
| [Accept users of a trusted realm](#accept-users-of-a-trusted-realm) | realm admins | works |
| [Move secrets between IPA replicas](#move-secrets-between-ipa-replicas) | realm admins | works |
| [Check what the realm vouched for](#check-what-the-realm-vouched-for) | auditors, realm admins | works |
| [Seal your own files](#seal-your-own-files) | every user | partly |
| [Share a seal with a team or a fleet](#share-a-seal-with-a-team-or-a-fleet) | teams, fleet owners | works |
| [Require several people to approve a break-glass release](#require-several-people-to-approve-a-break-glass-release) | security teams | works |
| [Recover a seal when every device is lost](#recover-a-seal-when-every-device-is-lost) | every user, helpdesk | works |
| [See who touched your seal](#see-who-touched-your-seal) | every user | works |
| [Work offline for a while](#work-offline-for-a-while) | every user | works where the realm allows it |
| [Sign files and commits under your login](#sign-files-and-commits-under-your-login) | developers, release engineers, CI | works |
| [Have independent witnesses watch the logs](#have-independent-witnesses-watch-the-logs) | auditors, partner sites | works |
| [Log in offline without a crackable password cache](#log-in-offline-without-a-crackable-password-cache) | laptop users | planned |
| [Tie secrets to a TPM, passkey or attested hardware](#tie-secrets-to-a-tpm-passkey-or-attested-hardware) | users, fleet owners | planned |
| [Anonymous tokens: surveys, reports, access](#anonymous-tokens-surveys-reports-access) | everyone | research |

Every use case follows the host's system crypto policy. Under a CNSA 2.0
policy, every algorithm and hash is CNSA-approved. kuipa adds no
algorithm settings of its own ([What kuipa protects](security.md#algorithms-and-the-crypto-policy)).

## Hosts

### Join hosts to the realm safely

**Why.** A new host must be sure it talks to *your* realm before it
accepts keys from it, and the realm must be sure the host may join. A
copied keytab *is* the host.

**What kuipa does.** The host learns the realm's anchors from an
enrollment string or a file baked into its image. It checks every server
against them, proves it may join (a one-time password, an admin's
password, or a Kerberos ticket), and receives its keytab, the CA chain and
the realm configuration encrypted with ML-KEM.

**Status:** works. See [Enrolling a host](host/enroll.md) and
[Letting hosts join](realm/enrollment.md).

### Join cloud instances from images and autoscalers

**Why.** Cloud instances are cloned from images and created by
automation that should not hold an admin password.

**What kuipa does.** Bake the realm's anchors into the image. Give each
instance a single-use **voucher** for one host name: the issuer signs it
without seeing what it signs, and the server spends it once.

**Status:** works. See [Cloud virtual machines](scenarios/cloud.md).

### Prepare hosts that join without a network

**Why.** Some hosts first boot where they cannot reach the IPA servers:
an isolated network, a factory, a ship.

**What kuipa does.** An admin stages the host in advance. The host enrolls
from a sealed, signed bundle with no network access, and checks the
bundle against its pinned anchors.

**Status:** works. See [Letting hosts join](realm/enrollment.md#staged-hosts-and-bundles).

### Rotate host keys automatically

**Why.** A key that never changes stays valuable to whoever copied it.

**What kuipa does.** A timer rotates the host's keys with forward
secrecy. Each rotation proves the host holds the current keys.

**Status:** works. See [Day-to-day host care](host/care.md#rotating-keys).

### Keep keytabs useless in backups and snapshots

**Why.** A keytab in a backup, a disk image or a VM snapshot lets anyone
impersonate the host or service.

**What kuipa does.** `kuipa protect` seals the host keytab, and any
service keytab, on disk. A sealed keytab opens only with an answer from
one of the realm's servers, and stops opening once the host is removed
from the realm. Services read it at start-up without it ever being
written in plain text (`kuipa-unseal`, gssproxy).

**Status:** works. See [Protecting keytabs and files](host/protect.md).

### Seal any file to a host

**Why.** Service passwords, TLS keys and API tokens sit next to keytabs
and leak the same way.

**What kuipa does.** `kuipa protect` seals any file the same way as a
keytab, and services can read it once at start-up.

**Status:** works. See [Protecting keytabs and files](host/protect.md#any-file).

### Unlock encrypted disks with a post-quantum Tang

**Why.** Clevis and Tang unlock LUKS disks automatically on the right
network, but Tang's key exchange is classical.

**What kuipa does.** `kuipad` serves a post-quantum Tang, and the
`tang-pqc` Clevis pin binds a disk to it with ML-KEM.

**Status:** works as a command and over HTTP. It is **not yet tested
under real Clevis, with LUKS2, or in an initramfs**. See
[Keys and rotation](realm/keys.md#tang).

### Deliver CA bundles without trusting DNS or TLS

**Why.** A host's trust store decides which TLS servers it believes, and
it is usually fetched over the very DNS and TLS it is meant to secure,
or baked into an image and never refreshed. When a CA fails, every
store must change quickly. In October 2026 eight eMudhra intermediate
CAs turned out to have private keys anyone could recover from their
certificates. Browsers blocked them within days, but trust stores in
containers, images, vendored bundles and early boot change only when
someone rebuilds them. An enrolled host has a better source: its own
realm, which it already authenticates with post-quantum anchors.

**What kuipa does.** The realm's advertisement carries its CA chain and
PKINIT anchors, signed by the server and vouched for by the anchors a
host pins. A host installs them at enrollment, `kuipa realm-info` does
the same for a machine that is not enrolled, and `kuipa trusted-realms`
for each trusted realm. Nothing in the path depends on DNS, on TLS, or
on a CA: an attacker who controls both still cannot change what the
host installs. Every entry must be a CA certificate before anything is
written, and Merkle Tree CAs are accepted.

**What it would do.** Make the realm the source of a host's whole trust
bundle, kept current:
- refresh the CA chain at every key rotation and health check, not only
  at enrollment;
- carry a realm-managed bundle in the advertisement: extra CAs the
  realm adds, and **distrusted** keys by SPKI hash, as browsers block
  intermediates, so one change by an administrator reaches every host
  at its next check;
- install them into the system trust store (`update-ca-trust`, with
  distrusted keys in the blocklist), and into containers at start;
- carry the pinned anchors and the last verified bundle into the
  initramfs (a dracut module, as `tang-pqc` has), so early-boot HTTPS
  (network root, provisioning, `tang-pqc` over `https`) trusts what the
  realm decided, verified before the root file system is mounted.

**Status:** partly. Authenticated delivery of the realm's own CA chain
works; refresh, distrust lists, the system trust store and the
initramfs are planned.

### Give CI runners short-lived identities

**Why.** CI runners are created and destroyed constantly, and often hold
long-lived secrets pasted into the CI system.

**What kuipa does.** The CI controller requests a voucher with a lease
(`kuipa-voucher request --lease-hours 4`) for each runner it starts. The
KDC issues the runner no ticket after the lease, and the realm removes
the host an hour later. Pipeline secrets are files sealed to a shared
seal of the runners' host group with `--ticket-leased`: they open with
a runner's ticket only while its lease runs, so a copied keytab is worth
at most the rest of the lease. See
[CI runners](reference/design.md#kuipa-for-ci-runners-leased-identities-and-pipeline-secrets).

## Realms

### Accept users of a trusted realm

**Why.** When two IPA realms trust each other, hosts must install the
other realm's KDCs and certificates, and must know they are genuine.

**What kuipa does.** Your servers vouch for the partner realm's anchors.
Hosts install its KDCs and PKINIT chain only after checking them through
your own realm.

**Status:** works. See [Trusted realms](realm/trusts.md).

### Move secrets between IPA replicas

**Why.** When a new IPA replica is set up, it fetches the CA and
Directory Manager secrets from an existing one (FreeIPA's Custodia). That
transport is classical.

**What kuipa does.** The `keys` operation fetches them sealed with
ML-KEM, only for a host the realm lists as a replica, and logs each fetch.

**Status:** works; not yet run against a real FreeIPA server. See
`kuipa keys fetch` in [Commands](reference/commands.md#kuipa-hosts).

### Check what the realm vouched for

**Why.** If a server, or a stolen anchor key, vouched for a rogue server,
you want to see it, and to know that every host saw the same record.

**What kuipa does.** Each anchor keeps a public, append-only log of the
servers it vouches for. `kuipa-audit` checks a server's log and compares
servers against each other. `kuipa-mirror` serves copies for sites that
cannot reach the realm.

**Status:** works. See [Auditing and mirroring](realm/audit.md).

### Have independent witnesses watch the logs

**Why.** A server could show one log to you and a different one to
someone else. A witness that checks the log only ever grows makes that
detectable.

**What kuipa does.** Each server keeps a public transparency log of seal
changes, releases of seal keys, replica secret fetches and signatures. Witnesses (a
partner site, an auditor's machine) cosign each new head after checking
that it extends the last one. Hosts and users can require a number of
witness cosignatures before they accept a head.

**Status:** works. See [Auditing and mirroring](realm/audit.md#the-transparency-log-and-its-witnesses).

## Users

### Seal your own files

**Why.** SSH keys, password databases and tokens in your home directory
end up in backups and on lost laptops.

**What kuipa does.** `kuipa seal` encrypts your files so that a copy
opens only under rules you choose. The rules can require your device's
key, your Kerberos login, and an answer from one of the realm's servers.
Your files never leave your machine.

**Status:** partly: devices with passphrase-protected keys or a PKCS#11
token, Kerberos, sessions and unlock limits work. Passkeys and attested
hardware do not yet. See [Sealing your own files](user/sealing.md).

### See who touched your seal

**Why.** If someone with your ticket, or an administrator, adds a device
to your seal or opens your files, you should find out.

**What kuipa does.** Every change to your seal and every key release is
recorded in the servers' transparency logs. `kuipa tlog watch` lists
the entries about your seal and flags those that the seal description
stored on your machine does not explain: a device it does not know, a
policy or sharing it does not show, a revocation. A change you made from
another machine is flagged too, until `kuipa seal show` updates the
description here.

**Status:** works. See [Sealing your own files](user/sealing.md#see-who-touched-your-seal).

### Work offline for a while

**Why.** On a plane or a train, you still need your sealed files.

**What kuipa does.** Where the realm allows it, one unlock while online
lets your device open your files offline until a time the realm sets.

**Status:** works where the realm allows it. See
[Sealing your own files](user/sealing.md#work-offline-for-a-while-if-your-administrators-allow-it).

### Share a seal with a team or a fleet

**Why.** Teams and host groups need shared secrets, such as a database
password or a fleet's API key, without a password everyone copies.

**What kuipa does.** A seal's owner shares it with users, IPA groups,
hosts or host groups, as members or as managers. Each member opens with
their own device and login, under the seal's one policy. Membership is
checked at every open, so removing someone from the group in IPA stops
their opens on every machine.

**Status:** works. See [Sealing your own files](user/sealing.md#share-a-secret-with-your-team).

### Require several people to approve a break-glass release

**Why.** Emergency access to a team's or a person's sealed secrets
should not rest on one person holding the factors.

**What kuipa does.** A seal's policy names approvers and how many must
agree. Whoever asks gets nothing until enough others have approved that
request, and each request, approval and denial is in the transparency
log.

**Status:** works. See [Sealing your own files](user/sealing.md#a-break-glass-secret-several-people-approve)
and [release approvals](reference/design.md#kuipa-release-approvals-m-of-n-before-a-break-glass-release).

### Recover a seal when every device is lost

**Why.** If a seal requires your device and you lose all your devices,
your files are gone.

**What kuipa does.** A recovery code you print brings your device key
back on a new machine. Without one, the helpdesk delivers it from a seal
it was deposited in when you registered the device, under several
people's approval and recorded in the transparency log. Hosts and
services deposit their LUKS and backup keys into a helpdesk seal the
same way, and cannot read them back.

**Status:** works. See [Sealing your own files](user/sealing.md#keep-a-recovery-code-in-case-it-was-your-only-device),
[Protecting keytabs and files](host/protect.md#deposit-recovery-keys-with-the-helpdesk)
and [recovery](reference/design.md#kuipa-recovery-lost-devices-luks-and-backup-keys).

### Sign files and commits under your login

**Why.** Signing usually means guarding a private key on every laptop
and CI runner. Losing one is hard to notice and hard to undo.

**What kuipa does.** `kuipa sign` has a realm server state that you,
by your Kerberos ticket, signed some files or a git commit. You keep no
key. The realm's policy decides who signs what. Every statement goes in
the server's transparency log, so you can see everything signed in your
name. Anyone who pins the realm's anchors can verify it, offline.

**Status:** works. RPM and container images keep their own OpenPGP
signing, which kuipa does not change. See [Signing under your ticket](user/signing.md).

## Planned

These are designed or proposed, not built. They reuse what kuipa already
has, and the ones marked *needs* depend on another item first. Each is
an entry in `TODO.md`.

### Log in offline without a crackable password cache

**Why.** SSSD lets a laptop log in offline by caching a hash of your
password. Anyone who copies that cache can guess the password at full
speed, on any machine.

**What kuipa would do.** While the realm is reachable, kuipa arms the
laptop: the realm signs an offline grant for one user, one machine and a
time window. The password check moves into the laptop's TPM, which
limits guesses and works only on that machine and only within the
window. The disk holds nothing to guess against.

### Tie secrets to a TPM, passkey or attested hardware

**Why.** A device key on disk can be copied. One inside a TPM, a passkey
or a security key cannot.

**What kuipa would do.** Passkeys as a seal factor, a TPM factor for
sealed keytabs and machine seals, and checked hardware attestation, so
a policy can demand keys that cannot leave the hardware.

### Anonymous tokens: surveys, reports, access

**Why.** Some things should be countable but not traceable: one vote per
person in a survey, an anonymous report, access that proves membership
without saying who.

**What kuipa would do.** The realm issues each person a fixed number of
tokens, and cannot tell later which person spent which token. kuipa
already has message-hiding ML-DSA signatures (`ml-dsa-blind`). The
unlinkable part needs a zero-knowledge proof about an ML-DSA signature,
which is research (`ml-dsa-zk` has its first building blocks).

### Recipes for tools you already use

**Why.** Many secrets live in tools with their own formats: Ansible seal
passwords, `systemd-creds`, container secrets.

**What kuipa would do.** Short guides and scripts that keep those
secrets sealed with `kuipa seal` or `kuipa protect`, without changing
the tools.
