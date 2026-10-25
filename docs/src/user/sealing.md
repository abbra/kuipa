# Sealing your own files with `kuipa seal`

> **Status: partly implemented.** This guide describes `kuipa seal` as
> the design's [user vaults](../reference/design.md#76-user-vaults-being-implemented)
> section has it. Working today: `create`,
> `policy`, `device add|remove` with passphrase-protected device keys or
> an ML-KEM key on a PKCS#11 token (`--pkcs11 URI`, registered at level
> `any` until attestation is checked), `file`, `open`, `reseal`, `show`, `list`, `revoke`, `unlock` and `lock`,
> with the `device` and `ticket` factors, re-authentication sessions
> (`--session-hours`), offline sessions (`--offline-hours`, where the realm
> allows them), unlock limits (`--max-unlocks`), registered sealing
> (`--sealing registered`, `kuipa seal retire`) and shared vaults
> (`share`, `unshare`). Not yet: passkeys,
> the attested `hardware-*` levels, and refusing or
> limiting delegated tickets (the server cannot tell them apart yet, so
> only the default `allow` is accepted). A vault policy asking for any of
> those is refused.

`kuipa seal` lets any user of an IPA realm encrypt their own files so that a
copy is useless on its own. Opening a sealed file needs one of the realm's
servers to agree, under rules you choose, and usually something only you
have: a key on your device, a passkey you touch, or your Kerberos login.

You don't need root, and your files never leave your machine. The servers
hold only the rules for releasing a key share, never the data. This is not
`ipa vault-*`, which stores secrets on the IPA servers; `kuipa seal`
keeps the data with you.

## The idea in one page

* A **vault** is a set of rules on the IPA servers, owned by you: which
  factors opening a file needs, until when, how many times. You create
  vaults yourself, within limits your administrators set, and can share
  one with other users, a group or a host group.
* A **device** is a key that belongs to you and lives on one machine or
  token: a passphrase-protected key file, a key wrapped by a passkey, or a
  key on a smart card or token. You register each device in the vault.
* **Sealing** a file encrypts it so that opening needs the server's share
  *and*, if the vault asks for it, a registered device. Sealing works
  offline.
* **Opening** a sealed file asks a server, which checks the vault's rules
  and answers only to a registered device. A server's answer alone cannot
  open your files, and neither can your device alone.

Each vault chooses its factors from:

| factor | what it asks of you | good for |
|---|---|---|
| `device` | a registered device key; its level can be `any`, `hardware-wrapped` (passkey or token-wrapped) or `hardware-bound` (a key that never leaves a token) | almost everything: copies at rest stay closed |
| `ticket` | your Kerberos ticket: the one your login gave you on an IPA-enrolled system (PAM, or SSH with protocol transition), or `kinit` | tying opens to your login session |
| `passkey` | a touch (and PIN) on one of the passkeys registered to your IPA account | proof that you are present |

A vault needs at least one of them; the server's agreement alone is never
enough.

A ticket that a machine obtained for you (sshd does after a public-key
login) records which machines it went through. A vault accepts such
tickets by default; it can refuse them (`--ticket-delegation refuse`), or
accept them only through named machines (`--ticket-via host/devvm1…`).

## Use cases

### Keep secrets in your home directory safe in backups

API tokens, `~/.config/*/credentials`, a database password, a recovery
code: files you need now and then that should not be readable from a
backup, a copied home directory or a stolen laptop.

```sh
kuipa seal create personal --require device
kuipa seal device add personal --passphrase      # this laptop
kuipa seal file personal ~/.config/app/token     # writes ~/.config/app/token.sealed
shred -u ~/.config/app/token
```

Later:

```sh
kuipa seal open ~/.config/app/token.sealed --out - | app --token-stdin
```

What you get:

* a copy of `token.sealed` opens nowhere: it needs your device key, its
  passphrase, and an answer from an IPA server;
* another user on the same machine who can read `token.sealed` cannot open
  it either: they have no registered device of yours.

Sealing needs no network, so you can seal files on a train. Opening needs a
server.

### Feed a secret to a program without writing it to disk

`kuipa seal open --out -` writes the plaintext to standard output and
nothing else. It refuses to print to a terminal unless you pass `--force`,
so a secret does not end up in your scrollback by accident.

```sh
kuipa seal open ~/.ssh/deploy_key.sealed --out - | ssh-add -
kuipa seal open ~/secrets/db.env.sealed --out - | ./migrate --env-file /dev/stdin
kuipa seal open ~/backup-codes.txt.sealed --out ~/backup-codes.txt   # a file again
```

### Require a touch on your security key

For secrets you want to open only when you are physically there, use a
passkey: either as the device (the key file is wrapped by the passkey, so
every open needs a touch), or as a factor the server checks, or both.

```sh
kuipa seal create signing --require device=hardware-wrapped,passkey
kuipa seal device add signing --passkey
kuipa seal file signing ~/release-signing.key
```

Any passkey registered to your IPA account (the ones you log in with) is
accepted for the `passkey` factor. If you remove a passkey from your
account, it stops opening these files too. Post-quantum (ML-DSA) passkeys
work where your libfido2 supports them.

### Use a smart card or hardware token

If your token supports ML-KEM keys (PKCS#11 3.2), the device key can live
on the token and never leave it: the strongest level, `hardware-bound`.

```sh
kuipa seal create work --require device=hardware-bound
kuipa seal device add work --pkcs11 'pkcs11:token=MyToken;object=kuipa'
```

Tokens that only hold AES keys can wrap a device key instead
(`--pkcs11-wrap URI`, level `hardware-wrapped`). Cards that only do RSA or
EC (most PIV cards today) are not accepted as wrappers: what they protect
could be decrypted later by a quantum computer.

### Open the same files from your laptop and your workstation

Register a device on each machine. Every file is sealed to all the devices
the vault has at the time, so either machine can open it.

```sh
laptop$      kuipa seal device add personal --passphrase
workstation$ kuipa seal device add personal --passkey
```

A device added later cannot open files sealed before it was added. Reseal
them from a machine that can:

```sh
kuipa seal reseal personal ~/secrets/*.sealed
```

### See who touched your vault

Every server records each change to your vault, and each time it hands
out its share of one of your files, in a public transparency log that it
cannot rewrite unnoticed. To check it:

```sh
kuipa tlog watch personal
```

It lists everything since the last watch, server by server. Anything the
vault description stored on this machine does not account for is marked
`UNEXPECTED`: a device you don't know of added, or opening files, or a
policy you didn't set. If you made the change yourself from another
machine, `kuipa seal show personal` updates the description, and the
next watch is clean. A server whose log no longer extends what you saw
before is reported as `FORKED`, which means its log was rewritten. A
server that changed to keys of another strength, as a change of the
crypto policy makes it do, keeps a new log under a new id: that is
`NEW LOG`, not a fork, and the new log is read and checked from its
start. The first watch only records where each log stands; run it once soon after
creating a vault. A periodic job (a systemd user timer, cron) can run it
for you: it exits non-zero when something needs a look.

The log never names you or your vault, only an opaque index, so anyone
can audit it without learning whose vault an entry is about.

### You lost a laptop

Remove its device from the vault, from any other machine (or ask an
administrator):

```sh
kuipa seal device remove personal <device id>     # ids: kuipa seal show personal
```

From the next open on, servers no longer answer to that device. Whoever has
the laptop has its sealed files and its device key file, but the servers
won't help them, so they can't open anything, even with your passphrase.
Your other devices keep working.

If you suspect your password was compromised too, and a vault requires only
`ticket`, revoke that vault: a ticket-only vault does not protect against
someone who has your password and a copy of the file.

### Stay signed in for a working day

Typing a passphrase or touching a key for every open gets tiring. If the
vault's policy allows it, one unlock starts a **session**:

```sh
kuipa seal create work --require device,ticket --session-hours 8
kuipa seal unlock work            # passphrase and ticket once
kuipa seal open report.sealed --out report.pdf   # no prompts until the session ends
kuipa seal lock work              # end it early
```

While the session lasts, your device key is kept unwrapped in your
runtime directory (`$XDG_RUNTIME_DIR`: memory only, yours alone, gone when
you log out), so neither the passphrase nor a ticket is asked for.

During a session each open still goes to a server, so the session's end,
revocation and the vault's limits still apply, and every open is logged.
Sessions are capped by the vault's policy and by the realm.

### Work offline for a while (if your administrators allow it)

Travelling without a network? Some realms allow **offline sessions**: one
unlock gives your device the key to open the vault's session files offline
for a set time.

```sh
kuipa seal create travel --require device,ticket --offline-hours 48
kuipa seal file travel notes.md --session    # sealed for offline sessions
kuipa seal unlock travel --offline           # before you leave
kuipa seal open notes.md.sealed --out notes.md   # on the plane: no server needed
kuipa seal lock travel                       # when you are back
```

Offline sessions are off unless your administrators enable them for the
realm *and* you enable them for the vault. Know what they cost: while a
session is unlocked, the key is on your machine, and the servers can no
longer enforce when it ends or count your opens. They are for convenience
on a machine you trust, not for your most sensitive files.

### Share a secret with your team

A database password the whole team needs belongs in a vault you share,
not in a chat message. Share it with the IPA group, and make a colleague
a manager so the vault does not depend on you alone:

```sh
alice$ kuipa seal create db --require device,ticket
alice$ kuipa seal share db --group dba
alice$ kuipa seal share db --manager --user carol
```

Others name your vault `alice/db`. Each member registers their own device
from their own machine, and `kuipa seal list` shows it among theirs:

```sh
bob$ kuipa seal device add alice/db --passphrase
bob$ kuipa seal file alice/db db-password.txt
bob$ kuipa seal open db-password.txt.sealed --out -
```

* Every file is sealed to every member's devices. Each member opens with
  their own device and their own ticket: Bob's ticket does not open with
  Alice's device.
* Membership is checked at every open. Someone who leaves the `dba` group
  in IPA opens nothing more, and their devices are dropped from the vault
  the next time anyone uses it. `kuipa seal unshare db --user bob` removes
  someone named directly. A member can leave with
  `kuipa seal unshare alice/db --user bob`.
* A file sealed before a member registered their device does not open for
  them until someone resealed it: `kuipa seal reseal alice/db *.sealed`.
* What a removed member already opened stays opened: change the secret
  itself, then reseal.

Managers change the policy, share and unshare, and revoke. Members open,
seal, start sessions and manage their own devices. The vault stays yours
(it counts against your vault limit) but keeps working for the team if
your account is disabled.

For a fleet, share with a host group (`--group webservers`) or hosts
(`--host web1.example.test`): each host runs `kuipa seal` as root, with
its host ticket (`kinit -k`) and its own device key in its kuipa
directory (`KUIPA_USER_DIR`).

### A break-glass secret that opens only a few times

An emergency root password or a recovery key should open rarely, with
proof of who opened it, and old copies should die when it changes.

```sh
kuipa seal create break-glass --require device=hardware-bound,ticket,passkey \
                              --max-unlocks 3 --expires 2027-06-30 --sealing registered
kuipa seal file break-glass root-password.txt
```

* Every open needs your token, your login and a touch, and is logged on the
  servers.
* After three opens the servers stop answering. The count is kept across
  all servers; it can be exceeded by a little if several servers are
  opened at the same moment, so treat it as a tripwire, not an exact
  counter.
* `--sealing registered` means sealing needs a server, and resealing
  (after you rotate the password) retires the old sealed copy everywhere.

### When you leave, or your account is disabled

Disabling your IPA account, or revoking a vault, stops every future open on
every machine at once. Nothing has to be found and deleted first. Vaults
you share keep opening for their other members; their managers, or your
administrators, can revoke them.

What this cannot undo: a file you already opened, or an offline session
already unlocked, has its plaintext or key on that machine.

## What protects what

| someone has | can they open your file? |
|---|---|
| a copy of the sealed file | no |
| the copy and network access to the IPA servers | no |
| the copy and your device key file, but not its passphrase, touch or token | no |
| the copy and your password, vault requires `device` | no |
| the copy and your password, vault requires only `ticket` | **yes**: require `device` or `passkey` too |
| an IPA administrator, with the servers' keys | no, if the vault requires `device`: your device holds the other half |
| anyone, after your account, the vault or that device is revoked | no new opens |
| root on your machine while you have a file open or a session unlocked | yes: nothing on a machine protects against its own root |

## What it does not do

* **Keep a secret from a vault's own members.** Everyone you share a
  vault with can open every file sealed to it, and sees its members,
  devices and policy.
* **Open files with no network.** Every open needs a server, except during
  an offline session.
* **Run unattended out of the box.** A job that opens files while
  nobody is around needs a device that works without you (for example a
  token whose PIN the job holds, which counts as level `any`) and a vault
  without `ticket` and `passkey`, or a session you started. For services and hosts, `kuipa protect` (run as
  root) is the right tool: those files are meant to open at boot without a
  human.
* **Protect files after they are opened.** Once plaintext is written out or
  piped into a program, it is that program's to protect.

## For administrators

Users manage their own vaults; administrators set the limits and can step
in:

* **Realm limits**, for the whole realm or for members of a group: the longest expiry, the largest `--max-unlocks`, vaults
  per user, devices per member of a vault, how many managers and members
  a shared vault may have, the longest sessions, which factor
  combinations are allowed (for example: never `ticket` alone), and whether
  offline sessions are allowed at all (off by default).
* **Revoke** a user's vault or one of its devices; disabling the user stops
  all their vaults.
* **Audit**: every open, unlock, device change and refusal is logged by the
  server that handled it. Opens, unlocks and changes also go to the
  server's public transparency log (`/ipa/ku/tlog/`), where owners check
  them with `kuipa tlog watch`.

The administration commands belong to the FreeIPA integration and are not
designed in detail yet.
