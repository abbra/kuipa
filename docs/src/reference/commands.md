# Commands

Every program prints its full options with `--help`. This page lists what
each command is for.

Common to `kuipa` and `kuipa-unseal`: `--json` prints the result as one
JSON object; `--verbose` and `--trace` trace on standard error;
`$KUIPA_TRACE` takes `tracing` filter directives instead. Exit status: 0
success, 75 retry later, 1 an administrator must act or another error, 2
usage.

## kuipa (hosts)

| command | does |
|---|---|
| `enroll` | join the realm online (OTP, `--ldap-otp`, `--principal` with a password, `--use-ccache`, `--voucher-file`) or offline (`--bundle`) |
| `prepare [--new] [--hostname H]` | make the machine key a mode A bundle is sealed to; print its thumbprint |
| `voucher-key --out F` | make the ephemeral key a voucher binds to; print the binding |
| `realm-info --krb5-dir D` | write a Kerberos configuration from the verified advertisement, for an armoured `kinit` before `--use-ccache` |
| `complete` | finish an offline enrollment at first contact |
| `rotate-keys` | new host keys; refresh pins and servers; reseal when protected |
| `protect` / `unprotect` | seal the host keytab on disk, or put it back |
| `protect` / `unprotect --keytab F` | the same for a service's or user's keytab |
| `protect` / `unprotect --file F [--keytab K]` | the same for any file, sealed for `K`'s principal (default: the host) |
| `trusted-realms` | install and refresh the realms this realm trusts; remove the others |
| `advertisement` | what each server advertises, verified, and an index of every anchor and key it names; writes nothing |
| `status` | the host's state, from its files |
| `check [--server S]` | every server, the delegations, a `kinit`, the sealed keytabs and files; exit 1 on a problem |
| `leave` | remove kuipa's state, writing protected keytabs and files back in plain form |

## kuipa seal (users)

| command | does |
|---|---|
| `create VAULT --require device,ticket [--expires DAYS] [--max-unlocks N] [--session-hours H] [--offline-hours H [--epoch-days D]] [--sealing registered] [--ticket-delegation allow\|refuse \| --ticket-via S…]` | create a vault |
| `policy VAULT …` | replace a vault's policy (same options) |
| `device add VAULT [--passphrase-file F]` | register this host's device key, made under a passphrase if there is none |
| `device add VAULT --pkcs11 URI [--module PATH]` | register an ML-KEM key on a PKCS#11 token instead |
| `device remove VAULT ID` | remove a device |
| `file VAULT FILE [--out F] [--session]` | seal a file (offline while the vault's description is recent) |
| `open SEALED --out F\|- [--force] [--passphrase-file F]` | open a sealed file |
| `reseal VAULT SEALED…` | seal files again to the vault's current devices |
| `retire VAULT SEALED…` | with registered sealing: make every copy of these unopenable |
| `unlock VAULT [--offline]` / `lock VAULT` | start or end a session on this host |
| `show VAULT` / `list` / `revoke VAULT` | describe or revoke vaults |

## kuipa-unseal

| invocation | does |
|---|---|
| `kuipa-unseal` | open the host keytab into `/run/ipa/krb5.keytab` |
| `kuipa-unseal --memfd` | write the host keytab to file descriptor 3 (gssproxy's loader protocol) |
| `kuipa-unseal --all` | at boot: the host keytab if protected, and every other protected keytab and file |
| `kuipa-unseal --sealed S [--out F \| --out - [--force] \| --memfd]` | one sealed keytab or file: to a file, to standard output, to fd 3, or to its usual unsealed copy |

## kuipa-voucher

| command | role | does |
|---|---|---|
| `keygen --key F [--alg ml-dsa-65]` | issuer | make the voucher key; print its public JWK for `kuipad add-voucher-key` |
| `quota --quota F --limit N` | issuer | set how many vouchers may ever be signed |
| `sign --key F --quota F` | issuer | count, then sign the blinded request on standard input |
| `request --public JWK --realm R --fqdn H [--hostgroup G] [--days N] [--binding B] --state F` | provisioner | blind a voucher for one host |
| `finish --state F` | provisioner | unblind the issuer's answer; print the voucher |
| `show` | anyone | print a voucher's claims |

## kuipad (IPA servers)

| command | does |
|---|---|
| `serve` | run the daemon (the default) |
| `generate-keys` | make the anchor and the server's keys; print the anchor |
| `anchor` | print the anchor's thumbprint |
| `enrollment-string [--days N]` | print a string to append `:<OTP>` to (default 7 days, at most 400) |
| `rotate-keys [--join] [--escrow] [--trust] [--signing]` | retire keys and make new ones (default: join, escrow, trust) |
| `rotate-anchor [--days N]` | replace the anchor, with a succession valid N days (default 400) |
| `prune-keys [--join-days N] [--escrow-days N]` | delete keys retired longer ago (default 14 and 400 days) |
| `add-voucher-key --file JWK` | accept vouchers under a voucher key |
| `trust-invitation [--days N]` | invite another realm to trust this one |
| `establish-trust --invitation-file F --server S…` | trust the realm that issued an invitation |
| `tang-keygen` / `tang-rotate` / `tang-thp` | the post-quantum Tang service's keys |

Every command takes `--config FILE` (default `/etc/ipa/kuipad.json`).
Restart the daemon after changing keys.

## tang-pqc

| invocation | does |
|---|---|
| `tang-pqc adv URL [--ca F]` | list the signing-key thumbprints a Tang server advertises |
| `tang-pqc encrypt CONFIG < IN > JWE` | encrypt to a Tang server (`{"url": …, "thp": …}`) |
| `tang-pqc decrypt < JWE > OUT` | decrypt through the server |
| `clevis luks bind -d DEV tang-pqc CONFIG` | the same as a Clevis pin, for LUKS (install with `contrib/clevis/install.sh`) |
