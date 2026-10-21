# Protecting keytabs and files

A plain keytab on disk is the host's identity for whoever copies it: a
backup, an image, a stolen disk. `kuipa protect` seals it, so a copy needs
the realm's servers to open, and stops opening when the host is removed.

## The host keytab

```sh
kuipa protect
systemctl enable kuipa-unseal.service kuipa-rotate.timer
```

* The host gets new keys (sealed straight away) and the sealed keytab is
  stored in `/etc/ipa/krb5.keytab.sealed`.
* `kuipa` opens it once through a server, checks the result, and only then
  replaces `/etc/krb5.keytab` with a link to `/run/ipa/krb5.keytab`, which
  lives in memory.
* At every boot, `kuipa-unseal.service` opens it again, after the network
  and before SSSD, gssproxy and certmonger. With no server reachable, it
  exits 75 and systemd retries every 30 seconds; the host boots meanwhile,
  without its Kerberos identity.
* Every key rotation reseals it: a copy from before the last rotation no
  longer opens.

`kuipa unprotect` writes the plain keytab back.

## A service's keytab

```sh
kuipa protect --keytab /etc/httpd/http.keytab
```

The keytab is sealed for the service's own principal, and its registration
is authenticated with the service's own keys. The file becomes a link to a
memory-only copy with the original mode and owner, refilled at boot by the
same unit. Order the service after unsealing:

```ini
# /etc/systemd/system/httpd.service.d/kuipa.conf
[Unit]
After=kuipa-unseal.service
Wants=kuipa-unseal.service
```

kuipa does not rotate a service's keys, since other machines may share
them. To rotate, run `ipa-getkeytab -k /etc/httpd/http.keytab` (it writes
through the link) and then `kuipa protect --keytab /etc/httpd/http.keytab`
again to reseal. The old sealed copy stops opening.

## Any file

```sh
kuipa protect --file /etc/app/db.conf                                   # for the host
kuipa protect --file /etc/pki/tls/private/app.key --keytab /etc/httpd/http.keytab   # for a service
```

The file is sealed for the principal of the keytab given (the host by
default) and treated like a keytab: a link to a memory copy, refilled at
boot. To change it, write through the link and run `kuipa protect
--file` again: the old sealed copy is retired. `kuipa unprotect --file`
puts the plain file back and retires its seal; without a reachable
server, the file is still restored and the output says the seal is still
registered.

## Reading a sealed file once

```sh
kuipa-unseal --sealed /etc/app/db.conf.sealed --out - | app --config /dev/stdin
kuipa-unseal --sealed /etc/app/db.conf.sealed --out /run/app/db.conf
```

`--out -` writes the plaintext, and nothing else, to standard output, and
refuses a terminal unless `--force`. Any other `--out` must be a regular
file or not exist yet, outside `/dev`.

## gssproxy

Services that go through gssproxy (NFS, `mod_auth_gssapi`) can load their
keytab straight into gssproxy's memory, never onto any filesystem, with
gssproxy's `keytab_loader`
([gssapi/gssproxy#135](https://github.com/gssapi/gssproxy/pull/135),
merged upstream; not in a release yet, so until it ships gssproxy must be
built from its main branch):

```ini
[service/nfs-server]
  mechs = krb5
  cred_store = keytab:MEMORY:nfs-server
  keytab_loader = /usr/libexec/kuipa-unseal --sealed /etc/nfs.keytab.sealed --memfd
  cred_usage = accept
```

## What sealing does and does not stop

It stops copies taken out of reach of your servers. A recent copy restored
inside your network still opens while the host or service is enabled.
Delete hosts you retire. See [What kuipa protects](../security.md#copies-of-disks-snapshots-and-backups).
