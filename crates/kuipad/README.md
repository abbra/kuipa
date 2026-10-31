# kuipad

The kuipa server daemon. It runs on each IPA server, next to httpd and
389-ds.

`kuipad` serves the post-quantum enrollment endpoints under `/ipa/ku/`.
Its jobs are to:

* publish the realm advertisement,
* handle join, rekey and stage requests,
* unseal keytabs for protected hosts,
* exchange anchors with the other IPA servers by digest-first repair,
  authenticated with their `ipa-ku/<fqdn>` Kerberos keys.

It works on the directory through 389-ds over LDAPI and GSSAPI. It can
also act as a general post-quantum Tang server, under `/ipa/ku/tang`.

Ordinary repair contacts up to four rotating peers per interval or local
change; an independent timer schedules every known peer every ten intervals.
The complete membership remains available for authentication and admission.
The outgoing concurrency starts at `max(1, 16 / (members - 1))`. Each
repair running longer than one second temporarily opens another slot, up to
16 total, so a stalled peer cannot indefinitely block other work. Incoming
repairs are limited to 16. Busy responses (HTTP 503 or source-rate-limit 429)
receive up to three delayed retries; later rounds and sweeps retry failures.

A repair compares state digests, then bucket hashes, and exchanges only
the entries that differ (DESIGN §4.2.1). If either state exceeds 4,096
entries or a summary or selection exceeds its bound, it transfers the whole
snapshot in authenticated chunks of at most 128 KiB, subject to a 1 MiB
per-message limit and a 64 MiB snapshot limit.
Incomplete uploads reserve at most 64 MiB of declared snapshot size in
total and expire after two minutes of inactivity. Only a complete
digest-verified snapshot is admitted and durably merged. A repair that
meets a concurrent change runs again, up to three times.

## Deployment

The daemon is socket-activated on `/run/ipa/kuipad.sock` and is reached
through httpd. The repository's [`contrib/`](../../contrib) directory
holds:

* the units, `kuipad.socket` and `kuipad.service`,
* the httpd snippet, `kuipa.conf`,
* an example configuration, `kuipad.json.example`. Install it as
  `/etc/ipa/kuipad.json`.

## Usage

```text
kuipad [serve] [--config FILE]
kuipad generate-keys                 create the keys, print the anchor
kuipad anchor                        print this server's anchor thumbprint
kuipad enrollment-string [--days N]  print an enrollment string to append :<OTP> to
kuipad rotate-anchor [--days N]      new anchor, with a succession from the old one
kuipad rotate-keys [--join] [--escrow] [--trust] [--signing]
kuipad trust-invitation [--days N]   invite another realm to trust this one
kuipad establish-trust --invitation-file F --server S...
kuipad add-voucher-key --file JWK    accept vouchers under a voucher key
kuipad tang-keygen | tang-rotate | tang-thp
kuipad prune-keys [--join-days N] [--escrow-days N]
```

For the configuration keys, the key store and the HTTP interface, see
[DESIGN.md §11](../../docs/DESIGN.md#11-server-kuipad).

## License

This crate is part of [kuipa](../../README.md). It is licensed under the
GNU General Public License v3.0 or later. See [LICENSE](LICENSE).
