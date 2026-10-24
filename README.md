# kuipa

Post-quantum enrollment and keytab protection for FreeIPA hosts.

A FreeIPA client's identity is its keytab, the long-term Kerberos keys of
`host/<fqdn>@REALM`. kuipa protects that keytab with standard
post-quantum primitives (FIPS 203 ML-KEM and FIPS 204 ML-DSA) wherever it
travels or rests, without changing Kerberos, the KDC or the way FreeIPA
creates keys.

> **Status:** research prototype. The protocol and its implementation are
> still changing, and wire formats are not stable. Do not deploy it to
> protect production realms.

## Features

* **Enrollment:** the host authenticates the realm against a pinned
  anchor, proves it may join, and receives its keytab, the CA chain and
  the realm configuration under ML-KEM. It can authenticate with:
  * a one-time password,
  * a user's password,
  * an existing Kerberos ticket,
  * a blind-signed voucher.
* **Rekey:** host keys rotate with forward secrecy.
* **Keytab at rest:** optionally, the keytab is sealed on disk, so a copy
  of the disk is useless without the IPA servers. It is unsealed at boot
  by `kuipa-unseal`. Service keytabs and any other file can be sealed the
  same way, for the principal whose keys they hold or belong to.
* **Offline enrollment:** an administrator stages a host and its keys in
  advance. The host enrolls from a sealed, signed bundle with no network
  access.
* **No single point of trust:** each server holds its own anchor. The
  servers vouch for each other through an exchange authenticated with
  their Kerberos keys, and anchors can be rotated. A host that knows two
  of a realm's anchors demands the claim proven by two distinct ones, so
  a server built on a single stolen anchor is refused. A host that has
  seen the realm once also keeps a watermark over the realm's anchor
  history, and refuses a server that record leaves behind.
* **Trusted realms:** a host can accept users from realms its realm
  trusts, with their KDCs and PKINIT anchors verified.
* **Post-quantum Tang:** the server can also act as a general
  post-quantum Tang server, with a Clevis pin for disk encryption.

All cryptography comes from OpenSSL through
[`native-ossl`](https://crates.io/crates/native-ossl), so server keys can
live in the FIPS provider or an HSM. The system crypto policy limits
which algorithms are used.

## Components

| crate | description |
|---|---|
| [`kuipa-enroll`](crates/kuipa-enroll) | The protocol, without I/O: delegations and the anchor exchange, realm advertisements, join, rekey and staging, vouchers, trusts, offline bundles, sealed keytabs |
| [`kuipad`](crates/kuipad) | The server daemon, behind httpd, using 389-ds over LDAPI |
| [`kuipa-tools`](crates/kuipa-tools) | Client programs: `kuipa`, `kuipa-unseal` and `kuipa-voucher` |
| [`kuipa-gssapi`](crates/kuipa-gssapi) | GSSAPI bindings |
| [`kuipa-ldap`](crates/kuipa-ldap) | OpenLDAP bindings |
| [`tang-pqc`](crates/tang-pqc) | Post-quantum Tang/Clevis-style key escrow with ML-KEM and ML-DSA |
| [`tang-pqc-clevis`](crates/tang-pqc-clevis) | A post-quantum Tang client and the Clevis pin `tang-pqc` |
| [`ml-dsa-blind`](crates/ml-dsa-blind) | Blind signing with stock FIPS 204 ML-DSA |
| [`shims/rand`](shims/rand) | A replacement for `rand`, backed by OpenSSL's random generator |

`tang-pqc`, `tang-pqc-clevis` and `ml-dsa-blind` don't depend on FreeIPA
and can be used on their own.

## Requirements

* Rust 1.89 or later
* OpenSSL 3.5 or later (for ML-KEM and ML-DSA)
* MIT Kerberos and OpenLDAP client libraries and headers
* A C compiler, libclang and pkg-config, used by the build scripts
* For the real-KDC tests: `krb5kdc`, `kdb5_util` and `kadmin.local`
  (the tests are skipped when these are missing)

On Fedora:

```sh
sudo dnf install cargo gcc clang-devel pkgconf-pkg-config \
    openssl-devel krb5-devel openldap-devel
sudo dnf install krb5-server krb5-workstation krb5-pkinit   # real-KDC tests
```

## Building

```sh
cargo build --release
```

The binaries are placed in `target/release/`.

## Installation

The `contrib/` directory holds:

* the systemd units: `kuipad.socket`/`.service`, `kuipa-unseal.service`,
  `ipa-client-complete.service` and `kuipa-rotate.timer`/`.service`,
* the httpd snippet that forwards `/ipa/ku/` to the daemon
  (`kuipa.conf`),
* an example daemon configuration (`kuipad.json.example`),
* a gssproxy example (`gssproxy-kuipa.conf.example`).

To install the post-quantum Tang client and its Clevis pin, with the
dracut module that brings the pin into the initramfs, run:

```sh
contrib/clevis/install.sh [PREFIX] [DESTDIR]
```

## Usage

On an IPA server, create the server's keys and print an enrollment
string:

```sh
kuipad generate-keys
kuipad enrollment-string --days 1
```

The output looks like `ipa-ku1:EXAMPLE.TEST:<anchor>:<expiry>`. Append
`:<OTP>` to it, using the one-time password from `ipa host-add --random`.
Then, on the host:

```sh
kuipa enroll --server ipa1.example.test < enrollment-string
kuipa protect    # optional: seal the keytab on disk
kuipa protect --keytab /etc/httpd/http.keytab   # optional: a service keytab
kuipa check
```

To learn what each command does, see the command overview in
[DESIGN.md §10](docs/DESIGN.md#10-client-kuipa-and-kuipa-unseal) for the
client, and [§11](docs/DESIGN.md#11-server-kuipad) for the server. To try
the client without touching the system, put all paths under `KUIPA_ROOT`:

```sh
KUIPA_ROOT=/tmp/h kuipa prepare --hostname web1.example.test
```

## Testing

```sh
cargo test --workspace            # unit, end-to-end, HTTP and real-KDC tests
./contrib/ci/local-ci.sh all      # everything CI runs
```

When the KDC programs are installed, `crates/kuipa-tools/tests/kdc.rs`
runs the client flows against a throwaway MIT KDC, with PKINIT and a
generated test CA. To keep its files under `/tmp/kuipa-kdc-<pid>`, set
`KUIPA_KEEP_REALM=1`.

To try every flow by hand, run:

```sh
./contrib/ci/local-ci.sh interactive
```

It starts a throwaway environment (an MIT KDC, two IPA servers, a
trusted realm and a voucher issuer) and opens a shell where `kuipa` and
helper commands are ready to use. `./contrib/ci/local-ci.sh
playground-test` runs a scripted session in the same environment, with
tracing on, and writes a report of it to `kuipa-playground-report/`:
every step's output and trace, plus an animated terminal capture of each
section of the session.
[A traced session](docs/src/scenarios/walkthrough.md) explains one step
by step.

A symbolic model of the enrollment protocol's core exchange (anchor
pins, advertisement verification, the ML-KEM join and rekey key
schedule, OTP and Kerberos authenticators, sealed-keytab escrow) is in
[`contrib/tamarin/kuipa.spthy`](contrib/tamarin/kuipa.spthy), for the
Tamarin prover. `tamarin-prover --prove contrib/tamarin/kuipa.spthy`
verifies secrecy, server authentication, rekey forward secrecy and
sealed-keytab offline resistance, and reproduces the two attacks
DESIGN §13 predicts for a mis-delivered enrollment string and a stolen
anchor. The model's header documents its abstractions.

## Documentation

The user documentation is an mdBook in [`docs/`](docs/src/SUMMARY.md):
guides for realm administrators, host administrators and users, scenarios,
and reference. Build it with `mdbook build docs` (and `mdbook-mermaid`
for the diagrams); the HTML lands in `docs/book/`.

* [docs/DESIGN.md](docs/DESIGN.md): the protocol, the implementation and
  its status (§19); the book includes it as its reference
* [TODO.md](TODO.md): planned work
* [docs/man/](docs/man): man pages for the programs (scdoc sources,
  `*.scd`; compile one with `scdoc < kuipa.1.scd > kuipa.1`)

## Contributing

Issues and pull requests are welcome. Before you submit a change, run
`./contrib/ci/local-ci.sh all`. It runs the same checks as CI: build,
formatting, workflow lint, dependency policy, clippy, documentation and
tests.

## License

kuipa is free software. You can redistribute it and modify it under the
terms of the GNU General Public License, as published by the Free
Software Foundation, either version 3 of the License or (at your option)
any later version. See [LICENSE](LICENSE).

`kuipa-gssapi` and `kuipa-ldap` are derived from the GSSAPI and LDAP
bindings of the ahdapa project.
