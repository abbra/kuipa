# Local CI

`contrib/ci/local-ci.sh` runs the CI pipeline on your machine, mirroring
`.github/workflows/ci.yml` job for job: every workflow job is a single
`local-ci.sh --no-deps <job>` call, so a job that passes locally passes in
CI with the same packages. Adapted from kurbu5-pkinit's harness.

## Prerequisites

The script needs bash 4 or later and checks for its tools at startup,
printing `✓` for what it found and `○` for what is missing:

| Tool | Needed for |
| --- | --- |
| `cargo` | everything |
| `rustfmt`, `clippy` | the `fmt` and `clippy` jobs |
| OpenSSL ≥ 3.5, krb5, OpenLDAP and libfido2 development files, libclang | building (Fedora: `openssl-devel krb5-devel openldap-devel libfido2-devel clang-devel`; bindgen needs libclang for native-ossl-sys) |
| `krb5kdc`, `kdb5_util`, `kadmin.local`, `kinit` (MIT krb5 1.22 or later), MIT `pkinit.so` | `kdc-test`, `playground-test` and `interactive` (Fedora: `krb5-server krb5-workstation krb5-pkinit`; macOS: `brew install krb5`, whose keg `bin`/`sbin` the script puts first on `PATH`) |
| `python3` | `playground-test`, to render its report, and `bench`/`scripts/bench.sh`, to collect and compare results |
| `rustup` with the MSRV toolchain | `msrv` (`rustup toolchain install 1.89`) |
| `valgrind` | `--valgrind` only |
| `actionlint` (or `yamllint` as a fallback) | `lint-workflows`; skipped with a warning if neither is installed |
| Homebrew `heimdal` (macOS) | optional: a `KUIPA_KRB5_VENDOR=heimdal` build; the script adds only its `pkg-config` directory, never its `bin`, so the MIT KDC tools stay in front on `PATH` |

## Kerberos vendor

`KUIPA_KRB5_VENDOR=mit|heimdal` selects the Kerberos implementation the build
scripts compile against; unset or `auto` means MIT when both are installed.
The script validates the value up front — a typo fails before anything
compiles — and exports it, so every job in one run sees the same vendor.

The realms `kdc-test`, `playground-test` and `interactive` create are MIT
ones (`kdb5_util`, `kadmin.local`, MIT's `pkinit.so`), so a Heimdal build
cannot drive them: those three jobs report `SKIP` with that reason instead of
failing, and `interactive` — which is not a job — fails outright. Everything
else, including `test`, runs under either vendor.

```sh
KUIPA_KRB5_VENDOR=heimdal ./contrib/ci/local-ci.sh build clippy test
```

## Running CI jobs

```sh
./contrib/ci/local-ci.sh all                 # every job, in order
./contrib/ci/local-ci.sh build fmt clippy    # just these
./contrib/ci/local-ci.sh --list              # job names
```

| Job | What it runs | Depends on |
| --- | --- | --- |
| `build` | `cargo build --workspace --all-targets` | |
| `fmt` | `cargo fmt --all -- --check` | |
| `lint-workflows` | `actionlint` (or `yamllint`) on `.github/workflows/*.yml` | |
| `deps` | fails if any RustCrypto algorithm or primitive crate (`sha2`, `aes-gcm`, `hmac`, `ml-kem`, …) is in the dependency tree: cryptography comes from OpenSSL through native-ossl | |
| `clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` (includes the denied `incompatible_msrv` lint) | `build` |
| `doc` | `cargo doc --workspace --no-deps --all-features`, with `RUSTDOCFLAGS=-D warnings` | `build` |
| `test` | `cargo test --workspace --all-features`, without the real-KDC tests | `build` |
| `kdc-test` | `cargo test -p kuipa-tools --test kdc --test trust --test voucher` with `KUIPA_REQUIRE_KDC=1`, so missing KDC tools fail the job instead of skipping the tests; `SKIP` (not `FAIL`) under `KUIPA_KRB5_VENDOR=heimdal` | `build` |
| `playground-test` | starts the interactive playground, runs a scripted session in it with tracing on (`contrib/ci/playground/session.sh`), and renders it as `kuipa-playground-report/` (see below); `SKIP` under `KUIPA_KRB5_VENDOR=heimdal` | `build` |
| `msrv` (opt-in) | `cargo build --workspace --all-targets` with the `rust-version` toolchain | |
| `bench` (opt-in) | the criterion targets in quick mode under the `smoke` profile (`scripts/bench.sh --quick --no-save`): a fixture that no longer verifies panics, so this job doubles as a protocol self-check; it keeps no baseline, so it does not catch timing regressions (see [Benchmarks](../reference/benchmarks.md)) | `build` |

Dependencies are run on demand: `local-ci.sh clippy` builds first. Inside
CI, `--no-deps` turns that off because the workflow's `needs:` already
orders the jobs.

## The real-KDC test

`kdc-test` starts an ephemeral MIT realm (adapted from kurbu5-pkinit's
`tests/system/pkinit/setup.py`): `kdb5_util` creates the database,
`kadmin.local` the principals and keytabs, and `krb5kdc` listens on a Unix
socket under `/tmp/kuipa-kdc-<pid>/`, so several realms can run side by side
without ports. A test CA and a PKINIT KDC certificate are generated with
synta-certificate, so anonymous PKINIT works with MIT's own `pkinit.so`.
Two servers run the daemon's router and anchor exchange in the test
process; their syncs use real `ipa-ku/<fqdn>` keys from that realm. The
`trust` test starts two such realms, A and B, each with its own CA: B
invites A, A's server establishes the trust over HTTP (creating the
cross-realm keys in both KDCs), and a host of A gets armour from B's KDC
only with the PKINIT chain `kuipa trusted-realms` installed for B. The
`voucher` test issues blind-signed vouchers and enrolls hosts with them.

Set `KUIPA_KEEP_REALM=1` to keep the realm's files (configuration,
`kdc.log`, keytabs, ccaches) after the run.

## The playground session report

`playground-test` starts the same playground as `interactive` (below) and,
instead of a shell, runs `contrib/ci/playground/session.sh` in it. The
session uses the playground's helpers the way a person would, with
`KUIPA_TRACE=kuipa_tools=trace,kuipa_gssapi=debug`:

* an OTP join, `status`, a rekey and `check`;
* `protect`, `kuipa-unseal` and `unprotect`;
* a user's vaults: devices, sealing, the transparency log and witnesses,
  sessions, offline sessions;
* realm limits, a vault shared with bob, a break-glass vault bob and
  carol approve, bob's lost device recovered with a code and then
  through the helpdesk, and carol's and web1's deposits;
* signing files and a git commit;
* failover to ipa2;
* password, ticket, offline and voucher joins, and CI runners joined
  with leased vouchers opening a pipeline secret;
* the trusted realm B.TEST, with a ticket across the trust;
* the post-quantum Tang pin;
* a health check that must fail with both servers down.

Each step records its command, exit status (checked against the expected
one), duration, output, trace and the lines the servers logged during it.
A step can also name text its output must contain: the health check with
both servers down must report each of them as unreachable, not just fail
for any reason. A step that runs longer than `KUIPA_STEP_TIMEOUT` seconds
(default 120) is stopped and fails, and the session goes on, so the
playground is still torn down and the report still written. The
playground itself gets `KUIPA_PLAYGROUND_START_TIMEOUT` seconds (default
120) to start.
`contrib/ci/playground/report.py` renders them as one self-contained HTML
file: a summary; an overview of the sections, each a link with its first
sentence, its number of steps and time, and its failures, which is the
table of contents on narrow screens; an index of the steps in a sidebar on
wide ones; and, per step, the command and its output, with the trace and
the server log in collapsed panels (open for a failed step). It has no external assets and follows the light or dark
system theme. Each section also carries an animated terminal capture —
one SVG per section, under `svg/` — built from what the session recorded:
the commands typed with the prompt of the host the shell acted as, the
output flowing in (long steps collapse their middle lines), the text a
step had to show highlighted green and the reason a failed step failed in
red. `terminal.py` compiles the session into a JSON spec,
`render-terminal.mjs` renders it with [svg-terminal], and the captures
play once, when scrolled into view, with a replay button. They are
renderings of the recording, not a replay: no second run of the
playground, and the report is the same without them.

[svg-terminal]: https://github.com/williamzujkowski/svg-terminal

The script needs `node.js` and `npm` to install its dependencies:

```
$ cd contrib/ci/playground && npm i
```

If dependencies aren't installed, SVG captures will be skipped.

The report goes to `kuipa-playground-report/` in the repository, or
wherever `KUIPA_PLAYGROUND_REPORT` names: `index.html` plus the `svg/`
captures. In GitHub Actions the job uploads the directory as the
`kuipa-playground-report` artifact and adds the step table, the
failed steps' output and a link to the artifact to the run's Summary tab. The job fails when any step ends with an unexpected exit
status. When the docs are published with the report left at the
repository root by a CI run, it is also served next to this page, as
[the playground session report](playground-report/) — the report is
generated per run, so the link is live only while that build had one.
To add a step, add a `step EXPECTED "title" 'command' ["text"...]` line to
`session.sh`, under the `section` it belongs to; `EXPECTED` is an exit
status or `fail` for any non-zero one.

## Options

| Option | Effect |
| --- | --- |
| `--no-color` | no ANSI colours (also `NO_COLOR=1`) |
| `--no-deps` | do not run prerequisite jobs |
| `--valgrind` | run test binaries under Valgrind with `contrib/ci/rust-valgrind.supp` |
| `CARGO_TARGET_DIR=…` | build somewhere else |

## The interactive playground

```sh
./contrib/ci/local-ci.sh interactive [--hosts N] [--keep]
```

starts a throwaway realm and drops you into a bash shell inside it. Exiting
the shell (`exit`, Ctrl-D) tears everything down: servers, KDC, files.

### What it sets up

| Piece | Details |
| --- | --- |
| KDC | MIT `krb5kdc`, realm `EXAMPLE.TEST`, on a Unix socket (`$PQ_KDC_SOCKET`), PKINIT with a generated test CA, so anonymous PKINIT works |
| IPA servers | `ipa1.example.test` and `ipa2.example.test`: the daemon's real HTTP router (`kuipad::http`) and anchor exchange on local ports, each with its own anchor, ML-DSA signing key and ML-KEM join and escrow keys; they exchange anchors with their `ipa-ku/<fqdn>` keys before the shell starts, and the log shows each step; `KUIPA_ENDPOINTS` maps their names to the ports |
| DNS | a stub nameserver (`KUIPA_DNS`) with `_ldap._tcp.example.test` and `_ldap._tcp.b.test` SRV records, as FreeIPA publishes them, so `kuipa` commands find the servers without `--server` ([Servers and failover](../reference/design.md#46-servers-and-failover)) |
| Directory | shared by both servers: GSS-API tokens are accepted for real, passwords are checked against the KDC, keys come from the KDC (`kadmin.local ktadd`, standing in for `KEYTAB_GET`); OTPs, escrow registrations and staging are kept in memory |
| Pinned anchor | `$PQ_ANCHOR`, ipa1's anchor; every enrollment string pins it, and it vouches for ipa2's claim |
| Administrator | `admin@EXAMPLE.TEST`, password `Secret123` |
| Trusted realm | `B.TEST` (`$PQ_TRUSTED_REALM`): its own KDC on `$PQ_TRUSTED_KDC_SOCKET` with its own test CA, one server `ipa1.b.test` with its own anchor, and a user `alice@B.TEST` (password `Secret123`); `B.TEST` invites `EXAMPLE.TEST` and ipa1 establishes the trust before the shell starts ([Establishing the trust](../reference/design.md#174-establishing-the-trust)): both KDCs get the cross-realm `krbtgt` keys from the derived secret, and both `EXAMPLE.TEST` servers list `B.TEST` in `trusts` with its anchor |
| Tang | every server also serves post-quantum Tang ([Post-quantum Tang](../reference/design.md#115-post-quantum-tang)): its URL and pinned thumbprint are in `$KUIPA_PLAYGROUND/tang/<server>.url` and `.thp`, e.g. `curl -s "$(cat $KUIPA_PLAYGROUND/tang/ipa1.example.test.url)/adv"` |
| Voucher issuer | a voucher key and a quota of 100 in `$KUIPA_PLAYGROUND/voucher`; both servers accept the key ([Vouchers](../reference/design.md#9-vouchers)) |
| Hosts | OTP enrollment strings for `web1`…`webN.example.test` in `$KUIPA_PLAYGROUND/enroll/webN`; `$KUIPA_PLAYGROUND/enroll/realm` is the string without a secret |
| Tools | `kuipa`, `kuipa-unseal`, `kuipa-voucher`, `tang-pqc` and `kuipa-playground` on `PATH` |

Each host has its own client root (`KUIPA_ROOT`), so several "machines"
live in one shell; nothing touches the real system.

### Helpers

| Helper | Does |
| --- | --- |
| `pq_host NAME` | act as `NAME.example.test` from now on (sets `KUIPA_ROOT`, `PQ_HOST`, the prompt) |
| `pq_enroll NAME [opts]` | enroll `NAME` online with its OTP string |
| `pq_password NAME [opts]` | enroll `NAME` with the administrator's password, sealed in the PQ channel |
| `pq_bootstrap` | `kuipa realm-info`, anonymous PKINIT with the advertised anchors, then the armoured `kinit` of the administrator: what `ipa-client-install` does before `--use-ccache` |
| `pq_offline NAME` | `kuipa prepare`, staging with an admin ticket (`kuipa-playground stage`, standing in for `ipa host-add --pq-stage`), then `kuipa enroll --bundle` |
| `pq_voucher NAME [--bound] [opts]` | enroll a new host `NAME` with a voucher in host group `webservers`: blind it, have the issuer sign it, unblind it, show it, enroll; with `--bound` it is bound to an ephemeral key `kuipa voucher-key` makes for the host |
| `pq_tang [SERVER]` | the `tang-pqc` pin configuration (`{"url":…,"thp":…}`) for a server's Tang service (default ipa1): `echo secret \| tang-pqc encrypt "$(pq_tang)" > s.jwe; tang-pqc decrypt < s.jwe` |
| `pq_trust` | `kuipa trusted-realms` for the current host: install `B.TEST`'s anchors, PKINIT chain, CA and `krb5.conf.d` snippet, verified through `EXAMPLE.TEST` |
| `pq_trusted_kinit [USER]` | log in a `B.TEST` user on the current host (default `alice@B.TEST`; a bare name means `USER@B.TEST`): anonymous PKINIT armour from B's KDC with the installed chain, then an armoured `kinit`; refuses before `pq_trust`. The ticket and the configuration (the realm's plus the installed snippet, B's KDC pointed at its socket) stay in `$KUIPA_ROOT/trusted-login` |
| `pq_trusted CMD…` | run `CMD` with that user's ticket and configuration, e.g. `pq_trusted klist` or `pq_trusted kvno host/$PQ_HOST` (a ticket for this `EXAMPLE.TEST` host over the trust) |
| `pq_admin_kinit` | log in as the administrator with a kuipa data directory and runtime directory of their own, for `kuipa seal` |
| `pq_as USER CMD…` | run `CMD` as `bob` or `carol` (password `Secret123`), each with a ticket and a kuipa data directory of their own, for shared vaults, approvals and deposits: `pq_as bob kuipa seal list` |
| `pq_passkey [ALG] [--pin PIN]` | register a new IPA passkey (`mldsa65` by default; `es256`, `es384`, `eddsa`, `rs256`, `mldsa44`, `mldsa87`) on the logged-in user's software security key, as `ipa user-add-passkey --register` does, setting the key's PIN first with `--pin`. `pq_admin_kinit` and `pq_as` give each user a key of their own (`$KUIPA_SOFT_FIDO2`): the playground's `kuipa` is built with the `soft-fido2` feature, so it uses that file instead of attached FIDO2 keys. `kuipa-playground passkey --user-verification on\|off` stands in for `ipa passkeyconfig-mod` |
| `pq_token LABEL` | make an ML-KEM-768 key `LABEL` on the playground's software PKCS#11 token (kryoptic, token `kuipa`, PIN `1234`) and print its URI, for `kuipa seal device add VAULT --pkcs11 URI --module $PQ_TOKEN_MODULE` |
| `kuipa-playground recovery --vault OWNER/NAME [--required]` | name the realm's device escrow vault, as an administrator sets `cn=recovery,cn=kuipa,cn=etc`: new device keys are deposited there (`DESIGN-recovery.md` §4) |
| `pq_down SERVER` / `pq_up` | make a server unreachable from this shell, and back (for failover) |
| `pq_log [N]` | the servers' log |

`$PQ_SERVERS` expands to `--server ipa1.example.test --server ipa2.example.test`;
every `kuipa` command that talks to a server needs at least one `--server`.
`KUIPA_ENROLLMENT_FILE` points at the realm's enrollment string without a
secret, so `kuipa realm-info $PQ_SERVERS --krb5-dir DIR`, ticket and
password joins and bundles need nothing typed; outside the playground,
`kuipa` prompts for the enrollment string (and a password without echo)
when standard input is a terminal.

### Recipes

[A traced session](../scenarios/walkthrough.md) follows the scripted
session `playground-test` records — every section of it, from OTP
enrollment through keytab and file protection, vaults, failover, offline
and voucher enrollment, auditing, mirroring, the trusted realm, Tang,
replica promotion and reported failure — with `KUIPA_TRACE` on, and
explains every traced step.

```sh
pq_enroll web1                  # OTP join through ipa1
kuipa status
kuipa rotate-keys --verbose    # every request, answer, decision and file on stderr
                                # (--trace for details, KUIPA_TRACE for filters)
kuipa rotate-keys              # rekey authenticated by the host keytab
kuipa check
kuipa protect                  # seal the keytab to both servers' escrow keys
kuipa-unseal                   # what the boot unit runs
kuipa unprotect

pq_down ipa1; pq_enroll web2; pq_up      # fails over to ipa2 (see "issuer"), which
                                         # carries ipa1's anchor through the exchange
kuipa status                            # both servers' anchors stored

pq_password web3                         # -p admin -w, without Kerberos on the host

pq_bootstrap                             # FAST armour from the advertised PKINIT anchors
pq_host web4
kuipa enroll $PQ_SERVERS --hostname $PQ_HOST --use-ccache

pq_host web1; pq_trust                   # install the trusted realm B.TEST on web1
pq_trusted_kinit                         # alice@B.TEST, armoured with B's PKINIT chain
pq_trusted kvno host/$PQ_HOST            # a ticket for web1 across the trust
kuipa status                            # trusted realms installed: B.TEST

pq_voucher web7                          # a blind-signed voucher instead of an OTP
pq_voucher web8 --bound                  # bound to web8's ephemeral key

pq_offline web5                          # bundle enrollment, no network needed
kuipa status                            # an unfinished offline enrollment, with its deferred steps
kuipa complete                          # first contact: the staged keys are rotated
pq_log                                   # "first contact: … unstaged"
```

Things to try that should fail:

* `pq_enroll web1` again — the OTP is consumed;
* `pq_voucher web7` again — a voucher creates only a host that does not
  exist yet;
* `pq_down ipa1; pq_down ipa2; pq_enroll web6` — exit status 75, retry later;
* `pq_trusted_kinit` on a host where `pq_trust` has not run — no `B.TEST`
  configuration, so no armour;
* editing a byte of `$KUIPA_ROOT/bundle` before `kuipa enroll --bundle`.

`--keep` (or `KUIPA_KEEP_REALM=1`) keeps the realm's directory
(`/tmp/kuipa-playground-<pid>`: KDC configuration and log, keytabs, ccaches,
host roots) after exit.
