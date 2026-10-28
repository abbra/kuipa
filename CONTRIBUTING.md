# Contributing to kuipa

Thank you for your interest in contributing to kuipa.  This document describes
everything you need to know: how to set up a development environment, the
contribution workflow, what we expect from licensing and sign-off, how to run
the same checks that CI runs, and how to write good commit messages.

## Licensing and Sign-off

### Licence

kuipa is licensed under **GPL-3.0-or-later**.  By submitting a contribution you
agree that your work will be made available under those same terms and that you
have the right to do so.

### Developer Certificate of Origin

kuipa uses the [Developer Certificate of Origin (DCO)](https://developercertificate.org/)
instead of a Contributor Licence Agreement (CLA).  Every commit must carry a
`Signed-off-by` trailer certifying that you wrote the code or have the right
to submit it under the project licence.

Add the sign-off with the `-s` flag when committing:

```bash
git commit -s
```

This appends a line like the following to your commit message:

```
Signed-off-by: Jane Smith <jane@example.com>
```

Commits without a `Signed-off-by` line will not be accepted.  If you are
contributing on behalf of an employer, ensure your employer permits open-source
contributions before submitting.

### AI-assisted contributions

AI coding tools (such as GitHub Copilot, Claude, or similar) may be used to
assist with writing code, tests, and documentation.  The following rules apply:

- **You are responsible for everything you submit.**  Review, understand, and
  test any AI-generated content before including it in a PR.  Submitting
  output you cannot explain or vouch for is not acceptable.
- **The DCO sign-off still applies.**  Signing off with `git commit -s`
  certifies that you have the right to submit the contribution and that you
  understand its content — regardless of how it was produced.
- **All CI checks must pass.**  AI-generated code is subject to the same
  quality bar as hand-written code: `cargo fmt`, `clippy -D warnings`, tests,
  and documentation builds.
- **Disclose AI assistance in the PR description** when a significant portion
  of the contribution was generated or substantially rewritten by an AI tool.
  A brief note is sufficient; the goal is transparency, not restriction.

---

## Contribution Workflow

The canonical repository is at
[github.com/abbra/kuipa](https://github.com/abbra/kuipa).
Pull requests should target the `main` branch.

### 1. Fork and clone

Fork the repository, then clone your fork:

```bash
git clone https://github.com/<your username>/kuipa
cd kuipa
git remote add upstream https://github.com/abbra/kuipa.git
```

### 2. Create a branch

Always work on a dedicated branch, not directly on `main`:

```bash
git fetch upstream
git checkout -b my-feature upstream/main
```

Choose a short, descriptive branch name (`fix-shard-wordlist`,
`recovery-shards-in-header`, `tang-pqc-kem-in-share`, etc.).

### 3. Make your changes

Implement your change and add tests (see [Writing Tests](#writing-tests)).
Keep each commit focused on a single concern; avoid bundling unrelated fixes
in the same PR.

### 4. Run local CI

Run the full CI suite before pushing to catch problems early:

```bash
./contrib/ci/local-ci.sh all
```

See [Running CI Locally](#running-ci-locally) for details on individual jobs
and flags.

### 5. Commit

Use `git commit -s` to sign off each commit.  Follow the
[commit message conventions](#commit-message-conventions) described below.

### 6. Open a pull request

Push your branch and open a pull request against `abbra/kuipa:main`:

```bash
git push origin my-feature
```

Then open a PR.  In the PR description:

- Summarise what the change does and why.
- Reference any related issues with `Fixes #NNN` or `See #NNN`.
- Mention if the change is a breaking API change.

The CI pipeline runs automatically on every PR.  All jobs must pass before
a PR can be merged.

### 7. Review and merge

A maintainer will review your PR.  If changes are requested:

- Push additional commits; do not force-push (it makes review history harder
  to follow).
- Mark review comments as resolved after addressing them.

Once the PR is approved and CI is green it will be merged.

---

## Commit Message Conventions

kuipa uses
[Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) with a
scope in parentheses:

```
<type>(<scope>): <short description>

<optional body — wrap at 72 characters>

Fixes: https://github.com/abbra/kuipa/issues/<number>

Signed-off-by: Jane Smith <jane@example.com>
```

`Fixes:` is optional; include it when the commit resolves a particular issue.
Use the full URL so the reference is unambiguous in any context.  Multiple
`Fixes:` lines are allowed when a commit addresses several issues.

`Signed-off-by:` is required on every commit (see
[Developer Certificate of Origin](#developer-certificate-of-origin)).
Add it with `git commit -s`.

**Types:**

| Type | When to use |
|---|---|
| `feat` | New feature or capability |
| `fix` | Bug fix |
| `perf` | Performance improvement |
| `refactor` | Restructuring without behaviour change |
| `test` | Adding or fixing tests |
| `docs` | Documentation only |
| `ci` | CI configuration |
| `build` | Build system / dependency changes |
| `chore` | Maintenance tasks that don't fit elsewhere |

**Scope** is the crate (`kuipa-enroll`, `kuipad`, `tang-pqc`, …) or the
subsystem (`playground`, `docs`, `ci`) affected.

**Example:**

```
feat(kuipa-enroll): record the recovery KEM in the shard header

Device escrow deposits need to be decoded offline, so the share header
now carries the ML-KEM encapsulation the shard was made against.

Fixes: https://github.com/abbra/kuipa/issues/123

Signed-off-by: Jane Smith <jane@example.com>
```

Keep the subject line under 72 characters and written in the imperative mood
("add", "fix", "remove" — not "added", "fixes", "removing").

---

## Code Style

### Rust

**Formatting** is enforced by `rustfmt` with the project defaults (no
`rustfmt.toml`).  Run before committing:

```bash
cargo fmt --all
```

CI fails if any file would be reformatted.

**Linting** is enforced by Clippy with all warnings treated as errors:

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

The workspace `[lints]` table sets `unsafe_code = "forbid"`,
`missing_docs = "warn"`, clippy `pedantic`, and `incompatible_msrv = "deny"`,
which catches standard-library APIs newer than the MSRV.  Crates that carry
`unsafe` lower it to `deny` and document where it is used: `kuipa-tools`
sets `KRB5_CONFIG` before any thread starts, `ml-dsa-zk` calls the
carry-less multiply, and the three FFI crates (`kuipa-gssapi`,
`kuipa-ldap`, `kuipa-fido2`) carry no `[lints]` table at all.  Fix every
diagnostic before opening a PR.  If a lint is a false positive, suppress it
with `#[allow(...)]` on the smallest possible scope and add a comment
explaining why.

**API documentation** is enforced with `RUSTDOCFLAGS=-D warnings`:

```bash
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --all-features
```

Public items must have doc comments.  The `doc` job also compiles every man
page in `docs/man/` with `scdoc` and builds the book in `docs/` with mdbook.

**Style guidelines:**

- Prefer zero-copy types (`&[u8]`, `&str`) over owned equivalents where the
  API permits it.
- Avoid unnecessary heap allocations on hot paths; the criterion targets in
  `kuipa-enroll`, `ml-dsa-blind` and `kuipa-perf` catch regressions.
- Use `#[derive(Debug, Clone, PartialEq)]` on public types where appropriate.
- Prefer `impl Trait` in argument position over generic bounds for readability
  when there is only one trait bound.
- Error types should implement `std::error::Error` and be non-exhaustive
  (`#[non_exhaustive]`) when public.

We recommend using agentic skills like https://github.com/morganlinton/BeautifulRust

### Python and JavaScript

The Python helpers under `contrib/ci/playground/` and `scripts/` are plain
Python 3 with no linting or formatting job; keep them dependency-free so
`local-ci.sh` runs on a stock Fedora install.  `contrib/ci/playground/*.mjs`
is used only to render the session report; its dependencies come from
`npm ci` in that directory and are not committed.

---

## Development Environment

The reference platform is **Fedora**: every CI job runs in the
`quay.io/fedora/fedora:45` container, and the packaging names below are the
Fedora ones.  The workspace builds on Debian/Ubuntu and macOS too, but CI
only tests Fedora, so a distribution mismatch is your problem to fix.

### Required tools

| Tool | Notes |
|---|---|
| **Bash 4+** | Required by `contrib/ci/local-ci.sh` and the other shell scripts. macOS ships bash 3.2; install a newer one with `brew install bash`. Each script checks the version on startup and exits with an error on bash 3 or earlier. |
| **Rust 1.89 or later** | The MSRV, from `rust-version` in the workspace `Cargo.toml`. Fedora's `cargo`/`rust` packages or [rustup](https://rustup.rs/); the `fmt` and `clippy` jobs need `rustfmt` and `cargo-clippy` too. |
| **OpenSSL 3.5 or later** | The only crypto backend: `native-ossl` wraps it, and ML-KEM/ML-DSA come from it. `openssl-devel` provides the headers and the `.pc` file `native-ossl-sys` looks for. |
| **MIT Kerberos** | `kuipa-gssapi`'s build script probes the `krb5-gssapi`/`mit-krb5-gssapi` pkg-config packages and static-asserts the FFI layouts against the installed headers. Kuipa relies on MIT extensions (`gss_acquire_cred_from`, S4U2Proxy, the responder API); Heimdal builds work for everything except the KDC jobs. |
| **OpenLDAP** | `kuipa-ldap` links `libldap` for the directory access `kuipad` uses over LDAPI. |
| **libfido2** | `kuipa-fido2` probes the `libfido2` pkg-config package. Passkeys with ML-DSA need a libfido2 with PQC support — on Fedora, the `abbra/pqc` COPR build. |
| **C compiler, libclang, pkg-config** | `gcc` (or `clang`) and `make`; `native-ossl-sys` runs bindgen, which needs libclang. |

On Fedora:

```bash
sudo dnf copr enable abbra/pqc            # PQC libfido2, kryoptic
sudo dnf install cargo rust rustfmt cargo-clippy gcc \
    openssl-devel krb5-devel openldap-devel libfido2-devel \
    clang-libs clang-devel pkgconf-pkg-config
```

CI installs the same set plus the packages named in the table below; see
`.github/workflows/ci.yml` (`DNF_PACKAGES`) for the authoritative list.

### Optional tools

| Tool | Needed for |
|---|---|
| `krb5kdc`, `kdb5_util`, `kadmin.local`, `kinit`, MIT `pkinit.so` | `kdc-test`, `playground-test`, `interactive` — an ephemeral MIT realm. Fedora: `krb5-server krb5-workstation krb5-pkinit`. |
| `python3` | `playground-test` (renders the session report) and `scripts/bench.sh` (collects and compares results). |
| `nodejs`/`npm` | `playground-test`'s animated terminal captures (`npm ci` in `contrib/ci/playground/`); GitHub Actions also needs node to run its own checkout/cache actions. |
| `opensc`, `pkcs11-provider` ≥ 1.2, `kryoptic` | the PKCS#11 device path of the `kdc` test and the playground's `pq_token`; ML-KEM keys on a token need pkcs11-provider 1.2, hence Fedora 45. |
| `scdoc` | the `doc` job's man pages; skipped with a warning when absent. |
| `mdbook` (+ `mdbook-mermaid`) | the `doc` job's book; skipped with a warning when absent. |
| `rustup` with the 1.89 toolchain | the opt-in `msrv` job. |
| `valgrind` | `--valgrind` only. |
| `actionlint` (falls back to `yamllint`) | `lint-workflows`; skipped with a warning if neither is installed. |

`git-core` is needed by the playground's commit-signing session step.

### No RustCrypto

Cryptography comes from OpenSSL through `native-ossl`: the `deps` CI job
fails if any RustCrypto algorithm or primitive crate (`sha2`, `aes-gcm`,
`hmac`, `ml-kem`, `ml-dsa`, `signature`, …) appears in the dependency tree.
Where a third-party crate insists on one, the workspace patches it out —
`shims/rand` and `shims/ring` implement the parts of those APIs that
hickory-resolver uses on top of OpenSSL.  Add a shim, don't add the crate.

### Kerberos vendor

`KUIPA_KRB5_VENDOR=mit|heimdal` selects the implementation the build scripts
compile against (`auto`/unset prefers MIT).  The realm-based jobs always need
MIT, so they report `SKIP` rather than `FAIL` under a Heimdal build.

---

## Running CI Locally

`contrib/ci/local-ci.sh` mirrors `.github/workflows/ci.yml`: every workflow
job is one `local-ci.sh --no-deps <job>` call, so a job that passes locally
passes in CI with the same packages.

```bash
./contrib/ci/local-ci.sh all                 # every job, in order
./contrib/ci/local-ci.sh fmt clippy          # just these
./contrib/ci/local-ci.sh --list              # job names
./contrib/ci/local-ci.sh interactive         # throwaway realm + shell
KUIPA_KRB5_VENDOR=heimdal ./contrib/ci/local-ci.sh build clippy test
CARGO_TARGET_DIR=/tmp/kuipa-target ./contrib/ci/local-ci.sh all
```

| Job | What it runs | Needs |
|---|---|---|
| `build` | `cargo build --workspace --all-targets` | — |
| `fmt` | `cargo fmt --all -- --check` | — |
| `lint-workflows` | `actionlint` (or `yamllint`) on `.github/workflows/*.yml` | — |
| `deps` | fails if any RustCrypto crate is in the dependency tree | — |
| `clippy` | `cargo clippy --workspace --all-targets --all-features -- -D warnings` | `build` |
| `doc` | `cargo doc --workspace --no-deps --all-features` with `RUSTDOCFLAGS=-D warnings`, then `scdoc` on `docs/man/*.scd` and the mdbook in `docs/` | `build` |
| `test` | `cargo test --workspace --all-features`, without the real-KDC tests | `build` |
| `kdc-test` | `cargo test -p kuipa-tools --test kdc --test trust --test voucher` with `KUIPA_REQUIRE_KDC=1` | `build`, MIT KDC tools |
| `playground-test` | a scripted session in the playground (`contrib/ci/playground/session.sh`), rendered as `kuipa-playground-report/` | `build`, MIT KDC tools, `python3`, `node` |
| `msrv` (not in `all`) | `cargo build --workspace --all-targets` with the `rust-version` toolchain | `rustup` + that toolchain |
| `bench` (not in `all`, not in CI) | the criterion targets in quick `smoke` profile: `scripts/bench.sh --quick --no-save` | `build`, `python3` |

Prerequisites run on demand — `local-ci.sh clippy` builds first.  In CI,
`--no-deps` turns that off because the workflow's `needs:` orders the jobs.
`--valgrind` runs the test binaries under Valgrind with
`contrib/ci/rust-valgrind.supp`.  `docs/src/development/local-ci.md` is the
full reference: options, the realm `kdc-test` and `interactive` build, and
every playground helper.

---

## Workspace Structure

The repository is a Cargo workspace (`crates/`, plus two dependency shims in
`shims/`):

| Crate | Purpose |
|---|---|
| `kuipa-enroll` | The kuipa protocol and key schedule: enrolments, seals, escrow, vouchers, trusts, the shard codec. Everything protocol-level lives here. |
| `kuipad` | The server daemon behind httpd: the `/ipa/ku/` HTTP router, the CRDT state (`agirru`), the directory over LDAPI. |
| `kuipa-tools` | The client binaries in `src/bin/`: `kuipa`, `kuipa-unseal`, `kuipa-voucher`, `kuipa-witness`, `kuipa-audit`, `kuipa-mirror`, `kuipa-gitsign`; the `kuipa-playground` example the playground runs; and the flow/DNS/CLI tests. |
| `kuipa-gssapi` / `kuipa-ldap` / `kuipa-fido2` | Hand-written FFI: GSS-API (MIT and Heimdal), OpenLDAP, libfido2. These carry no `[lints]` table, so they may use `unsafe`. |
| `tang-pqc` / `tang-pqc-clevis` | Post-quantum Tang escrow (ML-KEM + RFC 9964 ML-DSA JWS) and its client / Clevis pin. Standalone: no FreeIPA dependency. |
| `ml-dsa-blind` | Blind ML-DSA signing through OpenSSL external-mu. Standalone. |
| `ml-dsa-zk` | VOLE-in-the-head ZK proofs over boolean circuits, a research prototype toward unlinkable blind signatures. |
| `kuipa-perf` | Benchmark and test fixtures: synthetic realms, keytabs, CAs. Not published; a dev-dependency, never a runtime one. |
| `shims/rand`, `shims/ring` | The `rand` and `ring` APIs hickory needs, backed by OpenSSL; patched in through `[patch.crates-io]`. |

When adding a feature, decide which crate it belongs in: protocol changes go
to `kuipa-enroll`, wire-visible behaviour tests to `kuipa-tools/tests/`, and
anything reusable outside kuipa stays free of the FreeIPA crates (follow
`tang-pqc` or `ml-dsa-blind`).

---

## Writing Tests

### Rust unit and integration tests

Tests live alongside the code they test in `#[cfg(test)]` modules, or as
integration tests in a crate's `tests/` directory — `flows.rs`, `kdc.rs`,
`trust.rs`, `voucher.rs`, `dns.rs` and `cli.rs` in `kuipa-tools` cover the
client behaviour end to end against an in-process server, and
`kuipa-enroll/tests/end_to_end.rs` the protocol.

```bash
cargo test -p tang-pqc
cargo test -p kuipa-enroll --all-features
cargo test --workspace --all-features          # what CI runs, minus the KDC tests
```

The real-KDC tests (`--test kdc`, `--test trust`, `--test voucher`) skip
themselves unless the MIT KDC tools are installed; `KUIPA_REQUIRE_KDC=1`
turns those skips into failures, which is what the `kdc-test` job sets.
Anything else in the suite must not depend on a KDC, a network, or a
plausible wall clock.

Fixtures come from `kuipa-perf`: it synthesizes realms, keytabs, anchors and
certificates from a fixed seed, and every key from OpenSSL, so a broken
fixture panics during setup instead of producing a wrong result.  Prefer it
over hand-written bytes.

### Protocol model

The core exchange is modelled in `contrib/tamarin/kuipa.spthy` and
`contrib/tamarin/tang-pqc.spthy`.  A change to the wire format or the key
schedule must be reflected there and proved with
`tamarin-prover --prove contrib/tamarin/kuipa.spthy`; CI does not run the
prover, so run it yourself when a change touches the protocol.

---

## Documentation

### Rust API docs

Public items must have `///` doc comments (`missing_docs` warns workspace-wide
and the `doc` job builds with `RUSTDOCFLAGS=-D warnings`).  Examples in doc
comments are compiled and type-checked; if an example is intentionally
incomplete, mark it `no_run` or `ignore`.

### The book and the man pages

Narrative documentation lives in `docs/src/` (mdbook; `docs/src/SUMMARY.md`
is its table of contents), and the manual pages in `docs/man/*.scd`
(scdoc).  The `doc` job builds both: a broken include, a missing SUMMARY
entry or a man page that does not compile fails it.  Design documents —
`docs/DESIGN*.md` — are where protocol decisions are recorded: if your
change alters the wire format, the key schedule or the escrow rules, update
the relevant design document in the same PR.

---

## Benchmarks

Criterion targets live in the crate whose code they measure (`crypto`,
`protocol`, `anchors`, `escrow` in `kuipa-enroll`, `blind` in
`ml-dsa-blind`, `certs` in `kuipa-perf`); `scripts/bench.sh` runs them,
collects the estimates, and stores them next to the fixture sizes that
produced them.

```bash
./contrib/ci/local-ci.sh bench                 # smoke pass: does everything still verify
scripts/bench.sh --profile production          # a real run, saved to ~/.cache/kuipa-bench
scripts/bench.sh compare <before> <after>      # compare two stored runs
```

When contributing a performance improvement:

1. Run the relevant target before and after your change on the same machine
   under the same conditions (`--compare` on the stored run).
2. Include the comparison in your PR description.
3. Ensure the `bench` job still passes — a fixture that no longer verifies
   panics there.

`docs/src/reference/benchmarks.md` documents the profiles, targets and how to
read the numbers.

