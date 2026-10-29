# Fedora Packaging for kuipa

This directory builds the Fedora RPMs for the kuipa workspace: a hand-maintained
spec, the scripts that prepare its sources, and a vendor tarball (bundled
build) for the crates Fedora does not ship at the locked versions.

`kuipa.spec.in` is the maintained file.  `kuipa.spec` is generated from it by
`make spec` and is never committed.  `rust2rpm` cannot produce a spec for a
Cargo workspace — it requires a `.crate` archive and rejects a workspace
`Cargo.toml` — so there is no `rust2rpm.toml` here.

## Quick Start

```sh
sudo dnf install rpm-build rpmlint mock rust-cargo-vendor-filterer

make sources     # source tarball + vendor tarball   [needs network]
make srpm        # kuipa-<version>-1.<date>.git<sha>.fcNN.src.rpm
make mock        # rebuild that SRPM in a clean chroot
```

`make mock` uses `MOCK_CONFIG=fedora-rawhide-x86_64` unless overridden
(`make mock MOCK_CONFIG=fedora-45-x86_64`).  For mock builds, add your user to
the `mock` group:

```sh
sudo usermod -aG mock $USER   # then log out and back in
```

Build from a tag instead of the working tree:

```sh
make sources GIT_REF=v0.1.0
make srpm    GIT_REF=v0.1.0
```

Snapshot builds put the commit date and short SHA in `Release:`
(`1.<YYYYMMDDHHMM>.git<sha>%{dist}`); `GIT_REF=v0.1.0` gives a build tied to
that tag.  Nothing is published anywhere by these targets.

## Make Targets

| Target | Description |
|---|---|
| `sources` | Source tarball + vendor tarball |
| `tarball` | `git archive` of `GIT_REF` (default: `HEAD`) |
| `vendor` | Filtered vendor tarball + `system-crates.txt` |
| `spec` | Generate `kuipa.spec` from `kuipa.spec.in` with the snapshot identifiers |
| `srpm` | Build the SRPM in this directory |
| `mock` | Rebuild the SRPM in mock, with the `abbra/rust-deps` repo added |
| `lint` | `rpmlint` on the generated spec |
| `check-deps` | Report which `Cargo.lock` crates exist as system RPMs |
| `copr-build` | Submit the SRPM to COPR (`COPR=owner/project` required) |
| `clean` | Remove generated sources and the generated spec |

Two build switches, for `rpmbuild` and `mock --with/--without`:

| Switch | Default | Effect |
|---|---|---|
| `check` | on | skip `%check` (the test suite) |
| `clevis` | on | skip the `tang-pqc` Clevis pin and its dracut module |

## Subpackages

| Package | Contents |
|---|---|
| `kuipa` | host-side binaries (`/usr/sbin/kuipa`, `/usr/libexec/kuipa-unseal`, `/usr/bin/kuipa-{voucher,witness,audit,mirror,gitsign}`), the unseal / client-complete / rotate units and timer, and the gssproxy keytab snippet example |
| `kuipa-server` | `/usr/libexec/kuipad`, its socket-activated units, the httpd snippet `conf.d/kuipa.conf`, and `ipa/kuipad.json.example` |
| `tang-pqc` | the post-quantum Tang client |
| `clevis-pin-tang-pqc` | the `clevis-*-tang-pqc` pin links and the dracut module (noarch; `rpmbuild --without clevis` skips it) |

## Subpackage layout and binaries

`%install` copies the built binaries out of `target/rpm/` explicitly instead of
using `%cargo_install`: Fedora's Rust packaging guidance is that a workspace of
binaries installs its own files, which also lets the spec place root-only
programs (`kuipa`, `kuipa-unseal`, `kuipad`) in `/usr/sbin` or `/usr/libexec`
and user commands in `/usr/bin`.

## Bundled dependencies and `bundled(crate())`

The vendor tarball is self-sufficient — every crate source it needs is inside,
so one SRPM builds across Fedora versions even where an older release ships
different crate versions.

1. `cargo-vendor-filterer` drops what never compiles on Fedora Linux
   (Windows/macOS/WASM/Redox crates, and `tests/`+`benches/` inside the rest).
   Flags are in the `vendor` target.
2. `filter-vendor-fedora.sh` records into `system-crates.txt` (SRPM `Source10`)
   the crates Fedora ships at the *exact* locked version.  Crate directories
   stay in `vendor/`: they are the fallback for a Fedora that ships another
   version.
3. `%generate_buildrequires` emits `crate()` BuildRequires from
   `system-crates.txt`, so the system crate package is installed when this
   Fedora has it.
4. `%build` builds everything from `vendor/` — the system crate copies are not
   substituted, because Fedora patches the `Cargo.toml` of its crate packages
   and `cargo --locked` then rejects the metadata mismatch against `Cargo.lock`.
5. `%build` then writes `cargo-vendor.txt` (`%cargo_vendor_manifest`) and keeps
   only the `(name, version)` pairs that appear in the linked dependency graph,
   computed in the same buildroot with `cargo tree -e normal,build`.  Bench
   dev-dependencies (criterion and its plotters/rayon chain), test-only crates
   (`synta-krb5`, the DoT/DoH test server) and any remaining platform-only
   crates are therefore absent from `bundled(crate())`.  Deriving the list from
   the graph means a dependency change cannot leave a stale hand-written list.
   `rand` and `ring` never appear at all: `[patch.crates-io]` maps them to
   `shims/rand` and `shims/ring`, which are in-tree path dependencies from
   Source0, not vendored crates.

## Crates that must come from COPR

`native-ossl`, `native-ossl-sys`, `ring-native-ossl`, `rustls-native-ossl`,
`synta*`, `agirru-*` are not in Fedora: they are built in COPR
[abbra/rust-deps](https://copr.fedorainfracloud.org/coprs/abbra/rust-deps/),
which is an Additional repo of [abbra/pqc](https://copr.fedorainfracloud.org/coprs/abbra/pqc/).
`make mock` adds that repo to the chroot with `--addrepo`, using the URL whose
path is `MOCK_CONFIG` (rust-deps publishes one repo per chroot name), so no
chroot config needs editing.  A `MOCK_CONFIG` that is not a COPR chroot name
needs its own `RUST_DEPS_REPO=`.

COPR builds need the same crates: they arrive through abbra/pqc's Additional
repo, which is why `make copr-build COPR=abbra/pqc` needs no extra setup.

## File inventory

| File | Purpose |
|---|---|
| `kuipa.spec.in` | the maintained spec, with snapshot placeholders |
| `Makefile` | source preparation, SRPM/mock/COPR workflow |
| `filter-vendor-fedora.sh` | writes `system-crates.txt` for the crates Fedora ships at the locked version |
| `check-crate-deps.sh` | advisory report: which `Cargo.lock` crates have system RPMs, which are missing |

## Submitting to COPR

```sh
make copr-build COPR=abbra/pqc
```

`abbra/pqc` already carries `abbra/rust-deps` as an Additional repo, so the
crate prerequisites resolve there.  Submission is always an explicit action: no
target publishes anything on its own.
