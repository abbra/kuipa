# Makefile — helpers for preparing Fedora package sources and building SRPMs.
#
# Quick start:
#   make sources   # create all source files (tarball + vendor; needs network)
#   make spec      # generate kuipa.spec from kuipa.spec.in
#   make srpm      # build an SRPM in the current directory (no ~/rpmbuild needed)
#   make mock      # rebuild the SRPM in a clean mock chroot
#
# Override GIT_REF to build from a tag:
#   make sources GIT_REF=v0.1.0
#
# Requires: git, cargo, cargo-vendor-filterer, rpmbuild
# For 'mock': the mock package and your user in the 'mock' group
#   sudo usermod -aG mock $$USER   (then log out and back in)
# For 'copr-build': copr-cli configured with your API token
#
# rust2rpm cannot generate a spec for this workspace: it requires a .crate
# archive and rejects a workspace Cargo.toml.  kuipa.spec.in is therefore the
# maintained spec, and 'make spec' only fills in the snapshot release
# identifiers.

# Enable pipefail so that a failed 'git archive | gzip' pipe is not silently
# swallowed (gzip always exits 0, which would leave an empty .tar.gz behind).
SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c

# Delete the target file when a recipe exits with a non-zero status.
.DELETE_ON_ERROR:

SPEC_IN  := kuipa.spec.in
SPEC_OUT := kuipa.spec

# Absolute path to the repository root (two levels above this Makefile).
REPOROOT := $(abspath $(dir $(abspath $(lastword $(MAKEFILE_LIST))))/../..)

# NAME and VERSION come from the workspace manifest, not from the spec header,
# so a stale spec.in cannot produce a mis-named tarball.
NAME    := kuipa
VERSION := $(shell python3 -c \
    "import tomllib; print(tomllib.load(open('$(REPOROOT)/Cargo.toml','rb'))['workspace']['package']['version'])")

TARBALL        := $(NAME)-$(VERSION).tar.gz
VENDOR_TARBALL := $(NAME)-$(VERSION)-vendor.tar.gz

CHECKDEPS    := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))check-crate-deps.sh
FILTERVENDOR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))filter-vendor-fedora.sh

SYSTEM_CRATES := system-crates.txt

# Systemd units and the daemon config template: plain files in contrib/,
# copied into _sourcedir by 'make srpm' and referenced as Source2..Source8 by
# the spec.  contrib/kuipa.conf stays out: it is a manual-install snippet
# (docs/src/realm/deploy.md), and an IPA server ships its own /ipa/ku/ proxy.
EXTRA_SOURCES := kuipad.service kuipad.socket kuipa-unseal.service \
                 ipa-client-complete.service kuipa-rotate.service \
                 kuipa-rotate.timer kuipad.json.example

# Git ref used for the tarball and the snapshot release identifiers.
# Defaults to HEAD so snapshots reflect the current branch tip.
# Override to a release tag for stable builds:
#   make sources GIT_REF=v0.1.0
GIT_REF ?= HEAD

# Snapshot release identifiers derived from GIT_REF.
SNAPDATE   := $(shell git -C "$(REPOROOT)" log -1 --format=%cd --date=format:%Y%m%d%H%M $(GIT_REF) 2>/dev/null)
SNAPCOMMIT := $(shell git -C "$(REPOROOT)" rev-parse --short $(GIT_REF) 2>/dev/null)
RELEASE    := 1.$(SNAPDATE).git$(SNAPCOMMIT)

# Mock chroot for 'make mock'.
# Override on the command line:  make mock MOCK_CONFIG=fedora-44-x86_64
MOCK_CONFIG ?= fedora-rawhide-x86_64

# ──────────────────────────────────────────────────────────────────────────────

.PHONY: all sources tarball vendor spec srpm mock lint check-deps copr-build clean help

all: sources

help:
	@echo "Targets:"
	@echo "  sources     create the source and vendor tarballs"
	@echo "  tarball     create $(TARBALL) from GIT_REF=$(GIT_REF)"
	@echo "  vendor      create $(VENDOR_TARBALL) + $(SYSTEM_CRATES)  [needs network]"
	@echo "  spec        generate $(SPEC_OUT) from $(SPEC_IN)"
	@echo "  srpm        build SRPM (Release: $(RELEASE)%{?dist})"
	@echo "  mock        rebuild SRPM in mock chroot (MOCK_CONFIG=$(MOCK_CONFIG))"
	@echo "  lint        run rpmlint on the generated $(SPEC_OUT)"
	@echo "  check-deps  report which Cargo.lock crates are available as system packages"
	@echo "  copr-build  submit the SRPM to COPR  (COPR=project required)"
	@echo "              example: make copr-build COPR=abbra/pqc"
	@echo "  clean       remove generated sources and the generated spec"
	@echo ""
	@echo "Snapshot: GIT_REF=$(GIT_REF)  date=$(SNAPDATE)  commit=$(SNAPCOMMIT)"
	@echo ""
	@echo "Prerequisite for 'mock' and 'copr-build': the crates the spec names"
	@echo "explicitly (native-ossl*, synta*, agirru*, hickory-resolver,"
	@echo "rustls-platform-verifier) must be in the buildroot.  COPR abbra/rust-deps"
	@echo "is configured as an Additional repo of abbra/pqc, where they are built."

# ══════════════════════════════════════════════════════════════════════════════
# SOURCE PREPARATION
# ══════════════════════════════════════════════════════════════════════════════

sources: tarball vendor

# ── tarball ───────────────────────────────────────────────────────────────────
# The whole tree at GIT_REF, including shims/rand and shims/ring: both
# [patch.crates-io] entries are path dependencies, and cargo vendor does not
# vendor path or workspace members.

tarball: $(TARBALL)

$(TARBALL):
	@echo "==> Creating $@ from $(GIT_REF)"
	git -C "$(REPOROOT)" archive \
	    --prefix=$(NAME)-$(VERSION)/ \
	    $(GIT_REF) \
	| gzip -9 > $@

# ── vendor ────────────────────────────────────────────────────────────────────
#
# cargo-vendor-filterer replaces plain 'cargo vendor' and drops crates that are
# never compiled on Fedora Linux:
#   --platform='*-unknown-linux-gnu'   — no Windows/macOS/WASM/Redox crates
#   --tier=2                          — no sub-tier-2 platforms
#   --all-features                    — resolve with every feature enabled, so
#                                       kuipa-enroll's 'tls' feature deps are in
#                                       the tarball too
#   --exclude-crate-path='*#tests'    — strip test dirs from vendored sources
#   --exclude-crate-path='*#benches'  — strip bench dirs
#
# The dev-dependencies (criterion, synta-krb5 for the tests) stay in the
# tarball: %check builds the test targets, which need them.  %build strips
# them from the bundled(crate()) Provides.
#
# No asn1/ workaround here, unlike ahdapa: synta-mtc and synta-certificate
# ship their own asn1/ directory, which find_asn1_dir() finds crate-locally.

vendor: $(VENDOR_TARBALL)

$(VENDOR_TARBALL):
	@echo "==> Creating $@ — filtering and vendoring for Linux platforms"
	@# A [patch.crates-io] entry pointing outside the repository is a
	@# development override; the tarball has no such directory.
	@if grep -qE '^[[:space:]]*[a-z0-9_-]+[[:space:]]*=[[:space:]]*\{[[:space:]]*path[[:space:]]*=[[:space:]]*"\.\./' "$(REPOROOT)/Cargo.toml"; then \
	    echo "==> ERROR: Cargo.toml patches a crate outside the repository:" >&2; \
	    grep -nE '^[[:space:]]*[a-z0-9_-]+[[:space:]]*=[[:space:]]*\{[[:space:]]*path[[:space:]]*=[[:space:]]*"\.\./' "$(REPOROOT)/Cargo.toml" >&2; \
	    echo "==> Remove those [patch.crates-io] entries before vendoring." >&2; \
	    exit 1; \
	fi
	cd "$(REPOROOT)" && cargo vendor-filterer \
	    --platform='*-unknown-linux-gnu' \
	    --tier=2 \
	    --all-features \
	    --exclude-crate-path='*#tests' \
	    --exclude-crate-path='*#benches' \
	    --versioned-dirs \
	    vendor >/dev/null
	@# Coverage artefacts in vendored sources must go, and their entries out of
	@# .cargo-checksum.json too: cargo verifies every listed file.
	@find "$(REPOROOT)/vendor" -name '*.profraw' -delete
	@find "$(REPOROOT)/vendor" -name '.cargo-checksum.json' \
	    -exec python3 -c "import json,sys;[open(p,'w').write(json.dumps(dict(d,files={k:v for k,v in d['files'].items() if not k.endswith('.profraw')}),separators=(',',':'))) for p in sys.argv[1:] for d in [json.load(open(p))]]" {} +
	@# Record the crates Fedora ships at the exact locked version.  The manifest
	@# goes into the SRPM: %generate_buildrequires turns it into crate()
	@# BuildRequires and %build drops those crates from the bundled Provides.
	@# Their vendor/ directories stay: the fallback for a Fedora that does not
	@# ship them, or ships another version.
	bash "$(FILTERVENDOR)" "$(REPOROOT)/vendor" "$(CURDIR)/$(SYSTEM_CRATES)"
	tar -czf "$(CURDIR)/$@" \
	    -C "$(REPOROOT)" vendor/ Cargo.lock
	rm -rf "$(REPOROOT)/vendor"
	@echo "==> $@ ready"

# ══════════════════════════════════════════════════════════════════════════════
# SPEC / SRPM / MOCK / LINT
# ══════════════════════════════════════════════════════════════════════════════

# ── spec ──────────────────────────────────────────────────────────────────────
# Fill in the snapshot release identifiers.  kuipa.spec.in is the maintained
# file; kuipa.spec is generated and never committed.

spec:
	@echo "==> Generating $(SPEC_OUT) from $(SPEC_IN)"
	sed \
	    -e "s/^%global snapdate[[:space:]].*/%global snapdate    $(SNAPDATE)/" \
	    -e "s/^%global snapcommit[[:space:]].*/%global snapcommit  $(SNAPCOMMIT)/" \
	    "$(SPEC_IN)" > "$(SPEC_OUT)"

# ── srpm ──────────────────────────────────────────────────────────────────────

srpm: sources spec
	@echo "==> Building SRPM ($(NAME)-$(VERSION)-$(RELEASE))"
	cp -f $(addprefix "$(REPOROOT)/contrib/",$(EXTRA_SOURCES)) .
	rpmbuild -bs \
	    --define "_sourcedir $(CURDIR)" \
	    --define "_specdir   $(CURDIR)" \
	    --define "_srcrpmdir $(CURDIR)" \
	    "$(SPEC_OUT)"
	rm -f "$(SPEC_OUT)" $(EXTRA_SOURCES)
	@echo "==> To skip the tests:      rpmbuild -bs --without check ..."
	@echo "==> To skip the Clevis pin: rpmbuild -bs --without clevis ..."

# ── mock ──────────────────────────────────────────────────────────────────────
# The crates the spec names explicitly (native-ossl*, synta*, agirru*) are not
# in Fedora: they are built in COPR abbra/rust-deps, which publishes one repo
# per chroot name — the same name mock uses.  --addrepo therefore needs no
# chroot-config edits; COPR abbra/pqc gets the same crates through its
# Additional repo (copr://abbra/rust-deps).
# A custom MOCK_CONFIG that is not a COPR chroot name needs its own repo URL.
RUST_DEPS_REPO := https://download.copr.fedorainfracloud.org/results/abbra/rust-deps/$(MOCK_CONFIG)/

mock: srpm
	$(eval SRPM := $(shell ls -1t "$(CURDIR)"/$(NAME)-$(VERSION)-*.src.rpm 2>/dev/null | head -1))
	@if [ -z "$(SRPM)" ]; then \
	    echo "ERROR: no SRPM found in $(CURDIR) for $(NAME)-$(VERSION)"; \
	    exit 1; \
	fi
	@echo "==> Rebuilding $(SRPM) in mock ($(MOCK_CONFIG))"
	mock -r "$(MOCK_CONFIG)" --addrepo "$(RUST_DEPS_REPO)" --rebuild "$(SRPM)"

# ── lint / check-deps ─────────────────────────────────────────────────────────

lint: spec
	rpmlint "$(SPEC_OUT)"

check-deps:
	bash "$(CHECKDEPS)" "$(REPOROOT)/Cargo.lock"

# ── copr-build ────────────────────────────────────────────────────────────────
# Requires COPR=owner/project.  Public action: nothing is submitted without an
# explicit 'make copr-build COPR=…' invocation.

copr-build: srpm
	@if [ -z "$(COPR)" ]; then echo "ERROR: COPR=owner/project is required"; exit 1; fi
	$(eval SRPM := $(shell ls -1t "$(CURDIR)"/$(NAME)-$(VERSION)-*.src.rpm 2>/dev/null | head -1))
	copr-cli build --nowait "$(COPR)" "$(SRPM)"

clean:
	rm -f $(TARBALL) $(VENDOR_TARBALL) $(SPEC_OUT) $(SYSTEM_CRATES) $(EXTRA_SOURCES)
	rm -rf $(NAME)-$(VERSION)
