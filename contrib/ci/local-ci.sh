#!/usr/bin/env bash
# local-ci.sh — run the CI pipeline locally, mirroring .github/workflows/ci.yml
#
# Adapted from kurbu5-pkinit's contrib/ci/local-ci.sh.
#
# Usage:
#   ./contrib/ci/local-ci.sh all                 # run all jobs
#   ./contrib/ci/local-ci.sh build fmt clippy    # run specific jobs
#   ./contrib/ci/local-ci.sh --list              # print available job names
#   ./contrib/ci/local-ci.sh --no-color all      # disable ANSI colours
#   ./contrib/ci/local-ci.sh --valgrind test     # run tests under Valgrind
#   ./contrib/ci/local-ci.sh interactive         # throwaway realm + shell
#   ./contrib/ci/local-ci.sh playground-test     # scripted, traced session + HTML report
#   CARGO_TARGET_DIR=/tmp/kuipa-target ./contrib/ci/local-ci.sh all
#   KUIPA_KRB5_VENDOR=heimdal ./contrib/ci/local-ci.sh build   # build against Heimdal

# Require bash 4+
if [ "${BASH_VERSINFO:-0}" -lt 4 ]; then
    echo "error: bash 4 or later is required (you have ${BASH_VERSION:-unknown})" >&2
    exit 1
fi

set -euo pipefail

# ── Colour helpers ──────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

# NO_COLOR env var baseline (flags may override below).
if [[ "${NO_COLOR:-}" == "1" ]]; then
    RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
fi

# ── Flag parsing ─────────────────────────────────────────────────────────────
VALGRIND=0
NO_DEPS=0
while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-color)
            RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; BOLD=''; NC=''
            shift ;;
        --valgrind)
            VALGRIND=1
            shift ;;
        --no-deps)
            NO_DEPS=1
            shift ;;
        *) break ;;
    esac
done

# ── Locate repo root ────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

if [[ ! -f "$REPO_ROOT/Cargo.toml" ]]; then
    echo "error: must be run from the repository root (Cargo.toml not found)" >&2
    exit 1
fi

cd "$REPO_ROOT"

# ── Optional isolated target directory ──────────────────────────────────────
if [[ -n "${CARGO_TARGET_DIR:-}" ]]; then
    export CARGO_TARGET_DIR
    echo -e "${CYAN}Using CARGO_TARGET_DIR=${CARGO_TARGET_DIR}${NC}"
fi

export CARGO_TERM_COLOR=always
export RUSTDOCFLAGS="-D warnings"

# ── Kerberos vendor ─────────────────────────────────────────────────────────
# `KUIPA_KRB5_VENDOR` names the Kerberos implementation the build scripts
# compile against.  It is validated here rather than by the build scripts so a
# typo is reported before anything compiles, and exported so every job in one
# run sees the same vendor — cargo would otherwise re-detect, and therefore
# rebuild, per crate invocation.
case "${KUIPA_KRB5_VENDOR:-}" in
    ""|auto) KRB_VENDOR="auto" ;;
    mit|mit-krb5|krb5|massachusetts) KRB_VENDOR="mit" ;;
    heimdal) KRB_VENDOR="heimdal" ;;
    *)
        echo "error: KUIPA_KRB5_VENDOR='${KUIPA_KRB5_VENDOR}' is not a known vendor (expected mit, heimdal or auto)" >&2
        exit 1
        ;;
esac
export KUIPA_KRB5_VENDOR="$KRB_VENDOR"

# ── Keg-only Homebrew installs (macOS) ──────────────────────────────────────
# Homebrew refuses to symlink krb5 and openldap into the normal prefix because
# macOS ships its own copies (Heimdal Kerberos, its own LDAP), so a `brew
# install` of either puts binaries, headers, libraries and `.pc` files on
# neither PATH nor PKG_CONFIG_PATH. Put the keg directories first: `kinit` has
# to resolve to MIT, not the system Heimdal one, and the build scripts have to
# see the OpenLDAP and MIT Kerberos pkg-config packages.
keg_only_formulas() {
    if [[ "$(uname -s)" != "Darwin" ]] || ! command -v brew >/dev/null 2>&1; then
        return
    fi
    for formula in krb5 openldap; do
        local prefix=""
        prefix="$(brew --prefix "$formula" 2>/dev/null)" || continue
        [[ -n "$prefix" && -d "$prefix" ]] || continue
        for dir in "$prefix/bin" "$prefix/sbin"; do
            if [[ -d "$dir" ]]; then
                PATH="$dir:$PATH"
            fi
        done
        if [[ -d "$prefix/lib/pkgconfig" ]]; then
            PKG_CONFIG_PATH="$prefix/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
        fi
        echo -e "${CYAN}Keg-only Homebrew ${formula}:${NC} ${prefix}"
    done
    # The Heimdal keg deliberately stays off PATH: it ships its own `kinit`,
    # `klist` and `kswitch`, which would shadow the MIT tools the KDC jobs
    # start realms with, and it has no `krb5kdc`/`kdb5_util` at all.  Its
    # pkg-config directory is enough for a Heimdal build to find the headers.
    if [[ "$KRB_VENDOR" == "heimdal" ]]; then
        local heimdal=""
        heimdal="$(brew --prefix heimdal 2>/dev/null)" || heimdal=""
        if [[ -n "$heimdal" && -d "$heimdal/lib/pkgconfig" ]]; then
            PKG_CONFIG_PATH="$heimdal/lib/pkgconfig:${PKG_CONFIG_PATH:-}"
            echo -e "${CYAN}Keg-only Homebrew heimdal:${NC} ${heimdal} (pkg-config only; PATH stays MIT)"
        fi
    fi
    export PATH PKG_CONFIG_PATH
}
keg_only_formulas

# The minimum supported Rust version, from the workspace manifest.
MSRV="$(sed -n 's/^rust-version = "\(.*\)"/\1/p' Cargo.toml | head -1)"

# ── Tool detection ───────────────────────────────────────────────────────────

has_cargo=0
has_rustfmt=0
has_clippy=0
has_valgrind=0
has_actionlint=0
has_yamllint=0
has_krb5kdc=0
has_msrv=0
has_mdbook=0
has_mdbook_mermaid=0
has_scdoc=0

detect_tools() {
    echo -e "${BOLD}${CYAN}Tool availability check:${NC}"

    if command -v cargo >/dev/null 2>&1; then
        has_cargo=1
        echo -e "  ${GREEN}✓${NC} cargo $(cargo --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} cargo (install from https://rustup.rs/ or your distribution)"
    fi

    if cargo fmt --version >/dev/null 2>&1; then
        has_rustfmt=1
        echo -e "  ${GREEN}✓${NC} rustfmt $(cargo fmt --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} rustfmt (install with: rustup component add rustfmt)"
    fi

    if cargo clippy --version >/dev/null 2>&1; then
        has_clippy=1
        echo -e "  ${GREEN}✓${NC} clippy $(cargo clippy --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} clippy (install with: rustup component add clippy)"
    fi

    if command -v valgrind >/dev/null 2>&1; then
        has_valgrind=1
        echo -e "  ${GREEN}✓${NC} valgrind $(valgrind --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} valgrind (optional, needed for --valgrind flag)"
    fi

    if command -v actionlint >/dev/null 2>&1; then
        has_actionlint=1
        echo -e "  ${GREEN}✓${NC} actionlint $(actionlint --version | head -1)"
    else
        echo -e "  ${YELLOW}○${NC} actionlint (optional, for workflow validation)"
    fi

    if command -v yamllint >/dev/null 2>&1; then
        has_yamllint=1
    fi

    # kdc-test prerequisites: a real MIT KDC, its admin tools, and kinit.
    if command -v krb5kdc >/dev/null 2>&1 && command -v kdb5_util >/dev/null 2>&1 \
        && command -v kadmin.local >/dev/null 2>&1 && command -v kinit >/dev/null 2>&1; then
        has_krb5kdc=1
        echo -e "  ${GREEN}✓${NC} krb5kdc, kdb5_util, kadmin.local, kinit (kdc-test)"
    else
        echo -e "  ${YELLOW}○${NC} MIT KDC tools (optional, needed for kdc-test; install krb5-server krb5-workstation krb5-pkinit, or brew install krb5)"
    fi

    # Which Kerberos the build scripts compile against, and whether the
    # MIT-only jobs can run.
    if [[ "$KRB_VENDOR" == "auto" ]]; then
        echo -e "  ${CYAN}•${NC} Kerberos vendor: auto — MIT when both implementations are present"
    else
        echo -e "  ${CYAN}•${NC} Kerberos vendor: $KRB_VENDOR"
        if [[ "$KRB_VENDOR" == "heimdal" ]]; then
            echo -e "  ${YELLOW}○${NC} kdc-test, playground-test, interactive: MIT-only, skipped for a Heimdal build"
        fi
    fi

    if command -v mdbook >/dev/null 2>&1; then
        has_mdbook=1
        echo -e "  ${GREEN}✓${NC} mdbook $(mdbook --version | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} mdbook (optional, for the user documentation; cargo install mdbook)"
    fi

    if command -v mdbook-mermaid >/dev/null 2>&1; then
        has_mdbook_mermaid=1
        echo -e "  ${GREEN}✓${NC} mdbook-mermaid (found)"
    else
        echo -e "  ${YELLOW}○${NC} mdbook-mermaid (optional, for diagrams in the book; cargo install mdbook-mermaid)"
    fi

    if command -v scdoc >/dev/null 2>&1; then
        has_scdoc=1
        echo -e "  ${GREEN}✓${NC} scdoc $(scdoc --version 2>/dev/null | cut -d' ' -f2)"
    else
        echo -e "  ${YELLOW}○${NC} scdoc (optional, for the man pages; your distribution's scdoc package)"
    fi

    if [[ -n "$MSRV" ]] && command -v rustup >/dev/null 2>&1 \
        && rustup run "$MSRV" cargo --version >/dev/null 2>&1; then
        has_msrv=1
        echo -e "  ${GREEN}✓${NC} Rust $MSRV toolchain (msrv)"
    else
        echo -e "  ${YELLOW}○${NC} Rust ${MSRV:-?} toolchain (optional, needed for msrv; rustup toolchain install $MSRV)"
    fi

    echo ""
}

# Run tool detection unless --list or --help
if [[ "${1:-}" != "--list" && "${1:-}" != "--help" && "${1:-}" != "-h" && $# -gt 0 ]]; then
    detect_tools
fi

# ── Valgrind setup ───────────────────────────────────────────────────────────
if [[ "$VALGRIND" == "1" ]]; then
    if [[ $has_valgrind -eq 0 ]]; then
        echo "error: --valgrind requested but valgrind is not installed" >&2
        exit 1
    fi
    # Configure Cargo to run test binaries through Valgrind for the host target.
    # CARGO_TARGET_<TRIPLE>_RUNNER is the standard mechanism; Cargo passes each
    # test binary to the runner instead of executing it directly.
    _VALGRIND_OPTS="--error-exitcode=1 --leak-check=full --show-leak-kinds=all --suppressions=$SCRIPT_DIR/rust-valgrind.supp"
    _TARGET_TRIPLE=$(rustc --print host-tuple)
    _TARGET_RUNNER_VAR="CARGO_TARGET_$(printf '%s' "$_TARGET_TRIPLE" | tr '[:lower:]-' '[:upper:]_')_RUNNER"
    export "${_TARGET_RUNNER_VAR}=valgrind ${_VALGRIND_OPTS}"
    echo -e "${CYAN}Valgrind enabled (${_TARGET_TRIPLE}) — Rust test binaries will run under valgrind${NC}"
    unset _VALGRIND_OPTS _TARGET_TRIPLE _TARGET_RUNNER_VAR
fi

# ── Job tracking ────────────────────────────────────────────────────────────
declare -A JOB_STATUS=()
declare -A JOB_SECS=()
declare -A SKIP_NOTE=()
FAILED_JOBS=()
# A job whose environment cannot run it at all — here, a Heimdal Kerberos
# build trying to start a MIT realm — returns this after naming the reason, so
# the summary reports SKIP with that reason instead of a misleading FAIL.
SKIP_RC=75
SKIP_REASON=""
skip_job() {
    SKIP_REASON="$1"
    warn "$1"
    return $SKIP_RC
}

ALL_JOBS=(build fmt lint-workflows deps clippy doc test kdc-test playground-test)
# Opt-in jobs: not part of 'all' (need an extra toolchain).
EXTRA_JOBS=(msrv bench)

# Job dependencies — mirrors the 'needs:' fields in .github/workflows/ci.yml.
# Value is a space-separated list of prerequisite job names.
# Jobs absent from the map have no dependencies.
declare -A JOB_DEPS=(
    [clippy]="build"
    [doc]="build"
    [test]="build"
    [kdc-test]="build"
    [playground-test]="build"
    [bench]="build"
)

# ── Utilities ───────────────────────────────────────────────────────────────
step() { echo -e "\n${BOLD}${BLUE}▶ $*${NC}"; }
ok()   { echo -e "${GREEN}✔  $*${NC}"; }
fail() { echo -e "${RED}✘  $*${NC}"; }
warn() { echo -e "${YELLOW}!  $*${NC}"; }

run_job() {
    local name="$1"
    shift

    # Ensure all prerequisites have been executed, running them on demand if
    # they haven't been dispatched yet; then skip this job if any dep failed.
    # Skipped entirely when --no-deps is set (e.g. inside GitHub Actions, where
    # the workflow already enforces the dependency ordering via 'needs:').
    if [[ "$NO_DEPS" == "0" ]]; then
        local dep
        for dep in ${JOB_DEPS[$name]:-}; do
            if [[ -z "${JOB_STATUS[$dep]:-}" ]]; then
                dispatch_job "$dep"
            fi
            if [[ "${JOB_STATUS[$dep]}" != "PASS" ]]; then
                JOB_STATUS[$name]="SKIP"
                warn "[$name] skipped — '$dep' did not pass"
                return 0
            fi
        done
    fi

    local t0; t0=$(date +%s)
    step "[$name]"
    local _rc=0
    "$@" || _rc=$?
    local t1; t1=$(date +%s)
    JOB_SECS[$name]=$((t1 - t0))
    if [[ $_rc -eq 0 ]]; then
        JOB_STATUS[$name]="PASS"
        ok "[$name] passed (${JOB_SECS[$name]}s)"
    elif [[ $_rc -eq $SKIP_RC ]]; then
        JOB_STATUS[$name]="SKIP"
        SKIP_NOTE[$name]="${SKIP_REASON:-not runnable}"
    else
        JOB_STATUS[$name]="FAIL"
        FAILED_JOBS+=("$name")
        fail "[$name] FAILED (${JOB_SECS[$name]}s)"
    fi
    SKIP_REASON=""
}

# ── Individual job implementations ──────────────────────────────────────────

require_cargo() {
    if [[ $has_cargo -eq 0 ]]; then
        fail "cargo is required but not found"
        return 1
    fi
}

job_build() {
    require_cargo || return 1

    echo "Building workspace (debug, all targets)…"
    cargo build --workspace --all-targets
}

# RustCrypto algorithm and primitive crates must not be dependencies:
# cryptography comes from OpenSSL through native-ossl.  (rustls itself
# needs the non-cryptographic helpers zeroize and subtle.)
RUSTCRYPTO_CRATES=(
    aead aes aes-gcm aes-gcm-siv aes-kw argon2 blake2 block-buffer cbc ccm
    chacha20 chacha20poly1305 cipher cmac crypto-bigint crypto-common ctr
    curve25519-dalek der digest dsa ecdsa ed25519 ed25519-dalek elliptic-curve
    hkdf hmac k256 md-5 md4 ml-dsa ml-kem p256 p384 p521 password-hash pbkdf2
    pkcs1 pkcs8 poly1305 polyval rsa scrypt sec1 sha1 sha2 sha3 signature
    slh-dsa spki universal-hash x25519-dalek
)

job_deps() {
    require_cargo || return 1

    echo "Checking that no RustCrypto crate is a dependency…"
    local found=() c
    for c in "${RUSTCRYPTO_CRATES[@]}"; do
        if cargo tree --workspace -e all -i "$c" >/dev/null 2>&1; then
            found+=("$c")
        fi
    done
    if [[ ${#found[@]} -gt 0 ]]; then
        fail "RustCrypto crates in the dependency tree: ${found[*]}"
        for c in "${found[@]}"; do
            cargo tree --workspace -e all -i "$c" | head -8
        done
        return 1
    fi
    echo "none of ${#RUSTCRYPTO_CRATES[@]} RustCrypto crates found"
}

job_fmt() {
    require_cargo || return 1
    if [[ $has_rustfmt -eq 0 ]]; then
        fail "rustfmt is required (install with: rustup component add rustfmt)"
        return 1
    fi

    echo "Checking formatting…"
    cargo fmt --all -- --check
}

job_lint_workflows() {
    echo "Validating GitHub Actions workflow files…"

    local workflows=()
    while IFS= read -r -d '' f; do
        workflows+=("$f")
    done < <(find .github/workflows -name '*.yml' -print0 2>/dev/null)

    if [[ ${#workflows[@]} -eq 0 ]]; then
        warn "No workflow files found in .github/workflows/"
        return 0
    fi

    echo "Found ${#workflows[@]} workflow file(s)"

    # Prefer actionlint — validates GitHub Actions expression syntax,
    # runner labels, action inputs, step references, etc.
    if [[ $has_actionlint -eq 1 ]]; then
        echo "Using actionlint…"
        actionlint "${workflows[@]}"
        return
    fi

    warn "actionlint not found — falling back to yamllint (install from: https://github.com/rhysd/actionlint)"

    # Fall back to yamllint for structural / style validation.
    # Disable 'truthy' (GitHub Actions uses bare 'on:' keys) and relax
    # line-length to accommodate ci.yml step definitions.
    if [[ $has_yamllint -eq 1 ]]; then
        yamllint \
            -d "{extends: default, rules: {truthy: disable, line-length: {max: 120}}}" \
            "${workflows[@]}"
    else
        warn "yamllint not found — skipping workflow validation"
        return 0
    fi
}

job_clippy() {
    require_cargo || return 1
    if [[ $has_clippy -eq 0 ]]; then
        fail "clippy is required (install with: rustup component add clippy)"
        return 1
    fi

    # The workspace denies clippy::incompatible_msrv, so this also catches
    # standard-library APIs newer than the MSRV.
    echo "Running Clippy…"
    cargo clippy --workspace --all-targets --all-features -- -D warnings
}

job_doc() {
    require_cargo || return 1

    echo "Building documentation…"
    cargo doc --workspace --no-deps --all-features || return 1

    if [[ "$has_scdoc" -eq 1 ]]; then
        echo "Compiling the man pages…"
        local out
        out=$(mktemp -d)
        local page
        for page in docs/man/*.scd; do
            scdoc < "$page" > "$out/$(basename "${page%.scd}")" || return 1
        done
        # A compiled page must also render: catches empty output and
        # truncated sources.
        if command -v man >/dev/null 2>&1; then
            for page in "$out"/*; do
                MANWIDTH=80 man -l "$page" > /dev/null || return 1
            done
        else
            warn "man not found — rendering the compiled pages is skipped"
        fi
        rm -rf "$out"
    else
        warn "scdoc not found — skipping the man pages (install your distribution's scdoc package)"
    fi

    if [[ "$has_mdbook" -eq 0 ]]; then
        warn "mdbook not found — skipping the book (install with: cargo install mdbook)"
        return 0
    fi
    echo "Building the book…"
    if [[ "$has_mdbook_mermaid" -eq 0 ]]; then
        warn "mdbook-mermaid not found — diagrams will not render (install with: cargo install mdbook-mermaid)"
    fi
    mdbook build docs/
}

job_test() {
    require_cargo || return 1

    # The real-KDC tests have their own job; here they would only skip themselves.
    echo "Running test suite (without the real-KDC tests)…"
    cargo test --workspace --all-features -- --skip against_a_real_kdc --skip trusted_realm_against_real_kdcs
}

# The KDC realms are MIT: `kdb5_util`, `kadmin.local` and MIT's `pkinit.so`.
# A Heimdal build cannot drive them — its libkrb5 speaks to those daemons'
# database and preauth plugins as a different implementation — so the jobs that
# need them report a skip instead of failing for the wrong reason.
require_mit_vendor() {
    if [[ "$KRB_VENDOR" == "heimdal" ]]; then
        skip_job "$1 needs a MIT Kerberos build (KUIPA_KRB5_VENDOR=heimdal); the realm is created with MIT's kdb5_util and pkinit.so"
        return $SKIP_RC
    fi
    return 0
}

job_kdc_test() {
    require_cargo || return 1
    require_mit_vendor "kdc-test" || return $SKIP_RC
    if [[ $has_krb5kdc -eq 0 ]]; then
        fail "kdc-test requires krb5kdc, kdb5_util, kadmin.local and kinit (install krb5-server krb5-workstation krb5-pkinit)"
        return 1
    fi

    # Ephemeral MIT realm with PKINIT on a Unix socket; fail rather than
    # skip if anything is missing.
    echo "Running the client flows against real MIT KDCs…"
    KUIPA_REQUIRE_KDC=1 cargo test -p kuipa-tools --test kdc --test trust --test voucher
}

job_msrv() {
    if [[ $has_msrv -eq 0 ]]; then
        fail "msrv requires the Rust $MSRV toolchain (rustup toolchain install $MSRV)"
        return 1
    fi

    # Language features newer than the MSRV (clippy only checks library
    # APIs): build everything with the oldest supported compiler.
    echo "Building with Rust ${MSRV}…"
    rustup run "$MSRV" cargo build --workspace --all-targets
}

# ── Benchmarks ──────────────────────────────────────────────────────────────
#
# Criterion targets live in the crates whose code they measure
# (kuipa-enroll, ml-dsa-blind); kuipa-perf supplies the fixtures and owns the
# certificate-cost target.  CI runs a smoke pass: a few samples per benchmark,
# enough to catch a fixture that no longer verifies, but with no baseline to
# catch a timing regression.  Use scripts/bench.sh for a full run that stores
# comparable results.
job_bench() {
    require_cargo || return 1

    echo "Running the benchmark smoke pass (profile smoke)…"
    KUIPA_BENCH_PROFILE=smoke scripts/bench.sh --quick --no-save
}

# ── Interactive playground ──────────────────────────────────────────────────
print_interactive_help() {
    cat <<EOF
Usage: $(basename "$0") interactive [OPTIONS]

Start a throwaway kuipa realm and drop you into a shell inside it:

  * a real MIT KDC (realm EXAMPLE.TEST, PKINIT with a generated CA) on a
    Unix socket;
  * two IPA servers, ipa1 and ipa2.example.test, running the daemon's HTTP
    router over a directory backed by that KDC (GSS-API for real, keys from
    the KDC; only the LDAP side is simulated);
  * OTP enrollment strings for web1..webN.example.test, an administrator,
    admin@EXAMPLE.TEST (password Secret123), and the users bob and carol;
  * the kuipa, kuipa-unseal, kuipa-voucher, tang-pqc and kuipa-playground binaries on PATH, and
    shell helpers (pq_host, pq_enroll, pq_down/pq_up, pq_bootstrap, pq_log).

Exiting the shell (exit, Ctrl-D) tears everything down.

Options:
  --hosts N    OTP enrollment strings to create (default: 5)
  --keep       Keep the realm's files after exit (KUIPA_KEEP_REALM)

See docs/src/development/local-ci.md for a walkthrough.
EOF
}

# The realm behind 'interactive' and the playground-test job.  pg_start
# builds the binaries and starts it in the background; pg_stop tears it
# down.  Globals, because cleanup also runs from the INT/TERM trap.
PG_WORK="" PG_PID="" PG_ENV="" PG_LOG="" PG_BIN=""

pg_start() {
    local hosts="$1"
    # kuipa with its software security key (soft-fido2): the playground's
    # passkeys live in files, not on attached keys.
    cargo build -p kuipa-tools -p tang-pqc-clevis --bins --example kuipa-playground \
        --features kuipa-tools/soft-fido2 || return 1
    PG_BIN="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug"
    PG_WORK="$(mktemp -d /tmp/kuipa-playground.XXXXXXXXXX)"
    PG_ENV="$PG_WORK/env.sh" PG_LOG="$PG_WORK/servers.log"
    # The servers run in the background; they write the env file when
    # ready, which takes a few seconds (two realms, keys, the anchor
    # exchange) and longer on a slow runner.
    local wait="${KUIPA_PLAYGROUND_START_TIMEOUT:-120}"
    # KUIPA_KEEP_PLAYGROUND also keeps the realm's own directory (keys,
    # logs, hosts), which the KDC fixture removes unless KUIPA_KEEP_REALM.
    KUIPA_KEEP_REALM="${KUIPA_KEEP_REALM:-${KUIPA_KEEP_PLAYGROUND:-}}" \
        "$PG_BIN/examples/kuipa-playground" run --env-file "$PG_ENV" --hosts "$hosts" >"$PG_LOG" 2>&1 </dev/null &
    PG_PID=$!
    local deadline=$((SECONDS + wait))
    while [[ ! -f "$PG_ENV" && $SECONDS -lt $deadline ]]; do
        kill -0 "$PG_PID" 2>/dev/null || break
        sleep 0.1
    done
    if [[ ! -f "$PG_ENV" ]]; then
        cat "$PG_LOG" 2>/dev/null || true
        local why="exited"
        kill -0 "$PG_PID" 2>/dev/null && why="was not ready after ${wait}s (KUIPA_PLAYGROUND_START_TIMEOUT)"
        pg_stop
        fail "the playground $why; see the log above"
        return 1
    fi
}

pg_stop() {
    if [[ -n "$PG_PID" ]]; then
        kill "$PG_PID" 2>/dev/null || true
        wait "$PG_PID" 2>/dev/null || true
    fi
    # KUIPA_KEEP_PLAYGROUND=1 keeps the servers' and hosts' files, to
    # inspect them (or measure them, docs/src/reference/sizing.md).
    if [[ -n "$PG_WORK" && -n "${KUIPA_KEEP_PLAYGROUND:-}" ]]; then
        echo "Keeping the playground's files in $PG_WORK"
    elif [[ -n "$PG_WORK" ]]; then
        rm -rf "$PG_WORK"
    fi
    PG_PID="" PG_WORK=""
}

run_interactive_playground() {
    local hosts=5
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hosts) hosts="$2"; shift 2 ;;
            --keep) export KUIPA_KEEP_REALM=1; shift ;;
            --help|-h) print_interactive_help; return 0 ;;
            *) echo "interactive: unknown option: $1" >&2; print_interactive_help; return 2 ;;
        esac
    done

    require_cargo || return 1
    # The realm is a MIT one, so a Heimdal build cannot host it even when the
    # MIT server tools are installed.
    if [[ "$KRB_VENDOR" == "heimdal" ]]; then
        fail "interactive needs a MIT Kerberos build: the realm is created with MIT's kdb5_util and pkinit.so. Unset KUIPA_KRB5_VENDOR (or set it to mit) and rebuild."
        return 1
    fi
    if [[ $has_krb5kdc -eq 0 ]]; then
        fail "interactive requires krb5kdc, kdb5_util, kadmin.local and kinit (install krb5-server krb5-workstation krb5-pkinit)"
        return 1
    fi

    local hosts=5
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hosts) hosts="$2"; shift 2 ;;
            --keep) export KUIPA_KEEP_REALM=1; shift ;;
            --help|-h) print_interactive_help; return 0 ;;
            *) echo "interactive: unknown option: $1" >&2; print_interactive_help; return 2 ;;
        esac
    done

    step "[interactive] building kuipa, kuipa-unseal and the playground"
    trap 'echo; echo "Tearing down the playground…"; pg_stop; exit 130' INT TERM
    pg_start "$hosts" || return 1
    local bin="$PG_BIN"

    {
        echo '[ -f ~/.bashrc ] && . ~/.bashrc'
        echo ". '$PG_ENV'"
        echo "export PATH='$bin:$bin/examples':\"\$PATH\""
        echo "export PQ_SERVER_LOG='$PG_LOG'"
        echo 'pq_log() { tail -n "${1:-20}" "$PQ_SERVER_LOG"; }'
        echo 'pq_host web1'
    } >"$PG_WORK/rc"

    # shellcheck disable=SC1090
    source "$PG_ENV"
    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}kuipa playground ready${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "  realm:        EXAMPLE.TEST  (KDC on $PQ_KDC_SOCKET)"
    echo "  servers:      ipa1.example.test, ipa2.example.test  (pq_log shows their log)"
    echo "  anchor:       $PQ_ANCHOR"
    echo "  admin:        admin@EXAMPLE.TEST, password Secret123"
    echo "  users:        bob, carol (the same password; pq_as USER CMD runs as them)"
    echo "  hosts:        web1..web$hosts.example.test; OTP strings in \$KUIPA_PLAYGROUND/enroll/"
    echo "  current host: web1 (pq_host NAME switches; each host has its own KUIPA_ROOT)"
    echo
    echo "  Try:"
    echo "    pq_enroll web1                        # OTP join; then: kuipa status"
    echo "    kuipa rotate-keys; kuipa check      # rekey authenticated by the host keytab"
    echo "    kuipa protect; kuipa-unseal; kuipa unprotect"
    echo "    pq_down ipa1; pq_enroll web2; pq_up   # failover to ipa2"
    echo "    pq_password web3                      # admin password in the PQ channel"
    echo "    pq_bootstrap; pq_host web4; kuipa enroll \$PQ_SERVERS --hostname \$PQ_HOST \\"
    echo "        --use-ccache                      # armoured kinit, ticket join"
    echo "    pq_offline web5                       # prepare, stage, open the bundle"
    echo "    kuipa complete                       # first contact: rekey the staged keys"
    echo "    pq_admin_kinit; kuipa seal create team --require device,ticket"
    echo "    kuipa seal share team --user bob; pq_as bob kuipa seal list"
    echo "    pq_passkey mldsa65 --pin 1234          # an IPA passkey on a software security key"
    echo "    kuipa seal device add SEAL --pkcs11 \"\$(pq_token dev)\" --module \$PQ_TOKEN_MODULE"
    echo
    echo "  Exit this shell (exit or Ctrl-D) to tear the playground down."
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo

    bash --rcfile "$PG_WORK/rc" -i || true

    echo
    echo "Tearing down the playground…"
    pg_stop
    trap - INT TERM
}

# A scripted session in the playground, with tracing on, rendered as an HTML
# report (contrib/ci/playground/: session.sh runs it, report.py renders it).
job_playground_test() {
    require_cargo || return 1
    require_mit_vendor "playground-test" || return $SKIP_RC
    if [[ $has_krb5kdc -eq 0 ]]; then
        fail "playground-test requires krb5kdc, kdb5_util, kadmin.local and kinit (install krb5-server krb5-workstation krb5-pkinit)"
        return 1
    fi
    if ! command -v python3 >/dev/null 2>&1; then
        fail "playground-test requires python3 to render its report"
        return 1
    fi
    if ! command -v node >/dev/null 2>&1; then
        fail "playground-test requires node (>= 22) to render the session's terminal captures"
        return 1
    fi
    # The terminal captures need svg-terminal (contrib/ci/playground/
    # package.json); with npm present, install it when it is missing.
    # Without npm the captures are skipped below, as before.
    if [[ ! -d "$SCRIPT_DIR/playground/node_modules/svg-terminal" ]] \
        && command -v npm >/dev/null 2>&1; then
        echo "Installing svg-terminal (npm ci in contrib/ci/playground/)…"
        (cd "$SCRIPT_DIR/playground" && npm ci --no-fund --no-audit) \
            || warn "npm ci failed — terminal captures may be skipped"
    fi

    # The report is a directory: index.html plus the svg/ captures, one
    # animated terminal per session section.
    local report="${KUIPA_PLAYGROUND_REPORT:-$REPO_ROOT/kuipa-playground-report}"
    local out
    out="$(mktemp -d /tmp/kuipa-playground-session.XXXXXXXXXX)"
    pg_start 5 || { rm -rf "$out"; return 1; }

    echo "Running the scripted session…"
    local rc=0
    PATH="$PG_BIN:$PG_BIN/examples:$PATH" \
        bash "$SCRIPT_DIR/playground/session.sh" "$PG_ENV" "$PG_LOG" "$out" || rc=$?
    cp "$PG_LOG" "$out/servers.log" 2>/dev/null || true
    pg_stop

    local commit
    # GitHub's checkout has no .git without git in the container.
    commit="${GITHUB_SHA:-$(git -C "$REPO_ROOT" rev-parse HEAD 2>/dev/null || true)}"
    mkdir -p "$report"
    # One animated terminal capture per session section (svg-terminal);
    # they are renderings of what the session already recorded, so a
    # missing node only skips them, it does not fail the job.
    if python3 "$SCRIPT_DIR/playground/terminal.py" "$out" --json "$out/spec.json" \
        && node "$SCRIPT_DIR/playground/render-terminal.mjs" "$out/spec.json" "$report/svg"; then
        svg_args=(--svg "$report/svg")
    else
        warn "terminal captures skipped: $SCRIPT_DIR/playground/render-terminal.mjs failed"
        svg_args=()
    fi
    python3 "$SCRIPT_DIR/playground/report.py" "$out" --html "$report/index.html" \
        --commit "$commit" "${svg_args[@]}" || rc=1
    # Under GitHub Actions, also put the step table on the run's Summary tab.
    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        python3 "$SCRIPT_DIR/playground/report.py" "$out" --summary >> "$GITHUB_STEP_SUMMARY" || true
    fi
    if [[ $rc -eq 0 ]]; then
        rm -rf "$out"
    else
        echo "Session output kept for debugging: $out"
    fi
    echo "Playground report: $report/index.html"
    return $rc
}

dispatch_job() {
    case "$1" in
        build)          run_job build          job_build ;;
        fmt)            run_job fmt            job_fmt ;;
        lint-workflows) run_job lint-workflows job_lint_workflows ;;
        deps)           run_job deps           job_deps ;;
        clippy)         run_job clippy         job_clippy ;;
        doc)            run_job doc            job_doc ;;
        test)           run_job test           job_test ;;
        kdc-test)       run_job kdc-test       job_kdc_test ;;
        playground-test) run_job playground-test job_playground_test ;;
        msrv)           run_job msrv           job_msrv ;;
        bench)          run_job bench          job_bench ;;
        *)
            echo "Unknown job: $1" >&2
            echo "Run '$0 --list' for available jobs." >&2
            exit 1
            ;;
    esac
}

# ── Summary ──────────────────────────────────────────────────────────────────
print_summary() {
    local total_start="$1"
    local total_end; total_end=$(date +%s)

    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}CI Summary${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"

    local display_jobs=("${ALL_JOBS[@]}")
    local all_jobs_str=" ${ALL_JOBS[*]} "
    local job
    for job in "${REQUESTED_JOBS[@]}"; do
        [[ "$all_jobs_str" == *" $job "* ]] || display_jobs+=("$job")
    done

    for job in "${display_jobs[@]}"; do
        local status="${JOB_STATUS[$job]:-}"
        [[ -z "$status" ]] && continue
        local secs="${JOB_SECS[$job]:-0}"
        if [[ "$status" == "PASS" ]]; then
            printf "  ${GREEN}%-20s PASS${NC}  (%ds)\n" "$job" "$secs"
        elif [[ "$status" == "FAIL" ]]; then
            printf "  ${RED}%-20s FAIL${NC}  (%ds)\n" "$job" "$secs"
        elif [[ -n "${SKIP_NOTE[$job]:-}" ]]; then
            printf "  ${YELLOW}%-20s SKIP${NC}  (%s)\n" "$job" "${SKIP_NOTE[$job]}"
        else
            printf "  ${YELLOW}%-20s SKIP${NC}  (dep failed)\n" "$job"
        fi
    done

    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "Total time: $((total_end - total_start))s"

    if [[ ${#FAILED_JOBS[@]} -gt 0 ]]; then
        echo -e "${RED}${BOLD}FAILED: ${FAILED_JOBS[*]}${NC}"
        return 1
    else
        echo -e "${GREEN}${BOLD}All jobs passed.${NC}"
        return 0
    fi
}

# ── Help ─────────────────────────────────────────────────────────────────────
print_help() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS] <job> [job ...]

Run CI jobs locally, mirroring .github/workflows/ci.yml.

Special targets:
  all          Run every job in order
  interactive  Start a throwaway realm (MIT KDC + two IPA servers) and drop
               you into a shell inside it; torn down when the shell exits.
               Run '$(basename "$0") interactive --help' for its options,
               and see docs/src/development/local-ci.md for a walkthrough.

Available jobs:
$(printf '  %s\n' "${ALL_JOBS[@]}")

Opt-in jobs (not run by 'all'):
  msrv         Build the workspace with the minimum supported Rust
               (${MSRV:-see Cargo.toml}); needs that toolchain via rustup

Options:
  --list         Print available job names and exit
  --no-color     Disable ANSI colour output (also: NO_COLOR=1)
  --no-deps      Skip prerequisite checks and auto-runs.  Useful inside
                 GitHub Actions (or any other CI system) where the workflow
                 already enforces job ordering via 'needs:' so that running
                 a single job via local-ci.sh does not trigger its deps.
  --valgrind     Run Rust test binaries under Valgrind (test job).
                 Uses CARGO_TARGET_<TRIPLE>_RUNNER=valgrind with full leak
                 checking and the suppression file at contrib/ci/rust-valgrind.supp.

Environment:
  CARGO_TARGET_DIR    Redirect Cargo build output to an isolated directory.
  KUIPA_KRB5_VENDOR   Kerberos implementation to build against: mit, heimdal
                      or auto (default: MIT when both are installed).
                      kdc-test, playground-test and interactive need a MIT
                      build; with heimdal they report SKIP.
  KUIPA_KEEP_REALM   Keep the kdc-test realm's files (/tmp/kuipa-kdc-<pid>).
  KUIPA_PLAYGROUND_REPORT  Where playground-test writes its HTML report
                      (default: kuipa-playground-report/ in the repository;
                      index.html plus the svg/ terminal captures).
  KUIPA_PLAYGROUND_START_TIMEOUT  Seconds to wait for the playground to start
                      (interactive, playground-test; default 120).
  KUIPA_STEP_TIMEOUT  Seconds each playground-test step may take (default 120).

Examples:
  $(basename "$0") all
  $(basename "$0") build test
  $(basename "$0") --no-color all
  $(basename "$0") --valgrind test
  CARGO_TARGET_DIR=/tmp/kuipa-target $(basename "$0") all
  KUIPA_KRB5_VENDOR=heimdal $(basename "$0") build clippy test
EOF
}

# ── Entry point ──────────────────────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    print_help
    exit 0
fi

if [[ "${1:-}" == "--list" ]]; then
    printf '%s\n' all "${ALL_JOBS[@]}" "${EXTRA_JOBS[@]}"
    exit 0
fi

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
    print_help
    exit 0
fi

if [[ "${1:-}" == "interactive" ]]; then
    shift
    run_interactive_playground "$@"
    exit $?
fi

# Determine which jobs to run; 'all' expands to every job in order.
REQUESTED_JOBS=()
for arg in "$@"; do
    if [[ "$arg" == "all" ]]; then
        REQUESTED_JOBS+=("${ALL_JOBS[@]}")
    else
        REQUESTED_JOBS+=("$arg")
    fi
done

T0=$(date +%s)

for job in "${REQUESTED_JOBS[@]}"; do
    dispatch_job "$job"
done

print_summary "$T0"
