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
#   CARGO_TARGET_DIR=/tmp/kuipa-target ./contrib/ci/local-ci.sh all

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
        echo -e "  ${YELLOW}○${NC} MIT KDC tools (optional, needed for kdc-test; install krb5-server krb5-workstation krb5-pkinit)"
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
FAILED_JOBS=()

ALL_JOBS=(build fmt lint-workflows deps clippy doc test kdc-test)
# Opt-in jobs: not part of 'all' (need an extra toolchain).
EXTRA_JOBS=(msrv)

# Job dependencies — mirrors the 'needs:' fields in .github/workflows/ci.yml.
# Value is a space-separated list of prerequisite job names.
# Jobs absent from the map have no dependencies.
declare -A JOB_DEPS=(
    [clippy]="build"
    [doc]="build"
    [test]="build"
    [kdc-test]="build"
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
    else
        JOB_STATUS[$name]="FAIL"
        FAILED_JOBS+=("$name")
        fail "[$name] FAILED (${JOB_SECS[$name]}s)"
    fi
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
    cargo doc --workspace --no-deps --all-features
}

job_test() {
    require_cargo || return 1

    # The real-KDC tests have their own job; here they would only skip themselves.
    echo "Running test suite (without the real-KDC tests)…"
    cargo test --workspace --all-features -- --skip against_a_real_kdc --skip trusted_realm_against_real_kdcs
}

job_kdc_test() {
    require_cargo || return 1
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
    echo "Building with Rust $MSRV…"
    rustup run "$MSRV" cargo build --workspace --all-targets
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
  * OTP enrollment strings for web1..webN.example.test and an administrator,
    admin@EXAMPLE.TEST (password Secret123);
  * the kuipa, kuipa-unseal, kuipa-voucher, tang-pqc and kuipa-playground binaries on PATH, and
    shell helpers (pq_host, pq_enroll, pq_down/pq_up, pq_bootstrap, pq_log).

Exiting the shell (exit, Ctrl-D) tears everything down.

Options:
  --hosts N    OTP enrollment strings to create (default: 5)
  --keep       Keep the realm's files after exit (KUIPA_KEEP_REALM)

See docs/local-ci.md for a walkthrough.
EOF
}

run_interactive_playground() {
    require_cargo || return 1
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
    cargo build -p kuipa-tools -p tang-pqc-clevis --bins --example kuipa-playground || return 1
    local bin="${CARGO_TARGET_DIR:-$REPO_ROOT/target}/debug"

    # Cleanup runs explicitly at every exit point (the function's locals are
    # gone by the time a script-level EXIT trap would fire); INT/TERM are
    # trapped for signals that arrive while the playground is starting.
    local work="" pg_pid="" cleaned=0
    playground_cleanup() {
        [[ "$cleaned" == 1 ]] && return
        cleaned=1
        echo
        echo "Tearing down the playground…"
        [[ -n "$pg_pid" ]] && { kill "$pg_pid" 2>/dev/null || true; wait "$pg_pid" 2>/dev/null || true; }
        [[ -n "$work" ]] && rm -rf "$work"
    }
    trap playground_cleanup INT TERM

    work="$(mktemp -d /tmp/kuipa-playground.XXXXXXXXXX)"
    local env_file="$work/env.sh" log="$work/servers.log"
    # The servers run in the background; the shell below owns the terminal.
    "$bin/examples/kuipa-playground" run --env-file "$env_file" --hosts "$hosts" >"$log" 2>&1 </dev/null &
    pg_pid=$!
    for _ in $(seq 1 100); do
        [[ -f "$env_file" ]] && break
        kill -0 "$pg_pid" 2>/dev/null || break
        sleep 0.1
    done
    if [[ ! -f "$env_file" ]]; then
        cat "$log" 2>/dev/null || true
        playground_cleanup
        fail "the playground did not start; see the log above"
        return 1
    fi

    {
        echo '[ -f ~/.bashrc ] && . ~/.bashrc'
        echo ". '$env_file'"
        echo "export PATH='$bin:$bin/examples':\"\$PATH\""
        echo "export PQ_SERVER_LOG='$log'"
        echo 'pq_log() { tail -n "${1:-20}" "$PQ_SERVER_LOG"; }'
        echo 'pq_host web1'
    } >"$work/rc"

    # shellcheck disable=SC1090
    source "$env_file"
    echo
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${BOLD}kuipa playground ready${NC}"
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo "  realm:        EXAMPLE.TEST  (KDC on $PQ_KDC_SOCKET)"
    echo "  servers:      ipa1.example.test, ipa2.example.test  (pq_log shows their log)"
    echo "  anchor:       $PQ_ANCHOR"
    echo "  admin:        admin@EXAMPLE.TEST, password Secret123"
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
    echo
    echo "  Exit this shell (exit or Ctrl-D) to tear the playground down."
    echo -e "${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo

    bash --rcfile "$work/rc" -i || true

    playground_cleanup
    trap - INT TERM
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
        msrv)           run_job msrv           job_msrv ;;
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
               and see docs/local-ci.md for a walkthrough.

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
  KUIPA_KEEP_REALM   Keep the kdc-test realm's files (/tmp/kuipa-kdc-<pid>).

Examples:
  $(basename "$0") all
  $(basename "$0") build test
  $(basename "$0") --no-color all
  $(basename "$0") --valgrind test
  CARGO_TARGET_DIR=/tmp/kuipa-target $(basename "$0") all
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
