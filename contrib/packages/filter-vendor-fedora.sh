#!/bin/bash
# filter-vendor-fedora.sh — identify vendored crates replaceable by Fedora packages
#
# Scans a cargo vendor directory, queries the currently configured dnf repos
# for crate() provides, and records crates that can be replaced by system
# packages at build time.  Crate directories are NOT removed from vendor/ —
# the tarball stays self-sufficient so a single SRPM builds across Fedora
# versions even when older releases ship different crate versions.
#
# At RPM build time the spec overlays system crate sources onto vendor/
# when available, falling back to the vendor copy otherwise.
#
# Usage:
#   ./filter-vendor-fedora.sh VENDOR_DIR [OUTPUT_FILE]
#
# Arguments:
#   VENDOR_DIR   — path to the cargo vendor directory (e.g. vendor/)
#   OUTPUT_FILE  — manifest of replaceable crates (default: system-crates.txt)
#                  Format: one "NAME VERSION CHECKSUM" triple per line,
#                  sorted by name.  CHECKSUM is the package hash from the
#                  vendored .cargo-checksum.json (needed because system crate
#                  directories ship "package":"" which does not match
#                  Cargo.lock checksums).
#
# Exit codes:
#   0  — success (some or no crates recorded)
#   2  — bad arguments / directory not found

set -euo pipefail

if [[ $# -lt 1 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    sed -n '/^# Usage:/,/^[^#]/{ /^[^#]/q; s/^# \{0,2\}//; p }' "$0"
    exit 2
fi

VENDOR_DIR="$1"
OUTPUT="${2:-system-crates.txt}"

if [[ ! -d "$VENDOR_DIR" ]]; then
    printf 'error: %s: directory not found\n' "$VENDOR_DIR" >&2
    exit 2
fi

# ── 1. Fetch crate() provides from all configured repos (single dnf query) ────

_provides_tmp=$(mktemp -t filter-vendor-fedora.XXXXXX)
trap 'rm -f "$_provides_tmp"' EXIT

printf 'Fetching crate() provides from dnf repos... '
dnf repoquery --provides --quiet --refresh 2>/dev/null \
    | grep '^crate(' | sort -u > "$_provides_tmp" || true
printf 'done (%d provides).\n' "$(wc -l < "$_provides_tmp")"

# ── 2. Scan vendor directories and match against provides ─────────────────────

# Crates to keep vendored even when Fedora provides the exact version.
# Fedora may patch crate dependencies (e.g. sqlx-postgres: whoami ^1 → ^2)
# making the system version incompatible with upstream Cargo.lock under --locked.
EXCLUDE_PATTERN='^(sqlx|sqlx-core|sqlx-macros|sqlx-macros-core|sqlx-mysql|sqlx-postgres|sqlx-sqlite)$'

matched=0
total=0
: > "$OUTPUT"

for cargo_toml in "$VENDOR_DIR"/*/Cargo.toml; do
    crate_dir=$(dirname "$cargo_toml")

    # Parse name and version from the crate's Cargo.toml (robust against
    # dashed crate names like "async-trait" where splitting on the last
    # dash is ambiguous).
    name=$(sed -n '/^\[package\]/,/^\[/{/^name *= *"/{s/.*= *"//;s/".*//;p;q}}' "$cargo_toml")
    version=$(sed -n '/^\[package\]/,/^\[/{/^version *= *"/{s/.*= *"//;s/".*//;p;q}}' "$cargo_toml")

    if [[ -z "$name" ]] || [[ -z "$version" ]]; then
        continue
    fi

    total=$(( total + 1 ))
    provide="crate(${name}) = ${version}"

    if echo "$name" | grep -qE "$EXCLUDE_PATTERN"; then
        continue
    fi

    if grep -qF "$provide" "$_provides_tmp"; then
        cksum=$(python3 -c "import json,sys; print(json.load(open(sys.argv[1])).get('package',''))" \
            "$crate_dir/.cargo-checksum.json" 2>/dev/null || true)
        printf '%s %s %s\n' "$name" "$version" "$cksum" >> "$OUTPUT"
        matched=$(( matched + 1 ))
    fi
done

sort -o "$OUTPUT" "$OUTPUT"
printf 'Recorded %d / %d vendored crates replaceable by Fedora packages.\n' "$matched" "$total"
