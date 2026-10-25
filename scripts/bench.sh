#!/usr/bin/env bash
# scripts/bench.sh — kuipa benchmark orchestration
#
# Runs the criterion targets in the crates under test at a chosen profile,
# collects criterion's estimates into one JSON file, and stores it with the
# fixture sizes and git/platform metadata that produced them. Comparison is
# done from those stored files, so a baseline survives a `cargo clean`.
#
# Usage: bench.sh [OPTIONS] [COMMAND]
#
# Commands:
#   run                Run the benchmarks and save results (default)
#   compare DIR1 DIR2  Compare two saved result directories
#   list               List saved benchmark results
#   targets            List the bench targets and the crates that own them
#
# Run options:
#   --profile NAME      smoke|production|pqproduction|large (default: production)
#   --targets LIST      Comma-separated targets (default: all)
#   --quick             Fewer samples: --sample-size 10 --measurement-time 1
#   --samples N         Criterion sample size
#   --measurement SEC   Criterion measurement time per benchmark
#   --baseline NAME     Also save results as criterion baseline NAME
#   --no-save           Run without storing results
#   --results-dir DIR   Override result storage (default: ~/.cache/kuipa-bench)
#   --compare PATH      After a run, compare against this saved directory
#   --output FILE       Write the collected results to FILE
#   -h, --help

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ──────────────────────────────────────────────────────────────────

COMMAND="run"
PROFILE="${KUIPA_BENCH_PROFILE:-production}"
TARGETS="crypto,protocol,anchors,escrow,blind,certs"
QUICK=0
SAMPLES=""
MEASUREMENT=""
BASELINE=""
SAVE=1
COMPARE_PREV=""
RESULTS_BASE="${XDG_CACHE_HOME:-$HOME/.cache}/kuipa-bench"
OUTPUT_FILE=""
CRITERION_DIR="$REPO_ROOT/target/criterion"
COMPARE_DIR1=""
COMPARE_DIR2=""

# Each bench target lives in the crate whose code it measures; kuipa-perf owns
# only the certificate-cost target.
target_package() {
    case "$1" in
        crypto | protocol | anchors | escrow) echo kuipa-enroll ;;
        blind) echo ml-dsa-blind ;;
        certs) echo kuipa-perf ;;
        *) return 1 ;;
    esac
}

usage() {
    grep '^#' "$0" | grep -v '^#!/' | sed 's/^# \?//' | head -27
    exit 0
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        run | compare | list | targets) COMMAND="$1"; shift ;;
        --profile) PROFILE="$2"; shift 2 ;;
        --targets) TARGETS="$2"; shift 2 ;;
        --quick) QUICK=1; shift ;;
        --samples) SAMPLES="$2"; shift 2 ;;
        --measurement) MEASUREMENT="$2"; shift 2 ;;
        --baseline) BASELINE="$2"; shift 2 ;;
        --no-save) SAVE=0; shift ;;
        --results-dir) RESULTS_BASE="$2"; shift 2 ;;
        --compare) COMPARE_PREV="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        -h | --help) usage ;;
        *)
            if [[ "$COMMAND" == "compare" ]]; then
                COMPARE_DIR1="$1"
                shift
                COMPARE_DIR2="${1:-}"
                [[ -n "$COMPARE_DIR2" ]] && shift
            else
                echo "Unknown argument: $1" >&2
                exit 2
            fi
            ;;
        esac
done

# ── Criterion flags ───────────────────────────────────────────────────────────

CRITERION_ARGS=()
if [[ "$QUICK" == "1" ]]; then
    CRITERION_ARGS+=(--sample-size 10 --measurement-time 1)
fi
[[ -n "$SAMPLES" ]] && CRITERION_ARGS+=(--sample-size "$SAMPLES")
[[ -n "$MEASUREMENT" ]] && CRITERION_ARGS+=(--measurement-time "$MEASUREMENT")
[[ -n "$BASELINE" ]] && CRITERION_ARGS+=(--save-baseline "$BASELINE")

# ── Collection ────────────────────────────────────────────────────────────────

# Flatten criterion's per-benchmark estimates into one JSON array, keyed by
# full benchmark id, so comparison works after criterion's directory is gone.
collect_results() {
    python3 - "$CRITERION_DIR" <<'PY'
import json, os, sys

root = sys.argv[1]
out = []
for base, _dirs, files in os.walk(root):
    if os.path.basename(base) != "new" or "estimates.json" not in files:
        continue
    with open(os.path.join(base, "benchmark.json"), encoding="utf-8") as fh:
        info = json.load(fh)
    with open(os.path.join(base, "estimates.json"), encoding="utf-8") as fh:
        e = json.load(fh)
    ms = 1e6
    entry = {
        "id": info["full_id"],
        "group": info["group_id"],
        # Criterion leaves function_id null for benchmarks that are not
        # created through bench_with_input; the tail of full_id is it.
        "function": info.get("function_id")
        or info["full_id"].removeprefix(info["group_id"] + "/"),
        "mean_ms": e["mean"]["point_estimate"] / ms,
        "mean_ci_ms": [
            e["mean"]["confidence_interval"]["lower_bound"] / ms,
            e["mean"]["confidence_interval"]["upper_bound"] / ms,
        ],
        "median_ms": e["median"]["point_estimate"] / ms,
        "std_dev_ms": e["std_dev"]["point_estimate"] / ms,
    }
    tp = info.get("throughput")
    if tp:
        for kind, value in tp.items():
            entry["throughput"] = {"kind": kind, "value": value}
            break
    sample = os.path.join(base, "sample.json")
    if os.path.exists(sample):
        with open(sample, encoding="utf-8") as fh:
            raw = json.load(fh)
        # sample.json holds parallel `iters`/`times` (ns) lists.
        entry["samples"] = [[t / ms, i] for i, t in list(zip(raw["iters"], raw["times"]))[:20]]
        entry["sample_count"] = len(raw["times"])
    out.append(entry)

out.sort(key=lambda e: e["id"])
print(json.dumps(out, indent=2))
PY
}

# ── Result saving ─────────────────────────────────────────────────────────────

save_results() {
    local results_dir="$1"
    local results_json="$2"

    mkdir -p "$results_dir"

    local git_commit git_dirty fixture
    git_commit=$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo unknown)
    if git -C "$REPO_ROOT" diff --quiet HEAD 2>/dev/null; then
        git_dirty="False"
    else
        git_dirty="True"
    fi
    fixture=$(cargo run -q --manifest-path "$REPO_ROOT/Cargo.toml" -p kuipa-perf \
        --bin bench-meta -- "$PROFILE")

    KUIPA_FIXTURE="$fixture" \
    KUIPA_FLAGS="${CRITERION_ARGS[*]:-}" \
        python3 - "$git_commit" "$git_dirty" "$PROFILE" "$TARGETS" "$results_json" \
        >"$results_dir/params.json" <<'PY'
import datetime, json, os, platform, sys

commit, dirty, profile, targets, results = sys.argv[1:6]
fixture = json.loads(os.environ.get("KUIPA_FIXTURE", "{}"))
flags = os.environ.get("KUIPA_FLAGS", "").split()
print(json.dumps({
    "timestamp": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "git_commit": commit,
    "git_dirty": dirty == "True",
    "profile": profile,
    "fixture": fixture,
    "targets": [t for t in targets.split(",") if t],
    "criterion_flags": flags,
    "release": True,
    "platform": {
        "system": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
    },
    "benchmark_count": len(json.load(open(results, encoding="utf-8"))),
}, indent=2))
PY

    cp "$results_json" "$results_dir/results.json"
    echo "  Results saved to: $results_dir"
}

# ── Run ───────────────────────────────────────────────────────────────────────

run_benchmarks() {
    local IFS=','
    for target in $TARGETS; do
        local pkg
        pkg=$(target_package "$target") || {
            echo "Unknown bench target: $target" >&2
            exit 2
        }
        echo "==> $pkg/$target (profile $PROFILE)"
        KUIPA_BENCH_PROFILE="$PROFILE" cargo bench -p "$pkg" --bench "$target" \
            --manifest-path "$REPO_ROOT/Cargo.toml" -- "${CRITERION_ARGS[@]+"${CRITERION_ARGS[@]}"}"
    done
}

print_summary() {
    local results_json="$1"
    python3 - "$results_json" <<'PY'
import json, sys

with open(sys.argv[1], encoding="utf-8") as fh:
    results = json.load(fh)
print()
print("=== kuipa benchmark summary ===")
print(f"{len(results)} benchmarks")
group = None
for r in results:
    if r["group"] != group:
        group = r["group"]
        print(f"\n[{group}]")
    line = f"  {r['function']:<28} mean {r['mean_ms']:10.3f} ms"
    tp = r.get("throughput")
    if tp and tp["kind"] == "Bytes":
        line += f"  ({tp['value'] / (r['mean_ms'] / 1e3) / 1e6:9.1f} MB/s)"
    elif tp:
        line += f"  ({tp['value'] / (r['mean_ms'] / 1e3):9.1f} /s)"
    print(line)
PY
}

# ── Compare ───────────────────────────────────────────────────────────────────

compare_results() {
    local a="$1" b="$2"
    local fa="$a/results.json" fb="$b/results.json"
    if [[ ! -f "$fa" || ! -f "$fb" ]]; then
        echo "Both directories need results.json (from a previous run)" >&2
        exit 1
    fi
    python3 - "$fa" "$fb" "$a" "$b" <<'PY'
import json, os, sys

fa, fb, da, db = sys.argv[1:5]
base = {r["id"]: r for r in json.load(open(fa, encoding="utf-8"))}
new = {r["id"]: r for r in json.load(open(fb, encoding="utf-8"))}

def label(d):
    try:
        p = json.load(open(os.path.join(d, "params.json"), encoding="utf-8"))
        return f"{p['git_commit']} {p['profile']} {p['timestamp']}"
    except Exception:
        return d

print(f"baseline: {label(da)}")
print(f"current:  {label(db)}")
print()
common = sorted(set(base) & set(new))
rows = [(new[k]["mean_ms"] / base[k]["mean_ms"], k, base[k]["mean_ms"], new[k]["mean_ms"]) for k in common]
regressions = [r for r in rows if r[0] > 1.10]
improvements = [r for r in rows if r[0] < 0.90]

print(f"{len(common)} benchmarks compared")
print(f"  regressions >10%: {len(regressions)}   improvements >10%: {len(improvements)}")
if regressions:
    print("\nRegressions:")
    for ratio, k, b, n in sorted(regressions, reverse=True)[:15]:
        print(f"  {ratio:5.2f}x  {k:<34} {b:9.3f} -> {n:9.3f} ms")
if improvements:
    print("\nImprovements:")
    for ratio, k, b, n in sorted(improvements)[:15]:
        print(f"  {ratio:5.2f}x  {k:<34} {b:9.3f} -> {n:9.3f} ms")
missing = sorted(set(base) - set(new))
if missing:
    print(f"\nOnly in baseline: {len(missing)} (e.g. {missing[0]})")
added = sorted(set(new) - set(base))
if added:
    print(f"Only in current:  {len(added)} (e.g. {added[0]})")
PY
}

# ── List ──────────────────────────────────────────────────────────────────────

list_results() {
    [[ -d "$RESULTS_BASE" ]] || {
        echo "No saved results in $RESULTS_BASE"
        exit 0
    }
    python3 - "$RESULTS_BASE" <<'PY'
import json, os, sys

base = sys.argv[1]
rows = []
for name in os.listdir(base):
    p = os.path.join(base, name, "params.json")
    if not os.path.isfile(p):
        continue
    try:
        d = json.load(open(p, encoding="utf-8"))
    except Exception:
        continue
    rows.append((d.get("timestamp", "?"), name, d.get("git_commit", "?"),
                 d.get("profile", "?"), d.get("benchmark_count", "?"),
                 "dirty" if d.get("git_dirty") else "clean"))
for ts, name, commit, profile, count, state in sorted(rows, reverse=True):
    print(f"{ts}  {name:<24} {commit:<8} {profile:<12} {count:>4} benchmarks  {state}")
if not rows:
    print(f"No saved results in {base}")
PY
}

# ── Dispatch ──────────────────────────────────────────────────────────────────

case "$COMMAND" in
    targets)
        for t in crypto protocol anchors escrow blind certs; do
            printf '%-10s %s\n' "$t" "$(target_package "$t")"
        done
        ;;
    list)
        list_results
        ;;
    compare)
        [[ -n "$COMPARE_DIR1" && -n "$COMPARE_DIR2" ]] || {
            echo "compare needs two result directories" >&2
            exit 2
        }
        compare_results "$COMPARE_DIR1" "$COMPARE_DIR2"
        ;;
    run)
        WORKDIR=$(mktemp -d)
        trap 'rm -rf "$WORKDIR"' EXIT
        run_benchmarks
        collect_results >"$WORKDIR/results.json"
        print_summary "$WORKDIR/results.json"
        [[ -n "$OUTPUT_FILE" ]] && cp "$WORKDIR/results.json" "$OUTPUT_FILE"
        if [[ "$SAVE" == "1" ]]; then
            stamp=$(date -u +%Y%m%dT%H%M%SZ)
            save_results "$RESULTS_BASE/$stamp" "$WORKDIR/results.json"
            [[ -n "$COMPARE_PREV" ]] && compare_results "$COMPARE_PREV" "$RESULTS_BASE/$stamp"
        fi
        ;;
    *)
        echo "Unknown command: $COMMAND" >&2
        exit 2
        ;;
esac
