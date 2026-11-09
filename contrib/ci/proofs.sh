#!/usr/bin/env bash
# proofs.sh — verify every lemma in a peer theory and print a ledger.
#
# Each invocation runs in its own bounded systemd user scope: these searches
# grow without limit, and an unbounded run has taken the machine down. A scope
# limit is per-unit and free machine memory is not, so do not run two provers
# at once — a run that fits its own limit can still be killed.
#
# One lemma per process. Batch mode prints "analysis incomplete" for lemmas it
# did not request and prints no summary at all when the process is killed, so
# its output cannot be read as per-lemma verdicts.
#
# Usage:
#   ./contrib/ci/proofs.sh [-m GiB] [-t seconds] [-k REGEX] THEORY.spthy...
#   ./contrib/ci/proofs.sh -l                    # list lemmas, prove nothing
#   -k REGEX  prove only lemmas whose name matches, for iterating on one goal
#
# Exit status is 0 when every lemma verifies, 1 when any is open or falsified.

set -uo pipefail

TAMARIN=${TAMARIN:-tamarin-prover}
MEM=8
TIME=300
# Theories whose derivation check exceeds Tamarin's five-second default before
# any lemma runs: with --quit-on-warning that aborts the run, which reads as a
# fast OPEN when in fact no lemma was attempted. Everything else keeps the
# default, because generating the extra case rules changes which searches
# terminate - so a lemma's verdict is only comparable within one setting.
DERIVCHECK='peer-pruning kuipa trust sign'
# Theories that deliberately let a rule match through an equation (a fact
# carrying kem_ct(k, x) so the rule recovers x): Tamarin reports that as a
# wellformedness warning about unintended pattern matching, and --quit-on-warning
# would then abort before any lemma runs. Each such theory is listed here and its
# warning is accepted; a theory NOT listed gets --quit-on-warning, which is what
# catches genuinely accidental pattern matching.
NOWARN_ACCEPT='tang-pqc'

usage() { sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 2; }

LIST=0
FILTER=''
while getopts 'm:t:k:lh' o; do
    case $o in
        m) MEM=$OPTARG ;;
        t) TIME=$OPTARG ;;
        k) FILTER=$OPTARG ;;
        l) LIST=1 ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))
[[ $# -eq 0 ]] && usage

command -v "$TAMARIN" >/dev/null || { echo "error: $TAMARIN not found (set TAMARIN)" >&2; exit 2; }
command -v maude >/dev/null || { echo "error: maude not on PATH" >&2; exit 2; }

fail=0
for theory in "$@"; do
    [[ -f "$theory" ]] || { echo "error: no such theory: $theory" >&2; exit 2; }
    base=$(basename "$theory" .spthy)
    log=$(mktemp)
    OPENREUSE=''
    # Lemma identifiers may start with an uppercase letter (Attack_*, Seal*);
    # a lowercase-only pattern silently proves nothing in those theories.
    for lemma in $(grep -oE '^lemma [A-Za-z_][A-Za-z0-9_]*' "$theory" | cut -d' ' -f2); do
        # -k proves a subset only; proofs are unaffected because [reuse] sources
        # come from the file, not from what this run requested.
        [[ -n $FILTER ]] && ! printf '%s' "$lemma" | grep -qE "$FILTER" && continue
        if [[ $LIST -eq 1 ]]; then
            echo "$base $lemma"
            continue
        fi
        extra=()
        for d in $DERIVCHECK; do
            [[ $base == "$d" ]] && extra=(--derivcheck-timeout=180)
        done
        QUITONWARN='--quit-on-warning'
        for a in $NOWARN_ACCEPT; do
            [[ $base == "$a" ]] && QUITONWARN=''
        done
        systemd-run --user --scope -p "MemoryMax=${MEM}G" -p MemorySwapMax=0 \
            -p TasksMax=64 timeout "${TIME}s" \
            "$TAMARIN" "${extra[@]}" --prove="$lemma" $QUITONWARN \
            "$theory" +RTS -N1 -RTS >"$log" 2>&1
        status=$?
        verdict=$(grep -E "^  $lemma \(" "$log")
        case $verdict in
            *verified*) printf 'ok    %s %s\n' "$base" "$lemma" ;;
            *falsified*)
                printf 'FALSE %s %s\n' "$base" "$lemma"
                fail=1
                ;;
            *)
                # 124 is the timeout's, 137 the cgroup's: neither is a verdict.
                printf 'OPEN  %s %s (exit %s)\n' "$base" "$lemma" "$status"
                fail=1
                # An OPEN lemma marked [reuse] is assumed by every later proof.
                grep -qE "^lemma $lemma \[[^]]*reuse" "$theory" &&
                    OPENREUSE="$OPENREUSE $lemma"
                ;;
        esac
    done
    rm -f "$log"
    # [reuse] injects a lemma's STATEMENT into every later proof, whether or not
    # that lemma itself was proved in this run (with --prove only one lemma is
    # ever attempted, so an earlier [reuse] source is always an assumption). A
    # lemma that reports OPEN while marked [reuse] therefore makes every "ok"
    # after it conditional on an open goal. Say so rather than leaving the ledger
    # to be read as a list of proofs.
    if [[ -n $OPENREUSE ]]; then
        printf 'note  %s lemmas AFTER these may rest on an unproved [reuse] source\n' "$base" >&2
        printf 'note  %s unproved [reuse] sources: %s\n' "$base" "$OPENREUSE" >&2
    fi
done
exit $fail
