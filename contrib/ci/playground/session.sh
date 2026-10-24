#!/usr/bin/env bash
# contrib/ci/playground/session.sh -- a scripted, traced playground session
#
# Runs the steps below in one shell inside a running playground, the way a
# person would at the 'local-ci.sh interactive' prompt, with KUIPA_TRACE on.
# Steps share the shell, so state carries over: pq_host switches the current
# host for the steps after it, and an enrolled host stays enrolled.
#
# For each step it records, under OUT/steps/NNN/:
#   meta.env   section, title, expected and actual exit status, duration,
#              whether it timed out
#   command    the command line, as typed
#   stdout     the command's result
#   stderr     its trace (KUIPA_TRACE) and error messages
#   server.log what the playground's servers logged during the step
#   expect     text the output must contain, one per line, if any
#   missing    the expected text that was not there, if any
# and OUT/session.env with the realm's details.  report.py renders it.
#
# A step that runs longer than KUIPA_STEP_TIMEOUT seconds (default 120) is
# stopped and fails; the session goes on, so the report is still written.
#
# Usage (local-ci.sh playground-test runs it):
#   session.sh ENV_FILE SERVER_LOG OUT
# with the playground's binaries on PATH.  Exits 1 if any step fails: a
# different exit status than expected, expected output missing, or a
# timeout.
set -uo pipefail

env_file="$1" server_log="$2" out="$3"
mkdir -p "$out/steps"

# shellcheck disable=SC1090
source "$env_file"
# Every detail from the client tools, debug messages from the GSS-API
# bindings (docs/DESIGN.md §10.4).  Traces never contain secrets.
export KUIPA_TRACE="kuipa_tools=trace,kuipa_gssapi=debug"

{
    printf 'realm=EXAMPLE.TEST\n'
    printf 'trusted_realm=%s\n' "$PQ_TRUSTED_REALM"
    printf 'servers=%s\n' "$PQ_SERVERS"
    printf 'anchor=%s\n' "$PQ_ANCHOR"
    printf 'trace=%s\n' "$KUIPA_TRACE"
} > "$out/session.env"

n=0 failed=0
section="" section_text=""
step_timeout="${KUIPA_STEP_TIMEOUT:-120}"

# section TITLE TEXT: start a group of steps, with a sentence explaining it.
section() { section="$1"; section_text="$2"; }
# Nanoseconds since the epoch, on a `date` that may lack %N (older BSD).
now_ns() {
    local t
    t=$(date +%s%N 2>/dev/null) || t=""
    if [[ "$t" =~ ^[0-9]+$ ]]; then
        printf '%s\n' "$t"
    else
        printf '%s000000000\n' "$(date +%s)"
    fi
}

# The process IDs of every descendant of process $1, leaving out process
# $2 and its own descendants: from /proc where it exists, otherwise from
# `pgrep -P`, which macOS ships.
descendants() {
    local stat rest ppid pid kid
    if [[ -d /proc ]]; then
        for stat in /proc/[0-9]*/stat; do
            pid="${stat#/proc/}" pid="${pid%/stat}"
            [[ "$pid" == "$2" ]] && continue
            rest="$(cat "$stat" 2>/dev/null)" || continue
            rest="${rest##*) }"
            read -r _ ppid _ <<< "$rest"
            if [[ "$ppid" == "$1" ]]; then
                echo "$pid"
                descendants "$pid" "$2"
            fi
        done
        return
    fi
    for kid in $(pgrep -P "$1" 2>/dev/null); do
        [[ "$kid" == "$2" ]] && continue
        echo "$kid"
        descendants "$kid" "$2"
    done
}

# watchdog SHELL MARK: after $step_timeout seconds, create MARK and stop
# what SHELL is running for the step (its children and theirs), but not
# this watchdog.
watchdog() {
    local shell="$1" mark="$2" i
    for ((i = 0; i < step_timeout * 10; i++)); do sleep 0.1; done
    : > "$mark"
    local me="$BASHPID" pids
    pids=$(descendants "$shell" "$me")
    # shellcheck disable=SC2086 # one PID per word
    [[ -n "$pids" ]] && kill -TERM $pids 2>/dev/null
    sleep 5
    pids=$(descendants "$shell" "$me")
    # shellcheck disable=SC2086
    [[ -n "$pids" ]] && kill -KILL $pids 2>/dev/null
}

# step EXPECT TITLE COMMAND [TEXT...]: run COMMAND (a shell line) in this
# shell, at most $step_timeout seconds.
#   EXPECT  the exit status it must end with: a number, or "fail" for any
#           non-zero status
#   TEXT    each must appear in the output (standard output or error):
#           what makes the step show what it is meant to, e.g. why it failed
step() {
    local expect="$1" title="$2" cmd="$3"
    shift 3
    n=$((n + 1))
    local d
    d="$out/steps/$(printf '%03d' "$n")"
    mkdir -p "$d"
    printf '%s\n' "$cmd" > "$d/command"
    local offset t0 t1 rc dog shell="$BASHPID"
    offset=$(wc -c < "$server_log" 2>/dev/null || echo 0)
    t0=$(now_ns)
    # $shell is taken here: in the background job $BASHPID would be the
    # watchdog's own.
    watchdog "$shell" "$d/timed-out" &
    dog=$!
    eval "$cmd" > "$d/stdout" 2> "$d/stderr" < /dev/null
    rc=$?
    kill "$dog" 2>/dev/null
    wait "$dog" 2>/dev/null
    t1=$(now_ns)
    tail -c +"$((offset + 1))" "$server_log" > "$d/server.log" 2>/dev/null || true

    local ok=0 timed_out=0 text
    if [[ -e "$d/timed-out" ]]; then
        timed_out=1
        rm -f "$d/timed-out"
    elif [[ "$expect" == fail ]]; then
        [[ $rc -ne 0 ]] && ok=1
    elif [[ $rc -eq $expect ]]; then
        ok=1
    fi
    for text in "$@"; do
        printf '%s\n' "$text" >> "$d/expect"
        # Not `cat … | grep -q`: BSD grep stops reading at the first match,
        # and under pipefail the pipeline's status is then cat's SIGPIPE,
        # which reads as a failure even though the text was found.
        if ! grep -qF -- "$text" "$d/stdout" "$d/stderr"; then
            printf '%s\n' "$text" >> "$d/missing"
            ok=0
        fi
    done
    [[ $ok -eq 1 ]] || failed=$((failed + 1))
    {
        printf 'section=%s\n' "$section"
        printf 'section_text=%s\n' "$section_text"
        printf 'title=%s\n' "$title"
        printf 'expected=%s\n' "$expect"
        printf 'status=%s\n' "$rc"
        printf 'passed=%s\n' "$ok"
        printf 'timed_out=%s\n' "$timed_out"
        printf 'timeout=%s\n' "$step_timeout"
        printf 'ms=%s\n' "$(((t1 - t0) / 1000000))"
    } > "$d/meta.env"
    local note=""
    [[ $timed_out -eq 1 ]] && note=" (timed out after ${step_timeout}s)"
    [[ -s "$d/missing" ]] && note+=" (missing from the output: $(paste -sd';' "$d/missing"))"
    printf '  %-4s %3s  %s%s\n' "$([[ $ok -eq 1 ]] && echo ok || echo FAIL)" "$rc" "$title" "$note"
}

section "OTP enrollment" \
    "web1 enrolls with its one-time password: the host verifies the realm advertisement against the anchor in its enrollment string, and receives its keytab under ML-KEM."
step 0 "Enroll web1 with its OTP enrollment string" 'pq_enroll web1' \
    "principal: host/web1.example.test@EXAMPLE.TEST"
step 0 "Show web1's state" 'kuipa status'

section "Rekey and health check" \
    "The host replaces its keys through a request authenticated by its own keytab, then checks every server: advertisement, delegation, a kinit with the new keys."
step 0 "Rotate web1's keys" 'kuipa rotate-keys'
step 0 "Check web1 against every server" 'kuipa check'

section "Keytab protection" \
    "The keytab is sealed on disk: unsealing it needs one of the IPA servers, as at boot."
step 0 "Seal web1's keytab" 'kuipa protect'
step 0 "Unseal it, as kuipa-unseal does at boot" 'kuipa-unseal'
step 0 "Check web1 with the sealed keytab" 'kuipa check'
step 0 "Write the plain keytab back" 'kuipa unprotect'

section "Protecting any file" \
    "Any file can be sealed the same way, for the principal of a keytab (the host's by default): its bindings are registered with that principal's own ticket, and a host rekey leaves them in place."
step 0 "Write an application secret" \
    'mkdir -p "$KUIPA_ROOT/etc/app" && echo "token=playground" > "$KUIPA_ROOT/etc/app/secret.conf"'
step 0 "Seal it for web1's host principal" \
    'kuipa protect --file "$KUIPA_ROOT/etc/app/secret.conf"' \
    "bindings registered for: host/web1.example.test@EXAMPLE.TEST"
step 0 "Rotate web1's keys: only the keytab bindings change" 'kuipa rotate-keys'
step 0 "Unseal everything, as kuipa-unseal does at boot" 'kuipa-unseal --all'
step 0 "Read the secret through its symlink" 'cat "$KUIPA_ROOT/etc/app/secret.conf"' \
    "token=playground"
step 0 "Unseal it to standard output: only the plaintext, traces on stderr" \
    'diff <(kuipa-unseal --sealed "$KUIPA_ROOT/etc/app/secret.conf.sealed" --out -) "$KUIPA_ROOT/etc/app/secret.conf"'
step 1 "Refuse --out /dev/stdout, which would replace the link" \
    'kuipa-unseal --sealed "$KUIPA_ROOT/etc/app/secret.conf.sealed" --out /dev/stdout'
step 0 "Write the plain file back and retire its bindings" \
    'kuipa unprotect --file "$KUIPA_ROOT/etc/app/secret.conf"' \
    "are retired"

section "Sealing your own files" \
    "A user seals files of their own to a vault of theirs: opening needs this host's device key (under a passphrase), the user's Kerberos ticket, and a server that agrees. Nothing here runs as root."
step 0 "Log in as the administrator" 'pq_admin_kinit'
step 0 "Create a vault that needs a device and the ticket" \
    'kuipa seal create personal --require device,ticket' \
    "opening needs: a registered device (any) and your Kerberos ticket"
step 0 "Register this host's device key, made under a passphrase" \
    'echo "correct horse" > "$KUIPA_PLAYGROUND/pass" && kuipa seal device add personal --passphrase-file "$KUIPA_PLAYGROUND/pass"'
step 0 "Seal a file, offline once the vault is described" \
    'echo "token=playground-user" > "$KUIPA_PLAYGROUND/notes.txt" && kuipa seal file personal "$KUIPA_PLAYGROUND/notes.txt"'
step 0 "Open it to standard output: only the plaintext arrives" \
    'kuipa seal open "$KUIPA_PLAYGROUND/notes.txt.sealed" --out - --passphrase-file "$KUIPA_PLAYGROUND/pass" | cat' \
    "token=playground-user"
step 1 "A wrong passphrase does not open the device key" \
    'echo wrong > "$KUIPA_PLAYGROUND/wrong" && kuipa seal open "$KUIPA_PLAYGROUND/notes.txt.sealed" --out - --passphrase-file "$KUIPA_PLAYGROUND/wrong"'

section "Your vault's transparency log" \
    "Every server logs each change to a vault and each release of its share of a file, in a public log it cannot rewrite unnoticed.  kuipa tlog watch checks every server's log for the vault and flags what the vault description stored on this host does not account for; kuipa-audit tlog replays a server's whole log, naming nobody."
step 0 "The first watch records where each log stands" \
    'kuipa tlog watch personal' "baseline" "add-device" "release" "UTC" "0 unexpected"
step 0 "Nothing new since: a quiet watch" \
    'kuipa tlog watch personal' "0 unexpected"
step 0 "A second device is registered from another home directory" \
    'KUIPA_USER_DIR="$KUIPA_PLAYGROUND/users/admin-laptop" kuipa seal device add personal --passphrase-file "$KUIPA_PLAYGROUND/pass"'
step 1 "This host's watch flags the device it does not know" \
    'kuipa tlog watch personal' "UNEXPECTED" "add-device" "1 unexpected"
step 0 "Accept it: seal show stores the current description" \
    'kuipa seal show personal'
step 0 "The flag was reported once; the next watch is clean" \
    'kuipa tlog watch personal' "0 unexpected"
step 0 "Opening a file is logged as a release; --json keeps Unix times" \
    'kuipa seal open "$KUIPA_PLAYGROUND/notes.txt.sealed" --out - --passphrase-file "$KUIPA_PLAYGROUND/pass" >/dev/null && w=$(kuipa --json tlog watch personal) && echo "$w" && grep -Eq "\"time\":[0-9]+[,}]" <<<"$w"' \
    '"action":"release"' '"unexpected":0'
step 0 "An auditor replays ipa1's whole log from its public routes" \
    'kuipa-audit tlog --server ipa1.example.test --state "$KUIPA_PLAYGROUND/tlog-audit.json"' \
    "verified" "vault-device" "escrow-release"
step 0 "The next audit requires the log to extend the recorded head" \
    'kuipa seal open "$KUIPA_PLAYGROUND/notes.txt.sealed" --out - --passphrase-file "$KUIPA_PLAYGROUND/pass" >/dev/null && kuipa-audit tlog --server ipa1.example.test --state "$KUIPA_PLAYGROUND/tlog-audit.json"' \
    "verified" "recorded"

step 0 "A vault that allows hour-long sessions and 10 unlocks" \
    'kuipa seal create daily --require device,ticket --session-hours 1 --max-unlocks 10 && kuipa seal device add daily --passphrase-file "$KUIPA_PLAYGROUND/pass"' \
    "unlocks allowed: 10"
step 0 "Seal a note to it" \
    'echo "daily note" > "$KUIPA_PLAYGROUND/daily.txt" && kuipa seal file daily "$KUIPA_PLAYGROUND/daily.txt"'
step 0 "Start a session: one passphrase and ticket" \
    'kuipa seal unlock daily --passphrase-file "$KUIPA_PLAYGROUND/pass"' "Session started"
step 0 "Open without the passphrase while the session lasts" \
    'kuipa seal open "$KUIPA_PLAYGROUND/daily.txt.sealed" --out - </dev/null | cat' "daily note"
step 0 "End the session" 'kuipa seal lock daily' "has ended"
step 0 "The servers counted the releases" 'kuipa seal show daily' "unlocks so far: 1"
step 0 "Offline sessions (this realm allows them): a vault opts in" \
    'kuipa seal create travel --require device,ticket --offline-hours 2 && kuipa seal device add travel --passphrase-file "$KUIPA_PLAYGROUND/pass"'
step 0 "Seal a file for offline use" \
    'echo "boarding pass" > "$KUIPA_PLAYGROUND/pass.txt" && kuipa seal file travel "$KUIPA_PLAYGROUND/pass.txt" --session'
step 0 "Release the vault's session key to this device" \
    'kuipa seal unlock travel --offline --passphrase-file "$KUIPA_PLAYGROUND/pass"' "Offline session started"
step 0 "With every server down, the file still opens" \
    'pq_down ipa1 >/dev/null && pq_down ipa2 >/dev/null && kuipa seal open "$KUIPA_PLAYGROUND/pass.txt.sealed" --out - </dev/null | cat; pq_up' \
    "boarding pass"
step 0 "End the offline session" 'kuipa seal lock travel' "has ended"
step 0 "Revoke the vault" 'kuipa seal revoke personal' "revoked"
step 75 "No server opens a file of a revoked vault" \
    'kuipa seal open "$KUIPA_PLAYGROUND/notes.txt.sealed" --out - --passphrase-file "$KUIPA_PLAYGROUND/pass"'

section "Failover" \
    "With ipa1 unreachable, web2 enrolls through ipa2: every server presents an advertisement that ipa1's anchor vouches for.  Enrolled, web2 must then keep verifying ipa2 with the anchors it pinned — not the one anchor of the enrollment string it was issued, whose server is the one that is down."
step 0 "Make ipa1 unreachable" 'pq_down ipa1'
step 0 "Enroll web2 while ipa1 is down" 'pq_enroll web2' \
    "issuer: ipa2.example.test"
step 0 "web2, enrolled, verifies ipa2's advertisement whole: anchor log included" \
    'kuipa advertisement --server ipa2.example.test' \
    "its anchor log, every entry verified from sequence 0 up:"
step 0 "Make ipa1 reachable again" 'pq_up'

section "Password enrollment" \
    "web3 enrolls with the administrator's password, through an armoured kinit on the host."
step 0 "Enroll web3 with admin's password" 'pq_password web3'

section "Enrollment with an existing ticket" \
    "What ipa-client-install does before a ticket join: Kerberos configuration from the verified advertisement, anonymous PKINIT with the advertised anchors, an armoured kinit; then web4 enrolls with that ticket."
step 0 "Get admin's ticket through the armoured exchange" 'pq_bootstrap'
step 0 "Enroll web4 with the ticket" 'pq_host web4; kuipa enroll $PQ_SERVERS --hostname "$PQ_HOST" --use-ccache'

section "Offline enrollment" \
    "web5 prepares a machine key, the administrator stages it, and web5 enrolls from the sealed, signed bundle without talking to a server; at first contact it replaces the staged keys."
step 0 "Prepare, stage and enroll web5 offline" 'pq_offline web5'
step 0 "Finish the enrollment at first contact" 'kuipa complete'

section "Voucher enrollment" \
    "web6 has no host entry and no OTP: it enrolls with a voucher the issuer signed blindly, bound to the host's ephemeral key."
step 0 "Enroll web6 with a bound voucher" 'pq_voucher web6 --bound'

section "Auditing the claim logs" \
    "kuipa-audit reads the realm's public claim logs: what an anchor's tree covers, and whether the servers agree on their heads."
step 0 "web1's pinned heads, against the realm" \
    'pq_host web1; kuipa-audit coverage --server ipa1.example.test' \
    "current"
step 0 "The two servers agree on their heads" \
    'kuipa-audit split-view --server ipa1.example.test --server ipa2.example.test' \
    "no disagreements"

section "A keyless mirror" \
    "kuipa-mirror syncs the public endpoints of one server and serves them read-only: a head-pinned client verifies a proof with no signature and no key on the mirror."
step 0 "Serve a mirror of ipa1" \
    'kuipa-mirror --origin ipa1.example.test --listen 127.0.0.1:0 --interval 1 >"$KUIPA_PLAYGROUND/mirror.port" 2>/dev/null & MIRROR=$!; sleep 2; kill -0 $MIRROR; MIRROR_PORT=$(cat "$KUIPA_PLAYGROUND/mirror.port")'
step 0 "The mirror answers the claim log, with the head's vouch" \
    'kuipa-audit claim-log --server http://127.0.0.1:$MIRROR_PORT --anchor "$(cat "$KUIPA_PLAYGROUND/anchor")"; s=$?; kill $MIRROR; rm -f "$KUIPA_PLAYGROUND/mirror.port"; [[ $s -eq 0 ]]' \
    "vouch expires"

section "Trusted realm" \
    "web1 installs the realm its realm trusts, B.TEST, verified through EXAMPLE.TEST; a B.TEST user logs in on web1 and gets a ticket for it across the trust."
step 0 "Install the trusted realms on web1" 'pq_host web1; pq_trust'
step 0 "Log in a B.TEST user on web1" 'pq_trusted_kinit'
step 0 "Get a ticket for web1 as the B.TEST user" 'pq_trusted kvno "host/$PQ_HOST"' \
    "host/web1.example.test@EXAMPLE.TEST"

section "Post-quantum Tang" \
    "ipa1 also serves post-quantum Tang: a secret encrypted with the tang-pqc pin is recovered with ipa1's help."
step 0 "Encrypt a secret with the tang-pqc pin" 'echo "a secret" | tang-pqc encrypt "$(pq_tang)" > "$KUIPA_PLAYGROUND/secret.jwe"'
step 0 "Decrypt it through ipa1" 'tang-pqc decrypt < "$KUIPA_PLAYGROUND/secret.jwe"' \
    "a secret"

section "Replica promotion" \
    "web7 imitates a promoting replica: it fetches the material promotion delivers — the DM password hash, the RA agent key, the CA subsystem keys — through the keys operation, sealed under ML-KEM.  The server checks cn=masters first: a host that is not a server is refused, and only a CA server's host or dogtag service may ask for the wrapped CA keys."
step 0 "Enroll web7 with the administrator's password, as ipa-client-install -p does" 'pq_password web7' \
    "Enrolled host/web7.example.test@EXAMPLE.TEST in EXAMPLE.TEST"
step fail "A host outside cn=masters is refused, with the reason on the server only" \
    'kuipa keys fetch dm/DMHash' \
    "refused the request"
step 0 "Promotion adds web7 to cn=masters" \
    'kuipa-playground masters --add web7.example.test' \
    "web7.example.test joined cn=masters"
step 0 "Now the DM password hash arrives" \
    'mkdir -p "$KUIPA_ROOT/promotion" && kuipa keys fetch dm/DMHash --out "$KUIPA_ROOT/promotion/dmhash" && cat "$KUIPA_ROOT/promotion/dmhash"' \
    "playground-dm-hash"
step fail "An unknown nickname is refused" \
    'kuipa keys fetch dm/no-such-secret' \
    "refused the request"
step fail "The wrapped CA keys still need the CA role" \
    'kuipa keys fetch ca_wrapped/lwca-signing' \
    "refused the request"
step 0 "ipa-ca-install records the CA role" \
    'kuipa-playground masters --ca web7.example.test' \
    "web7.example.test has the CA role"
step 0 "The whole promotion set, as a CA replica fetches it" \
    'pq_promote web7' \
    "promotion material fetched"
step fail "A removed server is refused again (ipa-server-del)" \
    'kuipa-playground masters --remove web7.example.test >/dev/null && kuipa keys fetch dm/DMHash' \
    "refused the request"

section "Failure is reported" \
    "With both servers unreachable, the health check must fail and say why."
step 0 "Make ipa1 and ipa2 unreachable" 'pq_down ipa1; pq_down ipa2'
step fail "Check web1 with no server reachable" 'kuipa check' \
    "ipa1.example.test: server unreachable" "ipa2.example.test: server unreachable"
step 0 "Make them reachable again" 'pq_up'

echo
echo "$n steps, $failed failed"
[[ $failed -eq 0 ]]
