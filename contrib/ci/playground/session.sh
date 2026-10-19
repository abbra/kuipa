#!/usr/bin/env bash
# contrib/ci/playground/session.sh -- a scripted, traced playground session
#
# Runs the steps below in one shell inside a running playground, the way a
# person would at the 'local-ci.sh interactive' prompt, with KUIPA_TRACE on.
# Steps share the shell, so state carries over: pq_host switches the current
# host for the steps after it, and an enrolled host stays enrolled.
#
# For each step it records, under OUT/steps/NNN/:
#   meta.env   section, title, expected and actual exit status, duration
#   command    the command line, as typed
#   stdout     the command's result
#   stderr     its trace (KUIPA_TRACE) and error messages
#   server.log what the playground's servers logged during the step
# and OUT/session.env with the realm's details.  report.py renders it.
#
# Usage (local-ci.sh playground-test runs it):
#   session.sh ENV_FILE SERVER_LOG OUT
# with the playground's binaries on PATH.  Exits 1 if any step's exit status
# differs from the expected one.
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

# section TITLE TEXT: start a group of steps, with a sentence explaining it.
section() { section="$1"; section_text="$2"; }

# step EXPECT TITLE COMMAND: run COMMAND (a shell line) in this shell.
#   EXPECT  the exit status it must end with: a number, or "fail" for any
#           non-zero status
step() {
    local expect="$1" title="$2" cmd="$3"
    n=$((n + 1))
    local d
    d="$out/steps/$(printf '%03d' "$n")"
    mkdir -p "$d"
    printf '%s\n' "$cmd" > "$d/command"
    local offset t0 t1 rc
    offset=$(stat -c %s "$server_log" 2>/dev/null || echo 0)
    t0=$(date +%s%N)
    eval "$cmd" > "$d/stdout" 2> "$d/stderr" < /dev/null
    rc=$?
    t1=$(date +%s%N)
    tail -c +"$((offset + 1))" "$server_log" > "$d/server.log" 2>/dev/null || true

    local ok=0
    if [[ "$expect" == fail ]]; then
        [[ $rc -ne 0 ]] && ok=1
    elif [[ $rc -eq $expect ]]; then
        ok=1
    fi
    [[ $ok -eq 1 ]] || failed=$((failed + 1))
    {
        printf 'section=%s\n' "$section"
        printf 'section_text=%s\n' "$section_text"
        printf 'title=%s\n' "$title"
        printf 'expected=%s\n' "$expect"
        printf 'status=%s\n' "$rc"
        printf 'passed=%s\n' "$ok"
        printf 'ms=%s\n' "$(((t1 - t0) / 1000000))"
    } > "$d/meta.env"
    printf '  %-4s %3s  %s\n' "$([[ $ok -eq 1 ]] && echo ok || echo FAIL)" "$rc" "$title"
}

section "OTP enrollment" \
    "web1 enrolls with its one-time password: the host verifies the realm advertisement against the anchor in its enrollment string, and receives its keytab under ML-KEM."
step 0 "Enroll web1 with its OTP enrollment string" 'pq_enroll web1'
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

section "Failover" \
    "With ipa1 unreachable, web2 enrolls through ipa2: every server presents an advertisement that ipa1's anchor vouches for."
step 0 "Make ipa1 unreachable" 'pq_down ipa1'
step 0 "Enroll web2 while ipa1 is down" 'pq_enroll web2'
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

section "Trusted realm" \
    "web1 installs the realm its realm trusts, B.TEST, verified through EXAMPLE.TEST; a B.TEST user logs in on web1 and gets a ticket for it across the trust."
step 0 "Install the trusted realms on web1" 'pq_host web1; pq_trust'
step 0 "Log in a B.TEST user on web1" 'pq_trusted_kinit'
step 0 "Get a ticket for web1 as the B.TEST user" 'pq_trusted kvno "host/$PQ_HOST"'

section "Post-quantum Tang" \
    "ipa1 also serves post-quantum Tang: a secret encrypted with the tang-pqc pin is recovered with ipa1's help."
step 0 "Encrypt a secret with the tang-pqc pin" 'echo "a secret" | tang-pqc encrypt "$(pq_tang)" > "$KUIPA_PLAYGROUND/secret.jwe"'
step 0 "Decrypt it through ipa1" 'tang-pqc decrypt < "$KUIPA_PLAYGROUND/secret.jwe"'

section "Failure is reported" \
    "With both servers unreachable, the health check must fail and say why."
step 0 "Make ipa1 and ipa2 unreachable" 'pq_down ipa1; pq_down ipa2'
step fail "Check web1 with no server reachable" 'kuipa check'
step 0 "Make them reachable again" 'pq_up'

echo
echo "$n steps, $failed failed"
[[ $failed -eq 0 ]]
