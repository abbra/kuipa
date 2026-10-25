KUIPA(1) "kuipa" "User Commands"

# NAME

kuipa - manage host's identity in an IPA realm

# SYNOPSIS

*kuipa* [_global-flags_] _command_ [_args_]

*kuipa seal* [_global-flags_] _command_ [_args_]

# DESCRIPTION

*kuipa* manages the host's identity in a FreeIPA realm:
- enrollment (online or offline),
- host key rotation,
- keytabs and file protection,
- metadata of trusted realms, and
- health checks.

*kuipa* client talks to the deployments's IPA servers over HTTPS,
verifying the pinned deployment's anchors in */etc/ipa/ku-anchors*.

For all operations *kuipa* runs as root.

*kuipa seal* can be used as a user, with their Kerberos ticket.

# SECRETS

*kuipa* requires credentials for some of its operations. The secrets
are never taken from the command line:

- the enrollment string comes from *--enrollment-file*, *$KUIPA_ENROLLMENT_FILE* or standard input
- the password comes from *--password-file* or standard input, and on a terminal it is prompted for.

During the join process with a Kerberos principal, *kuipa* will ask for
credentials required by the IPA server, including multi-factor authentication.

When *--server* option is omitted, servers are found through the DNS SRV records
of the realm's domain.

# GLOBAL FLAGS

*--json*
	Print the result as one JSON object instead of text.

*--verbose*
	Trace each request, decision and file written on standard error.

*--trace*
	Trace with wire details.  *$KUIPA_TRACE* overrides both with
	*tracing* filter directives.

# ENROLLMENT FLAGS

*enroll*, *realm-info* and *advertisement* share these:

*--enrollment-file* _FILE_
	Enrollment string file; *-* reads standard input.  Defaults to
	*$KUIPA_ENROLLMENT_FILE*.

*--realm* _REALM_
	Verify realm _REALM_ against its pinned anchors instead of an
	enrollment string; with one given as well, _REALM_ is a
	cross-check of its realm.

*--password-file* _FILE_
	Read the password from this file instead of standard input.

*--server* _HOST_
	IPA server host; repeat for each server.  Found in DNS
	otherwise.

*--domain* _DOMAIN_
	Domain to look servers up in (default: this host's domain).

*--hostname* _FQDN_
	The host being enrolled (default: this host's FQDN).

# COMMANDS

## prepare [--new] [--hostname _FQDN_]

Prepare an offline bundle with the machine key for a system with _FQDN_.
The bundle is sealed with this key. *--new* creates a new machine key, replacing
the existing one.

## enroll [_enrollment-flags_] [_flags_]

Enroll online using host's one-time password (OTP, the default), a user's
Kerberos credential, an existing Kerberos ticket, a voucher, or offline from a
prepared bundle.

*--bundle* _FILE_
	Enroll offline from a prepared bundle instead of online; finish
	it at first contact with *kuipa complete*.

*--insecure-signed-only*
	Accept a bundle that is only signed, not sealed.

*--principal* _PRINCIPAL_
	Enroll with a Kerberos principal: perform an armoured *kinit*(1) of
	_PRINCIPAL_ on this host, inside FAST. All IPA multi-factor
	pre-authentication methods supported. For smart-card (PKINIT) use
	existing credentials cache (*--use-ccache*) and authenticate in advance.

*--use-ccache*
	Enroll with the ticket in *$KRB5CCNAME* as it is. Kerberos
	realm's configuration for that can be obtained first with
	*kuipa realm-info*.

*--voucher-file* _FILE_
	Enroll with this voucher (see *kuipa-voucher*(1)).

*--ephemeral-key* _FILE_
	The ephemeral key written by *kuipa voucher-key*; needed with a
	bound voucher.

*--ldap-otp*
	Check the OTP through LDAP (anchor servers only).

Online enrollment requires the enrollment string (with *:OTP* appended) or
one of authenticated methods above.

## voucher-key --out _FILE_

Write the ephemeral key that binds a voucher to this host; print its
binding, for *kuipa-voucher*(1)'s *--binding*.

## realm-info --krb5-dir _DIR_

Print, and write into _DIR_, the Kerberos configuration derived from
the verified advertisement (*krb5.conf* and the realm's PKINIT
anchors), so an armoured *kinit*(1) can obtain the ticket to use
with the *--use-ccache* enrollemnt option.

## complete

Finish an offline enrollment at first contact with the realm;
*ipa-client-complete.service* runs it while a pending file exists.

## rotate-keys

New host keys; refresh the pins and the recorded servers; reseal the
keytab and the protected files where needed.  *kuipa-rotate.timer*
runs it monthly.

## protect [--keytab _FILE_] [--file _FILE_]

Seal on disk: the host keytab when neither flag is given - */etc/krb5.keytab*
becomes */etc/ipa/krb5.keytab.sealed* and a symlink to */run/ipa/krb5.keytab*,
where *kuipa-unseal*(8) writes the decrypted version at every boot - another
keytab (a service's or a user's, sealed for its own principal), or any file
(sealed for the principal of *--keytab*, default the host). The original path of
a protected keytab or file becomes a symlink to an unsealed copy under
*/run/ipa/kuipa/*, so readers see the old path. Run again to reseal what is
there now; every key rotation reseals too.

## unprotect [--keytab _FILE_] [--file _FILE_]

Put the host keytab, or another keytab or file, back on disk in plain
form with its mode and owner, then retire its bindings.

## trusted-realms

Install and refresh the information about deployments this deployment trusts —
their Kerberos KDCs and PKINIT anchors, verified — so their users can log in
here; remove the others. Run at enrollment and from a timer.

## advertisement

Print what each server of the deployment advertises, verified against
the enrollment string's anchor or the pre-provisioned pins, and the
realm's anchor log (landmarks) it names: an index of every anchor and
key.

## status

Prints local *kuipa* configuration consistency.

## check [--server _HOST_]

Check this host's enrollment status against the realm: every server, the
delegations, a *kinit*(1), the sealed keytabs and files.  Exits 1 on a
problem.

## leave

Write protected keytabs back in plain form and remove *kuipa*'s state from this
host.

## keys fetch _NAME_ [--alg _ALG_] [--out _FILE_]

Fetch a named secret from the realm's servers, authenticated by this
host's keytab: *NAME* is *<namespace>/<nickname>*, one of *dm/DMHash*,
*ra/ipaCert*, *ca/<nickname>*, *ca_wrapped/<nickname>* or
*lwca/<nickname>*.  This is how a promoting replica receives the
Directory Manager password hash, the RA agent key and the CA subsystem
keys.  The value is written to standard output, or to *FILE*.  For
*ca_wrapped* only, *--alg* names the wrap algorithm: *aes-256-cbc-pad*
or *aes-256-wrap*.  A host outside the realm's server list, or without
the CA role for the wrapped CA keys, is refused.

# VAULT COMMANDS

*kuipa seal* seals a user's own files to a vault of hers, or to one
shared with her. It runs as the user, with her Kerberos ticket, and
needs no root. The device key lives in the user's data directory (see
*ENVIRONMENT*); vault sessions live in tmpfs under the runtime
directory.

__VAULT__ is a vault's name for its owner, and *OWNER/NAME* (for
example *alice/db*) for everyone it is shared with.

## seal create --require _FACTORS_ _VAULT_ [_policy-flags_]

Create a vault __VAULT__. Specify the additional factors for an unlock with
*--require* beside the IPA servers: *device* (or *device=hardware-wrapped*,
*device=hardware-bound*), *ticket*; comma-separated or repeated. The policy
flags:

*--expires* _DAYS_
	How many days the vault lives (default: the realm's limit).

*--max-unlocks* _N_
	How many times, in all, the servers may open files of the vault.

*--session-hours* _HOURS_
	Allow sessions of up to this many hours (*seal unlock*).

*--offline-hours* _HOURS_
	Allow offline sessions of up to this many hours
	(*seal unlock --offline*), where the realm allows them.

*--epoch-days* _DAYS_
	How many days one offline-session key serves new files.

*--sealing* _offline|registered_
	*registered*: sealing needs a server, and resealing or
	*seal retire* makes old copies unopenable (default: *offline*).

*--ticket-delegation* _allow|refuse_
	Which delegated tickets satisfy *ticket*.

*--ticket-via* _SERVICE_
	Accept delegated tickets only through these services.

## seal policy --require _FACTORS_ _VAULT_ [_policy-flags_]

Replace a vault's policy; the same flags as *seal create*.

*--approvals* _M_ with *--approver-user* _USER_ and *--approver-group*
_GROUP_ (each repeatable) makes every release wait for _M_ approvals
from them, other than the requester's (*seal request*, *seal approve*);
*--approval-hours* _H_ (default 24, at most 168) and *--approval-uses*
_N_ (default 1) bound what one request covers.

## seal device add _VAULT_ [_flags_]

Register this host's device key in a vault, making it (under a
passphrase) if this host has none:

*--passphrase-file* _FILE_
	Read the passphrase (or the token's PIN) from this file.

*--pkcs11* _URI_
	Register an ML-KEM key on a token instead, as a *pkcs11:* URI.

*--module* _PATH_
	The token's PKCS#11 module (default:
	*/usr/lib64/p11-kit-proxy.so*).

## seal device remove _VAULT_ _ID_

Remove a device from a vault.

## seal file _VAULT_ _FILE_ [--out _PATH_] [--session]

Seal _FILE_ to the vault; the sealed copy goes to *FILE.sealed* by
default.  Sealing works offline while this host has a recent
description of the vault.  *--session* seals for offline sessions: the
file opens without a server while one lasts, and only then.

## seal open _SEALED_ --out _PATH_ [_flags_]

Open a sealed file.  *--out* is a file, or *-* for standard output;
with *-* the command refuses a terminal unless *--force*.

*--passphrase-file* _FILE_
	Read the device key's passphrase from this file.

*--request* _ID_
	The approved release request, for a vault with approvals.

## seal reseal _VAULT_ _SEALED_...

Open sealed files and seal them again to the vault's current devices.

## seal retire _VAULT_ _SEALED_...

With registered sealing: make these sealed files, and every copy of
them, unopenable.

## seal unlock _VAULT_ [--offline] [--passphrase-file _FILE_]

Start a session: until it ends, files of the vault open on this host
without the passphrase or a ticket.  *--offline* starts an offline
session: files sealed with *--session* open without a server until it
ends.

## seal lock _VAULT_

End the vault's session on this host.

## seal show _VAULT_

Describe a vault.  *seal list* describes all your vaults and those
shared with you; *seal revoke VAULT* revokes it: no file sealed to it
opens any more.

## seal request _VAULT_ _SEALED_ --reason _TEXT_

For a vault with approvals: ask its approvers to approve the release of
_SEALED_, saying why.  Prints the request's id.

## seal pending [_VAULT_]

List the open release requests of _VAULT_, or of every vault you approve
for or have a part in, with their approvals so far.

## seal approve _VAULT_ _ID_, seal deny _VAULT_ _ID_

Approve or deny a release request, as one of the vault's approvers.  Your
own requests are not yours to approve.  One denial ends a request.

## seal share _VAULT_ [--manager] [--user _U_] [--group _G_] [--host _FQDN_] [--service _S_]

Share a vault, as its owner or a manager.  Members open and seal its
files, start sessions, and register and remove their own devices;
with *--manager*, they also change its policy, share and unshare it,
and revoke it.  Groups are IPA user groups or host groups; membership
is checked at every open.  Each option may be repeated.

## seal unshare _VAULT_ [--manager] [--user _U_] [--group _G_] [--host _FQDN_] [--service _S_]

Stop sharing a vault with those named (as managers with *--manager*),
and remove the devices of everyone left without a part in it.  A member
may remove themselves.  Files sealed to the vault stop opening for them
at once; reseal and change the secret if they may have opened it.

## tlog watch _VAULT_

Check every server's transparency log for the vault, authenticated
by your ticket, and list what happened since the last watch: devices
added and removed, policy changes, sessions, and every release of a
server's share of a sealed file.  Each server's answer must be signed
by the key its verified advertisement names and prove every entry, and
its log must extend the one the last watch saw.  An entry the vault
descriptor stored on this host does not account for — a device it
does not list added or acting, a device it lists removed, a policy it
does not show — is flagged *UNEXPECTED*.  Run *seal show* to accept
what you did elsewhere.  The first watch of a server sets the baseline
and flags nothing.  With trusted witnesses (*tlog witnesses*), each
head needs their cosignatures: one with fewer is *UNWITNESSED*, listed
but not recorded, so run the watch again after the witnesses' next
pass.  A server whose log id changed, because its key moved to another
category with the crypto policy (SHA-256 logs for ML-DSA-65, SHA-384
for ML-DSA-87), is *NEW LOG*: its new log is read and checked from its
start.  Exits 1 for a flag, a log that does not extend what was seen
(*FORKED*), an unwitnessed head, or a server that could not be checked.

## sign blob [--purpose _P_] _FILE_...

Have a realm server state that the principal of your ticket signed the
files, for purpose _P_ (default *blob*), as the realm's signing policy
allows; the statement is recorded in the server's transparency log.
Each file gets a _FILE_*.kusig* bundle.  Files are digested with
SHA-256, or SHA-384 when the system crypto policy allows only ML-DSA-87
(CNSA 2.0); a CNSA server refuses SHA-256 digests.  See *kuipa-gitsign*
for git commits.

## sign verify _FILE_ [--signature _SIG_] [--signer _S_] [--purpose _P_]

Verify _FILE_ against its bundle (default _FILE_*.kusig*) offline, with
this host's pinned anchors, as of the time it was signed.  Exits 1 for
another signer or purpose than asked for.

## tlog witnesses [--add _JWK_] [--remove _THUMBPRINT_] [--required _N_]

Show the transparency-log witnesses this host trusts, and how many
must cosign a head for *tlog watch* to accept it.  As root, trust the
witness whose public key is _JWK_ (from *kuipa-witness keygen*), stop
trusting one, or set _N_; _N_ cannot exceed the witnesses trusted.

# ENVIRONMENT

*KUIPA_ENROLLMENT_FILE*
	The enrollment string when *--enrollment-file* is absent.

*KUIPA_TRACE*
	*tracing-subscriber* filter directives (e.g. *kuipa=debug*), in
	place of *--verbose* and *--trace*.

*KUIPA_ROOT*
	Prefix for every system path (default */*), so the tools can be
	exercised without touching the system.

*KUIPA_USER_DIR*
	*seal*'s data directory, instead of *$XDG_DATA_HOME/kuipa*
	(default: *~/.local/share/kuipa*).

*KUIPA_RUNTIME_DIR*
	*seal*'s session directory, instead of *$XDG_RUNTIME_DIR/kuipa*.

*KRB5CCNAME*
	The ticket cache *--use-ccache* enrolls with.

# FILES

*/etc/ipa/ku-anchors*
	The realm anchors this host pins: one thumbprint per line,
	optionally followed by an expiry in seconds, plus an *epoch*
	line with the anchor-log watermark it has verified — the last
	anchor-log head this host accepts, so a swallowed rotation or a
	stolen anchor is noticed.

*/etc/ipa/ku-anchors.d/*
	The per-realm pins of the trusted realms.

*/etc/ipa/ca.crt*
	The IPA CA chain, used to verify the servers' TLS.

*/etc/ipa/ku-witnesses.json*
	The transparency-log witnesses this host trusts, and how many
	must cosign a head (*tlog witnesses*).

*/var/lib/ipa-client/ku/state.json*
	The client's persistent state: machine key, servers,
	enrollment, protected keytabs and files.

*/var/lib/ipa-client/ku/realm.json*
	Realm, FQDN and servers — what any user of the host may know.

*/var/lib/ipa-client/ku/pending.json*
	An offline enrollment waiting for *kuipa complete*.

*/var/lib/ipa-client/ku/trusts/*
	The trusted realms installed by *trusted-realms*.

*/etc/ipa/krb5.keytab.sealed*
	The protected host keytab; the plaintext is served from
	*/run/ipa/krb5.keytab*, and */etc/krb5.keytab* is a symlink to
	it.

*/run/ipa/kuipa/*
	Unsealed copies of the other protected keytabs and files; their
	original paths are symlinks here.

*FILE.sealed*
	The protected copy of a keytab or file other than the host
	keytab: the original path with *.sealed* appended.

*~/.local/share/kuipa*
	A user's device keys and vault state (*seal*); *vaults/VAULT.tlog*
	holds what *tlog watch* last verified of each server's log.

# EXIT STATUS

*0*	Success.

*75*	Retry later: no server was reachable, or the enrollment finishes
	at first contact; the units retry on it.

*1*	An administrator must act, or another error.

*2*	Usage error.

# EXAMPLES

Enroll with an enrollment string whose OTP is appended:

```
echo 'ipa-ku1:EXAMPLE.TEST:<anchor>:<expiry>:<OTP>' | kuipa enroll
```

Enroll with a domain administrator's password, answering the KDC's
challenges on the terminal:

```
kuipa enroll --principal admin
```

Enroll with an existing ticket:

```
kuipa realm-info --krb5-dir /tmp/krb
KRB5_CONFIG=/tmp/krb/krb5.conf kinit admin@EXAMPLE.TEST
kuipa enroll --use-ccache
```

Protect the host keytab and check the host:

```
kuipa protect
kuipa check
```

Seal a file to a personal vault and open it again:

```
kuipa seal create notes --require device,ticket
kuipa seal device add notes --passphrase-file ~/.notes-pass
kuipa seal file notes notes.txt
kuipa seal open notes.txt.sealed --out -
```

# SEE ALSO

*kuipa-unseal*(8), *kuipa-voucher*(1), *kuipad*(8), *tang-pqc*(1),
*kinit*(1), *krb5.conf*(5), *gssproxy*(8)

# AUTHORS

The kuipa project contributors.
