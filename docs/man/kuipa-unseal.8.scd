KUIPA-UNSEAL(8) "kuipa" "System Administration"

# NAME

kuipa-unseal - unseal the machine keytab, or another sealed keytab or
file, without a human

# SYNOPSIS

*kuipa-unseal* [_flags_]

# DESCRIPTION

*kuipa-unseal* is the unattended unseal path: it opens a sealed keytab
or file into its unsealed copy, talking to the IPA servers with the
host's sealed identity.  It is used at boot (*kuipa-unseal.service*)
and as gssproxy's per-service keytab loader, so that keys protected by
*kuipa protect* never need a human and, through gssproxy, never touch a
filesystem.

The command is installed as */usr/libexec/kuipa-unseal* and runs in its
own SELinux domain: it only reads the sealed keytabs and files, the
anchors and the CA, talks to the IPA servers, and writes the result.
It has no Kerberos client rights, so it never rebinds; *kuipa
rotate-keys*, on a timer, refreshes the host keytab's bindings.
Without a reachable server it exits *75* and systemd retries; the host
boots meanwhile without its Kerberos identity.

# FLAGS

*--memfd*
	Write the keytab to the memfd inherited as file descriptor 3
	(the gssproxy keytab_loader protocol, gssapi/gssproxy#135)
	instead of */run/ipa/krb5.keytab*.

*--all*
	At boot: unseal the host keytab if it is protected, and every
	other keytab and file *kuipa protect* sealed, each to its
	unsealed copy.  This is what *kuipa-unseal.service* runs.

*--sealed* _FILE_
	A sealed keytab or file to unseal instead of the host keytab.

*--out* _FILE_
	Where to write what *--sealed* holds: a file, or *-* for
	standard output.  Default: its unsealed copy, for one sealed by
	*kuipa protect*.

*--force*
	With *--out -*, write to standard output even when it is a
	terminal.

*--verbose*
	Trace each request and decision on standard error.

*--trace*
	Trace with wire details (*$KUIPA_TRACE* overrides with *tracing*
	filter directives).

# FILES

*/etc/ipa/krb5.keytab.sealed*
	The sealed host keytab.

*/run/ipa/krb5.keytab*
	Where the host keytab is written (mode 0600), and what
	*/etc/krb5.keytab* points at while it is protected.

*/run/ipa/kuipa/*
	Where the unsealed copies of other protected keytabs and files
	live; their original paths are symlinks here.

*/etc/ipa/ku-anchors*, */etc/ipa/ca.crt*
	The realm's pinned anchors and CA, read to verify the servers.

*/var/lib/ipa-client/ku/state.json*
	The host's enrollment state.

# ENVIRONMENT

*KUIPA_TRACE*
	*tracing-subscriber* filter directives (e.g. *kuipa=debug*), in
	place of *--verbose* and *--trace*.

*KUIPA_ROOT*
	Prefix for every system path (default */*).

# EXIT STATUS

*0*	Success.

*75*	Retry later: no server could unseal.

*1*	Error.

*2*	Usage error.

# EXAMPLES

Open the host keytab at boot:

	kuipa-unseal --all

Serve a service's keytab straight into gssproxy's memory (needs
gssproxy's keytab_loader, gssapi/gssproxy#135; until it ships in a
release, gssproxy must be built from its main branch):

```
# /etc/gssproxy/50-nfs-server.conf
[service/nfs-server]
  mechs = krb5
  cred_store = keytab:MEMORY:nfs-server
  keytab_loader = /usr/libexec/kuipa-unseal --sealed /etc/nfs.keytab.sealed --memfd
  cred_usage = accept
```

After a reseal (*kuipa protect* again), reload the keys with
*SIGHUP* to gssproxy.

Read a sealed file into a pipe, without writing it anywhere:

	kuipa-unseal --sealed /etc/app/db.conf.sealed --out - | app --config /dev/stdin

# SEE ALSO

*kuipa*(1), *kuipad*(8), *gssproxy*(8), *gssproxy.conf*(5),
*systemd.service*(5)

# AUTHORS

The kuipa project contributors.
