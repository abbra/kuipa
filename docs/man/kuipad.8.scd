KUIPAD(8) "kuipa" "System Administration"

# NAME

kuipad - the realm's post-quantum key daemon on IPA servers

# SYNOPSIS

*kuipad* [serve] [--config _FILE_]

*kuipad* _command_ [--config _FILE_] [_flags_]

# DESCRIPTION

*kuipa* is a post-quantum key exchange mechanism for IPA

*kuipad* is the kuipa daemon on each IPA server.  It serves the realm's
HTTPS endpoints under */ipa/ku/* behind *httpd*(8):
- enrollment and rekey,
- the anchor exchange and advertisement,
- vouchers (see *kuipa-voucher*(1)),
- user seals,
- trust establishment between IPA deployments, and
- a post-quantum Tang service at */ipa/ku/tang* (see *tang-pqc*(1)).

*kuipad* holds this server's anchor and keys in a key directory and keeps the
anchors of the deployment's servers converging.

The daemon is socket-activated (*kuipad.socket*,
*/run/ipa/kuipad.sock*) or listens on the *listen* configuration key.
It reads its keys at start: restart it after *generate-keys*,
*rotate-keys*, *rotate-anchor*, *prune-keys*, *add-voucher-key*, *add-witness-key*,
*tang-keygen* or *tang-rotate* — the socket stays open, so clients see
no outage.

On a configured IPA server *kuipad* configuration and state is managed by IPA
tools and does not require manual adjustment.

# COMMANDS

## serve [--config _FILE_]

Run the daemon.  This is the default command.

## generate-keys [--config _FILE_]

Make the anchor and the server's keys; print the anchor.  Run it once
per server, at install.

## anchor [--config _FILE_]

Print this server's anchor thumbprint.

## enrollment-string [--days _N_] [--config _FILE_]

Print the enrollment string *ipa-ku1:REALM:<anchor>:<expiry>*, to
which a host appends *:OTP* to enroll (see *kuipa*(1)).  Default
validity 7 days, at most 400.

## rotate-anchor [--days _N_] [--config _FILE_]

Replace the anchor: the old one signs a succession to the new one,
valid _N_ days (default 400), and is deleted.  Reissue enrollment
strings and image pins afterwards.

## rotate-keys [--join] [--escrow] [--trust] [--signing] [--config _FILE_]

Retire the named keys and make new ones (default: join, escrow, trust).

## prune-keys [--join-days _N_] [--escrow-days _N_] [--config _FILE_]

Remove keys retired longer ago (default 14 and 400 days).

## add-voucher-key --file _JWK_ [--config _FILE_]

Accept vouchers signed under the voucher key _JWK_ (see
*kuipa-voucher*(1)).

## add-witness-key --file _JWK_ [--config _FILE_]

Accept transparency-log cosignatures by the witness whose public key
is _JWK_ (from *kuipa-witness keygen*).  Served log heads then carry
its cosignatures, posted to */ipa/ku/tlog/ID/cosign*.  Remove the
*witness-THUMBPRINT.jwk* file from the key directory to stop.

## trust-invitation [--days _N_] [--config _FILE_]

Invite another realm to trust this one; the invitation is valid _N_
days (default 7).

## establish-trust --invitation-file _FILE_ --server _HOST_... [--config _FILE_]

Trust the realm that issued the invitation; _HOST_ names its servers,
repeat one per server.

## tang-keygen [--config _FILE_]

Create the post-quantum Tang service's keys; print the thumbprint.

## tang-rotate [--config _FILE_]

Retire the Tang keys and create new ones.

## tang-thp [--config _FILE_]

Print the Tang signing keys' thumbprints.

# FLAGS

*--config* _FILE_
	Configuration file; every command takes it (default
	*/etc/ipa/kuipad.json*).

# FILES

*/etc/ipa/kuipad.json*
	Configuration (JSON).  The required keys are *realm*,
	*domain*, *basedn*, *server*, *ldap_uri*, *principal* (the
	daemon's Kerberos principal, *ipa-ku/<server>@REALM*), *service*
	(its GSS-API service name, *ipa-ku@<server>*), *keytab* and
	*ca_file*.  The optional keys are *pkinit_anchors_file*,
	*key_dir*, *listen* (default *unix:/run/ipa/kuipad.sock*),
	*peers*, *discover_peers*, *peer_endpoints*, *peer_interval*,
	*anchor*, *vouch_interval*, *rate_limit*, *trusts*,
	*kdc_proxy* and *enctypes*.  Unknown keys are refused, so a typo
	stops the daemon instead of being ignored.

	*kdc_proxy* names this realm's KDC proxies (MS-KKDCP, FreeIPA's
	*/KdcProxy*) for realms that trust it, when its KDCs are not
	reachable from their hosts: *{"urls": ["https://ipa1.example.test/KdcProxy"]}*.
	Their TLS certificates are checked against the IPA CA, or with
	*"ca": "system"* against the hosts' system trust store, for a
	front end with a public certificate.  A *trusts* entry takes the
	same *kdc_proxy* key, for the trusted realm: what this realm's
	hosts use to reach its KDCs.  A trust established with
	*establish-trust* takes the partner's own *kdc_proxy* from its
	advertisement.

	Requests to other servers honour *HTTPS_PROXY*, *HTTP_PROXY*,
	*ALL_PROXY* and *NO_PROXY* in the daemon's environment; list the
	realm's own servers in *NO_PROXY* when only other realms are
	behind the proxy.

*/var/lib/ipa/ku/*
	The key directory (*key_dir*): the anchor and signing JWKs, the
	join, escrow, trust, voucher and succession keys, the Tang keys,
	peer state and the delegation rule.

*/run/ipa/kuipad.sock*
	The socket *kuipad.socket* listens on; httpd forwards
	*/ipa/ku/* to it.

# EXIT STATUS

*0*	Success.

*1*	Usage error or fatal failure; the reason is printed on standard
	error.

# EXAMPLES

Prepare a new server:

```
kuipad generate-keys
systemctl start kuipad.socket
```

Print an enrollment string for an image or a join:

```
kuipad enrollment-string --days 30 > string
```

Trust another IPA deployment:

- on IPA server in deployment A:

```
kuipad trust-invitation > invite
```

- on IPA server in deployment B:

```
kuipad establish-trust --invitation-file invite \\       
                       --server ipa1.a.example.test
```

Trust a realm whose KDCs are only reachable through a KDC proxy, as
*trusts* in */etc/ipa/kuipad.json*:

```
"trusts": [{
  "realm": "FEDORAPROJECT.ORG",
  "domain": "fedoraproject.org",
  "servers": ["id.fedoraproject.org"],
  "anchors": ["..."],
  "kdc_proxy": {
    "urls": ["https://id.fedoraproject.org/KdcProxy"],
    "ca": "system"
  }
}]
```

Serve post-quantum Tang:

```
kuipad tang-keygen
tang-pqc adv https://ipa1.example.test/ipa/ku/tang
```

# SEE ALSO

*kuipa*(1), *kuipa-unseal*(8), *kuipa-voucher*(1), *tang-pqc*(1),
*httpd*(8), *systemd.socket*(5)

# AUTHORS

The kuipa project contributors.
