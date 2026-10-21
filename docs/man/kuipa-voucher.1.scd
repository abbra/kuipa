KUIPA-VOUCHER(1) "kuipa" "User Commands"

# NAME

kuipa-voucher - issue enrollment vouchers with blind signatures

# SYNOPSIS

*kuipa-voucher* _command_ [_flags_]

# DESCRIPTION

*kuipa-voucher* issues single-use enrollment vouchers for *kuipa*(1).
The provisioner blinds a voucher request for one host; the issuer signs
the blinded request with a post-quantum (ML-DSA) blind-signature key:
it sees the voucher's claims, not the secret the host will prove.  The
host enrolls with the finished voucher using the *--voucher-file* flag
of *kuipa*(1).

With *--binding* (printed by *kuipa voucher-key* on the host) the
voucher works only with that host's ephemeral key.  Without it the
voucher is a bearer credential until used.

The issuer's public JWK must be accepted on the servers first:
*kuipad*(8) *add-voucher-key*.

# ISSUER COMMANDS

## keygen --key _FILE_ [--alg _ALG_]

Write a new voucher key and print its public JWK, for *kuipad*(8)'s
*add-voucher-key*.  _ALG_ is *ml-dsa-44*, *ml-dsa-65* (default) or
*ml-dsa-87*.

## quota --quota _FILE_ --limit _N_

Set how many vouchers may be issued in all.  *sign* counts against the
quota file.

## sign --key _FILE_ --quota _FILE_

Count, then sign the blinded request on standard input; print the
response for *finish*.

# PROVISIONER COMMANDS

## request --public _FILE_ --realm _REALM_ --fqdn _FQDN_ [_flags_]

Blind a voucher for one host; print the request for *sign*.

*--public* _FILE_
	The issuer's public JWK (printed by *keygen*).

*--realm* _REALM_
	The realm the voucher admits a host to.

*--fqdn* _FQDN_
	The host the voucher admits.

*--hostgroup* _GROUP_
	Only hosts of this IPA host group.

*--days* _N_
	Days the voucher is valid from now (default 7).

*--binding* _BASE64_
	Binding from *kuipa voucher-key*, base64; the voucher then
	works only with that host's ephemeral key.

*--state* _FILE_
	State file *finish* needs: the unblinding is kept there, not on
	the issuer.

## finish --state _FILE_

Unblind the response on standard input; print the voucher.

# ANYONE

## show

Print the claims of the voucher on standard input, as JSON.

# EXIT STATUS

*0*	Success.

*1*	Error.

*2*	Usage error.

# EXAMPLES

Issuer, once:

	kuipa-voucher keygen --key voucher.jwk > voucher.pub
	kuipa-voucher quota --quota voucher.quota --limit 100
	kuipad add-voucher-key --file voucher.pub

Issue one voucher for one host:

	# on the host: the ephemeral key and its binding
	kuipa voucher-key --out eph.key
	# provisioner: blind the request
	kuipa-voucher request --public voucher.pub --realm EXAMPLE.TEST --fqdn web1.example.test --binding <BINDING> --state st.json > req
	# issuer: sign it
	kuipa-voucher sign --key voucher.jwk --quota voucher.quota < req > resp
	# provisioner: unblind and hand over the voucher
	kuipa-voucher finish --state st.json < resp > voucher

Enroll with it:

	kuipa enroll --voucher-file voucher --ephemeral-key eph.key

# SEE ALSO

*kuipa*(1), *kuipad*(8)

# AUTHORS

The kuipa project contributors.
