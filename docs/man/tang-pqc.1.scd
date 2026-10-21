TANG-PQC(1) "kuipa" "User Commands"

# NAME

tang-pqc - post-quantum Tang client and Clevis pin

# SYNOPSIS

*tang-pqc* adv _URL_ [--ca _FILE_]

*tang-pqc* encrypt _CONFIG_ < _IN_ > _JWE_

*tang-pqc* decrypt < _JWE_ > _OUT_

# DESCRIPTION

*tang-pqc* is a Tang client with post-quantum keys: the server's
signing keys are ML-DSA and the key establishment is ML-KEM, so
advance verification and the recovered key survive later quantum
attacks on RSA and elliptic curves.  It talks to the Tang service
*kuipad*(8) serves at */ipa/ku/tang*, or any server speaking the same
protocol.

Installed by *contrib/clevis/install.sh* as *clevis-encrypt-tang-pqc*
and *clevis-decrypt-tang-pqc* — with the dracut module that brings the
pin into the initramfs — the same binary is the Clevis pin *tang-pqc*:

	clevis luks bind -d /dev/vda2 tang-pqc '{"url":…,"thp":…}'

# COMMANDS

## adv _URL_ [--ca _FILE_]

List the thumbprints of the signing keys _URL_ advertises.  *--ca* is
a PEM file to verify an https server against; otherwise the system
certificate authorities are used.

## encrypt _CONFIG_ < _IN_ > _JWE_

Encrypt standard input for a Tang server; print the JWE.  _CONFIG_ is
JSON with the keys *url*, *thp*, optionally *adv* and *ca*; *thp* must
be a thumbprint listed by *adv* — the pin is checked, not the TLS alone.

## decrypt < _JWE_ > _OUT_

Recover the key from the JWE on standard input; print the plaintext.

# EXIT STATUS

*0*	Success.

*1*	Error.

*2*	Usage error.

# EXAMPLES

See what a server's Tang service offers:

	tang-pqc adv https://ipa1.example.test/ipa/ku/tang

Encrypt a passphrase for it:

	echo secret | tang-pqc encrypt '{"url":"https://ipa1.example.test/ipa/ku/tang","thp":"<THP>"}' > jwe

Bind a LUKS volume through the pin, then unlock it in the initramfs:

	clevis luks bind -d /dev/vda2 tang-pqc '{"url":"https://ipa1.example.test/ipa/ku/tang","thp":"<THP>"}'

# SEE ALSO

*kuipad*(8), *clevis*(1), *clevis-luks-bind*(1)

# AUTHORS

The kuipa project contributors.
