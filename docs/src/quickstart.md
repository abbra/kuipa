# Quick start

The fastest way to see kuipa work is the **playground**: a throwaway realm
on your machine, with a real MIT KDC and two IPA servers running `kuipad`.
Nothing touches your system's configuration.

## Build

You need Rust 1.89 or later, OpenSSL 3.5 or later (for ML-KEM and ML-DSA),
and the Kerberos and OpenLDAP client libraries — MIT Kerberos by default, which
the playground's KDC needs. On Fedora:

```sh
sudo dnf install cargo gcc clang-devel pkgconf-pkg-config \
    openssl-devel krb5-devel openldap-devel
sudo dnf install krb5-server krb5-workstation krb5-pkinit   # the playground's KDC
cargo build --release
```

The programs are in `target/release/`: `kuipa`, `kuipa-unseal`,
`kuipa-voucher`, `kuipad` and `tang-pqc`.

## Try it in the playground

```sh
./contrib/ci/local-ci.sh interactive
```

You get a shell with a realm (`EXAMPLE.TEST`), two servers (`ipa1`,
`ipa2`), a trusted realm (`B.TEST`), a voucher issuer, and helper commands.
A first session:

```sh
pq_enroll web1             # web1 joins with its one-time password
kuipa status               # what web1 now knows: realm, keys, servers, anchors
kuipa rotate-keys          # new host keys, authenticated by the current ones
kuipa check                # every server, the delegations, a kinit with the keys

kuipa protect              # seal the keytab: /etc/krb5.keytab becomes a link into /run
kuipa-unseal               # what the boot unit does: unseal through a server
kuipa unprotect            # back to a plain keytab

pq_down ipa1; pq_enroll web2; pq_up   # web2 joins through ipa2 while ipa1 is down
pq_voucher web7            # a blind-signed, single-use voucher instead of an OTP
pq_offline web5            # staged in advance, enrolled from a bundle offline
```

And as a user, sealing a file of your own:

```sh
pq_admin_kinit                                 # a ticket, and a kuipa data directory
kuipa seal create personal --require device,ticket
kuipa seal device add personal                 # asks for a passphrase for the device key
echo "token=s3cret" > notes.txt
kuipa seal file personal notes.txt             # notes.txt.sealed
kuipa seal open notes.txt.sealed --out - | cat
```

[Local CI and the playground](development/local-ci.md) lists every helper,
and [A traced session](scenarios/walkthrough.md) explains, line by line,
what happens on the wire during an enrollment.

## On real systems

Running kuipa against a real FreeIPA deployment needs pieces that FreeIPA
does not have yet: the LDAP schema for kuipa's attributes, access controls
for the daemon, the `ipa-ku/<server>` service principal on each server, and
installer and `ipa` command support. Until then, deploying it means doing
those steps by hand, on a test realm only. The realm administrator chapters
describe what each server needs; the host administrator chapters cover the
client side, which works the same against the playground and a real realm.
