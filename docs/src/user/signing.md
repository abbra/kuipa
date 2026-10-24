# Signing under your ticket

`kuipa sign` has the realm state that **you**, by your Kerberos ticket,
signed some files. You need no signing key and keep nothing: a server
of the realm checks the realm's signing policy, records the statement
in its transparency log, and signs it. Anyone whose host pins the
realm's anchors can verify it, offline.

```sh
kinit alice
kuipa sign blob release-1.0.tar release-1.0.txt
```

This makes one statement for both files and writes
`release-1.0.tar.kusig` and `release-1.0.txt.kusig`:

```
release-1.0.tar -> release-1.0.tar.kusig
release-1.0.txt -> release-1.0.txt.kusig
Signed by alice@EXAMPLE.TEST for blob at 2026-10-24 13:30:02 UTC, stated by ipa1.example.test (log 3f2a… #41).
```

The purpose (`blob` by default, `--purpose` otherwise) must be one the
realm's signing policy lets you sign for. Your administrators decide
who signs what, by name or by group.

## Verifying

```sh
kuipa sign verify release-1.0.tar --signer alice --purpose blob
```

```
Good signature: release-1.0.tar signed by alice@EXAMPLE.TEST for blob at 2026-10-24 13:30:02 UTC, stated by ipa1.example.test (log 3f2a… #41).
```

No server is asked. A changed file, a signature from another realm, or
another signer or purpose than the one you asked for fails.
Verification checks the statement as of the time it was made, so it
keeps working after the realm rotates its servers' keys.

## Signing git commits

`kuipa-gitsign` plugs into git as an x509 signing program:

```sh
git config gpg.format x509
git config gpg.x509.program kuipa-gitsign
git config user.signingkey kuipa      # any value: your ticket decides
git commit -S -m "…"
git verify-commit HEAD
```

`git verify-commit` prints `Good signature by alice@EXAMPLE.TEST for
git-commit`. GitHub, GitLab and other forges show these commits as
unverified, because they do not know kuipa's signatures.

## In CI

A CI runner signs as its own service principal. It runs `kinit -k` with
its keytab, then `kuipa sign blob …`. Many artifacts go in one request
(up to 256), and each still gets its own `.kusig`.

## Seeing what was signed in your name

Every statement is in the log of the server that made it, filed under
your principal but without your name. Run `kuipa tlog watch` on a vault
to check that vault. Your signing statements are your principal's own
entries (see the design's `tlog` lookups).

## What it does not do

* **RPM packages and container images.** They already sign with
  post-quantum OpenPGP, and `kuipa sign` stays out of that.
* **Keep a key you could misplace.** The statement is the signature.
  There is nothing to revoke afterwards, except your account.
