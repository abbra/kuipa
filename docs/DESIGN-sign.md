# kuipa signing statements

A principal holding a Kerberos ticket asks a realm server to **state**
that it signed some digests for a purpose. The server checks the
realm's signing policy, records the statement in its transparency log
(DESIGN-tlog.md), and signs it with its delegation-vouched ML-DSA key.
The client holds nothing: no signing key to keep, no certificate whose
window a signature must fall in. Anyone holding the realm's anchors
verifies the statement offline.

| piece | status |
|---|---|
| statements, batches, bundles (`kuipa-enroll::sign`) | implemented |
| the `sign` operation, the policy, `memberOf` groups | implemented |
| `kuipa sign blob`, `kuipa sign verify` | implemented |
| `kuipa-gitsign` (git's `gpg.x509.program`) | implemented |
| RPM and OCI | out of scope: both sign with post-quantum OpenPGP, which kuipa leaves alone |

## 1. The exchange

`POST /ipa/ku/sign/{kid}` is a sealed, Kerberos-only operation,
labelled `sign` in the transcript. Its data is `IPGQ ‖ 1 ‖ purpose ‖
n(u64) ‖ [alg(1) ‖ digest]`, with up to 256 SHA-256, SHA-384 or SHA-512
digests. A purpose is lowercase letters, digits and `-`, at most 64
bytes. The server, in order:

1. Authenticates the caller by its ticket and refuses a locked
   principal.
2. Reads the realm's **signing policy** and the caller's groups.
   - The policy is the JSON `ipaKUSignPolicy` on
     `cn=sign-policy,cn=kuipa,cn=etc`. For each purpose it lists users
     (`alice` or `alice@REALM`), groups, host FQDNs and service
     principals (`HTTP/ci.example.test`).
   - The groups are the `memberOf` of the caller's entry, user groups
     and host groups alike, named by their `cn`.
   - No policy entry, or no such purpose, means no signing. PAC group
     data replaces `memberOf` once kuipa reads the PAC.
3. Builds the **batch**: an RFC 9162 tree over the digests' leaves,
   `H(0x00 ‖ IPGL ‖ 1 ‖ alg ‖ digest)`, in request order. One statement
   covers them all.
4. Appends a kind-5 leaf to its log. Its index is the caller's
   principal, and its body is `IPGS ‖ 1 ‖ purpose ‖ batch size ‖ batch
   root ‖ time`, with no name in it. A server that keeps no log
   refuses, because a statement nobody can find in a log is one its
   signer cannot monitor.
5. Signs the **statement** under the ML-DSA context `ipa-ku-sign/v1
   statement`, with the log's position in it:

```
IPGS  realm principal purpose batch_size(u64) batch_root(32) iat(u64) log(32) index(u64)
```

The answer `IPGR` is the signed statement (with the server's delegation
and public key, as a vault descriptor carries them) and each digest's
path in the batch. The client makes one **bundle** per digest: `IPGB ‖
statement ‖ digest ‖ index ‖ path`. It checks each bundle against the
batch and the purpose it asked for, and refuses an answer that does not
cover the request.

## 2. Verification

A bundle verifies with the realm's anchors and nothing else. The
verifier checks four things:
- the data's digest is the bundle's;
- the digest is in the statement's batch, at its index;
- the delegation in the statement verifies against the anchors **as
  of the statement's `iat`**, as offline enrollment bundles do (§8.4),
  and its key is the statement's signer, with an algorithm the policy
  allows;
- the principal is in the realm.

A statement therefore stays verifiable after the server's key rotates
or its delegation ends. The log entry it names, at `(log, index)`,
shows that the statement was made, and when. A verifier may also ask
for a particular signer (`--signer`) or purpose (`--purpose`).

The statement's algorithm follows the deployment. Under a CNSA 2.0
system policy the server's key is ML-DSA-87, and a verifier with that
policy refuses anything else.

## 3. Monitoring

Each statement's log leaf is indexed by its signer. A principal's
lookup with no vault named (DESIGN-tlog.md §6) lists everything signed
in its name. Auditors see statements counted by kind, without names
(`kuipa-audit tlog`).

## 4. Clients

- `kuipa sign blob FILE… [--purpose P]` signs, by the default ticket,
  and writes `FILE.kusig` beside each file. A CI runner runs it after
  `kinit -k` with its service keytab.
- `kuipa sign verify FILE [--signature F] [--signer S] [--purpose P]`
  verifies offline with the host's pinned anchors. It exits non-zero
  for another signer or purpose than asked for.
- `kuipa-gitsign` is git's `gpg.x509.program`:

  ```
  git config gpg.format x509
  git config gpg.x509.program kuipa-gitsign
  git config user.signingkey kuipa
  ```

  - **Signing.** Git runs it with `-bsau`. It signs for the purpose
    `git-commit` (`KUIPA_GITSIGN_PURPOSE` overrides this), writes the
    bundle armored as `-----BEGIN SIGNED MESSAGE-----`, and reports
    `SIG_CREATED`.
  - **Verifying.** Git runs it with `--verify`. It reports `GOODSIG`,
    `VALIDSIG` and `TRUST_FULLY` for a good bundle, and `BADSIG`
    otherwise.

  Forges show these commits as unverified, since they know only gpg,
  ssh and S/MIME signatures.

## 5. What it is not

- **Not a key certificate.** The server signs the statement. Nobody
  holds a key that could sign later, and nothing outlives the request.
- **Not RPM or OCI signing.** Both already sign with post-quantum
  OpenPGP, and kuipa does not take part in that chain. Binding those
  OpenPGP keys to Kerberos identities with a statement would be a
  later step.
- **Not a server that cannot lie.** A server holding the realm's
  delegation can state anything for anyone. Every statement is in a
  log its signer can watch, and witnesses keep the log honest
  (DESIGN-tlog.md §4).
