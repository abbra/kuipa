# Auditing and mirroring

The realm keeps two public, append-only records:

* **Claim logs.** Each anchor's claims about the realm's servers, in a
  Merkle tree whose head the anchor signs. They say which servers the
  realm vouched for.
* **Transparency logs.** Each server's record of what it did with users'
  and hosts' secrets: vault changes, releases of vault keys, replica
  secret fetches and signing statements. Leaves name no one; an index stands
  for the vault or principal. See
  [below](#the-transparency-log-and-its-witnesses).

`kuipa-audit` checks both. `kuipa-mirror` serves the claim logs to a
site that wants proof service without anchor keys.

## kuipa-audit

`kuipa-audit` reads the public endpoints only — the advertisement, the
anchor log, the claim-log pages — and checks what it fetches against
heads, pinned on this host or given on the command line. It holds no
keys and writes nothing.

```sh
# What does this server's tree cover, and does it extend our pins?
kuipa-audit coverage --server ipa1.example.test

# One anchor's claim log, decoded: leaves, the head, the signed vouch.
kuipa-audit claim-log --server ipa1.example.test --anchor <thumbprint>

# Do the servers agree on their heads?
kuipa-audit split-view --server ipa1.example.test --server ipa2.example.test
```

`coverage` reports, per pinned anchor, whether the server's log is
**current** with the pin, grew **past** it (the pin is stale), differs
**at the same size**, or is **shorter**, with both sides' sizes and
roots. Claim logs only grow: a removed server's claim is retired by a
tombstone, not cut out. A shorter log is a split, like a different root
at the same size. `split-view`
names every anchor two servers answer differently, with each side's
head and the signed vouch that commits to it — the claim-log
counterpart of a forked anchor log.

The served head is checked before it is reported: its vouch must
verify against the anchor's key and the pages must hash to its root,
so an unsigned or inconsistent head — and a server that names an
anchor it does not answer — reports as a **split**, and a tree larger
than the audit's fetch bound as **unchecked**.  The exit status is
`0` for a clean report (every anchor current or stale) and `2` for
anything else, so a cron job or a monitoring check can watch it.
`--json` prints the report as one JSON object instead of rows.

## kuipa-mirror

`kuipa-mirror` is a keyless, read-only replica of one server's public
endpoints, for a site that wants proof service — a branch office, a
DMZ enrollment point — without anchor keys:

```sh
kuipa-mirror --origin https://ipa1.example.test \
             --listen 0.0.0.0:8443 \
             --data /var/lib/kuipa-mirror \
             --interval 60
```

It syncs the origin's advertisement, anchor log and claim-log pages
into `--data`, and serves them as received: a page is cached only
under a head the synced advertisement *proves by signature*, so the
mirror never serves the origin's bare assertion as a proof.  A
head-pinned client verifies a proof from the mirror with no signature
and no key on it.
A head query the mirror has cached is answered with the origin's
head-proof advertisement; an unseen one falls back to the cached plain
advertisement, which the client verifies through signatures — the
same silent fallback a server gives a stale head. The cache survives
restarts.

A mirror answers no authenticated route: joining through one is
refused by the missing route, not by a policy. When the origin is
unreachable past a vouch's expiry (7 days), the mirror's head proofs
stop verifying for new verifications — the clients' own clocks decide,
and the mirror, serving signed bytes as received, cannot lie about it.
A mirror extends a site's proof capacity, not its availability of
trust.

## The transparency log and its witnesses

Every server appends an entry to its transparency log before it changes
a vault, releases a vault's key share, hands out a replica secret or
signs a statement. If the entry cannot be written, the request is
refused. Opening a sealed host or service keytab is not logged yet. Users
check the entries about their own vaults with `kuipa tlog watch`
([Sealing your own files](../user/sealing.md#see-who-touched-your-vault)).
Anyone can read the whole log at `/ipa/ku/tlog/<log id>/`, with no
login.

A log is only useful if everyone sees the same one. A server could show
one history to its auditors and another to a user. **Witnesses** stop
that from going unnoticed. A witness is a small program, run by someone
other than the realm's administrators (a partner site, an audit team),
that fetches each server's signed head and cosigns it only if it extends
the last head it cosigned:

```sh
# The witness, once: a key. It prints the public key to hand out.
kuipa-witness keygen --key /var/lib/witness/witness.jwk > witness.pub.jwk

# Each IPA server accepts its cosignatures, and serves heads with them.
kuipad add-witness-key --file witness.pub.jwk
systemctl restart kuipad

# The witness, from then on: one pass a minute.
kuipa-witness run --key /var/lib/witness/witness.jwk \
    --state /var/lib/witness/state.json \
    --server ipa1.example.test --server ipa2.example.test
```

Hosts decide how many cosignatures they require. A head with fewer is
reported as `UNWITNESSED` by `kuipa tlog watch` and not accepted:

```sh
kuipa tlog witnesses --add witness.pub.jwk --required 1   # as root
```

An auditor replays a whole log and checks it against the server's
signed head. With `--state`, each run also checks that the log still
extends the head the last run saw:

```sh
kuipa-audit tlog --server ipa1.example.test \
    --state /var/lib/audit/ipa1.json \
    --witness witness.pub.jwk --required 1
```

A witness key is ML-DSA-44 by default, as public witness networks use,
and ML-DSA-87 under a CNSA 2.0 crypto policy. A server whose crypto
policy changes the strength of its keys starts a new log under a new id;
`kuipa tlog watch` reports it as `NEW LOG`, not as a fork.
