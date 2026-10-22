# Auditing and mirroring the claim logs

The vouch-head exchange leaves a public record behind: each anchor's
claims, in a Merkle tree whose head the anchor signs. Two tools read
that record — one for the person who wants to know what the realm
vouched for, one for the site that wants proof service without anchor
keys.

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
**at the same size** or is **shorter** (the log restarted — the realm
removed something), with both sides' sizes and roots. `split-view`
names every anchor two servers answer differently, with each side's
head and the signed vouch that commits to it — the claim-log
counterpart of a forked anchor log.

The exit status is `0` for a clean report, `2` for a split view, so a
cron job or a monitoring check can watch it. `--json` prints the
report as one JSON object instead of rows.

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
into `--data`, and serves them as received: a head-pinned client
verifies a proof from the mirror with no signature and no key on it.
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
