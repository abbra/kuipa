# kuipa typed transparency logs

The claim log of DESIGN.md §4.9 records one thing — server claims —
and restarts whenever a claim drops out, so a host can only check it
by refetching every leaf. Users need more. "Who added a device to my
vault?" and "who released my escrow share?" should have answers that
a server cannot quietly rewrite. This document designs a log that can
hold such events, and the order in which it replaces the claim log.

| § | piece | what it adds | status |
|---|---|---|---|
| 1 | typed leaves | a kind inside every hashed leaf; an opaque subject index | implemented (`kuipa-enroll::tlog`) |
| 2 | tombstones | retiring a leaf appends, so heads only ever extend | implemented |
| 3 | signed heads, consistency proofs | RFC 9162 consistency instead of refetching | implemented |
| 4 | witness cosignatures | a fork needs the witnesses to collude | implemented (the cosign step) |
| 5 | storage and serving | `/var/lib/ipa/ku/tlog/`, public routes | implemented (paged routes; tiles planned) |
| 6 | producers and lookups | vault, Keys, signing and token events; the `tlog` operation | implemented for vault, escrow and Keys events, with receipts and lookups |
| 7 | clients | `kuipa tlog watch`, `kuipa-audit tlog`, `kuipa-mirror --witness` | `kuipa tlog watch` implemented; the others planned |
| 8 | claim-log migration | claims become kind-1 leaves; IPVH retires | planned |

## 1. Typed leaves

A leaf is `IPLF ‖ 1 ‖ kind(2) ‖ time(u64) ‖ index(32) ‖ body` and its
tree hash is RFC 9162's `H(0x00 ‖ leaf)`. The kind sits inside the hashed
bytes, so two leaves with the same body but different kinds are
different leaves. A claim leaf can therefore never be read as a vault
event. Unknown kinds parse, so mirrors and monitors keep working when a
server logs kinds they do not know yet.

| kind | meaning |
|---|---|
| 1 | server claim (`IPDC` body) |
| 2 | vault device added or removed |
| 3 | vault policy set, or vault revoked |
| 4 | escrow share released (unlock, offline session, override) |
| 5 | signing statement |
| 6 | Keys-operation fetch |
| 7 | token key epoch |
| 0xFFFF | tombstone (§2) |

`index` is `HMAC-SHA-256(k_index, subject)`. The subject is a vault id
or a principal, and `k_index` is the logging server's own key (§5). The
index lets the public log be mirrored and audited without listing who
it is about. Only the server that logged a leaf, answering an
authenticated lookup (§6), maps a subject to it. Servers use different
keys, so an auditor reading two servers' logs cannot tell that two
leaves concern the same vault. Leaves without a subject use zeros.

Each server keeps its own log, `LogId = SHA-256("ipa-ku-log/v1 id" ‖
len(realm) ‖ realm ‖ server)`. Events go to the log of the server that
handled them, so replicas never need to agree on one order. Clients
query every server, as they already fetch every server's claim log.
The id does not depend on the signing key, so a key rotation continues
the log rather than forking it.

## 2. Tombstones

A leaf that is no longer current, such as a renewed claim, stays in the
log. A tombstone leaf, kind 0xFFFF with body `IPLT ‖ 1 ‖ target(u64) ‖
reason`, retires it. A tombstone must name an earlier leaf that is
neither a tombstone nor already retired. `Log::append` refuses anything
else, and so does `Log::replay` when it rebuilds a log from storage, so
a store with a doubled tombstone does not load.

Every new head therefore extends every earlier one. The "restarted"
state of `kuipa-audit` and host windows (DESIGN-claim-logs.md §1.3)
disappears once claims move here (§8).

## 3. Signed heads and consistency

A head is `IPLH ‖ 1 ‖ log(32) ‖ size(u64) ‖ root(32) ‖ time(u64)`, never
of size zero. The server signs it with its delegation-vouched key under
the ML-DSA context `ipa-ku-log/v1 head`. `Head::extends` holds when the
log is the same, the size and time do not shrink, and the RFC 9162
§2.1.4 consistency proof verifies. That proof replaces the full refetch
from index 0 that `extend_windows` and `kuipa-audit` do today.
`kuipa-enroll::merkle::{consistency, verify_consistency}` wrap
`synta-mtc`. Their tests check every pair of sizes up to 33 against an
independent transcription of §2.1.4.2.

A proof does not pin the new size by itself; the size is signed with the
root. This is the same reason inclusion paths need a signed size.

## 4. Witness cosignatures

A cosignature is `{witness thumbprint, time, signature}` over `IPLC ‖ 1 ‖
time ‖ head` under `ipa-ku-log/v1 cosignature`. A signed head is
`IPLS ‖ 1 ‖ head ‖ signature ‖ n(1) ‖ [witness(32) ‖ time ‖ signature]`.
It carries at most 16 cosignatures and at most one per witness, and
cosigning again replaces a witness's earlier cosignature.

`tlog::witness` is a witness's whole step. It checks the log key's
signature, and requires the new head to extend the last head this
witness cosigned for that log, before it adds a cosignature. A server
that shows different logs to different clients is then caught unless
the witnesses collude. `SignedHead::witnesses` counts only cosignatures
by keys the verifier trusts, made with algorithms its policy allows.

**Algorithms follow the deployment.** The verifier's `tang_pqc::Policy`
comes from the system crypto policy (`Policy::from_system`).
- Under the default, witnesses may use ML-DSA-44, as C2SP tlog-witness
  and Chrome's quantum-resistant root policy expect of cosigners.
- Under CNSA 2.0, only ML-DSA-87 counts, both for the log key and for
  witnesses.

## 6. Producers and receipts

`EnrollServer` takes a `Ledger` (`with_ledger`). The default,
`NoLedger`, records nothing; `kuipad` will implement one over its store
(§5). Each event is appended after the operation's checks pass and
before anything is stored or answered. A failed append refuses the
request:
- a vault change is not stored;
- an escrow share or offline session key is not released.

| event | kind | subject | body |
|---|---|---|---|
| vault created, policy set, revoked | 3 | vault id | `IPLV`: action, SHA-256 of the policy (zeros for revoke) |
| device added or removed | 2 | vault id | `IPLV`: action, the device's id |
| session started, offline session keys released | 4 | vault id | `IPLV`: action, the device's id |
| server share of a sealed file released | 4 | vault id | `IPLV`: release, the device (if any), the binding's `H(ct)` |
| Keys fetch | 6 | the caller's principal | the `IPKG` fetch |

Reads (`show`, `list`) and binding registration record nothing. Vault
bodies never name the vault or its owner: the leaf's index stands for
the vault. Opening machine (keytab) bindings is not recorded yet.

A **receipt** (`IPLP`) is the server's signature, under
`ipa-ku-log/v1 receipt`, over `log ‖ index ‖ leaf hash ‖ time`. Vault
answers carry one per change, which is why `IPVR` moves to version 2.
The signature is separate from the sealed answer around it, so a client
can show a third party a promise the log did not keep. `proven_by`
checks a receipt against a head and its inclusion path. A head of the
same log that is large enough but does not hold the leaf is evidence
against the server. Escrow releases and Keys fetches have no receipt in
their answers; owners find them through lookups.

**Lookups.** `POST /ipa/ku/tlog/{kid}` is a sealed, Kerberos-only
operation, labelled `tlog` in the transcript. Its data is `IPLQ ‖ 1 ‖
vault ‖ from(u64)`:
- naming a vault the caller owns asks for that vault's entries;
- an empty name asks for those about the caller's principal (Keys
  fetches, for a host).

Nobody can look up another principal's entries, so auditors work from
the public log (§5). The answer is `IPLR ‖ 1 ‖ signer(JWK) ‖ head(IPLS,
empty for an empty log) ‖ n(u64) ‖ [index ‖ leaf(IPLF) ‖ m(1) ‖
[hash(32)]]`. Each entry carries its inclusion path in the head. At most
1024 entries come in one answer, and the client pages on with `from`.

The client accepts an answer only if three checks pass:
- the signer key's thumbprint is the one its verified advertisement names;
- the head's signature checks;
- every entry is included in the head.

Per-user completeness is not proven: a server could leave an entry out
of an answer. Omissions are left to public auditing and witnesses; a
prefix-tree map would need a post-quantum VRF.

## 5. Storage and serving

`kuipad` keeps its log under the key directory:

```text
tlog/index.key          the server's index key: 32 random bytes, 0600
tlog/<log id>/leaves    the leaves in order, each a u32 length ‖ IPLF
```

The log id is in lowercase hex. A leaf is checked (`Log::check`),
written and synced before it joins the in-memory log, so an append the
server acknowledged survives a crash. A record cut short by a crash
mid-write was never acknowledged, and is dropped when the store opens.
A malformed complete record stops the daemon instead of being skipped.

The head is signed with the server's signing key. It is signed again
when the log has grown, or when the last signature is an hour old,
since monitors want a recent time.

The routes are public, like the claim log:

| method | path | response |
|---|---|---|
| GET | `/ipa/ku/tlog/{id}/head` | the current `IPLS` (404 while the log is empty) |
| GET | `/ipa/ku/tlog/{id}/leaves?from=i` | JSON `{from, leaves}`: up to 4096 base64url `IPLF` |
| GET | `/ipa/ku/tlog/{id}/proof?index=i&size=n` | JSON `{path}`: leaf `i` in the tree of `n` leaves |
| GET | `/ipa/ku/tlog/{id}/consistency?from=m&size=n` | JSON `{proof}`: the tree of `m` leaves is a prefix of the tree of `n` |

Proofs are served at any size up to the current one, the size of a head
the client holds, so a client never needs the newest head to check an
old receipt. An id other than the server's own answers 404.

A tlog-tiles layout, a C2SP signed-note checkpoint encoding, and a
witness endpoint come with interoperable witnesses, once the ML-DSA note
format is settled.

## 7. `kuipa tlog watch`

An owner's monitor, run as the user with their ticket. For each server
the host's `realm.json` lists, it does three things:
- **Look up.** It runs `tlog` lookups for the vault from the size the
  last watch saw, paging on `from`. `finish_tlog` checks each answer.
- **Check the log extends.** The new head must extend the one last
  seen: the same root at the same size, or a consistency proof from
  `GET …/consistency` otherwise. A smaller log, an empty one, or another
  server's log id counts as **forked**. The state is not advanced
  past a fork.
- **List and flag.** It lists every new entry, and flags those the vault
  descriptor stored on this host does not account for:
  - a device it does not list added, or starting a session or receiving
    a release;
  - a device it lists removed;
  - a policy digest other than its policy's;
  - a revocation while it shows the vault enabled.

The first watch of a server is a baseline: history is listed, not
flagged. `vaults/<name>.tlog` in the user's directory keeps, per server,
the log id, size and root last verified. An unreadable state file is an
error, not a fresh baseline, so a corrupted file cannot silence a watch.
The result's `ok` is false for any flag, any fork, or any server that
could not be checked, so the command exits non-zero, which suits a timer.

What it cannot see: an entry a server leaves out of its answers (§6).
It flags against the stored descriptor, so a change the owner made from
another host is flagged until `kuipa seal show` stores the new
descriptor.

## 8. Next

* **Clients.** `kuipa-audit tlog` checks consistency and tombstones over
  the public log. `kuipa-mirror --witness` cosigns.
* **Migration.** Claims are appended as kind-1 leaves, and a dropped
  claim becomes a tombstone instead of a restart. IPVH/IPSV are kept for
  pinned hosts until their windows age out.
