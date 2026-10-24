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
| 4 | witness cosignatures | a fork needs the witnesses to collude | implemented: `kuipa-witness`, served cosignatures |
| 5 | storage and serving | `/var/lib/ipa/ku/tlog/`, public routes | implemented (paged routes; tiles planned) |
| 6 | producers and lookups | vault, Keys, signing and token events; the `tlog` operation | implemented for vault, escrow and Keys events, with receipts and lookups |
| 7 | clients | `kuipa tlog watch`, `kuipa-audit tlog`, `kuipa-mirror --witness` | implemented |
| 8 | claim-log migration | claims as kind-1 leaves, tombstones instead of restarts, the live tree, retired claims on hosts | implemented |

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

**The witness, `kuipa-witness`.** It is a separate tool from the keyless
`kuipa-mirror`, because a witness holds a key. `kuipa-witness keygen`
makes one: ML-DSA-44, the default profile's witness algorithm, unless
the system policy refuses it (CNSA 2.0 gives ML-DSA-87). The public JWK
it prints goes to each server with `kuipad add-witness-key`.

`kuipa-witness run --server S… [--anchor THP…] --state FILE` makes one
pass per server:
1. It verifies the server's advertisement against the anchors, which
   names the log's signing key.
2. It fetches the head, and a consistency proof from the last head it
   cosigned for that log. The state file records that head's size,
   root and time.
3. It cosigns through `tlog::witness`.
4. It posts the head with its cosignature to
   `POST /ipa/ku/tlog/{id}/cosign`.

The server takes a submission only when it is for the head being
served, and only adds trusted cosignatures that head does not already
carry. A stranger resubmitting a served head with the cosignatures it
was served adds nothing. The answer is `{cosignatures}`, `409` for a
head re-signed since it was fetched (the witness tries the next pass,
recording nothing), or `403`.

A head re-signed after the log grows starts with no cosignatures, so
witnesses should run more often than heads change: the default is
every 60 s, and heads are re-signed at least hourly. A rewritten log is
reported `forked` and is never cosigned again, until someone removes its
state entry by hand.

`kuipa-audit tlog --witness JWK… [--required K]` counts the trusted
cosignatures on the served head; fewer than K is not a clean report.

**Required cosignatures.** A host's trusted witnesses, and how many of
them must cosign a head, are in `/etc/ipa/ku-witnesses.json`. The file
is world-readable like the anchors, and root manages it with
`kuipa tlog witnesses --add JWK | --remove THP | --required K`.
`kuipa tlog watch` then needs K trusted cosignatures on each server's
head. A head with fewer is reported **unwitnessed**: its entries are
listed, but the watch does not record it, so the next watch sees them
again under a cosigned head. Such a head may be a view shown to this
reader alone, which only witnesses can rule out. Right after a log
grows, its new head has no cosignatures until the witnesses' next
pass, so a watch run in that gap is unwitnessed. Run it again after the
pass.

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

### `kuipa-audit tlog`

A public auditor's check of one server's whole log. It needs no
account, and only `--state` writes, to the file it names:
1. It verifies the server's advertisement against the given anchors, or
   the host's pinned ones. The advertisement names the server's signing
   key, and the served head must carry that key's signature.
2. It fetches every leaf and replays the log, so the tombstone rules
   apply. The replayed root must be the head's root.
3. With `--state FILE`, the recorded root must be the root of the same
   prefix of the replayed log. The auditor holds every leaf, so this is
   a direct recomputation rather than a proof. The new head is then
   recorded.

The report is `verified`, `empty`, `forked: …` (exit status 2), or
`unchecked: …` for a log larger than one run reads (2²⁰ leaves). It
counts the leaves by kind, and names nobody. Leaves carry only indexes.

## 8. Claim logs on typed leaves

An anchor's claim log (DESIGN.md §4.9) stays **anchor-signed**, so it
does not move into the server's own log. A claim is an anchor vouching
for a server, and the server's own key cannot vouch for itself. It
takes this log's rules instead:
- **Typed leaves.** A claim is a kind-1 leaf (`Leaf{kind: 1, time:
  iat, index: 0, body: IPDC}`).
- **Tombstones, not restarts.** A claim no longer vouched for is
  retired by a tombstone leaf naming its index, stamped with the
  vouch's `iat`, under the reason "claim dropped". `IPSV` v2 carries the
  entries, both claims and tombstones, and replays them under the same
  rules as `Log`: a claim is appended only while not live, and a
  tombstone retires an earlier live claim. A claim vouched for again
  is appended again.
- **The live tree.** `IPVH` v2 signs the log's `(size, root)` and the
  live tree's `(live_size, live_root)`. Signature proofs are inclusion
  in the live tree, so a dropped claim stops proving at the next vouch.
- **Retired claims on hosts.** Head proofs carry no signature. When a
  host pins a head, on first pin or when extending a window, it reads
  the head's signed vouch from the claim-log page, checks that its
  first `size` entries make the pinned root
  (`SignedVouch::retired_at`), and records the claims they retired as
  a `retired` line beside the pin. `verify_with_heads` refuses a head
  proof for a retired claim. A head whose retired claims cannot be
  read is not pinned.
- **Forks.** A log shorter than the window's newest head is refused
  and reported, and the audit reports it as a split. Before, it was a
  restart and the window started over.

Heads used without being pinned know nothing of retirements: an
enrollment string's head before enrollment, `realm-info`, and the
read-only `kuipa advertisement`. The window extension still walks the
pages from index 0. Moving it to the consistency proofs of §3 is the
next step.

## Next

* **Consistency proofs for claim-log windows**, instead of the walk
  from index 0.
