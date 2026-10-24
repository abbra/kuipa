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
| 5 | storage and serving | tiles under `/var/lib/ipa/ku/log/`, public routes | planned |
| 6 | producers and lookups | vault, Keys, signing and token events; the `log` operation | producers for vault, escrow and Keys events implemented, with receipts; lookups planned |
| 7 | clients | `kuipa log watch`, `kuipa-audit log`, `kuipa-mirror --witness` | planned |
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
or a principal, and `k_index` is a realm secret held escrow-sealed like
`ipaKUVaultSessionKey`. The index lets the public log be mirrored and
audited without listing who it is about. Only an authenticated lookup
(§6) maps a subject to its index. Leaves without a subject use zeros.

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

## 5, 7, 8. Next

* **Storage and serving.** The log lives in a `kuipad` tile store under
  `/var/lib/ipa/ku/log/<log id>/`, laid out as tlog-tiles. Routes:
  `GET /ipa/ku/log/{id}/checkpoint`, `GET /ipa/ku/log/{id}/tile/…`, and
  a witness endpoint for `kuipad` acting as one. A C2SP signed-note
  checkpoint encoding is added for interoperable witnesses once the
  ML-DSA note format is settled.
* **Lookups.** The Kerberos-authenticated `log` operation (`IPLQ`/`IPLR`)
  returns a caller's own entries with inclusion proofs. Per-user
  completeness is not proven. Omissions are left to public auditing and
  witnesses; a prefix-tree map would need a post-quantum VRF.
* **Clients.** `kuipa log watch` flags device and escrow events the user
  did not cause. `kuipa-audit log` checks consistency and tombstones.
  `kuipa-mirror --witness` cosigns.
* **Migration.** Claims are appended as kind-1 leaves, and a dropped
  claim becomes a tombstone instead of a restart. IPVH/IPSV are kept for
  pinned hosts until their windows age out.
