# kuipa claim-log services

Design for the services that the vouch-head exchange (DESIGN.md §4.9)
makes possible. §4.9 built the mechanism — claim logs, head proofs,
heads in pins — and one policy: a stale head falls back to a signature
proof. This document designs what else can be expressed on that
mechanism, in dependency order, and is the plan the implementation
follows. Nothing here changes §4.9's wire formats for existing
members; every new member is additive, and old clients ignore it.

| § | service | what it adds | over |
|---|---|---|---|
| 1 | head windows | trust the union of every head the host verified | §4.9.4 |
| 2 | frozen trust | a pin that never falls back to a signature | §1 |
| 3 | cross-realm heads | B's heads pinned through A's `trusts` | §1, DESIGN.md §17 |
| 4 | the signed vouch in the public claim log | audits that signature-check | §4.9.5 |
| 5 | `kuipa-audit` | coverage and split-view reports from public data | §4 |
| 6 | `kuipa-mirror` | a keyless, read-only proof replica | §1, §4 |

## 1. Head windows

### 1.1 What a pin holds today

A head pin today is one `(size, root)` per anchor, replaced by every
verified advertisement (§4.9.4). A claim whose leaf entered the log
*after* the pinned head cannot be proven head-wise, and the client
falls back to a signature proof. That is correct but wasteful: between
two refreshes of the pin file the tree grows by every renewed claim,
so in a realm with frequent renewals most verifications take the
signature path — exactly the cost §4.9 exists to avoid.

### 1.2 A window is a sequence of heads

A **head window** for an anchor is the sequence of heads the host has
verified for that anchor, kept oldest-first, at most
`MAX_HEAD_WINDOW` (4) of them. The window starts at enrollment (or at
the trust's installation, §3) with the advertisement's head. On every
verified advertisement or sealed response the new head is appended if
it extends the current window — strictly greater size — and the window
is trimmed to the newest `MAX_HEAD_WINDOW` entries. The oldest head
still in the window bounds how far back a claim can be proven: a claim
older than the window falls back to a signature, as today.

The pin-file grammar gains the repeated head pair:

```
<thumbprint> <expiry> <size1> <root1> [<size2> <root2> …] [frozen]
```

Backwards compatible: one head is today's line; the parser keeps the
disambiguation rule (the field after the first number is a thumbprint,
so the first number is a size) for expiry-less lines, and a lone
number stays an expiry. Heads in a line must strictly increase in
size; a duplicate or shrinking head is a parse error, not a silent
drop — the file is an administrator's assertion and must round-trip
exactly.

### 1.3 Extending the window: consistency, not trust

Appending a new head from a verified advertisement is not enough: the
advertisement says *what the head is*, and the host must also check
*that its own pinned history is a prefix of the new tree* — otherwise
a compromised server could hand the host a fresh, unrelated head (its
own tree) and the host would pin it, because the advertisement as a
whole verifies (the delegated key signs it, and a thief holding that
key signs anything). The signature path has the same exposure and
accepts it; for windows we do not have to, because the claim log gives
us the check:

**The consistency rule.** Before appending a new head `H2` over a
pinned `H1` for the same anchor, the client fetches the anchor's claim
log from index `H1.size` to `H2.size` (the pages between them, public
per §4.9.5) and checks that the leaves hash to `H1.root` as a prefix
of `H2.root` — an RFC 9162 consistency check between the two tree
sizes, computable from the fetched leaves alone (rebuild `H1`'s tree
from the first `H1.size` of them and compare roots, then `H2`'s from
all). `merkle::root` does both. Only then is `H2` appended. If the
check fails the head is not pinned, the server is reported (it served
a head that does not extend ours — the same split-view evidence the
anchor-log watermark treats as a fork, §4.8), and the window keeps
`H1`.

This is why the fetch is worth its cost: it turns "trust the newest
signed statement" into "trust the tree that provably contains my
history", which is the landmark-window property the MTC draft gives a
relying party that keeps its landmarks (draft-ietf-plants-merkle-tree-certs
§6.4): the past cannot change behind the window.

The fetch is bounded: `H2.size − H1.size` leaves at 32 bytes each,
paged like the anchor log (`MAX_CLAIM_LOG_PAGE`). Between routine
refreshes of a realm that renews claims daily, that is one page.

**Restart is a truncation, not an extension.** A head whose size is
*lower* than the window's newest (the anchor restarted its log — a
claim was dropped, §4.9.1) ends the old window: the old heads are
dropped and the new head starts a fresh window, exactly as a
first-time pin. The client reports the restart (`check` and `status`
show it): the realm removed something, and the host's trust in the
removed claim's anchor history ends with it. No signature fallback is
forced — the new window's heads still prove everything the new tree
covers — but the *reason* is visible, which the signature path cannot
express (§4.9.6: it cannot distinguish a removal from an addition).

### 1.4 Verification against a window

`verify_at_with_heads` (§4.9.2) today checks a head proof against each
pinned head and takes the first that matches. With windows it checks
against **every** head in the window: a proof for a claim under any of
them verifies, since every prefix of the log is the tree an earlier
vouch signed. The `?head=` parameters carry the whole window, in
order; the server's `advertisement_with_heads` already tries each
pinned head in turn and serves the first that makes a proof, so its
behaviour is unchanged. A claim below the oldest head in the window
still falls back to a signature proof — the window only widens what
is head-provable, it never narrows today's guarantees.

### 1.5 What this does not change

* The two-anchor quorum (§4.4) is unchanged: two windows by distinct
  anchors must both prove the claim.
* Successions (§4.7) carry the window as they carry the single head:
  a rotated anchor's window ends, the successor's starts fresh.
* The enrollment string (`ipa-ku2`) stays one head — it is printed by
  an administrator once, and a window in it would be stale at first
  use. The window is state the host grows.

## 2. Frozen trust

A **frozen** pin is a head window of one with the fallback removed:
the client refuses to verify a claim against anything but the pinned
head. On the wire it is the `frozen` marker at the end of a pin line
(§1.2's grammar); in the enrollment string a third form is not added
— freezing is a pin-file property, because it is an administrator's
decision about a host's lifetime, made when the image or profile that
writes the pin file is built.

Verification with a frozen pin: a head proof that checks against the
pinned head is accepted as today; a stale head, an absent head, or a
signature proof is refused with a reason that names the freeze —
`frozen: the pinned head does not prove this claim` — so the refusal
is diagnosable, not a generic verification failure. The two-pin
quorum still applies: two frozen pins by distinct anchors must both
prove the claim head-wise.

Refresh rules: a frozen pin is never refreshed from advertisements (a
frozen host may still enroll — the join's response writes its keys,
and the *pin file's* frozen lines are preserved untouched beside the
heads the response carries). This is deliberate: the point of frozen
trust is that the host's trust does not move without the operator,
which is the property an appliance or image wants (§4.9.4's
"trusts exactly the claims that were in the tree when its pin was
written", made a mode instead of a footnote). An operator unfreezes
by editing the pin file (removing the marker) or re-provisioning.

`kuipa status` reports frozen pins and the head they hold; `kuipa
check` refuses servers whose claims the frozen head cannot prove,
naming the freeze.

## 3. Cross-realm heads

DESIGN.md §17.3 installs a trusted realm B's anchors as pins, taken
from A's verified `trusts` member, and B's advertisement is then
verified with them on every refresh — signature proofs today.

The `TrustedRealm` wire member gains each anchor's current head:

```json
{"realm": "B.TEST", "domain": …, "servers": […],
 "anchors": ["<thp>", …],
 "heads": [{"anchor": "<thp>", "size": 12, "root": "<b64url>"}, …]}
```

— exactly `RealmInfo.heads`'s shape (§4.3), so `as_partner` reuses it,
and `kuipad`'s trust refresh fills it from B's advertisement the same
way it fills `anchors` today. A missing `heads` member means "A knows
B's anchors but not their heads" (an older partner, or B's first
advertisement carried none): the client pins the anchors alone, as
today, and B's refresh verifies with signatures until a later refresh
of the trust carries heads.

`kuipa trusted-realms` writes B's heads into
`/etc/ipa/ku-anchors.d/B.TEST` (§1.2's grammar, no expiry: the trust
refresh renews them) and verifies B's advertisement against them on
every refresh, with B's advertisement's own `heads` member as the
window extension source — subject to §1.3's consistency rule, so a
host of A watches B's tree grow only through provable prefixes. The
`heads` a host of A accepts for B come from A's *trusts* (signed by
A's delegated key) or B's *advertisement* (verified with B's pinned
anchors and heads) — never from B's delegation member, which is
untrusted input, the same rule as §4.9.4.

Trust refresh cadence is unchanged; the trust's pin file grows a
window per B anchor exactly as the host's own pin file does for A.

## 4. The signed vouch in the public claim log

§4.9.5's claim-log page carries the head and the leaves but not the
vouch that signed the head, so an auditor cannot check that the head
was signed at all — only that leaves are consistent with it. The page
gains the anchor's current signed vouch:

```json
{"anchor": …, "size": …, "root": …, "exp": …,
 "leaves": […],
 "vouch": "<b64url IPVH, version 2, signed>"}
```

The vouch is public data today (it travels in the exchange and in
every signature proof), so serving it changes no secret's exposure.
The auditor (§5) checks its signature against the anchor's key —
fetched from any advertisement, as `Proof.anchor` travels there — and
then the page's leaves against the vouch's head. A mirror (§6) serves
it as received; a mirror's copy being stale shows as a vouch whose
`exp` has passed, which the audit reports.

Old readers ignore the member; the page's version does not change
(new JSON members are the established compatibility rule for this
route).

## 5. `kuipa-audit`

A read-only tool for the person who wants to know what a realm's
anchors vouched for, or to compare what different servers say:

```
kuipa-audit claim-log  --server S [--from N] [--anchor THP]…
kuipa-audit coverage   --server S [--anchor THP]… [--pinned-head "THP SIZE ROOT"]…
kuipa-audit split-view --server S1 --server S2 [--anchor THP]…
```

* `claim-log` prints a fetched page (and the vouch, §4), decoded:
  index, leaf hash, and — when the realm's advertisement is fetchable
  and carries the anchor's key — the claim the leaf names (server,
  key thumbprint, validity), by matching the leaf against the
  advertisement's delegation claims. Read-only, no host state.
* `coverage` answers "what does this head cover": given a head (or
  the host's pinned heads, when run on an enrolled host with no
  `--pinned-head`), it fetches the pages up to the head's size and
  reports, per anchor, the tree size, the leaf range, each claim
  decoded as above, and — for a host pin — whether the pinned head is
  current (the server's newest head extends it), stale (the server's
  tree has grown: the consistency check of §1.3, applied read-only),
  or restarted (the server's tree is shorter).
* `split-view` fetches each server's current heads and reports
  anchors on which they disagree, with each side's `(size, root)` and
  vouch — the claim-log counterpart of the anchor-log fork report.

Output is the same labelled-rows text style as `kuipa advertisement`
(`--json` for machine-readable), and the refusal vocabulary of
`kuipa check` (no server reachable, refused, split view) is reused.
The tool holds no keys, writes nothing, and authenticates nothing a
public reader could not: it is `curl` plus the tree math.

## 6. `kuipa-mirror`

A read-only replica for a site that wants proof service without
anchor keys:

```
kuipa-mirror --origin https://ipa1.example.test \
             --listen 0.0.0.0:8443 [--data DIR] [--interval 60]
```

* **Sync.** Every `--interval` seconds (and once at start) it fetches
  the origin's *public* endpoints only: `/ipa/ku/adv` (its own
  `?anchor=`-less form — the plain advertisement), `/ipa/ku/anchor-log`
  and `/ipa/ku/claim-log/{anchor}` pages, storing them under `--data`.
  It follows head growth page by page (the same fetch as §1.3's
  consistency check), so its claim-log copy is always a verified
  prefix chain. It never authenticates to the origin, never receives
  a secret, and stores nothing but public bytes.
* **Serve.** It answers, read-only: `/ipa/ku/adv` (the cached
  advertisement, re-signed at half life *by the origin's delegated
  key as received* — it cannot re-sign, and does not need to: a
  cached advertisement is valid until its own expiry),
  `/ipa/ku/anchor-log`, `/ipa/ku/claim-log/{anchor}`, and
  `/ipa/ku/adv?anchor=&head=` — the head-proof path of
  `advertisement_with_heads`, served from the cached vouches exactly
  as `kuipad` serves them, which is why a mirror can serve proofs a
  head-pinned client accepts with no key material. Join, rekey and
  every authenticated route are absent: a mirror is not a server, and
  a client that tries to join through one is refused by the missing
  route, not by a policy it could be talked out of.
* **Freshness.** A mirror's vouches expire (7 days, §4.2): when the
  origin is unreachable past that, the mirror's head proofs stop
  verifying for *new* verifications (the client's own clock and the
  vouch's `exp` decide — the mirror cannot lie about it, it serves
  the signed vouch). `kuipa check` against a mirror reports it as a
  stale source. This is the honest bound: a mirror extends a site's
  proof capacity, not its availability of trust.
* **Compromise.** A thief who edits the mirror's stored vouches or
  leaves serves proofs that do not verify (the client checks against
  its pinned heads and the tree); a thief who serves a *different*
  realm's data is caught by the head check itself. The mirror is
  untrusted by construction — the client's pins are the only trust,
  the same property §4.9 gives any server.

## Threat model summary

| threat | today (§4.9) | with this design |
|---|---|---|
| compromised server serves its own tree as a head | client pins it (the advertisement verifies; same as the signature path) | §1.3's consistency check refuses it and keeps the old window |
| anchor key theft | head proofs bounded by pinned heads; signature path unbounded | unchanged (§4.9.6); audit (§5) reconstructs exactly what was covered |
| mirror operator edits stored data | — | proofs stop verifying against client pins; no trust in the mirror |
| realm removes a server | head restart; client silently re-pins | §1.3: restart reported by `check`/`status` |
| rogue server feeds different trees to different clients | undetectable from the client | `kuipa-audit split-view` compares heads (with signed vouches) across servers |
| frozen host's trust moves | impossible only by never refreshing | §2 makes it a checkable mode with named refusals |

## Wire-format changes (all additive)

| member | where | form |
|---|---|---|
| repeated `<size> <root>` pairs, `frozen` marker | pin-file lines (§1.2, §2) | text, backwards compatible |
| `heads` | `TrustedRealm` JSON (§3) | as `RealmInfo.heads` |
| `vouch` | claim-log page JSON (§4) | base64url signed IPVH v2 |

## Test plan

* `kuipa-enroll` unit: window append/truncate rules; the consistency
  check (a real extension passes, a forged head that skips history
  fails, a restart truncates and reports); frozen refusal reasons;
  `TrustedRealm` heads round-trip and the missing-member default.
* `kuipa-tools` unit: pin grammar with windows and `frozen`
  (round-trip, ordering errors, the expiry/size disambiguation kept);
  `kuipa-audit`'s decode of pages and heads against fixtures.
* `tests/flows.rs`: a window-holding client verifies an old claim
  head-wise after the tree grows (no signature fallback); a stale
  window extends through the consistency fetch; a forged head is
  refused and reported; a frozen client enrolls and then refuses a
  claim outside its head with the frozen reason; `trusted-realms`
  writes B's heads and B's next refresh is head-verified.
* `tests/kdc.rs` (real KDC, two servers): a client with a window
  rides a claim renewal head-wise across both servers; the audit
  tools' split-view agrees with itself on the healthy realm.
* mirror: sync from a router's public endpoints, serve head proofs a
  pinned client accepts, join through the mirror refused (no route),
  stale vouches reported; the playground gains a mirror and audit
  steps (§ `local-ci.sh playground-test`).

## What is deliberately not here

* No global log, no monitor role, no new quorum (§4.9.6 stands).
* No revocation (§4.7's limits stand; restart is observability).
* No `ipa-ku3` string form — windows are host state, not a string.
* No mirror-to-mirror gossip: one origin, fetch-only, operator-run.
