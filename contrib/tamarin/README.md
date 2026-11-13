# Formal models of the kuipa protocol

This directory holds formal models of the protocol. They carry the part of the
project's argument that is proved rather than tested. They describe the design in
`docs/DESIGN.md`. Nothing here is compiled or shipped.

When a wire format, a key schedule, or a state transition changes:

1. change the matching theory in the same commit;
2. re-prove it, as "Running the prover" below describes;
3. rewrite that theory's header verdict list from the new run, not from memory.

`CONTRIBUTING.md`, "Protocol model", states the same rule.

Paths in code font are relative to the repository root, and so are the commands;
run the commands from there. Paths inside markdown links are relative to this
file.

## What is here

Twenty-eight Tamarin theories and seven Z3 models. Each theory header says what it
assumes and what it leaves out, and lists its own proved, open, and refuted
results.

### The protocol as a whole

| File | What it models |
|---|---|
| `kuipa.spthy` | the core exchange: pins, advertisement checks, the ML-KEM join and rekey schedule, OTP and Kerberos authenticators, keytab escrow, vouchers, user seals |
| `tang-pqc.spthy` | the post-quantum Tang and its Clevis pin |
| `trust.spthy` | setting up trust between realms (DESIGN §17.4) |
| `sign.spthy` | signing statements (DESIGN-sign.md) |
| `peer-sync.spthy` | the peer-sync abstraction from DESIGN §4.2.1, in one theory |

### Peer theories, first set

| File | What it models |
|---|---|
| `peer-binding.spthy` | a request is bound to the member's signature |
| `peer-attestation.spthy` | attestation at enrollment |
| `peer-admission.spthy` | admitting a vouch signed by a pinned trust bridge |
| `peer-response.spthy` | a response is bound to its request nonce |
| `peer-snapshot.spthy` | a snapshot split into two chunks stays whole |
| `peer-order.spthy` | version order between two updates |

### Peer theories, second set

| File | What it models |
|---|---|
| `peer-pin-delivery.spthy` | how the enrollment string reaches the client |
| `peer-admission-checks.spthy` | admission with validity intervals, membership removal, and an algorithm allowlist |
| `peer-policy.spthy` | which policy applies to one admission |
| `peer-trust.spthy` | the bridge from an accepted pin back to a trust root |
| `peer-rotation.spthy` | retiring one anchor key, issuing the next |
| `peer-rotation-origin.spthy` | where a successor key's signature came from |
| `peer-rotation-client.spthy` | the client's view of the same rotation |

### Peer theories, state machines

| File | What it models |
|---|---|
| `peer-membership.spthy` | the membership generation lifecycle |
| `peer-ownership.spthy` | who owns an anchor, and releasing it |
| `peer-succession.spthy` | pin and vouch checks over a chain of successors |
| `peer-retention.spthy` | one claim: membership, validity, grace, vouch coverage |
| `peer-pruning.spthy` | how far removing one entry cascades |
| `peer-replacement.spthy` | two replicas merging the same entry |
| `peer-cache.spthy` | a receiver's cache across restarts and refills |

### Peer theories, deployment changes

| File | What it models |
|---|---|
| `peer-epoch.spthy` | the first entry of the anchor epoch log on two servers, and the gate that keeps them from forking it |
| `peer-voucher-spent.spthy` | the spent-voucher record, and what deleting a host does to it |
| `peer-custody.spthy` | the custody broker authenticating its callers, the replay cache, and the secrecy of custody secrets |

### Z3 models, for the arithmetic Tamarin cannot express

| File | What it models |
|---|---|
| `peer-validity.smt2` | exact `u64` validity and period arithmetic, with the 300-second skew |
| `peer-validity-multi.smt2` | validity updates for many entries, independently |
| `peer-ownership.smt2` | release before an owner change, one anchor |
| `peer-ownership-two.smt2` | the same, for two anchors |
| `peer-replacement.smt2` | `EntryVersion::replaces` as a total order |
| `peer-pruning-chain.smt2` | an unbounded chain of claims and vouches |
| `peer-pruning-multi.smt2` | two chains that keep each other alive |

## Proof results

The prover prints three verdicts. `verified` means proved. `falsified` means it
found a counterexample — for a lemma named `Attack_*`, that counterexample is the
attack, so a falsified `Attack_*` lemma is the result we want. This document says
"refuted" or "the attack is found" for that verdict, to keep the direction clear.
An unfinished lemma is reported as open, or by its exit code, 124 (timeout) or 137
(memory ceiling); none of those is a verdict in either direction.

One run covers the whole tree and is the only one quoted here: 2026-11-09,
Tamarin 1.12.0 with Maude 3.5.1, `contrib/ci/proofs.sh`, one lemma per process
inside an 8 GiB cgroup with no swap, 700 seconds per lemma, every lemma of every
theory attempted.

| Group | proved | open | refuted |
|---|---|---|---|
| `kuipa`, `tang-pqc`, `trust`, `sign` | 35 of 50 | 4 | 11 |
| peer theories (21 files) | 215 of 234 | 19 | 0 |
| **all theories** | **250 of 284** | **23** | **11** |

All 11 refuted results are `Attack_*` lemmas, and every one is a counterexample the
design promises (§13, §7.6.10, §17.4 Limits, DESIGN-sign.md, and the Tang attacks).
They matter: a secrecy proof that cannot be broken by a stolen key proves nothing,
and these traces show the models can be broken.

No run printed a `note` line, so no proved result in this table rests on an
assumption that was never proved. The `[reuse]` attribute can cause exactly that;
see "How to read a result" below.

Each theory header names its own open goals and the settings they were tried at.
"What is still open" at the end of this file gives the summary.

Two checks run in CI over every theory, with
`contrib/ci/local-ci.sh proof-vacuity`:

- `contrib/ci/vacuity-check.py` fails the build if a lemma reasons about a fact
  no trace can ever observe. Such a lemma is true for no good reason.
- `contrib/ci/vacuity-probes.py` writes a reachability probe for every universal
  lemma, so we can always ask whether an open goal is worth proving at all. The
  generator has a `--self-test`.

## What these proofs do not show

Four limits. Read them before quoting any number above.

**The Rust code is not proved to match these models.** The theories model the
protocol as designed. Nobody has proved that `crates/kuipa-enroll` or `kuipad`
behaves the way a theory says. Some models were written to copy an
implementation detail — the device share key in `seal.rs`, the
`(iat, encoded bytes)` comparison in `AnchorState`, the scheduler's clock
arithmetic — and each header says so. That explains why a model is shaped that
way; it is not a proof that the two agree. Rust tests pin the implementation
down. Nothing here pins the two together.

**The theories do not compose.** Each proves its own claims over its own rules.
There is no proof from a client command through to a stored anchor. Some claims
were split across theories on purpose: one theory containing all the rules is too
big for the prover. Membership closes on its own and does not close when the
admission rules are present.

**The Z3 models are separate.** They carry their own numeric assumptions and are
not joined to the symbolic proofs.

**Crypto here is symbolic.** Signatures, MACs and KEMs are idealized, and the
attacker has the usual power to combine what it sees. Nothing here says how hard
a primitive is to break. Parsing, machine-value timestamps, GSS and TLS channel
binding, storage, and crash behaviour are all outside these models. Each one is
named as omitted in the theory that would otherwise need it.

## Running the prover

To bound Tamarin and Maude together:

```sh
systemd-run --user --scope -p MemoryMax=2G -p MemorySwapMax=0 \
  tamarin-prover --prove contrib/tamarin/peer-sync.spthy +RTS -N1 -RTS
```

`contrib/ci/proofs.sh` proves every lemma in a theory and prints a table with one
row per lemma. Each lemma runs in its own process, inside its own memory limit:

```sh
TAMARIN=… PATH=$MAUDE_DIR:$PATH ./contrib/ci/proofs.sh contrib/tamarin/peer-cache.spthy
```

Do not use batch mode as evidence. It prints `analysis incomplete` for lemmas it
was not asked to prove, and prints nothing at all when the process is killed. An
exit code of 124 (timeout) or 137 (memory limit) is not a proof and is not a
counterexample either.

Run one prover at a time. A memory limit applies per process, but free machine
memory does not, so a run that fits inside its own limit can still be killed. When
that happens, timings and verdicts stop repeating.

Keep scratch files and saved tables in `~/tmp/kuipa-tamarin`, never in `/tmp`.
`/tmp` is cleared between sessions, and a ledger is the evidence behind the theory
headers and this document. A full day of ledgers was lost that way.

## How to read a result

Four things make a result wrong in a way the prover will not tell you.

**`[reuse]` hides an assumption.** `[reuse]` puts a lemma's statement into every
later proof as a simplification source, whether or not that lemma was ever
proved. In per-lemma mode an earlier `[reuse]` lemma is never attempted in the
same process, so it is always just an assumption. A lemma can report `verified`
while standing on an open goal.

Three results here were like that, and are now reported as open with the marker
removed:

- `maximum_persists` stood on an open goal above it;
- two cache invariants were each proved only by assuming the other — each verified
  with the other written above it as a source, and both ran out of search with
  neither assumed. That pair is circular, so neither is a proof.

`validity_interval_origin` was suspected too, and is fine: proved with nothing
assumed, it verifies in 1300 s. It stays a `[reuse]` source, and the validity
provenance lemmas that use it keep their proofs. Removing the marker from a lemma
that *is* proved throws away real results, so only markers on unproved lemmas get
removed. Mark `[reuse]` only on lemmas that verified in the same run.
`contrib/ci/proofs.sh` prints a `note` line naming any open `[reuse]` source,
because every `ok` after it needs reading again. Treat a table with such a note as
conditional.

**An open lemma may be empty.** A universal lemma says nothing if no trace
satisfies its assumptions, and a proof that runs out of budget cannot tell you
whether that is the case. `contrib/ci/vacuity-check.py` catches one form of this:
a lemma about a fact that is observable at no point in any trace. The other form
is a lemma about real actions whose assumptions may still be unreachable, and
`contrib/ci/vacuity-probes.py` handles it by asking for the assumptions alone, with
the conclusion's ordering dropped:

```
"All r s old new #i #j. Rotated(r,s,old,new) @i & Compromised(r,s,old) @j ==> not (#i < #j)"
->
"Ex r s old new #i #j. Rotated(r,s,old,new) @i & Compromised(r,s,old) @j"
```

Reading a probe: `verified` means the assumptions are reachable, so the lemma is a
real obligation. `FALSE` means no trace satisfies them, so the lemma is true only
because it says nothing — report it that way instead of leaving it as an open
goal. `OPEN` means unknown: a probe that does not finish is no evidence of
emptiness, just as a failed proof is no evidence of a counterexample. Asking for
the assumptions *with* the ordering is a different and much harder search, so the
shorter form is the one that settles it.

Twelve of these probes now live in the theories as `Nonvac_*` lemmas (three
rotation, three membership, three admission-path, two cache, one kuipa), and all
twelve verify. So those open goals are known to be real obligations, and the
ledger re-checks that claim instead of trusting this sentence. Seven assumptions
are still unknown: three cache, two replacement, one ownership and one kuipa
probes run out of the limit.

`local-ci.sh proof-vacuity` only checks that a probe *can* be generated for every
universal lemma. Probing them is the expensive sweep, not CI. Because
`contrib/ci/proofs.sh` picks its per-theory settings from the file name, run a
probe from a scratch directory under its original name.

**Order is part of the result.** A `[reuse]` source has to appear above the lemma
that uses it, so a chain of lemmas closes only in an order where each follows its
sources. Do not reorder a theory file without re-running it.

**The shape of a statement matters more than the budget.** `refill_follows_restart`
stayed open at every limit because it talked about two `CacheStarted` actions and
never named the refill it was about. That leaves every interleaving of every pair
of starts in the search. Narrowed to one action in its assumptions, as
`refill_follows_prior_restart`, it verifies in 141 s under the same 8 GiB. When a
goal looks unfinishable, narrow the statement before raising the limit; the
headers in `peer-cache.spthy` show this worked.

## Core exchange, vouchers and user seals — `kuipa.spthy`

This theory models the enrollment protocol's core: pins and advertisement checks,
the ML-KEM join and rekey schedule, OTP and Kerberos authenticators, sealed-keytab
escrow, vouchers (blind issue, bound and bearer use), and user seals (the
two-share format and the unified recovery request). Prove it one lemma at a time
with `contrib/ci/proofs.sh`. That script has `kuipa` in its derivation-check list:
the derivation check takes longer than the five-second default and would abort
before any lemma ran.

Proved: OTP and join-key secrecy; that a join is authenticated by the server;
rekey forward secrecy; that a voucher is authenticated by its issuer; that a
seal's release follows its file's sealing; that a keytab sealed under an honest
server stays secret. The attacks the design predicts are reproduced — the matching
`Attack_*` lemma is refuted — for a mis-delivered enrollment string and a stolen
anchor (`Attack_RoguePinLearnsOtp`, `Attack_StolenAnchorLearnsOtp`, §13), a bearer
voucher (`Attack_UnboundVoucherIsBearer`, §9), an escrow key that yields the server
share (`Attack_EscrowKeyYieldsServerShare`, §7.6.10), and a stolen device key with
an observed unlock (`Attack_StolenDevicePlusReleaseOpensSeal`, §7.6.10). Those
witnesses are what show the secrecy lemmas are conditioned on an honest pin and an
uncompromised key, rather than saying nothing. `Attack_EscrowKeyOpensDisk` is
*proved* instead, and that is the correct outcome: a sealed DEK needs both shares
(§7.6), so the escrow key alone gives only the server share.

Two things in this theory were wrong before they were fixed. Both are worth
reading, because the same mistake appears in the peer theories.

**Facts that no trace can see.** Earlier lemmas about join-seed secrecy, escrow
reachability and release provenance were true for no good reason. They reasoned
about persistent facts — `!Server`, `!EscrowKey`, and so on — at a point in a
trace. A trace formula can only name *action* facts, and a fact that only ever
appears in a rule's premises and conclusions is never named at any point. So the
assumptions could not be met, and the lemma was true for nothing.

The rules now write an action for each such fact: `ServerRegistered`,
`JoinEncap`, `EscrowKeyRegistered`, `DeviceRegistered`, `FileSealed`,
`UserReleased`, `FileOpened`. The lemmas read those instead and are now actually
proved. `contrib/ci/vacuity-check.py` fails CI if a lemma like the old ones
comes back.

**A guard that excluded nothing.** One claim did not survive that rewrite: that a
sealed file's DEK needs the device key even when the escrow key is compromised.
It came out FALSE. It had only ever "verified" vacuously, for the reason above.

Seven different assumptions over `DeviceRegistered` were refuted by the same
trace. Then the rules were changed to add a pairing the model lacked: the sealing
rule now records which device public key it sealed a slot for, and the rules that
open or compromise that slot require it. That matches
`crates/kuipa-enroll/src/seal.rs`, which derives each device share's key as
`HKDF(s_j, "device", … ‖ id_j ‖ H(c_j))` and encrypts the answer to that device's
key. It still came out FALSE, with no explanation.

So the guard itself was examined, and that was the fault. `not(Ex #j. K(dseed) @j)`
talks about a *seed term*. This model defines compromise through the actions
`StolenDeviceKey(dpk)` and `StolenEscrowKey(eek)`, and those are what the rules
that reveal a share need. Checking each share under the seed guard showed the
guard excluded nothing: `a`, `b` and `r` are all reachable with it in place. So
the assumptions allowed traces where the very key whose slot the file sealed had
already been stolen.

Guarding the compromise action for the key this file sealed under makes the claim
verify — and it needs no escrow guard at all. With the escrow key stolen and
release answers observed, the DEK stays closed as long as this file's device key
was never stolen. That is the design sentence read literally, and it is what gives
the escrow row of §7.6.10 its meaning: the administrator's key yields one share,
not the DEK.

The claim is non-vacuous in both directions. `Attack_StolenDevicePlusReleaseOpensSeal`
is refuted, which means with the device key stolen the DEK *is* known. Two
explanations considered along the way were both wrong or untested: two
registrations sharing one `kem_pk` cannot happen in this model (the witness comes
out FALSE, so non-injectivity was not the cause), and the equation-only KEM
signature was never shown to matter — the probe that suggested it did had a
positive control that was itself refuted, so that comparison proved nothing.

The two companion DEK claims, refuted by the same guard error, now verify with the
same fix: `CopyAtRestNoReleaseNoDek` with the escrow key free to be stolen, and
`CopyAtRestNoFactorsNoDek` with neither stolen.

**What §7.6.1 gets from this.** A chain of provenance: a sealed file's DEK is
released only after the server released a binding its owner asked for through a
registered device. That is `OpeningNeedsRelease`, `ReleaseNeedsOwnerRequest`, and
their composition `CopyAtRestNeedsOwnerFactor`, all proved. Next to it is
`SealNeedsDeviceKey`, the confidentiality bound. The first says which actions must
have happened for a copy to open; the second says what stays closed while the
device key is not stolen.

**Four lemmas are open**, not refuted: `Exec`, `KeytabSecret`, `VoucherSingleUse`,
`BoundVoucherKeytabSecret`. They stay open at 6 GiB with 300 s, 420 s and 700 s
per lemma, and the same four time out at the same settings in the unmodified
theory — so that cost was already there and is not a regression from the
instrumentation. Two of them close on time alone: at 8 GiB and 1300 s, `Exec` and
`BoundVoucherKeytabSecret` verify. That leaves `KeytabSecret` (exit 124, search
still running) and `VoucherSingleUse` (exit 137, memory ceiling).
`SealedNoOffline` and `VoucherExec` fail at 300 s and verify at 700 s, so the
settings a run used are part of its result. The header lists every abstraction.

## Trust establishment and signing — `trust.spthy`, `sign.spthy`

`trust.spthy` models trust establishment between realms on its own: the §17.4
invitation, the request and response exchange, the trust secret both realms derive,
and the cross-realm tickets. Prove it lemma by lemma with `contrib/ci/proofs.sh`;
the script gives this theory a longer derivation-check timeout.

Proved: agreement, responder authentication, and trust-secret secrecy. The attacks
§17.4 "Limits" predicts are reproduced: `Attack_RogueInviteLeaksTrustSecret` and
`Attack_LeakedTrustSecretForgesTickets` are refuted, so the traces the design warns
about do exist.

Responder authentication and the accepted-ticket source used to be stated over
`!Realm`, `!TrustAdv` and `!TrustEstablishedB` at a point in a trace. None of
those is an action fact, so both lemmas were vacuous. The rules now record the
same facts as actions — `RealmRegistered`, `TrustAdvVerified`,
`TrustEstablishedBRecorded` — at the steps that create or read them, and both
claims are proved over those actions with the same quantifiers and the same
witnesses.

`sign.spthy` models signing statements: the policy check, the signed statement with
its log leaf, and offline verification of a bundle against the pinned realm.
Proved: authorization, that the signer is vouched for by a delegation, batch
binding, the refusal when no policy applies, and `Attack_RogueAnchorSignsAnything`
— a realm that is not registered anywhere cannot be verified as one. The "not a
server that cannot lie" attack is reproduced: `Attack_MisPinnedVerifierAcceptsRogue`
is refuted, so a verifier that pinned the wrong anchor does accept a rogue realm's
statement. The same
`RealmRegistered` fix applies here: `Attack_RogueAnchorSignsAnything` had reported
"verified" vacuously, and the fix is what makes that verdict real.

## The peer-sync abstraction — `peer-sync.spthy`

`peer-sync.spthy` models one theory's worth of the peer-sync protocol from
DESIGN §4.2.1: that a response matches a request, that context is addressed by
hash, that a restart re-sends what it lost, and an abstract signed-entry
snapshot. It finds a trace where a request is forged after the channel is
compromised.

GSS, HTTPS and signature verification are idealized. The full admission policy,
cache eviction, snapshot chunking and convergence are not proved. The header says
what is left out.

## Peer-sync theories

The theories below each take one thing the earlier models had to idealize and model it
on its own. A theory header gives its exact assumptions and results; this section says
what each theory is for and what it does not cover.

`peer-binding.spthy` makes a request bound to a signature under the member
credential rather than to Kerberos itself. Hashes are collision-free symbolic
functions. The attacker controls network messages and may replay or change every
field.

`peer-attestation.spthy` models membership and delegation attestation at
enrollment. Anchored delegation proofs are signatures by their own anchor, which
may be attacker-chosen. Validity and policy are idealized, and there is no claim
log. One enrollment gets one attestation.

`peer-response.spthy` binds a response to the request nonce it answers. The
authenticated request is an idealized fact; TLS itself and confidentiality are not
modelled. Outstanding nonces are linear.

`peer-snapshot.spthy` models a snapshot as exactly two chunks with an authenticated
initial digest. Bytes, lengths, upload, arbitrary chunk counts and concurrency
limits are not modelled. Network chunks are attacker-delivered.

`peer-order.spthy` models two versions ordered by the application's merge order.
Ties, arbitrary version counts, message authentication and garbage collection are
not modelled. Delivery is adversarial, so an older message may arrive after a newer
one. Ordering does not prove that the two sides ever converge.

`peer-admission.spthy` covers admitting a claim with a vouch, and a trust bridge
pinned to a root. The claim and public key are attacker-controlled: putting them
into replicated state does not make them trusted. A vouch is accepted only if its
signature verifies, and one vouch covers one claim.

`peer-pin-delivery.spthy` separates two cases: an enrollment string issued for a
local anchor and delivered over an authenticated out-of-band channel, and an
attacker-controlled string.

Proved: an acceptance on the authenticated path traces back to issuance and to an
honest signature or a compromised anchor. A witness,
`untrusted_delivery_accepts_attacker_anchor`, shows the other case: accepting an
attacker-controlled string can pin the attacker's anchor. The first case assumes
delivery is authenticated. Expiry, head pins, deployment checks, membership, trust
propagation and succession are all left out, and this theory is not connected to
the others.

`peer-admission-checks.spthy` adds three admission checks: validity intervals,
membership removal, and a static allowlist of signature algorithms.

Proved: entry witnesses, membership provenance, that keys with a denied tag are
rejected, vouch and succession witnesses, that a server's own vouch is rejected,
that signatures come from honest anchors, and that validity intervals have a
provenance and do expire — for claims, vouches and successions. A compromised own
key can produce a vouch that passes the checks but still cannot be admitted. A
stolen remote anchor key can forge a vouch or a succession that was admitted.

Not proved: issuance authorization, because honest anchors sign whatever the
attacker asks for. Each server identity is assumed to belong to one realm, and two
realms may both admit claims.

Three lemmas are open: that an admitted claim's membership is live
(`admitted_claim_has_membership`), that an admitted server belongs to one realm
(`admitted_server_has_one_realm`), and that an admitted claim after a removal
follows a rejoin (`removed_member_requires_rejoin`). They stay open at 40 GiB and
600 s; none is refuted and no counterexample is known. A fourth,
`claim_admission_has_prior_join`, was open at every setting and now verifies: the
missing piece was `[use_induction]`, which makes the induction run over the
admission token instead of the whole trace. Two of the three open ones already had
that attribute; adding it to the third, in a scratch copy, changed nothing at
8 GiB and 700 s. So the attribute is not a general fix — it works when the lemma
is about a token the rules move.

The membership lifecycle (generation separation, removal safety, rejoin
provenance) is modelled separately in `peer-membership.spthy`, where it does not
depend on any admission rule. It has to be separate: with the admission rules
present as proof sources, the same searches exceed the memory limit. Those
lifecycle lemmas close in `peer-membership.spthy` and do not transfer here,
because these three are about admission itself.

Validity here is symbolic, not timestamp arithmetic and not clock skew. Expiry
properties apply to an interval identifier from an oracle, not permanently to an
entry: the proved witnesses re-admit the same claim, and an honestly signed vouch
and an honestly signed succession, after the first interval ends and a new one
starts. That can stand for clock rollback, but it does not constrain it. Algorithm
tags stand for real algorithms and JWK parsing. Policy changes, replacement,
retention and trust are not modelled.

### Validity arithmetic — `peer-validity.smt2`, `peer-validity-multi.smt2

Tamarin cannot do `u64` arithmetic, so these models do it directly.

`peer-validity.smt2` models the validity and period checks in `delegation.rs`:
saturating arithmetic and the 300-second skew. Six SMT-LIB queries cover the
expanded interval and duration boundaries, monotonic-clock behaviour, and a one-entry
scheduler that maps each real validity change to an abstract start, end or unchanged
interval. That scheduler allows clock rollback and assumes the entry is available and
a fresh interval id can be allocated. A seventh query shows that rollback restores
validity. Run it with `z3 -smt2 contrib/tamarin/peer-validity.smt2`: expect six
`unsat` and then `sat`. The mapping from scheduler to Tamarin is not machine-checked,
and the arithmetic model is not extracted automatically from the Rust code. A Rust
test does pin the constants this model hardcodes.

`peer-validity-multi.smt2` extends the scheduler to many entries, each with its own
issue and expiry times. Its four queries show that updating an entry matches the
real bitvector validity check, leaves other entries alone, commutes with other
updates, and is idempotent. All four must return `unsat`. Interval identifiers,
delivery, and the connection to Tamarin facts and to Rust remain assumptions.

### Policy selection at admission — `peer-policy.spthy

`peer-policy.spthy` models choosing a policy per admission. A strict and a relaxed
policy share one symbolic algorithm, and only the relaxed one allows another.

Proved: keys, vouches and successions using the second algorithm are rejected under
the strict policy; relaxed admission works; and a key admitted under one policy can
be reused under another. Policy provisioning, JWK parsing, real algorithms,
validity and membership are not modelled. There is a matching Rust test that admits
ML-DSA-65 keys, vouches and successions under a permissive policy and under an
ML-DSA-87-only policy, and rejects malformed JWK input. That test is not a proof of
parser or cryptographic correctness.

### The trust bridge — `peer-trust.spthy

`peer-trust.spthy` joins symbolic keys, member claims and signed vouches to
root-based trust propagation, static anchor ownership, and client verification.

Proved: every accepted client's pin traces either to a trust root or to an
admitted claim and vouch with an admitted key; an anchor cannot be trusted for two
servers in one realm. That provenance is about the pin, not necessarily about the
accepted claim. For a root pin, one-hop acceptance has first-succession origin
unless that root was compromised. Every succession followed from a modelled root
has issuance or compromise provenance, at later hops too. Acceptance at each of one
through four hops has the matching ordered follow events. A three-hop witness uses
four distinct uncompromised roots; a four-hop witness records no compromise but
allows cycles and attacker-chosen successors. A modelled root's advertisement
signer likewise has issuance or compromise provenance.

Initial pins come from issued enrollment strings; an authenticated refresh may
supply a computed trusted anchor. One witness follows an admitted claim and its vouch
key through propagation, a pinned refresh and a succession, to an advertisement
accepting that same claim. Both delivery channels are assumed authentic, and
refresh stands in for the real response and its verification. An unanchored member
can be a root, or can become trusted through another server's anchor. Honest roots
sign any claim or succession asked for. Key parsing, algorithm policy, validity,
ownership release and replacement are left out, and anchored and unanchored claims
for one server may both exist. This is not a complete proof of trust security.

One assumption matters a lot: a proved witness shows an attacker-chosen successor
being accepted with no recorded root compromise. That is a limit of the model, not
an attack on the implementation — `KeyStore::rotate_anchor` generates the successor
locally.

### Key rotation — `peer-rotation.spthy` and its two variants

`peer-rotation.spthy` models generating a fresh successor key and removing the old
one from a linear active-key state.

Proved: fresh keys are unique; honest rotation rejects one specific public attacker
key; active keys have provenance; successions have an origin; an attacker-chosen
successor requires a compromise; an `ActiveKey` action observes the key it names;
plus honest-rotation and stolen-key forgery witnesses.

The old claim that a retired key is never active again rested on the rule's
`Retired` fact, which is not an action fact and so is observable at no point. That
lemma was vacuous. Stated over the `Rotated` action and an `ActiveObs` observation,
both the observation-level form and the action-level consequence stay open at
8 GiB and 300 s, and neither is refuted: a lemma that had verified while the first
was marked `[reuse]` did not verify without it, so the earlier "verified" was
conditional on an open goal. One further property is open at 40 GiB: that after a
rotation, the retired key is never later the subject of a compromise.

None of the three is vacuous. Their assumptions are satisfiable, and the theory
asserts that itself as `Nonvac_rotated_key_never_active_again`,
`Nonvac_retired_key_not_active` and `Nonvac_retired_anchor_not_compromised`, which
verify in seconds. `contrib/ci/vacuity-probes.py` generated them. Note that asking
for the assumptions *together with* the ordering is a different, much harder
search: the same witnesses do not finish at 8 GiB. That is why reachability is
probed on the assumptions alone. All three are real obligations whose proofs are
open, not empty statements.

Crash recovery, backups, concurrent writers and physical erasure are left out, and
this theory is not yet connected to the trust theory.

`peer-rotation-origin.spthy` asks only where a signature came from, in an
over-approximation that generates keys independently, never retires them, and lets
them be reused.

Proved: an accepted succession under a generated anchor came from its rotation
signer or from an earlier compromise; and accepting a key produced by the
attacker-key rule needs an earlier compromise of the old anchor. Honest-rotation and
post-compromise forgery witnesses verify. This does not cover every way an attacker
could learn a generated key, and its agreement with the linear rotation model and
with the implementation is not proved.

`peer-rotation-client.spthy` connects that independently-generated-key view to
authenticated initial pin delivery and to client verification over one to four hops.

Proved: one-hop succession and honest-signer origin; and accepting a final key from
the attacker-key rule needs the pin, or an intermediate key before the matching
follow event, to have been compromised. Witnesses cover honest rotations, a
compromised pin, a stolen final signer, and an intermediate compromise that leads to
an attacker-generated final successor without compromising the pin. Keys stay
reusable, honest signers accept any claim, and validity, policy, membership, trust
propagation and other ways to get a successor key are left out. This is not a
complete client proof.

### Membership state — `peer-membership.spthy

`peer-membership.spthy` isolates the membership-generation lifecycle: one linear
`MState` token carrying the current or the last generation, moved by join, rejoin
and remove. It uses the same `MembershipStarted`, `MembershipEnded`, `Joined` and
`Removed` actions and the same structural restrictions as
`peer-admission-checks.spthy`.

Two modelling choices matter. Remove must not also name the generation that is
current at that step: doing so makes "a current generation was never ended earlier"
false and forces extra conditions into every later statement about currentness. And
two lemmas here were vacuous because they reasoned over `MState(...) @ t`, a fact
observable at no point; they are gone, as are two that named a `MembershipCurrent`
action no rule in this theory emits — reading current membership belongs to
`peer-admission-checks.spthy`, where that action does exist. The rules now emit
`MStateObs(realm, server, state)` for the state each step consumes and the state it
leaves. That is what makes state visible; premises, conclusions and reachable
states are unchanged.

Proved over those observations: that a `MembershipStarted` action observes the
member state it creates, which is the induction subject the closure goals need; the
state carried at an admission step (a first join carries `'initial'`, a rejoin
carries the retired generation it replaces); that a member state is never observed
after that generation ended; that two started generations for one server are
different; that a generation ends at most once; that a rejoin follows a removal and
changes the generation; that a rejoin is reachable; and that all three states really
are observed — which is what turns the invariants into guarantees rather than empty
statements.

Three forms of the closing property stay open, and none is refuted: the general one
over observations (every generation started before an observed state has ended by
that point, unless that state carries it) — an earlier version of that claim only
looked proved because the state fact it named was invisible; and the two that ask
*which earlier step* ended a prior generation, from the `MembershipInactive` action
(`inactive_membership_closes_prior_generations`) and for the generation a rejoin
replaces (`rejoin_closes_prior_generations`). The rejoin form verifies in 3 steps,
but only while the first is marked `[reuse]` and so assumed while still unproved.
That is a conditional result standing on an open goal, not a proof; proved on its
own, or with only proved lemmas available, it does not finish at 8, 16, 24 or
40 GiB.

Admission, validity intervals, realms, signatures and policies are left out here.
Adding them is exactly what makes the matching searches in
`peer-admission-checks.spthy` exceed the memory limit. The claim-admission path is
deliberately absent from this theory, where it would not verify either.

### Ownership and release — `peer-ownership.spthy`, `peer-ownership.smt2

`peer-ownership.spthy` isolates claim replacement and anchor release for two
servers and one anchor, where a single owner slot decides which claim is anchored.

Proved witnesses: replacement by the same owner, and a release followed by another
server's claim. Every ownership observation and every release traces back to an
earlier claim, both by induction over a persistent owner-active fact.

Open: that observing two different owners requires a release between those
observations. It verified in 14 steps in one configuration and did not finish in any
isolated run at 8, 16 or 40 GiB, or up to 900 s. So the earlier result came from
proof order, not from the model. Two claim-level helper lemmas that made it close in
that configuration are false as stated — an owner may claim, release and claim again
— and were removed. A `[reuse]`d lemma is available as an assumption whether or not
it has been proved, so a false one can support a conclusion about the traces it does
not rule out.

Ordering of newer claims, further anchors, membership and trust propagation are
abstracted or left out.

`peer-ownership.smt2` proves a release-before-owner-change property by induction for
one anchor and two servers, using a monitor that remembers the last observed owner
and whether it released the anchor. Its three queries must all return `unsat`.
`peer-ownership-two.smt2` extends the same monitor to two anchors whose claims,
releases and observations interleave; its four queries must also return `unsat`.
These finite-state models ignore claim validation and are not refinements of the
Tamarin theory or of the Rust code.

### Pin and vouch verification — `peer-succession.spthy

`peer-succession.spthy` models pin and vouch checks over up to four succession
hops. It proves that the first link has an origin; it does not prove that issuance
was authorized. Cycles are over-approximated, and validity and algorithm policy are
left out. The pin is assumed, not connected to `peer-trust.spthy`.

### Retention, pruning and cascade bounds — `peer-retention.spthy`, `peer-pruning.*

`peer-retention.spthy` explores one claim: its membership, validity, grace period,
and symbolic vouch coverage.

Proved: intervals have unique origins and ends; an end has a provenance; intervals
do not overlap; coverage runs uninterrupted from the start of the active interval;
coverage past grace; and rejection after expiry or membership removal. A detailed
grace/vouch witness also verifies. These stronger properties imply the weaker
coverage and grace/vouch obligations asked for earlier. Re-admission, replacement,
other claims, and vouch or key pruning are not modelled.

`peer-pruning.spthy` models two claims and one anchor's vouch and key; each claim
may name that anchor or not.

Proved: a retained vouch was named before the claims were pruned; a retained claim
was present. Witnesses cover keeping both claims, a replacement followed by claim
pruning, an orphaned vouch and key being pruned on the next pass, and a vouch
temporarily keeping alive a claim that does not name its anchor after the last claim
that does name it is removed.

Open: one witness, that replacing a vouch can remove the coverage a claim depended
on (`replacement_can_remove_coverage`). It stays unproved at 8, 16 and 40 GiB and up
to 600 s. It is a fixed two-claim witness, so this is a search limit and not a
limit of what the theory can express — `peer-pruning-multi.smt2` below shows a
cascade no two-claim theory could show at all. Running this theory needs
`--derivcheck-timeout`: its derivation check exceeds Tamarin's five-second default,
and without the flag the run stops before any lemma is attempted, which is easy to
mistake for a failed proof. There is also a Rust test that exercises orphan pruning.

Membership, validity and signature checks are assumed to pass. Grace is an oracle
asked once per pass. Coverage is fixed until replacement, and a replacement is
assumed newer and valid. Other vouches and keys, timestamp ordering and Merkle
proofs are left out.

`peer-pruning-chain.smt2` models a chain of any length in which claim `i` names
anchor `i`, and that anchor's vouch covers claim `i + 1`. Everything starts valid,
there is no grace, and no new entries arrive. Four arithmetic induction checks show
that removing the uncovered first claim can move one claim per pass, and that the
matching vouch and key survive one pass longer. A final query shows the delayed
pruning actually happens. Expect four `unsat` and then `sat`.

A pass here stands for one repeated call to `AnchorState::retain`, which drops
entries in the order that function does: invalid entries, then vouches whose anchor
no surviving claim names, then claims no surviving vouch covers, then keys no
surviving entry refers to. One call is one pass, and the unbounded cascade needs
several, so this model also stands in for the schedule. Coverage, signature checks
and agreement with Rust are assumed, not proved.

`peer-pruning-multi.smt2` models two interacting chains as bitmaps of surviving
entries rather than one chain at a time, and advances both every pass. Each chain's
claim at index 0 has no vouch inside its own chain, so it survives only if the other
chain's surviving vouch at index 0 covers it. With that edge off, chain A's claim at
index 0 is gone by pass 2. With it on, the claim is still there at pass 6, both
bitmaps stop changing, and they are pinned to exactly claims 0 and 1 with vouch 0 in
each chain. So whether one chain drains depends on the other chain's entries — which
no per-entry or per-chain argument captures on its own. Expect `unsat`, `sat`, then
two more `unsat`. The key stage is a separate filter over key entries and is not
modelled. Entry identity, membership, validity, signature checks, grace and
refinement to Rust are assumed, not proved.

### Replica convergence — `peer-replacement.spthy`, `peer-replacement.smt2

`peer-replacement.spthy` isolates two replicas that receive three ordered versions
of one vouch or succession.

Proved: one receipt cannot replace the maximum; and two different delivery orders
converge. Which version a replica held used to be reasoned about through the
`Replica` fact, which is not an action fact and so is observable at no point — both
lemmas over it were vacuous. The `receive` rule now emits `ReplicaObs` for the
version it consumes and the one it leaves. Neither persistence claim over those
observations is proved: `after_maximum_holds_maximum` is open at every limit tried,
and `maximum_persists` reported verified only because it consumed the first as a
`[reuse]` source while that was still unproved — with the marker removed and nothing
assumed, it runs out of search too. Both are open, and neither is refuted. Their
shape matches the open cache goals: the claim is about a chain of observations, and
the induction needed is over the step between two neighbouring observations, which
neither statement names. The total order stands in for `(iat, encoded bytes)`;
admission, pruning, real byte comparison and eventual message delivery are not
modelled.

`peer-replacement.smt2` models `EntryVersion::replaces` directly: a stored entry is
replaced when the incoming hash differs and its order is not lower. Its queries show
that a lower `iat` never replaces, that the stored `iat` never decreases, and that
two delivery orders converge and pick the highest `iat` once the `iat`s differ.
Expect four `unsat` with one `sat` among them: that query shows a same-`iat` version
replacing the stored entry, so with equal `iat`s the stored entry is not stable —
only its `iat` is. The model uses a 64-bit order-preserving rank in place of encoded
bytes. It does not prove that the rank matches Rust's byte comparison, and it does
not connect to the Tamarin or implementation models.

### Cache incarnations — `peer-cache.spthy

`peer-cache.spthy` models one receiver's per-sender cache across initialize,
replace, restart, refill, cached and miss. State for one pair is a single linear
token with a fixed head, whose status argument is `held` or `empty` and which names
the incarnation whose content it holds; the cached pair is a separate linear fact.
Two rules are restricted on purpose: restart must not emit an action naming the
incarnation it just made non-current, and refill must not record the incarnation the
cache stops being empty with. Each of those *is* the step where that state stops
holding, so either action would contradict the invariants below.

This theory is where the "facts no trace can see" rule was worked out, so it is
worth stating once here. Tamarin defines a trace as the sequence of action facts a
run appends, and a trace property as a formula over action facts and timepoints. So
a fact that appears only in a rule's premises and conclusions is observable at **no**
index. Measured on two-rule theories, for a linear fact and for a persistent fact no
rule consumes: not at the step that creates it, not at the step that consumes it, not
at any unrelated step. Every earlier lemma here over `Slot(s,r,st,inc) @t` or
`Content(s,r,d,e) @t` was therefore vacuously true, and the claim this file used to
make — that such a fact is "observable strictly between the steps that create and
consume it" — was simply wrong. There is no such window. The rules now emit
`SlotObs(sender, receiver, 'held'|'empty', incarnation)` for the state each step
consumes and, where it changes, the state it leaves. Premises, conclusions and `Out`
are untouched, so the transition system and the attacker's knowledge do not change;
the state just becomes visible, and the invariants are stated over the observations.

Proved: every cache action happens at a step that observes the state it names (the
`current`/`empty`/`ended`/`started`/`resolved` bridges, 3–9 steps); those observations
occur at all, including a held one followed later by an empty one, plus reachability
witnesses for a cached resolution and for restart then miss; a start for one pair is
unique; every held observation traces to a start at or before that step, which is how
"an end action traces to an earlier start" was finally closed — open in every earlier
formulation, and closed by composing those two; a current action traces to an earlier
start; a request that found the cache empty records an incarnation that ended earlier;
an end is observed holding and is followed at its own step by empty; every resolution
traces to an earlier delivery; and a refill follows the restart that emptied the slot.

Six statements do not close, and none is refuted: no incarnation observed empty is
observed holding it later, and the same question asked over end actions instead of
empty observations; no action names an incarnation current after an end or an empty
observation of it; no current action precedes that incarnation's end; a resolution
after a restart that was preceded by a delivery; and the reachability witness for
restart → refill → resolution (its restart → refill half verifies alone, its
refill → resolution half does not). All six are exit 137 — the memory ceiling — not
timeouts, so more time does not help. The first two were previously reported
verified only because each was written above the other as a `[reuse]` source and so
assumed by the other's proof; with neither assumed, both run out of search, which is
what makes that pair circular rather than proved. The middle two were reported
verified only because they consumed the first as a source.

One statement that had been open in every earlier formulation closed by being
restated, not by raising limits: the refill provenance claim written over *two
starts* (`refill_follows_restart`) never named the refill step, so the search had to
consider every pair of starts in every interleaving. Named for the one action it is
about, it verifies in 141 seconds where the other form used up 8 GiB at 700.

Because `[reuse]` lets a lemma use only the sources written above it, file order is
part of a result here. Each theory's order is chosen so chain lemmas follow their
sources; do not reorder without re-running.

Earlier versions of this file left five action-level claims open and called them
unbridgeable. One of them — an end action tracing to an earlier start — is now
proved, by composing the end observation with the held-observation provenance lemma.
That is the actual payoff of the instrumentation. The rest of the old
fact-level plumbing (`cache_and_empty_conflict`, `cache_fact_not_ended_before`,
`empty_fact_has_prior_restart`, `no_end_while_held`) is gone: those goals were
written over facts no trace can see, and the two of their claims that are true are
the directional statements above. Note that "a slot never reports both states at
once", read over the observations, is FALSE, and correctly: `restart` observes held
and empty for one incarnation at the single step where held becomes empty.

Tried, and not enough: raising the limit to 40 GiB; `heuristic=` options; a
`sources` lemma; bounding the replacement step; extra provenance facts; a state fact
carrying content and incarnation together; and removing `use_induction` so the prover
uses simplification instead. Proof search here repeats only for a fixed set of
attributes: Tamarin applies `[reuse]` to every lemma written after it, so moving or
removing one annotation changes which assumptions the rest of the file can use, and an
unproved lemma is offered as an assumption just like a proved one. With four unproved
invariants marked `[reuse]`, three witnesses and a basic origin lemma did not finish;
dropping the attribute made all six verify in under a minute. Elsewhere, dropping it
from an unproved lemma cost other lemmas that had finished. Order the file so proved
helpers come first, use `hide_lemma=` when a proved source is itself too expensive,
and treat the set of annotations as part of the proof. Proof skeletons do parse in
1.12.0, but not the way the surrounding prose suggests: a skeleton is a bare method
chain after the formula (`simplify`, `solve( Fact( args ) @ #t )`, `case rule`,
`SOLVED`, `qed`), and `by` is only a complete standalone suffix — which is why
`by sorry` parses and `by solve( ... )` does not. Forcing the action → rule case
split that way was tried on two of the open goals and did not close them. Membership
changes, expiry, and any connection to the admission and trust theories are outside
this model.

## Epoch log start, spent vouchers and the custody broker

Three theories follow the changes made after a security review and a real replica
deployment. They were run on their own, 2026-11-13, Tamarin 1.12.0 with Maude 3.5.1,
`contrib/ci/proofs.sh` at 200-250 s per lemma inside an 8 GiB cgroup; the whole-tree
table above predates them and does not count them.

| Theory | proved | refuted | what the refuted lemmas are |
|---|---|---|---|
| `peer-epoch.spthy` | 4 | 2 | the gate with early delivery of a peer's claim; the gate with a replica installed before the master minted |
| `peer-voucher-spent.spthy` | 5 | 1 | the record kept on the host entry |
| `peer-custody.spthy` | 8 | 2 | no replay cache; the previous broker that trusted the daemon |

The refuted lemmas are controls, like the `Attack_*` ones: each drops one
mechanism and the prover finds the trace the mechanism prevents.

**`peer-epoch.spthy`.** Two servers each mint entry 1 of the anchor epoch log, with
the set of anchors they trust. Before the change, a server minted at once, so the
replica's `{R}` met the master's `{L}` and the logs forked
(`previous_code_forks`). The gate mints only when membership is known and the
trusted anchors cover every member. `first_entry_agrees` proves that all first
entries agree, but only with two assumptions the model makes and the code does not
enforce: a sync that teaches a server a peer's anchor also carries that peer's
log, and a replica is installed after the master minted. The two falsified lemmas
are the traces without them. The Rust change does not close those races; it makes
them narrow.

**`peer-voucher-spent.spthy`.** Isolates the spent-salt record. With the record on
the host entry, deleting the host frees the salt and a voucher inside its window
enrols a second host. With one record per salt, deleting the host removes the host
only, and a record is purged only after the voucher's window closed
(`purge_only_after_expiry`). The signature and key exchange stay in `kuipa.spthy`.
It does not cover concurrent writes to one record, and the directory side was not
run against a real 389-ds.

**`peer-custody.spthy`.** The attacker is the network and the daemon. A token is
bound to the name asked for and to a key only the host holds; the broker accepts
host-class principals only and a nonce once. Proved: a release names a request the
principal made, for that name; each request is answered once; an administrator's
ticket is never answered; a custody secret is known only if a host-class key was
stolen. Kerberos, GSS wrap and handler policy are abstracted: the model says
nothing about how gssproxy implements the replay cache or about the socket's
permissions.

## What is still open

Twenty-three lemmas are open at 8 GiB and 700 s per lemma.

Nineteen are in the peer theories and every one is exit 137 — the memory ceiling,
not a timeout — so more time does not help. They all have the same shape: a claim
about a chain of observations where the induction step is the gap between two
neighbouring observations, and no statement in these theories names that step. A
disjunctive antecedent is unguarded, and a conjunction of two lemma bodies does not
parse.

The four in `kuipa.spthy` are budget problems: `Exec` and `BoundVoucherKeytabSecret`
verify at a 1300 s budget; `KeytabSecret` and `VoucherSingleUse` do not finish even
there. Each one is named, with the settings it was tried at, in its own header.

Twelve open peer goals have a proved `Nonvac_*` lemma next to them, so their
assumptions are known satisfiable — real obligations, not empty statements. For
seven, the reachability probe itself runs out of search, so their status is unknown,
which is not evidence of emptiness. Each header says which kind its open goals are.
