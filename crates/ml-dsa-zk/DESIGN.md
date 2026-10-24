# ml-dsa-zk: design

## 1. Goal

`ml-dsa-blind` gives counted, message-hiding blind signatures from an
unmodified ML-DSA signer, but the signer can link every signature to its
request (`crates/ml-dsa-blind/DESIGN.md` §2.1). Its §6 names the way to
unlinkability that leaves the signer alone. The requester keeps `σ` and
the salt secret and publishes instead a zero-knowledge proof of
knowledge of `(salt, σ)` such that `Verify(pk, salt ‖ m, σ)` holds.
Baum and Beckmann build such a proof over unmodified ML-DSA with VOLE in
the head, at about 1 MB (ePrint 2026/2473).

This crate is that road's first stretch:
- a VOLE-in-the-head proof core (FAEST-style, λ = 128 or 256) for
  **boolean circuits**;
- a Keccak-f\[1600\] gadget for the hashing ML-DSA verification does.

Everything cryptographic comes from OpenSSL, and only from CNSA 2.0's
general-purpose algorithms: AES-256-CTR as the PRG, and SHA-512 for
commitments, digests and the transcript. The code is safe Rust.

CNSA 2.0 does not approve SHA-3 or SHAKE as general-purpose hashes. It
allows them only where an approved algorithm prescribes them (CNSA 2.0
FAQ), so the proof never hashes with them. The Keccak-f gadget is
different: it *evaluates* ML-DSA's own SHAKE as part of the statement,
which FIPS 204 prescribes.

**The level follows the crypto policy.** The soundness parameter λ is
chosen the way the rest of kuipa chooses its ML-DSA parameter set and
hash (`docs/DESIGN.md` §4.1.1), from the system crypto policy:

| policy | `Level` | field | trees | Keccak-f preimage proof |
|---|---|---|---|---|
| allows ML-DSA-44 or ML-DSA-65 | `L128` (NIST category 1) | GF(2¹²⁸), `x¹²⁸ + x⁷ + x² + x + 1` | 16 | 85,814 B |
| allows only ML-DSA-87 (CNSA 2.0) | `L256` (category 5) | GF(2²⁵⁶), `x²⁵⁶ + x¹⁰ + x⁵ + x² + 1` | 32 | 172,486 B |

`prove` proves at the policy's level, and `verify` refuses a proof below
it (`Error::Weak`), so a CNSA verifier never accepts a λ = 128 proof,
however valid. A stronger proof satisfies a weaker policy. `prove_at`
and `verify_at` name a level explicitly. The level is the byte after
the magic, and the transcript absorbs it first, so a proof cannot be
relabelled. GF(2²⁵⁶) uses FAEST-256's modulus, and its unit tests check
that it is irreducible (Rabin's test). Seeds (32 bytes), the salt and
SHA-512 commitments already suit λ = 256, so only the field, the number
of trees and the mask lengths change.

**Research prototype. Not reviewed.**

## 2. The protocol

Parameters: τ = λ/8 trees of depth 8 (256 leaves each), so Δ has
τ × 8 = λ bits: 16 trees at λ = 128, 32 at λ = 256. `L = ℓ + 2λ`, where
ℓ is the witness bits (inputs and AND outputs), followed by λ
QuickSilver mask bits and λ VOLE-check mask bits. The description below
writes λ = 128, as GF(2¹²⁸) and 128 columns. At λ = 256, read GF(2²⁵⁶)
and 256 columns.

1. **Trees.** For each tree, a root seed is derived from a secret
   master seed. It is expanded as a GGM tree, each node's two 32-byte
   children being AES-256-CTR of the node. Each leaf `x` is committed as
   `com = SHA-512("leaf" ‖ salt ‖ i ‖ x ‖ seed)` and expanded to `L`
   bits `rₓ`. Tree `i` gives `uᵢ = ⊕ₓ rₓ`, and columns `b = 0..7` given
   by `⊕_{x : bitᵦ(x)} rₓ`. The prover sends `h_com`, the digest of all
   commitments, and the corrections `cᵢ = u₀ ⊕ uᵢ` for `i ≥ 1`. Row `j`
   of the 128 columns is `vⱼ ∈ GF(2¹²⁸)`.
2. **VOLE check.** χ is the first challenge. The hash is GF(2)-linear in
   its input bits: `H(z) = Σ_{j<ℓ+128} zⱼ·χ^{j+1} + Σ_t z_{ℓ+128+t}·xᵗ`.
   Its last term is a uniform mask, so `H(u)` says nothing about the
   witness. The prover sends `ũ = H(u)` and `h_V`, the digest of
   `H(column)` for every column.
3. **Witness.** `d = w ⊕ u[0..ℓ)`.
4. **QuickSilver.** η is the second challenge. MACs follow the gates:
   - XOR adds;
   - NOT keeps the prover's MAC and adds Δ on the verifier's side;
   - each AND output is a committed witness bit.
   
   For an AND `(a, b, c)`, the verifier's `K_a·K_b + K_c·Δ` equals
   `A₀ + A₁·Δ` with no Δ² term exactly when `c = a·b`. For a public
   output `o = y`, `(K_o + y·Δ)·Δ` contributes to `A₁` alone. The
   constraints are combined with powers of η and masked by the 128
   QuickSilver mask bits as one GF(2¹²⁸) pair, and the prover sends
   `(A₀, A₁)`.
5. **Δ** is the last challenge, 16 bytes, one per tree: `Δᵢ` is the
   hidden leaf of tree `i`. The prover opens each tree's co-path to
   `Δᵢ` (8 seeds) and the hidden leaf's commitment.

The verifier then:
1. rebuilds every leaf but the hidden ones;
2. checks `h_com`;
3. computes the columns of Q from the leaves at `x ⊕ Δᵢ` plus the
   corrections, so that `qⱼ = vⱼ + uⱼ·Δ`;
4. checks each column's hash: `H(Q_col) = H(V_col) + ũ·Δ_col`, digested
   against `h_V`;
5. checks QuickSilver with `K_j = q_j + d_j·Δ`.

Challenges come from one SHA-512 transcript. It absorbs the circuit's
digest, the public outputs, the salt and every prover message in order,
length-prefixed and labelled. A challenge is the counter mode
`SHA-512(state ‖ label ‖ i)` over a copy of the state, absorbed in turn,
for χ, η and Δ.

**Why the column-wise check.** A wrong correction `cᵢ` shifts tree i's
columns by `eᵢ·Δ_b`. Because the hash is GF(2)-linear and checked per
column, passing needs `H(eᵢ) = 0`, which has probability at most
`L/2¹²⁸` over χ, or a prediction of every bit of `Δᵢ` (2⁻⁸ per tree).
This is the VOLEitH argument FAEST relies on; it is not re-proven here.

**What is not done yet.**
- Proof-of-work grinding on Δ, which FAEST uses to buy back the
  per-tree guessing loss.
- A careful soundness bound for these parameters.
- Constant-time review of the prover. Field multiplication and
  `times_bit` are branch-free, but circuit evaluation runs on `bool`s.

## 3. Measured

The Keccak-f\[1600\] preimage statement ("I know a state whose image
is this") has 38,400 AND gates.

| statement | λ | witness bits | proof | prove | verify |
|---|---|---|---|---|---|
| Keccak-f\[1600\] preimage | 128 | 40,000 | 85,814 B | ~64 ms | ~36 ms |
| Keccak-f\[1600\] preimage | 256 | 40,000 | 172,486 B | ~92 ms | ~90 ms |

These are release builds on an Apple M-series laptop. The proof is about
`(τ−1)·L/8` bytes of corrections plus `ℓ/8` of witness: about two bytes
per committed bit at λ = 128, four at λ = 256.

## 4. The way to an ML-DSA statement

The statement for a blind ML-DSA-87 token is:

> knowledge of `salt` and `σ = (c̃, z, h)` such that, with
> `μ = SHAKE256(tr ‖ 0 ‖ |ctx| ‖ ctx ‖ salt ‖ m)`,
> `w′₁ = UseHint(h, A·z − c·t₁·2^d)`, `c = SampleInBall(c̃)`,
> `c̃ = H(μ ‖ w1Encode(w′₁))`, and `‖z‖∞ < γ₁ − β`.

Its parts and their costs:
- **Hashing** is about a dozen Keccak-f permutations (μ, c̃ over
  `w1Encode(w′₁)`, SampleInBall), roughly 460k AND gates. That is this
  crate's gadget, about 1 MB of proof as it stands.
- **The lattice part** is arithmetic mod q = 8380417. `A` and `t₁` are
  public, so `A·z` and `c·t₁` are linear in the secrets. But they are
  computed mod q over hundreds of thousands of coefficients, and
  HighBits/UseHint and the norm check need bit decompositions. As a
  boolean circuit this is about 10⁷ AND gates, which is tens of MB:
  impractical.

The remaining work, in order:
1. **VOLE over F_q's extension.** Commit `Z_q` values with MACs over a
   field containing `F_q`, so that linear maps over `Z_q` are free and
   products cost one constraint, as in Baum–Beckmann. The design of
   that VOLE needs the paper's full text. The abstract is not enough to
   implement it faithfully.
2. **Conversions** between committed bits and committed `Z_q` values,
   for HighBits, UseHint, the norm bound and w1Encode's input to
   Keccak.
3. **The ML-DSA circuit**, written generic over the parameter set,
   since the deployment's profile picks it. ML-DSA-87 comes first, as
   the only set CNSA 2.0 allows. It is tested against signatures from
   `ml-dsa-blind`'s unchanged signer.
4. **`BlindSignature::anonymize()`** in `ml-dsa-blind` behind a `zk`
   feature, then the token protocol (`IPNQ`/`IPNR`/`IPNT`).
5. **Review** by someone other than the author.
