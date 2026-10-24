//! The VOLE-in-the-head proof (`DESIGN.md` §2): a non-interactive
//! zero-knowledge proof of knowledge of a circuit input whose public
//! outputs are the given bits, at a security level λ ([`Level`]) the
//! system crypto policy picks.
//!
//! 1. **VOLE.** For each of `λ/8` trees the prover expands a GGM tree of
//!    [`LEAVES`] leaves and each leaf to `L` pseudorandom bits.  Tree `i`
//!    gives `uᵢ = ⊕ rₓ` and the columns `⊕_{x: bitᵦ(x)} rₓ`; the
//!    corrections `cᵢ = u₀ ⊕ uᵢ` make one `u` for all, and the λ columns
//!    make each row `vⱼ ∈ GF(2^λ)`.  Once the verifier knows `Δ` and
//!    every leaf but leaf `Δᵢ` of each tree, it computes `qⱼ = vⱼ + uⱼ·Δ`.
//! 2. **VOLE check.** Before `Δ`, the prover sends a GF(2)-linear
//!    universal hash of `u` and a digest of the hashes of the columns;
//!    the verifier checks each column's hash against `Δ`'s bit.  Wrong
//!    corrections pass only by guessing a whole tree's share of `Δ`.
//! 3. **Witness.** `d = w ⊕ u` commits the witness (inputs and AND
//!    outputs); `Kⱼ = qⱼ + dⱼΔ = vⱼ + wⱼΔ` is the verifier's MAC.
//! 4. **QuickSilver.** XOR and NOT act on MACs locally.  Each AND, and
//!    each public output, is a constraint; their random combination
//!    under `η`, masked by λ spare VOLE bits, is `A₀ + A₁Δ` exactly when
//!    every constraint holds.
//! 5. **Opening.** `Δ` is drawn after everything; the prover opens all
//!    leaves but leaf `Δᵢ` of each tree (its co-path, and the hidden
//!    leaf's commitment, so the verifier checks the commitment digest).
//!
//! Challenges come from a SHA-512 transcript over the level, the
//! circuit, the public outputs and every prover message.  The length
//! layout is `L = ℓ + 2λ`: `ℓ` witness bits, λ QuickSilver mask bits, λ
//! VOLE check mask bits.

use native_ossl::rand::Rand;

use crate::circuit::{Circuit, Gate};
use crate::field::{Field, Level};
use crate::gf128::Gf;
use crate::gf256::Gf256;
use crate::primitives::{Hash, Prg, Seed, Transcript, hash};
use crate::{Error, Result};

/// Tree depth: 8 bits of `Δ` per tree, so `λ/8` trees.
pub const DEPTH: usize = 8;
/// Leaves per tree.
pub const LEAVES: usize = 1 << DEPTH;
const DOMAIN: &str = "ml-dsa-zk/v1 proof";
const MAGIC: &[u8; 5] = b"IPZK\x01";

fn bit(bytes: &[u8], j: usize) -> bool {
    (bytes[j / 8] >> (j % 8)) & 1 == 1
}

fn xor_into(acc: &mut [u8], r: &[u8]) {
    for (a, b) in acc.iter_mut().zip(r) {
        *a ^= b;
    }
}

/// One tree's opening: the co-path to the hidden leaf, leaf level
/// first, and the hidden leaf's commitment.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Opening {
    copath: [Seed; DEPTH],
    hidden: Hash,
}

/// A proof, at the level it was made at.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    level: Level,
    salt: [u8; 32],
    h_com: Hash,
    corrections: Vec<Vec<u8>>,
    u_hash: Vec<u8>,
    h_v: Hash,
    d: Vec<u8>,
    a0: Vec<u8>,
    a1: Vec<u8>,
    openings: Vec<Opening>,
}

/// Sizes that follow from the circuit and the level.
struct Layout {
    lambda: usize,
    tau: usize,
    ell: usize,
    l: usize,
    lbytes: usize,
    dbytes: usize,
}

impl Layout {
    fn of(level: Level, circuit: &Circuit) -> Self {
        let lambda = level.lambda();
        let ell = circuit.witness_bits();
        let l = ell + 2 * lambda;
        Self {
            lambda,
            tau: lambda / DEPTH,
            ell,
            l,
            lbytes: l.div_ceil(8),
            dbytes: ell.div_ceil(8),
        }
    }
}

fn node_seed(master: &Seed, tree: usize) -> Result<Seed> {
    let h = hash(
        "ml-dsa-zk/v1 tree root",
        &[master, &(tree as u64).to_le_bytes()],
    )?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&h[..32]);
    Ok(out)
}

fn commit(salt: &[u8; 32], tree: usize, leaf: usize, seed: &Seed) -> Result<Hash> {
    hash(
        "ml-dsa-zk/v1 leaf",
        &[
            salt,
            &(tree as u64).to_le_bytes(),
            &(leaf as u64).to_le_bytes(),
            seed,
        ],
    )
}

/// The universal hash of the VOLE check: `Σ_{j<ℓ+λ} bitⱼ·χʲ⁺¹ +
/// Σ_t bit_{ℓ+λ+t}·xᵗ`, GF(2)-linear in the bits; the last λ bits mask
/// it.
fn vole_hash<F: Field>(bits: &[u8], powers: &[F], layout: &Layout) -> F {
    let mut h = F::ZERO;
    for (j, p) in powers.iter().enumerate() {
        h += p.times_bit(bit(bits, j));
    }
    let base = layout.ell + layout.lambda;
    for t in 0..layout.lambda {
        h += F::x_pow(t).times_bit(bit(bits, base + t));
    }
    h
}

fn powers<F: Field>(chi: F, n: usize) -> Vec<F> {
    let mut out = Vec::with_capacity(n);
    let mut p = chi;
    for _ in 0..n {
        out.push(p);
        p = p * chi;
    }
    out
}

fn column_digest<F: Field>(hashes: &[F]) -> Result<Hash> {
    let bytes: Vec<u8> = hashes.iter().flat_map(|h| h.to_vec()).collect();
    hash("ml-dsa-zk/v1 columns", &[&bytes])
}

/// The rows `Σ_c bitⱼ(column c)·xᶜ`.
fn rows<F: Field>(columns: &[Vec<u8>], l: usize) -> Vec<F> {
    let mut out = vec![F::ZERO; l];
    for (c, col) in columns.iter().enumerate() {
        for (j, row) in out.iter_mut().enumerate() {
            *row += F::x_pow(c).times_bit(bit(col, j));
        }
    }
    out
}

fn gf_challenge<F: Field>(t: &mut Transcript, label: &str) -> Result<F> {
    let mut b = vec![0u8; F::BITS / 8];
    t.challenge(label, &mut b)?;
    Ok(F::from_slice(&b))
}

fn transcript_start(
    level: Level,
    circuit: &Circuit,
    outputs: &[bool],
    salt: &[u8; 32],
    h_com: &Hash,
    corrections: &[Vec<u8>],
) -> Result<Transcript> {
    let mut t = Transcript::new(DOMAIN)?;
    t.absorb("level", &[level.id()])?;
    t.absorb("circuit", &circuit.digest()?)?;
    let out: Vec<u8> = outputs.iter().map(|b| u8::from(*b)).collect();
    t.absorb("outputs", &out)?;
    t.absorb("salt", salt)?;
    t.absorb("commitments", h_com)?;
    for c in corrections {
        t.absorb("correction", c)?;
    }
    Ok(t)
}

/// Prove that `input` makes `circuit`'s outputs what they are, at the
/// level the system crypto policy calls for ([`Level::from_system`]);
/// returns the proof and the outputs it states.
///
/// # Errors
///
/// [`Error::Malformed`] for a malformed circuit or input, or an
/// OpenSSL error, also for a policy that cannot be read.
pub fn prove(circuit: &Circuit, input: &[bool]) -> Result<(Proof, Vec<bool>)> {
    prove_at(Level::from_system()?, circuit, input)
}

/// [`prove`] at `level`.
///
/// # Errors
///
/// As [`prove`].
pub fn prove_at(level: Level, circuit: &Circuit, input: &[bool]) -> Result<(Proof, Vec<bool>)> {
    match level {
        Level::L128 => prove_in::<Gf>(level, circuit, input),
        Level::L256 => prove_in::<Gf256>(level, circuit, input),
    }
}

#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // the protocol's steps and names
fn prove_in<F: Field>(
    level: Level,
    circuit: &Circuit,
    input: &[bool],
) -> Result<(Proof, Vec<bool>)> {
    circuit.check()?;
    let (wires, outputs) = circuit.evaluate(input)?;
    let layout = Layout::of(level, circuit);
    let tau = layout.tau;
    let mut w: Vec<bool> = input.to_vec();
    for (i, g) in circuit.gates().iter().enumerate() {
        if matches!(g, Gate::And(..)) {
            w.push(wires[circuit.inputs() as usize + i]);
        }
    }
    let prg = Prg::new()?;
    let mut salt = [0u8; 32];
    Rand::fill(&mut salt)?;
    let mut master = [0u8; 32];
    Rand::fill_private(&mut master)?;

    // 1. The trees, their leaves' commitments, u and the columns.
    let mut trees: Vec<Vec<Seed>> = Vec::with_capacity(tau);
    let mut coms = Vec::with_capacity(tau * LEAVES * 64);
    let mut us: Vec<Vec<u8>> = Vec::with_capacity(tau);
    let mut columns = vec![vec![0u8; layout.lbytes]; tau * DEPTH];
    let mut r = vec![0u8; layout.lbytes];
    for i in 0..tau {
        let mut nodes = vec![[0u8; 32]; 2 * LEAVES];
        nodes[1] = node_seed(&master, i)?;
        for n in 1..LEAVES {
            let (a, b) = prg.children(&nodes[n])?;
            nodes[2 * n] = a;
            nodes[2 * n + 1] = b;
        }
        let mut u = vec![0u8; layout.lbytes];
        for x in 0..LEAVES {
            let seed = nodes[LEAVES + x];
            coms.extend_from_slice(&commit(&salt, i, x, &seed)?);
            prg.expand(&seed, &mut r)?;
            xor_into(&mut u, &r);
            for b in 0..DEPTH {
                if (x >> b) & 1 == 1 {
                    xor_into(&mut columns[DEPTH * i + b], &r);
                }
            }
        }
        us.push(u);
        trees.push(nodes);
    }
    let h_com = hash("ml-dsa-zk/v1 commitments", &[&salt, &coms])?;
    // The bits past L are never read; zero them, for one encoding.
    let tail = if layout.l.is_multiple_of(8) {
        0xff
    } else {
        (1u8 << (layout.l % 8)) - 1
    };
    let corrections: Vec<Vec<u8>> = us[1..]
        .iter()
        .map(|ui| {
            let mut c: Vec<u8> = us[0].iter().zip(ui).map(|(a, b)| a ^ b).collect();
            if let Some(last) = c.last_mut() {
                *last &= tail;
            }
            c
        })
        .collect();
    let u = &us[0];

    // 2. The VOLE check's hashes.
    let mut t = transcript_start(level, circuit, &outputs, &salt, &h_com, &corrections)?;
    let chi: F = gf_challenge(&mut t, "chi")?;
    let pw = powers(chi, layout.ell + layout.lambda);
    let u_hash = vole_hash(u, &pw, &layout);
    let col_hashes: Vec<F> = columns.iter().map(|c| vole_hash(c, &pw, &layout)).collect();
    let h_v = column_digest(&col_hashes)?;

    // 3. The witness, masked.
    let mut d = vec![0u8; layout.dbytes];
    for (j, wj) in w.iter().enumerate() {
        if *wj ^ bit(u, j) {
            d[j / 8] |= 1 << (j % 8);
        }
    }
    t.absorb("u hash", &u_hash.to_vec())?;
    t.absorb("column hashes", &h_v)?;
    t.absorb("witness", &d)?;
    let eta: F = gf_challenge(&mut t, "eta")?;

    // 4. QuickSilver over the MACs vⱼ.
    let v: Vec<F> = rows(&columns, layout.l);
    let mut macs: Vec<(bool, F)> = (0..circuit.inputs() as usize)
        .map(|j| (w[j], v[j]))
        .collect();
    let mut next = circuit.inputs() as usize;
    let (mut a0, mut a1) = (F::ZERO, F::ZERO);
    let mut weight = eta;
    for g in circuit.gates() {
        let m = match *g {
            Gate::Xor(a, b) => {
                let (x, y) = (macs[a as usize], macs[b as usize]);
                (x.0 ^ y.0, x.1 + y.1)
            }
            Gate::Not(a) => {
                let x = macs[a as usize];
                (!x.0, x.1)
            }
            Gate::And(a, b) => {
                let (x, y) = (macs[a as usize], macs[b as usize]);
                let c = (w[next], v[next]);
                next += 1;
                a0 += weight * (x.1 * y.1);
                a1 += weight * (x.1.times_bit(y.0) + y.1.times_bit(x.0) + c.1);
                weight = weight * eta;
                c
            }
        };
        macs.push(m);
    }
    for o in circuit.outputs() {
        a1 += weight * macs[*o as usize].1;
        weight = weight * eta;
    }
    let (mut mask_value, mut mask_mac) = (F::ZERO, F::ZERO);
    for t_ in 0..layout.lambda {
        let j = layout.ell + t_;
        mask_value += F::x_pow(t_).times_bit(bit(u, j));
        mask_mac += F::x_pow(t_) * v[j];
    }
    a0 += mask_mac;
    a1 += mask_value;

    // 5. Δ, and the openings.
    t.absorb("a0", &a0.to_vec())?;
    t.absorb("a1", &a1.to_vec())?;
    let mut delta = vec![0u8; tau];
    t.challenge("delta", &mut delta)?;
    let openings = trees
        .iter()
        .enumerate()
        .map(|(i, nodes)| {
            let hidden = usize::from(delta[i]);
            let mut copath = [[0u8; 32]; DEPTH];
            let mut n = LEAVES + hidden;
            for slot in &mut copath {
                *slot = nodes[n ^ 1];
                n >>= 1;
            }
            Ok(Opening {
                copath,
                hidden: commit(&salt, i, hidden, &nodes[LEAVES + hidden])?,
            })
        })
        .collect::<Result<_>>()?;
    Ok((
        Proof {
            level,
            salt,
            h_com,
            corrections,
            u_hash: u_hash.to_vec(),
            h_v,
            d,
            a0: a0.to_vec(),
            a1: a1.to_vec(),
            openings,
        },
        outputs,
    ))
}

/// Verify `proof` that some input makes `circuit`'s outputs `outputs`,
/// refusing a proof weaker than the system crypto policy calls for
/// ([`Level::from_system`]).
///
/// # Errors
///
/// [`Error::Invalid`] for a proof that does not verify, [`Error::Weak`]
/// for one below the policy's level, [`Error::Malformed`] for one of the
/// wrong shape, or an OpenSSL error, also for a policy that cannot be
/// read.
pub fn verify(circuit: &Circuit, outputs: &[bool], proof: &Proof) -> Result<()> {
    verify_at(Level::from_system()?, circuit, outputs, proof)
}

/// [`verify`], requiring a proof of at least `minimum`.
///
/// # Errors
///
/// As [`verify`].
pub fn verify_at(minimum: Level, circuit: &Circuit, outputs: &[bool], proof: &Proof) -> Result<()> {
    if proof.level < minimum {
        return Err(Error::Weak(proof.level));
    }
    match proof.level {
        Level::L128 => verify_in::<Gf>(circuit, outputs, proof),
        Level::L256 => verify_in::<Gf256>(circuit, outputs, proof),
    }
}

#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // the protocol's steps and names
fn verify_in<F: Field>(circuit: &Circuit, outputs: &[bool], proof: &Proof) -> Result<()> {
    circuit.check()?;
    let layout = Layout::of(proof.level, circuit);
    let tau = layout.tau;
    let fbytes = F::BITS / 8;
    if outputs.len() != circuit.outputs().len()
        || proof.corrections.len() != tau - 1
        || proof.corrections.iter().any(|c| c.len() != layout.lbytes)
        || proof.d.len() != layout.dbytes
        || proof.openings.len() != tau
        || [&proof.u_hash, &proof.a0, &proof.a1]
            .iter()
            .any(|e| e.len() != fbytes)
    {
        return Err(Error::Malformed("proof shape"));
    }
    let (u_hash, a0, a1) = (
        F::from_slice(&proof.u_hash),
        F::from_slice(&proof.a0),
        F::from_slice(&proof.a1),
    );
    let mut t = transcript_start(
        proof.level,
        circuit,
        outputs,
        &proof.salt,
        &proof.h_com,
        &proof.corrections,
    )?;
    let chi: F = gf_challenge(&mut t, "chi")?;
    t.absorb("u hash", &proof.u_hash)?;
    t.absorb("column hashes", &proof.h_v)?;
    t.absorb("witness", &proof.d)?;
    let eta: F = gf_challenge(&mut t, "eta")?;
    t.absorb("a0", &proof.a0)?;
    t.absorb("a1", &proof.a1)?;
    let mut delta_bytes = vec![0u8; tau];
    t.challenge("delta", &mut delta_bytes)?;
    let delta = F::from_slice(&delta_bytes);

    // The opened leaves, their commitments, and the columns of Q.
    let prg = Prg::new()?;
    let mut coms = Vec::with_capacity(tau * LEAVES * 64);
    let mut columns = vec![vec![0u8; layout.lbytes]; tau * DEPTH];
    let mut r = vec![0u8; layout.lbytes];
    for (i, opening) in proof.openings.iter().enumerate() {
        let hidden = usize::from(delta_bytes[i]);
        let mut known: Vec<Option<Seed>> = vec![None; 2 * LEAVES];
        let mut n = LEAVES + hidden;
        for seed in &opening.copath {
            known[n ^ 1] = Some(*seed);
            n >>= 1;
        }
        for n in 1..LEAVES {
            if let Some(seed) = known[n] {
                let (a, b) = prg.children(&seed)?;
                known[2 * n] = Some(a);
                known[2 * n + 1] = Some(b);
            }
        }
        for x in 0..LEAVES {
            if x == hidden {
                coms.extend_from_slice(&opening.hidden);
                continue;
            }
            let seed = known[LEAVES + x].ok_or(Error::Invalid)?;
            coms.extend_from_slice(&commit(&proof.salt, i, x, &seed)?);
            prg.expand(&seed, &mut r)?;
            let y = x ^ hidden;
            for b in 0..DEPTH {
                if (y >> b) & 1 == 1 {
                    xor_into(&mut columns[DEPTH * i + b], &r);
                }
            }
        }
        if i > 0 {
            for b in 0..DEPTH {
                if (hidden >> b) & 1 == 1 {
                    xor_into(&mut columns[DEPTH * i + b], &proof.corrections[i - 1]);
                }
            }
        }
    }
    let h_com = hash("ml-dsa-zk/v1 commitments", &[&proof.salt, &coms])?;
    if h_com != proof.h_com {
        return Err(Error::Invalid);
    }

    // The VOLE check: every column's hash is the prover's, shifted by
    // ũ where Δ's bit is set.
    let pw = powers(chi, layout.ell + layout.lambda);
    let expected: Vec<F> = columns
        .iter()
        .enumerate()
        .map(|(c, col)| vole_hash(col, &pw, &layout) + u_hash.times_bit(delta.bit(c)))
        .collect();
    if column_digest(&expected)? != proof.h_v {
        return Err(Error::Invalid);
    }

    // QuickSilver over the MACs Kⱼ = qⱼ + dⱼΔ.
    let q: Vec<F> = rows(&columns, layout.l);
    let k = |j: usize| q[j] + delta.times_bit(bit(&proof.d, j));
    let mut macs: Vec<F> = (0..circuit.inputs() as usize).map(k).collect();
    let mut next = circuit.inputs() as usize;
    let mut lhs = F::ZERO;
    let mut weight = eta;
    for g in circuit.gates() {
        let m = match *g {
            Gate::Xor(a, b) => macs[a as usize] + macs[b as usize],
            Gate::Not(a) => macs[a as usize] + delta,
            Gate::And(a, b) => {
                let c = k(next);
                next += 1;
                lhs += weight * (macs[a as usize] * macs[b as usize] + c * delta);
                weight = weight * eta;
                c
            }
        };
        macs.push(m);
    }
    for (o, y) in circuit.outputs().iter().zip(outputs) {
        lhs += weight * ((macs[*o as usize] + delta.times_bit(*y)) * delta);
        weight = weight * eta;
    }
    for t_ in 0..layout.lambda {
        lhs += F::x_pow(t_) * q[layout.ell + t_];
    }
    if lhs != a0 + a1 * delta {
        return Err(Error::Invalid);
    }
    Ok(())
}

impl Proof {
    /// The level it was made at.
    #[must_use]
    pub fn level(&self) -> Level {
        self.level
    }

    /// The encoding: `IPZK ‖ 1 ‖ level(1)`, then every field in order, at
    /// the sizes the circuit and the level fix.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(self.level.id());
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.h_com);
        for c in &self.corrections {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&self.u_hash);
        out.extend_from_slice(&self.h_v);
        out.extend_from_slice(&self.d);
        out.extend_from_slice(&self.a0);
        out.extend_from_slice(&self.a1);
        for o in &self.openings {
            for s in &o.copath {
                out.extend_from_slice(s);
            }
            out.extend_from_slice(&o.hidden);
        }
        out
    }

    /// The encoded size of a proof for `circuit` at `level`.
    #[must_use]
    pub fn size(level: Level, circuit: &Circuit) -> usize {
        let layout = Layout::of(level, circuit);
        let fbytes = layout.lambda / 8;
        // magic and level, salt, h_com, corrections, ũ, h_V, d, A₀ and
        // A₁, openings
        6 + 32
            + 64
            + (layout.tau - 1) * layout.lbytes
            + fbytes
            + 64
            + layout.dbytes
            + 2 * fbytes
            + layout.tau * (DEPTH * 32 + 64)
    }

    /// Parse a proof for `circuit`, at the level it names.  Unused bits
    /// past the vectors' lengths must be zero, so a proof has one
    /// encoding.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    ///
    /// # Panics
    ///
    /// Never: the length is checked before any field is read.
    pub fn from_bytes(circuit: &Circuit, bytes: &[u8]) -> Result<Self> {
        if bytes.len() < MAGIC.len() + 1 || !bytes.starts_with(MAGIC) {
            return Err(Error::Malformed("proof"));
        }
        let level = Level::from_id(bytes[MAGIC.len()])?;
        let layout = Layout::of(level, circuit);
        if bytes.len() != Self::size(level, circuit) {
            return Err(Error::Malformed("proof"));
        }
        let fbytes = layout.lambda / 8;
        let mut at = MAGIC.len() + 1;
        let mut take = |n: usize| {
            let s = &bytes[at..at + n];
            at += n;
            s
        };
        let arr32 = |s: &[u8]| -> [u8; 32] { s.try_into().expect("32 bytes") };
        let arr64 = |s: &[u8]| -> Hash { s.try_into().expect("64 bytes") };
        let salt = arr32(take(32));
        let h_com = arr64(take(64));
        let corrections: Vec<Vec<u8>> = (0..layout.tau - 1)
            .map(|_| take(layout.lbytes).to_vec())
            .collect();
        let u_hash = take(fbytes).to_vec();
        let h_v = arr64(take(64));
        let d = take(layout.dbytes).to_vec();
        let a0 = take(fbytes).to_vec();
        let a1 = take(fbytes).to_vec();
        let openings = (0..layout.tau)
            .map(|_| {
                let mut copath = [[0u8; 32]; DEPTH];
                for s in &mut copath {
                    *s = arr32(take(32));
                }
                Opening {
                    copath,
                    hidden: arr64(take(64)),
                }
            })
            .collect();
        let padded = |v: &[u8], bits: usize| {
            !bits.is_multiple_of(8) && v.last().is_some_and(|b| b >> (bits % 8) != 0)
        };
        if corrections.iter().any(|c| padded(c, layout.l)) || padded(&d, layout.ell) {
            return Err(Error::Malformed("proof padding"));
        }
        Ok(Self {
            level,
            salt,
            h_com,
            corrections,
            u_hash,
            h_v,
            d,
            a0,
            a1,
            openings,
        })
    }
}
