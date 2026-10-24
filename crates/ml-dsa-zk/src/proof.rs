//! The VOLE-in-the-head proof (`DESIGN.md` §2): a non-interactive
//! zero-knowledge proof of knowledge of a circuit input whose public
//! outputs are the given bits.
//!
//! 1. **VOLE.** For each of [`TAU`] trees the prover expands a GGM tree
//!    of [`LEAVES`] leaves and each leaf to `L` pseudorandom bits.  Tree
//!    `i` gives `uᵢ = ⊕ rₓ` and the columns `⊕_{x: bitᵦ(x)} rₓ`; the
//!    corrections `cᵢ = u₀ ⊕ uᵢ` make one `u` for all, and the 128
//!    columns make each row `vⱼ ∈ GF(2¹²⁸)`.  Once the verifier knows
//!    `Δ` and every leaf but leaf `Δᵢ` of each tree, it computes
//!    `qⱼ = vⱼ + uⱼ·Δ`.
//! 2. **VOLE check.** Before `Δ`, the prover sends a GF(2)-linear
//!    universal hash of `u` and a digest of the hashes of the columns;
//!    the verifier checks each column's hash against `Δ`'s bit.  Wrong
//!    corrections pass only by guessing a whole tree's share of `Δ`.
//! 3. **Witness.** `d = w ⊕ u` commits the witness (inputs and AND
//!    outputs); `Kⱼ = qⱼ + dⱼΔ = vⱼ + wⱼΔ` is the verifier's MAC.
//! 4. **QuickSilver.** XOR and NOT act on MACs locally.  Each AND, and
//!    each public output, is a constraint; their random combination
//!    under `η`, masked by 128 spare VOLE bits, is `A₀ + A₁Δ` exactly
//!    when every constraint holds.
//! 5. **Opening.** `Δ` is drawn after everything; the prover opens all
//!    leaves but leaf `Δᵢ` of each tree (its co-path, and the hidden
//!    leaf's commitment, so the verifier checks the commitment digest).
//!
//! Challenges come from a SHAKE256 transcript over the circuit, the
//! public outputs and every prover message.  The length layout is
//! `L = ℓ + 256`: `ℓ` witness bits, 128 QuickSilver mask bits, 128 VOLE
//! check mask bits.

use native_ossl::rand::Rand;

use crate::circuit::{Circuit, Gate};
use crate::gf128::Gf;
use crate::primitives::{Prg, Seed, Transcript, shake};
use crate::{Error, Result};

/// Trees.
pub const TAU: usize = 16;
/// Tree depth: `TAU · DEPTH` = 128 bits of `Δ`.
pub const DEPTH: usize = 8;
/// Leaves per tree.
pub const LEAVES: usize = 1 << DEPTH;
const MASKS: usize = 256;
const DOMAIN: &str = "ml-dsa-zk/v1 proof";

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
    hidden: [u8; 32],
}

/// A proof.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    salt: [u8; 32],
    h_com: [u8; 32],
    corrections: Vec<Vec<u8>>,
    u_hash: Gf,
    h_v: [u8; 32],
    d: Vec<u8>,
    a0: Gf,
    a1: Gf,
    openings: Vec<Opening>,
}

/// Sizes that follow from the circuit.
struct Layout {
    ell: usize,
    l: usize,
    lbytes: usize,
    dbytes: usize,
}

impl Layout {
    fn of(circuit: &Circuit) -> Self {
        let ell = circuit.witness_bits();
        let l = ell + MASKS;
        Self {
            ell,
            l,
            lbytes: l.div_ceil(8),
            dbytes: ell.div_ceil(8),
        }
    }
}

fn node_seed(master: &Seed, tree: usize) -> Result<Seed> {
    let mut out = [0u8; 16];
    shake(
        "ml-dsa-zk/v1 tree root",
        &[master, &(tree as u64).to_le_bytes()],
        &mut out,
    )?;
    Ok(out)
}

fn commit(salt: &[u8; 32], tree: usize, leaf: usize, seed: &Seed) -> Result<[u8; 32]> {
    let mut out = [0u8; 32];
    shake(
        "ml-dsa-zk/v1 leaf",
        &[
            salt,
            &(tree as u64).to_le_bytes(),
            &(leaf as u64).to_le_bytes(),
            seed,
        ],
        &mut out,
    )?;
    Ok(out)
}

/// The universal hash of the VOLE check: `Σ_{j<ℓ+128} bitⱼ·χʲ⁺¹ +
/// Σ_t bit_{ℓ+128+t}·xᵗ`, GF(2)-linear in the bits; the last 128 bits
/// mask it.
fn vole_hash(bits: &[u8], powers: &[Gf], layout: &Layout) -> Gf {
    let mut h = Gf::ZERO;
    for (j, p) in powers.iter().enumerate() {
        h += p.times_bit(bit(bits, j));
    }
    let base = layout.ell + 128;
    for t in 0..128 {
        h += Gf::x_pow(t).times_bit(bit(bits, base + t));
    }
    h
}

fn powers(chi: Gf, n: usize) -> Vec<Gf> {
    let mut out = Vec::with_capacity(n);
    let mut p = chi;
    for _ in 0..n {
        out.push(p);
        p = p * chi;
    }
    out
}

fn column_digest(hashes: &[Gf]) -> Result<[u8; 32]> {
    let bytes: Vec<u8> = hashes.iter().flat_map(|h| h.to_bytes()).collect();
    let mut out = [0u8; 32];
    shake("ml-dsa-zk/v1 columns", &[&bytes], &mut out)?;
    Ok(out)
}

/// The rows `Σ_c bitⱼ(column c)·xᶜ`.
fn rows(columns: &[Vec<u8>], l: usize) -> Vec<Gf> {
    let mut out = vec![Gf::ZERO; l];
    for (c, col) in columns.iter().enumerate() {
        for (j, row) in out.iter_mut().enumerate() {
            *row += Gf::x_pow(c).times_bit(bit(col, j));
        }
    }
    out
}

fn gf_challenge(t: &mut Transcript, label: &str) -> Result<Gf> {
    let mut b = [0u8; 16];
    t.challenge(label, &mut b)?;
    Ok(Gf::from_bytes(b))
}

fn transcript_start(
    circuit: &Circuit,
    outputs: &[bool],
    salt: &[u8; 32],
    h_com: &[u8; 32],
    corrections: &[Vec<u8>],
) -> Result<Transcript> {
    let mut t = Transcript::new(DOMAIN)?;
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

/// Prove that `input` makes `circuit`'s outputs what they are; returns
/// the proof and the outputs it states.
///
/// # Errors
///
/// [`Error::Malformed`] for a malformed circuit or input, or an
/// OpenSSL error.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // the protocol's steps and names
pub fn prove(circuit: &Circuit, input: &[bool]) -> Result<(Proof, Vec<bool>)> {
    circuit.check()?;
    let (wires, outputs) = circuit.evaluate(input)?;
    let layout = Layout::of(circuit);
    let mut w: Vec<bool> = input.to_vec();
    for (i, g) in circuit.gates().iter().enumerate() {
        if matches!(g, Gate::And(..)) {
            w.push(wires[circuit.inputs() as usize + i]);
        }
    }
    let prg = Prg::new()?;
    let mut salt = [0u8; 32];
    Rand::fill(&mut salt)?;
    let mut master = [0u8; 16];
    Rand::fill_private(&mut master)?;

    // 1. The trees, their leaves' commitments, u and the columns.
    let mut trees: Vec<Vec<Seed>> = Vec::with_capacity(TAU);
    let mut coms = Vec::with_capacity(TAU * LEAVES * 32);
    let mut us: Vec<Vec<u8>> = Vec::with_capacity(TAU);
    let mut columns = vec![vec![0u8; layout.lbytes]; TAU * DEPTH];
    let mut r = vec![0u8; layout.lbytes];
    for i in 0..TAU {
        let mut nodes = vec![[0u8; 16]; 2 * LEAVES];
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
    let mut h_com = [0u8; 32];
    shake("ml-dsa-zk/v1 commitments", &[&salt, &coms], &mut h_com)?;
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
    let mut t = transcript_start(circuit, &outputs, &salt, &h_com, &corrections)?;
    let chi = gf_challenge(&mut t, "chi")?;
    let pw = powers(chi, layout.ell + 128);
    let u_hash = vole_hash(u, &pw, &layout);
    let col_hashes: Vec<Gf> = columns.iter().map(|c| vole_hash(c, &pw, &layout)).collect();
    let h_v = column_digest(&col_hashes)?;

    // 3. The witness, masked.
    let mut d = vec![0u8; layout.dbytes];
    for (j, wj) in w.iter().enumerate() {
        if *wj ^ bit(u, j) {
            d[j / 8] |= 1 << (j % 8);
        }
    }
    t.absorb("u hash", &u_hash.to_bytes())?;
    t.absorb("column hashes", &h_v)?;
    t.absorb("witness", &d)?;
    let eta = gf_challenge(&mut t, "eta")?;

    // 4. QuickSilver over the MACs vⱼ.
    let v = rows(&columns, layout.l);
    let mut macs: Vec<(bool, Gf)> = (0..circuit.inputs() as usize)
        .map(|j| (w[j], v[j]))
        .collect();
    let mut next = circuit.inputs() as usize;
    let (mut a0, mut a1) = (Gf::ZERO, Gf::ZERO);
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
    let (mut mask_value, mut mask_mac) = (Gf::ZERO, Gf::ZERO);
    for t_ in 0..128 {
        let j = layout.ell + t_;
        mask_value += Gf::x_pow(t_).times_bit(bit(u, j));
        mask_mac += Gf::x_pow(t_) * v[j];
    }
    a0 += mask_mac;
    a1 += mask_value;

    // 5. Δ, and the openings.
    t.absorb("a0", &a0.to_bytes())?;
    t.absorb("a1", &a1.to_bytes())?;
    let mut delta = [0u8; 16];
    t.challenge("delta", &mut delta)?;
    let openings = trees
        .iter()
        .enumerate()
        .map(|(i, nodes)| {
            let hidden = usize::from(delta[i]);
            let mut copath = [[0u8; 16]; DEPTH];
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
            salt,
            h_com,
            corrections,
            u_hash,
            h_v,
            d,
            a0,
            a1,
            openings,
        },
        outputs,
    ))
}

/// Verify `proof` that some input makes `circuit`'s outputs `outputs`.
///
/// # Errors
///
/// [`Error::Invalid`] for a proof that does not verify, [`Error::Malformed`]
/// for one of the wrong shape, or an OpenSSL error.
#[allow(clippy::too_many_lines, clippy::many_single_char_names)] // the protocol's steps and names
pub fn verify(circuit: &Circuit, outputs: &[bool], proof: &Proof) -> Result<()> {
    circuit.check()?;
    let layout = Layout::of(circuit);
    if outputs.len() != circuit.outputs().len()
        || proof.corrections.len() != TAU - 1
        || proof.corrections.iter().any(|c| c.len() != layout.lbytes)
        || proof.d.len() != layout.dbytes
        || proof.openings.len() != TAU
    {
        return Err(Error::Malformed("proof shape"));
    }
    let mut t = transcript_start(
        circuit,
        outputs,
        &proof.salt,
        &proof.h_com,
        &proof.corrections,
    )?;
    let chi = gf_challenge(&mut t, "chi")?;
    t.absorb("u hash", &proof.u_hash.to_bytes())?;
    t.absorb("column hashes", &proof.h_v)?;
    t.absorb("witness", &proof.d)?;
    let eta = gf_challenge(&mut t, "eta")?;
    t.absorb("a0", &proof.a0.to_bytes())?;
    t.absorb("a1", &proof.a1.to_bytes())?;
    let mut delta_bytes = [0u8; 16];
    t.challenge("delta", &mut delta_bytes)?;
    let delta = Gf::from_bytes(delta_bytes);

    // The opened leaves, their commitments, and the columns of Q.
    let prg = Prg::new()?;
    let mut coms = Vec::with_capacity(TAU * LEAVES * 32);
    let mut columns = vec![vec![0u8; layout.lbytes]; TAU * DEPTH];
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
    let mut h_com = [0u8; 32];
    shake(
        "ml-dsa-zk/v1 commitments",
        &[&proof.salt, &coms],
        &mut h_com,
    )?;
    if h_com != proof.h_com {
        return Err(Error::Invalid);
    }

    // The VOLE check: every column's hash is the prover's, shifted by
    // ũ where Δ's bit is set.
    let pw = powers(chi, layout.ell + 128);
    let expected: Vec<Gf> = columns
        .iter()
        .enumerate()
        .map(|(c, col)| {
            vole_hash(col, &pw, &layout) + proof.u_hash.times_bit((delta.0 >> c) & 1 == 1)
        })
        .collect();
    if column_digest(&expected)? != proof.h_v {
        return Err(Error::Invalid);
    }

    // QuickSilver over the MACs Kⱼ = qⱼ + dⱼΔ.
    let q = rows(&columns, layout.l);
    let k = |j: usize| q[j] + delta.times_bit(bit(&proof.d, j));
    let mut macs: Vec<Gf> = (0..circuit.inputs() as usize).map(k).collect();
    let mut next = circuit.inputs() as usize;
    let mut lhs = Gf::ZERO;
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
    for t_ in 0..128 {
        lhs += Gf::x_pow(t_) * q[layout.ell + t_];
    }
    if lhs != proof.a0 + proof.a1 * delta {
        return Err(Error::Invalid);
    }
    Ok(())
}

impl Proof {
    /// The encoding: every field in order, at the sizes the circuit fixes.
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"IPZK\x01");
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.h_com);
        for c in &self.corrections {
            out.extend_from_slice(c);
        }
        out.extend_from_slice(&self.u_hash.to_bytes());
        out.extend_from_slice(&self.h_v);
        out.extend_from_slice(&self.d);
        out.extend_from_slice(&self.a0.to_bytes());
        out.extend_from_slice(&self.a1.to_bytes());
        for o in &self.openings {
            for s in &o.copath {
                out.extend_from_slice(s);
            }
            out.extend_from_slice(&o.hidden);
        }
        out
    }

    /// The encoded size of a proof for `circuit`.
    #[must_use]
    pub fn size(circuit: &Circuit) -> usize {
        let layout = Layout::of(circuit);
        5 + 32
            + 32
            + (TAU - 1) * layout.lbytes
            + 16
            + 32
            + layout.dbytes
            + 32
            + TAU * (DEPTH * 16 + 32)
    }

    /// Parse a proof for `circuit`.  Unused bits past the vectors'
    /// lengths must be zero, so a proof has one encoding.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    ///
    /// # Panics
    ///
    /// Never: the length is checked before any field is read.
    pub fn from_bytes(circuit: &Circuit, bytes: &[u8]) -> Result<Self> {
        let layout = Layout::of(circuit);
        if bytes.len() != Self::size(circuit) || !bytes.starts_with(b"IPZK\x01") {
            return Err(Error::Malformed("proof"));
        }
        let mut at = 5;
        let mut take = |n: usize| {
            let s = &bytes[at..at + n];
            at += n;
            s
        };
        let arr32 = |s: &[u8]| -> [u8; 32] { s.try_into().expect("32 bytes") };
        let arr16 = |s: &[u8]| -> [u8; 16] { s.try_into().expect("16 bytes") };
        let salt = arr32(take(32));
        let h_com = arr32(take(32));
        let corrections: Vec<Vec<u8>> =
            (0..TAU - 1).map(|_| take(layout.lbytes).to_vec()).collect();
        let u_hash = Gf::from_bytes(arr16(take(16)));
        let h_v = arr32(take(32));
        let d = take(layout.dbytes).to_vec();
        let a0 = Gf::from_bytes(arr16(take(16)));
        let a1 = Gf::from_bytes(arr16(take(16)));
        let openings = (0..TAU)
            .map(|_| {
                let mut copath = [[0u8; 16]; DEPTH];
                for s in &mut copath {
                    *s = arr16(take(16));
                }
                Opening {
                    copath,
                    hidden: arr32(take(32)),
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
