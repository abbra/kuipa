//! Keccak-f\[1600\] as a circuit: the permutation under SHAKE256, which
//! ML-DSA verification runs for `μ`, `c̃` and `SampleInBall`.  θ, ρ, π
//! and ι are linear (free); χ costs 1600 AND gates a round, 38400 for
//! the permutation.
//!
//! A state is 1600 wires, lane `(x, y)` at `64·(x + 5y)`, bit `z` of the
//! lane at `+ z` — the byte order of FIPS 202's state string.

use crate::circuit::{Circuit, Wire};

const ROUND_CONSTANTS: [u64; 24] = [
    0x0000_0000_0000_0001,
    0x0000_0000_0000_8082,
    0x8000_0000_0000_808a,
    0x8000_0000_8000_8000,
    0x0000_0000_0000_808b,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8009,
    0x0000_0000_0000_008a,
    0x0000_0000_0000_0088,
    0x0000_0000_8000_8009,
    0x0000_0000_8000_000a,
    0x0000_0000_8000_808b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_8000_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

/// ρ's rotation of lane `(x, y)`, as `ROTATIONS[x][y]`.
const ROTATIONS: [[u32; 5]; 5] = [
    [0, 36, 3, 41, 18],
    [1, 44, 10, 45, 2],
    [62, 6, 43, 15, 61],
    [28, 55, 25, 21, 56],
    [27, 20, 39, 8, 14],
];

const fn lane(x: usize, y: usize) -> usize {
    64 * (x % 5 + 5 * (y % 5))
}

/// Append Keccak-f\[1600\] of `state` to `c`; returns the new state.
pub fn permutation(circuit: &mut Circuit, state: &[Wire; 1600]) -> [Wire; 1600] {
    let mut lanes = *state;
    for round_const in ROUND_CONSTANTS {
        // θ
        let mut col = [0u32; 320];
        for x in 0..5 {
            for z in 0..64 {
                let mut acc = lanes[lane(x, 0) + z];
                for y in 1..5 {
                    acc = circuit.xor(acc, lanes[lane(x, y) + z]);
                }
                col[64 * x + z] = acc;
            }
        }
        for x in 0..5 {
            for z in 0..64 {
                let left = col[64 * ((x + 4) % 5) + z];
                let right = col[64 * ((x + 1) % 5) + (z + 63) % 64];
                let delta = circuit.xor(left, right);
                for y in 0..5 {
                    lanes[lane(x, y) + z] = circuit.xor(lanes[lane(x, y) + z], delta);
                }
            }
        }
        // ρ and π: B[y, 2x+3y] = rot(A[x, y], r[x][y]).
        let mut rho_pi = [0u32; 1600];
        for x in 0..5 {
            for y in 0..5 {
                let rot = ROTATIONS[x][y] as usize;
                for z in 0..64 {
                    rho_pi[lane(y, 2 * x + 3 * y) + (z + rot) % 64] = lanes[lane(x, y) + z];
                }
            }
        }
        // χ
        for x in 0..5 {
            for y in 0..5 {
                for z in 0..64 {
                    let inverted = circuit.not(rho_pi[lane(x + 1, y) + z]);
                    let masked = circuit.and(inverted, rho_pi[lane(x + 2, y) + z]);
                    lanes[lane(x, y) + z] = circuit.xor(rho_pi[lane(x, y) + z], masked);
                }
            }
        }
        // ι
        for (z, wire) in lanes.iter_mut().enumerate().take(64) {
            if (round_const >> z) & 1 == 1 {
                *wire = circuit.not(*wire);
            }
        }
    }
    lanes
}

/// Keccak-f\[1600\] in software, over lanes: for tests and witnesses.
#[must_use]
pub fn permute(state: [u64; 25]) -> [u64; 25] {
    let mut a = state;
    for rc in ROUND_CONSTANTS {
        let mut c = [0u64; 5];
        for (x, cx) in c.iter_mut().enumerate() {
            *cx = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left(ROTATIONS[x][y]);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ (!b[(x + 1) % 5 + 5 * y] & b[(x + 2) % 5 + 5 * y]);
            }
        }
        a[0] ^= rc;
    }
    a
}

/// A state's 1600 bits, in the circuit's order.
#[must_use]
pub fn to_bits(state: &[u64; 25]) -> Vec<bool> {
    state
        .iter()
        .flat_map(|lane| (0..64).map(move |z| (lane >> z) & 1 == 1))
        .collect()
}

#[cfg(test)]
mod tests {
    use native_ossl::digest::DigestAlg;

    use super::*;

    #[test]
    fn the_software_permutation_is_sha3() {
        // SHA3-256 of the empty message: one block, padding 0x06 … 0x80.
        let mut s = [0u64; 25];
        s[0] ^= 0x06;
        s[16] ^= 0x8000_0000_0000_0000; // rate 136 bytes: byte 135 is lane 16, top byte
        let out = permute(s);
        let ours: Vec<u8> = out[..4].iter().flat_map(|l| l.to_le_bytes()).collect();
        let alg = DigestAlg::fetch(c"SHA3-256", None).unwrap();
        let mut ctx = alg.new_context().unwrap();
        let mut theirs = [0u8; 32];
        ctx.finish(&mut theirs).unwrap();
        assert_eq!(ours, theirs);
    }

    #[test]
    fn the_circuit_is_the_permutation() {
        let mut c = Circuit::new(1600);
        let input: [Wire; 1600] = std::array::from_fn(|i| c.input(u32::try_from(i).unwrap()));
        let out = permutation(&mut c, &input);
        for w in out {
            c.output(w);
        }
        assert_eq!(c.ands(), 24 * 1600);
        let state: [u64; 25] =
            std::array::from_fn(|i| 0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1));
        let (_, outputs) = c.evaluate(&to_bits(&state)).unwrap();
        assert_eq!(outputs, to_bits(&permute(state)));
    }
}
