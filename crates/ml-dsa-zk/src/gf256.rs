//! GF(2²⁵⁶), as `x²⁵⁶ + x¹⁰ + x⁵ + x² + 1` (FAEST-256's field): the
//! field of the λ = 256 proofs ([`Level::L256`](crate::Level::L256)).
//! Bit `i` of the pair of `u128`s, low half first, is the coefficient of
//! `xⁱ`.  Multiplication is carry-less and branch-free, on the CPU's
//! carry-less multiply where it has one.

use std::ops::{Add, AddAssign, Mul};

use crate::clmul::clmul64;
use crate::gf128::halves;

/// An element of GF(2²⁵⁶).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gf256(pub [u128; 2]);

impl Gf256 {
    /// Addition: XOR.
    #[must_use]
    fn xor(self, other: Self) -> Self {
        Self([self.0[0] ^ other.0[0], self.0[1] ^ other.0[1]])
    }

    /// 0.
    pub const ZERO: Self = Self([0, 0]);
    /// 1.
    pub const ONE: Self = Self([1, 0]);

    /// `xᵗ`, for `t < 256`.
    #[must_use]
    pub const fn x_pow(t: usize) -> Self {
        if t < 128 {
            Self([1 << t, 0])
        } else {
            Self([0, 1 << (t - 128)])
        }
    }

    /// `self` if `bit`, else 0, without a branch.
    #[must_use]
    pub const fn times_bit(self, bit: bool) -> Self {
        let mask = 0u128.wrapping_sub(bit as u128);
        Self([self.0[0] & mask, self.0[1] & mask])
    }

    /// The coefficient of `xⁱ`, for `i < 256`.
    #[must_use]
    pub const fn bit(self, i: usize) -> bool {
        (self.0[i / 128] >> (i % 128)) & 1 == 1
    }

    /// The little-endian bytes.
    #[must_use]
    pub fn to_bytes(self) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..16].copy_from_slice(&self.0[0].to_le_bytes());
        out[16..].copy_from_slice(&self.0[1].to_le_bytes());
        out
    }

    /// From little-endian bytes.
    ///
    /// # Panics
    ///
    /// Never: both halves are 16 bytes of a 32-byte array.
    #[must_use]
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let half = |s: &[u8]| u128::from_le_bytes(s.try_into().expect("16 bytes"));
        Self([half(&bytes[..16]), half(&bytes[16..])])
    }
}

// Addition in characteristic 2 is XOR.
impl Add for Gf256 {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        self.xor(other)
    }
}

impl AddAssign for Gf256 {
    fn add_assign(&mut self, other: Self) {
        *self = self.xor(other);
    }
}

/// 128×128 → 256 carry-less multiplication by Karatsuba, as `(lo, hi)`.
fn clmul128(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = halves(a);
    let (b0, b1) = halves(b);
    let z0 = clmul64(a0, b0);
    let z2 = clmul64(a1, b1);
    let z1 = clmul64(a0 ^ a1, b0 ^ b1) ^ z0 ^ z2;
    (z0 ^ (z1 << 64), z2 ^ (z1 >> 64))
}

/// The low 256 bits of `h · xᵏ`, for `0 < k < 128`, and the `k` bits
/// pushed past `x²⁵⁵`.
const fn shl(h: [u128; 2], k: u32) -> ([u128; 2], u128) {
    (
        [h[0] << k, (h[1] << k) | (h[0] >> (128 - k))],
        h[1] >> (128 - k),
    )
}

impl Mul for Gf256 {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let ([a0, a1], [b0, b1]) = (self.0, other.0);
        // Karatsuba: the 512-bit product as four u128 limbs.
        let (z0l, z0h) = clmul128(a0, b0);
        let (z2l, z2h) = clmul128(a1, b1);
        let (m_l, m_h) = clmul128(a0 ^ a1, b0 ^ b1);
        let (z1l, z1h) = (m_l ^ z0l ^ z2l, m_h ^ z0h ^ z2h);
        let lo = [z0l, z0h ^ z1l];
        let hi = [z2l ^ z1h, z2h];
        // Reduce: x²⁵⁶ = x¹⁰ + x⁵ + x² + 1.  The shifted copies of `hi`
        // push at most ten bits past x²⁵⁵; those fold back once more, low
        // enough never to spill again.
        let (s2, p2) = shl(hi, 2);
        let (s5, p5) = shl(hi, 5);
        let (s10, p10) = shl(hi, 10);
        let spill = p2 ^ p5 ^ p10;
        let fold = spill ^ (spill << 2) ^ (spill << 5) ^ (spill << 10);
        Self([
            lo[0] ^ hi[0] ^ s2[0] ^ s5[0] ^ s10[0] ^ fold,
            lo[1] ^ hi[1] ^ s2[1] ^ s5[1] ^ s10[1],
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook multiplication with reduction, bit by bit.
    fn reference(a: Gf256, b: Gf256) -> Gf256 {
        let mut r = Gf256::ZERO;
        let mut a = a.0;
        for i in 0..256 {
            if b.bit(i) {
                r += Gf256(a);
            }
            let carry = a[1] >> 127;
            a = [a[0] << 1, (a[1] << 1) | (a[0] >> 127)];
            if carry == 1 {
                a[0] ^= 0x425; // x¹⁰ + x⁵ + x² + 1
            }
        }
        r
    }

    fn xorshift(s: &mut u128) -> u128 {
        *s ^= *s << 13;
        *s ^= *s >> 7;
        *s ^= *s << 17;
        *s
    }

    #[test]
    fn multiplication_matches_the_schoolbook() {
        let mut s = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128;
        for _ in 0..200 {
            let a = Gf256([xorshift(&mut s), xorshift(&mut s)]);
            let b = Gf256([xorshift(&mut s), xorshift(&mut s)]);
            assert_eq!(a * b, reference(a, b));
        }
        // x²⁵⁵ · x = x¹⁰ + x⁵ + x² + 1, and the largest spill folds back.
        assert_eq!(Gf256::x_pow(255) * Gf256::x_pow(1), Gf256([0x425, 0]));
        let all = Gf256([u128::MAX, u128::MAX]);
        assert_eq!(all * all, reference(all, all));
        assert_eq!(all * Gf256::ONE, all);
        assert_eq!(Gf256([5, 7]) * Gf256::ZERO, Gf256::ZERO);
        assert_eq!(Gf256([9, 1]).times_bit(false), Gf256::ZERO);
        let x = Gf256::from_bytes(all.to_bytes());
        assert_eq!(x, all);
    }

    /// Polynomials over GF(2) of up to 320 bits, for the field test.
    type Poly = [u64; 5];

    fn degree(p: &Poly) -> Option<usize> {
        (0..320).rev().find(|i| (p[i / 64] >> (i % 64)) & 1 == 1)
    }

    /// `a mod b`.
    fn rem(mut a: Poly, b: &Poly) -> Poly {
        let db = degree(b).unwrap();
        while let Some(da) = degree(&a).filter(|d| *d >= db) {
            let k = da - db;
            for i in (0..320).filter(|i| (b[i / 64] >> (i % 64)) & 1 == 1) {
                a[(i + k) / 64] ^= 1 << ((i + k) % 64);
            }
        }
        a
    }

    fn gcd(mut a: Poly, mut b: Poly) -> Poly {
        while degree(&b).is_some() {
            (a, b) = (b, rem(a, &b));
        }
        a
    }

    #[test]
    fn the_modulus_is_irreducible() {
        // Rabin's test for degree 256, whose only prime factor is 2:
        // x^(2²⁵⁶) ≡ x, and gcd(x^(2¹²⁸) − x, f) = 1.
        let x = Gf256::x_pow(1);
        let mut p = x;
        for _ in 0..128 {
            p = p * p;
        }
        let half = p + x;
        for _ in 0..128 {
            p = p * p;
        }
        assert_eq!(p, x);
        let f: Poly = [0x425, 0, 0, 0, 1];
        let [lo, hi] = half.0;
        let (lo0, lo1) = halves(lo);
        let (hi0, hi1) = halves(hi);
        let g: Poly = [lo0, lo1, hi0, hi1, 0];
        assert_eq!(degree(&gcd(f, g)), Some(0));
    }
}
