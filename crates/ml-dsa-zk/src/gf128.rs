//! GF(2¹²⁸), as `x¹²⁸ + x⁷ + x² + x + 1`: the field the VOLE correlations
//! and QuickSilver checks live in.  Bit `i` of the `u128` is the
//! coefficient of `xⁱ`.  Multiplication is carry-less and branch-free.

use std::ops::{Add, AddAssign, Mul};

/// An element of GF(2¹²⁸).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Gf(pub u128);

impl Gf {
    /// 0.
    pub const ZERO: Self = Self(0);
    /// 1.
    pub const ONE: Self = Self(1);

    /// `xᵗ`, for `t < 128`.
    #[must_use]
    pub const fn x_pow(t: usize) -> Self {
        Self(1 << t)
    }

    /// `self` if `bit`, else 0, without a branch.
    #[must_use]
    pub const fn times_bit(self, bit: bool) -> Self {
        Self(self.0 & (0u128.wrapping_sub(bit as u128)))
    }

    /// The little-endian bytes.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// From little-endian bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(bytes))
    }
}

// Addition in characteristic 2 is XOR.
#[allow(clippy::suspicious_arithmetic_impl)]
impl Add for Gf {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self(self.0 ^ other.0)
    }
}

#[allow(clippy::suspicious_op_assign_impl)]
impl AddAssign for Gf {
    fn add_assign(&mut self, other: Self) {
        self.0 ^= other.0;
    }
}

/// 64×64 → 128 carry-less multiplication, branch-free.
fn clmul64(a: u64, b: u64) -> u128 {
    let a = u128::from(a);
    let mut r = 0u128;
    for i in 0..64 {
        let mask = 0u128.wrapping_sub(u128::from((b >> i) & 1));
        r ^= (a << i) & mask;
    }
    r
}

impl Mul for Gf {
    type Output = Self;
    #[allow(clippy::cast_possible_truncation)] // splitting into halves
    fn mul(self, other: Self) -> Self {
        let (a0, a1) = (self.0 as u64, (self.0 >> 64) as u64);
        let (b0, b1) = (other.0 as u64, (other.0 >> 64) as u64);
        // Karatsuba: the 256-bit product as (hi, lo).
        let z0 = clmul64(a0, b0);
        let z2 = clmul64(a1, b1);
        let z1 = clmul64(a0 ^ a1, b0 ^ b1) ^ z0 ^ z2;
        let lo = z0 ^ (z1 << 64);
        let hi = z2 ^ (z1 >> 64);
        // Reduce: x¹²⁸ = x⁷ + x² + x + 1, twice for what the shifts push out.
        let spill = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
        let folded = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
        let r = lo ^ folded ^ spill ^ (spill << 1) ^ (spill << 2) ^ (spill << 7);
        Self(r)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Schoolbook multiplication with reduction, bit by bit.
    fn reference(a: u128, b: u128) -> u128 {
        let mut r = 0u128;
        let mut a = a;
        for i in 0..128 {
            if (b >> i) & 1 == 1 {
                r ^= a;
            }
            let carry = a >> 127;
            a <<= 1;
            if carry == 1 {
                a ^= 0x87;
            }
        }
        r
    }

    #[test]
    fn multiplication_matches_the_schoolbook() {
        let mut s = 0x0123_4567_89ab_cdef_fedc_ba98_7654_3210_u128;
        for _ in 0..200 {
            // xorshift for test values
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            let t = s.rotate_left(41) ^ 0x5555;
            assert_eq!((Gf(s) * Gf(t)).0, reference(s, t));
        }
        // x¹²⁷ · x = x⁷ + x² + x + 1.
        assert_eq!((Gf::x_pow(127) * Gf::x_pow(1)).0, 0x87);
        assert_eq!(Gf(u128::MAX) * Gf::ONE, Gf(u128::MAX));
        assert_eq!(Gf(5) * Gf::ZERO, Gf::ZERO);
        assert_eq!(Gf(9).times_bit(false), Gf::ZERO);
        assert_eq!(Gf(9).times_bit(true), Gf(9));
    }
}
