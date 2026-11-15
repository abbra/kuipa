//! GF(2¹²⁸), as `x¹²⁸ + x⁷ + x² + x + 1`: the field the VOLE correlations
//! and QuickSilver checks live in.  Bit `i` of the `u128` is the
//! coefficient of `xⁱ`.  Multiplication is carry-less and branch-free, on the CPU's
//! carry-less multiply where it has one.

use std::ops::{Add, AddAssign, Mul};

use crate::clmul::clmul128;
use crate::field::Field;

/// An element of GF(2¹²⁸).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(crate) struct Gf(pub(crate) u128);

impl Gf {
    /// The little-endian bytes.
    #[must_use]
    pub(crate) const fn to_bytes(self) -> [u8; 16] {
        self.0.to_le_bytes()
    }

    /// From little-endian bytes.
    #[must_use]
    pub(crate) const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(u128::from_le_bytes(bytes))
    }
}

impl Field for Gf {
    const BITS: usize = 128;
    const ZERO: Self = Self(0);
    fn x_pow(t: usize) -> Self {
        Self(1 << t)
    }
    fn times_bit(self, bit: bool) -> Self {
        Self(self.0 & (0u128.wrapping_sub(u128::from(bit))))
    }
    fn bit(self, i: usize) -> bool {
        (self.0 >> i) & 1 == 1
    }
    fn to_vec(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes.try_into().expect("16 bytes"))
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

impl AddAssign for Gf {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

impl Mul for Gf {
    type Output = Self;
    fn mul(self, other: Self) -> Self {
        let (lo, hi) = clmul128(self.0, other.0);
        // Reduce: x¹²⁸ = x⁷ + x² + x + 1, twice for what the shifts push out.
        let spill = (hi >> 127) ^ (hi >> 126) ^ (hi >> 121);
        let folded = hi ^ (hi << 1) ^ (hi << 2) ^ (hi << 7);
        Self(lo ^ folded ^ spill ^ (spill << 1) ^ (spill << 2) ^ (spill << 7))
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
        assert_eq!(Gf(u128::MAX) * Gf::x_pow(0), Gf(u128::MAX));
        assert_eq!(Gf(5) * Gf::ZERO, Gf::ZERO);
        assert_eq!(Gf(9).times_bit(false), Gf::ZERO);
        assert_eq!(Gf(9).times_bit(true), Gf(9));
    }
}
