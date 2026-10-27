//! Finite fields for recovery shards: GF(256) for Shamir's scheme and GF(2^10) for the
//! Reed-Solomon code over the words.

use std::sync::OnceLock;

/// Exponent and logarithm tables of a field with `size` elements, from a primitive polynomial with
/// `x` (or 3, for the AES polynomial) as the generator.
struct Tables {
    exp: Vec<u16>,
    log: Vec<u16>,
}

impl Tables {
    fn build(size: usize, reduce: impl Fn(u32) -> u32, step: impl Fn(u32) -> u32) -> Tables {
        let order = size - 1;
        let mut exp = vec![0u16; 2 * order];
        let mut log = vec![0u16; size];
        let mut x = 1u32;
        for (i, slot) in exp[..order].iter_mut().enumerate() {
            let symbol = u16::try_from(x).expect("a field element");
            *slot = symbol;
            log[usize::from(symbol)] = u16::try_from(i).expect("an exponent");
            x = reduce(step(x));
        }
        exp.copy_within(0..order, order);
        Tables { exp, log }
    }

    fn mul(&self, a: u16, b: u16) -> u16 {
        if a == 0 || b == 0 {
            return 0;
        }
        self.exp[usize::from(self.log[usize::from(a)]) + usize::from(self.log[usize::from(b)])]
    }

    fn div(&self, a: u16, b: u16) -> u16 {
        debug_assert!(b != 0, "division by zero");
        if a == 0 {
            return 0;
        }
        let order = self.log.len() - 1;
        self.exp
            [usize::from(self.log[usize::from(a)]) + order - usize::from(self.log[usize::from(b)])]
    }
}

/// GF(2^10) with the primitive polynomial `x^10 + x^3 + 1` and `x` as the generator.
pub(crate) struct Gf1024;

const ORDER_1024: usize = 1023;

fn tables_1024() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        Tables::build(
            1024,
            |x| if x & 0x400 != 0 { x ^ 0x409 } else { x },
            |x| x << 1,
        )
    })
}

impl Gf1024 {
    /// `a * b`.
    pub(crate) fn mul(a: u16, b: u16) -> u16 {
        tables_1024().mul(a, b)
    }

    /// `1 / a`; `a` must not be zero.
    pub(crate) fn inv(a: u16) -> u16 {
        Self::div(1, a)
    }

    /// `a / b`; `b` must not be zero.
    pub(crate) fn div(a: u16, b: u16) -> u16 {
        tables_1024().div(a, b)
    }

    /// The generator to the power `e`.
    pub(crate) fn alpha(e: usize) -> u16 {
        tables_1024().exp[e % ORDER_1024]
    }
}

/// GF(256) with the AES polynomial `x^8 + x^4 + x^3 + x + 1`, as Shamir's scheme uses it. Its
/// generator is 3, not `x`: `x` has order 51 for this polynomial.
pub(crate) struct Gf256;

fn tables_256() -> &'static Tables {
    static TABLES: OnceLock<Tables> = OnceLock::new();
    TABLES.get_or_init(|| {
        Tables::build(
            256,
            |x| x,
            |x| {
                let doubled = x << 1;
                (if doubled & 0x100 != 0 {
                    doubled ^ 0x11B
                } else {
                    doubled
                }) ^ x
            },
        )
    })
}

impl Gf256 {
    /// `a * b`.
    pub(crate) fn mul(a: u8, b: u8) -> u8 {
        u8::try_from(tables_256().mul(u16::from(a), u16::from(b))).expect("a field element")
    }

    /// `a / b`; `b` must not be zero.
    pub(crate) fn div(a: u8, b: u8) -> u8 {
        u8::try_from(tables_256().div(u16::from(a), u16::from(b))).expect("a field element")
    }
}

#[cfg(test)]
mod tests {
    use super::{Gf256, Gf1024};

    #[test]
    fn gf256_matches_the_aes_field() {
        // FIPS 197 §4.2: {57} * {83} = {c1}
        assert_eq!(Gf256::mul(0x57, 0x83), 0xC1);
        for a in 1..=255u8 {
            assert_eq!(Gf256::mul(a, Gf256::div(1, a)), 1, "a = {a}");
        }
    }

    #[test]
    fn gf1024_generator_has_full_order_and_inverses_exist() {
        assert_eq!(Gf1024::alpha(0), 1);
        assert_eq!(Gf1024::alpha(1023), 1);
        let mut seen = std::collections::HashSet::new();
        for e in 0..1023 {
            assert!(
                seen.insert(Gf1024::alpha(e)),
                "alpha^{e} repeats: the polynomial is not primitive"
            );
        }
        for a in 1..1024u16 {
            assert_eq!(Gf1024::mul(a, Gf1024::inv(a)), 1);
        }
    }
}
