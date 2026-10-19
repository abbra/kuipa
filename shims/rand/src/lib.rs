//! The part of the `rand` 0.10 API that `hickory` uses (DNS query ids,
//! source ports, name case randomisation, server start-up jitter), with
//! every value from OpenSSL's DRBG (`RAND_bytes`) through native-ossl, so
//! no `RustCrypto` generator (`chacha20`) is linked.
//!
//! Patched in for `rand` in the workspace `Cargo.toml`.  Generator failures
//! panic, as `rand`'s thread generator does when the OS source fails.

use std::ops::{Range, RangeInclusive};

fn fill(buf: &mut [u8]) {
    native_ossl::rand::Rand::fill(buf).expect("OpenSSL random generator failed");
}

/// Types with uniformly random values.
pub trait Random: Sized {
    /// A uniformly random value.
    fn random() -> Self;
}

macro_rules! ints {
    ($($t:ty),*) => {$(
        impl Random for $t {
            fn random() -> Self {
                let mut b = [0u8; size_of::<$t>()];
                fill(&mut b);
                <$t>::from_ne_bytes(b)
            }
        }
    )*};
}

ints!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize
);

impl Random for bool {
    fn random() -> Self {
        u8::random() & 1 == 1
    }
}

/// A uniformly random value of type `T`.
#[must_use]
pub fn random<T: Random>() -> T {
    T::random()
}

/// Ranges of integers to sample from.
pub trait SampleRange<T> {
    /// A uniformly random value in the range.
    ///
    /// # Panics
    ///
    /// For an empty range.
    fn sample(self) -> T;
}

/// A uniform value in `0..=span` (`span` as u128), by rejection sampling.
fn below_or_at(span: u128) -> u128 {
    if span == u128::MAX {
        return u128::random();
    }
    let n = span + 1;
    // The largest multiple of n that fits; values above it are rejected.
    let zone = u128::MAX - (u128::MAX - n + 1) % n;
    loop {
        let v = u128::random();
        if v <= zone {
            return v % n;
        }
    }
}

macro_rules! ranges {
    ($($t:ty),*) => {$(
        impl SampleRange<$t> for RangeInclusive<$t> {
            // Two's complement in i128 holds every span of these types;
            // the offset added to `lo` lands back in range by construction.
            #[allow(
                clippy::cast_lossless,
                clippy::cast_possible_truncation,
                clippy::cast_possible_wrap,
                clippy::cast_sign_loss
            )]
            fn sample(self) -> $t {
                let (lo, hi) = self.into_inner();
                assert!(lo <= hi, "empty range");
                let span = (hi as i128).wrapping_sub(lo as i128) as u128;
                ((lo as i128).wrapping_add(below_or_at(span) as i128)) as $t
            }
        }

        impl SampleRange<$t> for Range<$t> {
            fn sample(self) -> $t {
                assert!(self.start < self.end, "empty range");
                (self.start..=self.end - 1).sample()
            }
        }
    )*};
}

ranges!(u8, u16, u32, u64, usize, i8, i16, i32, i64, isize);

/// A uniformly random value in `range`.
///
/// # Panics
///
/// For an empty range.
pub fn random_range<T, R: SampleRange<T>>(range: R) -> T {
    range.sample()
}

/// The generator handle `rand::rng()` returns.
#[derive(Clone, Copy, Debug, Default)]
pub struct ThreadRng;

/// The thread generator: here, OpenSSL's DRBG.
#[must_use]
pub fn rng() -> ThreadRng {
    ThreadRng
}

/// Sampling methods on a generator.
pub trait RngExt {
    /// A uniformly random value of type `T`.
    fn random<T: Random>(&mut self) -> T {
        T::random()
    }

    /// A uniformly random value in `range`.
    ///
    /// # Panics
    ///
    /// For an empty range.
    fn random_range<T, R: SampleRange<T>>(&mut self, range: R) -> T {
        range.sample()
    }
}

impl RngExt for ThreadRng {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges_stay_in_bounds_and_cover_them() {
        let mut seen = [false; 6];
        for _ in 0..2000 {
            let v = random_range(10u16..=15);
            assert!((10..=15).contains(&v));
            seen[usize::from(v - 10)] = true;
            assert!((1u64..32).contains(&random_range(1u64..32)));
            let s = random_range(-3i32..3);
            assert!((-3..3).contains(&s));
        }
        assert!(seen.iter().all(|s| *s), "every value appears");
        assert_eq!(random_range(7u8..=7), 7);
        let _: u16 = rng().random();
        let _ = random_range(0u64..=u64::MAX);
        let _ = random_range(i64::MIN..=i64::MAX);
    }

    #[test]
    fn values_vary() {
        let a: u128 = random();
        let b: u128 = random();
        assert_ne!(a, b);
    }

    #[test]
    #[should_panic(expected = "empty range")]
    fn empty_ranges_panic() {
        let _ = random_range(5u16..5);
    }
}
