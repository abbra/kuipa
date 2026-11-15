//! 64×64 → 128 carry-less multiplication, the step both fields' products
//! are built from: the CPU's instruction where stable Rust reaches it
//! (`pclmulqdq` on `x86_64`, `pmull` on `aarch64`), found at run time, else a
//! portable branch-free loop.  All three compute the same product in
//! constant time; `ppc64le`, `s390x` and `riscv64` have instructions too, but
//! their intrinsics are not stable yet, so they take the loop.

/// `a · b` without carries.
#[must_use]
#[allow(unsafe_code)] // the crate's one exception: see the SAFETY notes
pub(crate) fn clmul64(a: u64, b: u64) -> u128 {
    #[cfg(target_arch = "x86_64")]
    if std::arch::is_x86_feature_detected!("pclmulqdq") {
        // SAFETY: the CPU has been found to support `pclmulqdq`.
        return unsafe { pclmul(a, b) };
    }
    #[cfg(target_arch = "aarch64")]
    if std::arch::is_aarch64_feature_detected!("aes") {
        // SAFETY: the CPU has been found to support `pmull` (FEAT_PMULL,
        // reported with the AES extension).
        return unsafe { pmull(a, b) };
    }
    portable(a, b)
}

/// The low and high 64-bit halves of `x`.
pub(crate) fn halves(x: u128) -> (u64, u64) {
    let lo = u64::try_from(x & u128::from(u64::MAX)).expect("masked to 64 bits");
    let hi = u64::try_from(x >> 64).expect("shifted to 64 bits");
    (lo, hi)
}

/// 128×128 → 256 carry-less multiplication by Karatsuba, as `(lo, hi)`.
pub(crate) fn clmul128(a: u128, b: u128) -> (u128, u128) {
    let (a0, a1) = halves(a);
    let (b0, b1) = halves(b);
    let z0 = clmul64(a0, b0);
    let z2 = clmul64(a1, b1);
    let z1 = clmul64(a0 ^ a1, b0 ^ b1) ^ z0 ^ z2;
    (z0 ^ (z1 << 64), z2 ^ (z1 >> 64))
}

/// The loop: one masked shift per bit of `b`.
fn portable(a: u64, b: u64) -> u128 {
    let a = u128::from(a);
    let mut r = 0u128;
    for i in 0..64 {
        let mask = 0u128.wrapping_sub(u128::from((b >> i) & 1));
        r ^= (a << i) & mask;
    }
    r
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "pclmulqdq")]
fn pclmul(a: u64, b: u64) -> u128 {
    use std::arch::x86_64::{
        _mm_clmulepi64_si128, _mm_cvtsi64_si128, _mm_cvtsi128_si64, _mm_srli_si128,
    };
    let lane = |x: u64| _mm_cvtsi64_si128(i64::from_ne_bytes(x.to_ne_bytes()));
    let r = _mm_clmulepi64_si128::<0x00>(lane(a), lane(b));
    let half = |x| u64::from_ne_bytes(_mm_cvtsi128_si64(x).to_ne_bytes());
    u128::from(half(r)) | (u128::from(half(_mm_srli_si128::<8>(r))) << 64)
}

#[cfg(target_arch = "aarch64")]
#[target_feature(enable = "aes")]
fn pmull(a: u64, b: u64) -> u128 {
    std::arch::aarch64::vmull_p64(a, b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_instruction_and_the_loop_agree() {
        let mut s = 0x9e37_79b9_7f4a_7c15_u64;
        let mut values = vec![0, 1, u64::MAX, 1 << 63];
        for _ in 0..500 {
            // xorshift for test values
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            values.push(s);
        }
        for &a in &values {
            for &b in values.iter().take(40) {
                assert_eq!(clmul64(a, b), portable(a, b), "{a:#x} · {b:#x}");
            }
        }
        // (x + 1)² = x² + 1 without carries.
        assert_eq!(portable(3, 3), 5);
        assert_eq!(portable(u64::MAX, 1), u128::from(u64::MAX));
    }
}
