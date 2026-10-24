//! The proof's binary field, and the security level that picks it.
//!
//! A proof at level λ commits with VOLE over GF(2^λ): λ trees' worth of
//! `Δ` bits, λ-bit MACs and challenges.  The system crypto policy picks
//! λ, as it picks the ML-DSA parameter set: λ = 128 while it allows a
//! category 2 or 3 signer, λ = 256 when it allows only ML-DSA-87 (CNSA
//! 2.0), so a CNSA deployment's proofs are as strong as its signatures.

use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul};

use native_ossl::system_policy::SystemPolicy;

use crate::gf128::Gf;
use crate::gf256::Gf256;
use crate::{Error, Result};

/// GF(2^λ), as the proof uses it.
pub trait Field:
    Copy + Default + Debug + Eq + Add<Output = Self> + AddAssign + Mul<Output = Self>
{
    /// λ: the field's bits.
    const BITS: usize;
    /// 0.
    const ZERO: Self;
    /// `xᵗ`, for `t < BITS`.
    #[must_use]
    fn x_pow(t: usize) -> Self;
    /// `self` if `bit`, else 0, without a branch.
    #[must_use]
    fn times_bit(self, bit: bool) -> Self;
    /// The coefficient of `xⁱ`.
    #[must_use]
    fn bit(self, i: usize) -> bool;
    /// The `BITS / 8` little-endian bytes.
    #[must_use]
    fn to_vec(self) -> Vec<u8>;
    /// From `BITS / 8` little-endian bytes.
    ///
    /// # Panics
    ///
    /// For another length.
    #[must_use]
    fn from_slice(bytes: &[u8]) -> Self;
}

impl Field for Gf {
    const BITS: usize = 128;
    const ZERO: Self = Self::ZERO;
    fn x_pow(t: usize) -> Self {
        Self::x_pow(t)
    }
    fn times_bit(self, bit: bool) -> Self {
        Self::times_bit(self, bit)
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

impl Field for Gf256 {
    const BITS: usize = 256;
    const ZERO: Self = Self::ZERO;
    fn x_pow(t: usize) -> Self {
        Self::x_pow(t)
    }
    fn times_bit(self, bit: bool) -> Self {
        Self::times_bit(self, bit)
    }
    fn bit(self, i: usize) -> bool {
        Self::bit(self, i)
    }
    fn to_vec(self) -> Vec<u8> {
        self.to_bytes().to_vec()
    }
    fn from_slice(bytes: &[u8]) -> Self {
        Self::from_bytes(bytes.try_into().expect("32 bytes"))
    }
}

/// A proof's security level λ.  Levels are ordered: a verifier that
/// requires one accepts it and every stronger one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Level {
    /// λ = 128, over GF(2¹²⁸), with 16 trees: NIST category 1, for
    /// deployments whose policy allows ML-DSA-44 or ML-DSA-65.
    L128,
    /// λ = 256, over GF(2²⁵⁶), with 32 trees: category 5, for a CNSA 2.0
    /// policy, which allows only ML-DSA-87.
    L256,
}

impl Level {
    /// λ.
    #[must_use]
    pub const fn lambda(self) -> usize {
        match self {
            Self::L128 => 128,
            Self::L256 => 256,
        }
    }

    /// The level `policy` calls for: 256 when it allows ML-DSA-87 alone,
    /// 128 while it allows a weaker set.
    #[must_use]
    pub fn for_policy(policy: &SystemPolicy) -> Self {
        if policy.allows_ml_dsa(44) || policy.allows_ml_dsa(65) {
            Self::L128
        } else {
            Self::L256
        }
    }

    /// The level the system crypto policy calls for ([`for_policy`]).
    ///
    /// [`for_policy`]: Self::for_policy
    ///
    /// # Errors
    ///
    /// [`Error::OpenSsl`] when the policy cannot be read: callers fail
    /// closed rather than guess a level.
    pub fn from_system() -> Result<Self> {
        Ok(Self::for_policy(SystemPolicy::current()?))
    }

    pub(crate) const fn id(self) -> u8 {
        match self {
            Self::L128 => 1,
            Self::L256 => 2,
        }
    }

    pub(crate) fn from_id(id: u8) -> Result<Self> {
        match id {
            1 => Ok(Self::L128),
            2 => Ok(Self::L256),
            _ => Err(Error::Malformed("proof level")),
        }
    }
}
