//! Zero-knowledge proofs of knowledge over boolean circuits, by VOLE in
//! the head (FAEST-style), toward unlinkable ML-DSA blind signatures
//! (`crates/ml-dsa-blind/DESIGN.md` §6, this crate's `DESIGN.md`).
//!
//! **Research prototype.**  This is the proof core and its first
//! gadget: a prover shows it knows a circuit input that makes the
//! circuit's public outputs the given bits, revealing nothing else.
//! Proving knowledge of an ML-DSA signature also needs arithmetic over
//! `Z_q` and conversions between bits and `Z_q`, which are not here yet.
//! The construction has not been reviewed; do not rely on it.
//!
//! * [`circuit`]: boolean circuits (XOR, NOT, AND).
//! * [`proof`]: [`prove`] and [`verify`].
//! * [`keccak`]: Keccak-f\[1600\] as a circuit.
//! * [`field`]: the proof's field GF(2^λ), and the [`Level`] λ.
//!
//! The system crypto policy picks λ, as it picks ML-DSA parameter sets:
//! λ = 128 while it allows ML-DSA-44 or 65, λ = 256 when it allows only
//! ML-DSA-87 (CNSA 2.0).  [`prove`] proves at that level and [`verify`]
//! refuses anything weaker; [`prove_at`] and [`verify_at`] name a level.
//!
//! Everything cryptographic comes from OpenSSL, and from CNSA 2.0's
//! general-purpose algorithms only: AES-256-CTR expands the GGM trees,
//! SHA-512 commits and drives Fiat–Shamir.  Keccak appears only as what
//! a statement evaluates (ML-DSA's own SHAKE), never as the proof's hash.

pub mod circuit;
mod clmul;
pub mod field;
pub mod gf128;
pub mod gf256;
pub mod keccak;
pub mod primitives;
pub mod proof;

pub use circuit::{Circuit, Gate, Wire};
pub use field::Level;
pub use proof::{Proof, prove, prove_at, verify, verify_at};

/// Errors.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An OpenSSL error.
    OpenSsl(native_ossl::error::ErrorStack),
    /// Something of the wrong shape.
    Malformed(&'static str),
    /// A proof that does not verify.
    Invalid,
    /// A proof at a lower level than the verifier requires.
    Weak(Level),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OpenSsl(e) => write!(f, "{e}"),
            Self::Malformed(what) => write!(f, "malformed {what}"),
            Self::Invalid => f.write_str("the proof does not verify"),
            Self::Weak(level) => write!(
                f,
                "a λ = {} proof is weaker than the crypto policy requires",
                level.lambda()
            ),
        }
    }
}

impl std::error::Error for Error {}

impl From<native_ossl::error::ErrorStack> for Error {
    fn from(e: native_ossl::error::ErrorStack) -> Self {
        Self::OpenSsl(e)
    }
}

/// Results of this crate.
pub type Result<T> = std::result::Result<T, Error>;
