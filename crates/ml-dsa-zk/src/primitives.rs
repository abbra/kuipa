//! What the proofs take from OpenSSL, CNSA 2.0's general-purpose
//! algorithms only: AES-256-CTR as the PRG that expands tree nodes and
//! leaves, and SHA-512 for commitments, digests and the Fiat–Shamir
//! transcript.  SHA-3 and SHAKE are not used: CNSA 2.0 allows them only
//! inside an algorithm that prescribes them, as ML-DSA does — which is
//! why the [`keccak`](crate::keccak) gadget *evaluates* Keccak in the
//! statement, while the proof itself never hashes with it.

use native_ossl::cipher::CipherAlg;
use native_ossl::digest::{DigestAlg, DigestCtx};

use crate::Result;

/// A 256-bit seed: an AES-256 key.
pub type Seed = [u8; 32];

/// A SHA-512 output.
pub type Hash = [u8; 64];

/// AES-256-CTR under `key`, IV zero: the PRG.
pub struct Prg {
    alg: CipherAlg,
}

impl Prg {
    /// Fetch AES-256-CTR.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn new() -> Result<Self> {
        Ok(Self {
            alg: CipherAlg::fetch(c"AES-256-CTR", None)?,
        })
    }

    /// Fill `out` with the keystream of `key`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn expand(&self, key: &Seed, out: &mut [u8]) -> Result<()> {
        out.fill(0);
        let mut ctx = self.alg.encrypt(key, &[0u8; 16], None)?;
        ctx.update_in_place(out)?;
        Ok(())
    }

    /// A node's two children.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn children(&self, node: &Seed) -> Result<(Seed, Seed)> {
        let mut out = [0u8; 64];
        self.expand(node, &mut out)?;
        let mut left = [0u8; 32];
        let mut right = [0u8; 32];
        left.copy_from_slice(&out[..32]);
        right.copy_from_slice(&out[32..]);
        Ok((left, right))
    }
}

fn sha512() -> Result<DigestCtx> {
    Ok(DigestAlg::fetch(c"SHA2-512", None)?.new_context()?)
}

fn absorb(ctx: &mut DigestCtx, data: &[u8]) -> Result<()> {
    ctx.update(&(data.len() as u64).to_le_bytes())?;
    ctx.update(data)?;
    Ok(())
}

fn finish(ctx: &mut DigestCtx) -> Result<Hash> {
    let mut out = [0u8; 64];
    ctx.finish(&mut out)?;
    Ok(out)
}

/// SHA-512 over domain-separated, length-prefixed parts.
///
/// # Errors
///
/// An OpenSSL error.
pub fn hash(domain: &str, parts: &[&[u8]]) -> Result<Hash> {
    let mut ctx = sha512()?;
    absorb(&mut ctx, domain.as_bytes())?;
    for p in parts {
        absorb(&mut ctx, p)?;
    }
    finish(&mut ctx)
}

/// A Fiat–Shamir transcript over SHA-512: every prover message is
/// absorbed, length prefixed under a label.  A challenge is the counter
/// mode `SHA-512(state ‖ label ‖ i)`, `i = 0, 1, …`, over a copy of the
/// state, and is absorbed in turn, so later challenges depend on it.
pub struct Transcript {
    ctx: DigestCtx,
}

impl Transcript {
    /// A transcript for protocol `domain`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn new(domain: &str) -> Result<Self> {
        let mut ctx = sha512()?;
        absorb(&mut ctx, domain.as_bytes())?;
        Ok(Self { ctx })
    }

    /// Absorb `data` under `label`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn absorb(&mut self, label: &str, data: &[u8]) -> Result<()> {
        absorb(&mut self.ctx, label.as_bytes())?;
        absorb(&mut self.ctx, data)
    }

    /// A challenge of `out.len()` bytes under `label`.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn challenge(&mut self, label: &str, out: &mut [u8]) -> Result<()> {
        for (i, chunk) in out.chunks_mut(64).enumerate() {
            let mut copy = self.ctx.fork()?;
            absorb(&mut copy, label.as_bytes())?;
            absorb(&mut copy, &(i as u64).to_le_bytes())?;
            let block = finish(&mut copy)?;
            chunk.copy_from_slice(&block[..chunk.len()]);
        }
        self.absorb(label, out)
    }
}
