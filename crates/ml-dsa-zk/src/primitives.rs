//! What the proofs take from OpenSSL: AES-128-CTR as the PRG that
//! expands tree nodes and leaves, and SHAKE256 for commitments and the
//! Fiat–Shamir transcript.

use native_ossl::cipher::CipherAlg;
use native_ossl::digest::{DigestAlg, DigestCtx};

use crate::Result;

/// A 128-bit seed.
pub type Seed = [u8; 16];

/// AES-128-CTR under `key`, IV zero: the PRG.
pub struct Prg {
    alg: CipherAlg,
}

impl Prg {
    /// Fetch AES-128-CTR.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn new() -> Result<Self> {
        Ok(Self {
            alg: CipherAlg::fetch(c"AES-128-CTR", None)?,
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
        let mut out = [0u8; 32];
        self.expand(node, &mut out)?;
        let mut left = [0u8; 16];
        let mut right = [0u8; 16];
        left.copy_from_slice(&out[..16]);
        right.copy_from_slice(&out[16..]);
        Ok((left, right))
    }
}

/// SHAKE256 over domain-separated, length-prefixed parts.
///
/// # Errors
///
/// An OpenSSL error.
pub fn shake(domain: &str, parts: &[&[u8]], out: &mut [u8]) -> Result<()> {
    let mut ctx = DigestAlg::fetch(c"SHAKE256", None)?.new_context()?;
    absorb(&mut ctx, domain.as_bytes())?;
    for p in parts {
        absorb(&mut ctx, p)?;
    }
    ctx.finish_xof(out)?;
    Ok(())
}

fn absorb(ctx: &mut DigestCtx, data: &[u8]) -> Result<()> {
    ctx.update(&(data.len() as u64).to_le_bytes())?;
    ctx.update(data)?;
    Ok(())
}

/// A Fiat–Shamir transcript: every prover message is absorbed, length
/// prefixed under a label, and challenges are squeezed from a copy.
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
        let mut ctx = DigestAlg::fetch(c"SHAKE256", None)?.new_context()?;
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

    /// A challenge of `out.len()` bytes under `label`; it is absorbed
    /// too, so later challenges depend on it.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn challenge(&mut self, label: &str, out: &mut [u8]) -> Result<()> {
        let mut copy = self.ctx.fork()?;
        absorb(&mut copy, label.as_bytes())?;
        copy.finish_xof(out)?;
        self.absorb(label, out)
    }
}
