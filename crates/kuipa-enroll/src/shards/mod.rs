//! Recovery shards: a recovery key hidden under a passphrase, split into N-of-M paper shares, each
//! written as words with Reed-Solomon check words (`docs/DESIGN-recovery.md` §2.1).
//!
//! This module is the pure part: Shamir's scheme over GF(256), the word code, the share format,
//! the passphrase mask and the recovery key a seed makes. It does no I/O and knows nothing of the
//! server; the seed it protects is 32 bytes.
//!
//! A share is `HEADER_WORDS + SALT_WORDS + SECRET_WORDS` data words and `parity` check words:
//!
//! ```text
//! header  5 words   version(4) set id(19) kem(1) threshold-1(4) shares-1(4) index-1(4) iterations(6) parity(8)
//! salt   13 words   the 16-byte PBKDF2 salt, 2 zero bits of padding
//! secret 26 words   this share's 32 bytes, 4 zero bits of padding
//! parity  P words   Reed-Solomon over GF(2^10), roots alpha^1..alpha^P
//! ```
//!
//! Words are written most significant bit first.

mod gf;
mod rs;
mod wordlist;

use gf::Gf256;
use native_ossl::digest::DigestAlg;
use native_ossl::kdf::Pbkdf2Builder;
use native_ossl::rand::Rand;
use std::fmt;
use unicode_normalization::UnicodeNormalization;

pub use rs::Repair;
pub use wordlist::{lookup, word};

/// The label of the recovery key's seed derivation ([`recovery_key`]).
const RECOVERY_DOMAIN: tang_pqc::primitives::Domain =
    tang_pqc::primitives::Domain::new("ipa-ku recovery key v1");

/// The format version a share's header carries.
pub const VERSION: u8 = 1;
/// Words of a share's header.
pub const HEADER_WORDS: usize = 5;
/// Words of a share's salt.
pub const SALT_WORDS: usize = 13;
/// Words of a share's secret bytes.
pub const SECRET_WORDS: usize = 26;
/// Words before the check words.
pub const DATA_WORDS: usize = HEADER_WORDS + SALT_WORDS + SECRET_WORDS;
/// The fewest and most check words a share may have.
pub const PARITY_RANGE: std::ops::RangeInclusive<u8> = 4..=200;
/// The largest set id a share header carries (19 bits).
pub const MAX_SET_ID: u32 = 0x7_FFFF;
/// Check words unless asked otherwise.
pub const DEFAULT_PARITY: u8 = 24;
/// The most shares in a set.
pub const MAX_SHARES: u8 = 16;
/// PBKDF2 iterations are counted in units of this many.
pub const ITERATION_UNIT: u32 = 100_000;
/// The iteration count the header's 6 bits allow, in units.
pub const ITERATION_RANGE: std::ops::RangeInclusive<u8> = 1..=63;
/// Iterations (in units) unless asked otherwise: 2 million.
pub const DEFAULT_ITERATIONS: u8 = 20;
/// Words on a printed line.
pub const WORDS_PER_LINE: usize = 5;
/// The shortest passphrase `kuipa` accepts without being told to, in characters.
pub const MIN_PASSPHRASE_CHARS: usize = 16;

/// Why a shard could not be made or read.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A parameter is outside what a share can say.
    Parameters(&'static str),
    /// The share has more damage than its check words can repair, or too many words are lost.
    Unreadable,
    /// The words decode, but not to a share: a wrong length, an unknown version, a header that
    /// contradicts itself.
    Malformed(&'static str),
    /// The shares do not belong together.
    Mixed(&'static str),
    /// Fewer shares than the threshold.
    NotEnough {
        /// How many different shares were given.
        have: usize,
        /// How many are needed.
        need: usize,
    },
    /// OpenSSL failed.
    Crypto(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Parameters(why) => write!(f, "{why}"),
            Error::Unreadable => write!(
                f,
                "the share is too damaged to read: too many words are lost or wrong"
            ),
            Error::Malformed(why) => write!(f, "not a recovery share: {why}"),
            Error::Mixed(why) => write!(f, "these shares do not belong together: {why}"),
            Error::NotEnough { have, need } => write!(f, "{have} share(s) given, {need} needed"),
            Error::Crypto(why) => write!(f, "{why}"),
        }
    }
}

impl std::error::Error for Error {}

/// A value known to be small, as a byte (saturating, which the callers' ranges never reach).
fn small(value: u32) -> u8 {
    u8::try_from(value).unwrap_or(u8::MAX)
}

fn crypto(e: impl fmt::Display) -> Error {
    Error::Crypto(e.to_string())
}

/// What the header of a share says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    /// Identifies the set the share belongs to (19 bits), so shares of two sets are not mixed.
    pub set_id: u32,
    /// Whether the recovery key is ML-KEM-1024 (CNSA 2.0) and not ML-KEM-768.
    pub kem_1024: bool,
    /// How many shares recombine the seed.
    pub threshold: u8,
    /// How many shares the set has.
    pub shares: u8,
    /// This share's place, from 1; it is also Shamir's x-coordinate.
    pub index: u8,
    /// PBKDF2 iterations, in units of [`ITERATION_UNIT`].
    pub iterations: u8,
    /// Check words after the data words.
    pub parity: u8,
}

/// One share: what a printed page carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The header.
    pub header: Header,
    /// The PBKDF2 salt, the same in every share of a set.
    pub salt: [u8; 16],
    /// This share's 32 bytes of the hidden seed.
    pub secret: [u8; 32],
}

/// The seed recovered from enough shares: still hidden under the passphrase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Combined {
    /// The hidden seed; [`mask`] with the passphrase gives the seed.
    pub hidden: [u8; 32],
    /// The PBKDF2 salt.
    pub salt: [u8; 16],
    /// PBKDF2 iterations, in units of [`ITERATION_UNIT`].
    pub iterations: u8,
    /// The set the shares belong to.
    pub set_id: u32,
    /// Whether the recovery key is ML-KEM-1024.
    pub kem_1024: bool,
}

struct BitWriter {
    words: Vec<u16>,
    acc: u32,
    bits: u32,
}

impl BitWriter {
    fn new() -> Self {
        BitWriter {
            words: Vec::new(),
            acc: 0,
            bits: 0,
        }
    }

    fn put(&mut self, value: u32, width: u32) {
        for shift in (0..width).rev() {
            self.acc = (self.acc << 1) | ((value >> shift) & 1);
            self.bits += 1;
            if self.bits == 10 {
                self.words.push(u16::try_from(self.acc).unwrap_or(0));
                self.acc = 0;
                self.bits = 0;
            }
        }
    }

    /// Pads with zero bits to a word boundary.
    fn align(&mut self) {
        while self.bits != 0 {
            self.put(0, 1);
        }
    }
}

struct BitReader<'a> {
    words: &'a [u16],
    bit: usize,
}

impl BitReader<'_> {
    fn take(&mut self, width: u32) -> u32 {
        let mut value = 0;
        for _ in 0..width {
            let word = self.words[self.bit / 10];
            value = (value << 1) | u32::from((word >> (9 - self.bit % 10)) & 1);
            self.bit += 1;
        }
        value
    }

    /// Skips to a word boundary, which must be zero padding.
    fn align(&mut self) -> Result<(), Error> {
        while !self.bit.is_multiple_of(10) {
            if self.take(1) != 0 {
                return Err(Error::Malformed("padding is not zero"));
            }
        }
        Ok(())
    }

    fn bytes<const N: usize>(&mut self) -> Result<[u8; N], Error> {
        let mut out = [0u8; N];
        for byte in &mut out {
            *byte = small(self.take(8));
        }
        self.align()?;
        Ok(out)
    }
}

impl Share {
    /// The share's words as 10-bit symbols: data, then check words.
    #[must_use]
    pub fn symbols(&self) -> Vec<u16> {
        let h = &self.header;
        let mut w = BitWriter::new();
        w.put(u32::from(VERSION), 4);
        w.put(h.set_id & 0x7_FFFF, 19);
        w.put(u32::from(h.kem_1024), 1);
        w.put(u32::from(h.threshold.saturating_sub(1)), 4);
        w.put(u32::from(h.shares.saturating_sub(1)), 4);
        w.put(u32::from(h.index.saturating_sub(1)), 4);
        w.put(u32::from(h.iterations), 6);
        w.put(u32::from(h.parity), 8);
        for &b in &self.salt {
            w.put(u32::from(b), 8);
        }
        w.align();
        for &b in &self.secret {
            w.put(u32::from(b), 8);
        }
        w.align();
        let mut words = w.words;
        debug_assert_eq!(words.len(), DATA_WORDS);
        let check = rs::parity_of(&words, usize::from(h.parity));
        words.extend(check);
        words
    }

    /// Reads a share from its words, `None` where a word is lost or unreadable. The length says how
    /// many check words there are, so the list must be as long as the share was.
    ///
    /// Returns the share and what was repaired.
    ///
    /// # Errors
    ///
    /// [`Error::Unreadable`] when too much is lost or wrong, [`Error::Malformed`] when what is
    /// left is not a share.
    pub fn from_symbols(symbols: &[Option<u16>]) -> Result<(Share, Repair), Error> {
        let parity = symbols
            .len()
            .checked_sub(DATA_WORDS)
            .ok_or(Error::Malformed("too short for a share"))?;
        if !PARITY_RANGE
            .contains(&u8::try_from(parity).map_err(|_| Error::Malformed("too long for a share"))?)
        {
            return Err(Error::Malformed(
                "the number of check words is out of range",
            ));
        }
        if symbols.iter().flatten().any(|&s| s >= 1024) {
            return Err(Error::Malformed("a symbol is not 10 bits"));
        }
        let lost: Vec<usize> = symbols
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_none())
            .map(|(i, _)| i)
            .collect();
        let mut word: Vec<u16> = symbols.iter().map(|s| s.unwrap_or(0)).collect();
        let repair = rs::decode(&mut word, &lost, parity).map_err(|_| Error::Unreadable)?;

        let mut r = BitReader {
            words: &word[..DATA_WORDS],
            bit: 0,
        };
        if r.take(4) != u32::from(VERSION) {
            return Err(Error::Malformed("unknown format version"));
        }
        let set_id = r.take(19);
        let kem_1024 = r.take(1) == 1;
        let threshold = small(r.take(4) + 1);
        let shares = small(r.take(4) + 1);
        let index = small(r.take(4) + 1);
        let iterations = small(r.take(6));
        let declared = usize::from(small(r.take(8)));
        if declared != parity {
            return Err(Error::Malformed(
                "the header disagrees with the length about the check words",
            ));
        }
        if threshold < 2
            || threshold > shares
            || index > shares
            || !ITERATION_RANGE.contains(&iterations)
        {
            return Err(Error::Malformed("the header is not consistent"));
        }
        let salt = r.bytes::<16>()?;
        let secret = r.bytes::<32>()?;
        let header = Header {
            set_id,
            kem_1024,
            threshold,
            shares,
            index,
            iterations,
            parity: small(u32::try_from(parity).unwrap_or(u32::MAX)),
        };
        Ok((
            Share {
                header,
                salt,
                secret,
            },
            repair,
        ))
    }
}

/// Splits `secret` bytewise with Shamir's scheme: `shares` shares, any `threshold` of which give it
/// back. `fill` provides the random coefficients.
fn split(
    secret: &[u8; 32],
    threshold: u8,
    shares: u8,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<[u8; 32]>, Error> {
    let mut out = vec![[0u8; 32]; usize::from(shares)];
    let mut coefficients = vec![0u8; usize::from(threshold) - 1];
    for (position, &byte) in secret.iter().enumerate() {
        fill(&mut coefficients)?;
        for (share, x) in out.iter_mut().zip(1u8..) {
            // Horner over a_0 = byte, a_1.. = coefficients
            let mut y = 0u8;
            for &a in coefficients.iter().rev() {
                y = Gf256::mul(y ^ a, x);
            }
            share[position] = y ^ byte;
        }
    }
    Ok(out)
}

/// The secret from `threshold` points `(x, share)`: Lagrange interpolation at zero.
fn interpolate(points: &[(u8, &[u8; 32])]) -> [u8; 32] {
    let mut secret = [0u8; 32];
    for (i, &(xi, yi)) in points.iter().enumerate() {
        let mut weight = 1u8;
        for (j, &(xj, _)) in points.iter().enumerate() {
            if i != j {
                weight = Gf256::mul(weight, Gf256::div(xj, xi ^ xj));
            }
        }
        for (s, &y) in secret.iter_mut().zip(yi) {
            *s ^= Gf256::mul(y, weight);
        }
    }
    secret
}

fn random(buf: &mut [u8]) -> Result<(), Error> {
    Rand::fill_private(buf).map_err(crypto)
}

/// What a set of shares is to look like.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SetParams {
    /// How many shares recombine the seed (2 to `shares`).
    pub threshold: u8,
    /// How many shares to make (at most [`MAX_SHARES`]).
    pub shares: u8,
    /// PBKDF2 iterations, in units of [`ITERATION_UNIT`].
    pub iterations: u8,
    /// Check words per share.
    pub parity: u8,
    /// Whether the recovery key is ML-KEM-1024 (CNSA 2.0) and not ML-KEM-768.
    pub kem_1024: bool,
}

impl SetParams {
    /// A threshold of `threshold` out of `shares`, with the default cost and check words.
    #[must_use]
    pub fn new(threshold: u8, shares: u8, kem_1024: bool) -> Self {
        SetParams {
            threshold,
            shares,
            iterations: DEFAULT_ITERATIONS,
            parity: DEFAULT_PARITY,
            kem_1024,
        }
    }
}

/// Makes a set of shares for a seed already hidden under the passphrase ([`mask`]).
///
/// # Errors
///
/// [`Error::Parameters`] for a threshold below 2, more shares than [`MAX_SHARES`] or fewer than the
/// threshold, an iteration count or parity outside their ranges; [`Error::Crypto`] if OpenSSL has
/// no random bytes.
pub fn make_shares(
    hidden: &[u8; 32],
    salt: [u8; 16],
    params: SetParams,
) -> Result<Vec<Share>, Error> {
    make_shares_with(hidden, salt, params, &mut random)
}

fn make_shares_with(
    hidden: &[u8; 32],
    salt: [u8; 16],
    params: SetParams,
    fill: &mut dyn FnMut(&mut [u8]) -> Result<(), Error>,
) -> Result<Vec<Share>, Error> {
    let SetParams {
        threshold,
        shares,
        iterations,
        parity,
        kem_1024,
    } = params;
    if threshold < 2 {
        return Err(Error::Parameters(
            "the threshold is at least 2: one share would be the whole key",
        ));
    }
    if shares > MAX_SHARES || shares < threshold {
        return Err(Error::Parameters(
            "a set has at least the threshold and at most 16 shares",
        ));
    }
    if !ITERATION_RANGE.contains(&iterations) {
        return Err(Error::Parameters(
            "the iteration count is 1 to 63 (in hundreds of thousands)",
        ));
    }
    if !PARITY_RANGE.contains(&parity) {
        return Err(Error::Parameters("the number of check words is 4 to 200"));
    }
    let mut id = [0u8; 3];
    fill(&mut id)?;
    let set_id =
        (u32::from(id[0]) << 11 | u32::from(id[1]) << 3 | u32::from(id[2]) >> 5) & 0x7_FFFF;
    let secrets = split(hidden, threshold, shares, fill)?;
    Ok(secrets
        .into_iter()
        .zip(1u8..)
        .map(|(secret, index)| Share {
            header: Header {
                set_id,
                kem_1024,
                threshold,
                shares,
                index,
                iterations,
                parity,
            },
            salt,
            secret,
        })
        .collect())
}

/// Recombines the hidden seed from shares of one set.
///
/// # Errors
///
/// [`Error::Mixed`] when the shares are of different sets or disagree about the set,
/// [`Error::NotEnough`] with fewer different shares than the threshold.
pub fn combine(shares: &[Share]) -> Result<Combined, Error> {
    let first = shares
        .first()
        .ok_or(Error::NotEnough { have: 0, need: 2 })?;
    let h = first.header;
    for s in shares {
        if s.header.set_id != h.set_id {
            return Err(Error::Mixed("they are from different sets"));
        }
        if s.header.threshold != h.threshold
            || s.header.shares != h.shares
            || s.header.iterations != h.iterations
            || s.header.kem_1024 != h.kem_1024
            || s.salt != first.salt
        {
            return Err(Error::Mixed("they disagree about the set's parameters"));
        }
    }
    let mut distinct: Vec<&Share> = Vec::new();
    for s in shares {
        if !distinct.iter().any(|d| d.header.index == s.header.index) {
            distinct.push(s);
        }
    }
    let need = usize::from(h.threshold);
    if distinct.len() < need {
        return Err(Error::NotEnough {
            have: distinct.len(),
            need,
        });
    }
    let points: Vec<(u8, &[u8; 32])> = distinct
        .iter()
        .take(need)
        .map(|s| (s.header.index, &s.secret))
        .collect();
    Ok(Combined {
        hidden: interpolate(&points),
        salt: first.salt,
        iterations: h.iterations,
        set_id: h.set_id,
        kem_1024: h.kem_1024,
    })
}

/// A new random PBKDF2 salt.
///
/// # Errors
///
/// [`Error::Crypto`] if OpenSSL has no random bytes.
pub fn new_salt() -> Result<[u8; 16], Error> {
    let mut salt = [0u8; 16];
    random(&mut salt)?;
    Ok(salt)
}

/// The passphrase as it is used: Unicode NFKC, so that it types the same on any keyboard.
#[must_use]
pub fn normalize_passphrase(passphrase: &str) -> String {
    passphrase.nfkc().collect()
}

/// Hides `seed` under the passphrase, or reveals it again: XOR with
/// `PBKDF2-HMAC-SHA-512(NFKC(passphrase), salt, iterations)[0..32]`. There is no check value on
/// purpose: a wrong passphrase gives a wrong seed, which only the key it makes can show.
///
/// # Errors
///
/// [`Error::Parameters`] for an iteration count outside its range, [`Error::Crypto`] if OpenSSL
/// fails.
pub fn mask(
    seed: &[u8; 32],
    passphrase: &str,
    salt: &[u8; 16],
    iterations: u8,
) -> Result<[u8; 32], Error> {
    if !ITERATION_RANGE.contains(&iterations) {
        return Err(Error::Parameters(
            "the iteration count is 1 to 63 (in hundreds of thousands)",
        ));
    }
    let md = DigestAlg::fetch(tang_pqc::primitives::SHA512, None).map_err(crypto)?;
    let normalized = normalize_passphrase(passphrase);
    let mut pad = [0u8; 32];
    Pbkdf2Builder::new(&md, normalized.as_bytes(), salt)
        .iterations(u32::from(iterations) * ITERATION_UNIT)
        .derive(&mut pad)
        .map_err(crypto)?;
    let mut out = *seed;
    for (o, p) in out.iter_mut().zip(pad) {
        *o ^= p;
    }
    Ok(out)
}

/// The recovery key a seed makes: the ML-KEM key pair FIPS 203 key generation makes from
/// `d ‖ z = HKDF(ikm = s, salt = label, info = label ‖ " seed")` by the KEM's hash, the label
/// `ipa-ku recovery key v1`. A share's header says which KEM, so a page decodes to its key with
/// nothing but the passphrase ([`mask`]) and this.
///
/// # Errors
///
/// [`Error::Crypto`] if OpenSSL fails or the system crypto policy disables the KEM.
pub fn recovery_key(seed: &[u8; 32], kem_1024: bool) -> Result<tang_pqc::ExchangeKeyPair, Error> {
    let alg = if kem_1024 {
        tang_pqc::KemAlg::MlKem1024
    } else {
        tang_pqc::KemAlg::MlKem768
    };
    let mut dz = [0u8; 64];
    RECOVERY_DOMAIN
        .hkdf(alg.hash(), &[seed], "seed", &[], &mut dz)
        .map_err(crypto)?;
    tang_pqc::ExchangeKeyPair::from_seed_bytes(alg, &dz).map_err(crypto)
}

/// The words of a share as printed: numbered lines of [`WORDS_PER_LINE`], `01  word word ...`.
#[must_use]
pub fn format_lines(symbols: &[u16]) -> Vec<String> {
    symbols
        .chunks(WORDS_PER_LINE)
        .enumerate()
        .map(|(line, chunk)| {
            format!(
                "{:02}  {}",
                line + 1,
                chunk.iter().map(|&s| word(s)).collect::<Vec<_>>().join(" ")
            )
        })
        .collect()
}

/// Reads typed lines back into `total` symbols. A line starts with its number (without one it is
/// the line after the previous); a word that is not in the list, or `?`, is a lost word, and so is
/// every place no line mentions.
#[must_use]
pub fn parse_lines(text: &str, total: usize) -> Vec<Option<u16>> {
    let mut symbols = vec![None; total];
    let mut next_line = 1usize;
    for line in text.lines() {
        let mut tokens = line.split_whitespace().peekable();
        let Some(&first) = tokens.peek() else {
            continue;
        };
        let number = first
            .trim_end_matches(['.', ':', ')'])
            .parse::<usize>()
            .ok()
            .filter(|&n| n >= 1);
        if let Some(n) = number {
            next_line = n;
            tokens.next();
        }
        for (k, token) in tokens.take(WORDS_PER_LINE).enumerate() {
            if let Some(slot) = symbols.get_mut((next_line - 1) * WORDS_PER_LINE + k) {
                *slot = lookup(token);
            }
        }
        next_line += 1;
    }
    symbols
}

#[cfg(test)]
mod tests;
