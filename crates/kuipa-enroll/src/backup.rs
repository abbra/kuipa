//! The sealed backup container `IPBK` (`docs/DESIGN-backup.md` §3): a stream
//! of AES-256-GCM chunks under a file key that each recipient's ML-KEM key
//! wraps.
//!
//! ```text
//! header_len(u32 BE) ‖ header ‖ chunk ‖ chunk ‖ …
//! header = "IPBK" ‖ 1 ‖ chunk_log2(u8) ‖ n(u8) ‖ n × recipient
//! recipient = set(4, BE) ‖ kid(32) ‖ ct(len-prefixed) ‖ wrap(len-prefixed)
//! ```
//!
//! * `wrap` is the file key `K` under `primitives::seal` with a key from the
//!   recipient's encapsulation, as a device delivery (`IPDD`) is.
//! * The data key and the 4-byte nonce prefix come from `K` and the header's
//!   digest. Each chunk is [`primitives::seal_chunk`] with the header as
//!   associated data and a last flag, so a dropped recipient, a reordered or
//!   truncated chunk, or an extended stream all fail.
//! * A chunk holds `1 << chunk_log2` plaintext bytes, and only the last may
//!   hold fewer, or none (an empty stream is one empty last chunk).

use std::ffi::CStr;
use std::io::{Read, Write};

use native_ossl::rand::Rand;
use native_ossl::util::SecretBuf;
use tang_pqc::primitives::{self, Domain};
use tang_pqc::wire::{Reader, Writer};
use tang_pqc::{ExchangeKey, ExchangeKeyPair, KemAlg};

use crate::error::{Error, Result};

/// The container's domain-separation label.
pub const DOMAIN: Domain = Domain::new("ipa-ku-enroll/v1 backup");

const MAGIC: [u8; 4] = *b"IPBK";
/// The chunk size a new container uses: 64 KiB.
pub const DEFAULT_CHUNK_LOG2: u8 = 16;
const MIN_CHUNK_LOG2: u8 = 12;
const MAX_CHUNK_LOG2: u8 = 24;
/// The most recipients one container names.
pub const MAX_RECIPIENTS: usize = 4;
const MAX_HEADER: usize = 16 * 1024;

/// A key a backup is sealed to, and the id of the recovery shard set it
/// stands for (carried so a reader can tell which papers to fetch).
#[derive(Clone)]
pub struct Recipient {
    /// The recovery public key.
    pub key: ExchangeKey,
    /// The shard set's id.
    pub set: u32,
}

fn io(e: &std::io::Error) -> Error {
    Error::Io(e.to_string())
}

/// The hash of everything derived from the file key: the strongest of the
/// recipients' suite hashes.
fn data_hash(algs: impl IntoIterator<Item = KemAlg>) -> &'static CStr {
    algs.into_iter()
        .map(KemAlg::hash)
        .max_by_key(|h| primitives::digest_len(h))
        .unwrap_or(primitives::SHA256)
}

fn kem_of(ct: &[u8]) -> Result<KemAlg> {
    KemAlg::ALL
        .into_iter()
        .find(|a| a.ciphertext_len() == ct.len())
        .ok_or(Error::Malformed("KEM ciphertext"))
}

fn wrap_key(secret: &[u8], kid: &[u8; 32], ct: &[u8], alg: KemAlg) -> Result<SecretBuf> {
    let hash = alg.hash();
    Ok(DOMAIN.derive_key(
        hash,
        &[secret],
        "wrap",
        &[kid, &primitives::digest(hash, &[ct])?],
    )?)
}

fn data_key(k: &[u8], header: &[u8], hash: &CStr) -> Result<(SecretBuf, [u8; 4])> {
    let digest = primitives::digest(hash, &[header])?;
    let key = DOMAIN.derive_key(hash, &[k], "data", &[&digest])?;
    let mut prefix = [0u8; 4];
    DOMAIN.hkdf(hash, &[k], "nonce", &[&digest], &mut prefix)?;
    Ok((key, prefix))
}

/// Read until `buf` is full or the input ends; the count read.
fn fill(r: &mut impl Read, buf: &mut [u8]) -> Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(m) => n += m,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(io(&e)),
        }
    }
    Ok(n)
}

/// Seal `input` to every recipient, writing the container to `out`.
///
/// # Errors
///
/// No or too many recipients, a crypto error, or an I/O error.
pub fn seal_stream(
    recipients: &[Recipient],
    chunk_log2: u8,
    mut input: impl Read,
    mut out: impl Write,
) -> Result<()> {
    if recipients.is_empty() || recipients.len() > MAX_RECIPIENTS {
        return Err(Error::Malformed("backup recipients"));
    }
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_log2) {
        return Err(Error::Malformed("backup chunk size"));
    }
    let mut k = SecretBuf::with_len(32);
    Rand::fill_private(k.as_mut_slice())?;

    let mut w = Writer::new(MAGIC);
    let count =
        u8::try_from(recipients.len()).map_err(|_| Error::Malformed("backup recipients"))?;
    w.u8(chunk_log2).u8(count);
    for r in recipients {
        let (ct, secret) = r.key.encapsulate()?;
        let kid = r.key.kid().as_bytes();
        let kek = wrap_key(secret.as_ref(), kid, &ct, r.key.alg())?;
        let wrap = primitives::seal(kek.as_ref(), k.as_ref())?;
        w.fixed(&r.set.to_be_bytes())
            .fixed(kid)
            .bytes(&ct)
            .bytes(&wrap);
    }
    let header = w.finish();
    let hash = data_hash(recipients.iter().map(|r| r.key.alg()));
    let (key, prefix) = data_key(k.as_ref(), &header, hash)?;

    let len = u32::try_from(header.len()).map_err(|_| Error::Malformed("backup header"))?;
    out.write_all(&len.to_be_bytes()).map_err(|e| io(&e))?;
    out.write_all(&header).map_err(|e| io(&e))?;

    // One byte past the chunk tells whether this one is the last.
    let size = 1usize << chunk_log2;
    let mut buf = vec![0u8; size + 1];
    let mut carry = 0;
    for counter in 0u64.. {
        let got = carry + fill(&mut input, &mut buf[carry..])?;
        let last = got <= size;
        let take = got.min(size);
        let sealed =
            primitives::seal_chunk(key.as_ref(), &prefix, counter, &header, last, &buf[..take])?;
        out.write_all(&sealed).map_err(|e| io(&e))?;
        if last {
            break;
        }
        buf[0] = buf[size];
        carry = 1;
    }
    out.flush().map_err(|e| io(&e))
}

/// Open a container with the recovery key pair it was sealed to, writing
/// the plaintext to `out`.  Plaintext is written chunk by chunk as each
/// authenticates, so a failure can leave a prefix in `out`: the caller
/// discards it.
///
/// # Errors
///
/// [`Error::Malformed`] for a container that is not one,
/// [`Error::WrongRecipient`] if the key is not among its recipients,
/// [`Error::BadResponse`] for a chunk that does not authenticate, one out of
/// place, a missing last chunk or bytes after it, or an I/O error.
pub fn open_stream(key: &ExchangeKeyPair, mut input: impl Read, mut out: impl Write) -> Result<()> {
    let mut len = [0u8; 4];
    if fill(&mut input, &mut len)? != 4 {
        return Err(Error::Malformed("backup container"));
    }
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_HEADER {
        return Err(Error::Malformed("backup container"));
    }
    let mut header = vec![0u8; len];
    if fill(&mut input, &mut header)? != len {
        return Err(Error::Malformed("backup container"));
    }

    let mut r = Reader::new(&header, MAGIC, "backup container")?;
    let chunk_log2 = r.u8()?;
    let n = usize::from(r.u8()?);
    if !(MIN_CHUNK_LOG2..=MAX_CHUNK_LOG2).contains(&chunk_log2) || n == 0 || n > MAX_RECIPIENTS {
        return Err(r.malformed().into());
    }
    let mut algs = Vec::with_capacity(n);
    let mut mine = None;
    for _ in 0..n {
        let _set = r.fixed::<4>()?;
        let kid = r.fixed::<32>()?;
        let ct = r.bytes()?;
        let wrap = r.bytes()?;
        let alg = kem_of(ct)?;
        algs.push(alg);
        if &kid == key.public().kid().as_bytes() {
            mine = Some((kid, ct, wrap, alg));
        }
    }
    r.finish()?;
    let (kid, ct, wrap, alg) = mine.ok_or(Error::WrongRecipient)?;

    let secret = key.decapsulate(ct)?;
    let kek = wrap_key(secret.as_ref(), &kid, ct, alg)?;
    let k = primitives::open(kek.as_ref(), wrap).map_err(|_| Error::BadResponse)?;
    let (dkey, prefix) = data_key(k.as_ref(), &header, data_hash(algs))?;

    let size = (1usize << chunk_log2) + primitives::TAG_LEN;
    let mut buf = vec![0u8; size + 1];
    let mut carry = 0;
    for counter in 0u64.. {
        let got = carry + fill(&mut input, &mut buf[carry..])?;
        let last = got <= size;
        let take = got.min(size);
        let plain =
            primitives::open_chunk(dkey.as_ref(), &prefix, counter, &header, last, &buf[..take])
                .map_err(|_| Error::BadResponse)?;
        out.write_all(plain.as_ref()).map_err(|e| io(&e))?;
        if last {
            break;
        }
        buf[0] = buf[size];
        carry = 1;
    }
    out.flush().map_err(|e| io(&e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(seed: u8, alg: KemAlg) -> ExchangeKeyPair {
        ExchangeKeyPair::from_seed_bytes(alg, &[seed; 64]).unwrap()
    }

    fn seal(to: &[&ExchangeKeyPair], data: &[u8]) -> Vec<u8> {
        let rs: Vec<_> = to
            .iter()
            .map(|p| Recipient {
                key: p.public().clone(),
                set: 7,
            })
            .collect();
        let mut out = Vec::new();
        seal_stream(&rs, MIN_CHUNK_LOG2, data, &mut out).unwrap();
        out
    }

    fn open(k: &ExchangeKeyPair, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        open_stream(k, bytes, &mut out).map(|()| out)
    }

    #[test]
    fn round_trips_at_chunk_boundaries() {
        let k = pair(1, KemAlg::MlKem768);
        let size: usize = 1 << MIN_CHUNK_LOG2;
        for n in [0, 1, size - 1, size, size + 1, 3 * size, 3 * size + 5] {
            let data: Vec<u8> = (0..n).map(|i| i.to_le_bytes()[0]).collect();
            assert_eq!(open(&k, &seal(&[&k], &data)).unwrap(), data, "{n} bytes");
        }
    }

    #[test]
    fn any_recipient_opens_and_a_stranger_does_not() {
        let (a, b) = (pair(1, KemAlg::MlKem768), pair(2, KemAlg::MlKem1024));
        let sealed = seal(&[&a, &b], b"realm secrets");
        assert_eq!(open(&a, &sealed).unwrap(), b"realm secrets");
        assert_eq!(open(&b, &sealed).unwrap(), b"realm secrets");
        let c = pair(3, KemAlg::MlKem768);
        assert!(matches!(open(&c, &sealed), Err(Error::WrongRecipient)));
    }

    #[test]
    fn tampering_is_refused() {
        let k = pair(1, KemAlg::MlKem768);
        let size = 1 << MIN_CHUNK_LOG2;
        let data = vec![9u8; 3 * size + 10];
        let sealed = seal(&[&k], &data);
        let frame = size + primitives::TAG_LEN;
        let body = sealed.len() - (3 * frame + 10 + primitives::TAG_LEN);

        // A flipped byte in a middle chunk, in the header, truncation at a
        // chunk boundary and inside one, an extension, and two swapped chunks.
        let mut flipped = sealed.clone();
        flipped[body + frame + 3] ^= 1;
        let mut header = sealed.clone();
        header[10] ^= 1;
        let mut swapped = sealed.clone();
        let (c0, c1) = (body..body + frame, body + frame..body + 2 * frame);
        let first = sealed[c0.clone()].to_vec();
        swapped[c0].copy_from_slice(&sealed[c1.clone()]);
        swapped[c1].copy_from_slice(&first);
        let mut extended = sealed.clone();
        extended.push(0);
        for bad in [
            flipped,
            header,
            swapped,
            extended,
            sealed[..body + 3 * frame].to_vec(),
            sealed[..sealed.len() - 1].to_vec(),
            sealed[..body].to_vec(),
        ] {
            assert!(open(&k, &bad).is_err());
        }
        assert_eq!(open(&k, &sealed).unwrap(), data);
    }
}
