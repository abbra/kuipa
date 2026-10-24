//! Merkle trees as in RFC 9162 §2.1 and the Merkle Tree Certificates
//! drafts, through `synta-mtc` (hashing with OpenSSL): leaves hashed as
//! `H(0x00 ‖ data)`, interior nodes as `H(0x01 ‖ left ‖ right)`, the left
//! subtree holding the largest power of two below the size, inclusion
//! proofs verified as in §2.1.3.2 and consistency proofs as in §2.1.4.2.
//!
//! `H` follows the strength of the key that signs the tree
//! ([`TreeHash::for_signer`], `docs/DESIGN.md` §4.1.1): SHA-256 under
//! ML-DSA-44/65, SHA-384 under ML-DSA-87 — so a CNSA 2.0 system policy,
//! which allows only ML-DSA-87, gives SHA-384 trees.  A [`struct@Hash`]'s length
//! names its algorithm, so trees verify without being told which one;
//! a tree, path or proof that mixes the two is refused.

use synta_mtc::crypto::{
    HashAlgorithm, compute_root, generate_consistency_proof, generate_inclusion_proof, hash_leaf,
    verify::{verify_consistency_proof, verify_inclusion_proof},
};
use tang_pqc::SignatureAlg;

use crate::error::{Error, Result};

/// A tree's hash function.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum TreeHash {
    /// SHA-256 (32 bytes).
    Sha256,
    /// SHA-384 (48 bytes).
    Sha384,
}

impl TreeHash {
    /// The hash for a tree signed by a key of `alg`: SHA-384 at category
    /// 5 (ML-DSA-87, CNSA 2.0), SHA-256 below, as `KemAlg::hash` picks the
    /// KEM suite's hash.
    #[must_use]
    pub const fn for_signer(alg: SignatureAlg) -> Self {
        match alg {
            SignatureAlg::MlDsa87 => Self::Sha384,
            SignatureAlg::MlDsa44 | SignatureAlg::MlDsa65 => Self::Sha256,
        }
    }

    /// The output length.
    #[must_use]
    pub const fn output_len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
        }
    }

    /// The OpenSSL name.
    #[must_use]
    pub const fn openssl_name(self) -> &'static std::ffi::CStr {
        match self {
            Self::Sha256 => c"SHA2-256",
            Self::Sha384 => c"SHA2-384",
        }
    }

    const fn backend(self) -> HashAlgorithm {
        match self {
            Self::Sha256 => HashAlgorithm::Sha256,
            Self::Sha384 => HashAlgorithm::Sha384,
        }
    }

    /// The algorithm whose output is `len` bytes.
    #[must_use]
    pub const fn of_len(len: usize) -> Option<Self> {
        match len {
            32 => Some(Self::Sha256),
            48 => Some(Self::Sha384),
            _ => None,
        }
    }
}

/// A tree hash: 32 bytes (SHA-256) or 48 (SHA-384).  It derefs to its
/// bytes.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Hash {
    len: u8,
    bytes: [u8; 48],
}

impl Hash {
    /// A hash from its bytes.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for a length that is neither algorithm's.
    pub fn from_slice(bytes: &[u8]) -> Result<Self> {
        TreeHash::of_len(bytes.len()).ok_or(Error::Malformed("tree hash"))?;
        let mut out = [0u8; 48];
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(Self {
            len: u8::try_from(bytes.len()).map_err(|_| Error::Malformed("tree hash"))?,
            bytes: out,
        })
    }

    /// The all-zero hash of `alg`'s length: a placeholder, never a node.
    #[must_use]
    pub const fn zero(alg: TreeHash) -> Self {
        Self {
            len: match alg {
                TreeHash::Sha256 => 32,
                TreeHash::Sha384 => 48,
            },
            bytes: [0; 48],
        }
    }

    /// Its algorithm.
    #[must_use]
    pub const fn alg(&self) -> TreeHash {
        if self.len == 48 {
            TreeHash::Sha384
        } else {
            TreeHash::Sha256
        }
    }

    /// Its bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl TryFrom<&[u8]> for Hash {
    type Error = Error;
    fn try_from(bytes: &[u8]) -> Result<Self> {
        Self::from_slice(bytes)
    }
}

impl TryFrom<Vec<u8>> for Hash {
    type Error = Error;
    fn try_from(bytes: Vec<u8>) -> Result<Self> {
        Self::from_slice(&bytes)
    }
}

impl std::ops::Deref for Hash {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl std::fmt::Debug for Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for b in self.as_bytes() {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A SHA-256-sized hash of `byte`s, for tests.
#[cfg(test)]
pub(crate) fn test_hash(byte: u8) -> Hash {
    Hash::from_slice(&[byte; 32]).expect("32 bytes")
}

/// The one algorithm of `hashes`, which must not be empty or mixed.
fn alg_of<'a>(hashes: impl IntoIterator<Item = &'a Hash>) -> Result<TreeHash> {
    let mut it = hashes.into_iter();
    let alg = it.next().ok_or(Error::Malformed("tree"))?.alg();
    if it.any(|h| h.alg() != alg) {
        return Err(Error::Malformed("tree hashes of two algorithms"));
    }
    Ok(alg)
}

fn hashes(v: &[Vec<u8>]) -> Result<Vec<Hash>> {
    v.iter().map(|h| Hash::from_slice(h)).collect()
}

/// The leaf hash of `data` under `alg`.
///
/// # Errors
///
/// [`Error::Malformed`] if the backend returns a hash of another size.
pub fn leaf_hash(alg: TreeHash, data: &[u8]) -> Result<Hash> {
    Hash::from_slice(&hash_leaf(alg.backend(), data))
}

/// The tree hash over `leaves` (leaf hashes, in order).
///
/// # Errors
///
/// [`Error::Malformed`] for an empty, mixed or too large tree.
pub fn root(leaves: &[Hash]) -> Result<Hash> {
    let alg = alg_of(leaves)?;
    let leaves = leaves.iter().map(|l| l.to_vec()).collect();
    Hash::from_slice(&compute_root(alg.backend(), leaves).map_err(|_| Error::Malformed("tree"))?)
}

/// The inclusion path of leaf `index` in the tree over `leaves`, leaf
/// level first.
///
/// # Errors
///
/// [`Error::Malformed`] for an index outside the tree, or a mixed tree.
pub fn path(leaves: &[Hash], index: usize) -> Result<Vec<Hash>> {
    let alg = alg_of(leaves)?;
    let all: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
    hashes(
        &generate_inclusion_proof(alg.backend(), index as u64, &all)
            .map_err(|_| Error::Malformed("leaf index"))?,
    )
}

/// Whether `leaf` is at `index` in a tree of `size` leaves with `root`,
/// given its inclusion `path` (RFC 9162 §2.1.3.2).  A leaf, path or root
/// of another algorithm than the root's does not verify.
///
/// # Errors
///
/// None in practice; the signature matches the other tree functions.
pub fn verify(leaf: &Hash, index: u64, size: u64, path: &[Hash], root: &Hash) -> Result<bool> {
    let alg = root.alg();
    if leaf.alg() != alg || path.iter().any(|h| h.alg() != alg) {
        return Ok(false);
    }
    let path: Vec<Vec<u8>> = path.iter().map(|h| h.to_vec()).collect();
    Ok(verify_inclusion_proof(alg.backend(), index, size, leaf, &path, root).is_ok())
}

/// The proof that the tree over the first `old_size` of `leaves` is a
/// prefix of the tree over all of them (RFC 9162 §2.1.4.1).
///
/// # Errors
///
/// [`Error::Malformed`] for an `old_size` of zero or beyond the tree, or
/// a mixed tree.
pub fn consistency(leaves: &[Hash], old_size: u64) -> Result<Vec<Hash>> {
    let alg = alg_of(leaves)?;
    let all: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
    hashes(
        &generate_consistency_proof(alg.backend(), old_size, leaves.len() as u64, &all)
            .map_err(|_| Error::Malformed("consistency sizes"))?,
    )
}

/// Whether the tree of `new_size` leaves with `new_root` extends the tree
/// of `old_size` leaves with `old_root`, given the consistency `proof`
/// (RFC 9162 §2.1.4.2).  Equal sizes need an empty proof and equal roots;
/// roots or a proof of two algorithms do not verify.
///
/// # Errors
///
/// None in practice; the signature matches the other tree functions.
pub fn verify_consistency(
    old_size: u64,
    old_root: &Hash,
    new_size: u64,
    new_root: &Hash,
    proof: &[Hash],
) -> Result<bool> {
    let alg = new_root.alg();
    if old_root.alg() != alg || proof.iter().any(|h| h.alg() != alg) {
        return Ok(false);
    }
    let proof: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
    Ok(verify_consistency_proof(
        alg.backend(),
        old_size,
        old_root,
        new_size,
        new_root,
        &proof,
    )
    .is_ok())
}

#[cfg(test)]
mod tests {
    use tang_pqc::primitives::digest;

    use super::*;

    const BOTH: [TreeHash; 2] = [TreeHash::Sha256, TreeHash::Sha384];

    fn h(alg: TreeHash, parts: &[&[u8]]) -> Hash {
        Hash::from_slice(&digest(alg.openssl_name(), parts).unwrap()).unwrap()
    }

    /// An interior node, computed independently of `synta-mtc`.
    fn node(left: &Hash, right: &Hash) -> Hash {
        h(left.alg(), &[&[0x01], left, right])
    }

    fn leaves(alg: TreeHash, n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(alg, &u32::try_from(i).unwrap().to_be_bytes()).unwrap())
            .collect()
    }

    /// RFC 9162 §2.1.1 written out directly, for comparison.
    fn reference(l: &[Hash]) -> Hash {
        if l.len() == 1 {
            return l[0];
        }
        let mut k = 1;
        while k * 2 < l.len() {
            k *= 2;
        }
        node(&reference(&l[..k]), &reference(&l[k..]))
    }

    #[test]
    fn roots_and_inclusion_proofs() {
        for (alg, n) in BOTH.into_iter().flat_map(|a| (1..=33).map(move |n| (a, n))) {
            let l = leaves(alg, n);
            let r = root(&l).unwrap();
            assert_eq!(r, reference(&l), "size {n}");
            for i in 0..n {
                let p = path(&l, i).unwrap();
                let (i64, n64) = (i as u64, n as u64);
                assert!(verify(&l[i], i64, n64, &p, &r).unwrap(), "{i} of {n}");
                // Wrong index, wrong leaf, truncated or extended path: all
                // fail.  (A path does not fix the size on its own — the left
                // edge of trees of 3 and 4 leaves has the same path — so the
                // size is signed together with the root, as in RFC 9162.)
                if n > 1 {
                    assert!(!verify(&l[i], (i64 + 1) % n64, n64, &p, &r).unwrap());
                    assert!(!verify(&l[(i + 1) % n], i64, n64, &p, &r).unwrap());
                }
                let mut longer = p.clone();
                longer.push(Hash::zero(alg));
                assert!(!verify(&l[i], i64, n64, &longer, &r).unwrap());
                if !p.is_empty() {
                    assert!(!verify(&l[i], i64, n64, &p[..p.len() - 1], &r).unwrap());
                }
            }
            assert!(path(&l, n).is_err());
        }
        assert!(root(&[]).is_err());
    }

    /// RFC 9162 §2.1.4.2 written out directly, for comparison.
    fn reference_consistency(
        first: u64,
        old_root: &Hash,
        second: u64,
        new_root: &Hash,
        proof: &[Hash],
    ) -> bool {
        if first == 0 || first > second {
            return false;
        }
        if first == second {
            return proof.is_empty() && old_root == new_root;
        }
        // Step 1: a power-of-two first size starts from its own root.
        let mut path: Vec<Hash> = proof.to_vec();
        if first.is_power_of_two() {
            path.insert(0, *old_root);
        }
        let Some((&start, rest)) = path.split_first() else {
            return false;
        };
        let (mut fn_, mut sn) = (first - 1, second - 1);
        while fn_ & 1 == 1 {
            fn_ >>= 1;
            sn >>= 1;
        }
        let (mut fr, mut sr) = (start, start);
        for c in rest {
            if sn == 0 {
                return false;
            }
            if fn_ & 1 == 1 || fn_ == sn {
                fr = node(c, &fr);
                sr = node(c, &sr);
                if fn_ & 1 == 0 {
                    while fn_ & 1 == 0 && fn_ != 0 {
                        fn_ >>= 1;
                        sn >>= 1;
                    }
                }
            } else {
                sr = node(&sr, c);
            }
            fn_ >>= 1;
            sn >>= 1;
        }
        fr == *old_root && sr == *new_root && sn == 0
    }

    #[test]
    fn consistency_proofs() {
        for (alg, size) in BOTH
            .into_iter()
            .flat_map(|a| (1..=33usize).map(move |n| (a, n)))
        {
            let l = leaves(alg, size);
            let new_root = root(&l).unwrap();
            let n = size as u64;
            for old in 1..=size {
                let m = old as u64;
                let old_root = root(&l[..old]).unwrap();
                let p = consistency(&l, m).unwrap();
                assert!(
                    verify_consistency(m, &old_root, n, &new_root, &p).unwrap(),
                    "{m} of {n}"
                );
                assert!(
                    reference_consistency(m, &old_root, n, &new_root, &p),
                    "reference {m} of {n}"
                );
                // A forked old tree, a tampered or truncated proof: all
                // fail, under both implementations.
                let forked = root(&leaves(alg, old + 1)[1..]).unwrap();
                assert!(!verify_consistency(m, &forked, n, &new_root, &p).unwrap());
                assert!(!reference_consistency(m, &forked, n, &new_root, &p));
                if let Some(first) = p.first() {
                    let mut tampered = p.clone();
                    tampered[0] = node(first, first);
                    assert!(!verify_consistency(m, &old_root, n, &new_root, &tampered).unwrap());
                    assert!(!verify_consistency(m, &old_root, n, &new_root, &p[1..]).unwrap());
                }
                // A proof does not fix the new size on its own (as with
                // inclusion paths, the size is signed with the root), but
                // both implementations judge a wrong one alike.
                if m < n {
                    assert_eq!(
                        verify_consistency(m, &old_root, n - 1, &new_root, &p).unwrap(),
                        reference_consistency(m, &old_root, n - 1, &new_root, &p),
                        "size {} for {m} of {n}",
                        n - 1
                    );
                }
            }
            assert!(consistency(&l, 0).is_err());
            assert!(consistency(&l, n + 1).is_err());
        }
    }

    #[test]
    fn leaf_hash_is_rfc_9162() {
        // H(0x00 ‖ data), also computed independently.
        for alg in BOTH {
            assert_eq!(leaf_hash(alg, b"x").unwrap(), h(alg, &[&[0x00], b"x"]));
        }
    }

    #[test]
    fn leaf_and_node_hashes_are_separated() {
        // H(0x00 ‖ x) for a leaf, H(0x01 ‖ l ‖ r) for a node: a leaf whose
        // data is two hashes is not the node over them.
        for alg in BOTH {
            let l = leaves(alg, 2);
            let mut both = l[0].to_vec();
            both.extend_from_slice(&l[1]);
            assert_ne!(leaf_hash(alg, &both).unwrap(), root(&l).unwrap());
        }
    }

    #[test]
    fn the_signer_picks_the_hash_and_trees_never_mix() {
        use tang_pqc::SignatureAlg as S;
        assert_eq!(TreeHash::for_signer(S::MlDsa44), TreeHash::Sha256);
        assert_eq!(TreeHash::for_signer(S::MlDsa65), TreeHash::Sha256);
        assert_eq!(TreeHash::for_signer(S::MlDsa87), TreeHash::Sha384);
        for alg in BOTH {
            assert_eq!(leaf_hash(alg, b"x").unwrap().len(), alg.output_len());
        }
        let (short, long) = (leaves(TreeHash::Sha256, 4), leaves(TreeHash::Sha384, 4));
        let mixed = [short[0], short[1], long[2], long[3]];
        assert!(root(&mixed).is_err());
        assert!(path(&mixed, 0).is_err());
        assert!(consistency(&mixed, 2).is_err());
        // A SHA-256 path into a SHA-384 tree, or roots of two hashes,
        // never verify — whatever the bytes.
        let r = root(&long).unwrap();
        let p: Vec<Hash> = path(&long, 0).unwrap();
        assert!(verify(&long[0], 0, 4, &p, &r).unwrap());
        let shortened: Vec<Hash> = p
            .iter()
            .map(|x| Hash::from_slice(&x[..32]).unwrap())
            .collect();
        assert!(!verify(&long[0], 0, 4, &shortened, &r).unwrap());
        assert!(!verify(&short[0], 0, 4, &p, &r).unwrap());
        let old = root(&short[..2]).unwrap();
        assert!(!verify_consistency(2, &old, 4, &r, &consistency(&long, 2).unwrap()).unwrap());
        // Lengths name algorithms; nothing else is a hash.
        assert!(Hash::from_slice(&[0; 33]).is_err());
        assert!(Hash::from_slice(&[]).is_err());
    }
}
