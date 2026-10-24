//! Merkle trees as in RFC 9162 §2.1 and the Merkle Tree Certificates
//! drafts, through `synta-mtc` (hashing with OpenSSL): SHA-256, leaves
//! hashed as `H(0x00 ‖ data)`, interior nodes as `H(0x01 ‖ left ‖ right)`,
//! the left subtree holding the largest power of two below the size,
//! inclusion proofs verified as in §2.1.3.2 and consistency proofs as in
//! §2.1.4.2.

use synta_mtc::crypto::{
    HashAlgorithm, compute_root, generate_consistency_proof, generate_inclusion_proof, hash_leaf,
    verify::{verify_consistency_proof, verify_inclusion_proof},
};

use crate::error::{Error, Result};

/// A tree hash.
pub type Hash = [u8; 32];

const SHA256: HashAlgorithm = HashAlgorithm::Sha256;

fn hash(v: &[u8]) -> Result<Hash> {
    v.try_into().map_err(|_| Error::Malformed("tree hash"))
}

/// The leaf hash of `data`.
///
/// # Errors
///
/// [`Error::Malformed`] if the backend returns a hash of another size.
pub fn leaf_hash(data: &[u8]) -> Result<Hash> {
    hash(&hash_leaf(SHA256, data))
}

/// The tree hash over `leaves` (leaf hashes, in order).
///
/// # Errors
///
/// [`Error::Malformed`] for an empty or too large tree.
pub fn root(leaves: &[Hash]) -> Result<Hash> {
    let leaves = leaves.iter().map(|l| l.to_vec()).collect();
    hash(&compute_root(SHA256, leaves).map_err(|_| Error::Malformed("tree"))?)
}

/// The inclusion path of leaf `index` in the tree over `leaves`, leaf
/// level first.
///
/// # Errors
///
/// [`Error::Malformed`] for an index outside the tree.
pub fn path(leaves: &[Hash], index: usize) -> Result<Vec<Hash>> {
    let all: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
    generate_inclusion_proof(SHA256, index as u64, &all)
        .map_err(|_| Error::Malformed("leaf index"))?
        .iter()
        .map(|h| hash(h))
        .collect()
}

/// Whether `leaf` is at `index` in a tree of `size` leaves with `root`,
/// given its inclusion `path` (RFC 9162 §2.1.3.2).
///
/// # Errors
///
/// None in practice; the signature matches the other tree functions.
pub fn verify(leaf: &Hash, index: u64, size: u64, path: &[Hash], root: &Hash) -> Result<bool> {
    let path: Vec<Vec<u8>> = path.iter().map(|h| h.to_vec()).collect();
    Ok(verify_inclusion_proof(SHA256, index, size, leaf, &path, root).is_ok())
}

/// The proof that the tree over the first `old_size` of `leaves` is a
/// prefix of the tree over all of them (RFC 9162 §2.1.4.1).
///
/// # Errors
///
/// [`Error::Malformed`] for an `old_size` of zero or beyond the tree.
pub fn consistency(leaves: &[Hash], old_size: u64) -> Result<Vec<Hash>> {
    let all: Vec<Vec<u8>> = leaves.iter().map(|l| l.to_vec()).collect();
    generate_consistency_proof(SHA256, old_size, leaves.len() as u64, &all)
        .map_err(|_| Error::Malformed("consistency sizes"))?
        .iter()
        .map(|h| hash(h))
        .collect()
}

/// Whether the tree of `new_size` leaves with `new_root` extends the tree
/// of `old_size` leaves with `old_root`, given the consistency `proof`
/// (RFC 9162 §2.1.4.2).  Equal sizes need an empty proof and equal roots.
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
    let proof: Vec<Vec<u8>> = proof.iter().map(|h| h.to_vec()).collect();
    Ok(verify_consistency_proof(SHA256, old_size, old_root, new_size, new_root, &proof).is_ok())
}

#[cfg(test)]
mod tests {
    use tang_pqc::primitives::sha256;

    use super::*;

    /// An interior node, computed independently of `synta-mtc`.
    fn node(left: &Hash, right: &Hash) -> Hash {
        sha256(&[&[0x01], left, right]).unwrap()
    }

    fn leaves(n: usize) -> Vec<Hash> {
        (0..n)
            .map(|i| leaf_hash(&u32::try_from(i).unwrap().to_be_bytes()).unwrap())
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
        for n in 1..=33 {
            let l = leaves(n);
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
                longer.push([0; 32]);
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
        for size in 1..=33usize {
            let l = leaves(size);
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
                let forked = root(&leaves(old + 1)[1..]).unwrap();
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
        assert_eq!(leaf_hash(b"x").unwrap(), sha256(&[&[0x00], b"x"]).unwrap());
    }

    #[test]
    fn leaf_and_node_hashes_are_separated() {
        // H(0x00 ‖ x) for a leaf, H(0x01 ‖ l ‖ r) for a node: a leaf whose
        // data is two hashes is not the node over them.
        let l = leaves(2);
        let mut both = l[0].to_vec();
        both.extend_from_slice(&l[1]);
        assert_ne!(leaf_hash(&both).unwrap(), root(&l).unwrap());
    }
}
