//! Merkle trees as in RFC 9162 §2.1 and the Merkle Tree Certificates
//! drafts, through `synta-mtc` (hashing with OpenSSL): SHA-256, leaves
//! hashed as `H(0x00 ‖ data)`, interior nodes as `H(0x01 ‖ left ‖ right)`,
//! the left subtree holding the largest power of two below the size, and
//! inclusion proofs verified as in §2.1.3.2.

use synta_mtc::crypto::{
    HashAlgorithm, compute_root, generate_inclusion_proof, hash_leaf,
    verify::verify_inclusion_proof,
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
