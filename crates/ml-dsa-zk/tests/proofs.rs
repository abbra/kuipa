//! The proof's completeness, soundness against the obvious cheats, and
//! its sizes.

use ml_dsa_zk::keccak::{permutation, permute, to_bits};
use ml_dsa_zk::{Circuit, Error, Proof, Wire, prove, verify};

/// `x₀ ∧ x₁ = out₀`, `x₀ ⊕ ¬x₂ = out₁`.
fn small() -> Circuit {
    let mut c = Circuit::new(3);
    let a = c.and(c.input(0), c.input(1));
    let n = c.not(c.input(2));
    let x = c.xor(c.input(0), n);
    c.output(a);
    c.output(x);
    c
}

#[test]
fn honest_proofs_verify_and_survive_the_wire() {
    let c = small();
    for input in [
        [true, true, false],
        [true, false, true],
        [false, false, false],
    ] {
        let (proof, outputs) = prove(&c, &input).unwrap();
        verify(&c, &outputs, &proof).unwrap();
        let bytes = proof.to_bytes();
        assert_eq!(bytes.len(), Proof::size(&c));
        let parsed = Proof::from_bytes(&c, &bytes).unwrap();
        verify(&c, &outputs, &parsed).unwrap();
    }
}

#[test]
fn a_proof_proves_only_its_outputs() {
    let c = small();
    let (proof, outputs) = prove(&c, &[true, true, false]).unwrap();
    for flip in 0..outputs.len() {
        let mut other = outputs.clone();
        other[flip] = !other[flip];
        assert!(matches!(verify(&c, &other, &proof), Err(Error::Invalid)));
    }
    // Another circuit of the same shape.
    let mut other = Circuit::new(3);
    let and = other.and(other.input(0), other.input(2));
    let not = other.not(other.input(2));
    let xor = other.xor(other.input(0), not);
    other.output(and);
    other.output(xor);
    assert!(verify(&other, &outputs, &proof).is_err());
}

#[test]
fn every_byte_of_a_proof_matters() {
    let c = small();
    let (proof, outputs) = prove(&c, &[true, false, true]).unwrap();
    let bytes = proof.to_bytes();
    // Flip one bit in each byte past the magic: parsing refuses it, or the
    // proof no longer verifies.  (Padding bits are refused by the parser.)
    for i in 5..bytes.len() {
        let mut tampered = bytes.clone();
        tampered[i] ^= 1;
        let rejected = match Proof::from_bytes(&c, &tampered) {
            Err(_) => true,
            Ok(p) => verify(&c, &outputs, &p).is_err(),
        };
        assert!(rejected, "byte {i} of {}", bytes.len());
    }
    assert!(Proof::from_bytes(&c, &bytes[..bytes.len() - 1]).is_err());
}

#[test]
fn a_keccak_preimage_is_proven_without_revealing_it() {
    // The statement: "I know a state whose Keccak-f[1600] image is this".
    let mut c = Circuit::new(1600);
    let input: [Wire; 1600] = std::array::from_fn(|i| c.input(u32::try_from(i).unwrap()));
    let out = permutation(&mut c, &input);
    for w in out {
        c.output(w);
    }
    let secret: [u64; 25] = std::array::from_fn(|i| {
        0xdead_beef_u64.rotate_left(u32::try_from(i).unwrap()) ^ (i as u64)
    });
    let started = std::time::Instant::now();
    let (proof, outputs) = prove(&c, &to_bits(&secret)).unwrap();
    let proving = started.elapsed();
    assert_eq!(outputs, to_bits(&permute(secret)));
    let started = std::time::Instant::now();
    verify(&c, &outputs, &proof).unwrap();
    let verifying = started.elapsed();
    let size = proof.to_bytes().len();
    eprintln!(
        "Keccak-f[1600] preimage: {} AND gates, proof {size} bytes, prove {proving:?}, verify {verifying:?}",
        c.ands()
    );
    // About 2 bytes per committed bit (16 trees) plus constants.
    assert!(size < 2 * c.witness_bits() + 8192, "{size}");
    // A wrong claimed image does not verify.
    let mut wrong = outputs.clone();
    wrong[777] = !wrong[777];
    assert!(verify(&c, &wrong, &proof).is_err());
}

#[test]
fn a_prover_without_a_preimage_fails() {
    // Proving with an input that does not produce the claimed outputs
    // yields a proof of the outputs it does produce, never of others:
    // the prover cannot choose outputs apart from its input.
    let c = small();
    let (proof, outputs) = prove(&c, &[false, false, false]).unwrap();
    assert_eq!(outputs, [false, true]);
    assert!(verify(&c, &[true, true], &proof).is_err());
}
