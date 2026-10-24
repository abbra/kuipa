//! The proof's completeness, soundness against the obvious cheats, and
//! its sizes, at both levels.

use ml_dsa_zk::keccak::{permutation, permute, to_bits};
use ml_dsa_zk::{Circuit, Error, Level, Proof, Wire, prove_at, verify_at};

const LEVELS: [Level; 2] = [Level::L128, Level::L256];

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
    for level in LEVELS {
        for input in [
            [true, true, false],
            [true, false, true],
            [false, false, false],
        ] {
            let (proof, outputs) = prove_at(level, &c, &input).unwrap();
            assert_eq!(proof.level(), level);
            verify_at(level, &c, &outputs, &proof).unwrap();
            let bytes = proof.to_bytes();
            assert_eq!(bytes.len(), Proof::size(level, &c));
            let parsed = Proof::from_bytes(&c, &bytes).unwrap();
            assert_eq!(parsed, proof);
            verify_at(level, &c, &outputs, &parsed).unwrap();
        }
    }
}

#[test]
fn a_verifier_refuses_a_weaker_level_and_accepts_a_stronger_one() {
    // A CNSA verifier requires λ = 256; a λ = 128 proof is refused
    // however valid, and a λ = 256 one satisfies a λ = 128 verifier.
    let c = small();
    let (weak, outputs) = prove_at(Level::L128, &c, &[true, true, false]).unwrap();
    assert!(matches!(
        verify_at(Level::L256, &c, &outputs, &weak),
        Err(Error::Weak(Level::L128))
    ));
    let (strong, outputs) = prove_at(Level::L256, &c, &[true, true, false]).unwrap();
    verify_at(Level::L128, &c, &outputs, &strong).unwrap();
    // The level is bound into the proof: relabelling one does not parse
    // (the sizes differ), and an unknown level is refused.
    let mut relabelled = weak.to_bytes();
    relabelled[5] = 2;
    assert!(Proof::from_bytes(&c, &relabelled).is_err());
    relabelled[5] = 3;
    assert!(Proof::from_bytes(&c, &relabelled).is_err());
    assert!(Level::L128 < Level::L256);
}

#[test]
fn a_proof_proves_only_its_outputs() {
    let c = small();
    for level in LEVELS {
        let (proof, outputs) = prove_at(level, &c, &[true, true, false]).unwrap();
        for flip in 0..outputs.len() {
            let mut other = outputs.clone();
            other[flip] = !other[flip];
            assert!(matches!(
                verify_at(level, &c, &other, &proof),
                Err(Error::Invalid)
            ));
        }
        // Another circuit of the same shape.
        let mut other = Circuit::new(3);
        let and = other.and(other.input(0), other.input(2));
        let not = other.not(other.input(2));
        let xor = other.xor(other.input(0), not);
        other.output(and);
        other.output(xor);
        assert!(verify_at(level, &other, &outputs, &proof).is_err());
    }
}

#[test]
fn every_byte_of_a_proof_matters() {
    let c = small();
    for level in LEVELS {
        let (proof, outputs) = prove_at(level, &c, &[true, false, true]).unwrap();
        let bytes = proof.to_bytes();
        // Flip one bit in each byte past the magic: parsing refuses it, or
        // the proof no longer verifies.  (Padding bits are refused by the
        // parser.)  At λ = 256 the openings' 10 KiB are sampled, every
        // other field byte by byte, to keep the test quick.
        let openings = bytes.len() - level.lambda() / 8 * (8 * 32 + 64);
        let sampled =
            |i: &usize| level == Level::L128 || *i < openings + 320 || i.is_multiple_of(29);
        for i in (5..bytes.len()).filter(sampled) {
            let mut tampered = bytes.clone();
            tampered[i] ^= 1;
            let rejected = match Proof::from_bytes(&c, &tampered) {
                Err(_) => true,
                Ok(p) => verify_at(level, &c, &outputs, &p).is_err(),
            };
            assert!(rejected, "byte {i} of {} at {level:?}", bytes.len());
        }
        assert!(Proof::from_bytes(&c, &bytes[..bytes.len() - 1]).is_err());
    }
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
    for level in LEVELS {
        let started = std::time::Instant::now();
        let (proof, outputs) = prove_at(level, &c, &to_bits(&secret)).unwrap();
        let proving = started.elapsed();
        assert_eq!(outputs, to_bits(&permute(secret)));
        let started = std::time::Instant::now();
        verify_at(level, &c, &outputs, &proof).unwrap();
        let verifying = started.elapsed();
        let size = proof.to_bytes().len();
        eprintln!(
            "Keccak-f[1600] preimage, λ = {}: {} AND gates, proof {size} bytes, prove {proving:?}, verify {verifying:?}",
            level.lambda(),
            c.ands()
        );
        // About λ/64 bytes per committed bit (λ/8 trees), plus constants.
        let per_bit = level.lambda() / 64;
        assert!(size < per_bit * c.witness_bits() + 16_384, "{size}");
        // A wrong claimed image does not verify.
        let mut wrong = outputs.clone();
        wrong[777] = !wrong[777];
        assert!(verify_at(level, &c, &wrong, &proof).is_err());
    }
}

#[test]
fn a_prover_without_a_preimage_fails() {
    // Proving with an input that does not produce the claimed outputs
    // yields a proof of the outputs it does produce, never of others:
    // the prover cannot choose outputs apart from its input.
    let c = small();
    for level in LEVELS {
        let (proof, outputs) = prove_at(level, &c, &[false, false, false]).unwrap();
        assert_eq!(outputs, [false, true]);
        assert!(verify_at(level, &c, &[true, true], &proof).is_err());
    }
}
