# ml-dsa-zk

Zero-knowledge proofs of knowledge over boolean circuits, by VOLE in the
head (FAEST-style, λ = 128), built only on OpenSSL: AES-128-CTR and
SHAKE256. A prover shows it knows a circuit input that makes the
circuit's public outputs the given bits, and reveals nothing else.

```rust
use ml_dsa_zk::{Circuit, prove, verify};

let mut c = Circuit::new(2);
let x = c.and(c.input(0), c.input(1));
c.output(x);
let (proof, outputs) = prove(&c, &[true, true])?;
verify(&c, &outputs, &proof)?;
```

It is the first part of an unlinkable ML-DSA blind signature, and comes
with a Keccak-f\[1600\] gadget: a preimage proof is 83 KB. The `Z_q`
arithmetic that ML-DSA's verification needs is not here yet. See
[DESIGN.md](DESIGN.md).

**Research prototype: not reviewed, do not rely on it.**
