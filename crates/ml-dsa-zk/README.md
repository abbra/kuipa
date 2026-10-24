# ml-dsa-zk

Zero-knowledge proofs of knowledge over boolean circuits, by VOLE in the
head (FAEST-style), built only on OpenSSL and only on CNSA 2.0's
general-purpose algorithms: AES-256-CTR and SHA-512. The system crypto
policy picks the level: λ = 128 while it allows ML-DSA-44 or 65, λ = 256
when it allows only ML-DSA-87 (CNSA 2.0), and verifiers refuse weaker
proofs. A prover shows it knows a circuit input that makes the
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
with a Keccak-f\[1600\] gadget, which evaluates ML-DSA's own SHAKE in
the statement: a preimage proof is 86 KB at λ = 128, 172 KB at
λ = 256. The `Z_q`
arithmetic that ML-DSA's verification needs is not here yet. See
[DESIGN.md](DESIGN.md).

**Research prototype: not reviewed, do not rely on it.**
