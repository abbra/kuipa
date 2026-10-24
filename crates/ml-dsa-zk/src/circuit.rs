//! Boolean circuits: secret input bits, XOR, NOT and AND gates, and the
//! wires whose values the statement makes public.  XOR and NOT are free
//! in the proof; each AND costs one committed bit and one QuickSilver
//! constraint.

use crate::primitives::hash;
use crate::{Error, Result};

/// A wire: an input, or a gate's output, numbered in creation order.
pub type Wire = u32;

/// A gate, over earlier wires.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Gate {
    /// `a ⊕ b`.
    Xor(Wire, Wire),
    /// `¬a`.
    Not(Wire),
    /// `a ∧ b`.
    And(Wire, Wire),
}

/// A circuit: `inputs` secret bits, then gates, and its public outputs.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Circuit {
    inputs: u32,
    gates: Vec<Gate>,
    outputs: Vec<Wire>,
}

impl Circuit {
    /// A circuit with `inputs` secret input bits, wires `0..inputs`.
    #[must_use]
    pub fn new(inputs: u32) -> Self {
        Self {
            inputs,
            ..Self::default()
        }
    }

    fn push(&mut self, g: Gate) -> Wire {
        self.gates.push(g);
        self.inputs + u32::try_from(self.gates.len() - 1).expect("fewer than 2³² gates")
    }

    /// The wire carrying input bit `i`.
    ///
    /// # Panics
    ///
    /// For an `i` past the inputs.
    #[must_use]
    pub fn input(&self, i: u32) -> Wire {
        assert!(i < self.inputs, "input {i} of {}", self.inputs);
        i
    }

    /// `a ⊕ b`.
    pub fn xor(&mut self, a: Wire, b: Wire) -> Wire {
        self.push(Gate::Xor(a, b))
    }

    /// `¬a`.
    pub fn not(&mut self, a: Wire) -> Wire {
        self.push(Gate::Not(a))
    }

    /// `a ∧ b`.
    pub fn and(&mut self, a: Wire, b: Wire) -> Wire {
        self.push(Gate::And(a, b))
    }

    /// Make `w` a public output.
    pub fn output(&mut self, w: Wire) {
        self.outputs.push(w);
    }

    /// The number of secret inputs.
    #[must_use]
    pub fn inputs(&self) -> u32 {
        self.inputs
    }

    /// The gates.
    #[must_use]
    pub fn gates(&self) -> &[Gate] {
        &self.gates
    }

    /// The public outputs.
    #[must_use]
    pub fn outputs(&self) -> &[Wire] {
        &self.outputs
    }

    /// How many AND gates: with the inputs, the committed witness's size.
    #[must_use]
    pub fn ands(&self) -> usize {
        self.gates
            .iter()
            .filter(|g| matches!(g, Gate::And(..)))
            .count()
    }

    /// The committed witness's size in bits: inputs and AND outputs.
    #[must_use]
    pub fn witness_bits(&self) -> usize {
        self.inputs as usize + self.ands()
    }

    /// Check every gate reads only earlier wires and every output exists.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`].
    pub fn check(&self) -> Result<()> {
        for (i, g) in self.gates.iter().enumerate() {
            let me = self.inputs as usize + i;
            let ok = |w: &Wire| (*w as usize) < me;
            let fine = match g {
                Gate::Xor(a, b) | Gate::And(a, b) => ok(a) && ok(b),
                Gate::Not(a) => ok(a),
            };
            if !fine {
                return Err(Error::Malformed("circuit wiring"));
            }
        }
        let wires = self.inputs as usize + self.gates.len();
        if self.outputs.iter().any(|w| *w as usize >= wires) {
            return Err(Error::Malformed("circuit output"));
        }
        Ok(())
    }

    /// Every wire's value for `input`, and the outputs'.
    ///
    /// # Errors
    ///
    /// [`Error::Malformed`] for an input of the wrong length.
    pub fn evaluate(&self, input: &[bool]) -> Result<(Vec<bool>, Vec<bool>)> {
        if input.len() != self.inputs as usize {
            return Err(Error::Malformed("circuit input length"));
        }
        let mut wires = input.to_vec();
        wires.reserve(self.gates.len());
        for g in &self.gates {
            let v = match *g {
                Gate::Xor(a, b) => wires[a as usize] ^ wires[b as usize],
                Gate::Not(a) => !wires[a as usize],
                Gate::And(a, b) => wires[a as usize] & wires[b as usize],
            };
            wires.push(v);
        }
        let outputs = self.outputs.iter().map(|w| wires[*w as usize]).collect();
        Ok((wires, outputs))
    }

    /// The circuit's identity, for the transcript: SHA-512 of its
    /// description.
    ///
    /// # Errors
    ///
    /// An OpenSSL error.
    pub fn digest(&self) -> Result<crate::primitives::Hash> {
        let mut bytes = Vec::with_capacity(9 * self.gates.len() + 8 * self.outputs.len() + 4);
        bytes.extend_from_slice(&self.inputs.to_le_bytes());
        for g in &self.gates {
            let (tag, a, b) = match *g {
                Gate::Xor(a, b) => (1u8, a, b),
                Gate::Not(a) => (2, a, 0),
                Gate::And(a, b) => (3, a, b),
            };
            bytes.push(tag);
            bytes.extend_from_slice(&a.to_le_bytes());
            bytes.extend_from_slice(&b.to_le_bytes());
        }
        for w in &self.outputs {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        hash("ml-dsa-zk/v1 circuit", &[&bytes])
    }
}
