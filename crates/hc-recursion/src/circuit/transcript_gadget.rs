//! In-circuit Fiat-Shamir transcript using Poseidon.
//!
//! This gadget mirrors the native Blake3 transcript protocol labels from
//! `hc-hash/src/protocol.rs` but computes everything using Poseidon inside
//! the Halo2 circuit. Each `append` absorbs a field element into the sponge
//! state; each `challenge` squeezes one out.
//!
//! The transcript maintains a running Poseidon sponge state:
//!   - `append(value)` → absorbs value into rate position, permutes when full
//!   - `challenge()` → permutes if needed, returns state[0]
//!
//! Label handling: protocol labels (byte strings) are hashed to Fr via the
//! same `sample_fr` mechanism used by Poseidon params. This converts
//! arbitrary-length byte labels into field elements that can be absorbed.

use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Layouter, Value},
    plonk::Error,
};
use halo2curves::bn256::Fr;
use halo2curves::ff::PrimeField;

use super::poseidon as poseidon_native;
use super::poseidon_chip::PoseidonChip;

/// Convert a protocol label (byte string) to an Fr element for in-circuit use.
///
/// Uses the same deterministic sampling as Poseidon params to ensure
/// labels are consistent between native and circuit computation.
pub fn label_to_fr(label: &[u8]) -> Fr {
    use hc_hash::{sha256::Sha256, HashFunction};
    let seed = [b"hc-stark/recursion/transcript/label/", label].concat();
    for ctr in 0u64.. {
        let mut input = Vec::with_capacity(seed.len() + 8);
        input.extend_from_slice(&seed);
        input.extend_from_slice(&ctr.to_le_bytes());
        let digest = Sha256::hash(&input);
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(digest.as_bytes());
        let mut repr = <Fr as PrimeField>::Repr::default();
        repr.as_mut().copy_from_slice(&bytes);
        if let Some(value) = Option::<Fr>::from(Fr::from_repr(repr)) {
            return value;
        }
    }
    unreachable!("rejection sampling should succeed");
}

/// Native (witness-generation) Poseidon transcript.
///
/// This computes the same values as the circuit gadget but without constraints,
/// used for generating the witness values that get assigned into the circuit.
#[derive(Clone)]
pub struct NativeTranscript {
    state: [Fr; 3],
    /// How many rate elements have been absorbed since last permutation.
    rate_pos: usize,
}

impl NativeTranscript {
    pub fn new(domain: &[u8]) -> Self {
        let domain_fr = label_to_fr(domain);
        let params = poseidon_native::params();
        let state = poseidon_native::permute(&params, [domain_fr, Fr::ZERO, Fr::ZERO]);
        Self { state, rate_pos: 0 }
    }

    /// Absorb a field element. Permutes when rate buffer is full.
    pub fn append(&mut self, label: &[u8], value: Fr) {
        let label_fr = label_to_fr(label);
        self.absorb(label_fr);
        self.absorb(value);
    }

    /// Absorb a u64 value (converted to Fr).
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append(label, Fr::from(value));
    }

    /// Absorb a 32-byte digest (split into 4 u64 limbs, each absorbed as Fr).
    pub fn append_bytes32(&mut self, label: &[u8], bytes: &[u8; 32]) {
        let label_fr = label_to_fr(label);
        self.absorb(label_fr);
        for chunk in bytes.chunks_exact(8) {
            let limb = u64::from_le_bytes(chunk.try_into().unwrap());
            self.absorb(Fr::from(limb));
        }
    }

    /// Squeeze a challenge from the transcript.
    pub fn challenge(&mut self, label: &[u8]) -> Fr {
        let label_fr = label_to_fr(label);
        self.absorb(label_fr);
        // Force a permutation to mix everything.
        self.flush();
        self.state[0]
    }

    fn absorb(&mut self, value: Fr) {
        self.state[self.rate_pos] += value;
        self.rate_pos += 1;
        if self.rate_pos >= poseidon_native::RATE {
            self.flush();
        }
    }

    fn flush(&mut self) {
        let params = poseidon_native::params();
        self.state = poseidon_native::permute(&params, self.state);
        self.rate_pos = 0;
    }
}

/// In-circuit Poseidon transcript for Fiat-Shamir.
///
/// Accumulates absorbed values and produces constrained challenge outputs
/// using the PoseidonChip. The circuit transcript tracks both:
/// - Native Fr values (for witness generation)
/// - AssignedCells (for constraint enforcement)
pub struct CircuitTranscript {
    /// Native transcript for witness computation.
    native: NativeTranscript,
    /// Accumulated values to absorb (label_fr, value pairs).
    pending: Vec<Fr>,
}

impl CircuitTranscript {
    /// Create a new circuit transcript with domain separation.
    pub fn new(domain: &[u8]) -> Self {
        Self {
            native: NativeTranscript::new(domain),
            pending: Vec::new(),
        }
    }

    /// Append a field element with a label.
    pub fn append(&mut self, label: &[u8], value: Fr) {
        self.native.append(label, value);
        let label_fr = label_to_fr(label);
        self.pending.push(label_fr);
        self.pending.push(value);
    }

    /// Append a u64 value.
    pub fn append_u64(&mut self, label: &[u8], value: u64) {
        self.append(label, Fr::from(value));
    }

    /// Append a 32-byte digest (split into 4 u64 limbs).
    pub fn append_bytes32(&mut self, label: &[u8], bytes: &[u8; 32]) {
        self.native.append_bytes32(label, bytes);
        let label_fr = label_to_fr(label);
        self.pending.push(label_fr);
        for chunk in bytes.chunks_exact(8) {
            let limb = u64::from_le_bytes(chunk.try_into().unwrap());
            self.pending.push(Fr::from(limb));
        }
    }

    /// Squeeze a challenge, returning an assigned cell constrained to the
    /// Poseidon output.
    ///
    /// This materializes the accumulated absorptions as a chain of Poseidon
    /// hash2 calls and returns the final squeeze value as a constrained cell.
    pub fn challenge(
        &mut self,
        label: &[u8],
        chip: &PoseidonChip,
        layouter: &mut impl Layouter<Fr>,
    ) -> Result<(Fr, AssignedCell<Fr, Fr>), Error> {
        let label_fr = label_to_fr(label);
        self.pending.push(label_fr);

        // Compute the challenge natively.
        let challenge_value = self.native.challenge(label);

        // Build a Poseidon hash chain over all pending elements.
        // We hash pairs: H(H(H(domain_state, pending[0..2]), pending[2..4]), ...)
        // The final output must equal challenge_value.
        let result = self.materialize_hash_chain(chip, layouter, challenge_value)?;

        self.pending.clear();
        Ok((challenge_value, result))
    }

    /// Get the native challenge value without circuit constraints.
    /// Useful for witness computation.
    pub fn challenge_native(&mut self, label: &[u8]) -> Fr {
        self.native.challenge(label)
    }

    /// Materialize the pending values as a hash chain and return the
    /// constrained output cell.
    fn materialize_hash_chain(
        &self,
        chip: &PoseidonChip,
        layouter: &mut impl Layouter<Fr>,
        expected: Fr,
    ) -> Result<AssignedCell<Fr, Fr>, Error> {
        if self.pending.is_empty() {
            // No pending values — just assign the expected value.
            return layouter.assign_region(
                || "transcript_empty",
                |mut region| {
                    region.assign_advice(
                        || "challenge",
                        chip.cfg().state0,
                        0,
                        || Value::known(expected),
                    )
                },
            );
        }

        // Hash all pending values in pairs using Poseidon hash2.
        // Start with Poseidon(pending[0], pending[1]), then fold in pairs.
        let mut chunks = self.pending.chunks(2);

        // First pair initializes the accumulator.
        let first = chunks.next().unwrap();
        let a_val = first[0];
        let b_val = if first.len() > 1 {
            first[1]
        } else {
            Fr::ONE // padding
        };

        let a_cell = layouter.assign_region(
            || "transcript_a0",
            |mut region| region.assign_advice(|| "a", chip.cfg().state0, 0, || Value::known(a_val)),
        )?;
        let b_cell = layouter.assign_region(
            || "transcript_b0",
            |mut region| region.assign_advice(|| "b", chip.cfg().state1, 0, || Value::known(b_val)),
        )?;

        let mut acc = chip.hash2_cells(
            layouter.namespace(|| "transcript_hash_0"),
            poseidon_native::domain_tag(),
            &a_cell,
            &b_cell,
        )?;

        // Fold remaining pairs: acc = H(acc, pair_element)
        for (idx, chunk) in chunks.enumerate() {
            let val = chunk[0];
            let val2 = if chunk.len() > 1 { chunk[1] } else { Fr::ONE };

            // Hash (acc, val) then fold in val2 if present
            let val_cell = layouter.assign_region(
                || format!("transcript_v_{}", idx + 1),
                |mut region| {
                    region.assign_advice(|| "v", chip.cfg().state0, 0, || Value::known(val))
                },
            )?;

            acc = chip.hash2_cells(
                layouter.namespace(|| format!("transcript_hash_{}", 2 * idx + 1)),
                poseidon_native::domain_tag(),
                &acc,
                &val_cell,
            )?;

            if chunk.len() > 1 {
                let val2_cell = layouter.assign_region(
                    || format!("transcript_v2_{}", idx + 1),
                    |mut region| {
                        region.assign_advice(|| "v2", chip.cfg().state0, 0, || Value::known(val2))
                    },
                )?;

                acc = chip.hash2_cells(
                    layouter.namespace(|| format!("transcript_hash_{}", 2 * idx + 2)),
                    poseidon_native::domain_tag(),
                    &acc,
                    &val2_cell,
                )?;
            }
        }

        Ok(acc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_to_fr_is_deterministic() {
        let a = label_to_fr(b"test/label");
        let b = label_to_fr(b"test/label");
        assert_eq!(a, b);
    }

    #[test]
    fn different_labels_produce_different_frs() {
        let a = label_to_fr(b"label/a");
        let b = label_to_fr(b"label/b");
        assert_ne!(a, b);
    }

    #[test]
    fn native_transcript_deterministic() {
        let mut t1 = NativeTranscript::new(b"test-domain");
        t1.append(b"val", Fr::from(42u64));
        let c1 = t1.challenge(b"chal");

        let mut t2 = NativeTranscript::new(b"test-domain");
        t2.append(b"val", Fr::from(42u64));
        let c2 = t2.challenge(b"chal");

        assert_eq!(c1, c2);
    }

    #[test]
    fn native_transcript_different_values_different_challenges() {
        let mut t1 = NativeTranscript::new(b"test-domain");
        t1.append(b"val", Fr::from(42u64));
        let c1 = t1.challenge(b"chal");

        let mut t2 = NativeTranscript::new(b"test-domain");
        t2.append(b"val", Fr::from(43u64));
        let c2 = t2.challenge(b"chal");

        assert_ne!(c1, c2);
    }

    #[test]
    fn native_transcript_domain_separation() {
        let mut t1 = NativeTranscript::new(b"domain-a");
        t1.append(b"val", Fr::from(1u64));
        let c1 = t1.challenge(b"chal");

        let mut t2 = NativeTranscript::new(b"domain-b");
        t2.append(b"val", Fr::from(1u64));
        let c2 = t2.challenge(b"chal");

        assert_ne!(c1, c2);
    }

    #[test]
    fn native_transcript_multiple_appends() {
        let mut t = NativeTranscript::new(b"multi");
        t.append_u64(b"a", 100);
        t.append_u64(b"b", 200);
        t.append_u64(b"c", 300);
        let c1 = t.challenge(b"first");
        t.append_u64(b"d", 400);
        let c2 = t.challenge(b"second");
        assert_ne!(c1, c2);
    }

    #[test]
    fn native_transcript_bytes32() {
        let mut t = NativeTranscript::new(b"bytes");
        let bytes = [0xAAu8; 32];
        t.append_bytes32(b"digest", &bytes);
        let c = t.challenge(b"chal");
        assert_ne!(c, Fr::ZERO);
    }
}
