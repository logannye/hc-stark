//! Native Poseidon-based Fiat-Shamir transcript.
//!
//! This mirrors the API and label structure of `hc_hash::Transcript<Blake3>`,
//! but uses the BN254 Poseidon sponge for circuit-friendliness.
//!
//! During recursion, the in-circuit `CircuitTranscript` (in `circuit/transcript_gadget.rs`)
//! must produce identical challenges. This native implementation is used:
//!
//! 1. By the prover to pre-compute Poseidon-derived challenges for the recursion witness.
//! 2. As a reference to validate the in-circuit transcript gadget.
//!
//! The label-to-Fr mapping uses the same `label_to_fr()` function from the transcript gadget,
//! ensuring domain-separated absorption of protocol labels.

use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

use crate::circuit::poseidon::{self, PoseidonParams};
use crate::circuit::transcript_gadget::label_to_fr;

/// A native Poseidon transcript matching the circuit's `CircuitTranscript`.
///
/// Mirrors the Blake3 `Transcript` API: `append_message` + `challenge_bytes/field`.
/// All operations are domain-separated using the same canonical labels from
/// `hc_hash::protocol::label`.
#[derive(Clone)]
pub struct PoseidonTranscript {
    /// Current sponge state.
    state: [Fr; poseidon::WIDTH],
    /// Cached Poseidon parameters.
    params: PoseidonParams,
}

impl PoseidonTranscript {
    /// Create a new transcript with a domain separator.
    ///
    /// The domain bytes are hashed to Fr via `label_to_fr` and absorbed.
    pub fn new(domain: impl AsRef<[u8]>) -> Self {
        let params = poseidon::params();
        let domain_fr = label_to_fr(domain.as_ref());
        let mut state = [Fr::ZERO; poseidon::WIDTH];
        state[0] = poseidon::domain_tag();
        state = poseidon::permute(&params, state);
        // Absorb domain separator.
        state[0] += domain_fr;
        state = poseidon::permute(&params, state);
        Self { state, params }
    }

    /// Append a labeled message (bytes) to the transcript.
    ///
    /// Both label and data are converted to Fr elements and absorbed.
    pub fn append_message(&mut self, label: impl AsRef<[u8]>, data: impl AsRef<[u8]>) {
        let label_fr = label_to_fr(label.as_ref());
        let data_fr = label_to_fr(data.as_ref());
        self.state[0] += label_fr;
        self.state[1] += data_fr;
        self.state = poseidon::permute(&self.params, self.state);
    }

    /// Append a labeled Fr element to the transcript.
    pub fn append_fr(&mut self, label: impl AsRef<[u8]>, value: Fr) {
        let label_fr = label_to_fr(label.as_ref());
        self.state[0] += label_fr;
        self.state[1] += value;
        self.state = poseidon::permute(&self.params, self.state);
    }

    /// Append a labeled u64 value to the transcript.
    pub fn append_u64(&mut self, label: impl AsRef<[u8]>, value: u64) {
        self.append_fr(label, Fr::from(value));
    }

    /// Append a labeled 32-byte hash digest to the transcript.
    ///
    /// The digest is split into 4 x u64 limbs and each is absorbed.
    pub fn append_digest(&mut self, label: impl AsRef<[u8]>, digest_bytes: &[u8; 32]) {
        let label_fr = label_to_fr(label.as_ref());
        self.state[0] += label_fr;
        self.state = poseidon::permute(&self.params, self.state);
        // Absorb digest as 4 x u64 limbs (each as Fr).
        for chunk in digest_bytes.chunks_exact(8) {
            let limb = u64::from_le_bytes(chunk.try_into().unwrap());
            self.state[0] += Fr::from(limb);
            self.state = poseidon::permute(&self.params, self.state);
        }
    }

    /// Squeeze a challenge Fr element from the transcript.
    ///
    /// The label is absorbed, then the state is permuted and `state[0]` is returned.
    pub fn challenge(&mut self, label: impl AsRef<[u8]>) -> Fr {
        let label_fr = label_to_fr(label.as_ref());
        self.state[0] += label_fr;
        self.state = poseidon::permute(&self.params, self.state);
        self.state[0]
    }

    /// Get the current sponge state (for advanced use / witness extraction).
    pub fn state(&self) -> [Fr; poseidon::WIDTH] {
        self.state
    }
}

/// Compute a Poseidon-Merkle root from leaf hashes.
///
/// Each leaf is a Poseidon hash. Internal nodes are `Poseidon(left, right)`.
/// This mirrors the Blake3-Merkle tree structure in `hc-commit` but uses Poseidon.
pub fn poseidon_merkle_root(leaves: &[Fr]) -> Fr {
    if leaves.is_empty() {
        return Fr::ZERO;
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    // Build tree bottom-up.
    let mut layer: Vec<Fr> = leaves.to_vec();

    // Pad to power of 2.
    let next_pow2 = layer.len().next_power_of_two();
    layer.resize(next_pow2, Fr::ZERO);

    while layer.len() > 1 {
        let mut next = Vec::with_capacity(layer.len() / 2);
        for pair in layer.chunks_exact(2) {
            next.push(poseidon::hash(&[pair[0], pair[1]]));
        }
        layer = next;
    }

    layer[0]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_hash::protocol;

    #[test]
    fn poseidon_transcript_deterministic() {
        let mut t1 = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);
        t1.append_u64(protocol::label::PUB_INITIAL_ACC, 5);
        t1.append_u64(protocol::label::PUB_FINAL_ACC, 42);
        let c1 = t1.challenge(protocol::label::CHAL_OOD_POINT);

        let mut t2 = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);
        t2.append_u64(protocol::label::PUB_INITIAL_ACC, 5);
        t2.append_u64(protocol::label::PUB_FINAL_ACC, 42);
        let c2 = t2.challenge(protocol::label::CHAL_OOD_POINT);

        assert_eq!(c1, c2);
    }

    #[test]
    fn poseidon_transcript_different_inputs_different_challenges() {
        let mut t1 = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);
        t1.append_u64(protocol::label::PUB_INITIAL_ACC, 5);
        let c1 = t1.challenge(protocol::label::CHAL_OOD_POINT);

        let mut t2 = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);
        t2.append_u64(protocol::label::PUB_INITIAL_ACC, 6);
        let c2 = t2.challenge(protocol::label::CHAL_OOD_POINT);

        assert_ne!(c1, c2);
    }

    #[test]
    fn poseidon_transcript_domain_separation() {
        let mut t1 = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);
        t1.append_u64(protocol::label::PUB_INITIAL_ACC, 5);
        let c1 = t1.challenge(protocol::label::CHAL_OOD_POINT);

        let mut t2 = PoseidonTranscript::new(protocol::DOMAIN_FRI_V3);
        t2.append_u64(protocol::label::PUB_INITIAL_ACC, 5);
        let c2 = t2.challenge(protocol::label::CHAL_OOD_POINT);

        assert_ne!(c1, c2);
    }

    #[test]
    fn poseidon_merkle_root_single_leaf() {
        let leaf = poseidon::hash(&[Fr::from(42u64)]);
        let root = poseidon_merkle_root(&[leaf]);
        assert_eq!(root, leaf);
    }

    #[test]
    fn poseidon_merkle_root_two_leaves() {
        let l0 = poseidon::hash(&[Fr::from(1u64)]);
        let l1 = poseidon::hash(&[Fr::from(2u64)]);
        let root = poseidon_merkle_root(&[l0, l1]);
        let expected = poseidon::hash(&[l0, l1]);
        assert_eq!(root, expected);
    }

    #[test]
    fn poseidon_merkle_root_four_leaves() {
        let leaves: Vec<Fr> = (0..4)
            .map(|i| poseidon::hash(&[Fr::from(i as u64)]))
            .collect();
        let root = poseidon_merkle_root(&leaves);

        // Manual: left = H(l0, l1), right = H(l2, l3), root = H(left, right)
        let left = poseidon::hash(&[leaves[0], leaves[1]]);
        let right = poseidon::hash(&[leaves[2], leaves[3]]);
        let expected = poseidon::hash(&[left, right]);
        assert_eq!(root, expected);
    }

    #[test]
    fn poseidon_merkle_root_pads_to_pow2() {
        // 3 leaves → padded to 4 with zeros.
        let leaves: Vec<Fr> = (0..3)
            .map(|i| poseidon::hash(&[Fr::from(i as u64 + 1)]))
            .collect();
        let root = poseidon_merkle_root(&leaves);

        let mut padded = leaves.clone();
        padded.push(Fr::ZERO);
        let left = poseidon::hash(&[padded[0], padded[1]]);
        let right = poseidon::hash(&[padded[2], padded[3]]);
        let expected = poseidon::hash(&[left, right]);
        assert_eq!(root, expected);
    }

    #[test]
    fn poseidon_transcript_append_digest() {
        let mut t = PoseidonTranscript::new(protocol::DOMAIN_MAIN_V3);
        let digest = [0xAAu8; 32];
        t.append_digest(protocol::label::COMMIT_TRACE_LDE_ROOT, &digest);
        let c = t.challenge(protocol::label::CHAL_OOD_POINT);
        assert_ne!(c, Fr::ZERO);
    }
}
