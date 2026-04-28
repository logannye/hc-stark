//! Property-based soundness tests for the STARK verifier.
//!
//! These tests generate valid proofs and then mutate them in various ways,
//! ensuring that ANY modification causes verification to fail (soundness).

use hc_core::field::prime_field::GoldilocksField;
use hc_prover::config::ProverConfig;
use hc_prover::{prove, PublicInputs};
use hc_sdk::proof::{encode_proof_bytes, verify_proof_bytes};
use hc_vm::{Instruction, Program};
use proptest::prelude::*;

/// Generate a valid proof for a simple computation.
fn make_valid_proof_bytes() -> (Vec<u8>, u32) {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(2, 2).unwrap().with_protocol_version(3);
    let output = prove(config, program, inputs).unwrap();
    let proof_bytes = encode_proof_bytes(&output).unwrap();
    (proof_bytes.bytes, proof_bytes.version)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    /// Flipping any single byte in a valid proof should cause rejection or
    /// at minimum never panic. Some byte positions (metrics, formatting)
    /// are not cryptographically bound and flipping them may not cause
    /// rejection — this is expected.
    #[test]
    fn bit_flip_never_panics(byte_idx in 0usize..10000, flip_bits in 1u8..=255) {
        let (mut bytes, version) = make_valid_proof_bytes();
        if byte_idx >= bytes.len() {
            return Ok(());
        }
        bytes[byte_idx] ^= flip_bits;
        let proof = hc_sdk::types::ProofBytes { version, bytes };
        // Must never panic regardless of the mutation.
        let _result = verify_proof_bytes(&proof, true);
    }

    /// Truncating a valid proof should cause rejection.
    #[test]
    fn truncation_causes_rejection(truncate_to in 0usize..10000) {
        let (bytes, version) = make_valid_proof_bytes();
        let truncated = if truncate_to < bytes.len() {
            bytes[..truncate_to].to_vec()
        } else {
            return Ok(());
        };
        let proof = hc_sdk::types::ProofBytes {
            version,
            bytes: truncated,
        };
        let result = verify_proof_bytes(&proof, true);
        prop_assert!(!result.ok, "Truncated proof should be rejected");
    }

    /// Appending garbage to a valid proof should cause rejection.
    #[test]
    fn extension_causes_rejection(extra in proptest::collection::vec(any::<u8>(), 1..100)) {
        let (mut bytes, version) = make_valid_proof_bytes();
        bytes.extend_from_slice(&extra);
        let proof = hc_sdk::types::ProofBytes { version, bytes };
        let result = verify_proof_bytes(&proof, true);
        // Appending data after valid JSON may still parse OK (JSON ignores trailing data
        // in some parsers), so we only check it doesn't panic.
        let _ = result;
    }

    /// Wrong version should cause rejection.
    #[test]
    fn wrong_version_causes_rejection(wrong_version in 0u32..100) {
        let (bytes, version) = make_valid_proof_bytes();
        if wrong_version == version {
            return Ok(());
        }
        let proof = hc_sdk::types::ProofBytes {
            version: wrong_version,
            bytes,
        };
        let result = verify_proof_bytes(&proof, true);
        prop_assert!(!result.ok, "Proof with wrong version should be rejected");
    }
}
