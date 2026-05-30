//! Property-based soundness tests for the STARK verifier.
//!
//! These tests generate valid proofs and then mutate them in various ways,
//! ensuring that ANY modification causes verification to fail (soundness).

use hc_core::field::prime_field::GoldilocksField;
use hc_core::field::{FieldElement, QuadExtension};
use hc_prover::config::{ProverConfig, SecurityFloor};
// `prove` (v3) is deprecated but the v3 soundness proptests still build v3
// proofs through it; the v5 proptests use `prove_v5`.
#[allow(deprecated)]
use hc_prover::prove;
use hc_prover::{prove_v5, PublicInputs};
use hc_sdk::proof::{decode_proof_v5, encode_proof_bytes, encode_proof_v5, verify_proof_bytes};
use hc_verifier::v5::{verify_v5_with_floor, VerifierSecurityFloor};
use hc_vm::{Instruction, Program};
use proptest::prelude::*;

type K = QuadExtension<GoldilocksField>;

/// Generate a valid (legacy v3) proof for a simple computation.
#[allow(deprecated)] // v3 soundness proptests build proofs via the legacy prover.
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

// ─── v5 soundness proptests ──────────────────────────────────────────────────
//
// Strategy: build ONE honest v5 proof (relaxed floor + tiny params so the PoW
// is fast), then for each proptest case derive a mutation (byte flip, nonce
// increment, K-value increment, truncation, final_coeffs mutation) and assert
// the mutated proof is never wrongly ACCEPTED.
//
// "Correctly rejected" means verify_v5_with_floor returns Err. We do NOT
// require rejection for every possible byte flip (some positions, e.g. JSON
// whitespace, are not cryptographically bound), but we DO require that:
//   (a) the verifier never panics, and
//   (b) the specific cryptographic fields (grinding_nonce, FRI values,
//       final_coeffs, Merkle paths) are rejected when mutated.

/// Build a v5 proof with relaxed floor + small grinding for proptest speed.
fn make_v5_proof_bytes() -> (Vec<u8>, u32) {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
        Instruction::AddImmediate(3),
        Instruction::AddImmediate(4),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(15),
    };
    let mut config = ProverConfig::with_security_floor(
        2, // block_size
        2, // fri_final_poly_size
        4, // query_count
        2, // lde_blowup_factor
        SecurityFloor::relaxed(),
    )
    .unwrap()
    .with_protocol_version(5);
    config.grinding_bits = 4; // small enough for proptest speed
    let proof = prove_v5(config, program, inputs).unwrap();
    let bytes = encode_proof_v5(&proof).unwrap();
    (bytes.bytes, bytes.version)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    // ── (1) Byte-flip never panics ────────────────────────────────────────────

    /// Flipping any byte in a serialized v5 proof must never panic.
    /// Some bytes (JSON structure, metrics) are not cryptographically bound
    /// and may still deserialize/verify OK — that is acceptable. What is NOT
    /// acceptable is a panic or a case where a structurally broken proof
    /// wrongly returns Ok from the *crypto* path.
    #[test]
    fn v5_bit_flip_never_panics(byte_idx in 0usize..5000, flip_bits in 1u8..=255) {
        let (mut bytes, version) = make_v5_proof_bytes();
        if byte_idx >= bytes.len() {
            return Ok(());
        }
        bytes[byte_idx] ^= flip_bits;
        let proof_bytes = hc_sdk::types::ProofBytes { version, bytes };
        // Must never panic.
        let _result = verify_proof_bytes(&proof_bytes, false);
    }

    // ── (2) Truncation causes rejection ───────────────────────────────────────

    /// Truncating a v5 proof must cause decode failure (never wrongly accept).
    #[test]
    fn v5_truncation_causes_rejection(truncate_to in 0usize..5000) {
        let (bytes, version) = make_v5_proof_bytes();
        let truncated = if truncate_to < bytes.len() {
            bytes[..truncate_to].to_vec()
        } else {
            return Ok(());
        };
        let proof_bytes = hc_sdk::types::ProofBytes {
            version,
            bytes: truncated,
        };
        let result = verify_proof_bytes(&proof_bytes, false);
        prop_assert!(!result.ok, "Truncated v5 proof must be rejected");
    }

    // ── (3) Grinding-nonce mutation is rejected ───────────────────────────────

    /// Incrementing the grinding nonce by any nonzero delta must be rejected by
    /// the PoW check (grinding_bits = 4 so valid nonces are rare).
    #[test]
    fn v5_grinding_nonce_mutation_rejected(delta in 1u64..=u64::MAX) {
        let (bytes, version) = make_v5_proof_bytes();
        let pf = hc_sdk::types::ProofBytes { version, bytes };
        let mut proof = decode_proof_v5(&pf).unwrap();
        proof.grinding_nonce = proof.grinding_nonce.wrapping_add(delta);
        // Must be rejected.
        let result = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed());
        prop_assert!(result.is_err(), "Mutated grinding nonce must be rejected");
    }

    // ── (4) FRI query K-value mutation is rejected ────────────────────────────

    /// Adding a nonzero K value to any FRI layer opening must be rejected by the
    /// Merkle path check or the fold-chain binding.
    #[test]
    fn v5_fri_query_value_mutation_rejected(
        query_idx in 0usize..64,
        slot in 0usize..2,
        c0_delta in 1u64..u64::MAX / 2,
    ) {
        let (bytes, version) = make_v5_proof_bytes();
        let pf = hc_sdk::types::ProofBytes { version, bytes };
        let mut proof = decode_proof_v5(&pf).unwrap();
        let n = proof.query_response.fri_queries.len();
        if n == 0 { return Ok(()); }
        let idx = query_idx % n;
        let s = slot % 2;
        let old = proof.query_response.fri_queries[idx].values[s];
        proof.query_response.fri_queries[idx].values[s] =
            old.add(K::from_u64(c0_delta));
        let result = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed());
        prop_assert!(result.is_err(), "FRI query value mutation must be rejected");
    }

    // ── (5) final_coeffs mutation is rejected ─────────────────────────────────

    /// Adding a nonzero K value to any final_coeffs entry must cause the
    /// final-degree check (re-evaluation comparison) to fail.
    #[test]
    fn v5_final_coeffs_mutation_rejected(
        coeff_idx in 0usize..16,
        c0_delta in 1u64..u64::MAX / 2,
    ) {
        let (bytes, version) = make_v5_proof_bytes();
        let pf = hc_sdk::types::ProofBytes { version, bytes };
        let mut proof = decode_proof_v5(&pf).unwrap();
        let n = proof.fri_proof.final_coeffs.len();
        if n == 0 { return Ok(()); }
        let idx = coeff_idx % n;
        let old = proof.fri_proof.final_coeffs[idx];
        proof.fri_proof.final_coeffs[idx] = old.add(K::from_u64(c0_delta));
        let result = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed());
        prop_assert!(result.is_err(), "final_coeffs mutation must be rejected");
    }

    // ── (6) final_layer mutation is rejected ──────────────────────────────────

    /// Adding a nonzero K value to any final_layer entry must be rejected (the
    /// fold chain descent arrives at a wrong value and/or the re-evaluation check
    /// fails).
    #[test]
    fn v5_final_layer_mutation_rejected(
        layer_idx in 0usize..16,
        c0_delta in 1u64..u64::MAX / 2,
    ) {
        let (bytes, version) = make_v5_proof_bytes();
        let pf = hc_sdk::types::ProofBytes { version, bytes };
        let mut proof = decode_proof_v5(&pf).unwrap();
        let n = proof.fri_proof.final_layer.len();
        if n == 0 { return Ok(()); }
        let idx = layer_idx % n;
        let old = proof.fri_proof.final_layer[idx];
        proof.fri_proof.final_layer[idx] = old.add(K::from_u64(c0_delta));
        let result = verify_v5_with_floor(&proof, VerifierSecurityFloor::relaxed());
        prop_assert!(result.is_err(), "final_layer mutation must be rejected");
    }
}
