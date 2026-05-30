use hc_core::field::prime_field::GoldilocksField;
#[allow(deprecated)] // exercises the legacy v3 prove + lower-level verify on purpose.
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_sdk::proof::decode_proof_bytes;
use hc_vm::{Instruction, Program};

/// Tampering a consensus-critical field (the trace commitment root) of a v3
/// proof must be rejected by the lower-level `hc_verifier::verify`.
///
/// Phase 1A note: the production `verify_proof_bytes` endpoint now rejects
/// every pre-v5 proof by version alone, which would mask tampering detection.
/// To keep this test MEANINGFUL (it asserts the crypto rejects a tampered
/// witness, not merely that v3 is unsupported), it drives the lower-level v3
/// verifier directly.
#[test]
fn mutated_proof_bytes_reject() {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(8, 2).unwrap();
    #[allow(deprecated)]
    let output = prove(config, program, inputs).unwrap();
    let proof = hc_sdk::proof::encode_proof_bytes(&output).unwrap();

    // Deterministically mutate a consensus-critical field (trace commitment root).
    // This avoids probabilistic/flaky behavior from byte-level mutations that might
    // only touch whitespace or other non-semantic JSON bytes.
    let mut v: serde_json::Value = serde_json::from_slice(&proof.bytes).expect("proof is JSON");
    let root = v["trace_commitment"]["root"]
        .as_str()
        .expect("stark trace_commitment.root");
    assert!(!root.is_empty(), "expected non-empty trace_commitment.root");
    let mut chars: Vec<char> = root.chars().collect();
    chars[0] = if chars[0] == '0' { '1' } else { '0' };
    v["trace_commitment"]["root"] = serde_json::Value::String(chars.into_iter().collect());

    let mutated = hc_sdk::types::ProofBytes {
        version: proof.version,
        bytes: serde_json::to_vec(&v).expect("serialize mutated json"),
    };

    // Decode the tampered bytes and run them through the lower-level v3 verifier.
    let decoded = decode_proof_bytes(&mutated).expect("tampered-but-structurally-valid proof");
    let lower = hc_verifier::Proof {
        version: decoded.version,
        trace_commitment: decoded.trace_commitment.clone(),
        composition_commitment: decoded.composition_commitment.clone(),
        fri_proof: decoded.fri_proof.clone(),
        initial_acc: decoded.public_inputs.initial_acc,
        final_acc: decoded.public_inputs.final_acc,
        query_response: decoded.query_response.clone(),
        trace_length: decoded.trace_length,
        params: decoded.params,
    };
    #[allow(deprecated)]
    let result = hc_verifier::verify(&lower);
    assert!(
        result.is_err(),
        "mutated proof unexpectedly verified (tampered trace root)"
    );
}
