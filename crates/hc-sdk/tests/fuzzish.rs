use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_vm::{Instruction, Program};

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

    let result = hc_sdk::proof::verify_proof_bytes(&mutated, true);
    assert!(
        !result.ok,
        "mutated proof unexpectedly verified (tampered trace root)"
    );
}
