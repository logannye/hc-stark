use std::time::Instant;

use hc_core::{
    error::{HcError, HcResult},
    field::prime_field::GoldilocksField,
};
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_verifier::{verify, Proof};
use hc_vm::{Instruction, Program};
use serde_json::json;

pub fn bench_verifier(iterations: usize) -> HcResult<serde_json::Value> {
    let iterations = iterations.max(1);
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(2, 2)?;
    let output = prove(config, program, inputs.clone())?;
    let proof = Proof {
        version: output.version,
        trace_commitment: output.trace_commitment,
        composition_commitment: output.composition_commitment,
        fri_proof: output.fri_proof,
        initial_acc: inputs.initial_acc,
        final_acc: inputs.final_acc,
        query_response: output.query_response,
        trace_length: output.trace_length,
        params: output.params,
    };

    // Sanity.
    verify(&proof)
        .map_err(|err| HcError::message(format!("baseline proof did not verify: {err}")))?;

    let start = Instant::now();
    for _ in 0..iterations {
        verify(&proof)?;
    }
    let elapsed = start.elapsed().as_secs_f64() * 1000.0;
    Ok(json!({
        "iterations": iterations,
        "total_ms": elapsed,
        "avg_ms": elapsed / iterations as f64,
    }))
}
