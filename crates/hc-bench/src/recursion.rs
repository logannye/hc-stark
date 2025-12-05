use std::time::Instant;

use hc_core::{
    error::{HcError, HcResult},
    field::prime_field::GoldilocksField,
};
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_recursion::wrap_proofs;
use hc_verifier::Proof;
use hc_vm::{Instruction, Program};
use serde_json::json;

pub fn bench_recursion(proofs: usize) -> HcResult<serde_json::Value> {
    if proofs == 0 {
        return Err(HcError::invalid_argument(
            "recursion bench requires at least one proof",
        ));
    }
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let config = ProverConfig::new(2, 2)?;

    let mut leaf_proofs = Vec::with_capacity(proofs);
    for offset in 0..proofs {
        let inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5 + offset as u64),
            final_acc: GoldilocksField::new(8 + offset as u64),
        };
        let prover = prove(config, program.clone(), inputs.clone())?;
        leaf_proofs.push(Proof {
            trace_commitment: prover.trace_commitment,
            composition_commitment: prover.composition_commitment,
            fri_proof: prover.fri_proof,
            initial_acc: inputs.initial_acc,
            final_acc: inputs.final_acc,
            query_response: prover.query_response,
            trace_length: prover.trace_length,
        });
    }

    let start = Instant::now();
    let aggregated = wrap_proofs(&leaf_proofs)?;
    aggregated.verify()?;
    let elapsed = start.elapsed();

    Ok(json!({
        "proofs": proofs,
        "depth": aggregated.schedule.depth(),
        "batches": aggregated.schedule.total_batches(),
        "duration_ms": elapsed.as_secs_f64() * 1000.0,
    }))
}
