use anyhow::Result;
use hc_core::field::prime_field::GoldilocksField;
use hc_verifier::{verify, Proof};

use super::prove::run_prove;

pub fn run_verify() -> Result<()> {
    let prover_output = run_prove()?;
    let proof = Proof::<GoldilocksField> {
        trace_root: prover_output.trace_root,
        fri_proof: prover_output.fri_proof,
        initial_acc: prover_output.public_inputs.initial_acc,
        final_acc: prover_output.public_inputs.final_acc,
    };
    verify(&proof)?;
    Ok(())
}
