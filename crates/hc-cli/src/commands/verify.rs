use anyhow::Result;
use hc_core::field::prime_field::GoldilocksField;
use hc_verifier::verify;

use super::prove::{read_proof, run_prove, to_verifier_proof};

pub fn run_verify() -> Result<()> {
    let prover_output = run_prove()?;
    run_verify_with_output(prover_output)
}

pub fn run_verify_with_output(
    prover_output: hc_prover::queries::ProverOutput<GoldilocksField>,
) -> Result<()> {
    let proof = to_verifier_proof(&prover_output);
    verify(&proof)?;
    Ok(())
}

pub fn run_verify_from_file(path: &std::path::Path) -> Result<()> {
    let output = read_proof(path)?;
    run_verify_with_output(output)
}
