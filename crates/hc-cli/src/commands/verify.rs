use anyhow::Result;
use hc_core::field::prime_field::GoldilocksField;
use hc_prover::commitment::CommitmentScheme;
use hc_verifier::verify;

use super::prove::{read_proof, run_prove, to_verifier_proof, ProveOptions};

pub fn run_verify(allow_legacy_v2: bool) -> Result<()> {
    let prover_output = run_prove(&ProveOptions::default())?;
    run_verify_with_output(prover_output, allow_legacy_v2)
}

pub fn run_verify_with_output(
    prover_output: hc_prover::queries::ProverOutput<GoldilocksField>,
    allow_legacy_v2: bool,
) -> Result<()> {
    if prover_output.version < 3
        && prover_output.commitment_scheme == CommitmentScheme::Stark
        && !allow_legacy_v2
    {
        anyhow::bail!(
            "refusing to verify legacy v{} Stark proof without --allow-legacy-v2",
            prover_output.version
        );
    }
    let proof = to_verifier_proof(&prover_output);
    verify(&proof)?;
    Ok(())
}

pub fn run_verify_from_file(path: &std::path::Path, allow_legacy_v2: bool) -> Result<()> {
    let output = read_proof(path)?;
    run_verify_with_output(output, allow_legacy_v2)
}
