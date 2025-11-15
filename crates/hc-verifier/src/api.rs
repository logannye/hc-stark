use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::FriConfig;
use hc_hash::hash::HashDigest;

use crate::{errors::VerifierError, fri_verify};

// Re-export query types for convenience
pub use hc_prover::queries::{QueryResponse, TraceQuery, FriQuery};

#[derive(Clone, Debug)]
pub struct Proof<F: FieldElement> {
    pub trace_root: HashDigest,
    pub fri_proof: hc_fri::FriProof<F>,
    pub initial_acc: F,
    pub final_acc: F,
    pub query_response: Option<QueryResponse<F>>,
}

pub fn verify<F: FieldElement>(proof: &Proof<F>) -> HcResult<()> {
    if proof.final_acc == proof.initial_acc {
        return Err(VerifierError::InvalidPublicInputs.into());
    }

    // Check that query responses are present (basic check for now)
    if proof.query_response.is_none() {
        return Err(VerifierError::MissingQueryResponses.into());
    }

    let config = FriConfig::new(2)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;

    // TODO: Implement full query verification
    // This would include:
    // 1. Verifying trace query Merkle paths against trace_root
    // 2. Verifying FRI query Merkle paths and evaluation consistency
    // 3. Checking that queries were generated correctly from transcript

    Ok(())
}
