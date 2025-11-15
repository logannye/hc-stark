use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::FriConfig;
use hc_hash::hash::HashDigest;

use crate::{errors::VerifierError, fri_verify};

#[derive(Clone, Debug)]
pub struct Proof<F: FieldElement> {
    pub trace_root: HashDigest,
    pub fri_proof: hc_fri::FriProof<F>,
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn verify<F: FieldElement>(proof: &Proof<F>) -> HcResult<()> {
    if proof.final_acc == proof.initial_acc {
        return Err(VerifierError::InvalidPublicInputs.into());
    }
    let config = FriConfig::new(2)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;
    Ok(())
}
