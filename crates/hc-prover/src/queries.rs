use hc_fri::FriProof;
use hc_hash::hash::HashDigest;

use crate::PublicInputs;

#[derive(Clone, Debug)]
pub struct ProverOutput<F: hc_core::field::FieldElement> {
    pub trace_root: HashDigest,
    pub fri_proof: FriProof<F>,
    pub public_inputs: PublicInputs<F>,
}
