use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::{FriConfig, FriProof, FriVerifier};
use hc_hash::Blake3;

use crate::transcript::VerifierTranscript;

pub fn verify_fri<F: FieldElement>(config: FriConfig, proof: &FriProof<F>) -> HcResult<()> {
    let mut transcript = VerifierTranscript::new("fri");
    let mut verifier = FriVerifier::<F, Blake3>::new(config, &mut transcript);
    verifier.verify(proof).map(|_| ())
}
