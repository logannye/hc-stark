use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::{FriConfig, FriProof, FriVerifier};

pub fn verify_fri<F: FieldElement>(config: FriConfig, proof: &FriProof<F>) -> HcResult<()> {
    let mut verifier = FriVerifier::<F>::new(config);
    verifier.verify(proof).map(|_| ())
}
