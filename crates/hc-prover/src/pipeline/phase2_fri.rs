use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::{FriConfig, FriProof, FriProver};
use hc_hash::Blake3;

use crate::transcript::ProverTranscript;

pub fn run_fri<F: FieldElement>(config: FriConfig, evaluations: Vec<F>) -> HcResult<FriProof<F>> {
    let mut transcript = ProverTranscript::new("fri");
    let mut prover = FriProver::<F, Blake3>::new(config, &mut transcript);
    prover.prove(evaluations)
}
