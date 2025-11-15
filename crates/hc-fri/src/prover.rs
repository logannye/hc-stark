use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::{hash::HashFunction, Transcript};

use crate::{
    config::FriConfig,
    layer::{fold_layer, FriLayer},
    oracles::InMemoryFriOracle,
    queries::FriProof,
    util::serialize_evaluations,
};

pub struct FriProver<'a, F: FieldElement, H: HashFunction> {
    config: FriConfig,
    transcript: &'a mut Transcript<H>,
    _marker: core::marker::PhantomData<F>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verifier::FriVerifier;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_hash::Blake3;

    #[test]
    fn prover_and_verifier_roundtrip() {
        let config = FriConfig::new(2).unwrap();
        let mut prover_transcript = Transcript::<Blake3>::new("fri");
        let evaluations: Vec<_> = (0u64..8).map(GoldilocksField::from_u64).collect();
        let proof = FriProver::<GoldilocksField, Blake3>::new(config, &mut prover_transcript)
            .prove(evaluations)
            .unwrap();
        let mut verifier_transcript = Transcript::<Blake3>::new("fri");
        FriVerifier::<GoldilocksField, Blake3>::new(config, &mut verifier_transcript)
            .verify(&proof)
            .unwrap();
    }
}

impl<'a, F: FieldElement, H: HashFunction> FriProver<'a, F, H> {
    pub fn new(config: FriConfig, transcript: &'a mut Transcript<H>) -> Self {
        Self {
            config,
            transcript,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn prove(&mut self, evaluations: Vec<F>) -> HcResult<FriProof<F>> {
        self.config.validate_trace_length(evaluations.len())?;
        let mut layers = Vec::new();
        let mut current = evaluations;
        while current.len() > self.config.final_polynomial_size() {
            self.transcript
                .append_message("fri_layer", serialize_evaluations(&current));
            let beta = self.transcript.challenge_field::<F>("fri_beta");
            layers.push(FriLayer {
                beta,
                oracle: InMemoryFriOracle::new(current.clone()),
            });
            current = fold_layer(&current, beta)?;
        }
        Ok(FriProof::new(layers, current))
    }
}
