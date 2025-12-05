use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_hash::{hash::HashFunction, Transcript};

use crate::{
    config::FriConfig, layer::fold_layer, oracles::FriOracle, queries::FriProof,
    util::serialize_evaluations,
};

pub struct FriVerifier<'a, F: FieldElement, H: HashFunction> {
    config: FriConfig,
    transcript: &'a mut Transcript<H>,
    _marker: core::marker::PhantomData<F>,
}

impl<'a, F: FieldElement, H: HashFunction> FriVerifier<'a, F, H> {
    pub fn new(config: FriConfig, transcript: &'a mut Transcript<H>) -> Self {
        Self {
            config,
            transcript,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn verify(&mut self, proof: &FriProof<F>) -> HcResult<()> {
        if proof.layers.is_empty() {
            return Err(HcError::invalid_argument("FRI proof missing layers"));
        }
        for (index, layer) in proof.layers.iter().enumerate() {
            self.transcript.append_message(
                "fri_layer",
                serialize_evaluations(layer.oracle.evaluations()),
            );
            let beta = self.transcript.challenge_field::<F>("fri_beta");
            if beta != layer.beta {
                return Err(HcError::message("beta mismatch"));
            }
            let next = fold_layer(layer.oracle.evaluations(), beta)?;
            let expected = if let Some(next_layer) = proof.layers.get(index + 1) {
                next_layer.oracle.evaluations()
            } else {
                proof.final_layer.evaluations()
            };
            if next.len() != expected.len()
                || !next
                    .iter()
                    .zip(expected.iter())
                    .all(|(lhs, rhs)| lhs == rhs)
            {
                return Err(HcError::message("FRI folding mismatch"));
            }
        }
        if proof.final_layer.len() > self.config.final_polynomial_size() {
            return Err(HcError::invalid_argument(
                "final layer larger than configuration",
            ));
        }
        Ok(())
    }
}
