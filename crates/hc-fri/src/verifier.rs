use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::{
    config::FriConfig,
    layer::{compute_leaf_hashes, merkle_root_from_hashes},
    queries::FriProof,
};

/// Verifier-side checks for the *committed* final layer of a FRI proof.
///
/// Important: this does **not** verify folding consistency; that is an oracle
/// protocol check that must be performed by a higher-level verifier using:
/// - committed layer roots,
/// - opened coset pairs (and Merkle paths) at query indices,
/// - transcript-derived folding challenges (betas),
/// - the final polynomial values.
///
/// See `hc-verifier::api::verify_fri_queries` for the full oracle check.
pub struct FriVerifier<F: FieldElement> {
    config: FriConfig,
    _marker: core::marker::PhantomData<F>,
}

impl<F: FieldElement> FriVerifier<F> {
    pub fn new(config: FriConfig) -> Self {
        Self {
            config,
            _marker: core::marker::PhantomData,
        }
    }

    pub fn verify(&mut self, proof: &FriProof<F>) -> HcResult<()> {
        if proof.final_layer.is_empty() {
            return Err(HcError::invalid_argument("final FRI layer is empty"));
        }
        if proof.final_layer.len() != self.config.final_polynomial_size() {
            return Err(HcError::invalid_argument(
                "final layer size does not match configuration",
            ));
        }

        // Sanity check final root matches the provided final evaluations.
        let hashes = compute_leaf_hashes(proof.final_layer.as_slice());
        let computed = merkle_root_from_hashes(&hashes)?;
        if computed != proof.final_root {
            return Err(HcError::message("final FRI root mismatch"));
        }

        Ok(())
    }
}
