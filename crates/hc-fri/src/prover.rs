use std::sync::Arc;

use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::{hash::HashFunction, Transcript};
use hc_replay::{config::ReplayConfig, trace_replay::TraceReplay, VecBlockProducer};

use crate::{
    config::FriConfig,
    layer::{FriFinalLayer, FriLayer},
    queries::FriProof,
    stream::{fold_layer_streaming, StreamingStats},
    util::serialize_evaluations,
};

pub struct FriProver<'a, F: FieldElement, H: HashFunction> {
    config: FriConfig,
    transcript: &'a mut Transcript<H>,
    _marker: core::marker::PhantomData<F>,
    stream_stats: StreamingStats,
}

impl<'a, F: FieldElement, H: HashFunction> FriProver<'a, F, H> {
    pub fn new(config: FriConfig, transcript: &'a mut Transcript<H>) -> Self {
        Self {
            config,
            transcript,
            _marker: core::marker::PhantomData,
            stream_stats: StreamingStats::default(),
        }
    }

    fn replay_from_arc(
        &self,
        values: Arc<Vec<F>>,
    ) -> HcResult<TraceReplay<VecBlockProducer<F>, F>> {
        let block_size = values.len().clamp(1, 1024);
        let config = ReplayConfig::new(block_size, values.len())?;
        TraceReplay::new(config, VecBlockProducer::from_arc(values))
    }

    pub fn prove(&mut self, evaluations: Vec<F>) -> HcResult<(FriProof<F>, StreamingStats)> {
        self.config.validate_trace_length(evaluations.len())?;
        let mut layers = Vec::new();
        let mut current = evaluations;
        while current.len() > self.config.final_polynomial_size() {
            let current_arc = Arc::new(current);
            self.transcript
                .append_message("fri_layer", serialize_evaluations(current_arc.as_ref()));
            let beta = self.transcript.challenge_field::<F>("fri_beta");
            let mut replay = self.replay_from_arc(Arc::clone(&current_arc))?;
            let layer = FriLayer::from_values(beta, Arc::clone(&current_arc))?;
            layers.push(layer);
            let (next_layer, stats) = fold_layer_streaming(&mut replay, beta)?;
            self.stream_stats.blocks_loaded += stats.blocks_loaded;
            current = next_layer;
        }
        let final_values = Arc::new(current);
        let final_layer = FriFinalLayer::from_values(final_values)?;
        Ok((FriProof::new(layers, final_layer), self.stream_stats))
    }
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
        let (proof, _) = FriProver::<GoldilocksField, Blake3>::new(config, &mut prover_transcript)
            .prove(evaluations)
            .unwrap();
        let mut verifier_transcript = Transcript::<Blake3>::new("fri");
        FriVerifier::<GoldilocksField, Blake3>::new(config, &mut verifier_transcript)
            .verify(&proof)
            .unwrap();
        assert!(!proof.final_layer.is_empty());
        let path = proof.final_layer.merkle_path(0).unwrap();
        let leaf = proof.final_layer.evaluations()[0];
        let leaf_hash = FriFinalLayer::hash_leaf(&leaf);
        assert!(path.verify::<Blake3>(proof.final_layer.merkle_root(), leaf_hash));
    }
}
