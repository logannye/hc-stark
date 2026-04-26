use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::hash::HashDigest;
use hc_hash::protocol;
use hc_hash::{hash::HashFunction, Transcript};
use hc_replay::{block_range::BlockRange, traits::BlockProducer, VecBlockProducer};
use rayon::prelude::*;
use std::sync::Arc;

use crate::{
    config::FriConfig, parallel::compute_leaf_hashes_parallel, queries::FriProof,
    stream::StreamingStats,
};

#[derive(Clone)]
pub struct FriProverArtifacts<F: FieldElement> {
    /// The succinct proof artifact (roots + final layer).
    pub proof: FriProof<F>,
    /// The FRI folding challenges (one per committed layer root).
    ///
    /// These are not part of the proof format; they are derived from the prover transcript
    /// and are used to answer query openings without buffering full layers.
    pub betas: Vec<F>,
    /// The producer for the *base* layer evaluations (length = `base_length`).
    pub base_producer: Arc<dyn BlockProducer<F>>,
    /// The length of the base layer (must be a power of two).
    pub base_length: usize,
    pub stats: StreamingStats,
}

pub struct FriProver<'a, F: FieldElement, H: HashFunction> {
    config: FriConfig,
    transcript: &'a mut Transcript<H>,
    _marker: core::marker::PhantomData<F>,
    stream_stats: StreamingStats,
}

#[derive(Clone)]
struct FoldedLayerProducer<F: FieldElement> {
    prev: Arc<dyn BlockProducer<F>>,
    prev_len: usize,
    beta: F,
}

/// Threshold for switching from sequential to parallel folding.
/// Below this, Rayon overhead exceeds the computation benefit.
const PARALLEL_FOLD_THRESHOLD: usize = 512;

impl<F: FieldElement> BlockProducer<F> for FoldedLayerProducer<F> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<F>> {
        let out_len = self.prev_len / 2;
        let end = range.end().min(out_len);
        if range.start >= end {
            return Ok(Vec::new());
        }
        let len = end - range.start;
        let prev_range = BlockRange::new(range.start * 2, len * 2);
        let prev_values = self.prev.produce(prev_range)?;

        let out = if len >= PARALLEL_FOLD_THRESHOLD {
            // Parallel: each pair fold is independent.
            prev_values
                .par_chunks(2)
                .map(|pair| pair[0].add(self.beta.mul(pair[1])))
                .collect()
        } else {
            // Sequential: avoid Rayon overhead for small blocks.
            let mut out = Vec::with_capacity(len);
            for pair in prev_values.chunks(2) {
                out.push(pair[0].add(self.beta.mul(pair[1])));
            }
            out
        };
        Ok(out)
    }
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

    pub fn prove_with_producer(
        &mut self,
        producer: Arc<dyn BlockProducer<F>>,
        trace_length: usize,
    ) -> HcResult<FriProverArtifacts<F>> {
        self.config.validate_trace_length(trace_length)?;

        let base_producer = Arc::clone(&producer);
        let base_length = trace_length;

        let mut roots: Vec<HashDigest> = Vec::new();
        let mut betas: Vec<F> = Vec::new();
        let mut current_producer: Arc<dyn BlockProducer<F>> = producer;
        let mut current_len = trace_length;

        while current_len > self.config.final_polynomial_size() {
            // Commit this layer (streaming with parallel leaf hashing).
            let mut builder =
                hc_commit::merkle::height_dfs::StreamingMerkle::<hc_hash::Blake3>::new();
            let block_size = current_len.clamp(1, 1024);
            let mut start = 0usize;
            while start < current_len {
                let len = (current_len - start).min(block_size);
                let block = current_producer.produce(BlockRange::new(start, len))?;
                // Parallel hash: compute all leaf hashes concurrently, then
                // feed into the sequential Merkle builder.
                let hashes = compute_leaf_hashes_parallel(&block);
                for hash in hashes {
                    builder.push(hash);
                }
                start += len;
                self.stream_stats.blocks_loaded += 1;
            }
            let root = builder.finalize().ok_or_else(|| {
                hc_core::error::HcError::message("failed to finalize FRI layer root")
            })?;

            self.transcript
                .append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
            let beta = self
                .transcript
                .challenge_field::<F>(protocol::label::CHAL_FRI_BETA);

            roots.push(root);
            betas.push(beta);

            // Advance to the next folded layer producer.
            current_producer = Arc::new(FoldedLayerProducer {
                prev: current_producer,
                prev_len: current_len,
                beta,
            });
            current_len /= 2;
        }

        // Materialize the final layer values (configured to be tiny) and compute its root.
        let mut final_values: Vec<F> = Vec::with_capacity(current_len);
        let mut builder = hc_commit::merkle::height_dfs::StreamingMerkle::<hc_hash::Blake3>::new();
        let block_size = current_len.clamp(1, 1024);
        let mut start = 0usize;
        while start < current_len {
            let len = (current_len - start).min(block_size);
            let block = current_producer.produce(BlockRange::new(start, len))?;
            let hashes = compute_leaf_hashes_parallel(&block);
            for hash in hashes {
                builder.push(hash);
            }
            final_values.extend(block);
            start += len;
            self.stream_stats.blocks_loaded += 1;
        }
        let final_root = builder
            .finalize()
            .ok_or_else(|| hc_core::error::HcError::message("failed to finalize final FRI root"))?;

        self.transcript.append_message(
            protocol::label::COMMIT_FRI_FINAL_ROOT,
            final_root.as_bytes(),
        );

        let proof = FriProof::new(roots, final_values, final_root);
        Ok(FriProverArtifacts {
            proof,
            betas,
            base_producer,
            base_length,
            stats: self.stream_stats,
        })
    }

    pub fn prove(&mut self, evaluations: Vec<F>) -> HcResult<FriProverArtifacts<F>>
    where
        F: Clone + Send + Sync + 'static,
    {
        let len = evaluations.len();
        let producer: Arc<dyn BlockProducer<F>> = Arc::new(VecBlockProducer::new(evaluations));
        self.prove_with_producer(producer, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_hash::Blake3;

    #[test]
    fn prover_emits_commitments_and_final_layer() {
        let config = FriConfig::new(2).unwrap();
        let mut prover_transcript = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V2);
        let evaluations: Vec<_> = (0u64..8).map(GoldilocksField::from_u64).collect();
        let artifacts = FriProver::<GoldilocksField, Blake3>::new(config, &mut prover_transcript)
            .prove(evaluations)
            .unwrap();
        assert!(!artifacts.proof.final_layer.is_empty());
        assert_eq!(
            artifacts.proof.final_layer.len(),
            config.final_polynomial_size()
        );
    }
}
