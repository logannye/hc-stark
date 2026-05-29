use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::hash::HashDigest;
use hc_hash::protocol;
use hc_hash::{hash::HashFunction, Transcript};
use hc_replay::{block_range::BlockRange, traits::BlockProducer, VecBlockProducer};
use rayon::prelude::*;
use std::sync::Arc;

use crate::{
    config::FriConfig,
    layer::{batch_invert, LayerDomain},
    parallel::compute_leaf_hashes_parallel,
    queries::FriProof,
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

/// Streaming producer for the correct antipodal, 1/x fold (spec §3).
///
/// Produces the folded layer block-at-a-time. The output index `j`
/// (`j in 0..prev_len/2`) is derived from the *antipodal* pair
/// `prev[j]` (the "low" value) and `prev[j + prev_len/2]` (the "high"
/// value) — NOT `prev[2j]`/`prev[2j+1]`. To answer `produce([s, e))` it
/// therefore issues **two** reads of the previous layer:
///
/// - `prev.produce([s, e))` — the low values `a`
/// - `prev.produce([s + half, e + half))` — the high values `b`
///
/// plus computes `x = prev_domain.point(s..e)`. Memory stays O(block): two
/// block reads of size `e - s`, no full-layer buffering.
///
/// Carries the PREVIOUS layer's [`LayerDomain`]; the squared domain of the
/// produced layer is `prev_domain.squared()`.
///
/// Currently exercised only by the v5 streaming-parity tests; the prover
/// itself still drives the legacy [`FoldedLayerProducer`] (strangler pattern),
/// so this is `dead_code` in non-test builds until a later task swaps it in.
#[derive(Clone)]
#[cfg_attr(not(test), allow(dead_code))]
struct FoldedLayerProducerV5<F: FieldElement> {
    prev: Arc<dyn BlockProducer<F>>,
    prev_len: usize,
    prev_domain: LayerDomain<F>,
    beta: F,
}

impl<F: FieldElement> BlockProducer<F> for FoldedLayerProducerV5<F> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<F>> {
        let out_len = self.prev_len / 2;
        let half = self.prev_len / 2; // antipodal stride into prev layer
        let end = range.end().min(out_len);
        if range.start >= end {
            return Ok(Vec::new());
        }
        let s = range.start;
        let len = end - s;

        // Two block reads: low values prev[s..e], high values prev[s+half..e+half].
        let lo = self.prev.produce(BlockRange::new(s, len))?;
        let hi = self.prev.produce(BlockRange::new(s + half, len))?;
        debug_assert_eq!(lo.len(), len);
        debug_assert_eq!(hi.len(), len);

        let two_inv = F::from_u64(2)
            .inverse()
            .ok_or_else(|| hc_core::error::HcError::math("2 not invertible"))?;
        // 1/(2 * D[s + k]) for k in 0..len.
        let mut inv_two_x: Vec<F> = (0..len)
            .map(|k| {
                let x = self.prev_domain.point(s + k);
                x.add(x)
            })
            .collect();
        batch_invert(&mut inv_two_x)?;

        let mut out = Vec::with_capacity(len);
        for k in 0..len {
            let a = lo[k];
            let b = hi[k];
            let even = a.add(b).mul(two_inv);
            let odd = a.sub(b).mul(inv_two_x[k]);
            out.push(even.add(self.beta.mul(odd)));
        }
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
    use crate::layer::fold_layer_v5;
    use hc_core::domain::EvaluationDomain;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_hash::Blake3;

    type F = GoldilocksField;

    fn layer_domain(n: usize) -> (EvaluationDomain<F>, LayerDomain<F>) {
        let dom = EvaluationDomain::<F>::new_coset(n, F::from_u64(7)).unwrap();
        let ld = LayerDomain {
            offset: dom.offset(),
            gen: dom.generator(),
            size: dom.size(),
        };
        (dom, ld)
    }

    fn det_vec(seed: u64, n: usize) -> Vec<F> {
        let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(1);
        (0..n)
            .map(|_| {
                x = x
                    .wrapping_mul(0x5851_F42D_4C95_7F2D)
                    .wrapping_add(0x14_05_7B_7E_F7_67_81_4F);
                F::from_u64(x)
            })
            .collect()
    }

    /// Streaming v5 producer over a full layer must equal scalar `fold_layer_v5`.
    #[test]
    fn streaming_v5_full_layer_matches_scalar() {
        for &n in &[2usize, 4, 8, 16, 64, 256, 1024] {
            let (_dom, ld) = layer_domain(n);
            let values = det_vec(n as u64 + 1, n);
            let beta = F::from_u64(0x1234_5678_9ABC_DEF0);

            let want = fold_layer_v5(&values, &ld, beta).unwrap();

            let base: Arc<dyn BlockProducer<F>> = Arc::new(VecBlockProducer::new(values.clone()));
            let producer = FoldedLayerProducerV5 {
                prev: base,
                prev_len: n,
                prev_domain: ld.clone(),
                beta,
            };
            let got = producer.produce(BlockRange::new(0, n / 2)).unwrap();
            assert_eq!(got, want, "streaming-v5 full layer mismatch at n={n}");
        }
    }

    /// Streaming v5 producer over PARTIAL ranges (produce [0,k) then [k,half))
    /// must concatenate to scalar `fold_layer_v5`. This catches the
    /// two-cursor antipodal indexing bug — the partner read must use the
    /// SAME absolute window offset by `half`, not a relative one.
    #[test]
    fn streaming_v5_partial_ranges_match_scalar() {
        for &n in &[8usize, 16, 64, 256, 1024] {
            let (_dom, ld) = layer_domain(n);
            let values = det_vec(7 * n as u64 + 3, n);
            let beta = F::from_u64(0xCAFE_BABE_DEAD_C0DE);
            let half = n / 2;

            let want = fold_layer_v5(&values, &ld, beta).unwrap();

            let base: Arc<dyn BlockProducer<F>> = Arc::new(VecBlockProducer::new(values.clone()));
            let producer = FoldedLayerProducerV5 {
                prev: base,
                prev_len: n,
                prev_domain: ld.clone(),
                beta,
            };

            // Split the output range at several cut points, including 1 and
            // half-1 (asymmetric, non-WIDTH-aligned), and reassemble.
            for &k in &[1usize, half / 3 + 1, half / 2, half - 1] {
                if k == 0 || k >= half {
                    continue;
                }
                let mut got = producer.produce(BlockRange::new(0, k)).unwrap();
                let tail = producer.produce(BlockRange::new(k, half - k)).unwrap();
                got.extend(tail);
                assert_eq!(
                    got, want,
                    "streaming-v5 partial ranges mismatch at n={n}, split k={k}"
                );
            }

            // Also a finer 3-way split.
            let a = producer.produce(BlockRange::new(0, half / 4)).unwrap();
            let b = producer
                .produce(BlockRange::new(half / 4, half / 4))
                .unwrap();
            let c = producer
                .produce(BlockRange::new(half / 2, half - half / 2))
                .unwrap();
            let mut got3 = a;
            got3.extend(b);
            got3.extend(c);
            assert_eq!(got3, want, "streaming-v5 3-way split mismatch at n={n}");
        }
    }

    /// Producing past the output length must clamp (return only valid indices),
    /// matching the legacy producer's clamp behaviour.
    #[test]
    fn streaming_v5_clamps_past_end() {
        let n = 64usize;
        let (_dom, ld) = layer_domain(n);
        let values = det_vec(99, n);
        let beta = F::from_u64(5);
        let base: Arc<dyn BlockProducer<F>> = Arc::new(VecBlockProducer::new(values));
        let producer = FoldedLayerProducerV5 {
            prev: base,
            prev_len: n,
            prev_domain: ld,
            beta,
        };
        // Request more than n/2 outputs; expect exactly n/2.
        let got = producer.produce(BlockRange::new(0, n)).unwrap();
        assert_eq!(got.len(), n / 2);
        // Fully out-of-range start -> empty.
        let empty = producer.produce(BlockRange::new(n, 4)).unwrap();
        assert!(empty.is_empty());
    }

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
