use hc_core::{error::HcResult, field::FieldElement};
use hc_hash::hash::HashDigest;
use hc_hash::protocol;
use hc_hash::{hash::HashFunction, Transcript};
use hc_replay::{block_range::BlockRange, traits::BlockProducer, VecBlockProducer};
use rayon::prelude::*;
use std::sync::Arc;

use crate::{
    config::FriConfig,
    layer::{batch_invert, hash_value_ext, ExtLeafHashable, LayerDomain},
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
/// Driven by [`FriProver::prove_with_producer_v5`] (the v5 commit phase). The
/// legacy v3 [`FriProver::prove_with_producer`] still drives the legacy
/// [`FoldedLayerProducer`] (strangler pattern); the two paths coexist.
#[derive(Clone)]
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
        // 1/(2 * D[s + k]) for k in 0..len; D[s] via one pow, then running multiply.
        let mut inv_two_x: Vec<F> = Vec::with_capacity(len);
        let mut x = self.prev_domain.point(s);
        for _ in 0..len {
            inv_two_x.push(x.add(x));
            x = x.mul(self.prev_domain.gen);
        }
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

    /// v5 FRI commit phase over a value field `F` (production: `QuadExtension`).
    ///
    /// ADDITIVE counterpart to [`Self::prove_with_producer`] that performs the
    /// cryptographically-correct **antipodal + 1/x** fold (spec §3) entirely in
    /// `F`, committing each layer with the [`hash_value_ext`] K-leaf hash (binds
    /// BOTH extension coefficients). The legacy adjacent-pair fold of
    /// `prove_with_producer` is left untouched.
    ///
    /// Differences from v3:
    /// - leaves are hashed with `hash_value_ext` (K-aware) rather than the
    ///   base-field `hash_value`;
    /// - layers advance via [`FoldedLayerProducerV5`] over the running
    ///   [`LayerDomain`] (`domain = domain.squared()` after each fold), so the
    ///   coset points enter the fold;
    /// - the final layer additionally yields explicit low-degree coefficients
    ///   (`final_coeffs`): the final `F` evals are interpolated over the final
    ///   coset and the first `final_size / blowup` coefficients are retained
    ///   (the honest final polynomial has degree `< final_size / blowup`).
    ///
    /// Memory stays O(block): leaves are streamed block-at-a-time, and the
    /// producer chain reads only O(block) per layer. The only full-layer
    /// materialization is the final layer, which is configured tiny.
    ///
    /// `base_domain` is the layer-0 coset (e.g. the LDE coset, offset 7) in `F`;
    /// `base_len` is the producer length (a power of two); `blowup` is the LDE
    /// blowup factor used to bound the retained `final_coeffs`.
    ///
    /// NOTE: query openings, the v5 proof/output type, grinding wiring, and
    /// serialization are SEPARATE later tasks (7b-2 / 8). This produces only the
    /// commit-phase artifacts (`FriProof` with `final_coeffs`, betas, base
    /// producer, stats).
    pub fn prove_with_producer_v5(
        &mut self,
        producer: Arc<dyn BlockProducer<F>>,
        base_domain: LayerDomain<F>,
        base_len: usize,
        blowup: usize,
    ) -> HcResult<FriProverArtifacts<F>>
    where
        F: ExtLeafHashable,
    {
        self.config.validate_trace_length(base_len)?;
        if blowup == 0 || !blowup.is_power_of_two() {
            return Err(hc_core::error::HcError::invalid_argument(
                "blowup must be a non-zero power of two",
            ));
        }
        debug_assert_eq!(
            base_domain.size, base_len,
            "base LayerDomain size must equal base_len"
        );

        let base_producer = Arc::clone(&producer);

        let mut roots: Vec<HashDigest> = Vec::new();
        let mut betas: Vec<F> = Vec::new();
        let mut current_producer: Arc<dyn BlockProducer<F>> = producer;
        let mut current_len = base_len;
        let mut domain = base_domain;

        while current_len > self.config.final_polynomial_size() {
            // Commit this layer with K-aware leaf hashes, streaming block-at-a-time.
            let root = self.commit_layer_ext(&current_producer, current_len)?;

            self.transcript
                .append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
            let beta = self
                .transcript
                .challenge_field::<F>(protocol::label::CHAL_FRI_BETA);

            roots.push(root);
            betas.push(beta);

            // Advance to the antipodal + 1/x folded layer over THIS domain,
            // then square the domain for the next round.
            current_producer = Arc::new(FoldedLayerProducerV5 {
                prev: current_producer,
                prev_len: current_len,
                prev_domain: domain.clone(),
                beta,
            });
            domain = domain.squared();
            current_len /= 2;
        }

        // Materialize the final layer (configured tiny) and commit its root.
        let mut final_values: Vec<F> = Vec::with_capacity(current_len);
        let mut builder = hc_commit::merkle::height_dfs::StreamingMerkle::<hc_hash::Blake3>::new();
        let block_size = current_len.clamp(1, 1024);
        let mut start = 0usize;
        while start < current_len {
            let len = (current_len - start).min(block_size);
            let block = current_producer.produce(BlockRange::new(start, len))?;
            for value in &block {
                builder.push(hash_value_ext(value));
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

        // final_coeffs: interpolate the final evals over the final coset, keep
        // the first final_size / blowup coefficients (honest degree bound).
        let final_size = current_len;
        let coset_points: Vec<F> = (0..final_size).map(|j| domain.point(j)).collect();
        let mut coeffs = hc_core::poly::interpolate(&final_values, &coset_points);
        let keep = (final_size / blowup).max(1).min(final_size);
        coeffs.truncate(keep);

        let proof = FriProof::new(roots, final_values, final_root).with_final_coeffs(coeffs);
        Ok(FriProverArtifacts {
            proof,
            betas,
            base_producer,
            base_length: base_len,
            stats: self.stream_stats,
        })
    }

    /// Commit one K-valued FRI layer: stream `len` values block-at-a-time,
    /// hashing each with the K-aware [`hash_value_ext`] leaf hash, and build the
    /// Merkle root. O(block) memory.
    fn commit_layer_ext(
        &mut self,
        producer: &Arc<dyn BlockProducer<F>>,
        len: usize,
    ) -> HcResult<HashDigest>
    where
        F: ExtLeafHashable,
    {
        let mut builder = hc_commit::merkle::height_dfs::StreamingMerkle::<hc_hash::Blake3>::new();
        let block_size = len.clamp(1, 1024);
        let mut start = 0usize;
        while start < len {
            let blk = (len - start).min(block_size);
            let block = producer.produce(BlockRange::new(start, blk))?;
            for value in &block {
                builder.push(hash_value_ext(value));
            }
            start += blk;
            self.stream_stats.blocks_loaded += 1;
        }
        builder
            .finalize()
            .ok_or_else(|| hc_core::error::HcError::message("failed to finalize FRI layer root"))
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

    // -----------------------------------------------------------------------
    // Task 7b-1: v5 commit phase over K = QuadExtension<GoldilocksField>.
    // -----------------------------------------------------------------------

    mod v5 {
        use super::*;
        use crate::layer::hash_value_ext;
        use hc_core::field::QuadExtension;

        type K = QuadExtension<F>;

        /// Build the K `LayerDomain` matching `EvaluationDomain::new_coset(n, 7)`
        /// embedded into K (offset/generator via `from_base`).
        fn k_layer_domain(n: usize) -> LayerDomain<K> {
            let dom = EvaluationDomain::<F>::new_coset(n, F::from_u64(7)).unwrap();
            LayerDomain {
                offset: K::from_base(dom.offset()),
                gen: K::from_base(dom.generator()),
                size: dom.size(),
            }
        }

        /// Deterministic K codeword with nonzero c1 in (most) lanes.
        fn det_kvec(seed: u64, n: usize) -> Vec<K> {
            let c0 = det_vec(seed, n);
            let c1 = det_vec(seed ^ 0xABCD_1234_5678_9F01, n);
            (0..n).map(|i| K::new(c0[i], c1[i])).collect()
        }

        /// Independently materialize every committed layer via `fold_layer_v5`
        /// using the SAME betas, then check each layer's Merkle root (built with
        /// `hash_value_ext`) equals the committed root, AND the final fold
        /// equals `proof.final_layer`. This binds the committed roots to the
        /// correct antipodal + 1/x fold.
        fn merkle_root_ext(values: &[K]) -> HashDigest {
            let mut b = hc_commit::merkle::height_dfs::StreamingMerkle::<Blake3>::new();
            for v in values {
                b.push(hash_value_ext(v));
            }
            b.finalize().unwrap()
        }

        #[test]
        fn fold_consistency_committed_layers_match_independent_fold() {
            for &(base_len, final_size) in &[(16usize, 2usize), (64, 4), (256, 8), (1024, 2)] {
                let config = FriConfig::new(final_size).unwrap();
                let base_domain = k_layer_domain(base_len);
                let values = det_kvec(base_len as u64 + 17, base_len);

                let producer: Arc<dyn BlockProducer<K>> =
                    Arc::new(VecBlockProducer::new(values.clone()));
                let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V5);
                let artifacts = FriProver::<K, Blake3>::new(config, &mut t)
                    .prove_with_producer_v5(producer, base_domain.clone(), base_len, 2)
                    .unwrap();

                // Independently fold round-by-round with the artifact betas.
                let mut layer = values.clone();
                let mut dom = base_domain;
                let mut expected_roots: Vec<HashDigest> = Vec::new();
                for &beta in &artifacts.betas {
                    // Root of the CURRENT layer (committed before folding by beta).
                    expected_roots.push(merkle_root_ext(&layer));
                    layer = fold_layer_v5(&layer, &dom, beta).unwrap();
                    dom = dom.squared();
                }
                assert_eq!(
                    artifacts.proof.layer_roots, expected_roots,
                    "committed layer roots must match the independent antipodal fold \
                     (base_len={base_len}, final_size={final_size})"
                );
                assert_eq!(
                    layer, artifacts.proof.final_layer,
                    "independent final fold must equal proof.final_layer"
                );
                assert_eq!(
                    merkle_root_ext(&artifacts.proof.final_layer),
                    artifacts.proof.final_root,
                    "final root must commit the final layer via hash_value_ext"
                );
                // betas count == committed layer count.
                assert_eq!(artifacts.betas.len(), artifacts.proof.layer_roots.len());
            }
        }

        /// Honest low-degree base: build the base as the eval table of a
        /// degree-(base_len/blowup - 1) polynomial in K on the base coset.
        /// final_coeffs must have length final_size/blowup AND re-evaluating
        /// them on the final coset must reproduce proof.final_layer exactly.
        #[test]
        fn final_coeffs_roundtrip_honest_low_degree() {
            let blowup = 2usize;
            for &(base_len, final_size) in &[(16usize, 2usize), (64, 4), (256, 8)] {
                let config = FriConfig::new(final_size).unwrap();
                let base_domain = k_layer_domain(base_len);

                // Genuinely low-degree codeword: degree = base_len/blowup - 1.
                let deg = base_len / blowup - 1;
                let poly: Vec<K> = det_kvec(0xD06_0F00D ^ base_len as u64, deg + 1);
                let base_points: Vec<K> = (0..base_len).map(|j| base_domain.point(j)).collect();
                let values = hc_core::poly::evaluate_batch(&poly, &base_points);

                let producer: Arc<dyn BlockProducer<K>> =
                    Arc::new(VecBlockProducer::new(values));
                let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V5);
                let artifacts = FriProver::<K, Blake3>::new(config, &mut t)
                    .prove_with_producer_v5(producer, base_domain.clone(), base_len, blowup)
                    .unwrap();

                let keep = final_size / blowup;
                assert_eq!(
                    artifacts.proof.final_coeffs.len(),
                    keep,
                    "final_coeffs length must be final_size/blowup \
                     (base_len={base_len}, final_size={final_size})"
                );

                // Final coset = base coset squared log2(base_len/final_size) times.
                let mut dom = base_domain;
                let mut n = base_len;
                while n > final_size {
                    dom = dom.squared();
                    n /= 2;
                }
                let final_points: Vec<K> = (0..final_size).map(|j| dom.point(j)).collect();
                let reeval = hc_core::poly::evaluate_batch(
                    &artifacts.proof.final_coeffs,
                    &final_points,
                );
                assert_eq!(
                    reeval, artifacts.proof.final_layer,
                    "evaluating final_coeffs on the final coset must reproduce final_layer \
                     (base_len={base_len}, final_size={final_size})"
                );
            }
        }

        /// K betas have genuine entropy: across a few seeds/layers at least one
        /// beta has c1 != 0. Satisfiable thanks to the 81efb3c challenge fix.
        #[test]
        fn k_betas_have_nonzero_c1() {
            let config = FriConfig::new(2).unwrap();
            let base_len = 256usize;
            let base_domain = k_layer_domain(base_len);
            let mut any_c1_nonzero = false;
            for seed in 0u64..4 {
                let values = det_kvec(0x5EED ^ seed.wrapping_mul(0x9999), base_len);
                let producer: Arc<dyn BlockProducer<K>> =
                    Arc::new(VecBlockProducer::new(values));
                let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V5);
                let artifacts = FriProver::<K, Blake3>::new(config, &mut t)
                    .prove_with_producer_v5(producer, base_domain.clone(), base_len, 2)
                    .unwrap();
                if artifacts.betas.iter().any(|b| !b.c1.is_zero()) {
                    any_c1_nonzero = true;
                    break;
                }
            }
            assert!(
                any_c1_nonzero,
                "at least one K beta must have c1 != 0 (genuine extension challenge)"
            );
        }

        /// Block-counting producer: the v5 commit + fold chain must read the
        /// base producer in bounded blocks, never the whole layer at once.
        /// We assert the MAX single read never exceeds the layer block cap.
        #[derive(Clone)]
        struct CountingProducer {
            inner: Arc<dyn BlockProducer<K>>,
            max_read: Arc<std::sync::atomic::AtomicUsize>,
            total_reads: Arc<std::sync::atomic::AtomicUsize>,
        }
        impl BlockProducer<K> for CountingProducer {
            fn produce(&self, range: BlockRange) -> HcResult<Vec<K>> {
                use std::sync::atomic::Ordering;
                self.max_read.fetch_max(range.len, Ordering::Relaxed);
                self.total_reads.fetch_add(1, Ordering::Relaxed);
                self.inner.produce(range)
            }
        }

        #[test]
        fn streaming_reads_bounded_blocks() {
            use std::sync::atomic::{AtomicUsize, Ordering};
            let config = FriConfig::new(2).unwrap();
            let base_len = 4096usize; // > 1024 block cap, so streaming must chunk.
            let base_domain = k_layer_domain(base_len);
            let values = det_kvec(0xBEEF, base_len);

            let max_read = Arc::new(AtomicUsize::new(0));
            let total_reads = Arc::new(AtomicUsize::new(0));
            let counting = CountingProducer {
                inner: Arc::new(VecBlockProducer::new(values)),
                max_read: Arc::clone(&max_read),
                total_reads: Arc::clone(&total_reads),
            };
            let producer: Arc<dyn BlockProducer<K>> = Arc::new(counting);

            let mut t = Transcript::<Blake3>::new(protocol::DOMAIN_FRI_V5);
            let _ = FriProver::<K, Blake3>::new(config, &mut t)
                .prove_with_producer_v5(producer, base_domain, base_len, 2)
                .unwrap();

            let peak = max_read.load(Ordering::Relaxed);
            assert!(
                peak <= 1024,
                "max single base read ({peak}) must stay within the O(block) cap (1024), \
                 never O(N)={base_len}"
            );
            // And it must actually have streamed in multiple reads.
            assert!(
                total_reads.load(Ordering::Relaxed) > 1,
                "base producer must be read in multiple bounded blocks"
            );
        }
    }
}
