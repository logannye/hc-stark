use hc_core::field::{GoldilocksField, QuadExtension};
use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::layer::LayerDomain;
use hc_fri::{FriConfig, FriProver, FriProverArtifacts};
use hc_hash::protocol;
use hc_hash::Blake3;
use hc_hash::HashDigest;
use hc_replay::traits::BlockProducer;
use std::sync::Arc;

use crate::transcript::ProverTranscript;

/// Production extension field used by the v5 (uniform-K) FRI commit phase.
type K = QuadExtension<GoldilocksField>;

/// LDE coset offset used by the prover when building the quotient oracle.
///
/// Mirrors the `EvaluationDomain::new_coset(_, F::from_u64(7))` offset used
/// throughout the prover/tests for the LDE coset domain.
const LDE_COSET_OFFSET: u64 = 7;

#[derive(Clone, Copy, Debug)]
pub struct FriTranscriptSeed {
    pub protocol_version: u32,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub trace_length: u64,
    pub query_count: u64,
    pub lde_blowup: u64,
    pub fri_final_size: u64,
    pub folding_ratio: u64,
    pub zk_enabled: bool,
    pub zk_mask_degree: u64,
    pub trace_commitment: HashDigest,
    pub composition_commitment: HashDigest,
}

pub fn run_fri<F: FieldElement>(
    config: FriConfig,
    producer: Arc<dyn BlockProducer<F>>,
    trace_length: usize,
    seed: FriTranscriptSeed,
) -> HcResult<FriProverArtifacts<F>> {
    let domain = if seed.protocol_version >= 4 {
        protocol::DOMAIN_FRI_V4
    } else if seed.protocol_version >= 3 {
        protocol::DOMAIN_FRI_V3
    } else {
        protocol::DOMAIN_FRI_V2
    };
    let mut transcript = ProverTranscript::new(domain);
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_INITIAL_ACC,
        seed.initial_acc,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_FINAL_ACC,
        seed.final_acc,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        seed.trace_length,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        seed.query_count,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        seed.lde_blowup,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        seed.fri_final_size,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        seed.folding_ratio,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    if seed.protocol_version >= 4 {
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_ZK_ENABLED,
            u64::from(seed.zk_enabled),
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_ZK_MASK_DEGREE,
            seed.zk_mask_degree,
        );
    }
    transcript.append_message(
        if seed.protocol_version >= 3 {
            protocol::label::COMMIT_TRACE_LDE_ROOT
        } else {
            protocol::label::COMMIT_TRACE_ROOT
        },
        seed.trace_commitment.as_bytes(),
    );
    transcript.append_message(
        if seed.protocol_version >= 3 {
            protocol::label::COMMIT_QUOTIENT_ROOT
        } else {
            protocol::label::COMMIT_COMPOSITION_ROOT
        },
        seed.composition_commitment.as_bytes(),
    );
    let mut prover = FriProver::<F, Blake3>::new(config, &mut transcript);
    prover.prove_with_producer(producer, trace_length)
}

/// Transcript seed for the v5 (uniform-K) FRI commit phase.
///
/// ADDITIVE counterpart to [`FriTranscriptSeed`]: identical fields PLUS a
/// `grinding_bits` parameter that is bound into the transcript param block.
/// v5 always commits to the v4+ ZK fields and the v3+ LDE/quotient commitment
/// labels (it extends v4), so there are no version branches here.
#[derive(Clone, Copy, Debug)]
pub struct FriTranscriptSeedV5 {
    pub protocol_version: u32,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub trace_length: u64,
    pub query_count: u64,
    pub lde_blowup: u64,
    pub fri_final_size: u64,
    pub folding_ratio: u64,
    /// Proof-of-work grinding difficulty (bits). Bound into the param block via
    /// [`protocol::label::PARAM_GRINDING_BITS`]; the grinding *nonce* search and
    /// verification are wired by a later task (7b-2 / 8).
    pub grinding_bits: u64,
    pub zk_enabled: bool,
    pub zk_mask_degree: u64,
    pub trace_commitment: HashDigest,
    pub composition_commitment: HashDigest,
}

/// Run the v5 (uniform-K) FRI commit phase over a K-valued quotient producer.
///
/// ADDITIVE counterpart to [`run_fri`]: builds the v5 FRI transcript
/// ([`protocol::DOMAIN_FRI_V5`]) seeded with the same public/param/commitment
/// fields as `run_fri` PLUS the grinding-bits param, builds the layer-0
/// `LayerDomain<K>` from the LDE coset (offset 7) embedded into K, and drives the
/// antipodal + 1/x commit phase ([`FriProver::prove_with_producer_v5`]).
///
/// Phase 1A.2: the composition challenges are now sampled in `K`, so the quotient
/// codeword is natively `K = QuadExtension<F>`; this takes the K producer directly
/// (no F→K embedding adapter).
///
/// `base_len` is the FRI base codeword length (the producer length, = the LDE
/// coset size, a power of two). Returns the K-valued commit-phase artifacts
/// (a [`hc_fri::FriProof`] carrying `final_coeffs`, the K betas, the base K
/// producer, and streaming stats).
pub fn run_fri_v5(
    config: FriConfig,
    producer: Arc<dyn BlockProducer<K>>,
    base_len: usize,
    seed: FriTranscriptSeedV5,
) -> HcResult<FriProverArtifacts<K>> {
    let mut transcript = ProverTranscript::new(protocol::DOMAIN_FRI_V5);
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_INITIAL_ACC,
        seed.initial_acc,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_FINAL_ACC,
        seed.final_acc,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        seed.trace_length,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        seed.query_count,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        seed.lde_blowup,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        seed.fri_final_size,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        seed.folding_ratio,
    );
    // v5 param-block addition: bind the grinding difficulty.
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_GRINDING_BITS,
        seed.grinding_bits,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    // v5 extends v4: always bind the ZK fields.
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_ZK_ENABLED,
        u64::from(seed.zk_enabled),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_ZK_MASK_DEGREE,
        seed.zk_mask_degree,
    );
    // v5 extends v3: LDE-trace + quotient commitment labels.
    transcript.append_message(
        protocol::label::COMMIT_TRACE_LDE_ROOT,
        seed.trace_commitment.as_bytes(),
    );
    transcript.append_message(
        protocol::label::COMMIT_QUOTIENT_ROOT,
        seed.composition_commitment.as_bytes(),
    );

    // Layer-0 coset = LDE coset (offset 7) of size base_len, embedded into K.
    let base_domain_f = hc_core::domain::EvaluationDomain::<GoldilocksField>::new_coset(
        base_len,
        GoldilocksField::from_u64(LDE_COSET_OFFSET),
    )?;
    let base_domain = LayerDomain::<K> {
        offset: K::from_base(base_domain_f.offset()),
        gen: K::from_base(base_domain_f.generator()),
        size: base_domain_f.size(),
    };

    let blowup = seed.lde_blowup.max(1) as usize;
    let mut prover = FriProver::<K, Blake3>::new(config, &mut transcript);
    prover.prove_with_producer_v5(producer, base_domain, base_len, blowup)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_replay::traits::VecBlockProducer;

    fn seed_v5(base_len: usize, blowup: usize, final_size: usize) -> FriTranscriptSeedV5 {
        FriTranscriptSeedV5 {
            protocol_version: 5,
            initial_acc: 5,
            final_acc: 8,
            trace_length: (base_len / blowup) as u64,
            query_count: 4,
            lde_blowup: blowup as u64,
            fri_final_size: final_size as u64,
            folding_ratio: 2,
            grinding_bits: 16,
            zk_enabled: false,
            zk_mask_degree: 0,
            trace_commitment: HashDigest::new([0xA5u8; 32]),
            composition_commitment: HashDigest::new([0x5Au8; 32]),
        }
    }

    /// The final K coset matching what `run_fri_v5` builds: LDE coset (offset 7)
    /// in F embedded into K, squared down to `final_size`.
    fn final_coset_k(base_len: usize, final_size: usize) -> Vec<K> {
        let dom_f = hc_core::domain::EvaluationDomain::<GoldilocksField>::new_coset(
            base_len,
            GoldilocksField::from_u64(LDE_COSET_OFFSET),
        )
        .unwrap();
        let mut ld = LayerDomain::<K> {
            offset: K::from_base(dom_f.offset()),
            gen: K::from_base(dom_f.generator()),
            size: dom_f.size(),
        };
        let mut n = base_len;
        while n > final_size {
            ld = ld.squared();
            n /= 2;
        }
        (0..final_size).map(|j| ld.point(j)).collect()
    }

    /// End-to-end: a genuinely low-degree K base codeword on the LDE coset must
    /// yield `final_coeffs` of length `final_size/blowup` that re-evaluate to
    /// `proof.final_layer`. (Phase 1A.2: the FRI base is natively K.)
    #[test]
    fn run_fri_v5_honest_low_degree_final_coeffs_roundtrip() {
        let blowup = 2usize;
        for &(base_len, final_size) in &[(16usize, 2usize), (64, 4), (256, 8)] {
            // Low-degree base: degree base_len/blowup - 1 poly on the LDE coset.
            let dom_f = hc_core::domain::EvaluationDomain::<GoldilocksField>::new_coset(
                base_len,
                GoldilocksField::from_u64(LDE_COSET_OFFSET),
            )
            .unwrap();
            let deg = base_len / blowup - 1;
            let poly: Vec<GoldilocksField> = (0..=deg)
                .map(|i| GoldilocksField::from_u64((i as u64).wrapping_mul(7919) + 13))
                .collect();
            let points: Vec<GoldilocksField> = (0..base_len).map(|j| dom_f.element(j)).collect();
            let values: Vec<K> = hc_core::poly::evaluate_batch(&poly, &points)
                .into_iter()
                .map(K::from_base)
                .collect();

            let config = FriConfig::new(final_size).unwrap();
            let producer: Arc<dyn BlockProducer<K>> = Arc::new(VecBlockProducer::new(values));
            let artifacts = run_fri_v5(
                config,
                producer,
                base_len,
                seed_v5(base_len, blowup, final_size),
            )
            .unwrap();

            assert_eq!(
                artifacts.proof.final_coeffs.len(),
                final_size / blowup,
                "final_coeffs length (base_len={base_len})"
            );
            let final_points = final_coset_k(base_len, final_size);
            let reeval =
                hc_core::poly::evaluate_batch(&artifacts.proof.final_coeffs, &final_points);
            assert_eq!(
                reeval, artifacts.proof.final_layer,
                "final_coeffs must re-evaluate to final_layer through run_fri_v5 (base_len={base_len})"
            );
            // betas are genuine K elements (full entropy); base length preserved.
            assert_eq!(artifacts.base_length, base_len);
            assert_eq!(artifacts.betas.len(), artifacts.proof.layer_roots.len());
        }
    }

    /// Distinct `grinding_bits` must change the transcript (and thus the betas),
    /// proving the param is actually bound into the v5 transcript.
    #[test]
    fn run_fri_v5_grinding_bits_bound_into_transcript() {
        let (base_len, blowup, final_size) = (64usize, 2usize, 2usize);
        let values: Vec<K> = (0..base_len as u64)
            .map(|i| K::from_base(GoldilocksField::from_u64(i)))
            .collect();
        let config = FriConfig::new(final_size).unwrap();

        let run = |bits: u64| {
            let mut s = seed_v5(base_len, blowup, final_size);
            s.grinding_bits = bits;
            let producer: Arc<dyn BlockProducer<K>> =
                Arc::new(VecBlockProducer::new(values.clone()));
            run_fri_v5(config, producer, base_len, s).unwrap().betas
        };
        assert_ne!(
            run(0),
            run(20),
            "grinding_bits must be bound into the transcript (different bits => different betas)"
        );
    }

    /// The v5 commit phase preserves O(block) streaming: the K base producer is
    /// read in bounded blocks, never the whole layer at once.
    #[derive(Clone)]
    struct CountingK {
        inner: Arc<dyn BlockProducer<K>>,
        max_read: Arc<std::sync::atomic::AtomicUsize>,
    }
    impl BlockProducer<K> for CountingK {
        fn produce(&self, range: hc_replay::block_range::BlockRange) -> HcResult<Vec<K>> {
            self.max_read
                .fetch_max(range.len, std::sync::atomic::Ordering::Relaxed);
            self.inner.produce(range)
        }
    }

    #[test]
    fn run_fri_v5_base_producer_streams_bounded_blocks() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let (base_len, blowup, final_size) = (4096usize, 2usize, 2usize);
        let values: Vec<K> = (0..base_len as u64)
            .map(|i| K::from_base(GoldilocksField::from_u64(i.wrapping_mul(1_000_003) + 7)))
            .collect();
        let max_read = Arc::new(AtomicUsize::new(0));
        let producer: Arc<dyn BlockProducer<K>> = Arc::new(CountingK {
            inner: Arc::new(VecBlockProducer::new(values)),
            max_read: Arc::clone(&max_read),
        });
        let config = FriConfig::new(final_size).unwrap();
        let _ = run_fri_v5(
            config,
            producer,
            base_len,
            seed_v5(base_len, blowup, final_size),
        )
        .unwrap();
        let peak = max_read.load(Ordering::Relaxed);
        assert!(
            peak <= 1024,
            "v5 commit must read the K base producer in O(block) chunks (peak={peak}), not O(N)={base_len}"
        );
    }
}
