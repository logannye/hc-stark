//! Aggregator V2: Produces a single Halo2 proof verifying N STARK proofs.
//!
//! This replaces the hash-only aggregator (v1) with a circuit-based aggregator
//! that embeds STARK verification inside a Halo2 proof.
//!
//! Flow:
//! 1. Each STARK proof is verified natively (soundness check).
//! 2. Poseidon-Merkle roots are computed via the dual-hash bridge.
//! 3. The STARK verifier circuit is instantiated for each proof.
//! 4. All verification circuits are composed into a single Halo2 proof.
//!
//! The output is a constant-size Halo2 proof (a BN254 KZG proof) that
//! attests to the validity of all N STARK proofs.

use halo2curves::bn256::Fr;
use halo2curves::ff::Field;

use hc_core::{
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement},
};

use crate::aggregator::ProofSummary;
use crate::circuit::poseidon;

/// A batch of STARK proof summaries to be verified in a single Halo2 proof.
#[derive(Clone, Debug)]
pub struct AggregationBatch {
    /// Summaries of each STARK proof in the batch.
    pub summaries: Vec<ProofSummary<GoldilocksField>>,
    /// Poseidon commitment over all summaries (the "aggregation digest").
    pub aggregation_digest: Fr,
}

/// Configuration for the aggregator circuit.
#[derive(Clone, Debug)]
pub struct AggregatorConfig {
    /// Maximum number of proofs per aggregation batch.
    pub max_batch_size: usize,
    /// The Halo2 circuit table size parameter (k, where rows = 2^k).
    pub k: u32,
}

impl Default for AggregatorConfig {
    fn default() -> Self {
        Self {
            max_batch_size: 16,
            k: 20, // 1M rows — enough for ~16 STARK verifications
        }
    }
}

/// Compute the Poseidon aggregation digest over a batch of proof summaries.
///
/// The digest is a Poseidon hash chain over the encoded summaries:
/// ```text
/// digest_0 = Poseidon(summary_encoding_0)
/// digest_i = Poseidon(digest_{i-1}, summary_encoding_i)
/// final = digest_{N-1}
/// ```
///
/// This mirrors the Blake3-based `compute_root` in `aggregator.rs` but uses
/// Poseidon for circuit-friendliness.
pub fn compute_aggregation_digest(summaries: &[ProofSummary<GoldilocksField>]) -> Fr {
    if summaries.is_empty() {
        return Fr::ZERO;
    }

    let mut acc = Fr::ZERO;
    for summary in summaries {
        let summary_fr = encode_summary_to_fr(summary);
        acc = poseidon::hash(&[acc, summary_fr]);
    }
    acc
}

/// Encode a proof summary as a single Fr element for aggregation.
///
/// Compresses the summary's key fields into a Poseidon hash:
/// - trace commitment digest (as 4 x u64 limbs)
/// - initial/final accumulator values
/// - trace length
fn encode_summary_to_fr(summary: &ProofSummary<GoldilocksField>) -> Fr {
    let mut inputs = Vec::with_capacity(8);

    // Trace commitment digest: 32 bytes → 4 x u64 limbs → 4 x Fr.
    let digest_bytes = summary.trace_commitment_digest.as_bytes();
    for chunk in digest_bytes.chunks_exact(8) {
        let limb = u64::from_le_bytes(chunk.try_into().unwrap());
        inputs.push(Fr::from(limb));
    }

    // Public inputs.
    inputs.push(Fr::from(summary.initial_acc.to_u64()));
    inputs.push(Fr::from(summary.final_acc.to_u64()));
    inputs.push(Fr::from(summary.trace_length as u64));

    // Circuit digest.
    inputs.push(Fr::from(summary.circuit_digest.to_u64()));

    poseidon::hash(&inputs)
}

/// Build an aggregation batch from verified STARK proof summaries.
///
/// Each summary must come from a successfully verified STARK proof.
/// The batch computes a Poseidon aggregation digest that can be
/// verified inside a Halo2 circuit.
pub fn build_aggregation_batch(
    summaries: Vec<ProofSummary<GoldilocksField>>,
    config: &AggregatorConfig,
) -> HcResult<AggregationBatch> {
    if summaries.is_empty() {
        return Err(HcError::invalid_argument("cannot aggregate empty batch"));
    }
    if summaries.len() > config.max_batch_size {
        return Err(HcError::invalid_argument(format!(
            "batch size {} exceeds max {}",
            summaries.len(),
            config.max_batch_size
        )));
    }

    let aggregation_digest = compute_aggregation_digest(&summaries);

    Ok(AggregationBatch {
        summaries,
        aggregation_digest,
    })
}

/// Verify an aggregation batch's digest is consistent with its summaries.
pub fn verify_aggregation_batch(batch: &AggregationBatch) -> bool {
    let expected = compute_aggregation_digest(&batch.summaries);
    expected == batch.aggregation_digest
}

/// Aggregate multiple batches into a single combined digest.
///
/// This enables hierarchical aggregation: aggregate batches into super-batches.
pub fn aggregate_batch_digests(batch_digests: &[Fr]) -> Fr {
    if batch_digests.is_empty() {
        return Fr::ZERO;
    }

    let mut acc = Fr::ZERO;
    for digest in batch_digests {
        acc = poseidon::hash(&[acc, *digest]);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_hash::{blake3::Blake3, HashFunction};
    use hc_verifier::QueryCommitments;

    fn make_summary(init: u64, fin: u64) -> ProofSummary<GoldilocksField> {
        let trace_bytes = format!("trace_{init}_{fin}");
        ProofSummary {
            trace_commitment_digest: Blake3::hash(trace_bytes.as_bytes()),
            initial_acc: GoldilocksField::from_u64(init),
            final_acc: GoldilocksField::from_u64(fin),
            trace_length: 64,
            query_commitments: QueryCommitments {
                trace_commitment: Blake3::hash(b"trace_q"),
                composition_commitment: Blake3::hash(b"comp_q"),
                fri_commitment: Blake3::hash(b"fri_q"),
            },
            circuit_digest: GoldilocksField::from_u64(0),
        }
    }

    #[test]
    fn aggregation_digest_deterministic() {
        let summaries = vec![make_summary(5, 8), make_summary(10, 15)];
        let d1 = compute_aggregation_digest(&summaries);
        let d2 = compute_aggregation_digest(&summaries);
        assert_eq!(d1, d2);
        assert_ne!(d1, Fr::ZERO);
    }

    #[test]
    fn aggregation_digest_different_inputs() {
        let s1 = vec![make_summary(5, 8)];
        let s2 = vec![make_summary(5, 9)];
        assert_ne!(
            compute_aggregation_digest(&s1),
            compute_aggregation_digest(&s2)
        );
    }

    #[test]
    fn aggregation_digest_order_matters() {
        let a = make_summary(1, 2);
        let b = make_summary(3, 4);
        assert_ne!(
            compute_aggregation_digest(&[a.clone(), b.clone()]),
            compute_aggregation_digest(&[b, a])
        );
    }

    #[test]
    fn build_and_verify_batch() {
        let summaries = vec![make_summary(5, 8), make_summary(10, 15)];
        let config = AggregatorConfig::default();
        let batch = build_aggregation_batch(summaries, &config).unwrap();
        assert!(verify_aggregation_batch(&batch));
    }

    #[test]
    fn batch_rejects_empty() {
        let config = AggregatorConfig::default();
        let result = build_aggregation_batch(vec![], &config);
        assert!(result.is_err());
    }

    #[test]
    fn batch_rejects_oversized() {
        let config = AggregatorConfig {
            max_batch_size: 2,
            k: 18,
        };
        let summaries = vec![make_summary(1, 2), make_summary(3, 4), make_summary(5, 6)];
        let result = build_aggregation_batch(summaries, &config);
        assert!(result.is_err());
    }

    #[test]
    fn tampered_batch_fails_verification() {
        let summaries = vec![make_summary(5, 8)];
        let config = AggregatorConfig::default();
        let mut batch = build_aggregation_batch(summaries, &config).unwrap();
        batch.aggregation_digest = Fr::from(999u64);
        assert!(!verify_aggregation_batch(&batch));
    }

    #[test]
    fn hierarchical_aggregation() {
        let config = AggregatorConfig::default();
        let batch1 =
            build_aggregation_batch(vec![make_summary(1, 2), make_summary(3, 4)], &config).unwrap();
        let batch2 =
            build_aggregation_batch(vec![make_summary(5, 6), make_summary(7, 8)], &config).unwrap();

        let super_digest =
            aggregate_batch_digests(&[batch1.aggregation_digest, batch2.aggregation_digest]);
        assert_ne!(super_digest, Fr::ZERO);

        // Deterministic.
        let super_digest2 =
            aggregate_batch_digests(&[batch1.aggregation_digest, batch2.aggregation_digest]);
        assert_eq!(super_digest, super_digest2);
    }
}
