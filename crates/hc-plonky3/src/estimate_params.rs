use crate::bounded_prover::{
    estimated_atomic_checkpoint_bytes, estimated_profile_proof_bytes, fri_mmcs_payload_bytes,
    fri_mmcs_store_count, merkle_payload_bytes, merkle_store_count, BoundedProverError,
};
use crate::dft::ResourceBoundedDft;
use hc_stream::{PhaseEstimate, ResourceEstimate, ResourcePolicyV1, SCRATCH_STORE_HEADER_BYTES};

/// Every scalar the analytic cost model needs. Deliberately contains no AIR
/// and no field type, so it can describe a configuration TinyZKP cannot prove.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EstimateParams {
    pub workload_id: String,
    pub rows: u64,
    pub width: u64,
    pub quotient_chunks: u64,
    pub public_values: u64,
    pub has_next_row_columns: bool,
    /// Bytes per base-field element. Goldilocks = 8.
    pub field_bytes: u64,
    /// Bytes per extension-field element. Goldilocks degree 2 = 16.
    pub ext_field_bytes: u64,
    /// Bytes per Merkle digest. Poseidon2 256-bit = 32.
    pub digest_bytes: u64,
}

/// The parameter-only analytic cost model behind `estimate_air_pipeline`.
///
/// Body copied verbatim from `bounded_prover::estimate_air_pipeline`,
/// substituting the four AIR-derived values for `params` fields and the
/// three byte-width literals (8, 16, 32) for `params.field_bytes`,
/// `params.ext_field_bytes`, and `params.digest_bytes` respectively. Do not
/// "improve" any expression here without re-verifying every byte-equality
/// parity test below and the release-evidence-pinning tests in
/// `bounded_prover.rs`.
pub fn estimate_from_params(
    params: &EstimateParams,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate, BoundedProverError> {
    if params.rows == 0 || !params.rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let width = params.width as usize;
    let quotient_chunks = params.quotient_chunks;
    let rows = params.rows;
    let workload_id = params.workload_id.as_str();
    let public_values = params.public_values as usize;
    let field_bytes = params.field_bytes;
    let ext_field_bytes = params.ext_field_bytes;
    let digest_bytes = params.digest_bytes;
    // The frozen profile always uses at least a two-times FRI blowup. AIRs
    // whose quotient degree needs more chunks raise the blowup to match.
    let blowup = quotient_chunks.max(2);
    let lde_rows = rows.saturating_mul(blowup);
    let trace_bytes = rows
        .saturating_mul(width as u64)
        .saturating_mul(field_bytes);
    let trace_lde_bytes = lde_rows
        .saturating_mul(width as u64)
        .saturating_mul(field_bytes);
    let quotient_bytes = rows
        .saturating_mul(quotient_chunks)
        .saturating_mul(ext_field_bytes);
    let quotient_lde_bytes = lde_rows
        .saturating_mul(quotient_chunks)
        .saturating_mul(ext_field_bytes);
    let one_input_leaf = lde_rows.saturating_mul(digest_bytes);
    let one_input_tree = merkle_payload_bytes(lde_rows);
    let input_mmcs_bytes = one_input_tree.saturating_mul(2);
    // Every retained extension-field FRI vector has lengths blowup*N,
    // blowup*N/2, ..., blowup. Their geometric sum is
    // 2*blowup*N - blowup elements at 16 bytes each.
    let fri_vector_bytes = lde_rows
        .saturating_mul(2)
        .saturating_sub(blowup)
        .saturating_mul(ext_field_bytes);
    let opening_layer_bytes = fri_vector_bytes / 2;
    let fri_mmcs_bytes = fri_mmcs_payload_bytes(lde_rows / 2);
    let durable_core = trace_lde_bytes
        .saturating_add(quotient_lde_bytes)
        .saturating_add(input_mmcs_bytes);
    let proof_bytes = estimated_profile_proof_bytes(rows, width as u64, quotient_chunks);
    let log_rows = rows.trailing_zeros() as u64;
    let max_store_count = 1u64
        .saturating_add(quotient_chunks)
        .saturating_add(merkle_store_count(lde_rows).saturating_mul(2))
        .saturating_add(log_rows.saturating_add(1))
        .saturating_add(fri_mmcs_store_count(log_rows))
        .saturating_add(1);
    let store_headers = max_store_count.saturating_mul(SCRATCH_STORE_HEADER_BYTES);
    let checkpoint_atomic_bytes = estimated_atomic_checkpoint_bytes(
        policy,
        workload_id,
        rows,
        width,
        public_values,
        quotient_chunks,
        params.has_next_row_columns,
        proof_bytes,
    )?;
    // Atomic checkpoint replacement temporarily keeps the previous manifest
    // beside the fully-synced replacement. Store headers and both manifests
    // are therefore included in every candidate phase peak rather than hidden
    // in a row-linear calibration factor.
    let phase_metadata_bytes = store_headers.saturating_add(checkpoint_atomic_bytes);
    let fri_peak = durable_core
        .saturating_add(fri_vector_bytes)
        .saturating_add(fri_mmcs_bytes)
        .saturating_add(phase_metadata_bytes);
    // Once FRI query openings have been assembled, the FRI MMCS trees are
    // released. The retained LDEs, input MMCS trees, all FRI vectors, and the
    // serialized proof artifact remain live through the proof checkpoint.
    let proof_checkpoint_peak = durable_core
        .saturating_add(fri_vector_bytes)
        .saturating_add(proof_bytes)
        .saturating_add(phase_metadata_bytes);
    // Caller input plus padded coefficients and the two active four-step DFT
    // matrices. Quotient transforms additionally coexist with the trace tree,
    // raw/interleaved chunks, and already completed chunk LDEs.
    let trace_transform_peak = rows
        .saturating_mul(width as u64)
        .saturating_mul(56)
        .saturating_add(phase_metadata_bytes);
    let quotient_transform_peak = rows
        .saturating_mul(
            ext_field_bytes
                .saturating_mul(width as u64)
                .saturating_add(64u64.saturating_mul(quotient_chunks))
                .saturating_add(192),
        )
        .saturating_add(phase_metadata_bytes);
    let scratch_high_water_bytes = fri_peak
        .max(trace_transform_peak)
        .max(quotient_transform_peak)
        .max(proof_checkpoint_peak);

    let dft = ResourceBoundedDft::new(policy.clone())?;
    let trace_dft = dft.estimate_scratch(lde_rows as usize, width, false)?;
    let quotient_dft = dft.estimate_scratch(lde_rows as usize, 2, false)?;
    let peak_resident_bytes = trace_dft
        .peak_resident_bytes
        .max(quotient_dft.peak_resident_bytes)
        // Opening reduction holds one bounded source block plus extension-field
        // denominators/reductions and two permutation tiles.
        .max(64 * 1024 * 1024);
    let phases = vec![
        PhaseEstimate {
            phase: "trace_generation".into(),
            read_bytes: 0,
            write_bytes: trace_bytes,
        },
        PhaseEstimate {
            phase: "trace_lde".into(),
            read_bytes: trace_dft.total_read_bytes,
            write_bytes: trace_dft.total_write_bytes,
        },
        PhaseEstimate {
            phase: "trace_commitment".into(),
            read_bytes: trace_lde_bytes
                .saturating_add(one_input_leaf.saturating_mul(3))
                .saturating_add(one_input_tree),
            write_bytes: one_input_tree.saturating_add(one_input_leaf.saturating_mul(3)),
        },
        PhaseEstimate {
            phase: "quotient".into(),
            read_bytes: trace_lde_bytes
                .saturating_add((width as u64).saturating_mul(ext_field_bytes)),
            write_bytes: quotient_bytes,
        },
        PhaseEstimate {
            phase: "quotient_lde".into(),
            read_bytes: quotient_dft
                .total_read_bytes
                .saturating_mul(quotient_chunks),
            write_bytes: quotient_dft
                .total_write_bytes
                .saturating_mul(quotient_chunks),
        },
        PhaseEstimate {
            phase: "quotient_commitment".into(),
            read_bytes: quotient_lde_bytes
                .saturating_add(one_input_leaf.saturating_mul(3))
                .saturating_add(one_input_tree),
            write_bytes: one_input_tree.saturating_add(one_input_leaf.saturating_mul(3)),
        },
        PhaseEstimate {
            phase: "openings".into(),
            read_bytes: trace_lde_bytes
                .saturating_mul(2)
                .saturating_add(quotient_lde_bytes)
                .saturating_add(opening_layer_bytes.saturating_mul(3)),
            write_bytes: opening_layer_bytes.saturating_mul(4),
        },
        PhaseEstimate {
            phase: "fri".into(),
            read_bytes: fri_vector_bytes.saturating_add(fri_mmcs_bytes),
            write_bytes: fri_vector_bytes.saturating_add(fri_mmcs_bytes),
        },
        PhaseEstimate {
            phase: "proof_assembly".into(),
            read_bytes: 0,
            write_bytes: proof_bytes,
        },
    ];
    Ok(ResourceEstimate {
        peak_resident_bytes,
        scratch_high_water_bytes,
        total_read_bytes: phases.iter().map(|phase| phase.read_bytes).sum(),
        total_write_bytes: phases.iter().map(|phase| phase.write_bytes).sum(),
        phases,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded_prover::{estimate_air_pipeline_for_test, params_for_workload_for_test};
    use crate::workloads::{FibonacciWorkload, Poseidon2Workload};

    /// The parameter-only core must reproduce the AIR-driven estimator exactly.
    /// Any divergence would change published evidence in
    /// release/evidence/backend-v1/, so this is byte-equality, not a tolerance.
    #[test]
    fn params_core_matches_air_pipeline_for_reference_workloads() {
        let policy = crate::test_support::release_policy_2gib();

        let fib = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 1 << 20,
        };
        let via_air = estimate_air_pipeline_for_test(&fib, &policy).unwrap();
        let via_params =
            estimate_from_params(&params_for_workload_for_test(&fib), &policy).unwrap();
        assert_eq!(via_air, via_params, "fibonacci 1M estimate diverged");

        let pos = Poseidon2Workload {
            logical_rows: 1 << 20,
        };
        let via_air = estimate_air_pipeline_for_test(&pos, &policy).unwrap();
        let via_params =
            estimate_from_params(&params_for_workload_for_test(&pos), &policy).unwrap();
        assert_eq!(via_air, via_params, "poseidon2 1M estimate diverged");
    }

    /// Row count is the only free variable in the published scaling evidence,
    /// so the core must track it across the full release range.
    #[test]
    fn params_core_matches_air_pipeline_across_row_scale() {
        let policy = crate::test_support::release_policy_2gib();
        for log_rows in 10..=24 {
            let fib = FibonacciWorkload {
                initial_a: 0,
                initial_b: 1,
                logical_rows: 1u64 << log_rows,
            };
            let via_air = estimate_air_pipeline_for_test(&fib, &policy).unwrap();
            let via_params =
                estimate_from_params(&params_for_workload_for_test(&fib), &policy).unwrap();
            assert_eq!(via_air, via_params, "diverged at 2^{log_rows} rows");
        }
    }
}
