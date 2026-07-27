use crate::bounded_prover::{
    estimated_atomic_checkpoint_bytes, estimated_profile_proof_bytes, fri_mmcs_payload_bytes,
    fri_mmcs_store_count, merkle_payload_bytes, merkle_store_count, BoundedProverError,
};
use crate::dft::ResourceBoundedDft;
use hc_stream::{PhaseEstimate, SCRATCH_STORE_HEADER_BYTES};

/// Re-exported so a caller building an `EstimateParams`/`ResourcePolicyV1`
/// pair from `hc_plonky3::estimate_params` alone (e.g. `hc-wasm`'s shared
/// `estimate_request` core) never needs its own direct `hc-stream`
/// dependency just to name these types. `hc-plonky3` already depends on
/// `hc-stream`; this widens visibility only, it adds no new crate edge.
pub use hc_stream::{CheckpointPolicy, ResourceEstimate, ResourceMode, ResourcePolicyV1};

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
/// `params.ext_field_bytes`, and `params.digest_bytes` respectively. The two
/// remaining compound literals (formerly the bare `56` in
/// `trace_transform_peak` and the bare `64`/`192` in
/// `quotient_transform_peak`) are likewise decomposed into a small
/// live-copy count times one of those same byte widths — see the comments
/// at each site. Do not "improve" any expression here without
/// re-verifying every byte-equality parity test below and the
/// release-evidence-pinning tests in `bounded_prover.rs`.
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
    // matrices. What is established: the measured coefficient is seven live
    // copies of the trace's base-field footprint, matching observed peaks,
    // and every copy is a base-field element, so the per-element width is
    // `field_bytes`, not `ext_field_bytes` — this part is pinned by the
    // byte-equality parity tests below and must not be changed without
    // re-verifying them. What is NOT established: the "1 + 1 + 2 doubled
    // across the idft/dft halves of the coset LDE" narrative for why it is
    // seven — that arithmetic sums to eight (1 + 1 + 2 = 4, doubled = 8), not
    // seven, so it does not reconstruct the measured coefficient. The
    // buffer-level attribution behind the `7` is therefore unverified; only
    // the coefficient itself is.
    let trace_transform_peak = rows
        .saturating_mul(width as u64)
        .saturating_mul(7)
        .saturating_mul(field_bytes)
        .saturating_add(phase_metadata_bytes);
    // Quotient transforms additionally coexist with the trace tree,
    // raw/interleaved chunks, and already completed chunk LDEs. The
    // per-chunk term (`4 * ext_field_bytes`) is established: every chunk
    // buffer in `quotient.rs::stream_quotient_values` /
    // `build_quotient_chunk_ldes` stores extension-field coefficients, so
    // four live copies of the quotient-value footprint (raw + interleaved +
    // chunk store + chunk LDE) trace to those named buffers. The fixed `+3`
    // chunk-equivalent floor does NOT: it is only inferred from the
    // algebraic relation `192 = 3 * 64`, and for Goldilocks `192` is equally
    // consistent with `6 * digest_bytes` or `24 * field_bytes` — no test
    // here holds `ext_field_bytes` and `digest_bytes` apart, so the unit
    // choice below is unverified for non-Goldilocks fields. Known
    // limitation of `quotient_transform_peak` outside Goldilocks; if a
    // BabyBear/KoalaBear/Mersenne31 estimate is ever contradicted by
    // measurement, start here.
    let quotient_transform_peak = rows
        .saturating_mul(
            ext_field_bytes
                .saturating_mul(width as u64)
                .saturating_add(
                    4u64.saturating_mul(ext_field_bytes)
                        .saturating_mul(quotient_chunks),
                )
                .saturating_add(12u64.saturating_mul(ext_field_bytes)),
        )
        .saturating_add(phase_metadata_bytes);
    let scratch_high_water_bytes = fri_peak
        .max(trace_transform_peak)
        .max(quotient_transform_peak)
        .max(proof_checkpoint_peak);

    let dft = ResourceBoundedDft::new(policy.clone())?;
    let trace_dft = dft.estimate_scratch(lde_rows as usize, width, false, field_bytes)?;
    let quotient_dft = dft.estimate_scratch(lde_rows as usize, 2, false, field_bytes)?;
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
    // Every individual `phase.*_bytes` value above is already computed with
    // `saturating_*` arithmetic, so no single addend can exceed `u64::MAX`.
    // But plain `Iterator::sum()` adds those addends with ordinary wrapping
    // `+`, so summing several near-`u64::MAX` phases can itself overflow and
    // silently wrap to a small number — release builds have overflow checks
    // disabled, so this would produce a wrong answer at exit 0, not a panic.
    // Fold with `saturating_add` so the total can only saturate, never wrap.
    let total_read_bytes = phases
        .iter()
        .fold(0u64, |total, phase| total.saturating_add(phase.read_bytes));
    let total_write_bytes = phases
        .iter()
        .fold(0u64, |total, phase| total.saturating_add(phase.write_bytes));
    Ok(ResourceEstimate {
        peak_resident_bytes,
        scratch_high_water_bytes,
        total_read_bytes,
        total_write_bytes,
        phases,
    })
}

/// Parameter-only mirror of `conventional_pipeline_estimate` in `prover.rs`
/// (the naive, fully-in-memory Plonky3 pipeline — no streaming, no scratch),
/// generalised by `field_bytes`/`ext_field_bytes` the same way
/// `estimate_from_params` was. `conventional_pipeline_estimate` never streams
/// anything through scratch, so unlike `estimate_from_params` this reports a
/// flat `peak_resident_bytes` and none of that function's streaming
/// `scratch_high_water_bytes`/`total_read_bytes`/`total_write_bytes` figures.
///
/// Decomposition of `conventional_pipeline_estimate`'s formula
/// (`rows * (24*width + 32*chunks + 448) + 32 MiB`), checked against the
/// single field this codebase actually measures (Goldilocks:
/// `field_bytes = 8`, `ext_field_bytes = 16`):
///
/// - `24` -> `3 * field_bytes`. Exact at Goldilocks (`3 * 8 = 24`); a
///   conventional in-memory run naturally keeps a small, fixed number of
///   live base-field-typed trace buffers per column (e.g. the trace, its
///   LDE, and one committed copy), so a `3` live-copy count is a plausible
///   read, in the same style as `trace_transform_peak`'s live-copy count
///   above — but as with that term, no named buffer in this codebase has
///   been checked one-for-one against this `3`, so treat the *coefficient*
///   `24 = 3 * field_bytes` as established (it reproduces the real function
///   exactly) and the "3 named buffers" story as a plausible but unverified
///   gloss on it.
/// - `32` -> `2 * ext_field_bytes`. Also exact at Goldilocks (`2 * 16 =
///   32`), but with only one field's numbers to calibrate against, `32`
///   is equally consistent with `4 * field_bytes` (`4 * 8 = 32`) — this
///   single data point cannot distinguish an ext-field-typed unit from a
///   base-field-typed one, the same ambiguity flagged for the `192` term in
///   `quotient_transform_peak` above. It is decomposed as
///   `2 * ext_field_bytes` here (quotient chunks are extension-field
///   values, so an ext-field-typed unit is the more natural read) purely
///   for documentation symmetry with the other terms: for all four fields
///   `field_widths` currently resolves, `ext_field_bytes` is 16, so this
///   choice is numerically identical to leaving `32` a bare literal for
///   every config this estimator can actually be asked to price today. If a
///   field with a different `ext_field_bytes` is ever added, this term must
///   be re-verified against real measurement before being trusted.
/// - `448` and the flat `32 * 1024 * 1024`: left as bare literals,
///   deliberately NOT scaled by any field width. With a single Goldilocks
///   calibration point, `448` is simultaneously consistent with
///   `56 * field_bytes`, `28 * ext_field_bytes`, and `14 * digest_bytes` (and
///   `32 MiB` has no per-element structure at all), so no unit can be
///   established from the evidence available. Per the "leave it fixed and
///   document it" rule for unestablished terms: an unscaled literal is also
///   the conservative choice — for a narrower field it does not shrink, so
///   it never turns an under-estimate into a false "this fits" — whereas
///   guessing a scaling that turns out wrong could silently under-report.
///
/// CRITICAL INVARIANT: for Goldilocks this must reproduce
/// `conventional_pipeline_estimate`'s `peak_resident_bytes` byte-for-byte —
/// see the parity tests below, which hold this to the same standard as the
/// bounded-core parity tests above and the release-evidence-pinning tests in
/// `bounded_prover.rs`.
///
/// Unlike `estimate_from_params`, this does NOT itself validate that `rows`
/// is a nonzero power of two — neither does the real
/// `conventional_pipeline_estimate` it mirrors; that check lives in its
/// caller, `estimate_resource_conventional_workload`. `estimate_config::run`
/// gets this for free because it calls `estimate_from_params` for `bounded`
/// first and propagates that call's error before ever reaching this
/// function; a caller that invokes this function standalone with unvalidated
/// `rows` is responsible for validating it first.
pub fn estimate_conventional_from_params(params: &EstimateParams) -> ResourceEstimate {
    let per_row_width_bytes = 3u64
        .saturating_mul(params.field_bytes)
        .saturating_mul(params.width);
    let per_row_chunk_bytes = 2u64
        .saturating_mul(params.ext_field_bytes)
        .saturating_mul(params.quotient_chunks);
    const PER_ROW_FIXED_BYTES: u64 = 448;
    const FLAT_FLOOR_BYTES: u64 = 32 * 1024 * 1024;

    let peak_resident_bytes = params
        .rows
        .saturating_mul(
            per_row_width_bytes
                .saturating_add(per_row_chunk_bytes)
                .saturating_add(PER_ROW_FIXED_BYTES),
        )
        .saturating_add(FLAT_FLOOR_BYTES);

    ResourceEstimate {
        peak_resident_bytes,
        scratch_high_water_bytes: 1,
        total_read_bytes: 0,
        total_write_bytes: 0,
        phases: vec![PhaseEstimate {
            phase: "conventional_full_pipeline".into(),
            read_bytes: 0,
            write_bytes: 0,
        }],
    }
}

/// Base-field byte width and canonical binomial-extension degree for fields
/// Plonky3 ships. Goldilocks (64-bit) reaches ~128-bit security at degree 2;
/// BabyBear/KoalaBear/Mersenne31 (31-bit) need degree 4. A caller-supplied
/// `extension_degree` that does not match the field's canonical degree is
/// rejected rather than priced: this function only reports widths for
/// extensions this codebase would actually reach for, not every degree that
/// happens to be algebraically valid.
fn canonical_extension_degree(field: &str) -> Option<(u64, u8)> {
    match field {
        "goldilocks" => Some((8, 2)),
        "babybear" | "koalabear" | "mersenne31" => Some((4, 4)),
        _ => None,
    }
}

/// Base and extension element widths in bytes for fields Plonky3 ships.
/// Returns None for anything unrecognised, including a recognised field
/// paired with an extension degree this codebase does not use: an estimate
/// built on a guessed element width would be worse than no estimate.
pub fn field_widths(field: &str, extension_degree: u8) -> Option<(u64, u64)> {
    let (base, degree) = canonical_extension_degree(field)?;
    if extension_degree != degree {
        return None;
    }
    Some((base, base * degree as u64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded_prover::{
        estimate_air_pipeline_for_test, estimate_resource_conventional_workload,
        params_for_workload_for_test,
    };
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

    /// The parameter-only conventional core must reproduce
    /// `conventional_pipeline_estimate` (via
    /// `estimate_resource_conventional_workload`) exactly for Goldilocks —
    /// this is the CRITICAL INVARIANT documented on
    /// `estimate_conventional_from_params`: any divergence would mean
    /// `estimates.conventional` in the CLI's JSON output no longer means
    /// what `doctor`/`RequestedModeV1::Auto` mean by "conventional".
    #[test]
    fn conventional_params_core_matches_conventional_pipeline_for_reference_workloads() {
        let fib = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 1 << 20,
        };
        let via_real = estimate_resource_conventional_workload(&fib).unwrap();
        let via_params = estimate_conventional_from_params(&params_for_workload_for_test(&fib));
        assert_eq!(
            via_real, via_params,
            "fibonacci 1M conventional estimate diverged"
        );

        let pos = Poseidon2Workload {
            logical_rows: 1 << 20,
        };
        let via_real = estimate_resource_conventional_workload(&pos).unwrap();
        let via_params = estimate_conventional_from_params(&params_for_workload_for_test(&pos));
        assert_eq!(
            via_real, via_params,
            "poseidon2 1M conventional estimate diverged"
        );
    }

    /// Same row-scale sweep as `params_core_matches_air_pipeline_across_row_scale`,
    /// applied to the conventional core.
    #[test]
    fn conventional_params_core_matches_conventional_pipeline_across_row_scale() {
        for log_rows in 10..=24 {
            let fib = FibonacciWorkload {
                initial_a: 0,
                initial_b: 1,
                logical_rows: 1u64 << log_rows,
            };
            let via_real = estimate_resource_conventional_workload(&fib).unwrap();
            let via_params = estimate_conventional_from_params(&params_for_workload_for_test(&fib));
            assert_eq!(via_real, via_params, "diverged at 2^{log_rows} rows");
        }
    }

    /// The property that makes `field_bytes`/`ext_field_bytes` generalisation
    /// meaningful here too: a narrower field must not report the same (or a
    /// larger) conventional peak as Goldilocks at identical shape.
    #[test]
    fn conventional_narrower_field_yields_smaller_estimate() {
        let base = EstimateParams {
            workload_id: "synthetic".to_string(),
            rows: 1 << 20,
            width: 64,
            quotient_chunks: 2,
            public_values: 4,
            has_next_row_columns: true,
            field_bytes: 8,
            ext_field_bytes: 16,
            digest_bytes: 32,
        };
        let narrow = EstimateParams {
            field_bytes: 4,
            ..base.clone()
        };

        let wide_est = estimate_conventional_from_params(&base);
        let narrow_est = estimate_conventional_from_params(&narrow);

        assert!(
            narrow_est.peak_resident_bytes < wide_est.peak_resident_bytes,
            "4-byte field {} should need less conventional resident memory than 8-byte {}",
            narrow_est.peak_resident_bytes,
            wide_est.peak_resident_bytes
        );
    }

    #[test]
    fn known_field_widths_are_resolved() {
        assert_eq!(field_widths("goldilocks", 2), Some((8, 16)));
        assert_eq!(field_widths("babybear", 4), Some((4, 16)));
        assert_eq!(field_widths("koalabear", 4), Some((4, 16)));
        assert_eq!(field_widths("mersenne31", 4), Some((4, 16)));
    }

    #[test]
    fn unknown_field_is_rejected_rather_than_guessed() {
        assert_eq!(field_widths("bn254", 1), None);
        assert_eq!(field_widths("goldilocks", 7), None);
    }

    /// A 4-byte base field must produce a strictly smaller trace footprint AND
    /// a strictly smaller resident-memory footprint than an 8-byte one at
    /// identical shape. This is the property that makes cross-field estimates
    /// meaningful rather than decorative: a prior version of this core left
    /// several byte-width literals hardcoded to Goldilocks, so `field_bytes`
    /// was a no-op on both `scratch_high_water_bytes` and
    /// `peak_resident_bytes`.
    #[test]
    fn narrower_field_yields_smaller_estimate() {
        let policy = crate::test_support::release_policy_2gib();
        let base = EstimateParams {
            workload_id: "synthetic".to_string(),
            rows: 1 << 20,
            width: 64,
            quotient_chunks: 2,
            public_values: 4,
            has_next_row_columns: true,
            field_bytes: 8,
            ext_field_bytes: 16,
            digest_bytes: 32,
        };
        let narrow = EstimateParams {
            field_bytes: 4,
            ..base.clone()
        };

        let wide_est = estimate_from_params(&base, &policy).unwrap();
        let narrow_est = estimate_from_params(&narrow, &policy).unwrap();

        assert!(
            narrow_est.scratch_high_water_bytes < wide_est.scratch_high_water_bytes,
            "4-byte field {} should need less scratch than 8-byte {}",
            narrow_est.scratch_high_water_bytes,
            wide_est.scratch_high_water_bytes
        );
        assert!(
            narrow_est.peak_resident_bytes < wide_est.peak_resident_bytes,
            "4-byte field {} should need less resident memory than 8-byte {}",
            narrow_est.peak_resident_bytes,
            wide_est.peak_resident_bytes
        );
    }

    /// Goldilocks is the field TinyZKP actually proves; its numbers must
    /// match exactly what `field_widths("goldilocks", 2)` reproduces, so a
    /// caller building `EstimateParams` from the declared config string gets
    /// today's published evidence back byte-for-byte.
    #[test]
    fn goldilocks_field_widths_reproduce_the_pinned_byte_widths() {
        assert_eq!(field_widths("goldilocks", 2), Some((8, 16)));
    }

    /// Regression for a real defect: `total_read_bytes`/`total_write_bytes`
    /// used `Iterator::sum()`, which adds with ordinary wrapping `+`. Every
    /// individual `phase.*_bytes` is already `saturating_*`-computed and can
    /// individually reach `u64::MAX`, so summing several such phases could
    /// overflow the `sum()` itself and wrap to a small number — in release
    /// builds (no overflow checks) this was a silently wrong answer at exit
    /// 0, not a panic. At 2^48 rows this produced
    /// `total_read_bytes = 10_700_552_714_632_300_784`; at 2^50 rows (a
    /// *larger* row count) it wrapped down to `1_297_036_692_682_705_071` —
    /// 4x the input row count produced an 8x *smaller* answer. A correct,
    /// saturating total can only ever be monotonically non-decreasing in
    /// rows, so this asserts that ordering directly using the exact row
    /// counts that reproduced the bug, rather than merely re-deriving the
    /// same (possibly still-wrapped) arithmetic in the test.
    #[test]
    fn overflowing_row_counts_saturate_rather_than_wrap() {
        let policy = crate::test_support::release_policy_2gib();
        let params_at = |rows: u64| EstimateParams {
            workload_id: "overflow-probe".to_string(),
            rows,
            width: 2,
            quotient_chunks: 1,
            public_values: 3,
            has_next_row_columns: false,
            field_bytes: 8,
            ext_field_bytes: 16,
            digest_bytes: 32,
        };

        let at_2_48 = estimate_from_params(&params_at(1u64 << 48), &policy).unwrap();
        let at_2_50 = estimate_from_params(&params_at(1u64 << 50), &policy).unwrap();

        assert!(
            at_2_50.total_read_bytes >= at_2_48.total_read_bytes,
            "more rows must never read fewer total bytes: 2^50 gave {}, 2^48 gave {} \
             (a wrapped total would go backwards here)",
            at_2_50.total_read_bytes,
            at_2_48.total_read_bytes
        );
        assert!(
            at_2_50.total_write_bytes >= at_2_48.total_write_bytes,
            "more rows must never write fewer total bytes: 2^50 gave {}, 2^48 gave {} \
             (a wrapped total would go backwards here)",
            at_2_50.total_write_bytes,
            at_2_48.total_write_bytes
        );

        // A saturating total can never fall below the largest single phase
        // that feeds it — a wrapped total could.
        for estimate in [&at_2_48, &at_2_50] {
            let max_phase_read = estimate
                .phases
                .iter()
                .map(|phase| phase.read_bytes)
                .max()
                .unwrap();
            let max_phase_write = estimate
                .phases
                .iter()
                .map(|phase| phase.write_bytes)
                .max()
                .unwrap();
            assert!(
                estimate.total_read_bytes >= max_phase_read,
                "total_read_bytes {} is below its own largest phase {} — wrapped",
                estimate.total_read_bytes,
                max_phase_read
            );
            assert!(
                estimate.total_write_bytes >= max_phase_write,
                "total_write_bytes {} is below its own largest phase {} — wrapped",
                estimate.total_write_bytes,
                max_phase_write
            );
        }
    }
}
