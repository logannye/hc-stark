//! Cross-field calibration of `estimate_params.rs`'s scratch cost model against
//! the durable pipeline's OWN accounting, run at Goldilocks and at BabyBear.
//!
//! ## What this measures, and what it deliberately does not
//!
//! The measured number is the high-water mark of
//! `bounded_prover::measure_resource_usage`'s `scratch_bytes` — the summed
//! length of every file under the job's scratch root, sampled while the proof
//! runs. That is the pipeline's own deterministic filesystem accounting: file
//! lengths, not an OS memory counter. It is meaningful on any platform.
//!
//! Peak RESIDENT memory is NOT measured here and must not be inferred from
//! anything this file prints. `measure_resource_usage` returns
//! `resident_bytes: None` on every non-Linux target, and
//! `scripts/benchmark/run_plonky3_cgroup.py` refuses to emit release evidence
//! without Linux cgroup v2 accounting.
//!
//! `total_read_bytes`/`total_write_bytes` are also NOT measured: the durable
//! pipeline carries no I/O byte counters anywhere in this workspace, so those
//! two fields of `ResourceEstimate` are model output with no runtime
//! counterpart to compare against. They are printed for completeness and
//! labelled as modelled-only.
//!
//! ## The question this exists to answer
//!
//! `estimate_params::estimate_from_params`'s `quotient_transform_peak` carries
//! a fixed per-row term written as `12 * ext_field_bytes`. At Goldilocks that
//! is 192 bytes/row, and the in-code comment records that 192 is equally
//! consistent with `6 * digest_bytes` and with `24 * field_bytes` — no
//! Goldilocks test can separate them.
//!
//! `estimate_params::canonical_extension_degree` returns `(8, 2)` for
//! Goldilocks and `(4, 4)` for BabyBear/KoalaBear/Mersenne31, so
//! `ext_field_bytes` is 16 and `digest_bytes` is 32 for EVERY field this
//! codebase supports. Consequently:
//!
//! | reading                | goldilocks | babybear |
//! |------------------------|-----------:|---------:|
//! | `12 * ext_field_bytes` |        192 |      192 |
//! | `6 * digest_bytes`     |        192 |      192 |
//! | `24 * field_bytes`     |        192 |   **96** |
//!
//! A BabyBear measurement can therefore FALSIFY the `24 * field_bytes`
//! reading, and can say NOTHING about `12 * ext_field_bytes` versus
//! `6 * digest_bytes` — those coincide in every field on this roadmap. This
//! file is written to respect that boundary exactly.
//!
//! ## Scalar-SIMD caveat on any timing printed here
//!
//! `hc-simd` selects its packed kernels through a runtime `TypeId` check for
//! Goldilocks only, so BabyBear runs the SCALAR path. Wall-clock numbers
//! printed by this harness are therefore NOT a fair CPU comparison between the
//! two fields. Nothing about the scratch byte accounting depends on which
//! kernel computed the values.
//!
//! ## Running it
//!
//! ```text
//! # model sweep + the Fibonacci reading (seconds)
//! cargo test -p hc-plonky3 --lib scratch_calibration -- --nocapture
//!
//! # the reading inside the band where the disputed term is observable
//! cargo test --release -p hc-plonky3 --lib scratch_calibration -- \
//!     --ignored --nocapture
//! ```

#![cfg(test)]

use crate::bounded_prover::{
    estimate_resource_bounded_workload_with_profile, estimated_atomic_checkpoint_bytes,
    estimated_profile_proof_bytes, fri_mmcs_payload_bytes, fri_mmcs_store_count,
    measure_resource_usage, merkle_payload_bytes, merkle_store_count,
    prove_resource_bounded_with_profile,
};
use crate::estimate_params::{estimate_from_params, EstimateParams};
use crate::profile::{BabyBearProfile, DurableFieldProfile, GoldilocksProfile};
use crate::workloads::{
    FibonacciWorkload, GeneratedTraceV1, ResourceBoundedWorkload, WorkloadError,
    WorkloadIdentityV1, WorkloadResult,
};
use hc_stream::{
    CheckpointPolicy, MatrixStore, ResourceEstimate, ResourceMode, ResourcePolicyV1,
    SCRATCH_STORE_HEADER_BYTES,
};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::PrimeCharacteristicRing;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Goldilocks' Poseidon2 permutation width and Merkle digest size.
const GOLDILOCKS_PW: usize = 8;
const GOLDILOCKS_DE: usize = 4;
/// BabyBear's. Plonky3's own reference BabyBear config numbers.
const BABYBEAR_PW: usize = 16;
const BABYBEAR_DE: usize = 8;

/// Number of independent proving runs per field per shape. The sampler is a
/// lower bound per run (see [`polled_scratch_peak`]), so repeating tightens it.
/// Two runs is enough to expose whether sampling noise is anywhere near the
/// scale of the effect being tested; in practice the observed spread is 0.00%.
const RUNS_PER_FIELD: usize = 2;

fn policy(root: &Path) -> ResourcePolicyV1 {
    ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 128 * 1024 * 1024,
        max_scratch_bytes: 2 * 1024 * 1024 * 1024,
        scratch_dir: root.to_path_buf(),
        max_threads: 1,
        // BabyBear cannot write a resumable checkpoint (`BabyBearProfile`
        // returns `None` from `capture_challenger`), so a single-shot policy is
        // the only one both fields can share.
        checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
    }
}

// ---------------------------------------------------------------------------
// A second, WIDE, field-agnostic workload
// ---------------------------------------------------------------------------

/// A width-`columns` AIR whose transition constraint is a squaring, giving a
/// total constraint degree of 3 (2 for the squaring, +1 for the transition
/// selector) and therefore TWO quotient chunks.
///
/// It exists because the only workload this crate implements for every profile
/// is `FibonacciWorkload`, whose shape is fixed at width 2 / one quotient chunk
/// — and at that shape the disputed `quotient_transform_peak` term is
/// dominated by `fri_peak` at every row count, so no Fibonacci measurement can
/// see it. `Poseidon2Workload` is pinned to
/// `ResourceBoundedWorkload<8, 4, GoldilocksProfile>` because its AIR bakes in
/// Goldilocks round constants, so it cannot supply a wide BabyBear trace
/// either.
///
/// This is a measurement fixture, not a product AIR: it is `#[cfg(test)]`, it
/// is not registered with the CLI, and it asserts nothing about soundness
/// beyond the fact that the stock pipeline proves it.
#[derive(Clone, Copy, Debug)]
struct SquaringChainAir {
    columns: usize,
}

impl<F> BaseAir<F> for SquaringChainAir {
    fn width(&self) -> usize {
        self.columns
    }

    fn num_public_values(&self) -> usize {
        0
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB: AirBuilder> Air<AB> for SquaringChainAir {
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();
        let seeds: Vec<AB::Expr> = (0..self.columns)
            .map(|column| AB::Expr::from_u64(column as u64 + 1))
            .collect();
        let squares: Vec<AB::Expr> = (0..self.columns)
            .map(|column| local[column] * local[column])
            .collect();
        for (column, seed) in seeds.into_iter().enumerate() {
            builder.when_first_row().assert_eq(local[column], seed);
        }
        for (column, square) in squares.into_iter().enumerate() {
            builder.when_transition().assert_eq(next[column], square);
        }
    }
}

/// Row 0 is `[1, 2, ..., columns]`; every later row is the previous row
/// squared elementwise. Field-agnostic, so it generates a valid trace at any
/// profile.
#[derive(Clone, Copy, Debug)]
struct SquaringChainWorkload {
    logical_rows: u64,
    columns: usize,
}

impl<const PW: usize, const DE: usize, P> ResourceBoundedWorkload<PW, DE, P>
    for SquaringChainWorkload
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    type Air = SquaringChainAir;

    fn identity(&self) -> WorkloadIdentityV1 {
        WorkloadIdentityV1 {
            id: "squaring_chain_calibration",
            version: 1,
        }
    }

    fn rows(&self) -> u64 {
        self.logical_rows
    }

    fn air(&self) -> Self::Air {
        SquaringChainAir {
            columns: self.columns,
        }
    }

    fn public_values(&self) -> Vec<P::Val> {
        Vec::new()
    }

    fn input_digest(&self) -> [u8; 32] {
        let mut digest = [0u8; 32];
        digest[..8].copy_from_slice(&self.logical_rows.to_le_bytes());
        digest[8..16].copy_from_slice(&(self.columns as u64).to_le_bytes());
        digest
    }

    fn write_trace<S: MatrixStore<P::Word>>(
        &self,
        store: &mut S,
        block_rows: usize,
    ) -> WorkloadResult<GeneratedTraceV1<P::Val>> {
        let rows = usize::try_from(self.logical_rows).map_err(|_| WorkloadError::InvalidShape)?;
        if rows == 0 || !rows.is_power_of_two() || block_rows == 0 {
            return Err(WorkloadError::InvalidShape);
        }
        let columns = self.columns;
        let block_rows = block_rows.min(rows);
        let mut block = vec![P::Word::default(); block_rows * columns];
        let mut state: Vec<P::Val> = (0..columns)
            .map(|column| P::Val::from_u64(column as u64 + 1))
            .collect();
        for block_start in (0..rows).step_by(block_rows) {
            let row_count = (rows - block_start).min(block_rows);
            for row in 0..row_count {
                let offset = row * columns;
                for column in 0..columns {
                    block[offset + column] = P::Word::from(state[column]);
                }
                if block_start + row + 1 < rows {
                    for value in state.iter_mut() {
                        *value = *value * *value;
                    }
                }
            }
            store.write_rows(block_start as u64, row_count, &block[..row_count * columns])?;
        }
        let trace_digest = store.finalize()?;
        Ok(GeneratedTraceV1 {
            identity: ResourceBoundedWorkload::<PW, DE, P>::identity(self),
            rows: self.logical_rows,
            columns,
            public_values: Vec::new(),
            input_digest: ResourceBoundedWorkload::<PW, DE, P>::input_digest(self),
            trace_digest,
        })
    }
}

// ---------------------------------------------------------------------------
// The cost model, decomposed
// ---------------------------------------------------------------------------

/// The four candidate peaks `estimate_from_params` maximises over, plus the
/// counterfactual quotient peak under the `24 * field_bytes` reading of the
/// disputed term.
///
/// This is a MIRROR of the shipped model, not a second implementation of it:
/// every construction site asserts `max(fri, trace, quotient, proof) ==
/// estimate_from_params(..).scratch_high_water_bytes`, so if the model ever
/// changes shape this file fails loudly instead of reporting a stale
/// decomposition. It exists only so the harness can say WHICH term binds —
/// without that, agreement on the total says nothing about the disputed term.
#[derive(Clone, Copy, Debug)]
struct Peaks {
    fri: u64,
    trace_transform: u64,
    quotient_transform: u64,
    proof_checkpoint: u64,
    /// `quotient_transform` with `12 * ext_field_bytes` replaced by
    /// `24 * field_bytes`. Identical to `quotient_transform` at Goldilocks by
    /// construction: `24 * 8 == 12 * 16 == 192`.
    quotient_transform_under_24_field_bytes: u64,
}

impl Peaks {
    fn shipped_high_water(self) -> u64 {
        self.fri
            .max(self.trace_transform)
            .max(self.quotient_transform)
            .max(self.proof_checkpoint)
    }

    fn high_water_under_24_field_bytes(self) -> u64 {
        self.fri
            .max(self.trace_transform)
            .max(self.quotient_transform_under_24_field_bytes)
            .max(self.proof_checkpoint)
    }

    /// True when the shipped model and the `24 * field_bytes` counterfactual
    /// disagree on `scratch_high_water_bytes` — i.e. when a measurement of the
    /// high-water can tell the two readings apart at all.
    fn discriminates(self) -> bool {
        self.shipped_high_water() != self.high_water_under_24_field_bytes()
    }

    fn binding_term(self) -> &'static str {
        let high_water = self.shipped_high_water();
        if high_water == self.quotient_transform {
            "quotient_transform_peak"
        } else if high_water == self.fri {
            "fri_peak"
        } else if high_water == self.proof_checkpoint {
            "proof_checkpoint_peak"
        } else {
            "trace_transform_peak"
        }
    }
}

fn peaks(params: &EstimateParams, policy: &ResourcePolicyV1) -> Peaks {
    peaks_with_metadata(params, phase_metadata_bytes(params, policy))
}

/// `phase_metadata_bytes` is added to all five values in [`Peaks`] identically,
/// so it is a common offset: `max(a+m, .., e+m) == max(a, .., e) + m`, and
/// [`Peaks::discriminates`] — an equality between two such maxima — is
/// therefore invariant to it. The sweep passes `0` because computing the real
/// value costs two `serde_json` serialisations of a full checkpoint manifest
/// per shape, which dominates a 6000-shape sweep.
fn peaks_with_metadata(params: &EstimateParams, phase_metadata_bytes: u64) -> Peaks {
    let rows = params.rows;
    let field_bytes = params.field_bytes;
    let ext_field_bytes = params.ext_field_bytes;
    let digest_bytes = params.digest_bytes;
    let width = params.width;
    let quotient_chunks = params.quotient_chunks;

    let blowup = quotient_chunks.max(2);
    let lde_rows = rows * blowup;
    let trace_lde_bytes = lde_rows * width * field_bytes;
    let quotient_lde_bytes = lde_rows * quotient_chunks * ext_field_bytes;
    let one_input_tree = merkle_payload_bytes(lde_rows);
    let input_mmcs_bytes = one_input_tree * 2;
    let fri_vector_bytes = (lde_rows * 2 - blowup) * ext_field_bytes;
    let fri_mmcs_bytes = fri_mmcs_payload_bytes(lde_rows / 2);
    let durable_core = trace_lde_bytes + quotient_lde_bytes + input_mmcs_bytes;

    let extension_degree = ext_field_bytes / field_bytes;
    let digest_words = digest_bytes / field_bytes;
    let proof_bytes =
        estimated_profile_proof_bytes(rows, width, quotient_chunks, digest_words, extension_degree);
    let quotient_common = ext_field_bytes * width + 4 * ext_field_bytes * quotient_chunks;

    Peaks {
        fri: durable_core + fri_vector_bytes + fri_mmcs_bytes + phase_metadata_bytes,
        trace_transform: rows * width * 7 * field_bytes + phase_metadata_bytes,
        quotient_transform: rows * (quotient_common + 12 * ext_field_bytes) + phase_metadata_bytes,
        proof_checkpoint: durable_core + fri_vector_bytes + proof_bytes + phase_metadata_bytes,
        quotient_transform_under_24_field_bytes: rows * (quotient_common + 24 * field_bytes)
            + phase_metadata_bytes,
    }
}

/// Scratch-store headers plus the two checkpoint manifests an atomic
/// replacement holds — the term `estimate_from_params` adds to every candidate
/// phase peak.
fn phase_metadata_bytes(params: &EstimateParams, policy: &ResourcePolicyV1) -> u64 {
    let rows = params.rows;
    let lde_rows = rows * params.quotient_chunks.max(2);
    let extension_degree = params.ext_field_bytes / params.field_bytes;
    let digest_words = params.digest_bytes / params.field_bytes;
    let log_rows = u64::from(rows.trailing_zeros());
    let max_store_count = 1
        + params.quotient_chunks
        + merkle_store_count(lde_rows) * 2
        + (log_rows + 1)
        + fri_mmcs_store_count(log_rows)
        + 1;
    let proof_bytes = estimated_profile_proof_bytes(
        rows,
        params.width,
        params.quotient_chunks,
        digest_words,
        extension_degree,
    );
    let checkpoint_atomic_bytes = estimated_atomic_checkpoint_bytes(
        policy,
        &params.workload_id,
        rows,
        params.width as usize,
        params.public_values as usize,
        params.quotient_chunks,
        params.has_next_row_columns,
        proof_bytes,
        digest_words as usize,
        extension_degree as usize,
        crate::bounded_prover::GOLDILOCKS_CHALLENGER_SNAPSHOT_BYTES,
    )
    .unwrap();
    max_store_count * SCRATCH_STORE_HEADER_BYTES + checkpoint_atomic_bytes
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

/// The shape being priced and proved, spelled once so the predicted and
/// measured sides cannot silently describe different configurations.
#[derive(Clone, Copy, Debug)]
struct Shape {
    label: &'static str,
    rows: u64,
    width: u64,
    quotient_chunks: u64,
    public_values: u64,
    has_next_row_columns: bool,
}

const FIBONACCI_SHAPE: Shape = Shape {
    label: "fibonacci",
    rows: 1 << 14,
    width: 2,
    quotient_chunks: 1,
    public_values: 3,
    has_next_row_columns: true,
};

/// `squaring_chain` at width 25 with two quotient chunks. This is not an
/// arbitrary choice: `disputed_quotient_term_is_observable_only_in_a_narrow_band`
/// derives, by exhaustive sweep of the shipped model, that
/// `scratch_high_water_bytes` distinguishes the `12 * ext_field_bytes` and
/// `24 * field_bytes` readings at BabyBear ONLY for `quotient_chunks == 2` and
/// `trace_width` in 24..=26. Width 25 sits in the middle of that band.
const SQUARING_CHAIN_SHAPE: Shape = Shape {
    label: "squaring_chain",
    rows: 1 << 14,
    width: 25,
    quotient_chunks: 2,
    public_values: 0,
    has_next_row_columns: true,
};

fn params_for(shape: Shape, workload_id: &str, field_bytes: u64) -> EstimateParams {
    EstimateParams {
        workload_id: workload_id.to_string(),
        rows: shape.rows,
        width: shape.width,
        quotient_chunks: shape.quotient_chunks,
        public_values: shape.public_values,
        has_next_row_columns: shape.has_next_row_columns,
        field_bytes,
        // Both fields: `ext_field_bytes = field_bytes * extension_degree`
        // (8*2 and 4*4) and `digest_bytes = field_bytes * DIGEST_ELEMS`
        // (8*4 and 4*8). See `bounded_prover::profile_estimate_params`.
        ext_field_bytes: 16,
        digest_bytes: 32,
    }
}

/// Poll the scratch root's total file size while `prove` runs, returning the
/// largest total observed.
///
/// The sampler polls rather than hooking phase boundaries because
/// phase-boundary sampling systematically misses intra-phase peaks: the
/// Goldilocks calibration already in `bounded_prover.rs` reports a
/// phase-boundary peak 2.6x BELOW the polled peak for the Poseidon2 workload.
/// A polled peak is a LOWER BOUND on the true high-water — it can miss a peak,
/// but it can never report one that did not occur — which is why the harness
/// takes the max across repeated runs and prints the spread.
fn polled_scratch_peak(root: &Path, prove: impl FnOnce() -> Vec<u8>) -> (u64, Vec<u8>, Duration) {
    let stopped = Arc::new(AtomicBool::new(false));
    let peak = Arc::new(AtomicU64::new(0));
    let sampler_root = root.to_path_buf();
    let sampler_stopped = stopped.clone();
    let sampler_peak = peak.clone();
    let sampler = std::thread::spawn(move || {
        while !sampler_stopped.load(Ordering::Acquire) {
            sampler_peak.fetch_max(
                measure_resource_usage(Some(&sampler_root)).scratch_bytes,
                Ordering::AcqRel,
            );
            std::thread::yield_now();
        }
        sampler_peak.fetch_max(
            measure_resource_usage(Some(&sampler_root)).scratch_bytes,
            Ordering::AcqRel,
        );
    });

    let started = Instant::now();
    let proof = prove();
    let elapsed = started.elapsed();

    stopped.store(true, Ordering::Release);
    sampler.join().unwrap();
    (peak.load(Ordering::Acquire), proof, elapsed)
}

/// One field's full reading at one shape.
struct Reading {
    field: &'static str,
    shape: Shape,
    predicted: ResourceEstimate,
    peaks: Peaks,
    measured_runs: Vec<u64>,
    elapsed: Duration,
    proof_bytes: usize,
}

impl Reading {
    /// The primary measured number: the LARGEST scratch high-water any run
    /// observed. The sampler can only miss a peak, never invent one, so the max
    /// over runs is the tightest lower bound this harness can produce.
    fn measured(&self) -> u64 {
        self.measured_runs.iter().copied().max().unwrap_or(0)
    }

    fn sampling_spread_percent(&self) -> f64 {
        let max = self.measured() as f64;
        let min = self.measured_runs.iter().copied().min().unwrap_or(0) as f64;
        if max == 0.0 {
            return 0.0;
        }
        (max - min) / max * 100.0
    }

    fn ratio(&self) -> f64 {
        self.predicted.scratch_high_water_bytes as f64 / self.measured() as f64
    }

    fn counterfactual_ratio(&self) -> f64 {
        self.peaks.high_water_under_24_field_bytes() as f64 / self.measured() as f64
    }
}

/// Run one field at one shape: price it, prove it, and hold the hand-written
/// `EstimateParams` to the profile-driven estimate byte for byte.
fn reading(
    field: &'static str,
    shape: Shape,
    field_bytes: u64,
    workload_id: &str,
    estimate: impl FnOnce(&ResourcePolicyV1) -> ResourceEstimate,
    mut prove: impl FnMut(&Path) -> Vec<u8>,
) -> Reading {
    let params = params_for(shape, workload_id, field_bytes);
    // ONE policy drives both estimates. `estimated_atomic_checkpoint_bytes`
    // serialises the whole `ResourcePolicyV1` — scratch path included — into
    // its sizing manifests, so estimating against two different temporary
    // directories would differ by the length of the path and defeat the
    // byte-equality check below.
    let scratch = tempfile::tempdir().unwrap();
    let estimate_policy = policy(scratch.path());
    let predicted = estimate(&estimate_policy);
    let peaks = peaks(&params, &estimate_policy);

    assert_eq!(
        estimate_from_params(&params, &estimate_policy)
            .unwrap()
            .scratch_high_water_bytes,
        predicted.scratch_high_water_bytes,
        "{field}/{}: the hand-written EstimateParams disagree with the \
         profile-driven estimate, so the shape being priced is not the shape \
         being proved",
        shape.label
    );
    assert_eq!(
        peaks.shipped_high_water(),
        predicted.scratch_high_water_bytes,
        "{field}/{}: the peak decomposition no longer reproduces \
         estimate_from_params",
        shape.label
    );

    let mut measured_runs = Vec::with_capacity(RUNS_PER_FIELD);
    let mut elapsed = Duration::ZERO;
    let mut proof_bytes = 0usize;
    for _ in 0..RUNS_PER_FIELD {
        let run_dir = tempfile::tempdir().unwrap();
        let (peak, proof, run_elapsed) =
            polled_scratch_peak(run_dir.path(), || prove(run_dir.path()));
        measured_runs.push(peak);
        elapsed += run_elapsed;
        proof_bytes = proof.len();
    }

    Reading {
        field,
        shape,
        predicted,
        peaks,
        measured_runs,
        elapsed: elapsed / RUNS_PER_FIELD as u32,
        proof_bytes,
    }
}

fn print_reading(reading: &Reading) {
    let predicted = reading.predicted.scratch_high_water_bytes;
    let measured = reading.measured();
    let shape = reading.shape;
    eprintln!("--- {} / {} ---", shape.label, reading.field);
    eprintln!(
        "  shape                         rows=2^{} width={} quotient_chunks={}",
        shape.rows.trailing_zeros(),
        shape.width,
        shape.quotient_chunks
    );
    eprintln!("  proof bytes                   {}", reading.proof_bytes);
    eprintln!(
        "  mean wall clock               {:?}   (BabyBear runs hc-simd's SCALAR path)",
        reading.elapsed
    );
    eprintln!("  PREDICTED scratch_high_water  {predicted}");
    eprintln!(
        "  MEASURED  scratch_high_water  {measured}   runs={:?} spread={:.2}%",
        reading.measured_runs,
        reading.sampling_spread_percent()
    );
    eprintln!(
        "  predicted / measured          {:.4}   ({:+.2}%)",
        reading.ratio(),
        (reading.ratio() - 1.0) * 100.0
    );
    eprintln!(
        "  binding model term            {}",
        reading.peaks.binding_term()
    );
    eprintln!("    fri_peak                    {}", reading.peaks.fri);
    eprintln!(
        "    trace_transform_peak        {}",
        reading.peaks.trace_transform
    );
    eprintln!(
        "    quotient_transform_peak     {}",
        reading.peaks.quotient_transform
    );
    eprintln!(
        "    proof_checkpoint_peak       {}",
        reading.peaks.proof_checkpoint
    );
    eprintln!(
        "  `24 * field_bytes` counterfactual: quotient_transform_peak={} high_water={} \
         ratio={:.4} discriminating={}",
        reading.peaks.quotient_transform_under_24_field_bytes,
        reading.peaks.high_water_under_24_field_bytes(),
        reading.counterfactual_ratio(),
        reading.peaks.discriminates()
    );
    eprintln!("  MODELLED ONLY (no runtime counterpart exists to compare against):");
    eprintln!(
        "    total_read_bytes            {}",
        reading.predicted.total_read_bytes
    );
    eprintln!(
        "    total_write_bytes           {}",
        reading.predicted.total_write_bytes
    );
    eprintln!(
        "    peak_resident_bytes         {}   NOT MEASURABLE on this platform",
        reading.predicted.peak_resident_bytes
    );
}

/// The model is a preflight gate: `ResourcePolicyV1::preflight` refuses a job
/// whose `scratch_high_water_bytes` exceeds the configured ceiling. An estimate
/// BELOW the measured high-water would therefore admit a job that does not fit.
/// Only that direction is asserted — the polled sampler is a lower bound, so an
/// estimate above it may be genuinely conservative or may merely reflect a
/// missed sample.
fn assert_not_optimistic(reading: &Reading) {
    assert!(
        reading.measured() > 0,
        "{}/{}: the sampler observed no scratch at all",
        reading.shape.label,
        reading.field
    );
    assert!(
        reading.predicted.scratch_high_water_bytes >= reading.measured(),
        "{}/{}: the cost model predicts {} but the pipeline actually accounted \
         for {} — the model UNDER-predicts, so preflight can admit a job that \
         does not fit",
        reading.shape.label,
        reading.field,
        reading.predicted.scratch_high_water_bytes,
        reading.measured()
    );
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Exhaustively sweep the shipped model to find every shape where a
/// `scratch_high_water_bytes` measurement could tell the `12 * ext_field_bytes`
/// reading of the disputed term apart from the `24 * field_bytes` reading.
///
/// This is pure arithmetic on the cost model — no proving — so it can cover the
/// whole provable range rather than a sampled corner of it. Its result bounds
/// what any measurement in this file is entitled to conclude.
#[test]
fn disputed_quotient_term_is_observable_only_in_a_narrow_band() {
    let dir = tempfile::tempdir().unwrap();
    let sweep_policy = policy(dir.path());
    let sweep = |field_bytes: u64| {
        let mut bands: Vec<(u64, u32, Vec<u64>)> = Vec::new();
        // The largest fraction by which the disputed term moves
        // `scratch_high_water_bytes` anywhere in the grid.
        let mut worst_impact_percent = 0.0f64;
        let mut worst_shape = (0u64, 0u32, 0u64);
        for quotient_chunks in [1u64, 2, 4, 8] {
            for log_rows in [10u32, 12, 14, 16, 20, 24] {
                let mut widths = Vec::new();
                // `tinyzkp_contracts::MAX_TRACE_WIDTH` is 256.
                for width in 1u64..=256 {
                    let params = EstimateParams {
                        workload_id: "sweep".to_string(),
                        rows: 1u64 << log_rows,
                        width,
                        quotient_chunks,
                        public_values: 3,
                        has_next_row_columns: true,
                        field_bytes,
                        ext_field_bytes: 16,
                        digest_bytes: 32,
                    };
                    let peaks = peaks_with_metadata(&params, 0);
                    if !peaks.discriminates() {
                        continue;
                    }
                    widths.push(width);
                    let shipped = peaks.shipped_high_water() as f64;
                    let alternative = peaks.high_water_under_24_field_bytes() as f64;
                    let impact = (shipped - alternative) / shipped * 100.0;
                    if impact > worst_impact_percent {
                        worst_impact_percent = impact;
                        worst_shape = (quotient_chunks, log_rows, width);
                    }
                }
                if !widths.is_empty() {
                    bands.push((quotient_chunks, log_rows, widths));
                }
            }
        }
        (bands, worst_impact_percent, worst_shape)
    };

    let (goldilocks, goldilocks_impact, _) = sweep(8);
    assert!(
        goldilocks.is_empty() && goldilocks_impact == 0.0,
        "Goldilocks cannot discriminate the two readings by construction \
         (24 * 8 == 12 * 16 == 192), yet the sweep found {goldilocks:?}"
    );

    let (babybear, babybear_impact, worst_shape) = sweep(4);
    eprintln!("babybear discriminating band (quotient_chunks, log2 rows, widths):");
    for (quotient_chunks, log_rows, widths) in &babybear {
        eprintln!("  chunks={quotient_chunks} rows=2^{log_rows} widths={widths:?}");
    }
    eprintln!(
        "  largest effect of the disputed term on any BabyBear \
         scratch_high_water_bytes in the grid: {babybear_impact:.2}% \
         (chunks={} rows=2^{} width={})",
        worst_shape.0, worst_shape.1, worst_shape.2
    );
    assert!(
        !babybear.is_empty(),
        "no BabyBear shape distinguishes the readings, so the disputed term is \
         unobservable in scratch_high_water_bytes and this file's measurement \
         cannot bear on it at all"
    );
    assert!(
        babybear.iter().all(|(quotient_chunks, _, widths)| {
            *quotient_chunks == 2 && widths.iter().all(|width| (24..=26).contains(width))
        }),
        "the discriminating band moved: {babybear:?}. \
         SQUARING_CHAIN_SHAPE was chosen to sit inside chunks=2, width 24..=26 \
         and must be re-derived before its measurement means anything."
    );
    assert!(
        peaks(
            &params_for(SQUARING_CHAIN_SHAPE, "squaring_chain_calibration", 4),
            &sweep_policy
        )
        .discriminates(),
        "SQUARING_CHAIN_SHAPE is no longer inside the discriminating band"
    );
    assert!(
        !peaks(&params_for(FIBONACCI_SHAPE, "fibonacci", 4), &sweep_policy).discriminates(),
        "FIBONACCI_SHAPE is now discriminating, which contradicts the sweep"
    );
}

/// The calibrated shape: Fibonacci, the only workload this crate implements at
/// every profile, proved for real at both fields.
#[test]
fn scratch_high_water_tracks_the_cost_model_at_goldilocks_and_babybear() {
    let workload = FibonacciWorkload {
        initial_a: 0,
        initial_b: 1,
        logical_rows: FIBONACCI_SHAPE.rows,
    };
    let goldilocks = reading(
        "goldilocks",
        FIBONACCI_SHAPE,
        8,
        "fibonacci",
        |estimate_policy| {
            estimate_resource_bounded_workload_with_profile::<
                GOLDILOCKS_PW,
                GOLDILOCKS_DE,
                GoldilocksProfile,
                _,
            >(&workload, estimate_policy)
            .unwrap()
        },
        |root| {
            prove_resource_bounded_with_profile::<GOLDILOCKS_PW, GOLDILOCKS_DE, GoldilocksProfile, _>(
                &workload,
                &policy(root),
            )
            .unwrap()
        },
    );
    let babybear = reading(
        "babybear",
        FIBONACCI_SHAPE,
        4,
        "fibonacci",
        |estimate_policy| {
            estimate_resource_bounded_workload_with_profile::<
                BABYBEAR_PW,
                BABYBEAR_DE,
                BabyBearProfile,
                _,
            >(&workload, estimate_policy)
            .unwrap()
        },
        |root| {
            prove_resource_bounded_with_profile::<BABYBEAR_PW, BABYBEAR_DE, BabyBearProfile, _>(
                &workload,
                &policy(root),
            )
            .unwrap()
        },
    );

    eprintln!();
    eprintln!("=== scratch high-water: pipeline accounting vs analytic cost model ===");
    print_reading(&goldilocks);
    print_reading(&babybear);
    eprintln!("=====================================================================");
    eprintln!();

    assert_not_optimistic(&goldilocks);
    assert_not_optimistic(&babybear);
}

/// The discriminating shape. Ignored by default: it proves a 25-column trace at
/// 2^14 rows twice per field, which is minutes in a debug build.
///
/// ```text
/// cargo test --release -p hc-plonky3 --lib \
///     quotient_transform_peak_measured_inside_the_discriminating_band -- \
///     --ignored --nocapture
/// ```
#[test]
#[ignore = "wide-trace calibration: minutes in debug, run explicitly in --release"]
fn quotient_transform_peak_measured_inside_the_discriminating_band() {
    let workload = SquaringChainWorkload {
        logical_rows: SQUARING_CHAIN_SHAPE.rows,
        columns: SQUARING_CHAIN_SHAPE.width as usize,
    };
    let goldilocks = reading(
        "goldilocks",
        SQUARING_CHAIN_SHAPE,
        8,
        "squaring_chain_calibration",
        |estimate_policy| {
            estimate_resource_bounded_workload_with_profile::<
                GOLDILOCKS_PW,
                GOLDILOCKS_DE,
                GoldilocksProfile,
                _,
            >(&workload, estimate_policy)
            .unwrap()
        },
        |root| {
            prove_resource_bounded_with_profile::<GOLDILOCKS_PW, GOLDILOCKS_DE, GoldilocksProfile, _>(
                &workload,
                &policy(root),
            )
            .unwrap()
        },
    );
    let babybear = reading(
        "babybear",
        SQUARING_CHAIN_SHAPE,
        4,
        "squaring_chain_calibration",
        |estimate_policy| {
            estimate_resource_bounded_workload_with_profile::<
                BABYBEAR_PW,
                BABYBEAR_DE,
                BabyBearProfile,
                _,
            >(&workload, estimate_policy)
            .unwrap()
        },
        |root| {
            prove_resource_bounded_with_profile::<BABYBEAR_PW, BABYBEAR_DE, BabyBearProfile, _>(
                &workload,
                &policy(root),
            )
            .unwrap()
        },
    );

    eprintln!();
    eprintln!("=== discriminating band: 12*ext_field_bytes vs 24*field_bytes ===");
    print_reading(&goldilocks);
    print_reading(&babybear);
    eprintln!(
        "  BabyBear verdict input: measured={} shipped={} counterfactual={}",
        babybear.measured(),
        babybear.predicted.scratch_high_water_bytes,
        babybear.peaks.high_water_under_24_field_bytes()
    );
    eprintln!("=================================================================");
    eprintln!();

    // The shape was selected precisely so this holds; if it stops holding the
    // measurement below is meaningless and must not be reported as a verdict.
    assert!(
        babybear.peaks.discriminates(),
        "the BabyBear reading is not inside the discriminating band"
    );
    assert!(
        !goldilocks.peaks.discriminates(),
        "Goldilocks cannot discriminate the two readings by construction"
    );
    assert_not_optimistic(&goldilocks);
    assert_not_optimistic(&babybear);
}

/// The wide fixture must actually have the shape it is priced at, or the
/// measurement above prices one configuration and proves another. Cheap enough
/// to run by default even though the measurement itself is `#[ignore]`d.
#[test]
fn squaring_chain_fixture_has_the_shape_it_is_priced_at() {
    let workload = SquaringChainWorkload {
        logical_rows: 1 << 10,
        columns: SQUARING_CHAIN_SHAPE.width as usize,
    };
    let air = ResourceBoundedWorkload::<BABYBEAR_PW, BABYBEAR_DE, BabyBearProfile>::air(&workload);
    assert_eq!(
        BaseAir::<<BabyBearProfile as DurableFieldProfile<BABYBEAR_PW, BABYBEAR_DE>>::Val>::width(
            &air
        ),
        SQUARING_CHAIN_SHAPE.width as usize
    );

    // `quotient_chunks` is derived by Plonky3 from the symbolic constraint
    // degree, not declared. Two chunks is what puts this shape in the band, so
    // pin it here rather than trusting the AIR's `max_constraint_degree` hint.
    let dir = tempfile::tempdir().unwrap();
    let estimate_policy = policy(dir.path());
    let priced = estimate_from_params(
        &EstimateParams {
            rows: 1 << 10,
            ..params_for(SQUARING_CHAIN_SHAPE, "squaring_chain_calibration", 4)
        },
        &estimate_policy,
    )
    .unwrap();
    let actual = estimate_resource_bounded_workload_with_profile::<
        BABYBEAR_PW,
        BABYBEAR_DE,
        BabyBearProfile,
        _,
    >(&workload, &estimate_policy)
    .unwrap();
    assert_eq!(
        priced.scratch_high_water_bytes, actual.scratch_high_water_bytes,
        "SQUARING_CHAIN_SHAPE's declared quotient_chunks/public_values do not \
         match what Plonky3 derives from the AIR"
    );
}

/// A short BabyBear proof of the wide fixture must actually verify, so the
/// measurement is of a real proof and not of a pipeline running on garbage.
#[test]
fn squaring_chain_proves_and_verifies_at_babybear() {
    let dir = tempfile::tempdir().unwrap();
    let workload = SquaringChainWorkload {
        logical_rows: 1 << 6,
        columns: SQUARING_CHAIN_SHAPE.width as usize,
    };
    let proof =
        prove_resource_bounded_with_profile::<BABYBEAR_PW, BABYBEAR_DE, BabyBearProfile, _>(
            &workload,
            &policy(dir.path()),
        )
        .unwrap();
    crate::bounded_prover::verify_resource_bounded_proof_with_profile::<
        BABYBEAR_PW,
        BABYBEAR_DE,
        BabyBearProfile,
        _,
    >(&workload, &proof)
    .expect("the stock Plonky3 verifier must accept the wide BabyBear proof");
}
