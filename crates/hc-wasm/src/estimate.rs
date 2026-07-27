//! The shared cost-model core: "declared config in, priced estimate out."
//!
//! This is the ONLY place this mapping is implemented. `hc-cli`'s
//! `estimate_config::run()` and this crate's `estimate_json` WASM export
//! both call [`estimate_request`] directly — neither recomputes any part of
//! it. Phase 1a's `conventional` estimate was 7.8x wrong purely because one
//! concept (the cost of a declared config) was computed two different ways
//! in two places; this module exists so that mistake cannot recur.
//!
//! It lives in `hc-wasm`, not `hc-cli` or `hc-plonky3`, because of a three-way
//! constraint: it must see `tinyzkp_contracts::EstimateRequestV1` (so
//! `hc-wasm` gained a `tinyzkp-contracts` path dependency) and
//! `hc_plonky3::estimate_params` (already present), while never pulling
//! `hc-cli`'s `clap`/`anyhow`/`tempfile` into a `wasm32` build. `hc-wasm` is
//! the only crate satisfying all three at once.

use hc_plonky3::estimate_params::{
    estimate_conventional_from_params, estimate_from_params, field_widths, CheckpointPolicy,
    EstimateParams, ResourceEstimate, ResourceMode, ResourcePolicyV1,
};
use hc_plonky3::BoundedProverError;
use tinyzkp_contracts::{
    EstimateRequestV1, EstimateResponseV1, ReasonCodeV1, ResourceEstimateV1, ResourceEstimatesV1,
    MIN_RAM_BUDGET_BYTES,
};

/// Upper bound on `logical_rows` this estimator will price, deliberately far
/// above `tinyzkp_contracts::MAX_ROWS` (2^24 — the *provable* range enforced
/// by `EstimateRequestV1::blocking_reasons()`). This is a distinct, wider
/// ceiling: estimation is meant to price configs TinyZKP cannot prove, so it
/// must not reuse the provable-range limit. It exists purely to keep every
/// product term this module and `estimate_params.rs` compute — rows times
/// width times a byte width, rows times FRI blowup times a byte width, and
/// so on — within `u64` headroom so `saturating_*` never needs to clamp.
/// Rows beyond this are refused outright with `UnsupportedProfile` rather
/// than priced and silently saturated: a refusal is honest, a saturated
/// number that looks precise is not. `2^32` rows at the widest plausible
/// trace width and blowup still leaves many bits of `u64` headroom before
/// any single product term could reach `u64::MAX`.
const MAX_ESTIMATE_ROWS: u64 = 1 << 32;

/// Upper bound on `trace_width` this estimator will price, deliberately far
/// above `tinyzkp_contracts::MAX_TRACE_WIDTH` (256 — the provable range).
/// Same overflow-headroom rationale as `MAX_ESTIMATE_ROWS`.
const MAX_ESTIMATE_TRACE_WIDTH: u32 = 65536;

/// Everything a caller needs to build a structured error response for a
/// failed [`estimate_request`] call.
///
/// `hc-wasm` cannot depend on `hc-cli` (that dependency direction is
/// forbidden — `hc-wasm`'s `wasm32` build must never see `hc-cli`'s
/// `clap`/`anyhow`/`tempfile`), so this cannot reuse `hc-cli`'s
/// `ProtocolFailure` type directly. It carries exactly the one thing both
/// callers need: the `ReasonCodeV1`. `estimate_json` (below) turns it into
/// the standard JSON error envelope; `hc-cli`'s `estimate_config::run`
/// turns it into its own `ProtocolFailure` with an identical code, so the
/// two callers still report identical reasons for identical failures.
#[derive(Clone, Copy, Debug)]
pub struct EstimateFailure(ReasonCodeV1);

impl EstimateFailure {
    pub fn new(code: ReasonCodeV1) -> Self {
        Self(code)
    }

    pub fn reason_code(self) -> ReasonCodeV1 {
        self.0
    }
}

/// Cost a declared configuration. Never proves, never reads a witness, and
/// never rejects a config merely because TinyZKP cannot prove it — with one
/// exception: `logical_rows`/`trace_width` far outside anything this
/// estimator was built to price are refused (`UnsupportedProfile`) rather
/// than priced, because pricing them would risk a silently wrong number
/// (see `MAX_ESTIMATE_ROWS`/`MAX_ESTIMATE_TRACE_WIDTH`).
///
/// Errors map onto the same `ReasonCodeV1` vocabulary every other command
/// uses. `estimate_from_params`'s only documented failure mode,
/// `BoundedProverError::UnsupportedProfile` (rows that are zero or not a
/// power of two), maps to `ReasonCodeV1::UnsupportedProfile` for the same
/// reason: an ordinary, if malformed, input must not present as an internal
/// fault. Every other `BoundedProverError` variant maps to `InternalError`,
/// which is reserved for genuine internal faults.
///
/// This is the function both the CLI (`hc-cli`'s `estimate_config::run`)
/// and the hosted API (`estimate_json`, below) call, so its signature is
/// load-bearing: a request in, a fully-formed response (or an
/// `EstimateFailure` naming exactly which reason code applies) out. It never
/// panics and never performs I/O, so it is safe to call from a `wasm32`
/// target with no filesystem or stdio.
pub fn estimate_request(request: EstimateRequestV1) -> Result<EstimateResponseV1, EstimateFailure> {
    if request.logical_rows > MAX_ESTIMATE_ROWS || request.trace_width > MAX_ESTIMATE_TRACE_WIDTH {
        return Err(EstimateFailure::new(ReasonCodeV1::UnsupportedProfile));
    }

    let (field_bytes, ext_field_bytes) = field_widths(&request.field, request.extension_degree)
        .ok_or_else(|| EstimateFailure::new(ReasonCodeV1::UnsupportedProfile))?;

    let params = EstimateParams {
        workload_id: request.digest(),
        rows: request.logical_rows,
        width: u64::from(request.trace_width),
        quotient_chunks: request.quotient_chunks(),
        public_values: u64::from(request.public_values),
        has_next_row_columns: request.has_next_row_columns,
        field_bytes,
        ext_field_bytes,
        digest_bytes: 32,
    };

    // A caller-declared RAM budget below the floor `ResourcePolicyV1` itself
    // requires (`MIN_RAM_BUDGET_BYTES`, 16 MiB) must not hard-fail the whole
    // estimate: `request.blocking_reasons()` below already reports
    // `RamBudgetInsufficient` for exactly this case, carrying the declared
    // (sub-floor) budget as `limit_bytes` and the floor as `required_bytes`.
    // Substituting the floor as the bounded ceiling here lets that reason
    // communicate the gap without this function refusing to estimate.
    let bounded_ceiling = request.ram_budget_bytes.max(MIN_RAM_BUDGET_BYTES);
    let bounded_policy = ResourcePolicyV1 {
        max_resident_bytes: bounded_ceiling,
        ..policy_defaults()
    };
    let bounded = estimate_from_params(&params, &bounded_policy).map_err(map_estimate_error)?;

    // The conventional model is the naive, fully-in-memory Plonky3 pipeline
    // (see `estimate_conventional_from_params`), not the bounded/streaming
    // model run with an unbounded ceiling: those are different shapes, and
    // conflating them previously made `estimates.conventional` byte-identical
    // to `estimates.bounded`'s streaming scratch/read/write figures, which a
    // real in-memory prover does not have.
    let conventional = estimate_conventional_from_params(&params);

    let blocking_reasons = request.blocking_reasons();
    Ok(EstimateResponseV1 {
        schema_version: 1,
        request_digest: request.digest(),
        provable_today: blocking_reasons.is_empty(),
        blocking_reasons,
        estimates: ResourceEstimatesV1 {
            bounded: to_contract(bounded),
            conventional: to_contract(conventional),
        },
    })
}

/// `BoundedProverError::UnsupportedProfile` is `estimate_from_params`'s
/// documented response to an ordinary, if malformed, input (rows that are
/// zero or not a power of two) — it must reach the caller as
/// `ReasonCodeV1::UnsupportedProfile`, not `InternalError`. Every other
/// variant (DFT/stream/checkpoint faults, etc.) is a genuine internal fault
/// and keeps mapping to `InternalError`.
fn map_estimate_error(error: BoundedProverError) -> EstimateFailure {
    match error {
        BoundedProverError::UnsupportedProfile => {
            EstimateFailure::new(ReasonCodeV1::UnsupportedProfile)
        }
        _ => EstimateFailure::new(ReasonCodeV1::InternalError),
    }
}

/// Mirrors `examples/plonky3/fibonacci-1m.json`'s `resource_policy`, apart
/// from `max_resident_bytes`, which each call site overrides. `scratch_dir`
/// is never touched on disk here (and could not be, from a `wasm32`
/// target): `estimate_from_params` only costs a hypothetical run, it never
/// executes one.
fn policy_defaults() -> ResourcePolicyV1 {
    ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 0,
        max_scratch_bytes: 1_000_000_000,
        scratch_dir: std::path::PathBuf::from("/var/lib/tinyzkp-bench/scratch/fibonacci-1m"),
        max_threads: 4,
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    }
}

fn to_contract(e: ResourceEstimate) -> ResourceEstimateV1 {
    ResourceEstimateV1 {
        peak_resident_bytes: e.peak_resident_bytes,
        scratch_high_water_bytes: e.scratch_high_water_bytes,
        total_read_bytes: e.total_read_bytes,
        total_write_bytes: e.total_write_bytes,
    }
}
