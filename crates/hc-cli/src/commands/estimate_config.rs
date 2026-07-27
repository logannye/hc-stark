use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context, Result};
use hc_plonky3::estimate_params::{estimate_from_params, field_widths, EstimateParams};
use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
use tinyzkp_contracts::{
    EstimateRequestV1, EstimateResponseV1, ResourceEstimateV1, ResourceEstimatesV1,
};

/// Cost a declared configuration. Never proves, never reads a witness, and
/// never rejects a config merely because TinyZKP cannot prove it.
///
/// This is the function a future hosted estimator API calls directly, so its
/// signature is load-bearing: a config path in, a fully-formed response (or
/// an error naming exactly what was wrong) out.
pub fn run(config_path: &Path) -> Result<EstimateResponseV1> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let request: EstimateRequestV1 =
        serde_json::from_str(&raw).context("parsing estimate request")?;

    let (field_bytes, ext_field_bytes) = field_widths(&request.field, request.extension_degree)
        .ok_or_else(|| {
            anyhow!(
                "unsupported field '{}' with extension degree {}: \
                 element width is unknown, so no honest estimate is possible",
                request.field,
                request.extension_degree
            )
        })?;

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

    let bounded_policy = ResourcePolicyV1 {
        max_resident_bytes: request.ram_budget_bytes,
        ..policy_defaults()
    };
    let bounded = estimate_from_params(&params, &bounded_policy)
        .map_err(|e| anyhow!("bounded estimate failed: {e:?}"))?;

    // Conventional holds every vector resident, so it is the same shape with
    // an effectively unbounded ceiling.
    let conventional_policy = ResourcePolicyV1 {
        max_resident_bytes: u64::MAX,
        ..policy_defaults()
    };
    let conventional = estimate_from_params(&params, &conventional_policy)
        .map_err(|e| anyhow!("conventional estimate failed: {e:?}"))?;

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

/// Mirrors `examples/plonky3/fibonacci-1m.json`'s `resource_policy`, apart
/// from `max_resident_bytes`, which each call site overrides. `scratch_dir`
/// is never touched on disk here: `estimate_from_params` only costs a
/// hypothetical run, it never executes one.
fn policy_defaults() -> ResourcePolicyV1 {
    ResourcePolicyV1 {
        mode: ResourceMode::Scratch,
        max_resident_bytes: 0,
        max_scratch_bytes: 1_000_000_000,
        scratch_dir: PathBuf::from("/var/lib/tinyzkp-bench/scratch/fibonacci-1m"),
        max_threads: 4,
        checkpoint_policy: CheckpointPolicy::RetainOnFailure,
    }
}

fn to_contract(e: hc_stream::ResourceEstimate) -> ResourceEstimateV1 {
    ResourceEstimateV1 {
        peak_resident_bytes: e.peak_resident_bytes,
        scratch_high_water_bytes: e.scratch_high_water_bytes,
        total_read_bytes: e.total_read_bytes,
        total_write_bytes: e.total_write_bytes,
    }
}
