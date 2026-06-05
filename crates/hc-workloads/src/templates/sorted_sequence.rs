//! `sorted_sequence` — prove a list of integers is non-decreasing (sorted).
//!
//! Builds a real `hc_air::SortedAir` (the v7 sound core): each step
//! `v_{i+1} - v_i` is range-checked into `[0, 2^16)`, so the proof cryptographically
//! binds "the sequence is sorted ascending" — verifiable in milliseconds without
//! re-scanning the list. `Enforced` but gated (`audited = false`) until the
//! Phase-4 external audit. Sound, not zero-knowledge (the values appear in the
//! opened trace, like `range_proof`).

use super::*;
use hc_air::air_general::F;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let values = require_u64_array(params, "values")?;

    // `build_sorted_trace` enforces: ≥ 2 values, non-decreasing, each step
    // < 2^16, each value < 2^48. Surface its error as a build failure.
    let trace = hc_air::build_sorted_trace(&values)
        .map_err(|e| anyhow::anyhow!("sorted trace construction failed: {e}"))?;

    // Safe: build_sorted_trace already rejected len < 2.
    let first = values[0];
    let last = values[values.len() - 1];

    Ok(TemplateBuildResult::Air {
        air: Box::new(hc_air::SortedAir),
        trace,
        public_inputs: vec![F::new(first), F::new(last)],
        recommended_zk: false,
    })
}

static PARAMS: &[StaticParam] = &[StaticParam {
    name: "values",
    description: "The integer sequence to prove is non-decreasing (sorted ascending). \
                  At least 2 values; each step (vᵢ₊₁ - vᵢ) < 65536; each value < 2^48.",
    param_type: "array",
    required: true,
}];

static TAGS: &[&str] = &["sorted", "ordering", "sequence", "verification"];

inventory::submit!(ProofTemplate {
    id: "sorted_sequence",
    summary: "Prove a sequence of integers is non-decreasing (sorted)",
    description: "Proves a list of integers is sorted in non-decreasing order (each \
                  value >= the previous) without re-scanning it — verify a long \
                  ordered sequence in milliseconds from a tiny proof. Use for ordered \
                  logs, monotonic timestamps/counters, leaderboards, or sorted-set \
                  attestation. Steps must be < 65536 and values < 2^48. Enforced on \
                  the sound v7 STARK core but gated (audited = false) until the \
                  external audit; sound but not zero-knowledge (the values appear in \
                  the opened trace).",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    enforcement: Enforcement::Enforced,
    audited: false,
    example_json: r#"{"values":[3,5,5,9,40,41,1000]}"#,
    build_program: build,
});
