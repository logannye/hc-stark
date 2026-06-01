//! `range_proof` — prove that a secret value lies within [min, max].
//!
//! Phase 1B: this template now builds a REAL range AIR (`hc_air::RangeAir`)
//! that cryptographically binds `min ≤ V ≤ max` on the sound v7 STARK core.
//! `V` is the private witness — it is never a public input nor a committed
//! trace column (only `{min, max}` are public). The proof is `Enforced` but
//! gated (`audited = false`) until the Phase 4 external audit. See
//! `docs/security/zk_range.md` for the soundness / confidentiality analysis
//! (v7 is sound and hides `V` from the public interface, but is not yet
//! zero-knowledge of the openings — ZK is a deferred follow-up).

use super::*;
use hc_air::air_general::F;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let min = require_u64(params, "min")?;
    let max = require_u64(params, "max")?;
    let value = require_u64(params, "value")?;

    // `build_range_trace` enforces min ≤ max, min ≤ value ≤ max, and the
    // field-safety bound (max - min < 2^n). It returns a descriptive error
    // otherwise — surface it as a bad-request-style build failure.
    let trace = hc_air::build_range_trace(min, max, value)
        .map_err(|e| anyhow::anyhow!("range trace construction failed: {e}"))?;

    Ok(TemplateBuildResult::Air {
        air: Box::new(hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N)),
        trace,
        public_inputs: vec![F::new(min), F::new(max)],
        // v7 sound proving (NOT v8/ZK): the trace-additive mask is degree-
        // incompatible with the degree-2 booleanity constraints, so genuine ZK
        // is a deferred follow-up (see docs/security/zk_range.md). Range is
        // proved at v7 — sound, with V absent from the public interface.
        recommended_zk: false,
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "min",
        description: "Lower bound of the allowed range (inclusive)",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "max",
        description: "Upper bound of the allowed range (inclusive)",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "value",
        description: "The secret value V to prove lies in [min, max]. Private: \
                      never appears in the proof's public inputs or trace columns.",
        param_type: "integer",
        required: true,
    },
];

static TAGS: &[&str] = &["range", "privacy", "verification"];

inventory::submit!(ProofTemplate {
    id: "range_proof",
    summary: "Prove a secret value lies within a range",
    description: "Proves that a secret value V satisfies min <= V <= max without \
                  publishing V. V is the private witness; only {min, max} are \
                  public. Use this for age verification, credit score ranges, or \
                  any threshold check where the exact value should remain \
                  private. Enforced on the sound v7 STARK core but gated until \
                  the external audit (sound, and V-hiding at the public \
                  interface; full zero-knowledge of the openings is a deferred \
                  follow-up).",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    enforcement: Enforcement::Enforced,
    audited: false,
    example_json: r#"{"min":18,"max":120,"value":42}"#,
    build_program: build,
});
