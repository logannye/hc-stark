//! `range_proof` — prove that a secret value lies within [min, max].

use super::*;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let min = require_u64(params, "min")?;
    let max = require_u64(params, "max")?;
    let witness_steps = require_u64_array(params, "witness_steps")?;

    if min > max {
        anyhow::bail!("'min' ({min}) must be <= 'max' ({max})");
    }
    if witness_steps.is_empty() {
        anyhow::bail!("'witness_steps' must contain at least one element");
    }

    let value: u64 = witness_steps.iter().fold(min, |acc, &s| acc.wrapping_add(s));
    if value > max {
        anyhow::bail!(
            "range violation: min ({min}) + sum(witness_steps) = {value}, \
             which exceeds max ({max})"
        );
    }

    let instructions = add_immediate_chain(&witness_steps);
    Ok(TemplateBuildResult {
        program: Program::new(instructions),
        initial_acc: min,
        final_acc: value,
        recommended_zk: true,
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
        name: "witness_steps",
        description: "Additive steps from min that sum to (value - min)",
        param_type: "array",
        required: true,
    },
];

static TAGS: &[&str] = &["range", "privacy", "zero-knowledge", "verification"];

inventory::submit!(ProofTemplate {
    id: "range_proof",
    summary: "Prove a secret value lies within a range",
    description: "Proves that a secret value V satisfies min <= V <= max without \
                  revealing V. The witness_steps encode the difference (V - min) \
                  as additive components. Use this for age verification, credit \
                  score ranges, or any threshold check where the exact value \
                  should remain private.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    example_json: r#"{"min":18,"max":120,"witness_steps":[7]}"#,
    build_program: build,
});
