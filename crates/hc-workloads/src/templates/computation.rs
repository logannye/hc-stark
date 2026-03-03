//! `computation_attestation` — prove that f(secret_steps) = expected_output.

use super::*;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let steps = require_u64_array(params, "steps")?;
    let expected_output = require_u64(params, "expected_output")?;

    if steps.is_empty() {
        anyhow::bail!("'steps' must contain at least one element");
    }

    let computed: u64 = steps.iter().fold(0u64, |acc, &s| acc.wrapping_add(s));
    if computed != expected_output {
        anyhow::bail!(
            "computation mismatch: sum(steps) = {computed}, \
             but expected_output = {expected_output}"
        );
    }

    let instructions = add_immediate_chain(&steps);
    Ok(TemplateBuildResult {
        program: Program::new(instructions),
        initial_acc: 0,
        final_acc: expected_output,
        recommended_zk: true,
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "steps",
        description: "Secret computation steps (additive values applied sequentially)",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "expected_output",
        description: "The public output that the computation must produce",
        param_type: "integer",
        required: true,
    },
];

static TAGS: &[&str] = &["attestation", "computation", "zero-knowledge"];

inventory::submit!(ProofTemplate {
    id: "computation_attestation",
    summary: "Prove f(secret) = public_output",
    description: "Proves that applying a secret sequence of computation steps \
                  produces a known public output. The steps are hidden from \
                  the verifier (when ZK is enabled), but the output is public. \
                  Use this when an agent needs to attest that it computed \
                  a result correctly without revealing the inputs.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    example_json: r#"{"steps":[10,20,12],"expected_output":42}"#,
    build_program: build,
});
