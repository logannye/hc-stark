//! `policy_compliance` — prove that accumulated actions stay within a threshold.

use super::*;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let actions = require_u64_array(params, "actions")?;
    let threshold = require_u64(params, "threshold")?;

    if actions.is_empty() {
        anyhow::bail!("'actions' must contain at least one element");
    }

    let total: u64 = actions.iter().fold(0u64, |acc, &a| acc.wrapping_add(a));
    if total > threshold {
        anyhow::bail!(
            "policy violation: sum(actions) = {total}, which exceeds threshold = {threshold}"
        );
    }

    let instructions = add_immediate_chain(&actions);
    Ok(TemplateBuildResult {
        program: Program::new(instructions),
        initial_acc: 0,
        final_acc: total,
        recommended_zk: false,
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "actions",
        description: "Array of action values (costs/amounts) applied sequentially",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "threshold",
        description: "Maximum allowed cumulative total",
        param_type: "integer",
        required: true,
    },
];

static TAGS: &[&str] = &["policy", "compliance", "threshold", "agent"];

inventory::submit!(ProofTemplate {
    id: "policy_compliance",
    summary: "Prove actions satisfy a policy constraint",
    description: "Proves that a series of actions (represented as additive values) \
                  accumulate to a total that does not exceed a given threshold. \
                  Use this when an agent needs to attest that its actions complied \
                  with spending limits, rate limits, resource quotas, or any \
                  cumulative policy constraint.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    example_json: r#"{"actions":[10,20,15],"threshold":50}"#,
    build_program: build,
});
