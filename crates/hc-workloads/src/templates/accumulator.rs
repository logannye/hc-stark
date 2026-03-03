//! `accumulator_step` — prove that a chain of deltas transitions from `initial` to `final`.

use super::*;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let initial = require_u64(params, "initial")?;
    let final_val = require_u64(params, "final")?;
    let deltas = require_u64_array(params, "deltas")?;

    if deltas.is_empty() {
        anyhow::bail!("'deltas' must contain at least one element");
    }

    let computed: u64 = deltas.iter().fold(initial, |acc, &d| acc.wrapping_add(d));
    if computed != final_val {
        anyhow::bail!(
            "accumulator mismatch: initial ({initial}) + sum(deltas) = {computed}, \
             but expected final = {final_val}"
        );
    }

    let instructions = add_immediate_chain(&deltas);
    Ok(TemplateBuildResult {
        program: Program::new(instructions),
        initial_acc: initial,
        final_acc: final_val,
        recommended_zk: false,
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "initial",
        description: "Starting accumulator value",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "final",
        description: "Expected accumulator value after all deltas",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "deltas",
        description: "Array of additive deltas to apply sequentially",
        param_type: "array",
        required: true,
    },
];

static TAGS: &[&str] = &["state-transition", "accumulator", "chain"];

inventory::submit!(ProofTemplate {
    id: "accumulator_step",
    summary: "Prove a valid state-transition chain",
    description: "Proves that applying a sequence of additive deltas to an initial \
                  accumulator value produces the claimed final value. Use this to \
                  attest that a series of state transitions is internally consistent.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    example_json: r#"{"initial":0,"final":15,"deltas":[5,3,7]}"#,
    build_program: build,
});
