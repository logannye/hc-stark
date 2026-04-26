//! `hash_preimage` — prove knowledge of a preimage whose iterative hash equals `digest`.

use super::*;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let digest = require_u64(params, "digest")?;
    let preimage_steps = require_u64_array(params, "preimage_steps")?;

    if preimage_steps.is_empty() {
        anyhow::bail!("'preimage_steps' must contain at least one element");
    }

    let computed: u64 = preimage_steps
        .iter()
        .fold(0u64, |acc, &s| acc.wrapping_add(s));
    if computed != digest {
        anyhow::bail!(
            "hash preimage mismatch: accumulated value = {computed}, \
             but digest = {digest}"
        );
    }

    let instructions = add_immediate_chain(&preimage_steps);
    Ok(TemplateBuildResult {
        program: Program::new(instructions),
        initial_acc: 0,
        final_acc: digest,
        recommended_zk: true,
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "digest",
        description: "The public hash digest to match",
        param_type: "integer",
        required: true,
    },
    StaticParam {
        name: "preimage_steps",
        description: "Secret preimage as additive components (hashed iteratively)",
        param_type: "array",
        required: true,
    },
];

static TAGS: &[&str] = &["hash", "preimage", "zero-knowledge", "commitment"];

inventory::submit!(ProofTemplate {
    id: "hash_preimage",
    summary: "Prove knowledge of a hash preimage",
    description: "Proves that the prover knows a secret preimage whose iterative \
                  arithmetic hash equals a publicly known digest. The preimage \
                  remains hidden (when ZK is enabled). Use this for password \
                  verification, commitment opening, or any scenario where an \
                  agent must prove it knows a secret without revealing it.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    example_json: r#"{"digest":100,"preimage_steps":[25,25,25,25]}"#,
    build_program: build,
});
