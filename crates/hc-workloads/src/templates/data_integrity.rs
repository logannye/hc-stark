//! `data_integrity` — prove that elements sum to a committed checksum.

use super::*;

fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let elements = require_u64_array(params, "elements")?;
    let checksum = require_u64(params, "checksum")?;

    if elements.is_empty() {
        anyhow::bail!("'elements' must contain at least one element");
    }

    let computed: u64 = elements.iter().fold(0u64, |acc, &e| acc.wrapping_add(e));
    if computed != checksum {
        anyhow::bail!(
            "data integrity mismatch: sum(elements) = {computed}, \
             but checksum = {checksum}"
        );
    }

    let instructions = add_immediate_chain(&elements);
    Ok(TemplateBuildResult {
        program: Program::new(instructions),
        initial_acc: 0,
        final_acc: checksum,
        recommended_zk: false,
    })
}

static PARAMS: &[StaticParam] = &[
    StaticParam {
        name: "elements",
        description: "Array of data element values",
        param_type: "array",
        required: true,
    },
    StaticParam {
        name: "checksum",
        description: "Expected sum of all elements",
        param_type: "integer",
        required: true,
    },
];

static TAGS: &[&str] = &["data", "integrity", "checksum", "audit"];

inventory::submit!(ProofTemplate {
    id: "data_integrity",
    summary: "Prove data elements match a committed checksum",
    description: "Proves that a set of data elements sums to a previously committed \
                  checksum value. Use this when an agent needs to attest that a \
                  dataset has not been tampered with, that all items in a batch \
                  are accounted for, or that a ledger balances.",
    parameters: PARAMS,
    tags: TAGS,
    cost_category: "lightweight",
    example_json: r#"{"elements":[100,200,300],"checksum":600}"#,
    build_program: build,
});
