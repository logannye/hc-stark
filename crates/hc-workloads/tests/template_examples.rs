//! Integration test: every template documented at https://tinyzkp.com/docs#template-examples
//! must build cleanly with the exact params shown there.
//!
//! If you change a doc example, change the matching case here too. If a template's
//! parameter schema changes incompatibly, this test fails and the docs need to be
//! updated before the change ships.

use hc_workloads::templates::build_from_template;
use serde_json::json;

fn params(value: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
    value.as_object().expect("params must be an object").clone()
}

#[test]
fn range_proof_doc_example_builds() {
    let p = params(json!({"min": 0, "max": 10000, "witness_steps": [2000, 2237]}));
    build_from_template("range_proof", &p).expect("range_proof builds");
}

#[test]
fn hash_preimage_doc_example_builds() {
    let p = params(json!({"digest": 12, "preimage_steps": [7, 3, 2]}));
    build_from_template("hash_preimage", &p).expect("hash_preimage builds");
}

#[test]
fn computation_attestation_doc_example_builds() {
    let p = params(json!({"steps": [3, 5, 7, 11], "expected_output": 26}));
    build_from_template("computation_attestation", &p).expect("computation_attestation builds");
}

#[test]
fn accumulator_step_doc_example_builds() {
    let p = params(json!({"initial": 1000, "final": 1450, "deltas": [100, 200, 150]}));
    build_from_template("accumulator_step", &p).expect("accumulator_step builds");
}

#[test]
fn policy_compliance_doc_example_builds() {
    let p = params(json!({"actions": [150, 200, 75, 300, 180], "threshold": 1000}));
    build_from_template("policy_compliance", &p).expect("policy_compliance builds");
}

#[test]
fn data_integrity_doc_example_builds() {
    let p = params(json!({"elements": [100, 250, 75, 500, 125], "checksum": 1050}));
    build_from_template("data_integrity", &p).expect("data_integrity builds");
}

#[test]
fn all_six_documented_templates_are_registered() {
    let want = [
        "range_proof",
        "hash_preimage",
        "computation_attestation",
        "accumulator_step",
        "policy_compliance",
        "data_integrity",
    ];
    let have: std::collections::HashSet<&str> = hc_workloads::templates::list_templates()
        .iter()
        .map(|t| t.id)
        .collect();
    for id in want {
        assert!(have.contains(id), "missing template: {id}");
    }
}
