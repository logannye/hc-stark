//! Proof template registry for AI agent consumption.
//!
//! Templates are parameterized proof patterns that carry rich metadata
//! (descriptions, parameter schemas, examples) designed for LLM tool discovery.
//! Each template knows how to build a [`Program`] from JSON parameters.

use anyhow::{anyhow, Result};
use hc_vm::{Instruction, Program};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Whether a template's AIR actually enforces its named predicate.
///
/// `Enforced` — the constraint system cryptographically binds the claim
/// (e.g. `accumulator_step`). `StructureOnly` — the template currently
/// only produces a structurally valid proof and does NOT cryptographically
/// constrain the named predicate; it must be hidden/refused in production
/// until a real AIR lands (see the Phase 1B roadmap).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Enforced,
    StructureOnly,
}

pub mod accumulator;
pub mod computation;
pub mod data_integrity;
pub mod hash_preimage;
pub mod policy;
pub mod range_proof;

// ── Static-friendly types (for inventory registration) ──────────────────────

/// Parameter definition using only static references (const-constructible).
#[derive(Clone, Copy, Debug)]
pub struct StaticParam {
    pub name: &'static str,
    pub description: &'static str,
    pub param_type: &'static str,
    pub required: bool,
}

/// A registered proof template (const-constructible for `inventory`).
#[derive(Clone, Copy)]
pub struct ProofTemplate {
    pub id: &'static str,
    pub summary: &'static str,
    pub description: &'static str,
    pub parameters: &'static [StaticParam],
    pub tags: &'static [&'static str],
    pub cost_category: &'static str,
    /// Whether this template's AIR enforces its named predicate.
    pub enforcement: Enforcement,
    /// JSON example as a string literal (parsed on demand).
    pub example_json: &'static str,
    pub build_program: fn(&serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult>,
}

inventory::collect!(ProofTemplate);

// ── Serializable types (for MCP/API responses) ──────────────────────────────

/// Parameter definition for a proof template (agent-readable, serializable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TemplateParam {
    pub name: String,
    pub description: String,
    pub param_type: String,
    pub required: bool,
}

/// Full template metadata exposed to agents via MCP tool discovery.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TemplateInfo {
    pub id: String,
    pub summary: String,
    pub description: String,
    pub parameters: Vec<TemplateParam>,
    pub example: JsonValue,
    pub tags: Vec<String>,
    pub cost_category: String,
    pub enforcement: Enforcement,
}

impl ProofTemplate {
    /// Convert the static template into a serializable `TemplateInfo`.
    pub fn to_info(&self) -> TemplateInfo {
        TemplateInfo {
            id: self.id.to_string(),
            summary: self.summary.to_string(),
            description: self.description.to_string(),
            parameters: self
                .parameters
                .iter()
                .map(|p| TemplateParam {
                    name: p.name.to_string(),
                    description: p.description.to_string(),
                    param_type: p.param_type.to_string(),
                    required: p.required,
                })
                .collect(),
            example: serde_json::from_str(self.example_json).unwrap_or(JsonValue::Null),
            tags: self.tags.iter().map(|t| t.to_string()).collect(),
            cost_category: self.cost_category.to_string(),
            enforcement: self.enforcement,
        }
    }
}

/// Result of building a program from template parameters.
pub struct TemplateBuildResult {
    pub program: Program,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub recommended_zk: bool,
}

/// List all registered templates.
pub fn list_templates() -> Vec<&'static ProofTemplate> {
    inventory::iter::<ProofTemplate>.into_iter().collect()
}

/// Look up a template by its ID.
pub fn template_by_id(id: &str) -> Option<&'static ProofTemplate> {
    inventory::iter::<ProofTemplate>
        .into_iter()
        .find(|t| t.id == id)
}

/// Build a program from a template ID and JSON parameters.
pub fn build_from_template(
    id: &str,
    params: &serde_json::Map<String, JsonValue>,
) -> Result<TemplateBuildResult> {
    let t = template_by_id(id).ok_or_else(|| anyhow!("unknown template: {id}"))?;
    (t.build_program)(params)
}

// ── Helpers for template builders ───────────────────────────────────────────

/// Extract a required u64 parameter.
pub(crate) fn require_u64(params: &serde_json::Map<String, JsonValue>, name: &str) -> Result<u64> {
    params
        .get(name)
        .and_then(|v| v.as_u64())
        .ok_or_else(|| anyhow!("missing or invalid parameter '{name}': expected integer"))
}

/// Extract a required `Vec<u64>` parameter.
pub(crate) fn require_u64_array(
    params: &serde_json::Map<String, JsonValue>,
    name: &str,
) -> Result<Vec<u64>> {
    let arr = params
        .get(name)
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow!("missing or invalid parameter '{name}': expected array"))?;
    arr.iter()
        .enumerate()
        .map(|(i, v)| {
            v.as_u64()
                .ok_or_else(|| anyhow!("parameter '{name}[{i}]': expected integer"))
        })
        .collect()
}

/// Build a simple `AddImmediate` chain from a slice of deltas.
pub(crate) fn add_immediate_chain(deltas: &[u64]) -> Vec<Instruction> {
    deltas
        .iter()
        .map(|&d| Instruction::AddImmediate(d))
        .collect()
}

#[cfg(test)]
mod enforcement_tests {
    use super::*;

    #[test]
    fn enforcement_serializes_snake_case() {
        assert_eq!(
            serde_json::to_string(&Enforcement::Enforced).unwrap(),
            "\"enforced\""
        );
        assert_eq!(
            serde_json::to_string(&Enforcement::StructureOnly).unwrap(),
            "\"structure_only\""
        );
    }

    #[test]
    fn to_info_carries_enforcement() {
        // accumulator_step is the only enforced template.
        let t = template_by_id("accumulator_step").expect("accumulator_step registered");
        assert_eq!(t.enforcement, Enforcement::Enforced);
        assert_eq!(t.to_info().enforcement, Enforcement::Enforced);
    }
}

#[cfg(test)]
mod enforcement_classification_tests {
    use super::*;

    #[test]
    fn only_accumulator_step_is_enforced() {
        let enforced: Vec<&str> = list_templates()
            .iter()
            .filter(|t| t.enforcement == Enforcement::Enforced)
            .map(|t| t.id)
            .collect();
        assert_eq!(
            enforced.len(),
            1,
            "expected exactly one Enforced template, got {enforced:?}"
        );
        assert!(
            enforced.contains(&"accumulator_step"),
            "accumulator_step must be the Enforced template"
        );
    }

    #[test]
    fn the_five_predicate_templates_are_structure_only() {
        for id in [
            "range_proof",
            "hash_preimage",
            "computation_attestation",
            "data_integrity",
            "policy_compliance",
        ] {
            let t = template_by_id(id).unwrap_or_else(|| panic!("{id} registered"));
            assert_eq!(
                t.enforcement,
                Enforcement::StructureOnly,
                "{id} must be StructureOnly until its real AIR lands"
            );
        }
    }
}
