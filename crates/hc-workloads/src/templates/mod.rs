//! Proof template registry for AI agent consumption.
//!
//! Templates are parameterized proof patterns that carry rich metadata
//! (descriptions, parameter schemas, examples) designed for LLM tool discovery.
//! Each template knows how to build a [`Program`] from JSON parameters.

use anyhow::{anyhow, Result};
use hc_vm::{Instruction, Program};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

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
