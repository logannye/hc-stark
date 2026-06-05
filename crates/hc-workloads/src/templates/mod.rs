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
    /// Whether this template has cleared the external cryptographic audit
    /// (Phase 4). A template is exposed/dispatchable in production only when it
    /// is BOTH `Enforced` AND `audited` — or when the deployment explicitly
    /// opts into unaudited templates (`HC_ALLOW_UNAUDITED_TEMPLATES`). This is a
    /// separate axis from `enforcement`: a template can cryptographically bind
    /// its predicate (`Enforced`) yet remain gated until the audit signs off
    /// (e.g. `range_proof` on the sound-but-not-yet-audited v7 core).
    pub audited: bool,
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
    /// Whether the template has cleared the external audit (see
    /// [`ProofTemplate::audited`]). Defaults to `false` for older clients.
    #[serde(default)]
    pub audited: bool,
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
            audited: self.audited,
        }
    }
}

/// Result of building a provable statement from template parameters.
///
/// Two shapes:
/// - `Vm` — a VM `Program` plus its accumulator boundary, proved on the v5
///   accumulator path (`prove_v5`). Used by `accumulator_step` and the
///   structure-only predicate templates that have not yet been ported to a
///   real AIR.
/// - `Air` — a general AIR (`hc_air::GeneralAir`) with its width-N trace and
///   public-input vector, proved on the sound v7 path (`prove_v7`). Used by
///   templates whose AIR actually binds the named predicate (`range_proof`).
pub enum TemplateBuildResult {
    Vm {
        program: Program,
        initial_acc: u64,
        final_acc: u64,
        recommended_zk: bool,
    },
    Air {
        air: Box<dyn hc_air::GeneralAir + Send + Sync>,
        trace: hc_air::MultiColumnTrace<hc_air::air_general::F>,
        public_inputs: Vec<hc_air::air_general::F>,
        recommended_zk: bool,
    },
}

impl TemplateBuildResult {
    /// Whether ZK masking is recommended for this statement by default.
    pub fn recommended_zk(&self) -> bool {
        match self {
            TemplateBuildResult::Vm { recommended_zk, .. }
            | TemplateBuildResult::Air { recommended_zk, .. } => *recommended_zk,
        }
    }

    /// Size hint for the block-size heuristic: VM program length, or the AIR
    /// trace height.
    pub fn size_hint(&self) -> usize {
        match self {
            TemplateBuildResult::Vm { program, .. } => program.len(),
            TemplateBuildResult::Air { trace, .. } => trace.num_rows(),
        }
    }

    /// Cosmetic `initial_acc` for the request record. VM: the accumulator's
    /// initial value; AIR: the first public input (e.g. range `min`), else 0.
    /// The worker rebuilds AIR statements from the template params and does NOT
    /// consume this for AIR proving.
    pub fn initial_acc(&self) -> u64 {
        use hc_core::field::FieldElement;
        match self {
            TemplateBuildResult::Vm { initial_acc, .. } => *initial_acc,
            TemplateBuildResult::Air { public_inputs, .. } => {
                public_inputs.first().map(|f| f.to_u64()).unwrap_or(0)
            }
        }
    }

    /// Cosmetic `final_acc` for the request record. VM: the accumulator's final
    /// value; AIR: the second public input (e.g. range `max`), else 0.
    pub fn final_acc(&self) -> u64 {
        use hc_core::field::FieldElement;
        match self {
            TemplateBuildResult::Vm { final_acc, .. } => *final_acc,
            TemplateBuildResult::Air { public_inputs, .. } => {
                public_inputs.get(1).map(|f| f.to_u64()).unwrap_or(0)
            }
        }
    }
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
    fn accumulator_and_range_are_enforced() {
        // Phase 1B: `range_proof` now cryptographically binds its predicate
        // (sound v7 AIR), so it joins `accumulator_step` as Enforced. The two
        // are distinguished by the `audited` axis (see below), not enforcement.
        let enforced: std::collections::HashSet<&str> = list_templates()
            .iter()
            .filter(|t| t.enforcement == Enforcement::Enforced)
            .map(|t| t.id)
            .collect();
        assert!(
            enforced.contains("accumulator_step"),
            "accumulator_step must be Enforced"
        );
        assert!(
            enforced.contains("range_proof"),
            "range_proof must be Enforced once its real AIR lands"
        );
    }

    #[test]
    fn only_accumulator_step_is_audited() {
        // `audited` gates production exposure. Until the Phase 4 external audit,
        // only `accumulator_step` is audited; everything else (including the
        // sound-but-unaudited `range_proof`) stays gated by default.
        let audited: Vec<&str> = list_templates()
            .iter()
            .filter(|t| t.audited)
            .map(|t| t.id)
            .collect();
        assert_eq!(
            audited,
            vec!["accumulator_step"],
            "exactly one audited template (accumulator_step), got {audited:?}"
        );
    }

    #[test]
    fn the_four_remaining_predicate_templates_are_structure_only() {
        // `range_proof` graduated to Enforced (real AIR). The rest still only
        // produce structurally valid proofs until their AIRs land.
        for id in [
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
            assert!(!t.audited, "{id} must not be audited");
        }
    }
}
