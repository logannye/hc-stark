//! Spartan R1CS template registry — parallel surface to [`super::templates`]
//! and [`super::zkml_templates`].
//!
//! ## Why a third registry
//!
//! Spartan templates produce a [`hc_sumcheck_spartan::R1csProof`] envelope
//! that is structurally distinct from the accumulator-VM `Program` and from
//! the zkML model graph. Rather than overload the existing builders we add
//! a dedicated registry so each backend's typed inputs stay typed.
//!
//! Discovery, parameter schemas, and dispatch live here; server-side
//! plumbing for `POST /prove/template/spartan_*` lands in a follow-on PR
//! that touches `hc-server` only.

use anyhow::{anyhow, Result};
use hc_core::field::GoldilocksField as F;
use hc_sumcheck_spartan::{prove_r1cs, HcSpartanConfig, R1cs, R1csProof};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

pub mod r1cs_template;

// ── Static-friendly registration types ──────────────────────────────────

#[derive(Clone, Copy, Debug)]
pub struct StaticParam {
    pub name: &'static str,
    pub description: &'static str,
    pub param_type: &'static str,
    pub required: bool,
}

#[derive(Clone, Copy)]
pub struct SpartanTemplate {
    pub id: &'static str,
    pub summary: &'static str,
    pub description: &'static str,
    pub parameters: &'static [StaticParam],
    pub tags: &'static [&'static str],
    pub cost_category: &'static str,
    pub example_json: &'static str,
    /// Build function: takes a JSON parameter map, returns the typed
    /// inputs to the Spartan prover.
    pub build: fn(&serde_json::Map<String, JsonValue>) -> Result<SpartanBuildResult>,
}

inventory::collect!(SpartanTemplate);

/// Result of building a Spartan template.
#[derive(Debug)]
pub struct SpartanBuildResult {
    pub r1cs: R1cs,
    pub tau: Vec<F>,
    pub config: HcSpartanConfig,
}

// ── Serializable types for MCP / API discovery ─────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpartanTemplateParam {
    pub name: String,
    pub description: String,
    pub param_type: String,
    pub required: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SpartanTemplateInfo {
    pub id: String,
    pub summary: String,
    pub description: String,
    pub parameters: Vec<SpartanTemplateParam>,
    pub example: JsonValue,
    pub tags: Vec<String>,
    pub cost_category: String,
    /// Backend discriminator for unified `/templates` listings.
    pub backend: &'static str,
}

impl SpartanTemplate {
    pub fn to_info(&self) -> SpartanTemplateInfo {
        SpartanTemplateInfo {
            id: self.id.to_string(),
            summary: self.summary.to_string(),
            description: self.description.to_string(),
            parameters: self
                .parameters
                .iter()
                .map(|p| SpartanTemplateParam {
                    name: p.name.to_string(),
                    description: p.description.to_string(),
                    param_type: p.param_type.to_string(),
                    required: p.required,
                })
                .collect(),
            example: serde_json::from_str(self.example_json).unwrap_or(JsonValue::Null),
            tags: self.tags.iter().map(|t| t.to_string()).collect(),
            cost_category: self.cost_category.to_string(),
            backend: "spartan",
        }
    }
}

// ── Discovery / build / dispatch API ───────────────────────────────────

pub fn list_spartan_templates() -> Vec<&'static SpartanTemplate> {
    inventory::iter::<SpartanTemplate>.into_iter().collect()
}

pub fn list_spartan_template_infos() -> Vec<SpartanTemplateInfo> {
    list_spartan_templates()
        .iter()
        .map(|t| t.to_info())
        .collect()
}

pub fn spartan_template_by_id(id: &str) -> Option<&'static SpartanTemplate> {
    inventory::iter::<SpartanTemplate>
        .into_iter()
        .find(|t| t.id == id)
}

pub fn describe_spartan_template(id: &str) -> Option<SpartanTemplateInfo> {
    spartan_template_by_id(id).map(|t| t.to_info())
}

pub fn build_spartan_from_template(
    id: &str,
    params: &serde_json::Map<String, JsonValue>,
) -> Result<SpartanBuildResult> {
    let t = spartan_template_by_id(id).ok_or_else(|| anyhow!("unknown spartan template: {id}"))?;
    (t.build)(params)
}

/// One-call dispatch helper: build the template, run `prove_r1cs`, return
/// the proof envelope. Mirror of `prove_zkml_template`.
pub fn prove_spartan_template(
    id: &str,
    params: &serde_json::Map<String, JsonValue>,
) -> Result<R1csProof> {
    let build = build_spartan_from_template(id, params)?;
    prove_r1cs(&build.r1cs, &build.tau, &build.config)
        .map_err(|e| anyhow!("spartan prover failed: {e}"))
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_spartan_r1cs() {
        assert!(spartan_template_by_id("spartan_r1cs").is_some());
    }

    #[test]
    fn list_includes_spartan_r1cs() {
        let ids: Vec<_> = list_spartan_templates().iter().map(|t| t.id).collect();
        assert!(ids.contains(&"spartan_r1cs"));
    }

    #[test]
    fn build_spartan_from_unknown_id_errors() {
        let params = serde_json::Map::new();
        assert!(build_spartan_from_template("does_not_exist", &params).is_err());
    }
}
