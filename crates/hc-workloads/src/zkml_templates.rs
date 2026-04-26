//! zkML template registry — parallel surface to [`super::templates`].
//!
//! ## Why a parallel registry
//!
//! The existing [`super::templates::ProofTemplate`] is wired tightly to the
//! accumulator-style VM (`hc-vm::Program`) that today's STARK prover
//! consumes. zkML templates produce a fundamentally different proving
//! payload — a model graph and an inference witness — so they cannot reuse
//! the `Program`-shaped builder return.
//!
//! Rather than touch the existing template registry (and the four
//! `hc-server` / `hc-mcp` consumers that depend on its exact shape), we
//! expose zkML templates through a sibling registry here. Discovery,
//! parameter schemas, and dispatch live in this module; server-side
//! plumbing to route `POST /prove/template/zkml_*` through `hc-zkml` lands
//! in a follow-on PR that touches `hc-server` only.
//!
//! ## Stability
//!
//! Public types (`ZkmlTemplate`, `ZkmlBuildResult`, `ZkmlTemplateInfo`) are
//! the long-term contract for the zkML template surface — `inventory::submit!`
//! at compile time, JSON schema for agents at runtime, and a build function
//! that returns a fully-typed `(ModelGraph, InferenceWitness, HcZkmlConfig)`
//! triple ready to hand to `hc_zkml::prove_inference`.

use anyhow::{anyhow, Result};
use hc_zkml::graph::ModelGraph;
use hc_zkml::proof::InferenceWitness;
use hc_zkml::HcZkmlConfig;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Re-exports of `hc_zkml` types used by the verify-side dispatcher in
/// `hc-server`. Keeping these reachable through `hc-workloads` means
/// downstream crates can integrate the zkml flow without depending on
/// `hc-zkml` directly.
pub use hc_zkml::proof::{PublicIo as ZkmlPublicIo, ZkmlProof};

pub mod matmul;

// ── Static-friendly registration types ──────────────────────────────────

/// Parameter definition using only static references so it can be embedded
/// in the const-constructible [`ZkmlTemplate`] struct (matches the shape of
/// [`super::templates::StaticParam`] for symmetry).
#[derive(Clone, Copy, Debug)]
pub struct StaticParam {
    pub name: &'static str,
    pub description: &'static str,
    pub param_type: &'static str,
    pub required: bool,
}

/// A registered zkML template, collected at compile time via `inventory`.
#[derive(Clone, Copy)]
pub struct ZkmlTemplate {
    pub id: &'static str,
    pub summary: &'static str,
    pub description: &'static str,
    pub parameters: &'static [StaticParam],
    pub tags: &'static [&'static str],
    pub cost_category: &'static str,
    pub example_json: &'static str,
    /// Build function: takes a JSON parameter map, returns the typed
    /// inputs to `hc_zkml::prove_inference`.
    pub build: fn(&serde_json::Map<String, JsonValue>) -> Result<ZkmlBuildResult>,
}

inventory::collect!(ZkmlTemplate);

/// Result of building a zkML template — everything needed to hand to
/// `hc_zkml::prove_inference`.
#[derive(Debug)]
pub struct ZkmlBuildResult {
    pub graph: ModelGraph,
    pub witness: InferenceWitness,
    pub config: HcZkmlConfig,
    /// Recommended ZK masking flag (mirrors the existing
    /// `recommended_zk` knob from accumulator-VM templates).
    pub recommended_zk: bool,
}

// ── Serializable types for MCP / API discovery ─────────────────────────

/// Parameter definition (agent-readable, serializable).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkmlTemplateParam {
    pub name: String,
    pub description: String,
    pub param_type: String,
    pub required: bool,
}

/// Full zkML template metadata exposed to agents via MCP / `/templates`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ZkmlTemplateInfo {
    pub id: String,
    pub summary: String,
    pub description: String,
    pub parameters: Vec<ZkmlTemplateParam>,
    pub example: JsonValue,
    pub tags: Vec<String>,
    pub cost_category: String,
    /// Discriminator so a unified `/templates` listing can distinguish zkML
    /// templates from accumulator-VM templates in a single response.
    pub backend: &'static str,
}

impl ZkmlTemplate {
    pub fn to_info(&self) -> ZkmlTemplateInfo {
        ZkmlTemplateInfo {
            id: self.id.to_string(),
            summary: self.summary.to_string(),
            description: self.description.to_string(),
            parameters: self
                .parameters
                .iter()
                .map(|p| ZkmlTemplateParam {
                    name: p.name.to_string(),
                    description: p.description.to_string(),
                    param_type: p.param_type.to_string(),
                    required: p.required,
                })
                .collect(),
            example: serde_json::from_str(self.example_json).unwrap_or(JsonValue::Null),
            tags: self.tags.iter().map(|t| t.to_string()).collect(),
            cost_category: self.cost_category.to_string(),
            backend: "zkml",
        }
    }
}

// ── Public discovery / build API ───────────────────────────────────────

/// List all registered zkML templates. Stable order is not guaranteed.
pub fn list_zkml_templates() -> Vec<&'static ZkmlTemplate> {
    inventory::iter::<ZkmlTemplate>.into_iter().collect()
}

/// Find a zkML template by ID.
pub fn zkml_template_by_id(id: &str) -> Option<&'static ZkmlTemplate> {
    inventory::iter::<ZkmlTemplate>
        .into_iter()
        .find(|t| t.id == id)
}

/// Build a zkML template from a parameter map.
pub fn build_zkml_from_template(
    id: &str,
    params: &serde_json::Map<String, JsonValue>,
) -> Result<ZkmlBuildResult> {
    let t = zkml_template_by_id(id).ok_or_else(|| anyhow!("unknown zkML template: {id}"))?;
    (t.build)(params)
}

/// List all zkML templates as a serializable info struct.
pub fn list_zkml_template_infos() -> Vec<ZkmlTemplateInfo> {
    list_zkml_templates().iter().map(|t| t.to_info()).collect()
}

/// Find a zkML template's serializable info by ID.
pub fn describe_zkml_template(id: &str) -> Option<ZkmlTemplateInfo> {
    zkml_template_by_id(id).map(|t| t.to_info())
}

/// Verify a zkML envelope structurally. Wraps `hc_zkml::verify_inference`
/// so callers (MCP, server) need not depend on `hc-zkml` directly.
pub fn verify_zkml_envelope(
    public_io: &hc_zkml::proof::PublicIo,
    proof: &hc_zkml::proof::ZkmlProof,
) -> Result<bool> {
    // The model_commitment is not currently consumed by the structural
    // verifier; pass a zero commitment until the FRI lowering binds it.
    let zero_digest = [0u8; 32];
    let model_commitment = hc_zkml::graph::ModelCommitment::new(zero_digest, zero_digest);
    hc_zkml::verify_inference(&model_commitment, public_io, proof)
        .map_err(|e| anyhow!("zkml verify failed: {e}"))
}

/// One-call dispatch helper: build a zkML template and run the prover.
///
/// This is the function that `hc-server`'s `POST /prove/template/:id` route
/// will call when `:id` starts with `zkml_`. It encapsulates the full
/// pipeline so the server change in the follow-on PR is a one-liner: take
/// the (id, params), call this function, store the resulting outcome's
/// `proof` and `public_io` against the job ID, return the job ID.
///
/// ## Why this lives here, not in hc-server
///
/// Keeping the dispatch logic in `hc-workloads` means:
/// - The single-touchpoint update to add a new zkML template is to register
///   a `ZkmlTemplate`; the server doesn't need to know about each template.
/// - The unit tests in this crate exercise the *exact* same code path the
///   server runs.
/// - hc-server stays thin and avoids pulling hc-zkml as a direct dep.
pub fn prove_zkml_template(
    id: &str,
    params: &serde_json::Map<String, JsonValue>,
) -> Result<hc_zkml::streaming::StreamingOutcome> {
    let build = build_zkml_from_template(id, params)?;
    hc_zkml::streaming::prove_single_matmul(&build.graph, &build.witness, &build.config)
        .map_err(|e| anyhow!("zkml prover failed: {e}"))
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_contains_zkml_matmul() {
        assert!(zkml_template_by_id("zkml_matmul").is_some());
    }

    #[test]
    fn list_includes_matmul() {
        let ids: Vec<_> = list_zkml_templates().iter().map(|t| t.id).collect();
        assert!(ids.contains(&"zkml_matmul"));
    }

    #[test]
    fn build_zkml_from_unknown_id_errors() {
        let params = serde_json::Map::new();
        assert!(build_zkml_from_template("does_not_exist", &params).is_err());
    }

    #[test]
    fn prove_zkml_template_end_to_end() {
        let params: JsonValue = serde_json::from_str(
            r#"{
                "m": 2, "n": 2, "k": 3,
                "input":   [1, 2, 3, 4, 5, 6],
                "weights": [1, 0, 0, 1, 1, 1]
            }"#,
        )
        .unwrap();
        let outcome =
            prove_zkml_template("zkml_matmul", params.as_object().unwrap()).unwrap();
        assert_eq!(
            outcome.proof.version,
            hc_zkml::streaming::ENVELOPE_VERSION
        );
        assert_eq!(
            outcome.proof.bytes.len(),
            hc_zkml::streaming::ENVELOPE_BYTES
        );
        // Output shape must match (m, n).
        assert_eq!(outcome.output.shape.0, vec![2, 2]);
        // Structural verification round-trips.
        assert!(
            hc_zkml::verify_inference(&outcome.model_commitment, &outcome.public_io, &outcome.proof)
                .unwrap()
        );
    }

    #[test]
    fn prove_zkml_template_unknown_id_errors() {
        let params = serde_json::Map::new();
        assert!(prove_zkml_template("zkml_does_not_exist", &params).is_err());
    }

    #[test]
    fn prove_zkml_template_propagates_param_errors() {
        // m*k ≠ input.len() — should bubble up as a clear template-build error.
        let params: JsonValue = serde_json::from_str(
            r#"{
                "m": 2, "n": 2, "k": 3,
                "input":   [1, 2, 3],
                "weights": [1, 0, 0, 1, 1, 1]
            }"#,
        )
        .unwrap();
        let err = prove_zkml_template("zkml_matmul", params.as_object().unwrap()).unwrap_err();
        assert!(format!("{err}").contains("does not match m*k"));
    }
}
