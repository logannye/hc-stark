//! Unified template-discovery surface across all proving backends.
//!
//! [`list_all_templates`] returns a single flat list combining the three
//! parallel registries — accumulator-VM `ProofTemplate`, zkML
//! `ZkmlTemplate`, and Spartan `SpartanTemplate` — with a `backend`
//! discriminator so MCP and HTTP `/templates` consumers can render them in
//! a single response.
//!
//! ## Design notes
//!
//! - The three registries stay separate at the type level so each
//!   backend's typed inputs remain typed. This module does not introduce
//!   a sum type over `ProofTemplate | ZkmlTemplate | SpartanTemplate` —
//!   instead it produces a homogeneous *info* struct that flattens the
//!   metadata each registry exposes.
//! - Stable order: VM templates first, then zkML, then Spartan. Within
//!   each backend the order is unspecified (matches `inventory` collection
//!   order).
//! - The `backend` field is a `&'static str` taken from each registry's
//!   `to_info()` output; the existing `ProofTemplateInfo` does not carry a
//!   backend field, so this module attaches `"vm"` to it explicitly.

use crate::spartan_templates::SpartanTemplateInfo;
use crate::templates::{Enforcement, TemplateInfo, TemplateLifecycle};
use crate::zkml_templates::ZkmlTemplateInfo;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;

/// Flat union of template metadata across backends.
///
/// All four backends fill the common fields; backend-specific extensions
/// (e.g., zkML's tile-dim auto-tuning info) are not surfaced here — call
/// the per-backend describe endpoint for those.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnifiedTemplateInfo {
    pub id: String,
    pub summary: String,
    pub description: String,
    pub tags: Vec<String>,
    pub cost_category: String,
    pub example: JsonValue,
    /// One of: `"vm"`, `"zkml"`, `"spartan"`.
    pub backend: &'static str,
    pub enforcement: Enforcement,
    /// Whether the template has cleared the external audit (Phase 4). Combined
    /// with `enforcement` by [`is_live`] to decide production exposure. zkML and
    /// Spartan are preview backends and are always `false`.
    #[serde(default)]
    pub audited: bool,
    /// Public lifecycle label: `live`, `audit_gated`, or `preview`.
    pub lifecycle: TemplateLifecycle,
}

impl UnifiedTemplateInfo {
    fn from_vm(info: TemplateInfo) -> Self {
        Self {
            id: info.id,
            summary: info.summary,
            description: info.description,
            tags: info.tags,
            cost_category: info.cost_category,
            example: info.example,
            backend: "vm",
            enforcement: info.enforcement,
            audited: info.audited,
            lifecycle: info.lifecycle,
        }
    }

    fn from_zkml(info: ZkmlTemplateInfo) -> Self {
        Self {
            id: info.id,
            summary: info.summary,
            description: info.description,
            tags: info.tags,
            cost_category: info.cost_category,
            example: info.example,
            backend: info.backend,
            enforcement: Enforcement::StructureOnly,
            audited: false,
            lifecycle: TemplateLifecycle::Preview,
        }
    }

    fn from_spartan(info: SpartanTemplateInfo) -> Self {
        Self {
            id: info.id,
            summary: info.summary,
            description: info.description,
            tags: info.tags,
            cost_category: info.cost_category,
            example: info.example,
            backend: info.backend,
            enforcement: Enforcement::StructureOnly,
            audited: false,
            lifecycle: TemplateLifecycle::Preview,
        }
    }
}

/// Return the union of every registered template across all backends.
pub fn list_all_templates() -> Vec<UnifiedTemplateInfo> {
    let mut out = Vec::new();
    for t in crate::templates::list_templates() {
        out.push(UnifiedTemplateInfo::from_vm(t.to_info()));
    }
    for t in crate::zkml_templates::list_zkml_templates() {
        out.push(UnifiedTemplateInfo::from_zkml(t.to_info()));
    }
    for t in crate::spartan_templates::list_spartan_templates() {
        out.push(UnifiedTemplateInfo::from_spartan(t.to_info()));
    }
    out
}

/// Resolve a template's enforcement across all backends. `None` if the id
/// is unknown. zkML and Spartan templates are preview => `StructureOnly`.
pub fn enforcement_for(id: &str) -> Option<Enforcement> {
    if let Some(t) = crate::templates::template_by_id(id) {
        return Some(t.enforcement);
    }
    // Cheap existence check via the inventory lookups (no info-struct
    // allocation): enforcement_for is on the per-request dispatch path.
    // NOTE: the zkML and Spartan registries carry no per-template
    // `enforcement` field, so they are assumed `StructureOnly`; revisit
    // this when either registry grows an `enforcement` field.
    if crate::zkml_templates::zkml_template_by_id(id).is_some()
        || crate::spartan_templates::spartan_template_by_id(id).is_some()
    {
        return Some(Enforcement::StructureOnly);
    }
    None
}

/// Whether a template should be exposed (listed AND dispatchable) in this
/// deployment.
///
/// A template is live iff it BOTH cryptographically binds its predicate
/// (`Enforced`) AND has cleared the external audit (`audited`) — or the
/// deployment explicitly opts into unaudited templates
/// (`HC_ALLOW_UNAUDITED_TEMPLATES`). This single predicate governs both the
/// `/templates` listing and prove/estimate dispatch so both surfaces agree.
///
/// `enforcement` and `audited` are independent axes: `range_proof` is
/// `Enforced` (sound v7 AIR) yet `audited = false`, so it stays gated until the
/// Phase 4 audit even though it genuinely enforces its predicate.
pub fn is_live(enforcement: Enforcement, audited: bool, allow_unaudited: bool) -> bool {
    (matches!(enforcement, Enforcement::Enforced) && audited) || allow_unaudited
}

/// May a prove/estimate request for this template id proceed? Looks up the
/// template's enforcement + audit status across all backends and applies
/// [`is_live`]. Unknown ids are never dispatchable.
pub fn is_dispatchable(id: &str, allow_unaudited: bool) -> bool {
    if let Some(t) = crate::templates::template_by_id(id) {
        return is_live(t.enforcement, t.audited, allow_unaudited);
    }
    // zkML / Spartan are preview backends: StructureOnly + unaudited.
    if crate::zkml_templates::zkml_template_by_id(id).is_some()
        || crate::spartan_templates::spartan_template_by_id(id).is_some()
    {
        return is_live(Enforcement::StructureOnly, false, allow_unaudited);
    }
    false
}

/// Whether unaudited (StructureOnly) templates are exposed/dispatchable in
/// this deployment. Default `false`: only templates whose AIR enforces their
/// predicate are offered. Set `HC_ALLOW_UNAUDITED_TEMPLATES=true` (or `1`)
/// for dev / Phase-1B work. Shared by hc-server and hc-mcp so both surfaces
/// agree on a single parse of the flag.
pub fn allow_unaudited_templates() -> bool {
    matches!(
        std::env::var("HC_ALLOW_UNAUDITED_TEMPLATES").as_deref(),
        Ok("true") | Ok("1")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unified_listing_includes_all_three_backends() {
        let all = list_all_templates();
        let backends: std::collections::HashSet<&str> = all.iter().map(|t| t.backend).collect();
        assert!(backends.contains("vm"), "expected at least one vm template");
        assert!(
            backends.contains("zkml"),
            "expected at least one zkml template"
        );
        assert!(
            backends.contains("spartan"),
            "expected at least one spartan template"
        );
    }

    #[test]
    fn unified_listing_includes_known_template_ids() {
        let all = list_all_templates();
        let ids: std::collections::HashSet<String> = all.iter().map(|t| t.id.clone()).collect();
        assert!(ids.contains("range_proof"));
        assert!(ids.contains("zkml_matmul"));
        assert!(ids.contains("spartan_r1cs"));
    }

    #[test]
    fn vm_templates_get_vm_backend_label() {
        let all = list_all_templates();
        let range = all.iter().find(|t| t.id == "range_proof").unwrap();
        assert_eq!(range.backend, "vm");
    }

    #[test]
    fn unified_listing_is_nonempty() {
        let all = list_all_templates();
        assert!(!all.is_empty());
    }

    #[test]
    fn unified_info_carries_enforcement_and_audited() {
        let all = list_all_templates();
        let acc = all.iter().find(|t| t.id == "accumulator_step").unwrap();
        assert_eq!(acc.enforcement, crate::templates::Enforcement::Enforced);
        assert!(acc.audited, "accumulator_step is audited");
        assert_eq!(acc.lifecycle, TemplateLifecycle::Live);
        // range_proof now Enforced (real AIR) but NOT yet audited → gated.
        let range = all.iter().find(|t| t.id == "range_proof").unwrap();
        assert_eq!(range.enforcement, crate::templates::Enforcement::Enforced);
        assert!(!range.audited, "range_proof is not yet audited");
        assert_eq!(range.lifecycle, TemplateLifecycle::AuditGated);
        let zkml = all.iter().find(|t| t.id == "zkml_matmul").unwrap();
        assert_eq!(
            zkml.enforcement,
            crate::templates::Enforcement::StructureOnly
        );
        assert!(!zkml.audited);
        assert_eq!(zkml.lifecycle, TemplateLifecycle::Preview);
    }

    #[test]
    fn enforcement_for_resolves_all_backends() {
        use crate::templates::Enforcement;
        assert_eq!(
            enforcement_for("accumulator_step"),
            Some(Enforcement::Enforced)
        );
        // range_proof graduated to Enforced (sound v7 AIR).
        assert_eq!(enforcement_for("range_proof"), Some(Enforcement::Enforced));
        // zkML/Spartan are preview => structure-only.
        assert_eq!(
            enforcement_for("zkml_matmul"),
            Some(Enforcement::StructureOnly)
        );
        assert_eq!(
            enforcement_for("spartan_r1cs"),
            Some(Enforcement::StructureOnly)
        );
        assert_eq!(enforcement_for("does_not_exist"), None);
    }

    #[test]
    fn dispatch_and_listing_truth_table() {
        // Audited + Enforced: always dispatchable (accumulator_step).
        assert!(is_dispatchable("accumulator_step", false));
        assert!(is_dispatchable("accumulator_step", true));
        // Enforced but unaudited (range_proof): only when unaudited allowed.
        assert!(!is_dispatchable("range_proof", false));
        assert!(is_dispatchable("range_proof", true));
        // StructureOnly + unaudited: only when unaudited allowed.
        assert!(!is_dispatchable("hash_preimage", false));
        assert!(is_dispatchable("hash_preimage", true));
        // Unknown id: never dispatchable.
        assert!(!is_dispatchable("does_not_exist", true));
    }

    #[test]
    fn range_proof_is_enforced_but_gated_until_audit() {
        use crate::templates::{template_by_id, Enforcement};
        let r = template_by_id("range_proof").unwrap();
        assert_eq!(
            r.enforcement,
            Enforcement::Enforced,
            "range now truly enforces its predicate"
        );
        assert!(!r.audited, "range is not yet audited → gated");
        // gated off by default, on with the unaudited flag:
        assert!(!is_dispatchable("range_proof", false));
        assert!(is_dispatchable("range_proof", true));
        // accumulator stays live unconditionally:
        assert!(is_dispatchable("accumulator_step", false));
    }

    #[test]
    fn only_accumulator_step_is_live_by_default() {
        let live: Vec<String> = list_all_templates()
            .into_iter()
            .filter(|t| is_live(t.enforcement, t.audited, false))
            .map(|t| t.id)
            .collect();
        assert_eq!(
            live,
            vec!["accumulator_step".to_string()],
            "only accumulator_step is live without HC_ALLOW_UNAUDITED_TEMPLATES, got {live:?}"
        );
    }

    #[test]
    fn allow_unaudited_flag_parses_true_and_one() {
        std::env::remove_var("HC_ALLOW_UNAUDITED_TEMPLATES");
        assert!(!allow_unaudited_templates());
        std::env::set_var("HC_ALLOW_UNAUDITED_TEMPLATES", "1");
        assert!(allow_unaudited_templates());
        std::env::set_var("HC_ALLOW_UNAUDITED_TEMPLATES", "true");
        assert!(allow_unaudited_templates());
        std::env::set_var("HC_ALLOW_UNAUDITED_TEMPLATES", "false");
        assert!(!allow_unaudited_templates());
        std::env::remove_var("HC_ALLOW_UNAUDITED_TEMPLATES");
    }
}
