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
use crate::templates::{Enforcement, TemplateInfo};
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
    if crate::zkml_templates::describe_zkml_template(id).is_some()
        || crate::spartan_templates::describe_spartan_template(id).is_some()
    {
        return Some(Enforcement::StructureOnly);
    }
    None
}

/// Should this enforcement level appear in public listings?
pub fn is_listable(enforcement: Enforcement, allow_unaudited: bool) -> bool {
    matches!(enforcement, Enforcement::Enforced) || allow_unaudited
}

/// May a prove/estimate request for this template id proceed?
/// Unknown ids are never dispatchable.
pub fn is_dispatchable(id: &str, allow_unaudited: bool) -> bool {
    match enforcement_for(id) {
        Some(e) => is_listable(e, allow_unaudited),
        None => false,
    }
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
    fn unified_info_carries_enforcement() {
        let all = list_all_templates();
        let acc = all.iter().find(|t| t.id == "accumulator_step").unwrap();
        assert_eq!(acc.enforcement, crate::templates::Enforcement::Enforced);
        let range = all.iter().find(|t| t.id == "range_proof").unwrap();
        assert_eq!(
            range.enforcement,
            crate::templates::Enforcement::StructureOnly
        );
    }

    #[test]
    fn enforcement_for_resolves_all_backends() {
        use crate::templates::Enforcement;
        assert_eq!(enforcement_for("accumulator_step"), Some(Enforcement::Enforced));
        assert_eq!(enforcement_for("range_proof"), Some(Enforcement::StructureOnly));
        // zkML/Spartan are preview => structure-only.
        assert_eq!(enforcement_for("zkml_matmul"), Some(Enforcement::StructureOnly));
        assert_eq!(enforcement_for("spartan_r1cs"), Some(Enforcement::StructureOnly));
        assert_eq!(enforcement_for("does_not_exist"), None);
    }

    #[test]
    fn dispatch_and_listing_truth_table() {
        // Enforced: always listable + dispatchable.
        assert!(is_dispatchable("accumulator_step", false));
        assert!(is_dispatchable("accumulator_step", true));
        // StructureOnly: only when unaudited explicitly allowed.
        assert!(!is_dispatchable("range_proof", false));
        assert!(is_dispatchable("range_proof", true));
        // Unknown id: never dispatchable.
        assert!(!is_dispatchable("does_not_exist", true));
    }
}
