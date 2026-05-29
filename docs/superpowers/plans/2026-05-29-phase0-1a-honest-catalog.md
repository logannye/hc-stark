# Phase 0.1a — Honest Template Catalog Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the service honest by default — only templates whose AIR actually enforces their named predicate (today: only `accumulator_step`) are listed, described, and dispatchable; the five "structure-only" templates (`range_proof`, `hash_preimage`, `computation_attestation`, `data_integrity`, `policy_compliance`) and the preview zkML/Spartan templates are hidden and refused unless an operator explicitly sets `HC_ALLOW_UNAUDITED_TEMPLATES=true`.

**Architecture:** Add a const-constructible `Enforcement` classification to the `ProofTemplate` registry. Centralize the visibility/dispatch decision in three *pure* helper functions in `hc-workloads` (`enforcement_for`, `is_listable`, `is_dispatchable`) so the gating logic is unit-tested without HTTP. The `hc-server` HTTP handlers and `hc-mcp` tool impls call those helpers, reading the `HC_ALLOW_UNAUDITED_TEMPLATES` env flag (default `false`). No cryptography changes — this is a truthful-surface change only. A useful side effect: with the flag off (prod default), the unmetered zkML/Spartan fast-paths (audit finding G9) are refused before they run.

**Tech Stack:** Rust (workspace crates `hc-workloads`, `hc-server`, `hc-mcp`), `inventory` for compile-time template registration, `serde`, `axum`, `rmcp`.

**Scope note:** This plan is Phase 0.1**a** (engine/API/MCP). The customer-facing copy changes (README, `site/`, the `tinyzkp-proofs` skill, `deploy/server-card.json`, marking `contracts/StarkVerifier.sol` non-functional) are Phase 0.1**b** and get their own plan — they depend on the `enforcement` values this plan establishes.

---

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/hc-workloads/src/templates/mod.rs` | VM template registry types | Add `Enforcement` enum; add `enforcement` field to `ProofTemplate` + `TemplateInfo`; carry it in `to_info()` |
| `crates/hc-workloads/src/templates/accumulator.rs` | `accumulator_step` registration | Set `enforcement: Enforcement::Enforced` |
| `crates/hc-workloads/src/templates/{range_proof,hash_preimage,computation,data_integrity,policy}.rs` | the 5 structure-only registrations | Set `enforcement: Enforcement::StructureOnly` |
| `crates/hc-workloads/src/unified.rs` | cross-backend listing + gating helpers | Add `enforcement` to `UnifiedTemplateInfo`; add pure `enforcement_for` / `is_listable` / `is_dispatchable` |
| `crates/hc-workloads/src/lib.rs` | crate exports | Re-export the three helpers + `Enforcement` |
| `crates/hc-server/src/lib.rs` | HTTP handlers | Add `allow_unaudited_templates()` env helper; filter `templates_list`; gate `template_detail`, `prove_template`, `estimate`; add `enforcement` to `TemplateSummary` |
| `crates/hc-mcp/src/tools/discovery.rs` | MCP discovery tools | Filter `list_templates_impl` + `list_all_templates_impl`; add caveat in `describe_template_impl` |
| `crates/hc-mcp/src/tools/proving.rs` | MCP prove tool | Gate `prove_template_impl` |
| `deploy/hetzner/docker-compose.prod.yml` | prod config | Ensure `HC_ALLOW_UNAUDITED_TEMPLATES` is unset/false (default-off) — documented, no functional change |
| `README.md` | server-config table | Document the new env var |

---

## Task 1: Add the `Enforcement` classification to the registry

**Files:**
- Modify: `crates/hc-workloads/src/templates/mod.rs`

- [ ] **Step 1: Write the failing test**

Append to the bottom of `crates/hc-workloads/src/templates/mod.rs`:

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-workloads enforcement_tests 2>&1 | tail -20`
Expected: FAIL to compile — `cannot find type Enforcement`, `no field enforcement on ProofTemplate`.

- [ ] **Step 3: Write minimal implementation**

In `crates/hc-workloads/src/templates/mod.rs`, after the `use` block (after line 10), add the enum:

```rust
/// Whether a template's AIR actually enforces its named predicate.
///
/// `Enforced` — the constraint system cryptographically binds the claim
/// (e.g. `accumulator_step`). `StructureOnly` — the template currently
/// only produces a well-formed accumulator proof and does NOT constrain
/// the named predicate; it must be hidden/refused in production until a
/// real AIR lands (see the Phase 1B roadmap).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Enforcement {
    Enforced,
    StructureOnly,
}
```

Add the field to `ProofTemplate` (inside the struct, after `build_program` on line 41):

```rust
    /// Whether this template's AIR enforces its named predicate.
    pub enforcement: Enforcement,
```

Add the field to `TemplateInfo` (inside the struct, after `cost_category` on line 66):

```rust
    pub enforcement: Enforcement,
```

Add it to `to_info()` (inside the returned `TemplateInfo { .. }`, after `cost_category:` on line 88):

```rust
            enforcement: self.enforcement,
```

- [ ] **Step 4: Run the test (still failing — registrations not yet updated)**

Run: `cargo build -p hc-workloads 2>&1 | tail -20`
Expected: FAIL — the six `inventory::submit!(ProofTemplate { .. })` blocks now miss the `enforcement` field (`missing field enforcement`). This is expected and fixed in Task 2.

- [ ] **Step 5: No commit yet** — Task 2 restores compilation. (Committing a non-compiling crate is disallowed.)

---

## Task 2: Tag all six templates with their enforcement status

**Files:**
- Modify: `crates/hc-workloads/src/templates/accumulator.rs`
- Modify: `crates/hc-workloads/src/templates/range_proof.rs`
- Modify: `crates/hc-workloads/src/templates/hash_preimage.rs`
- Modify: `crates/hc-workloads/src/templates/computation.rs`
- Modify: `crates/hc-workloads/src/templates/data_integrity.rs`
- Modify: `crates/hc-workloads/src/templates/policy.rs`

- [ ] **Step 1: Write the failing test**

Append to the bottom of `crates/hc-workloads/src/templates/mod.rs`:

```rust
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
        assert_eq!(enforced, vec!["accumulator_step"]);
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-workloads enforcement 2>&1 | tail -20`
Expected: FAIL to compile (still `missing field enforcement` from Task 1's incomplete state).

- [ ] **Step 3: Write minimal implementation**

In `crates/hc-workloads/src/templates/accumulator.rs`, inside `inventory::submit!(ProofTemplate { .. })`, add after the `cost_category: "lightweight",` line:

```rust
    enforcement: Enforcement::Enforced,
```

In **each** of `range_proof.rs`, `hash_preimage.rs`, `computation.rs`, `data_integrity.rs`, `policy.rs`, inside their `inventory::submit!(ProofTemplate { .. })`, add after the `cost_category: "lightweight",` line:

```rust
    enforcement: Enforcement::StructureOnly,
```

(`Enforcement` is in scope in each template file via the existing `use super::*;`.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-workloads enforcement 2>&1 | tail -20`
Expected: PASS — `enforcement_tests` and `enforcement_classification_tests` green; crate compiles.

- [ ] **Step 5: Commit**

```bash
git add crates/hc-workloads/src/templates/
git commit -m "feat(workloads): add Enforcement classification to proof templates

Only accumulator_step enforces its predicate today; the other five
templates are marked StructureOnly so the surface can hide/refuse them.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 3: Pure gating helpers + `enforcement` on the unified listing

**Files:**
- Modify: `crates/hc-workloads/src/unified.rs`
- Modify: `crates/hc-workloads/src/lib.rs`

- [ ] **Step 1: Write the failing test**

Append to the `tests` module at the bottom of `crates/hc-workloads/src/unified.rs` (inside the existing `mod tests { .. }`):

```rust
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-workloads -- unified 2>&1 | tail -20`
Expected: FAIL to compile — `no field enforcement on UnifiedTemplateInfo`, `cannot find function enforcement_for / is_dispatchable`.

- [ ] **Step 3: Write minimal implementation**

In `crates/hc-workloads/src/unified.rs`, add `use crate::templates::Enforcement;` to the imports, add the field to the struct (after `backend` on line 43):

```rust
    pub enforcement: Enforcement,
```

Set it in each constructor. In `from_vm` (after `backend: "vm",`):

```rust
            enforcement: info.enforcement,
```

In `from_zkml` and `from_spartan` (after their `backend: info.backend,`), preview backends are structure-only:

```rust
            enforcement: Enforcement::StructureOnly,
```

Then append these pure helpers to `unified.rs` (after `list_all_templates`):

```rust
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
```

In `crates/hc-workloads/src/lib.rs`, extend the `pub use unified::{..}` line (line 90) to:

```rust
pub use unified::{
    enforcement_for, is_dispatchable, is_listable, list_all_templates, UnifiedTemplateInfo,
};
```

and re-export the enum next to it:

```rust
pub use templates::Enforcement;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-workloads 2>&1 | tail -20`
Expected: PASS — all workloads tests green (existing + new). Note: the pre-existing `unified_listing_includes_known_template_ids` test still passes because `list_all_templates()` is unchanged (it returns everything; filtering is the caller's job).

- [ ] **Step 5: Commit**

```bash
git add crates/hc-workloads/src/unified.rs crates/hc-workloads/src/lib.rs
git commit -m "feat(workloads): pure enforcement-gating helpers + unified enforcement field

enforcement_for/is_listable/is_dispatchable centralize the listing+dispatch
decision so hc-server and hc-mcp share one tested truth table.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 4: Gate the HTTP surface behind `HC_ALLOW_UNAUDITED_TEMPLATES`

**Files:**
- Modify: `crates/hc-server/src/lib.rs` (handlers `templates_list` ~line 2026, `template_detail` ~2052, `prove_template` ~2077, `estimate` ~2461; struct `TemplateSummary`)

- [ ] **Step 1: Write the failing test**

Add a test module near the other server tests (end of `crates/hc-server/src/lib.rs`). These test the env helper + the filtering decision directly (no HTTP needed):

```rust
#[cfg(test)]
mod honest_catalog_tests {
    use super::*;

    #[test]
    fn allow_helper_defaults_false_and_reads_true() {
        std::env::remove_var("HC_ALLOW_UNAUDITED_TEMPLATES");
        assert!(!allow_unaudited_templates());
        std::env::set_var("HC_ALLOW_UNAUDITED_TEMPLATES", "true");
        assert!(allow_unaudited_templates());
        std::env::set_var("HC_ALLOW_UNAUDITED_TEMPLATES", "false");
        assert!(!allow_unaudited_templates());
        std::env::remove_var("HC_ALLOW_UNAUDITED_TEMPLATES");
    }

    #[test]
    fn default_catalog_lists_only_enforced() {
        // With the flag off, the only listable template id is accumulator_step
        // (plus any future enforced ones). range_proof must be hidden.
        let listed: Vec<String> = hc_workloads::list_all_templates()
            .into_iter()
            .filter(|t| hc_workloads::is_listable(t.enforcement, false))
            .map(|t| t.id)
            .collect();
        assert!(listed.contains(&"accumulator_step".to_string()));
        assert!(!listed.contains(&"range_proof".to_string()));
        assert!(!listed.iter().any(|id| id.starts_with("zkml_")));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-server honest_catalog 2>&1 | tail -20`
Expected: FAIL to compile — `cannot find function allow_unaudited_templates`.

- [ ] **Step 3: Write minimal implementation**

(3a) Add the env helper. Place it just above `async fn templates_list(` (before line 2026):

```rust
/// Whether unaudited (StructureOnly) templates are exposed/dispatchable.
/// Default `false`: production offers only templates whose AIR enforces
/// their predicate. Set `HC_ALLOW_UNAUDITED_TEMPLATES=true` for dev/Phase-1B.
fn allow_unaudited_templates() -> bool {
    matches!(
        std::env::var("HC_ALLOW_UNAUDITED_TEMPLATES").as_deref(),
        Ok("true") | Ok("1")
    )
}
```

(3b) Add `enforcement` to the `TemplateSummary` struct. It currently holds the fields populated in `templates_list` — `id`, `summary`, `tags`, `cost_category`, `backend` — and derives the same `Serialize`/`utoipa::ToSchema` attributes as its sibling response structs. Add one field alongside them (a plain `String` needs no extra annotation):

```rust
    pub enforcement: String,
```

(3c) Filter + populate in `templates_list` (replace the body lines 2027-2042). The `.map` gains the enforcement string and a `.filter` drops non-listable entries:

```rust
    let allow = allow_unaudited_templates();
    let unified = hc_workloads::list_all_templates();
    let summaries: Vec<TemplateSummary> = unified
        .iter()
        .filter(|t| hc_workloads::is_listable(t.enforcement, allow))
        .map(|t| TemplateSummary {
            id: t.id.clone(),
            summary: t.summary.clone(),
            tags: t.tags.clone(),
            cost_category: t.cost_category.clone(),
            backend: t.backend.to_string(),
            enforcement: serde_json::to_value(t.enforcement)
                .ok()
                .and_then(|v| v.as_str().map(str::to_string))
                .unwrap_or_else(|| "structure_only".to_string()),
        })
        .collect();
    let count = summaries.len();
    Json(TemplateListResponse {
        templates: summaries,
        count,
    })
```

(3d) Gate `template_detail` — at the very top of the function body (before line 2055's first `if let`):

```rust
    let allow = allow_unaudited_templates();
    if let Some(enf) = hc_workloads::enforcement_for(&template_id) {
        if !hc_workloads::is_listable(enf, allow) {
            return Err(ApiError::new(
                StatusCode::NOT_FOUND,
                "not_found",
                format!("unknown template: {template_id}"),
            ));
        }
    }
```

(3e) Gate `prove_template` — immediately after `state.metrics.prove_submitted.inc();` (after line 2083):

```rust
    if !hc_workloads::is_dispatchable(&template_id, allow_unaudited_templates()) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "template_unavailable",
            format!(
                "template '{template_id}' does not currently enforce its named predicate \
                 and is disabled in this deployment"
            ),
        ));
    }
```

(This runs before the `zkml_`/`spartan_` fast-paths at lines 2144/2153, so those unmetered paths are also refused when the flag is off — addresses part of G9.)

(3f) Gate `estimate` — the handler (`async fn estimate`, line 2452) binds the requested id as `tid` via `if let Some(ref tid) = req.template_id {`. Insert the gate inside that block, immediately before the `let build = hc_workloads::templates::build_from_template(tid, params)` call (line 2461), i.e. right after the `let params = ...?;` extraction ends:

```rust
        if !hc_workloads::is_dispatchable(tid, allow_unaudited_templates()) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "template_unavailable",
                "template is not available in this deployment",
            ));
        }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-server honest_catalog 2>&1 | tail -20`
Expected: PASS. Then full crate build: `cargo build -p hc-server 2>&1 | tail -5` → success.

- [ ] **Step 5: Commit**

```bash
git add crates/hc-server/src/lib.rs
git commit -m "feat(server): hide+refuse unaudited templates by default (HC_ALLOW_UNAUDITED_TEMPLATES)

/templates, /templates/:id, /prove/template/:id and /estimate now only
expose templates whose AIR enforces their predicate unless the operator
opts in. Also refuses the unmetered zkML/Spartan fast-paths by default.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 5: Gate the MCP surface

**Files:**
- Modify: `crates/hc-mcp/src/tools/discovery.rs` (`list_templates_impl` ~28, `list_all_templates_impl` ~8, `describe_template_impl` ~53)
- Modify: `crates/hc-mcp/src/tools/proving.rs` (`prove_template_impl` ~9)

- [ ] **Step 1: Write the failing test**

Append a test module to `crates/hc-mcp/src/tools/discovery.rs`:

```rust
#[cfg(test)]
mod honest_catalog_mcp_tests {
    #[test]
    fn mcp_allow_helper_defaults_false() {
        std::env::remove_var("HC_ALLOW_UNAUDITED_TEMPLATES");
        assert!(!super::allow_unaudited_templates());
    }

    #[test]
    fn mcp_default_listing_excludes_structure_only() {
        std::env::remove_var("HC_ALLOW_UNAUDITED_TEMPLATES");
        let allow = super::allow_unaudited_templates();
        let visible: Vec<String> = hc_workloads::list_all_templates()
            .into_iter()
            .filter(|t| hc_workloads::is_listable(t.enforcement, allow))
            .map(|t| t.id)
            .collect();
        assert!(visible.contains(&"accumulator_step".to_string()));
        assert!(!visible.contains(&"range_proof".to_string()));
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-mcp honest_catalog 2>&1 | tail -20`
Expected: FAIL to compile — `cannot find function allow_unaudited_templates` in `discovery.rs`.

- [ ] **Step 3: Write minimal implementation**

(5a) Add the env helper at the top of `crates/hc-mcp/src/tools/discovery.rs` (after the `use` lines, before `impl HcMcpServer {`):

```rust
/// See hc-server's identical helper: default-false gate for unaudited templates.
pub(crate) fn allow_unaudited_templates() -> bool {
    matches!(
        std::env::var("HC_ALLOW_UNAUDITED_TEMPLATES").as_deref(),
        Ok("true") | Ok("1")
    )
}
```

(5b) In `list_templates_impl`, filter the VM templates. Replace the `.iter()`-to-`.collect()` mapping so it filters and includes the marker:

```rust
        let allow = allow_unaudited_templates();
        let templates = hc_workloads::templates::list_templates();
        let listing: Vec<serde_json::Value> = templates
            .iter()
            .filter(|t| hc_workloads::is_listable(t.enforcement, allow))
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "summary": t.summary,
                    "tags": t.tags,
                    "cost": t.cost_category,
                    "enforcement": if matches!(t.enforcement, hc_workloads::Enforcement::Enforced) { "enforced" } else { "structure_only" },
                })
            })
            .collect();
```

(5c) In `list_all_templates_impl`, apply the same filter on the unified list:

```rust
        let allow = allow_unaudited_templates();
        let unified = hc_workloads::list_all_templates();
        let listing: Vec<serde_json::Value> = unified
            .iter()
            .filter(|t| hc_workloads::is_listable(t.enforcement, allow))
            .map(|t| {
                serde_json::json!({
                    "id": t.id,
                    "summary": t.summary,
                    "tags": t.tags,
                    "cost": t.cost_category,
                    "backend": t.backend,
                })
            })
            .collect();
```

(5d) In `describe_template_impl`, refuse hidden templates rather than describing them. Replace the `template_by_id(..).ok_or_else(..)?` lookup so a non-listable template returns the same "unknown" error:

```rust
        let allow = allow_unaudited_templates();
        let tmpl = hc_workloads::templates::template_by_id(&params.template_id)
            .filter(|t| hc_workloads::is_listable(t.enforcement, allow))
            .ok_or_else(|| {
                ErrorData::invalid_params(
                    format!(
                        "Unknown template '{}'. Call list_templates to see available options.",
                        params.template_id
                    ),
                    None,
                )
            })?;
```

(5e) In `crates/hc-mcp/src/tools/proving.rs`, gate `prove_template_impl`. At the very start of the function body (before the `build_from_template` call ~line 13), add:

```rust
        if !hc_workloads::is_dispatchable(
            &params.template_id,
            super::discovery::allow_unaudited_templates(),
        ) {
            return Err(ErrorData::invalid_params(
                format!(
                    "Template '{}' is not available in this deployment.",
                    params.template_id
                ),
                None,
            ));
        }
```

(`discovery` and `proving` are sibling modules under `tools` — confirmed in `crates/hc-mcp/src/tools/mod.rs` — so `super::discovery::allow_unaudited_templates()` resolves. `prove_template_impl` binds the id as `params.template_id` on `ProveTemplateParams`; insert this block as the first statement of the function body, before the existing `let build_result = ...` on line 13.)

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-mcp honest_catalog 2>&1 | tail -20`
Expected: PASS. Then `cargo build -p hc-mcp 2>&1 | tail -5` → success.

- [ ] **Step 5: Commit**

```bash
git add crates/hc-mcp/src/tools/discovery.rs crates/hc-mcp/src/tools/proving.rs
git commit -m "feat(mcp): hide+refuse unaudited templates by default

list_templates/list_all_templates/describe_template/prove_template honor
HC_ALLOW_UNAUDITED_TEMPLATES (default off), matching hc-server.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 6: Prod default-off config + document the env var

**Files:**
- Modify: `deploy/hetzner/docker-compose.prod.yml`
- Modify: `README.md` (server-config env table, ~lines 409-430)

- [ ] **Step 1: Confirm prod leaves the flag off**

Read `deploy/hetzner/docker-compose.prod.yml`. Confirm `HC_ALLOW_UNAUDITED_TEMPLATES` is NOT set in the `hc-server` (or `hc-mcp`) environment. Default-absent ⇒ helper returns false ⇒ unaudited templates hidden in production. If a stray setting exists, remove it. (No code; verification step.)

- [ ] **Step 2: Document the env var in README**

In `README.md`, add a row to the "Server configuration" table (the table around lines 409-430, before the `HC_MCP_*` rows):

```markdown
| `HC_ALLOW_UNAUDITED_TEMPLATES` | `false` | Expose/dispatch templates whose AIR does not yet enforce their named predicate (all except `accumulator_step`). Off in production; set `true` only for Phase-1B development. |
```

- [ ] **Step 3: Run the full workspace test + lint gate**

Run: `cargo test -p hc-workloads -p hc-server -p hc-mcp 2>&1 | tail -20`
Expected: PASS.
Run: `cargo clippy -p hc-workloads -p hc-server -p hc-mcp -- -D warnings 2>&1 | tail -20`
Expected: no warnings (matches the repo's CI gate).

- [ ] **Step 4: Commit**

```bash
git add deploy/hetzner/docker-compose.prod.yml README.md
git commit -m "docs(config): document HC_ALLOW_UNAUDITED_TEMPLATES; keep prod default-off

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Acceptance criteria (Phase 0.1a)

- With no env override (production default): `GET /templates` returns only `accumulator_step` (and any future enforced templates); `GET /templates/range_proof` → 404; `POST /prove/template/range_proof` → 403 `template_unavailable`; `POST /prove/template/zkml_matmul` and `spartan_r1cs` → 403; MCP `list_templates`/`list_all_templates` omit structure-only ids; MCP `prove_template` on a structure-only id is refused.
- `POST /prove/template/accumulator_step` continues to work end-to-end.
- With `HC_ALLOW_UNAUDITED_TEMPLATES=true`: all templates list (each carrying an `enforcement` marker) and dispatch as before — preserving the Phase-1B development path.
- `cargo test` (the three crates) and `cargo clippy -- -D warnings` pass.

## Out of scope (later sub-plans)

- 0.1b: customer-facing copy (README template tables, `site/`, `skills/tinyzkp-proofs/`, `deploy/server-card.json`), and marking `contracts/StarkVerifier.sol` non-functional.
- 0.2: G3 portal auth, G4 magic-link session, G10 `/metrics` auth.
- 0.3: G8 signup uniqueness, full G9 metering/caps, G12 underbill fix.
- 0.4: repo/infra hygiene (G15). 0.5: off-box backup (G13).

---

## Execution record (completed 2026-05-29, branch `roadmap/production-hardening`)

Implemented via subagent-driven development (fresh implementer → spec-compliance review → code-quality review per task, with fix loops). Code commits `71735be..8743fa6`. Final gates all green: `cargo test` (17 suites, 0 failures), `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`.

**Deviations from the plan as written, discovered during execution/review:**
- **`TemplateSummary` lives in `crates/hc-sdk/src/types.rs`** (not `hc-server`), so the `enforcement` field + `#[serde(default = "default_enforcement")]` landed there.
- **The env helper was centralized** into `hc-workloads` (`allow_unaudited_templates()`, re-exported) rather than duplicated per surface, so `hc-server` and `hc-mcp` share one parse of the flag.
- **[critical — caught by code-quality review] `/prove` (`prove_submit`) and `/prove/batch` were also ungated.** They accept a `template_id` and would have dispatched a StructureOnly template straight to the worker. Both are now gated (commit `4a876c4`). The plan's Task 4 had only covered `/prove/template/:id` + `/estimate`.
- **zkml/Spartan MCP impls pre-gated** (commit `8743fa6`) though not yet registered as tools, to remove a Phase-1B footgun; `template_detail` gained an `enforcement_for`-coverage invariant comment.

**Deferred (documented, non-blocking):** the env-helper unit test is not `serial`-isolated (no concurrent reader exists today, so it can't flake); `list_all_templates_impl` in hc-mcp is pre-existing dead code (gated for consistency, not registered).

**Net effect:** with `HC_ALLOW_UNAUDITED_TEMPLATES` unset (production default), only `accumulator_step` is listed / describable / dispatchable across the HTTP API **and** MCP; the five predicate-faking templates plus the zkml/Spartan previews are hidden and refused on every entry point (`/templates`, `/templates/:id`, `/prove`, `/prove/batch`, `/prove/template/:id`, `/estimate`, and the MCP `list_templates`/`describe_template`/`prove_template`). No cryptography was changed — this is the **truthful-surface half of audit finding G1**; the real per-template AIRs are Phase 1B.
