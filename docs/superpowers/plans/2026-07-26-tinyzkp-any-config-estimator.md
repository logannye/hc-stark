# TinyZKP Phase 0 + Phase 1a Implementation Plan — deck-clearing and the any-config estimator core

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Delete the retired hosted stack and the Guard SKU, then make TinyZKP's resource estimator run on *any* declared Plonky3 configuration — including configurations the prover cannot yet prove — exposed through `tinyzkp-engine estimate`.

**Architecture:** `estimate_air_pipeline` in `crates/hc-plonky3/src/bounded_prover.rs` is already a pure analytic cost model; it consults the live AIR only to derive four scalars (`width`, `quotient_chunks`, `public_values`, `has_next_row_columns`). All four are already declared fields on `WorkloadInputV1`. We extract a parameter-only core, prove it byte-identical to the AIR path on the two reference workloads, generalise it across field widths, and expose it behind a new estimate contract that does **not** reject out-of-profile configurations.

**Tech Stack:** Rust 1.95.0 (pinned), Plonky3 0.6.1 (exact-pinned), `serde`, `schemars` (JsonSchema), `clap` (CLI), `cargo test`.

## Global Constraints

- Rust toolchain is pinned to `1.95.0` by `rust-toolchain.toml`. Do not change it.
- Plonky3 is exact-pinned at `0.6.1`. Do not bump any `p3-*` dependency.
- The production compatibility profile string is `tinyzkp-p3-goldilocks-v1` (`tinyzkp_contracts::COMPATIBILITY_PROFILE`). Estimation may accept other profiles; **proving must not**.
- Never weaken `JobManifestV1::compatibility_reasons()`. Proving admission stays exactly as strict as it is today. Estimation gets a *separate* path.
- All new public contract types derive `Serialize, Deserialize, JsonSchema` and use `#[serde(deny_unknown_fields)]`, matching every existing type in `crates/tinyzkp-contracts/src/lib.rs`.
- No new network calls, telemetry, or file writes outside paths the caller passes in.
- Commit after every task. Never push to `main`; work on a branch and open a PR.
- Existing evidence values are ground truth. If a refactor changes any number in `release/evidence/backend-v1/`, the refactor is wrong.

## Operator prerequisites (Logan only — not agent tasks)

These are required for Phase 0 to be *complete* but cannot be done by an agent. Do them in parallel with Task 1.

- [ ] Check the Hetzner console: confirm whether CPX42 `46.225.78.136` is deleted or merely firewalled. If alive, delete it. Ports 22/80/443 are currently filtered, which is consistent with deletion but does not prove it.
- [ ] Publish the `backend-v0.1.0` GitHub release (currently a **draft**). It is the free MIT engine and is the entire top of funnel.
- [ ] Submit to `Plonky3/awesome-plonky3`.
- [ ] Add a forward-pointing banner to `logannye/space-efficient-zero-knowledge-proofs` (50 stars) directing readers to `hc-stark`.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `Cargo.toml` | workspace membership | Modify — drop retired crates |
| `crates/hc-server`, `hc-beta-api`, `hc-beta-worker`, `hc-beta-client`, `hc-mcp` | retired hosted stack | Delete |
| `billing/` | retired Stripe/subscription tooling | Delete |
| `crates/hc-plonky3/src/estimate_params.rs` | **new** — parameter-only analytic cost core | Create |
| `crates/hc-plonky3/src/bounded_prover.rs` | AIR-based estimation | Modify — delegate to the core |
| `crates/tinyzkp-contracts/src/lib.rs` | public contracts | Modify — add estimate request/response types |
| `crates/hc-cli/src/commands/estimate_config.rs` | **new** — `estimate` subcommand | Create |
| `crates/hc-cli/src/main.rs` | CLI dispatch | Modify — register subcommand |
| `site/pricing.html`, `site/guard.html`, `site/commerce.json` | Guard SKU copy | Modify — retire SKU |

---

### Task 1: Delete the retired hosted stack

The pivot retired hosted proving on 2026-07-17 (`release/hosted-beta-retirement-v1.json`). Roughly 20k LOC of server, beta-API, MCP, and Stripe billing code remains on `main` and must not be revived by the new design. Deleting it also clears the `legacy_obligations_resolved` launch gate.

**Files:**
- Delete: `crates/hc-server/`, `crates/hc-beta-api/`, `crates/hc-beta-worker/`, `crates/hc-beta-client/`, `crates/hc-mcp/`, `billing/`
- Modify: `Cargo.toml` (workspace members)
- Modify: `docker-compose.yml`, `Dockerfile` (drop retired services if referenced)

**Interfaces:**
- Consumes: nothing.
- Produces: a workspace that builds without the retired crates. No later task depends on any symbol from them.

- [ ] **Step 1: Confirm nothing surviving depends on the retired crates**

```bash
grep -rn "hc-server\|hc_server\|hc-beta\|hc_beta\|hc-mcp\|hc_mcp" \
  --include=Cargo.toml --include=*.rs \
  crates/hc-cli crates/hc-plonky3 crates/hc-stream crates/tinyzkp-contracts \
  crates/hc-workloads crates/hc-bench
```

Expected: no output. If anything prints, stop and report it — a surviving crate depends on a retired one and this task needs redesign.

- [ ] **Step 2: Record the current baseline so the deletion can be proven non-destructive**

```bash
cargo test -p tinyzkp-contracts -p hc-plonky3 -p hc-stream 2>&1 | tail -20
```

Expected: PASS. Note the test counts; Step 5 must match them.

- [ ] **Step 3: Delete the crates and billing directory**

```bash
git rm -r --quiet crates/hc-server crates/hc-beta-api crates/hc-beta-worker \
  crates/hc-beta-client crates/hc-mcp billing
```

- [ ] **Step 4: Remove them from the workspace**

In `Cargo.toml`, delete these five lines from `[workspace] members`:

```toml
    "crates/hc-server",
    "crates/hc-beta-api",
    "crates/hc-beta-worker",
    "crates/hc-beta-client",
    "crates/hc-mcp",
```

- [ ] **Step 5: Verify the workspace still builds and tests still pass**

```bash
cargo build --workspace 2>&1 | tail -5
cargo test -p tinyzkp-contracts -p hc-plonky3 -p hc-stream 2>&1 | tail -20
```

Expected: build succeeds; test counts match Step 2 exactly.

- [ ] **Step 6: Drop retired services from container config**

```bash
grep -n "hc-server\|hc-mcp\|billing" docker-compose.yml Dockerfile
```

Remove any service block, build stage, or `COPY` line naming a deleted path. If a file references nothing, leave it unchanged.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "Delete retired hosted stack

Hosted proving was retired 2026-07-17. Removes hc-server, hc-beta-api,
hc-beta-worker, hc-beta-client, hc-mcp, and billing/ so the new metered
design cannot accidentally revive them. Clears the legacy_obligations_resolved
launch gate. No surviving crate referenced any deleted symbol."
```

---

### Task 2: Retire the Guard SKU from the public site

Guard's `$499/mo` SKU is superseded. Its supervisor code (private repo `logannye/tinyzkp-guard`) will be reused internally in Plan 2, but the public offer goes away now so the site stops advertising a product that will never open.

**Files:**
- Modify: `site/pricing.html`
- Modify: `site/guard.html`
- Modify: `site/commerce.json`
- Test: `scripts/ci/` site-check scripts (discover the exact name in Step 1)

**Interfaces:**
- Consumes: nothing.
- Produces: a site with no purchasable Guard SKU. Plan 2 replaces these pages with estimator and proving copy.

- [ ] **Step 1: Find the site checks that assert on pricing copy**

```bash
ls scripts/ci/ | grep -i "site\|route\|pricing"
grep -rln "499\|4990\|Guard monthly\|Guard annual" scripts/ site/ | sort
```

Record every file that hardcodes `499` or `4990`. All of them must be updated together or CI will fail.

- [ ] **Step 2: Run the site checks to capture the current passing baseline**

```bash
python3 scripts/ci/site_route_check.py 2>&1 | tail -20
```

Expected: PASS. (If the script has a different name, use the one found in Step 1.)

- [ ] **Step 3: Replace the Guard offer in `site/pricing.html`**

Replace the Guard subscription card's price block and CTA with a superseded notice. Keep the Community card exactly as-is.

```html
<section class="tier" id="guard">
  <h2>TinyZKP Guard</h2>
  <p class="status">Withdrawn</p>
  <p>
    The Guard subscription is no longer offered. TinyZKP is moving to a
    metered proving utility priced per unit of trace, with a free resource
    estimator that runs on any Plonky3 configuration.
  </p>
  <p>The MIT engine, verifier, schemas, and doctor remain free.</p>
</section>
```

- [ ] **Step 4: Set the commerce contract to withdrawn**

In `site/commerce.json`, change these three fields (leave every other field untouched so the fail-closed derivation still validates):

```json
  "checkout_enabled": false,
  "commerce_state": "withdrawn",
  "mode": "withdrawn",
```

- [ ] **Step 5: Update `site/guard.html` to a superseded notice**

Replace the page body's offer content with the same withdrawn language used in Step 3. Do not delete the file — inbound links and the sitemap reference it.

- [ ] **Step 6: Update every other file found in Step 1**

For each remaining file that hardcodes `499` or `4990`, remove the price assertion or update the expected copy to match Steps 3–5.

- [ ] **Step 7: Run the site checks**

```bash
python3 scripts/ci/site_route_check.py 2>&1 | tail -20
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add site scripts
git commit -m "Retire the Guard subscription SKU

Guard's local-supervisor offer is superseded by the metered proving utility.
The supervisor code is retained privately for internal fleet reuse; only the
public offer is withdrawn. Community tier is unchanged."
```

---

### Task 3: Extract the parameter-only estimator core

This is the keystone. `estimate_air_pipeline` consults the AIR only for `width`, `quotient_chunks`, `public_values`, and `has_next_row_columns`. Extracting a core that takes those as plain numbers makes estimation possible for configurations we cannot prove — without touching a single byte of the arithmetic.

The test is a **parity test**: for the two reference workloads, the new core must return results byte-identical to the AIR path. This guarantees the refactor cannot silently change any published evidence number.

**Files:**
- Create: `crates/hc-plonky3/src/estimate_params.rs`
- Modify: `crates/hc-plonky3/src/bounded_prover.rs:427-500` (`estimate_air_pipeline`)
- Modify: `crates/hc-plonky3/src/lib.rs` (register the module)
- Test: `crates/hc-plonky3/src/estimate_params.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `ResourceEstimate` and `ResourcePolicyV1` from `hc_stream`, already imported by `bounded_prover.rs`.
- Produces:
  - `pub struct EstimateParams { pub workload_id: String, pub rows: u64, pub width: u64, pub quotient_chunks: u64, pub public_values: u64, pub has_next_row_columns: bool, pub field_bytes: u64, pub ext_field_bytes: u64, pub digest_bytes: u64 }`
  - `pub fn estimate_from_params(params: &EstimateParams, policy: &ResourcePolicyV1) -> Result<ResourceEstimate, BoundedProverError>`
  - Task 4 generalises the byte-width fields; Task 5 constructs `EstimateParams` from declared config; Task 6 calls it from the CLI.

- [ ] **Step 1: Write the failing parity test**

Create `crates/hc-plonky3/src/estimate_params.rs` with only the test module for now:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::bounded_prover::{estimate_air_pipeline_for_test, params_for_workload_for_test};
    use crate::workloads::{FibonacciWorkload, Poseidon2Workload};

    /// The parameter-only core must reproduce the AIR-driven estimator exactly.
    /// Any divergence would change published evidence in
    /// release/evidence/backend-v1/, so this is byte-equality, not a tolerance.
    #[test]
    fn params_core_matches_air_pipeline_for_reference_workloads() {
        let policy = crate::test_support::release_policy_2gib();

        let fib = FibonacciWorkload::new(1 << 20);
        let via_air = estimate_air_pipeline_for_test(&fib, &policy).unwrap();
        let via_params =
            estimate_from_params(&params_for_workload_for_test(&fib), &policy).unwrap();
        assert_eq!(via_air, via_params, "fibonacci 1M estimate diverged");

        let pos = Poseidon2Workload::new(1 << 20);
        let via_air = estimate_air_pipeline_for_test(&pos, &policy).unwrap();
        let via_params =
            estimate_from_params(&params_for_workload_for_test(&pos), &policy).unwrap();
        assert_eq!(via_air, via_params, "poseidon2 1M estimate diverged");
    }

    /// Row count is the only free variable in the published scaling evidence,
    /// so the core must track it across the full release range.
    #[test]
    fn params_core_matches_air_pipeline_across_row_scale() {
        let policy = crate::test_support::release_policy_2gib();
        for log_rows in 10..=24 {
            let fib = FibonacciWorkload::new(1u64 << log_rows);
            let via_air = estimate_air_pipeline_for_test(&fib, &policy).unwrap();
            let via_params =
                estimate_from_params(&params_for_workload_for_test(&fib), &policy).unwrap();
            assert_eq!(via_air, via_params, "diverged at 2^{log_rows} rows");
        }
    }
}
```

**Note on names:** `estimate_air_pipeline_for_test`, `params_for_workload_for_test`, and `test_support::release_policy_2gib` do not exist yet — Steps 3 and 4 create them. The exact workload constructor names may differ; discover them with `grep -n "pub struct .*Workload" crates/hc-plonky3/src/workloads.rs` and use the real ones.

- [ ] **Step 2: Register the module and run the test to verify it fails**

Add to `crates/hc-plonky3/src/lib.rs`:

```rust
pub mod estimate_params;
```

Run:

```bash
cargo test -p hc-plonky3 estimate_params 2>&1 | tail -20
```

Expected: FAIL to compile — `estimate_from_params` not found.

- [ ] **Step 3: Move the arithmetic into the parameter core**

In `crates/hc-plonky3/src/estimate_params.rs`, above the test module, add the struct and function. Copy the body of `estimate_air_pipeline` (`bounded_prover.rs:427-500` and its continuation) **verbatim**, replacing only the four AIR-derived values with `params` fields. Do not "improve" any arithmetic.

```rust
use crate::bounded_prover::BoundedProverError;
use hc_stream::{ResourceEstimate, ResourcePolicyV1};

/// Every scalar the analytic cost model needs. Deliberately contains no AIR
/// and no field type, so it can describe a configuration TinyZKP cannot prove.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EstimateParams {
    pub workload_id: String,
    pub rows: u64,
    pub width: u64,
    pub quotient_chunks: u64,
    pub public_values: u64,
    pub has_next_row_columns: bool,
    /// Bytes per base-field element. Goldilocks = 8.
    pub field_bytes: u64,
    /// Bytes per extension-field element. Goldilocks degree 2 = 16.
    pub ext_field_bytes: u64,
    /// Bytes per Merkle digest. Poseidon2 256-bit = 32.
    pub digest_bytes: u64,
}

pub fn estimate_from_params(
    params: &EstimateParams,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate, BoundedProverError> {
    if params.rows == 0 || !params.rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    // Body copied verbatim from estimate_air_pipeline, substituting:
    //   width           -> params.width
    //   quotient_chunks -> params.quotient_chunks
    //   rows            -> params.rows
    //   public_values   -> params.public_values
    //   air.main_next_row_columns().is_empty() -> !params.has_next_row_columns
    //   literal 8  -> params.field_bytes
    //   literal 16 -> params.ext_field_bytes
    //   literal 32 -> params.digest_bytes
    todo!("paste the verbatim body here")
}
```

Replace the `todo!` with the actual copied body. The literal substitutions are what Task 4 depends on, so make them now even though Goldilocks values are unchanged.

- [ ] **Step 4: Reduce `estimate_air_pipeline` to a thin wrapper and add the test hooks**

In `bounded_prover.rs`, replace the body of `estimate_air_pipeline` with parameter derivation plus a call to the core:

```rust
fn estimate_air_pipeline<A>(
    air: &A,
    workload_id: &str,
    public_values: usize,
    rows: usize,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate>
where
    A: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let width = BaseAir::<Val>::width(air);
    let params = crate::estimate_params::EstimateParams {
        workload_id: workload_id.to_string(),
        rows: rows as u64,
        width: width as u64,
        quotient_chunks: quotient_chunks(air, width, public_values)?,
        public_values: public_values as u64,
        has_next_row_columns: !air.main_next_row_columns().is_empty(),
        field_bytes: 8,
        ext_field_bytes: 16,
        digest_bytes: 32,
    };
    crate::estimate_params::estimate_from_params(&params, policy)
}

#[cfg(test)]
pub(crate) fn estimate_air_pipeline_for_test<W>(
    workload: &W,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    estimate_resource_bounded_workload(workload, policy)
}

#[cfg(test)]
pub(crate) fn params_for_workload_for_test<W>(workload: &W) -> crate::estimate_params::EstimateParams
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let air = workload.air();
    let width = BaseAir::<Val>::width(&air);
    let public_values = air.num_public_values();
    crate::estimate_params::EstimateParams {
        workload_id: workload.identity().id.to_string(),
        rows: workload.rows(),
        width: width as u64,
        quotient_chunks: quotient_chunks(&air, width, public_values).unwrap(),
        public_values: public_values as u64,
        has_next_row_columns: !air.main_next_row_columns().is_empty(),
        field_bytes: 8,
        ext_field_bytes: 16,
        digest_bytes: 32,
    }
}
```

Add a `test_support` helper in `crates/hc-plonky3/src/lib.rs`:

```rust
#[cfg(test)]
pub(crate) mod test_support {
    use hc_stream::ResourcePolicyV1;

    /// The 2 GiB ceiling used by examples/plonky3/fibonacci-1m.json and
    /// fibonacci-16m.json, so tests exercise the published release policy.
    pub fn release_policy_2gib() -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            max_resident_bytes: 2 * 1024 * 1024 * 1024,
            ..Default::default()
        }
    }
}
```

If `ResourcePolicyV1` has no `Default`, construct it explicitly by copying the field values from `examples/plonky3/fibonacci-1m.json`.

- [ ] **Step 5: Run the parity tests**

```bash
cargo test -p hc-plonky3 estimate_params 2>&1 | tail -20
```

Expected: PASS, both tests. If they fail, a literal was substituted incorrectly — diff the core body against git history for `estimate_air_pipeline`.

- [ ] **Step 6: Run the full crate suite to confirm no evidence number moved**

```bash
cargo test -p hc-plonky3 2>&1 | tail -20
```

Expected: PASS with the same counts as before the refactor. The existing `scratch_estimates_track_multiple_release_scale_powers` and `full_pipeline_scratch_estimates_track_small_measured_peaks` tests are the real guard here — they pin estimates against measured peaks.

- [ ] **Step 7: Commit**

```bash
git add crates/hc-plonky3/src/estimate_params.rs crates/hc-plonky3/src/bounded_prover.rs crates/hc-plonky3/src/lib.rs
git commit -m "Extract parameter-only estimator core

estimate_air_pipeline consulted the AIR only for width, quotient_chunks,
public_values, and has_next_row_columns. All four are declarable, so the
arithmetic is now reachable without an AIR - the prerequisite for estimating
configurations TinyZKP cannot prove.

Arithmetic is copied verbatim and pinned by a byte-equality parity test
across 2^10..2^24 rows, so no published evidence value can move."
```

---

### Task 4: Generalise the core across field widths

Goldilocks is 8 bytes per element; BabyBear and KoalaBear are 4. The demand signal we want from Phase 1 is precisely "who is asking about BabyBear multi-table configs", so the estimator must produce honest numbers for fields we cannot prove.

**Files:**
- Modify: `crates/hc-plonky3/src/estimate_params.rs`
- Test: `crates/hc-plonky3/src/estimate_params.rs` (`mod tests`)

**Interfaces:**
- Consumes: `EstimateParams` and `estimate_from_params` from Task 3.
- Produces: `pub fn field_widths(field: &str, extension_degree: u8) -> Option<(u64, u64)>` returning `(field_bytes, ext_field_bytes)`. Task 5 uses it to build `EstimateParams` from a declared config string.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/hc-plonky3/src/estimate_params.rs`:

```rust
#[test]
fn known_field_widths_are_resolved() {
    assert_eq!(field_widths("goldilocks", 2), Some((8, 16)));
    assert_eq!(field_widths("babybear", 4), Some((4, 16)));
    assert_eq!(field_widths("koalabear", 4), Some((4, 16)));
    assert_eq!(field_widths("mersenne31", 4), Some((4, 16)));
}

#[test]
fn unknown_field_is_rejected_rather_than_guessed() {
    assert_eq!(field_widths("bn254", 1), None);
    assert_eq!(field_widths("goldilocks", 7), None);
}

/// A 4-byte base field must produce a strictly smaller trace footprint than
/// an 8-byte one at identical shape. This is the property that makes
/// cross-field estimates meaningful rather than decorative.
#[test]
fn narrower_field_yields_smaller_estimate() {
    let policy = crate::test_support::release_policy_2gib();
    let base = EstimateParams {
        workload_id: "synthetic".to_string(),
        rows: 1 << 20,
        width: 64,
        quotient_chunks: 2,
        public_values: 4,
        has_next_row_columns: true,
        field_bytes: 8,
        ext_field_bytes: 16,
        digest_bytes: 32,
    };
    let narrow = EstimateParams { field_bytes: 4, ..base.clone() };

    let wide_est = estimate_from_params(&base, &policy).unwrap();
    let narrow_est = estimate_from_params(&narrow, &policy).unwrap();

    assert!(
        narrow_est.scratch_high_water_bytes < wide_est.scratch_high_water_bytes,
        "4-byte field {} should need less scratch than 8-byte {}",
        narrow_est.scratch_high_water_bytes,
        wide_est.scratch_high_water_bytes
    );
}
```

- [ ] **Step 2: Run to verify failure**

```bash
cargo test -p hc-plonky3 estimate_params 2>&1 | tail -20
```

Expected: FAIL to compile — `field_widths` not found.

- [ ] **Step 3: Implement `field_widths`**

Add to `crates/hc-plonky3/src/estimate_params.rs`:

```rust
/// Base and extension element widths in bytes for fields Plonky3 ships.
/// Returns None for anything unrecognised: an estimate built on a guessed
/// element width would be worse than no estimate.
pub fn field_widths(field: &str, extension_degree: u8) -> Option<(u64, u64)> {
    let base: u64 = match field {
        "goldilocks" => 8,
        "babybear" | "koalabear" | "mersenne31" => 4,
        _ => return None,
    };
    if !(1..=8).contains(&extension_degree) {
        return None;
    }
    Some((base, base * extension_degree as u64))
}
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p hc-plonky3 estimate_params 2>&1 | tail -20
```

Expected: PASS, all five tests. If `narrower_field_yields_smaller_estimate` fails, Task 3 Step 3 missed a literal `8` — find it by grepping the core for bare `8`, `16`, and `32`.

- [ ] **Step 5: Confirm the Goldilocks parity tests still hold**

```bash
cargo test -p hc-plonky3 2>&1 | tail -20
```

Expected: PASS. The Task 3 parity tests must be unaffected — `field_widths("goldilocks", 2)` returns exactly the literals they pinned.

- [ ] **Step 6: Commit**

```bash
git add crates/hc-plonky3/src/estimate_params.rs
git commit -m "Generalise estimator core across field widths

Adds field_widths for goldilocks, babybear, koalabear, and mersenne31 so the
estimator produces honest numbers for fields the prover does not support.
Unknown fields return None rather than a guessed element width. Goldilocks
parity with the AIR path is unchanged."
```

---

### Task 5: Add estimate contracts that accept out-of-profile configs

`JobManifestV1::compatibility_reasons()` rejects unsupported fields, widths, and AIR features — correctly, for proving. Estimation needs the opposite: accept the config, compute the cost, and *report* which features would block proving. This separation is the whole product.

**Files:**
- Modify: `crates/tinyzkp-contracts/src/lib.rs`
- Test: `crates/tinyzkp-contracts/src/lib.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `AirFeaturesV1`, `ReasonV1`, `ReasonCodeV1`, `ResourceEstimatesV1`, `COMPATIBILITY_PROFILE` — all already in this file.
- Produces:
  - `pub struct EstimateRequestV1 { pub schema_version: u32, pub field: String, pub extension_degree: u8, pub logical_rows: u64, pub trace_width: u32, pub max_constraint_degree: u8, pub public_values: u32, pub has_next_row_columns: bool, pub features: AirFeaturesV1, pub ram_budget_bytes: u64 }`
  - `pub struct EstimateResponseV1 { pub schema_version: u32, pub request_digest: String, pub provable_today: bool, pub blocking_reasons: Vec<ReasonV1>, pub estimates: ResourceEstimatesV1 }`
  - `impl EstimateRequestV1 { pub fn blocking_reasons(&self) -> Vec<ReasonV1>; pub fn digest(&self) -> String; pub fn quotient_chunks(&self) -> u64 }`
  - Task 6 consumes all of these.

- [ ] **Step 1: Write the failing tests**

Append to the `tests` module in `crates/tinyzkp-contracts/src/lib.rs`:

```rust
fn babybear_multi_table_request() -> EstimateRequestV1 {
    EstimateRequestV1 {
        schema_version: 1,
        field: "babybear".to_string(),
        extension_degree: 4,
        logical_rows: 1 << 22,
        trace_width: 180,
        max_constraint_degree: 3,
        public_values: 8,
        has_next_row_columns: true,
        features: AirFeaturesV1 {
            uses_lookups: true,
            uses_buses: false,
            uses_permutations: false,
            uses_multi_table: true,
            uses_preprocessed_columns: false,
            uses_periodic_columns: false,
            uses_recursion: false,
            uses_gpu: false,
        },
        ram_budget_bytes: 2 * 1024 * 1024 * 1024,
    }
}

/// The product thesis: an SP1-shaped config we cannot prove must still be
/// estimable, and must say precisely why proving is blocked.
#[test]
fn out_of_profile_request_is_estimable_and_reports_blockers() {
    let request = babybear_multi_table_request();
    let reasons = request.blocking_reasons();

    assert!(!reasons.is_empty(), "babybear multi-table must be blocked for proving");
    assert!(
        reasons.iter().any(|r| r.code == ReasonCodeV1::UnsupportedProfile),
        "non-goldilocks field must raise UnsupportedProfile"
    );
    assert!(
        reasons.iter().any(|r| r.code == ReasonCodeV1::UnsupportedAirFeature),
        "lookups and multi-table must raise UnsupportedAirFeature"
    );
    assert!(reasons.iter().all(|r| r.validate()), "every reason must validate");
}

#[test]
fn in_profile_request_has_no_blockers() {
    let request = EstimateRequestV1 {
        schema_version: 1,
        field: FIELD.to_string(),
        extension_degree: EXTENSION_DEGREE,
        logical_rows: 1 << 20,
        trace_width: 3,
        max_constraint_degree: 3,
        public_values: 3,
        has_next_row_columns: true,
        features: AirFeaturesV1 {
            uses_lookups: false,
            uses_buses: false,
            uses_permutations: false,
            uses_multi_table: false,
            uses_preprocessed_columns: false,
            uses_periodic_columns: false,
            uses_recursion: false,
            uses_gpu: false,
        },
        ram_budget_bytes: 2 * 1024 * 1024 * 1024,
    };
    assert!(request.blocking_reasons().is_empty());
}

/// The digest is the demand-aggregation key: identical shapes must collide,
/// different shapes must not.
#[test]
fn digest_is_stable_and_shape_sensitive() {
    let a = babybear_multi_table_request();
    let b = babybear_multi_table_request();
    assert_eq!(a.digest(), b.digest());

    let mut c = babybear_multi_table_request();
    c.trace_width = 181;
    assert_ne!(a.digest(), c.digest());
}

/// Rows never change the AIR shape, so they must not change the digest -
/// otherwise every row count looks like separate demand.
#[test]
fn digest_ignores_row_count() {
    let a = babybear_multi_table_request();
    let mut b = babybear_multi_table_request();
    b.logical_rows = 1 << 23;
    assert_eq!(a.digest(), b.digest());
}

#[test]
fn quotient_chunks_are_derived_from_declared_degree() {
    let mut r = babybear_multi_table_request();
    r.max_constraint_degree = 3;
    assert_eq!(r.quotient_chunks(), 2);
    r.max_constraint_degree = 2;
    assert_eq!(r.quotient_chunks(), 1);
}
```

**Note on `quotient_chunks_are_derived_from_declared_degree`:** the hypothesis is `quotient_degree = max_constraint_degree - 1`, `chunks = quotient_degree.next_power_of_two()`. Verify it against the real AIR-derived value before trusting it:

```bash
cargo test -p hc-plonky3 estimate_params -- --nocapture 2>&1 | tail -20
```

Compare `params_for_workload_for_test(&FibonacciWorkload::new(1 << 20)).quotient_chunks` with what the formula gives for Fibonacci's declared degree. If they disagree, fix the expected values in this test to match the AIR — the AIR is ground truth, not the formula.

- [ ] **Step 2: Run to verify failure**

```bash
cargo test -p tinyzkp-contracts 2>&1 | tail -20
```

Expected: FAIL to compile — `EstimateRequestV1` not found.

- [ ] **Step 3: Implement the contract types**

Add to `crates/tinyzkp-contracts/src/lib.rs`, near `ResourceEstimatesV1`:

```rust
/// A configuration to be costed. Unlike JobManifestV1 this describes shape
/// only: no paths, no witness, no AIR package. It may describe a
/// configuration TinyZKP cannot prove.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EstimateRequestV1 {
    pub schema_version: u32,
    pub field: String,
    pub extension_degree: u8,
    pub logical_rows: u64,
    pub trace_width: u32,
    pub max_constraint_degree: u8,
    pub public_values: u32,
    pub has_next_row_columns: bool,
    pub features: AirFeaturesV1,
    pub ram_budget_bytes: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EstimateResponseV1 {
    pub schema_version: u32,
    /// Shape-only key for aggregating demand across callers. Excludes rows.
    pub request_digest: String,
    pub provable_today: bool,
    pub blocking_reasons: Vec<ReasonV1>,
    pub estimates: ResourceEstimatesV1,
}

impl EstimateRequestV1 {
    /// Reasons this config could not be PROVED today. Estimation itself is
    /// never blocked by these; they are reported, not enforced.
    pub fn blocking_reasons(&self) -> Vec<ReasonV1> {
        let mut reasons = Vec::new();
        if self.field != FIELD
            || self.extension_degree != EXTENSION_DEGREE
            || !(MIN_ROWS..=MAX_ROWS).contains(&self.logical_rows)
            || !self.logical_rows.is_power_of_two()
            || !(1..=MAX_TRACE_WIDTH).contains(&self.trace_width)
            || !(1..=MAX_CONSTRAINT_DEGREE).contains(&self.max_constraint_degree)
        {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::UnsupportedProfile).profiles(
                    Some(ProfileIdentifierV1::TinyzkpP3GoldilocksV1),
                    Some(ProfileIdentifierV1::Other),
                ),
            );
        }
        if self.features.has_unsupported_enabled() {
            push_unique(
                &mut reasons,
                ReasonV1::new(ReasonCodeV1::UnsupportedAirFeature),
            );
        }
        reasons
    }

    /// Quotient chunk count implied by the declared constraint degree.
    pub fn quotient_chunks(&self) -> u64 {
        let quotient_degree = u64::from(self.max_constraint_degree).saturating_sub(1).max(1);
        quotient_degree.next_power_of_two()
    }

    /// Stable shape key. Row count is deliberately excluded so that the same
    /// AIR probed at different sizes aggregates as one demand signal.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(self.field.as_bytes());
        hasher.update(self.extension_degree.to_le_bytes());
        hasher.update(self.trace_width.to_le_bytes());
        hasher.update(self.max_constraint_degree.to_le_bytes());
        hasher.update(self.public_values.to_le_bytes());
        hasher.update([u8::from(self.has_next_row_columns)]);
        for flag in [
            self.features.uses_lookups,
            self.features.uses_buses,
            self.features.uses_permutations,
            self.features.uses_multi_table,
            self.features.uses_preprocessed_columns,
            self.features.uses_periodic_columns,
            self.features.uses_recursion,
            self.features.uses_gpu,
        ] {
            hasher.update([u8::from(flag)]);
        }
        format!("{:x}", hasher.finalize())
    }
}
```

If `sha2` is not already a dependency of `tinyzkp-contracts`, add it to that crate's `Cargo.toml` using the exact version already in `Cargo.lock`:

```bash
grep -A2 '^name = "sha2"' Cargo.lock
```

- [ ] **Step 4: Run the tests**

```bash
cargo test -p tinyzkp-contracts 2>&1 | tail -20
```

Expected: PASS, all five new tests plus the existing suite.

- [ ] **Step 5: Regenerate published schemas if the crate emits them**

```bash
grep -rn "EstimateRequestV1\|PUBLIC_SCHEMA_NAMES" crates/tinyzkp-contracts/src/lib.rs | head
```

If `PUBLIC_SCHEMA_NAMES` drives schema emission, add `"estimate-request-v1.schema.json"` and `"estimate-response-v1.schema.json"`, then regenerate and re-run:

```bash
cargo test -p tinyzkp-contracts 2>&1 | tail -20
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/tinyzkp-contracts
git commit -m "Add estimate contracts that accept out-of-profile configs

EstimateRequestV1 describes AIR shape only - no paths, no witness, no AIR
package - and may describe configurations TinyZKP cannot prove.
blocking_reasons reports why proving is blocked without preventing the
estimate. JobManifestV1 admission is unchanged, so proving stays exactly as
strict as before.

request_digest excludes row count so one AIR probed at several sizes
aggregates as a single demand signal."
```

---

### Task 6: Expose `tinyzkp-engine estimate`

Turns the core into something a stranger can run against their own config. This is the artifact Plan 2's hosted API wraps.

**Files:**
- Create: `crates/hc-cli/src/commands/estimate_config.rs`
- Modify: `crates/hc-cli/src/main.rs`
- Modify: `crates/hc-cli/src/commands/mod.rs`
- Test: `crates/hc-cli/tests/estimate_config.rs`

**Interfaces:**
- Consumes: `EstimateRequestV1`, `EstimateResponseV1` (Task 5); `EstimateParams`, `estimate_from_params`, `field_widths` (Tasks 3–4).
- Produces: `pub fn run(config_path: &Path) -> anyhow::Result<EstimateResponseV1>`. Plan 2 calls this same function from the serverless handler.

- [ ] **Step 1: Write the failing integration test**

Create `crates/hc-cli/tests/estimate_config.rs`:

```rust
use std::io::Write;

fn write_config(json: &str) -> tempfile::NamedTempFile {
    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(json.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

const BABYBEAR_MULTI_TABLE: &str = r#"{
  "schema_version": 1,
  "field": "babybear",
  "extension_degree": 4,
  "logical_rows": 4194304,
  "trace_width": 180,
  "max_constraint_degree": 3,
  "public_values": 8,
  "has_next_row_columns": true,
  "features": {
    "uses_lookups": true,
    "uses_buses": false,
    "uses_permutations": false,
    "uses_multi_table": true,
    "uses_preprocessed_columns": false,
    "uses_periodic_columns": false,
    "uses_recursion": false,
    "uses_gpu": false
  },
  "ram_budget_bytes": 2147483648
}"#;

/// The product in one test: a config we cannot prove still returns real
/// numbers, flagged as unprovable.
#[test]
fn estimates_a_config_that_cannot_be_proved() {
    let cfg = write_config(BABYBEAR_MULTI_TABLE);
    let response = hc_cli::commands::estimate_config::run(cfg.path()).unwrap();

    assert!(!response.provable_today);
    assert!(!response.blocking_reasons.is_empty());
    assert!(response.estimates.bounded.peak_resident_bytes > 0);
    assert!(response.estimates.conventional.peak_resident_bytes > 0);
    assert!(!response.request_digest.is_empty());
}

/// The headline claim must be visible in the output: bounded mode needs
/// materially less resident memory than conventional.
#[test]
fn bounded_estimate_is_below_conventional() {
    let cfg = write_config(BABYBEAR_MULTI_TABLE);
    let response = hc_cli::commands::estimate_config::run(cfg.path()).unwrap();
    assert!(
        response.estimates.bounded.peak_resident_bytes
            < response.estimates.conventional.peak_resident_bytes,
        "bounded {} must be below conventional {}",
        response.estimates.bounded.peak_resident_bytes,
        response.estimates.conventional.peak_resident_bytes
    );
}

#[test]
fn unknown_field_is_rejected_with_a_clear_error() {
    let cfg = write_config(&BABYBEAR_MULTI_TABLE.replace("babybear", "bn254"));
    let err = hc_cli::commands::estimate_config::run(cfg.path()).unwrap_err();
    assert!(
        err.to_string().contains("bn254"),
        "error must name the unsupported field, got: {err}"
    );
}

#[test]
fn malformed_config_is_rejected() {
    let cfg = write_config("{ not json");
    assert!(hc_cli::commands::estimate_config::run(cfg.path()).is_err());
}
```

Ensure `tempfile` is a dev-dependency of `hc-cli`:

```bash
grep -n "tempfile" crates/hc-cli/Cargo.toml
```

If absent, add it under `[dev-dependencies]` at the version already in `Cargo.lock`.

- [ ] **Step 2: Run to verify failure**

```bash
cargo test -p hc-cli --test estimate_config 2>&1 | tail -20
```

Expected: FAIL to compile — `estimate_config` not found.

- [ ] **Step 3: Implement the command**

Create `crates/hc-cli/src/commands/estimate_config.rs`:

```rust
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use hc_plonky3::estimate_params::{estimate_from_params, field_widths, EstimateParams};
use hc_stream::ResourcePolicyV1;
use tinyzkp_contracts::{
    EstimateRequestV1, EstimateResponseV1, ResourceEstimateV1, ResourceEstimatesV1,
};

/// Cost a declared configuration. Never proves, never reads a witness, and
/// never rejects a config merely because TinyZKP cannot prove it.
pub fn run(config_path: &Path) -> Result<EstimateResponseV1> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let request: EstimateRequestV1 =
        serde_json::from_str(&raw).context("parsing estimate request")?;

    let (field_bytes, ext_field_bytes) =
        field_widths(&request.field, request.extension_degree).ok_or_else(|| {
            anyhow!(
                "unsupported field '{}' with extension degree {}: \
                 element width is unknown, so no honest estimate is possible",
                request.field,
                request.extension_degree
            )
        })?;

    let params = EstimateParams {
        workload_id: request.digest(),
        rows: request.logical_rows,
        width: u64::from(request.trace_width),
        quotient_chunks: request.quotient_chunks(),
        public_values: u64::from(request.public_values),
        has_next_row_columns: request.has_next_row_columns,
        field_bytes,
        ext_field_bytes,
        digest_bytes: 32,
    };

    let bounded_policy = ResourcePolicyV1 {
        max_resident_bytes: request.ram_budget_bytes,
        ..policy_defaults()
    };
    let bounded = estimate_from_params(&params, &bounded_policy)
        .map_err(|e| anyhow!("bounded estimate failed: {e:?}"))?;

    // Conventional holds every vector resident, so it is the same shape with
    // an effectively unbounded ceiling.
    let conventional_policy = ResourcePolicyV1 {
        max_resident_bytes: u64::MAX,
        ..policy_defaults()
    };
    let conventional = estimate_from_params(&params, &conventional_policy)
        .map_err(|e| anyhow!("conventional estimate failed: {e:?}"))?;

    let blocking_reasons = request.blocking_reasons();
    Ok(EstimateResponseV1 {
        schema_version: 1,
        request_digest: request.digest(),
        provable_today: blocking_reasons.is_empty(),
        blocking_reasons,
        estimates: ResourceEstimatesV1 {
            bounded: to_contract(bounded),
            conventional: to_contract(conventional),
        },
    })
}

fn policy_defaults() -> ResourcePolicyV1 {
    // Mirrors examples/plonky3/fibonacci-1m.json apart from the ceiling.
    ResourcePolicyV1::default()
}

fn to_contract(e: hc_stream::ResourceEstimate) -> ResourceEstimateV1 {
    ResourceEstimateV1 {
        peak_resident_bytes: e.peak_resident_bytes,
        scratch_high_water_bytes: e.scratch_high_water_bytes,
        total_read_bytes: e.total_read_bytes,
        total_write_bytes: e.total_write_bytes,
    }
}
```

If `ResourcePolicyV1` has no `Default`, replace `policy_defaults` with an explicit constructor copying field values from `examples/plonky3/fibonacci-1m.json`. If `hc_stream::ResourceEstimate` field names differ from `ResourceEstimateV1`, adjust `to_contract` — check with `sed -n '99,113p' crates/hc-stream/src/lib.rs`.

Register the module in `crates/hc-cli/src/commands/mod.rs`:

```rust
pub mod estimate_config;
```

Confirm `crates/hc-cli/src/main.rs` exposes a library target so integration tests can call `hc_cli::commands::...`. If `hc-cli` is binary-only, add `src/lib.rs` re-exporting `pub mod commands;` and add `[lib] name = "hc_cli"` to its `Cargo.toml`.

- [ ] **Step 4: Run the tests**

```bash
cargo test -p hc-cli --test estimate_config 2>&1 | tail -20
```

Expected: PASS, all four tests.

- [ ] **Step 5: Wire the subcommand**

In `crates/hc-cli/src/main.rs`, add to `enum Commands` (alongside the existing `EstimateAir` variant):

```rust
    /// Estimate resources for a declared Plonky3 configuration.
    /// Works on configurations TinyZKP cannot prove.
    Estimate {
        #[arg(long)]
        config: std::path::PathBuf,
    },
```

And in the dispatch `match`:

```rust
        Commands::Estimate { config } => {
            let response = commands::estimate_config::run(&config)?;
            println!("{}", serde_json::to_string_pretty(&response)?);
            Ok(())
        }
```

- [ ] **Step 6: Verify end to end from the command line**

```bash
cat > /tmp/sp1-shaped.json <<'JSON'
{
  "schema_version": 1,
  "field": "babybear",
  "extension_degree": 4,
  "logical_rows": 4194304,
  "trace_width": 180,
  "max_constraint_degree": 3,
  "public_values": 8,
  "has_next_row_columns": true,
  "features": {
    "uses_lookups": true, "uses_buses": false, "uses_permutations": false,
    "uses_multi_table": true, "uses_preprocessed_columns": false,
    "uses_periodic_columns": false, "uses_recursion": false, "uses_gpu": false
  },
  "ram_budget_bytes": 2147483648
}
JSON
cargo run -p hc-cli -- estimate --config /tmp/sp1-shaped.json
```

Expected: pretty-printed JSON with `"provable_today": false`, a non-empty `blocking_reasons`, and non-zero bounded and conventional estimates.

- [ ] **Step 7: Run the full workspace suite**

```bash
cargo test --workspace 2>&1 | tail -20
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/hc-cli
git commit -m "Add tinyzkp-engine estimate for arbitrary configs

Costs a declared Plonky3 configuration without proving it and without
reading a witness, reporting bounded and conventional estimates plus the
reasons proving is blocked. This is the free top-of-funnel surface and the
function the hosted estimator API will wrap.

Unknown fields are refused rather than estimated with a guessed element
width."
```

---

## Self-review

**Spec coverage.** This plan covers the spec's Phase 0 (Tasks 1–2 plus the operator prerequisites) and the engine half of Phase 1 (Tasks 3–6). Deliberately deferred to Plan 2: the serverless control plane, API keys and rate limiting, demand-signal collection and ranking, the regression-CI GitHub Action, the site estimator page and generated capability table, and all of Phase 2 (ledger, credits, spot fleet, merchant-of-record). Task 5's `request_digest` is the forward hook those depend on.

**Known follow-ups for Plan 2, carried from the spec's open items.** Serverless host and managed batch provider selection; the exact trace-cell definition and per-profile degree factor; merchant-of-record selection for prepaid credits (existing Lemon Squeezy evidence assumed subscriptions); which three launch gates survive the collapse from nine.

**Type consistency.** `EstimateParams` fields are identical across Tasks 3, 4, and 6. `field_widths` returns `(field_bytes, ext_field_bytes)` in Task 4 and is destructured in that order in Task 6. `EstimateRequestV1::digest()` is used as both `workload_id` and `request_digest` in Task 6, matching Task 5's definition. `blocking_reasons()` is named identically in Tasks 5 and 6.

**Discovery steps rather than assumptions.** Three places make an explicit hypothesis and tell the implementer to verify against ground truth rather than trust the plan: the `quotient_chunks` formula (Task 5 Step 1), `ResourcePolicyV1: Default` (Tasks 3 and 6), and whether `hc-cli` has a library target (Task 6 Step 3). These are real uncertainties in code the plan could not fully read; each names the command that resolves it.
