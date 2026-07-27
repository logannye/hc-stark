# TinyZKP hosted estimator (Phase 1b) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Serve `POST /v1/estimate` from the existing Cloudflare Pages worker, backed by the same Rust cost model compiled to WASM, and log shape-only demand records so the pre-committed kill criterion becomes measurable.

**Architecture:** `crates/hc-wasm` already compiles `hc-plonky3` to `wasm32-unknown-unknown` (proven by `ci.yml:69`). We add a WASM export wrapping the same `EstimateRequestV1 → EstimateResponseV1` path the CLI uses, import it into `site/_worker.js` (Pages Advanced Mode), and append shape-only records to D1. The Rust core stays the single source of truth for every number.

**Tech Stack:** Rust 1.95.0 (pinned), `wasm-bindgen`, Cloudflare Pages Advanced Mode (`_worker.js`), Wrangler, D1 (SQLite), `cargo test`, `pytest`.

## Global Constraints

- Rust toolchain pinned `1.95.0`; Plonky3 exact-pinned `0.6.1`. **Do not add, remove, or bump any EXTERNAL dependency, and never change a version.** Task 1 deliberately adds one internal path edge (`tinyzkp-contracts` to `hc-wasm`), which moves the lock and is handled by its Step 7a re-freeze — the root `Cargo.lock` SHA-256 is frozen at `974b350620f98ee29a8d90bca0302000cd229bbd381169e2f772944387dc012b` in `release/plonky3-compatibility-v1.json`, `crates/hc-plonky3/src/prover.rs` (`DEPENDENCY_LOCK_SHA256`), `crates/hc-cli/tests/cli_roundtrip.rs`, and several scripts. A bump reds `scripts/ci/plonky3_compatibility_gate.py`.
- Any dependency-graph change also stales `fuzz/Cargo.lock` and `clients/rust/Cargo.lock` — standalone workspaces NOT covered by a root gate. Verify both with `cargo +1.95.0 fetch --locked --manifest-path <each>`.
- **The cost model is never reimplemented in JavaScript.** Every number in a response must originate from the Rust WASM module. Phase 1a shipped a `conventional` estimate that diverged 7.8x from computing one concept two ways; this constraint exists to prevent recreating that at the API boundary.
- `scripts/ci/claim_containment_scan.py` scans `docs/**/*.md` for `\bzero[- ]knowledge\b`. Tripping it blocks the Pages deploy.
- Do not resurrect `api.tinyzkp.com` / `mcp.tinyzkp.com` / `webhook.tinyzkp.com` — they are in `RETIRED_HOSTS` in `site/_worker.js` and publicly announced as retired. The endpoint lives at a path on `tinyzkp.com`.
- No always-on infrastructure. Scale-to-zero only.
- Never push to `main`; branch and open a PR.
- **Shape-only logging.** No witness, AIR source, path, email-in-log, or raw request body may ever be written to the demand log.

## File Structure

| File | Responsibility | Change |
|---|---|---|
| `crates/hc-wasm/src/lib.rs` | WASM exports | Modify — add the estimate export |
| `crates/hc-cli/src/commands/estimate_config.rs` | shared request→response core | Modify — extract a wasm-callable fn |
| `site/_worker.js` | Pages router | Modify — add `/v1/estimate`, update the honesty header, adjust CSP |
| `site/wrangler.toml` | bindings | Modify — D1 + WASM module |
| `site/estimate.html` | **new** — public estimator page | Create |
| `migrations/0001_demand_log.sql` | **new** — D1 schema | Create |
| `scripts/ci/demand_report.py` | **new** — kill-criterion report | Create |
| `scripts/ci/test_demand_report.py` | **new** — its tests | Create |

---

### Task 1: Expose the estimator as a WASM export

**Files:**
- Modify: `crates/hc-cli/src/commands/estimate_config.rs` (delegate to the shared core)
- Modify: `crates/hc-wasm/Cargo.toml` (add the `tinyzkp-contracts` path edge)
- Modify: `crates/hc-wasm/src/lib.rs`
- Test: `crates/hc-wasm/src/lib.rs` (`#[cfg(test)] mod tests`)

**Interfaces:**
- Consumes: `tinyzkp_contracts::{EstimateRequestV1, EstimateResponseV1}`; `hc_plonky3::estimate_params::{estimate_from_params, estimate_conventional_from_params, field_widths, EstimateParams}`.
- Produces: `pub fn estimate_request(request: EstimateRequestV1) -> Result<EstimateResponseV1, EstimateFailure>` **in `hc-wasm`** (see the placement note in Step 2), re-used by `hc-cli`; and `#[wasm_bindgen] pub fn estimate_json(input: &str) -> String` in `hc-wasm`. Task 2 calls `estimate_json`.

- [ ] **Step 1: Find where the shared logic currently lives**

```bash
sed -n '1,120p' crates/hc-cli/src/commands/estimate_config.rs
grep -n "pub fn run" crates/hc-cli/src/commands/estimate_config.rs
```

`run()` currently takes a `&Path`, reads the file, then estimates. The file-reading half is CLI-only; the request→response half must be shared. Note the exact current signature before changing it.

- [ ] **Step 2: Write the failing parity test**

The WASM export and the CLI must produce byte-identical JSON for the same request — otherwise the API and the CLI become two sources of truth, which is the exact failure this plan forbids.

Add to `crates/hc-wasm/src/lib.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    const SP1_SHAPED: &str = r#"{
      "schema_version": 1, "field": "babybear", "extension_degree": 4,
      "logical_rows": 4194304, "trace_width": 180, "max_constraint_degree": 3,
      "public_values": 8, "has_next_row_columns": true,
      "features": {"uses_lookups": true, "uses_buses": false,
        "uses_permutations": false, "uses_multi_table": true,
        "uses_preprocessed_columns": false, "uses_periodic_columns": false,
        "uses_recursion": false, "uses_gpu": false},
      "ram_budget_bytes": 2147483648
    }"#;

    /// The JSON export must return exactly what the typed core returns.
    /// `estimate_request` lives in THIS crate (see the placement note below);
    /// `hc-cli` calls it too, so the CLI and the API cannot diverge.
    #[test]
    fn wasm_export_matches_the_shared_core() {
        let request: tinyzkp_contracts::EstimateRequestV1 =
            serde_json::from_str(SP1_SHAPED).unwrap();
        let direct = estimate_request(request).unwrap();
        let via_wasm: tinyzkp_contracts::EstimateResponseV1 =
            serde_json::from_str(&estimate_json(SP1_SHAPED)).unwrap();
        assert_eq!(direct, via_wasm);
    }

    /// An unprovable config must still return numbers — the product thesis.
    #[test]
    fn unprovable_config_still_returns_estimates() {
        let r: tinyzkp_contracts::EstimateResponseV1 =
            serde_json::from_str(&estimate_json(SP1_SHAPED)).unwrap();
        assert!(!r.provable_today);
        assert!(!r.blocking_reasons.is_empty());
        assert!(r.estimates.bounded.peak_resident_bytes > 0);
        assert!(r.estimates.conventional.peak_resident_bytes
            > r.estimates.bounded.peak_resident_bytes);
    }

    /// Errors must be structured, never a panic across the WASM boundary.
    #[test]
    fn malformed_input_returns_a_structured_error_not_a_panic() {
        let out = estimate_json("{ not json");
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
        assert!(v["error"]["reason"]["code"].is_string());
        assert_ne!(v["error"]["reason"]["code"], "internal_error");
    }
}
```

**Where the shared core lives — resolved by the controller, do not re-litigate:**

Verified dependency facts:
- `hc-wasm` depends on `hc-plonky3` but **not** on `tinyzkp-contracts` or `hc-cli`.
- `hc-plonky3` depends on `hc-stream` but **not** on `tinyzkp-contracts`.
- `hc-cli` is the **only** crate depending on both `tinyzkp-contracts` and `hc-plonky3`, and it also pulls `clap`, `anyhow`, and `tempfile` — which must not enter a `wasm32` build.

So `estimate_request` needs a home reachable from `hc-wasm` that can see `EstimateRequestV1`. **Add `tinyzkp-contracts` as a dependency of `hc-wasm`** and put the glue in `hc-wasm` itself, calling into `hc_plonky3::estimate_params::*`. Then make `hc-cli`'s `estimate_config::run()` call that same function so the CLI and the API cannot diverge. Do NOT add a new workspace crate, and do NOT make `hc-wasm` depend on `hc-cli`.

⚠️ **This edge changes `Cargo.lock` and therefore requires a re-freeze.** `Cargo.lock` records each package's `dependencies` list, so adding `tinyzkp-contracts` to `hc-wasm`'s entry moves the file hash away from the frozen `974b3506…`. This is expected and permitted — see Step 7a. It is not a reason to duplicate the cost model in JavaScript or in `hc-wasm`.

- [ ] **Step 3: Run to verify failure**

```bash
cargo test -p hc-wasm 2>&1 | tail -20
```

Expected: FAIL to compile — `estimate_json` not found.

- [ ] **Step 4: Extract the shared core**

In `estimate_config.rs`, split `run()` so the request→response logic is a public function and `run()` becomes the file-reading wrapper:

```rust
/// Cost a declared configuration. Never proves, never reads a witness.
/// Shared by the CLI and the WASM export so both produce identical numbers.
pub fn estimate_request(
    request: EstimateRequestV1,
) -> Result<EstimateResponseV1, ProtocolFailure> {
    // move the existing body of run() here, minus the file read
}

pub fn run(config_path: &Path) -> Result<EstimateResponseV1> {
    let raw = std::fs::read_to_string(config_path)
        .with_context(|| format!("reading {}", config_path.display()))?;
    let request: EstimateRequestV1 =
        serde_json::from_str(&raw).map_err(|_| /* existing ManifestContractInvalid mapping */)?;
    Ok(estimate_request(request)?)
}
```

Preserve every `ReasonCodeV1` mapping exactly — Phase 1a needed a fix round to get these right, and the existing end-to-end tests pin them.

- [ ] **Step 5: Add the WASM export**

In `crates/hc-wasm/src/lib.rs`:

```rust
/// Estimate from a JSON `EstimateRequestV1`. Returns a JSON
/// `EstimateResponseV1` on success, or the standard error envelope on failure.
/// Never panics across the WASM boundary.
#[wasm_bindgen]
pub fn estimate_json(input: &str) -> String {
    match serde_json::from_str::<tinyzkp_contracts::EstimateRequestV1>(input) {
        Err(_) => error_envelope(tinyzkp_contracts::ReasonCodeV1::ManifestContractInvalid),
        Ok(request) => match estimate_request(request) {
            Ok(response) => serde_json::to_string(&response)
                .unwrap_or_else(|_| error_envelope(
                    tinyzkp_contracts::ReasonCodeV1::InternalError)),
            Err(failure) => error_envelope(failure.reason_code()),
        },
    }
}
```

Implement `error_envelope` to emit the same shape the CLI writes via `protocol::write_error`, so API and CLI errors are indistinguishable. Discover that shape with `grep -n "fn write_error" -A 25 crates/hc-cli/src/protocol.rs`.

- [ ] **Step 6: Run the tests**

```bash
cargo test -p hc-wasm 2>&1 | tail -20
cargo check --locked -p hc-wasm --target wasm32-unknown-unknown 2>&1 | tail -5
```

Expected: all three tests PASS, and the wasm32 check succeeds.

- [ ] **Step 7: Confirm the lock moved for exactly one expected reason**

```bash
git diff Cargo.lock | grep -E '^[+-]' | grep -v '^[+-][+-]'
shasum -a 256 Cargo.lock
```

Expected: the ONLY change is `tinyzkp-contracts` appearing in `hc-wasm`'s `dependencies` list. **Zero `-version =` lines** — no existing package may be bumped. If any version changed, revert and investigate.

- [ ] **Step 7a: Re-freeze the lock hash**

The new hash must replace `974b350620f98ee29a8d90bca0302000cd229bbd381169e2f772944387dc012b` everywhere it is pinned. Find every site — the last re-freeze touched eight files:

```bash
grep -rln "974b350620f98ee29a8d90bca0302000cd229bbd381169e2f772944387dc012b" \
  --exclude-dir=target --exclude-dir=.git .
```

Update all of them **except anything under `release/evidence/`** — those are signed historical attestations of past release SHAs and must never be edited. If the gate demands a change inside `release/evidence/`, STOP and report BLOCKED.

Then verify, and also regenerate the two standalone workspace locks, which are not covered by any root gate:

```bash
python3 scripts/ci/plonky3_compatibility_gate.py
cargo +1.95.0 fetch --locked --manifest-path fuzz/Cargo.toml
cargo +1.95.0 fetch --locked --manifest-path clients/rust/Cargo.toml
```

If either standalone fetch fails, regenerate that lock minimally (`cargo +1.95.0 fetch --manifest-path <it>`, no `--locked`) and confirm its diff adds only dependency edges with zero version changes.

Record in your report: the old hash, the new hash, every file you changed, and confirmation that `git diff --name-only -- release/evidence/` is empty.

- [ ] **Step 8: Commit**

```bash
git add crates/hc-wasm crates/hc-cli
git commit -m "Expose the estimator as a WASM export

Splits the request-to-response core out of the CLI's file-reading wrapper so
the hosted API and the CLI share one implementation. A parity test pins them
byte-identical: the API must never become a second source of truth for a
number, which is how the conventional estimate diverged 7.8x in Phase 1a."
```

---

### Task 2: Serve `POST /v1/estimate` from the Pages worker

**Files:**
- Modify: `site/_worker.js`
- Modify: `site/wrangler.toml`
- Test: `scripts/ci/test_worker_estimate.mjs` (**new**)

**Interfaces:**
- Consumes: `estimate_json` from Task 1's WASM module.
- Produces: `POST /v1/estimate` accepting an `EstimateRequestV1` JSON body and returning `EstimateResponseV1` or the error envelope. Task 3 adds rate limiting around it; Task 4 logs from it.

- [ ] **Step 1: Read the existing worker before touching it**

```bash
sed -n '1,60p' site/_worker.js
grep -n "PUBLIC_ROUTES\|RETIRED_HOSTS\|export default\|async fetch" site/_worker.js
grep -rn "_worker.js" scripts/ci/ | head
```

Note: the file header claims it "imports no function, calls no upstream service, and stores no visitor or proof data." Two of those three become false in this plan. **Update that header honestly in this task** — a stale accuracy claim in a security-relevant file is worse than no claim. Check whether any CI script asserts on that header text.

- [ ] **Step 2: Write the failing endpoint test**

Create `scripts/ci/test_worker_estimate.mjs` exercising the worker's fetch handler directly (import the default export and call `fetch(new Request(...), env, ctx)`), covering: a valid request returns 200 with non-zero bounded and conventional estimates; a malformed body returns a structured error whose reason code is not `internal_error`; and `GET /v1/estimate` returns 405.

- [ ] **Step 3: Run to verify failure**

```bash
node --test scripts/ci/test_worker_estimate.mjs 2>&1 | tail -20
```

Expected: FAIL — the route does not exist.

- [ ] **Step 4: Wire the WASM module and the route**

Add the WASM binding to `site/wrangler.toml` and import it in `_worker.js`. Cloudflare Pages Advanced Mode supports importing a `.wasm` module directly; determine the exact import form for `compatibility_date = "2025-12-01"` from the Wrangler docs rather than guessing, and record it in your report.

Route handling must: accept only `POST`, cap the request body (a few KB — this is a shape-only manifest), parse it, call `estimate_json`, and return the result with `Content-Type: application/json`.

- [ ] **Step 5: Adjust CSP for the estimator page**

The current CSP sets `form-action 'none'` and `connect-src 'self' https://cloudflareinsights.com`. A same-origin `fetch` from `/estimate` is already permitted by `connect-src 'self'`, so **prefer a `fetch`-based page and leave `form-action 'none'` intact** — do not weaken the CSP unless a test proves you must. If you do change any CSP directive, state exactly which and why in the report.

- [ ] **Step 6: Run the tests and the site gates**

```bash
node --test scripts/ci/test_worker_estimate.mjs 2>&1 | tail -20
python3 scripts/ci/site_route_check.py
python3 scripts/ci/site_deploy_check.py
python3 -m pytest scripts/ci/test_guard_site_contract.py -q
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add site scripts/ci/test_worker_estimate.mjs
git commit -m "Serve POST /v1/estimate from the Pages worker

Backs the endpoint with the Task 1 WASM module so responses come from the same
Rust cost model as the CLI. Updates the worker header, which previously claimed
the file calls no upstream and stores no data; the first is now false."
```

---

### Task 3: Rate-limit anonymous callers

**Files:**
- Modify: `site/_worker.js`
- Modify: `site/wrangler.toml`
- Test: `scripts/ci/test_worker_estimate.mjs`

**Interfaces:**
- Consumes: the Task 2 route.
- Produces: a per-IP fixed-window limiter returning HTTP 429 with a `Retry-After` header. Task 5 adds a keyed tier that raises the ceiling.

- [ ] **Step 1: Write the failing test**

Add to `scripts/ci/test_worker_estimate.mjs`: N+1 requests from one simulated IP within the window — the first N return 200, the last returns 429 with `Retry-After`; a request from a different IP still returns 200.

- [ ] **Step 2: Run to verify failure**

```bash
node --test scripts/ci/test_worker_estimate.mjs 2>&1 | tail -20
```

Expected: FAIL — no limiting yet.

- [ ] **Step 3: Implement the limiter**

Use a D1-backed or KV-backed fixed window keyed on a **salted hash of `CF-Connecting-IP`**, never the raw IP. Pick a conservative anonymous limit (suggested: 30 requests/hour) and put the number in one named constant. Document it in the report; the plan does not fix the value.

- [ ] **Step 4: Run tests and gates**

```bash
node --test scripts/ci/test_worker_estimate.mjs 2>&1 | tail -20
python3 scripts/ci/site_deploy_check.py
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add site scripts/ci/test_worker_estimate.mjs
git commit -m "Rate-limit anonymous estimator calls

Per-IP fixed window keyed on a salted hash, never the raw address."
```

---

### Task 4: Log shape-only demand records and report the kill criterion

This is the task the whole phase exists for. Without it the 90-day clock never starts.

**Files:**
- Create: `migrations/0001_demand_log.sql`
- Modify: `site/_worker.js`, `site/wrangler.toml`
- Create: `scripts/ci/demand_report.py`, `scripts/ci/test_demand_report.py`

**Interfaces:**
- Consumes: the Task 2 route and its `EstimateResponseV1`.
- Produces: a `demand_log` D1 table and a report emitting an explicit `CONTINUE` / `KILL_THRESHOLD_MET` verdict.

- [ ] **Step 1: Write the failing report test**

Create `scripts/ci/test_demand_report.py` against a temporary SQLite file with the same schema. Assert: with 14 distinct keyed orgs in the window the verdict is `KILL_THRESHOLD_MET`; with 15 it is `CONTINUE`; records older than 90 days are excluded; and keyed and anonymous counts are reported **separately and never summed** (anonymous attribution is approximate, so blending them would flatter the number).

Also assert the report ranks blocking reason codes by **distinct organizations**, not raw request count — one enthusiastic caller must not outvote fifteen quiet ones. That ranking is the profile-expansion queue.

- [ ] **Step 2: Run to verify failure**

```bash
python3 -m pytest scripts/ci/test_demand_report.py -q 2>&1 | tail -10
```

Expected: FAIL — module not found.

- [ ] **Step 3: Create the schema**

`migrations/0001_demand_log.sql`, storing only: `request_digest`, `field`, `extension_degree`, bucketed `trace_width` and `logical_rows`, the eight feature flags, `provable_today`, blocking reason codes, a coarse timestamp, and either `key_id` or a salted IP hash.

**Never store** the raw request body, an email, a raw IP, a path, or an AIR. Choose bucket boundaries and document them.

- [ ] **Step 4: Write from the worker**

Append one record per successful estimate, using `ctx.waitUntil` so logging never delays or fails the response. A logging failure must never turn a good estimate into an error.

- [ ] **Step 5: Implement the report**

`scripts/ci/demand_report.py` emits JSON with: distinct keyed organizations, distinct approximate anonymous sources, top request digests, blocking reason codes ranked by distinct organizations, and an explicit `verdict` field. State the verdict outright rather than emitting numbers a reader can interpret favourably.

- [ ] **Step 6: Run the tests and full gates**

```bash
python3 -m pytest scripts/ci/test_demand_report.py -q
node --test scripts/ci/test_worker_estimate.mjs
python3 scripts/ci/site_deploy_check.py
python3 scripts/ci/claim_containment_scan.py
```

Expected: all PASS.

- [ ] **Step 7: Commit**

```bash
git add migrations scripts/ci/demand_report.py scripts/ci/test_demand_report.py site
git commit -m "Log shape-only demand and report the kill criterion

Starts the 90-day clock the staged strategy depends on. Keyed and anonymous
counts are reported separately because anonymous attribution is approximate.
Blocking reason codes rank by distinct organization, making the
profile-expansion queue empirical rather than a guess."
```

---

### Task 5: Optional free keys and the public estimator page

**Files:**
- Modify: `site/_worker.js`, `site/wrangler.toml`
- Create: `site/estimate.html`
- Modify: `migrations/0001_demand_log.sql` or add `migrations/0002_keys.sql`
- Test: `scripts/ci/test_worker_estimate.mjs`

**Interfaces:**
- Consumes: Tasks 2–4.
- Produces: `POST /v1/keys` returning an opaque key; a keyed rate tier; and `/estimate`.

- [ ] **Step 1: Write the failing tests**

Assert: `POST /v1/keys` with a valid email returns an opaque key not derivable from the email; a request bearing that key gets the higher limit; an invalid or revoked key returns a structured error, not `internal_error`; and the demand log records `key_id`, **never the email**.

- [ ] **Step 2: Run to verify failure**

```bash
node --test scripts/ci/test_worker_estimate.mjs 2>&1 | tail -20
```

Expected: FAIL.

- [ ] **Step 3: Implement key minting and the keyed tier**

Store a hash of the key, never the key itself. Store the email separately from the demand log, and only if genuinely needed to contact a user — if it is not needed, do not store it at all and say so on the page.

- [ ] **Step 4: Build `site/estimate.html`**

A `fetch`-based form (CSP keeps `form-action 'none'`), the equivalent CLI one-liner, and honest scope copy: the four supported fields, and that an unsupported config still returns an estimate with the reasons proving is blocked. Match the existing pages' structure and classes.

- [ ] **Step 5: Run everything**

```bash
node --test scripts/ci/test_worker_estimate.mjs
python3 -m pytest scripts/ci/test_demand_report.py scripts/ci/test_guard_site_contract.py -q
python3 scripts/ci/site_route_check.py
python3 scripts/ci/site_deploy_check.py
python3 scripts/commercial/render_offers.py --check
python3 scripts/ci/guard_launch_gate.py --check
python3 scripts/ci/claim_containment_scan.py
cargo test --workspace
cargo fmt --all -- --check
shasum -a 256 Cargo.lock
cargo +1.95.0 fetch --locked --manifest-path fuzz/Cargo.toml
cargo +1.95.0 fetch --locked --manifest-path clients/rust/Cargo.toml
```

Expected: all PASS; lock hash unchanged; both standalone workspaces clean.

- [ ] **Step 6: Commit**

```bash
git add site migrations scripts
git commit -m "Add optional free keys and the public estimator page

Anonymous access stays the default so trial is unobstructed; a free key raises
the limit and makes distinct-organization counting exact for serious users."
```

---

## Self-review

**Spec coverage.** Covers the Phase 1b spec's Worker+WASM architecture (Tasks 1–2), access model (Tasks 3, 5), demand log (Task 4), kill-criterion report (Task 4), and public page (Task 5). Deliberately deferred, matching the spec's out-of-scope section: metered proving, credit ledger, merchant-of-record, spot fleet, the regression-CI GitHub Action, and publishing the estimate JSON schemas.

**Discovery over assumption.** Four points state a hypothesis and name the command that resolves it rather than asserting: where the shared `estimate_request` should live (Task 1 Step 2 — `hc-wasm` depending on `hc-cli` is likely wrong, and adding a crate would move the frozen lock); the exact WASM import form for Pages Advanced Mode at the pinned compatibility date (Task 2 Step 4); whether any CI script pins the `_worker.js` header text (Task 2 Step 1); and the rate-limit and bucket values (Tasks 3, 4 — deliberately left to the implementer with a requirement to document).

**Type consistency.** `estimate_request` has the same signature in Tasks 1 and 2. `estimate_json` takes `&str` and returns `String` in both its definition and the worker call site. `EstimateRequestV1`/`EstimateResponseV1` are used unchanged from `tinyzkp-contracts`; no task redefines them.

**Known risk not fully mitigated.** The `_worker.js` header currently asserts the file stores no visitor data. Task 4 makes that false in a narrow sense — salted IP hashes and shape-only records. Task 2 requires updating the header, but a reviewer should check the final wording actually describes what is stored, since this is a security-relevant claim on a public site.
