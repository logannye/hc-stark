# Phase 0.3 — Abuse & Billing-Correctness Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Close the abuse + billing-correctness findings: **G8** (unlimited free re-signup), **G9** (`/aggregate` uncapped/unmetered), **G11** (divergent pricing systems — Compute tier never billed; `pro` alias mismatch), **G12** (trace_length under-bill; cap/inflight TOCTOU).

**Decisions (approved):** **Disable `/aggregate`** (it's not real recursion — engine audit D-10 — and the marketing was withdrawn in 0.1b). **Keep the Compute tier and wire its metering** (emit `trace_step_usage`), so it's actually billable.

**Branch:** `phase0.3-abuse-billing` (off `main` @ `8d2ab9f`, which includes #19 + #20).

**Key facts (verified):** `PlanLimits::for_plan` (`crates/hc-server/src/lib.rs:92`) has free/team/scale + a default arm whose comment says it "covers legacy standard **and pro**" — the G11 bug (`pro` should map to scale's limits/discount). No `compute` plan anywhere. `/aggregate` handler at `lib.rs:2652`, route at `:831`. trace_length under-bill = `.unwrap_or(0)` at `:1265` before `usage.record` (`:1267`). Cap/inflight/insert are separate lock acquisitions (`:1358`/`:1382`/`:1471` in `prove_submit`; mirrored in `prove_template` ~`:2189`+ and `prove_batch` ~`:1736`+). `billing/sync_usage.py` emits only `proof_usage` (cents value); `DISCOUNT_FACTORS` already includes `pro: 0.60`. `provision_free` (`billing/provision_tenant.py:407`) already returns 409 in an `except`, but `create_tenant` never raises for free tenants (no email uniqueness) → the 409 is dead. `pricing.json` is the SSOT with parity tests in `billing/tests/test_pricing_parity.py` + a Rust-side parity test.

---

## Task 1 — G8: enforce one free tenant per email

**Files:** Modify `billing/provision_tenant.py`; Test `billing/tests/test_provision_free.py` (create or extend).

- [ ] **Step 1: test** — assert that a second `/provision-free` for an email that already has a tenant returns 409 (and does NOT create a second tenant). Use the webhook test-client pattern from `billing/tests/test_session_endpoints.py`; set `INTERNAL_SECRET` + a temp `HC_TENANT_STORE_PATH`.
- [ ] **Step 2:** run → fails (currently a second free signup succeeds).
- [ ] **Step 3: implement** — in `provision_free`, BEFORE `create_tenant`, add an explicit duplicate check:
```python
    conn = tenant_store.open_db()
    if tenant_store.get_by_email(conn, email):
        conn.close()
        return flask.jsonify(error="account already exists for this email"), 409
    # ... existing create_tenant flow ...
```
(Keep the existing `except → 409` as defense-in-depth. This blocks free re-signup for ANY email that already has a tenant — the abuse vector. Paid checkout is a separate path and unaffected.)
- [ ] **Step 4:** run → pass. `cd billing && python3 -m pytest tests/ -q`.
- [ ] **Step 5: commit** `fix(billing): one free tenant per email — block free re-signup abuse (G8)`.

## Task 2 — G9: disable `/aggregate`

**Files:** Modify `crates/hc-server/src/lib.rs`.

- [ ] **Step 1: test** — a request to the `aggregate` handler returns `410 GONE` with a clear message. (Unit-test the handler if it's callable in isolation, else assert via the router test pattern used elsewhere; if neither is easy, a `#[test]` asserting the handler returns the 410 response is sufficient.)
- [ ] **Step 2:** run → fails.
- [ ] **Step 3: implement** — replace the body of `async fn aggregate(...)` (`~:2652`) so it returns 410 immediately (do NOT run `hc_recursion::aggregate`):
```rust
async fn aggregate(/* keep extractor params or reduce to the minimum */) -> impl IntoResponse {
    (
        StatusCode::GONE,
        Json(serde_json::json!({
            "error": "aggregate_disabled",
            "message": "Proof aggregation is not available. It was a non-recursive digest and has been withdrawn; real recursive aggregation is future work."
        })),
    ).into_response()
}
```
Keep the route registered (so it returns a clean 410, not a 404) OR remove the route and let it 404 — prefer the 410 with the message. Remove now-unused imports/`hc_recursion` usage if that leaves dead code + clippy warnings (check `cargo clippy`).
- [ ] **Step 4:** `cargo test -p hc-server -q` + `cargo clippy -p hc-server --all-targets -- -D warnings` + `cargo fmt --all`.
- [ ] **Step 5: commit** `feat(server): disable /aggregate (410) — not real recursion, claim withdrawn (G9)`.

## Task 3 — G12: trace_length under-bill + cap/inflight atomicity

**Files:** Modify `crates/hc-server/src/lib.rs`.

- [ ] **3a — trace_length:** at `~:1265`, the usage record uses a trace_length parsed from the proof output with `.unwrap_or(0)` → a parse miss prices at the cheapest 5¢ tier. READ the surrounding worker code: the job already knows its `program_len`/`block_size` (the submitted `ProveRequest`), so the *authoritative* trace_length is computable server-side (`padded_len * block_size`, as `estimate` does at `:2576`). Change the usage record to use that computed trace_length (don't trust a parse of the proof output). If a computed value is genuinely unavailable, record with a conservative non-cheapest fallback AND `log::warn!` + a metric so it's visible — never silently 0/5¢.
- [ ] **3b — TOCTOU:** the monthly-cap check, inflight count, and `jobs.insert` happen under separate `jobs.lock()` acquisitions in `prove_submit` (`:1358`/`:1382`/`:1471`), `prove_template` (~`:2189`+), and `prove_batch` (~`:1736`+). Make the inflight-count + insert atomic: hold ONE `jobs.lock()` guard across "count this tenant's inflight → if `< max_inflight` insert the new job, else reject" so concurrent requests can't both pass the check. (The monthly-cap read can stay just before, but the inflight gate + insert must be one critical section.) Add a regression test that two concurrent submissions for a tenant at `max_inflight=1` yield exactly one accepted + one `429 too_many_inflight`.
- [ ] **Step: tests** — `cargo test -p hc-server -q` (incl. the new concurrency + trace_length tests) + clippy + fmt.
- [ ] **Step: commit** `fix(server): bill computed trace_length + atomic inflight gate (G12)`.

## Task 4 — G11: Compute plan + `trace_step_usage` metering + alias unification

**Files:** Modify `pricing.json`, `crates/hc-server/src/lib.rs` (`PlanLimits::for_plan`), `billing/sync_usage.py`, the parity tests (`billing/tests/test_pricing_parity.py` + the Rust parity test), and the Stripe meter setup (`billing/setup_stripe_*.sh` — ensure a `trace_step_usage` meter exists).

- [ ] **Step 1 — pricing.json:** add a `compute` plan to `plans` (usage-based: `prove_rpm: 100`, `verify_rpm: 300`, `max_inflight: 8`, `max_prove_seconds: 3600`, and a `monthly_cap_cents` high enough to be effectively usage-bounded, e.g. the scale cap or a dedicated large value — pick one and document it). Add a `"billing_meter": "trace_step_usage"` marker on `compute` (and implicitly `proof_usage` for the others) so the SSOT records WHICH meter each plan bills through. Confirm `plan_aliases` has `pro → scale` (it does).
- [ ] **Step 2 — hc-server `PlanLimits::for_plan`:** add a `"compute"` arm matching pricing.json; FIX the default arm so `"pro"` maps to **scale** limits (not developer). Read `crates/hc-server/src/usage_log.rs` (the parity loader) to see how plans are validated against pricing.json and keep them consistent.
- [ ] **Step 3 — `billing/sync_usage.py`:** route metering by plan. For a tenant whose plan is `compute`, emit a `trace_step_usage` meter event with `value = str(trace_length)` (raw steps; the Stripe price is $0.50 / 1e6 steps) and the same identifier/idempotency scheme — do NOT apply the per-proof `TIERS`/`DISCOUNT_FACTORS` to compute. For all other plans, keep the existing `proof_usage` (cents) path. Factor the meter selection cleanly (e.g. `meter_name, value = ("trace_step_usage", row["trace_length"]) if plan == "compute" else ("proof_usage", discounted_price_cents(...))`).
- [ ] **Step 4 — Stripe meter setup:** in the setup script(s), ensure a meter named `trace_step_usage` exists (sum aggregation; the Compute Stripe price meters on it at $0.50/M). If the script already creates it, confirm; else add it. (This is config/idempotent shell — verify, don't run against live Stripe.)
- [ ] **Step 5 — parity tests:** update `billing/tests/test_pricing_parity.py` AND the Rust parity test so the new `compute` plan + the `pro→scale` resolution pass on both sides. Add an assertion that `compute` bills via `trace_step_usage` and the per-proof plans via `proof_usage`. The whole point of the SSOT is that drift fails CI — make all three (pricing.json, hc-server, sync_usage) agree.
- [ ] **Step 6: verify** — `cd billing && python3 -m pytest tests/ -q` (parity green) + `cargo test -p hc-server -q` (parity green) + clippy + fmt.
- [ ] **Step 7: commit** `feat(billing): Compute tier billed via trace_step_usage; unify pro→scale (G11)`.

## Task 5 — Final verification + review

- [ ] **Step 1:** `cd billing && python3 -m pytest tests/ -q`; `cargo test -p hc-server -q`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo fmt --all --check`.
- [ ] **Step 2:** holistic review of the 0.3 diff: (a) free re-signup is blocked per email; (b) `/aggregate` returns 410 and no longer runs `hc_recursion`; (c) trace_length can't silently bill at the cheapest tier; (d) concurrent submissions can't exceed `max_inflight`/cap (TOCTOU closed); (e) a `compute`-plan tenant's usage emits `trace_step_usage` (not 0 / not proof_usage), other plans unchanged; (f) pricing.json ↔ hc-server ↔ sync_usage agree (parity green); (g) `pro` resolves to scale on BOTH sides.

## Acceptance criteria
- A 2nd free signup for an existing email → 409, no new tenant (G8).
- `/aggregate` → 410, no compute performed (G9).
- Usage records use the authoritative computed trace_length; missing → conservative + logged, never 5¢-silent (G12a).
- Inflight gate + insert are atomic; cap/inflight cannot be overshot under concurrency (G12b).
- `compute` plan exists in pricing.json + hc-server + sync_usage; compute usage bills via `trace_step_usage`; `pro`→scale everywhere; parity tests green (G11).

## Out of scope (other phases)
- Plaintext `api_keys.txt` retirement, `INTERNAL_SECRET`→signed tokens (Phase 3). SPOF/backup G13 (Phase 0.5), audit-on-laptop G14 (Phase 3). The FRI-soundness core G2/G7 (Phase 1A).
