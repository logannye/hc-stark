# TinyZKP: Truthful Surfaces and Demand-Measurement Validity — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make every machine-readable surface tell the truth about what TinyZKP is today, and make the frozen kill criterion measure something it is actually capable of measuring — so that a future `KILL_THRESHOLD_MET` verdict is a *result* rather than an artifact of an undiscoverable product.

**Origin:** Comprehensive review, 2026-07-29, against `main` @ `e07f249`. The review found the engine healthy (115 tests pass, 0 fail) and every material defect on the business/claims surface.

## The single root cause

Three separate incidents — the Guard withdrawal, the Phase 1b estimator launch, and the hosted-stack retirement — each changed *what TinyZKP is*, and each updated **only the human-readable HTML**. Every machine-readable surface still describes the prior world:

| Change | HTML updated | Machine surface updated |
|---|---|---|
| Guard SKU withdrawn | ✅ | ❌ `offers.jsonld`, `pricing.json`, `commerce.json`, `llms.txt` |
| Estimator + D1 + keys shipped | ✅ (`/estimate` page) | ❌ `privacy.html`, `discovery.json`, `sitemap.xml`, `llms.txt` |
| Hosted stack retired | ✅ (410s) | ❌ `server.json`, `smithery.yaml` |

**Therefore the governing design rule of this plan:** *no task is complete when the surface is corrected. A task is complete when a gate exists that fails if the surface drifts from the code again.* Every remediation below ships with its enforcing gate in the same commit. Fixing the strings alone reproduces this exact review in six months.

## Global Constraints

- **No engine changes in Phases 0–3.** `crates/` is touched only in Phase 5. The Goldilocks and BabyBear proof paths must stay byte-identical; `cargo test --workspace` green throughout.
- **`site/llms.txt`, `site/sitemap.xml`, `site/discovery.json`, `site/offers.jsonld`, and parts of `site/privacy.html` are GENERATED**, not hand-maintained. `scripts/ci/guard_launch_gate.py` (5,534 lines) renders them under `--write` and validates under `--check`; `scripts/commercial/render_offers.py` renders `offers.jsonld` from `site/pricing.json`. **Editing the rendered file directly will be reverted by the next `--write`.** Change the generator, then regenerate, then verify `--check` passes.
- Run the correct interpreter per gate — this bites every time: `scripts/ci/site_route_check.py` needs **`/usr/bin/python3`** (pyexpat); `scripts/ci/site_deploy_check.py` needs **Homebrew `python3`** (tomllib).
- `scripts/ci/claim_containment_scan.py` scans `docs/**/*.md`, `README.md`, and the `site/`/`release/` trees for unsupported-claim patterns. Run it after every task that touches copy.
- `release/evidence/` is signed historical attestation — **never edit it**. A diff there after any task is a bug in that task.
- **Do not weaken the kill criterion.** Phase 1 makes the measurement *valid*; it must not make `KILL_THRESHOLD_MET` harder to reach on the merits. The threshold constant (15 orgs / 90 days) is frozen and stays frozen.
- Deploy-path gates only run post-merge (`preview`/`production` show `skipping` on PRs). Run the full local gate set before merging anything in this plan.

---

## Phase 0 — Stop asserting something false (P0, ship first, alone)

The live privacy policy affirmatively denies systems that exist. This is the only finding with legal exposure and it should ship as its own PR, ahead of everything else.

### Task 0.1: Disclose what the estimator actually collects

**File:** `site/privacy.html:15` ("Website delivery"), via its generator in `scripts/ci/guard_launch_gate.py`.

The live sentence is false in three places:

> "The site contains no custom contact form, event collector, customer account, proof API, or **TinyZKP analytics database**."

- [ ] Locate the renderer for the "Website delivery" section in `guard_launch_gate.py` and replace the blanket denial with an accurate disclosure. It must state, in plain language:
  - TinyZKP operates a Cloudflare D1 database for the resource estimator.
  - `POST /v1/estimate` records, per request: the hour (not the timestamp), a request digest, the declared field/extension degree, **bucketed** trace width and row count, boolean feature flags, whether the config is provable today, blocking reason codes, and **either** a minted key id **or** a hash derived from the caller's IP — never both (`migrations/0001_demand_log.sql`).
  - It records **no** workload, witness, AIR, trace, proof, path, or email.
  - `POST /v1/keys` accepts an email **for shape validation only** and stores a SHA-256 of the minted key plus an independent random key id. **The email is never stored** (`migrations/0002_keys.sql`).
  - Why the data exists: to evaluate a pre-committed demand threshold. Not advertising, not resale, not profiling.
- [ ] **Disclose the IP-hash limitation honestly.** `IP_HASH_SALT` (`site/_worker.js:89`) is a hardcoded constant in a public repository. IPv4 has 2³² preimages, so `anon_ip_hash` is **reversible by anyone** and is not anonymisation. The worker's own comments already concede this; the privacy policy must not imply protection the construction does not provide. State that it is a coarse de-duplication token, not an anonymising transform.
  - **Do not "fix" this by inventing a secret salt in this task.** The static site deliberately has no secret surface (`scripts/ci/cloudflare_pages_secret_check.py` asserts it). Changing that is a separate decision; see Task 5.2. Disclosure now, architecture later.
- [ ] State a retention period. If none is currently enforced, say so plainly and open Task 5.3 to add one — do not imply a policy that no code implements.

**Verify:** `/opt/homebrew/bin/python3 scripts/ci/guard_launch_gate.py --write` then `--check`; `/usr/bin/python3 scripts/ci/site_route_check.py`; `python3 scripts/ci/claim_containment_scan.py`.

### Task 0.2: Correct the machine-readable denials

**File:** `site/discovery.json`, via `guard_launch_gate.py`.

- [ ] `event_collector: false` → `true`. The `demand_log` table is an event collector by any reasonable reading; the flag was accurate before Phase 1b and is not now.
- [ ] `customer_accounts`: keep `false`, and add an adjacent, more precise flag rather than overloading this one. A minted bearer key with no password, no dashboard, no recovery, and no stored email is genuinely *not* an account, and flipping this to `true` would be its own misstatement. Add `anonymous_api_keys: true`.
- [ ] Add `resource_estimator_api: true` so the retired-hosted-service flags (`hosted_proving`, `hosted_verification`, both correctly `false`) are not read as "no API at all".

### Task 0.3: The gate that stops this recurring

This is the load-bearing part of Phase 0. Without it the disclosure rots the next time a column is added.

- [ ] Add `scripts/ci/privacy_disclosure_gate.py`. It must:
  1. Parse `migrations/*.sql` for every `CREATE TABLE` and its column list.
  2. Parse `site/_worker.js` for every `INSERT INTO <table>` and the bound column names.
  3. Assert every table and column that the worker writes appears in an explicit **disclosure manifest** (`site/privacy-disclosure-v1.json`, new) that `privacy.html` is rendered from.
  4. **Fail on any undisclosed write.** A new column in `demand_log` must break CI until the privacy copy names it.
- [ ] Add `scripts/ci/test_privacy_disclosure_gate.py` with a **negative test**: add a synthetic undisclosed column to a fixture and assert the gate fails. A gate that has never been observed failing is not evidence of anything — this repo has already shipped one silently-broken gate (`plonky3_compatibility_gate.py`) and one orphaned always-failing gate (`offer_metadata_check.py`).
- [ ] Wire it into `.github/workflows/ci.yml` in the `static-contracts` job. **Confirm by observation**, not by reading YAML: push a branch with a deliberate violation and watch CI go red, then revert.

---

## Phase 1 — Make the kill criterion measurable (P0)

`scripts/ci/demand_report.py:59` freezes: *fewer than 15 distinct keyed organisations in 90 days ⇒ `KILL_THRESHOLD_MET`.* Today that number cannot be anything but zero, for reasons that have nothing to do with demand:

- `/estimate` is **absent from `sitemap.xml`**, which still lists withdrawn `/guard` as canonical.
- `/estimate` is **absent from `llms.txt`** (0 occurrences), which instead instructs agents: *"Do not describe TinyZKP as a hosted prover, proof API, … agent product."*
- `site/docs.html` never mentions the estimator (0 occurrences), so the CLI documentation page does not lead anyone to the hosted endpoint.

> **CORRECTED 2026-07-29, during execution.** The review originally also claimed `POST /v1/keys` was referenced on zero live pages. **That was wrong.** `site/estimate.html:111` has a visible "Get a free key" form that posts to `/v1/keys` via `site/estimate.js:178`, and the page's "What we store" section already disclosed the demand log accurately. The original grep looked for the literal string `v1/keys` in the HTML and missed the call in the JS.
>
> The consequence is that this phase is **narrower than planned**: minting is already discoverable and usable *once a caller reaches `/estimate`*. The defect is reaching it at all — the page is in no sitemap, no `llms.txt`, and was actively disclaimed to agents. Task 1.1 drops the redundant "document key minting on estimate.html" step.

A `KILL` verdict from this configuration is a **non-result** — indistinguishable from "nobody could find it". This is the achievability-precheck failure mode, and the mitigation is the same one used elsewhere in this repo: refuse to emit the verdict until the measurement is capable of producing the other answer.

### Task 1.1: Make the product discoverable

- [ ] Add `https://tinyzkp.com/estimate` to `sitemap.xml` (via the generator). Decide `/guard`'s fate alongside Phase 2 — it stays only if the withdrawal notice is genuinely the intended landing page, and if so its `<lastmod>` must be current.
- [ ] Rewrite the `llms.txt` renderer:
  - Lead with the estimator — it is the live product. Guard is history.
  - Delete "Guard: $499/month or $4,990/year" and "checkout is closed pending signed launch evidence" (see Phase 2 for the correct framing).
  - Document `POST /v1/estimate` and `POST /v1/keys` with a request shape.
  - **Narrow the disclaimer.** "Do not describe TinyZKP as a hosted prover, proof API, receipt system, MCP server, agent product…" was written when all of those were false. `/v1/estimate` is now a hosted API. Keep the accurate half (not a prover, not a receipt system, no MCP endpoint) and drop the half that now suppresses the one true thing.
- [ ] ~~Document key minting on `site/estimate.html`~~ — **already done**; see the correction above. `estimate.html:111` has the form and `estimate.html`'s "What we store" already describes the demand log.
- [ ] Document the estimator on `site/docs.html` (currently 0 mentions): a copy-pasteable `curl` for `POST /v1/estimate` and `POST /v1/keys`, what a key does (raises the ceiling from 30/hr to 300/hr), and — stated plainly — that minting one is how a caller is counted as a distinct organisation. People are more willing to be counted when told why.

### Task 1.2: Stop discarding the strongest demand signal

**File:** `site/_worker.js:356` (`logDemand`).

`logDemand` early-returns unless the response carries `provable_today` and `estimates`. Every rejected request — malformed schema, oversized body, unparseable JSON — is dropped and counted **nowhere**. Someone attempting to integrate and failing on the request shape is the strongest possible signal of demand, and it is currently invisible. (The review reproduced this: a plausible-looking hand-written request was rejected with a bare `manifest_contract_invalid` and left no trace.)

- [ ] Add `migrations/0003_rejected_log.sql` — a shape-only table: `observed_at_hour`, `reason_code`, and the same mutually-exclusive `key_id` / `anon_ip_hash` pair. **No request body, ever** — a malformed body is exactly where a witness or a path is most likely to leak in.
- [ ] Extend `logDemand` (or add a sibling) to record error envelopes to that table. Keep it fire-and-forget via `ctx.waitUntil`; it must never delay or fail a response.
- [ ] Surface `rejected_requests_by_reason` in `demand_report.py`, reported **separately** and never summed into any demand count — the same discipline the script already applies to keyed vs. anonymous counts.
- [ ] Improve the rejection itself: `manifest_contract_invalid` with no indication of *which* field was wrong is poor DX for a self-serve tool whose entire job is self-service. Return the offending field path in the reason envelope if the contract allows it without a schema break; otherwise record it and open a follow-up.

### Task 1.3: The achievability precheck

**File:** `scripts/ci/demand_report.py`.

- [ ] Add a `discoverability_preconditions` block, computed from the repo, not asserted by hand:
  - `/estimate` present in `sitemap.xml`
  - `/estimate` and `/v1/keys` present in `llms.txt`
  - `v1/keys` documented in `site/estimate.html`
  - a `demand_clock_started_at` date recorded in a committed file, set to the date all of the above first became true
- [ ] **Gate the verdict on it.** If any precondition is false, or fewer than 90 days have elapsed since `demand_clock_started_at`, emit `VERDICT_MEASUREMENT_INVALID` (new) instead of `KILL_THRESHOLD_MET`, with the specific unmet precondition named in the output. `CONTINUE` remains reachable — a real signal arriving early is still a real signal.
- [ ] **Delete the now-stale caveat** at `demand_report.py:42-45` ("Until Task 5 ships free keys… the expected, honest state of an unstarted clock"). Keys shipped. That paragraph is the only thing currently preventing a reader from taking a zero at face value, and it no longer describes reality — replace it with a pointer to the precondition block.
- [ ] Add a test asserting the verdict is `MEASUREMENT_INVALID` when a precondition is unmet **even if the org count is zero**. This is the whole point: the verdict must not be reachable by accident.

**Do not** move the threshold, widen the window, or let anonymous traffic count. The criterion's severity is the feature.

---

## Phase 2 — Land the Guard withdrawal on machine surfaces (P1)

The commercial data model has **no representation for a withdrawn SKU**. `scripts/commercial/render_offers.py:227-231, 268-271` admits exactly three states — `live` / `frozen` / `closed` → `InStock` / `InStock` / `OutOfStock`. So a withdrawn product is indistinguishable from a temporarily closed one, everywhere a machine reads.

Meanwhile the only gate touching withdrawal (`scripts/ci/test_guard_site_contract.py:328`) asserts the word "withdraw" appears somewhere in the HTML. It passes green while every machine surface contradicts it — a gate manufacturing false confidence.

### Task 2.1: Add `withdrawn` as a first-class state

- [ ] `scripts/commercial/render_offers.py`: add `withdrawn` to the legal `sales_state` set (line 230), map it to product availability `"withdrawn"` (line 268), and map the schema.org offer availability to **`https://schema.org/Discontinued`** (line 326). `OutOfStock` means *temporarily unavailable* — Google reads it as a product that is coming back.
- [ ] `site/pricing.json`: `sales_state: "withdrawn"`; guard `availability: "withdrawn"`. Retain `prices` **as historical record** for the price-lock obligation to any grandfathered subscriber — but the renderer must no longer present them as an offer.
- [ ] `site/commerce.json`: move `price_policy` under a `historical_price_policy` key. `price_lock` and `existing_subscribers_grandfathered` are live *obligations* and must not be deleted; they must simply stop reading as a current price sheet.
- [ ] Regenerate `offers.jsonld` via `render_offers.py`; confirm both Guard offers now carry `Discontinued`.
- [ ] Update the price assertions at `render_offers.py:261-264` (currently hard-asserting `499` / `4990`) so they validate the historical record rather than a live offer.

### Task 2.2: Bind copy to data, in both directions

- [ ] Replace the substring check at `test_guard_site_contract.py:328` with a bidirectional gate:
  - if any pricing surface says `withdrawn`, the HTML **must** carry the withdrawal notice; **and**
  - if the HTML carries the withdrawal notice, `pricing.json`, `commerce.json`, and `offers.jsonld` **must** all reflect `withdrawn` / `Discontinued`.
- [ ] Negative test both directions: perturb each surface independently and assert the gate fails each time.

---

## Phase 3 — Retract the dead external listings (P1)

These are the only findings that reach users who never visit the site, and they advertise capabilities that were deleted from the repository.

### Task 3.1: `server.json` (MCP registry)

Every field is wrong: `remotes[0].url` → `https://mcp.tinyzkp.com/mcp` (**410**); `_meta…contactUrl` → `/requests` (**410**); `repository.subfolder` → `crates/hc-mcp`, **a crate deleted in `b4570c5`**.

- [ ] Decide: delist from the MCP registry, or retain a truthful capability-only entry. **Recommend delisting** — the description already concedes that proving, verification, accounts, keys, and checkout are all unavailable, which describes no product.
- [ ] If retained: fix all three fields, point `websiteUrl`/`contactUrl` at surfaces that return 200, and drop `subfolder` entirely.
- [ ] Either way, publish the change to the registry — editing the file in-repo changes nothing users see.

### Task 3.2: `smithery.yaml`

Advertises the dead endpoint, "100 evaluation receipts/month", "Get a free key at https://tinyzkp.com/signup" (**410**), and ten tools that no longer exist.

- [ ] Delete the file and delist from Smithery. There is no version of this manifest that is both truthful and worth publishing.
- [ ] Same for `glama.json` if a Glama listing exists.

### Task 3.3: The claude.ai connector

A TinyZKP MCP connector is registered on the owner's claude.ai account and points at the 410 host.

- [ ] **Owner action, not automatable:** remove it from claude.ai connector settings.

### Task 3.4: Gate it

- [ ] Extend `scripts/ci/site_route_check.py` (or add `external_listing_check.py`) to resolve every URL appearing in `server.json`, `smithery.yaml`, `glama.json`, and `site/llms.txt` against the live site's route table, failing on any that maps to a 410 or a missing route. This is a pure-static check — no network needed, since the retired hosts and redirects are already declared in `site/_worker.js`.

---

## Phase 4 — Gate hygiene (P2)

The review found ~10 orphaned gates and ~24 "tested-only" gates whose unit tests run in CI but which never execute against real repository state. `scripts/ci/offer_metadata_check.py` is both orphaned **and failing** (`site/.well-known/tinyzkp-offers.json is missing`). Some of these are legitimately owner-run and manual — this needs triage, not a purge.

### Task 4.1: Triage

- [ ] Classify every non-`test_` script in `scripts/ci/`, `scripts/commercial/`, `scripts/deploy/` as exactly one of: **wired** (runs in a workflow), **manual** (owner-run, intentionally not in CI), or **retired** (belongs to a withdrawn surface).
- [ ] Delete the retired ones — `backend_recovery_gate.py` and friends belong to the retired hosted stack.
- [ ] Fix or delete `offer_metadata_check.py`. If `.well-known/tinyzkp-offers.json` should exist, generate it in Phase 2; if not, the gate is dead code that has been failing unobserved.

### Task 4.2: The meta-gate

- [ ] Add `scripts/ci/gate_wiring_check.py`: every executable script must be referenced by a workflow **or** listed in a committed `scripts/ci/manual-gates.txt` allowlist with a one-line reason. Unclassified script ⇒ CI fails.
- [ ] Negative test: add an unclassified script to a fixture, assert failure.

This is the generalisation of the two silent-gate incidents already on record. It is the difference between having gates and having coverage.

---

## Phase 5 — Lower-severity engine and worker fixes (P2/P3)

Safe to batch into one PR after Phases 0–3.

- [ ] **5.1** Production `/v1/estimate` reports `engine_release_identity: "development-unreleased"`. Either bind a real release identity or make the string self-explanatory to an external caller.
- [ ] **5.2** `saltedIpHash("")` (`site/_worker.js`) collapses every caller into one rate-limit bucket when `CF-Connecting-IP` is absent. Cloudflare always sets it, so this is latent — handle the empty case explicitly rather than relying on the platform. Revisit the public-salt question here if a secret surface is ever introduced (see Task 0.1).
- [ ] **5.3** Implement and document a `demand_log` / `rejected_log` retention window, matching whatever Task 0.1 disclosed.
- [ ] **5.4** `crates/hc-plonky3/src/estimate_params.rs:99-100` — `checked_div(...).unwrap_or(2)` / `.unwrap_or(4)` silently substitutes Goldilocks-shaped defaults when `field_bytes == 0`, producing plausible-looking wrong numbers instead of an error. Return an error. (Not currently reachable from `/v1/estimate`, which resolves widths from a fixed table — fix it before that stops being true.)
- [ ] **5.5** `site/robots.txt` emits two `User-agent: *` groups; parsers differ on merge semantics. Emit one. *(The AI-crawler blocks are training-only — `OAI-SearchBot` and `Claude-SearchBot` are not blocked — so that stance is coherent and should be left alone.)*
- [ ] **5.6** `field_widths` accepts `koalabear` and `mersenne31` at `(4, 4)`. Neither crate is in `Cargo.lock` and `provable_today` is always false for them, so impact is bounded — but **verify Mersenne31's canonical Plonky3 extension degree before those strings are ever advertised**, since the estimator will happily emit confident numbers for them today.
- [ ] **5.7** CSP allows `static.cloudflareinsights.com` although no beacon is present on any page. Narrow the allowlist to what is actually loaded.

---

## Sequencing and PR boundaries

| PR | Phase | Rationale |
|---|---|---|
| 1 | Phase 0 | Legal exposure. Ships alone, reviewed on its own merits. |
| 2 | Phase 1 | Unblocks a business decision that is otherwise un-makeable. |
| 3 | Phase 2 | Commercial accuracy; independent of 1 and 2. |
| 4 | Phase 3 | External retractions; partly manual. |
| 5 | Phase 4 | Prevents recurrence of all of the above. |
| 6 | Phase 5 | Cleanup batch. |

Phases 2 and 3 can run in parallel with Phase 1 — they share no files.

## Definition of done

- [ ] Every gate added in this plan has been **observed failing** on a deliberate violation, then observed passing after revert. No gate is trusted on the strength of its source code.
- [ ] `demand_report.py` emits `MEASUREMENT_INVALID` today, and states exactly which precondition is unmet.
- [ ] No live surface — HTML, JSON, JSON-LD, `llms.txt`, `robots.txt`, or external registry — describes Guard as purchasable, the MCP endpoint as reachable, or the site as collecting nothing.
- [ ] `cargo test --workspace` green; the frozen known-answer constant in `bounded_prover.rs` unchanged.
- [ ] Full local deploy-path gate set run **before** merge, since `preview`/`production` skip on PRs.

## Explicitly out of scope

- Phase 3B (multi-table scheduling) and anything that opens the `tinyzkp-contracts` gate to a CLI-reachable BabyBear path.
- The Linux cgroup-v2 fixed-host qualification run for release-grade peak-RSS evidence.
- Introducing a secret surface to the static site (would invalidate `cloudflare_pages_secret_check.py`); Task 0.1 discloses the limitation rather than re-architecting around it.
- Any change to the kill threshold itself (15 organisations / 90 days). This plan makes the measurement valid; it does not make the bar easier.
