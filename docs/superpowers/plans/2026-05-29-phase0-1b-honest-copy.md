# Phase 0.1b — Honest Customer-Facing Copy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax.

**Goal:** Make every customer-facing surface (site, README, docs, the `tinyzkp-proofs` skill, MCP directory cards, marketing drafts) tell the truth that Phase 0.1a established in code: only `accumulator_step` is a live, predicate-enforcing proof; the other template types and the unbacked security/feature claims are removed. Also rebuild the `/try` playground around `accumulator_step` (functional, not just copy) and mark the Solidity verifier non-functional.

**Architecture:** A single **honesty rulebook** (below) is applied across all surfaces. One functional task (playground), several copy-sweep tasks (one per surface group, each subagent reads its files and applies the rulebook), one source-comment task (Solidity), and a final grep-based verification task that fails if any removed term survives in a live surface.

**Tech stack:** Markdown (README), static HTML/CSS/JS (`site/`), Cloudflare Pages Function (`demo-prove.js`), JSON (`server-card.json`), YAML (`smithery.yaml`), Solidity (comment only).

**Branch:** Continue on `roadmap/production-hardening` (PR #19). 0.1b MUST ship with 0.1a because 0.1a's gate breaks the range_proof-based playground until 0.1b repoints it.

**User decisions baked in (2026-05-29):**
- Non-enforced templates: **remove entirely** from customer pages (no "Preview" labels). Show only `accumulator_step` + "more coming soon".
- Tone: **quiet correction** — NO "undergoing audit / hardening" messaging anywhere.

---

## The Honesty Rulebook (apply to every surface)

**REMOVE / REPLACE:**
- **R1 — Non-live proof types.** Remove all customer-facing presentation of `range_proof`, `hash_preimage`, `computation_attestation`, `policy_compliance`, `data_integrity`, `zkml_matmul`, `spartan_r1cs` as if usable. This includes: feature lists, "what you can prove" tables, per-template examples, NL use-cases in the skill, and directory catalog entries. Replace example snippets that used `range_proof` with the canonical `accumulator_step` example (R6). Where a sentence enumerates proof types ("range proofs, hash preimages, …"), replace with the single live capability.
- **R2 — Template counts.** Remove "8 templates", "6 production templates", "6 built-in templates", "All 6 proof templates", etc. Replace with language like "state-transition (accumulator) proofs, with more proof types in development." Do NOT state a count.
- **R3 — Unbacked security claims.** Remove every instance of `128-bit`, `≥128-bit`, `≥128-bit soundness`, "production prover", "the only production prover", "production STARK prover", "production-grade", "production-ready". KEEP the architectural truths: `O(√N)`/`O(√T)` memory, "transparent (no trusted setup)", "ZK-STARK". For "post-quantum": KEEP factual descriptor "hash-based" / "post-quantum (hash-based)" but REMOVE the word "secure" when attached (i.e. "post-quantum secure" → "post-quantum (hash-based)").
- **R4 — Unshipped features.** Remove customer-facing claims that the following are available/shipped: **on-chain / EVM verifier** ("EVM on-chain ready", "/calldata for on-chain verification", "on-chain verifier contract"), **recursive aggregation** ("recursive aggregation", "aggregate proofs into one" as a product feature), **KZG / Halo2** wrapping. (The `/aggregate` and `/proof/:id/calldata` endpoints still exist but must not be marketed.) Do NOT add "coming soon" for these — just remove (quiet correction). Competitor mentions of recursion/aggregation (e.g. "RISC Zero uses continuations") are factual about others and stay.
- **R6 — Canonical example.** Everywhere an example proof call is shown, use `accumulator_step`:
  - curl: `curl -X POST https://api.tinyzkp.com/prove/template/accumulator_step -H "Authorization: Bearer tzk_..." -H "Content-Type: application/json" -d '{"params":{"initial":1000,"final":1045,"deltas":[10,20,15]}}'`
  - Python: `await client.prove_template("accumulator_step", params={"initial":1000,"final":1045,"deltas":[10,20,15]})`
  - TS: `await client.proveTemplate("accumulator_step", { initial:1000, final:1045, deltas:[10,20,15] })`
  - CLI: `npx @tinyzkp/cli prove accumulator_step '{"initial":1000,"final":1045,"deltas":[10,20,15]}' --wait`

**KEEP (do not touch):** the √T value prop, "ZK-STARK proofs as an API", the MCP wedge + "10 tools" count (the tools are real), transparent/no-trusted-setup, ZK-masked mode (v4 exists), the free-tier framing, pricing *plans* (Free/Developer/Scale) — but see R5 for the Compute tier.

- **R5 — Compute tier (`compute.html` + index Compute card).** The Compute tier sells zkVM/zkML/rollup long-trace proving, which is not honestly available (zkML is structural-only, zkVM stubbed). Soften it: keep the √T *architecture* explanation (it's the real differentiator) but mark the long-trace **product** as in development — e.g. change "the Compute tier rents it" / hard sell into "in development". Remove `≥128-bit` per R3. Do NOT claim zkVM/zkML proofs are available today.

---

## Task 1: Rebuild the `/try` playground around `accumulator_step` (FUNCTIONAL)

**Files:**
- Modify: `site/functions/api/demo-prove.js`
- Modify: `site/try.html`

The playground is currently a `range_proof` demo end-to-end. Rebuild it to demo `accumulator_step` (params `{initial, final, deltas[]}`), which is the only live template. To guarantee the demo always succeeds, the client computes `final = initial + sum(deltas)` (the template's `build` rejects a mismatch).

- [ ] **Step 1: Rewrite `demo-prove.js`**

Replace the whole file with (note the new upstream path, the new validate(), and the new request body):

```javascript
// Cloudflare Pages Function — proxies a single canned `accumulator_step` proof
// to api.tinyzkp.com using a server-side demo API key. Heavily rate-limited by
// IP so this is safe to expose to anonymous /try traffic.
//
// Secret required (set via wrangler):
//   TINYZKP_DEMO_API_KEY  — a tzk_... key for a demo tenant with low caps.
//
// Request body: {initial: number, deltas: number[]}
//   - initial: 0..1000
//   - deltas: 1..10 ints, each 0..1000
//   final is computed server-side as initial + sum(deltas) so the proof always
//   builds (the template rejects a mismatched final).
//
// Returns: {job_id, status, eta_ms} from upstream, or {error}.

const RATE_LIMIT_MAX = 5;          // 5 demo proofs per IP per window
const RATE_LIMIT_WINDOW_S = 3600;  // 1-hour window
const UPSTREAM = "https://api.tinyzkp.com/prove/template/accumulator_step";

async function checkRateLimit(ip) {
  const cache = caches.default;
  const key = new Request(`https://rate-limit.internal/demo-prove/${ip}`);
  const cached = await cache.match(key);
  let count = 0;
  if (cached) count = parseInt(await cached.text(), 10) || 0;
  if (count >= RATE_LIMIT_MAX) return false;
  const resp = new Response(String(count + 1), {
    headers: { "Cache-Control": `s-maxage=${RATE_LIMIT_WINDOW_S}` },
  });
  await cache.put(key, resp);
  return true;
}

function corsHeaders(origin) {
  const allowed = origin === "https://tinyzkp.com" || origin === "https://www.tinyzkp.com"
    ? origin : "https://tinyzkp.com";
  return {
    "Access-Control-Allow-Origin": allowed,
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
  };
}

function validate(body) {
  const { initial, deltas } = body || {};
  if (typeof initial !== "number" || !Number.isFinite(initial) || initial < 0 || initial > 1000) {
    return "initial must be a number in [0, 1000]";
  }
  if (!Array.isArray(deltas) || deltas.length < 1 || deltas.length > 10) {
    return "deltas must be an array of 1..10 ints";
  }
  for (const d of deltas) {
    if (typeof d !== "number" || !Number.isFinite(d) || d < 0 || d > 1000) {
      return "each delta must be in [0, 1000]";
    }
  }
  return null;
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin") || "";
  const headers = { "Content-Type": "application/json", ...corsHeaders(origin) };
  try {
    const ip = context.request.headers.get("cf-connecting-ip") || "unknown";
    if (!(await checkRateLimit(ip))) {
      return new Response(JSON.stringify({
        error: "Rate limit reached. Try again in an hour, or sign up for a free key for unlimited proofs.",
        signup: "https://tinyzkp.com/signup",
      }), { status: 429, headers });
    }
    const body = await context.request.json();
    const err = validate(body);
    if (err) return new Response(JSON.stringify({ error: err }), { status: 400, headers });

    const apiKey = context.env.TINYZKP_DEMO_API_KEY;
    if (!apiKey) {
      return new Response(JSON.stringify({ error: "demo unavailable (server misconfigured)" }), {
        status: 500, headers,
      });
    }

    const finalVal = body.deltas.reduce((a, d) => a + d, body.initial);
    const upstream = await fetch(UPSTREAM, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        params: { initial: body.initial, final: finalVal, deltas: body.deltas },
      }),
    });
    const json = await upstream.json();
    if (!upstream.ok) {
      console.error("demo-prove upstream error:", JSON.stringify(json));
      return new Response(JSON.stringify({ error: "upstream proving failed" }), {
        status: 502, headers,
      });
    }
    return new Response(JSON.stringify(json), { status: 200, headers });
  } catch (e) {
    console.error("demo-prove error:", e);
    return new Response(JSON.stringify({ error: "internal error" }), { status: 500, headers });
  }
}

export async function onRequestOptions(context) {
  return new Response(null, { headers: corsHeaders(context.request.headers.get("Origin") || "") });
}
```

- [ ] **Step 2: Rebuild the `try.html` form + JS**

Read `site/try.html`. Replace the range-proof input section and its JS handler so the demo proves an accumulator chain:
- Card copy (was "Prove you know a number in [min,max]…"): change to *"Prove that starting from an initial value and applying a sequence of deltas reaches the final value — without revealing the deltas. The verifier only learns the start and end."*
- Inputs: replace `min`/`max`/`witness_steps` with `initial` (number 0..1000, default `0`) and `deltas` (comma-separated 1..10 ints each 0..1000, default `5, 3, 7`). Show a read-only computed `final` = initial + sum(deltas) (update live) so the user sees what's being proven.
- JS handler: parse `initial` + `deltas`; validate (initial 0..1000; 1..10 deltas each 0..1000); POST `{ initial, deltas }` to `/api/demo-prove`. Remove the old `value > max` pre-flight; it no longer applies.
- Keep the existing poll + verify steps unchanged (they operate on the returned `job_id` / proof and are template-agnostic).
- Any surrounding marketing copy on the page mentioning range/min/max → reword to the accumulator framing.

- [ ] **Step 3: Verify**

`rg -n "range_proof|min, max|witness_steps" site/try.html site/functions/api/demo-prove.js` → no matches (all replaced).
(There is no local runtime for the CF function; correctness is by inspection + the upstream contract. Confirm the request body shape matches `accumulator_step` params: `{params:{initial,final,deltas}}`.)

- [ ] **Step 4: Commit**

```bash
git add site/try.html site/functions/api/demo-prove.js
git commit -m "feat(site): rebuild /try playground around accumulator_step

range_proof is gated off by default (Phase 0.1a); repoint the only public
demo to the one live, predicate-enforcing template so /try keeps working
post-deploy.

Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>"
```

---

## Task 2: README.md honesty sweep

**Files:** Modify: `README.md`

- [ ] **Step 1: Apply the rulebook.** Read `README.md` and apply R1–R6:
  - Headline/intro: keep "ZK-STARK proofs / verifiable receipts", remove any "production"/"128-bit".
  - "What you can prove" tables (two of them) and the "Proof templates" table: reduce to a single `accumulator_step` row; remove the other 5 + the 2 Preview rows; remove the "Six production templates… plus two preview" sentence and the "Eight built-in templates" line (R1, R2).
  - All curl/Python/TS/CLI/`/prove` examples using `range_proof` or `accumulator_step` with the toy IDs → the canonical `accumulator_step` example (R6). Fix the fake `prf_a1b2c3` job IDs to a UUID-style placeholder `<job_id>`.
  - Comparison table (Property | hc-stark | Standard STARK): drop any "128-bit" row if present; keep √T, transparent, post-quantum (hash-based) — change "Post-quantum (hash-based)" row value from any "secure" wording to just "Yes (hash-based)".
  - Pricing section: keep the plans + per-proof rate table (those are real), but remove proof-type enumerations tied to templates.
  - Roadmap "Shipped" / "Recently shipped" lists: remove the bullets claiming on-chain verifier contract, recursive aggregation, EVM calldata, KZG/Halo2 as shipped product features (R4). Leave genuinely-shipped items (MCP, SDKs, WASM verifier, free tier, monitoring).
  - MCP section: keep ("10 tools" is accurate); ensure the `prove_template` example uses `accumulator_step`.
- [ ] **Step 2: Verify** `rg -ni "range_proof|hash_preimage|computation_attestation|policy_compliance|data_integrity|zkml_matmul|spartan_r1cs|128-bit|production prover|on-chain|recursive aggregation|\bKZG\b|EVM calldata" README.md` → only acceptable residue (e.g. a single mention in a clearly-internal context) — ideally zero. Report any remaining and why.
- [ ] **Step 3: Commit** `docs(readme): remove non-live templates + unbacked claims (honest catalog)` (with Co-Authored-By trailer).

---

## Task 3: `site/index.html` honesty sweep

**Files:** Modify: `site/index.html`

- [ ] **Step 1: Apply the rulebook.** Read `site/index.html` and apply R1–R6 to: the `<meta>`/OG/Twitter descriptions + JSON-LD `description` (remove "production prover"; keep √N framing); the FAQ JSON-LD "post-quantum secure" → "post-quantum (hash-based)"; the hero "The only production prover that runs in O(√N)…" → "Runs in O(√N) memory instead of O(N)…" (drop "only production"); the curl/Python/TS/CLI example blocks (range_proof → accumulator_step, R6); "Choose from 6 built-in templates" → "Use the `accumulator_step` template — more proof types in development"; the "Range proofs, hash preimages, policy compliance, data integrity, accumulator steps, computation attestations." blurb → "State-transition (accumulator) proofs today — more proof types in development."; "/calldata for on-chain verification" sentence → remove the on-chain clause (keep the free `/verify`); the Compute card "≥128-bit soundness" → remove (R3/R5); "Same cryptographic guarantees: ZK-STARK, ≥128-bit soundness, transparent, post-quantum." → "Same architecture: ZK-STARK, transparent, post-quantum (hash-based)."; proof badges: remove "EVM on-chain ready", change "Post-quantum secure" → "Post-quantum (hash-based)", keep "No trusted setup".
- [ ] **Step 2: Verify** `rg -ni "range_proof|hash_preimage|policy compliance|data integrit|computation attestation|128-bit|only production|production prover|on-chain|EVM on-chain|post-quantum secure" site/index.html` → zero matches (or report residue).
- [ ] **Step 3: Commit** `docs(site): honest homepage — accumulator_step only, drop unbacked claims`.

---

## Task 4: Remaining site pages (`compute.html`, `welcome.html`, `account.html`, `terms.html`, `signup.html`, `docs.html`)

**Files:** Modify: `site/compute.html`, `site/welcome.html`, `site/account.html`, `site/terms.html`, `site/signup.html`, `site/docs.html`

- [ ] **Step 1: Apply the rulebook per page.**
  - `docs.html` (the heaviest — 27 template refs): reduce all per-template docs/examples to `accumulator_step`; remove the other template sections; fix the documented poll/verify examples to use `accumulator_step`; remove "6 templates" language; remove on-chain `/calldata` as a featured capability (R1, R2, R4, R6).
  - `compute.html`: apply R5 — keep the √N architecture explanation + competitor-continuation discussion, remove "only production STARK prover" → "a STARK prover", remove all "≥128-bit soundness" bullets/lines, mark the long-trace zkVM/zkML **product** as in development (do not claim it's available), drop "post-quantum" "secure" wording per R3.
  - `welcome.html`: the onboarding curl (`/prove/template/range_proof`) → `accumulator_step` (R6); "All 6 proof templates" → "the accumulator_step template (more in development)"; the NL-prompt example "anything that maps to a template" → an accumulator/state-transition example.
  - `account.html`: the two `range_proof` curl snippets (the static one ~line 556 and the JS-built `var cmd` ~line 1220) → `accumulator_step` (R6); the `/docs#templates` link can stay.
  - `terms.html`: check the "on-chain" mention; if it's a feature/marketing claim, remove; if it's legal boilerplate (e.g. "you may use proofs on-chain at your own risk"), leave it.
  - `signup.html`: verify it does not enumerate templates/claims; if it mentions "6 templates" or a removed claim, fix; otherwise no change.
- [ ] **Step 2: Verify** `rg -ni "range_proof|hash_preimage|policy compliance|data integrit|computation attestation|128-bit|only production|production STARK|post-quantum secure|on-chain verif|EVM on-chain" site/compute.html site/welcome.html site/account.html site/terms.html site/signup.html site/docs.html` → zero (or reported residue with justification).
- [ ] **Step 3: Commit** `docs(site): honest docs/compute/account/welcome copy`.

---

## Task 5: Skill + MCP directory cards (`SKILL.md`, skill `README.md`, `server-card.json`, `smithery.yaml`)

**Files:** Modify: `skills/tinyzkp-proofs/SKILL.md`, `skills/tinyzkp-proofs/README.md`, `deploy/server-card.json`, `smithery.yaml`

- [ ] **Step 1: Apply the rulebook.**
  - `SKILL.md` + skill `README.md`: the skill routes natural language → templates. Rewrite so it only routes to `accumulator_step` (state-transition / "starting at X, applying deltas, reaches Y" / spending-cap-as-running-sum framed honestly as accumulator). REMOVE the range/hash-preimage/policy/data-integrity/computation routing and examples (R1). Remove "128-bit"/"production" claims (R3). Keep the honest trust-contract section.
  - `server-card.json`: remove the non-live templates from any tools/capabilities/`configSchema` catalog; keep the real tool list (`list_templates`, `prove_template`, etc.). Remove unbacked claims from descriptions (R3/R4).
  - `smithery.yaml`: same — the tools catalog stays (tools are real), but remove non-live template enumerations and unbacked claims from descriptions.
- [ ] **Step 2: Verify** `rg -ni "range_proof|hash_preimage|policy_compliance|data_integrity|computation_attestation|zkml_matmul|spartan_r1cs|128-bit|production" skills/tinyzkp-proofs/ deploy/server-card.json smithery.yaml` → zero (or reported residue).
- [ ] **Step 3: Commit** `docs(skill,mcp): honest skill routing + directory cards`.

---

## Task 6: Mark the Solidity verifier non-functional

**Files:** Modify: `contracts/StarkVerifier.sol`

- [ ] **Step 1:** Add a prominent NOTICE banner at the very top of the file (after the SPDX line), and a `revert` is NOT required — just an unmistakable comment so no one mistakes it for a deployable verifier:

```solidity
// ============================================================================
// NOTICE: NON-FUNCTIONAL PLACEHOLDER — DO NOT DEPLOY.
// This contract does NOT verify proofs. `verifyProof` returns true after a
// partial parse (no Merkle/FRI checks), the embedded verification-key
// constants are placeholders, and the file is not part of any audited or
// shipped on-chain verification path. On-chain verification is future work
// (see the production-hardening roadmap, Phase 4). Tracked so the source is
// in version control; it is intentionally excluded from the product surface.
// ============================================================================
```
(Do not change any logic; this is a comment-only change. If the file currently does not compile due to the stray `b tried29f` literal, leave the logic as-is — it is explicitly non-functional — but you MAY fix only that one malformed hex literal to a syntactically-valid placeholder `0x25f83c43523e8ce6a8d3aa7e99d4cfd3bcfa3ee33415aeeaa3dd6a17b00029f` if a compile is desired; note it in your report.)

- [ ] **Step 2: Commit** `docs(contracts): mark StarkVerifier.sol as a non-functional placeholder`.

---

## Task 7: Marketing drafts sweep (lower priority — not yet published)

**Files:** Modify: `marketing/HN_LAUNCH.md`, `marketing/X_THREAD.md`, `marketing/OUTBOUND_EMAIL.md`, `marketing/INTEGRATION_CURSOR.md`, `marketing/INTEGRATION_LANGCHAIN.md`, `marketing/MCP_DIRECTORY.md`, `marketing/MCP_DIRECTORY_MCPSO.md`, `marketing/MCP_DIRECTORY_SMITHERY.md`, `marketing/USER_INTERVIEWS.md`, `marketing/screenshots/render_shots.py`

- [ ] **Step 1:** These are unpublished drafts, so this prevents a future overclaim rather than fixing a live one. Apply R1–R6 to each: remove non-live template enumerations/examples, remove "128-bit"/"production"/on-chain/recursion/KZG claims, switch any example to `accumulator_step`. Keep the √T + MCP positioning.
- [ ] **Step 2: Verify** `rg -ni "range_proof|hash_preimage|policy_compliance|data_integrity|computation_attestation|zkml_matmul|spartan_r1cs|128-bit|on-chain verif" marketing/` → zero (or reported residue).
- [ ] **Step 3: Commit** `docs(marketing): align launch drafts with honest catalog`.

---

## Task 8: Final cross-surface verification

**Files:** none (verification only)

- [ ] **Step 1:** Run the master grep across ALL live customer surfaces and confirm no removed term survives:
```bash
rg -ni "range_proof|hash_preimage|computation_attestation|policy_compliance|data_integrity|zkml_matmul|spartan_r1cs|128-bit|≥128-bit|only production|production prover|production STARK|post-quantum secure|EVM on-chain|on-chain verif|recursive aggregation|\bKZG\b" \
  README.md site/ skills/ deploy/server-card.json smithery.yaml contracts/StarkVerifier.sol
```
Expected: zero matches in live surfaces (competitor-context mentions of recursion in `compute.html`, and the Solidity NOTICE's own mention of "on-chain verification is future work", are acceptable — list any such expected residue explicitly).
- [ ] **Step 2:** Confirm the only live, advertised template anywhere is `accumulator_step`, and that every example call uses the R6 canonical params.
- [ ] **Step 3:** No commit (or a tiny `docs: final honesty-sweep verification` no-op if any straggler was fixed).

---

## Acceptance criteria (Phase 0.1b)

- `/try` works post-deploy: it proves an `accumulator_step` chain (the one live template), with no `range_proof` references in `try.html`/`demo-prove.js`.
- No customer-facing surface presents `range_proof`/`hash_preimage`/`computation_attestation`/`policy_compliance`/`data_integrity`/`zkml_matmul`/`spartan_r1cs` as usable; only `accumulator_step` is shown ("more coming soon").
- No `128-bit`, "production prover/STARK", "post-quantum secure", "EVM on-chain ready", "/calldata for on-chain verification", "recursive aggregation", or KZG/Halo2 product claims remain in live copy.
- `contracts/StarkVerifier.sol` carries an unmistakable non-functional NOTICE.
- Final master grep is clean (modulo explicitly-listed competitor/NOTICE residue).
- No code/logic changed except the `demo-prove.js` proxy + `try.html` form (and optionally the one Solidity hex literal); `cargo` builds are untouched.

## Out of scope (deferred / other phases)
- Pricing/checkout/signup *behavior* (e.g. pausing the Compute tier purchase) — a business decision, not copy; revisit in 0.3.
- The actual per-template AIRs (so range_proof returns as a real product) — Phase 1B.
