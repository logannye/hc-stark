# TinyZKP / hc-stark — Production-Hardening Master Roadmap

- **Status:** Approved (shape); per-phase specs/plans to follow
- **Date:** 2026-05-29
- **Author:** Logan Nye
- **Scope:** The `hc-stark` Rust ZK-STARK engine and the tinyzkp.com hosted service (API, MCP, billing, site, ops)
- **Type:** Master roadmap. This document is the umbrella; each phase gets its own `spec → plan → build` cycle as it is reached.

---

## 1. Background & motivation

A full-repo audit (2026-05-29) found that, while the business/distribution layer (API, MCP, SDKs, Stripe, monitoring) is largely well-built, the **cryptographic core is not sound as implemented** and several **production-reliability and truth-in-advertising gaps** exist. The two findings that invalidate the core product claim:

- **G1 — Templates don't prove their predicate.** All six "production" templates compile down to a toy accumulator AIR (`crates/hc-workloads/src/builtin.rs` hardcodes `[AddImmediate(1), AddImmediate(2)]`, `max_program_len: 2`; the verifier only knows `ToyAir` with public inputs limited to `initial_acc`/`final_acc`). So `range_proof` does not constrain a value to `[min,max]`, `hash_preimage` never arithmetizes a hash, etc. Only `accumulator_step` is honest.
- **G2 — FRI is not a valid low-degree test.** `fold_layer` (`crates/hc-fri/src/layer.rs`) folds `out[i] = v[2i] + β·v[2i+1]` over *adjacent*, natural-order pairs with no `x→x²` domain map and no domain-point weighting. The verifier mirrors the same fold, so the protocol is internally consistent but does not establish proximity to a low-degree codeword — the entire purpose of FRI. Standard STARK soundness does not close.

Supporting cryptographic gaps: base-field (64-bit) Fiat-Shamir challenges (D-5), a fake out-of-domain check the verifier trusts (D-7), no grinding, **no verifier-side security floor** (G7, params are read from the attacker-supplied proof), a quantitatively incorrect soundness proof (G9/D-9), a non-functional/non-compiling on-chain verifier (G5/D-4), and a KZG path with a hardcoded trusted-setup seed (G6/D-2).

Business/ops gaps: billing-portal account takeover by email with no auth (G3), magic-link returns the plaintext long-lived API key (G4), unlimited free-tier re-signup (G8), unmetered/uncapped zkML/Spartan/`/aggregate` paths (G9), unauthenticated `/metrics` leaking per-tenant revenue (G10), two divergent pricing systems with the Compute tier never billed (G11), metering edge cases (G12), a single-box SPOF holding the only copy of all state with no off-box backup (G13), the daily health audit running on a personal laptop (G14), repo hygiene (G15), and onboarding docs that contradict the live API (G16).

Full detail with `path:line` references is in the audit memory entry `project_hc_stark_audit_2026-05-29.md`.

## 2. Strategic decisions (inputs that shaped this roadmap)

| Decision | Choice | Implication |
|---|---|---|
| Proving core | **Fix & audit the homegrown √T engine** | Preserve the √T moat; invest in real soundness + a third-party audit rather than adopting an off-the-shelf prover. |
| Core moat | **The √T-memory engine itself** | The streaming O(√T) prover is the technical bet; it justifies the multi-month rebuild. |
| Live status | **Live, ~no real customers yet** | Harden fast and honestly; no incident-response/customer-comms drama, and we may take templates down or run in a controlled mode while rebuilding. |
| Resourcing | **Solo (Logan), willing to invest months** | Sequence deliberately rather than parallelize heavily; bias toward doing it correctly. |

**Governing principle:** *Soundness and honesty are non-negotiable and come first; performance, scale, and feature breadth follow a correct, audited base.* A guiding sub-decision: **make the STARK sound for the trivial statement first and ship `accumulator_step` as an honest MVP, then layer real AIRs onto the sound base** — rather than a big-bang rebuild.

## 3. Sequencing logic

`Phase 0` (days) runs now. `Phase 1` (soundness, the critical path) splits into **1A** (sound core) → **1B** (real arithmetization). `Phase 2` (correctness infrastructure) is woven through Phase 1 via test-driven development, not appended. `Phase 3` (production systems) front-loads its cheap/critical items into Phase 0 and defers the heavy Postgres cutover to just before relaunch. `Phase 4` is the external audit. `Phase 5` validates and monetizes the √T moat on the now-sound base.

```
Phase 0 ─► Phase 1A ─► Phase 1B ─► Phase 4 (audit) ─► Phase 5
              │            │
              └─ Phase 2 (TDD, woven through 1A/1B)
        Phase 3 (prod systems): cheap items in Phase 0; Postgres cutover before Phase 4 relaunch
```

---

## 4. Phases

### Phase 0 — Honest scope + stop-the-bleeding (days)

**Goal:** the service stops misrepresenting itself; the two takeover holes close; no unmetered compute path; backups land off-box. No crypto rebuilt yet.

- **Narrow templates to truth.** Gate all templates except `accumulator_step` behind an explicit `preview`/`unaudited` flag (or take them down). Update README, `site/`, `/docs`, `/templates`, MCP tool descriptions, and the `tinyzkp-proofs` Claude skill in lockstep.
- **Withdraw unbacked claims:** remove "on-chain verifier (shipped)", the KZG path, "128-bit", and "recursive aggregation" from all marketing until real and audited. Mark `contracts/StarkVerifier.sol` non-functional (it `return true`s and does not compile — `VK_DELTA_X1` contains stray text `b tried29f`).
- **G3 — billing-portal takeover:** require a proven factor (logged-in session or Bearer) before `site/functions/api/create-portal-session.js` mints a portal URL; bind the email to the authenticated tenant. Also fix the non-standard single-quoted Stripe search query.
- **G4 — magic-link leaks API key:** magic-link verification mints a short-lived session, never returns the raw `tzk_` key (`billing/provision_tenant.py`).
- **Cheap high-value patches:** auth-gate `/metrics` (G10); enforce per-email uniqueness + a payment/device gate on free signup (G8); disable or hard-cap+meter `/aggregate`, zkML, Spartan (G9); fix `trace_length` parse→cheapest-tier underbill (G12); rotate/remove `demo:demo_key` from `docker-compose.yml` (G15); `.gitignore` `.env`, `git rm --cached` the committed CF account file (G15); tighten `api.tinyzkp.com` CORS off `*` (G15); fix `welcome.html` status/format mismatch (G16).
- **First DR step (G13):** automated **off-box** nightly backup of `tenant_store.sqlite` / `usage.sqlite` / `api_keys.txt` to object storage, with a test-verified restore.

**Exit gate:** every public claim maps to something the code enforces; G3/G4 closed; no unmetered/uncapped compute path; off-box backup + restore verified.

### Phase 1A — Make the STARK sound (the core crypto, weeks)

**Goal:** the existing accumulator AIR becomes a genuinely sound STARK at a stated, provable security target. New protocol **v5**; v2/v3/v4 are rejected (no `allow_legacy`).

1. **Correct FRI folding.** Replace the adjacent-pair fold with proper coset FRI pairing **antipodal** points:
   `f'(x²) = ½·(f(x)+f(−x)) + β·(2x)⁻¹·(f(x)−f(−x))`, next layer on the squared domain (offset², generator², half size). Implementation: store LDE evaluations in **bit-reversed order** so antipodal pairs are adjacent (Winterfell/Plonky layout); the fold then reads neighbors *and* uses the domain point `x`. The verifier recomputes `x` per query and checks the fold equation layer-by-layer down to a final polynomial whose degree it explicitly bounds.
2. **Extension-field challenges (D-5).** Move all Fiat-Shamir-derived field challenges (α, β, ζ, DEEP combinations) and out-of-domain evaluations into the degree-2 extension `QuadExtension` (~128-bit). Trace and commitments stay in the base field.
3. **Real DEEP / OOD (D-7).** Sample `ζ ∈ F_ext` from the transcript; prover opens trace at `ζ` and `g·ζ` and the quotient at `ζ`; verifier checks the constraint identity at `ζ`; FRI proves low-degree of the DEEP quotients `(p(x)−p(ζ))/(x−ζ)`. **Verifier re-derives `ζ`; never reads it from the proof.**
4. **Grinding (proof-of-work).** Absorb a configurable (~20-bit) PoW nonce into the transcript before sampling query indices.
5. **Security floor by protocol version, enforced at the verifier (G7).** Bake `{blowup, query_count, grinding_bits, ext_degree}` into protocol v5 as constants the verifier knows from the version. The verifier rejects anything below the floor; stop reading these from `proof.params`.
6. **Correct, concrete soundness proof (G9).** Rewrite `docs/security/soundness_proof.md` with the real math — FRI soundness via code rate `ρ=1/blowup` and RS proximity-gap/list-decoding bounds, DEEP/Schwartz–Zippel terms over `F_ext`, and grinding — and choose parameters that provably reach the target (≥100-bit conjectured). This is the auditor's primary artifact.
7. **ZK (v4 mask) review.** Verify `T+Z_H·R` masking gives real zero-knowledge given the query count (mask degree ≥ #queries); fold the analysis into the soundness doc.

**Exit gate:** sound v5 prover/verifier for the accumulator statement; written, correct soundness proof with concrete parameters; **`accumulator_step` ships as an honest, sound MVP.**

### Phase 1B — Real arithmetization + honest templates (weeks→months)

**Goal:** each advertised template gets an AIR that actually enforces its predicate, on the sound v5 core.

- **Generalize the AIR layer first.** Wire the dormant constraint DSL into the v5 prover/verifier: multi-column traces, transition + boundary + periodic/selector columns, multiple constraints combined via α-powers, with correct quotient-degree bookkeeping. Reusable substrate for all templates.
- **`range_proof`:** bit-decomposition AIR — boolean-constrain bits, recompose, prove `x−min ≥ 0` and `max−x ≥ 0` via N-bit non-negativity.
- **`hash_preimage`:** reframe to **Poseidon2-over-Goldilocks** ("I know the Poseidon preimage") and implement its permutation AIR. (Blake3 is hostile to arithmetization; a bit-level AIR is not worth it.)
- **`policy_compliance`:** running-sum column + per-step range/threshold constraints.
- **`data_integrity`:** enforce the checksum relation (sum, or a Poseidon-based accumulator/Merkle for membership).
- **`computation_attestation`:** scope honestly — a constrained fixed field-op sequence now, or mark Preview and fold into the zkVM effort (Phase 5).

**Exit gate:** every non-preview template has an AIR + negative tests proving a false witness is rejected. Marketing copy re-enabled per template only as it passes.

### Phase 2 — Correctness infrastructure (woven through 1A/1B)

**Goal:** the soundness work is test-driven and independently checkable, not asserted.

- **Adversarial/negative suite:** tampered trace/quotient/FRI layers and forged low-degree claims are rejected; expand `fuzz/` to the new FRI + AIR paths.
- **Forge attempts as tests:** explicitly construct proofs of false statements (non-low-degree commitments; out-of-range range proof; wrong preimage) and assert rejection — the direct regression guard against the audited bug class.
- **Independent verifier / KAT:** pin known-answer test vectors per protocol version; ideally a second, spec-derived verifier to catch prover↔verifier collusion.
- **Wire-format discipline:** v5 is a clean break; unsound legacy proofs are rejected.

### Phase 3 — Production systems hardening (before relaunch)

**Goal:** the service survives real traffic and a box failure.

- **State: SQLite → Postgres cutover** (the `DualWriter` scaffolding + `docs/postgres_migration.md` exist) — removes the data SPOF, enables replicated PITR backups, unblocks horizontal scale.
- **HA/DR:** managed Postgres with automated backups + a tested restore runbook; secrets moved to a real secret store; warm-standby plan documented.
- **Auth model:** sessions (not raw-key-in-browser); store **only hashed** keys (retire `api_keys.txt` as the auth source); shared cross-surface tenant quota (Redis-class) across MCP + HTTP.
- **Billing correctness:** reconcile the two pricing systems + the Compute meter (G11); unify plan-alias resolution (`pro`); make cap+inflight+insert atomic (G12 TOCTOU); meter every proving path (G9).
- **Independent monitoring:** move the daily audit off the laptop to an external uptime monitor + on-box Alertmanager, with a dead-man's-switch (G14).
- **CI/CD:** build the Docker image and lint CF Functions in CI; automated deploy with rollback; pin toolchain parity between CI and the image.
- **Worker model:** spawn-per-job → bounded warm pool; sandbox custom programs if offered.

### Phase 4 — External cryptographic audit + controlled relaunch

**Goal:** independent sign-off — the reason "fix & audit" was chosen.

- Freeze protocol v5; finalize the formal spec + soundness proof; commission a **third-party ZK audit** (engine + AIRs + Fiat-Shamir + ZK mask).
- Remediate findings; re-run the adversarial suite.
- Re-enable templates and re-introduce √T / security claims only as backed by the audited proof + benchmarks. Decide on-chain-verifier scope (a correct, audited verifier — likely a recursive-SNARK wrapper — or keep the claim retired).

### Phase 5 — √T validation + the long-trace moat

**Goal:** prove and monetize the differentiator on a sound base.

- Rigorously validate O(√T) prover memory with RSS-ladder benchmarks; **fix the v3 DEEP-oracle `O(N·blowup)` materialization** in `crates/hc-prover/src/prove.rs` that currently dents √T on the hot path.
- Build the long-trace **Compute tier** (zkVM / zkML) honestly on the sound engine — where √T pays for itself.

---

## 5. Findings → phase traceability

| Finding | Phase(s) |
|---|---|
| G1 templates don't enforce predicate | 0 (narrow) → 1B (real AIRs) |
| G2 FRI fold not a low-degree test | 1A |
| D-5 base-field challenges | 1A |
| D-7 fake/ trusted OOD | 1A |
| no grinding | 1A |
| G7 no verifier security floor | 1A |
| G9/D-9 incorrect soundness proof | 1A |
| ZK (v4) mask correctness | 1A → 4 |
| G5/D-4 Solidity verifier stub/non-compiling | 0 (retract) → 4 (real, if pursued) |
| G6/D-2 KZG hardcoded setup seed | 0 (disable/retract) |
| D-3 KZG accepts empty query response | 0 (disable KZG path) |
| D-10 "recursion" not real | 0 (retract) → 4/5 |
| G3 billing-portal takeover | 0 |
| G4 magic-link leaks API key | 0 |
| G8 unlimited free re-signup | 0 |
| G9 unmetered/uncapped aggregate/zkML/Spartan | 0 (cap/disable) → 3 (proper metering) |
| G10 unauthenticated `/metrics` | 0 |
| G11 two pricing systems / Compute unbilled / plan alias | 3 |
| G12 trace_length underbill + cap/inflight TOCTOU | 0 (underbill) → 3 (atomic) |
| G13 single-box SPOF + only-copy state | 0 (off-box backup) → 3 (Postgres/HA) |
| G14 audit on personal laptop | 3 |
| G15 hygiene (.env, CF acct id, CORS `*`, demo key) | 0 |
| G16 welcome.html contradicts API | 0 |
| D compute_deep_oracles O(N·blowup) | 5 (√T validation) |

## 6. Risks & open questions

- **Cryptographic risk is concentrated in Phase 1A.** Getting FRI + DEEP + extension-field + parameter selection correct is the highest-judgment work and the most valuable to pair with an external cryptographer *before* the formal audit. Consider pulling the auditor/reviewer in at 1A rather than only at 4.
- **`hash_preimage` semantics change** (Blake3 → Poseidon2). This alters the public claim; acceptable since templates are being narrowed/relabeled anyway, but it is a product decision to confirm.
- **Postgres cutover timing.** Defaulted to "before Phase 4 relaunch"; can be pulled earlier if scale pressure appears.
- **Effort is genuinely multi-month** solo: Phase 0 ≈ days; 1A ≈ several focused weeks; 1B + 3 ≈ months; 4 gated on auditor availability.

## 7. Process

Each phase is delivered as its own `spec → implementation plan → build` cycle. The immediate next step after this roadmap is approved is to turn **Phase 0** into a concrete, test-driven implementation plan and begin execution.
