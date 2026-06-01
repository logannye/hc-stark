# TinyZKP / hc-stark — Phase 1B: General AIR layer + first real template (`range_proof`)

- **Status:** Approved (design); implementation plan to follow
- **Date:** 2026-06-01
- **Author:** Logan Nye
- **Branch:** `phase1b-real-airs` (off `main` @ `7d21c9c`, which carries Phase 1A + 1A.2)
- **Scope:** The `hc-stark` Rust ZK-STARK engine — the AIR layer (`hc-air`), the sound v5 prover/verifier seam (`hc-prover`, `hc-verifier`), proof format/version (`hc-hash`, `hc-sdk`), and the `range_proof` template (`hc-workloads`).
- **Type:** Per-phase spec under the master roadmap (`2026-05-29-production-hardening-roadmap-design.md`, §Phase 1B). One `spec → plan → build` cycle.

---

## 1. Background & motivation

Phase 1A + 1A.2 made the STARK **sound** — correct antipodal `1/x` FRI fold, extension-field (`K = QuadExtension<Goldilocks>`) challenges for both FRI betas and composition α, grinding, a verifier security floor, and a forge-PoC that flips RED→GREEN. But that soundness was delivered for **exactly one statement**: the width-2 accumulator (`ToyAir`).

Confirmed by reading the code on this branch's parent:

- **The v5 prover and verifier are hardwired to `ToyAir`.** `prove.rs` (`build_quotient_lde_k`, and the streaming/non-streaming paths at `:309/:837/:1617/:1692`) and the verifier (`v5.rs:532`, `api.rs:357`) literally do `let air = ToyAir;` and combine constraints as a fixed 2-tuple `c = K::from_base(b)·α_boundary + K::from_base(t)·α_transition`, where `(b,t)` come from `DeepStarkAir::constraint_values(...) -> (F, F)`.
- **A general substrate already exists but is unwired and partly unsound.** `hc-air` has `ConstraintSystem` / `DslAir` (`dsl.rs`, 600 lines: N columns, α-power constraint mixing, boundaries, conditional transitions), `MultiColumnTrace` (`multi_column.rs`), and correct one-hot selector primitives (`selectors.rs`). **None of `DslAir` is referenced by the live prover/verifier.** Worse, its bridge to the sound seam is unsound for real AIRs:
  - `evaluate_constraint_values` collapses *all* constraints into the 2-tuple `(boundary_sum, transition_sum)` with **no α-power separation**. The module documents this (`dsl.rs:250-253`): the invariant `α_b·b + α_t·t == quotient_numerator` *"only holds for single-constraint systems; with multiple constraints the power-series mixing differs."* Two summed boundary constraints `b1+b2` are forgeable (`b1=5, b2=-5`).
  - `conditional_transition` branches on `selector_match == F::ZERO` at evaluation time — a **non-arithmetic runtime branch**, not a low-degree polynomial identity, so it cannot be committed/verified soundly via FRI.
- **The templates are build-time theater (audit finding G1).** `range_proof` (`templates/range_proof.rs`) builds an `AddImmediate` chain, checks `value ≤ max` in plain Rust at build time, and sets `final_acc = value` — which both fails to constrain the range *and leaks V as a public input*. It is correctly flagged `enforcement: StructureOnly` and gated off in production (Phase 0.1a).

So Phase 1B is the **depth** half of G1: a sound, general AIR layer wired into the v5 core, with `range_proof` as the first template whose AIR actually binds its predicate.

## 2. Strategic decisions (locked via brainstorming)

| Decision | Choice | Implication |
|---|---|---|
| **Deliverable scope** | General N-constraint AIR seam **+ `range_proof` end-to-end** with negative tests | One template, not many. Excludes Poseidon2's degree-7 quotient-splitting (a later template). |
| **Approach** | **A** — generalize the seam (width-N, α-powers in K, degree bookkeeping) once, re-express accumulator on it, then build `range_proof` as a bespoke degree-2 bit-decomposition AIR | Reusable substrate for all future templates; matches the roadmap's "generalize the AIR layer first". Rejected: B (width-2 special-case — pays twice) and C (full VM AIR / zkVM — Phase 5). |
| **Production posture** | **Merge sound, keep gated** behind `HC_ALLOW_UNAUDITED_TEMPLATES` until the Phase 4 external audit | This phase delivers *soundness*; *exposure/advertising* stays gated on the audit. Requires a new "production-exposure" axis (see §6.5) so the template can be honestly `Enforced` yet held back. |
| **Zero-knowledge bar** | **Soundness + structural hiding + a worked ZK argument now** | `V` is a masked private witness (never a public input); the v4 mask is generalized to all witness columns; a mask-degree ≥ query-count argument is written into `docs/security/` this phase (pulls some Phase-4 ZK-review work forward). |

**Governing principle (inherited):** soundness and honesty come first; performance/scale/feature-breadth follow.

## 3. Architecture & component boundaries

Introduce **one** new abstraction — a general `Air` that owns its columns, constraints, public-input layout, and canonical constraint ordering — and make the prover/verifier generic over it. FRI, grinding, Merkle, DEEP, and query sampling (Phase 1A) are unchanged. The accumulator becomes an *instance* of the general `Air`, not a hardcoded special case.

**Changes by crate:**

- **`hc-air`** (most new code; in isolation):
  - Redesigned `Air` trait (§5): `width()`, `public_input_layout()`, `constraints()` (ordered, each with degree + domain), and the consensus-critical `compose_at(current, next, l0, l_last, selector_last, public_inputs, α: K) -> K` returning `Σ αⁱ·cᵢ` over the canonical order.
  - `RangeAir` (new) + its trace builder (§7). `AccumulatorAir` (the existing `toy_air_system` re-expressed) for the differential.
  - Fix the two DSL soundness bugs: 2-tuple collapse (replaced by `compose_at`) and the branchy `conditional_transition` (replaced by arithmetic selector gating from `selectors.rs`).
- **`hc-prover`** (`prove.rs`, `pipeline/phase1_commit.rs`, `pipeline/phase3_queries.rs`): width-2 → width-N trace LDE, width-N Merkle leaf hash, width-N openings; `build_quotient_lde_k` calls `air.compose_at(...)` with a single α∈K; ZK mask loops over all N columns; `production_v7` config.
- **`hc-verifier`** (`v5.rs`): mirror — width-N openings/leaf hash, `verify_v5_trace_and_quotient` calls the same `compose_at`; `enforce_floor.min_sound_version → 7`; reject `version < 7` in `verify_proof_bytes`.
- **`hc-hash::protocol`**: add `DOMAIN_MAIN_V7`/`DOMAIN_FRI_V7` (sound general) + `V8` (= v7 + ZK), `COMPOSITION_ALPHA`, public-input-vector labels (`PUB_INPUT_COUNT`, `PUB_INPUT[i]`), `PARAM_TRACE_WIDTH`.
- **`hc-workloads`**: `range_proof` build() produces a `RangeAir` + trace (via the new `TemplateBuildResult::Air` variant); registry adds the `audited` axis (§6.5).
- **`hc-sdk`**: proof struct gains width-N trace openings + a public-input vector; v7/v8 serialization + bytes round-trip.

**Data flow (range):** `params {min,max,value}` → `RangeAir::build_trace` (bits of `a=V−min`, `c=max−V`) → `MultiColumnTrace` (width 4) → prover LDE + mask + commit → `compose_at` quotient in K → FRI (unchanged) → proof. Verifier replays the transcript, evaluates `compose_at` at queried points, runs FRI low-degree, accepts/rejects.

**Isolation invariant:** the `Air` trait is the single interface between "what predicate" (`hc-air`) and "how to prove it" (`hc-prover`/`hc-verifier`). After this phase, a new template is a new `Air` impl + trace builder with **zero** prover/verifier changes.

## 4. Interfaces & key types

The new/changed type-level contract (exact signatures finalized in the plan). In the v5/v7 path `F = Goldilocks`, `K = QuadExtension<Goldilocks>`; trace/public values are `F`, the composition challenge and quotient are `K`.

```rust
// hc-air
pub enum MaskKind { First, Last, Transition, All }   // ×l0, ×l_last, ×selector_last, ×1

pub trait Air {
    fn width(&self) -> usize;                         // number of trace columns N
    fn public_input_len(&self) -> usize;              // number of public inputs
    fn constraints(&self) -> &[ConstraintMeta];       // canonical order; each carries degree + MaskKind
    fn max_constraint_degree(&self) -> usize;         // drives the blowup ≥ degree check
    // consensus-critical: called identically by prover and verifier
    fn compose_at(&self, current: &[F], next: &[F],
                  l0: F, l_last: F, selector_last: F,
                  public_inputs: &[F], alpha: K) -> HcResult<K>;   // Σ αⁱ·cᵢ
}

// hc-workloads
pub enum TemplateBuildResult {
    Vm  { program: Program, initial_acc: u64, final_acc: u64, recommended_zk: bool },
    Air { air: Box<dyn Air>, trace: MultiColumnTrace<F>, public_inputs: Vec<F>, recommended_zk: bool },
}
```

The proof type (`hc-sdk`) gains `trace_width: usize`, per-query `evaluation: Vec<F>` (was `[F;2]`), `public_inputs: Vec<F>` (replacing the fixed `initial_acc`/`final_acc`), and `version ∈ {7,8}`. The legacy `DeepStarkAir::{quotient_numerator, constraint_values}` 2-tuple seam is retired from the live path (kept test-only for the v5 differential).

## 5. The sound generalized seam (crypto core)

**Trait.** An `Air` exposes an *ordered* constraint list. Each constraint `i` carries an evaluator `eᵢ(current, next) → F` and a **domain mask** `mᵢ ∈ {first, last, transition, all}`, applied at point `x` as a multiplier:

| mask | multiplier | meaning |
|---|---|---|
| `first` | `l0(x)` | holds at row 0 |
| `last` | `l_last(x)` | holds at row N−1 |
| `transition` | `selector_last(x) = 1 − l_last(x)` | holds at every row except the last (constraint references `next`) |
| `all` | `1` | holds at every row (constraint references only `current`) |

`l0`, `l_last` are the Lagrange selectors already computed per LDE point in `build_quotient_lde_k`. The invariant: for a valid trace, `mᵢ(x)·eᵢ(x)` vanishes on **all** of the trace domain `H`, so the single quotient is a polynomial. (`all` is the addition this phase — booleanity-style constraints must hold at the last row too, where `transition` would wrongly disable them.)

**The one consensus-critical function** (identical on prover and verifier):

```
compose_at(current, next, l0, l_last, selector_last, public_inputs, α∈K) -> K:
    C = 0
    for i, (eᵢ, maskᵢ) in canonical_order(constraints):
        m = select(maskᵢ, l0, l_last, selector_last, ONE)
        C += αⁱ · K::from_base( m · eᵢ(current, next, public_inputs) )
    return C
q(x) = C(x) · Z_H(x)⁻¹     # in K, exactly as today
```

This replaces the fixed `(b,t)` 2-tuple and the two challenges `COMPOSITION_ALPHA_{BOUNDARY,TRANSITION}`. A **single** composition challenge `α∈K` is drawn from the transcript (new label `COMPOSITION_ALPHA`); powers are assigned by the AIR's fixed constraint order (order is part of the AIR definition → consensus by construction).

**Soundness (the only new term vs Phase 1A).** If any masked constraint fails to vanish on `H`, then `C(x)` is a nonzero polynomial in `α` of degree `< n_c`; for uniform `α∈K`, `Pr[C ≡ 0] ≤ (n_c − 1)/|K| ≈ n_c / 2¹²⁸`. When `C ≢ 0` on `H`, `q = C/Z_H` has a pole → not low-degree → Phase 1A's sound FRI rejects. The α-union-bound is added to `docs/security/soundness_proof.md`.

**Degree bookkeeping.** A degree-`k` constraint, masked (mask degree `N−1`) and divided by `Z_H` (degree `N`), gives quotient degree `≈ k·(N−1)`. **Rule: `blowup ≥ max constraint degree`.** `range_proof` is degree 2 (booleanity `b·(b−1)`); production blowup is 8 ≫ 2 → the quotient stays one committed column inside the FRI degree bound; **no quotient-splitting this phase.** (Poseidon2's degree-7 S-box is precisely why it is a later template.)

**Accumulator reduction — behavior-preserving, not byte-preserving.** `AccumulatorAir` = ordered `[first: acc−init, last: acc−final, transition: acc_next−acc−delta]` under single-α powers. This is a *different* polynomial in the challenges than today's grouped `α_b·boundary + α_t·transition`, so accumulator proof **bytes change** — which is exactly why we bump the protocol version (§6) rather than claim byte-compat. The guarantee held: same statement, still sound, tampered traces rejected, Phase-1A forge-PoC stays GREEN (differential test, §8).

## 6. Format generalization

### 6.1 Width-N trace, leaf, openings (the bulk of the plumbing)
Today everything is `TraceRow = [F; 2]`: the LDE, the leaf hash (`hash_trace_pair` in both the streaming `phase1_commit.rs` and the non-streaming `commit_trace_lde`), the query openings, and the SDK types. Generalize to width-N:
- Trace LDE carries N columns; the Merkle **leaf** for row `x` becomes `hash_trace_row(&[F])` — one shared vector hash absorbing the N field values in canonical column order, used identically on both sides (replaces the 2-arg pair hash).
- Each trace query opens an N-vector (`evaluation: Vec<F>`) for the row and its neighbor; `build_quotient_lde_k` reads N columns at `i` and `i+shift`.
- `N` is bound in the transcript (`PARAM_TRACE_WIDTH`) and the proof params so the verifier knows leaf arity.
- This threads through prover commit (×2 paths), `phase3_queries.rs` openings, SDK proof types, and the verifier. It is plumbing, not new crypto.

### 6.2 Public-input vector
Replace fixed `{initial_acc, final_acc}` with an AIR-defined `public_inputs: Vec<F>` (length from `public_input_layout()`), bound length-prefixed in the transcript (`PUB_INPUT_COUNT` + `PUB_INPUT[i]`); `trace_length` stays separate. `accumulator = [init, final]`; `range = [min, max]`. The verifier passes `public_inputs` into `compose_at`. The acc-specific `final_acc == initial_acc` degenerate guard (`v5.rs:160`) is replaced by per-AIR validation (range: `min ≤ max` at build + the AIR constraints).

### 6.3 ZK mask over all columns
Generalize the v4 mask from `{acc, delta}` to all N trace columns: per column `j`, sample an independent `R_j` (degree `mask_degree`, domain-separated by `j` from the stored seed) and add `Z_H(x)·R_j(x)` to column `j`'s LDE (trace on `H` unchanged since `Z_H = 0` there). Applies in both the commitment and the masked-oracle recomputation paths (`prove.rs:369-407`, `:790-817`).

### 6.4 The worked ZK argument (the "full ZK now" deliverable)
Written into `docs/security/` (new `zk_range.md` and/or folded into `soundness_proof.md`), scoped to the range AIR:
- `V` is neither a public input nor a column (`V = min + a`) → never directly revealed.
- With `mask_degree ≥ query_count Q`, the `Q` opened masked trace values (at off-domain points, `Z_H ≠ 0`) are jointly uniform in `Kᵠ` and **simulatable** independent of the witness → openings leak nothing about `a` (hence nothing about `V` beyond `V ∈ [min,max]`). Standard ethSTARK/Winterfell mask argument.
- **Honest subtlety to resolve, not hand-wave:** the *quotient* openings must also be simulatable given the masked trace openings (or `mask_degree` bumped to cover them). The doc resolves this rigorously; if it needs `mask_degree ≥ Q + (small)`, it says so and the production config is set accordingly.

### 6.5 Protocol version bump + production-exposure gate
- Add `DOMAIN_MAIN_V7`/`DOMAIN_FRI_V7` (general sound) and `V8` (= v7 + ZK), paralleling v5/v6. New `ProverConfig::production_v7` (same floor: blowup 8 / q40 / grind 20, plus `trace_width` and `public_inputs` from the AIR). Production proving + the MCP executor cut over to v7/v8; `enforce_floor.min_sound_version → 7`; `verify_proof_bytes` rejects `< 7`. v5/v6 kept test-only (as v3/v4 are now) for the differential. Hard cutover; prover + verifier + MCP co-deploy — safe because proofs are verified-on-receipt (not stored) and there are ~no customers.
- **Production-exposure axis (so a sound template stays gated).** Today `is_listable`/`is_dispatchable` treat `Enforced` as unconditionally live, with tests asserting only `accumulator_step` is `Enforced`. To keep `range_proof` honestly `Enforced` yet out of prod until Phase 4, add a per-template **`audited: bool`** (precise meaning: *"cleared for unflagged production exposure via the Phase-4 audit gate"*; `accumulator_step` grandfathered `true`, everything else `false`). New liveness rule: `is_live = (enforcement == Enforced && audited) || allow_unaudited`. The `HC_ALLOW_UNAUDITED_TEMPLATES` flag name/semantics are unchanged.

## 7. The `range_proof` AIR

**`RangeAir`** — width 4, columns `[a_bit, a_acc, c_bit, c_acc]`, `n` rows where `n` is a power of two `≥ bitlen(max − min)` (default 32, comfortably within the field-safety bound `2^(n+1) < p`; extensible toward `n ≤ 62`, beyond which `a + c` could wrap mod `p`). Because `n` is a power of two the trace is exactly `n` real rows — **no padding**, hence no padding/transition mismatch.

Canonical constraint order:

| # | constraint | degree | mask |
|---|---|---|---|
| 0 | `a_bit·(a_bit − 1) = 0` (booleanity) | 2 | all |
| 1 | `c_bit·(c_bit − 1) = 0` | 2 | all |
| 2 | `a_acc − a_bit = 0` (acc seeds at MSB) | 1 | first |
| 3 | `c_acc − c_bit = 0` | 1 | first |
| 4 | `a_acc' − (2·a_acc + a_bit') = 0` (Horner) | 1 | transition |
| 5 | `c_acc' − (2·c_acc + c_bit') = 0` | 1 | transition |
| 6 | `(a_acc + c_acc) − (max − min) = 0` (tie) | 1 | last |

**Public inputs = `[min, max]`.** Max degree 2 → blowup 8, one quotient column.

**Soundness of the predicate.** Booleanity + Horner force `a, c ∈ [0, 2ⁿ)`; the tie forces `a + c = max − min`. Since `2^(n+1) < p`, the field identity is the integer identity, so `c ≥ 0 ⟹ a ≤ max − min` and `a ≥ 0`, giving `0 ≤ a ≤ max − min`, i.e. `min ≤ V = min + a ≤ max`. **No assignment exists with `V ∉ [min,max]`.** `V` appears in no column and no public input → hidden (masked witness).

**Trace builder & params.** `range_proof` params change `{min, max, witness_steps}` → **`{min, max, value}`** (`value = V`, private). The builder validates `min ≤ V ≤ max` and `max − min < 2ⁿ`, bit-decomposes `a = V − min` and `c = max − V` MSB-first, fills the Horner accumulators → `MultiColumnTrace` (width 4). Example: `{"min":18,"max":120,"value":42}`.

**Dispatch.** `TemplateBuildResult` becomes an enum:
- `Vm { program, initial_acc, final_acc, recommended_zk }` — `accumulator_step` keeps VM execute → trace → `AccumulatorAir`.
- `Air { air, trace, public_inputs, recommended_zk }` — `range_proof`.

The worker/MCP prove path generalizes from "(program)" to "(Air, trace, public_inputs) → `prove_v7`" — one match arm, no other call-site logic.

**Gating.** `range_proof`: `enforcement: Enforced` (honest — it now binds), `audited: false` → gated behind `HC_ALLOW_UNAUDITED_TEMPLATES` until Phase 4 flips `audited: true`. `accumulator_step`: `Enforced`, `audited: true` → stays live. Test updates: `only_accumulator_step_is_enforced` → `only_accumulator_step_is_live_by_default`; `the_five_predicate_templates_are_structure_only` → `range_proof` moves to `Enforced + unaudited`, the other four stay `StructureOnly`.

## 8. Testing & verification strategy

**Negative/forge tests (the core deliverable — "a false witness is rejected").** Each builds a specific bad trace and asserts verifier rejection:
- **Out-of-range** (`V > max` / `V < min`): builder rejects; a hand-crafted trace bypassing the builder sets `c = max − V ≡ p − |…|`, not `n`-bit boolean → booleanity/Horner nonzero on `H` → quotient pole → FRI rejects.
- **Non-boolean bit** (`a_bit = 2`) → constraint 0/1 nonzero → reject.
- **Bad Horner step** → constraint 4/5 → reject. **Wrong tie** (`a + c ≠ max − min`) → constraint 6 → reject. **Lying public `max`** → tie fails → reject.

**Seam soundness:** a 7-constraint AIR with exactly one violated constraint must be rejected — proves the single-α power combination does not mask a lone violation.

**Differential / behavior-preservation (accumulator):** `AccumulatorAir` on the v7 seam (a) verifies honest proofs, (b) rejects the same tamper cases the v5 ToyAir path did, (c) keeps Phase 1A's forge-PoC GREEN, (d) unit-level: `compose_at` vanishes on `H` for valid traces and is nonzero for each violation.

**ZK:** the worked argument lives in `docs/security/` (§6.4). Mechanical sanity tests: `V` appears in neither proof bytes nor public inputs; openings change with the mask seed.

**KAT + property tests:** pin v7/v8 known-answer vectors (format lock); proptest random `(min,max,V)` → in-range round-trips verify, out-of-range/tampered reject; production floor rejects `version < 7`.

**Process:** subagent-driven TDD (RED → GREEN per task); `fmt --all --check` + `clippy --workspace --all-targets -D warnings` + full suite green at **every task boundary**; honor the shared-tree hazard (no subagent `cargo fix` / mutating git; verify clean tree + commit-stat each boundary).

## 9. Exit gates

Phase 1B is done when:
1. General seam lands; `AccumulatorAir` re-expressed on it; accumulator differential + forge-PoC GREEN.
2. `RangeAir` honest proof verifies; **all** negative/forge tests reject.
3. ZK: `V` absent from proof/public inputs; mask covers all columns; the worked ZK argument is committed to `docs/security/` with the quotient-opening subtlety resolved.
4. v7/v8 cutover: prover + verifier + MCP on v7/v8; floor rejects `< 7`; v5/v6 test-only.
5. `range_proof` = `Enforced` + `audited: false` (gated); production `/templates` still shows only `accumulator_step` (verified post-merge).
6. Full gate (fmt + clippy `-D warnings` + suite incl. range/differential/proptests/KAT) green.

## 10. Explicitly out of scope

External cryptographic audit (Phase 4); production-enable / re-advertise of `range_proof` (gated on Phase 4); the other four templates `hash_preimage`/`policy_compliance`/`data_integrity`/`computation_attestation` (fast-follows on the now-general seam); Poseidon2 and quotient-degree-splitting; performance (Phase 5, incl. the `compute_deep_oracles` `O(N·blowup)` materialization and width-N hot-path layout); the still-vacuous `hc-recursion` in-circuit fold (gated off; tracked below).

## 11. Findings → traceability

| Finding | Status after Phase 1B |
|---|---|
| **G1 (depth)** templates don't enforce their predicate | `range_proof` now binds its predicate; the general seam unblocks the other four (fast-follows). |
| Multi-constraint α-mixing unsound in the DSL bridge | Fixed by `compose_at` (single-α power series in K). |
| DSL branchy `conditional_transition` | Replaced by arithmetic selector gating (`selectors.rs`). |
| `range_proof` leaks `V` (`final_acc = value`) | Fixed: `V` is a masked private witness; public inputs are `{min,max}`. |
| **G2 inheritance** (`hc-recursion` in-circuit fold still vacuous) | Out of scope; remains gated off. Real fix tracked for a later 1B/recursion follow-up. |

## 12. Risks & open questions

- **Width-N is the largest mechanical change** and touches two commit paths plus all openings. Mitigation: land it additively behind the v7 types with the accumulator differential as a continuous guard, mirroring Phase 1A's strangler discipline.
- **ZK quotient-opening subtlety** (§6.4): the trace-only mask may not by itself simulate the quotient openings. The ZK doc must resolve this; if `mask_degree` must exceed `Q` to cover it, the production config follows the doc.
- **Bit-width `n` default (32) vs field safety.** Default 32 covers the canonical range-proof use cases (age, score, thresholds). Extending toward `n ≤ 62` requires the `2^(n+1) < p` guard (beyond which `a + c` wraps mod `p`); deferred unless a concrete need appears.
- **Single-α vs two independent challenges.** Single-α power series is standard and sound (Schwartz–Zippel over `K`); it changes accumulator proof bytes, which is why the version bumps. No byte-compat is promised.

## 13. Process

Delivered as `spec → implementation plan → build`. Next step after this spec is approved: turn Phase 1B into a concrete, test-driven implementation plan (subagent-driven TDD, PoC-first strangler) via the writing-plans skill.
