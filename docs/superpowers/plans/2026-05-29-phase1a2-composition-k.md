# Phase 1A.2 — Composition / DEEP challenges in the extension field K (full 128-bit)

> **For agentic workers:** REQUIRED SUB-SKILL: superpowers:subagent-driven-development. Builds on Phase 1A (merged, main `7892a81`).

## Goal

Close the last soundness gap from Phase 1A: the constraint-combination challenges `α_boundary`/`α_transition` are drawn from the **base field** F (≈2⁶⁴), capping the composition Fiat-Shamir term at ~64 bits even though the FRI betas are already in K (128-bit). Promote `α` to `K = QuadExtension<Goldilocks>` so the quotient/composition becomes K-valued and overall conjectured soundness reaches the full **128-bit** target.

## Why this is the gap (confirmed in code)

- `prove.rs:424–429` and `v5.rs:250–253` sample `α_boundary`/`α_transition` via `challenge_field::<F>` (64-bit).
- The quotient `q(x) = [α_b·B(x) + α_t·T(x)] / Z_H(x)` is computed + committed in F (`prove.rs:437–477`, `hash_field_element`).
- Soundness of the combination ≈ `degree/|field of α|` → ~2⁻⁶⁴ with α∈F; ~2⁻¹²⁸ with α∈K.
- **Not gaps** (verified): FRI betas already K; the "OOD" check (`v5.rs:305`) is an extra *in-domain query index* (field-independent); trace low-degree is enforced indirectly (a high-degree trace ⇒ high-degree quotient ⇒ FRI rejects — exactly what the Phase 1A forge-PoC showed).

## Design

`α ∈ K` ⇒ the constraint-combination and quotient become K (the **trace stays F**; only the combination + everything downstream of it goes to K). The AIR's constraint *evaluation* stays F; the α-combination moves out of the AIR into the prover/verifier, in K.

**In-place v5 (not a new version):** v5 is brand-new and **not yet deployed** (the box deploy is still pending), so there are no v5 proofs in the wild — change v5 in place rather than introducing v7. v3/v4 are untouched (deprecated, F).

**Validation:** unlike G2, there is no *runnable* exploit (a 64-bit attack is ~2⁶⁴ work). Closure = the structural change + the soundness-bits accounting (64→128 on that term) + a **differential** (K-α with `c1=0` reproduces the old F-α quotient) + round-trip + soundness proptests. The definitive 128-bit sign-off remains the external cryptographer audit (Phase 4 — still tracked).

## Strangler / green-per-task note

The α-field change is **atomic across prover + verifier** (the quotient root depends on α, so both sides must switch together or the v5 round-trip breaks). So T2 changes both sides + the v5 proof types + serialization + the v5 tests in one coherent task. T1 (hc-air) is additive; T3 is tests/gate.

---

## Task 1 — hc-air: expose F constraint values (additive)

**Files:** `crates/hc-air/src/air.rs` (+ AIR impls: ToyAir, DeepStarkAir).

The combination `α_t·transition + α_b·boundary_term` currently lives inside `quotient_numerator`. Expose the two constraint values so the caller can combine in K.

- [ ] **Step 1** — Read `air.rs`. Identify the trait(s) the v5 prover/verifier use (`Air` and/or `DeepStarkAir`; the v5 path calls `air.quotient_numerator(...)`).
- [ ] **Step 2** — Add a method to that trait (ADDITIVE; keep `quotient_numerator`):
```rust
/// The individual constraint values (base-field), BEFORE the random α-combination.
/// Returns (boundary_value, transition_value). The α-combination is performed by
/// the caller (in the base field for v3, in the extension field K for v5+).
fn constraint_values(
    &self, current: &[F], next: &[F],
    l0: F, l_last: F, selector_last: F,
    initial_acc: F, final_acc: F,
) -> HcResult<(F, F)>;
```
Implement for ToyAir (return `(boundary_term, transition)` — the exact subexpressions already in `quotient_numerator`) and any other AIR impl. OPTIONAL DRY: re-express `quotient_numerator` as `α_b·b + α_t·t` over `constraint_values` (only if it stays byte-identical to today for v3).
- [ ] **Step 3** — Test: for random α/rows, `α_b·b + α_t·t == quotient_numerator(...)` (the new method is consistent with the old combination). `cargo test -p hc-air`.
- [ ] **Step 4** — `cargo build --workspace`; `cargo clippy -p hc-air --all-targets -- -D warnings`. Commit: `feat(air): expose base-field constraint_values for K-combination (1A.2)`.

## Task 2 — α → K end-to-end (prover + verifier + types + serialization), ATOMIC

**Files:** `crates/hc-prover/src/prove.rs` (prove_v5/prove_stark_v5 quotient build), `crates/hc-prover/src/queries.rs` (`CompositionQuery` use in `QueryResponseV5`/`ProofV5` → K for the quotient opening), `crates/hc-prover/src/pipeline/phase2_fri.rs` (drop the `EmbeddingProducer` — quotient is now natively K), `crates/hc-verifier/src/v5.rs` (α sampling + quotient-relation check + base binding), `crates/hc-sdk/src/proof.rs` (serialize K quotient openings), and the v5 tests (forge-PoC + round-trip) updated to the K quotient.

- [ ] **Step 1 — α to K.** In prover (`prove.rs`) and verifier (`v5.rs`): `challenge_field::<F>` → `challenge_field::<K>` for `α_boundary`/`α_transition`. (Transcript STATE is unchanged — `challenge_field` consumes one squeeze either way; only α's value gains entropy. Everything downstream of the quotient root recomputes consistently as long as BOTH sides change.)
- [ ] **Step 2 — quotient in K (prover).** Replace the per-point `air.quotient_numerator(...)` (F) with: `let (b, t) = air.constraint_values(...)` (F); `let c = K::from_base(b).mul(alpha_b).add(K::from_base(t).mul(alpha_t))` (K); `let q = c.mul(K::from_base(z_h_inv))` (K). Commit the quotient with `hash_value_ext` (K leaves) instead of `hash_field_element`. The quotient producer is now K → pass it DIRECTLY to `run_fri_v5` (delete the `EmbeddingProducer` wrap; the base is natively K).
- [ ] **Step 3 — quotient openings in K.** `CompositionQuery` value → K for the v5 path: make `QueryResponseV5.composition_queries` carry K-valued quotient openings (`CompositionQuery<QuadExtension<F>>` or a K variant), with K Merkle paths (`hash_value_ext`). Update `ProofV5` accordingly.
- [ ] **Step 4 — verifier quotient check in K (`v5.rs`).** `verify_v5_trace_and_quotient`: recompute `c = K::from_base(b)·α_b + K::from_base(t)·α_t` (α∈K, b/t from `constraint_values` on the F trace opening), assert `c == q(x)·Z_H(x)` in K at each queried point (q is the K quotient opening). The FRI base-layer binding is now natively K: `expected = composition_opening_K` (drop the `K::from_base(...)` embed).
- [ ] **Step 5 — serialization.** Extend the v5 serializer (`hc-sdk/src/proof.rs`) so the quotient/composition openings serialize as K (16-byte `to_le_bytes`, same as the FRI K values). Round-trip must stay field-exact.
- [ ] **Step 6 — update v5 tests.** The forge-PoC (`v5_rejects_high_degree_codeword`) and the v5 round-trip must build/verify the K-quotient v5. The forge-PoC must STILL be GREEN (a high-degree trace ⇒ high-degree K quotient ⇒ FRI final-degree check rejects). The honest round-trip must STILL ACCEPT. Keep both green.
- [ ] **Step 7 — gate + commit.** `cargo test -p hc-prover -p hc-verifier -p hc-sdk` (all pass, incl. forge-PoC GREEN + round-trip ACCEPT); `cargo build --workspace`; `cargo clippy --workspace --all-targets -- -D warnings`. Commit: `feat(prover/verifier/sdk): composition challenges + quotient in K — full 128-bit (1A.2)`.

## Task 3 — differential, soundness proptests, full gate

**Files:** test files in `hc-verifier`/`hc-prover`/`hc-sdk`.

- [ ] **Step 1 — differential (K generalizes F).** A test: building the quotient with α embedded from F (i.e. K elements with `c1=0`) reproduces the OLD F-α quotient values exactly (sanity that the K path is a faithful generalization). Use `constraint_values` + the F combination vs the K combination with embedded α.
- [ ] **Step 2 — α entropy.** Assert the v5 α challenges now have `c1 != 0` sometimes (genuinely K, like the FRI betas), and that the committed quotient differs from what F-α would produce (the combination really uses both limbs).
- [ ] **Step 3 — soundness proptests.** Extend the v5 soundness proptests so mutating a quotient (composition) opening value → REJECT (the quotient-relation check in K catches it). Confirm honest proofs still verify.
- [ ] **Step 4 — full gate.** `cargo fmt --all --check`; `cargo clippy --workspace --all-targets -- -D warnings`; `cargo test --workspace` (ALL pass). Commit: `test(1A.2): K-quotient differential + α-entropy + soundness proptests; full gate`.

## Acceptance criteria
- `α_boundary`/`α_transition` are drawn from K in prover + verifier; the quotient/composition is K-valued end to end (commit, open, verify, serialize); the **trace stays F**.
- The differential test shows the K path with embedded (c1=0) α reproduces the prior F quotient (faithful generalization).
- Forge-PoC still GREEN; honest v5 round-trip still ACCEPT; quotient-opening tampering REJECTED.
- `fmt --all --check`, `clippy --workspace -D warnings`, full `cargo test --workspace` all green.

## Out of scope / still-tracked
- External cryptographer audit (Phase 4) — the definitive 128-bit sign-off.
- hc-recursion in-circuit fold (gated off; Phase 1B). Removal of deprecated v3/legacy fold. Per-template AIRs (Phase 1B).
