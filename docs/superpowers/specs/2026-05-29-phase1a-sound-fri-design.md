# Phase 1A — Sound FRI Low-Degree Test + Verifier Soundness Floor — Design Spec

- **Status:** Approved (design); precedes the implementation plan
- **Date:** 2026-05-29
- **Branch:** `phase1a-sound-fri` (off `main` @ `8d2ab9f`)
- **Closes audit findings:** **G2** (FRI low-degree test is unsound) and **G7** (verifier enforces no security-parameter floor). Reference: `project_hc_stark_audit_2026-05-29.md`.
- **Decisions locked (via AskUserQuestion):** target = **conjectured 128-bit**; rigor = **spec + forge-PoC + differential test**; live posture = **fix quietly, announce on release** (no interim public disclosure → no docs/dashboard changes in this phase).

---

## 1. Problem

The FRI subprotocol — the low-degree test that underpins the soundness of the entire STARK — does not test low-degreeness. Three compounding defects:

### 1.1 The fold is vacuous (G2, core)

Prover (`hc-fri/src/layer.rs:65`, `prover.rs:63`, `parallel.rs:25`, `stream.rs:92`, `simd_fold.rs`) and verifier (`hc-verifier/src/api.rs:829`) both compute:

```
next[i] = values[2i] + β · values[2i + 1]
```

A correct FRI fold combines **antipodal** points `f(x)`, `f(−x)`:

```
f^(β)(x²) = (f(x) + f(−x))/2  +  β · (f(x) − f(−x))/(2x)
```

The current code (a) pairs **adjacent** indices `(2i, 2i+1)` instead of antipodal `(j, j+N/2)`, (b) omits the symmetric/antisymmetric `(a±b)/2` split, and (c) — the fatal omission — **drops the `1/x` factor**. There are no domain points anywhere in the FRI layers.

**Why this is vacuous, not merely weak:** the prover *constructs* each next layer as exactly `fold(prev)` (`FoldedLayerProducer`). The recurrence `L_{k+1}[i] = L_k[2i] + β·L_k[2i+1]` therefore holds at every index **by construction, for any base codeword** — including high-degree garbage. The verifier checks that same recurrence against the prover's own committed layers, which the prover built to satisfy it. The challenge `β` constrains nothing because there is no independent representation to over-determine. Passing every query tells the verifier nothing about the degree of the committed quotient oracle. Because the FRI base layer is bound to the quotient/composition oracle (`api.rs:781`, "the crucial glue"), the soundness of the whole STARK collapses: the quotient need not be a real low-degree polynomial, so the AIR constraints are not enforced, so **a proof for a false statement can be forged**.

### 1.2 The verifier enforces no security floor (G7)

`SecurityFloor` (min 80 queries, blowup ≥2) exists **only in `ProverConfig`** (`hc-prover/src/config.rs`). The **verifier reads `proof.params.query_count` and uses it directly** (`api.rs:186`) with no minimum. A hand-crafted proof can declare `query_count = 1`, `lde_blowup_factor = 1` and be accepted. The floor lives on the wrong side — it must be enforced by the party that needs the guarantee.

### 1.3 Challenges are field-capped at 64 bits (G7, soundness)

`betas` are drawn via `challenge_field::<F>()` with `F = GoldilocksField` (`api.rs:768`). With 64-bit challenges, Fiat-Shamir soundness is capped at ~64 bits regardless of query count. No grinding/proof-of-work exists in `ProofParams` or `ProverConfig` (verified: neither struct has such a field; the only `leading_zeros` in the tree is unrelated KZG coefficient encoding).

The "Default values enforce ≥128-bit security" comment in `config.rs` is therefore false: blowup 2 + 80 queries + no grinding + 64-bit challenges is ≈64-bit *conjectured* at best.

---

## 2. Decisions

| # | Decision | Rationale |
|---|---|---|
| D1 | **Conjectured 128-bit** target | Industry standard (ethSTARK / plonky2 / RISC0). Smaller/faster proofs; relies on the FRI proximity-gap "up to capacity" conjecture (ethSTARK Conjecture 1.5) — knowingly chosen. |
| D2 | **Spec + forge-PoC + differential** | Implement to a published construction; forge-PoC proves the bug and anchors the fix; differential test cross-checks the fold against an independent reference. |
| D3 | **Fix quietly, announce on release** | No interim public disclosure → **no docs/dashboard/marketing changes in this phase.** |
| D4 | **Natural-order layout** (proceed) | Antipodal pairing reads two half-ranges, streamable with two cursors (preserves the √T memory contract). Bit-reversed order would force bit-reversing the base LDE and rewriting trace/quotient index mapping — far larger blast radius. |
| D5 | **Protocol v5 hard cutover** (proceed) | Old proofs are unsound; rejecting them is correct, not a regression. v5 = sound STARK, v6 = sound STARK + ZK. |
| D6 | **PoC-first / TDD** (proceed) | The forge attack lands (red) before the fix (green). |

---

## 3. The corrected fold (G2 core)

### 3.1 Math

For a codeword `f` on coset domain `D_k = offset_k · ⟨ω_k⟩` of size `N` folding to `D_{k+1} = {x² : x ∈ D_k}` of size `N/2`, with challenge `β`:

```
for j in 0 .. N/2:
    x = D_k[j]                 # = offset_k · ω_k^j   (base-field domain point)
    a = L_k[j]                 # f(x)
    b = L_k[j + N/2]           # f(−x)   because ω_k^(N/2) = −1
    e = (a + b) · ½            # f_e(x²)   (even part)
    o = (a − b) · (2x)⁻¹       # f_o(x²)   (odd part)
    L_{k+1}[j] = e + β · o     # = f_e(x²) + β·f_o(x²),  degree < deg(f)/2
```

This is the even/odd decomposition `f(X) = f_e(X²) + X·f_o(X²)`.

### 3.2 Index propagation

Antipodal partner of index `q` in a size-`N` layer is `q ⊕ (N/2)` (flip top bit). The pair is `(low, low+N/2)` where `low = q & (N/2 − 1)`. Both `x` (index `low`) and `−x` (index `low+N/2`) fold to `D_{k+1}` index `low`. Therefore:

```
next_index = q & (N/2 − 1)        # not q/2
```

`propagate_query_index` must take the **current layer size** (the present `(idx, ratio)` signature is insufficient).

### 3.3 Domain points per layer

`D_{k+1}[j] = (D_k[j])²`, so `offset_{k+1} = offset_k²`, `ω_{k+1} = ω_k²`. The verifier reconstructs `x` for layer `k` either by tracking `(offset_k, ω_k)` (square each round) or as `x = offset_k · ω_k^{low}`. `D_0` is the LDE coset (`generate_lde_coset_domain`, offset = `F::from_u64(7)`), already constructed by both sides.

### 3.4 Batch inversion (performance)

`(2x)⁻¹` is one field inversion per output element — too slow naively. Use **Montgomery batch inversion** over each streamed block: invert the block's `2x` values in a single pass (n muls + 1 inversion). `½` is a precomputed constant. The streaming `FoldedLayerProducer` batch-inverts its block's domain points.

### 3.5 Final layer

The final layer must be **directly verified to be low-degree** (degree `< fri_final_poly_size / blowup`); shipping its evaluations and only checking a Merkle root + that folds land in it (current behavior) is insufficient. Mechanism (interpolate-and-check vs. ship-coefficients-and-evaluate) is chosen in the plan.

---

## 4. Extension-field challenges (G2 / G7 — closes the 64-bit cap)

Draw `β` and the DEEP/composition random challenges from `K = QuadExtension<GoldilocksField>` (≈2¹²⁸; exists at `hc-core/src/field/extension.rs`, implements `FieldElement`).

- **Domain points `x` stay in the base field `F`** (the LDE coset is over F). Only **values and challenges** are in `K`.
- **Base layer (layer 0) stays F-valued** (the quotient oracle is F-valued and binds to the AIR). The first fold uses `β_0 ∈ K`, so **layers ≥ 1 are K-valued**. This is the standard "FRI folding in the extension field" structure (Winterfell / plonky2).
- Consequence: Merkle leaves, `hash_value`, and `FriQuery.values` for layers ≥ 1 carry `K` elements. The arithmetic `e + β·o` with `e, o, β ∈ K` and `(2x)⁻¹ ∈ F` is `K`-valued (embed F into K, or scalar-multiply).
- `QuadExtension` needs: embedding from `F`, mul by an `F` scalar, `inverse`, serialization for leaves/transcript. (Confirm/extend in the plan.)

---

## 5. Grinding / proof-of-work (G7 — new)

Standard grinding (ethSTARK §"proof of work", Winterfell `GrindingFactor`):

- New field `grinding_bits: u32` in `ProofParams` (and `ProverConfig`), transcript-bound.
- **Prover:** after committing all FRI layer roots + final root (i.e., after the commit phase, before query sampling), find a `nonce: u64` such that `H(transcript_state ‖ nonce)` has `≥ grinding_bits` leading zero bits. Append the nonce to the transcript, then sample query indices.
- **Verifier:** recompute the same hash with the proof-supplied nonce; reject if it lacks `grinding_bits` leading zeros. The nonce is added to the proof artifact.

---

## 6. Verifier-enforced soundness floor (G7 — the actual fix)

Hard constants in the verifier, checked **before** any proof-supplied param is trusted (i.e., before `generate_queries`). Reject the proof if any fails:

| Floor | Value | Reason |
|---|---|---|
| `MIN_BLOWUP` | 8 | rate ρ = 1/8 → log₂(1/ρ) = 3 conjectured bits/query |
| `MIN_QUERIES` | 40 | 40 × 3 = 120 query bits |
| `MIN_GRINDING_BITS` | 20 | + 20 = **140 conjectured bits ≥ 128** (12-bit margin) |
| `MAX_FRI_FINAL_POLY_SIZE` | 256 | bound residual degree |
| challenge field | must be the ≥128-bit extension `K` | closes §1.3 |
| `protocol_version` | ≥ 5 | sound versions only |

**Soundness budget (conjectured, ethSTARK Conjecture 1.5):** query phase = `q · log₂(blowup) + grinding_bits`; commit (folding) phase error ≈ `O(N / |K|) ≈ 2⁻¹⁰⁰`, negligible against the query phase given `|K| ≈ 2¹²⁸`. Floor minimums give ≥128 bits; provers may exceed them.

These minimums also become the verifier-side truth (the existing prover-side `SecurityFloor` is retained but is no longer the security boundary — the verifier is).

---

## 7. Transcript, proof format, version cutover

- `FriTranscriptSeed` (`hc-prover/src/pipeline/phase2_fri.rs`) and the verifier mirror (`api.rs` `verify_fri_queries` + `verify_stark_v3`) gain `grinding_bits` and an extension/challenge-field marker, both bound into the transcript so they cannot be lied about.
- New domain-separation labels for v5/v6 (`DOMAIN_MAIN_V5`, `DOMAIN_FRI_V5`, etc.) in `hc-hash::protocol`.
- **Proof format changes:** `FriQuery.values` is `K`-valued for layers ≥ 1 and opens antipodal indices `(low, low+half)`; add the grinding `nonce`; `ProofParams` gains `grinding_bits`.
- **Version cutover:** prover emits **v5** (and **v6** with ZK). Production `verify` entry rejects `version < 5`. The v2/v3/v4 verify code is retained only behind a **test-only flag** for differential/migration tests, never on the production path.

---

## 8. Blast radius (files that change)

- **`hc-fri`:** `layer.rs` (`fold_layer` → antipodal + `1/x` + domain), `simd_fold.rs` (new arithmetic + parity test), `parallel.rs`, `stream.rs` (two-cursor streaming fold), `prover.rs` (`FoldedLayerProducer` gains domain + two-range read), `queries.rs` (`propagate_query_index` signature, `FriQuery` semantics), `config.rs` (carry domain/offset).
- **`hc-prover`:** `prove.rs` (FRI base setup, K-valued layers, grinding loop, final-layer low-degree material), `pipeline/phase2_fri.rs` (seed + grinding), `pipeline/phase3_queries.rs` (`generate_queries`, antipodal pair openings, K values), `config.rs` + `queries.rs::ProofParams` (`grinding_bits`).
- **`hc-verifier`:** `api.rs` (`verify_fri_queries` rewrite, floor, grinding, final-layer degree check, K challenges), `lib.rs` (floor constants + version gate).
- **`hc-core`:** `field/extension.rs` (embedding / F-scalar mul / serialization helpers if missing).
- **`hc-hash`:** `protocol.rs` (v5/v6 domain labels + grinding label).
- **`hc-sdk`:** proof (de)serialization for the new format / K values / nonce.

---

## 9. Out of scope — flagged with mitigation

- **`hc-recursion` in-circuit fold is also broken** (`circuit/verify_fri.rs:74`: gate `vnext − (v0 + beta·v1)` — the same vacuous fold, in Halo2). Correcting the in-circuit gadget (antipodal + `1/x` + extension) is a substantial separate effort (Phase 1B/2). **Mitigation (in this phase):** confirm whether recursion/aggregation is reachable from the live server/MCP; if so, **gate it off** until the circuit is fixed. (`/aggregate` HTTP is already 410'd from Phase 0.3 — confirm no other path: `hc-node`, `hc-mcp`, `aggregator_v2`.)
- **KZG commitment path** (`verify_kzg`, pinned to legacy v2) — separate scheme, separate soundness story; not corrected here. **Mitigation:** confirm it is not the default/exposed proving path; if exposed, gate behind an explicit experimental flag.
- **zkML** (`hc-zkml`) — out of scope.

---

## 10. Testing strategy (D2)

1. **Forge-PoC (TDD red → green) — deliverable #1.** A test that constructs a proof of a **false** statement (e.g., a quotient codeword that is *not* a genuine low-degree quotient, or one encoding a `final_acc` inconsistent with the trace) and asserts `verify` **rejects** it. **Fails against today's code** (the forgery passes) and **passes after the fix.** Lives in a dedicated `hc-verifier` (or `hc-attacks`) test module; the regression anchor for G2.
2. **Differential test (fold level).** Compare the new `fold_layer` against an independent reference on identical `(codeword, β, domain)`: primary = a dependency-free naive antipodal-with-`1/x` reference **plus** a small set of hardcoded vectors independently computed (committed sage/python snippet in `docs/`); optional `#[ignore]` cross-check vs. Winterfell's folding if the dev-dependency cooperates.
3. **Streaming / SIMD / parallel parity.** All optimized paths must match the naive reference bit-for-bit (existing parity tests updated to the new arithmetic).
4. **Soundness proptests.** Extend `hc-verifier/tests/proptest_soundness.rs`: mutating any opened FRI value, index, the grinding nonce, or a security param must cause rejection; below-floor params must be rejected.
5. **Honest end-to-end.** A valid v5/v6 proof round-trips (prove → encode → decode → verify) across all live templates; the daily-audit E2E updated to v5.

---

## 11. Security properties achieved

- **G2 closed:** the fold is a genuine degree-halving of an actual polynomial (antipodal + `1/x`); passing the query phase implies the quotient is close to low-degree (under the proximity-gap conjecture), so the AIR constraints are enforced. The forge-PoC that passes today is rejected.
- **G7 closed:** the verifier enforces blowup/query/grinding/extension/version floors independent of proof-supplied params; ≥128-bit conjectured soundness with margin; challenges live in a ≥128-bit field, removing the 64-bit cap.

## 12. Threats considered / residual

- **Conjecture reliance (accepted, D1):** 128-bit figure is conjectured (proximity gap to capacity), the same assumption plonky2 / RISC0 / ethSTARK ship on. A provable-soundness regime (≈80 queries, no conjecture) remains a config option but is not the default.
- **No external audit yet (D2):** differential + PoC raise confidence but are not a substitute for a cryptographer's review before advertising the soundness level. Tracked as a follow-on; do not make external soundness claims until then.
- **Recursion deferred (§9):** the in-circuit verifier remains unsound until Phase 1B/2; must be gated off in production in the meantime.
- **`INTERNAL_SECRET` / non-FRI items:** unchanged by this phase.

---

## 13. Implementation order (→ becomes the plan)

1. Forge-PoC + naive reference fold + hardcoded vectors (**red**).
2. `hc-fri` fold → antipodal + `1/x`, natural order, domain-aware, batch inversion; update SIMD/parallel/stream + parity (parity **green**, PoC still red).
3. Extension-field challenges: base layer F, layers ≥1 in K; Merkle/leaf/serialization for K.
4. Grinding: `grinding_bits` in params, prover grind loop, transcript placement.
5. Verifier `verify_fri_queries` rewrite (antipodal, `1/x`, K, domain) + final-layer degree check + **floor** + grinding check (PoC **green**).
6. Prover/verifier wiring: v5/v6 versions, transcript labels, `ProofParams.grinding_bits`, proof (de)serialization.
7. Recursion/KZG exposure audit + gate (§9).
8. Full gate: `cargo clippy --workspace --all-targets -- -D warnings`, `cargo fmt --all --check`, workspace tests, soundness proptests, differential, honest E2E.

## 14. Acceptance criteria

- The forge-PoC (proof of a false statement) is **rejected** by the v5 verifier; the same construction **passed** against the pre-fix code (demonstrated in the PoC's git history / a recorded baseline).
- New `fold_layer` matches the independent reference and hardcoded vectors; all optimized paths match bit-for-bit.
- Verifier rejects any proof below the floor (blowup < 8, queries < 40, grinding < 20, wrong challenge field, version < 5) regardless of what the proof claims.
- A valid v5/v6 proof round-trips and verifies across all live templates.
- `clippy -D warnings` and `fmt --check` clean; soundness proptests pass.
- Recursion/KZG either corrected or gated off from any live path (documented).

## 15. Out of scope (other phases)

- `hc-recursion` in-circuit fold correction (Phase 1B/2).
- KZG path soundness; zkML.
- Independent external cryptographer audit (follow-on before public soundness claims).
- Operational items (G13/G14/G15 — Phase 0; monitoring — Phase 3).
