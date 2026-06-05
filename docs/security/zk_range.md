# Confidentiality & Zero-Knowledge of `range_proof` (v7)

- **Status:** Honest current-state analysis (Phase 1B). Tracks a follow-up for full ZK.
- **Scope:** The `range_proof` template AIR (`RangeAir`) on the sound v7 STARK core.

## 1. What `range_proof` proves

`range_proof` proves the statement `min ≤ V ≤ max` for a secret value `V`, using the bit-decomposition AIR (`crates/hc-air/src/range_air.rs`):

- Width-4 trace `[a_bit, a_acc, c_bit, c_acc]` over `n` rows, where `a = V − min` and `c = max − V` are each decomposed MSB-first and recomposed via Horner.
- Constraints (degree ≤ 2): booleanity of the bit columns, the Horner recurrences, the seed boundaries, and the tie `a_acc[last] + c_acc[last] = max − min`.
- **Public inputs are `{min, max}` only.** `V` is *not* a public input and is *not* a committed trace column — it appears only implicitly as `V = min + a`, where `a` is reconstructed from the private witness columns.

Soundness (that the range is genuinely enforced) is argued in [`soundness_proof.md`](soundness_proof.md) §6 (the single-α composition over `K`) plus the v5/v7 FRI low-degree test. There is **no** assignment of the witness columns satisfying all constraints with `V ∉ [min, max]`.

## 2. Confidentiality provided at v7

- `V` is absent from the public inputs and from the committed columns. A party that sees only `{min, max}` and the verifier's accept learns exactly the statement `V ∈ [min, max]` — nothing more *from the public interface*.

## 3. What v7 does NOT provide: zero-knowledge of the openings

v7 is **not** zero-knowledge. The witness columns are Merkle-committed and **opened, unmasked, at the FRI query points** (and the OOD point). Those openings are evaluations of the witness polynomials at verifier-chosen off-domain points; with enough of them a verifier can extract information about the witness polynomials — hence about `a`, hence about `V`. So a determined verifier is not cryptographically prevented from learning `V` beyond `V ∈ [min, max]`.

For a privacy product whose promise is "prove the range *without revealing V*", this is a real gap. It is acceptable to ship at v7 only because:

1. v7 `range_proof` is strictly better than the prior `Enforcement::StructureOnly` template, which both failed to enforce the range *and* published `V` as `final_acc`.
2. `range_proof` remains **gated** (`audited: false`, behind `HC_ALLOW_UNAUDITED_TEMPLATES`) and is not exposed/advertised in production until the Phase 4 external audit — the same gate that governs the soundness claim.

## 4. Why the trace-additive mask (v4/v6) does not achieve ZK here

The existing mask blinds openings by adding `R(x)·Z_H(x)` to each trace column before committing (`T'(x) = T(x) + R(x)·Z_H(x)`; zero on the trace domain `H`, random off it). For a degree-`d` constraint this is **degree-incompatible with the FRI rate**:

- The masked trace polynomial has degree `≈ |H| + deg(R)` (up from `|H| − 1`).
- A degree-`d` constraint over the masked trace yields a composition of degree `≈ d·(|H| + deg(R))`, so the quotient `q = C/Z_H` has degree `≈ d·|H| + … − |H|`.
- The FRI low-degree test certifies degree `< lde_len / blowup = |H|`. For `d ≥ 2`, the masked quotient degree exceeds `|H|` for any `deg(R) ≥ 0`, so FRI rejects.

`range_proof`'s booleanity (`bit·(bit−1)`) is degree 2, so the trace-additive mask cannot be used. This was confirmed empirically: a v8 (masked) range proof fails verification with `fri final-layer degree check failed` at every tested `(blowup, fri_final_poly_size, mask_degree)` — e.g. blowup 8 / final 32 / mask 1, blowup 16 / final 64 / mask 1. The mask remains valid for **degree-1** AIRs (e.g. the accumulator), where the quotient retains headroom.

## 5. The path to genuine ZK (planned follow-up)

The standard fix is **randomized trace rows** (Winterfell-style), not a higher-degree trace polynomial:

- Append `≈ 2·query_count + O(1)` extra rows holding uniformly random values, and add a selector column that is `1` on the real rows and `0` on the padding.
- Gate every constraint by the selector so the padding rows are unconstrained, and divide the quotient by the vanishing polynomial of the **real** rows only.
- This raises `|H|` (hence the FRI degree bound) enough that the `query_count` openings per column are simulatable — i.e. jointly uniform and independent of the witness — giving statistical zero-knowledge, while the constraint degree stays at 2.

This reopens the seam (selector-gated constraints in `compose_at`, a modified vanishing/quotient domain, and a degree re-analysis), so it is scoped as a dedicated follow-up rather than part of this phase. The formal simulator argument and the concrete row count will be finalized there and reviewed under the Phase 4 external cryptographic audit before any zero-knowledge claim is advertised.

## 6. Summary

| Property | v7 `range_proof` |
|---|---|
| Range `min ≤ V ≤ max` enforced (soundness) | **Yes** (audit-pending, conjectured ~128-bit) |
| `V` absent from public inputs / committed columns | **Yes** |
| Zero-knowledge of openings (verifier cannot learn `V`) | **No** — deferred to the randomized-row follow-up |
| Production exposure | Gated (`audited: false`) until Phase 4 |
