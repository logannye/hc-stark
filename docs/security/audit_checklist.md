# External Audit Checklist — deployed v5 / v7 surface

> **Scope.** This checklist targets the **deployed** proving/verifying path that
> backs tinyzkp.com: the sound v5 STARK (single-α composition + FRI low-degree
> test in the quadratic extension K) and the v7 general-AIR layer. It is the
> surface a Phase-4 external cryptographer should review. Soundness is
> **conjectured** under the ethSTARK Reed-Solomon **proximity-gap conjecture**
> (see [`soundness_proof.md`](soundness_proof.md)); the goal of the audit is to
> validate the implementation against that conjecture, not to prove the
> conjecture. Everything in **§Out of scope** is fenced from every live path and
> should not consume audit budget.
>
> **Start here:** the [`auditor_guide.md`](auditor_guide.md) maps each soundness
> claim to the test that demonstrates it, and `./scripts/run_soundness_suite.sh`
> runs them all in one command (~70 s, 10/10 groups).

## Priority 1 — Live verifier (the forgery boundary)

### `crates/hc-verifier/src/v5.rs`
- [ ] `verify_v5` / `verify_v7` reconstruct the Fiat-Shamir transcript byte-identically to the prover (DOMAIN_MAIN_V5/V7 order; see prover `prove_v5`/`prove_v7`).
- [ ] **Verifier security floor enforced before any crypto:** `VerifierSecurityFloor::default` = min_queries 40, min_blowup 8, min_grinding_bits 20, min_sound_version 5; a proof below any of these is rejected (no path skips the floor).
- [ ] FRI fold checked as **antipodal + 1/x** (`f(x), f(x+half)` with the `1/x` domain weighting), natural-order layout, K-valued.
- [ ] **Final-degree bound** re-evaluated: `final_coeffs` interpolated and degree `< fri_final_size/blowup` enforced (`FriFinalDegreeMismatch`) — this is the check that closed the previously-vacuous fold (G2). A high-degree codeword must be rejected here.
- [ ] FRI layer roots verified against their Merkle commitments; query openings (antipodal pairs) verified against layer-0 leaves.
- [ ] K-extension leaf binding: `hash_value_ext` binds **both** coefficients (c0‖c1, 16 bytes) of every K element; a c1-only tamper is caught.
- [ ] Composition relation checked in K: `C == q · Z_H` via `compose_at` (single composition challenge α drawn from K; v7 sums `Σ αⁱ·cᵢ` over width-N columns).
- [ ] Grinding (proof-of-work) nonce verified against the transcript-bound `grinding_bits`.
- [ ] Public inputs are transcript-bound (v7: PUB_INPUT_COUNT + each element); boundary constraints checked at first/last rows.
- [ ] No early return skips a check; version-tamper and relaxed-parameter proofs are rejected.

## Priority 2 — FRI, prover, transcript

### `crates/hc-fri/src/layer.rs` (+ `simd_fold.rs`, `prover.rs`)
- [ ] `fold_layer_v5` (and SIMD/parallel/streaming twins) compute antipodal + 1/x identically to the verifier, over natural-order coset domain (offset 7).
- [ ] Streaming fold holds **O(block)** state (no full-layer buffering) and produces byte-identical roots to the non-streaming reference.

### `crates/hc-prover/src/prove.rs`, `queries.rs`
- [ ] `prove_v5` / `prove_v7`: grind happens **after** FRI roots and **before** `generate_queries`; query sampling derives from the post-grind transcript.
- [ ] `build_quotient_lde_k` (v5) / `build_quotient_lde_k_n` (v7) commit the K-valued quotient; the composition is one K column regardless of trace width.
- [ ] Width-N trace leaves (`hash_trace_row_n`) are byte-identical to the width-2 hash for width 2 (back-compat) and bind all N columns otherwise.

### `crates/hc-hash/src/{protocol.rs,transcript.rs,grinding}`
- [ ] v5/v7 domain + seam labels are unique (`protocol_invariants` uniqueness tests); no label reuse across steps.
- [ ] `challenge_field::<K>` is genuinely extension-degree-aware (draws c0 **and** c1 from the digest; base-field challenge stays byte-identical to v3 — determinism preserved).
- [ ] `grind` / `check_grinding` bind the transcript state + counter (manual `Transcript: Clone` is faithful).

## Priority 3 — Field & hash primitives

### `crates/hc-core/src/field/` (Goldilocks + `QuadExtension<Goldilocks>` = K)
- [ ] `add/sub/mul/neg/inverse`: result always reduced mod p; `mul` 128-bit intermediate correct for Goldilocks (p = 2^64−2^32+1).
- [ ] `QuadExtension` arithmetic (the challenge field K ≈ 2^128) is correct; `from_base`, `to_le_bytes` (16-byte c0‖c1) round-trip.

### `crates/hc-hash/src/blake3.rs`, `crates/hc-commit/src/merkle/`
- [ ] Blake3 wrapper + leaf/internal domain separation (no leaf↔internal collision).
- [ ] Streaming (height-DFS) Merkle root == full-tree root; `path::verify` recomputes the root from leaf + siblings; multi-open chunking (≤64 leaves) is byte-identical.

## Priority 4 — Serialization & version routing

### `crates/hc-sdk/src/proof.rs`
- [ ] `encode/decode_proof_v5` and `encode/decode_proof_v7` are inverse; version field consistent (envelope vs payload).
- [ ] `verify_proof_bytes` routes version ≥7 → v7, ≥5 → v5, and **rejects < 5** (the pre-v5 unsound path is unreachable); KZG-scheme proofs are rejected on the v7 path.
- [ ] No information loss in u64 ↔ field-element conversion.

## Priority 5 — AIR constraint soundness (per live/gated template)

### `crates/hc-air/src/{accumulator_air.rs,range_air.rs}`
- [ ] `AccumulatorAir` (live): boundary acc-init/acc-final + transition `acc' − acc − delta` vanish exactly on valid traces; a tamper is caught.
- [ ] `RangeAir` (gated, `audited:false`): degree-2 booleanity `cur·(cur−1)`, Horner recomposition, and the `a + c = max − min` tie are all enforced; an out-of-range witness is refused at build and a tampered trace fails to verify.

## Soundness test inventory (run these)
- [ ] The **forge-PoC** (a high-degree codeword the pre-v5 verifier accepted) is REJECTED by v5 while honest proofs verify — the concrete G2 closure.
- [ ] Soundness proptests (`proptest_soundness`) + v7 range round-trip/determinism proptests.
- [ ] Production-config round-trip: a `production_v5` proof verifies through `verify_proof_bytes`; legacy v2/v3 are rejected.

## Out of scope (fenced from every live path — do not audit for production)
- **KZG commitment** (`crates/hc-prover/src/kzg.rs`): legacy/experimental, **default off** (`CommitmentScheme::Stark` is the default and the only scheme the live worker uses), pinned to the legacy v2 transcript, and **rejected** by `verify_proof_bytes` (`< v5`). Its setup uses a hardcoded RNG seed (recoverable τ) and is **NOT a secure trusted setup** — see the DO-NOT-USE banner in `kzg.rs`. Slated for feature-gating out of the default build.
- **`contracts/StarkVerifier.sol`**: a non-functional placeholder (`verifyProof` returns true after a partial parse); carries a DO-NOT-DEPLOY banner; not part of any shipped verification path.
- **hc-recursion in-circuit FRI fold** (`circuit/verify_fri.rs`): still the legacy vacuous fold; gated off — the live `/aggregate` endpoint returns **410 Gone**. Real fix is a future phase.
- **Pre-v5 paths** (`verify_stark_v3`, the old `fri_verify.rs`): retained only as deprecated/test references; rejected by the verifier floor and `verify_proof_bytes`.
