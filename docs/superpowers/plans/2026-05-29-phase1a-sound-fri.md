# Phase 1A — Sound FRI Low-Degree Test + Verifier Soundness Floor — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development. Steps use checkbox (`- [ ]`) syntax. Spec: `docs/superpowers/specs/2026-05-29-phase1a-sound-fri-design.md`.

**Goal:** Replace the vacuous adjacent-pair FRI fold (no `1/x`) with the correct antipodal fold, draw challenges from a 128-bit extension field, add grinding, and enforce a verifier-side security floor — closing audit findings G2 and G7.

**Architecture:** Strangler pattern. New `*_v5` fold/commit/verify code is added **alongside** the existing path so the workspace compiles after every task. The prover switches to v5 (Task 7), the verifier switches to v5 (Task 8, which flips the forge-PoC red→green), then the old vacuous path is deleted (Task 10). FRI folds in `K = QuadExtension<Goldilocks>`; the base layer stays F-committed (== quotient root) and is embedded into `K` only for the fold arithmetic; layers ≥1 are K-committed.

**Tech Stack:** Rust workspace; `hc-fri`, `hc-prover`, `hc-verifier`, `hc-core` (field/domain), `hc-hash` (transcript/protocol), `hc-sdk` (serialization). Blake3 transcript, Goldilocks + QuadExtension, Merkle (`hc-commit`).

**Invariant for every task:** `cargo build --workspace` succeeds and `cargo test -p <touched crate>` passes before commit. The forge-PoC (Task 4) is the one deliberately-failing test, committed `#[ignore]` until Task 8.

**Shared-tree hazard (from project memory):** subagents share ONE working tree. Never let a subagent run `cargo fix` or mutating git. Verify a clean tree + the expected new commit at each task boundary.

---

## Task 1 — Protocol v5/v6 constants + domain-separation labels

**Files:**
- Modify: `crates/hc-hash/src/protocol.rs`

Additive only — establishes the labels later tasks reference. Nothing switches yet.

- [ ] **Step 1 — Read** `crates/hc-hash/src/protocol.rs` to learn the existing `DOMAIN_*` and `label::*` naming (e.g. `DOMAIN_MAIN_V4`, `DOMAIN_FRI_V4`, `label::CHAL_FRI_BETA`, `label::PARAM_*`).

- [ ] **Step 2 — Add v5/v6 domain constants** mirroring the v4 ones:

```rust
pub const DOMAIN_MAIN_V5: &[u8] = b"hc-stark/main/v5";
pub const DOMAIN_FRI_V5: &[u8]  = b"hc-stark/fri/v5";
pub const DOMAIN_MAIN_V6: &[u8] = b"hc-stark/main/v6";
pub const DOMAIN_FRI_V6: &[u8]  = b"hc-stark/fri/v6";
```

- [ ] **Step 3 — Add the new transcript labels** in the `label` module (match the existing label style/const type exactly):

```rust
pub const PARAM_GRINDING_BITS: &[u8] = b"param/grinding_bits";
pub const PARAM_CHALLENGE_FIELD: &[u8] = b"param/challenge_field"; // marks extension-field challenges
pub const FRI_GRINDING_NONCE: &[u8] = b"fri/grinding_nonce";
```

- [ ] **Step 4 — Build & commit.** Run `cargo build -p hc-hash`. Commit: `feat(protocol): v5/v6 domain labels + grinding/challenge-field labels (G2/G7 prep)`.

---

## Task 2 — Naive antipodal reference fold + independently-computed vectors

**Files:**
- Create: `crates/hc-fri/src/reference.rs`
- Modify: `crates/hc-fri/src/lib.rs` (add `pub mod reference;`)
- Create: `docs/fri-reference-vectors.md` (the independent derivation)

This is the differential oracle (spec §10.2) and the executable definition of the correct fold. Pure, obvious, un-optimized.

- [ ] **Step 1 — Write the reference fold.** It operates entirely in `E` (the value field; `E = K` in production) with domain points supplied as `E` (the base-field point embedded into `E`). Natural order, antipodal pairing, `1/x`, no batching, no SIMD:

```rust
//! Dependency-free, obviously-correct FRI fold. The differential oracle for
//! the optimized paths and the executable definition of the spec §3 math.
use hc_core::field::FieldElement;

/// Fold one FRI layer of size `n` (even) to size `n/2`.
///
/// `values[j]` = f(D[j]); `domain[j]` = D[j] (the layer's coset points, the
/// VALUE field's embedding of the base-field point). Pairs antipodal indices
/// `(j, j + n/2)` since D[j + n/2] = -D[j], and computes
///   out[j] = (a+b)/2 + beta * (a-b)/(2*x),  x = D[j],  j in 0..n/2.
pub fn reference_fold<E: FieldElement>(values: &[E], domain: &[E], beta: E) -> Vec<E> {
    assert!(values.len() % 2 == 0, "layer size must be even");
    assert_eq!(values.len(), domain.len());
    let half = values.len() / 2;
    let two_inv = E::from_u64(2).inverse().expect("2 is invertible");
    let mut out = Vec::with_capacity(half);
    for j in 0..half {
        let a = values[j];
        let b = values[j + half];
        let x = domain[j];
        let even = a.add(b).mul(two_inv);
        let two_x_inv = x.add(x).inverse().expect("domain point nonzero on a coset");
        let odd = a.sub(b).mul(two_x_inv);
        out.push(even.add(beta.mul(odd)));
    }
    out
}
```

(If `FieldElement` lacks `sub`, use `a.add(b.neg())` — check the trait in `hc-core/src/field/mod.rs` and match it.)

- [ ] **Step 2 — Independently compute vectors.** Write `docs/fri-reference-vectors.md` containing a short Python/sage snippet that computes, over Goldilocks `p = 2^64 - 2^32 + 1`, the fold of 2–3 small codewords on an explicit coset domain, and paste its numeric outputs. Example structure:

```
# Goldilocks p = 18446744069414584321
# domain: D[j] = offset * g^j, g a 2^k-th root of unity, offset = 7
# fold: out[j] = (f[j]+f[j+n/2])/2 + beta*(f[j]-f[j+n/2])/(2*D[j])  mod p
# (snippet that prints out[] for n=4 and n=8; values pasted below)
```

- [ ] **Step 3 — Write tests** in `reference.rs` asserting `reference_fold` reproduces the pasted vectors exactly (build the domain with `hc_core::domain::EvaluationDomain::new_coset`, offset 7, embed to `E = GoldilocksField` for these base-field vectors). Run `cargo test -p hc-fri reference`. Expected: PASS.

- [ ] **Step 4 — Commit.** `test(fri): naive antipodal reference fold + independent vectors (differential oracle)`.

---

## Task 3 — Correct fold across all `hc-fri` paths (`*_v5`, additive)

**Files:**
- Modify: `crates/hc-fri/src/layer.rs` (add `fold_layer_v5`), `simd_fold.rs`, `parallel.rs`, `stream.rs`, `prover.rs` (`FoldedLayerProducer` → domain-aware v5 producer), `queries.rs` (`propagate_query_index_v5`).

Add the production fold alongside the old one. **Do not remove or change** the existing `fold_layer` / `propagate_query_index` (callers still use them until Tasks 7–8).

- [ ] **Step 1 — `layer.rs`: add the domain-aware fold.** A `LayerDomain` carries the coset so points are cheap and the streaming path can advance incrementally:

```rust
/// Coset of a single FRI layer: D[j] = offset * gen^j, size n. `gen^n = 1`,
/// `gen^(n/2) = -1` (antipodal partner of j is j + n/2). Values are field `E`;
/// domain points are produced in `E` (base-field points embedded into `E`).
#[derive(Clone, Debug)]
pub struct LayerDomain<E: FieldElement> {
    pub offset: E,
    pub gen: E,
    pub size: usize,
}
impl<E: FieldElement> LayerDomain<E> {
    pub fn point(&self, j: usize) -> E { self.offset.mul(self.gen.pow(j as u64)) }
    /// Next layer: square offset and generator, halve size (x -> x^2 domain).
    pub fn squared(&self) -> Self {
        Self { offset: self.offset.mul(self.offset), gen: self.gen.mul(self.gen), size: self.size / 2 }
    }
}

/// Antipodal, 1/x fold of a layer of size n -> n/2 (spec §3). Bit-identical to
/// `reference::reference_fold`. Uses Montgomery batch inversion of the `2*D[j]`.
pub fn fold_layer_v5<E: FieldElement>(values: &[E], domain: &LayerDomain<E>, beta: E) -> HcResult<Vec<E>> {
    if values.len() % 2 != 0 { return Err(HcError::invalid_argument("FRI layer size must be even")); }
    let half = values.len() / 2;
    let two_inv = E::from_u64(2).inverse().ok_or_else(|| HcError::math("2 not invertible"))?;
    // Batch-invert 2*D[j] for j in 0..half.
    let mut two_x: Vec<E> = (0..half).map(|j| { let x = domain.point(j); x.add(x) }).collect();
    batch_invert(&mut two_x)?; // helper below or from hc-core::field::batch_ops
    let mut out = Vec::with_capacity(half);
    for j in 0..half {
        let a = values[j];
        let b = values[j + half];
        let even = a.add(b).mul(two_inv);
        let odd = a.add(b.neg()).mul(two_x[j]);
        out.push(even.add(beta.mul(odd)));
    }
    Ok(out)
}
```

Prefer an existing batch inversion in `hc-core/src/field/batch_ops.rs`; if none fits, add a small private `batch_invert<E: FieldElement>(xs: &mut [E]) -> HcResult<()>` (Montgomery: prefix products → one inverse → back-substitute). **Differential test:** `fold_layer_v5` must equal `reference::reference_fold` for assorted sizes (4..=4096) and random codewords/betas/cosets. Add this test now; run `cargo test -p hc-fri`.

- [ ] **Step 2 — `simd_fold.rs`: v5 SIMD path.** The packed step is `even + beta*odd` with precomputed per-lane `(2x)^-1` and `1/2`. Add `try_fold_goldilocks_v5` (or generalize) and keep a scalar tail. **Parity test:** SIMD v5 == `fold_layer_v5` scalar at all sizes incl. tails. (If the extension field `K` is the production value type and packing only exists for base Goldilocks, it is acceptable for the SIMD fast-path to apply only when `E == GoldilocksField` and fall back to scalar for `K`; document this and keep the parity test for the Goldilocks case.)

- [ ] **Step 3 — `parallel.rs`: v5 parallel fold.** `fold_layer_v5_parallel` — same arithmetic, `par_iter` over `j in 0..half`, batch-invert per chunk. Parity test vs scalar v5.

- [ ] **Step 4 — `stream.rs` + `prover.rs`: domain-aware streaming producer.** Add a `FoldedLayerProducerV5<E>` that, for output range `[s, e)`, reads the previous layer's **two half-ranges** `prev[s..e]` and `prev[s+half .. e+half]` (two cursors, antipodal) and the domain points for `s..e`, then applies the v5 fold. It carries the previous layer's `LayerDomain`. Confirm memory stays O(block) (two block-sized reads, not O(N)). Test: a `VecBlockProducer` base folded via the v5 producer matches `fold_layer_v5` on the whole layer.

- [ ] **Step 5 — `queries.rs`: v5 index propagation.**

```rust
/// Antipodal fold: x and -x (indices j and j+n/2) both map to D'[j].
/// next_index = q mod (n/2) = q & (n/2 - 1).  `layer_size` = n (power of two).
pub fn propagate_query_index_v5(current_index: usize, layer_size: usize) -> usize {
    debug_assert!(layer_size.is_power_of_two());
    current_index & ((layer_size / 2) - 1)
}
```

Unit-test against hand values (e.g. layer_size 8: q=5 → 1, q=2 → 2, q=7 → 3).

- [ ] **Step 6 — Build & test & commit.** `cargo test -p hc-fri` (reference, differential, parity, producer, index). Commit: `feat(fri): correct antipodal 1/x fold (v5) across scalar/simd/parallel/streaming + index map (G2)`.

---

## Task 4 — Forge-PoC: FRI accepts a high-degree codeword (RED, ignored)

**Files:**
- Modify: `crates/hc-verifier/src/api.rs` (make `verify_fri_queries` reachable from a test — `pub(crate)` if not already, or add the test in the same module) and add a `#[cfg(test)]` module, **or** create `crates/hc-verifier/tests/forge_poc_g2.rs` with a minimal exposed shim.
- Reference: spec §10.1.

**Goal:** isolate G2 — demonstrate the low-degree test accepts a codeword that is *not* low-degree. Pre-fix this passes (assertion that it's rejected FAILS → red). Post-fix (Task 8) it passes.

- [ ] **Step 1 — Build a high-degree base codeword** `C` on the LDE coset (size `lde_len = padded_len * blowup`): e.g. evaluations of a degree `lde_len - 1` polynomial, or pseudo-random values seeded deterministically. `C` is NOT a low-degree codeword (rate ≪ 1).

- [ ] **Step 2 — Commit `C` through the (current) FRI prover** to get `layer_roots`, `betas`, `final_layer`, `final_root`, and produce the `FriQuery` openings at the FS-sampled query indices (reuse `hc_prover::pipeline::phase3_queries::generate_queries` for the indices and the FRI artifacts' producers + `hc_fri::layer::merkle_path_from_hashes` for paths). Assemble a `Proof`/`QueryResponse` whose `composition_queries` equal `C` at those indices (so the base binding is satisfied) and whose `fri_queries` open `C`'s committed layers.

- [ ] **Step 3 — Assert rejection (the spec'd post-fix behavior):**

```rust
// G2 forge: a high-degree codeword must NOT pass the low-degree test.
let result = /* call the FRI verification path on the assembled proof */;
assert!(result.is_err(), "FRI accepted a high-degree codeword — low-degree test is vacuous (G2)");
```

- [ ] **Step 4 — Run it and CONFIRM RED.** `cargo test -p hc-verifier forge_poc_g2 -- --include-ignored` (or without ignore first). Expected **FAIL** against current code (the high-degree codeword is accepted → `result.is_err()` is false). **Record the red result in the commit message.** This is the concrete demonstration that G2 is real.

- [ ] **Step 5 — Add `#[ignore = "RED until G2 fix lands in Task 8; see Phase 1A plan"]`** so the suite stays green, and commit: `test(verifier): forge-PoC — current FRI accepts a high-degree codeword (G2, RED/ignored)`.

> Stretch (optional, only if cheap): a full false-statement forge (high-degree quotient table reaching a wrong `final_acc` that passes pointwise relation + vacuous FRI). Not required — the fold-level PoC above is the regression anchor.

---

## Task 5 — Extension-field plumbing (`K = QuadExtension<Goldilocks>`)

**Files:**
- Modify: `crates/hc-core/src/field/extension.rs` (helpers if missing), `crates/hc-fri/src/layer.rs` (`hash_value` for K), `crates/hc-fri/src/queries.rs` (K-valued types or generics).

The base layer is committed/opened in `F`; folded layers (≥1) are in `K`. The fold arithmetic runs in `K` (base pair embedded F→K at round 0). This task makes `K` carry the needed ops; it does not switch the prover/verifier yet.

- [ ] **Step 1 — Read** `crates/hc-core/src/field/extension.rs`. Confirm `QuadExtension<F>` implements `FieldElement` (it does) and identify what's missing for: (a) **embed** a base `F` into `K` (`K::from_base(f)` or via `from_u64` of the limbs / a `c0 + 0·c1` constructor), (b) **multiply** a `K` by an `F` scalar (or just embed then `mul`), (c) **serialize** a `K` to bytes for Merkle leaves and the transcript (need a stable little-endian encoding of both coefficients).

- [ ] **Step 2 — Add the missing helpers** (TDD): write tests first.
  - `pub fn from_base(c0: F) -> Self` (c1 = 0). Test: `from_base(x)` embeds and round-trips; `from_base(a).mul(from_base(b)) == from_base(a.mul(b))` (field homomorphism).
  - `pub fn to_le_bytes(&self) -> [u8; 16]` and `from_le_bytes` (two Goldilocks limbs). Test: round-trip.
  - Confirm `inverse`, `add`, `mul`, `neg`, `pow`, `ONE`, `ZERO`, `from_u64` exist (used by the fold).

- [ ] **Step 3 — `hash_value` for K leaves.** `hc-fri/src/layer.rs::hash_value` currently encodes `[value.to_u64(), value.square().to_u64()]` (16 bytes, base-field-only — lossy for K). Add `hash_value_ext<E: FieldElement>` (or make `hash_value` encode via a field-width-aware byte serialization) so K leaves bind both coefficients. **Important:** the base layer keeps the existing F encoding (it must match the quotient-oracle commitment); only layers ≥1 use the K encoding. Test: distinct K values hash distinctly; equal values hash equally.

- [ ] **Step 4 — K-valued `FriProof`/`FriQuery`.** These are already generic `FriProof<F>` / `FriQuery<F>`. Confirm the production FRI proof for layers ≥1 will be instantiated at `K` while the base binding uses `F`. If the proof must hold a mix (F base opening + K folded openings), document the chosen representation here (recommended: `FriQuery` for the base layer carries embedded-K values via `from_base`, so the whole `FriProof` is `FriProof<K>` and the base binding compares `K::from_base(composition_opening_F)` to the base FRI value). Add a type/towers note as a doc comment.

- [ ] **Step 5 — Build & test & commit.** `cargo test -p hc-core extension`, `cargo test -p hc-fri`. Commit: `feat(core/fri): QuadExtension embed/serialize + K-aware leaf hashing for FRI (G2 ext-field challenges)`.

---

## Task 6 — Grinding / proof-of-work

**Files:**
- Modify: `crates/hc-prover/src/config.rs` (`ProverConfig` + `SecurityFloor`), `crates/hc-prover/src/queries.rs` (`ProofParams`), `crates/hc-prover/src/pipeline/phase2_fri.rs` (grind loop + seed), `crates/hc-sdk/src/proof.rs` (serialize the nonce + grinding_bits).

Additive: the old path ignores grinding; v5 (Task 8) enforces it.

- [ ] **Step 1 — Add `grinding_bits: u32`** to `ProverConfig` (default 20) and to `ProofParams`, and to `SecurityFloor` as `min_grinding_bits` (default 20; `relaxed()` → 0). Thread it through the `ProverConfig` constructors (preserve existing call sites with the default). Bind it into the transcript wherever the other `PARAM_*` are appended (prover `phase2_fri.rs` seed + the `verify_stark_v3`/`verify_fri_queries` mirrors) using `protocol::label::PARAM_GRINDING_BITS`.

- [ ] **Step 2 — Grind loop** (in the FRI prover after all roots are committed, before query sampling). Search a `u64` nonce so the transcript-derived challenge has ≥ `grinding_bits` leading zero bits:

```rust
/// Find a nonce whose appended transcript squeeze has >= bits leading zeros.
fn grind<H: HashFunction>(transcript: &mut Transcript<H>, label: &[u8], bits: u32) -> u64 {
    let mut nonce: u64 = 0;
    loop {
        let mut probe = transcript.clone(); // fork; do not mutate the real transcript while searching
        protocol::append_u64::<H>(&mut probe, label, nonce);
        let digest = probe.challenge_bytes(protocol::label::FRI_GRINDING_NONCE);
        if leading_zero_bits(&digest) >= bits { return nonce; }
        nonce = nonce.checked_add(1).expect("grinding nonce space exhausted");
    }
}
```

Then append the winning nonce to the *real* transcript (same label) so query sampling is downstream of it. `leading_zero_bits(&[u8])` counts MSB-first zero bits across the digest. Confirm `Transcript` is `Clone`; if not, snapshot its state another way (e.g. a probe transcript seeded identically). Store the nonce in the artifacts/proof.

- [ ] **Step 3 — Serialize** `grinding_bits` and `nonce` in the proof format (`hc-sdk/src/proof.rs`). Round-trip test.

- [ ] **Step 4 — Build & test & commit.** Commit: `feat(prover): grinding/proof-of-work nonce + grinding_bits param (G7)`.

---

## Task 7 — Prover v5 path

**Files:**
- Modify: `crates/hc-prover/src/prove.rs` (FRI base setup → K, v5 fold via the new producer, final-layer low-degree material, emit v5/v6), `crates/hc-prover/src/pipeline/phase2_fri.rs` (use `FriProverV5`/v5 producer + grind), `crates/hc-prover/src/pipeline/phase3_queries.rs` (`generate_queries` unchanged for index sampling; **open antipodal pairs** `(low, low+half)` per layer with K values), `crates/hc-fri/src/prover.rs` (a `prove_with_producer_v5` that uses `fold_layer_v5` + `LayerDomain` + K + grinding hook).

- [ ] **Step 1 — FRI v5 commit.** Add `FriProver::prove_with_producer_v5` that: builds the base `LayerDomain<K>` from the LDE coset (offset 7, embedded to K), commits the base layer in **F** (matching the quotient root), then for each round samples `beta ∈ K` (`challenge_field::<K>`), folds via `FoldedLayerProducerV5` (round 0 embeds F→K), commits each folded layer in **K**, down to `final_poly_size`. Returns K-valued artifacts + betas. Reuse the streaming commit loop already in `prove_with_producer`.

- [ ] **Step 2 — Final-layer low-degree material** (spec §3.5). Ship what the verifier needs to confirm the final layer has degree `< final_poly_size / blowup`: either the `final_poly_size / blowup` coefficients (verifier evaluates), or the full final evaluations + the verifier interpolates and checks the high coefficients are zero. Choose coefficients (smaller, unambiguous): include them in `FriProof` (a `final_coeffs: Vec<K>` of length `final_poly_size / blowup`). Document the choice.

- [ ] **Step 3 — Query openings (antipodal).** In `phase3_queries`, for each base query `q` and each layer (size `n`), open the pair at `(q & (n/2-1), (q & (n/2-1)) + n/2)` with Merkle paths against that layer's root; values are K for layers ≥1, F (embedded) for the base. Propagate `q := propagate_query_index_v5(q, n)`. Keep the base binding to the composition oracle (embed F→K for the comparison).

- [ ] **Step 4 — Emit v5/v6.** Set `protocol_version = 5` for the native STARK and `6` when ZK masking is on (mirror the existing v3/v4 split). Use `DOMAIN_MAIN_V5/V6`, `DOMAIN_FRI_V5/V6`. Put `grinding_bits` + nonce + `final_coeffs` in the proof.

- [ ] **Step 5 — Build & test & commit.** A prover-side unit test: prove a small honest statement at v5, assert it produces K-valued layers, a nonce meeting the grind, and `final_coeffs` of the right length. (End-to-end verify lands in Task 8.) Commit: `feat(prover): v5 sound-FRI proving — antipodal fold in K, grinding, final coeffs (G2/G7)`.

---

## Task 8 — Verifier v5 path (flips the forge-PoC GREEN)

**Files:**
- Modify: `crates/hc-verifier/src/api.rs` (rewrite `verify_fri_queries` for v5; route v5/v6; final-layer degree check; K challenges), `crates/hc-verifier/src/lib.rs` (floor constants + version gate), `crates/hc-verifier/src/errors.rs` (new error variants if needed).

- [ ] **Step 1 — Verifier soundness floor (G7)**, checked in the top-level `verify` **before** trusting any proof param:

```rust
// Verifier-enforced minimums (spec §6). Independent of what the proof claims.
const MIN_BLOWUP: usize = 8;
const MIN_QUERIES: usize = 40;
const MIN_GRINDING_BITS: u32 = 20;
const MAX_FRI_FINAL_POLY_SIZE: usize = 256;
const MIN_SOUND_VERSION: u32 = 5;

fn enforce_floor<F>(proof: &Proof<F>) -> HcResult<()> {
    if proof.version < MIN_SOUND_VERSION { return Err(VerifierError::UnsoundLegacyVersion.into()); }
    let p = &proof.params;
    if p.lde_blowup_factor < MIN_BLOWUP { return Err(VerifierError::BelowSecurityFloor.into()); }
    if p.query_count < MIN_QUERIES { return Err(VerifierError::BelowSecurityFloor.into()); }
    if p.grinding_bits < MIN_GRINDING_BITS { return Err(VerifierError::BelowSecurityFloor.into()); }
    if p.fri_final_poly_size > MAX_FRI_FINAL_POLY_SIZE { return Err(VerifierError::BelowSecurityFloor.into()); }
    // challenge field must be the >=128-bit extension (bound via PARAM_CHALLENGE_FIELD).
    Ok(())
}
```

Call `enforce_floor` at the start of `verify_with_summary` for v5/v6. Add the error variants.

- [ ] **Step 2 — Recompute the grinding check.** After recomputing the FRI transcript (betas in K), re-derive the grind digest with the proof's nonce and reject unless it has ≥ `grinding_bits` leading zeros (mirror `grind`/`leading_zero_bits`). Sample query indices downstream of the nonce (match the prover's ordering exactly).

- [ ] **Step 3 — Rewrite the per-layer fold check** (the heart). Replace the `values[0] + beta*values[1]` loop with the antipodal, `1/x`, K, domain-aware version:

```rust
// Per base query q, descend the layers. layer 0 size = base_len, domain = LDE coset (K-embedded).
let mut layer_size = base_len;
let mut domain = LayerDomain::<K> { offset: K::from_base(F::from_u64(7)), gen: base_gen_k, size: base_len };
let mut current_index = base_query;
let mut expected: Option<K> = bind_base_to_composition
    .then(|| K::from_base(*composition_by_index.get(&base_query).ok_or(VerifierError::QueryIndexMismatch)?));
let two_inv = K::from_u64(2).inverse().unwrap();

for (layer_idx, beta) in betas.iter().enumerate() {
    let half = layer_size / 2;
    let low = current_index & (half - 1);
    let rec = fri_iter.next().ok_or(VerifierError::FriQueryCountMismatch)?;
    if rec.layer_index != layer_idx || rec.query_index != low { return Err(VerifierError::FriQueryIndexMismatch.into()); }

    // Merkle-verify the antipodal pair at indices (low, low+half) against layer_roots[layer_idx].
    let root = proof.fri_proof.layer_roots[layer_idx];
    // hash_value_for_layer (add here): a dispatcher that uses the base F encoding
    // (hc-fri `hash_value`, on the base-field part c0) for layer 0 so it matches the
    // quotient root, and the K encoding (`hash_value_ext` from Task 5) for layers >= 1.
    let leaf0 = hash_value_for_layer(layer_idx, &rec.values[0]);
    let leaf1 = hash_value_for_layer(layer_idx, &rec.values[1]);
    if !rec.merkle_paths[0].verify::<Blake3>(root, leaf0) || !rec.merkle_paths[1].verify::<Blake3>(root, leaf1) {
        return Err(VerifierError::FriQueryMerkleMismatch.into());
    }

    // The opened value at the queried position must match the running fold value.
    if let Some(exp) = expected {
        let at_low = current_index == low; // queried element is values[0] iff current_index == low, else values[1]
        let v = if at_low { rec.values[0] } else { rec.values[1] };
        if v != exp { return Err(VerifierError::FriQueryEvaluationMismatch.into()); }
    }

    // Correct fold: a=f(x)=values at low, b=f(-x)=values at low+half, x = domain.point(low).
    let a = rec.values[0]; // values[0] is the low index, values[1] the high — enforced by rec.query_index == low
    let b = rec.values[1];
    let x = domain.point(low);
    let even = a.add(b).mul(two_inv);
    let odd = a.add(b.neg()).mul(x.add(x).inverse().ok_or(VerifierError::Math)?);
    expected = Some(even.add(beta.mul(odd)));

    current_index = low;            // = propagate_query_index_v5(current_index, layer_size)
    layer_size = half;
    domain = domain.squared();
}

// Final-layer low-degree check: the descended value must equal the final polynomial evaluated at the
// final domain point, AND the final polynomial degree must be < final_poly_size / blowup.
verify_final_layer::<K>(&proof.fri_proof, current_index, expected, &domain, blowup)?;
```

Implement `verify_final_layer` to (a) check the running `expected` equals `final_coeffs` evaluated at `domain.point(current_index)`, and (b) confirm `final_coeffs.len() == final_poly_size / blowup` (degree bound). This is what makes a high-degree codeword fail.

- [ ] **Step 4 — Route v5/v6** to this path in `verify_with_summary`; keep v2/v3/v4 verification only behind `#[cfg(any(test, feature = "legacy-verify"))]` (for the differential/migration tests), never on the default production path.

- [ ] **Step 5 — Flip the forge-PoC GREEN.** Remove `#[ignore]` from Task 4's test and point it at the v5 verifier. The high-degree codeword must now be **rejected** (its correctly-folded final layer is not degree `< final/blowup`, or the consistency check fails). Run `cargo test -p hc-verifier forge_poc_g2`. Expected: **PASS**.

- [ ] **Step 6 — Build & test & commit.** `cargo test -p hc-verifier`. Commit: `feat(verifier): v5 sound-FRI verification — antipodal 1/x fold, K challenges, grinding + security floor; forge-PoC now rejected (G2/G7)`.

---

## Task 9 — Recursion / KZG exposure audit + gate

**Files:**
- Inspect: `crates/hc-recursion/**`, `crates/hc-node/src/lib.rs`, `crates/hc-mcp/src/tools/**`, `crates/hc-server/src/lib.rs`, `crates/hc-recursion/src/aggregator_v2.rs`.
- Modify: whatever exposes them, to gate.

- [ ] **Step 1 — Determine reachability.** Grep for live entry points that invoke `hc-recursion` (in-circuit FRI fold `verify_fri.rs:74` shares the G2 bug) or the KZG verify path from the **server or MCP**. `/aggregate` HTTP is already 410 (Phase 0.3) — confirm there is no other route (node, MCP tool, batch).

- [ ] **Step 2 — Gate anything exposed.** If recursion/aggregation or KZG proving is reachable from a live endpoint, disable it (return a clear "unavailable — pending soundness fix" error, mirroring the 410 pattern) behind a documented flag. If nothing is reachable, record that finding (a short note in the plan/PR) and gate only at the library boundary with a `#[doc]`/`debug_assert`-style guardrail.

- [ ] **Step 3 — Commit.** `chore(recursion/kzg): gate unsound in-circuit FRI / KZG paths off live endpoints (G2 follow-on)` (or `docs:` if only a finding + library guard).

---

## Task 10 — Cleanup, soundness proptests, honest E2E, full gate

**Files:**
- Modify: `crates/hc-fri/**` (remove old `fold_layer`, `propagate_query_index`, old producer, old SIMD path), all old callers; `crates/hc-verifier/tests/proptest_soundness.rs`; the daily-audit E2E script; `crates/hc-server` if it pins a protocol version.

- [ ] **Step 1 — Delete the vacuous path.** Remove the old adjacent-pair `fold_layer`/`propagate_query_index`/`FoldedLayerProducer`/old SIMD fold and rename the `*_v5` symbols to the canonical names (drop the `_v5` suffix) now that they're the only path. Ensure no caller references the removed symbols. `cargo build --workspace`.

- [ ] **Step 2 — Extend soundness proptests.** In `proptest_soundness.rs`: generate valid v5 proofs and assert rejection when mutating any opened FRI value, a Merkle path, the grinding nonce, `query_count`/`blowup`/`grinding_bits` (below floor), or the `final_coeffs`. Add a direct floor test: a proof with `query_count = MIN_QUERIES - 1` is rejected.

- [ ] **Step 3 — Honest E2E.** Prove → encode → decode → verify a valid statement at v5/v6 across all live templates (mirror existing E2E tests). Update the daily-audit script (`api_health_audit.sh` or equivalent) to the v5 flow if it pins a version.

- [ ] **Step 4 — Full workspace gate (run by the controller, not truncated):**
  - `cargo fmt --all --check`
  - `cargo clippy --workspace --all-targets -- -D warnings`
  - `cargo test --workspace`
  - `cargo test -p hc-verifier forge_poc_g2` (GREEN), `cargo test -p hc-fri` (differential/parity), soundness proptests.

- [ ] **Step 5 — Commit.** `refactor(fri): remove vacuous fold; v5 is the only path + soundness proptests + v5 E2E (G2/G7 complete)`.

---

## Acceptance criteria (spec §14)

- The forge-PoC (high-degree codeword) is **rejected** by the v5 verifier; the same construction **passed** pre-fix (recorded in Task 4's commit message / git history).
- `fold_layer` (production) matches `reference::reference_fold` and the independent vectors; SIMD/parallel/streaming match scalar bit-for-bit.
- The verifier rejects any proof below the floor (blowup < 8, queries < 40, grinding < 20, version < 5, wrong challenge field) regardless of proof-claimed params.
- A valid v5/v6 proof round-trips and verifies across all live templates.
- `cargo fmt --all --check` and `cargo clippy --workspace --all-targets -- -D warnings` clean; soundness proptests pass.
- Recursion/KZG are corrected or gated off every live path, with the finding documented.

## Out of scope (other phases)

- `hc-recursion` in-circuit fold *correction* (Phase 1B/2) — this phase only gates it.
- KZG path soundness; zkML.
- External cryptographer audit (follow-on before any public soundness claim).
- Performance optimization (e.g. base-layer-in-F to avoid K re-commit overhead) — correctness first; perf is Phase E.

## Self-review notes (controller)

- **Type strategy:** FRI proof is `FriProof<K>`; base-layer values are `K::from_base(F)`; base-layer Merkle leaves keep the F encoding (to equal the quotient root) — the base binding compares `K::from_base(composition_F)`. Confirm this is coherent during Task 5/7/8; if the base re-commit in K is simpler than a mixed encoding, that's an acceptable alternative (note it and keep the F→K binding) at a small proof-size cost.
- **Green-per-task:** Tasks 1–7 are additive (`*_v5` alongside old); the prover still emits the old version until Task 7, the verifier still uses the old path until Task 8. The PoC is the only red test and is `#[ignore]`d until Task 8. Task 10 removes the old path.
- **Transcript ordering:** the prover (`phase2_fri.rs`) and verifier (`verify_fri_queries`) MUST append `grinding_bits` / challenge-field marker / nonce in the identical order; any mismatch silently changes the challenges. Diff the two append sequences during Task 8.
