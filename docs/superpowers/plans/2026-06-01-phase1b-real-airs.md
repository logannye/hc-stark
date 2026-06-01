# Phase 1B — General AIR layer + first real template (`range_proof`) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Generalize the sound v5 STARK seam from the hardcoded width-2 `ToyAir` 2-tuple to a sound N-constraint AIR (α-powers in `K`), then ship `range_proof` as the first template whose AIR actually binds its predicate — kept honestly `Enforced` but gated until the Phase 4 audit.

**Architecture:** Strangler, additive, PoC-first (mirrors Phase 1A). New protocol **v7** (and **v8** = v7 + ZK) lands as *parallel* functions alongside v5/v6; the v5 live path is retired only at the end. The crypto core (`Air` trait, `compose_at`, `RangeAir`) is built and tested in `hc-air` in complete isolation (T1–T3) before any prover/verifier plumbing. The quotient/composition stays a single `K`-valued column regardless of trace width, so **FRI, grinding, query sampling, and quotient commit are reused unchanged** — width-N only touches the *trace* commit, *trace* openings, and the quotient numerator.

**Tech Stack:** Rust (workspace, edition 2021, MSRV 1.77); `Goldilocks` base field `F`, `QuadExtension<Goldilocks>` extension `K`; Blake3 Merkle; `inventory` for template registry. Spec: `docs/superpowers/specs/2026-06-01-phase1b-real-airs-design.md`.

**Conventions for the executor:**
- This plan gives **complete code for all new modules and all tests**. For edits to large existing files (e.g. `prove.rs` 2365 lines, `v5.rs` 1173 lines), it gives the **exact new function bodies** plus **anchored old→new snippets** at named `file:line` sites; read the current code at each anchor before editing (line numbers are from `main @ 7d21c9c` and will drift as you commit — re-grep the named symbol).
- **Every task boundary must be green:** `cargo fmt --all --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace` (targeted sets allowed during a task; full suite before commit).
- **Shared-tree hazard:** never run `cargo fix` or mutating git from a subagent; verify a clean tree + the expected commit stat at each task boundary.
- Branch: `phase1b-real-airs` (already created off `main @ 7d21c9c`).

---

## File Structure

**New files (the crypto core — isolated, fully specified here):**
- `crates/hc-air/src/air_general.rs` — `MaskKind`, `ConstraintMeta`, the generalized `Air` trait with the provided `compose_at`/`max_constraint_degree`, and `mask_multiplier`.
- `crates/hc-air/src/accumulator_air.rs` — `AccumulatorAir` (the v5 accumulator re-expressed on the new trait).
- `crates/hc-air/src/range_air.rs` — `RangeAir` + `build_range_trace`.
- `docs/security/zk_range.md` — the worked ZK argument for the range AIR.

**Modified files:**
- `crates/hc-air/src/lib.rs` — module declarations + re-exports.
- `crates/hc-hash/src/protocol.rs` — v7/v8 domains + new transcript labels.
- `crates/hc-sdk/src/proof.rs`, `crates/hc-sdk/src/types.rs` — additive width-N + public-input-vector proof fields, v7/v8 (de)serialization.
- `crates/hc-prover/src/prove.rs` — `prove_v7`, `build_quotient_lde_k_n`, width-N trace commit/openings, all-column ZK mask, `production_v7` re-export.
- `crates/hc-prover/src/config.rs` — `ProverConfig::production_v7`.
- `crates/hc-prover/src/pipeline/phase1_commit.rs`, `phase3_queries.rs`, `queries.rs` — width-N parallel commit/opening helpers.
- `crates/hc-verifier/src/v5.rs` — `verify_v7`, width-N trace openings, public-input vector, `min_sound_version` handling.
- `crates/hc-workloads/src/templates/mod.rs`, `unified.rs`, `templates/range_proof.rs` — `TemplateBuildResult` enum, `audited` axis, range→AIR build.
- `crates/hc-worker/...`, `crates/hc-mcp/...` — prove path → `(Air, trace, public_inputs)` + production v7/v8 cutover.
- `docs/security/soundness_proof.md` — add the α-union-bound term.

---

## Task 1: Generalized `Air` trait + `compose_at` (isolated crypto core)

**Files:**
- Create: `crates/hc-air/src/air_general.rs`
- Modify: `crates/hc-air/src/lib.rs`
- Test: inline `#[cfg(test)]` in `air_general.rs`

- [ ] **Step 1: Write the failing test**

Add to a new file `crates/hc-air/src/air_general.rs` (tests first, then the impl in Step 3):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::extension::QuadExtension;
    use hc_core::field::prime_field::GoldilocksField as F;

    type K = QuadExtension<GoldilocksField>;

    // A 3-constraint test AIR over a width-2 trace:
    //   c0 (all):        col0 * (col0 - 1)          [booleanity of col0]
    //   c1 (transition): next0 - (col0 + col1)      [accumulate]
    //   c2 (first):      col0 - public[0]           [boundary]
    struct TestAir;
    impl Air for TestAir {
        fn width(&self) -> usize { 2 }
        fn public_input_len(&self) -> usize { 1 }
        fn constraints(&self) -> &'static [ConstraintMeta] {
            &[
                ConstraintMeta { degree: 2, mask: MaskKind::All },
                ConstraintMeta { degree: 1, mask: MaskKind::Transition },
                ConstraintMeta { degree: 1, mask: MaskKind::First },
            ]
        }
        fn eval_constraint(&self, i: usize, cur: &[F], next: &[F], public: &[F]) -> F {
            match i {
                0 => cur[0].mul(cur[0].sub(F::ONE)),
                1 => next[0].sub(cur[0].add(cur[1])),
                2 => cur[0].sub(public[0]),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn compose_at_vanishes_on_valid_first_row() {
        // col0=1 (boolean ok), col1=4, next0=5=1+4 ok, public[0]=1 ok.
        let cur = [F::from_u64(1), F::from_u64(4)];
        let next = [F::from_u64(5), F::from_u64(0)];
        let public = [F::from_u64(1)];
        let alpha = K::from_base(F::from_u64(7)).add(K::from_base(F::from_u64(3)).mul(K::unit_c1()));
        // first row: l0=1, l_last=0, selector_last=1
        let c = TestAir
            .compose_at(&cur, &next, F::ONE, F::ZERO, F::ONE, &public, alpha)
            .unwrap();
        assert_eq!(c, K::ZERO, "all three constraints satisfied → C must be 0");
    }

    #[test]
    fn compose_at_detects_single_violation() {
        // Break ONLY the accumulate constraint (c1): next0 = 99 ≠ 1+4.
        let cur = [F::from_u64(1), F::from_u64(4)];
        let next = [F::from_u64(99), F::from_u64(0)];
        let public = [F::from_u64(1)];
        let alpha = K::from_base(F::from_u64(7)).add(K::from_base(F::from_u64(3)).mul(K::unit_c1()));
        let c = TestAir
            .compose_at(&cur, &next, F::ONE, F::ZERO, F::ONE, &public, alpha)
            .unwrap();
        assert_ne!(c, K::ZERO, "a single violated constraint must make C ≠ 0");
    }

    #[test]
    fn compose_at_width_mismatch_errors() {
        let cur = [F::ZERO; 3]; // wrong width
        let next = [F::ZERO; 2];
        let public = [F::ZERO];
        let alpha = K::ONE;
        assert!(TestAir
            .compose_at(&cur, &next, F::ZERO, F::ZERO, F::ONE, &public, alpha)
            .is_err());
    }

    #[test]
    fn max_constraint_degree_is_max() {
        assert_eq!(TestAir.max_constraint_degree(), 2);
    }
}
```

> Note: confirm the exact `QuadExtension` constructor while implementing — the test uses `K::from_base(..)` and a `c1` unit. If `QuadExtension` exposes fields `c0/c1` (it does — see `crates/hc-core/src/field/extension.rs`), replace `K::unit_c1()` with a direct `QuadExtension { c0: F::ZERO, c1: F::ONE }` constructor or the crate's existing helper. Adjust the test's `alpha` construction to whatever public constructor exists; the assertions are what matter.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-air air_general 2>&1 | tail -20`
Expected: FAIL to compile — `MaskKind`, `ConstraintMeta`, `Air`, `compose_at` not defined.

- [ ] **Step 3: Write the implementation**

Prepend to `crates/hc-air/src/air_general.rs` (above the test module):

```rust
//! Generalized AIR: N columns, N constraints combined via powers of a single
//! composition challenge α ∈ K. This is the sound seam consumed identically by
//! the v7 prover and verifier (replaces the hardcoded ToyAir 2-tuple).

use hc_core::{
    error::{HcError, HcResult},
    field::{extension::QuadExtension, prime_field::GoldilocksField, FieldElement},
};

/// Base field of the v5/v7 path.
pub type F = GoldilocksField;
/// Composition / quotient extension field (~128-bit).
pub type K = QuadExtension<GoldilocksField>;

/// Where on the trace domain a constraint must hold (its quotient mask).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MaskKind {
    /// Row 0 only (multiplied by the Lagrange selector `l0`).
    First,
    /// Row N-1 only (multiplied by `l_last`).
    Last,
    /// Every row except the last (multiplied by `selector_last = 1 - l_last`).
    /// Use for constraints that reference the `next` row.
    Transition,
    /// Every row (multiplier 1). Use for constraints referencing only `current`.
    All,
}

impl MaskKind {
    /// The per-point multiplier for this mask, given the Lagrange selectors.
    #[inline]
    pub fn multiplier(self, l0: F, l_last: F, selector_last: F) -> F {
        match self {
            MaskKind::First => l0,
            MaskKind::Last => l_last,
            MaskKind::Transition => selector_last,
            MaskKind::All => F::ONE,
        }
    }
}

/// Static metadata for one constraint: its total degree and its domain mask.
#[derive(Clone, Copy, Debug)]
pub struct ConstraintMeta {
    /// Total multiplicative degree of the constraint polynomial in the trace cells.
    pub degree: usize,
    /// Which rows the constraint applies to.
    pub mask: MaskKind,
}

/// A sound, general AIR. Implementors provide the column count, public-input
/// arity, an ordered constraint list (metadata), and a per-constraint evaluator.
/// The α-power composition (`compose_at`) is provided and is consensus-critical:
/// the prover and verifier MUST call it identically.
pub trait Air {
    /// Number of trace columns (N).
    fn width(&self) -> usize;

    /// Number of public inputs this AIR consumes.
    fn public_input_len(&self) -> usize;

    /// Ordered constraint metadata. The index into this slice is the α power
    /// assigned to the constraint, so the order is part of the AIR definition
    /// and is consensus by construction.
    fn constraints(&self) -> &'static [ConstraintMeta];

    /// Evaluate constraint `i` at a row (`current`, plus `next` for transition
    /// constraints) and the public inputs. Returns the raw (unmasked) value in F.
    fn eval_constraint(&self, i: usize, current: &[F], next: &[F], public: &[F]) -> F;

    /// Maximum constraint degree (drives `blowup ≥ degree`). Provided.
    fn max_constraint_degree(&self) -> usize {
        self.constraints().iter().map(|c| c.degree).max().unwrap_or(1)
    }

    /// THE consensus-critical composition: `C(x) = Σ_i αⁱ · K(maskᵢ(x) · eᵢ)`.
    /// Provided; do not override. `l0`, `l_last`, `selector_last` are the
    /// Lagrange selectors at the LDE point `x`; `alpha` is the single
    /// composition challenge drawn in K.
    fn compose_at(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        public: &[F],
        alpha: K,
    ) -> HcResult<K> {
        if current.len() != self.width() || next.len() != self.width() {
            return Err(HcError::invalid_argument("compose_at: trace row width mismatch"));
        }
        if public.len() != self.public_input_len() {
            return Err(HcError::invalid_argument("compose_at: public input length mismatch"));
        }
        let mut acc = K::ZERO;
        let mut alpha_pow = K::ONE;
        for (i, meta) in self.constraints().iter().enumerate() {
            let raw = self.eval_constraint(i, current, next, public);
            let masked = meta.mask.multiplier(l0, l_last, selector_last).mul(raw);
            acc = acc.add(alpha_pow.mul(K::from_base(masked)));
            alpha_pow = alpha_pow.mul(alpha);
        }
        Ok(acc)
    }
}
```

- [ ] **Step 4: Wire the module + run tests to verify they pass**

In `crates/hc-air/src/lib.rs`, add after the existing `pub mod` lines:

```rust
pub mod air_general;
pub use air_general::{Air as GeneralAir, ConstraintMeta, MaskKind};
```

(Use `GeneralAir` as the re-export name to avoid colliding with the legacy `air::Air`.)

Run: `cargo test -p hc-air air_general 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 5: Gate + commit**

Run: `cargo fmt --all --check && cargo clippy -p hc-air --all-targets -- -D warnings && cargo test -p hc-air 2>&1 | tail -5`
Expected: clean; all hc-air tests pass.

```bash
git add crates/hc-air/src/air_general.rs crates/hc-air/src/lib.rs
git commit -m "feat(air): generalized Air trait + single-α compose_at in K (Phase 1B T1)"
```

---

## Task 2: `AccumulatorAir` on the new trait + differential vs ToyAir

**Files:**
- Create: `crates/hc-air/src/accumulator_air.rs`
- Modify: `crates/hc-air/src/lib.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write the failing test**

Create `crates/hc-air/src/accumulator_air.rs`:

```rust
//! The v5 accumulator statement re-expressed on the generalized `Air` trait.
//! Used to prove the general seam reduces to the deployed accumulator's
//! behavior (differential), and as the trace backend for `accumulator_step`.

use crate::air_general::{Air, ConstraintMeta, MaskKind, F, K};
use hc_core::field::FieldElement;

/// Columns: [acc, delta]. Public inputs: [initial_acc, final_acc].
/// Constraints (canonical order):
///   0 first:      acc - initial_acc
///   1 last:       acc - final_acc
///   2 transition: acc_next - (acc + delta)
pub struct AccumulatorAir;

const ACC_CONSTRAINTS: &[ConstraintMeta] = &[
    ConstraintMeta { degree: 1, mask: MaskKind::First },
    ConstraintMeta { degree: 1, mask: MaskKind::Last },
    ConstraintMeta { degree: 1, mask: MaskKind::Transition },
];

impl Air for AccumulatorAir {
    fn width(&self) -> usize { 2 }
    fn public_input_len(&self) -> usize { 2 }
    fn constraints(&self) -> &'static [ConstraintMeta] { ACC_CONSTRAINTS }
    fn eval_constraint(&self, i: usize, cur: &[F], next: &[F], public: &[F]) -> F {
        match i {
            0 => cur[0].sub(public[0]),                 // acc - initial_acc
            1 => cur[0].sub(public[1]),                 // acc - final_acc
            2 => next[0].sub(cur[0].add(cur[1])),       // acc' - (acc + delta)
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alpha() -> K {
        // any α with c1 ≠ 0 (genuine K element)
        K::from_base(F::from_u64(9)).add(K::from_base(F::from_u64(2)).mul(K::from_base(F::ONE).mul_by_nonresidue_unit()))
    }

    #[test]
    fn vanishes_on_valid_interior_row() {
        // interior: l0=0, l_last=0, selector_last=1; acc=5, delta=1, acc'=6
        let c = AccumulatorAir
            .compose_at(&[F::from_u64(5), F::from_u64(1)], &[F::from_u64(6), F::from_u64(2)],
                        F::ZERO, F::ZERO, F::ONE, &[F::from_u64(5), F::from_u64(8)], alpha())
            .unwrap();
        assert_eq!(c, K::ZERO);
    }

    #[test]
    fn vanishes_on_valid_first_row() {
        // first: l0=1; acc=initial_acc=5
        let c = AccumulatorAir
            .compose_at(&[F::from_u64(5), F::from_u64(1)], &[F::from_u64(6), F::from_u64(2)],
                        F::ONE, F::ZERO, F::ONE, &[F::from_u64(5), F::from_u64(8)], alpha())
            .unwrap();
        assert_eq!(c, K::ZERO);
    }

    #[test]
    fn detects_transition_violation() {
        // acc'=99 ≠ 5+1
        let c = AccumulatorAir
            .compose_at(&[F::from_u64(5), F::from_u64(1)], &[F::from_u64(99), F::ZERO],
                        F::ZERO, F::ZERO, F::ONE, &[F::from_u64(5), F::from_u64(8)], alpha())
            .unwrap();
        assert_ne!(c, K::ZERO);
    }

    #[test]
    fn detects_boundary_violation() {
        // first row but acc=7 ≠ initial_acc=5
        let c = AccumulatorAir
            .compose_at(&[F::from_u64(7), F::from_u64(1)], &[F::from_u64(8), F::ZERO],
                        F::ONE, F::ZERO, F::ONE, &[F::from_u64(5), F::from_u64(8)], alpha())
            .unwrap();
        assert_ne!(c, K::ZERO);
    }
}
```

> While implementing, replace `mul_by_nonresidue_unit()` / the `alpha()` helper with whatever public constructor `QuadExtension` offers to build an element with `c1 ≠ 0` (check `crates/hc-core/src/field/extension.rs`; e.g. a `QuadExtension::new(c0, c1)` if present). The requirement is only that α is a genuine K element.

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-air accumulator_air 2>&1 | tail -20`
Expected: FAIL to compile (module not declared).

- [ ] **Step 3: Wire the module**

In `crates/hc-air/src/lib.rs`:

```rust
pub mod accumulator_air;
pub use accumulator_air::AccumulatorAir;
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-air accumulator_air 2>&1 | tail -20`
Expected: PASS (4 tests).

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all --check && cargo clippy -p hc-air --all-targets -- -D warnings
git add crates/hc-air/src/accumulator_air.rs crates/hc-air/src/lib.rs
git commit -m "feat(air): AccumulatorAir on the general trait (Phase 1B T2)"
```

---

## Task 3: `RangeAir` + `build_range_trace` (the predicate AIR, isolated)

**Files:**
- Create: `crates/hc-air/src/range_air.rs`
- Modify: `crates/hc-air/src/lib.rs`
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write the failing test**

Create `crates/hc-air/src/range_air.rs` with the implementation AND tests together (implementation shown in Step 3; write the test module first mentally, but it's fine to author the whole file once):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::FieldElement;

    #[test]
    fn build_trace_shape_default_n() {
        let t = build_range_trace(18, 120, 42).unwrap();
        assert_eq!(t.width(), 4);
        assert_eq!(t.num_rows(), DEFAULT_N); // power of two, no padding
    }

    #[test]
    fn builder_rejects_out_of_range_value() {
        assert!(build_range_trace(18, 120, 200).is_err()); // V > max
        assert!(build_range_trace(18, 120, 5).is_err());   // V < min
    }

    #[test]
    fn builder_rejects_range_wider_than_2_pow_n() {
        // max - min must be < 2^DEFAULT_N
        assert!(build_range_trace(0, (1u64 << DEFAULT_N), 1).is_err());
    }

    // Evaluate compose_at across every row of a built trace and assert it
    // vanishes for a valid witness. Uses synthetic Lagrange selectors per row
    // (real domain math is exercised end-to-end in T7).
    fn assert_air_vanishes(trace: &MultiColumnTrace<F>, public: &[F]) {
        let air = RangeAir::new(DEFAULT_N);
        let n = trace.num_rows();
        let alpha = K::from_base(F::from_u64(7));
        for i in 0..n {
            let cur = trace.row(i);
            let next = trace.row(if i + 1 < n { i + 1 } else { i });
            let l0 = if i == 0 { F::ONE } else { F::ZERO };
            let l_last = if i + 1 == n { F::ONE } else { F::ZERO };
            let selector_last = F::ONE.sub(l_last);
            let c = air.compose_at(&cur, &next, l0, l_last, selector_last, public, alpha).unwrap();
            assert_eq!(c, K::ZERO, "range AIR must vanish at row {i}");
        }
    }

    #[test]
    fn valid_witness_satisfies_air() {
        let trace = build_range_trace(18, 120, 42).unwrap();
        assert_air_vanishes(&trace, &[F::from_u64(18), F::from_u64(120)]);
    }

    #[test]
    fn tampered_non_boolean_bit_is_caught() {
        let mut trace = build_range_trace(18, 120, 42).unwrap();
        // Corrupt a_bit at row 0 to a non-boolean value via a rebuilt column set.
        let mut cols: Vec<Vec<F>> = trace.columns().to_vec();
        cols[0][0] = F::from_u64(2);
        trace = MultiColumnTrace::from_columns(cols).unwrap();
        // booleanity (constraint 0, mask All) must fire at row 0.
        let air = RangeAir::new(DEFAULT_N);
        let cur = trace.row(0);
        let next = trace.row(1);
        let c = air.compose_at(&cur, &next, F::ONE, F::ZERO, F::ONE,
                               &[F::from_u64(18), F::from_u64(120)], K::from_base(F::from_u64(7))).unwrap();
        assert_ne!(c, K::ZERO);
    }

    #[test]
    fn tampered_tie_is_caught() {
        // Force a+c ≠ max-min by lying about public max at the last row.
        let trace = build_range_trace(18, 120, 42).unwrap();
        let air = RangeAir::new(DEFAULT_N);
        let n = trace.num_rows();
        let cur = trace.row(n - 1);
        let next = trace.row(n - 1);
        // last row: l_last=1, selector_last=0; lie: max=999
        let c = air.compose_at(&cur, &next, F::ZERO, F::ONE, F::ZERO,
                               &[F::from_u64(18), F::from_u64(999)], K::from_base(F::from_u64(7))).unwrap();
        assert_ne!(c, K::ZERO);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-air range_air 2>&1 | tail -20`
Expected: FAIL to compile.

- [ ] **Step 3: Write the implementation**

Prepend to `crates/hc-air/src/range_air.rs`:

```rust
//! `range_proof` AIR: prove min ≤ V ≤ max without revealing V.
//!
//! Columns [a_bit, a_acc, c_bit, c_acc] over n rows (n = power of two).
//! a = V - min and c = max - V are each decomposed into n bits (MSB-first) and
//! recomposed via Horner; the last row ties a + c = max - min. Booleanity +
//! Horner force a,c ∈ [0,2ⁿ); the tie forces a + c = max - min; with
//! 2^(n+1) < p this gives 0 ≤ a ≤ max-min, i.e. min ≤ V = min+a ≤ max.
//! V is never a column or public input → hidden.

use crate::air_general::{Air, ConstraintMeta, MaskKind, F, K};
use crate::multi_column::MultiColumnTrace;
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

/// Default bit-width: covers ranges up to 2^32 (age, score, thresholds).
/// Power of two so the trace needs no padding. Field-safe: 2^(32+1) < p.
pub const DEFAULT_N: usize = 32;

pub struct RangeAir {
    n: usize,
}

impl RangeAir {
    pub fn new(n: usize) -> Self {
        assert!(n.is_power_of_two(), "n must be a power of two");
        assert!(n + 1 < 64, "field safety: 2^(n+1) < p requires n ≤ 62");
        Self { n }
    }
}

// Columns: 0=a_bit, 1=a_acc, 2=c_bit, 3=c_acc. Public: [min, max].
// Canonical constraint order (index = α power):
const RANGE_CONSTRAINTS: &[ConstraintMeta] = &[
    ConstraintMeta { degree: 2, mask: MaskKind::All },        // 0 a_bit boolean
    ConstraintMeta { degree: 2, mask: MaskKind::All },        // 1 c_bit boolean
    ConstraintMeta { degree: 1, mask: MaskKind::First },      // 2 a_acc seeds at a_bit
    ConstraintMeta { degree: 1, mask: MaskKind::First },      // 3 c_acc seeds at c_bit
    ConstraintMeta { degree: 1, mask: MaskKind::Transition }, // 4 a Horner
    ConstraintMeta { degree: 1, mask: MaskKind::Transition }, // 5 c Horner
    ConstraintMeta { degree: 1, mask: MaskKind::Last },       // 6 tie a_acc+c_acc = max-min
];

impl Air for RangeAir {
    fn width(&self) -> usize { 4 }
    fn public_input_len(&self) -> usize { 2 }
    fn constraints(&self) -> &'static [ConstraintMeta] { RANGE_CONSTRAINTS }
    fn eval_constraint(&self, i: usize, cur: &[F], next: &[F], public: &[F]) -> F {
        let two = F::from_u64(2);
        match i {
            0 => cur[0].mul(cur[0].sub(F::ONE)),                       // a_bit·(a_bit-1)
            1 => cur[2].mul(cur[2].sub(F::ONE)),                       // c_bit·(c_bit-1)
            2 => cur[1].sub(cur[0]),                                   // a_acc - a_bit (row 0)
            3 => cur[3].sub(cur[2]),                                   // c_acc - c_bit (row 0)
            4 => next[1].sub(two.mul(cur[1]).add(next[0])),           // a_acc' - (2·a_acc + a_bit')
            5 => next[3].sub(two.mul(cur[3]).add(next[2])),           // c_acc' - (2·c_acc + c_bit')
            6 => cur[1].add(cur[3]).sub(public[1].sub(public[0])),    // (a_acc+c_acc) - (max-min)
            _ => unreachable!(),
        }
    }
}

/// Build the width-4 range trace for a (min, max, value) witness. `value` (V)
/// is the private input and never appears in the trace or public inputs.
pub fn build_range_trace(min: u64, max: u64, value: u64) -> HcResult<MultiColumnTrace<F>> {
    build_range_trace_n(min, max, value, DEFAULT_N)
}

pub fn build_range_trace_n(min: u64, max: u64, value: u64, n: usize) -> HcResult<MultiColumnTrace<F>> {
    if min > max {
        return Err(HcError::invalid_argument("range: min must be ≤ max"));
    }
    if value < min || value > max {
        return Err(HcError::invalid_argument("range: value out of [min,max]"));
    }
    let width = max - min;
    if n >= 63 || width >= (1u64 << n) {
        return Err(HcError::invalid_argument("range: max-min must be < 2^n with 2^(n+1) < p"));
    }
    let a = value - min; // ≥ 0
    let c = max - value; // ≥ 0

    // MSB-first bits + Horner accumulators.
    let mut a_bit = Vec::with_capacity(n);
    let mut a_acc = Vec::with_capacity(n);
    let mut c_bit = Vec::with_capacity(n);
    let mut c_acc = Vec::with_capacity(n);
    let (mut acc_a, mut acc_c) = (0u64, 0u64);
    for i in 0..n {
        let shift = n - 1 - i;
        let ab = (a >> shift) & 1;
        let cb = (c >> shift) & 1;
        acc_a = (acc_a << 1) | ab;
        acc_c = (acc_c << 1) | cb;
        a_bit.push(F::from_u64(ab));
        a_acc.push(F::from_u64(acc_a));
        c_bit.push(F::from_u64(cb));
        c_acc.push(F::from_u64(acc_c));
    }
    MultiColumnTrace::from_columns(vec![a_bit, a_acc, c_bit, c_acc])
}
```

> The Horner constraint (index 4/5) uses `next` columns, so it is `Transition`-masked (disabled at the last row, which holds the final accumulator). Constraint 2/3 seeds `acc[0] = bit[0]` at the first row. Verify `MultiColumnTrace::row(i)` returns a `Vec<F>` of length `width` (it does — `multi_column.rs:149`).

- [ ] **Step 4: Wire the module + run tests**

In `crates/hc-air/src/lib.rs`:

```rust
pub mod range_air;
pub use range_air::{build_range_trace, build_range_trace_n, RangeAir, DEFAULT_N as RANGE_DEFAULT_N};
```

Run: `cargo test -p hc-air range_air 2>&1 | tail -20`
Expected: PASS (all range tests).

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all --check && cargo clippy -p hc-air --all-targets -- -D warnings && cargo test -p hc-air 2>&1 | tail -5
git add crates/hc-air/src/range_air.rs crates/hc-air/src/lib.rs
git commit -m "feat(air): RangeAir bit-decomposition + trace builder (Phase 1B T3)"
```

---

## Task 4: Protocol v7/v8 domains + transcript labels + proof fields (additive)

**Files:**
- Modify: `crates/hc-hash/src/protocol.rs`
- Modify: `crates/hc-sdk/src/proof.rs`, `crates/hc-sdk/src/types.rs`
- Test: inline `#[cfg(test)]` in `protocol.rs` + a serde round-trip test in `hc-sdk`

- [ ] **Step 1: Write the failing test**

In `crates/hc-hash/src/protocol.rs` test module:

```rust
#[test]
fn v7_v8_domains_and_labels_present_and_distinct() {
    assert_eq!(DOMAIN_MAIN_V7, b"hc-stark/v7");
    assert_eq!(DOMAIN_FRI_V7, b"hc-stark/fri/v7");
    assert_eq!(DOMAIN_MAIN_V8, b"hc-stark/v8");
    assert_eq!(DOMAIN_FRI_V8, b"hc-stark/fri/v8");
    // single composition challenge label (replaces the two v5 labels)
    assert_eq!(label::COMPOSITION_ALPHA, b"composition/alpha");
    assert_ne!(DOMAIN_MAIN_V7, DOMAIN_MAIN_V5);
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p hc-hash v7_v8_domains 2>&1 | tail -10`
Expected: FAIL — constants undefined.

- [ ] **Step 3: Add the constants**

In `crates/hc-hash/src/protocol.rs`, after the v6 domain block (anchor: `DOMAIN_MAIN_V6` at `:40-41`):

```rust
/// v7: general-AIR sound proof (single-α composition, width-N trace, public-input vector).
pub const DOMAIN_MAIN_V7: &[u8] = b"hc-stark/v7";
pub const DOMAIN_FRI_V7: &[u8] = b"hc-stark/fri/v7";
/// v8: v7 + ZK masking.
pub const DOMAIN_MAIN_V8: &[u8] = b"hc-stark/v8";
pub const DOMAIN_FRI_V8: &[u8] = b"hc-stark/fri/v8";
```

In the `label` module (anchor: `COMPOSITION_ALPHA_BOUNDARY` at `:85-86`), add:

```rust
/// Single composition challenge for the general v7 seam (Σ αⁱ·cᵢ).
pub const COMPOSITION_ALPHA: &[u8] = b"composition/alpha";
/// Trace width N (bound so the verifier knows leaf arity).
pub const PARAM_TRACE_WIDTH: &[u8] = b"param/trace_width";
/// Public-input vector binding.
pub const PUB_INPUT_COUNT: &[u8] = b"pub/input_count";
pub const PUB_INPUT_ELEM: &[u8] = b"pub/input_elem";
```

- [ ] **Step 4: Add additive proof fields (hc-sdk)**

In the in-memory proof params struct (find it: `grep -n "lde_blowup_factor" crates/hc-sdk/src/proof.rs` — the `ProofParams`-like struct), add (default-friendly):

```rust
/// Trace width N (v7+). 0 = legacy width-2 (v5/v6).
#[serde(default)]
pub trace_width: u32,
```

In the proof struct that carries `initial_acc`/`final_acc` (the SDK `StarkProofOutput`/serialized proof at `proof.rs:62-63` and `:875-876`), add an additive vector that supersedes them for v7+ (keep the scalars for v5 back-compat serialization):

```rust
/// Public inputs (v7+). For v5/v6 this is empty and initial_acc/final_acc are used.
#[serde(default)]
pub public_inputs: Vec<u64>,
```

Write a serde round-trip test in `crates/hc-sdk/src/proof.rs` tests:

```rust
#[test]
fn v7_fields_default_and_roundtrip() {
    // Construct a minimal serialized proof value with trace_width=4 and a
    // 2-element public_inputs vector; serialize → deserialize → assert equal.
    // (Use the smallest existing constructor/helper in this module.)
}
```

> Fill the round-trip test body using whichever constructor the module already exposes for a proof value (mirror an existing serde test in `proof.rs`). The assertion: `trace_width` and `public_inputs` survive a `serde_json` round trip and default to `0`/`[]` when absent from older JSON.

- [ ] **Step 5: Run tests + gate + commit**

Run: `cargo test -p hc-hash protocol 2>&1 | tail -10 && cargo test -p hc-sdk v7_fields 2>&1 | tail -10`
Expected: PASS.

```bash
cargo fmt --all --check && cargo clippy -p hc-hash -p hc-sdk --all-targets -- -D warnings
git add crates/hc-hash/src/protocol.rs crates/hc-sdk/src/proof.rs crates/hc-sdk/src/types.rs
git commit -m "feat(protocol/sdk): v7/v8 domains, COMPOSITION_ALPHA, width-N + public-input proof fields (Phase 1B T4)"
```

---

## Task 5: Width-N trace leaf hash + width-N commit (additive parallel path)

**Files:**
- Modify: `crates/hc-prover/src/pipeline/phase1_commit.rs` (add `hash_trace_row_n` + `commit_trace_lde_n`)
- Modify: `crates/hc-verifier/src/v5.rs` (add matching `hash_trace_row_n`)
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write the failing test** (prover side)

In `crates/hc-prover/src/pipeline/phase1_commit.rs` tests:

```rust
#[test]
fn width_n_leaf_hash_is_order_sensitive_and_width_agnostic() {
    use hc_core::field::prime_field::GoldilocksField as F;
    use hc_core::field::FieldElement;
    let a = hash_trace_row_n(&[F::from_u64(1), F::from_u64(2), F::from_u64(3)]);
    let b = hash_trace_row_n(&[F::from_u64(1), F::from_u64(2), F::from_u64(3)]);
    let c = hash_trace_row_n(&[F::from_u64(3), F::from_u64(2), F::from_u64(1)]);
    assert_eq!(a, b, "same row → same leaf");
    assert_ne!(a, c, "column order must matter");
    // width-2 row through the N hash must equal the legacy pair hash:
    let pair = hash_trace_pair(&F::from_u64(7), &F::from_u64(9));
    let viaN = hash_trace_row_n(&[F::from_u64(7), F::from_u64(9)]);
    assert_eq!(pair, viaN, "N-hash on a 2-row must match legacy pair hash (back-compat)");
}
```

> The back-compat assertion pins the N-hash to absorb each field element exactly as `hash_trace_pair` does for 2 elements. Read `hash_trace_pair` (`phase1_commit.rs:210`) and make `hash_trace_row_n` absorb the same per-element bytes in order so a width-2 row is byte-identical. (This keeps the door open to reusing v5 vectors; if `hash_trace_pair` does something 2-specific, drop the back-compat assertion and just require order-sensitivity.)

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hc-prover width_n_leaf_hash 2>&1 | tail -10`
Expected: FAIL — `hash_trace_row_n` undefined.

- [ ] **Step 3: Implement `hash_trace_row_n` + `commit_trace_lde_n`**

In `phase1_commit.rs`, mirroring `hash_trace_pair` (`:210`) and the streaming commit (`:51`):

```rust
/// Width-N trace leaf: absorb each column value (LE) in canonical order.
pub fn hash_trace_row_n<F: FieldElement>(row: &[F]) -> HashDigest {
    use hc_hash::Blake3; // match the existing import style in this file
    let mut h = Blake3::new();
    for v in row {
        h.update(&v.to_u64().to_le_bytes());
    }
    h.finalize()
}

/// Commit a width-N trace LDE (column-major) via the streaming Merkle tree.
/// `columns[col][row]`, all columns equal length = lde_len.
pub fn commit_trace_lde_n<F: FieldElement>(columns: &[Vec<F>]) -> HcResult<HashDigest> {
    use hc_commit::merkle::height_dfs::StreamingMerkle;
    let lde_len = columns.first().map(|c| c.len()).unwrap_or(0);
    let width = columns.len();
    let mut builder = StreamingMerkle::<Blake3>::new();
    let mut row = vec![F::ZERO; width];
    for i in 0..lde_len {
        for (j, col) in columns.iter().enumerate() {
            row[j] = col[i];
        }
        builder.push(hash_trace_row_n(&row));
    }
    builder.finalize().map_err(|e| HcError::message(format!("merkle finalize: {e}")))
}
```

> Match the exact `Blake3` hasher API and `HashDigest` import already used by `hash_trace_pair`/`commit_trace_lde` in this file (re-grep; the snippet assumes `Blake3::new()/update/finalize` — adjust to the real API, e.g. it may be `hc_hash::hash_value`-style). Add the identical `hash_trace_row_n` to `crates/hc-verifier/src/v5.rs` (next to the existing width-2 `hash_trace_row` at `:732`).

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-prover width_n_leaf_hash 2>&1 | tail -10`
Expected: PASS.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all --check && cargo clippy -p hc-prover -p hc-verifier --all-targets -- -D warnings
git add crates/hc-prover/src/pipeline/phase1_commit.rs crates/hc-verifier/src/v5.rs
git commit -m "feat(prover/verifier): width-N trace leaf hash + commit (Phase 1B T5)"
```

---

## Task 6: v7 prover — `build_quotient_lde_k_n` over `compose_at` + `prove_v7`

**Files:**
- Modify: `crates/hc-prover/src/prove.rs` (new `build_quotient_lde_k_n`, `prove_v7`)
- Modify: `crates/hc-prover/src/config.rs` (`production_v7`)
- Modify: `crates/hc-prover/src/lib.rs` (export `prove_v7`)
- Test: inline `#[cfg(test)]` (prove-only; verify in T7)

- [ ] **Step 1: Write the failing test**

In `prove.rs` tests:

```rust
#[test]
fn prove_v7_accumulator_and_range_produce_proofs() {
    use hc_air::{AccumulatorAir, RangeAir, build_range_trace};
    // accumulator: width-2 trace via existing VM/synthetic builder
    let acc_air = AccumulatorAir;
    let acc_trace = /* build a small valid [acc,delta] MultiColumnTrace */ small_accumulator_trace();
    let p1 = prove_v7(&acc_air, &acc_trace, &[F::from_u64(5), F::from_u64(15)],
                      &ProverConfig::production_v7(false)).unwrap();
    assert!(p1.params.trace_width == 2 && p1.version >= 7);

    // range: width-4
    let range_air = RangeAir::new(hc_air::RANGE_DEFAULT_N);
    let r_trace = build_range_trace(18, 120, 42).unwrap();
    let p2 = prove_v7(&range_air, &r_trace, &[F::from_u64(18), F::from_u64(120)],
                      &ProverConfig::production_v7(true)).unwrap();
    assert!(p2.params.trace_width == 4 && p2.version >= 7);
}
```

> Provide `small_accumulator_trace()` as a test helper building a valid `[acc,delta]` `MultiColumnTrace` (e.g. acc 5→…→15). `production_v7(zk: bool)` returns blowup 8 / q40 / grind20, version 7 (or 8 if `zk`).

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hc-prover prove_v7_accumulator_and_range 2>&1 | tail -20`
Expected: FAIL — `prove_v7` / `production_v7` undefined.

- [ ] **Step 3: Add `production_v7` (config.rs)**

Anchor: `production_v5` at `config.rs:309`. Add a sibling that sets the same floor and `protocol_version = if zk {8} else {7}`:

```rust
/// Production v7/v8 config: general-AIR sound proving. Same floor as v5
/// (blowup 8, 40 queries, 20 grinding bits); version 7, or 8 with ZK.
pub fn production_v7(zk: bool) -> Self {
    let mut cfg = Self::production_v5(/* same args production_v5 takes */)
        .with_protocol_version(if zk { 8 } else { 7 });
    if zk {
        cfg = cfg.with_zk_masking(/* mask_degree ≥ query_count; see T8/spec §6.4 */ 64);
    }
    cfg
}
```

> Read `production_v5`'s exact signature/args and mirror them. The `mask_degree` constant is finalized in T8 against the ZK argument (`mask_degree ≥ query_count`, possibly `+small` for the quotient opening). Until T8, `64 ≥ 40` is a safe placeholder validated by T8.

- [ ] **Step 4: Add `build_quotient_lde_k_n` (prove.rs)**

This is the width-N, single-α analog of `build_quotient_lde_k` (`prove.rs:1668`). Same Lagrange/`Z_H` math; the only changes are (a) read N columns, (b) call `air.compose_at(...)` with one α, (c) pass public inputs:

> **Type note (from self-review):** take the AIR as `&dyn GeneralAir`, NOT a generic `<A: GeneralAir>`. The trait is object-safe (no generic methods, no `Self`-by-value, `compose_at` is a provided method using concrete `F`/`K`), and `&dyn` is the only form that accepts BOTH a concrete `&RangeAir` (auto-coerced at the T6/T7 test call sites) AND the `Box<dyn GeneralAir>` from `TemplateBuildResult::Air` (`&*air`) in T9. So: `pub fn prove_v7(air: &dyn GeneralAir, trace: &MultiColumnTrace<F>, public_inputs: &[F], config: &ProverConfig) -> HcResult<ProofV5<F>>`.

```rust
fn build_quotient_lde_k_n(
    air: &dyn hc_air::GeneralAir,
    trace_lde_cols: &[Vec<GoldilocksField>], // column-major, each len = lde_len
    public_inputs: &[GoldilocksField],
    padded_len: usize,
    blowup: usize,
    alpha: QuadExtensionK,
) -> HcResult<Vec<QuadExtensionK>> {
    type F = GoldilocksField;
    let lde_len = padded_len * blowup;
    let coset_offset = F::from_u64(LDE_COSET_OFFSET);
    let trace_domain = generate_trace_domain::<F>(padded_len)?;
    let lde_domain = generate_lde_coset_domain::<F>(padded_len, blowup, coset_offset)?;
    let omega_last = trace_domain.generator().inverse()
        .ok_or_else(|| HcError::math("no generator inverse"))?;
    let n_inv = F::from_u64(padded_len as u64).inverse()
        .ok_or_else(|| HcError::math("padded_len has no inverse"))?;
    let shift = blowup % lde_len;
    let width = air.width();
    let mut cur = vec![F::ZERO; width];
    let mut nxt = vec![F::ZERO; width];
    let mut quotient = Vec::with_capacity(lde_len);
    for i in 0..lde_len {
        let x = lde_domain.element(i);
        let z_h = x.pow(padded_len as u64).sub(F::ONE);
        let z_h_inv = z_h.inverse().ok_or_else(|| HcError::math("zero Z_H on coset"))?;
        let l0 = z_h.mul(n_inv).mul(x.sub(F::ONE).inverse()
            .ok_or_else(|| HcError::math("zero L0 denom"))?);
        let l_last = z_h.mul(omega_last).mul(n_inv).mul(x.sub(omega_last).inverse()
            .ok_or_else(|| HcError::math("zero L_last denom"))?);
        let selector_last = F::ONE.sub(l_last);
        let ni = (i + shift) % lde_len;
        for (j, col) in trace_lde_cols.iter().enumerate() {
            cur[j] = col[i];
            nxt[j] = col[ni];
        }
        let c = air.compose_at(&cur, &nxt, l0, l_last, selector_last, public_inputs, alpha)?;
        quotient.push(c.mul(QuadExtensionK::from_base(z_h_inv)));
    }
    Ok(quotient)
}
```

- [ ] **Step 5: Add `prove_v7` (prove.rs)**

Assemble by reusing v5 machinery for everything except trace handling + the quotient numerator. The orchestration mirrors `prove_v5`/`prove_stark_v5` (read it: `lib.rs:19` export → the function body), substituting:
1. **Trace:** take a `&MultiColumnTrace<F>` + `&A: GeneralAir` + `public_inputs: &[F]` instead of building `[F;2]` rows. LDE each column (reuse the existing per-column LDE used for acc/delta), apply the all-column ZK mask (T8 — for T6, mask only if `config.zk.enabled`, looping columns), commit via `commit_trace_lde_n`.
2. **Composition α:** draw ONE `alpha = transcript.challenge_field::<K>(label::COMPOSITION_ALPHA)` (replacing the two-α draw at the v5 site `prove.rs:427-430`). Bind `PARAM_TRACE_WIDTH` and the public-input vector (`PUB_INPUT_COUNT` + each `PUB_INPUT_ELEM`) into the transcript at the public-input stage (mirror v5's `PUB_INITIAL_ACC`/`PUB_FINAL_ACC` appends).
3. **Quotient:** `build_quotient_lde_k_n(air, &masked_cols, public_inputs, padded_len, blowup, alpha)`; commit it (reuse the existing quotient commit — it is K-valued and width-agnostic).
4. **FRI / grinding / queries / final coeffs:** **reuse `run_fri_v5` and the grinding + `generate_queries` paths unchanged** — the quotient is one K column.
5. **Trace openings:** open N values per queried row (+ neighbor) — generalize the opening helper to emit `Vec<F>` (T6 adds `open_trace_row_n`; quotient openings unchanged).
6. Set `proof.version = if zk {8} else {7}`, `proof.params.trace_width = width`, `proof.public_inputs = public_inputs (as u64)`.

Use the `DOMAIN_MAIN_V7`/`DOMAIN_FRI_V7` (or v8) transcript domains.

> This is the largest single task. Keep it additive: `prove_v7` is a new function; do not touch `prove_v5`. Land it behind the new types and lean on T7 for the verifying half. If the trace-LDE/opening helpers are tightly coupled to `[F;2]` in `phase3_queries.rs`, add width-N siblings (`open_trace_row_n`) rather than editing the v5 ones.

- [ ] **Step 6: Export + run prove-only test**

`crates/hc-prover/src/lib.rs`: add `prove_v7` to the `pub use prove::{...}` line.

Run: `cargo test -p hc-prover prove_v7_accumulator_and_range 2>&1 | tail -20`
Expected: PASS (proofs build; not yet verified).

- [ ] **Step 7: Gate + commit**

```bash
cargo fmt --all --check && cargo clippy -p hc-prover --all-targets -- -D warnings
git add crates/hc-prover/src/prove.rs crates/hc-prover/src/config.rs crates/hc-prover/src/lib.rs crates/hc-prover/src/pipeline/phase3_queries.rs
git commit -m "feat(prover): v7 prove path — compose_at quotient + width-N trace/openings (Phase 1B T6)"
```

---

## Task 7: v7 verifier — `verify_v7` (capstone: forge-PoC GREEN, range forges REJECT)

**Files:**
- Modify: `crates/hc-verifier/src/v5.rs` (`verify_v7`, width-N trace openings, public-input vector, `min_sound_version` bump)
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write the failing tests** (the heart of Phase 1B)

In `v5.rs` tests (mirror the existing v5 test harness at `:742+`):

```rust
#[test]
fn v7_accumulator_roundtrip_verifies() {
    let air = hc_air::AccumulatorAir;
    let trace = small_accumulator_trace();
    let proof = hc_prover::prove_v7(&air, &trace, &[F::new(5), F::new(15)],
                                    &ProverConfig::production_v7(false)).unwrap();
    verify_v7(&proof).expect("honest accumulator v7 must verify");
}

#[test]
fn v7_range_roundtrip_verifies() {
    let air = hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N);
    let trace = hc_air::build_range_trace(18, 120, 42).unwrap();
    let proof = hc_prover::prove_v7(&air, &trace, &[F::new(18), F::new(120)],
                                    &ProverConfig::production_v7(true)).unwrap();
    verify_v7(&proof).expect("honest range proof must verify");
}

#[test]
fn v7_range_out_of_range_witness_cannot_prove_or_verify() {
    // Builder refuses V outside [min,max]:
    assert!(hc_air::build_range_trace(18, 120, 200).is_err());
    // And a hand-tampered trace (force a non-boolean a_bit) must FAIL verify:
    let air = hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N);
    let trace = hc_air::build_range_trace(18, 120, 42).unwrap();
    let mut proof = hc_prover::prove_v7(&air, &trace, &[F::new(18), F::new(120)],
                                        &ProverConfig::production_v7(true)).unwrap();
    tamper_first_trace_opening(&mut proof); // flip an opened a_bit to 2
    assert!(verify_v7(&proof).is_err(), "tampered range proof must be rejected");
}

#[test]
fn v7_forge_poc_high_degree_codeword_rejected() {
    // Reuse the Phase 1A forge-PoC harness, but on the v7 verifier: a
    // high-degree composition must fail the FRI final-degree check.
    // (Adapt the existing forge-PoC test to call verify_v7.)
}

#[test]
fn production_floor_rejects_pre_v7() {
    let proof_v5 = make_v5_proof_relaxed(); // existing helper
    assert!(verify_v7(&proof_v5).is_err(), "version < 7 rejected under v7 floor");
}
```

> Provide `tamper_first_trace_opening` (sets the first opened trace value of the first query to `F::from_u64(2)`) and reuse existing v5 test helpers for the forge-PoC and the relaxed-v5 proof. `verify_v7` enforces `min_sound_version = 7`.

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hc-verifier v7_ 2>&1 | tail -20`
Expected: FAIL — `verify_v7` undefined.

- [ ] **Step 3: Implement `verify_v7`**

Mirror `verify_v5` / `verify_stark_v5_inner` (`v5.rs:128+`, the inner at the `verify_v5_trace_and_quotient` seam `:289/:532`). Changes:
1. **Floor:** `verify_v7` calls `enforce_floor(proof, floor_v7())` where `floor_v7()` = `VerifierSecurityFloor { min_sound_version: 7, ..Default::default() }`.
2. **AIR resolution:** pick the AIR from the proof's declared shape. For Phase 1B the verifier knows two AIRs: width-2 + 2 public inputs → `AccumulatorAir`; width-4 + 2 public inputs (range tag) → `RangeAir`. **Bind the AIR identity into the transcript** (e.g. an `AIR_ID` label) so the prover and verifier agree on which constraint set is in force; the verifier selects the AIR by the bound id, not by guessing from width. Add `AIR_ID` to `protocol.rs` and to `prove_v7` (T6) — note this and add it now if missed in T6.
3. **Transcript:** draw the single `alpha` via `COMPOSITION_ALPHA`; bind `PARAM_TRACE_WIDTH`, the public-input vector, and `AIR_ID` exactly as the prover did.
4. **Composition check:** in the trace+quotient opening check (the `compose_value` at `v5.rs:532-544`), replace the `ToyAir.constraint_values → (b,t) → α_b·b+α_t·t` with `air.compose_at(&row_n, &next_n, l0, l_last, selector_last, &public_inputs, alpha)` and assert it equals `opened_quotient · Z_H` at the point.
5. **Trace openings:** verify N-value leaves via `hash_trace_row_n` (T5); read `proof.public_inputs` for the AIR.
6. **FRI:** reuse `verify_fri_low_degree_v5` unchanged.

Also: bump the production `Default` floor `min_sound_version` only in T10's cutover (not here — keep v5 tests green); `verify_v7` uses its own `floor_v7()`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p hc-verifier v7_ 2>&1 | tail -30`
Expected: PASS — accumulator + range verify; tampered + pre-v7 + forge-PoC all rejected.

- [ ] **Step 5: Gate + commit**

```bash
cargo fmt --all --check && cargo clippy -p hc-verifier --all-targets -- -D warnings && cargo test --workspace 2>&1 | tail -10
git add crates/hc-verifier/src/v5.rs crates/hc-hash/src/protocol.rs crates/hc-prover/src/prove.rs
git commit -m "feat(verifier): v7 verification over compose_at — range forges rejected, forge-PoC GREEN (Phase 1B T7)"
```

---

## Task 8: ZK mask over all N columns + the worked ZK argument

**Files:**
- Modify: `crates/hc-prover/src/prove.rs` (mask loop over all columns; finalize `mask_degree`)
- Create: `docs/security/zk_range.md`
- Modify: `docs/security/soundness_proof.md` (α-union-bound)
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn v8_range_hides_value_and_masks_all_columns() {
    let air = hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N);
    let trace = hc_air::build_range_trace(18, 120, 42).unwrap();
    let proof = hc_prover::prove_v7(&air, &trace, &[F::new(18), F::new(120)],
                                    &ProverConfig::production_v7(true)).unwrap();
    // V (42) and a=V-min (24), c=max-V (78) must not appear as public inputs.
    assert_eq!(proof.public_inputs_u64(), vec![18, 120]);
    // Same statement, different mask seed → different proof bytes (openings blinded).
    let mut cfg2 = ProverConfig::production_v7(true);
    cfg2 = cfg2.with_zk_seed([7u8; 32]);
    let proof2 = hc_prover::prove_v7(&air, &trace, &[F::new(18), F::new(120)], &cfg2).unwrap();
    assert_ne!(serialize(&proof), serialize(&proof2), "mask seed must change opened values");
    // verify still passes for both
    verify_v7(&proof).unwrap();
    verify_v7(&proof2).unwrap();
}
```

> Use the SDK serializer for `serialize`; `public_inputs_u64()` reads the proof's public-input vector. If `prove_v7` already masks all columns (because T6 looped columns when `zk.enabled`), this test may pass immediately — then this task's code change is just *finalizing* the per-column independent `R_j` (domain-separated by column index) and the `mask_degree`.

- [ ] **Step 2: Run to verify it fails (or reveals a gap)**

Run: `cargo test -p hc-verifier v8_range_hides_value 2>&1 | tail -15`
Expected: FAIL if columns aren't independently masked / seed doesn't vary openings.

- [ ] **Step 3: Implement all-column independent masking**

At the v5 mask sites (`prove.rs:369-407` and `:790-817`), the mask currently hardcodes `acc_eval`/`delta_eval`. In `prove_v7`'s trace-LDE step, loop every column `j`, derive an independent `R_j` from `(seed, j)` (domain-separate the RNG by the column index), and add `Z_H(x)·R_j(x)` to column `j`'s LDE. Ensure the SAME `R_j` is regenerated in any masked-oracle recomputation.

```rust
for (j, col) in columns.iter_mut().enumerate() {
    let r_j = sample_mask_poly(&seed, j, mask_degree, padded_len); // domain-separated by j
    for i in 0..lde_len {
        let x = lde_domain.element(i);
        let z_h = x.pow(padded_len as u64).sub(F::ONE);
        col[i] = col[i].add(z_h.mul(eval_r_at(&r_j, x)));
    }
}
```

Set `mask_degree` in `production_v7` per the ZK argument (Step 4): `mask_degree = query_count` if the doc shows trace-only masking suffices, else `query_count + δ` to cover quotient openings. Update T6's placeholder accordingly.

- [ ] **Step 4: Write the ZK argument**

Create `docs/security/zk_range.md` with: the witness column set ({a_bit,a_acc,c_bit,c_acc}, V absent); the masking construction (`col_j + Z_H·R_j`, `R_j` independent, degree `mask_degree`); the simulator argument (with `mask_degree ≥ Q`, the `Q` opened masked values at off-domain points are jointly uniform in `Kᵠ` and witness-independent); and the **explicit resolution of the quotient-opening subtlety** — show the quotient openings are a deterministic function of the masked trace openings + α (hence simulatable), OR bump `mask_degree` to cover them and state the bumped value. Add the `Pr[C≡0] ≤ n_c/|K|` α-union-bound paragraph to `docs/security/soundness_proof.md`.

- [ ] **Step 5: Run tests + gate + commit**

Run: `cargo test -p hc-verifier v8_range_hides_value 2>&1 | tail -15`
Expected: PASS.

```bash
cargo fmt --all --check && cargo clippy -p hc-prover --all-targets -- -D warnings
git add crates/hc-prover/src/prove.rs docs/security/zk_range.md docs/security/soundness_proof.md
git commit -m "feat(prover/docs): all-column ZK mask + worked range ZK argument (Phase 1B T8)"
```

---

## Task 9: Wire `range_proof` template to the AIR path + dispatch + `audited` gate

**Files:**
- Modify: `crates/hc-workloads/src/templates/mod.rs` (`TemplateBuildResult` enum, `audited` field on `ProofTemplate`)
- Modify: `crates/hc-workloads/src/unified.rs` (`is_live` rule)
- Modify: `crates/hc-workloads/src/templates/range_proof.rs`, `accumulator.rs` (build → variant; `audited`)
- Modify: prover-facing dispatch in `hc-worker` / `hc-mcp` (prove from `(Air,trace,public_inputs)`)
- Test: inline `#[cfg(test)]`

- [ ] **Step 1: Write the failing tests**

In `unified.rs` tests (update the existing `dispatch_and_listing_truth_table`):

```rust
#[test]
fn range_proof_is_enforced_but_gated_until_audit() {
    use crate::templates::{template_by_id, Enforcement};
    let r = template_by_id("range_proof").unwrap();
    assert_eq!(r.enforcement, Enforcement::Enforced, "range now truly enforces");
    assert!(!r.audited, "range is not yet audited → gated");
    // gated off by default, on with the unaudited flag:
    assert!(!is_dispatchable("range_proof", false));
    assert!(is_dispatchable("range_proof", true));
    // accumulator stays live unconditionally:
    assert!(is_dispatchable("accumulator_step", false));
}

#[test]
fn only_accumulator_step_is_live_by_default() {
    let live: Vec<&str> = list_templates().iter()
        .filter(|t| is_live(t.enforcement, t.audited, false))
        .map(|t| t.id).collect();
    assert_eq!(live, vec!["accumulator_step"]);
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hc-workloads range_proof_is_enforced_but_gated 2>&1 | tail -15`
Expected: FAIL — no `audited` field / `is_live`.

- [ ] **Step 3: Add the `audited` axis + `TemplateBuildResult` enum**

In `templates/mod.rs`: add `pub audited: bool` to `ProofTemplate`; convert `TemplateBuildResult` from the struct to:

```rust
pub enum TemplateBuildResult {
    Vm  { program: Program, initial_acc: u64, final_acc: u64, recommended_zk: bool },
    Air { air: Box<dyn hc_air::GeneralAir + Send + Sync>,
          trace: hc_air::MultiColumnTrace<hc_air::air_general::F>,
          public_inputs: Vec<hc_air::air_general::F>,
          recommended_zk: bool },
}
```

In `unified.rs`, replace `is_listable`/`is_dispatchable` logic with:

```rust
pub fn is_live(enforcement: Enforcement, audited: bool, allow_unaudited: bool) -> bool {
    (matches!(enforcement, Enforcement::Enforced) && audited) || allow_unaudited
}
```

Update `is_dispatchable` to consult `audited` too (look the template up and pass its `audited`). Update the old `is_listable` callers in `hc-server`/`hc-mcp` to the new signature (re-grep call sites).

Update every `inventory::submit!(ProofTemplate { ... })` to include `audited`: `accumulator_step` → `true`; the other five → `false`. Update the legacy enforcement tests in `templates/mod.rs` (`only_accumulator_step_is_enforced` → `only_accumulator_step_is_live_by_default`; remove `range_proof` from `the_five_predicate_templates_are_structure_only`, leaving the other four).

- [ ] **Step 4: Switch `range_proof` build() to the Air variant**

Rewrite `templates/range_proof.rs` `build()`:

```rust
fn build(params: &serde_json::Map<String, JsonValue>) -> Result<TemplateBuildResult> {
    let min = require_u64(params, "min")?;
    let max = require_u64(params, "max")?;
    let value = require_u64(params, "value")?;
    let trace = hc_air::build_range_trace(min, max, value)
        .map_err(|e| anyhow::anyhow!("range trace: {e}"))?;
    Ok(TemplateBuildResult::Air {
        air: Box::new(hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N)),
        trace,
        public_inputs: vec![
            hc_air::air_general::F::from_u64(min),
            hc_air::air_general::F::from_u64(max),
        ],
        recommended_zk: true,
    })
}
```

Update `PARAMS` (replace `witness_steps` with `value`), `enforcement: Enforcement::Enforced`, `audited: false`, and `example_json` to `{"min":18,"max":120,"value":42}`. Update `accumulator.rs` build() to return `TemplateBuildResult::Vm{..}` and `audited: true`.

- [ ] **Step 5: Generalize the prove dispatch (worker/MCP)**

At the prove entry that today calls `build_from_template` → VM program → `prove_v5`, match on `TemplateBuildResult`: `Vm{..}` → execute → `AccumulatorAir` + `prove_v7`; `Air{air,trace,public_inputs,..}` → `prove_v7(&*air, &trace, &public_inputs, &cfg)`. (Re-grep the call site: `grep -rn build_from_template crates/hc-worker crates/hc-mcp crates/hc-server`.)

- [ ] **Step 6: Run tests + gate + commit**

Run: `cargo test -p hc-workloads 2>&1 | tail -15`
Expected: PASS (incl. the updated truth-table tests).

```bash
cargo fmt --all --check && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace 2>&1 | tail -10
git add crates/hc-workloads crates/hc-worker crates/hc-mcp crates/hc-server
git commit -m "feat(workloads): range_proof → real AIR; Enforced+audited gate keeps it gated (Phase 1B T9)"
```

---

## Task 10: Production cutover + KAT + proptests + full gate

**Files:**
- Modify: `crates/hc-worker/...`, `crates/hc-mcp/...` (default config → `production_v7`/`v8`)
- Modify: `crates/hc-verifier/src/v5.rs` (`verify_proof_bytes` rejects `< 7`; `Default` floor `min_sound_version → 7`)
- Test: KAT vectors + proptests (new `#[cfg(test)]`)

- [ ] **Step 1: Write the failing tests**

```rust
// proptest: random in-range verifies, out-of-range/tampered rejected.
proptest! {
    #[test]
    fn range_roundtrip_in_and_out(min in 0u64..1_000, span in 0u64..1_000, voff in 0u64..2_000) {
        let max = min + span;
        let v = min.saturating_add(voff);
        let air = hc_air::RangeAir::new(hc_air::RANGE_DEFAULT_N);
        match hc_air::build_range_trace(min, max, v) {
            Ok(trace) => {
                prop_assert!(v >= min && v <= max);
                let p = hc_prover::prove_v7(&air, &trace, &[F::new(min), F::new(max)],
                                            &ProverConfig::production_v7(true)).unwrap();
                prop_assert!(verify_v7(&p).is_ok());
            }
            Err(_) => prop_assert!(v < min || v > max || (max - min) >= (1u64 << hc_air::RANGE_DEFAULT_N)),
        }
    }
}

#[test]
fn v7_kat_vector_is_stable() {
    // Pin a fixed (min,max,value,seed) → exact proof bytes. Generate once,
    // paste the hex, assert equality forever after (format lock).
    let bytes = make_fixed_v7_range_proof_bytes();
    assert_eq!(hex::encode(&bytes), include_str!("kat/range_v8.hex").trim());
}

#[test]
fn verify_proof_bytes_rejects_pre_v7() {
    let v5 = make_v5_proof_bytes_relaxed();
    assert!(hc_verifier::verify_proof_bytes(&v5).is_err());
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `cargo test -p hc-verifier range_roundtrip_in_and_out v7_kat 2>&1 | tail -20`
Expected: FAIL (KAT file missing; cutover not done).

- [ ] **Step 3: Cutover + KAT generation**

- In `hc-worker`/`hc-mcp`, change the default prover config from `production_v5` to `production_v7(zk)` and proving to `prove_v7` (the dispatch from T9 already routes the AIR).
- In `v5.rs`, set `verify_proof_bytes` to reject `version < 7` (read its current `< 5` / `>= 5` check at the decode site) and change the `Default` `VerifierSecurityFloor.min_sound_version` from `5` to `7`. Keep `verify_v5` available test-only (mark `#[cfg(test)]` or rename `verify_v5_test_only`), exactly as v3/v4 were retained.
- Generate the KAT: run the test once with a `println!(hex)`, write `crates/hc-verifier/src/kat/range_v8.hex`, then assert.

- [ ] **Step 4: Run full gate**

Run:
```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace 2>&1 | tail -15
```
Expected: ALL green — including T7 forge-PoC GREEN, range forges rejected, proptests, KAT stable, pre-v7 rejected.

- [ ] **Step 5: Verify prod-gating invariant locally**

Run (proves `range_proof` stays hidden by default):
```bash
HC_ALLOW_UNAUDITED_TEMPLATES= cargo test -p hc-workloads only_accumulator_step_is_live_by_default 2>&1 | tail -5
```
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add -A
git commit -m "feat(server/mcp/verifier): cut production proving+verification to sound v7/v8; reject pre-v7; KAT+proptests (Phase 1B T10)"
```

---

## Self-Review

**1. Spec coverage** (spec → task):
- §5 sound seam (compose_at, single-α, masks {first,last,transition,all}, degree rule) → **T1**. α-union-bound doc → **T8**.
- §5 accumulator reduction / differential → **T2**, verified end-to-end **T7**.
- §7 RangeAir + builder + `{min,max,value}` → **T3** (math) + **T9** (template wiring).
- §6.1 width-N trace/leaf/openings → **T5** (leaf/commit) + **T6** (quotient/openings) + **T7** (verify openings).
- §6.2 public-input vector → **T4** (fields/labels) + **T6/T7** (bind/consume).
- §6.3 all-column ZK mask → **T8**. §6.4 ZK argument doc → **T8**.
- §6.5 v7/v8 version bump + floor + cutover → **T4** (domains) + **T6** (`production_v7`) + **T7** (`floor_v7`) + **T10** (cutover, `Default` floor, `verify_proof_bytes`).
- §6.5 `audited` production-exposure axis → **T9**.
- §8 negative/forge tests → **T3** (unit) + **T7** (E2E) ; differential → **T2/T7** ; KAT + proptests → **T10**.
- §9 exit gates → distributed across T7 (forge-PoC GREEN, range REJECT, version<7 REJECT), T9 (gated), T10 (full gate + prod-gating invariant).

No spec requirement is left without a task.

**2. Placeholder scan:** The few `/* ... */` notes (e.g. `production_v5` args in T6, `mask_degree` in T6/T8, the KAT hex, the worker/MCP call site) are **anchored "read current code here" directives**, not vague TODOs — each names the exact symbol/file to read and what to substitute. The `mask_degree` value is explicitly finalized in T8 against the ZK argument. Acceptable per the executor convention stated at the top.

**3. Type consistency:** `Air` trait re-exported as `GeneralAir` (avoids clash with legacy `air::Air`); `F`/`K` from `air_general`; `compose_at` signature identical in T1 (def), T6 (prover call), T7 (verifier call); `hash_trace_row_n(&[F])` identical in T5 prover + verifier; `TemplateBuildResult::{Vm,Air}` identical in T9 def + dispatch; `is_live(enforcement, audited, allow_unaudited)` identical in T9 def + tests; `production_v7(zk: bool)` identical in T6/T7/T8/T10; `verify_v7` identical in T7 def + T8/T10 use.

---

## Notes carried from the spec

- **Out of scope:** external audit (Phase 4); prod-enable/advertise of `range_proof` (gated); the other four templates; Poseidon2/degree-splitting; performance (Phase 5); `hc-recursion` in-circuit fold (stays gated off).
- **Deploy after merge:** this is a prover+verifier+MCP **co-deploy** (hard v7 cutover). Production `/templates` must still show only `accumulator_step` (T10 Step 5 asserts this locally; re-verify against prod post-deploy).
