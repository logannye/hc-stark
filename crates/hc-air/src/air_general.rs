//! Generalized AIR: N columns, N constraints combined via powers of a single
//! composition challenge α ∈ K. This is the sound seam consumed identically by
//! the v7 prover and verifier (replaces the hardcoded ToyAir 2-tuple).
//!
//! Implementors provide the column count, public-input arity, an ordered
//! constraint list (metadata), and a per-constraint evaluator. The α-power
//! composition ([`Air::compose_at`]) is a provided method and is
//! consensus-critical: the prover and verifier MUST call it identically.

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

/// A sound, general AIR.
///
/// The constraint order returned by [`Air::constraints`] is the α power
/// assigned to each constraint in [`Air::compose_at`], so the order is part of
/// the AIR definition and is consensus by construction.
pub trait Air {
    /// Number of trace columns (N).
    fn width(&self) -> usize;

    /// Number of public inputs this AIR consumes.
    fn public_input_len(&self) -> usize;

    /// Ordered constraint metadata. Index `i` is the α power for constraint `i`.
    fn constraints(&self) -> &'static [ConstraintMeta];

    /// Evaluate constraint `i` at a row (`current`, plus `next` for transition
    /// constraints) and the public inputs. Returns the raw (unmasked) value in F.
    fn eval_constraint(&self, i: usize, current: &[F], next: &[F], public: &[F]) -> F;

    /// Maximum constraint degree (drives the `blowup ≥ degree` requirement).
    fn max_constraint_degree(&self) -> usize {
        self.constraints()
            .iter()
            .map(|c| c.degree)
            .max()
            .unwrap_or(1)
    }

    /// THE consensus-critical composition: `C(x) = Σ_i αⁱ · K(maskᵢ(x) · eᵢ)`.
    ///
    /// Provided; do not override. `l0`, `l_last`, `selector_last` are the
    /// Lagrange selectors at the LDE point `x`; `alpha` is the single
    /// composition challenge drawn in K. The prover divides the result by
    /// `Z_H(x)` to form the quotient; the verifier checks it against the opened
    /// quotient. Both call this method with identical inputs.
    ///
    /// The explicit parameter list (rather than a bundled struct) is kept
    /// deliberately: this is consensus-critical prover/verifier plumbing and we
    /// want call sites maximally clear (mirrors `air::DeepStarkAir`).
    #[allow(clippy::too_many_arguments)]
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
            return Err(HcError::invalid_argument(
                "compose_at: trace row width mismatch",
            ));
        }
        if public.len() != self.public_input_len() {
            return Err(HcError::invalid_argument(
                "compose_at: public input length mismatch",
            ));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A 3-constraint test AIR over a width-2 trace:
    ///   c0 (all):        col0 * (col0 - 1)      [booleanity of col0]
    ///   c1 (transition): next0 - (col0 + col1)  [accumulate]
    ///   c2 (first):      col0 - public[0]       [boundary]
    struct TestAir;
    impl Air for TestAir {
        fn width(&self) -> usize {
            2
        }
        fn public_input_len(&self) -> usize {
            1
        }
        fn constraints(&self) -> &'static [ConstraintMeta] {
            &[
                ConstraintMeta {
                    degree: 2,
                    mask: MaskKind::All,
                },
                ConstraintMeta {
                    degree: 1,
                    mask: MaskKind::Transition,
                },
                ConstraintMeta {
                    degree: 1,
                    mask: MaskKind::First,
                },
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

    /// A genuine K element (c1 ≠ 0) for composition.
    fn alpha() -> K {
        K::new(F::from_u64(7), F::from_u64(3))
    }

    #[test]
    fn compose_at_vanishes_on_valid_first_row() {
        // col0=1 (boolean ok), col1=4, next0=5=1+4 ok, public[0]=1 ok.
        let cur = [F::from_u64(1), F::from_u64(4)];
        let next = [F::from_u64(5), F::from_u64(0)];
        let public = [F::from_u64(1)];
        // first row: l0=1, l_last=0, selector_last=1
        let c = TestAir
            .compose_at(&cur, &next, F::ONE, F::ZERO, F::ONE, &public, alpha())
            .unwrap();
        assert_eq!(c, K::ZERO, "all three constraints satisfied → C must be 0");
    }

    #[test]
    fn compose_at_detects_single_violation() {
        // Break ONLY the accumulate constraint (c1): next0 = 99 ≠ 1+4.
        let cur = [F::from_u64(1), F::from_u64(4)];
        let next = [F::from_u64(99), F::from_u64(0)];
        let public = [F::from_u64(1)];
        let c = TestAir
            .compose_at(&cur, &next, F::ONE, F::ZERO, F::ONE, &public, alpha())
            .unwrap();
        assert_ne!(c, K::ZERO, "a single violated constraint must make C ≠ 0");
    }

    #[test]
    fn compose_at_interior_row_only_transition_active() {
        // Interior: l0=0, l_last=0, selector_last=1. Booleanity (All) still on.
        // col0=1 boolean, next0=1+4 ok → vanishes; break accumulate → nonzero.
        let cur = [F::from_u64(1), F::from_u64(4)];
        let ok_next = [F::from_u64(5), F::from_u64(0)];
        let bad_next = [F::from_u64(6), F::from_u64(0)];
        let public = [F::from_u64(999)]; // boundary inactive at interior row
        let ok = TestAir
            .compose_at(&cur, &ok_next, F::ZERO, F::ZERO, F::ONE, &public, alpha())
            .unwrap();
        assert_eq!(
            ok,
            K::ZERO,
            "interior valid row vanishes (boundary masked off)"
        );
        let bad = TestAir
            .compose_at(&cur, &bad_next, F::ZERO, F::ZERO, F::ONE, &public, alpha())
            .unwrap();
        assert_ne!(bad, K::ZERO);
    }

    #[test]
    fn compose_at_width_mismatch_errors() {
        let cur = [F::ZERO; 3]; // wrong width
        let next = [F::ZERO; 2];
        let public = [F::ZERO];
        assert!(TestAir
            .compose_at(&cur, &next, F::ZERO, F::ZERO, F::ONE, &public, K::ONE)
            .is_err());
    }

    #[test]
    fn compose_at_public_len_mismatch_errors() {
        let cur = [F::ZERO; 2];
        let next = [F::ZERO; 2];
        let public = [F::ZERO, F::ZERO]; // expected 1
        assert!(TestAir
            .compose_at(&cur, &next, F::ZERO, F::ZERO, F::ONE, &public, K::ONE)
            .is_err());
    }

    #[test]
    fn max_constraint_degree_is_max() {
        assert_eq!(TestAir.max_constraint_degree(), 2);
    }
}
