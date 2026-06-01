//! The v5 accumulator statement re-expressed on the generalized [`Air`] trait.
//!
//! Used to prove the general seam reduces to the deployed accumulator's
//! behavior (the v7 differential), and as the trace backend for the
//! `accumulator_step` template once it moves to the v7 path.

use crate::air_general::{Air, ConstraintMeta, MaskKind, F};
use hc_core::field::FieldElement;

/// Columns: `[acc, delta]`. Public inputs: `[initial_acc, final_acc]`.
///
/// Constraints (canonical order = α power):
///   0 first:      `acc - initial_acc`
///   1 last:       `acc - final_acc`
///   2 transition: `acc_next - (acc + delta)`
pub struct AccumulatorAir;

const ACC_CONSTRAINTS: &[ConstraintMeta] = &[
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::First,
    },
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::Last,
    },
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::Transition,
    },
];

impl Air for AccumulatorAir {
    fn width(&self) -> usize {
        2
    }
    fn public_input_len(&self) -> usize {
        2
    }
    fn constraints(&self) -> &'static [ConstraintMeta] {
        ACC_CONSTRAINTS
    }
    fn eval_constraint(&self, i: usize, cur: &[F], next: &[F], public: &[F]) -> F {
        match i {
            0 => cur[0].sub(public[0]),           // acc - initial_acc
            1 => cur[0].sub(public[1]),           // acc - final_acc
            2 => next[0].sub(cur[0].add(cur[1])), // acc' - (acc + delta)
            _ => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_general::K;

    /// A genuine K element (c1 ≠ 0).
    fn alpha() -> K {
        K::new(F::from_u64(9), F::from_u64(2))
    }

    fn public() -> [F; 2] {
        [F::from_u64(5), F::from_u64(8)]
    }

    #[test]
    fn vanishes_on_valid_interior_row() {
        // interior: l0=0, l_last=0, selector_last=1; acc=5, delta=1, acc'=6
        let c = AccumulatorAir
            .compose_at(
                &[F::from_u64(5), F::from_u64(1)],
                &[F::from_u64(6), F::from_u64(2)],
                F::ZERO,
                F::ZERO,
                F::ONE,
                &public(),
                alpha(),
            )
            .unwrap();
        assert_eq!(c, K::ZERO);
    }

    #[test]
    fn vanishes_on_valid_first_row() {
        // first: l0=1; acc=initial_acc=5
        let c = AccumulatorAir
            .compose_at(
                &[F::from_u64(5), F::from_u64(1)],
                &[F::from_u64(6), F::from_u64(2)],
                F::ONE,
                F::ZERO,
                F::ONE,
                &public(),
                alpha(),
            )
            .unwrap();
        assert_eq!(c, K::ZERO);
    }

    #[test]
    fn vanishes_on_valid_last_row() {
        // last: l_last=1, selector_last=0 (transition disabled); acc=final_acc=8
        let c = AccumulatorAir
            .compose_at(
                &[F::from_u64(8), F::from_u64(0)],
                &[F::from_u64(8), F::from_u64(0)],
                F::ZERO,
                F::ONE,
                F::ZERO,
                &public(),
                alpha(),
            )
            .unwrap();
        assert_eq!(c, K::ZERO);
    }

    #[test]
    fn detects_transition_violation() {
        // acc'=99 ≠ 5+1
        let c = AccumulatorAir
            .compose_at(
                &[F::from_u64(5), F::from_u64(1)],
                &[F::from_u64(99), F::ZERO],
                F::ZERO,
                F::ZERO,
                F::ONE,
                &public(),
                alpha(),
            )
            .unwrap();
        assert_ne!(c, K::ZERO);
    }

    #[test]
    fn detects_boundary_violation() {
        // first row but acc=7 ≠ initial_acc=5
        let c = AccumulatorAir
            .compose_at(
                &[F::from_u64(7), F::from_u64(1)],
                &[F::from_u64(8), F::ZERO],
                F::ONE,
                F::ZERO,
                F::ONE,
                &public(),
                alpha(),
            )
            .unwrap();
        assert_ne!(c, K::ZERO);
    }
}
