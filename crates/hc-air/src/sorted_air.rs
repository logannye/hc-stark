//! `sorted_sequence` AIR: prove a sequence `v_0, v_1, …, v_{n-1}` is
//! **non-decreasing** (`v_{i+1} ≥ v_i`) with each step `< 2^BITS`.
//!
//! Layout (width `1 + BITS`): column 0 = `v`; columns `1..=BITS` = the `BITS`
//! little-endian bits of the step `d_i = v_{i+1} - v_i`. Per row: each bit is
//! boolean, and a transition constraint ties `Σ bit_j·2^j = next_v - cur_v`.
//! Because a negative step would be `p - |d|` (≈2^64) and cannot be written as
//! `BITS` bits when `2^BITS < p`, booleanity + recomposition force every step
//! into `[0, 2^BITS)`, i.e. the sequence is non-decreasing with bounded steps.
//! Two boundary constraints pin the first/last value to the public endpoints.
//!
//! Sound but NOT zero-knowledge (the values appear in the opened trace, like
//! `range_proof`); shipped gated (`audited = false`) until the Phase-4 audit.

use crate::air_general::{Air, ConstraintMeta, MaskKind, F};
use crate::multi_column::MultiColumnTrace;
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

/// Bits per step. Steps must be `< 2^BITS` (65 536). Fixed so the constraint
/// list is static. Field-safe: `2^BITS < p`.
pub const SORTED_BITS: usize = 16;

/// Number of constraints: `BITS` booleanity + recomposition + 2 boundary.
const N_CONSTRAINTS: usize = SORTED_BITS + 3;

/// Largest value we accept (well below Goldilocks `p`, so `from_u64` never
/// reduces and u64 ordering == field ordering). A demo-scale bound.
const MAX_VALUE: u64 = 1 << 48;

const fn build_constraints() -> [ConstraintMeta; N_CONSTRAINTS] {
    // First `SORTED_BITS` entries: booleanity (degree 2, every row).
    let mut arr = [ConstraintMeta {
        degree: 2,
        mask: MaskKind::All,
    }; N_CONSTRAINTS];
    // Recomposition / non-decrease: references `next`, so Transition.
    arr[SORTED_BITS] = ConstraintMeta {
        degree: 1,
        mask: MaskKind::Transition,
    };
    // Boundary: first value, last value.
    arr[SORTED_BITS + 1] = ConstraintMeta {
        degree: 1,
        mask: MaskKind::First,
    };
    arr[SORTED_BITS + 2] = ConstraintMeta {
        degree: 1,
        mask: MaskKind::Last,
    };
    arr
}

static SORTED_CONSTRAINTS: [ConstraintMeta; N_CONSTRAINTS] = build_constraints();

/// AIR for the `sorted_sequence` predicate.
pub struct SortedAir;

impl Air for SortedAir {
    fn width(&self) -> usize {
        1 + SORTED_BITS
    }
    fn public_input_len(&self) -> usize {
        2 // [first, last]
    }
    fn air_id(&self) -> u32 {
        3
    }
    fn constraints(&self) -> &'static [ConstraintMeta] {
        &SORTED_CONSTRAINTS
    }
    fn eval_constraint(&self, i: usize, cur: &[F], next: &[F], public: &[F]) -> F {
        // Constraints 0..SORTED_BITS: booleanity of step bit `i` (column 1+i).
        if i < SORTED_BITS {
            let b = cur[1 + i];
            return b.mul(b.sub(F::ONE));
        }
        match i - SORTED_BITS {
            // Recomposition / non-decrease: Σ bit_j·2^j - (next_v - cur_v).
            0 => {
                let two = F::from_u64(2);
                let mut sum = F::ZERO;
                let mut pow = F::ONE;
                for j in 0..SORTED_BITS {
                    sum = sum.add(cur[1 + j].mul(pow));
                    pow = pow.mul(two);
                }
                sum.sub(next[0].sub(cur[0]))
            }
            1 => cur[0].sub(public[0]), // first endpoint
            2 => cur[0].sub(public[1]), // last endpoint
            _ => unreachable!(),
        }
    }
}

/// Build the width-`(1+BITS)` trace for a non-decreasing `values` sequence.
/// Rejects sequences that decrease, step by `≥ 2^BITS`, or contain a value
/// `≥ MAX_VALUE`. Returns the trace; the caller supplies public `[first, last]`.
pub fn build_sorted_trace(values: &[u64]) -> HcResult<MultiColumnTrace<F>> {
    if values.len() < 2 {
        return Err(HcError::invalid_argument("sorted: need at least 2 values"));
    }
    if values.iter().any(|&x| x >= MAX_VALUE) {
        return Err(HcError::invalid_argument("sorted: value exceeds MAX_VALUE"));
    }
    let n = values.len().next_power_of_two();
    let last = *values.last().unwrap();
    // Pad to a power-of-two height with the last value (padded steps are 0).
    let mut v = values.to_vec();
    v.resize(n, last);

    let mut cols: Vec<Vec<F>> = (0..1 + SORTED_BITS)
        .map(|_| Vec::with_capacity(n))
        .collect();
    for i in 0..n {
        cols[0].push(F::from_u64(v[i]));
        let diff = if i + 1 < n {
            let d = v[i + 1].checked_sub(v[i]).ok_or_else(|| {
                HcError::invalid_argument("sorted: sequence must be non-decreasing")
            })?;
            if d >= (1u64 << SORTED_BITS) {
                return Err(HcError::invalid_argument(
                    "sorted: step exceeds 2^SORTED_BITS",
                ));
            }
            d
        } else {
            0 // last row: transition masked off; bits unconstrained → 0
        };
        for j in 0..SORTED_BITS {
            cols[1 + j].push(F::from_u64((diff >> j) & 1));
        }
    }
    MultiColumnTrace::from_columns(cols)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_general::K;

    fn alpha() -> K {
        K::new(F::from_u64(7), F::from_u64(3))
    }

    /// Evaluate compose_at across every row; assert it vanishes for a valid trace.
    fn assert_air_vanishes(trace: &MultiColumnTrace<F>, public: &[F]) {
        let air = SortedAir;
        let n = trace.num_rows();
        for i in 0..n {
            let cur = trace.row(i);
            let next = trace.row(if i + 1 < n { i + 1 } else { i });
            let l0 = if i == 0 { F::ONE } else { F::ZERO };
            let l_last = if i + 1 == n { F::ONE } else { F::ZERO };
            let selector_last = F::ONE.sub(l_last);
            let c = air
                .compose_at(&cur, &next, l0, l_last, selector_last, public, alpha())
                .unwrap();
            assert_eq!(c, K::ZERO, "sorted AIR must vanish at row {i}");
        }
    }

    #[test]
    fn build_trace_shape_is_power_of_two_and_width() {
        let t = build_sorted_trace(&[3, 5, 5, 9, 40]).unwrap();
        assert_eq!(t.width(), 1 + SORTED_BITS);
        assert_eq!(t.num_rows(), 8); // 5 values padded to next pow2
    }

    #[test]
    fn valid_non_decreasing_sequence_vanishes() {
        let vals = [3u64, 5, 5, 9, 40, 41, 1000];
        let t = build_sorted_trace(&vals).unwrap();
        let public = [F::from_u64(vals[0]), F::from_u64(*vals.last().unwrap())];
        assert_air_vanishes(&t, &public);
    }

    #[test]
    fn flat_sequence_is_non_decreasing() {
        let vals = [7u64, 7, 7, 7];
        let t = build_sorted_trace(&vals).unwrap();
        assert_air_vanishes(&t, &[F::from_u64(7), F::from_u64(7)]);
    }

    #[test]
    fn builder_rejects_decreasing_sequence() {
        assert!(build_sorted_trace(&[5u64, 3, 9]).is_err());
    }

    #[test]
    fn builder_rejects_step_too_large() {
        assert!(build_sorted_trace(&[0u64, 1 << SORTED_BITS]).is_err());
    }

    #[test]
    fn builder_rejects_too_short() {
        assert!(build_sorted_trace(&[5u64]).is_err());
    }

    #[test]
    fn builder_rejects_value_over_max() {
        assert!(build_sorted_trace(&[0u64, MAX_VALUE]).is_err());
    }

    #[test]
    fn tampered_decreasing_step_is_caught() {
        // Hand-build a trace where v decreases (9 → 4); booleanity+recomposition
        // can't represent the negative step, so the AIR must not vanish.
        let t = build_sorted_trace(&[4u64, 9]).unwrap();
        let mut cols: Vec<Vec<F>> = t.columns().to_vec();
        // swap the two real values so the sequence "decreases" 9 → 4
        cols[0][0] = F::from_u64(9);
        cols[0][1] = F::from_u64(4);
        let t2 = MultiColumnTrace::from_columns(cols).unwrap();
        let air = SortedAir;
        let cur = t2.row(0);
        let next = t2.row(1);
        // interior transition row: l0=0,l_last=0,selector_last=1
        let c = air
            .compose_at(
                &cur,
                &next,
                F::ZERO,
                F::ZERO,
                F::ONE,
                &[F::from_u64(9), F::from_u64(4)],
                alpha(),
            )
            .unwrap();
        assert_ne!(c, K::ZERO, "a decreasing step must make C ≠ 0");
    }

    #[test]
    fn tampered_first_boundary_is_caught() {
        let t = build_sorted_trace(&[3u64, 5, 9, 40]).unwrap();
        let air = SortedAir;
        let cur = t.row(0);
        let next = t.row(1);
        // lie about the public `first` (claim 99, real 3) at row 0
        let c = air
            .compose_at(
                &cur,
                &next,
                F::ONE,
                F::ZERO,
                F::ONE,
                &[F::from_u64(99), F::from_u64(40)],
                alpha(),
            )
            .unwrap();
        assert_ne!(c, K::ZERO, "wrong first endpoint must make C ≠ 0");
    }

    #[test]
    fn non_boolean_bit_is_caught() {
        let t = build_sorted_trace(&[3u64, 9]).unwrap();
        let mut cols: Vec<Vec<F>> = t.columns().to_vec();
        cols[1][0] = F::from_u64(2); // bit 0 of step set to 2 (non-boolean)
        let t2 = MultiColumnTrace::from_columns(cols).unwrap();
        let air = SortedAir;
        let cur = t2.row(0);
        let next = t2.row(1);
        let c = air
            .compose_at(
                &cur,
                &next,
                F::ONE,
                F::ZERO,
                F::ONE,
                &[F::from_u64(3), F::from_u64(9)],
                alpha(),
            )
            .unwrap();
        assert_ne!(c, K::ZERO, "non-boolean bit must make C ≠ 0");
    }

    #[test]
    fn max_degree_is_two() {
        assert_eq!(SortedAir.max_constraint_degree(), 2);
    }
}
