//! `range_proof` AIR: prove `min ≤ V ≤ max` without revealing `V`.
//!
//! Columns `[a_bit, a_acc, c_bit, c_acc]` over `n` rows (`n` = power of two).
//! `a = V - min` and `c = max - V` are each decomposed into `n` bits (MSB-first)
//! and recomposed via Horner; the last row ties `a + c = max - min`. Booleanity
//! and Horner force `a, c ∈ [0, 2ⁿ)`; the tie forces `a + c = max - min`; and
//! with `2^(n+1) < p` this gives `0 ≤ a ≤ max-min`, i.e. `min ≤ V = min+a ≤ max`.
//! `V` is never a column or a public input, so it stays hidden.

use crate::air_general::{Air, ConstraintMeta, MaskKind, F};
use crate::multi_column::MultiColumnTrace;
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

/// Default bit-width: covers ranges up to 2^32 (age, score, thresholds).
/// Power of two so the trace needs no padding. Field-safe: `2^(32+1) < p`.
pub const DEFAULT_N: usize = 32;

/// AIR for the `range_proof` predicate. `n` is the bit-width of the
/// decomposition (a power of two).
pub struct RangeAir {
    #[allow(dead_code)]
    n: usize,
}

impl RangeAir {
    /// `n` must be a power of two with `2^(n+1) < p` (Goldilocks), i.e. `n ≤ 62`.
    pub fn new(n: usize) -> Self {
        assert!(
            n.is_power_of_two(),
            "range bit-width n must be a power of two"
        );
        assert!(n + 1 < 64, "field safety: 2^(n+1) < p requires n ≤ 62");
        Self { n }
    }
}

// Columns: 0=a_bit, 1=a_acc, 2=c_bit, 3=c_acc. Public: [min, max].
// Canonical constraint order (index = α power):
const RANGE_CONSTRAINTS: &[ConstraintMeta] = &[
    ConstraintMeta {
        degree: 2,
        mask: MaskKind::All,
    }, // 0 a_bit boolean
    ConstraintMeta {
        degree: 2,
        mask: MaskKind::All,
    }, // 1 c_bit boolean
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::First,
    }, // 2 a_acc seeds at a_bit
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::First,
    }, // 3 c_acc seeds at c_bit
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::Transition,
    }, // 4 a Horner
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::Transition,
    }, // 5 c Horner
    ConstraintMeta {
        degree: 1,
        mask: MaskKind::Last,
    }, // 6 tie a_acc+c_acc = max-min
];

impl Air for RangeAir {
    fn width(&self) -> usize {
        4
    }
    fn public_input_len(&self) -> usize {
        2
    }
    fn air_id(&self) -> u32 {
        2
    }
    fn constraints(&self) -> &'static [ConstraintMeta] {
        RANGE_CONSTRAINTS
    }
    fn eval_constraint(&self, i: usize, cur: &[F], next: &[F], public: &[F]) -> F {
        let two = F::from_u64(2);
        match i {
            0 => cur[0].mul(cur[0].sub(F::ONE)), // a_bit·(a_bit-1)
            1 => cur[2].mul(cur[2].sub(F::ONE)), // c_bit·(c_bit-1)
            2 => cur[1].sub(cur[0]),             // a_acc - a_bit (row 0)
            3 => cur[3].sub(cur[2]),             // c_acc - c_bit (row 0)
            4 => next[1].sub(two.mul(cur[1]).add(next[0])), // a_acc' - (2·a_acc + a_bit')
            5 => next[3].sub(two.mul(cur[3]).add(next[2])), // c_acc' - (2·c_acc + c_bit')
            6 => cur[1].add(cur[3]).sub(public[1].sub(public[0])), // (a_acc+c_acc) - (max-min)
            _ => unreachable!(),
        }
    }
}

/// Build the width-4 range trace for a `(min, max, value)` witness using the
/// default bit-width. `value` (V) is the private input and never appears in the
/// trace or the public inputs.
pub fn build_range_trace(min: u64, max: u64, value: u64) -> HcResult<MultiColumnTrace<F>> {
    build_range_trace_n(min, max, value, DEFAULT_N)
}

/// Build the width-4 range trace with an explicit bit-width `n`.
pub fn build_range_trace_n(
    min: u64,
    max: u64,
    value: u64,
    n: usize,
) -> HcResult<MultiColumnTrace<F>> {
    if min > max {
        return Err(HcError::invalid_argument("range: min must be ≤ max"));
    }
    if value < min || value > max {
        return Err(HcError::invalid_argument("range: value out of [min,max]"));
    }
    if n >= 63 || !n.is_power_of_two() {
        return Err(HcError::invalid_argument(
            "range: n must be a power of two with 2^(n+1) < p (n ≤ 62)",
        ));
    }
    let width = max - min;
    if width >= (1u64 << n) {
        return Err(HcError::invalid_argument("range: max-min must be < 2^n"));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::air_general::K;

    #[test]
    fn build_trace_shape_default_n() {
        let t = build_range_trace(18, 120, 42).unwrap();
        assert_eq!(t.width(), 4);
        assert_eq!(t.num_rows(), DEFAULT_N); // power of two, no padding
    }

    #[test]
    fn builder_rejects_out_of_range_value() {
        assert!(build_range_trace(18, 120, 200).is_err()); // V > max
        assert!(build_range_trace(18, 120, 5).is_err()); // V < min
    }

    #[test]
    fn builder_rejects_range_wider_than_2_pow_n() {
        // max - min must be < 2^DEFAULT_N
        assert!(build_range_trace(0, 1u64 << DEFAULT_N, 1).is_err());
    }

    /// Evaluate compose_at across every row and assert it vanishes for a valid
    /// witness. Uses synthetic Lagrange selectors per row (real domain math is
    /// exercised end-to-end in T7).
    fn assert_air_vanishes(trace: &MultiColumnTrace<F>, public: &[F]) {
        let air = RangeAir::new(DEFAULT_N);
        let n = trace.num_rows();
        let alpha = K::new(F::from_u64(7), F::from_u64(3));
        for i in 0..n {
            let cur = trace.row(i);
            let next = trace.row(if i + 1 < n { i + 1 } else { i });
            let l0 = if i == 0 { F::ONE } else { F::ZERO };
            let l_last = if i + 1 == n { F::ONE } else { F::ZERO };
            let selector_last = F::ONE.sub(l_last);
            let c = air
                .compose_at(&cur, &next, l0, l_last, selector_last, public, alpha)
                .unwrap();
            assert_eq!(c, K::ZERO, "range AIR must vanish at row {i}");
        }
    }

    #[test]
    fn valid_witness_satisfies_air() {
        let trace = build_range_trace(18, 120, 42).unwrap();
        assert_air_vanishes(&trace, &[F::from_u64(18), F::from_u64(120)]);
    }

    #[test]
    fn valid_boundary_values_satisfy_air() {
        // V == min and V == max are both valid.
        assert_air_vanishes(
            &build_range_trace(18, 120, 18).unwrap(),
            &[F::from_u64(18), F::from_u64(120)],
        );
        assert_air_vanishes(
            &build_range_trace(18, 120, 120).unwrap(),
            &[F::from_u64(18), F::from_u64(120)],
        );
    }

    #[test]
    fn tampered_non_boolean_bit_is_caught() {
        let trace = build_range_trace(18, 120, 42).unwrap();
        // Corrupt a_bit at row 0 to a non-boolean value.
        let mut cols: Vec<Vec<F>> = trace.columns().to_vec();
        cols[0][0] = F::from_u64(2);
        let trace = MultiColumnTrace::from_columns(cols).unwrap();
        let air = RangeAir::new(DEFAULT_N);
        let cur = trace.row(0);
        let next = trace.row(1);
        // row 0: l0=1, l_last=0, selector_last=1; booleanity (constraint 0) fires.
        let c = air
            .compose_at(
                &cur,
                &next,
                F::ONE,
                F::ZERO,
                F::ONE,
                &[F::from_u64(18), F::from_u64(120)],
                K::new(F::from_u64(7), F::from_u64(3)),
            )
            .unwrap();
        assert_ne!(c, K::ZERO);
    }

    #[test]
    fn tampered_tie_is_caught() {
        // Lie about public max at the last row → tie (constraint 6) fires.
        let trace = build_range_trace(18, 120, 42).unwrap();
        let air = RangeAir::new(DEFAULT_N);
        let n = trace.num_rows();
        let cur = trace.row(n - 1);
        let next = trace.row(n - 1);
        // last row: l_last=1, selector_last=0; public max lied to 999.
        let c = air
            .compose_at(
                &cur,
                &next,
                F::ZERO,
                F::ONE,
                F::ZERO,
                &[F::from_u64(18), F::from_u64(999)],
                K::new(F::from_u64(7), F::from_u64(3)),
            )
            .unwrap();
        assert_ne!(c, K::ZERO);
    }
}
