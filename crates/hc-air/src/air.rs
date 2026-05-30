use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::constraints::boundary::BoundaryConstraints;

/// A minimal, verifier-facing AIR interface.
///
/// The goal is to make the native verifier generic over different AIRs while
/// keeping the proving pipeline mostly unchanged.
pub trait Air<F: FieldElement> {
    /// Number of trace columns.
    fn trace_width(&self) -> usize;

    /// Whether this AIR requires the next row to evaluate transition constraints.
    fn needs_next_row(&self) -> bool;

    /// Compute the row-aligned composition oracle value used by the native verifier.
    ///
    /// This should be a linear combination of constraint evaluations with transcript-derived
    /// mixing coefficients, returning one field element per row index.
    ///
    /// Note: we keep this explicit parameter list (instead of bundling into structs) because
    /// it is consensus-critical verifier plumbing and we want call sites to be maximally clear.
    #[allow(clippy::too_many_arguments)]
    fn composition_value_for_row(
        &self,
        current: &[F],
        next: &[F],
        row_index: usize,
        trace_len: usize,
        boundary: &BoundaryConstraints<F>,
        alpha_boundary: F,
        alpha_transition: F,
    ) -> HcResult<F>;
}

/// AIR interface for DEEP-STARK v3 quotient evaluation at a single LDE point.
///
/// This intentionally keeps the verifier-facing API narrow: given opened trace values at `x`
/// (and any required neighbor values), return the quotient *numerator* `C(x)` such that the
/// prover commits to `q(x) = C(x) / Z_H(x)` on an LDE coset.
pub trait DeepStarkAir<F: FieldElement> {
    fn trace_width(&self) -> usize;

    /// Compute `C(x)` from opened values and Lagrange selectors on the trace subgroup.
    ///
    /// - `current`: trace columns at `x`
    /// - `next`: trace columns at the neighbor point used by the transition constraint (e.g., shifted by blowup)
    /// - `l0`, `l_last`: Lagrange selector values evaluated at `x` for first/last row constraints
    /// - `selector_last`: typically `1 - l_last`, used to disable transition at the last row
    /// - `alpha_boundary`, `alpha_transition`: transcript-derived mixing coefficients
    ///
    /// Note: we keep this explicit parameter list (instead of bundling into structs) because
    /// it is consensus-critical verifier plumbing and we want call sites to be maximally clear.
    #[allow(clippy::too_many_arguments)]
    fn quotient_numerator(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        alpha_boundary: F,
        alpha_transition: F,
        initial_acc: F,
        final_acc: F,
    ) -> HcResult<F>;

    /// The individual constraint values in the base field, BEFORE the random α-combination.
    /// Returns `(boundary_value, transition_value)`. Callers combine them with the
    /// transcript α challenges — in the base field for v3, in the extension field K for v5+.
    ///
    /// The consistency invariant is:
    /// `alpha_boundary * boundary_value + alpha_transition * transition_value
    ///     == quotient_numerator(current, next, l0, l_last, selector_last,
    ///                           alpha_boundary, alpha_transition, initial_acc, final_acc)`
    #[allow(clippy::too_many_arguments)]
    fn constraint_values(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        initial_acc: F,
        final_acc: F,
    ) -> HcResult<(F, F)>;
}

/// The current toy AIR (accumulator + delta).
#[derive(Clone, Copy, Debug, Default)]
pub struct ToyAir;

impl<F: FieldElement> Air<F> for ToyAir {
    fn trace_width(&self) -> usize {
        2
    }

    fn needs_next_row(&self) -> bool {
        true
    }

    fn composition_value_for_row(
        &self,
        current: &[F],
        next: &[F],
        row_index: usize,
        trace_len: usize,
        boundary: &BoundaryConstraints<F>,
        alpha_boundary: F,
        alpha_transition: F,
    ) -> HcResult<F> {
        if trace_len == 0 {
            return Err(HcError::invalid_argument("trace length must be non-zero"));
        }
        if row_index >= trace_len {
            return Err(HcError::invalid_argument("row index out of range"));
        }
        if current.len() != 2 || next.len() != 2 {
            return Err(HcError::invalid_argument("toy air expects width=2"));
        }

        // Boundary constraints: apply only at first/last row.
        let mut boundary_diff = F::ZERO;
        if row_index == 0 {
            boundary_diff = boundary_diff.add(current[0].sub(boundary.initial_acc));
        }
        if row_index + 1 == trace_len {
            boundary_diff = boundary_diff.add(current[0].sub(boundary.final_acc));
        }

        // Transition constraint: acc_{i+1} = acc_i + delta_i.
        let transition_diff = if row_index + 1 < trace_len {
            let expected_next_acc = current[0].add(current[1]);
            next[0].sub(expected_next_acc)
        } else {
            F::ZERO
        };

        Ok(alpha_boundary
            .mul(boundary_diff)
            .add(alpha_transition.mul(transition_diff)))
    }
}

impl<F: FieldElement> DeepStarkAir<F> for ToyAir {
    fn trace_width(&self) -> usize {
        2
    }

    fn quotient_numerator(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        alpha_boundary: F,
        alpha_transition: F,
        initial_acc: F,
        final_acc: F,
    ) -> HcResult<F> {
        if current.len() != 2 || next.len() != 2 {
            return Err(HcError::invalid_argument("toy air expects width=2"));
        }
        let acc = current[0];
        let delta = current[1];
        let acc_next = next[0];

        let transition = selector_last.mul(acc_next.sub(acc.add(delta)));
        let boundary_term = (acc.sub(initial_acc))
            .mul(l0)
            .add((acc.sub(final_acc)).mul(l_last));
        Ok(alpha_transition
            .mul(transition)
            .add(alpha_boundary.mul(boundary_term)))
    }

    #[allow(clippy::too_many_arguments)]
    fn constraint_values(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        initial_acc: F,
        final_acc: F,
    ) -> HcResult<(F, F)> {
        if current.len() != 2 || next.len() != 2 {
            return Err(HcError::invalid_argument("toy air expects width=2"));
        }
        let acc = current[0];
        let delta = current[1];
        let acc_next = next[0];

        let transition = selector_last.mul(acc_next.sub(acc.add(delta)));
        let boundary_term = (acc.sub(initial_acc))
            .mul(l0)
            .add((acc.sub(final_acc)).mul(l_last));
        Ok((boundary_term, transition))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    /// Verify the consistency invariant:
    ///   alpha_boundary * b + alpha_transition * t == quotient_numerator(...)
    /// for ToyAir across a variety of inputs.
    #[test]
    fn toy_air_constraint_values_consistency() {
        let air = ToyAir;

        // (current, next, l0, l_last, selector_last, initial_acc, final_acc, alpha_b, alpha_t)
        #[allow(clippy::type_complexity)]
        let cases: &[([u64; 2], [u64; 2], u64, u64, u64, u64, u64, u64, u64)] = &[
            // Interior row: both boundary selectors zero, transition active
            ([5, 1], [6, 2], 0, 0, 1, 5, 8, 3, 7),
            // First row: l0=1, no last
            ([5, 1], [6, 2], 1, 0, 1, 5, 8, 3, 7),
            // Last row: l_last=1, selector_last=0 (transition disabled)
            ([8, 0], [8, 0], 0, 1, 0, 5, 8, 3, 7),
            // Both boundary selectors active (degenerate single-row)
            ([5, 0], [5, 0], 1, 1, 0, 5, 5, 11, 13),
            // Transition violation visible (selector_last=1, wrong next acc)
            ([5, 1], [99, 0], 0, 0, 1, 5, 8, 2, 9),
            // Different alpha values
            ([10, 3], [13, 5], 0, 0, 1, 10, 20, 17, 19),
        ];

        for &(curr_raw, next_raw, l0_v, l_last_v, sel_last_v, init_v, fin_v, ab_v, at_v) in cases {
            let current = [F::from_u64(curr_raw[0]), F::from_u64(curr_raw[1])];
            let next = [F::from_u64(next_raw[0]), F::from_u64(next_raw[1])];
            let l0 = F::from_u64(l0_v);
            let l_last = F::from_u64(l_last_v);
            let selector_last = F::from_u64(sel_last_v);
            let initial_acc = F::from_u64(init_v);
            let final_acc = F::from_u64(fin_v);
            let alpha_b = F::from_u64(ab_v);
            let alpha_t = F::from_u64(at_v);

            let (b, t) = air
                .constraint_values(
                    &current,
                    &next,
                    l0,
                    l_last,
                    selector_last,
                    initial_acc,
                    final_acc,
                )
                .expect("constraint_values should not fail");

            let combined = alpha_b.mul(b).add(alpha_t.mul(t));

            let qn = air
                .quotient_numerator(
                    &current,
                    &next,
                    l0,
                    l_last,
                    selector_last,
                    alpha_b,
                    alpha_t,
                    initial_acc,
                    final_acc,
                )
                .expect("quotient_numerator should not fail");

            assert_eq!(
                combined, qn,
                "consistency violated: alpha_b*b + alpha_t*t != quotient_numerator \
                 (case curr={curr_raw:?} next={next_raw:?} l0={l0_v} l_last={l_last_v} \
                 sel={sel_last_v} init={init_v} fin={fin_v} ab={ab_v} at={at_v})"
            );
        }
    }

    #[test]
    fn toy_air_constraint_values_width_check() {
        let air = ToyAir;
        let bad = [F::ZERO; 3];
        let good = [F::ZERO; 2];
        assert!(air.constraint_values(&bad, &good, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO).is_err());
        assert!(air.constraint_values(&good, &bad, F::ZERO, F::ZERO, F::ZERO, F::ZERO, F::ZERO).is_err());
    }
}
