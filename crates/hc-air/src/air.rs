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
}
