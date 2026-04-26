//! Declarative constraint DSL for multi-column AIRs.
//!
//! This module provides a `ConstraintSystem` that can express arbitrary
//! transition and boundary constraints over N-column traces, then implement
//! the `Air<F>` and `DeepStarkAir<F>` traits automatically.
//!
//! # Example
//!
//! ```ignore
//! let mut cs = ConstraintSystem::new(3); // 3 columns
//! // Transition: col[2]' = col[0] + col[1]
//! cs.transition(|curr, next| next[2].sub(curr[0].add(curr[1])));
//! // Boundary: col[0] starts at 0
//! cs.boundary_first(0, F::ZERO);
//! // Boundary: col[2] ends at expected_result
//! cs.boundary_last(2, expected_result);
//! ```

use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::constraints::boundary::BoundaryConstraints;

// ─── Constraint types ────────────────────────────────────────────────────────

/// A transition constraint expressed as a closure.
///
/// Given `current[0..width]` and `next[0..width]`, returns the constraint
/// evaluation. The constraint is satisfied when the return value is zero.
pub type TransitionFn<F> = Box<dyn Fn(&[F], &[F]) -> F + Send + Sync>;

/// A boundary constraint: at a specific row position, a specific column
/// must equal a specific value.
#[derive(Clone, Debug)]
pub struct BoundaryPoint<F: FieldElement> {
    /// Which row this applies to.
    pub position: BoundaryPosition,
    /// Column index.
    pub column: usize,
    /// Expected value.
    pub value: F,
}

/// Where a boundary constraint applies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundaryPosition {
    /// First row (row 0).
    First,
    /// Last row (row N-1).
    Last,
}

/// A conditional transition constraint: only active when the opcode selector
/// column equals a specific value.
pub struct ConditionalTransition<F: FieldElement> {
    /// Column index for the opcode selector.
    pub selector_col: usize,
    /// Opcode value that activates this constraint.
    pub selector_value: F,
    /// The constraint function (evaluated only when selector matches).
    pub constraint: TransitionFn<F>,
}

// ─── Constraint system ───────────────────────────────────────────────────────

/// A complete AIR constraint system for an N-column trace.
///
/// Collects transition constraints (universal or conditional) and boundary
/// constraints, then implements `Air<F>` and `DeepStarkAir<F>`.
pub struct ConstraintSystem<F: FieldElement> {
    /// Number of trace columns.
    width: usize,
    /// Universal transition constraints (apply at every non-last row).
    transitions: Vec<TransitionFn<F>>,
    /// Conditional transition constraints (apply only when selector matches).
    conditional_transitions: Vec<ConditionalTransition<F>>,
    /// Boundary constraints.
    boundaries: Vec<BoundaryPoint<F>>,
}

impl<F: FieldElement> ConstraintSystem<F> {
    /// Create a new constraint system for a trace with `width` columns.
    pub fn new(width: usize) -> Self {
        assert!(width > 0, "trace width must be positive");
        Self {
            width,
            transitions: Vec::new(),
            conditional_transitions: Vec::new(),
            boundaries: Vec::new(),
        }
    }

    /// Number of trace columns.
    pub fn width(&self) -> usize {
        self.width
    }

    /// Add a universal transition constraint.
    ///
    /// The closure receives `(current_row, next_row)` as slices and must
    /// return zero when satisfied.
    pub fn transition<C>(&mut self, constraint: C)
    where
        C: Fn(&[F], &[F]) -> F + Send + Sync + 'static,
    {
        self.transitions.push(Box::new(constraint));
    }

    /// Add a conditional transition constraint that is only active when
    /// `current[selector_col] == selector_value`.
    ///
    /// The constraint is multiplied by the selector match, so it automatically
    /// evaluates to zero when the selector doesn't match.
    pub fn conditional_transition<C>(
        &mut self,
        selector_col: usize,
        selector_value: F,
        constraint: C,
    ) where
        C: Fn(&[F], &[F]) -> F + Send + Sync + 'static,
    {
        assert!(selector_col < self.width, "selector column out of range");
        self.conditional_transitions.push(ConditionalTransition {
            selector_col,
            selector_value,
            constraint: Box::new(constraint),
        });
    }

    /// Add a boundary constraint at the first row.
    pub fn boundary_first(&mut self, column: usize, value: F) {
        assert!(column < self.width, "column index out of range");
        self.boundaries.push(BoundaryPoint {
            position: BoundaryPosition::First,
            column,
            value,
        });
    }

    /// Add a boundary constraint at the last row.
    pub fn boundary_last(&mut self, column: usize, value: F) {
        assert!(column < self.width, "column index out of range");
        self.boundaries.push(BoundaryPoint {
            position: BoundaryPosition::Last,
            column,
            value,
        });
    }

    /// Total number of constraints (for alpha sampling).
    pub fn num_constraints(&self) -> usize {
        self.transitions.len() + self.conditional_transitions.len() + self.boundaries.len()
    }

    /// Evaluate all constraints for a single row transition.
    ///
    /// Returns the composed value: a random linear combination of all
    /// constraint evaluations using powers of `alpha`.
    pub fn evaluate_composition(
        &self,
        current: &[F],
        next: &[F],
        row_index: usize,
        trace_len: usize,
        alpha: F,
    ) -> HcResult<F> {
        if current.len() != self.width || next.len() != self.width {
            return Err(HcError::invalid_argument(format!(
                "row width mismatch: got ({}, {}), expected {}",
                current.len(),
                next.len(),
                self.width
            )));
        }

        let is_last = row_index + 1 == trace_len;
        let mut result = F::ZERO;
        let mut alpha_power = F::ONE;

        // Boundary constraints
        for bp in &self.boundaries {
            let eval = match bp.position {
                BoundaryPosition::First if row_index == 0 => current[bp.column].sub(bp.value),
                BoundaryPosition::Last if is_last => current[bp.column].sub(bp.value),
                _ => F::ZERO,
            };
            result = result.add(alpha_power.mul(eval));
            alpha_power = alpha_power.mul(alpha);
        }

        // Universal transition constraints (not applied at last row)
        if !is_last {
            for tc in &self.transitions {
                let eval = tc(current, next);
                result = result.add(alpha_power.mul(eval));
                alpha_power = alpha_power.mul(alpha);
            }
        } else {
            // Skip evaluation but still advance alpha powers for consistency
            for _ in &self.transitions {
                alpha_power = alpha_power.mul(alpha);
            }
        }

        // Conditional transition constraints
        if !is_last {
            for ct in &self.conditional_transitions {
                let selector_match = current[ct.selector_col].sub(ct.selector_value);
                // If selector matches (diff == 0), the constraint must hold.
                // We multiply the constraint by the inverse selector match — but
                // the standard approach is simpler: just evaluate and multiply
                // by a boolean indicator.
                //
                // For degree-2 constraints: multiply constraint * (1 - selector_diff)
                // only works for boolean selectors. For opcode selectors with many
                // values, use the product-of-differences approach.
                //
                // Here we use the simple approach: if selector matches, evaluate
                // the constraint directly. Otherwise output zero.
                let eval = if selector_match == F::ZERO {
                    (ct.constraint)(current, next)
                } else {
                    F::ZERO
                };
                result = result.add(alpha_power.mul(eval));
                alpha_power = alpha_power.mul(alpha);
            }
        } else {
            for _ in &self.conditional_transitions {
                alpha_power = alpha_power.mul(alpha);
            }
        }

        Ok(result)
    }

    /// Evaluate the quotient numerator for DEEP-STARK.
    ///
    /// This is similar to `evaluate_composition` but uses Lagrange selectors
    /// (l0, l_last) instead of row-index checks, and includes the
    /// `selector_last` term for disabling transitions at the last row.
    pub fn evaluate_quotient_numerator(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        alpha: F,
    ) -> HcResult<F> {
        if current.len() != self.width || next.len() != self.width {
            return Err(HcError::invalid_argument(format!(
                "row width mismatch: got ({}, {}), expected {}",
                current.len(),
                next.len(),
                self.width
            )));
        }

        let mut result = F::ZERO;
        let mut alpha_power = F::ONE;

        // Boundary constraints using Lagrange selectors
        for bp in &self.boundaries {
            let diff = current[bp.column].sub(bp.value);
            let eval = match bp.position {
                BoundaryPosition::First => diff.mul(l0),
                BoundaryPosition::Last => diff.mul(l_last),
            };
            result = result.add(alpha_power.mul(eval));
            alpha_power = alpha_power.mul(alpha);
        }

        // Universal transition constraints (masked by selector_last)
        for tc in &self.transitions {
            let eval = selector_last.mul(tc(current, next));
            result = result.add(alpha_power.mul(eval));
            alpha_power = alpha_power.mul(alpha);
        }

        // Conditional transition constraints (masked by selector_last)
        for ct in &self.conditional_transitions {
            let selector_match = current[ct.selector_col].sub(ct.selector_value);
            let eval = if selector_match == F::ZERO {
                selector_last.mul((ct.constraint)(current, next))
            } else {
                F::ZERO
            };
            result = result.add(alpha_power.mul(eval));
            alpha_power = alpha_power.mul(alpha);
        }

        Ok(result)
    }
}

// ─── Air trait implementations ───────────────────────────────────────────────

/// A generic AIR backed by a `ConstraintSystem`.
///
/// This bridges the DSL to the prover/verifier via the `Air` and `DeepStarkAir`
/// traits. The legacy `BoundaryConstraints` (initial_acc / final_acc) are
/// accepted for backward compatibility but the actual constraint checking
/// comes from the `ConstraintSystem`.
pub struct DslAir<F: FieldElement> {
    pub system: ConstraintSystem<F>,
}

impl<F: FieldElement> DslAir<F> {
    pub fn new(system: ConstraintSystem<F>) -> Self {
        Self { system }
    }
}

impl<F: FieldElement> super::air::Air<F> for DslAir<F> {
    fn trace_width(&self) -> usize {
        self.system.width()
    }

    fn needs_next_row(&self) -> bool {
        // If we have any transition constraints, we need the next row.
        !self.system.transitions.is_empty() || !self.system.conditional_transitions.is_empty()
    }

    fn composition_value_for_row(
        &self,
        current: &[F],
        next: &[F],
        row_index: usize,
        trace_len: usize,
        _boundary: &BoundaryConstraints<F>,
        alpha_boundary: F,
        _alpha_transition: F,
    ) -> HcResult<F> {
        // Use alpha_boundary as the composition alpha for all constraints.
        self.system
            .evaluate_composition(current, next, row_index, trace_len, alpha_boundary)
    }
}

impl<F: FieldElement> super::air::DeepStarkAir<F> for DslAir<F> {
    fn trace_width(&self) -> usize {
        self.system.width()
    }

    fn quotient_numerator(
        &self,
        current: &[F],
        next: &[F],
        l0: F,
        l_last: F,
        selector_last: F,
        alpha_boundary: F,
        _alpha_transition: F,
        _initial_acc: F,
        _final_acc: F,
    ) -> HcResult<F> {
        self.system.evaluate_quotient_numerator(
            current,
            next,
            l0,
            l_last,
            selector_last,
            alpha_boundary,
        )
    }
}

// ─── Convenience: build a ToyAir-compatible constraint system ────────────────

/// Build a constraint system equivalent to ToyAir (for testing / migration).
///
/// Columns: [accumulator, delta]
/// Transition: next[0] = current[0] + current[1]
/// Boundary: first[0] = initial_acc, last[0] = final_acc
pub fn toy_air_system<F: FieldElement>(initial_acc: F, final_acc: F) -> ConstraintSystem<F> {
    let mut cs = ConstraintSystem::new(2);
    cs.transition(|curr: &[F], next: &[F]| next[0].sub(curr[0].add(curr[1])));
    cs.boundary_first(0, initial_acc);
    cs.boundary_last(0, final_acc);
    cs
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn toy_air_system_satisfied() {
        let cs = toy_air_system(F::from_u64(5), F::from_u64(8));
        // Trace: acc=5 +1 → 6 +2 → 8
        let rows = [
            [F::from_u64(5), F::from_u64(1)],
            [F::from_u64(6), F::from_u64(2)],
            [F::from_u64(8), F::from_u64(0)],
        ];
        let alpha = F::from_u64(7);
        for i in 0..3 {
            let next_idx = if i + 1 < 3 { i + 1 } else { i };
            let val = cs
                .evaluate_composition(&rows[i], &rows[next_idx], i, 3, alpha)
                .unwrap();
            assert_eq!(val, F::ZERO, "constraint violated at row {i}");
        }
    }

    #[test]
    fn toy_air_system_detects_violation() {
        let cs = toy_air_system(F::from_u64(5), F::from_u64(8));
        // Wrong transition: 5 + 1 should be 6, not 7
        let rows = [
            [F::from_u64(5), F::from_u64(1)],
            [F::from_u64(7), F::from_u64(1)], // wrong!
            [F::from_u64(8), F::from_u64(0)],
        ];
        let alpha = F::from_u64(7);
        let val = cs
            .evaluate_composition(&rows[0], &rows[1], 0, 3, alpha)
            .unwrap();
        assert_ne!(val, F::ZERO, "should detect transition violation");
    }

    #[test]
    fn boundary_first_detects_violation() {
        let cs = toy_air_system(F::from_u64(5), F::from_u64(8));
        // Wrong initial value
        let row = [F::from_u64(999), F::from_u64(1)];
        let next = [F::from_u64(1000), F::from_u64(0)];
        let alpha = F::from_u64(3);
        let val = cs.evaluate_composition(&row, &next, 0, 3, alpha).unwrap();
        assert_ne!(val, F::ZERO, "should detect boundary violation");
    }

    #[test]
    fn conditional_transition() {
        // 3-column trace: [opcode, a, b]
        // When opcode == 1 (ADD): next[2] = curr[0] (just a test constraint)
        // When opcode == 2 (MUL): no constraint
        let mut cs = ConstraintSystem::<F>::new(3);
        cs.conditional_transition(0, F::from_u64(1), |curr, next| {
            next[2].sub(curr[1].add(curr[2]))
        });

        let alpha = F::from_u64(5);

        // ADD row: opcode=1, a=3, b=4 → next b should be 7
        let curr_add = [F::from_u64(1), F::from_u64(3), F::from_u64(4)];
        let next_add = [F::from_u64(0), F::from_u64(0), F::from_u64(7)];
        let val = cs
            .evaluate_composition(&curr_add, &next_add, 0, 3, alpha)
            .unwrap();
        assert_eq!(val, F::ZERO, "ADD constraint should be satisfied");

        // MUL row: opcode=2, constraint should not fire
        let curr_mul = [F::from_u64(2), F::from_u64(3), F::from_u64(4)];
        let next_mul = [F::from_u64(0), F::from_u64(0), F::from_u64(999)]; // any value
        let val = cs
            .evaluate_composition(&curr_mul, &next_mul, 0, 3, alpha)
            .unwrap();
        assert_eq!(val, F::ZERO, "MUL constraint should not fire");
    }

    #[test]
    fn quotient_numerator_toy_air() {
        let cs = toy_air_system(F::from_u64(5), F::from_u64(8));
        // At a non-boundary, non-last row with l0=0, l_last=0, selector_last=1:
        let curr = [F::from_u64(5), F::from_u64(1)];
        let next = [F::from_u64(6), F::from_u64(2)];
        let alpha = F::from_u64(7);
        let val = cs
            .evaluate_quotient_numerator(
                &curr,
                &next,
                F::ONE,  // l0 = 1 (first row)
                F::ZERO, // l_last = 0
                F::ONE,  // selector_last = 1 (transition active)
                alpha,
            )
            .unwrap();
        // At first row with correct values: boundary(first) = 5-5 = 0, transition = 6-(5+1) = 0
        assert_eq!(val, F::ZERO);
    }

    #[test]
    fn multi_column_fibonacci_air() {
        // Fibonacci AIR: columns [a, b]
        // Transition: next[0] = curr[1], next[1] = curr[0] + curr[1]
        let mut cs = ConstraintSystem::<F>::new(2);
        cs.transition(|curr, next| next[0].sub(curr[1]));
        cs.transition(|curr, next| next[1].sub(curr[0].add(curr[1])));
        cs.boundary_first(0, F::from_u64(1));
        cs.boundary_first(1, F::from_u64(1));

        // Trace: fib sequence
        // (1,1) → (1,2) → (2,3) → (3,5) → (5,8)
        let rows = [
            [F::from_u64(1), F::from_u64(1)],
            [F::from_u64(1), F::from_u64(2)],
            [F::from_u64(2), F::from_u64(3)],
            [F::from_u64(3), F::from_u64(5)],
            [F::from_u64(5), F::from_u64(8)],
        ];
        let alpha = F::from_u64(13);
        for i in 0..5 {
            let next_idx = if i + 1 < 5 { i + 1 } else { i };
            let val = cs
                .evaluate_composition(&rows[i], &rows[next_idx], i, 5, alpha)
                .unwrap();
            assert_eq!(val, F::ZERO, "constraint violated at row {i}");
        }
    }

    #[test]
    fn width_mismatch_returns_error() {
        let cs = ConstraintSystem::<F>::new(3);
        let curr = [F::ZERO, F::ZERO]; // only 2 cols, expected 3
        let next = [F::ZERO, F::ZERO];
        let result = cs.evaluate_composition(&curr, &next, 0, 2, F::ONE);
        assert!(result.is_err());
    }
}
