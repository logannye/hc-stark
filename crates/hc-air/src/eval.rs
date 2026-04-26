use hc_core::{error::HcResult, field::FieldElement};

use crate::{
    air::Air,
    air::ToyAir,
    constraints::{boundary::BoundaryConstraints, composition},
    trace::TraceTable,
};

#[derive(Clone, Debug)]
pub struct PublicInputs<F> {
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn evaluate<F: hc_core::field::FieldElement>(
    trace: &TraceTable<F>,
    public_inputs: PublicInputs<F>,
) -> HcResult<()> {
    let boundary = BoundaryConstraints {
        initial_acc: public_inputs.initial_acc,
        final_acc: public_inputs.final_acc,
    };
    composition::enforce(trace, &boundary)
}

/// Compute the per-row composition value used by the STARK verifier at a queried index.
///
/// This is a simplified composition for the toy AIR:
/// - Boundary constraint(s) apply only at the first and last row.
/// - Transition constraint applies at every row except the last (which has no successor).
///
/// The composition value is a linear combination:
/// \n
/// `alpha_boundary * boundary_diff + alpha_transition * transition_diff`\n
/// \n
/// where boundary_diff is 0 except at the first/last row, and transition_diff is 0 at the last row.
pub fn composition_value_for_row<F: FieldElement>(
    current: [F; 2],
    next: [F; 2],
    row_index: usize,
    total_trace_len: usize,
    boundary: &BoundaryConstraints<F>,
    alpha_boundary: F,
    alpha_transition: F,
) -> HcResult<F> {
    ToyAir.composition_value_for_row(
        current.as_slice(),
        next.as_slice(),
        row_index,
        total_trace_len,
        boundary,
        alpha_boundary,
        alpha_transition,
    )
}

/// Evaluate all constraints for a single block of trace rows.
/// Returns constraint evaluations that can be used to build the composition polynomial.
pub fn evaluate_block<F: FieldElement>(
    block: &[[F; 2]],
    block_start_idx: usize,
    total_trace_len: usize,
    boundary: &BoundaryConstraints<F>,
) -> HcResult<Vec<F>> {
    let mut constraint_evals = Vec::new();

    // Boundary constraints
    if block_start_idx == 0 && !block.is_empty() {
        // Initial accumulator constraint
        let actual = block[0][0];
        let expected = boundary.initial_acc;
        constraint_evals.push(actual.sub(expected));
    }

    if block_start_idx + block.len() == total_trace_len && !block.is_empty() {
        // Final accumulator constraint
        let actual = block.last().unwrap()[0];
        let expected = boundary.final_acc;
        constraint_evals.push(actual.sub(expected));
    }

    // Transition constraints within this block
    for i in 0..block.len().saturating_sub(1) {
        let current = block[i];
        let next = block[i + 1];
        let expected = current[0].add(current[1]);
        let diff = next[0].sub(expected);
        constraint_evals.push(diff);
    }

    Ok(constraint_evals)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    #[test]
    fn simple_trace_satisfies_constraints() {
        let rows = [
            [GoldilocksField::new(5), GoldilocksField::new(1)],
            [GoldilocksField::new(6), GoldilocksField::new(2)],
            [GoldilocksField::new(8), GoldilocksField::new(0)],
        ];
        let trace = TraceTable::new(rows.to_vec()).unwrap();
        let public_inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        evaluate(&trace, public_inputs).unwrap();
    }

    #[test]
    fn block_wise_evaluation() {
        let rows = [
            [GoldilocksField::new(5), GoldilocksField::new(1)],
            [GoldilocksField::new(6), GoldilocksField::new(2)],
            [GoldilocksField::new(8), GoldilocksField::new(0)],
        ];
        let boundary = crate::constraints::boundary::BoundaryConstraints {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };

        // Test first block (includes initial boundary)
        let constraint_evals = evaluate_block(&rows[0..2], 0, 3, &boundary).unwrap();
        assert_eq!(constraint_evals.len(), 2); // 1 boundary + 1 transition

        // Initial boundary should be satisfied (diff = 0)
        assert_eq!(constraint_evals[0], GoldilocksField::ZERO);

        // Transition should be satisfied (6 = 5 + 1, diff = 0)
        assert_eq!(constraint_evals[1], GoldilocksField::ZERO);

        // Test last block (includes final boundary)
        let constraint_evals = evaluate_block(&rows[1..3], 1, 3, &boundary).unwrap();
        assert_eq!(constraint_evals.len(), 2); // 1 boundary + 1 transition

        // Transition should be satisfied (8 = 6 + 2, diff = 0)
        assert_eq!(constraint_evals[0], GoldilocksField::ZERO);

        // Final boundary should be satisfied (diff = 0)
        assert_eq!(constraint_evals[1], GoldilocksField::ZERO);
    }
}
