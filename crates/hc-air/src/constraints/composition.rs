use hc_core::error::HcResult;

use super::{boundary::BoundaryConstraints, transition};
use crate::trace::TraceTable;

pub fn enforce<F: hc_core::field::FieldElement>(
    trace: &TraceTable<F>,
    boundary: &BoundaryConstraints<F>,
) -> HcResult<()> {
    super::boundary::enforce(trace, boundary)?;
    transition::enforce(trace)?;
    Ok(())
}

/// Build composition polynomial contributions from constraint evaluations.
/// This combines all constraints into values suitable for FRI commitment.
pub fn build_composition_contributions<F: hc_core::field::FieldElement>(
    constraint_evals: &[F],
    random_coeffs: &[F],
) -> Vec<F> {
    assert_eq!(constraint_evals.len(), random_coeffs.len());

    constraint_evals.iter()
        .zip(random_coeffs.iter())
        .map(|(constraint, coeff)| constraint.mul(*coeff))
        .collect()
}
