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
