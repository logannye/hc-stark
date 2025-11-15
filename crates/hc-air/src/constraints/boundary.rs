use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::trace::TraceTable;

#[derive(Clone, Debug)]
pub struct BoundaryConstraints<F: FieldElement> {
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn enforce<F: FieldElement>(
    trace: &TraceTable<F>,
    constraints: &BoundaryConstraints<F>,
) -> HcResult<()> {
    if trace.first()[0] != constraints.initial_acc {
        return Err(HcError::message("initial accumulator mismatch"));
    }
    if trace.last()[0] != constraints.final_acc {
        return Err(HcError::message("final accumulator mismatch"));
    }
    Ok(())
}
