use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::trace::TraceTable;

pub fn enforce<F: FieldElement>(trace: &TraceTable<F>) -> HcResult<()> {
    for window in trace.rows().windows(2) {
        let current = window[0];
        let next = window[1];
        let expected = current[0].add(current[1]);
        if next[0] != expected {
            return Err(HcError::message("transition constraint violated"));
        }
    }
    Ok(())
}
