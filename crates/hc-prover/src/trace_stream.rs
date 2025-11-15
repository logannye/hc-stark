use hc_core::{error::HcResult, field::FieldElement};
use hc_replay::{block_range::BlockRange, traits::BlockProducer};

use crate::TraceRow;

pub struct SliceTraceProducer<'a, F: FieldElement> {
    pub rows: &'a [TraceRow<F>],
}

impl<'a, F: FieldElement> BlockProducer<TraceRow<F>> for SliceTraceProducer<'a, F> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<TraceRow<F>>> {
        let end = range.end().min(self.rows.len());
        Ok(self.rows[range.start..end].to_vec())
    }
}
