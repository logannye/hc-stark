use hc_core::field::FieldElement;

use crate::{pipeline::phase1_commit, TraceRow};

pub fn compute_root<F: FieldElement>(
    rows: &[TraceRow<F>],
) -> hc_core::error::HcResult<hc_hash::hash::HashDigest> {
    phase1_commit::commit_trace(rows)
}
