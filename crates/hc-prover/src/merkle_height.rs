use hc_air::constraints::boundary::BoundaryConstraints;
use hc_core::{
    error::{HcError, HcResult},
    field::{FieldElement, TwoAdicField},
};
use hc_hash::hash::HashDigest;
use hc_replay::{config::ReplayConfig, trace_replay::TraceReplay};

use crate::{
    config::ProverConfig, pipeline::phase1_commit, trace_stream::SliceTraceProducer, TraceRow,
};

pub fn compute_root<F: FieldElement + TwoAdicField>(rows: &[TraceRow<F>]) -> HcResult<HashDigest> {
    if rows.is_empty() {
        return Err(HcError::invalid_argument("trace must contain rows"));
    }
    let producer = SliceTraceProducer { rows };
    let config = ReplayConfig::new(rows.len(), rows.len())?;
    let mut replay = TraceReplay::new(config, producer)?;
    let prover_config = ProverConfig::new(1, 1)?; // Simple config for testing
    let boundary = BoundaryConstraints {
        initial_acc: rows.first().unwrap()[0],
        final_acc: rows.last().unwrap()[0],
    };
    let (trace_root, _) =
        phase1_commit::commit_trace_streaming(&mut replay, &prover_config, &boundary)?;
    Ok(trace_root)
}
