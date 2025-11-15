use hc_core::{
    error::{HcError, HcResult},
    field::{FieldElement, TwoAdicField},
};
use hc_replay::{config::ReplayConfig, trace_replay::TraceReplay};

use crate::{config::ProverConfig, pipeline::phase1_commit, trace_stream::SliceTraceProducer, TraceRow};

pub fn compute_root<F: FieldElement + TwoAdicField>(rows: &[TraceRow<F>]) -> HcResult<hc_hash::hash::HashDigest> {
    if rows.is_empty() {
        return Err(HcError::invalid_argument("trace must contain rows"));
    }
    let producer = SliceTraceProducer { rows };
    let config = ReplayConfig::new(rows.len(), rows.len())?;
    let mut replay = TraceReplay::new(config, producer)?;
    let prover_config = ProverConfig::new(1, 1)?; // Simple config for testing
    phase1_commit::commit_trace_streaming(&mut replay, &prover_config)
}
