use hc_air::constraints::boundary::BoundaryConstraints;
use hc_core::{
    error::{HcError, HcResult},
    field::{FieldElement, TwoAdicField},
};
use hc_hash::hash::HashDigest;
use hc_replay::{config::ReplayConfig, trace_replay::TraceReplay};

use crate::{
    commitment::CommitmentScheme, config::ProverConfig, pipeline::phase1_commit,
    trace_stream::SliceTraceProducer, TraceRow,
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
    let commitments =
        phase1_commit::commit_trace_streaming(&mut replay, &prover_config, &boundary)?;
    if commitments.trace_commitment.scheme() != CommitmentScheme::Stark {
        return Err(HcError::invalid_argument(
            "trace root is only defined for Stark commitments",
        ));
    }
    commitments
        .merkle_trace_root
        .ok_or_else(|| HcError::message("missing Stark trace root"))
}
