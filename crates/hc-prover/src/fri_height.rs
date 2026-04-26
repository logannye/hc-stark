use hc_core::field::FieldElement;
use hc_fri::FriConfig;
use hc_fri::FriProverArtifacts;
use hc_replay::traits::BlockProducer;
use std::sync::Arc;

use crate::pipeline::phase2_fri;
use crate::pipeline::phase2_fri::FriTranscriptSeed;

pub fn prove_fri<F: FieldElement>(
    config: FriConfig,
    producer: Arc<dyn BlockProducer<F>>,
    trace_length: usize,
    seed: FriTranscriptSeed,
) -> hc_core::error::HcResult<FriProverArtifacts<F>> {
    phase2_fri::run_fri(config, producer, trace_length, seed)
}
