use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::{FriConfig, FriProver, FriProverArtifacts};
use hc_hash::protocol;
use hc_hash::Blake3;
use hc_hash::HashDigest;
use hc_replay::traits::BlockProducer;
use std::sync::Arc;

use crate::transcript::ProverTranscript;

#[derive(Clone, Copy, Debug)]
pub struct FriTranscriptSeed {
    pub protocol_version: u32,
    pub initial_acc: u64,
    pub final_acc: u64,
    pub trace_length: u64,
    pub query_count: u64,
    pub lde_blowup: u64,
    pub fri_final_size: u64,
    pub folding_ratio: u64,
    pub zk_enabled: bool,
    pub zk_mask_degree: u64,
    pub trace_commitment: HashDigest,
    pub composition_commitment: HashDigest,
}

pub fn run_fri<F: FieldElement>(
    config: FriConfig,
    producer: Arc<dyn BlockProducer<F>>,
    trace_length: usize,
    seed: FriTranscriptSeed,
) -> HcResult<FriProverArtifacts<F>> {
    let domain = if seed.protocol_version >= 4 {
        protocol::DOMAIN_FRI_V4
    } else if seed.protocol_version >= 3 {
        protocol::DOMAIN_FRI_V3
    } else {
        protocol::DOMAIN_FRI_V2
    };
    let mut transcript = ProverTranscript::new(domain);
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_INITIAL_ACC,
        seed.initial_acc,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_FINAL_ACC,
        seed.final_acc,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        seed.trace_length,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        seed.query_count,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        seed.lde_blowup,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        seed.fri_final_size,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        seed.folding_ratio,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    if seed.protocol_version >= 4 {
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_ZK_ENABLED,
            u64::from(seed.zk_enabled),
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_ZK_MASK_DEGREE,
            seed.zk_mask_degree,
        );
    }
    transcript.append_message(
        if seed.protocol_version >= 3 {
            protocol::label::COMMIT_TRACE_LDE_ROOT
        } else {
            protocol::label::COMMIT_TRACE_ROOT
        },
        seed.trace_commitment.as_bytes(),
    );
    transcript.append_message(
        if seed.protocol_version >= 3 {
            protocol::label::COMMIT_QUOTIENT_ROOT
        } else {
            protocol::label::COMMIT_COMPOSITION_ROOT
        },
        seed.composition_commitment.as_bytes(),
    );
    let mut prover = FriProver::<F, Blake3>::new(config, &mut transcript);
    prover.prove_with_producer(producer, trace_length)
}
