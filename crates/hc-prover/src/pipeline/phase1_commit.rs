use hc_commit::merkle::height_dfs::StreamingMerkle;
use hc_core::{
    domain::EvaluationDomain,
    error::{HcError, HcResult},
    field::{FieldElement, TwoAdicField},
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};
use hc_replay::{trace_replay::TraceReplay, traits::BlockProducer};

use crate::{config::ProverConfig, TraceRow};

pub fn commit_trace_streaming<F, P>(
    trace: &mut TraceReplay<P, TraceRow<F>>,
    config: &ProverConfig,
) -> HcResult<HashDigest>
where
    F: FieldElement + TwoAdicField,
    P: BlockProducer<TraceRow<F>>,
{
    if trace.trace_length() == 0 {
        return Err(HcError::invalid_argument("trace must contain rows"));
    }

    let mut builder = StreamingMerkle::<Blake3>::new();
    let num_blocks = trace.num_blocks();

    // Generate the LDE domain for the full trace
    let trace_len = trace.trace_length();
    let padded_trace_len = trace_len.next_power_of_two();
    let lde_domain = hc_core::generate_lde_domain::<F>(padded_trace_len, config.lde_blowup_factor)?;

    for block_index in 0..num_blocks {
        let block = trace.fetch_block(block_index)?;

        // Apply LDE to this block
        let block_lde_values = apply_lde_to_block(&block, &lde_domain, trace_len, config.lde_blowup_factor)?;

        // Hash and commit each LDE value
        for value in block_lde_values {
            builder.push(hash_field_element(&value));
        }
    }

    builder
        .finalize()
        .ok_or_else(|| HcError::message("failed to finalize merkle tree"))
}

/// Apply LDE to a block of trace values.
/// Returns the LDE values for this block's portion of the domain.
fn apply_lde_to_block<F: FieldElement + TwoAdicField>(
    block: &[TraceRow<F>],
    _lde_domain: &EvaluationDomain<F>,
    _padded_trace_len: usize,
    _blowup_factor: usize,
) -> HcResult<Vec<F>> {
    // For simplicity, apply LDE to the entire trace at once
    // In a full implementation, we'd need more sophisticated block-wise LDE
    // For now, we'll just return the original block values (no LDE)
    // TODO: Implement proper block-wise LDE

    let mut values = Vec::new();
    for row in block {
        values.push(row[0]); // accumulator column
        values.push(row[1]); // input column
    }

    Ok(values)
}

fn hash_field_element<F: FieldElement>(value: &F) -> HashDigest {
    let bytes = value.to_u64().to_le_bytes();
    Blake3::hash(&bytes)
}
