use hc_commit::merkle::reconstruct_path_from_replay;
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_fri::{
    get_folding_ratio, is_valid_query_index, oracles::FriOracle, propagate_query_index, FriProof,
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction};
use hc_replay::{trace_replay::TraceReplay, traits::BlockProducer};

use crate::{queries::FriQuery, TraceRow};

/// Generate verifier challenge query indices using Fiat-Shamir
pub fn generate_queries<F: FieldElement>(
    transcript: &mut hc_hash::Transcript<Blake3>,
    trace_length: usize,
    num_queries: usize,
) -> HcResult<Vec<usize>> {
    let mut queries = Vec::with_capacity(num_queries);

    for i in 0..num_queries {
        transcript.append_message(b"query_round", &i.to_le_bytes());
        let challenge = transcript.challenge_field::<F>(b"query_index");
        // Map field element to index in trace
        let index = challenge.to_u64() as usize % trace_length;
        queries.push(index);
    }

    Ok(queries)
}

/// Answer queries for trace evaluations and Merkle paths
pub fn answer_trace_queries<F, P>(
    queries: &[usize],
    trace_replay: &mut TraceReplay<P, TraceRow<F>>,
) -> HcResult<Vec<crate::queries::TraceQuery<F>>>
where
    F: FieldElement + Clone,
    P: BlockProducer<TraceRow<F>>,
{
    let mut results = Vec::with_capacity(queries.len());

    // Group queries by block for efficiency
    let mut queries_by_block: std::collections::HashMap<usize, Vec<usize>> =
        std::collections::HashMap::new();

    for &query_idx in queries {
        let block_idx = query_idx / trace_replay.block_size();
        queries_by_block
            .entry(block_idx)
            .or_insert_with(Vec::new)
            .push(query_idx);
    }

    let trace_len = trace_replay.trace_length();
    let mut trace_hashes = Vec::with_capacity(trace_len);
    for block_index in 0..trace_replay.num_blocks() {
        let block = trace_replay.fetch_block(block_index)?;
        for row in block.iter() {
            trace_hashes.push(hash_trace_row(row));
        }
    }

    for (block_idx, block_queries) in queries_by_block {
        let block_size = trace_replay.block_size();
        let block_offset = block_idx * block_size;

        // Replay this block
        {
            let block = trace_replay.fetch_block(block_idx)?;
            let mut query_payloads = Vec::with_capacity(block_queries.len());

            for &query_idx in &block_queries {
                let in_block_idx = query_idx - block_offset;
                let evaluation = block[in_block_idx].clone();
                query_payloads.push((query_idx, evaluation));
            }

            for (query_idx, evaluation) in query_payloads {
                let producer = |leaf_index: usize| trace_hashes[leaf_index];

                let merkle_path =
                    reconstruct_path_from_replay::<Blake3, _>(query_idx, trace_len, &producer)
                        .map_err(|err| {
                            HcError::message(format!("Failed to extract Merkle path: {}", err))
                        })?;

                results.push(crate::queries::TraceQuery {
                    index: query_idx,
                    evaluation,
                    merkle_path,
                });
            }
        }
    }

    // Sort results by query index for deterministic output
    results.sort_by_key(|q| q.index);

    Ok(results)
}

/// Answer queries for FRI layer evaluations and Merkle paths
pub fn answer_fri_queries<F>(
    base_queries: &[usize],
    fri_proof: &FriProof<F>,
) -> HcResult<Vec<FriQuery<F>>>
where
    F: FieldElement,
{
    let folding_ratio = get_folding_ratio();
    let mut results = Vec::new();

    for &base_query in base_queries {
        let mut current_query = base_query;

        for (layer_idx, layer) in fri_proof.layers.iter().enumerate() {
            // Check if query is valid for this layer
            if !is_valid_query_index(current_query, layer.len()) {
                continue; // Skip invalid queries
            }

            // Get evaluation at current query position
            let evaluation = layer.oracle.evaluations()[current_query];

            // For FRI layers, we need to extract Merkle paths
            // This requires the layer's Merkle commitment
            // For now, we'll use a simplified approach
            // TODO: Implement proper FRI layer Merkle path extraction

            // Create a placeholder Merkle path (this needs proper implementation)
            let merkle_path = hc_commit::merkle::MerklePath::new(vec![]);

            results.push(FriQuery {
                layer_index: layer_idx,
                query_index: current_query,
                evaluation,
                merkle_path,
            });

            // Propagate to next layer
            current_query = propagate_query_index(current_query, folding_ratio);
        }

        // Handle final layer
        if !fri_proof.final_layer.is_empty() {
            let final_query = propagate_query_index(current_query, folding_ratio);
            if is_valid_query_index(final_query, fri_proof.final_layer.len()) {
                let evaluation = fri_proof.final_layer[final_query];
                let merkle_path = hc_commit::merkle::MerklePath::new(vec![]); // Placeholder

                results.push(FriQuery {
                    layer_index: fri_proof.layers.len(),
                    query_index: final_query,
                    evaluation,
                    merkle_path,
                });
            }
        }
    }

    Ok(results)
}

/// Build complete query response including both trace and FRI queries
pub fn build_queries<F, P>(
    transcript: &mut hc_hash::Transcript<Blake3>,
    trace_replay: &mut TraceReplay<P, TraceRow<F>>,
    fri_proof: &FriProof<F>,
    num_queries: usize,
) -> HcResult<crate::queries::QueryResponse<F>>
where
    F: FieldElement + Clone,
    P: BlockProducer<TraceRow<F>>,
{
    let trace_length = trace_replay.trace_length();
    let query_indices = generate_queries::<F>(transcript, trace_length, num_queries)?;

    let trace_queries = answer_trace_queries(&query_indices, trace_replay)?;
    let fri_queries = answer_fri_queries(&query_indices, fri_proof)?;

    Ok(crate::queries::QueryResponse {
        trace_queries,
        fri_queries,
    })
}

fn hash_trace_row<F: FieldElement>(row: &TraceRow<F>) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&row[0].to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&row[1].to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}
