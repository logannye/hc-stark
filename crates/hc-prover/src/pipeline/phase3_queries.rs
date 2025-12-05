use crate::{
    commitment::CommitmentScheme,
    kzg::{open_polynomial, serialize_fr, serialize_proof, TraceKzgState},
    queries::{FriQuery, KzgColumnProof, KzgTraceWitness, TraceQuery, TraceWitness},
    TraceRow,
};
use ark_poly::Polynomial;
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

/// Generate verifier challenge query indices using Fiat-Shamir
pub fn generate_queries<F: FieldElement>(
    transcript: &mut hc_hash::Transcript<Blake3>,
    trace_length: usize,
    num_queries: usize,
) -> HcResult<Vec<usize>> {
    let mut queries = Vec::with_capacity(num_queries);

    for i in 0..num_queries {
        let round_bytes = i.to_le_bytes();
        transcript.append_message(b"query_round", round_bytes);
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
    scheme: CommitmentScheme,
    kzg_state: Option<&TraceKzgState>,
) -> HcResult<Vec<TraceQuery<F>>>
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
            .or_default()
            .push(query_idx);
    }

    let use_merkle = matches!(scheme, CommitmentScheme::Stark);
    let trace_hashes = if use_merkle {
        let trace_len = trace_replay.trace_length();
        let mut hashes = Vec::with_capacity(trace_len);
        for block_index in 0..trace_replay.num_blocks() {
            let block = trace_replay.fetch_block(block_index)?;
            for row in block.iter() {
                hashes.push(hash_trace_row(row));
            }
        }
        Some(hashes)
    } else {
        None
    };
    let kzg = if use_merkle {
        None
    } else {
        Some(kzg_state.expect("kzg state required for KZG commitment scheme"))
    };

    for (block_idx, block_queries) in queries_by_block {
        let block_size = trace_replay.block_size();
        let block_offset = block_idx * block_size;

        // Replay this block
        {
            let block = trace_replay.fetch_block(block_idx)?;
            let mut query_payloads = Vec::with_capacity(block_queries.len());

            for &query_idx in &block_queries {
                let in_block_idx = query_idx - block_offset;
                let evaluation = block[in_block_idx];
                query_payloads.push((query_idx, evaluation));
            }

            for (query_idx, evaluation) in query_payloads {
                let witness = if use_merkle {
                    let producer = |leaf_index: usize| trace_hashes.as_ref().unwrap()[leaf_index];
                    let merkle_path = reconstruct_path_from_replay::<Blake3, _>(
                        query_idx,
                        trace_replay.trace_length(),
                        2,
                        &producer,
                    )
                    .map_err(|err| {
                        HcError::message(format!("Failed to extract Merkle path: {err}"))
                    })?;
                    TraceWitness::Merkle(merkle_path)
                } else {
                    let state = kzg.unwrap();
                    let point = state
                        .domain_points
                        .get(query_idx)
                        .ok_or_else(|| HcError::message("missing KZG domain point"))?;
                    let mut column_proofs = Vec::with_capacity(state.polynomials.len());
                    let mut column_evals = Vec::with_capacity(state.polynomials.len());
                    for (column, ((poly, randomness), commitment)) in state
                        .polynomials
                        .iter()
                        .zip(state.randomness.iter())
                        .zip(state.commitments.iter())
                        .enumerate()
                    {
                        let eval_fr = poly.evaluate(point);
                        column_evals.push(serialize_fr(&eval_fr)?);
                        let proof = open_polynomial(poly, *point, randomness)?;
                        #[cfg(debug_assertions)]
                        {
                            use crate::kzg::verify_proof as check_kzg_proof;
                            let eval_value = eval_fr;
                            debug_assert!(
                                check_kzg_proof(commitment, *point, eval_value, &proof)?,
                                "generated invalid KZG proof"
                            );
                        }
                        column_proofs.push(KzgColumnProof {
                            column,
                            proof: serialize_proof(&proof)?,
                        });
                    }
                    TraceWitness::Kzg(KzgTraceWitness {
                        point: serialize_fr(point)?,
                        proofs: column_proofs,
                        evaluations: column_evals,
                    })
                };

                results.push(TraceQuery {
                    index: query_idx,
                    evaluation,
                    witness,
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
    let per_query: HcResult<Vec<Vec<FriQuery<F>>>> = base_queries
        .iter()
        .map(|&base_query| {
            let mut local = Vec::new();
            let mut current_query = base_query;

            for (layer_idx, layer) in fri_proof.layers.iter().enumerate() {
                if !is_valid_query_index(current_query, layer.len()) {
                    continue;
                }

                let evaluation = layer.oracle.evaluations()[current_query];
                let merkle_path = layer.merkle_path(current_query).map_err(|err| {
                    HcError::message(format!("Failed to extract FRI Merkle path: {err}"))
                })?;

                local.push(FriQuery {
                    layer_index: layer_idx,
                    query_index: current_query,
                    evaluation,
                    merkle_path,
                });
                current_query = propagate_query_index(current_query, folding_ratio);
            }

            if !fri_proof.final_layer.is_empty() {
                let final_query = propagate_query_index(current_query, folding_ratio);
                if is_valid_query_index(final_query, fri_proof.final_layer.len()) {
                    let evaluation = fri_proof.final_layer.evaluations()[final_query];
                    let merkle_path =
                        fri_proof
                            .final_layer
                            .merkle_path(final_query)
                            .map_err(|err| {
                                HcError::message(format!(
                                    "Failed to extract final FRI layer Merkle path: {err}"
                                ))
                            })?;
                    local.push(FriQuery {
                        layer_index: fri_proof.layers.len(),
                        query_index: final_query,
                        evaluation,
                        merkle_path,
                    });
                }
            }

            Ok(local)
        })
        .collect();

    Ok(per_query?.into_iter().flatten().collect())
}

/// Build complete query response including both trace and FRI queries
pub fn build_queries<F, P>(
    transcript: &mut hc_hash::Transcript<Blake3>,
    trace_replay: &mut TraceReplay<P, TraceRow<F>>,
    fri_proof: &FriProof<F>,
    num_queries: usize,
    scheme: CommitmentScheme,
    kzg_state: Option<&TraceKzgState>,
) -> HcResult<crate::queries::QueryResponse<F>>
where
    F: FieldElement + Clone,
    P: BlockProducer<TraceRow<F>>,
{
    let trace_length = trace_replay.trace_length();
    let query_indices = generate_queries::<F>(transcript, trace_length, num_queries)?;

    let trace_queries = answer_trace_queries(&query_indices, trace_replay, scheme, kzg_state)?;
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
