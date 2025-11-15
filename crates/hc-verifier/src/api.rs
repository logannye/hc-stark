use hc_core::{error::HcResult, field::FieldElement};
use hc_fri::{
    get_folding_ratio, is_valid_query_index, oracles::FriOracle, propagate_query_index, FriConfig,
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction, Transcript};
use hc_prover::{pipeline::phase3_queries::generate_queries, queries::QueryResponse};

use crate::{errors::VerifierError, fri_verify};

#[derive(Clone, Debug)]
pub struct Proof<F: FieldElement> {
    pub trace_root: HashDigest,
    pub fri_proof: hc_fri::FriProof<F>,
    pub initial_acc: F,
    pub final_acc: F,
    pub query_response: Option<QueryResponse<F>>,
    pub trace_length: usize,
}

pub fn verify<F: FieldElement>(proof: &Proof<F>) -> HcResult<()> {
    if proof.final_acc == proof.initial_acc {
        return Err(VerifierError::InvalidPublicInputs.into());
    }

    let query_response = proof
        .query_response
        .as_ref()
        .ok_or(VerifierError::MissingQueryResponses)?;

    let mut transcript = Transcript::<Blake3>::new(b"hc-stark");
    transcript.append_message(b"initial_acc", &proof.initial_acc.to_u64().to_le_bytes());
    transcript.append_message(b"final_acc", &proof.final_acc.to_u64().to_le_bytes());

    let base_queries = generate_queries::<F>(
        &mut transcript,
        proof.trace_length,
        query_response.trace_queries.len(),
    )?;

    verify_trace_queries::<F>(proof.trace_root, query_response, &base_queries)?;
    verify_fri_queries::<F>(proof, &base_queries, query_response)?;

    let config = FriConfig::new(2)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;

    Ok(())
}

fn verify_trace_queries<F: FieldElement>(
    trace_root: HashDigest,
    query_response: &QueryResponse<F>,
    base_queries: &[usize],
) -> HcResult<()> {
    let mut expected_indices = base_queries.to_vec();
    expected_indices.sort_unstable();

    let mut reported_indices: Vec<usize> = query_response
        .trace_queries
        .iter()
        .map(|query| query.index)
        .collect();
    reported_indices.sort_unstable();

    if reported_indices != expected_indices {
        return Err(VerifierError::QueryIndexMismatch.into());
    }

    for trace_query in &query_response.trace_queries {
        let leaf_hash = hash_trace_row(&trace_query.evaluation);
        if !trace_query
            .merkle_path
            .verify::<Blake3>(trace_root, leaf_hash)
        {
            return Err(VerifierError::TraceQueryMerkleMismatch.into());
        }
    }

    Ok(())
}

fn verify_fri_queries<F: FieldElement>(
    proof: &Proof<F>,
    base_queries: &[usize],
    query_response: &QueryResponse<F>,
) -> HcResult<()> {
    let mut fri_iter = query_response.fri_queries.iter();
    let folding_ratio = get_folding_ratio();

    for &base_query in base_queries {
        let mut current_query = base_query;
        for (layer_idx, layer) in proof.fri_proof.layers.iter().enumerate() {
            if !is_valid_query_index(current_query, layer.len()) {
                continue;
            }

            let recorded = fri_iter
                .next()
                .ok_or(VerifierError::FriQueryCountMismatch)?;
            if recorded.layer_index != layer_idx || recorded.query_index != current_query {
                return Err(VerifierError::FriQueryIndexMismatch.into());
            }

            let expected = layer.oracle.evaluations()[current_query];
            if recorded.evaluation != expected {
                return Err(VerifierError::FriQueryEvaluationMismatch.into());
            }

            current_query = propagate_query_index(current_query, folding_ratio);
        }

        if !proof.fri_proof.final_layer.is_empty() {
            let final_query = propagate_query_index(current_query, folding_ratio);
            if is_valid_query_index(final_query, proof.fri_proof.final_layer.len()) {
                let recorded = fri_iter
                    .next()
                    .ok_or(VerifierError::FriQueryCountMismatch)?;
                if recorded.layer_index != proof.fri_proof.layers.len()
                    || recorded.query_index != final_query
                    || recorded.evaluation != proof.fri_proof.final_layer[final_query]
                {
                    return Err(VerifierError::FriQueryEvaluationMismatch.into());
                }
            }
        }
    }

    if fri_iter.next().is_some() {
        return Err(VerifierError::FriQueryCountMismatch.into());
    }

    Ok(())
}

fn hash_trace_row<F: FieldElement>(row: &[F; 2]) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&row[0].to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&row[1].to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}
