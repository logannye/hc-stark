use hc_core::{
    domain::generate_trace_domain,
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement},
};
use hc_fri::{
    get_folding_ratio, is_valid_query_index, oracles::FriOracle, propagate_query_index, FriConfig,
    FriFinalLayer,
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction, Transcript};
use hc_prover::kzg::{
    commitment_from_projective, deserialize_fr, deserialize_proof, goldilocks_to_fr,
    verify_proof as verify_kzg_proof,
};
use hc_prover::{
    commitment::{commitment_digest, Commitment, CommitmentScheme},
    pipeline::phase3_queries::generate_queries,
    queries::{FriQuery, QueryResponse, TraceQuery, TraceWitness},
};

use crate::{errors::VerifierError, fri_verify};

#[derive(Clone, Debug)]
pub struct Proof<F: FieldElement> {
    pub trace_commitment: Commitment,
    pub composition_commitment: Commitment,
    pub fri_proof: hc_fri::FriProof<F>,
    pub initial_acc: F,
    pub final_acc: F,
    pub query_response: Option<QueryResponse<F>>,
    pub trace_length: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCommitments {
    pub trace_commitment: HashDigest,
    pub fri_commitment: HashDigest,
}

#[derive(Clone, Debug)]
pub struct VerificationSummary<F: FieldElement> {
    pub trace_commitment_digest: HashDigest,
    pub initial_acc: F,
    pub final_acc: F,
    pub trace_length: usize,
    pub query_commitments: QueryCommitments,
    pub commitment_scheme: CommitmentScheme,
}

pub fn verify<F: FieldElement>(proof: &Proof<F>) -> HcResult<()> {
    verify_with_summary(proof).map(|_| ())
}

pub fn verify_with_summary<F: FieldElement>(proof: &Proof<F>) -> HcResult<VerificationSummary<F>> {
    if proof.final_acc == proof.initial_acc {
        return Err(VerifierError::InvalidPublicInputs.into());
    }

    match proof.trace_commitment.scheme() {
        CommitmentScheme::Stark => verify_stark(proof),
        CommitmentScheme::Kzg => verify_kzg(proof),
    }
}

fn verify_stark_trace_queries<F: FieldElement>(
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
        match &trace_query.witness {
            TraceWitness::Merkle(path) => {
                if !path.verify::<Blake3>(trace_root, leaf_hash) {
                    return Err(VerifierError::TraceQueryMerkleMismatch.into());
                }
            }
            TraceWitness::Kzg(_) => {
                return Err(VerifierError::TraceWitnessUnsupported.into());
            }
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

            let leaf_hash = hc_fri::layer::FriLayer::<F>::hash_value(&recorded.evaluation);
            if !recorded
                .merkle_path
                .verify::<Blake3>(layer.merkle_root(), leaf_hash)
            {
                return Err(VerifierError::FriQueryMerkleMismatch.into());
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
                {
                    return Err(VerifierError::FriQueryEvaluationMismatch.into());
                }
                let expected = proof.fri_proof.final_layer.evaluations()[final_query];
                if recorded.evaluation != expected {
                    return Err(VerifierError::FriQueryEvaluationMismatch.into());
                }
                let leaf_hash = FriFinalLayer::hash_leaf(&recorded.evaluation);
                if !recorded
                    .merkle_path
                    .verify::<Blake3>(proof.fri_proof.final_layer.merkle_root(), leaf_hash)
                {
                    return Err(VerifierError::FriQueryMerkleMismatch.into());
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

fn commit_trace_queries<F: FieldElement>(queries: &[TraceQuery<F>]) -> HashDigest {
    let mut ordered: Vec<&TraceQuery<F>> = queries.iter().collect();
    ordered.sort_by_key(|query| query.index);

    let mut transcript = Transcript::<Blake3>::new(b"trace_query_commitment");
    for query in ordered {
        let index_bytes = (query.index as u64).to_le_bytes();
        transcript.append_message(b"trace_index", index_bytes);
        let eval0_bytes = query.evaluation[0].to_u64().to_le_bytes();
        transcript.append_message(b"trace_eval_0", eval0_bytes);
        let eval1_bytes = query.evaluation[1].to_u64().to_le_bytes();
        transcript.append_message(b"trace_eval_1", eval1_bytes);
    }

    transcript.challenge_bytes(b"trace_queries_digest")
}

fn commit_fri_queries<F: FieldElement>(queries: &[FriQuery<F>]) -> HashDigest {
    let mut ordered: Vec<&FriQuery<F>> = queries.iter().collect();
    ordered.sort_by(|a, b| {
        a.layer_index
            .cmp(&b.layer_index)
            .then_with(|| a.query_index.cmp(&b.query_index))
    });

    let mut transcript = Transcript::<Blake3>::new(b"fri_query_commitment");
    for query in ordered {
        let layer_bytes = (query.layer_index as u64).to_le_bytes();
        transcript.append_message(b"fri_layer", layer_bytes);
        let index_bytes = (query.query_index as u64).to_le_bytes();
        transcript.append_message(b"fri_index", index_bytes);
        let eval_bytes = query.evaluation.to_u64().to_le_bytes();
        transcript.append_message(b"fri_eval", eval_bytes);
    }

    transcript.challenge_bytes(b"fri_queries_digest")
}

fn verify_stark<F: FieldElement>(proof: &Proof<F>) -> HcResult<VerificationSummary<F>> {
    let trace_root = proof
        .trace_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for Stark commitment"))?;

    let query_response = proof
        .query_response
        .as_ref()
        .ok_or(VerifierError::MissingQueryResponses)?;

    let mut transcript = Transcript::<Blake3>::new(b"hc-stark");
    let initial_bytes = proof.initial_acc.to_u64().to_le_bytes();
    transcript.append_message(b"initial_acc", initial_bytes);
    let final_bytes = proof.final_acc.to_u64().to_le_bytes();
    transcript.append_message(b"final_acc", final_bytes);

    let base_queries = generate_queries::<F>(
        &mut transcript,
        proof.trace_length,
        query_response.trace_queries.len(),
    )?;

    verify_stark_trace_queries::<F>(trace_root, query_response, &base_queries)?;
    verify_fri_queries::<F>(proof, &base_queries, query_response)?;

    let config = FriConfig::new(2)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;

    let query_commitments = QueryCommitments {
        trace_commitment: commit_trace_queries(&query_response.trace_queries),
        fri_commitment: commit_fri_queries(&query_response.fri_queries),
    };

    Ok(VerificationSummary {
        trace_commitment_digest: commitment_digest(&proof.trace_commitment),
        initial_acc: proof.initial_acc,
        final_acc: proof.final_acc,
        trace_length: proof.trace_length,
        query_commitments,
        commitment_scheme: CommitmentScheme::Stark,
    })
}

fn verify_kzg<F: FieldElement>(proof: &Proof<F>) -> HcResult<VerificationSummary<F>> {
    if proof.query_response.is_none() {
        // Backward compatibility with legacy proofs that did not bundle witnesses.
        return verify_kzg_legacy(proof);
    }

    let query_response = proof
        .query_response
        .as_ref()
        .ok_or(VerifierError::MissingQueryResponses)?;

    let mut transcript = Transcript::<Blake3>::new(b"hc-stark");
    let initial_bytes = proof.initial_acc.to_u64().to_le_bytes();
    transcript.append_message(b"initial_acc", initial_bytes);
    let final_bytes = proof.final_acc.to_u64().to_le_bytes();
    transcript.append_message(b"final_acc", final_bytes);

    let base_queries = generate_queries::<F>(
        &mut transcript,
        proof.trace_length,
        query_response.trace_queries.len(),
    )?;

    verify_kzg_trace_queries(proof, query_response, &base_queries)?;

    let query_commitments = QueryCommitments {
        trace_commitment: commit_trace_queries(&query_response.trace_queries),
        fri_commitment: commit_fri_queries(&query_response.fri_queries),
    };

    Ok(VerificationSummary {
        trace_commitment_digest: commitment_digest(&proof.trace_commitment),
        initial_acc: proof.initial_acc,
        final_acc: proof.final_acc,
        trace_length: proof.trace_length,
        query_commitments,
        commitment_scheme: CommitmentScheme::Kzg,
    })
}

fn verify_kzg_trace_queries<F: FieldElement>(
    proof: &Proof<F>,
    query_response: &QueryResponse<F>,
    base_queries: &[usize],
) -> HcResult<()> {
    let points = match &proof.trace_commitment {
        Commitment::Kzg { points } if !points.is_empty() => points,
        _ => return Err(VerifierError::TraceKzgCommitmentMissing.into()),
    };

    let mut commitments = Vec::with_capacity(points.len());
    for point in points {
        commitments.push(commitment_from_projective(point));
    }

    let mut expected_indices = base_queries.to_vec();
    expected_indices.sort_unstable();

    let mut reported_indices: Vec<usize> = query_response
        .trace_queries
        .iter()
        .map(|query| query.index)
        .collect();
    reported_indices.sort_unstable();

    if expected_indices != reported_indices {
        return Err(VerifierError::QueryIndexMismatch.into());
    }

    let padded_length = proof.trace_length.next_power_of_two();
    let domain = generate_trace_domain::<GoldilocksField>(padded_length)?;

    for trace_query in &query_response.trace_queries {
        let witness = match &trace_query.witness {
            TraceWitness::Kzg(witness) => witness,
            TraceWitness::Merkle(_) => return Err(VerifierError::TraceKzgWitnessMissing.into()),
        };

        if witness.proofs.len() != commitments.len() {
            return Err(VerifierError::TraceKzgWitnessMissing.into());
        }

        let expected_point = goldilocks_to_fr(domain.element(trace_query.index));
        let provided_point = deserialize_fr(&witness.point)?;
        if provided_point != expected_point {
            return Err(VerifierError::KzgPointMismatch.into());
        }

        for proof_data in &witness.proofs {
            let column = proof_data.column;
            if column >= commitments.len() {
                return Err(VerifierError::KzgUnknownColumn(column).into());
            }
            let proof = deserialize_proof(&proof_data.proof)?;
            let value = match witness.evaluations.get(column) {
                Some(bytes) if !bytes.is_empty() => deserialize_fr(bytes)?,
                _ => {
                    let eval = match column {
                        0 => trace_query.evaluation[0],
                        1 => trace_query.evaluation[1],
                        other => return Err(VerifierError::KzgUnknownColumn(other).into()),
                    };
                    let eval_gl = GoldilocksField::from_u64(eval.to_u64());
                    goldilocks_to_fr(eval_gl)
                }
            };

            let valid = verify_kzg_proof(&commitments[column], provided_point, value, &proof)?;
            if !valid {
                return Err(VerifierError::KzgProofInvalid.into());
            }
        }
    }

    Ok(())
}

fn verify_kzg_legacy<F: FieldElement>(proof: &Proof<F>) -> HcResult<VerificationSummary<F>> {
    Ok(VerificationSummary {
        trace_commitment_digest: commitment_digest(&proof.trace_commitment),
        initial_acc: proof.initial_acc,
        final_acc: proof.final_acc,
        trace_length: proof.trace_length,
        query_commitments: mock_query_commitments(&proof.trace_commitment),
        commitment_scheme: CommitmentScheme::Kzg,
    })
}

fn mock_query_commitments(commitment: &Commitment) -> QueryCommitments {
    let digest = commitment_digest(commitment);
    QueryCommitments {
        trace_commitment: digest,
        fri_commitment: digest,
    }
}
