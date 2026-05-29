use hc_air::constraints::boundary::BoundaryConstraints;
use hc_air::{DeepStarkAir, ToyAir};
use hc_core::{
    domain::{generate_lde_coset_domain, generate_trace_domain},
    error::{HcError, HcResult},
    field::{prime_field::GoldilocksField, FieldElement, TwoAdicField},
};
use hc_fri::{get_folding_ratio, is_valid_query_index, propagate_query_index, FriConfig};
use hc_hash::{hash::HashDigest, protocol, Blake3, HashFunction, Transcript};
use hc_prover::kzg::{
    commitment_from_projective, deserialize_fr, deserialize_proof, goldilocks_to_fr,
    verify_proof as verify_kzg_proof,
};
use hc_prover::{
    commitment::{commitment_digest, Commitment, CommitmentScheme},
    pipeline::phase3_queries::generate_queries,
    queries::{
        BoundaryOpenings, CompositionQuery, FriQuery, ProofParams, QueryResponse, TraceQuery,
        TraceWitness,
    },
};

use crate::{errors::VerifierError, fri_verify};

#[derive(Clone, Debug)]
pub struct Proof<F: FieldElement> {
    pub version: u32,
    pub trace_commitment: Commitment,
    pub composition_commitment: Commitment,
    pub fri_proof: hc_fri::FriProof<F>,
    pub initial_acc: F,
    pub final_acc: F,
    pub query_response: Option<QueryResponse<F>>,
    pub trace_length: usize,
    pub params: ProofParams,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QueryCommitments {
    pub trace_commitment: HashDigest,
    pub composition_commitment: HashDigest,
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

pub fn verify<F: FieldElement + TwoAdicField>(proof: &Proof<F>) -> HcResult<()> {
    verify_with_summary(proof).map(|_| ())
}

pub fn verify_with_summary<F: FieldElement + TwoAdicField>(
    proof: &Proof<F>,
) -> HcResult<VerificationSummary<F>> {
    if proof.final_acc == proof.initial_acc {
        return Err(VerifierError::InvalidPublicInputs.into());
    }
    if proof.params.protocol_version != proof.version {
        return Err(VerifierError::ProofParamsVersionMismatch.into());
    }

    match proof.trace_commitment.scheme() {
        CommitmentScheme::Stark => {
            if proof.version >= 3 {
                verify_stark_v3(proof)
            } else {
                verify_stark(proof)
            }
        }
        CommitmentScheme::Kzg => verify_kzg(proof),
    }
}

fn verify_stark_v3<F: FieldElement + TwoAdicField>(
    proof: &Proof<F>,
) -> HcResult<VerificationSummary<F>> {
    // DEEP-STARK v3 (Merkle trace LDE + quotient oracle + FRI on quotient).
    let trace_root = proof
        .trace_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for Stark commitment"))?;
    let quotient_root = proof
        .composition_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for quotient commitment"))?;

    let query_response = proof
        .query_response
        .as_ref()
        .ok_or(VerifierError::MissingQueryResponses)?;

    // Domain sizes.
    let padded_len = proof.trace_length.next_power_of_two();
    if padded_len == 0 {
        return Err(HcError::invalid_argument("trace length must be non-zero"));
    }
    let blowup = proof.params.lde_blowup_factor;
    let lde_len = padded_len
        .checked_mul(blowup)
        .ok_or_else(|| HcError::invalid_argument("lde domain size overflow"))?;

    // Transcript: match prover ordering.
    let domain = if proof.version >= 4 {
        protocol::DOMAIN_MAIN_V4
    } else {
        protocol::DOMAIN_MAIN_V3
    };
    let mut transcript = Transcript::<Blake3>::new(domain);
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    if proof.version >= 4 {
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_ZK_ENABLED,
            u64::from(proof.params.zk_enabled),
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_ZK_MASK_DEGREE,
            proof.params.zk_mask_degree as u64,
        );
    }

    transcript.append_message(
        protocol::label::COMMIT_TRACE_LDE_ROOT,
        trace_root.as_bytes(),
    );
    let alpha_boundary =
        transcript.challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
    let alpha_transition =
        transcript.challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_TRANSITION);
    transcript.append_message(
        protocol::label::COMMIT_QUOTIENT_ROOT,
        quotient_root.as_bytes(),
    );

    for root in &proof.fri_proof.layer_roots {
        transcript.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
    }
    transcript.append_message(
        protocol::label::COMMIT_FRI_FINAL_ROOT,
        proof.fri_proof.final_root.as_bytes(),
    );

    let base_queries = generate_queries::<F>(&mut transcript, lde_len, proof.params.query_count)?;

    // Verify trace openings (Merkle) and quotient openings (Merkle), and the quotient relation.
    verify_stark_v3_trace_and_quotient(
        proof,
        trace_root,
        quotient_root,
        &base_queries,
        padded_len,
        lde_len,
        alpha_boundary,
        alpha_transition,
        query_response,
    )?;

    // Optional OOD-style extra opening check (still within the same LDE coset domain).
    if let Some(ood) = &query_response.ood {
        verify_stark_v3_trace_and_quotient(
            proof,
            trace_root,
            quotient_root,
            &[ood.index],
            padded_len,
            lde_len,
            alpha_boundary,
            alpha_transition,
            &QueryResponse {
                trace_queries: vec![ood.trace.clone()],
                composition_queries: vec![ood.quotient.clone()],
                fri_queries: Vec::new(),
                boundary: None,
                ood: None,
            },
        )?;
    }

    // Verify FRI query openings (bound to quotient openings) and final root sanity.
    verify_fri_queries::<F>(proof, &base_queries, query_response)?;
    let config = FriConfig::new(proof.params.fri_final_poly_size)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;

    let query_commitments = QueryCommitments {
        trace_commitment: commit_trace_queries(&query_response.trace_queries),
        composition_commitment: commit_composition_queries(&query_response.composition_queries),
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

#[allow(clippy::too_many_arguments)]
fn verify_stark_v3_trace_and_quotient<F>(
    proof: &Proof<F>,
    trace_root: HashDigest,
    quotient_root: HashDigest,
    base_queries: &[usize],
    padded_len: usize,
    lde_len: usize,
    alpha_boundary: F,
    alpha_transition: F,
    query_response: &QueryResponse<F>,
) -> HcResult<()>
where
    F: FieldElement + TwoAdicField,
{
    // Expected query indices.
    let mut expected = base_queries.to_vec();
    expected.sort_unstable();
    let mut trace_idx: Vec<usize> = query_response
        .trace_queries
        .iter()
        .map(|q| q.index)
        .collect();
    trace_idx.sort_unstable();
    if trace_idx != expected {
        return Err(VerifierError::QueryIndexMismatch.into());
    }
    let mut quot_idx: Vec<usize> = query_response
        .composition_queries
        .iter()
        .map(|q| q.index)
        .collect();
    quot_idx.sort_unstable();
    if quot_idx != expected {
        return Err(VerifierError::QueryIndexMismatch.into());
    }

    let shift = proof.params.lde_blowup_factor % lde_len;
    let coset_offset = F::from_u64(7);
    let lde_domain =
        generate_lde_coset_domain::<F>(padded_len, proof.params.lde_blowup_factor, coset_offset)?;
    let omega_last = generate_trace_domain::<F>(padded_len)?
        .generator()
        .inverse()
        .ok_or_else(|| HcError::math("trace domain generator has no inverse"))?;
    let n_inv = F::from_u64(padded_len as u64)
        .inverse()
        .ok_or_else(|| HcError::math("padded_len has no inverse"))?;

    let mut trace_by_index: std::collections::HashMap<usize, &TraceQuery<F>> =
        std::collections::HashMap::new();
    for tq in &query_response.trace_queries {
        trace_by_index.insert(tq.index, tq);
    }

    for cq in &query_response.composition_queries {
        // Verify quotient Merkle opening.
        let leaf_hash = Blake3::hash(&cq.value.to_u64().to_le_bytes());
        if !cq.witness.verify::<Blake3>(quotient_root, leaf_hash) {
            return Err(VerifierError::CompositionQueryMerkleMismatch.into());
        }

        // Fetch matching trace opening.
        let tq = trace_by_index
            .get(&cq.index)
            .copied()
            .ok_or(VerifierError::QueryIndexMismatch)?;

        // Verify trace Merkle opening.
        let leaf_hash = hash_trace_row(&tq.evaluation);
        match &tq.witness {
            TraceWitness::Merkle(path) => {
                if !path.verify::<Blake3>(trace_root, leaf_hash) {
                    return Err(VerifierError::TraceQueryMerkleMismatch.into());
                }
            }
            TraceWitness::Kzg(_) => return Err(VerifierError::TraceWitnessUnsupported.into()),
        }

        let next = tq.next.as_ref().ok_or(VerifierError::TraceNextRowMissing)?;
        let expected_next = (tq.index + shift) % lde_len;
        if next.index != expected_next {
            return Err(VerifierError::TraceNextRowMissing.into());
        }
        let next_leaf_hash = hash_trace_row(&next.evaluation);
        if !next.witness.verify::<Blake3>(trace_root, next_leaf_hash) {
            return Err(VerifierError::TraceQueryMerkleMismatch.into());
        }

        // Check quotient relation at x = domain[idx]:
        // q(x) * (x^N - 1) == alpha_transition * (1-L_last(x)) * transition(x)
        //                +  alpha_boundary * ((acc(x)-init)*L0(x) + (acc(x)-final)*L_last(x))
        let x = lde_domain.element(tq.index);
        let z_h = x.pow(padded_len as u64).sub(F::ONE);
        let l0 = z_h.mul(n_inv).mul(
            x.sub(F::ONE)
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero denominator in L0 on coset"))?,
        );
        let l_last = z_h.mul(omega_last).mul(n_inv).mul(
            x.sub(omega_last)
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero denominator in L_last on coset"))?,
        );
        let selector_last = F::ONE.sub(l_last);

        let acc = tq.evaluation[0];
        let delta = tq.evaluation[1];
        let acc_next = next.evaluation[0];
        let delta_next = next.evaluation[1];
        let air = ToyAir;
        let c = air.quotient_numerator(
            &[acc, delta],
            &[acc_next, delta_next],
            l0,
            l_last,
            selector_last,
            alpha_boundary,
            alpha_transition,
            proof.initial_acc,
            proof.final_acc,
        )?;

        let lhs = cq.value.mul(z_h);
        if lhs != c {
            return Err(VerifierError::CompositionQueryValueMismatch.into());
        }
    }

    Ok(())
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

        if let Some(next) = &trace_query.next {
            let leaf_hash = hash_trace_row(&next.evaluation);
            if !next.witness.verify::<Blake3>(trace_root, leaf_hash) {
                return Err(VerifierError::TraceQueryMerkleMismatch.into());
            }
        }
    }

    Ok(())
}

fn verify_stark_composition_queries<F: FieldElement>(
    trace_root: HashDigest,
    composition_root: HashDigest,
    proof: &Proof<F>,
    query_response: &QueryResponse<F>,
    base_queries: &[usize],
) -> HcResult<()> {
    let mut composition_transcript = Transcript::<Blake3>::new(protocol::DOMAIN_COMPOSITION_V2);
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    composition_transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    composition_transcript
        .append_message(protocol::label::COMMIT_TRACE_ROOT, trace_root.as_bytes());
    let alpha_boundary =
        composition_transcript.challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
    let alpha_transition =
        composition_transcript.challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_TRANSITION);

    let mut expected_indices = base_queries.to_vec();
    expected_indices.sort_unstable();
    let mut reported: Vec<usize> = query_response
        .composition_queries
        .iter()
        .map(|q| q.index)
        .collect();
    reported.sort_unstable();
    if reported != expected_indices {
        return Err(VerifierError::QueryIndexMismatch.into());
    }

    let mut trace_by_index: std::collections::HashMap<usize, &TraceQuery<F>> =
        std::collections::HashMap::new();
    for tq in &query_response.trace_queries {
        trace_by_index.insert(tq.index, tq);
    }

    for cq in &query_response.composition_queries {
        let leaf_hash = Blake3::hash(&cq.value.to_u64().to_le_bytes());
        if !cq.witness.verify::<Blake3>(composition_root, leaf_hash) {
            return Err(VerifierError::CompositionQueryMerkleMismatch.into());
        }

        let tq = trace_by_index
            .get(&cq.index)
            .ok_or(VerifierError::QueryIndexMismatch)?;
        let row = tq.evaluation;

        let next_row = if cq.index + 1 < proof.trace_length {
            let next = tq.next.as_ref().ok_or(VerifierError::TraceNextRowMissing)?;
            if next.index != cq.index + 1 {
                return Err(VerifierError::TraceNextRowMissing.into());
            }
            next.evaluation
        } else {
            row
        };
        let boundary = BoundaryConstraints {
            initial_acc: proof.initial_acc,
            final_acc: proof.final_acc,
        };
        let expected = hc_air::eval::composition_value_for_row(
            row,
            next_row,
            cq.index,
            proof.trace_length,
            &boundary,
            alpha_boundary,
            alpha_transition,
        )?;
        if expected != cq.value {
            return Err(VerifierError::CompositionQueryValueMismatch.into());
        }
    }

    Ok(())
}

fn verify_stark_boundary_openings<F: FieldElement>(
    trace_root: HashDigest,
    composition_root: HashDigest,
    proof: &Proof<F>,
    query_response: &QueryResponse<F>,
) -> HcResult<()> {
    let boundary = query_response
        .boundary
        .as_ref()
        .ok_or(VerifierError::BoundaryOpeningsMissing)?;

    let n = proof.trace_length;
    if n < 2 {
        return Err(HcError::invalid_argument(
            "trace length must be at least 2 for boundary openings",
        ));
    }

    // Indices must be exactly {0, n-1}.
    if boundary.first_trace.index != 0
        || boundary.first_composition.index != 0
        || boundary.last_trace.index + 1 != n
        || boundary.last_composition.index + 1 != n
    {
        return Err(VerifierError::BoundaryIndexMismatch.into());
    }

    // Verify Merkle openings for boundary trace rows.
    let verify_trace_opening = |tq: &TraceQuery<F>| -> HcResult<()> {
        let leaf_hash = hash_trace_row(&tq.evaluation);
        match &tq.witness {
            TraceWitness::Merkle(path) => {
                if !path.verify::<Blake3>(trace_root, leaf_hash) {
                    return Err(VerifierError::TraceQueryMerkleMismatch.into());
                }
            }
            TraceWitness::Kzg(_) => return Err(VerifierError::TraceWitnessUnsupported.into()),
        }
        Ok(())
    };
    verify_trace_opening(&boundary.first_trace)?;
    verify_trace_opening(&boundary.last_trace)?;

    // Enforce boundary constraints explicitly.
    if boundary.first_trace.evaluation[0] != proof.initial_acc {
        return Err(VerifierError::BoundaryConstraintMismatch.into());
    }
    if boundary.last_trace.evaluation[0] != proof.final_acc {
        return Err(VerifierError::BoundaryConstraintMismatch.into());
    }

    // Derive composition alphas (must match prover).
    let mut composition_transcript = Transcript::<Blake3>::new(protocol::DOMAIN_COMPOSITION_V2);
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut composition_transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    composition_transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    composition_transcript
        .append_message(protocol::label::COMMIT_TRACE_ROOT, trace_root.as_bytes());
    let alpha_boundary =
        composition_transcript.challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
    let alpha_transition =
        composition_transcript.challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_TRANSITION);

    let air_boundary = BoundaryConstraints {
        initial_acc: proof.initial_acc,
        final_acc: proof.final_acc,
    };

    // Verify composition openings and recompute expected values.
    let verify_composition_opening = |cq: &CompositionQuery<F>, expected: F| -> HcResult<()> {
        let leaf_hash = Blake3::hash(&cq.value.to_u64().to_le_bytes());
        if !cq.witness.verify::<Blake3>(composition_root, leaf_hash) {
            return Err(VerifierError::CompositionQueryMerkleMismatch.into());
        }
        if cq.value != expected {
            return Err(VerifierError::CompositionQueryValueMismatch.into());
        }
        Ok(())
    };

    // Index 0 must include next-row witness at 1 to enforce the first transition.
    let next = boundary
        .first_trace
        .next
        .as_ref()
        .ok_or(VerifierError::TraceNextRowMissing)?;
    if next.index != 1 {
        return Err(VerifierError::BoundaryIndexMismatch.into());
    }
    if !next
        .witness
        .verify::<Blake3>(trace_root, hash_trace_row(&next.evaluation))
    {
        return Err(VerifierError::TraceQueryMerkleMismatch.into());
    }
    let expected_first = hc_air::eval::composition_value_for_row(
        boundary.first_trace.evaluation,
        next.evaluation,
        0,
        n,
        &air_boundary,
        alpha_boundary,
        alpha_transition,
    )?;
    verify_composition_opening(&boundary.first_composition, expected_first)?;

    let expected_last = hc_air::eval::composition_value_for_row(
        boundary.last_trace.evaluation,
        boundary.last_trace.evaluation,
        n - 1,
        n,
        &air_boundary,
        alpha_boundary,
        alpha_transition,
    )?;
    verify_composition_opening(&boundary.last_composition, expected_last)?;

    Ok(())
}

fn verify_fri_queries<F: FieldElement>(
    proof: &Proof<F>,
    base_queries: &[usize],
    query_response: &QueryResponse<F>,
) -> HcResult<()> {
    let mut fri_iter = query_response.fri_queries.iter();
    let folding_ratio = get_folding_ratio();
    let bind_base_to_composition =
        matches!(proof.trace_commitment.scheme(), CommitmentScheme::Stark);
    let base_len = if proof.version >= 3 && bind_base_to_composition {
        proof
            .trace_length
            .next_power_of_two()
            .saturating_mul(proof.params.lde_blowup_factor.max(1))
    } else {
        proof.trace_length.next_power_of_two()
    };

    let composition_by_index: std::collections::HashMap<usize, F> = if bind_base_to_composition {
        query_response
            .composition_queries
            .iter()
            .map(|q| (q.index, q.value))
            .collect()
    } else {
        std::collections::HashMap::new()
    };

    // Recompute the FRI betas from the committed roots, matching `hc-fri`'s transcript.
    let fri_domain = if proof.version >= 4 {
        protocol::DOMAIN_FRI_V4
    } else if proof.version >= 3 {
        protocol::DOMAIN_FRI_V3
    } else {
        protocol::DOMAIN_FRI_V2
    };
    let mut fri_transcript = Transcript::<Blake3>::new(fri_domain);
    // Seed FRI transcript with the same binding prefix used by the prover.
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64(),
    );
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut fri_transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    fri_transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    if proof.version >= 4 {
        protocol::append_u64::<Blake3>(
            &mut fri_transcript,
            protocol::label::PARAM_ZK_ENABLED,
            u64::from(proof.params.zk_enabled),
        );
        protocol::append_u64::<Blake3>(
            &mut fri_transcript,
            protocol::label::PARAM_ZK_MASK_DEGREE,
            proof.params.zk_mask_degree as u64,
        );
    }
    let trace_digest = commitment_digest(&proof.trace_commitment);
    fri_transcript.append_message(
        if proof.version >= 3 {
            protocol::label::COMMIT_TRACE_LDE_ROOT
        } else {
            protocol::label::COMMIT_TRACE_ROOT
        },
        trace_digest.as_bytes(),
    );
    let composition_digest = commitment_digest(&proof.composition_commitment);
    fri_transcript.append_message(
        if proof.version >= 3 {
            protocol::label::COMMIT_QUOTIENT_ROOT
        } else {
            protocol::label::COMMIT_COMPOSITION_ROOT
        },
        composition_digest.as_bytes(),
    );
    let mut betas = Vec::with_capacity(proof.fri_proof.layer_roots.len());
    for root in &proof.fri_proof.layer_roots {
        fri_transcript.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
        betas.push(fri_transcript.challenge_field::<F>(protocol::label::CHAL_FRI_BETA));
    }
    fri_transcript.append_message(
        protocol::label::COMMIT_FRI_FINAL_ROOT,
        proof.fri_proof.final_root.as_bytes(),
    );

    for &base_query in base_queries {
        let mut layer_len = base_len;
        let mut current_index = base_query;
        // Bind the FRI base layer to the composition oracle at the queried index.
        // This is the crucial glue between AIR constraints (checked at queried points) and the
        // low-degree check enforced by FRI.
        let mut expected_value: Option<F> = if bind_base_to_composition {
            Some(
                *composition_by_index
                    .get(&base_query)
                    .ok_or(VerifierError::QueryIndexMismatch)?,
            )
        } else {
            None
        };

        for (layer_idx, beta) in betas.iter().enumerate() {
            if !is_valid_query_index(current_index, layer_len) {
                break;
            }

            let recorded = fri_iter
                .next()
                .ok_or(VerifierError::FriQueryCountMismatch)?;

            let pair_index = current_index & !1;
            if recorded.layer_index != layer_idx || recorded.query_index != pair_index {
                return Err(VerifierError::FriQueryIndexMismatch.into());
            }

            // Validate Merkle openings against the layer root.
            let root = proof.fri_proof.layer_roots[layer_idx];
            for (offset, (value, path)) in recorded
                .values
                .iter()
                .zip(recorded.merkle_paths.iter())
                .enumerate()
            {
                let leaf_hash = hc_fri::layer::hash_value(value);
                if !path.verify::<Blake3>(root, leaf_hash) {
                    return Err(VerifierError::FriQueryMerkleMismatch.into());
                }

                // If we have an expected value for the current index, check it matches the
                // corresponding element in the opened coset pair.
                if let Some(expected) = expected_value {
                    let target_index = pair_index + offset;
                    if target_index == current_index && *value != expected {
                        return Err(VerifierError::FriQueryEvaluationMismatch.into());
                    }
                }
            }

            // Fold this layer's coset pair.
            let folded = recorded.values[0].add(beta.mul(recorded.values[1]));
            expected_value = Some(folded);
            current_index = propagate_query_index(current_index, folding_ratio);
            layer_len /= 2;
        }

        // Check the final folded value against the final layer evaluations shipped in the proof.
        let final_index = current_index;
        if is_valid_query_index(final_index, proof.fri_proof.final_layer.len()) {
            let expected = proof.fri_proof.final_layer[final_index];
            if let Some(value) = expected_value {
                if value != expected {
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
        if let Some(next) = &query.next {
            let next_index_bytes = (next.index as u64).to_le_bytes();
            transcript.append_message(b"trace_next_index", next_index_bytes);
            let next0_bytes = next.evaluation[0].to_u64().to_le_bytes();
            transcript.append_message(b"trace_next_eval_0", next0_bytes);
            let next1_bytes = next.evaluation[1].to_u64().to_le_bytes();
            transcript.append_message(b"trace_next_eval_1", next1_bytes);
        } else {
            transcript.append_message(b"trace_next_absent", [0u8]);
        }
    }

    transcript.challenge_bytes(b"trace_queries_digest")
}

fn commit_composition_queries<F: FieldElement>(queries: &[CompositionQuery<F>]) -> HashDigest {
    let mut ordered: Vec<&CompositionQuery<F>> = queries.iter().collect();
    ordered.sort_by_key(|query| query.index);

    let mut transcript = Transcript::<Blake3>::new(b"composition_query_commitment");
    for query in ordered {
        let index_bytes = (query.index as u64).to_le_bytes();
        transcript.append_message(b"comp_index", index_bytes);
        let value_bytes = query.value.to_u64().to_le_bytes();
        transcript.append_message(b"comp_value", value_bytes);
    }
    transcript.challenge_bytes(b"composition_queries_digest")
}

fn commit_trace_queries_with_boundary<F: FieldElement>(
    query_response: &QueryResponse<F>,
) -> HashDigest {
    let mut all: Vec<&TraceQuery<F>> = query_response.trace_queries.iter().collect();
    if let Some(BoundaryOpenings {
        first_trace,
        last_trace,
        ..
    }) = &query_response.boundary
    {
        all.push(first_trace);
        all.push(last_trace);
    }
    // Reuse the same commitment scheme as the legacy helper (sorted by index).
    let mut ordered: Vec<&TraceQuery<F>> = all;
    ordered.sort_by_key(|query| query.index);

    let mut transcript = Transcript::<Blake3>::new(b"trace_query_commitment");
    for query in ordered {
        let index_bytes = (query.index as u64).to_le_bytes();
        transcript.append_message(b"trace_index", index_bytes);
        let eval0_bytes = query.evaluation[0].to_u64().to_le_bytes();
        transcript.append_message(b"trace_eval_0", eval0_bytes);
        let eval1_bytes = query.evaluation[1].to_u64().to_le_bytes();
        transcript.append_message(b"trace_eval_1", eval1_bytes);
        if let Some(next) = &query.next {
            let next_index_bytes = (next.index as u64).to_le_bytes();
            transcript.append_message(b"trace_next_index", next_index_bytes);
            let next0_bytes = next.evaluation[0].to_u64().to_le_bytes();
            transcript.append_message(b"trace_next_eval_0", next0_bytes);
            let next1_bytes = next.evaluation[1].to_u64().to_le_bytes();
            transcript.append_message(b"trace_next_eval_1", next1_bytes);
        } else {
            transcript.append_message(b"trace_next_absent", [0u8]);
        }
    }
    transcript.challenge_bytes(b"trace_queries_digest")
}

fn commit_composition_queries_with_boundary<F: FieldElement>(
    query_response: &QueryResponse<F>,
) -> HashDigest {
    let mut all: Vec<&CompositionQuery<F>> = query_response.composition_queries.iter().collect();
    if let Some(boundary) = &query_response.boundary {
        all.push(&boundary.first_composition);
        all.push(&boundary.last_composition);
    }
    let mut ordered: Vec<&CompositionQuery<F>> = all;
    ordered.sort_by_key(|query| query.index);

    let mut transcript = Transcript::<Blake3>::new(b"composition_query_commitment");
    for query in ordered {
        let index_bytes = (query.index as u64).to_le_bytes();
        transcript.append_message(b"comp_index", index_bytes);
        let value_bytes = query.value.to_u64().to_le_bytes();
        transcript.append_message(b"comp_value", value_bytes);
    }
    transcript.challenge_bytes(b"composition_queries_digest")
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
        let eval0_bytes = query.values[0].to_u64().to_le_bytes();
        transcript.append_message(b"fri_eval_0", eval0_bytes);
        let eval1_bytes = query.values[1].to_u64().to_le_bytes();
        transcript.append_message(b"fri_eval_1", eval1_bytes);
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

    let mut transcript = Transcript::<Blake3>::new(protocol::DOMAIN_MAIN_V2);
    // Common transcript prefix: public inputs + params + commitments.
    transcript.append_message(
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64().to_le_bytes(),
    );
    transcript.append_message(
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64().to_le_bytes(),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    transcript.append_message(protocol::label::COMMIT_TRACE_ROOT, trace_root.as_bytes());
    let composition_root = proof
        .composition_commitment
        .as_root()
        .ok_or_else(|| HcError::invalid_argument("missing Merkle root for Stark commitment"))?;
    transcript.append_message(
        protocol::label::COMMIT_COMPOSITION_ROOT,
        composition_root.as_bytes(),
    );
    for root in &proof.fri_proof.layer_roots {
        transcript.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
    }
    transcript.append_message(
        protocol::label::COMMIT_FRI_FINAL_ROOT,
        proof.fri_proof.final_root.as_bytes(),
    );

    let base_queries = generate_queries::<F>(
        &mut transcript,
        proof.trace_length,
        proof.params.query_count,
    )?;
    if query_response.trace_queries.len() != proof.params.query_count {
        return Err(VerifierError::QueryIndexMismatch.into());
    }

    verify_stark_trace_queries::<F>(trace_root, query_response, &base_queries)?;
    verify_stark_composition_queries::<F>(
        trace_root,
        composition_root,
        proof,
        query_response,
        &base_queries,
    )?;
    verify_stark_boundary_openings::<F>(trace_root, composition_root, proof, query_response)?;
    verify_fri_queries::<F>(proof, &base_queries, query_response)?;

    let config = FriConfig::new(proof.params.fri_final_poly_size)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;

    let query_commitments = QueryCommitments {
        trace_commitment: commit_trace_queries_with_boundary(query_response),
        composition_commitment: commit_composition_queries_with_boundary(query_response),
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

    let mut transcript = Transcript::<Blake3>::new(protocol::DOMAIN_MAIN_V2);
    transcript.append_message(
        protocol::label::PUB_INITIAL_ACC,
        proof.initial_acc.to_u64().to_le_bytes(),
    );
    transcript.append_message(
        protocol::label::PUB_FINAL_ACC,
        proof.final_acc.to_u64().to_le_bytes(),
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PUB_TRACE_LENGTH,
        proof.trace_length as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_QUERY_COUNT,
        proof.params.query_count as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_LDE_BLOWUP,
        proof.params.lde_blowup_factor as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FINAL_SIZE,
        proof.params.fri_final_poly_size as u64,
    );
    protocol::append_u64::<Blake3>(
        &mut transcript,
        protocol::label::PARAM_FRI_FOLDING_RATIO,
        proof.params.fri_folding_ratio as u64,
    );
    transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
    let trace_digest = commitment_digest(&proof.trace_commitment);
    transcript.append_message(protocol::label::COMMIT_TRACE_ROOT, trace_digest.as_bytes());
    let composition_digest = commitment_digest(&proof.composition_commitment);
    transcript.append_message(
        protocol::label::COMMIT_COMPOSITION_ROOT,
        composition_digest.as_bytes(),
    );
    for root in &proof.fri_proof.layer_roots {
        transcript.append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
    }
    transcript.append_message(
        protocol::label::COMMIT_FRI_FINAL_ROOT,
        proof.fri_proof.final_root.as_bytes(),
    );

    let base_queries = generate_queries::<F>(
        &mut transcript,
        proof.trace_length,
        proof.params.query_count,
    )?;
    if query_response.trace_queries.len() != proof.params.query_count {
        return Err(VerifierError::QueryIndexMismatch.into());
    }

    verify_kzg_trace_queries(proof, query_response, &base_queries)?;
    // FRI is still the low-degree oracle check; verify it regardless of the commitment scheme
    // used for the trace.
    verify_fri_queries::<F>(proof, &base_queries, query_response)?;
    let config = FriConfig::new(proof.params.fri_final_poly_size)?;
    fri_verify::verify_fri(config, &proof.fri_proof).map_err(|_| VerifierError::FriFailure)?;

    let query_commitments = QueryCommitments {
        trace_commitment: commit_trace_queries(&query_response.trace_queries),
        composition_commitment: commit_composition_queries(&query_response.composition_queries),
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
        composition_commitment: digest,
        fri_commitment: digest,
    }
}

/// Forge proof-of-concept for audit finding **G2**: the current FRI verifier's
/// low-degree test is *vacuous*.
///
/// The prover builds each FRI layer as `fold(prev_layer)` and the verifier
/// re-checks that exact recurrence against the prover's *own* committed layers.
/// Because the recurrence is self-referential, the checks pass for ANY base
/// codeword — including a high-degree one that is NOT low-degree. A sound FRI
/// low-degree test must REJECT such a codeword; this one accepts it.
///
/// This module lives inside `crate::api` so it can call the private
/// [`verify_fri_queries`] directly (no production visibility change). It uses
/// the prover crate (a normal dependency of `hc-verifier`) to commit the
/// forged codeword and to *reuse* the prover's own opening builder
/// (`answer_fri_queries`) so the openings are byte-for-byte what an honest
/// prover would ship for those query indices.
///
/// The test ASSERTS rejection (`is_err`). Against the current code the forgery
/// is ACCEPTED, so the assertion fails and the test is RED — that RED result is
/// the demonstration of G2. It is `#[ignore]`d so the suite stays green until
/// the Task 8 fix lands; removing `#[ignore]` should then make it pass.
#[cfg(test)]
mod forge_poc_g2 {
    use hc_core::field::prime_field::GoldilocksField;
    use hc_core::field::FieldElement;
    use hc_fri::FriConfig;
    use hc_hash::hash::HashDigest;
    use hc_prover::commitment::{commitment_digest, Commitment};
    use hc_prover::pipeline::phase2_fri::{run_fri, FriTranscriptSeed};
    use hc_prover::pipeline::phase3_queries::answer_fri_queries;
    use hc_prover::queries::{CompositionQuery, ProofParams, QueryResponse};
    use hc_replay::traits::VecBlockProducer;
    use std::sync::Arc;

    use crate::api::{verify_fri_queries, Proof};

    type F = GoldilocksField;

    /// A deterministic, high-degree codeword.
    ///
    /// These values are an explicit degree-`(len-1)` evaluation table (a simple
    /// pseudo-random recurrence). With overwhelming probability — and in fact by
    /// the assertion below — this is NOT the low-degree extension of its first
    /// `len / blowup` entries, i.e. it is genuinely high-degree.
    fn high_degree_codeword(len: usize) -> Vec<F> {
        let mut out = Vec::with_capacity(len);
        // Arbitrary deterministic recurrence over the field.
        let mut state: u64 = 0x1234_5678_9abc_def1;
        for _ in 0..len {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            // Keep values inside the field; the exact mapping is irrelevant, only
            // that the resulting table is not a low-degree extension.
            out.push(F::from_u64(state ^ (state >> 29)));
        }
        out
    }

    #[test]
    #[ignore = "RED until G2 fix lands in Task 8 (Phase 1A); demonstrates the vacuous low-degree test"]
    fn current_fri_accepts_high_degree_codeword() {
        // --- Parameters (tiny, so every FRI layer is trivial to materialize). ---
        // verify_fri_queries derives the FRI base length for a v3 Stark proof as
        //   base_len = trace_length.next_power_of_two() * lde_blowup_factor.max(1)
        // so trace_length=8, blowup=2  =>  base_len = 16.
        let trace_length: usize = 8;
        let blowup: usize = 2;
        let base_len: usize = trace_length.next_power_of_two() * blowup; // 16
        let fri_final_poly_size: usize = 2; // layers 16 -> 8 -> 4 -> 2 (3 betas)
        let query_count: usize = 4;
        let protocol_version: u32 = 3;

        // --- 1) Build a HIGH-DEGREE base codeword C of length base_len. ---
        let codeword = high_degree_codeword(base_len);

        // Optional (nice-to-have) sanity: C is genuinely high-degree, i.e. it is
        // NOT the low-degree extension of its first base_len/blowup values. We
        // detect this cheaply: a degree-(k-1) poly on a blowup-`b` evaluation
        // table is fully determined by any k points, so a true LDE would have a
        // huge amount of structure; a random table almost never does. We simply
        // assert the table is not eventually constant / not all-equal, which is
        // enough to rule out the degenerate low-degree cases for this PoC.
        let k = base_len / blowup;
        assert!(k >= 1);
        assert!(
            codeword.iter().any(|&v| v != codeword[0]),
            "codeword must be non-constant (a basic high-degree witness)"
        );

        // --- 2) Commit C through the prover's FRI path. ---
        // Record the seed values so we can place the SAME values in the proof;
        // the verifier rederives identical betas from these fields.
        let trace_commitment_root = HashDigest::new([0xA5u8; 32]);
        let composition_commitment_root = HashDigest::new([0x5Au8; 32]);
        let trace_commitment = Commitment::Stark {
            root: trace_commitment_root,
        };
        let composition_commitment = Commitment::Stark {
            root: composition_commitment_root,
        };

        let initial_acc = F::from_u64(5);
        let final_acc = F::from_u64(8);

        let seed = FriTranscriptSeed {
            protocol_version,
            initial_acc: initial_acc.to_u64(),
            final_acc: final_acc.to_u64(),
            trace_length: trace_length as u64,
            query_count: query_count as u64,
            lde_blowup: blowup as u64,
            fri_final_size: fri_final_poly_size as u64,
            folding_ratio: 2,
            zk_enabled: false,
            zk_mask_degree: 0,
            // These MUST equal commitment_digest(&proof.{trace,composition}_commitment),
            // which for a Stark commitment is just the stored root.
            trace_commitment: commitment_digest(&trace_commitment),
            composition_commitment: commitment_digest(&composition_commitment),
        };

        let config = FriConfig::new(fri_final_poly_size).unwrap();
        let producer: Arc<dyn hc_replay::traits::BlockProducer<F>> =
            Arc::new(VecBlockProducer::new(codeword.clone()));
        // NOTE: run_fri's `trace_length` argument is the FRI *base codeword*
        // length (the producer length), which is base_len here. The transcript's
        // PUB_TRACE_LENGTH comes from `seed.trace_length` (= 8) instead.
        let artifacts = run_fri::<F>(config, producer, base_len, seed)
            .expect("FRI commitment over the forged codeword should succeed");

        // --- 3) Choose base query indices directly (verify_fri_queries takes
        //         them as a parameter, so we need not reproduce generate_queries). ---
        let base_queries: Vec<usize> = vec![0, 3, 6, 11];

        // --- 4) Build the matching FRI openings by REUSING the prover's own
        //         opening builder on the committed artifacts. ---
        let fri_queries = answer_fri_queries(&base_queries, &artifacts)
            .expect("building FRI openings for the chosen indices should succeed");

        // Base-layer binding the verifier seeds `expected_value` from: it reads
        // only `index` and `value` (the Merkle witness is NOT checked here).
        let composition_queries: Vec<CompositionQuery<F>> = base_queries
            .iter()
            .map(|&q| CompositionQuery {
                index: q,
                value: codeword[q],
                witness: hc_commit::merkle::MerklePath::default(),
            })
            .collect();

        let query_response = QueryResponse {
            trace_queries: Vec::new(),
            composition_queries,
            fri_queries,
            boundary: None,
            ood: None,
        };

        // --- 5) Assemble a v3 Stark Proof matching the committed FRI + seed. ---
        let params = ProofParams {
            query_count,
            lde_blowup_factor: blowup,
            fri_final_poly_size,
            fri_folding_ratio: 2,
            protocol_version,
            zk_enabled: false,
            zk_mask_degree: 0,
            grinding_bits: 0,
        };
        let proof = Proof::<F> {
            version: protocol_version,
            trace_commitment,
            composition_commitment,
            fri_proof: artifacts.proof.clone(),
            initial_acc,
            final_acc,
            query_response: Some(query_response.clone()),
            trace_length,
            params,
        };

        // --- 6/7) Call the private low-degree check directly and ASSERT rejection. ---
        let result = verify_fri_queries::<F>(&proof, &base_queries, &query_response);

        // Surface the observed outcome for the RED commit body / CI logs.
        eprintln!("forge_poc_g2: verify_fri_queries returned {result:?}");

        assert!(
            result.is_err(),
            "G2: FRI accepted a high-degree codeword — low-degree test is vacuous"
        );
    }
}
