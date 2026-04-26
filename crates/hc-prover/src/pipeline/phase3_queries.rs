use crate::{
    commitment::CommitmentScheme,
    kzg::{open_polynomial, serialize_fr, serialize_proof, TraceKzgState},
    queries::{
        BoundaryOpenings, CompositionQuery, FriQuery, KzgColumnProof, KzgTraceWitness,
        NextTraceRow, TraceQuery, TraceWitness,
    },
    TraceRow,
};
use ark_poly::Polynomial;
use hc_air::constraints::boundary::BoundaryConstraints;
use hc_commit::merkle::reconstruct_path_from_replay_mut;
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_fri::{get_folding_ratio, is_valid_query_index, propagate_query_index};
use hc_hash::protocol;
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
        transcript.append_message(protocol::label::CHAL_QUERY_ROUND, round_bytes);
        let challenge = transcript.challenge_field::<F>(protocol::label::CHAL_QUERY_INDEX);
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
                    let trace_len = trace_replay.trace_length();
                    let block_size = trace_replay.block_size();
                    let mut producer = |leaf_index: usize| -> HcResult<HashDigest> {
                        let block_idx = leaf_index / block_size;
                        let in_block = leaf_index % block_size;
                        let block = trace_replay.fetch_block(block_idx)?;
                        let row = block
                            .get(in_block)
                            .ok_or_else(|| HcError::message("trace leaf index out of range"))?;
                        Ok(hash_trace_row(row))
                    };
                    let merkle_path = reconstruct_path_from_replay_mut::<Blake3, _>(
                        query_idx,
                        trace_len,
                        2,
                        &mut producer,
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

                let next = if use_merkle && query_idx + 1 < trace_replay.trace_length() {
                    let next_idx = query_idx + 1;
                    let block_size = trace_replay.block_size();
                    let next_block_idx = next_idx / block_size;
                    let next_in_block = next_idx % block_size;
                    let next_block = trace_replay.fetch_block(next_block_idx)?;
                    let next_eval = *next_block
                        .get(next_in_block)
                        .ok_or_else(|| HcError::message("missing next trace row"))?;

                    let trace_len = trace_replay.trace_length();
                    let block_size = trace_replay.block_size();
                    let mut producer = |leaf_index: usize| -> HcResult<HashDigest> {
                        let block_idx = leaf_index / block_size;
                        let in_block = leaf_index % block_size;
                        let block = trace_replay.fetch_block(block_idx)?;
                        let row = block
                            .get(in_block)
                            .ok_or_else(|| HcError::message("trace leaf index out of range"))?;
                        Ok(hash_trace_row(row))
                    };
                    let next_path = reconstruct_path_from_replay_mut::<Blake3, _>(
                        next_idx,
                        trace_len,
                        2,
                        &mut producer,
                    )
                    .map_err(|err| {
                        HcError::message(format!("Failed to extract next-row Merkle path: {err}"))
                    })?;
                    Some(NextTraceRow {
                        index: next_idx,
                        evaluation: next_eval,
                        witness: next_path,
                    })
                } else {
                    None
                };

                results.push(TraceQuery {
                    index: query_idx,
                    evaluation,
                    witness,
                    next,
                });
            }
        }
    }

    // Sort results by query index for deterministic output
    results.sort_by_key(|q| q.index);

    Ok(results)
}

pub fn answer_composition_queries<F, P>(
    queries: &[usize],
    trace_replay: &mut TraceReplay<P, TraceRow<F>>,
    alpha_boundary: F,
    alpha_transition: F,
    boundary_initial: F,
    boundary_final: F,
) -> HcResult<Vec<CompositionQuery<F>>>
where
    F: FieldElement,
    P: BlockProducer<TraceRow<F>>,
{
    let trace_len = trace_replay.trace_length();
    let block_size = trace_replay.block_size();

    let boundary = BoundaryConstraints {
        initial_acc: boundary_initial,
        final_acc: boundary_final,
    };
    let leaf_value = |idx: usize, row: TraceRow<F>, next: TraceRow<F>| -> HcResult<F> {
        hc_air::eval::composition_value_for_row(
            row,
            next,
            idx,
            trace_len,
            &boundary,
            alpha_boundary,
            alpha_transition,
        )
    };

    let mut results = Vec::with_capacity(queries.len());
    for &query_idx in queries {
        let block_idx = query_idx / block_size;
        let in_block = query_idx % block_size;
        let block = trace_replay.fetch_block(block_idx)?;
        let row = *block
            .get(in_block)
            .ok_or_else(|| HcError::message("composition query index out of range"))?;
        let next = if query_idx + 1 < trace_len {
            let next_idx = query_idx + 1;
            let nb = trace_replay.fetch_block(next_idx / block_size)?;
            Some(
                *nb.get(next_idx % block_size)
                    .ok_or_else(|| HcError::message("composition query missing next row"))?,
            )
        } else {
            None
        };
        let next_row = next.unwrap_or(row);
        let value = leaf_value(query_idx, row, next_row)?;

        let mut producer = |leaf_index: usize| -> HcResult<HashDigest> {
            let block_idx = leaf_index / block_size;
            let in_block = leaf_index % block_size;
            let block = trace_replay.fetch_block(block_idx)?;
            let row = *block
                .get(in_block)
                .ok_or_else(|| HcError::message("composition leaf index out of range"))?;
            let next = if leaf_index + 1 < trace_len {
                let next_idx = leaf_index + 1;
                let nb = trace_replay.fetch_block(next_idx / block_size)?;
                Some(
                    *nb.get(next_idx % block_size)
                        .ok_or_else(|| HcError::message("composition leaf missing next row"))?,
                )
            } else {
                None
            };
            let next_row = next.unwrap_or(row);
            let v = leaf_value(leaf_index, row, next_row)?;
            Ok(hash_field_element(&v))
        };

        let path =
            reconstruct_path_from_replay_mut::<Blake3, _>(query_idx, trace_len, 2, &mut producer)
                .map_err(|err| {
                HcError::message(format!("Failed to extract composition Merkle path: {err}"))
            })?;

        results.push(CompositionQuery {
            index: query_idx,
            value,
            witness: path,
        });
    }
    results.sort_by_key(|q| q.index);
    Ok(results)
}

/// Answer queries for FRI layer evaluations and Merkle paths
pub fn answer_fri_queries<F>(
    base_queries: &[usize],
    fri_artifacts: &hc_fri::FriProverArtifacts<F>,
) -> HcResult<Vec<FriQuery<F>>>
where
    F: FieldElement,
{
    use hc_commit::merkle::reconstruct_paths_from_replay_mut;
    use hc_fri::layer::hash_value as hash_fri_value;
    use std::collections::{BTreeSet, HashMap};
    use std::sync::Arc;

    #[derive(Clone)]
    struct FoldedLayerProducer<F: FieldElement> {
        prev: Arc<dyn hc_replay::traits::BlockProducer<F>>,
        prev_len: usize,
        beta: F,
    }

    impl<F: FieldElement> hc_replay::traits::BlockProducer<F> for FoldedLayerProducer<F> {
        fn produce(&self, range: hc_replay::block_range::BlockRange) -> HcResult<Vec<F>> {
            let out_len = self.prev_len / 2;
            let end = range.end().min(out_len);
            if range.start >= end {
                return Ok(Vec::new());
            }
            let len = end - range.start;
            let prev_range = hc_replay::block_range::BlockRange::new(range.start * 2, len * 2);
            let prev_values = self.prev.produce(prev_range)?;
            let mut out = Vec::with_capacity(len);
            for pair in prev_values.chunks(2) {
                out.push(pair[0].add(self.beta.mul(pair[1])));
            }
            Ok(out)
        }
    }

    struct ProducerValueStream<F: FieldElement> {
        producer: Arc<dyn hc_replay::traits::BlockProducer<F>>,
        len: usize,
        index: usize,
        block_base: usize,
        block_size: usize,
        block: Vec<F>,
    }

    impl<F: FieldElement> ProducerValueStream<F> {
        fn new(producer: Arc<dyn hc_replay::traits::BlockProducer<F>>, len: usize) -> Self {
            Self {
                producer,
                len,
                index: 0,
                block_base: 0,
                block_size: len.clamp(1, 1024),
                block: Vec::new(),
            }
        }

        fn next_value(&mut self) -> HcResult<Option<F>> {
            if self.index >= self.len {
                return Ok(None);
            }
            if self.block.is_empty() || self.index >= self.block_base + self.block.len() {
                self.block_base = self.index;
                let chunk = (self.len - self.index).min(self.block_size);
                self.block = self
                    .producer
                    .produce(hc_replay::block_range::BlockRange::new(self.index, chunk))?;
            }
            let offset = self.index - self.block_base;
            let value = self
                .block
                .get(offset)
                .copied()
                .ok_or_else(|| HcError::message("fri producer returned short block"))?;
            self.index += 1;
            Ok(Some(value))
        }
    }

    fn open_many<F: FieldElement>(
        producer: Arc<dyn hc_replay::traits::BlockProducer<F>>,
        len: usize,
        indices: &[usize],
    ) -> HcResult<HashMap<usize, (F, hc_commit::merkle::MerklePath)>> {
        let mut unique = BTreeSet::new();
        for &idx in indices {
            unique.insert(idx);
        }
        let leaf_indices: Vec<usize> = unique.into_iter().collect();
        if leaf_indices.is_empty() {
            return Ok(HashMap::new());
        }
        if leaf_indices.iter().any(|&idx| idx >= len) {
            return Err(HcError::invalid_argument("fri leaf index out of range"));
        }

        let mut values: HashMap<usize, F> = HashMap::with_capacity(leaf_indices.len());
        let mut stream = ProducerValueStream::new(Arc::clone(&producer), len);
        let mut cursor = 0usize;
        let mut targets = std::collections::HashSet::with_capacity(leaf_indices.len());
        for idx in &leaf_indices {
            targets.insert(*idx);
        }
        let mut leaf_hash_producer = |idx: usize| -> HcResult<HashDigest> {
            if idx != cursor {
                return Err(HcError::message(
                    "fri merkle path reconstruction called out of order",
                ));
            }
            let value = stream
                .next_value()?
                .ok_or_else(|| HcError::message("fri producer ended early"))?;
            if targets.contains(&idx) {
                values.insert(idx, value);
            }
            cursor += 1;
            Ok(hash_fri_value(&value))
        };

        let paths = reconstruct_paths_from_replay_mut::<Blake3, _>(
            &leaf_indices,
            len,
            2,
            &mut leaf_hash_producer,
        )
        .map_err(|err| HcError::message(format!("Failed to extract FRI Merkle paths: {err}")))?;

        let mut out = HashMap::with_capacity(leaf_indices.len());
        for (idx, path) in leaf_indices.into_iter().zip(paths.into_iter()) {
            let value = values
                .remove(&idx)
                .ok_or_else(|| HcError::message("missing fri opened value"))?;
            out.insert(idx, (value, path));
        }
        Ok(out)
    }

    let folding_ratio = get_folding_ratio();
    let num_layers = fri_artifacts.proof.layer_roots.len();
    let mut needed_by_layer: Vec<Vec<usize>> = vec![Vec::new(); num_layers];

    // Record, per base query, which layer indices are actually opened and at which pair index.
    let mut per_base: Vec<Vec<(usize, usize)>> = Vec::with_capacity(base_queries.len());
    for &base_query in base_queries {
        let mut local = Vec::new();
        let mut current_index = base_query;
        let mut layer_len = fri_artifacts.base_length;
        for (layer_idx, needed) in needed_by_layer.iter_mut().enumerate() {
            if !is_valid_query_index(current_index, layer_len) {
                break;
            }
            let pair_index = current_index & !1;
            if pair_index + 1 >= layer_len {
                return Err(HcError::message("fri coset pair out of bounds"));
            }
            needed.push(pair_index);
            needed.push(pair_index + 1);
            local.push((layer_idx, pair_index));
            current_index = propagate_query_index(current_index, folding_ratio);
            layer_len /= 2;
        }
        per_base.push(local);
    }

    // Open all leaves needed per layer in a single pass per layer.
    let mut opened_by_layer: Vec<HashMap<usize, (F, hc_commit::merkle::MerklePath)>> =
        Vec::with_capacity(num_layers);
    let mut current_producer: Arc<dyn hc_replay::traits::BlockProducer<F>> =
        Arc::clone(&fri_artifacts.base_producer);
    let mut current_len = fri_artifacts.base_length;
    for (layer_idx, beta) in fri_artifacts.betas.iter().copied().enumerate() {
        let opened = open_many(
            Arc::clone(&current_producer),
            current_len,
            &needed_by_layer[layer_idx],
        )?;
        opened_by_layer.push(opened);
        // advance producer for next layer
        current_producer = Arc::new(FoldedLayerProducer {
            prev: current_producer,
            prev_len: current_len,
            beta,
        });
        current_len /= 2;
    }

    let mut out = Vec::new();
    for local in per_base {
        for (layer_idx, pair_index) in local {
            let layer = &opened_by_layer[layer_idx];
            let (v0, p0) = layer
                .get(&pair_index)
                .cloned()
                .ok_or_else(|| HcError::message("missing fri opening for pair index"))?;
            let (v1, p1) = layer
                .get(&(pair_index + 1))
                .cloned()
                .ok_or_else(|| HcError::message("missing fri opening for pair index+1"))?;
            out.push(FriQuery {
                layer_index: layer_idx,
                query_index: pair_index,
                values: [v0, v1],
                merkle_paths: [p0, p1],
            });
        }
    }

    Ok(out)
}

/// Build complete query response including both trace and FRI queries
pub fn build_queries<F, P>(
    transcript: &mut hc_hash::Transcript<Blake3>,
    trace_replay: &mut TraceReplay<P, TraceRow<F>>,
    fri_artifacts: &hc_fri::FriProverArtifacts<F>,
    num_queries: usize,
    scheme: CommitmentScheme,
    kzg_state: Option<&TraceKzgState>,
    composition_coeffs: Option<(F, F, F, F)>,
) -> HcResult<crate::queries::QueryResponse<F>>
where
    F: FieldElement + Clone,
    P: BlockProducer<TraceRow<F>>,
{
    let trace_length = trace_replay.trace_length();
    let query_indices = generate_queries::<F>(transcript, trace_length, num_queries)?;

    let trace_queries = answer_trace_queries(&query_indices, trace_replay, scheme, kzg_state)?;
    let composition_queries = if matches!(scheme, CommitmentScheme::Stark) {
        let (alpha_boundary, alpha_transition, boundary_initial, boundary_final) =
            composition_coeffs
                .ok_or_else(|| HcError::message("missing composition coefficients"))?;
        answer_composition_queries(
            &query_indices,
            trace_replay,
            alpha_boundary,
            alpha_transition,
            boundary_initial,
            boundary_final,
        )?
    } else {
        Vec::new()
    };
    let fri_queries = answer_fri_queries(&query_indices, fri_artifacts)?;

    let boundary = if matches!(scheme, CommitmentScheme::Stark) {
        // Always include boundary openings for soundness: row 0 and row (n-1),
        // plus the corresponding composition leaves at indices 0 and (n-1).
        if trace_length < 2 {
            return Err(HcError::invalid_argument(
                "trace length must be at least 2 for boundary openings",
            ));
        }

        let (alpha_boundary, alpha_transition, boundary_initial, boundary_final) =
            composition_coeffs
                .ok_or_else(|| HcError::message("missing composition coefficients"))?;

        let boundary_trace_queries = answer_trace_queries(
            &[0, trace_length - 1],
            trace_replay,
            CommitmentScheme::Stark,
            None,
        )?;
        let first_trace = boundary_trace_queries
            .iter()
            .find(|q| q.index == 0)
            .cloned()
            .ok_or_else(|| HcError::message("missing boundary trace opening at index 0"))?;
        let last_trace = boundary_trace_queries
            .iter()
            .find(|q| q.index + 1 == trace_length)
            .cloned()
            .ok_or_else(|| HcError::message("missing boundary trace opening at last index"))?;

        // Ensure the boundary opening at 0 includes next-row witness at 1.
        if first_trace.next.is_none() {
            // Re-run with explicit index 0 (should always have next), but keep a hard error if not.
            return Err(HcError::message(
                "boundary opening at index 0 missing next-row witness",
            ));
        }

        let boundary_composition_queries = answer_composition_queries(
            &[0, trace_length - 1],
            trace_replay,
            alpha_boundary,
            alpha_transition,
            boundary_initial,
            boundary_final,
        )?;
        let first_composition = boundary_composition_queries
            .iter()
            .find(|q| q.index == 0)
            .cloned()
            .ok_or_else(|| HcError::message("missing boundary composition opening at index 0"))?;
        let last_composition = boundary_composition_queries
            .iter()
            .find(|q| q.index + 1 == trace_length)
            .cloned()
            .ok_or_else(|| {
                HcError::message("missing boundary composition opening at last index")
            })?;

        Some(BoundaryOpenings {
            first_trace,
            last_trace,
            first_composition,
            last_composition,
        })
    } else {
        None
    };

    Ok(crate::queries::QueryResponse {
        trace_queries,
        composition_queries,
        fri_queries,
        boundary,
        ood: None,
    })
}

fn hash_trace_row<F: FieldElement>(row: &TraceRow<F>) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&row[0].to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&row[1].to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}

fn hash_field_element<F: FieldElement>(value: &F) -> HashDigest {
    let bytes = value.to_u64().to_le_bytes();
    Blake3::hash(&bytes)
}
