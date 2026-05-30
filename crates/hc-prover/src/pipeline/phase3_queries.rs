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
    field::{FieldElement, GoldilocksField, QuadExtension},
};
use hc_fri::{get_folding_ratio, is_valid_query_index};
// Legacy v3 query propagation: deprecated in favor of the sound v5 path
// (`propagate_query_index_v5`), but the v3 query answerer still depends on it.
#[allow(deprecated)]
use hc_fri::propagate_query_index;
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

/// Answer queries for FRI layer evaluations and Merkle paths (legacy v3 path).
#[allow(deprecated)] // v3 FRI query answering uses the legacy propagate_query_index.
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

        // `reconstruct_paths_from_replay_mut` tracks targets with a u64 bitmask
        // → max 64 leaves per pass. Open in chunks of ≤ 64; each chunk is an
        // independent streaming pass and yields byte-identical per-leaf paths
        // (a path depends only on the leaf index + the fixed Merkle tree).
        const MERKLE_MULTI_OPEN_MAX: usize = 64;

        let mut out = HashMap::with_capacity(leaf_indices.len());
        for chunk in leaf_indices.chunks(MERKLE_MULTI_OPEN_MAX) {
            let mut values: HashMap<usize, F> = HashMap::with_capacity(chunk.len());
            let mut stream = ProducerValueStream::new(Arc::clone(&producer), len);
            let mut cursor = 0usize;
            let mut targets = std::collections::HashSet::with_capacity(chunk.len());
            for idx in chunk {
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
                chunk,
                len,
                2,
                &mut leaf_hash_producer,
            )
            .map_err(|err| {
                HcError::message(format!("Failed to extract FRI Merkle paths: {err}"))
            })?;

            for (&idx, path) in chunk.iter().zip(paths) {
                let value = values
                    .remove(&idx)
                    .ok_or_else(|| HcError::message("missing fri opened value"))?;
                out.insert(idx, (value, path));
            }
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

/// Answer FRI query openings for the v5 (antipodal, K-valued) FRI proof.
///
/// ADDITIVE counterpart to [`answer_fri_queries`]: it produces the openings for
/// the cryptographically-correct **antipodal + 1/x** fold (spec §3) over the
/// extension field `K = QuadExtension<GoldilocksField>`. The v3 function (and
/// all v3 behaviour) is left untouched.
///
/// Key differences from v3:
/// - At a layer of size `n`, a query that arrives at `current_index` opens the
///   **antipodal pair** `(low, low + n/2)` where `low = current & (n/2 - 1)`
///   (= `propagate_query_index_v5`), NOT the adjacent pair `(2i, 2i+1)`. The
///   opened `values = [layer[low], layer[low + n/2]] = [f(x), f(-x)]`, the
///   recorded `query_index` is `low`, and the next index is `low`.
/// - Leaves are hashed with [`hash_value_ext`](hc_fri::layer::hash_value_ext)
///   (binds BOTH K coefficients) so the reconstructed Merkle paths verify
///   against the roots produced by the v5 commit phase
///   (`prove_with_producer_v5` / `run_fri_v5`).
/// - Each layer is re-derived from the base K producer by the
///   antipodal + 1/x fold over the running [`LayerDomain<K>`], rebuilt
///   deterministically from the LDE coset (offset 7) of size `base_length`
///   embedded into K — exactly as `run_fri_v5` builds the layer-0 domain. The
///   producer chain reads each previous layer in O(block).
///
/// Stopping condition mirrors v3: descend exactly `betas.len()`
/// (= `layer_roots.len()`) layers, i.e. until the layer reaches
/// `final_polynomial_size`.
///
/// NOTE: the v5 proof/output type, grinding nonce wiring, and the verifier are
/// SEPARATE later tasks (7b-3 / 8); this produces only the query openings.
pub fn answer_fri_queries_v5(
    base_queries: &[usize],
    artifacts: &hc_fri::FriProverArtifacts<QuadExtension<GoldilocksField>>,
) -> HcResult<Vec<FriQuery<QuadExtension<GoldilocksField>>>> {
    use hc_commit::merkle::reconstruct_paths_from_replay_mut;
    use hc_fri::layer::{hash_value_ext, LayerDomain};
    use hc_fri::propagate_query_index_v5;
    use std::collections::{BTreeSet, HashMap, HashSet};
    use std::sync::Arc;

    type K = QuadExtension<GoldilocksField>;

    /// LDE coset offset used by the v5 commit phase (matches `run_fri_v5`).
    const LDE_COSET_OFFSET: u64 = 7;

    /// Streaming producer for the antipodal + 1/x fold (spec §3), mirroring
    /// `hc_fri::prover::FoldedLayerProducerV5` (private to that crate). The
    /// output index `j` is derived from the antipodal pair `prev[j]` and
    /// `prev[j + prev_len/2]` over the previous layer's [`LayerDomain`].
    #[derive(Clone)]
    struct FoldedLayerProducerV5 {
        prev: Arc<dyn hc_replay::traits::BlockProducer<K>>,
        prev_len: usize,
        prev_domain: LayerDomain<K>,
        beta: K,
    }

    impl hc_replay::traits::BlockProducer<K> for FoldedLayerProducerV5 {
        fn produce(&self, range: hc_replay::block_range::BlockRange) -> HcResult<Vec<K>> {
            let out_len = self.prev_len / 2;
            let half = self.prev_len / 2;
            let end = range.end().min(out_len);
            if range.start >= end {
                return Ok(Vec::new());
            }
            let s = range.start;
            let len = end - s;

            // Two block reads: low values prev[s..e], high prev[s+half..e+half].
            let lo = self
                .prev
                .produce(hc_replay::block_range::BlockRange::new(s, len))?;
            let hi = self
                .prev
                .produce(hc_replay::block_range::BlockRange::new(s + half, len))?;
            if lo.len() != len || hi.len() != len {
                return Err(HcError::message(
                    "fri v5 fold producer returned short block",
                ));
            }

            let two_inv = K::from_u64(2)
                .inverse()
                .ok_or_else(|| HcError::math("2 not invertible"))?;
            // 1 / (2 * D[s + k]) for k in 0..len. We invert each element
            // individually (the batched Montgomery trick is `pub(crate)` to
            // hc-fri); the field result is identical and this path touches only
            // O(block) elements per layer in the query-answer phase.
            let mut x = self.prev_domain.point(s);
            let mut out = Vec::with_capacity(len);
            for k in 0..len {
                let inv_two_x = x
                    .add(x)
                    .inverse()
                    .ok_or_else(|| HcError::math("2*D[j] not invertible (zero coset point?)"))?;
                let a = lo[k];
                let b = hi[k];
                let even = a.add(b).mul(two_inv);
                let odd = a.sub(b).mul(inv_two_x);
                out.push(even.add(self.beta.mul(odd)));
                x = x.mul(self.prev_domain.gen);
            }
            Ok(out)
        }
    }

    /// In-order streaming reader over a layer producer (mirrors v3's
    /// `ProducerValueStream`): the Merkle-path replay walks leaves
    /// `0, 1, 2, ...` in order, so we keep a cursor and feed leaves one block
    /// at a time.
    struct ProducerValueStream {
        producer: Arc<dyn hc_replay::traits::BlockProducer<K>>,
        len: usize,
        index: usize,
        block_base: usize,
        block_size: usize,
        block: Vec<K>,
    }

    impl ProducerValueStream {
        fn new(producer: Arc<dyn hc_replay::traits::BlockProducer<K>>, len: usize) -> Self {
            Self {
                producer,
                len,
                index: 0,
                block_base: 0,
                block_size: len.clamp(1, 1024),
                block: Vec::new(),
            }
        }

        fn next_value(&mut self) -> HcResult<Option<K>> {
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
                .ok_or_else(|| HcError::message("fri v5 producer returned short block"))?;
            self.index += 1;
            Ok(Some(value))
        }
    }

    /// Open the given leaf indices of one K layer: stream leaves in order,
    /// hashing each with `hash_value_ext`, recording the requested values and
    /// reconstructing a Merkle path for each.
    ///
    /// `reconstruct_paths_from_replay_mut` tracks the in-flight target set with
    /// a `u64` bitmask, so it accepts at most 64 leaf indices per call. The v5
    /// FRI floor requires `query_count ≥ 40`, and layer 0 opens an antipodal
    /// PAIR `(low, low+half)` per base query — up to `2 * query_count` (≈ 80)
    /// distinct leaves on a non-trivial domain — which exceeds 64. We therefore
    /// open in chunks of ≤ 64 indices, each chunk a fresh streaming pass. This
    /// is purely a batching detail: the per-leaf Merkle path a chunk emits is a
    /// function only of the leaf index and the (fixed) layer Merkle tree, so the
    /// resulting paths — and thus the proof bytes — are byte-identical to a
    /// single 64-bounded call. No crypto changes.
    fn open_many(
        producer: Arc<dyn hc_replay::traits::BlockProducer<K>>,
        len: usize,
        indices: &[usize],
    ) -> HcResult<HashMap<usize, (K, hc_commit::merkle::MerklePath)>> {
        let mut unique = BTreeSet::new();
        for &idx in indices {
            unique.insert(idx);
        }
        let leaf_indices: Vec<usize> = unique.into_iter().collect();
        if leaf_indices.is_empty() {
            return Ok(HashMap::new());
        }
        if leaf_indices.iter().any(|&idx| idx >= len) {
            return Err(HcError::invalid_argument("fri v5 leaf index out of range"));
        }

        // Merkle multi-opening bitmask cap (u64) → at most 64 leaves per pass.
        const MERKLE_MULTI_OPEN_MAX: usize = 64;

        let mut out = HashMap::with_capacity(leaf_indices.len());
        for chunk in leaf_indices.chunks(MERKLE_MULTI_OPEN_MAX) {
            let mut values: HashMap<usize, K> = HashMap::with_capacity(chunk.len());
            let mut stream = ProducerValueStream::new(Arc::clone(&producer), len);
            let mut cursor = 0usize;
            let mut targets: HashSet<usize> = HashSet::with_capacity(chunk.len());
            for idx in chunk {
                targets.insert(*idx);
            }
            let mut leaf_hash_producer = |idx: usize| -> HcResult<HashDigest> {
                if idx != cursor {
                    return Err(HcError::message(
                        "fri v5 merkle path reconstruction called out of order",
                    ));
                }
                let value = stream
                    .next_value()?
                    .ok_or_else(|| HcError::message("fri v5 producer ended early"))?;
                if targets.contains(&idx) {
                    values.insert(idx, value);
                }
                cursor += 1;
                Ok(hash_value_ext(&value))
            };

            let paths = reconstruct_paths_from_replay_mut::<Blake3, _>(
                chunk,
                len,
                2,
                &mut leaf_hash_producer,
            )
            .map_err(|err| {
                HcError::message(format!("Failed to extract v5 FRI Merkle paths: {err}"))
            })?;

            for (&idx, path) in chunk.iter().zip(paths) {
                let value = values
                    .remove(&idx)
                    .ok_or_else(|| HcError::message("missing v5 fri opened value"))?;
                out.insert(idx, (value, path));
            }
        }
        Ok(out)
    }

    let num_layers = artifacts.proof.layer_roots.len();
    debug_assert_eq!(
        num_layers,
        artifacts.betas.len(),
        "v5 layer-root count must equal beta count"
    );

    // Layer-0 coset = LDE coset (offset 7) of size base_length, embedded into K
    // — identical to how `run_fri_v5` builds the base LayerDomain.
    let base_domain_f = hc_core::domain::EvaluationDomain::<GoldilocksField>::new_coset(
        artifacts.base_length,
        GoldilocksField::from_u64(LDE_COSET_OFFSET),
    )?;
    let base_domain: LayerDomain<K> = LayerDomain {
        offset: K::from_base(base_domain_f.offset()),
        gen: K::from_base(base_domain_f.generator()),
        size: base_domain_f.size(),
    };

    // Record, per base query, which layer indices are opened and at which `low`.
    let mut needed_by_layer: Vec<Vec<usize>> = vec![Vec::new(); num_layers];
    let mut per_base: Vec<Vec<(usize, usize)>> = Vec::with_capacity(base_queries.len());
    for &base_query in base_queries {
        let mut local = Vec::new();
        let mut current_index = base_query;
        let mut layer_len = artifacts.base_length;
        for (layer_idx, needed) in needed_by_layer.iter_mut().enumerate() {
            if !is_valid_query_index(current_index, layer_len) {
                break;
            }
            if layer_len < 2 {
                return Err(HcError::message("fri v5 layer too small to fold"));
            }
            let half = layer_len / 2;
            let low = current_index & (half - 1);
            // Antipodal pair (low, low + half) — both < layer_len by construction.
            needed.push(low);
            needed.push(low + half);
            local.push((layer_idx, low));
            current_index = propagate_query_index_v5(current_index, layer_len);
            layer_len /= 2;
        }
        per_base.push(local);
    }

    // Open all needed leaves per layer in a single pass, advancing the antipodal
    // fold producer + squared domain after each layer (mirrors the commit phase).
    let mut opened_by_layer: Vec<HashMap<usize, (K, hc_commit::merkle::MerklePath)>> =
        Vec::with_capacity(num_layers);
    let mut current_producer: Arc<dyn hc_replay::traits::BlockProducer<K>> =
        Arc::clone(&artifacts.base_producer);
    let mut current_len = artifacts.base_length;
    let mut domain = base_domain;
    for (layer_idx, beta) in artifacts.betas.iter().copied().enumerate() {
        let opened = open_many(
            Arc::clone(&current_producer),
            current_len,
            &needed_by_layer[layer_idx],
        )?;
        opened_by_layer.push(opened);
        // Advance to the next folded layer over THIS domain, then square it.
        current_producer = Arc::new(FoldedLayerProducerV5 {
            prev: current_producer,
            prev_len: current_len,
            prev_domain: domain.clone(),
            beta,
        });
        domain = domain.squared();
        current_len /= 2;
    }

    let mut out = Vec::new();
    for local in per_base {
        for (layer_idx, low) in local {
            let half = artifacts.base_length / (1usize << (layer_idx + 1));
            let layer = &opened_by_layer[layer_idx];
            let (v0, p0) = layer
                .get(&low)
                .cloned()
                .ok_or_else(|| HcError::message("missing v5 fri opening for low index"))?;
            let (v1, p1) = layer
                .get(&(low + half))
                .cloned()
                .ok_or_else(|| HcError::message("missing v5 fri opening for antipodal index"))?;
            out.push(FriQuery {
                layer_index: layer_idx,
                query_index: low,
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

#[cfg(test)]
mod v5_query_tests {
    use super::answer_fri_queries_v5;
    use crate::pipeline::phase2_fri::{run_fri_v5, FriTranscriptSeedV5};
    use hc_commit::merkle::MerklePath;
    use hc_core::domain::EvaluationDomain;
    use hc_core::field::{FieldElement, GoldilocksField, QuadExtension};
    use hc_fri::layer::{hash_value_ext, LayerDomain};
    use hc_fri::{propagate_query_index_v5, FriConfig};
    use hc_hash::{Blake3, HashDigest};
    use hc_replay::traits::{BlockProducer, VecBlockProducer};
    use std::sync::Arc;

    type K = QuadExtension<GoldilocksField>;

    /// LDE coset offset matching `run_fri_v5` / the v5 commit phase.
    const LDE_COSET_OFFSET: u64 = 7;

    fn seed_v5(base_len: usize, blowup: usize, final_size: usize) -> FriTranscriptSeedV5 {
        FriTranscriptSeedV5 {
            protocol_version: 5,
            initial_acc: 5,
            final_acc: 8,
            trace_length: (base_len / blowup) as u64,
            query_count: 4,
            lde_blowup: blowup as u64,
            fri_final_size: final_size as u64,
            folding_ratio: 2,
            grinding_bits: 16,
            zk_enabled: false,
            zk_mask_degree: 0,
            trace_commitment: HashDigest::new([0xA5u8; 32]),
            composition_commitment: HashDigest::new([0x5Au8; 32]),
        }
    }

    /// Build the K layer-0 `LayerDomain` exactly as `run_fri_v5` does: the LDE
    /// coset (offset 7) of size `base_len` in F, embedded into K.
    fn base_layer_domain_k(base_len: usize) -> LayerDomain<K> {
        let dom_f = EvaluationDomain::<GoldilocksField>::new_coset(
            base_len,
            GoldilocksField::from_u64(LDE_COSET_OFFSET),
        )
        .unwrap();
        LayerDomain {
            offset: K::from_base(dom_f.offset()),
            gen: K::from_base(dom_f.generator()),
            size: dom_f.size(),
        }
    }

    /// A genuinely low-degree F base codeword (degree `base_len/blowup - 1`) on
    /// the LDE coset, ready to be embedded into K by `run_fri_v5`'s adapter.
    fn low_degree_base(base_len: usize, blowup: usize) -> Vec<GoldilocksField> {
        let dom_f = EvaluationDomain::<GoldilocksField>::new_coset(
            base_len,
            GoldilocksField::from_u64(LDE_COSET_OFFSET),
        )
        .unwrap();
        let deg = base_len / blowup - 1;
        let poly: Vec<GoldilocksField> = (0..=deg)
            .map(|i| GoldilocksField::from_u64((i as u64).wrapping_mul(2_654_435_761) + 101))
            .collect();
        let points: Vec<GoldilocksField> = (0..base_len).map(|j| dom_f.element(j)).collect();
        hc_core::poly::evaluate_batch(&poly, &points)
    }

    /// The antipodal + 1/x fold of a single opened pair at domain point `x`:
    /// `(a + b)/2 + beta*(a - b)/(2*x)`. Mirrors `fold_layer_v5` per element.
    fn fold_pair(a: K, b: K, beta: K, x: K) -> K {
        let two_inv = K::from_u64(2).inverse().unwrap();
        let inv_two_x = x.add(x).inverse().unwrap();
        let even = a.add(b).mul(two_inv);
        let odd = a.sub(b).mul(inv_two_x);
        even.add(beta.mul(odd))
    }

    /// Verify a MerklePath against a root using the K-aware leaf hash.
    fn path_verifies(path: &MerklePath, root: HashDigest, value: &K) -> bool {
        path.verify::<Blake3>(root, hash_value_ext(value))
    }

    /// **Openings Merkle-verify against the committed v5 roots.**
    /// For every opened value of every base query, its reconstructed Merkle path
    /// must verify against `layer_roots[layer_idx]` using `hash_value_ext` leaf
    /// hashes — exactly the check the Task-8 verifier will perform.
    #[test]
    fn v5_openings_merkle_verify_against_committed_roots() {
        let blowup = 2usize;
        for &(base_len, final_size) in &[(16usize, 2usize), (64, 4), (256, 8), (1024, 2)] {
            let config = FriConfig::new(final_size).unwrap();
            let values = low_degree_base(base_len, blowup);
            let producer: Arc<dyn BlockProducer<GoldilocksField>> =
                Arc::new(VecBlockProducer::new(values));
            let artifacts = run_fri_v5(
                config,
                producer,
                base_len,
                seed_v5(base_len, blowup, final_size),
            )
            .unwrap();

            // A spread of base queries across the LDE coset.
            let base_queries: Vec<usize> =
                vec![0, 1, 3, base_len / 2, base_len / 2 + 1, base_len - 1];
            let queries = answer_fri_queries_v5(&base_queries, &artifacts).unwrap();
            assert!(
                !queries.is_empty(),
                "expected openings (base_len={base_len})"
            );

            for q in &queries {
                let root = artifacts.proof.layer_roots[q.layer_index];
                assert!(
                    path_verifies(&q.merkle_paths[0], root, &q.values[0]),
                    "low opening path must verify against layer {} root (base_len={base_len})",
                    q.layer_index
                );
                assert!(
                    path_verifies(&q.merkle_paths[1], root, &q.values[1]),
                    "antipodal opening path must verify against layer {} root (base_len={base_len})",
                    q.layer_index
                );
            }
        }
    }

    /// **Antipodal-fold consistency.** For each consecutive layer pair in an
    /// opening chain, folding the opened pair `[a, b] = [f(x), f(-x)]` at the
    /// layer's domain point `x = D[low]` with the artifact beta must equal the
    /// next layer's opened value at its `low` position (`values[0]`). This is
    /// precisely the internal consistency Task 8's verifier checks.
    #[test]
    fn v5_openings_antipodal_fold_consistency() {
        let blowup = 2usize;
        for &(base_len, final_size) in &[(64usize, 2usize), (256, 4), (1024, 2)] {
            let config = FriConfig::new(final_size).unwrap();
            let values = low_degree_base(base_len, blowup);
            let producer: Arc<dyn BlockProducer<GoldilocksField>> =
                Arc::new(VecBlockProducer::new(values));
            let artifacts = run_fri_v5(
                config,
                producer,
                base_len,
                seed_v5(base_len, blowup, final_size),
            )
            .unwrap();

            // Per-layer LayerDomain chain (offset 7, embedded to K, squared each layer).
            let mut domains: Vec<LayerDomain<K>> = Vec::new();
            let mut dom = base_layer_domain_k(base_len);
            for _ in 0..artifacts.betas.len() {
                domains.push(dom.clone());
                dom = dom.squared();
            }

            for &bq in &[1usize, 3, base_len / 2 + 1, base_len - 1] {
                let chain = answer_fri_queries_v5(&[bq], &artifacts).unwrap();
                // chain is ordered by descending layer for a single base query.
                for w in chain.windows(2) {
                    let cur = &w[0];
                    let next = &w[1];
                    assert_eq!(
                        cur.layer_index + 1,
                        next.layer_index,
                        "opening chain must be consecutive layers"
                    );
                    let beta = artifacts.betas[cur.layer_index];
                    let x = domains[cur.layer_index].point(cur.query_index);
                    let folded = fold_pair(cur.values[0], cur.values[1], beta, x);

                    // The folded value f_{L+1} lives at next-layer index
                    // `current_{L+1} = cur.query_index` (size = half of layer L).
                    // The NEXT opening exposes the antipodal pair around
                    // `next.query_index`; the folded value is whichever slot
                    // `current_{L+1}` lands in: slot 0 if it equals the recorded
                    // low, else slot 1 (the antipodal partner).
                    let next_current = cur.query_index;
                    let slot = if next_current == next.query_index {
                        0
                    } else {
                        1
                    };
                    assert_eq!(
                        folded, next.values[slot],
                        "antipodal fold of layer {} pair must equal layer {} opened value \
                         at the propagated index (base_len={base_len}, base_query={bq})",
                        cur.layer_index, next.layer_index
                    );
                }

                // Also tie the FINAL opened layer into proof.final_layer: folding
                // the last opened pair lands at final_layer[current_{L+1}].
                if let Some(last) = chain.last() {
                    let beta = artifacts.betas[last.layer_index];
                    let x = domains[last.layer_index].point(last.query_index);
                    let folded = fold_pair(last.values[0], last.values[1], beta, x);
                    // current_{L+1} == last.query_index (= low of the last layer).
                    let final_idx = last.query_index;
                    assert_eq!(
                        folded, artifacts.proof.final_layer[final_idx],
                        "fold of last opened layer must equal final_layer[current] \
                         (base_len={base_len}, base_query={bq})"
                    );
                }
            }
        }
    }

    /// **Index map.** The `query_index` recorded at each layer must equal
    /// `propagate_query_index_v5` applied down the chain from the base query,
    /// and the opened values must be the antipodal pair `[layer[low], layer[low+half]]`.
    #[test]
    fn v5_recorded_query_indices_follow_propagate_v5() {
        let blowup = 2usize;
        let (base_len, final_size) = (256usize, 4usize);
        let config = FriConfig::new(final_size).unwrap();
        let values = low_degree_base(base_len, blowup);
        let producer: Arc<dyn BlockProducer<GoldilocksField>> =
            Arc::new(VecBlockProducer::new(values));
        let artifacts = run_fri_v5(
            config,
            producer,
            base_len,
            seed_v5(base_len, blowup, final_size),
        )
        .unwrap();

        for &bq in &[0usize, 5, 130, base_len - 1] {
            let chain = answer_fri_queries_v5(&[bq], &artifacts).unwrap();
            let mut expected_current = bq;
            let mut layer_len = base_len;
            for q in &chain {
                let expected_low = expected_current & (layer_len / 2 - 1);
                assert_eq!(
                    q.query_index, expected_low,
                    "recorded query_index must be `current & (n/2 - 1)` \
                     (layer={}, base_query={bq})",
                    q.layer_index
                );
                expected_current = propagate_query_index_v5(expected_current, layer_len);
                layer_len /= 2;
            }
            // Chain length equals the committed layer count (descends to final size).
            assert_eq!(chain.len(), artifacts.proof.layer_roots.len());
        }
    }

    /// The opened pair really is the antipodal pair of the materialized layer:
    /// independently fold the base codeword down with `fold_layer_v5` using the
    /// artifact betas, then check `values == [layer[low], layer[low + n/2]]` at
    /// each opened layer.
    #[test]
    fn v5_opened_values_are_antipodal_pair_of_materialized_layer() {
        let blowup = 2usize;
        let (base_len, final_size) = (256usize, 4usize);
        let config = FriConfig::new(final_size).unwrap();
        let base_values_f = low_degree_base(base_len, blowup);
        let base_values_k: Vec<K> = base_values_f.iter().map(|&v| K::from_base(v)).collect();
        let producer: Arc<dyn BlockProducer<GoldilocksField>> =
            Arc::new(VecBlockProducer::new(base_values_f));
        let artifacts = run_fri_v5(
            config,
            producer,
            base_len,
            seed_v5(base_len, blowup, final_size),
        )
        .unwrap();

        // Materialize every committed layer independently via fold_layer_v5.
        let mut layers: Vec<Vec<K>> = Vec::new();
        let mut layer = base_values_k;
        let mut dom = base_layer_domain_k(base_len);
        for &beta in &artifacts.betas {
            layers.push(layer.clone());
            layer = hc_fri::layer::fold_layer_v5(&layer, &dom, beta).unwrap();
            dom = dom.squared();
        }

        let base_queries: Vec<usize> = vec![0, 7, 128, 200, base_len - 1];
        let queries = answer_fri_queries_v5(&base_queries, &artifacts).unwrap();
        for q in &queries {
            let lyr = &layers[q.layer_index];
            let n = lyr.len();
            let half = n / 2;
            let low = q.query_index;
            assert_eq!(q.values[0], lyr[low], "values[0] must be layer[low]");
            assert_eq!(
                q.values[1],
                lyr[low + half],
                "values[1] must be layer[low + n/2] (antipodal partner)"
            );
        }
    }
}
