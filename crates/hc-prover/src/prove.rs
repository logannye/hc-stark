use std::{sync::Arc, time::Instant};

use hc_air::{constraints::boundary::BoundaryConstraints, DeepStarkAir, ToyAir};
use hc_core::{
    domain::{generate_lde_coset_domain, generate_trace_domain},
    error::{HcError, HcResult},
    fft::{fft_parallel as fft_in_place, ifft_parallel as ifft_in_place},
    field::FieldElement,
};
use hc_fri::{FriConfig, FriProof};
use hc_hash::{hash::HashDigest, protocol, Blake3, HashFunction, Transcript};
use hc_replay::traits::VecBlockProducer;
use hc_replay::{
    block_range::BlockRange, config::ReplayConfig, trace_replay::TraceReplay, traits::BlockProducer,
};
use hc_vm::Program;

use crate::{
    commitment::{Commitment, CommitmentScheme},
    config::ProverConfig,
    fri_height,
    kzg::TraceKzgState,
    metrics::ProverMetrics,
    pipeline::{phase1_commit, phase3_queries},
    queries::{ProofParams, ProverOutput},
    trace_stream::VmTraceProducer,
};

pub type TraceRow<F> = [F; 2];

#[derive(Clone, Debug)]
pub struct PublicInputs<F> {
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn prove<F: FieldElement + hc_core::field::TwoAdicField>(
    config: ProverConfig,
    program: Program,
    public_inputs: PublicInputs<F>,
) -> HcResult<ProverOutput<F>> {
    if program.instructions.is_empty() {
        return Err(HcError::invalid_argument(
            "program must contain instructions",
        ));
    }
    let trace_length = program.instructions.len() + 1;
    let trace_producer = VmTraceProducer::new(
        program.clone(),
        public_inputs.initial_acc,
        config.block_size.max(1),
    )?;

    // Streaming AIR/trace sanity check: verify boundary and transitions without materializing
    // the full trace table.
    {
        let replay_config = ReplayConfig::new(config.block_size.max(1), trace_length)?;
        let mut replay = TraceReplay::new(replay_config, trace_producer.clone())?;
        let mut prev: Option<TraceRow<F>> = None;
        for block_index in 0..replay.num_blocks() {
            let block = replay.fetch_block(block_index)?;
            for row in block.iter().copied() {
                if let Some(prev_row) = prev {
                    let expected = prev_row[0].add(prev_row[1]);
                    if row[0] != expected {
                        return Err(HcError::invalid_argument(
                            "trace violates transition constraint",
                        ));
                    }
                }
                prev = Some(row);
            }
        }
        let first_block = replay.fetch_block(0)?;
        let first_row = first_block
            .first()
            .copied()
            .ok_or_else(|| HcError::invalid_argument("empty trace"))?;
        if first_row[0] != public_inputs.initial_acc {
            return Err(HcError::invalid_argument(
                "trace violates initial boundary constraint",
            ));
        }
        let last_block = replay.fetch_block(replay.num_blocks() - 1)?;
        let last_row = last_block
            .last()
            .copied()
            .ok_or_else(|| HcError::invalid_argument("empty trace"))?;
        if last_row[0] != public_inputs.final_acc {
            return Err(HcError::invalid_argument(
                "trace violates final boundary constraint",
            ));
        }
    }

    let fri_config = FriConfig::new(config.fri_final_poly_size)?;
    let mut context = ProverContext::new(
        trace_producer,
        trace_length,
        config,
        fri_config,
        public_inputs,
    );
    let mut frames = vec![Frame::BuildQueries, Frame::RunFri, Frame::CommitTrace];
    while let Some(frame) = frames.pop() {
        frame.execute(&mut context)?;
    }
    context.into_output()
}

enum Frame {
    CommitTrace,
    RunFri,
    BuildQueries,
}

impl Frame {
    fn execute<F: FieldElement + hc_core::field::TwoAdicField>(
        &self,
        ctx: &mut ProverContext<F>,
    ) -> HcResult<()> {
        match self {
            Frame::CommitTrace => ctx.run_commit(),
            Frame::RunFri => ctx.run_fri(),
            Frame::BuildQueries => ctx.build_output(),
        }
    }
}

struct ProverContext<F: FieldElement> {
    trace_producer: VmTraceProducer<F>,
    trace_length: usize,
    config: ProverConfig,
    fri_config: FriConfig,
    public_inputs: PublicInputs<F>,
    transcript: Transcript<Blake3>,
    trace_root: Option<HashDigest>,
    trace_commitment: Option<Commitment>,
    composition_commitment: Option<Commitment>,
    composition_coeffs: Option<(u64, u64)>,
    fri_proof: Option<FriProof<F>>,
    fri_artifacts: Option<hc_fri::FriProverArtifacts<F>>,
    output: Option<ProverOutput<F>>,
    metrics: ProverMetrics,
    trace_kzg_state: Option<TraceKzgState>,
    // DEEP-STARK (v3) metadata. We intentionally avoid caching O(N·blowup) oracle vectors;
    // instead we recompute them in phases as needed (trading time for peak memory).
    deep_padded_len: Option<usize>,
    // ZK masking seed (v4). Stored so later phases can recompute masked oracles consistently.
    zk_seed: Option<[u8; 32]>,
}

impl<F: FieldElement + hc_core::field::TwoAdicField> ProverContext<F> {
    fn new(
        trace_producer: VmTraceProducer<F>,
        trace_length: usize,
        config: ProverConfig,
        fri_config: FriConfig,
        public_inputs: PublicInputs<F>,
    ) -> Self {
        let domain = if config.protocol_version >= 4 {
            protocol::DOMAIN_MAIN_V4
        } else if config.protocol_version >= 3 {
            protocol::DOMAIN_MAIN_V3
        } else {
            protocol::DOMAIN_MAIN_V2
        };
        let mut transcript = Transcript::<Blake3>::new(domain);
        // Initialize transcript with public inputs (canonical labels).
        let initial_bytes = public_inputs.initial_acc.to_u64().to_le_bytes();
        transcript.append_message(protocol::label::PUB_INITIAL_ACC, initial_bytes);
        let final_bytes = public_inputs.final_acc.to_u64().to_le_bytes();
        transcript.append_message(protocol::label::PUB_FINAL_ACC, final_bytes);
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PUB_TRACE_LENGTH,
            trace_length as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_QUERY_COUNT,
            config.query_count as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_LDE_BLOWUP,
            config.lde_blowup_factor as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_FRI_FINAL_SIZE,
            config.fri_final_poly_size as u64,
        );
        protocol::append_u64::<Blake3>(
            &mut transcript,
            protocol::label::PARAM_FRI_FOLDING_RATIO,
            hc_fri::get_folding_ratio() as u64,
        );
        transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");

        if config.protocol_version >= 4 {
            protocol::append_u64::<Blake3>(
                &mut transcript,
                protocol::label::PARAM_ZK_ENABLED,
                u64::from(config.zk.enabled),
            );
            protocol::append_u64::<Blake3>(
                &mut transcript,
                protocol::label::PARAM_ZK_MASK_DEGREE,
                config.zk.mask_degree as u64,
            );
        }

        Self {
            trace_producer,
            trace_length,
            config,
            fri_config,
            public_inputs,
            transcript,
            trace_root: None,
            trace_commitment: None,
            composition_commitment: None,
            composition_coeffs: None,
            fri_proof: None,
            fri_artifacts: None,
            output: None,
            metrics: ProverMetrics::default(),
            trace_kzg_state: None,
            deep_padded_len: None,
            zk_seed: config.zk.seed,
        }
    }

    fn run_commit(&mut self) -> HcResult<()> {
        let block_size = self.config.block_size.max(1);
        let replay_config = ReplayConfig::new(block_size, self.trace_length)?;
        let mut trace_replay = TraceReplay::new(replay_config, self.trace_producer.clone())?;
        let total_blocks = trace_replay.num_blocks();
        let boundary = BoundaryConstraints {
            initial_acc: self.public_inputs.initial_acc,
            final_acc: self.public_inputs.final_acc,
        };
        if self.config.commitment == CommitmentScheme::Stark && self.config.protocol_version >= 3 {
            self.run_commit_deep_stark(&mut trace_replay, &boundary)?;
        } else {
            let commitments =
                phase1_commit::commit_trace_streaming(&mut trace_replay, &self.config, &boundary)?;
            self.trace_root = commitments.merkle_trace_root;
            self.trace_commitment = Some(commitments.trace_commitment);
            self.composition_commitment = Some(commitments.composition_commitment);
            self.trace_kzg_state = commitments.trace_kzg_state;
            self.composition_coeffs = commitments.composition_coeffs;
        }

        // Bind commitments into the main transcript before any query indices are sampled.
        // For v3 DEEP-STARK, `run_commit_deep_stark` is responsible for commitment ordering
        // because it must sample alphas after committing the trace LDE root and before
        // building the quotient oracle.
        if !(self.config.commitment == CommitmentScheme::Stark && self.config.protocol_version >= 3)
        {
            let trace_digest = crate::commitment::commitment_digest(
                self.trace_commitment
                    .as_ref()
                    .ok_or_else(|| HcError::message("missing trace commitment"))?,
            );
            self.transcript
                .append_message(protocol::label::COMMIT_TRACE_ROOT, trace_digest.as_bytes());
            let composition_digest = crate::commitment::commitment_digest(
                self.composition_commitment
                    .as_ref()
                    .ok_or_else(|| HcError::message("missing composition commitment"))?,
            );
            self.transcript.append_message(
                protocol::label::COMMIT_COMPOSITION_ROOT,
                composition_digest.as_bytes(),
            );
        }

        self.metrics.add_trace_blocks(total_blocks);
        self.metrics.add_composition_blocks(total_blocks);
        Ok(())
    }

    fn run_commit_deep_stark(
        &mut self,
        trace_replay: &mut TraceReplay<VmTraceProducer<F>, TraceRow<F>>,
        boundary: &BoundaryConstraints<F>,
    ) -> HcResult<()> {
        use hc_commit::merkle::height_dfs::StreamingMerkle;
        use hc_core::random::{sample_field_elements, seeded_rng};
        use rand::rngs::OsRng;
        use rand::RngCore;
        let air = ToyAir;

        let trace_len = self.trace_length;
        let padded_len = trace_len.next_power_of_two();
        let blowup = self.config.lde_blowup_factor;
        let lde_len = padded_len * blowup;
        if padded_len == 0 || lde_len == 0 {
            return Err(HcError::invalid_argument("invalid trace length"));
        }

        // Fixed coset offset for v3 (must match verifier).
        let coset_offset = F::from_u64(7);
        let trace_domain = generate_trace_domain::<F>(padded_len)?;
        let lde_domain = generate_lde_coset_domain::<F>(padded_len, blowup, coset_offset)?;
        let omega_last = trace_domain
            .generator()
            .inverse()
            .ok_or_else(|| HcError::math("trace domain generator has no inverse"))?;

        // Materialize padded trace values for each column on the base trace domain.
        let mut acc_vals = vec![F::ZERO; padded_len];
        let mut delta_vals = vec![F::ZERO; padded_len];
        let block_size = trace_replay.block_size();
        for idx in 0..trace_len {
            let block = trace_replay.fetch_block(idx / block_size)?;
            let row = *block
                .get(idx % block_size)
                .ok_or_else(|| HcError::message("missing trace row while building padded trace"))?;
            acc_vals[idx] = row[0];
            delta_vals[idx] = row[1];
        }
        let last_row = {
            let block = trace_replay.fetch_block((trace_len - 1) / block_size)?;
            *block
                .get((trace_len - 1) % block_size)
                .ok_or_else(|| HcError::message("missing last trace row"))?
        };
        for idx in trace_len..padded_len {
            acc_vals[idx] = last_row[0];
            delta_vals[idx] = last_row[1];
        }

        // Convert base evaluations on H_N into monomial coefficients via IFFT.
        ifft_in_place(&mut acc_vals)?;
        ifft_in_place(&mut delta_vals)?;
        let acc_coeffs = acc_vals;
        let delta_coeffs = delta_vals;

        // Evaluate on the LDE coset by scaling coefficients with offset^k and FFT'ing at size lde_len.
        let mut acc_eval = vec![F::ZERO; lde_len];
        let mut delta_eval = vec![F::ZERO; lde_len];
        let mut offset_pow = F::ONE;
        for k in 0..padded_len {
            acc_eval[k] = acc_coeffs[k].mul(offset_pow);
            delta_eval[k] = delta_coeffs[k].mul(offset_pow);
            offset_pow = offset_pow.mul(coset_offset);
        }
        fft_in_place(&mut acc_eval)?;
        fft_in_place(&mut delta_eval)?;

        // ZK masking (v4): add Z_H(x) * R(x) at LDE points, with R sampled by the prover.
        // This keeps trace values unchanged on H_N (since Z_H=0 there) while blinding openings
        // on the LDE coset domain.
        if self.config.zk.enabled && self.config.zk.mask_degree > 0 {
            // Seed the RNG from OS entropy unless explicitly fixed (tests/bench).
            let seed = if let Some(seed) = self.config.zk.seed {
                seed
            } else {
                let mut seed = [0u8; 32];
                OsRng.fill_bytes(&mut seed);
                seed
            };
            // Persist the seed so later phases can regenerate masked oracles consistently.
            self.zk_seed = Some(seed);
            let mut rng = seeded_rng(seed);

            // Sample low-degree coefficients for R(X) (on the base polynomial basis).
            let r_len = self.config.zk.mask_degree.min(padded_len.saturating_sub(1)) + 1;
            let r_acc = sample_field_elements::<F>(&mut rng, r_len);
            let r_delta = sample_field_elements::<F>(&mut rng, r_len);

            // Evaluate R on the LDE coset (same evaluation method as trace polynomials).
            let mut r_acc_eval = vec![F::ZERO; lde_len];
            let mut r_delta_eval = vec![F::ZERO; lde_len];
            let mut offset_pow = F::ONE;
            for k in 0..r_len {
                r_acc_eval[k] = r_acc[k].mul(offset_pow);
                r_delta_eval[k] = r_delta[k].mul(offset_pow);
                offset_pow = offset_pow.mul(coset_offset);
            }
            fft_in_place(&mut r_acc_eval)?;
            fft_in_place(&mut r_delta_eval)?;

            // Apply Z_H(x) * R(x) at each LDE point.
            for i in 0..lde_len {
                let x = lde_domain.element(i);
                let z_h = x.pow(padded_len as u64).sub(F::ONE);
                acc_eval[i] = acc_eval[i].add(z_h.mul(r_acc_eval[i]));
                delta_eval[i] = delta_eval[i].add(z_h.mul(r_delta_eval[i]));
            }
        }

        // Commit trace LDE oracle (packed leaf: [acc(x), delta(x)]).
        let mut trace_builder = StreamingMerkle::<Blake3>::new();
        for i in 0..lde_len {
            let row = [acc_eval[i], delta_eval[i]];
            trace_builder.push(hash_trace_pair(&row[0], &row[1]));
        }
        let trace_root = trace_builder
            .finalize()
            .ok_or_else(|| HcError::message("failed to finalize trace LDE merkle tree"))?;

        // Sample mixing coefficients from the main transcript.
        // Note: public inputs/params were already appended in `new()`.
        self.transcript.append_message(
            protocol::label::COMMIT_TRACE_LDE_ROOT,
            trace_root.as_bytes(),
        );
        let alpha_boundary = self
            .transcript
            .challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
        let alpha_transition = self
            .transcript
            .challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_TRANSITION);

        // Quotient oracle q(x) = C(x)/(x^N - 1) on the LDE coset.
        let n_inv = F::from_u64(padded_len as u64)
            .inverse()
            .ok_or_else(|| HcError::math("padded_len has no inverse"))?;
        let shift = blowup % lde_len;

        let mut quotient_builder = StreamingMerkle::<Blake3>::new();
        for i in 0..lde_len {
            let x = lde_domain.element(i);
            let z_h = x.pow(padded_len as u64).sub(F::ONE); // x^N - 1
            let z_h_inv = z_h
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero Z_H on coset domain"))?;

            // Lagrange selectors on H_N evaluated at x (coset point).
            let l0 = z_h.mul(n_inv).mul(
                x.sub(F::ONE)
                    .inverse()
                    .ok_or_else(|| HcError::math("unexpected zero denominator in L0 on coset"))?,
            );
            let l_last =
                z_h.mul(omega_last)
                    .mul(n_inv)
                    .mul(x.sub(omega_last).inverse().ok_or_else(|| {
                        HcError::math("unexpected zero denominator in L_last on coset")
                    })?);
            let selector_last = F::ONE.sub(l_last);

            let acc = acc_eval[i];
            let delta = delta_eval[i];
            let acc_next = acc_eval[(i + shift) % lde_len];
            let delta_next = delta_eval[(i + shift) % lde_len];

            let c = air.quotient_numerator(
                &[acc, delta],
                &[acc_next, delta_next],
                l0,
                l_last,
                selector_last,
                alpha_boundary,
                alpha_transition,
                boundary.initial_acc,
                boundary.final_acc,
            )?;

            let q = c.mul(z_h_inv);
            quotient_builder.push(hash_field_element(&q));
        }
        let quotient_root = quotient_builder
            .finalize()
            .ok_or_else(|| HcError::message("failed to finalize quotient merkle tree"))?;

        // Bind the quotient commitment after sampling alphas and building the quotient oracle.
        self.transcript.append_message(
            protocol::label::COMMIT_QUOTIENT_ROOT,
            quotient_root.as_bytes(),
        );

        self.trace_root = Some(trace_root);
        self.trace_commitment = Some(Commitment::Stark { root: trace_root });
        self.composition_commitment = Some(Commitment::Stark {
            root: quotient_root,
        });
        self.composition_coeffs = Some((alpha_boundary.to_u64(), alpha_transition.to_u64()));
        self.deep_padded_len = Some(padded_len);
        Ok(())
    }

    fn run_fri(&mut self) -> HcResult<()> {
        // Streaming FRI:
        // - For the transparent (Merkle) commitment scheme:
        //   - v2: prove low-degree of the row-aligned composition oracle.
        //   - v3: prove low-degree of the DEEP-STARK quotient oracle (evaluated on an LDE coset).
        // - For the KZG commitment scheme, keep the legacy base oracle (acc column) for now.
        let padded_len = self.trace_length.next_power_of_two();
        if padded_len == 0 {
            return Err(HcError::invalid_argument("trace must contain rows"));
        }

        // v3 DEEP-STARK: run FRI directly over the committed quotient oracle.
        if self.config.commitment == CommitmentScheme::Stark && self.config.protocol_version >= 3 {
            let padded_len = self
                .deep_padded_len
                .ok_or_else(|| HcError::message("missing DEEP padded length"))?;
            let lde_len = padded_len * self.config.lde_blowup_factor;
            let (_trace, q) = self.compute_deep_oracles()?;
            if q.len() != lde_len {
                return Err(HcError::message("DEEP quotient oracle length mismatch"));
            }

            let trace_commitment = self
                .trace_commitment
                .as_ref()
                .ok_or_else(|| HcError::message("missing trace commitment"))?;
            let quotient_commitment = self
                .composition_commitment
                .as_ref()
                .ok_or_else(|| HcError::message("missing quotient commitment"))?;
            let seed = crate::pipeline::phase2_fri::FriTranscriptSeed {
                protocol_version: self.config.protocol_version,
                initial_acc: self.public_inputs.initial_acc.to_u64(),
                final_acc: self.public_inputs.final_acc.to_u64(),
                trace_length: self.trace_length as u64,
                query_count: self.config.query_count as u64,
                lde_blowup: self.config.lde_blowup_factor as u64,
                fri_final_size: self.config.fri_final_poly_size as u64,
                folding_ratio: hc_fri::get_folding_ratio() as u64,
                zk_enabled: self.config.zk.enabled,
                zk_mask_degree: self.config.zk.mask_degree as u64,
                trace_commitment: crate::commitment::commitment_digest(trace_commitment),
                composition_commitment: crate::commitment::commitment_digest(quotient_commitment),
            };
            let base_producer: Arc<dyn BlockProducer<F>> = Arc::new(VecBlockProducer::new(q));
            let artifacts = fri_height::prove_fri(self.fri_config, base_producer, lde_len, seed)?;
            self.metrics.add_fri_blocks(artifacts.stats.blocks_loaded);
            self.fri_proof = Some(artifacts.proof.clone());
            self.fri_artifacts = Some(artifacts);
            return Ok(());
        }

        let last_row = self
            .trace_producer
            .produce(BlockRange::new(self.trace_length - 1, 1))?
            .first()
            .copied()
            .ok_or_else(|| HcError::message("failed to fetch last trace row"))?;

        #[derive(Clone)]
        struct PaddedAccProducer<P, F: FieldElement> {
            trace: P,
            trace_len: usize,
            padded_len: usize,
            last_acc: F,
        }

        impl<P, F> BlockProducer<F> for PaddedAccProducer<P, F>
        where
            P: BlockProducer<TraceRow<F>>,
            F: FieldElement,
        {
            fn produce(&self, range: BlockRange) -> HcResult<Vec<F>> {
                let end = range.end().min(self.padded_len);
                if range.start >= end {
                    return Ok(Vec::new());
                }
                let len = end - range.start;
                let mut out = Vec::with_capacity(len);

                if range.start < self.trace_len {
                    let real_end = end.min(self.trace_len);
                    let real_len = real_end - range.start;
                    let rows = self.trace.produce(BlockRange::new(range.start, real_len))?;
                    out.extend(rows.into_iter().map(|row| row[0]));
                }
                while out.len() < len {
                    out.push(self.last_acc);
                }
                Ok(out)
            }
        }

        #[derive(Clone)]
        struct PaddedCompositionProducer<P, F: FieldElement> {
            trace: P,
            boundary: BoundaryConstraints<F>,
            alpha_boundary: F,
            alpha_transition: F,
            trace_len: usize,
            padded_len: usize,
            last_value: F,
        }

        impl<P, F> BlockProducer<F> for PaddedCompositionProducer<P, F>
        where
            P: BlockProducer<TraceRow<F>>,
            F: FieldElement,
        {
            fn produce(&self, range: BlockRange) -> HcResult<Vec<F>> {
                let end = range.end().min(self.padded_len);
                if range.start >= end {
                    return Ok(Vec::new());
                }
                let len = end - range.start;
                let mut out = Vec::with_capacity(len);

                // Real trace portion: compute composition value per row.
                if range.start < self.trace_len {
                    let real_end = end.min(self.trace_len);
                    let real_len = real_end - range.start;
                    let rows = self.trace.produce(BlockRange::new(range.start, real_len))?;

                    for (offset, row) in rows.iter().copied().enumerate() {
                        let idx = range.start + offset;
                        let next_row = if idx + 1 < self.trace_len {
                            if offset + 1 < rows.len() {
                                rows[offset + 1]
                            } else {
                                // Cross-range lookahead
                                let next = self.trace.produce(BlockRange::new(idx + 1, 1))?;
                                *next
                                    .first()
                                    .ok_or_else(|| HcError::message("missing next trace row"))?
                            }
                        } else {
                            row
                        };
                        let value = hc_air::eval::composition_value_for_row(
                            row,
                            next_row,
                            idx,
                            self.trace_len,
                            &self.boundary,
                            self.alpha_boundary,
                            self.alpha_transition,
                        )?;
                        out.push(value);
                    }
                }

                // Padding portion: repeat the last composition value (computed at `trace_len - 1`).
                while out.len() < len {
                    out.push(self.last_value);
                }
                Ok(out)
            }
        }

        let base_producer: std::sync::Arc<dyn BlockProducer<F>> =
            if self.config.commitment == CommitmentScheme::Stark {
                let boundary = BoundaryConstraints {
                    initial_acc: self.public_inputs.initial_acc,
                    final_acc: self.public_inputs.final_acc,
                };
                let (alpha_boundary_u64, alpha_transition_u64) = self
                    .composition_coeffs
                    .ok_or_else(|| HcError::message("missing composition coefficients"))?;
                let alpha_boundary = F::from_u64(alpha_boundary_u64);
                let alpha_transition = F::from_u64(alpha_transition_u64);
                let last_value = hc_air::eval::composition_value_for_row(
                    last_row,
                    last_row,
                    self.trace_length - 1,
                    self.trace_length,
                    &boundary,
                    alpha_boundary,
                    alpha_transition,
                )?;
                std::sync::Arc::new(PaddedCompositionProducer::<_, F> {
                    trace: self.trace_producer.clone(),
                    boundary,
                    alpha_boundary,
                    alpha_transition,
                    trace_len: self.trace_length,
                    padded_len,
                    last_value,
                })
            } else {
                std::sync::Arc::new(PaddedAccProducer::<_, F> {
                    trace: self.trace_producer.clone(),
                    trace_len: self.trace_length,
                    padded_len,
                    last_acc: last_row[0],
                })
            };
        let trace_commitment = self
            .trace_commitment
            .as_ref()
            .ok_or_else(|| HcError::message("missing trace commitment"))?;
        let composition_commitment = self
            .composition_commitment
            .as_ref()
            .ok_or_else(|| HcError::message("missing composition commitment"))?;
        let seed = crate::pipeline::phase2_fri::FriTranscriptSeed {
            protocol_version: self.config.protocol_version,
            initial_acc: self.public_inputs.initial_acc.to_u64(),
            final_acc: self.public_inputs.final_acc.to_u64(),
            trace_length: self.trace_length as u64,
            query_count: self.config.query_count as u64,
            lde_blowup: self.config.lde_blowup_factor as u64,
            fri_final_size: self.config.fri_final_poly_size as u64,
            folding_ratio: hc_fri::get_folding_ratio() as u64,
            zk_enabled: self.config.zk.enabled,
            zk_mask_degree: self.config.zk.mask_degree as u64,
            trace_commitment: crate::commitment::commitment_digest(trace_commitment),
            composition_commitment: crate::commitment::commitment_digest(composition_commitment),
        };
        let artifacts = fri_height::prove_fri(self.fri_config, base_producer, padded_len, seed)?;
        self.metrics.add_fri_blocks(artifacts.stats.blocks_loaded);
        self.fri_proof = Some(artifacts.proof.clone());
        self.fri_artifacts = Some(artifacts);
        Ok(())
    }

    fn compute_deep_oracles(&self) -> HcResult<(Vec<TraceRow<F>>, Vec<F>)> {
        // NOTE: This currently materializes vectors. We keep it as a shared helper so we can
        // replace its internals with true streaming producers (BlockProducer-based) in the
        // next iteration without changing call sites.
        let trace_len = self.trace_length;
        let padded_len = trace_len.next_power_of_two();
        let blowup = self.config.lde_blowup_factor;
        let lde_len = padded_len * blowup;
        if trace_len == 0 || padded_len == 0 || lde_len == 0 {
            return Err(HcError::invalid_argument("invalid trace length"));
        }

        let coset_offset = F::from_u64(7);
        let trace_domain = generate_trace_domain::<F>(padded_len)?;
        let lde_domain = generate_lde_coset_domain::<F>(padded_len, blowup, coset_offset)?;
        let omega_last = trace_domain
            .generator()
            .inverse()
            .ok_or_else(|| HcError::math("trace domain generator has no inverse"))?;

        // Load padded trace values.
        let mut acc_vals = vec![F::ZERO; padded_len];
        let mut delta_vals = vec![F::ZERO; padded_len];
        let replay_config = ReplayConfig::new(self.config.block_size.max(1), trace_len)?;
        let mut replay = TraceReplay::new(replay_config, self.trace_producer.clone())?;
        let block_size = replay.block_size();
        for idx in 0..trace_len {
            let block = replay.fetch_block(idx / block_size)?;
            let row = *block
                .get(idx % block_size)
                .ok_or_else(|| HcError::message("missing trace row while building padded trace"))?;
            acc_vals[idx] = row[0];
            delta_vals[idx] = row[1];
        }
        let last_row = {
            let block = replay.fetch_block((trace_len - 1) / block_size)?;
            *block
                .get((trace_len - 1) % block_size)
                .ok_or_else(|| HcError::message("missing last trace row"))?
        };
        for idx in trace_len..padded_len {
            acc_vals[idx] = last_row[0];
            delta_vals[idx] = last_row[1];
        }

        // IFFT to coefficients.
        let mut acc_coeffs = acc_vals;
        let mut delta_coeffs = delta_vals;
        ifft_in_place(&mut acc_coeffs)?;
        ifft_in_place(&mut delta_coeffs)?;

        // Evaluate on coset: scale coeffs by offset^k then FFT at size lde_len.
        let mut acc_eval = vec![F::ZERO; lde_len];
        let mut delta_eval = vec![F::ZERO; lde_len];
        let mut offset_pow = F::ONE;
        for k in 0..padded_len {
            acc_eval[k] = acc_coeffs[k].mul(offset_pow);
            delta_eval[k] = delta_coeffs[k].mul(offset_pow);
            offset_pow = offset_pow.mul(coset_offset);
        }
        fft_in_place(&mut acc_eval)?;
        fft_in_place(&mut delta_eval)?;

        // Apply the same ZK masking as used during commitment (v4).
        if self.config.zk.enabled && self.config.zk.mask_degree > 0 {
            use hc_core::random::{sample_field_elements, seeded_rng};
            let seed = self.zk_seed.ok_or_else(|| {
                HcError::message("missing ZK seed for masked oracle recomputation")
            })?;
            let mut rng = seeded_rng(seed);

            let r_len = self.config.zk.mask_degree.min(padded_len.saturating_sub(1)) + 1;
            let r_acc = sample_field_elements::<F>(&mut rng, r_len);
            let r_delta = sample_field_elements::<F>(&mut rng, r_len);

            let mut r_acc_eval = vec![F::ZERO; lde_len];
            let mut r_delta_eval = vec![F::ZERO; lde_len];
            let mut offset_pow = F::ONE;
            for k in 0..r_len {
                r_acc_eval[k] = r_acc[k].mul(offset_pow);
                r_delta_eval[k] = r_delta[k].mul(offset_pow);
                offset_pow = offset_pow.mul(coset_offset);
            }
            fft_in_place(&mut r_acc_eval)?;
            fft_in_place(&mut r_delta_eval)?;

            for i in 0..lde_len {
                let x = lde_domain.element(i);
                let z_h = x.pow(padded_len as u64).sub(F::ONE);
                acc_eval[i] = acc_eval[i].add(z_h.mul(r_acc_eval[i]));
                delta_eval[i] = delta_eval[i].add(z_h.mul(r_delta_eval[i]));
            }
        }

        // Compute quotient.
        let n_inv = F::from_u64(padded_len as u64)
            .inverse()
            .ok_or_else(|| HcError::math("padded_len has no inverse"))?;
        let shift = blowup % lde_len;
        let boundary = BoundaryConstraints {
            initial_acc: self.public_inputs.initial_acc,
            final_acc: self.public_inputs.final_acc,
        };
        // Re-derive alphas (must match commit ordering).
        // We store the u64 forms so this is deterministic.
        let (alpha_boundary_u64, alpha_transition_u64) = self
            .composition_coeffs
            .ok_or_else(|| HcError::message("missing composition coefficients"))?;
        let alpha_boundary = F::from_u64(alpha_boundary_u64);
        let alpha_transition = F::from_u64(alpha_transition_u64);
        let air = ToyAir;

        let mut trace_lde = Vec::with_capacity(lde_len);
        let mut quotient = Vec::with_capacity(lde_len);
        for i in 0..lde_len {
            let x = lde_domain.element(i);
            let z_h = x.pow(padded_len as u64).sub(F::ONE);
            let z_h_inv = z_h
                .inverse()
                .ok_or_else(|| HcError::math("unexpected zero Z_H on coset domain"))?;
            let l0 = z_h.mul(n_inv).mul(
                x.sub(F::ONE)
                    .inverse()
                    .ok_or_else(|| HcError::math("unexpected zero denominator in L0 on coset"))?,
            );
            let l_last =
                z_h.mul(omega_last)
                    .mul(n_inv)
                    .mul(x.sub(omega_last).inverse().ok_or_else(|| {
                        HcError::math("unexpected zero denominator in L_last on coset")
                    })?);
            let selector_last = F::ONE.sub(l_last);

            let acc = acc_eval[i];
            let delta = delta_eval[i];
            let acc_next = acc_eval[(i + shift) % lde_len];
            let delta_next = delta_eval[(i + shift) % lde_len];
            let c = air.quotient_numerator(
                &[acc, delta],
                &[acc_next, delta_next],
                l0,
                l_last,
                selector_last,
                alpha_boundary,
                alpha_transition,
                boundary.initial_acc,
                boundary.final_acc,
            )?;
            quotient.push(c.mul(z_h_inv));
            trace_lde.push([acc, delta]);
        }

        Ok((trace_lde, quotient))
    }

    fn build_output(&mut self) -> HcResult<()> {
        let fri_artifacts = self
            .fri_artifacts
            .take()
            .ok_or_else(|| HcError::message("missing FRI prover artifacts"))?;
        let fri_proof = fri_artifacts.proof.clone();

        // Bind FRI commitments into the main transcript before sampling query indices.
        for root in &fri_proof.layer_roots {
            self.transcript
                .append_message(protocol::label::COMMIT_FRI_LAYER_ROOT, root.as_bytes());
        }
        self.transcript.append_message(
            protocol::label::COMMIT_FRI_FINAL_ROOT,
            fri_proof.final_root.as_bytes(),
        );
        let trace_commitment = self
            .trace_commitment
            .clone()
            .ok_or_else(|| HcError::message("missing trace commitment"))?;
        let composition_commitment = self
            .composition_commitment
            .clone()
            .ok_or_else(|| HcError::message("missing composition commitment"))?;

        if self.config.commitment == CommitmentScheme::Stark && self.trace_root.is_none() {
            return Err(HcError::message("missing trace root for Stark commitment"));
        }
        let block_size = self.config.block_size.max(1);
        let replay_config = ReplayConfig::new(block_size, self.trace_length)?;
        let mut trace_replay = TraceReplay::new(replay_config, self.trace_producer.clone())?;
        let query_timer = Instant::now();
        let composition_coeffs = if self.config.commitment == CommitmentScheme::Stark {
            let (alpha_boundary_u64, alpha_transition_u64) = self
                .composition_coeffs
                .ok_or_else(|| HcError::message("missing composition coefficients"))?;
            Some((
                F::from_u64(alpha_boundary_u64),
                F::from_u64(alpha_transition_u64),
                self.public_inputs.initial_acc,
                self.public_inputs.final_acc,
            ))
        } else {
            None
        };
        let queries = if self.config.commitment == CommitmentScheme::Stark
            && self.config.protocol_version >= 3
        {
            // DEEP-STARK (v3): queries are over the LDE coset oracles (trace LDE + quotient LDE).
            use hc_commit::merkle::reconstruct_path_from_replay_mut;

            let padded_len = self
                .deep_padded_len
                .ok_or_else(|| HcError::message("missing DEEP padded length"))?;
            let blowup = self.config.lde_blowup_factor;
            let lde_len = padded_len * blowup;
            let (trace_lde, quotient_lde) = self.compute_deep_oracles()?;
            if trace_lde.len() != lde_len || quotient_lde.len() != lde_len {
                return Err(HcError::message("DEEP oracle length mismatch"));
            }

            let base_queries = phase3_queries::generate_queries::<F>(
                &mut self.transcript,
                lde_len,
                self.config.query_count,
            )?;

            let shift = blowup % lde_len;

            let mut trace_queries = Vec::with_capacity(base_queries.len());
            for &idx in &base_queries {
                let evaluation = *trace_lde
                    .get(idx)
                    .ok_or_else(|| HcError::message("trace LDE query out of range"))?;
                let mut leaf_hash = |leaf_index: usize| -> HcResult<HashDigest> {
                    let row = trace_lde
                        .get(leaf_index)
                        .ok_or_else(|| HcError::message("trace LDE leaf out of range"))?;
                    Ok(hash_trace_pair(&row[0], &row[1]))
                };
                let witness =
                    reconstruct_path_from_replay_mut::<Blake3, _>(idx, lde_len, 2, &mut leaf_hash)
                        .map_err(|err| {
                            HcError::message(format!("Failed to extract trace LDE path: {err}"))
                        })?;

                let next_idx = (idx + shift) % lde_len;
                let next_eval = *trace_lde
                    .get(next_idx)
                    .ok_or_else(|| HcError::message("trace LDE next out of range"))?;
                let mut leaf_hash2 = |leaf_index: usize| -> HcResult<HashDigest> {
                    let row = trace_lde
                        .get(leaf_index)
                        .ok_or_else(|| HcError::message("trace LDE leaf out of range"))?;
                    Ok(hash_trace_pair(&row[0], &row[1]))
                };
                let next_witness = reconstruct_path_from_replay_mut::<Blake3, _>(
                    next_idx,
                    lde_len,
                    2,
                    &mut leaf_hash2,
                )
                .map_err(|err| {
                    HcError::message(format!("Failed to extract trace LDE next path: {err}"))
                })?;
                let next = Some(crate::queries::NextTraceRow {
                    index: next_idx,
                    evaluation: next_eval,
                    witness: next_witness,
                });

                trace_queries.push(crate::queries::TraceQuery {
                    index: idx,
                    evaluation,
                    witness: crate::queries::TraceWitness::Merkle(witness),
                    next,
                });
            }
            trace_queries.sort_by_key(|q| q.index);

            let mut composition_queries = Vec::with_capacity(base_queries.len());
            for &idx in &base_queries {
                let value = *quotient_lde
                    .get(idx)
                    .ok_or_else(|| HcError::message("quotient query out of range"))?;
                let mut leaf_hash = |leaf_index: usize| -> HcResult<HashDigest> {
                    let v = quotient_lde
                        .get(leaf_index)
                        .copied()
                        .ok_or_else(|| HcError::message("quotient leaf out of range"))?;
                    Ok(hash_field_element(&v))
                };
                let witness =
                    reconstruct_path_from_replay_mut::<Blake3, _>(idx, lde_len, 2, &mut leaf_hash)
                        .map_err(|err| {
                            HcError::message(format!(
                                "Failed to extract quotient Merkle path: {err}"
                            ))
                        })?;
                composition_queries.push(crate::queries::CompositionQuery {
                    index: idx,
                    value,
                    witness,
                });
            }
            composition_queries.sort_by_key(|q| q.index);

            let fri_queries = phase3_queries::answer_fri_queries(&base_queries, &fri_artifacts)?;

            // OOD-style extra check: sample an additional index from the transcript (separate label)
            // and include its trace/quotient openings in the proof.
            self.transcript
                .append_message(protocol::label::CHAL_OOD_POINT, [0u8]);
            let ood_fe = self
                .transcript
                .challenge_field::<F>(protocol::label::CHAL_OOD_INDEX);
            let ood_index = (ood_fe.to_u64() as usize) % lde_len;
            let ood_trace_eval = *trace_lde
                .get(ood_index)
                .ok_or_else(|| HcError::message("ood trace query out of range"))?;
            let mut leaf_hash = |leaf_index: usize| -> HcResult<HashDigest> {
                let row = trace_lde
                    .get(leaf_index)
                    .ok_or_else(|| HcError::message("trace LDE leaf out of range"))?;
                Ok(hash_trace_pair(&row[0], &row[1]))
            };
            let ood_trace_path = hc_commit::merkle::reconstruct_path_from_replay_mut::<Blake3, _>(
                ood_index,
                lde_len,
                2,
                &mut leaf_hash,
            )
            .map_err(|err| HcError::message(format!("Failed to extract OOD trace path: {err}")))?;
            let ood_next_idx = (ood_index + shift) % lde_len;
            let ood_next_eval = *trace_lde
                .get(ood_next_idx)
                .ok_or_else(|| HcError::message("ood trace next out of range"))?;
            let mut leaf_hash2 = |leaf_index: usize| -> HcResult<HashDigest> {
                let row = trace_lde
                    .get(leaf_index)
                    .ok_or_else(|| HcError::message("trace LDE leaf out of range"))?;
                Ok(hash_trace_pair(&row[0], &row[1]))
            };
            let ood_next_path = hc_commit::merkle::reconstruct_path_from_replay_mut::<Blake3, _>(
                ood_next_idx,
                lde_len,
                2,
                &mut leaf_hash2,
            )
            .map_err(|err| {
                HcError::message(format!("Failed to extract OOD trace next path: {err}"))
            })?;
            let ood_trace = crate::queries::TraceQuery {
                index: ood_index,
                evaluation: ood_trace_eval,
                witness: crate::queries::TraceWitness::Merkle(ood_trace_path),
                next: Some(crate::queries::NextTraceRow {
                    index: ood_next_idx,
                    evaluation: ood_next_eval,
                    witness: ood_next_path,
                }),
            };

            let ood_q = *quotient_lde
                .get(ood_index)
                .ok_or_else(|| HcError::message("ood quotient out of range"))?;
            let mut q_leaf_hash = |leaf_index: usize| -> HcResult<HashDigest> {
                let v = quotient_lde
                    .get(leaf_index)
                    .copied()
                    .ok_or_else(|| HcError::message("quotient leaf out of range"))?;
                Ok(hash_field_element(&v))
            };
            let ood_q_path = hc_commit::merkle::reconstruct_path_from_replay_mut::<Blake3, _>(
                ood_index,
                lde_len,
                2,
                &mut q_leaf_hash,
            )
            .map_err(|err| {
                HcError::message(format!("Failed to extract OOD quotient path: {err}"))
            })?;
            let ood_quotient = crate::queries::CompositionQuery {
                index: ood_index,
                value: ood_q,
                witness: ood_q_path,
            };
            let ood = Some(crate::queries::OodOpenings {
                index: ood_index,
                trace: ood_trace,
                quotient: ood_quotient,
            });

            crate::queries::QueryResponse {
                trace_queries,
                composition_queries,
                fri_queries,
                boundary: None,
                ood,
            }
        } else {
            phase3_queries::build_queries(
                &mut self.transcript,
                &mut trace_replay,
                &fri_artifacts,
                self.config.query_count,
                self.config.commitment,
                self.trace_kzg_state.as_ref(),
                composition_coeffs,
            )?
        };
        let elapsed_ms = query_timer.elapsed().as_millis() as u64;
        self.metrics.record_fri_queries(
            self.config.query_count,
            queries.fri_queries.len(),
            elapsed_ms,
        );
        let query_response = Some(queries);

        self.output = Some(ProverOutput {
            version: self.config.protocol_version,
            trace_commitment,
            composition_commitment,
            fri_proof,
            public_inputs: self.public_inputs.clone(),
            query_response,
            metrics: self.metrics.clone(),
            trace_length: self.trace_length,
            commitment_scheme: self.config.commitment,
            params: ProofParams {
                query_count: self.config.query_count,
                lde_blowup_factor: self.config.lde_blowup_factor,
                fri_final_poly_size: self.config.fri_final_poly_size,
                fri_folding_ratio: hc_fri::get_folding_ratio(),
                protocol_version: self.config.protocol_version,
                zk_enabled: self.config.zk.enabled,
                zk_mask_degree: self.config.zk.mask_degree,
            },
        });
        Ok(())
    }

    fn into_output(mut self) -> HcResult<ProverOutput<F>> {
        self.output
            .take()
            .ok_or_else(|| HcError::message("prover output not built"))
    }
}

fn hash_trace_pair<F: FieldElement>(left: &F, right: &F) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&left.to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&right.to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}

fn hash_field_element<F: FieldElement>(value: &F) -> HashDigest {
    Blake3::hash(&value.to_u64().to_le_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commitment::CommitmentScheme;
    use hc_vm::isa::Instruction;

    #[test]
    fn prover_generates_proof_for_toy_program() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: hc_core::field::prime_field::GoldilocksField::new(5),
            final_acc: hc_core::field::prime_field::GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        let proof = prove(config, program, inputs.clone()).unwrap();
        assert_eq!(proof.public_inputs.final_acc, inputs.final_acc);
    }

    #[test]
    fn prover_emits_kzg_commitment() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: hc_core::field::prime_field::GoldilocksField::new(5),
            final_acc: hc_core::field::prime_field::GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2)
            .unwrap()
            .with_commitment(CommitmentScheme::Kzg);
        let proof = prove(config, program, inputs).unwrap();
        assert_eq!(proof.commitment_scheme, CommitmentScheme::Kzg);
        assert!(matches!(
            proof.trace_commitment,
            crate::commitment::Commitment::Kzg { .. }
        ));
        let query_response = proof
            .query_response
            .expect("kzg proofs should carry query responses");
        assert!(
            query_response
                .trace_queries
                .iter()
                .all(|query| matches!(query.witness, crate::queries::TraceWitness::Kzg(_))),
            "all witnesses should be KZG proofs"
        );
    }
}
