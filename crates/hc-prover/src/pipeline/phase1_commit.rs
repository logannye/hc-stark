use hc_air::constraints::boundary::BoundaryConstraints;
use hc_commit::merkle::height_dfs::StreamingMerkle;
use hc_core::{
    error::{HcError, HcResult},
    field::{FieldElement, TwoAdicField},
};
use hc_hash::protocol;
use hc_hash::{hash::HashDigest, Blake3, HashFunction, Transcript};
use hc_replay::{trace_replay::TraceReplay, traits::BlockProducer};

use crate::{
    commitment::{Commitment, CommitmentScheme},
    config::ProverConfig,
    kzg::{convert_coeffs, convert_domain, ensure_degree, serialize_commitment, TraceKzgState},
    TraceRow,
};

pub struct CommitmentArtifacts {
    pub trace_commitment: Commitment,
    pub composition_commitment: Commitment,
    pub merkle_trace_root: Option<HashDigest>,
    pub trace_kzg_state: Option<TraceKzgState>,
    pub composition_coeffs: Option<(u64, u64)>,
}

pub fn commit_trace_streaming<F, P>(
    trace: &mut TraceReplay<P, TraceRow<F>>,
    config: &ProverConfig,
    boundary: &BoundaryConstraints<F>,
) -> HcResult<CommitmentArtifacts>
where
    F: FieldElement + TwoAdicField,
    P: BlockProducer<TraceRow<F>>,
{
    let trace_len = trace.trace_length();
    if trace_len == 0 {
        return Err(HcError::invalid_argument("trace must contain rows"));
    }

    let block_size = trace.block_size();
    let num_blocks = trace.num_blocks();
    match config.commitment {
        CommitmentScheme::Stark => {
            let mut trace_builder = StreamingMerkle::<Blake3>::new();
            let mut composition_builder = StreamingMerkle::<Blake3>::new();

            // Trace commitment: stream over trace rows, no buffering.
            for block_index in 0..num_blocks {
                let block = trace.fetch_block(block_index)?;
                for row in block.iter() {
                    trace_builder.push(hash_trace_pair(&row[0], &row[1]));
                }
            }

            let trace_root = trace_builder
                .finalize()
                .ok_or_else(|| HcError::message("failed to finalize trace merkle tree"))?;

            // Composition transcript is seeded with public inputs + parameters + trace commitment.
            let mut composition_transcript =
                Transcript::<Blake3>::new(protocol::DOMAIN_COMPOSITION_V2);
            protocol::append_u64::<Blake3>(
                &mut composition_transcript,
                protocol::label::PUB_INITIAL_ACC,
                boundary.initial_acc.to_u64(),
            );
            protocol::append_u64::<Blake3>(
                &mut composition_transcript,
                protocol::label::PUB_FINAL_ACC,
                boundary.final_acc.to_u64(),
            );
            protocol::append_u64::<Blake3>(
                &mut composition_transcript,
                protocol::label::PUB_TRACE_LENGTH,
                trace_len as u64,
            );
            protocol::append_u64::<Blake3>(
                &mut composition_transcript,
                protocol::label::PARAM_LDE_BLOWUP,
                config.lde_blowup_factor as u64,
            );
            protocol::append_u64::<Blake3>(
                &mut composition_transcript,
                protocol::label::PARAM_FRI_FOLDING_RATIO,
                hc_fri::get_folding_ratio() as u64,
            );
            composition_transcript.append_message(protocol::label::PARAM_HASH_ID, b"blake3");
            composition_transcript
                .append_message(protocol::label::COMMIT_TRACE_ROOT, trace_root.as_bytes());

            // Global mixing coefficients for a row-aligned composition oracle.
            let alpha_boundary = composition_transcript
                .challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_BOUNDARY);
            let alpha_transition = composition_transcript
                .challenge_field::<F>(protocol::label::COMPOSITION_ALPHA_TRANSITION);

            // Row-aligned composition commitment: one value per trace row.
            // c[i] = alpha_transition * (next_acc - (acc+delta)) + alpha_boundary * boundary_diff
            let mut row_index = 0usize;
            for block_index in 0..num_blocks {
                let block = trace.fetch_block(block_index)?;
                let local_len = block.len();
                let rows: Vec<TraceRow<F>> = block.to_vec();
                for (offset, row) in rows.iter().copied().enumerate() {
                    let next = if row_index + 1 < trace_len {
                        if offset + 1 < local_len {
                            Some(rows[offset + 1])
                        } else {
                            // Cross-block lookahead
                            let next_idx = row_index + 1;
                            let nb = trace.fetch_block(next_idx / block_size)?;
                            Some(*nb.get(next_idx % block_size).ok_or_else(|| {
                                HcError::message("missing next row while building composition")
                            })?)
                        }
                    } else {
                        None
                    };

                    let next_row = next.unwrap_or(row);
                    let value = hc_air::eval::composition_value_for_row(
                        row,
                        next_row,
                        row_index,
                        trace_len,
                        boundary,
                        alpha_boundary,
                        alpha_transition,
                    )?;
                    composition_builder.push(hash_field_element(&value));
                    row_index += 1;
                }
            }

            let composition_root = composition_builder
                .finalize()
                .ok_or_else(|| HcError::message("failed to finalize composition merkle tree"))?;

            Ok(CommitmentArtifacts {
                trace_commitment: Commitment::Stark { root: trace_root },
                composition_commitment: Commitment::Stark {
                    root: composition_root,
                },
                merkle_trace_root: Some(trace_root),
                trace_kzg_state: None,
                composition_coeffs: Some((alpha_boundary.to_u64(), alpha_transition.to_u64())),
            })
        }
        CommitmentScheme::Kzg => {
            // Keep the existing KZG path for now (it still materializes full vectors).
            // The transparent STARK path is the primary target for √T-space.
            use hc_core::domain::{generate_lde_domain, generate_trace_domain};
            use hc_core::poly::interpolate;

            let padded_trace_len = trace_len.next_power_of_two();
            let trace_domain = generate_trace_domain::<F>(padded_trace_len)?;
            let lde_domain = generate_lde_domain::<F>(padded_trace_len, config.lde_blowup_factor)?;

            let mut full_trace = Vec::with_capacity(trace_len);
            for block_index in 0..num_blocks {
                let block = trace.fetch_block(block_index)?;
                full_trace.extend_from_slice(block);
            }

            let mut padded_trace = full_trace.clone();
            let padding_extra = padded_trace_len - trace_len;
            let last_row = padded_trace
                .last()
                .copied()
                .ok_or_else(|| HcError::message("trace contains no rows"))?;
            padded_trace.extend(std::iter::repeat(last_row).take(padding_extra));

            let acc_values: Vec<F> = padded_trace.iter().map(|row| row[0]).collect();
            let input_values: Vec<F> = padded_trace.iter().map(|row| row[1]).collect();
            let trace_elements = trace_domain.elements();
            let acc_coeffs = interpolate(&acc_values, trace_elements);
            let input_coeffs = interpolate(&input_values, trace_elements);
            let converted_trace_domain = convert_domain(trace_elements);

            ensure_degree(trace_elements.len())?;
            let acc_poly_fr = convert_coeffs(&acc_coeffs);
            let input_poly_fr = convert_coeffs(&input_coeffs);
            let (acc_comm, acc_rand) = crate::kzg::commit_polynomial(&acc_poly_fr)?;
            let (input_comm, input_rand) = crate::kzg::commit_polynomial(&input_poly_fr)?;
            let points = vec![
                serialize_commitment(&acc_comm)?,
                serialize_commitment(&input_comm)?,
            ];
            let trace_kzg_state = Some(TraceKzgState {
                polynomials: vec![acc_poly_fr, input_poly_fr],
                randomness: vec![acc_rand, input_rand],
                commitments: vec![acc_comm, input_comm],
                domain_points: converted_trace_domain.clone(),
            });

            // (Optional) keep composition commitment empty for KZG path.
            let _ = lde_domain;

            Ok(CommitmentArtifacts {
                trace_commitment: Commitment::Kzg { points },
                composition_commitment: Commitment::Kzg { points: Vec::new() },
                merkle_trace_root: None,
                trace_kzg_state,
                composition_coeffs: None,
            })
        }
    }
}

fn hash_trace_pair<F: FieldElement>(left: &F, right: &F) -> HashDigest {
    let mut bytes = [0u8; 16];
    bytes[..8].copy_from_slice(&left.to_u64().to_le_bytes());
    bytes[8..].copy_from_slice(&right.to_u64().to_le_bytes());
    Blake3::hash(&bytes)
}

fn hash_field_element<F: FieldElement>(value: &F) -> HashDigest {
    let bytes = value.to_u64().to_le_bytes();
    Blake3::hash(&bytes)
}
