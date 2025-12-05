use hc_air::{
    constraints::{boundary::BoundaryConstraints, composition},
    eval::evaluate_block,
};
use hc_commit::merkle::height_dfs::StreamingMerkle;
use hc_core::{
    domain::{generate_lde_domain, generate_trace_domain},
    error::{HcError, HcResult},
    field::{FieldElement, TwoAdicField},
    poly::{evaluate_columns_parallel, interpolate},
};
use hc_hash::{hash::HashDigest, Blake3, HashFunction, Transcript};
use hc_replay::{trace_replay::TraceReplay, traits::BlockProducer};
use rayon::join;

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
    let padded_trace_len = trace_len.next_power_of_two();
    let trace_domain = generate_trace_domain::<F>(padded_trace_len)?;
    let lde_domain = generate_lde_domain::<F>(padded_trace_len, config.lde_blowup_factor)?;

    let mut full_trace = Vec::with_capacity(trace_len);
    let mut composition_transcript = Transcript::<Blake3>::new(b"composition");
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

    let selected_lde_points = lde_domain.elements();
    let converted_trace_domain = convert_domain(trace_elements);

    let mut trace_builder = if config.commitment == CommitmentScheme::Stark {
        Some(StreamingMerkle::<Blake3>::new())
    } else {
        None
    };
    let mut composition_builder = if config.commitment == CommitmentScheme::Stark {
        Some(StreamingMerkle::<Blake3>::new())
    } else {
        None
    };

    let mut lde_cursor = 0;
    let mut padding_remaining = padding_extra;

    for row in &full_trace {
        if let Some(builder) = &mut trace_builder {
            builder.push(hash_trace_pair(&row[0], &row[1]));
        }
    }

    for block_index in 0..num_blocks {
        let block = trace.fetch_block(block_index)?;
        let block_start_idx = block_index * block_size;
        let block_rows = block.len();

        let extra_rows_for_block = if block_index + 1 == num_blocks {
            padding_remaining
        } else {
            0
        };

        padding_remaining = padding_remaining.saturating_sub(extra_rows_for_block);

        let block_rows_padded = block_rows + extra_rows_for_block;
        let block_lde_points = block_rows_padded * config.lde_blowup_factor;

        let (lde_hashes, constraint_evals) = join(
            || -> HcResult<Vec<HashDigest>> {
                if block_lde_points == 0 {
                    return Ok(Vec::new());
                }

                let end_cursor = lde_cursor + block_lde_points;
                if end_cursor > selected_lde_points.len() {
                    return Err(HcError::message("lde cursor out of bounds"));
                }
                let block_slice = &selected_lde_points[lde_cursor..end_cursor];
                lde_cursor = end_cursor;

                let columns = evaluate_columns_parallel(&[&acc_coeffs, &input_coeffs], block_slice);
                let acc_lde = &columns[0];
                let input_lde = &columns[1];

                let mut hashes = Vec::with_capacity(block_lde_points);
                for i in 0..block_lde_points {
                    hashes.push(hash_trace_pair(&acc_lde[i], &input_lde[i]));
                }

                Ok(hashes)
            },
            || evaluate_block(block, block_start_idx, trace_len, boundary),
        );

        for digest in lde_hashes? {
            if let Some(builder) = &mut composition_builder {
                builder.push(digest);
            }
        }

        let constraint_evals = constraint_evals?;
        if !constraint_evals.is_empty() {
            let random_coeffs = random_coeffs_for_block(
                &mut composition_transcript,
                block_index,
                constraint_evals.len(),
            );
            let composition_values =
                composition::build_composition_contributions(&constraint_evals, &random_coeffs);
            if let Some(builder) = &mut composition_builder {
                for value in &composition_values {
                    builder.push(hash_field_element(value));
                }
            }
        }
    }

    if lde_cursor != selected_lde_points.len() {
        return Err(HcError::message("lde points left unconsumed"));
    }

    let trace_root = if let Some(builder) = trace_builder {
        Some(
            builder
                .finalize()
                .ok_or_else(|| HcError::message("failed to finalize trace merkle tree"))?,
        )
    } else {
        None
    };
    let composition_root = if let Some(builder) = composition_builder {
        Some(
            builder
                .finalize()
                .ok_or_else(|| HcError::message("failed to finalize composition merkle tree"))?,
        )
    } else {
        None
    };

    let mut trace_kzg_state = None;
    let trace_commitment = match config.commitment {
        CommitmentScheme::Stark => Commitment::Stark {
            root: trace_root.expect("trace root must exist for Stark"),
        },
        CommitmentScheme::Kzg => {
            ensure_degree(trace_elements.len())?;
            let acc_poly_fr = convert_coeffs(&acc_coeffs);
            let input_poly_fr = convert_coeffs(&input_coeffs);
            let (acc_comm, acc_rand) = crate::kzg::commit_polynomial(&acc_poly_fr)?;
            let (input_comm, input_rand) = crate::kzg::commit_polynomial(&input_poly_fr)?;
            let points = vec![
                serialize_commitment(&acc_comm)?,
                serialize_commitment(&input_comm)?,
            ];
            trace_kzg_state = Some(TraceKzgState {
                polynomials: vec![acc_poly_fr, input_poly_fr],
                randomness: vec![acc_rand, input_rand],
                commitments: vec![acc_comm, input_comm],
                domain_points: converted_trace_domain.clone(),
            });
            Commitment::Kzg { points }
        }
    };
    let composition_commitment = match config.commitment {
        CommitmentScheme::Stark => Commitment::Stark {
            root: composition_root.expect("composition root must exist for Stark"),
        },
        CommitmentScheme::Kzg => Commitment::Kzg { points: Vec::new() },
    };

    Ok(CommitmentArtifacts {
        trace_commitment,
        composition_commitment,
        merkle_trace_root: trace_root,
        trace_kzg_state,
    })
}

fn random_coeffs_for_block<F: FieldElement>(
    transcript: &mut Transcript<Blake3>,
    block_index: usize,
    count: usize,
) -> Vec<F> {
    let block_bytes = block_index.to_le_bytes();
    transcript.append_message(b"composition_block", block_bytes);
    (0..count)
        .map(|_| transcript.challenge_field::<F>(b"composition_coeff"))
        .collect()
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
