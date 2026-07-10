use crate::dft::{GoldilocksWord, ResourceBoundedDft, ResourceBoundedMatrix};
use crate::prover::GoldilocksConfig;
use hc_stream::{BlockMatrix, MatrixStore, ResourcePolicyV1, ScratchMatrixStore, StreamError};
use p3_air::{Air, BaseAir, RowWindow};
use p3_commit::PolynomialSpace;
use p3_dft::Radix2DitParallel;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_matrix::dense::RowMajorMatrixView;
use p3_matrix::stack::VerticalPair;
use p3_uni_stark::VerifierConstraintFolder;
use rayon::prelude::*;
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

type Challenge = BinomialExtensionField<Goldilocks, 2>;
pub(crate) type EvaluationConfig = GoldilocksConfig<Radix2DitParallel<Goldilocks>>;
static CHUNK_JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum StreamedQuotientError {
    #[error("streamed quotient requires the frozen non-preprocessed, non-periodic profile")]
    UnsupportedAir,
    #[error("trace LDE and quotient domain shapes are incompatible")]
    InvalidShape,
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Dft(#[from] crate::dft::DftError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, StreamedQuotientError>;

/// Evaluate the quotient directly from a standard-order trace LDE into a
/// scratch matrix of extension-field basis coefficients. Constraint folding
/// uses Plonky3's verifier folder, which is algebraically identical to the
/// packed prover folder and avoids retaining a quotient Vec.
#[allow(clippy::too_many_arguments)]
pub fn stream_quotient_values<A, M>(
    air: &A,
    public_values: &[Goldilocks],
    trace_domain: TwoAdicMultiplicativeCoset<Goldilocks>,
    mut quotient_domain: TwoAdicMultiplicativeCoset<Goldilocks>,
    trace_lde: &M,
    alpha: Challenge,
    policy: &ResourcePolicyV1,
    output_root: &Path,
    output_name: &str,
) -> Result<ScratchMatrixStore<GoldilocksWord>>
where
    A: BaseAir<Goldilocks> + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig>> + Sync,
    M: BlockMatrix<GoldilocksWord>,
{
    if air.preprocessed_width() != 0 || air.num_periodic_columns() != 0 {
        return Err(StreamedQuotientError::UnsupportedAir);
    }
    let quotient_size = quotient_domain.size();
    let trace_size = trace_domain.size();
    let lde_rows =
        usize::try_from(trace_lde.rows()).map_err(|_| StreamedQuotientError::InvalidShape)?;
    let width = trace_lde.columns();
    if width != air.width()
        || quotient_size < trace_size
        || !quotient_size.is_power_of_two()
        || lde_rows < quotient_size
        || lde_rows % quotient_size != 0
        || !(lde_rows / quotient_size).is_power_of_two()
    {
        return Err(StreamedQuotientError::InvalidShape);
    }
    let lde_stride = lde_rows / quotient_size;
    let next_step = quotient_size / trace_size;
    let mut output = ScratchMatrixStore::<GoldilocksWord>::create(
        output_root,
        output_name,
        quotient_size as u64,
        2,
    )?;
    let block_rows = policy.tile_rows(8, width)?.min(quotient_size);
    let max_physical_rows = block_rows
        .saturating_add(next_step)
        .saturating_mul(lde_stride);
    let mut trace_block = vec![GoldilocksWord::default(); max_physical_rows * width];
    let wrap_physical_rows = next_step.saturating_sub(1).saturating_mul(lde_stride) + 1;
    let mut wrap_block = vec![GoldilocksWord::default(); wrap_physical_rows * width];
    let mut encoded = vec![GoldilocksWord::default(); block_rows * 2];
    let mut local = vec![Challenge::ZERO; width];
    let mut next = vec![Challenge::ZERO; width];
    let pool = (policy.max_threads > 1)
        .then(|| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(policy.max_threads)
                .build()
                .map_err(|_| StreamedQuotientError::InvalidShape)
        })
        .transpose()?;

    for (block_index, block_start) in (0..quotient_size).step_by(block_rows).enumerate() {
        let row_count = (quotient_size - block_start).min(block_rows);
        let physical_start = block_start * lde_stride;
        let physical_rows = lde_rows - physical_start;
        let desired_rows = row_count
            .saturating_add(next_step)
            .saturating_sub(1)
            .saturating_mul(lde_stride)
            .saturating_add(1);
        let read_rows = desired_rows.min(physical_rows);
        trace_lde.read_rows(
            physical_start as u64,
            read_rows,
            &mut trace_block[..read_rows * width],
        )?;
        let wraps = block_start + row_count + next_step > quotient_size;
        if wraps {
            trace_lde.read_rows(
                0,
                wrap_physical_rows,
                &mut wrap_block[..wrap_physical_rows * width],
            )?;
        }
        let evaluate =
            |local_index: usize,
             destination: &mut [GoldilocksWord],
             local: &mut Vec<Challenge>,
             next: &mut Vec<Challenge>,
             domain: &mut TwoAdicMultiplicativeCoset<Goldilocks>| {
                let quotient_row = block_start + local_index;
                let next_row = (quotient_row + next_step) % quotient_size;
                let local_offset = local_index * lde_stride * width;
                let (next_source, next_offset) = if next_row < block_start {
                    (&wrap_block, next_row * lde_stride * width)
                } else {
                    (&trace_block, (next_row - block_start) * lde_stride * width)
                };
                for column in 0..width {
                    local[column] = Challenge::from(trace_block[local_offset + column].0);
                    next[column] = Challenge::from(next_source[next_offset + column].0);
                }
                let point = Challenge::from(domain.element(quotient_row));
                let selectors = trace_domain.selectors_at_point(point);
                let main = VerticalPair::new(
                    RowMajorMatrixView::new_row(local),
                    RowMajorMatrixView::new_row(next),
                );
                let empty: [Challenge; 0] = [];
                let preprocessed = VerticalPair::new(
                    RowMajorMatrixView::new_row(&empty),
                    RowMajorMatrixView::new_row(&empty),
                );
                let preprocessed_window =
                    RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);
                let mut folder = VerifierConstraintFolder::<EvaluationConfig> {
                    main,
                    preprocessed,
                    preprocessed_window,
                    periodic_values: &[],
                    public_values,
                    is_first_row: selectors.is_first_row,
                    is_last_row: selectors.is_last_row,
                    is_transition: selectors.is_transition,
                    alpha,
                    accumulator: Challenge::ZERO,
                };
                air.eval(&mut folder);
                let quotient = folder.accumulator * selectors.inv_vanishing;
                let coefficients = quotient.as_basis_coefficients_slice();
                destination[0] = GoldilocksWord(coefficients[0]);
                destination[1] = GoldilocksWord(coefficients[1]);
            };
        if let Some(pool) = &pool {
            pool.install(|| {
                encoded[..row_count * 2]
                    .par_chunks_mut(2)
                    .enumerate()
                    .for_each_init(
                        || {
                            (
                                vec![Challenge::ZERO; width],
                                vec![Challenge::ZERO; width],
                                quotient_domain,
                            )
                        },
                        |(local, next, domain), (local_index, destination)| {
                            evaluate(local_index, destination, local, next, domain)
                        },
                    )
            });
        } else {
            for (local_index, destination) in
                encoded[..row_count * 2].chunks_exact_mut(2).enumerate()
            {
                evaluate(
                    local_index,
                    destination,
                    &mut local,
                    &mut next,
                    &mut quotient_domain,
                );
            }
        }
        debug_assert_eq!(block_index * block_rows, block_start);
        output.write_rows(block_start as u64, row_count, &encoded[..row_count * 2])?;
    }
    output.finalize()?;
    Ok(output)
}

/// Split extension-valued quotient evaluations into Plonky3's interleaved
/// chunks and compute each chunk LDE without materializing the flattened
/// quotient matrix.
pub fn build_quotient_chunk_ldes(
    quotient_domain: TwoAdicMultiplicativeCoset<Goldilocks>,
    quotient_values: &ScratchMatrixStore<GoldilocksWord>,
    num_chunks: usize,
    dft: &ResourceBoundedDft,
    policy: &ResourcePolicyV1,
    output_root: &Path,
) -> Result<Vec<ResourceBoundedMatrix>> {
    let quotient_rows =
        usize::try_from(quotient_values.rows()).map_err(|_| StreamedQuotientError::InvalidShape)?;
    if quotient_values.columns() != 2
        || num_chunks == 0
        || !num_chunks.is_power_of_two()
        || quotient_rows % num_chunks != 0
    {
        return Err(StreamedQuotientError::InvalidShape);
    }
    let chunk_rows = quotient_rows / num_chunks;
    let id = CHUNK_JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let staging = output_root.join(format!("quotient-chunks-{}-{id}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&staging)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&staging)?;

    let result = (|| {
        let mut chunks = (0..num_chunks)
            .map(|chunk| {
                ScratchMatrixStore::<GoldilocksWord>::create(
                    &staging,
                    &format!("quotient-chunk-{chunk}.bin"),
                    chunk_rows as u64,
                    2,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let block_rows = policy.tile_rows(8, 2)?.min(chunk_rows);
        let mut interleaved = vec![GoldilocksWord::default(); block_rows * num_chunks * 2];
        let mut chunk_buffer = vec![GoldilocksWord::default(); block_rows * 2];
        for row_start in (0..chunk_rows).step_by(block_rows) {
            let row_count = (chunk_rows - row_start).min(block_rows);
            quotient_values.read_rows(
                (row_start * num_chunks) as u64,
                row_count * num_chunks,
                &mut interleaved[..row_count * num_chunks * 2],
            )?;
            for (chunk_index, chunk) in chunks.iter_mut().enumerate() {
                for row in 0..row_count {
                    let source = (row * num_chunks + chunk_index) * 2;
                    let destination = row * 2;
                    chunk_buffer[destination..destination + 2]
                        .copy_from_slice(&interleaved[source..source + 2]);
                }
                chunk.write_rows(row_start as u64, row_count, &chunk_buffer[..row_count * 2])?;
            }
        }
        for chunk in &mut chunks {
            chunk.finalize()?;
        }

        let subdomains = quotient_domain.split_domains(num_chunks);
        let mut ldes = Vec::with_capacity(num_chunks);
        for (chunk, domain) in chunks.into_iter().zip(subdomains) {
            let shift = Goldilocks::GENERATOR / domain.shift();
            let lde = dft.try_coset_lde_block_matrix(&chunk, 1, shift)?;
            chunk.remove()?;
            ldes.push(lde);
        }
        Ok(ldes)
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    } else {
        let _ = fs::remove_dir(&staging);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dft::ResourceBoundedDft;
    use crate::prover::make_config;
    use crate::workloads::{
        fibonacci_trace, poseidon2_goldilocks_air, poseidon2_trace, FibonacciAir,
    };
    use hc_stream::{CheckpointPolicy, ResourceMode};
    use p3_air::symbolic::AirLayout;
    use p3_commit::Pcs;
    use p3_field::{BasedVectorSpace, Field};
    use p3_matrix::bitrev::BitReversibleMatrix;
    use p3_matrix::Matrix;
    use p3_uni_stark::{get_log_num_quotient_chunks, quotient_values};

    fn policy(root: &Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 64 * 1024 * 1024,
            max_scratch_bytes: 1024 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 4,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        }
    }

    #[test]
    fn streamed_fibonacci_quotient_matches_upstream_values() {
        let dir = tempfile::tempdir().unwrap();
        let rows = 16usize;
        let trace = fibonacci_trace::<Goldilocks>(0, 1, rows);
        let public = vec![
            Goldilocks::ZERO,
            Goldilocks::ONE,
            *trace.values.last().unwrap(),
        ];
        let config = make_config(Radix2DitParallel::<Goldilocks>::default());
        let pcs = p3_uni_stark::StarkGenericConfig::pcs(&config);
        type EvalPcs = <EvaluationConfig as p3_uni_stark::StarkGenericConfig>::Pcs;
        type EvalChallenger = <EvaluationConfig as p3_uni_stark::StarkGenericConfig>::Challenger;
        let trace_domain =
            <EvalPcs as Pcs<Challenge, EvalChallenger>>::natural_domain_for_degree(pcs, rows);
        let ext_trace_domain = trace_domain;
        let (_, trace_data) = <EvalPcs as Pcs<Challenge, EvalChallenger>>::commit(
            pcs,
            [(ext_trace_domain, trace.clone())],
        );
        let layout = AirLayout {
            main_width: BaseAir::<Goldilocks>::width(&FibonacciAir),
            num_public_values: BaseAir::<Goldilocks>::num_public_values(&FibonacciAir),
            ..Default::default()
        };
        let log_chunks = get_log_num_quotient_chunks::<Goldilocks, _>(&FibonacciAir, layout, 0);
        let quotient_domain = ext_trace_domain
            .create_disjoint_domain(1 << (rows.trailing_zeros() as usize + log_chunks));
        let trace_on_quotient =
            <EvalPcs as Pcs<Challenge, EvalChallenger>>::get_evaluations_on_domain(
                pcs,
                &trace_data,
                0,
                quotient_domain,
            );
        let alpha =
            Challenge::from_basis_coefficients_fn(|index| Goldilocks::from_u64((index + 7) as u64));
        let expected = quotient_values::<EvaluationConfig, _, _>(
            pcs,
            &FibonacciAir,
            &public,
            layout,
            trace_domain,
            quotient_domain,
            &trace_on_quotient,
            None,
            alpha,
        );

        let mut trace_store = ScratchMatrixStore::<GoldilocksWord>::create(
            dir.path(),
            "trace.bin",
            rows as u64,
            trace.width(),
        )
        .unwrap();
        let words: Vec<_> = trace.values.into_iter().map(GoldilocksWord).collect();
        trace_store.write_rows(0, rows, &words).unwrap();
        trace_store.finalize().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        let trace_lde = dft
            .try_coset_lde_block_matrix(&trace_store, 1, Goldilocks::GENERATOR)
            .unwrap();
        let actual = stream_quotient_values(
            &FibonacciAir,
            &public,
            trace_domain,
            quotient_domain,
            &trace_lde,
            alpha,
            &policy(dir.path()),
            dir.path(),
            "quotient.bin",
        )
        .unwrap();
        let mut actual_words = vec![GoldilocksWord::default(); expected.len() * 2];
        actual
            .read_rows(0, expected.len(), &mut actual_words)
            .unwrap();
        let actual_values: Vec<_> = actual_words
            .chunks_exact(2)
            .map(|words| {
                Challenge::from_basis_coefficients_slice(&[words[0].0, words[1].0]).unwrap()
            })
            .collect();
        assert_eq!(actual_values, expected);

        let expected_flat =
            p3_matrix::dense::RowMajorMatrix::new_col(expected.clone()).flatten_to_base();
        let expected_sub_evaluations = quotient_domain.split_evals(1, expected_flat);
        let expected_sub_domains = quotient_domain.split_domains(1);
        let expected_ldes = <EvalPcs as Pcs<Challenge, EvalChallenger>>::get_quotient_ldes(
            pcs,
            expected_sub_domains
                .into_iter()
                .zip(expected_sub_evaluations),
            1,
        );
        let actual_ldes = build_quotient_chunk_ldes(
            quotient_domain,
            &actual,
            1,
            &dft,
            &policy(dir.path()),
            dir.path(),
        )
        .unwrap();
        assert_eq!(actual_ldes.len(), expected_ldes.len());
        for (actual_lde, expected_lde) in actual_ldes.iter().zip(expected_ldes) {
            let expected_standard = expected_lde.bit_reverse_rows().to_row_major_matrix();
            assert_eq!(
                actual_lde.try_rows(0, actual_lde.height()).unwrap(),
                expected_standard.values
            );
        }
    }

    #[test]
    fn streamed_poseidon2_quotient_matches_upstream_values() {
        let dir = tempfile::tempdir().unwrap();
        let rows = 8usize;
        let air = poseidon2_goldilocks_air();
        let trace = poseidon2_trace(rows, 0);
        let config = make_config(Radix2DitParallel::<Goldilocks>::default());
        let pcs = p3_uni_stark::StarkGenericConfig::pcs(&config);
        type EvalPcs = <EvaluationConfig as p3_uni_stark::StarkGenericConfig>::Pcs;
        type EvalChallenger = <EvaluationConfig as p3_uni_stark::StarkGenericConfig>::Challenger;
        let trace_domain =
            <EvalPcs as Pcs<Challenge, EvalChallenger>>::natural_domain_for_degree(pcs, rows);
        let (_, trace_data) = <EvalPcs as Pcs<Challenge, EvalChallenger>>::commit(
            pcs,
            [(trace_domain, trace.clone())],
        );
        let layout = AirLayout {
            main_width: BaseAir::<Goldilocks>::width(&air),
            num_public_values: BaseAir::<Goldilocks>::num_public_values(&air),
            ..Default::default()
        };
        let log_chunks = get_log_num_quotient_chunks::<Goldilocks, _>(&air, layout, 0);
        let quotient_domain =
            trace_domain.create_disjoint_domain(1 << (rows.trailing_zeros() as usize + log_chunks));
        let trace_on_quotient =
            <EvalPcs as Pcs<Challenge, EvalChallenger>>::get_evaluations_on_domain(
                pcs,
                &trace_data,
                0,
                quotient_domain,
            );
        let alpha = Challenge::from_basis_coefficients_fn(|index| {
            Goldilocks::from_u64((index + 13) as u64)
        });
        let expected = quotient_values::<EvaluationConfig, _, _>(
            pcs,
            &air,
            &[],
            layout,
            trace_domain,
            quotient_domain,
            &trace_on_quotient,
            None,
            alpha,
        );

        let mut trace_store = ScratchMatrixStore::<GoldilocksWord>::create(
            dir.path(),
            "poseidon-trace.bin",
            rows as u64,
            trace.width(),
        )
        .unwrap();
        let words: Vec<_> = trace.values.into_iter().map(GoldilocksWord).collect();
        trace_store.write_rows(0, rows, &words).unwrap();
        trace_store.finalize().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        let trace_lde = dft
            .try_coset_lde_block_matrix(&trace_store, 1, Goldilocks::GENERATOR)
            .unwrap();
        let actual = stream_quotient_values(
            &air,
            &[],
            trace_domain,
            quotient_domain,
            &trace_lde,
            alpha,
            &policy(dir.path()),
            dir.path(),
            "poseidon-quotient.bin",
        )
        .unwrap();
        let mut actual_words = vec![GoldilocksWord::default(); expected.len() * 2];
        actual
            .read_rows(0, expected.len(), &mut actual_words)
            .unwrap();
        let actual_values: Vec<_> = actual_words
            .chunks_exact(2)
            .map(|words| {
                Challenge::from_basis_coefficients_slice(&[words[0].0, words[1].0]).unwrap()
            })
            .collect();
        assert_eq!(actual_values, expected);

        let num_chunks = 1usize << log_chunks;
        let expected_flat =
            p3_matrix::dense::RowMajorMatrix::new_col(expected.clone()).flatten_to_base();
        let expected_sub_evaluations = quotient_domain.split_evals(num_chunks, expected_flat);
        let expected_sub_domains = quotient_domain.split_domains(num_chunks);
        let expected_ldes = <EvalPcs as Pcs<Challenge, EvalChallenger>>::get_quotient_ldes(
            pcs,
            expected_sub_domains
                .into_iter()
                .zip(expected_sub_evaluations),
            num_chunks,
        );
        let actual_ldes = build_quotient_chunk_ldes(
            quotient_domain,
            &actual,
            num_chunks,
            &dft,
            &policy(dir.path()),
            dir.path(),
        )
        .unwrap();
        assert_eq!(actual_ldes.len(), expected_ldes.len());
        for (actual_lde, expected_lde) in actual_ldes.iter().zip(expected_ldes) {
            let expected_standard = expected_lde.bit_reverse_rows().to_row_major_matrix();
            assert_eq!(
                actual_lde.try_rows(0, actual_lde.height()).unwrap(),
                expected_standard.values
            );
        }
    }
}
