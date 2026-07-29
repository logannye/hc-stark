// Generic over `DurableFieldProfile<W, D>`, matching `dft`/`fri`. Every
// `Goldilocks` that used to be written here is now `P::Val`, and every
// `GoldilocksWord` is `P::Word`.
use crate::dft::ResourceBoundedMatrix;
use crate::fri::{bit_reverse_challenge_vector, DurableFriError, ScratchChallengeVector};
use crate::profile::DurableFieldProfile;
use hc_stream::{BlockMatrix, CanonicalElement, ResourcePolicyV1};
use p3_field::{
    batch_multiplicative_inverse, dot_product, Field, PrimeCharacteristicRing, TwoAdicField,
};
use p3_matrix::Matrix;
use rayon::prelude::*;

#[derive(Debug, thiserror::Error)]
pub enum DurableOpeningError {
    #[error("opening matrix shape is invalid")]
    InvalidShape,
    #[error(transparent)]
    Stream(#[from] hc_stream::StreamError),
    #[error(transparent)]
    Fri(#[from] DurableFriError),
}

pub type Result<T> = std::result::Result<T, DurableOpeningError>;

pub struct MatrixOpening<'a, const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub matrix: &'a ResourceBoundedMatrix<W, D, P>,
    pub points_and_values: Vec<(P::Challenge, Vec<P::Challenge>)>,
}

/// Evaluate every column polynomial represented by a standard-order coset LDE
/// at an out-of-domain point using bounded batches.
pub fn interpolate_standard_lde<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    matrix: &ResourceBoundedMatrix<W, D, P>,
    polynomial_height: usize,
    point: P::Challenge,
    policy: &ResourcePolicyV1,
) -> Result<Vec<P::Challenge>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let lde_height = matrix.height();
    if polynomial_height == 0
        || !polynomial_height.is_power_of_two()
        || lde_height % polynomial_height != 0
    {
        return Err(DurableOpeningError::InvalidShape);
    }
    let blowup = lde_height / polynomial_height;
    if !blowup.is_power_of_two() || blowup < 2 {
        return Err(DurableOpeningError::InvalidShape);
    }
    let width = matrix.width();
    let block_rows = policy
        .tile_rows(<P::Word as CanonicalElement>::WIDTH, width)?
        .min(polynomial_height);
    let subgroup_generator =
        P::Val::two_adic_generator(polynomial_height.trailing_zeros() as usize);
    let shift = P::Val::GENERATOR;
    let point_inverse = point.inverse();
    let mut sums = vec![P::Challenge::ZERO; width];
    let mut row_words = vec![P::Word::default(); width];

    for row_start in (0..polynomial_height).step_by(block_rows) {
        let row_count = (polynomial_height - row_start).min(block_rows);
        let mut x = shift * subgroup_generator.exp_u64(row_start as u64);
        let mut points = Vec::with_capacity(row_count);
        for _ in 0..row_count {
            points.push(x);
            x *= subgroup_generator;
        }
        let diffs: Vec<_> = points.iter().map(|value| point - *value).collect();
        let inverses = batch_multiplicative_inverse(&diffs);
        for (row, inverse) in inverses.iter().enumerate().take(row_count) {
            matrix.read_rows(((row_start + row) * blowup) as u64, 1, &mut row_words)?;
            let adjusted = *inverse - point_inverse;
            for column in 0..width {
                sums[column] += adjusted * row_words[column].into();
            }
        }
    }

    let log_height = polynomial_height.trailing_zeros() as usize;
    let z_pow_n = point.exp_power_of_2(log_height);
    let shift_pow_n = shift.exp_power_of_2(log_height);
    let denominator_inverse = shift_pow_n.mul_2exp_u64(log_height as u64).inverse();
    let scale = point * (z_pow_n - shift_pow_n) * denominator_inverse;
    for value in &mut sums {
        *value *= scale;
    }
    Ok(sums)
}

/// Build the bit-reversed reduced-opening polynomial consumed by FRI. All
/// matrices must share the same LDE height and active TinyZKP profile.
pub fn build_reduced_opening_layer<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    openings: &[MatrixOpening<'_, W, D, P>],
    batching_alpha: P::Challenge,
    policy: &ResourcePolicyV1,
) -> Result<ScratchChallengeVector<W, D, P>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let Some(lde_height) = openings.first().map(|opening| opening.matrix.height()) else {
        return Err(DurableOpeningError::InvalidShape);
    };
    if !lde_height.is_power_of_two()
        || openings.iter().any(|opening| {
            opening.matrix.height() != lde_height
                || opening
                    .points_and_values
                    .iter()
                    .any(|(_, values)| values.len() != opening.matrix.width())
        })
    {
        return Err(DurableOpeningError::InvalidShape);
    }

    struct ReductionTerm<'a, const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
    where
        [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        matrix: &'a ResourceBoundedMatrix<W, D, P>,
        point: P::Challenge,
        opening: &'a [P::Challenge],
        powers: Vec<P::Challenge>,
    }

    let mut alpha_offset = 0usize;
    let mut terms = Vec::new();
    for opening in openings {
        for (point, values) in &opening.points_and_values {
            let powers = (0..opening.matrix.width())
                .map(|column| batching_alpha.exp_u64((alpha_offset + column) as u64))
                .collect();
            terms.push(ReductionTerm {
                matrix: opening.matrix,
                point: *point,
                opening: values,
                powers,
            });
            alpha_offset += opening.matrix.width();
        }
    }

    let subgroup_generator = P::Val::two_adic_generator(lde_height.trailing_zeros() as usize);
    let shift = P::Val::GENERATOR;
    let widest_matrix = terms
        .iter()
        .map(|term| term.matrix.width())
        .max()
        .ok_or(DurableOpeningError::InvalidShape)?;
    const BUFFER_BYTES: usize = 32 * 1024 * 1024;
    let bytes_per_row = widest_matrix
        .checked_mul(<P::Word as CanonicalElement>::WIDTH)
        .and_then(|bytes| bytes.checked_add(64))
        .ok_or(DurableOpeningError::InvalidShape)?;
    let fixed_rows = (BUFFER_BYTES / bytes_per_row).max(1);
    let block_rows = policy
        .tile_rows(<P::Word as CanonicalElement>::WIDTH, widest_matrix.max(1))?
        .min(fixed_rows)
        .min(lde_height)
        .max(1);
    let pool = (policy.max_threads > 1)
        .then(|| {
            rayon::ThreadPoolBuilder::new()
                .num_threads(policy.max_threads)
                .build()
                .map_err(|_| DurableOpeningError::InvalidShape)
        })
        .transpose()?;
    let standard_layer = ScratchChallengeVector::from_block_generator_with_rows(
        policy,
        lde_height,
        block_rows,
        |standard_start, row_count| {
            let mut x = shift * subgroup_generator.exp_u64(standard_start as u64);
            let x_values: Vec<_> = (0..row_count)
                .map(|_| {
                    let current = x;
                    x *= subgroup_generator;
                    current
                })
                .collect();
            let mut reduced = vec![P::Challenge::ZERO; row_count];
            for term in &terms {
                let diffs: Vec<_> = x_values.iter().map(|x| term.point - *x).collect();
                let inverse_denominators = batch_multiplicative_inverse(&diffs);
                let reduced_opening: P::Challenge =
                    dot_product(term.powers.iter().copied(), term.opening.iter().copied());
                let width = term.matrix.width();
                let mut row_words = vec![P::Word::default(); row_count * width];
                term.matrix
                    .read_rows(standard_start as u64, row_count, &mut row_words)?;
                let reduce_row = |(row, destination): (usize, &mut P::Challenge)| {
                    let source = row * width;
                    let reduced_row: P::Challenge = dot_product(
                        term.powers.iter().copied(),
                        row_words[source..source + width]
                            .iter()
                            .map(|word| P::Challenge::from((*word).into())),
                    );
                    *destination += (reduced_opening - reduced_row) * inverse_denominators[row];
                };
                if let Some(pool) = &pool {
                    pool.install(|| reduced.par_iter_mut().enumerate().for_each(reduce_row));
                } else {
                    reduced.iter_mut().enumerate().for_each(reduce_row);
                }
            }
            Ok(reduced)
        },
    )?;
    bit_reverse_challenge_vector(standard_layer, policy).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{GoldilocksWord, ResourceBoundedDft};
    use hc_stream::{CheckpointPolicy, MatrixStore, ResourceMode, ScratchMatrixStore};
    use p3_field::BasedVectorSpace;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_matrix::interpolation::Interpolate;

    type ProfileChallenge = crate::fri::ProfileChallenge;

    fn policy(root: &std::path::Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 32 * 1024 * 1024,
            max_scratch_bytes: 128 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        }
    }

    #[test]
    fn bounded_interpolation_matches_plonky3_formula() {
        assert_bounded_interpolation_matches_plonky3_formula(1);
    }

    #[test]
    fn bounded_interpolation_supports_degree_three_blowup() {
        assert_bounded_interpolation_matches_plonky3_formula(2);
    }

    fn assert_bounded_interpolation_matches_plonky3_formula(log_blowup: usize) {
        let dir = tempfile::tempdir().unwrap();
        let height = 16usize;
        let width = 3usize;
        let evaluations = RowMajorMatrix::new(
            (0..height * width)
                .map(|index| Goldilocks::from_u64((index * 11 + 2) as u64))
                .collect(),
            width,
        );
        let mut store = ScratchMatrixStore::<GoldilocksWord>::create(
            dir.path(),
            "opening-input.bin",
            height as u64,
            width,
        )
        .unwrap();
        store
            .write_rows(
                0,
                height,
                &evaluations
                    .values
                    .iter()
                    .copied()
                    .map(GoldilocksWord)
                    .collect::<Vec<_>>(),
            )
            .unwrap();
        store.finalize().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        let lde = dft
            .try_coset_lde_block_matrix(&store, log_blowup, Goldilocks::GENERATOR)
            .unwrap();
        let point = ProfileChallenge::from_basis_coefficients_fn(|coordinate| {
            Goldilocks::from_u64((coordinate + 31) as u64)
        });
        let actual = interpolate_standard_lde(&lde, height, point, &policy(dir.path())).unwrap();
        let blowup = 1usize << log_blowup;
        let standard_subset = RowMajorMatrix::new(
            (0..height)
                .flat_map(|row| lde.try_row(row * blowup).unwrap())
                .collect(),
            width,
        );
        let expected = standard_subset.interpolate_coset(Goldilocks::GENERATOR, point);
        assert_eq!(actual, expected);
    }
}

/// Goldilocks pins, matching the `goldilocks` sub-module every other
/// genericized module in this crate exposes (`dft`, `mmcs`, `fri`,
/// `bounded_pcs`). `opening.rs` was genericized without one, which silently
/// broke `hc_plonky3::MatrixOpening<'a>` as a nameable type on a root
/// re-export — a source break for any external caller, and the one place the
/// "public API is unchanged" property did not actually hold.
pub mod goldilocks {
    use crate::profile::GoldilocksProfile;

    /// The pre-generic name for a matrix opening at Goldilocks' `<8, 4>`.
    pub type MatrixOpening<'a> = super::MatrixOpening<'a, 8, 4, GoldilocksProfile>;
}
