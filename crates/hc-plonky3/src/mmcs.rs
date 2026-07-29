use crate::dft::ResourceBoundedMatrix;
use crate::profile::DurableFieldProfile;
use crate::scratch::create_unique_job_dir;
use hc_stream::{
    BlockMatrix, CanonicalElement, ExecutionMode, MatrixStore, PhaseEstimate, ResourceEstimate,
    ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::Field;
use p3_matrix::bitrev::{BitReversedMatrixView, BitReversibleMatrix};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleCap, MerkleTreeError, MerkleTreeMmcs};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicU64;

static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Bytes per durable scratch element (`CanonicalElement::WIDTH`): 8 for
/// Goldilocks, 4 for BabyBear. Distinct from both `PERM_WIDTH` (`W`) and the
/// digest size (`D`), all three of which appear in this module.
const fn word_bytes<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>() -> usize
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    <P::Word as CanonicalElement>::WIDTH
}

pub(crate) type ProfilePacking<const W: usize, const D: usize, P> =
    <<P as DurableFieldProfile<W, D>>::Val as Field>::Packing;
/// The unmodified upstream Merkle MMCS at this profile's dimensions. Doubles
/// as the verifier reference and as `bounded_pcs`'s `ValMmcs`.
pub(crate) type ReferenceMmcs<const W: usize, const D: usize, P> = MerkleTreeMmcs<
    ProfilePacking<W, D, P>,
    ProfilePacking<W, D, P>,
    <P as DurableFieldProfile<W, D>>::Hash,
    <P as DurableFieldProfile<W, D>>::Compression,
    2,
    D,
>;
type ProfileCap<const W: usize, const D: usize, P> =
    MerkleCap<<P as DurableFieldProfile<W, D>>::Val, [<P as DurableFieldProfile<W, D>>::Val; D]>;
type DurableCommitmentData<const W: usize, const D: usize, P, M> =
    (ProfileCap<W, D, P>, DurableMerkleData<W, D, P, M>);

#[derive(Debug, thiserror::Error)]
pub enum DurableMmcsError {
    #[error("durable MMCS requires non-empty equal-height power-of-two matrices")]
    InvalidShape,
    #[error("durable MMCS batch queries must be strictly sorted, unique, and in range")]
    InvalidQuerySet,
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, DurableMmcsError>;

/// Scratch-backed prover data. All digest layers are durable so openings can
/// be generated after Fiat-Shamir query positions are known.
pub struct DurableMerkleData<const W: usize, const D: usize, P: DurableFieldProfile<W, D>, M>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    matrices: Vec<M>,
    layers: Vec<ScratchMatrixStore<P::Word>>,
    job_dir: PathBuf,
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>, M> DurableMerkleData<W, D, P, M>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    pub fn job_dir(&self) -> &Path {
        &self.job_dir
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>, M> Drop
    for DurableMerkleData<W, D, P, M>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn drop(&mut self) {
        for layer in &self.layers {
            let _ = fs::remove_file(layer.path());
        }
        let _ = fs::remove_dir(&self.job_dir);
    }
}

/// Binary Poseidon2 MMCS matching the frozen Plonky3 profile. The verifier
/// implementation is the unmodified upstream `MerkleTreeMmcs`; only prover
/// storage and opening reads differ.
#[derive(Clone)]
pub struct DurableProfileMmcs<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    hash: P::Hash,
    compress: P::Compression,
    reference: ReferenceMmcs<W, D, P>,
    policy: ResourcePolicyV1,
}

// Hand-written: `#[derive(Debug)]` would require `P::Hash`/`P::Compression` to
// be `Debug`, which `DurableFieldProfile` deliberately does not demand.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> std::fmt::Debug
    for DurableProfileMmcs<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableProfileMmcs")
            .field("field", &P::FIELD_NAME)
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> DurableProfileMmcs<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn new(hash: P::Hash, compress: P::Compression, policy: ResourcePolicyV1) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            reference: ReferenceMmcs::<W, D, P>::new(hash.clone(), compress.clone(), 0),
            hash,
            compress,
            policy,
        })
    }

    pub fn estimate(&self, height: usize) -> Result<ResourceEstimate> {
        if height == 0 || !height.is_power_of_two() {
            return Err(DurableMmcsError::InvalidShape);
        }
        let digest_bytes = (height as u64)
            .saturating_mul(D as u64)
            .saturating_mul(word_bytes::<W, D, P>() as u64);
        let scratch = digest_bytes.saturating_mul(2).saturating_sub(32);
        let permutation_io = digest_bytes.saturating_mul(3);
        let read_bytes = digest_bytes
            .saturating_mul(2)
            .saturating_add(permutation_io);
        let write_bytes = scratch.saturating_add(permutation_io);
        Ok(ResourceEstimate {
            peak_resident_bytes: 8 * 1024 * 1024,
            scratch_high_water_bytes: scratch,
            total_read_bytes: read_bytes,
            total_write_bytes: write_bytes,
            phases: vec![PhaseEstimate {
                phase: "durable_mmcs".into(),
                read_bytes,
                write_bytes,
            }],
        })
    }

    fn worker_pool(&self) -> Result<Option<rayon::ThreadPool>> {
        if self.policy.max_threads == 1 {
            return Ok(None);
        }
        rayon::ThreadPoolBuilder::new()
            .num_threads(self.policy.max_threads)
            .build()
            .map(Some)
            .map_err(|_| DurableMmcsError::InvalidShape)
    }

    /// Open a strictly sorted set of positions with one ordered scan per
    /// durable tree level. Sibling positions are deduplicated at each level;
    /// the returned openings remain aligned with `indices`.
    pub fn open_batches_sorted<M: Matrix<P::Val>>(
        &self,
        indices: &[usize],
        prover_data: &DurableMerkleData<W, D, P, M>,
    ) -> Result<Vec<BatchOpening<P::Val, Self>>>
    where
        [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        let height = prover_data
            .matrices
            .first()
            .map(Matrix::height)
            .ok_or(DurableMmcsError::InvalidShape)?;
        if prover_data
            .matrices
            .iter()
            .any(|matrix| matrix.height() != height)
            || indices.iter().any(|index| *index >= height)
            || indices.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return Err(DurableMmcsError::InvalidQuerySet);
        }
        if indices.is_empty() {
            return Ok(Vec::new());
        }

        let opened_values: Vec<Vec<Vec<P::Val>>> = indices
            .iter()
            .map(|index| {
                prover_data
                    .matrices
                    .iter()
                    .map(|matrix| {
                        matrix
                            .row(*index)
                            .expect("validated matrix row")
                            .into_iter()
                            .collect()
                    })
                    .collect()
            })
            .collect();
        let mut proofs = vec![Vec::with_capacity(prover_data.layers.len() - 1); indices.len()];
        let mut layer_indices = indices.to_vec();
        for layer in prover_data
            .layers
            .iter()
            .take(prover_data.layers.len().saturating_sub(1))
        {
            let mut sibling_indices: Vec<_> = layer_indices.iter().map(|index| index ^ 1).collect();
            sibling_indices.sort_unstable();
            sibling_indices.dedup();
            let sibling_digests = read_sorted_digests::<W, D, P>(layer, &sibling_indices)?;
            for (proof, layer_index) in proofs.iter_mut().zip(&layer_indices) {
                let position = sibling_indices
                    .binary_search(&(layer_index ^ 1))
                    .expect("requested sibling is present in the scan");
                proof.push(sibling_digests[position]);
            }
            for index in &mut layer_indices {
                *index >>= 1;
            }
        }
        Ok(opened_values
            .into_iter()
            .zip(proofs)
            .map(|(values, proof)| BatchOpening::new(values, proof))
            .collect())
    }

    /// Commit standard-order resource-bounded matrices as the bit-reversed
    /// Plonky3 LDE view. Source rows are read in contiguous blocks and leaf
    /// digests are placed at their bit-reversed commitment positions.
    #[allow(clippy::type_complexity)]
    pub fn try_commit_bit_reversed(
        &self,
        matrices: Vec<ResourceBoundedMatrix<W, D, P>>,
    ) -> Result<(
        ProfileCap<W, D, P>,
        DurableMerkleData<W, D, P, BitReversedMatrixView<ResourceBoundedMatrix<W, D, P>>>,
    )> {
        let Some(height) = matrices.first().map(Matrix::height) else {
            return Err(DurableMmcsError::InvalidShape);
        };
        let total_width = matrices.iter().try_fold(0usize, |total, matrix| {
            if matrix.height() != height {
                return Err(DurableMmcsError::InvalidShape);
            }
            total
                .checked_add(matrix.width())
                .ok_or(DurableMmcsError::InvalidShape)
        })?;
        if height == 0 || !height.is_power_of_two() || total_width == 0 {
            return Err(DurableMmcsError::InvalidShape);
        }
        self.policy
            .preflight_for_mode(ExecutionMode::Scratch, self.estimate(height)?)?;
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let mut standard_leaves = ScratchMatrixStore::<P::Word>::create(
                &job_dir,
                "mmcs-leaves-standard.bin",
                height as u64,
                D,
            )?;
            let block_rows = bounded_leaf_block_rows::<W, D, P>(&self.policy, total_width, height)?;
            let mut buffers: Vec<Vec<P::Word>> = matrices
                .iter()
                .map(|matrix| vec![P::Word::default(); block_rows * matrix.width()])
                .collect();
            let widths: Vec<_> = matrices.iter().map(Matrix::width).collect();
            let pool = self.worker_pool()?;
            let mut leaf_words = vec![P::Word::default(); block_rows * D];
            for row_start in (0..height).step_by(block_rows) {
                let row_count = (height - row_start).min(block_rows);
                for (matrix, buffer) in matrices.iter().zip(&mut buffers) {
                    matrix.read_rows(
                        row_start as u64,
                        row_count,
                        &mut buffer[..row_count * matrix.width()],
                    )?;
                }
                hash_buffered_rows::<W, D, P>(
                    &self.hash,
                    &buffers,
                    &widths,
                    row_count,
                    &mut leaf_words,
                    pool.as_ref(),
                );
                standard_leaves.write_rows(
                    row_start as u64,
                    row_count,
                    &leaf_words[..row_count * D],
                )?;
            }
            standard_leaves.finalize()?;
            let leaves = bit_reverse_digest_store::<W, D, P>(
                standard_leaves,
                &job_dir,
                height,
                &self.policy,
            )?;
            let committed_matrices = matrices
                .into_iter()
                .map(BitReversibleMatrix::bit_reverse_rows)
                .collect();
            self.finish_tree(committed_matrices, leaves, &job_dir, height)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    /// Commit block-readable base-field matrices in their existing row order.
    /// This is used by durable FRI layers after extension values are flattened
    /// into canonical Goldilocks coordinates.
    #[allow(clippy::type_complexity)]
    pub fn try_commit_blocks<M>(
        &self,
        matrices: Vec<M>,
    ) -> Result<DurableCommitmentData<W, D, P, M>>
    where
        M: Matrix<P::Val> + BlockMatrix<P::Word>,
    {
        let Some(height) = matrices.first().map(Matrix::height) else {
            return Err(DurableMmcsError::InvalidShape);
        };
        let total_width = matrices.iter().try_fold(0usize, |total, matrix| {
            if matrix.height() != height || BlockMatrix::rows(matrix) != height as u64 {
                return Err(DurableMmcsError::InvalidShape);
            }
            total
                .checked_add(matrix.width())
                .ok_or(DurableMmcsError::InvalidShape)
        })?;
        if height == 0 || !height.is_power_of_two() || total_width == 0 {
            return Err(DurableMmcsError::InvalidShape);
        }
        self.policy
            .preflight_for_mode(ExecutionMode::Scratch, self.estimate(height)?)?;
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let mut leaves = ScratchMatrixStore::<P::Word>::create(
                &job_dir,
                "mmcs-level-0.bin",
                height as u64,
                D,
            )?;
            let block_rows = bounded_leaf_block_rows::<W, D, P>(&self.policy, total_width, height)?;
            let mut buffers: Vec<Vec<P::Word>> = matrices
                .iter()
                .map(|matrix| vec![P::Word::default(); block_rows * matrix.width()])
                .collect();
            let widths: Vec<_> = matrices.iter().map(Matrix::width).collect();
            let pool = self.worker_pool()?;
            let mut leaf_words = vec![P::Word::default(); block_rows * D];
            for row_start in (0..height).step_by(block_rows) {
                let row_count = (height - row_start).min(block_rows);
                for (matrix, buffer) in matrices.iter().zip(&mut buffers) {
                    matrix.read_rows(
                        row_start as u64,
                        row_count,
                        &mut buffer[..row_count * matrix.width()],
                    )?;
                }
                hash_buffered_rows::<W, D, P>(
                    &self.hash,
                    &buffers,
                    &widths,
                    row_count,
                    &mut leaf_words,
                    pool.as_ref(),
                );
                leaves.write_rows(row_start as u64, row_count, &leaf_words[..row_count * D])?;
            }
            leaves.finalize()?;
            self.finish_tree(matrices, leaves, &job_dir, height)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    fn finish_tree<M: Matrix<P::Val>>(
        &self,
        matrices: Vec<M>,
        leaves: ScratchMatrixStore<P::Word>,
        job_dir: &Path,
        height: usize,
    ) -> Result<DurableCommitmentData<W, D, P, M>> {
        let mut layers = Vec::with_capacity(height.trailing_zeros() as usize + 1);
        layers.push(leaves);
        let pool = self.worker_pool()?;
        let parent_block_rows = bounded_parent_block_rows::<W, D, P>(&self.policy)?;
        let mut level_height = height;
        while level_height > 1 {
            let next_height = level_height / 2;
            let level_index = layers.len();
            let mut next = ScratchMatrixStore::<P::Word>::create(
                job_dir,
                &format!("mmcs-level-{level_index}.bin"),
                next_height as u64,
                D,
            )?;
            for row_start in (0..next_height).step_by(parent_block_rows) {
                let row_count = (next_height - row_start).min(parent_block_rows);
                let mut children = vec![P::Word::default(); row_count * D * 2];
                layers.last().expect("leaf layer exists").read_rows(
                    (row_start * 2) as u64,
                    row_count * 2,
                    &mut children,
                )?;
                let mut parents = vec![P::Word::default(); row_count * D];
                compress_buffered_rows::<W, D, P>(
                    &self.compress,
                    &children,
                    row_count,
                    &mut parents,
                    pool.as_ref(),
                );
                next.write_rows(row_start as u64, row_count, &parents)?;
            }
            next.finalize()?;
            layers.push(next);
            level_height = next_height;
        }

        let mut root_words = [P::Word::default(); D];
        layers
            .last()
            .expect("root layer exists")
            .read_rows(0, 1, &mut root_words)?;
        Ok((
            MerkleCap::new(vec![root_words.map(Into::into)]),
            DurableMerkleData {
                matrices,
                layers,
                job_dir: job_dir.to_path_buf(),
            },
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn try_commit<M: Matrix<P::Val>>(
        &self,
        matrices: Vec<M>,
    ) -> Result<DurableCommitmentData<W, D, P, M>> {
        let Some(height) = matrices.first().map(Matrix::height) else {
            return Err(DurableMmcsError::InvalidShape);
        };
        if height == 0
            || !height.is_power_of_two()
            || matrices.iter().any(|matrix| matrix.height() != height)
        {
            return Err(DurableMmcsError::InvalidShape);
        }
        self.policy
            .preflight_for_mode(ExecutionMode::Scratch, self.estimate(height)?)?;
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let mut leaves = ScratchMatrixStore::<P::Word>::create(
                &job_dir,
                "mmcs-level-0.bin",
                height as u64,
                D,
            )?;
            for row in 0..height {
                let digest = self.hash.hash_iter(
                    matrices
                        .iter()
                        .flat_map(|matrix| matrix.row(row).expect("validated matrix row")),
                );
                let words: [P::Word; D] = digest.map(Into::into);
                leaves.write_rows(row as u64, 1, &words)?;
            }
            leaves.finalize()?;
            self.finish_tree(matrices, leaves, &job_dir, height)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }
}

const MMCS_BUFFER_BYTES: usize = 8 * 1024 * 1024;

fn hash_buffered_rows<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    hash: &P::Hash,
    buffers: &[Vec<P::Word>],
    widths: &[usize],
    row_count: usize,
    output: &mut [P::Word],
    pool: Option<&rayon::ThreadPool>,
) where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let hash_row = |(row, destination): (usize, &mut [P::Word])| {
        let digest = hash.hash_iter(buffers.iter().zip(widths).flat_map(|(buffer, width)| {
            buffer[row * *width..(row + 1) * *width]
                .iter()
                .map(|word| (*word).into())
        }));
        let words: [P::Word; D] = digest.map(Into::into);
        destination.copy_from_slice(&words);
    };
    if let Some(pool) = pool {
        pool.install(|| {
            output[..row_count * D]
                .par_chunks_mut(D)
                .enumerate()
                .for_each(hash_row)
        });
    } else {
        output[..row_count * D]
            .chunks_exact_mut(D)
            .enumerate()
            .for_each(hash_row);
    }
}

fn compress_buffered_rows<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    compress: &P::Compression,
    children: &[P::Word],
    row_count: usize,
    parents: &mut [P::Word],
    pool: Option<&rayon::ThreadPool>,
) where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let compress_row = |(row, destination): (usize, &mut [P::Word])| {
        let offset = row * D * 2;
        let left: [P::Val; D] = core::array::from_fn(|index| children[offset + index].into());
        let right: [P::Val; D] = core::array::from_fn(|index| children[offset + D + index].into());
        let words: [P::Word; D] = compress.compress([left, right]).map(Into::into);
        destination.copy_from_slice(&words);
    };
    if let Some(pool) = pool {
        pool.install(|| {
            parents[..row_count * D]
                .par_chunks_mut(D)
                .enumerate()
                .for_each(compress_row)
        });
    } else {
        parents[..row_count * D]
            .chunks_exact_mut(D)
            .enumerate()
            .for_each(compress_row);
    }
}

fn bit_reverse_digest_store<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    standard: ScratchMatrixStore<P::Word>,
    job_dir: &Path,
    height: usize,
    policy: &ResourcePolicyV1,
) -> Result<ScratchMatrixStore<P::Word>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let log_height = height.trailing_zeros() as usize;
    let row_bits = log_height / 2;
    let column_bits = log_height - row_bits;
    let row_factor = 1usize << row_bits;
    let column_factor = 1usize << column_bits;

    let columns_reversed = reverse_digest_groups::<W, D, P>(
        &standard,
        job_dir,
        "mmcs-bitrev-columns.bin",
        column_factor,
        column_bits,
    )?;
    standard.remove()?;
    let transposed = transpose_digest_grid::<W, D, P>(
        &columns_reversed,
        job_dir,
        "mmcs-bitrev-transpose.bin",
        row_factor,
        column_factor,
        policy,
    )?;
    columns_reversed.remove()?;
    let leaves = reverse_digest_groups::<W, D, P>(
        &transposed,
        job_dir,
        "mmcs-level-0.bin",
        row_factor,
        row_bits,
    )?;
    transposed.remove()?;
    Ok(leaves)
}

fn reverse_digest_groups<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    source: &ScratchMatrixStore<P::Word>,
    job_dir: &Path,
    file_name: &str,
    group_rows: usize,
    bits: usize,
) -> Result<ScratchMatrixStore<P::Word>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let height = usize::try_from(source.rows()).map_err(|_| DurableMmcsError::InvalidShape)?;
    if group_rows == 0 || height % group_rows != 0 || source.columns() != D {
        return Err(DurableMmcsError::InvalidShape);
    }
    let mut target = ScratchMatrixStore::<P::Word>::create(job_dir, file_name, height as u64, D)?;
    let mut input = vec![P::Word::default(); group_rows * D];
    let mut output = vec![P::Word::default(); group_rows * D];
    for group_start in (0..height).step_by(group_rows) {
        source.read_rows(group_start as u64, group_rows, &mut input)?;
        for row in 0..group_rows {
            let destination = reverse_low_bits(row, bits);
            output[destination * D..(destination + 1) * D]
                .copy_from_slice(&input[row * D..(row + 1) * D]);
        }
        target.write_rows(group_start as u64, group_rows, &output)?;
    }
    target.finalize()?;
    Ok(target)
}

fn transpose_digest_grid<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    source: &ScratchMatrixStore<P::Word>,
    job_dir: &Path,
    file_name: &str,
    rows: usize,
    columns: usize,
    policy: &ResourcePolicyV1,
) -> Result<ScratchMatrixStore<P::Word>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let height = rows
        .checked_mul(columns)
        .ok_or(DurableMmcsError::InvalidShape)?;
    if source.rows() != height as u64 || source.columns() != D {
        return Err(DurableMmcsError::InvalidShape);
    }
    let fixed_items = MMCS_BUFFER_BYTES / (2 * D * word_bytes::<W, D, P>());
    let max_items = policy
        .tile_rows(word_bytes::<W, D, P>(), D * 2)?
        .min(fixed_items)
        .max(1);
    let max_side = rows.min(columns);
    let mut tile_side = 1usize;
    while tile_side < max_side {
        let Some(next) = tile_side.checked_mul(2) else {
            break;
        };
        if next > max_side || next.checked_mul(next).is_none_or(|items| items > max_items) {
            break;
        }
        tile_side = next;
    }
    let mut target = ScratchMatrixStore::<P::Word>::create(job_dir, file_name, height as u64, D)?;
    let tile_items = tile_side
        .checked_mul(tile_side)
        .and_then(|items| items.checked_mul(D))
        .ok_or(DurableMmcsError::InvalidShape)?;
    let mut input = vec![P::Word::default(); tile_items];
    let mut output = vec![P::Word::default(); tile_items];
    for row_start in (0..rows).step_by(tile_side) {
        let row_count = (rows - row_start).min(tile_side);
        for column_start in (0..columns).step_by(tile_side) {
            let column_count = (columns - column_start).min(tile_side);
            for row in 0..row_count {
                let destination = row * column_count * D;
                source.read_rows(
                    ((row_start + row) * columns + column_start) as u64,
                    column_count,
                    &mut input[destination..destination + column_count * D],
                )?;
            }
            for row in 0..row_count {
                for column in 0..column_count {
                    let source_offset = (row * column_count + column) * D;
                    let destination_offset = (column * row_count + row) * D;
                    output[destination_offset..destination_offset + D]
                        .copy_from_slice(&input[source_offset..source_offset + D]);
                }
            }
            for column in 0..column_count {
                let source_offset = column * row_count * D;
                target.write_rows(
                    ((column_start + column) * rows + row_start) as u64,
                    row_count,
                    &output[source_offset..source_offset + row_count * D],
                )?;
            }
        }
    }
    target.finalize()?;
    Ok(target)
}

fn bounded_leaf_block_rows<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    policy: &ResourcePolicyV1,
    total_width: usize,
    height: usize,
) -> Result<usize>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let bytes_per_row = total_width
        .checked_mul(word_bytes::<W, D, P>())
        .ok_or(DurableMmcsError::InvalidShape)?;
    let fixed_budget_rows = MMCS_BUFFER_BYTES.checked_div(bytes_per_row).unwrap_or(0);
    if fixed_budget_rows == 0 {
        return Err(StreamError::ResourceLimit {
            resource: "resident memory",
            required: bytes_per_row as u64,
            cap: MMCS_BUFFER_BYTES as u64,
        }
        .into());
    }
    let rows = policy
        .tile_rows(word_bytes::<W, D, P>(), total_width)?
        .min(fixed_budget_rows)
        .min(height)
        .max(1);
    Ok(highest_power_of_two_at_most(rows))
}

fn bounded_parent_block_rows<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    policy: &ResourcePolicyV1,
) -> Result<usize>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let bytes_per_parent = D * word_bytes::<W, D, P>() * 3;
    let fixed_budget_rows = (MMCS_BUFFER_BYTES / bytes_per_parent).max(1);
    Ok(highest_power_of_two_at_most(
        policy
            .tile_rows(word_bytes::<W, D, P>(), D * 3)?
            .min(fixed_budget_rows)
            .max(1),
    ))
}

fn highest_power_of_two_at_most(value: usize) -> usize {
    1usize << (usize::BITS - 1 - value.max(1).leading_zeros())
}

fn reverse_low_bits(value: usize, bits: usize) -> usize {
    if bits == 0 {
        0
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }
}

fn read_sorted_digests<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    layer: &ScratchMatrixStore<P::Word>,
    indices: &[usize],
) -> Result<Vec<[P::Val; D]>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let mut output = Vec::with_capacity(indices.len());
    let mut start = 0;
    while start < indices.len() {
        let mut end = start + 1;
        while end < indices.len() && indices[end] == indices[end - 1] + 1 {
            end += 1;
        }
        let row_count = end - start;
        let mut words = vec![P::Word::default(); row_count * D];
        layer.read_rows(indices[start] as u64, row_count, &mut words)?;
        output.extend(
            words
                .chunks_exact(D)
                .map(|row| core::array::from_fn(|column| row[column].into())),
        );
        start = end;
    }
    Ok(output)
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Mmcs<P::Val>
    for DurableProfileMmcs<W, D, P>
where
    // The one bound the trait's own `where` clause does not elaborate to
    // callers: `Mmcs` requires its `Commitment`/`Proof` to be serde types, and
    // serde's array impls are macro-generated per length, so a generic `D`
    // cannot select one.
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type ProverData<M> = DurableMerkleData<W, D, P, M>;
    type Commitment = ProfileCap<W, D, P>;
    type Proof = Vec<[P::Val; D]>;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<P::Val>>(&self, inputs: Vec<M>) -> (Self::Commitment, Self::ProverData<M>) {
        self.try_commit(inputs)
            .expect("durable MMCS resource preflight or persistence failed")
    }

    fn open_batch<M: Matrix<P::Val>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<P::Val, Self> {
        let height = prover_data
            .matrices
            .first()
            .map(Matrix::height)
            .expect("committed matrices are non-empty");
        assert!(index < height, "MMCS opening index out of bounds");
        let opened_values = prover_data
            .matrices
            .iter()
            .map(|matrix| {
                matrix
                    .row(index)
                    .expect("validated matrix row")
                    .into_iter()
                    .collect()
            })
            .collect();
        let mut proof = Vec::with_capacity(prover_data.layers.len().saturating_sub(1));
        let mut layer_index = index;
        for layer in prover_data
            .layers
            .iter()
            .take(prover_data.layers.len().saturating_sub(1))
        {
            let mut sibling = [P::Word::default(); D];
            layer
                .read_rows((layer_index ^ 1) as u64, 1, &mut sibling)
                .expect("durable MMCS layer passed finalization");
            proof.push(sibling.map(Into::into));
            layer_index >>= 1;
        }
        BatchOpening::new(opened_values, proof)
    }

    fn get_matrices<'a, M: Matrix<P::Val>>(
        &self,
        prover_data: &'a Self::ProverData<M>,
    ) -> Vec<&'a M> {
        prover_data.matrices.iter().collect()
    }

    fn verify_batch(
        &self,
        commit: &Self::Commitment,
        dimensions: &[Dimensions],
        index: usize,
        opening: BatchOpeningRef<'_, P::Val, Self>,
    ) -> std::result::Result<(), Self::Error> {
        self.reference.verify_batch(
            commit,
            dimensions,
            index,
            BatchOpeningRef::new(opening.opened_values, opening.opening_proof),
        )
    }
}

fn create_job_dir(root: &Path) -> Result<PathBuf> {
    create_unique_job_dir(root, "mmcs", &JOB_COUNTER).map_err(Into::into)
}

/// Goldilocks pins, so `bounded_pcs`/`bounded_prover` keep naming exactly the
/// types they named before this module became generic.
pub mod goldilocks {
    use crate::profile::GoldilocksProfile;

    /// The pre-generic name for the durable MMCS at Goldilocks' `<8, 4>`.
    pub type DurableGoldilocksMmcs = super::DurableProfileMmcs<8, 4, GoldilocksProfile>;
    pub type DurableMerkleData<M> = super::DurableMerkleData<8, 4, GoldilocksProfile, M>;
}

#[cfg(test)]
mod tests {
    use super::goldilocks::DurableGoldilocksMmcs;
    use super::*;
    use crate::checkpoint::profile_permutation;
    use crate::dft::GoldilocksWord;
    use crate::profile::GoldilocksProfile;
    use hc_stream::{CheckpointPolicy, ResourceMode};
    use p3_commit::Mmcs;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

    type Permutation = crate::ProfilePermutation;
    type Hash = PaddingFreeSponge<Permutation, 8, 4, 4>;
    type Compression = TruncatedPermutation<Permutation, 2, 4, 8>;
    const DIGEST_ELEMS: usize = 4;

    fn policy(root: &Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 32 * 1024 * 1024,
            max_scratch_bytes: 128 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        }
    }

    fn components() -> (Hash, Compression) {
        let permutation = profile_permutation();
        (
            Hash::new(permutation.clone()),
            Compression::new(permutation),
        )
    }

    #[test]
    fn tiled_bit_reversal_matches_index_permutation_across_rectangular_splits() {
        let dir = tempfile::tempdir().unwrap();
        for height in [1usize, 2, 8, 32, 128] {
            let job_dir = create_job_dir(dir.path()).unwrap();
            let mut standard = ScratchMatrixStore::<GoldilocksWord>::create(
                &job_dir,
                "mmcs-leaves-standard.bin",
                height as u64,
                DIGEST_ELEMS,
            )
            .unwrap();
            let words: Vec<_> = (0..height * DIGEST_ELEMS)
                .map(|value| GoldilocksWord(Goldilocks::from_u64(value as u64)))
                .collect();
            standard.write_rows(0, height, &words).unwrap();
            standard.finalize().unwrap();
            let reversed = bit_reverse_digest_store::<8, 4, GoldilocksProfile>(
                standard,
                &job_dir,
                height,
                &policy(dir.path()),
            )
            .unwrap();
            let mut actual = vec![GoldilocksWord::default(); words.len()];
            reversed.read_rows(0, height, &mut actual).unwrap();
            for source in 0..height {
                let destination = reverse_low_bits(source, height.trailing_zeros() as usize);
                assert_eq!(
                    &actual[destination * DIGEST_ELEMS..(destination + 1) * DIGEST_ELEMS],
                    &words[source * DIGEST_ELEMS..(source + 1) * DIGEST_ELEMS]
                );
            }
            reversed.remove().unwrap();
            fs::remove_dir(job_dir).unwrap();
        }
    }

    #[test]
    fn durable_roots_and_openings_match_upstream_mmcs() {
        let dir = tempfile::tempdir().unwrap();
        let (hash, compression) = components();
        let durable =
            DurableGoldilocksMmcs::new(hash.clone(), compression.clone(), policy(dir.path()))
                .unwrap();
        let reference: ReferenceMmcs<8, 4, GoldilocksProfile> =
            ReferenceMmcs::<8, 4, GoldilocksProfile>::new(hash, compression, 0);
        let first = RowMajorMatrix::new((0..64).map(Goldilocks::from_u64).collect::<Vec<_>>(), 4);
        let second = RowMajorMatrix::new((64..96).map(Goldilocks::from_u64).collect::<Vec<_>>(), 2);
        let (expected_root, expected_data) = reference.commit(vec![first.clone(), second.clone()]);
        let (actual_root, actual_data) = durable.commit(vec![first, second]);
        assert_eq!(actual_root, expected_root);
        assert_eq!(actual_data.layer_count(), 5);

        for index in 0..16 {
            let expected = reference.open_batch(index, &expected_data);
            let actual = durable.open_batch(index, &actual_data);
            assert_eq!(actual.opened_values, expected.opened_values);
            assert_eq!(actual.opening_proof, expected.opening_proof);
            durable
                .verify_batch(
                    &actual_root,
                    &[
                        Dimensions {
                            width: 4,
                            height: 16,
                        },
                        Dimensions {
                            width: 2,
                            height: 16,
                        },
                    ],
                    index,
                    (&actual).into(),
                )
                .unwrap();
        }

        let indices = [0, 1, 3, 7, 12, 15];
        let batched = durable.open_batches_sorted(&indices, &actual_data).unwrap();
        for (index, batched_opening) in indices.into_iter().zip(batched) {
            let individual = durable.open_batch(index, &actual_data);
            assert_eq!(batched_opening.opened_values, individual.opened_values);
            assert_eq!(batched_opening.opening_proof, individual.opening_proof);
        }
        assert!(matches!(
            durable.open_batches_sorted(&[2, 1], &actual_data),
            Err(DurableMmcsError::InvalidQuerySet)
        ));
    }

    #[test]
    fn rejects_shapes_outside_the_frozen_profile_invariant() {
        let dir = tempfile::tempdir().unwrap();
        let (hash, compression) = components();
        let durable = DurableGoldilocksMmcs::new(hash, compression, policy(dir.path())).unwrap();
        let bad = RowMajorMatrix::new(vec![Goldilocks::ZERO; 12], 2);
        assert!(matches!(
            durable.try_commit(vec![bad]),
            Err(DurableMmcsError::InvalidShape)
        ));
    }
}
