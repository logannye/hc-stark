use crate::dft::{GoldilocksWord, ResourceBoundedMatrix};
use hc_stream::{
    BlockMatrix, CanonicalElement, ExecutionMode, MatrixStore, PhaseEstimate, ResourceEstimate,
    ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::Field;
use p3_goldilocks::Goldilocks;
use p3_matrix::bitrev::{BitReversedMatrixView, BitReversibleMatrix};
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::{MerkleCap, MerkleTreeError, MerkleTreeMmcs};
use p3_symmetric::{CryptographicHasher, PseudoCompressionFunction};
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const DIGEST_ELEMS: usize = 4;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

type Packing = <Goldilocks as Field>::Packing;
type ReferenceMmcs<H, C> = MerkleTreeMmcs<Packing, Packing, H, C, 2, DIGEST_ELEMS>;
type DurableCommitmentData<M> = (
    MerkleCap<Goldilocks, [Goldilocks; DIGEST_ELEMS]>,
    DurableMerkleData<M>,
);

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
pub struct DurableMerkleData<M> {
    matrices: Vec<M>,
    layers: Vec<ScratchMatrixStore<GoldilocksWord>>,
    job_dir: PathBuf,
}

impl<M> DurableMerkleData<M> {
    pub fn layer_count(&self) -> usize {
        self.layers.len()
    }

    pub fn job_dir(&self) -> &Path {
        &self.job_dir
    }
}

impl<M> Drop for DurableMerkleData<M> {
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
#[derive(Clone, Debug)]
pub struct DurableGoldilocksMmcs<H, C> {
    hash: H,
    compress: C,
    reference: ReferenceMmcs<H, C>,
    policy: ResourcePolicyV1,
}

impl<H: Clone, C: Clone> DurableGoldilocksMmcs<H, C> {
    pub fn new(hash: H, compress: C, policy: ResourcePolicyV1) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            reference: ReferenceMmcs::new(hash.clone(), compress.clone(), 0),
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
            .saturating_mul(DIGEST_ELEMS as u64)
            .saturating_mul(8);
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
    pub fn open_batches_sorted<M: Matrix<Goldilocks>>(
        &self,
        indices: &[usize],
        prover_data: &DurableMerkleData<M>,
    ) -> Result<Vec<BatchOpening<Goldilocks, Self>>>
    where
        H: CryptographicHasher<Goldilocks, [Goldilocks; DIGEST_ELEMS]>
            + CryptographicHasher<Packing, [Packing; DIGEST_ELEMS]>
            + Sync,
        C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2>
            + PseudoCompressionFunction<[Packing; DIGEST_ELEMS], 2>
            + Sync,
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

        let opened_values: Vec<Vec<Vec<Goldilocks>>> = indices
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
            let sibling_digests = read_sorted_digests(layer, &sibling_indices)?;
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
        matrices: Vec<ResourceBoundedMatrix>,
    ) -> Result<(
        MerkleCap<Goldilocks, [Goldilocks; DIGEST_ELEMS]>,
        DurableMerkleData<BitReversedMatrixView<ResourceBoundedMatrix>>,
    )>
    where
        H: CryptographicHasher<Goldilocks, [Goldilocks; DIGEST_ELEMS]> + Sync,
        C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2> + Sync,
    {
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
            let mut standard_leaves = ScratchMatrixStore::<GoldilocksWord>::create(
                &job_dir,
                "mmcs-leaves-standard.bin",
                height as u64,
                DIGEST_ELEMS,
            )?;
            let block_rows = bounded_leaf_block_rows(&self.policy, total_width, height)?;
            let mut buffers: Vec<Vec<GoldilocksWord>> = matrices
                .iter()
                .map(|matrix| vec![GoldilocksWord::default(); block_rows * matrix.width()])
                .collect();
            let widths: Vec<_> = matrices.iter().map(Matrix::width).collect();
            let pool = self.worker_pool()?;
            let mut leaf_words = vec![GoldilocksWord::default(); block_rows * DIGEST_ELEMS];
            for row_start in (0..height).step_by(block_rows) {
                let row_count = (height - row_start).min(block_rows);
                for (matrix, buffer) in matrices.iter().zip(&mut buffers) {
                    matrix.read_rows(
                        row_start as u64,
                        row_count,
                        &mut buffer[..row_count * matrix.width()],
                    )?;
                }
                hash_buffered_rows(
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
                    &leaf_words[..row_count * DIGEST_ELEMS],
                )?;
            }
            standard_leaves.finalize()?;
            let leaves = bit_reverse_digest_store(standard_leaves, &job_dir, height, &self.policy)?;
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
    pub fn try_commit_blocks<M>(&self, matrices: Vec<M>) -> Result<DurableCommitmentData<M>>
    where
        M: Matrix<Goldilocks> + BlockMatrix<GoldilocksWord>,
        H: CryptographicHasher<Goldilocks, [Goldilocks; DIGEST_ELEMS]> + Sync,
        C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2> + Sync,
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
            let mut leaves = ScratchMatrixStore::<GoldilocksWord>::create(
                &job_dir,
                "mmcs-level-0.bin",
                height as u64,
                DIGEST_ELEMS,
            )?;
            let block_rows = bounded_leaf_block_rows(&self.policy, total_width, height)?;
            let mut buffers: Vec<Vec<GoldilocksWord>> = matrices
                .iter()
                .map(|matrix| vec![GoldilocksWord::default(); block_rows * matrix.width()])
                .collect();
            let widths: Vec<_> = matrices.iter().map(Matrix::width).collect();
            let pool = self.worker_pool()?;
            let mut leaf_words = vec![GoldilocksWord::default(); block_rows * DIGEST_ELEMS];
            for row_start in (0..height).step_by(block_rows) {
                let row_count = (height - row_start).min(block_rows);
                for (matrix, buffer) in matrices.iter().zip(&mut buffers) {
                    matrix.read_rows(
                        row_start as u64,
                        row_count,
                        &mut buffer[..row_count * matrix.width()],
                    )?;
                }
                hash_buffered_rows(
                    &self.hash,
                    &buffers,
                    &widths,
                    row_count,
                    &mut leaf_words,
                    pool.as_ref(),
                );
                leaves.write_rows(
                    row_start as u64,
                    row_count,
                    &leaf_words[..row_count * DIGEST_ELEMS],
                )?;
            }
            leaves.finalize()?;
            self.finish_tree(matrices, leaves, &job_dir, height)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    fn finish_tree<M: Matrix<Goldilocks>>(
        &self,
        matrices: Vec<M>,
        leaves: ScratchMatrixStore<GoldilocksWord>,
        job_dir: &Path,
        height: usize,
    ) -> Result<DurableCommitmentData<M>>
    where
        C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2> + Sync,
    {
        let mut layers = Vec::with_capacity(height.trailing_zeros() as usize + 1);
        layers.push(leaves);
        let pool = self.worker_pool()?;
        let parent_block_rows = bounded_parent_block_rows(&self.policy)?;
        let mut level_height = height;
        while level_height > 1 {
            let next_height = level_height / 2;
            let level_index = layers.len();
            let mut next = ScratchMatrixStore::<GoldilocksWord>::create(
                job_dir,
                &format!("mmcs-level-{level_index}.bin"),
                next_height as u64,
                DIGEST_ELEMS,
            )?;
            for row_start in (0..next_height).step_by(parent_block_rows) {
                let row_count = (next_height - row_start).min(parent_block_rows);
                let mut children = vec![GoldilocksWord::default(); row_count * DIGEST_ELEMS * 2];
                layers.last().expect("leaf layer exists").read_rows(
                    (row_start * 2) as u64,
                    row_count * 2,
                    &mut children,
                )?;
                let mut parents = vec![GoldilocksWord::default(); row_count * DIGEST_ELEMS];
                compress_buffered_rows(
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

        let mut root_words = [GoldilocksWord::default(); DIGEST_ELEMS];
        layers
            .last()
            .expect("root layer exists")
            .read_rows(0, 1, &mut root_words)?;
        Ok((
            MerkleCap::new(vec![root_words.map(|word| word.0)]),
            DurableMerkleData {
                matrices,
                layers,
                job_dir: job_dir.to_path_buf(),
            },
        ))
    }

    #[allow(clippy::type_complexity)]
    pub fn try_commit<M: Matrix<Goldilocks>>(
        &self,
        matrices: Vec<M>,
    ) -> Result<(
        MerkleCap<Goldilocks, [Goldilocks; DIGEST_ELEMS]>,
        DurableMerkleData<M>,
    )>
    where
        H: CryptographicHasher<Goldilocks, [Goldilocks; DIGEST_ELEMS]> + Sync,
        C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2> + Sync,
    {
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
            let mut leaves = ScratchMatrixStore::<GoldilocksWord>::create(
                &job_dir,
                "mmcs-level-0.bin",
                height as u64,
                DIGEST_ELEMS,
            )?;
            for row in 0..height {
                let digest = self.hash.hash_iter(
                    matrices
                        .iter()
                        .flat_map(|matrix| matrix.row(row).expect("validated matrix row")),
                );
                let words = digest.map(GoldilocksWord);
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

fn hash_buffered_rows<H>(
    hash: &H,
    buffers: &[Vec<GoldilocksWord>],
    widths: &[usize],
    row_count: usize,
    output: &mut [GoldilocksWord],
    pool: Option<&rayon::ThreadPool>,
) where
    H: CryptographicHasher<Goldilocks, [Goldilocks; DIGEST_ELEMS]> + Sync,
{
    let hash_row = |(row, destination): (usize, &mut [GoldilocksWord])| {
        let digest = hash.hash_iter(buffers.iter().zip(widths).flat_map(|(buffer, width)| {
            buffer[row * *width..(row + 1) * *width]
                .iter()
                .map(|word| word.0)
        }));
        destination.copy_from_slice(&digest.map(GoldilocksWord));
    };
    if let Some(pool) = pool {
        pool.install(|| {
            output[..row_count * DIGEST_ELEMS]
                .par_chunks_mut(DIGEST_ELEMS)
                .enumerate()
                .for_each(hash_row)
        });
    } else {
        output[..row_count * DIGEST_ELEMS]
            .chunks_exact_mut(DIGEST_ELEMS)
            .enumerate()
            .for_each(hash_row);
    }
}

fn compress_buffered_rows<C>(
    compress: &C,
    children: &[GoldilocksWord],
    row_count: usize,
    parents: &mut [GoldilocksWord],
    pool: Option<&rayon::ThreadPool>,
) where
    C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2> + Sync,
{
    let compress_row = |(row, destination): (usize, &mut [GoldilocksWord])| {
        let offset = row * DIGEST_ELEMS * 2;
        let left = core::array::from_fn(|index| children[offset + index].0);
        let right = core::array::from_fn(|index| children[offset + DIGEST_ELEMS + index].0);
        destination.copy_from_slice(&compress.compress([left, right]).map(GoldilocksWord));
    };
    if let Some(pool) = pool {
        pool.install(|| {
            parents[..row_count * DIGEST_ELEMS]
                .par_chunks_mut(DIGEST_ELEMS)
                .enumerate()
                .for_each(compress_row)
        });
    } else {
        parents[..row_count * DIGEST_ELEMS]
            .chunks_exact_mut(DIGEST_ELEMS)
            .enumerate()
            .for_each(compress_row);
    }
}

fn bit_reverse_digest_store(
    standard: ScratchMatrixStore<GoldilocksWord>,
    job_dir: &Path,
    height: usize,
    policy: &ResourcePolicyV1,
) -> Result<ScratchMatrixStore<GoldilocksWord>> {
    let log_height = height.trailing_zeros() as usize;
    let row_bits = log_height / 2;
    let column_bits = log_height - row_bits;
    let row_factor = 1usize << row_bits;
    let column_factor = 1usize << column_bits;

    let columns_reversed = reverse_digest_groups(
        &standard,
        job_dir,
        "mmcs-bitrev-columns.bin",
        column_factor,
        column_bits,
    )?;
    standard.remove()?;
    let transposed = transpose_digest_grid(
        &columns_reversed,
        job_dir,
        "mmcs-bitrev-transpose.bin",
        row_factor,
        column_factor,
        policy,
    )?;
    columns_reversed.remove()?;
    let leaves = reverse_digest_groups(
        &transposed,
        job_dir,
        "mmcs-level-0.bin",
        row_factor,
        row_bits,
    )?;
    transposed.remove()?;
    Ok(leaves)
}

fn reverse_digest_groups(
    source: &ScratchMatrixStore<GoldilocksWord>,
    job_dir: &Path,
    file_name: &str,
    group_rows: usize,
    bits: usize,
) -> Result<ScratchMatrixStore<GoldilocksWord>> {
    let height = usize::try_from(source.rows()).map_err(|_| DurableMmcsError::InvalidShape)?;
    if group_rows == 0 || height % group_rows != 0 || source.columns() != DIGEST_ELEMS {
        return Err(DurableMmcsError::InvalidShape);
    }
    let mut target = ScratchMatrixStore::<GoldilocksWord>::create(
        job_dir,
        file_name,
        height as u64,
        DIGEST_ELEMS,
    )?;
    let mut input = vec![GoldilocksWord::default(); group_rows * DIGEST_ELEMS];
    let mut output = vec![GoldilocksWord::default(); group_rows * DIGEST_ELEMS];
    for group_start in (0..height).step_by(group_rows) {
        source.read_rows(group_start as u64, group_rows, &mut input)?;
        for row in 0..group_rows {
            let destination = reverse_low_bits(row, bits);
            output[destination * DIGEST_ELEMS..(destination + 1) * DIGEST_ELEMS]
                .copy_from_slice(&input[row * DIGEST_ELEMS..(row + 1) * DIGEST_ELEMS]);
        }
        target.write_rows(group_start as u64, group_rows, &output)?;
    }
    target.finalize()?;
    Ok(target)
}

fn transpose_digest_grid(
    source: &ScratchMatrixStore<GoldilocksWord>,
    job_dir: &Path,
    file_name: &str,
    rows: usize,
    columns: usize,
    policy: &ResourcePolicyV1,
) -> Result<ScratchMatrixStore<GoldilocksWord>> {
    let height = rows
        .checked_mul(columns)
        .ok_or(DurableMmcsError::InvalidShape)?;
    if source.rows() != height as u64 || source.columns() != DIGEST_ELEMS {
        return Err(DurableMmcsError::InvalidShape);
    }
    let fixed_items = MMCS_BUFFER_BYTES / (2 * DIGEST_ELEMS * GoldilocksWord::WIDTH);
    let max_items = policy
        .tile_rows(GoldilocksWord::WIDTH, DIGEST_ELEMS * 2)?
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
    let mut target = ScratchMatrixStore::<GoldilocksWord>::create(
        job_dir,
        file_name,
        height as u64,
        DIGEST_ELEMS,
    )?;
    let tile_items = tile_side
        .checked_mul(tile_side)
        .and_then(|items| items.checked_mul(DIGEST_ELEMS))
        .ok_or(DurableMmcsError::InvalidShape)?;
    let mut input = vec![GoldilocksWord::default(); tile_items];
    let mut output = vec![GoldilocksWord::default(); tile_items];
    for row_start in (0..rows).step_by(tile_side) {
        let row_count = (rows - row_start).min(tile_side);
        for column_start in (0..columns).step_by(tile_side) {
            let column_count = (columns - column_start).min(tile_side);
            for row in 0..row_count {
                let destination = row * column_count * DIGEST_ELEMS;
                source.read_rows(
                    ((row_start + row) * columns + column_start) as u64,
                    column_count,
                    &mut input[destination..destination + column_count * DIGEST_ELEMS],
                )?;
            }
            for row in 0..row_count {
                for column in 0..column_count {
                    let source_offset = (row * column_count + column) * DIGEST_ELEMS;
                    let destination_offset = (column * row_count + row) * DIGEST_ELEMS;
                    output[destination_offset..destination_offset + DIGEST_ELEMS]
                        .copy_from_slice(&input[source_offset..source_offset + DIGEST_ELEMS]);
                }
            }
            for column in 0..column_count {
                let source_offset = column * row_count * DIGEST_ELEMS;
                target.write_rows(
                    ((column_start + column) * rows + row_start) as u64,
                    row_count,
                    &output[source_offset..source_offset + row_count * DIGEST_ELEMS],
                )?;
            }
        }
    }
    target.finalize()?;
    Ok(target)
}

fn bounded_leaf_block_rows(
    policy: &ResourcePolicyV1,
    total_width: usize,
    height: usize,
) -> Result<usize> {
    let bytes_per_row = total_width
        .checked_mul(GoldilocksWord::WIDTH)
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
        .tile_rows(GoldilocksWord::WIDTH, total_width)?
        .min(fixed_budget_rows)
        .min(height)
        .max(1);
    Ok(highest_power_of_two_at_most(rows))
}

fn bounded_parent_block_rows(policy: &ResourcePolicyV1) -> Result<usize> {
    let bytes_per_parent = DIGEST_ELEMS * GoldilocksWord::WIDTH * 3;
    let fixed_budget_rows = (MMCS_BUFFER_BYTES / bytes_per_parent).max(1);
    Ok(highest_power_of_two_at_most(
        policy
            .tile_rows(GoldilocksWord::WIDTH, DIGEST_ELEMS * 3)?
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

fn read_sorted_digests(
    layer: &ScratchMatrixStore<GoldilocksWord>,
    indices: &[usize],
) -> Result<Vec<[Goldilocks; DIGEST_ELEMS]>> {
    let mut output = Vec::with_capacity(indices.len());
    let mut start = 0;
    while start < indices.len() {
        let mut end = start + 1;
        while end < indices.len() && indices[end] == indices[end - 1] + 1 {
            end += 1;
        }
        let row_count = end - start;
        let mut words = vec![GoldilocksWord::default(); row_count * DIGEST_ELEMS];
        layer.read_rows(indices[start] as u64, row_count, &mut words)?;
        output.extend(
            words
                .chunks_exact(DIGEST_ELEMS)
                .map(|row| core::array::from_fn(|column| row[column].0)),
        );
        start = end;
    }
    Ok(output)
}

impl<H, C> Mmcs<Goldilocks> for DurableGoldilocksMmcs<H, C>
where
    H: CryptographicHasher<Goldilocks, [Goldilocks; DIGEST_ELEMS]>
        + CryptographicHasher<Packing, [Packing; DIGEST_ELEMS]>
        + Clone
        + Sync,
    C: PseudoCompressionFunction<[Goldilocks; DIGEST_ELEMS], 2>
        + PseudoCompressionFunction<[Packing; DIGEST_ELEMS], 2>
        + Clone
        + Sync,
{
    type ProverData<M> = DurableMerkleData<M>;
    type Commitment = MerkleCap<Goldilocks, [Goldilocks; DIGEST_ELEMS]>;
    type Proof = Vec<[Goldilocks; DIGEST_ELEMS]>;
    type Error = MerkleTreeError;

    fn commit<M: Matrix<Goldilocks>>(
        &self,
        inputs: Vec<M>,
    ) -> (Self::Commitment, Self::ProverData<M>) {
        self.try_commit(inputs)
            .expect("durable MMCS resource preflight or persistence failed")
    }

    fn open_batch<M: Matrix<Goldilocks>>(
        &self,
        index: usize,
        prover_data: &Self::ProverData<M>,
    ) -> BatchOpening<Goldilocks, Self> {
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
            let mut sibling = [GoldilocksWord::default(); DIGEST_ELEMS];
            layer
                .read_rows((layer_index ^ 1) as u64, 1, &mut sibling)
                .expect("durable MMCS layer passed finalization");
            proof.push(sibling.map(|word| word.0));
            layer_index >>= 1;
        }
        BatchOpening::new(opened_values, proof)
    }

    fn get_matrices<'a, M: Matrix<Goldilocks>>(
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
        opening: BatchOpeningRef<'_, Goldilocks, Self>,
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
    fs::create_dir_all(root)?;
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StreamError::UnsafePath.into());
    }
    let id = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = root.join(format!("mmcs-{}-{id}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::profile_permutation;
    use hc_stream::{CheckpointPolicy, ResourceMode};
    use p3_commit::Mmcs;
    use p3_field::PrimeCharacteristicRing;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

    type Permutation = crate::ProfilePermutation;
    type Hash = PaddingFreeSponge<Permutation, 8, 4, 4>;
    type Compression = TruncatedPermutation<Permutation, 2, 4, 8>;

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
            let reversed =
                bit_reverse_digest_store(standard, &job_dir, height, &policy(dir.path())).unwrap();
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
        let reference: ReferenceMmcs<Hash, Compression> = ReferenceMmcs::new(hash, compression, 0);
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
