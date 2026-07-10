use hc_stream::{
    BlockMatrix, CanonicalElement, ExecutionMode, MatrixStore, PhaseEstimate, ResourceEstimate,
    ResourceMode, ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::{PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::bitrev::{BitReversalPerm, BitReversedMatrixView, BitReversibleMatrix};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
static JOB_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, thiserror::Error)]
pub enum DftError {
    #[error("invalid Plonky3 matrix: {0}")]
    InvalidMatrix(&'static str),
    #[error("matrix dimensions overflow the host address space")]
    SizeOverflow,
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

type Result<T> = std::result::Result<T, DftError>;

#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub struct GoldilocksWord(pub Goldilocks);

impl From<Goldilocks> for GoldilocksWord {
    fn from(value: Goldilocks) -> Self {
        Self(value)
    }
}

impl From<GoldilocksWord> for Goldilocks {
    fn from(value: GoldilocksWord) -> Self {
        value.0
    }
}

impl CanonicalElement for GoldilocksWord {
    const WIDTH: usize = 8;

    fn encode(self, output: &mut [u8]) {
        output.copy_from_slice(&self.0.as_canonical_u64().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> hc_stream::Result<Self> {
        let bytes: [u8; 8] = bytes
            .try_into()
            .map_err(|_| StreamError::Corrupt("invalid Goldilocks width"))?;
        let value = u64::from_le_bytes(bytes);
        if value >= GOLDILOCKS_MODULUS {
            return Err(StreamError::Corrupt("non-canonical Goldilocks element"));
        }
        Ok(Self(Goldilocks::new(value)))
    }
}

struct ManagedStore {
    store: Mutex<Option<ScratchMatrixStore<GoldilocksWord>>>,
    path: PathBuf,
    job_dir: PathBuf,
}

impl Drop for ManagedStore {
    fn drop(&mut self) {
        if let Ok(store) = self.store.get_mut() {
            if let Some(store) = store.take() {
                let _ = store.remove();
            }
        }
        let _ = fs::remove_dir(&self.job_dir);
    }
}

/// A Plonky3 matrix backed by a checksummed, owner-only scratch artifact.
#[derive(Clone)]
pub struct ScratchPlonky3Matrix {
    inner: Arc<ManagedStore>,
    width: usize,
    height: usize,
}

impl ScratchPlonky3Matrix {
    fn new(
        store: ScratchMatrixStore<GoldilocksWord>,
        width: usize,
        height: usize,
        job_dir: PathBuf,
    ) -> Self {
        let path = store.path().to_path_buf();
        Self {
            inner: Arc::new(ManagedStore {
                store: Mutex::new(Some(store)),
                path,
                job_dir,
            }),
            width,
            height,
        }
    }

    pub fn artifact_path(&self) -> &Path {
        &self.inner.path
    }

    pub fn try_row(&self, row: usize) -> Result<Vec<Goldilocks>> {
        self.try_rows(row, 1)
    }

    pub fn try_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<Goldilocks>> {
        if row_start
            .checked_add(row_count)
            .is_none_or(|end| end > self.height)
        {
            return Err(DftError::InvalidMatrix("row is out of bounds"));
        }
        let guard = self
            .inner
            .store
            .lock()
            .map_err(|_| StreamError::Corrupt("scratch matrix lock poisoned"))?;
        let store = guard
            .as_ref()
            .ok_or(StreamError::Corrupt("scratch matrix was released"))?;
        let mut words = vec![GoldilocksWord::default(); self.width * row_count];
        store.read_rows(row_start as u64, row_count, &mut words)?;
        Ok(words.into_iter().map(Into::into).collect())
    }
}

impl Matrix<Goldilocks> for ScratchPlonky3Matrix {
    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = Goldilocks, IntoIter = impl Iterator<Item = Goldilocks> + Send + Sync>
    {
        self.try_row(row)
            .expect("validated scratch row must remain readable")
            .into_iter()
    }
}

impl BitReversibleMatrix<Goldilocks> for ScratchPlonky3Matrix {
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

/// Result matrix selected by `ResourcePolicyV1`.
#[derive(Clone)]
pub enum ResourceBoundedMatrix {
    Memory(RowMajorMatrix<Goldilocks>),
    Scratch(ScratchPlonky3Matrix),
}

impl ResourceBoundedMatrix {
    pub fn try_row(&self, row: usize) -> Result<Vec<Goldilocks>> {
        self.try_rows(row, 1)
    }

    pub fn try_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<Goldilocks>> {
        match self {
            Self::Memory(matrix) => {
                let end = row_start
                    .checked_add(row_count)
                    .ok_or(DftError::SizeOverflow)?;
                if end > matrix.height() {
                    return Err(DftError::InvalidMatrix("row is out of bounds"));
                }
                let start = row_start
                    .checked_mul(matrix.width())
                    .ok_or(DftError::SizeOverflow)?;
                let end = end
                    .checked_mul(matrix.width())
                    .ok_or(DftError::SizeOverflow)?;
                Ok(matrix.values[start..end].to_vec())
            }
            Self::Scratch(matrix) => matrix.try_rows(row_start, row_count),
        }
    }

    pub fn execution_mode(&self) -> ExecutionMode {
        match self {
            Self::Memory(_) => ExecutionMode::Memory,
            Self::Scratch(_) => ExecutionMode::Scratch,
        }
    }
}

impl Matrix<Goldilocks> for ResourceBoundedMatrix {
    fn width(&self) -> usize {
        match self {
            Self::Memory(matrix) => matrix.width(),
            Self::Scratch(matrix) => matrix.width(),
        }
    }

    fn height(&self) -> usize {
        match self {
            Self::Memory(matrix) => matrix.height(),
            Self::Scratch(matrix) => matrix.height(),
        }
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = Goldilocks, IntoIter = impl Iterator<Item = Goldilocks> + Send + Sync>
    {
        self.try_row(row)
            .expect("validated resource-bounded row must remain readable")
            .into_iter()
    }
}

impl BitReversibleMatrix<Goldilocks> for ResourceBoundedMatrix {
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

/// Deterministic blockwise radix-2 DFT with two scratch matrices.
///
/// Plonky3 0.6.1's public DFT trait still owns a `RowMajorMatrix`; that input
/// is included in preflight and dropped after ingestion. `try_dft_block_matrix`
/// is the fully block-readable entry point proposed for upstream integration.
#[derive(Clone, Debug)]
pub struct ResourceBoundedDft {
    policy: ResourcePolicyV1,
}

impl Default for ResourceBoundedDft {
    fn default() -> Self {
        Self {
            policy: ResourcePolicyV1 {
                mode: ResourceMode::Scratch,
                max_resident_bytes: 512 * 1024 * 1024,
                max_scratch_bytes: 8 * 1024 * 1024 * 1024,
                scratch_dir: std::env::temp_dir().join("tinyzkp-plonky3"),
                max_threads: 1,
                checkpoint_policy: hc_stream::CheckpointPolicy::DeleteOnSuccess,
            },
        }
    }
}

impl ResourceBoundedDft {
    pub fn new(policy: ResourcePolicyV1) -> Result<Self> {
        policy.validate()?;
        Ok(Self { policy })
    }

    pub fn resource_policy(&self) -> &ResourcePolicyV1 {
        &self.policy
    }

    pub fn estimate_memory(&self, height: usize, width: usize) -> Result<ResourceEstimate> {
        let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)? as u64;
        let artifact_bytes = elements.checked_mul(8).ok_or(DftError::SizeOverflow)?;
        let twiddle_bytes = (height as u64).saturating_div(2).saturating_mul(8);
        let row_buffers = (width as u64).saturating_mul(8).saturating_mul(4);
        Ok(ResourceEstimate {
            peak_resident_bytes: artifact_bytes
                .saturating_add(twiddle_bytes)
                .saturating_add(row_buffers)
                .saturating_add(8 * 1024 * 1024),
            scratch_high_water_bytes: 0,
            total_read_bytes: 0,
            total_write_bytes: 0,
            phases: vec![PhaseEstimate {
                phase: "in_memory_radix2_dft".into(),
                read_bytes: 0,
                write_bytes: 0,
            }],
        })
    }

    pub fn estimate_scratch(
        &self,
        height: usize,
        width: usize,
        owned_input: bool,
    ) -> Result<ResourceEstimate> {
        let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)? as u64;
        let artifact_bytes = elements.checked_mul(8).ok_or(DftError::SizeOverflow)?;
        let owned_input_bytes = if owned_input { artifact_bytes } else { 0 };
        let tile_rows = self.policy.tile_rows(8, width)?.min(height) as u64;
        let tile_buffers = tile_rows
            .saturating_mul(width as u64)
            .saturating_mul(8)
            .saturating_mul(2);
        let layers = height.max(1).trailing_zeros() as u64;
        Ok(ResourceEstimate {
            peak_resident_bytes: owned_input_bytes
                .saturating_add(tile_buffers)
                .saturating_add(8 * 1024 * 1024),
            scratch_high_water_bytes: artifact_bytes.saturating_mul(2),
            total_read_bytes: artifact_bytes.saturating_mul(layers.saturating_add(1)),
            total_write_bytes: artifact_bytes.saturating_mul(layers.saturating_add(1)),
            phases: vec![PhaseEstimate {
                phase: "tiled_blockwise_radix2_dft".into(),
                read_bytes: artifact_bytes.saturating_mul(layers),
                write_bytes: artifact_bytes.saturating_mul(layers),
            }],
        })
    }

    pub fn try_dft_batch(
        &self,
        matrix: RowMajorMatrix<Goldilocks>,
    ) -> Result<ResourceBoundedMatrix> {
        let height = matrix.height();
        let width = matrix.width();
        self.validate_shape(height, width)?;
        let selected = self
            .policy
            .select_mode(&self.estimate_memory(height, width)?)?;
        let estimate = match selected {
            ExecutionMode::Memory => self.estimate_memory(height, width)?,
            ExecutionMode::Scratch => self.estimate_scratch(height, width, true)?,
        };
        self.policy.preflight_for_mode(selected, estimate)?;
        if selected == ExecutionMode::Memory {
            return Ok(ResourceBoundedMatrix::Memory(
                Radix2Dit::<Goldilocks>::default().dft_batch(matrix),
            ));
        }
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let mut input = ScratchMatrixStore::<GoldilocksWord>::create(
                &job_dir,
                "dft-a.bin",
                height as u64,
                width,
            )?;
            let log_height = height.trailing_zeros() as usize;
            for destination in 0..height {
                let source = reverse_low_bits(destination, log_height);
                let start = source.checked_mul(width).ok_or(DftError::SizeOverflow)?;
                let end = start.checked_add(width).ok_or(DftError::SizeOverflow)?;
                let row: Vec<_> = matrix.values[start..end]
                    .iter()
                    .copied()
                    .map(GoldilocksWord::from)
                    .collect();
                input.write_rows(destination as u64, 1, &row)?;
            }
            input.finalize()?;
            drop(matrix);
            self.finish_transform(input, height, width, &job_dir)
                .map(ResourceBoundedMatrix::Scratch)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    pub fn try_dft_block_matrix<M: BlockMatrix<GoldilocksWord>>(
        &self,
        matrix: &M,
    ) -> Result<ResourceBoundedMatrix> {
        let height = usize::try_from(matrix.rows()).map_err(|_| DftError::SizeOverflow)?;
        let width = matrix.columns();
        self.validate_shape(height, width)?;
        let selected = self
            .policy
            .select_mode(&self.estimate_memory(height, width)?)?;
        let estimate = match selected {
            ExecutionMode::Memory => self.estimate_memory(height, width)?,
            ExecutionMode::Scratch => self.estimate_scratch(height, width, false)?,
        };
        self.policy.preflight_for_mode(selected, estimate)?;
        if selected == ExecutionMode::Memory {
            let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)?;
            let mut words = vec![GoldilocksWord::default(); elements];
            matrix.read_rows(0, height, &mut words)?;
            let values = words.into_iter().map(Into::into).collect();
            return Ok(ResourceBoundedMatrix::Memory(
                Radix2Dit::<Goldilocks>::default().dft_batch(RowMajorMatrix::new(values, width)),
            ));
        }
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let mut input = ScratchMatrixStore::<GoldilocksWord>::create(
                &job_dir,
                "dft-a.bin",
                height as u64,
                width,
            )?;
            let log_height = height.trailing_zeros() as usize;
            let mut row = vec![GoldilocksWord::default(); width];
            for destination in 0..height {
                let source = reverse_low_bits(destination, log_height);
                matrix.read_rows(source as u64, 1, &mut row)?;
                input.write_rows(destination as u64, 1, &row)?;
            }
            input.finalize()?;
            self.finish_transform(input, height, width, &job_dir)
                .map(ResourceBoundedMatrix::Scratch)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    fn validate_shape(&self, height: usize, width: usize) -> Result<()> {
        if height == 0 || !height.is_power_of_two() {
            return Err(DftError::InvalidMatrix(
                "height must be a non-zero power of two",
            ));
        }
        if width == 0 {
            return Err(DftError::InvalidMatrix("width must be positive"));
        }
        Ok(())
    }

    fn finish_transform(
        &self,
        mut current: ScratchMatrixStore<GoldilocksWord>,
        height: usize,
        width: usize,
        job_dir: &Path,
    ) -> Result<ScratchPlonky3Matrix> {
        let log_height = height.trailing_zeros() as usize;
        let root = Goldilocks::two_adic_generator(log_height);
        let tile_rows = self.policy.tile_rows(8, width)?.min(height);
        let tile_elements = tile_rows.checked_mul(width).ok_or(DftError::SizeOverflow)?;
        let mut high = vec![GoldilocksWord::default(); tile_elements];
        let mut low = vec![GoldilocksWord::default(); tile_elements];
        for layer in 0..log_height {
            let next_name = if layer % 2 == 0 {
                "dft-b.bin"
            } else {
                "dft-a-next.bin"
            };
            let mut next = ScratchMatrixStore::<GoldilocksWord>::create(
                job_dir,
                next_name,
                height as u64,
                width,
            )?;
            let half = 1usize << layer;
            let block = half * 2;
            let twiddle_stride = height / block;
            for block_start in (0..height).step_by(block) {
                for offset in (0..half).step_by(tile_rows) {
                    let rows = (half - offset).min(tile_rows);
                    let elements = rows.checked_mul(width).ok_or(DftError::SizeOverflow)?;
                    let high_row = block_start + offset;
                    let low_row = high_row + half;
                    current.read_rows(high_row as u64, rows, &mut high[..elements])?;
                    current.read_rows(low_row as u64, rows, &mut low[..elements])?;
                    for local_row in 0..rows {
                        let twiddle = root.exp_u64(((offset + local_row) * twiddle_stride) as u64);
                        let row_start = local_row * width;
                        for column in 0..width {
                            let index = row_start + column;
                            let value = high[index].0;
                            let product = low[index].0 * twiddle;
                            high[index] = GoldilocksWord(value + product);
                            low[index] = GoldilocksWord(value - product);
                        }
                    }
                    next.write_rows(high_row as u64, rows, &high[..elements])?;
                    next.write_rows(low_row as u64, rows, &low[..elements])?;
                }
            }
            next.finalize()?;
            current.remove()?;
            current = next;
        }
        Ok(ScratchPlonky3Matrix::new(
            current,
            width,
            height,
            job_dir.to_path_buf(),
        ))
    }
}

impl TwoAdicSubgroupDft<Goldilocks> for ResourceBoundedDft {
    type Evaluations = ResourceBoundedMatrix;

    fn dft_batch(&self, matrix: RowMajorMatrix<Goldilocks>) -> Self::Evaluations {
        self.try_dft_batch(matrix)
            .expect("Plonky3 DFT exceeded or violated the configured resource policy")
    }
}

fn reverse_low_bits(value: usize, bits: usize) -> usize {
    if bits == 0 {
        0
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }
}

fn create_job_dir(root: &Path) -> Result<PathBuf> {
    fs::create_dir_all(root)?;
    let metadata = fs::symlink_metadata(root)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(StreamError::UnsafePath.into());
    }
    let id = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = root.join(format!("dft-{}-{id}", std::process::id()));
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        use std::os::unix::fs::PermissionsExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(&path)?;
        debug_assert_eq!(fs::metadata(&path)?.permissions().mode() & 0o777, 0o700);
    }
    #[cfg(not(unix))]
    fs::create_dir(&path)?;
    Ok(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_stream::{CheckpointPolicy, MatrixStore};
    use p3_dft::Radix2Dit;

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

    fn memory_policy(root: &Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Memory,
            ..policy(root)
        }
    }

    #[test]
    fn scratch_dft_matches_unmodified_plonky3_reference() {
        let dir = tempfile::tempdir().unwrap();
        for height in [1usize, 2, 4, 8, 16] {
            for width in [1usize, 3, 8] {
                let values: Vec<_> = (0..height * width)
                    .map(|value| Goldilocks::new(value as u64))
                    .collect();
                let input = RowMajorMatrix::new(values, width);
                let expected = Radix2Dit::<Goldilocks>::default().dft_batch(input.clone());
                let actual = ResourceBoundedDft::new(policy(dir.path()))
                    .unwrap()
                    .try_dft_batch(input)
                    .unwrap();
                for row in 0..height {
                    assert_eq!(
                        actual.try_row(row).unwrap(),
                        expected.row_slice(row).unwrap().as_ref()
                    );
                }
            }
        }
    }

    #[test]
    fn block_matrix_entrypoint_avoids_owned_input_floor() {
        let dir = tempfile::tempdir().unwrap();
        let mut input =
            ScratchMatrixStore::<GoldilocksWord>::create(dir.path(), "input.bin", 8, 2).unwrap();
        let values: Vec<_> = (0..16)
            .map(|value| GoldilocksWord(Goldilocks::new(value)))
            .collect();
        input.write_rows(0, 8, &values).unwrap();
        input.finalize().unwrap();
        let output = ResourceBoundedDft::new(policy(dir.path()))
            .unwrap()
            .try_dft_block_matrix(&input)
            .unwrap();
        assert_eq!(output.height(), 8);
        assert_eq!(output.width(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn scratch_artifact_and_job_directory_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let input = RowMajorMatrix::new((0..16).map(Goldilocks::new).collect(), 2);
        let output = ResourceBoundedDft::new(policy(dir.path()))
            .unwrap()
            .try_dft_batch(input)
            .unwrap();
        let ResourceBoundedMatrix::Scratch(matrix) = output else {
            panic!("scratch policy returned an in-memory matrix");
        };
        let artifact_mode = fs::metadata(matrix.artifact_path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let job_mode = fs::metadata(matrix.artifact_path().parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(artifact_mode, 0o600);
        assert_eq!(job_mode, 0o700);
    }

    #[test]
    fn memory_and_scratch_modes_are_distinct_and_equivalent() {
        let dir = tempfile::tempdir().unwrap();
        let values: Vec<_> = (0..128).map(Goldilocks::new).collect();
        let input = RowMajorMatrix::new(values, 8);
        let memory = ResourceBoundedDft::new(memory_policy(dir.path()))
            .unwrap()
            .try_dft_batch(input.clone())
            .unwrap();
        let scratch = ResourceBoundedDft::new(policy(dir.path()))
            .unwrap()
            .try_dft_batch(input)
            .unwrap();
        assert_eq!(memory.execution_mode(), ExecutionMode::Memory);
        assert_eq!(scratch.execution_mode(), ExecutionMode::Scratch);
        assert_eq!(
            memory.try_rows(0, 16).unwrap(),
            scratch.try_rows(0, 16).unwrap()
        );
    }

    #[test]
    fn differential_release_dimensions_match_reference() {
        let dir = tempfile::tempdir().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        let mut state = 0x4d595df4d0f33173u64;
        for log_height in 10..=18 {
            let height = 1usize << log_height;
            let width = if log_height % 2 == 0 { 1 } else { 3 };
            let values: Vec<_> = (0..height * width)
                .map(|index| {
                    state = state
                        .wrapping_mul(6364136223846793005)
                        .wrapping_add(1442695040888963407);
                    match index {
                        0 => Goldilocks::ZERO,
                        1 => Goldilocks::new(GOLDILOCKS_MODULUS - 1),
                        _ => Goldilocks::new(state % GOLDILOCKS_MODULUS),
                    }
                })
                .collect();
            let input = RowMajorMatrix::new(values, width);
            let expected = Radix2Dit::<Goldilocks>::default().dft_batch(input.clone());
            let actual = dft.try_dft_batch(input).unwrap();
            for row_start in (0..height).step_by(1024) {
                let row_count = (height - row_start).min(1024);
                let start = row_start * width;
                let end = (row_start + row_count) * width;
                assert_eq!(
                    actual.try_rows(row_start, row_count).unwrap(),
                    expected.values[start..end]
                );
            }
        }
    }
}
