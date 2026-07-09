use hc_stream::{
    BlockMatrix, CanonicalElement, MatrixStore, PhaseEstimate, ResourceEstimate, ResourceMode,
    ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_dft::TwoAdicSubgroupDft;
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
        if row >= self.height {
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
        let mut words = vec![GoldilocksWord::default(); self.width];
        store.read_rows(row as u64, 1, &mut words)?;
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

    pub fn estimate(
        &self,
        height: usize,
        width: usize,
        owned_input: bool,
    ) -> Result<ResourceEstimate> {
        let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)? as u64;
        let artifact_bytes = elements.checked_mul(8).ok_or(DftError::SizeOverflow)?;
        let input_bytes = if owned_input { artifact_bytes } else { 0 };
        let row_buffers = (width as u64).saturating_mul(8).saturating_mul(4);
        let layers = height.max(1).trailing_zeros() as u64;
        Ok(ResourceEstimate {
            peak_resident_bytes: input_bytes
                .saturating_add(row_buffers)
                .saturating_add(8 * 1024 * 1024),
            scratch_high_water_bytes: artifact_bytes.saturating_mul(2),
            total_read_bytes: artifact_bytes.saturating_mul(layers.saturating_add(1)),
            total_write_bytes: artifact_bytes.saturating_mul(layers.saturating_add(1)),
            phases: vec![PhaseEstimate {
                phase: "blockwise_radix2_dft".into(),
                read_bytes: artifact_bytes.saturating_mul(layers),
                write_bytes: artifact_bytes.saturating_mul(layers),
            }],
        })
    }

    pub fn try_dft_batch(
        &self,
        matrix: RowMajorMatrix<Goldilocks>,
    ) -> Result<ScratchPlonky3Matrix> {
        let height = matrix.height();
        let width = matrix.width();
        self.validate_shape(height, width)?;
        self.policy.preflight(self.estimate(height, width, true)?)?;
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
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    pub fn try_dft_block_matrix<M: BlockMatrix<GoldilocksWord>>(
        &self,
        matrix: &M,
    ) -> Result<ScratchPlonky3Matrix> {
        let height = usize::try_from(matrix.rows()).map_err(|_| DftError::SizeOverflow)?;
        let width = matrix.columns();
        self.validate_shape(height, width)?;
        self.policy
            .preflight(self.estimate(height, width, false)?)?;
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
            let mut high = vec![GoldilocksWord::default(); width];
            let mut low = vec![GoldilocksWord::default(); width];
            let mut high_out = vec![GoldilocksWord::default(); width];
            let mut low_out = vec![GoldilocksWord::default(); width];
            for block_start in (0..height).step_by(block) {
                for offset in 0..half {
                    let high_row = block_start + offset;
                    let low_row = high_row + half;
                    current.read_rows(high_row as u64, 1, &mut high)?;
                    current.read_rows(low_row as u64, 1, &mut low)?;
                    let twiddle = root.exp_u64((offset * twiddle_stride) as u64);
                    for column in 0..width {
                        let product = low[column].0 * twiddle;
                        high_out[column] = GoldilocksWord(high[column].0 + product);
                        low_out[column] = GoldilocksWord(high[column].0 - product);
                    }
                    next.write_rows(high_row as u64, 1, &high_out)?;
                    next.write_rows(low_row as u64, 1, &low_out)?;
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
    type Evaluations = ScratchPlonky3Matrix;

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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    }
    let id = JOB_COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = root.join(format!("dft-{}-{id}", std::process::id()));
    fs::create_dir(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
    }
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
}
