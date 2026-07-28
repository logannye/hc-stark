use crate::profile::DurableFieldProfile;
use crate::scratch::create_unique_job_dir;
use hc_stream::{
    ArtifactDigest, BlockMatrix, CanonicalElement, ExecutionMode, MatrixStore, PhaseEstimate,
    ResourceEstimate, ResourceMode, ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_baby_bear::BabyBear;
use p3_dft::{Radix2Dit, TwoAdicSubgroupDft};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField32, PrimeField64, TwoAdicField};
use p3_goldilocks::Goldilocks;
use p3_matrix::bitrev::{BitReversalPerm, BitReversedMatrixView, BitReversibleMatrix};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use rayon::prelude::*;
use std::fs;
use std::marker::PhantomData;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// The durable scratch element width, in BYTES PER ELEMENT, for a profile.
///
/// Deliberately spelled out rather than written `8` inline: this is
/// `hc_stream::CanonicalElement::WIDTH` (8 for Goldilocks, 4 for BabyBear) and
/// is a completely different quantity from the Poseidon2 permutation width
/// `PERM_WIDTH` (8 for Goldilocks, 16 for BabyBear), which only ever appears
/// here as the first const generic parameter. Conflating them would corrupt
/// the on-SSD layout.
const fn word_bytes<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>() -> usize
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    <P::Word as CanonicalElement>::WIDTH
}

const GOLDILOCKS_MODULUS: u64 = 0xffff_ffff_0000_0001;
/// BabyBear's prime, 2^31 - 2^27 + 1. Matches `BabyBearParameters::PRIME`
/// (`p3-baby-bear-0.6.1/src/baby_bear.rs:18`).
const BABYBEAR_MODULUS: u32 = 0x7800_0001;
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

/// BabyBear's durable scratch word. Sits alongside `GoldilocksWord` rather
/// than replacing it — Task 4 makes the DFT generic over the profile; until
/// then nothing outside `profile.rs` and this module's tests refers to it.
#[derive(Clone, Copy, Default, Debug, Eq, PartialEq)]
pub struct BabyBearWord(pub BabyBear);

impl From<BabyBear> for BabyBearWord {
    fn from(value: BabyBear) -> Self {
        Self(value)
    }
}

impl From<BabyBearWord> for BabyBear {
    fn from(value: BabyBearWord) -> Self {
        value.0
    }
}

impl CanonicalElement for BabyBearWord {
    /// BabyBear is a 31-bit field, so 4 bytes per scratch element — NOT the
    /// permutation width (16). `estimate_params.rs`'s
    /// `canonical_extension_degree` already prices babybear at 4 bytes; if
    /// these two ever disagree, the estimator and the real on-SSD footprint
    /// disagree, and `/v1/estimate` is already answering BabyBear queries in
    /// production.
    const WIDTH: usize = 4;

    fn encode(self, output: &mut [u8]) {
        output.copy_from_slice(&self.0.as_canonical_u32().to_le_bytes());
    }

    fn decode(bytes: &[u8]) -> hc_stream::Result<Self> {
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| StreamError::Corrupt("invalid BabyBear width"))?;
        let value = u32::from_le_bytes(bytes);
        // Mirrors GoldilocksWord's canonicity check above, and is NOT
        // optional. `BabyBear::new` accepts any `u32` and silently reduces it
        // mod p ("Any `u32` value is accepted", p3-monty-31-0.6.1
        // src/monty_31.rs:47), so without this guard `x` and `x + p` would
        // decode to the same element: decode stops being injective and the
        // scratch layer loses its corruption detector. `encode` emits
        // `as_canonical_u32`, so any value >= p is by definition corrupt.
        if value >= BABYBEAR_MODULUS {
            return Err(StreamError::Corrupt("non-canonical BabyBear element"));
        }
        Ok(Self(BabyBear::new(value)))
    }
}

struct ManagedStore<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    store: Mutex<Option<ScratchMatrixStore<P::Word>>>,
    path: PathBuf,
    job_dir: PathBuf,
    remove_on_drop: AtomicBool,
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Drop for ManagedStore<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn drop(&mut self) {
        if !self.remove_on_drop.load(Ordering::Relaxed) {
            return;
        }
        if let Ok(store) = self.store.get_mut() {
            if let Some(store) = store.take() {
                let _ = store.remove();
            }
        }
        let _ = fs::remove_dir(&self.job_dir);
    }
}

/// A Plonky3 matrix backed by a checksummed, owner-only scratch artifact.
pub struct ScratchPlonky3Matrix<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    inner: Arc<ManagedStore<W, D, P>>,
    width: usize,
    height: usize,
}

// Hand-written so the bound stays `P: DurableFieldProfile` instead of the
// `P: Clone` that `#[derive(Clone)]` would add; an `Arc` clone never touches
// `P` anyway.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ScratchPlonky3Matrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            width: self.width,
            height: self.height,
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> ScratchPlonky3Matrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn new(
        store: ScratchMatrixStore<P::Word>,
        width: usize,
        height: usize,
        job_dir: PathBuf,
        remove_on_drop: bool,
    ) -> Self {
        let path = store.path().to_path_buf();
        Self {
            inner: Arc::new(ManagedStore {
                store: Mutex::new(Some(store)),
                path,
                job_dir,
                remove_on_drop: AtomicBool::new(remove_on_drop),
            }),
            width,
            height,
        }
    }

    pub fn artifact_path(&self) -> &Path {
        &self.inner.path
    }

    pub fn artifact_digest(&self) -> Result<ArtifactDigest> {
        let guard = self
            .inner
            .store
            .lock()
            .map_err(|_| StreamError::Corrupt("scratch matrix lock poisoned"))?;
        guard
            .as_ref()
            .and_then(MatrixStore::digest)
            .ok_or_else(|| StreamError::Corrupt("scratch matrix is not finalized").into())
    }

    pub fn reopen(path: &Path, expected: ArtifactDigest) -> Result<Self> {
        let job_dir = path.parent().ok_or(StreamError::UnsafePath)?.to_path_buf();
        let store = ScratchMatrixStore::<P::Word>::reopen(path, expected)?;
        let height = usize::try_from(expected.rows).map_err(|_| DftError::SizeOverflow)?;
        Ok(Self::new(store, expected.columns, height, job_dir, false))
    }

    pub fn try_row(&self, row: usize) -> Result<Vec<P::Val>> {
        self.try_rows(row, 1)
    }

    pub fn try_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<P::Val>> {
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
        let mut words = vec![P::Word::default(); self.width * row_count];
        store.read_rows(row_start as u64, row_count, &mut words)?;
        Ok(words.into_iter().map(Into::into).collect())
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Matrix<P::Val>
    for ScratchPlonky3Matrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn width(&self) -> usize {
        self.width
    }

    fn height(&self) -> usize {
        self.height
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = P::Val, IntoIter = impl Iterator<Item = P::Val> + Send + Sync>
    {
        self.try_row(row)
            .expect("validated scratch row must remain readable")
            .into_iter()
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> BitReversibleMatrix<P::Val>
    for ScratchPlonky3Matrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type BitRev = BitReversedMatrixView<Self>;

    fn bit_reverse_rows(self) -> Self::BitRev {
        BitReversalPerm::new_view(self)
    }
}

/// Result matrix selected by `ResourcePolicyV1`.
pub enum ResourceBoundedMatrix<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    Memory(RowMajorMatrix<P::Val>),
    Scratch(ScratchPlonky3Matrix<W, D, P>),
}

// Hand-written for the same reason as `ScratchPlonky3Matrix`'s: `#[derive]`
// would demand `P: Clone` even though no `P` value is ever stored.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ResourceBoundedMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        match self {
            Self::Memory(matrix) => Self::Memory(matrix.clone()),
            Self::Scratch(matrix) => Self::Scratch(matrix.clone()),
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> ResourceBoundedMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn try_row(&self, row: usize) -> Result<Vec<P::Val>> {
        self.try_rows(row, 1)
    }

    pub fn try_rows(&self, row_start: usize, row_count: usize) -> Result<Vec<P::Val>> {
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

    pub fn scratch_artifact(&self) -> Result<(&Path, ArtifactDigest)> {
        match self {
            Self::Scratch(matrix) => Ok((matrix.artifact_path(), matrix.artifact_digest()?)),
            Self::Memory(_) => Err(DftError::InvalidMatrix(
                "in-memory matrix has no resumable artifact",
            )),
        }
    }

    pub fn reopen_scratch(path: &Path, expected: ArtifactDigest) -> Result<Self> {
        ScratchPlonky3Matrix::reopen(path, expected).map(Self::Scratch)
    }

    pub fn retain_for_resume(&self) {
        if let Self::Scratch(matrix) = self {
            matrix.inner.remove_on_drop.store(false, Ordering::Relaxed);
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Matrix<P::Val>
    for ResourceBoundedMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
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
    ) -> impl IntoIterator<Item = P::Val, IntoIter = impl Iterator<Item = P::Val> + Send + Sync>
    {
        self.try_row(row)
            .expect("validated resource-bounded row must remain readable")
            .into_iter()
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> BlockMatrix<P::Word>
    for ResourceBoundedMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn rows(&self) -> u64 {
        self.height() as u64
    }

    fn columns(&self) -> usize {
        self.width()
    }

    fn read_rows(
        &self,
        row_start: u64,
        row_count: usize,
        output: &mut [P::Word],
    ) -> hc_stream::Result<()> {
        let row_start = usize::try_from(row_start).map_err(|_| StreamError::OutOfBounds)?;
        let values = self
            .try_rows(row_start, row_count)
            .map_err(|error| match error {
                DftError::Stream(stream) => stream,
                _ => StreamError::Corrupt("resource-bounded matrix read failed"),
            })?;
        if output.len() != values.len() {
            return Err(StreamError::OutOfBounds);
        }
        for (slot, value) in output.iter_mut().zip(values) {
            *slot = value.into();
        }
        Ok(())
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> BitReversibleMatrix<P::Val>
    for ResourceBoundedMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
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
pub struct ResourceBoundedDft<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    policy: ResourcePolicyV1,
    profile: PhantomData<P>,
}

// Hand-written so neither impl demands `P: Clone`/`P: Debug`; the struct holds
// no `P` value, only a marker.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ResourceBoundedDft<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        Self {
            policy: self.policy.clone(),
            profile: PhantomData,
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> std::fmt::Debug
    for ResourceBoundedDft<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResourceBoundedDft")
            .field("policy", &self.policy)
            .field("field", &P::FIELD_NAME)
            .finish()
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Default
    for ResourceBoundedDft<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
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
            profile: PhantomData,
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> ResourceBoundedDft<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn new(policy: ResourcePolicyV1) -> Result<Self> {
        policy.validate()?;
        Ok(Self {
            policy,
            profile: PhantomData,
        })
    }

    pub fn resource_policy(&self) -> &ResourcePolicyV1 {
        &self.policy
    }

    pub fn estimate_memory(&self, height: usize, width: usize) -> Result<ResourceEstimate> {
        // `word_bytes` is 8 for Goldilocks, so this is bit-identical to the
        // literal `8` it replaces; it is a per-element field width, unlike the
        // fixed 8 MiB slack term below.
        let field_bytes = word_bytes::<W, D, P>() as u64;
        let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)? as u64;
        let artifact_bytes = elements
            .checked_mul(field_bytes)
            .ok_or(DftError::SizeOverflow)?;
        let twiddle_bytes = (height as u64)
            .saturating_div(2)
            .saturating_mul(field_bytes);
        let row_buffers = (width as u64).saturating_mul(field_bytes).saturating_mul(4);
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

    /// `field_bytes` is the per-element byte width to cost the transform at.
    /// Real execution through this type only ever moves `P::Word` values, so
    /// every caller that actually runs the DFT (as opposed to estimating a
    /// hypothetical configuration) must pass `P::Word::WIDTH as u64`.
    /// `estimate_params::estimate_from_params` is the one caller that passes a
    /// caller-declared width to price fields TinyZKP does not execute.
    pub fn estimate_scratch(
        &self,
        height: usize,
        width: usize,
        owned_input: bool,
        field_bytes: u64,
    ) -> Result<ResourceEstimate> {
        let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)? as u64;
        let artifact_bytes = elements
            .checked_mul(field_bytes)
            .ok_or(DftError::SizeOverflow)?;
        let owned_input_bytes = if owned_input { artifact_bytes } else { 0 };
        let (first_factor, second_factor) = four_step_factors(height);
        let first_sub_fft_buffers =
            self.sub_fft_buffer_bytes(first_factor, second_factor, width, field_bytes)?;
        let second_sub_fft_buffers =
            self.sub_fft_buffer_bytes(second_factor, first_factor, width, field_bytes)?;
        let sub_fft_buffers = first_sub_fft_buffers.max(second_sub_fft_buffers);
        let (outer_tile, inner_tile) = self.transpose_tile_shape(
            width,
            first_factor.max(second_factor),
            first_factor.min(second_factor),
            field_bytes,
        )?;
        let transpose_buffers = (outer_tile as u64)
            .saturating_mul(inner_tile as u64)
            .saturating_mul(width as u64)
            .saturating_mul(field_bytes)
            .saturating_mul(2);
        let working_buffers = sub_fft_buffers.max(transpose_buffers);
        // Initial transpose, first sub-FFT/twiddle, middle transpose, second
        // sub-FFT, and final transpose each read and write one full artifact.
        let passes = 5u64;
        Ok(ResourceEstimate {
            peak_resident_bytes: owned_input_bytes
                .saturating_add(working_buffers)
                .saturating_add(8 * 1024 * 1024),
            scratch_high_water_bytes: artifact_bytes.saturating_mul(2),
            total_read_bytes: artifact_bytes.saturating_mul(passes),
            total_write_bytes: artifact_bytes.saturating_mul(passes),
            phases: vec![PhaseEstimate {
                phase: "near_square_four_step_dft".into(),
                read_bytes: artifact_bytes.saturating_mul(passes),
                write_bytes: artifact_bytes.saturating_mul(passes),
            }],
        })
    }

    pub fn try_dft_batch(
        &self,
        matrix: RowMajorMatrix<P::Val>,
    ) -> Result<ResourceBoundedMatrix<W, D, P>> {
        let height = matrix.height();
        let width = matrix.width();
        self.validate_shape(height, width)?;
        let selected = self
            .policy
            .select_mode(&self.estimate_memory(height, width)?)?;
        let estimate = match selected {
            ExecutionMode::Memory => self.estimate_memory(height, width)?,
            ExecutionMode::Scratch => {
                self.estimate_scratch(height, width, true, word_bytes::<W, D, P>() as u64)?
            }
        };
        self.policy.preflight_for_mode(selected, estimate)?;
        if selected == ExecutionMode::Memory {
            return Ok(ResourceBoundedMatrix::Memory(
                Radix2Dit::<P::Val>::default().dft_batch(matrix),
            ));
        }
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let (first_factor, second_factor) = four_step_factors(height);
            let mut input = self.transpose_from_reader(
                &job_dir,
                "dft-a.bin",
                second_factor,
                first_factor,
                width,
                |row_start, row_count, output| {
                    let start = row_start.checked_mul(width).ok_or(DftError::SizeOverflow)?;
                    let end = start
                        .checked_add(row_count.checked_mul(width).ok_or(DftError::SizeOverflow)?)
                        .ok_or(DftError::SizeOverflow)?;
                    for (slot, value) in output.iter_mut().zip(&matrix.values[start..end]) {
                        *slot = (*value).into();
                    }
                    Ok(())
                },
            )?;
            input.finalize()?;
            drop(matrix);
            self.finish_four_step(input, height, width, &job_dir, false)
                .map(ResourceBoundedMatrix::Scratch)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    pub fn try_dft_block_matrix<M: BlockMatrix<P::Word>>(
        &self,
        matrix: &M,
    ) -> Result<ResourceBoundedMatrix<W, D, P>> {
        let height = usize::try_from(matrix.rows()).map_err(|_| DftError::SizeOverflow)?;
        let width = matrix.columns();
        self.validate_shape(height, width)?;
        let selected = self
            .policy
            .select_mode(&self.estimate_memory(height, width)?)?;
        let estimate = match selected {
            ExecutionMode::Memory => self.estimate_memory(height, width)?,
            ExecutionMode::Scratch => {
                self.estimate_scratch(height, width, false, word_bytes::<W, D, P>() as u64)?
            }
        };
        self.policy.preflight_for_mode(selected, estimate)?;
        if selected == ExecutionMode::Memory {
            let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)?;
            let mut words = vec![P::Word::default(); elements];
            matrix.read_rows(0, height, &mut words)?;
            let values = words.into_iter().map(Into::into).collect();
            return Ok(ResourceBoundedMatrix::Memory(
                Radix2Dit::<P::Val>::default().dft_batch(RowMajorMatrix::new(values, width)),
            ));
        }
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let (first_factor, second_factor) = four_step_factors(height);
            let mut input = self.transpose_from_reader(
                &job_dir,
                "dft-a.bin",
                second_factor,
                first_factor,
                width,
                |row_start, row_count, output| {
                    matrix
                        .read_rows(row_start as u64, row_count, output)
                        .map_err(DftError::from)
                },
            )?;
            input.finalize()?;
            self.finish_four_step(input, height, width, &job_dir, false)
                .map(ResourceBoundedMatrix::Scratch)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    /// Inverse transform over a caller-buffered matrix. This is the first half
    /// of an external-memory LDE and avoids reconstructing the trace in a Vec.
    pub fn try_idft_block_matrix<M: BlockMatrix<P::Word>>(
        &self,
        matrix: &M,
    ) -> Result<ResourceBoundedMatrix<W, D, P>> {
        let height = usize::try_from(matrix.rows()).map_err(|_| DftError::SizeOverflow)?;
        let width = matrix.columns();
        self.validate_shape(height, width)?;
        let selected = self
            .policy
            .select_mode(&self.estimate_memory(height, width)?)?;
        let estimate = match selected {
            ExecutionMode::Memory => self.estimate_memory(height, width)?,
            ExecutionMode::Scratch => {
                self.estimate_scratch(height, width, false, word_bytes::<W, D, P>() as u64)?
            }
        };
        self.policy.preflight_for_mode(selected, estimate)?;
        if selected == ExecutionMode::Memory {
            let elements = height.checked_mul(width).ok_or(DftError::SizeOverflow)?;
            let mut words = vec![P::Word::default(); elements];
            matrix.read_rows(0, height, &mut words)?;
            let values = words.into_iter().map(Into::into).collect();
            return Ok(ResourceBoundedMatrix::Memory(
                Radix2Dit::<P::Val>::default().idft_batch(RowMajorMatrix::new(values, width)),
            ));
        }
        let job_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let (first_factor, second_factor) = four_step_factors(height);
            let mut input = self.transpose_from_reader(
                &job_dir,
                "dft-a.bin",
                second_factor,
                first_factor,
                width,
                |row_start, row_count, output| {
                    matrix
                        .read_rows(row_start as u64, row_count, output)
                        .map_err(DftError::from)
                },
            )?;
            input.finalize()?;
            self.finish_four_step(input, height, width, &job_dir, true)
                .map(ResourceBoundedMatrix::Scratch)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    /// Compute a coset LDE from a block-readable evaluation matrix. The
    /// coefficient and padded-evaluation stores are released before returning;
    /// the result remains compatible with Plonky3's ordinary DFT output order.
    pub fn try_coset_lde_block_matrix<M: BlockMatrix<P::Word>>(
        &self,
        matrix: &M,
        log_blowup: usize,
        shift: P::Val,
    ) -> Result<ResourceBoundedMatrix<W, D, P>> {
        let height = usize::try_from(matrix.rows()).map_err(|_| DftError::SizeOverflow)?;
        let width = matrix.columns();
        self.validate_shape(height, width)?;
        let blowup = 1usize
            .checked_shl(log_blowup as u32)
            .ok_or(DftError::SizeOverflow)?;
        let lde_height = height.checked_mul(blowup).ok_or(DftError::SizeOverflow)?;
        self.validate_shape(lde_height, width)?;

        let coefficients = self.try_idft_block_matrix(matrix)?;
        let staging_dir = create_job_dir(&self.policy.scratch_dir)?;
        let result = (|| {
            let mut padded = ScratchMatrixStore::<P::Word>::create(
                &staging_dir,
                "coset-coefficients.bin",
                lde_height as u64,
                width,
            )?;
            let tile_rows = self
                .policy
                .tile_rows(word_bytes::<W, D, P>(), width)?
                .min(height);
            let mut power = P::Val::ONE;
            for row_start in (0..height).step_by(tile_rows) {
                let row_count = (height - row_start).min(tile_rows);
                let mut values: Vec<P::Val> = coefficients.try_rows(row_start, row_count)?;
                for row in 0..row_count {
                    let start = row * width;
                    for value in &mut values[start..start + width] {
                        *value *= power;
                    }
                    power *= shift;
                }
                let words: Vec<P::Word> = values.into_iter().map(Into::into).collect();
                padded.write_rows(row_start as u64, row_count, &words)?;
            }
            padded.finalize()?;
            drop(coefficients);
            let output = self.try_dft_block_matrix(&padded)?;
            padded.remove()?;
            Ok(output)
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&staging_dir);
        } else {
            let _ = fs::remove_dir(&staging_dir);
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

    fn finish_four_step(
        &self,
        current: ScratchMatrixStore<P::Word>,
        height: usize,
        width: usize,
        job_dir: &Path,
        inverse: bool,
    ) -> Result<ScratchPlonky3Matrix<W, D, P>> {
        let (first_factor, second_factor) = four_step_factors(height);
        let mut root = P::Val::two_adic_generator(height.trailing_zeros() as usize);
        if inverse {
            root = root.inverse();
        }

        // The ingested matrix is laid out as [j1][j2], with each length-n2
        // transform contiguous. This first stage computes the j2 transforms
        // and applies the cross-factor twiddle w_N^(j1*k2).
        let first = self.sub_fft_stage(
            current,
            job_dir,
            "dft-b.bin",
            first_factor,
            second_factor,
            width,
            Some(root),
            inverse,
        )?;

        // [j1][k2] -> [k2][j1], making every length-n1 transform contiguous.
        let second = self.transpose_store(
            first,
            job_dir,
            "dft-a.bin",
            first_factor,
            second_factor,
            width,
        )?;
        let third = self.sub_fft_stage(
            second,
            job_dir,
            "dft-b.bin",
            second_factor,
            first_factor,
            width,
            None,
            inverse,
        )?;

        // [k2][k1] -> [k1][k2]. The resulting physical row index is the
        // ordinary DFT output index k = k2 + n2*k1 expected by Plonky3.
        let current = self.transpose_store(
            third,
            job_dir,
            "dft-a.bin",
            second_factor,
            first_factor,
            width,
        )?;
        Ok(ScratchPlonky3Matrix::new(
            current,
            width,
            height,
            job_dir.to_path_buf(),
            true,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn sub_fft_stage(
        &self,
        source: ScratchMatrixStore<P::Word>,
        job_dir: &Path,
        output_name: &str,
        group_count: usize,
        group_len: usize,
        width: usize,
        twiddle_root: Option<P::Val>,
        inverse: bool,
    ) -> Result<ScratchMatrixStore<P::Word>> {
        let mut output =
            ScratchMatrixStore::<P::Word>::create(job_dir, output_name, source.rows(), width)?;
        let group_elements = group_len.checked_mul(width).ok_or(DftError::SizeOverflow)?;
        let workers = self.sub_fft_workers(group_count, group_len, width)?;
        let pool = (workers > 1)
            .then(|| {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(workers)
                    .build()
                    .map_err(|_| DftError::InvalidMatrix("failed to create bounded DFT workers"))
            })
            .transpose()?;
        let mut batches = vec![vec![P::Word::default(); group_elements]; workers];
        for batch_start in (0..group_count).step_by(workers) {
            let batch_count = (group_count - batch_start).min(workers);
            for (offset, words) in batches[..batch_count].iter_mut().enumerate() {
                let group = batch_start + offset;
                let row_start = group.checked_mul(group_len).ok_or(DftError::SizeOverflow)?;
                source.read_rows(row_start as u64, group_len, words)?;
            }
            let transform = |(offset, words): (usize, &mut Vec<P::Word>)| {
                transform_sub_fft_group::<W, D, P>(
                    words,
                    batch_start + offset,
                    group_len,
                    width,
                    twiddle_root,
                    inverse,
                );
            };
            if let Some(pool) = &pool {
                pool.install(|| {
                    batches[..batch_count]
                        .par_iter_mut()
                        .enumerate()
                        .for_each(transform)
                });
            } else {
                batches[..batch_count]
                    .iter_mut()
                    .enumerate()
                    .for_each(transform);
            }
            for (offset, words) in batches[..batch_count].iter().enumerate() {
                let row_start = (batch_start + offset)
                    .checked_mul(group_len)
                    .ok_or(DftError::SizeOverflow)?;
                output.write_rows(row_start as u64, group_len, words)?;
            }
        }
        output.finalize()?;
        source.remove()?;
        Ok(output)
    }

    fn sub_fft_workers(&self, group_count: usize, group_len: usize, width: usize) -> Result<usize> {
        let bytes_per_worker = group_len
            .checked_mul(width)
            .and_then(|elements| elements.checked_mul(word_bytes::<W, D, P>()))
            .and_then(|bytes| bytes.checked_mul(3))
            .ok_or(DftError::SizeOverflow)?;
        let memory_workers = usize::try_from(
            (self.policy.max_resident_bytes / 2)
                .checked_div(bytes_per_worker as u64)
                .unwrap_or(0),
        )
        .unwrap_or(usize::MAX);
        if memory_workers == 0 {
            return Err(StreamError::ResourceLimit {
                resource: "resident memory",
                required: bytes_per_worker as u64,
                cap: self.policy.max_resident_bytes / 2,
            }
            .into());
        }
        Ok(self
            .policy
            .max_threads
            .min(group_count)
            .min(memory_workers)
            .max(1))
    }

    fn sub_fft_buffer_bytes(
        &self,
        group_count: usize,
        group_len: usize,
        width: usize,
        field_bytes: u64,
    ) -> Result<u64> {
        let bytes_per_worker = (group_len as u64)
            .saturating_mul(width as u64)
            .saturating_mul(field_bytes)
            .saturating_mul(3);
        let memory_workers = (self.policy.max_resident_bytes / 2)
            .checked_div(bytes_per_worker)
            .unwrap_or(0);
        let workers = (self.policy.max_threads as u64)
            .min(group_count as u64)
            .min(memory_workers.max(1));
        Ok(bytes_per_worker.saturating_mul(workers))
    }

    fn transpose_store(
        &self,
        source: ScratchMatrixStore<P::Word>,
        job_dir: &Path,
        output_name: &str,
        outer: usize,
        inner: usize,
        width: usize,
    ) -> Result<ScratchMatrixStore<P::Word>> {
        let mut output = self.transpose_from_reader(
            job_dir,
            output_name,
            outer,
            inner,
            width,
            |row_start, row_count, values| {
                source
                    .read_rows(row_start as u64, row_count, values)
                    .map_err(DftError::from)
            },
        )?;
        output.finalize()?;
        source.remove()?;
        Ok(output)
    }

    fn transpose_from_reader<R>(
        &self,
        job_dir: &Path,
        output_name: &str,
        outer: usize,
        inner: usize,
        width: usize,
        mut read_rows: R,
    ) -> Result<ScratchMatrixStore<P::Word>>
    where
        R: FnMut(usize, usize, &mut [P::Word]) -> Result<()>,
    {
        let height = outer.checked_mul(inner).ok_or(DftError::SizeOverflow)?;
        let mut output =
            ScratchMatrixStore::<P::Word>::create(job_dir, output_name, height as u64, width)?;
        let (outer_tile, inner_tile) =
            self.transpose_tile_shape(width, outer, inner, word_bytes::<W, D, P>() as u64)?;
        let max_elements = outer_tile
            .checked_mul(inner_tile)
            .and_then(|value| value.checked_mul(width))
            .ok_or(DftError::SizeOverflow)?;
        let mut input = vec![P::Word::default(); max_elements];
        let mut transposed = vec![P::Word::default(); max_elements];

        for outer_start in (0..outer).step_by(outer_tile) {
            let outer_count = (outer - outer_start).min(outer_tile);
            for inner_start in (0..inner).step_by(inner_tile) {
                let inner_count = (inner - inner_start).min(inner_tile);
                let tile_elements = outer_count
                    .checked_mul(inner_count)
                    .and_then(|value| value.checked_mul(width))
                    .ok_or(DftError::SizeOverflow)?;
                for outer_offset in 0..outer_count {
                    let source_start = (outer_start + outer_offset)
                        .checked_mul(inner)
                        .and_then(|value| value.checked_add(inner_start))
                        .ok_or(DftError::SizeOverflow)?;
                    let destination = outer_offset * inner_count * width;
                    read_rows(
                        source_start,
                        inner_count,
                        &mut input[destination..destination + inner_count * width],
                    )?;
                }
                for outer_offset in 0..outer_count {
                    for inner_offset in 0..inner_count {
                        let source = (outer_offset * inner_count + inner_offset) * width;
                        let destination = (inner_offset * outer_count + outer_offset) * width;
                        transposed[destination..destination + width]
                            .copy_from_slice(&input[source..source + width]);
                    }
                }
                debug_assert!(tile_elements <= max_elements);
                for inner_offset in 0..inner_count {
                    let destination_start = (inner_start + inner_offset)
                        .checked_mul(outer)
                        .and_then(|value| value.checked_add(outer_start))
                        .ok_or(DftError::SizeOverflow)?;
                    let source = inner_offset * outer_count * width;
                    output.write_rows(
                        destination_start as u64,
                        outer_count,
                        &transposed[source..source + outer_count * width],
                    )?;
                }
            }
        }
        Ok(output)
    }

    fn transpose_tile_shape(
        &self,
        width: usize,
        outer: usize,
        inner: usize,
        field_bytes: u64,
    ) -> Result<(usize, usize)> {
        let bytes_per_factor_element = (width as u64)
            .checked_mul(field_bytes)
            .and_then(|value| value.checked_mul(2))
            .ok_or(DftError::SizeOverflow)?;
        let element_budget = (self.policy.max_resident_bytes / 2)
            .checked_div(bytes_per_factor_element)
            .unwrap_or(0);
        if element_budget == 0 {
            return Err(StreamError::ResourceLimit {
                resource: "resident memory",
                required: bytes_per_factor_element,
                cap: self.policy.max_resident_bytes / 2,
            }
            .into());
        }
        let side = highest_power_of_two_at_most(integer_sqrt(element_budget) as usize);
        let outer_tile = side.min(outer).max(1);
        let remaining = usize::try_from(element_budget)
            .unwrap_or(usize::MAX)
            .checked_div(outer_tile)
            .unwrap_or(1);
        let inner_tile = highest_power_of_two_at_most(remaining).min(inner).max(1);
        Ok((outer_tile, inner_tile))
    }
}

fn transform_sub_fft_group<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    words: &mut [P::Word],
    group: usize,
    group_len: usize,
    width: usize,
    twiddle_root: Option<P::Val>,
    inverse: bool,
) where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let values: Vec<P::Val> = words.iter().map(|word| (*word).into()).collect();
    let transformed = if inverse {
        Radix2Dit::<P::Val>::default().idft_batch(RowMajorMatrix::new(values, width))
    } else {
        Radix2Dit::<P::Val>::default().dft_batch(RowMajorMatrix::new(values, width))
    };
    let twiddle_step = twiddle_root
        .map(|root| root.exp_u64(group as u64))
        .unwrap_or(P::Val::ONE);
    let mut twiddle = P::Val::ONE;
    for row in 0..group_len {
        let start = row * width;
        for column in 0..width {
            words[start + column] = (transformed.values[start + column] * twiddle).into();
        }
        twiddle *= twiddle_step;
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> TwoAdicSubgroupDft<P::Val>
    for ResourceBoundedDft<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    type Evaluations = ResourceBoundedMatrix<W, D, P>;

    fn dft_batch(&self, matrix: RowMajorMatrix<P::Val>) -> Self::Evaluations {
        self.try_dft_batch(matrix)
            .expect("Plonky3 DFT exceeded or violated the configured resource policy")
    }
}

/// The Goldilocks pins for the callers that are still field-concrete
/// (`prover`, `bounded_prover`, `opening`, `estimate_params`). Each name here
/// is exactly the type those modules used before this module became generic,
/// so importing from here leaves their bodies untouched.
pub mod goldilocks {
    use crate::profile::GoldilocksProfile;

    pub type ScratchPlonky3Matrix = super::ScratchPlonky3Matrix<8, 4, GoldilocksProfile>;
    pub type ResourceBoundedMatrix = super::ResourceBoundedMatrix<8, 4, GoldilocksProfile>;
    pub type ResourceBoundedDft = super::ResourceBoundedDft<8, 4, GoldilocksProfile>;
}

fn four_step_factors(height: usize) -> (usize, usize) {
    let log_height = height.trailing_zeros() as usize;
    let first = 1usize << (log_height / 2);
    (first, height / first)
}

fn integer_sqrt(value: u64) -> u64 {
    if value < 2 {
        return value;
    }
    let mut low = 1u64;
    let mut high = value.min(u32::MAX as u64 + 1);
    while low + 1 < high {
        let middle = low + (high - low) / 2;
        if middle <= value / middle {
            low = middle;
        } else {
            high = middle;
        }
    }
    low
}

fn highest_power_of_two_at_most(value: usize) -> usize {
    1usize << (usize::BITS - 1 - value.max(1).leading_zeros())
}

fn create_job_dir(root: &Path) -> Result<PathBuf> {
    create_unique_job_dir(root, "dft", &JOB_COUNTER).map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use super::goldilocks::{ResourceBoundedDft, ResourceBoundedMatrix};
    use super::*;
    use crate::profile::BabyBearProfile;
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
    fn policy_bounded_parallel_sub_ffts_are_deterministic() {
        let single_dir = tempfile::tempdir().unwrap();
        let parallel_dir = tempfile::tempdir().unwrap();
        let height = 1024;
        let width = 8;
        let values: Vec<_> = (0..height * width)
            .map(|value| Goldilocks::new((value as u64).wrapping_mul(17).wrapping_add(3)))
            .collect();
        let input = RowMajorMatrix::new(values, width);
        let single = ResourceBoundedDft::new(policy(single_dir.path()))
            .unwrap()
            .try_dft_batch(input.clone())
            .unwrap();
        let mut parallel_policy = policy(parallel_dir.path());
        parallel_policy.max_threads = 4;
        let parallel_dft = ResourceBoundedDft::new(parallel_policy).unwrap();
        let estimate = parallel_dft
            .estimate_scratch(height, width, true, GoldilocksWord::WIDTH as u64)
            .unwrap();
        assert!(estimate.peak_resident_bytes <= 32 * 1024 * 1024);
        let parallel = parallel_dft.try_dft_batch(input).unwrap();
        assert_eq!(
            single.try_rows(0, height).unwrap(),
            parallel.try_rows(0, height).unwrap()
        );
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

    #[test]
    fn inverse_and_coset_lde_block_paths_match_reference() {
        let dir = tempfile::tempdir().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        for height in [2usize, 8, 32] {
            let width = 3;
            let values: Vec<_> = (0..height * width)
                .map(|value| Goldilocks::new((value * 17 + 9) as u64))
                .collect();
            let input = RowMajorMatrix::new(values.clone(), width);
            let mut store = ScratchMatrixStore::<GoldilocksWord>::create(
                dir.path(),
                &format!("lde-input-{height}.bin"),
                height as u64,
                width,
            )
            .unwrap();
            let words: Vec<_> = values.into_iter().map(GoldilocksWord).collect();
            store.write_rows(0, height, &words).unwrap();
            store.finalize().unwrap();

            let expected_inverse = Radix2Dit::<Goldilocks>::default().idft_batch(input.clone());
            let actual_inverse = dft.try_idft_block_matrix(&store).unwrap();
            assert_eq!(
                actual_inverse.try_rows(0, height).unwrap(),
                expected_inverse.values
            );

            let shift = Goldilocks::GENERATOR;
            let expected_lde = Radix2Dit::<Goldilocks>::default().coset_lde_batch(input, 1, shift);
            let actual_lde = dft.try_coset_lde_block_matrix(&store, 1, shift).unwrap();
            assert_eq!(
                actual_lde.try_rows(0, height * 2).unwrap(),
                expected_lde.values
            );
        }
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
    fn concurrent_outputs_use_isolated_scratch_directories() {
        let dir = tempfile::tempdir().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        let first = dft
            .try_dft_batch(RowMajorMatrix::new(
                (0..32).map(Goldilocks::new).collect(),
                2,
            ))
            .unwrap();
        let second = dft
            .try_dft_batch(RowMajorMatrix::new(
                (32..64).map(Goldilocks::new).collect(),
                2,
            ))
            .unwrap();
        let (first_path, _) = first.scratch_artifact().unwrap();
        let (second_path, _) = second.scratch_artifact().unwrap();
        assert_ne!(first_path.parent(), second_path.parent());
        assert!(first_path.is_file() && second_path.is_file());
    }

    #[test]
    fn insufficient_resident_budget_fails_in_preflight() {
        let dir = tempfile::tempdir().unwrap();
        let mut constrained = policy(dir.path());
        constrained.max_resident_bytes = 16 * 1024 * 1024;
        constrained.max_scratch_bytes = u64::MAX;
        let dft = ResourceBoundedDft::new(constrained.clone()).unwrap();
        let estimate = dft
            .estimate_scratch(1 << 30, 180, false, GoldilocksWord::WIDTH as u64)
            .unwrap();
        assert!(matches!(
            constrained.preflight_for_mode(ExecutionMode::Scratch, estimate),
            Err(StreamError::ResourceLimit {
                resource: "resident memory",
                ..
            })
        ));
    }

    /// The generalization has to be real, not merely syntactic: instantiate the
    /// whole durable DFT at BabyBear's `<16, 8>` dimensions and run a transform
    /// against the unmodified Plonky3 reference over the same field. Nothing
    /// here touches the Goldilocks entry points, so it cannot perturb the
    /// frozen transcript.
    #[test]
    fn scratch_dft_generalizes_to_babybear_dimensions() {
        use p3_baby_bear::BabyBear;

        let dir = tempfile::tempdir().unwrap();
        let dft =
            super::ResourceBoundedDft::<16, 8, BabyBearProfile>::new(policy(dir.path())).unwrap();
        // 4 bytes per scratch element (`CanonicalElement::WIDTH`), NOT 16 (the
        // permutation width) and NOT 8 (the digest size).
        assert_eq!(word_bytes::<16, 8, BabyBearProfile>(), 4);
        for height in [2usize, 8, 64] {
            let width = 3usize;
            let values: Vec<_> = (0..height * width)
                .map(|value| BabyBear::new((value as u32) * 13 + 5))
                .collect();
            let input = RowMajorMatrix::new(values, width);
            let expected = Radix2Dit::<BabyBear>::default().dft_batch(input.clone());
            let actual = dft.try_dft_batch(input).unwrap();
            assert_eq!(actual.try_rows(0, height).unwrap(), expected.values);
        }
    }

    #[test]
    fn differential_release_dimensions_match_reference() {
        let dir = tempfile::tempdir().unwrap();
        let dft = ResourceBoundedDft::new(policy(dir.path())).unwrap();
        let mut state = 0x4d595df4d0f33173u64;
        let max_log_height = if cfg!(debug_assertions) { 18 } else { 20 };
        for log_height in 10..=max_log_height {
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
