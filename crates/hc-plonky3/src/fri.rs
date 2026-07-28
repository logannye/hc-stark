use crate::mmcs::{DurableMerkleData, DurableProfileMmcs};
use crate::profile::{DurableFieldProfile, GoldilocksProfile};
use crate::scratch::create_unique_job_dir;
use hc_stream::{
    ArtifactDigest, BlockMatrix, CanonicalElement, ExecutionMode, MatrixStore, PhaseEstimate,
    ResourceEstimate, ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_challenger::{
    CanObserve, CanSampleBits, DuplexChallenger, FieldChallenger, GrindingChallenger,
};
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DFTSmallBatch, TwoAdicSubgroupDft};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{
    compute_log_arity_for_round, CommitPhaseProofStep, FriParameters, FriProof, QueryProof,
};
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleCap;
use rayon::prelude::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// The Goldilocks FRI challenge field. Kept under its pre-generic name and
/// spelled through the profile so it cannot drift from `GoldilocksProfile`.
pub type ProfileChallenge = <GoldilocksProfile as DurableFieldProfile<8, 4>>::Challenge;
/// The duplex challenger at a profile's dimensions. `RATE` is the digest size
/// `D` (4 for Goldilocks, 8 for BabyBear), matching `checkpoint::RATE` and
/// Plonky3's own reference configs; `WIDTH` is the permutation width `W`.
pub(crate) type ProfileChallengerFor<const W: usize, const D: usize, P> = DuplexChallenger<
    <P as DurableFieldProfile<W, D>>::Val,
    <P as DurableFieldProfile<W, D>>::Permutation,
    W,
    D,
>;
pub type DurableFriMmcs<const W: usize, const D: usize, P> = ExtensionMmcs<
    <P as DurableFieldProfile<W, D>>::Val,
    <P as DurableFieldProfile<W, D>>::Challenge,
    DurableProfileMmcs<W, D, P>,
>;
pub type DurableFriCommitment<const W: usize, const D: usize, P> =
    MerkleCap<<P as DurableFieldProfile<W, D>>::Val, [<P as DurableFieldProfile<W, D>>::Val; D]>;
/// The FRI proof this module produces. Factored into an alias because the
/// four-parameter `FriProof<..>` written inline trips
/// `clippy::type_complexity` now that each parameter is a projection.
/// `P::Val` is the grinding witness type, matching `DuplexChallenger`'s
/// `GrindingChallenger::Witness = F`.
pub type DurableFriProof<const W: usize, const D: usize, P, InputProof> = FriProof<
    <P as DurableFieldProfile<W, D>>::Challenge,
    DurableFriMmcs<W, D, P>,
    <P as DurableFieldProfile<W, D>>::Val,
    InputProof,
>;
static LAYER_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Number of base-field coordinates per extension element — the number of
/// durable scratch columns each FRI value occupies. 2 for Goldilocks, 4 for
/// BabyBear. Every `2` that used to be written inline in this module was this
/// quantity.
fn extension_degree<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>() -> usize
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    <P::Challenge as BasedVectorSpace<P::Val>>::DIMENSION
}

/// Bytes on disk per stored extension element: 16 for Goldilocks (2 x 8),
/// 16 for BabyBear (4 x 4).
fn challenge_bytes<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>() -> usize
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    extension_degree::<W, D, P>() * <P::Word as CanonicalElement>::WIDTH
}

#[derive(Debug, thiserror::Error)]
pub enum DurableFriError {
    #[error("FRI layer shape is invalid")]
    InvalidShape,
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("FRI checkpoint observer failed: {0}")]
    Observer(String),
    #[error(transparent)]
    Mmcs(#[from] crate::DurableMmcsError),
}

pub type Result<T> = std::result::Result<T, DurableFriError>;

fn worker_pool(policy: &ResourcePolicyV1) -> Result<Option<rayon::ThreadPool>> {
    if policy.max_threads == 1 {
        return Ok(None);
    }
    rayon::ThreadPoolBuilder::new()
        .num_threads(policy.max_threads)
        .build()
        .map(Some)
        .map_err(|_| DurableFriError::InvalidShape)
}

struct ChallengeArtifact<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    store: ScratchMatrixStore<P::Word>,
    job_dir: PathBuf,
    remove_on_drop: AtomicBool,
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Drop
    for ChallengeArtifact<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn drop(&mut self) {
        if !self.remove_on_drop.load(Ordering::Relaxed) {
            return;
        }
        let _ = fs::remove_file(self.store.path());
        let _ = fs::remove_dir(&self.job_dir);
    }
}

/// Durable bit-reversed FRI evaluation vector. Each extension element occupies
/// `extension_degree::<W, D, P>()` canonical base-field words in its scratch
/// row (2 for Goldilocks, 4 for BabyBear).
pub struct ScratchChallengeVector<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    inner: Arc<ChallengeArtifact<W, D, P>>,
    len: usize,
}

// Hand-written so the bound stays `P: DurableFieldProfile`; cloning is an
// `Arc` bump that never touches `P`.
impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ScratchChallengeVector<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            len: self.len,
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> ScratchChallengeVector<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub fn from_values(policy: &ResourcePolicyV1, values: &[P::Challenge]) -> Result<Self> {
        if values.is_empty() || !values.len().is_power_of_two() {
            return Err(DurableFriError::InvalidShape);
        }
        preflight_layer::<W, D, P>(policy, values.len())?;
        let job_dir = create_job_dir(&policy.scratch_dir)?;
        let result = (|| {
            let mut store = ScratchMatrixStore::<P::Word>::create(
                &job_dir,
                "fri-layer.bin",
                values.len() as u64,
                extension_degree::<W, D, P>(),
            )?;
            let words = flatten_challenges::<W, D, P>(values);
            store.write_rows(0, values.len(), &words)?;
            store.finalize()?;
            Ok(Self {
                inner: Arc::new(ChallengeArtifact {
                    store,
                    job_dir: job_dir.clone(),
                    remove_on_drop: AtomicBool::new(true),
                }),
                len: values.len(),
            })
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    pub fn from_block_generator<G>(
        policy: &ResourcePolicyV1,
        len: usize,
        generate: G,
    ) -> Result<Self>
    where
        G: FnMut(usize, usize) -> Result<Vec<P::Challenge>>,
    {
        let block_rows = policy.tile_rows(challenge_bytes::<W, D, P>(), 1)?.min(len);
        Self::from_block_generator_with_rows(policy, len, block_rows, generate)
    }

    pub(crate) fn from_block_generator_with_rows<G>(
        policy: &ResourcePolicyV1,
        len: usize,
        block_rows: usize,
        mut generate: G,
    ) -> Result<Self>
    where
        G: FnMut(usize, usize) -> Result<Vec<P::Challenge>>,
    {
        if len == 0 || !len.is_power_of_two() {
            return Err(DurableFriError::InvalidShape);
        }
        if block_rows == 0 {
            return Err(DurableFriError::InvalidShape);
        }
        let block_rows = block_rows.min(len);
        preflight_layer::<W, D, P>(policy, len)?;
        let job_dir = create_job_dir(&policy.scratch_dir)?;
        let result = (|| {
            let mut store = ScratchMatrixStore::<P::Word>::create(
                &job_dir,
                "fri-layer.bin",
                len as u64,
                extension_degree::<W, D, P>(),
            )?;
            for row_start in (0..len).step_by(block_rows) {
                let row_count = (len - row_start).min(block_rows);
                let values = generate(row_start, row_count)?;
                if values.len() != row_count {
                    return Err(DurableFriError::InvalidShape);
                }
                store.write_rows(
                    row_start as u64,
                    row_count,
                    &flatten_challenges::<W, D, P>(&values),
                )?;
            }
            store.finalize()?;
            Ok(Self::from_store(store, job_dir.clone(), len))
        })();
        if result.is_err() {
            let _ = fs::remove_dir_all(&job_dir);
        }
        result
    }

    fn from_store(store: ScratchMatrixStore<P::Word>, job_dir: PathBuf, len: usize) -> Self {
        Self {
            inner: Arc::new(ChallengeArtifact {
                store,
                job_dir,
                remove_on_drop: AtomicBool::new(true),
            }),
            len,
        }
    }

    pub fn scratch_artifact(&self) -> Result<(&Path, ArtifactDigest)> {
        let digest = self
            .inner
            .store
            .digest()
            .ok_or(DurableFriError::InvalidShape)?;
        Ok((self.inner.store.path(), digest))
    }

    pub fn retain_for_resume(&self) {
        self.inner.remove_on_drop.store(false, Ordering::Relaxed);
    }

    pub fn reopen(path: &Path, expected: ArtifactDigest) -> Result<Self> {
        if expected.columns != extension_degree::<W, D, P>() {
            return Err(DurableFriError::InvalidShape);
        }
        let len = usize::try_from(expected.rows).map_err(|_| DurableFriError::InvalidShape)?;
        if len == 0 || !len.is_power_of_two() {
            return Err(DurableFriError::InvalidShape);
        }
        let store = ScratchMatrixStore::<P::Word>::reopen(path, expected)?;
        let job_dir = path.parent().ok_or(StreamError::UnsafePath)?.to_path_buf();
        Ok(Self {
            inner: Arc::new(ChallengeArtifact {
                store,
                job_dir,
                remove_on_drop: AtomicBool::new(false),
            }),
            len,
        })
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn try_read(&self, start: usize, count: usize) -> Result<Vec<P::Challenge>> {
        if start.checked_add(count).is_none_or(|end| end > self.len) {
            return Err(DurableFriError::InvalidShape);
        }
        let degree = extension_degree::<W, D, P>();
        let mut words = vec![P::Word::default(); count * degree];
        self.inner
            .store
            .read_rows(start as u64, count, &mut words)?;
        words
            .chunks_exact(degree)
            .map(|coordinates| {
                let values: Vec<P::Val> = coordinates.iter().map(|word| (*word).into()).collect();
                P::Challenge::from_basis_coefficients_slice(&values)
                    .ok_or(DurableFriError::InvalidShape)
            })
            .collect()
    }

    pub fn arity_matrix(&self, arity: usize) -> Result<ChallengeArityMatrix<W, D, P>> {
        if arity == 0 || !arity.is_power_of_two() || !self.len.is_multiple_of(arity) {
            return Err(DurableFriError::InvalidShape);
        }
        Ok(ChallengeArityMatrix {
            vector: self.clone(),
            arity,
        })
    }

    fn arity_base_matrix(&self, arity: usize) -> Result<ChallengeArityBaseMatrix<W, D, P>> {
        if arity == 0 || !arity.is_power_of_two() || !self.len.is_multiple_of(arity) {
            return Err(DurableFriError::InvalidShape);
        }
        Ok(ChallengeArityBaseMatrix {
            vector: self.clone(),
            arity,
        })
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Matrix<P::Challenge>
    for ScratchChallengeVector<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn width(&self) -> usize {
        1
    }

    fn height(&self) -> usize {
        self.len
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<
        Item = P::Challenge,
        IntoIter = impl Iterator<Item = P::Challenge> + Send + Sync,
    > {
        self.try_read(row, 1)
            .expect("validated FRI row remains readable")
            .into_iter()
    }
}

pub struct ChallengeArityMatrix<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    vector: ScratchChallengeVector<W, D, P>,
    arity: usize,
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ChallengeArityMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        Self {
            vector: self.vector.clone(),
            arity: self.arity,
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Matrix<P::Challenge>
    for ChallengeArityMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn width(&self) -> usize {
        self.arity
    }

    fn height(&self) -> usize {
        self.vector.len / self.arity
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<
        Item = P::Challenge,
        IntoIter = impl Iterator<Item = P::Challenge> + Send + Sync,
    > {
        self.vector
            .try_read(row * self.arity, self.arity)
            .expect("validated FRI group remains readable")
            .into_iter()
    }
}

struct ChallengeArityBaseMatrix<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    vector: ScratchChallengeVector<W, D, P>,
    arity: usize,
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Clone
    for ChallengeArityBaseMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn clone(&self) -> Self {
        Self {
            vector: self.vector.clone(),
            arity: self.arity,
        }
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> Matrix<P::Val>
    for ChallengeArityBaseMatrix<W, D, P>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    fn width(&self) -> usize {
        self.arity * extension_degree::<W, D, P>()
    }

    fn height(&self) -> usize {
        self.vector.len / self.arity
    }

    unsafe fn row_unchecked(
        &self,
        row: usize,
    ) -> impl IntoIterator<Item = P::Val, IntoIter = impl Iterator<Item = P::Val> + Send + Sync>
    {
        self.vector
            .try_read(row * self.arity, self.arity)
            .expect("validated FRI base row remains readable")
            .into_iter()
            .flat_map(|value| value.as_basis_coefficients_slice().to_vec())
    }
}

impl<const W: usize, const D: usize, P: DurableFieldProfile<W, D>> BlockMatrix<P::Word>
    for ChallengeArityBaseMatrix<W, D, P>
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
        if row_start
            .checked_add(row_count)
            .is_none_or(|end| end > self.height())
            || output.len() != row_count * self.width()
        {
            return Err(StreamError::OutOfBounds);
        }
        let values = self
            .vector
            .try_read(row_start * self.arity, row_count * self.arity)
            .map_err(|error| match error {
                DurableFriError::Stream(stream) => stream,
                _ => StreamError::Corrupt("FRI base block read failed"),
            })?;
        let words = flatten_challenges::<W, D, P>(&values);
        output.copy_from_slice(&words);
        Ok(())
    }
}

/// Exact binary Plonky3 FRI fold over a bit-reversed durable vector.
pub fn fold_binary_layer<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    source: &ScratchChallengeVector<W, D, P>,
    beta: P::Challenge,
    policy: &ResourcePolicyV1,
) -> Result<ScratchChallengeVector<W, D, P>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    if source.len < 2 || !source.len.is_power_of_two() {
        return Err(DurableFriError::InvalidShape);
    }
    let output_len = source.len / 2;
    preflight_layer::<W, D, P>(policy, output_len)?;
    let job_dir = create_job_dir(&policy.scratch_dir)?;
    let result = (|| {
        let mut output = ScratchMatrixStore::<P::Word>::create(
            &job_dir,
            "fri-layer.bin",
            output_len as u64,
            extension_degree::<W, D, P>(),
        )?;
        let block_rows = policy
            .tile_rows(challenge_bytes::<W, D, P>(), 1)?
            .min(output_len);
        let pool = worker_pool(policy)?;
        let log_output_len = output_len.trailing_zeros() as usize;
        let generator_inverse = P::Val::two_adic_generator(log_output_len + 1).inverse();
        for row_start in (0..output_len).step_by(block_rows) {
            let row_count = (output_len - row_start).min(block_rows);
            let inputs = source.try_read(row_start * 2, row_count * 2)?;
            let mut folded = vec![P::Challenge::ZERO; row_count];
            let fold_row = |(row, destination): (usize, &mut P::Challenge)| {
                let index = row_start + row;
                let exponent = reverse_low_bits(index, log_output_len);
                let halve_inverse_power = generator_inverse.exp_u64(exponent as u64).halve();
                let low = inputs[row * 2];
                let high = inputs[row * 2 + 1];
                *destination = (low + high).halve() + (low - high) * beta * halve_inverse_power;
            };
            if let Some(pool) = &pool {
                pool.install(|| folded.par_iter_mut().enumerate().for_each(fold_row));
            } else {
                folded.iter_mut().enumerate().for_each(fold_row);
            }
            let words = flatten_challenges::<W, D, P>(&folded);
            output.write_rows(row_start as u64, row_count, &words)?;
        }
        output.finalize()?;
        Ok(ScratchChallengeVector::from_store(
            output,
            job_dir.clone(),
            output_len,
        ))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&job_dir);
    }
    result
}

/// Prover-side FRI loop with durable layers and the official Plonky3 proof
/// structure. The frozen production profile uses binary folding; test profiles
/// may vary query and grinding counts but must retain `max_log_arity = 1`.
pub struct FriLayerCheckpoint<'a, const W: usize, const D: usize, P: DurableFieldProfile<W, D>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    pub layer: u32,
    pub committed_layer: &'a ScratchChallengeVector<W, D, P>,
    pub next_layer: &'a ScratchChallengeVector<W, D, P>,
    pub commitment: &'a DurableFriCommitment<W, D, P>,
    pub commit_pow_witness: P::Val,
    pub log_arity: u8,
}

pub fn prove_durable_fri<const W: usize, const D: usize, P, InputProof, OpenInput>(
    params: &FriParameters<DurableFriMmcs<W, D, P>>,
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    inputs: Vec<ScratchChallengeVector<W, D, P>>,
    challenger: &mut ProfileChallengerFor<W, D, P>,
    log_global_max_height: usize,
    open_input: OpenInput,
    policy: &ResourcePolicyV1,
) -> Result<DurableFriProof<W, D, P, InputProof>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    InputProof: Clone,
    OpenInput: FnMut(usize) -> InputProof,
{
    prove_durable_fri_observed(
        params,
        base_mmcs,
        inputs,
        challenger,
        log_global_max_height,
        open_input,
        policy,
        |_, _| Ok(()),
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prove_durable_fri_observed<
    const W: usize,
    const D: usize,
    P,
    InputProof,
    OpenInput,
    Observe,
>(
    params: &FriParameters<DurableFriMmcs<W, D, P>>,
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    inputs: Vec<ScratchChallengeVector<W, D, P>>,
    challenger: &mut ProfileChallengerFor<W, D, P>,
    log_global_max_height: usize,
    mut open_input: OpenInput,
    policy: &ResourcePolicyV1,
    observe: Observe,
) -> Result<DurableFriProof<W, D, P, InputProof>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    InputProof: Clone,
    OpenInput: FnMut(usize) -> InputProof,
    Observe: FnMut(
        FriLayerCheckpoint<'_, W, D, P>,
        &ProfileChallengerFor<W, D, P>,
    ) -> std::result::Result<(), String>,
{
    prove_durable_fri_observed_batched(
        params,
        base_mmcs,
        inputs,
        challenger,
        log_global_max_height,
        |indices| Ok(indices.iter().copied().map(&mut open_input).collect()),
        policy,
        observe,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn prove_durable_fri_observed_batched<
    const W: usize,
    const D: usize,
    P,
    InputProof,
    OpenInputs,
    Observe,
>(
    params: &FriParameters<DurableFriMmcs<W, D, P>>,
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    inputs: Vec<ScratchChallengeVector<W, D, P>>,
    challenger: &mut ProfileChallengerFor<W, D, P>,
    log_global_max_height: usize,
    mut open_inputs: OpenInputs,
    policy: &ResourcePolicyV1,
    mut observe: Observe,
) -> Result<DurableFriProof<W, D, P, InputProof>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    InputProof: Clone,
    OpenInputs: FnMut(&[usize]) -> std::result::Result<Vec<InputProof>, String>,
    Observe: FnMut(
        FriLayerCheckpoint<'_, W, D, P>,
        &ProfileChallengerFor<W, D, P>,
    ) -> std::result::Result<(), String>,
{
    if inputs.is_empty()
        || params.num_queries == 0
        || params.max_log_arity != 1
        || inputs
            .windows(2)
            .any(|window| window[0].len() < window[1].len())
        || inputs[0].len().trailing_zeros() as usize != log_global_max_height
    {
        return Err(DurableFriError::InvalidShape);
    }
    let mut input_iter = inputs.into_iter().peekable();
    let folded = input_iter.next().ok_or(DurableFriError::InvalidShape)?;
    continue_durable_fri_batched(
        params,
        base_mmcs,
        input_iter,
        folded,
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        challenger,
        log_global_max_height,
        &mut open_inputs,
        policy,
        &mut observe,
    )
}

/// Continue from FRI source layers persisted after completed fold rounds. The
/// challenger must be restored immediately after the last recorded beta was
/// sampled. Prior MMCS prover data is reconstructed without observing or
/// sampling the transcript again.
#[allow(clippy::too_many_arguments)]
pub fn resume_durable_fri_observed<
    const W: usize,
    const D: usize,
    P,
    InputProof,
    OpenInput,
    Observe,
>(
    params: &FriParameters<DurableFriMmcs<W, D, P>>,
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    layers: Vec<ScratchChallengeVector<W, D, P>>,
    commitments: Vec<DurableFriCommitment<W, D, P>>,
    commit_pow_witnesses: Vec<P::Val>,
    log_arities: Vec<usize>,
    challenger: &mut ProfileChallengerFor<W, D, P>,
    log_global_max_height: usize,
    mut open_input: OpenInput,
    policy: &ResourcePolicyV1,
    observe: Observe,
) -> Result<DurableFriProof<W, D, P, InputProof>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    InputProof: Clone,
    OpenInput: FnMut(usize) -> InputProof,
    Observe: FnMut(
        FriLayerCheckpoint<'_, W, D, P>,
        &ProfileChallengerFor<W, D, P>,
    ) -> std::result::Result<(), String>,
{
    resume_durable_fri_observed_batched(
        params,
        base_mmcs,
        layers,
        commitments,
        commit_pow_witnesses,
        log_arities,
        challenger,
        log_global_max_height,
        |indices| Ok(indices.iter().copied().map(&mut open_input).collect()),
        policy,
        observe,
    )
}

#[allow(clippy::too_many_arguments)]
pub fn resume_durable_fri_observed_batched<
    const W: usize,
    const D: usize,
    P,
    InputProof,
    OpenInputs,
    Observe,
>(
    params: &FriParameters<DurableFriMmcs<W, D, P>>,
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    layers: Vec<ScratchChallengeVector<W, D, P>>,
    commitments: Vec<DurableFriCommitment<W, D, P>>,
    commit_pow_witnesses: Vec<P::Val>,
    log_arities: Vec<usize>,
    challenger: &mut ProfileChallengerFor<W, D, P>,
    log_global_max_height: usize,
    mut open_inputs: OpenInputs,
    policy: &ResourcePolicyV1,
    mut observe: Observe,
) -> Result<DurableFriProof<W, D, P, InputProof>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    InputProof: Clone,
    OpenInputs: FnMut(&[usize]) -> std::result::Result<Vec<InputProof>, String>,
    Observe: FnMut(
        FriLayerCheckpoint<'_, W, D, P>,
        &ProfileChallengerFor<W, D, P>,
    ) -> std::result::Result<(), String>,
{
    if layers.len() != commitments.len() + 1
        || commitments.len() != commit_pow_witnesses.len()
        || commitments.len() != log_arities.len()
        || layers.is_empty()
        || layers[0].len().trailing_zeros() as usize != log_global_max_height
        || layers
            .windows(2)
            .any(|window| window[0].len() / 2 != window[1].len())
        || log_arities.iter().any(|arity| *arity != 1)
    {
        return Err(DurableFriError::InvalidShape);
    }
    let mut data = Vec::with_capacity(commitments.len());
    for (layer, expected) in layers.iter().take(commitments.len()).zip(&commitments) {
        let matrix = layer.arity_base_matrix(2)?;
        let (actual, prover_data) = base_mmcs.try_commit_blocks(vec![matrix])?;
        if &actual != expected {
            return Err(DurableFriError::InvalidShape);
        }
        data.push(prover_data);
    }
    let folded = layers
        .last()
        .cloned()
        .ok_or(DurableFriError::InvalidShape)?;
    continue_durable_fri_batched(
        params,
        base_mmcs,
        Vec::new().into_iter().peekable(),
        folded,
        commitments,
        data,
        log_arities,
        commit_pow_witnesses,
        challenger,
        log_global_max_height,
        &mut open_inputs,
        policy,
        &mut observe,
    )
}

#[allow(clippy::too_many_arguments)]
fn continue_durable_fri_batched<
    const W: usize,
    const D: usize,
    P,
    InputProof,
    OpenInputs,
    Observe,
>(
    params: &FriParameters<DurableFriMmcs<W, D, P>>,
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    mut input_iter: std::iter::Peekable<std::vec::IntoIter<ScratchChallengeVector<W, D, P>>>,
    mut folded: ScratchChallengeVector<W, D, P>,
    mut commits: Vec<DurableFriCommitment<W, D, P>>,
    mut data: Vec<DurableMerkleData<W, D, P, ChallengeArityBaseMatrix<W, D, P>>>,
    mut log_arities: Vec<usize>,
    mut commit_pow_witnesses: Vec<P::Val>,
    challenger: &mut ProfileChallengerFor<W, D, P>,
    log_global_max_height: usize,
    open_inputs: &mut OpenInputs,
    policy: &ResourcePolicyV1,
    observe: &mut Observe,
) -> Result<DurableFriProof<W, D, P, InputProof>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    InputProof: Clone,
    OpenInputs: FnMut(&[usize]) -> std::result::Result<Vec<InputProof>, String>,
    Observe: FnMut(
        FriLayerCheckpoint<'_, W, D, P>,
        &ProfileChallengerFor<W, D, P>,
    ) -> std::result::Result<(), String>,
{
    let log_final_height = params.log_blowup + params.log_final_poly_len;

    while folded.len() > params.blowup() * params.final_poly_len() {
        let log_current_height = folded.len().trailing_zeros() as usize;
        let next_input_log_height = input_iter
            .peek()
            .map(|input| input.len().trailing_zeros() as usize);
        let log_arity = compute_log_arity_for_round(
            log_current_height,
            next_input_log_height,
            log_final_height,
            params.max_log_arity,
        );
        if log_arity != 1 {
            return Err(DurableFriError::InvalidShape);
        }
        log_arities.push(log_arity);
        let matrix = folded.arity_base_matrix(2)?;
        let (commit, prover_data) = base_mmcs.try_commit_blocks(vec![matrix])?;
        challenger.observe(commit.clone());
        commits.push(commit);
        commit_pow_witnesses.push(challenger.grind(params.commit_proof_of_work_bits));
        let beta: P::Challenge = challenger.sample_algebra_element();
        let mut next = fold_binary_layer(&folded, beta, policy)?;
        if input_iter
            .peek()
            .is_some_and(|input| input.len() == next.len())
        {
            let addition = input_iter.next().expect("peeked FRI input exists");
            next = add_scaled_layer(&next, &addition, beta.square(), policy)?;
        }
        observe(
            FriLayerCheckpoint {
                layer: (commits.len() - 1) as u32,
                committed_layer: &folded,
                next_layer: &next,
                commitment: commits.last().expect("FRI commitment was appended"),
                commit_pow_witness: *commit_pow_witnesses
                    .last()
                    .expect("FRI PoW witness was appended"),
                log_arity: log_arity as u8,
            },
            challenger,
        )
        .map_err(DurableFriError::Observer)?;
        data.push(prover_data);
        folded = next;
    }

    let final_len = params.final_poly_len();
    let mut final_evaluations = folded.try_read(0, final_len)?;
    reverse_slice_index_bits(&mut final_evaluations);
    let final_dft = Radix2DFTSmallBatch::<P::Val>::default();
    let final_poly = <Radix2DFTSmallBatch<P::Val> as TwoAdicSubgroupDft<P::Val>>::idft_algebra::<
        P::Challenge,
    >(&final_dft, final_evaluations);
    challenger.observe_algebra_slice(&final_poly);
    for &log_arity in &log_arities {
        challenger.observe(P::Val::from_usize(log_arity));
    }
    let query_pow_witness = challenger.grind(params.query_proof_of_work_bits);
    let query_indices: Vec<_> = (0..params.num_queries)
        .map(|_| challenger.sample_bits(log_global_max_height))
        .collect();
    let mut sorted_indices = query_indices.clone();
    sorted_indices.sort_unstable();
    sorted_indices.dedup();
    let input_proofs = open_inputs(&sorted_indices).map_err(DurableFriError::Observer)?;
    if input_proofs.len() != sorted_indices.len() {
        return Err(DurableFriError::InvalidShape);
    }
    let commit_phase_openings = answer_queries_batched(base_mmcs, &data, &sorted_indices)?;
    let query_proofs = query_indices
        .into_iter()
        .map(|index| {
            let sorted_position = sorted_indices
                .binary_search(&index)
                .expect("sampled query is present in sorted query set");
            QueryProof {
                input_proof: input_proofs[sorted_position].clone(),
                commit_phase_openings: commit_phase_openings[sorted_position].clone(),
            }
        })
        .collect();

    Ok(FriProof {
        commit_phase_commits: commits,
        commit_pow_witnesses,
        query_proofs,
        final_poly,
        query_pow_witness,
    })
}

fn add_scaled_layer<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    current: &ScratchChallengeVector<W, D, P>,
    addition: &ScratchChallengeVector<W, D, P>,
    scale: P::Challenge,
    policy: &ResourcePolicyV1,
) -> Result<ScratchChallengeVector<W, D, P>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    if current.len() != addition.len() {
        return Err(DurableFriError::InvalidShape);
    }
    let len = current.len();
    preflight_layer::<W, D, P>(policy, len)?;
    let job_dir = create_job_dir(&policy.scratch_dir)?;
    let result = (|| {
        let mut output = ScratchMatrixStore::<P::Word>::create(
            &job_dir,
            "fri-layer.bin",
            len as u64,
            extension_degree::<W, D, P>(),
        )?;
        let block_rows = policy.tile_rows(challenge_bytes::<W, D, P>(), 1)?.min(len);
        let pool = worker_pool(policy)?;
        for row_start in (0..len).step_by(block_rows) {
            let row_count = (len - row_start).min(block_rows);
            let current_values = current.try_read(row_start, row_count)?;
            let addition_values = addition.try_read(row_start, row_count)?;
            let mut combined = vec![P::Challenge::ZERO; row_count];
            let combine = |(index, destination): (usize, &mut P::Challenge)| {
                *destination = current_values[index] + scale * addition_values[index];
            };
            if let Some(pool) = &pool {
                pool.install(|| combined.par_iter_mut().enumerate().for_each(combine));
            } else {
                combined.iter_mut().enumerate().for_each(combine);
            }
            output.write_rows(
                row_start as u64,
                row_count,
                &flatten_challenges::<W, D, P>(&combined),
            )?;
        }
        output.finalize()?;
        Ok(ScratchChallengeVector::from_store(
            output,
            job_dir.clone(),
            len,
        ))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&job_dir);
    }
    result
}

pub(crate) fn bit_reverse_challenge_vector<
    const W: usize,
    const D: usize,
    P: DurableFieldProfile<W, D>,
>(
    source: ScratchChallengeVector<W, D, P>,
    policy: &ResourcePolicyV1,
) -> Result<ScratchChallengeVector<W, D, P>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let len = source.len();
    if len == 0 || !len.is_power_of_two() {
        return Err(DurableFriError::InvalidShape);
    }
    let bytes = (len as u64).saturating_mul(challenge_bytes::<W, D, P>() as u64);
    policy.preflight_for_mode(
        ExecutionMode::Scratch,
        ResourceEstimate {
            peak_resident_bytes: 8 * 1024 * 1024,
            scratch_high_water_bytes: bytes.saturating_mul(2),
            total_read_bytes: bytes.saturating_mul(3),
            total_write_bytes: bytes.saturating_mul(3),
            phases: vec![PhaseEstimate {
                phase: "challenge_bit_reversal".into(),
                read_bytes: bytes.saturating_mul(3),
                write_bytes: bytes.saturating_mul(3),
            }],
        },
    )?;
    let log_len = len.trailing_zeros() as usize;
    let row_bits = log_len / 2;
    let column_bits = log_len - row_bits;
    let rows = 1usize << row_bits;
    let columns = 1usize << column_bits;

    let columns_reversed =
        reverse_challenge_groups::<W, D, P>(&source, columns, column_bits, policy)?;
    drop(source);
    let transposed = transpose_challenge_grid::<W, D, P>(&columns_reversed, rows, columns, policy)?;
    drop(columns_reversed);
    let output = reverse_challenge_groups::<W, D, P>(&transposed, rows, row_bits, policy)?;
    drop(transposed);
    Ok(output)
}

fn reverse_challenge_groups<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    source: &ScratchChallengeVector<W, D, P>,
    group_rows: usize,
    bits: usize,
    policy: &ResourcePolicyV1,
) -> Result<ScratchChallengeVector<W, D, P>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let len = source.len();
    if group_rows == 0 || !len.is_multiple_of(group_rows) {
        return Err(DurableFriError::InvalidShape);
    }
    let degree = extension_degree::<W, D, P>();
    let job_dir = create_job_dir(&policy.scratch_dir)?;
    let result = (|| {
        let mut store =
            ScratchMatrixStore::<P::Word>::create(&job_dir, "fri-layer.bin", len as u64, degree)?;
        let mut input = vec![P::Word::default(); group_rows * degree];
        let mut output = vec![P::Word::default(); group_rows * degree];
        for group_start in (0..len).step_by(group_rows) {
            source
                .inner
                .store
                .read_rows(group_start as u64, group_rows, &mut input)?;
            for row in 0..group_rows {
                let destination = reverse_low_bits(row, bits);
                output[destination * degree..destination * degree + degree]
                    .copy_from_slice(&input[row * degree..row * degree + degree]);
            }
            store.write_rows(group_start as u64, group_rows, &output)?;
        }
        store.finalize()?;
        Ok(ScratchChallengeVector::from_store(
            store,
            job_dir.clone(),
            len,
        ))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&job_dir);
    }
    result
}

fn transpose_challenge_grid<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    source: &ScratchChallengeVector<W, D, P>,
    rows: usize,
    columns: usize,
    policy: &ResourcePolicyV1,
) -> Result<ScratchChallengeVector<W, D, P>>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    const BUFFER_BYTES: usize = 8 * 1024 * 1024;
    let len = rows
        .checked_mul(columns)
        .ok_or(DurableFriError::InvalidShape)?;
    if source.len() != len {
        return Err(DurableFriError::InvalidShape);
    }
    let degree = extension_degree::<W, D, P>();
    let word_width = <P::Word as CanonicalElement>::WIDTH;
    let fixed_items = BUFFER_BYTES / (2 * degree * word_width);
    let max_items = policy
        .tile_rows(word_width, 2 * degree)?
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
    let job_dir = create_job_dir(&policy.scratch_dir)?;
    let result = (|| {
        let mut store =
            ScratchMatrixStore::<P::Word>::create(&job_dir, "fri-layer.bin", len as u64, degree)?;
        let mut input = vec![P::Word::default(); tile_side * tile_side * degree];
        let mut output = vec![P::Word::default(); tile_side * tile_side * degree];
        for row_start in (0..rows).step_by(tile_side) {
            let row_count = (rows - row_start).min(tile_side);
            for column_start in (0..columns).step_by(tile_side) {
                let column_count = (columns - column_start).min(tile_side);
                for row in 0..row_count {
                    let destination = row * column_count * degree;
                    source.inner.store.read_rows(
                        ((row_start + row) * columns + column_start) as u64,
                        column_count,
                        &mut input[destination..destination + column_count * degree],
                    )?;
                }
                for row in 0..row_count {
                    for column in 0..column_count {
                        let source_offset = (row * column_count + column) * degree;
                        let destination_offset = (column * row_count + row) * degree;
                        output[destination_offset..destination_offset + degree]
                            .copy_from_slice(&input[source_offset..source_offset + degree]);
                    }
                }
                for column in 0..column_count {
                    let source_offset = column * row_count * degree;
                    store.write_rows(
                        ((column_start + column) * rows + row_start) as u64,
                        row_count,
                        &output[source_offset..source_offset + row_count * degree],
                    )?;
                }
            }
        }
        store.finalize()?;
        Ok(ScratchChallengeVector::from_store(
            store,
            job_dir.clone(),
            len,
        ))
    })();
    if result.is_err() {
        let _ = fs::remove_dir_all(&job_dir);
    }
    result
}

#[allow(clippy::type_complexity)]
fn answer_queries_batched<const W: usize, const D: usize, P>(
    base_mmcs: &DurableProfileMmcs<W, D, P>,
    data: &[DurableMerkleData<W, D, P, ChallengeArityBaseMatrix<W, D, P>>],
    start_indices: &[usize],
) -> Result<Vec<Vec<CommitPhaseProofStep<P::Challenge, DurableFriMmcs<W, D, P>>>>>
where
    P: DurableFieldProfile<W, D>,
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let mut answers = vec![Vec::with_capacity(data.len()); start_indices.len()];
    let mut current_indices = start_indices.to_vec();
    for prover_data in data {
        let group_indices: Vec<_> = current_indices.iter().map(|index| index >> 1).collect();
        let mut unique_groups = group_indices.clone();
        unique_groups.sort_unstable();
        unique_groups.dedup();
        let openings = base_mmcs.open_batches_sorted(&unique_groups, prover_data)?;
        for ((answer, current_index), group_index) in
            answers.iter_mut().zip(&current_indices).zip(&group_indices)
        {
            let position = unique_groups
                .binary_search(group_index)
                .expect("query group was included in the sorted scan");
            let (base_rows, opening_proof) = openings[position].clone().unpack();
            let mut rows: Vec<_> = base_rows
                .into_iter()
                .map(P::Challenge::reconstitute_from_base)
                .collect();
            let row = rows.pop().ok_or(DurableFriError::InvalidShape)?;
            // The committed arity is 2 (binary folding), independent of the
            // extension degree: each group holds exactly the value and its
            // sibling.
            if !rows.is_empty() || row.len() != 2 {
                return Err(DurableFriError::InvalidShape);
            }
            let index_in_group = current_index & 1;
            let sibling_values = row
                .into_iter()
                .enumerate()
                .filter_map(|(index, value)| (index != index_in_group).then_some(value))
                .collect();
            answer.push(CommitPhaseProofStep {
                log_arity: 1,
                sibling_values,
                opening_proof,
            });
        }
        current_indices = group_indices;
    }
    Ok(answers)
}

fn reverse_slice_index_bits<T>(values: &mut [T]) {
    let bits = values.len().trailing_zeros() as usize;
    for index in 0..values.len() {
        let reversed = reverse_low_bits(index, bits);
        if reversed > index {
            values.swap(index, reversed);
        }
    }
}

fn flatten_challenges<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    values: &[P::Challenge],
) -> Vec<P::Word>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    values
        .iter()
        .flat_map(|value| {
            value
                .as_basis_coefficients_slice()
                .iter()
                .copied()
                .map(Into::into)
        })
        .collect()
}

fn preflight_layer<const W: usize, const D: usize, P: DurableFieldProfile<W, D>>(
    policy: &ResourcePolicyV1,
    len: usize,
) -> Result<()>
where
    [P::Val; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
{
    let bytes = (len as u64).saturating_mul(challenge_bytes::<W, D, P>() as u64);
    policy.preflight_for_mode(
        ExecutionMode::Scratch,
        ResourceEstimate {
            peak_resident_bytes: 8 * 1024 * 1024,
            scratch_high_water_bytes: bytes,
            total_read_bytes: bytes.saturating_mul(2),
            total_write_bytes: bytes,
            phases: vec![PhaseEstimate {
                phase: "fri_layer".into(),
                read_bytes: bytes.saturating_mul(2),
                write_bytes: bytes,
            }],
        },
    )?;
    Ok(())
}

fn reverse_low_bits(value: usize, bits: usize) -> usize {
    if bits == 0 {
        0
    } else {
        value.reverse_bits() >> (usize::BITS as usize - bits)
    }
}

fn create_job_dir(root: &Path) -> Result<PathBuf> {
    create_unique_job_dir(root, "fri-layer", &LAYER_COUNTER).map_err(Into::into)
}

/// Goldilocks pins, so `bounded_prover`/`opening` keep naming exactly the
/// types they named before this module became generic.
pub mod goldilocks {
    use crate::profile::GoldilocksProfile;

    pub type ScratchChallengeVector = super::ScratchChallengeVector<8, 4, GoldilocksProfile>;
    pub type ChallengeArityMatrix = super::ChallengeArityMatrix<8, 4, GoldilocksProfile>;
    pub type DurableFriCommitment = super::DurableFriCommitment<8, 4, GoldilocksProfile>;
    pub type FriLayerCheckpoint<'a> = super::FriLayerCheckpoint<'a, 8, 4, GoldilocksProfile>;
}

#[cfg(test)]
mod tests {
    use super::goldilocks::ScratchChallengeVector;
    use super::*;
    use crate::checkpoint::profile_permutation;
    use crate::mmcs::goldilocks::DurableGoldilocksMmcs;
    use crate::ProfileChallenger;
    use hc_stream::{CheckpointPolicy, ResourceMode};
    use p3_commit::{BatchOpening, ExtensionMmcs, Mmcs};
    use p3_field::Field;
    use p3_fri::{FriFoldingStrategy, TwoAdicFriFolding, TwoAdicFriFoldingForMmcs};
    use p3_goldilocks::Goldilocks;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};

    type Packing = <Goldilocks as Field>::Packing;
    type Permutation = crate::ProfilePermutation;
    type Hash = PaddingFreeSponge<Permutation, 8, 4, 4>;
    type Compression = TruncatedPermutation<Permutation, 2, 4, 8>;
    type ReferenceBase = MerkleTreeMmcs<Packing, Packing, Hash, Compression, 2, 4>;
    type ReferenceFri = ExtensionMmcs<Goldilocks, ProfileChallenge, ReferenceBase>;

    fn policy(root: &Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 32 * 1024 * 1024,
            max_scratch_bytes: 128 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 4,
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
    fn durable_binary_fold_matches_plonky3_and_mmcs_openings() {
        let dir = tempfile::tempdir().unwrap();
        let values: Vec<_> = (0..32)
            .map(|index| {
                ProfileChallenge::from_basis_coefficients_fn(|coordinate| {
                    Goldilocks::from_u64((index * 19 + coordinate + 3) as u64)
                })
            })
            .collect();
        let beta = ProfileChallenge::from_basis_coefficients_fn(|coordinate| {
            Goldilocks::from_u64((coordinate + 41) as u64)
        });
        let source = ScratchChallengeVector::from_values(&policy(dir.path()), &values).unwrap();
        let actual_fold = fold_binary_layer(&source, beta, &policy(dir.path())).unwrap();

        let (hash, compression) = components();
        let reference_base: ReferenceBase =
            ReferenceBase::new(hash.clone(), compression.clone(), 0);
        let reference_fri = ReferenceFri::new(reference_base);
        let folding: TwoAdicFriFoldingForMmcs<Goldilocks, ReferenceBase> =
            TwoAdicFriFolding(core::marker::PhantomData);
        let reference_matrix = RowMajorMatrix::new(values.clone(), 2);
        let expected_fold = <_ as FriFoldingStrategy<Goldilocks, ProfileChallenge>>::fold_matrix(
            &folding,
            beta,
            1,
            reference_matrix.clone(),
        );
        assert_eq!(
            actual_fold.try_read(0, actual_fold.len()).unwrap(),
            expected_fold
        );

        let durable_base =
            DurableGoldilocksMmcs::new(hash, compression, policy(dir.path())).unwrap();
        let durable_fri = ExtensionMmcs::new(durable_base.clone());
        let (expected_root, expected_data) = reference_fri.commit_matrix(reference_matrix);
        let (actual_root, actual_data) = durable_fri.commit_matrix(source.arity_matrix(2).unwrap());
        assert_eq!(actual_root, expected_root);
        for index in 0..16 {
            let expected = reference_fri.open_batch(index, &expected_data);
            let actual = durable_fri.open_batch(index, &actual_data);
            assert_eq!(actual.opened_values, expected.opened_values);
            assert_eq!(actual.opening_proof, expected.opening_proof);
        }
    }

    #[test]
    #[allow(clippy::type_complexity)]
    fn durable_fri_proof_bytes_match_plonky3_reference() {
        let dir = tempfile::tempdir().unwrap();
        let values: Vec<_> = (0..32)
            .map(|index| {
                ProfileChallenge::from_basis_coefficients_fn(|coordinate| {
                    Goldilocks::from_u64((index * 23 + coordinate + 5) as u64)
                })
            })
            .collect();
        let (hash, compression) = components();
        let reference_base: ReferenceBase =
            ReferenceBase::new(hash.clone(), compression.clone(), 0);
        let reference_fri = ReferenceFri::new(reference_base.clone());
        let reference_params = FriParameters::new_testing(reference_fri, 0);
        let folding: TwoAdicFriFoldingForMmcs<Goldilocks, ReferenceBase> =
            TwoAdicFriFolding(core::marker::PhantomData);
        let mut reference_challenger = ProfileChallenger::new(profile_permutation());
        let no_openings: Vec<
            p3_fri::ProverDataWithOpeningPoints<
                '_,
                ProfileChallenge,
                <ReferenceBase as Mmcs<Goldilocks>>::ProverData<RowMajorMatrix<Goldilocks>>,
            >,
        > = vec![];
        let reference_proof = p3_fri::prover::prove_fri(
            &folding,
            &reference_params,
            vec![values.clone()],
            &mut reference_challenger,
            5,
            &no_openings,
            &reference_base,
        );

        let durable_base =
            DurableGoldilocksMmcs::new(hash, compression, policy(dir.path())).unwrap();
        let durable_fri = ExtensionMmcs::new(durable_base.clone());
        let durable_params = FriParameters::new_testing(durable_fri, 0);
        let input = ScratchChallengeVector::from_values(&policy(dir.path()), &values).unwrap();
        let mut durable_challenger = ProfileChallenger::new(profile_permutation());
        let batch_calls = std::cell::Cell::new(0usize);
        let durable_proof = prove_durable_fri_observed_batched(
            &durable_params,
            &durable_base,
            vec![input],
            &mut durable_challenger,
            5,
            |indices| {
                batch_calls.set(batch_calls.get() + 1);
                assert!(indices.windows(2).all(|pair| pair[0] < pair[1]));
                Ok(vec![
                    Vec::<BatchOpening<Goldilocks, DurableGoldilocksMmcs>>::new(
                    );
                    indices.len()
                ])
            },
            &policy(dir.path()),
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(batch_calls.get(), 1);

        assert_eq!(
            postcard::to_allocvec(&durable_proof).unwrap(),
            postcard::to_allocvec(&reference_proof).unwrap()
        );
        assert_eq!(
            crate::ChallengerSnapshotV1::capture(&durable_challenger),
            crate::ChallengerSnapshotV1::capture(&reference_challenger)
        );
    }
}
