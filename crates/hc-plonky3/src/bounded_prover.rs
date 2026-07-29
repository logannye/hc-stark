// Generic over `DurableFieldProfile<PERM_WIDTH, DIGEST_ELEMS>`, like
// `dft`/`mmcs`/`fri`/`quotient`/`bounded_pcs` before it.
//
// NAMING: the const parameters are spelled `PW` (Poseidon2 permutation width)
// and `DE` (Merkle digest size in field elements), the profile is `P`, and the
// **workload is `Wk`** — deliberately NOT `W`, which this module's public
// entry points have always used for the workload and which is also the
// conventional name for the permutation width. Reusing one letter for both
// would make every signature here ambiguous to read.
//
// The public entry points below stay pinned to `<8, 4, GoldilocksProfile>` and
// keep their exact pre-generic signatures; the `*_with_profile` variants are
// the generic ones. Nothing outside this crate had to change.
use crate::bounded_pcs::{
    make_bounded_verifier_config, make_durable_mmcs, BoundedConfig, DurableInputMmcs,
    ProfileStarkConfig,
};
use crate::checkpoint::ChallengerSnapshotV1;
use crate::dft::{ResourceBoundedDft, ResourceBoundedMatrix};
use crate::fri::{
    prove_durable_fri_observed_batched, resume_durable_fri_observed_batched, DurableFriCommitment,
    DurableFriError, FriLayerCheckpoint, ProfileChallengerFor, ScratchChallengeVector,
};
use crate::mmcs::DurableMerkleData;
use crate::opening::{
    build_reduced_opening_layer, interpolate_standard_lde, DurableOpeningError, MatrixOpening,
};
use crate::profile::{DurableFieldProfile, GoldilocksProfile};
use crate::prover::{GoldilocksConfig, Val, COMPATIBILITY_PROFILE, PLONKY3_VERSION};
use crate::quotient::{
    build_quotient_chunk_ldes, stream_quotient_values, EvaluationConfig, StreamedQuotientError,
};
use crate::scratch::create_unique_job_dir;
use crate::workloads::{
    FibonacciWorkload, Poseidon2Workload, ResourceBoundedWorkload, WorkloadError,
};
use hc_stream::{
    cleanup_job_directory, ArtifactDigest, BlockMatrix, CanonicalElement, CheckpointArtifactV2,
    CheckpointIdentityV2, CheckpointManifestV2, CheckpointPolicy, ExecutionMode, MatrixStore,
    MemoryMatrix, PipelineArtifactKindV1, PipelinePhaseV1, PreflightReport, ResourceEstimate,
    ResourceMode, ResourcePolicyV1, ScratchMatrixStore, StreamError,
};
use p3_air::symbolic::{AirLayout, SymbolicAirBuilder};
use p3_air::{Air, BaseAir};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_commit::{ExtensionMmcs, PolynomialSpace};
use p3_dft::Radix2DitParallel;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::FriParameters;
use p3_matrix::bitrev::BitReversedMatrixView;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::Matrix;
use p3_merkle_tree::MerkleCap;
use p3_uni_stark::{
    get_log_num_quotient_chunks, prove, verify, Commitments, OpenedValues, Proof,
    ProverConstraintFolder, StarkGenericConfig, VerifierConstraintFolder,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

static PROVER_JOB_COUNTER: AtomicU64 = AtomicU64::new(0);
const FRI_CANCELLED_SENTINEL: &str = "tinyzkp-prover-cancelled";
// Structural upper envelope for the frozen `postcard-1.1.3` proof. A u64 can
// occupy ten LEB128 bytes, each Merkle digest has four Goldilocks words, and
// the profile fixes 100 queries. Summed FRI authentication depths are
// triangular (the log-squared term); the three linear path/opening families
// cover trace, quotient, and folded-layer data. The fixed envelope covers caps,
// challenges, length prefixes, and the final polynomial.
const PROFILE_FRI_QUERY_COUNT: u64 = 100;
const MAX_POSTCARD_U64_BYTES: u64 = 10;
const PROFILE_PROOF_FIXED_BYTES: u64 = 16 * 1024;
const PROFILE_PROOF_TRACE_COLUMN_BYTES: u64 = PROFILE_FRI_QUERY_COUNT * MAX_POSTCARD_U64_BYTES;

/// Upper bound on one encoded `ChallengerSnapshotV1`: magic, the whole sponge
/// state, two length bytes, both `RATE`-bounded buffers, and the checksum.
/// `perm_width` is the sponge state size and `rate` its input/output buffer
/// bound — 8/4 for Goldilocks, 16/8 for BabyBear. Both were folded into the
/// literal `8 + 8 * 8 + 2 + 8 * 8 + 32`, where the two `8`s meant different
/// things (state length, and 2 * rate).
const fn max_challenger_snapshot_bytes(perm_width: usize, rate: usize) -> usize {
    8 + perm_width * 8 + 2 + 2 * rate * 8 + 32
}

/// The Goldilocks value of [`max_challenger_snapshot_bytes`], which is what the
/// field-agnostic estimator in `estimate_params.rs` prices. See the note on
/// [`estimated_atomic_checkpoint_bytes`].
pub(crate) const GOLDILOCKS_CHALLENGER_SNAPSHOT_BYTES: usize = max_challenger_snapshot_bytes(8, 4);
const MAX_ARTIFACT_PATH_COUNTER: &str = "18446744073709551615";
const MAX_ARTIFACT_PATH_PID: &str = "4294967295";

#[derive(Debug, thiserror::Error)]
pub enum BoundedProverError {
    #[error("bounded prover supports only the frozen non-ZK Plonky3 profile")]
    UnsupportedProfile,
    #[error("official verifier rejected the bounded proof: {0}")]
    Verification(String),
    #[error("proof serialization failed: {0}")]
    Serialization(String),
    #[error("checkpoint is not a compatible resumable TinyZKP Plonky3 state")]
    InvalidCheckpoint,
    #[error("checkpoint belongs to a different exact TinyZKP engine release")]
    CheckpointReleaseMismatch,
    #[error("checkpoint payload is malformed: {0}")]
    CheckpointPayload(String),
    #[error("the exact checkpoint directory already contains state")]
    CheckpointStateExists,
    #[error("proving was cancelled")]
    Cancelled,
    #[error(transparent)]
    ChallengerSnapshot(#[from] crate::ChallengerSnapshotError),
    #[error(transparent)]
    Stream(#[from] StreamError),
    #[error(transparent)]
    Dft(#[from] crate::dft::DftError),
    #[error(transparent)]
    Workload(#[from] WorkloadError),
    #[error(transparent)]
    Quotient(#[from] StreamedQuotientError),
    #[error(transparent)]
    Opening(#[from] DurableOpeningError),
    #[error(transparent)]
    Fri(#[from] DurableFriError),
    #[error(transparent)]
    Mmcs(#[from] crate::DurableMmcsError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, BoundedProverError>;

#[derive(Clone, Debug, Default)]
pub struct CancellationToken {
    cancelled: Arc<AtomicBool>,
}

impl CancellationToken {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }
}

type DurableCommitMatrix<const PW: usize, const DE: usize, P> =
    BitReversedMatrixView<ResourceBoundedMatrix<PW, DE, P>>;
type DurableCommitData<const PW: usize, const DE: usize, P> =
    DurableMerkleData<PW, DE, P, DurableCommitMatrix<PW, DE, P>>;
/// One Merkle cap of `[P::Val; DIGEST_ELEMS]` roots. The `4` this replaced was
/// the Goldilocks digest size, not an arity.
type DurableCommitment<const PW: usize, const DE: usize, P> = DurableFriCommitment<PW, DE, P>;
/// The unmodified upstream `StarkConfig` this module verifies every proof
/// against, at the active profile. `GoldilocksConfig<Radix2DitParallel<Val>>`
/// is exactly its `<8, 4, GoldilocksProfile>` instantiation.
type OfficialConfig<const PW: usize, const DE: usize, P> =
    ProfileStarkConfig<PW, DE, P, Radix2DitParallel<<P as DurableFieldProfile<PW, DE>>::Val>>;

/// Number of base-field coordinates per challenge element: 2 for Goldilocks,
/// 4 for BabyBear. Same quantity `fri.rs`/`quotient.rs` call
/// `extension_degree()`; every inline `2` describing an extension element's
/// column count in this module was this number.
fn extension_degree<const PW: usize, const DE: usize, P: DurableFieldProfile<PW, DE>>() -> usize
where
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    <P::Challenge as BasedVectorSpace<P::Val>>::DIMENSION
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ResumeDescriptorV1 {
    schema_version: u32,
    workload_id: String,
    workload_version: u32,
    logical_rows: u64,
    public_values: Vec<u64>,
    resource_policy: ResourcePolicyV1,
    // `Vec<Vec<u64>>` rather than `Vec<[u64; 4]>`: the inner length is
    // `DIGEST_ELEMS`, which is 4 for Goldilocks and 8 for BabyBear, and serde's
    // fixed-size-array impls are macro-generated per length so a generic one
    // cannot be selected. The JSON encoding is unchanged (a fixed array and a
    // `Vec` both serialize as a JSON array), so existing Goldilocks
    // checkpoints still round-trip; `validate_resume_descriptor` now enforces
    // the inner length explicitly, which the array type used to do.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    trace_commitment: Option<Vec<Vec<u64>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    quotient_commitment: Option<Vec<Vec<u64>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    fri_state: Option<FriResumeStateV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FriResumeStateV1 {
    // Inner lengths are the extension degree (2 Goldilocks / 4 BabyBear) for
    // the opening vectors and `DIGEST_ELEMS` for the commitments. See
    // `ResumeDescriptorV1` for why these are `Vec` rather than fixed arrays,
    // and `validate_resume_descriptor` / `decode_challenges` /
    // `decode_commitment` for where the lengths are now checked.
    trace_local: Vec<Vec<u64>>,
    trace_next: Option<Vec<Vec<u64>>>,
    quotient_chunks: Vec<Vec<Vec<u64>>>,
    commitments: Vec<Vec<Vec<u64>>>,
    commit_pow_witnesses: Vec<u64>,
    log_arities: Vec<u8>,
}

struct ProverCheckpointContext<const PW: usize, const DE: usize, P: DurableFieldProfile<PW, DE>>
where
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    profile: std::marker::PhantomData<P>,
    root: PathBuf,
    manifest: CheckpointManifestV2,
    descriptor: ResumeDescriptorV1,
    base_artifacts: Vec<CheckpointArtifactV2>,
    fri_artifacts: BTreeMap<u32, CheckpointArtifactV2>,
}

enum TraceLdeContinuation<const PW: usize, const DE: usize, P: DurableFieldProfile<PW, DE>>
where
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    FromTraceLde,
    AfterTraceCommitment,
    FromQuotient(ScratchMatrixStore<P::Word>),
    FromQuotientLdes(Vec<ResourceBoundedMatrix<PW, DE, P>>),
}

impl<const PW: usize, const DE: usize, P: DurableFieldProfile<PW, DE>>
    TraceLdeContinuation<PW, DE, P>
where
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    fn skips_trace_commitment_checkpoint(&self) -> bool {
        !matches!(self, Self::FromTraceLde)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResumedProofV1 {
    pub workload_id: String,
    pub logical_rows: u64,
    pub public_values: Vec<u64>,
    pub resource_policy: ResourcePolicyV1,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CheckpointInspectionV1 {
    pub completed_phase: PipelinePhaseV1,
    pub artifact_count: usize,
}

struct ValidatedCheckpointV1 {
    manifest: CheckpointManifestV2,
    descriptor: ResumeDescriptorV1,
    job_dir: PathBuf,
}

/// A mode-aware plan for a statically linked or declarative workload.
///
/// Auto selection is always based on the conventional estimate. The selected
/// mode is then preflighted against its own estimate, so the smaller resident
/// footprint of the scratch path can never cause Auto to reselect memory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResourceExecutionPlanV1 {
    pub selected_mode: ExecutionMode,
    pub conventional_estimate: ResourceEstimate,
    pub bounded_estimate: ResourceEstimate,
    pub preflight: PreflightReport,
}

/// Proof bytes together with the mode selected by [`plan_resource_workload`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlannedResourceProofV1 {
    pub selected_mode: ExecutionMode,
    pub proof_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum ProverEventV1 {
    ResourceEstimate {
        estimate: ResourceEstimate,
    },
    Phase {
        phase: PipelinePhaseV1,
        completed_phases: u32,
        total_phases: u32,
        checkpoint_path: Option<PathBuf>,
        resource_usage: ResourceUsageV1,
    },
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct ResourceUsageV1 {
    pub scratch_bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resident_bytes: Option<u64>,
}

/// Conservative, mode-aware full-pipeline estimate for the two frozen CLI
/// workloads. Scratch estimates use the AIR quotient degree calculation from
/// the prover; memory/eligible Auto jobs use the conventional pipeline model.
pub fn estimate_builtin_manifest(
    manifest: &crate::contracts::WorkloadManifestV1,
) -> Result<ResourceEstimate> {
    manifest
        .validate()
        .map_err(|_| BoundedProverError::UnsupportedProfile)?;
    let rows = usize::try_from(manifest.logical_rows)
        .map_err(|_| BoundedProverError::UnsupportedProfile)?;
    match manifest.workload_id {
        crate::contracts::WorkloadId::Fibonacci
            if crate::prover::uses_in_memory_pipeline(&manifest.resource_policy, rows, 2, 1) =>
        {
            Ok(crate::prover::conventional_pipeline_estimate(
                rows, 2, 1, 8, 16,
            ))
        }
        crate::contracts::WorkloadId::Poseidon2Goldilocks
            if crate::prover::uses_in_memory_pipeline(&manifest.resource_policy, rows, 180, 2) =>
        {
            Ok(crate::prover::conventional_pipeline_estimate(
                rows, 180, 2, 8, 16,
            ))
        }
        crate::contracts::WorkloadId::Fibonacci => {
            estimate_air_pipeline::<8, 4, GoldilocksProfile, _>(
                &crate::FibonacciAir,
                "fibonacci",
                3,
                rows,
                &manifest.resource_policy,
            )
        }
        crate::contracts::WorkloadId::Poseidon2Goldilocks => {
            estimate_air_pipeline::<8, 4, GoldilocksProfile, _>(
                &crate::poseidon2_goldilocks_air(),
                "poseidon2_goldilocks",
                0,
                rows,
                &manifest.resource_policy,
            )
        }
    }
}

/// Preflight a built-in CLI workload using the same conventional-vs-bounded
/// decision as the prover. Auto must not reselect memory from the smaller
/// scratch-mode estimate.
pub fn preflight_builtin_manifest(
    manifest: &crate::contracts::WorkloadManifestV1,
) -> Result<PreflightReport> {
    manifest
        .validate()
        .map_err(|_| BoundedProverError::UnsupportedProfile)?;
    let rows = usize::try_from(manifest.logical_rows)
        .map_err(|_| BoundedProverError::UnsupportedProfile)?;
    let mode = match manifest.workload_id {
        crate::contracts::WorkloadId::Fibonacci
            if crate::prover::uses_in_memory_pipeline(&manifest.resource_policy, rows, 2, 1) =>
        {
            ExecutionMode::Memory
        }
        crate::contracts::WorkloadId::Poseidon2Goldilocks
            if crate::prover::uses_in_memory_pipeline(&manifest.resource_policy, rows, 180, 2) =>
        {
            ExecutionMode::Memory
        }
        _ => ExecutionMode::Scratch,
    };
    let estimate = estimate_builtin_manifest(manifest)?;
    Ok(manifest
        .resource_policy
        .preflight_for_mode(mode, estimate)?)
}

/// Conservative full-pipeline preflight for a statically linked partner AIR.
/// This uses the same quotient-degree and storage accounting as the bounded
/// prover, without requiring the workload to be registered in the CLI.
pub fn estimate_resource_bounded_workload<W>(
    workload: &W,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    estimate_resource_bounded_workload_with_profile::<8, 4, GoldilocksProfile, W>(workload, policy)
}

/// The profile-generic form of [`estimate_resource_bounded_workload`].
pub fn estimate_resource_bounded_workload_with_profile<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val> + Air<SymbolicAirBuilder<P::Val>>,
{
    let rows =
        usize::try_from(workload.rows()).map_err(|_| BoundedProverError::UnsupportedProfile)?;
    if rows == 0 || !rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let air = workload.air();
    if workload.public_values().len() != air.num_public_values() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    estimate_air_pipeline::<PW, DE, P, _>(
        &air,
        workload.identity().id,
        air.num_public_values(),
        rows,
        policy,
    )
}

/// Conservative resident-memory estimate for the conventional upstream
/// Plonky3 pipeline for any supported resource-bounded workload.
pub fn estimate_resource_conventional_workload<W>(workload: &W) -> Result<ResourceEstimate>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    estimate_resource_conventional_workload_with_profile::<8, 4, GoldilocksProfile, W>(workload)
}

/// The profile-generic form of [`estimate_resource_conventional_workload`].
pub fn estimate_resource_conventional_workload_with_profile<
    const PW: usize,
    const DE: usize,
    P,
    Wk,
>(
    workload: &Wk,
) -> Result<ResourceEstimate>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val> + Air<SymbolicAirBuilder<P::Val>>,
{
    let rows =
        usize::try_from(workload.rows()).map_err(|_| BoundedProverError::UnsupportedProfile)?;
    if rows == 0 || !rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let air = workload.air();
    if air.preprocessed_width() != 0
        || air.num_periodic_columns() != 0
        || workload.public_values().len() != air.num_public_values()
    {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let width = BaseAir::<P::Val>::width(&air);
    let quotient_chunks = quotient_chunks::<PW, DE, P, _>(&air, width, air.num_public_values())?;
    // Profile-derived, NOT Goldilocks' 8/16: this function is generic over P,
    // and passing the Goldilocks widths here made the in-process planner
    // disagree 2x with the shipped `/v1/estimate` model on BabyBear's
    // conventional trace term.
    let field_bytes = <P::Word as CanonicalElement>::WIDTH as u64;
    let ext_field_bytes = field_bytes.saturating_mul(extension_degree::<PW, DE, P>() as u64);
    Ok(crate::prover::conventional_pipeline_estimate(
        rows,
        width as u64,
        quotient_chunks,
        field_bytes,
        ext_field_bytes,
    ))
}

/// Calculate and preflight both supported execution paths, selecting the
/// conventional path for Auto only when its estimated resident peak is at or
/// below 70% of the configured cap.
pub fn plan_resource_workload<W>(
    workload: &W,
    policy: &ResourcePolicyV1,
) -> Result<ResourceExecutionPlanV1>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    plan_resource_workload_with_profile::<8, 4, GoldilocksProfile, W>(workload, policy)
}

/// The profile-generic form of [`plan_resource_workload`].
pub fn plan_resource_workload_with_profile<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
    policy: &ResourcePolicyV1,
) -> Result<ResourceExecutionPlanV1>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val> + Air<SymbolicAirBuilder<P::Val>>,
{
    policy.validate()?;
    let conventional_estimate =
        estimate_resource_conventional_workload_with_profile::<PW, DE, P, Wk>(workload)?;
    let bounded_estimate =
        estimate_resource_bounded_workload_with_profile::<PW, DE, P, Wk>(workload, policy)?;
    let selected_mode = match policy.mode {
        ResourceMode::Memory => ExecutionMode::Memory,
        ResourceMode::Scratch => ExecutionMode::Scratch,
        ResourceMode::Auto
            if conventional_estimate.peak_resident_bytes <= policy.memory_selection_threshold() =>
        {
            ExecutionMode::Memory
        }
        ResourceMode::Auto => ExecutionMode::Scratch,
    };
    let selected_estimate = match selected_mode {
        ExecutionMode::Memory => conventional_estimate.clone(),
        ExecutionMode::Scratch => bounded_estimate.clone(),
    };
    let preflight = policy.preflight_for_mode(selected_mode, selected_estimate)?;
    Ok(ResourceExecutionPlanV1 {
        selected_mode,
        conventional_estimate,
        bounded_estimate,
        preflight,
    })
}

fn quotient_chunks<const PW: usize, const DE: usize, P, A>(
    air: &A,
    width: usize,
    public_values: usize,
) -> Result<u64>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val> + Air<SymbolicAirBuilder<P::Val>>,
{
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: width,
        num_public_values: public_values,
        num_periodic_columns: 0,
        ..Default::default()
    };
    1u64.checked_shl(get_log_num_quotient_chunks::<P::Val, _>(air, layout, 0) as u32)
        .ok_or(BoundedProverError::UnsupportedProfile)
}

fn estimate_air_pipeline<const PW: usize, const DE: usize, P, A>(
    air: &A,
    workload_id: &str,
    public_values: usize,
    rows: usize,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val> + Air<SymbolicAirBuilder<P::Val>>,
{
    let width = BaseAir::<P::Val>::width(air);
    let params = profile_estimate_params::<PW, DE, P>(
        workload_id,
        rows,
        width,
        quotient_chunks::<PW, DE, P, _>(air, width, public_values)?,
        public_values,
        !air.main_next_row_columns().is_empty(),
    );
    crate::estimate_params::estimate_from_params(&params, policy)
}

/// The three byte widths the analytic cost model needs, read off the profile
/// instead of the Goldilocks literals `8`, `16`, `32`.
///
/// `field_bytes` is the durable scratch element width (8 Goldilocks, 4
/// BabyBear — `CanonicalElement::WIDTH`, NOT the permutation width);
/// `ext_field_bytes` is that times the extension degree (16 for both profiles,
/// via 2x8 and 4x4); `digest_bytes` is `DIGEST_ELEMS` times the same element
/// width (32 for both, via 4x8 and 8x4).
fn profile_estimate_params<const PW: usize, const DE: usize, P>(
    workload_id: &str,
    rows: usize,
    width: usize,
    quotient_chunks: u64,
    public_values: usize,
    has_next_row_columns: bool,
) -> crate::estimate_params::EstimateParams
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    let field_bytes = <P::Word as CanonicalElement>::WIDTH as u64;
    crate::estimate_params::EstimateParams {
        workload_id: workload_id.to_string(),
        rows: rows as u64,
        width: width as u64,
        quotient_chunks,
        public_values: public_values as u64,
        has_next_row_columns,
        field_bytes,
        ext_field_bytes: field_bytes * extension_degree::<PW, DE, P>() as u64,
        digest_bytes: field_bytes * DE as u64,
    }
}

#[cfg(test)]
pub(crate) fn estimate_air_pipeline_for_test<W>(
    workload: &W,
    policy: &ResourcePolicyV1,
) -> Result<ResourceEstimate>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    estimate_resource_bounded_workload(workload, policy)
}

#[cfg(test)]
pub(crate) fn params_for_workload_for_test<W>(
    workload: &W,
) -> crate::estimate_params::EstimateParams
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val> + Air<SymbolicAirBuilder<Val>>,
{
    let air = workload.air();
    let width = BaseAir::<Val>::width(&air);
    let public_values = air.num_public_values();
    profile_estimate_params::<8, 4, GoldilocksProfile>(
        workload.identity().id,
        usize::try_from(workload.rows()).unwrap(),
        width,
        quotient_chunks::<8, 4, GoldilocksProfile, _>(&air, width, public_values).unwrap(),
        public_values,
        !air.main_next_row_columns().is_empty(),
    )
}

fn quotient_log_blowup<const PW: usize, const DE: usize, P, A>(
    air: &A,
    width: usize,
    public_values: usize,
) -> usize
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val> + Air<SymbolicAirBuilder<P::Val>>,
{
    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: width,
        num_public_values: public_values,
        num_periodic_columns: 0,
        ..Default::default()
    };
    get_log_num_quotient_chunks::<P::Val, _>(air, layout, 0).max(1)
}

/// `digest_words` is `DIGEST_ELEMS` and `extension_degree` is the challenge
/// field's dimension over the base field; both used to be written as literals
/// (`4` and `2`), correct only for Goldilocks. Passing 4 and 2 reproduces the
/// previous constants exactly.
pub(crate) fn estimated_profile_proof_bytes(
    rows: u64,
    trace_width: u64,
    quotient_chunks: u64,
    digest_words: u64,
    extension_degree: u64,
) -> u64 {
    let log_squared_bytes = PROFILE_FRI_QUERY_COUNT * digest_words * MAX_POSTCARD_U64_BYTES / 2;
    let log_bytes = PROFILE_FRI_QUERY_COUNT * digest_words * MAX_POSTCARD_U64_BYTES * 3;
    let extra_quotient_chunk_bytes =
        PROFILE_FRI_QUERY_COUNT * extension_degree * MAX_POSTCARD_U64_BYTES;
    let log_rows = rows.trailing_zeros() as u64;
    log_squared_bytes
        .saturating_mul(log_rows.saturating_mul(log_rows))
        .saturating_add(log_bytes.saturating_mul(log_rows))
        .saturating_add(PROFILE_PROOF_FIXED_BYTES)
        .saturating_add(PROFILE_PROOF_TRACE_COLUMN_BYTES.saturating_mul(trace_width))
        .saturating_add(
            extra_quotient_chunk_bytes.saturating_mul(quotient_chunks.saturating_sub(1)),
        )
}

pub(crate) fn merkle_payload_bytes(leaves: u64) -> u64 {
    leaves
        .saturating_mul(2)
        .saturating_sub(1)
        .saturating_mul(32)
}

pub(crate) fn merkle_store_count(leaves: u64) -> u64 {
    u64::from(leaves.trailing_zeros()).saturating_add(1)
}

pub(crate) fn fri_mmcs_payload_bytes(rows: u64) -> u64 {
    let mut leaves = rows;
    let mut total = 0u64;
    while leaves >= 2 {
        total = total.saturating_add(merkle_payload_bytes(leaves));
        leaves /= 2;
    }
    total
}

pub(crate) fn fri_mmcs_store_count(log_rows: u64) -> u64 {
    // Trees have N, N/2, ..., 2 leaves. A tree with 2^k leaves owns k + 1
    // scratch stores, so the total is sum(k + 1), k=1..log2(N).
    log_rows
        .saturating_mul(log_rows.saturating_add(1))
        .saturating_div(2)
        .saturating_add(log_rows)
}

/// `digest_elems`, `extension_degree`, and `challenger_snapshot_bytes` used to
/// be the literals `4`, `2`, and `MAX_CHALLENGER_SNAPSHOT_BYTES`. They are
/// arguments so `estimate_params.rs` — which is deliberately field-agnostic and
/// carries only byte widths — can derive the first two from
/// `digest_bytes / field_bytes` and `ext_field_bytes / field_bytes`. Passing
/// `4, 2, GOLDILOCKS_CHALLENGER_SNAPSHOT_BYTES` reproduces the previous
/// behavior byte for byte.
#[allow(clippy::too_many_arguments)]
pub(crate) fn estimated_atomic_checkpoint_bytes(
    policy: &ResourcePolicyV1,
    workload_id: &str,
    rows: u64,
    trace_width: usize,
    public_value_count: usize,
    quotient_chunks: u64,
    has_trace_next: bool,
    proof_bytes: u64,
    digest_elems: usize,
    extension_degree: usize,
    challenger_snapshot_bytes: usize,
) -> Result<u64> {
    let fri_rounds = rows.trailing_zeros() as usize;
    let quotient_chunks =
        usize::try_from(quotient_chunks).map_err(|_| BoundedProverError::UnsupportedProfile)?;
    let maximum = u64::MAX;
    let widest_challenge = vec![maximum; extension_degree];
    let widest_digest = vec![maximum; digest_elems];
    let fri_state = FriResumeStateV1 {
        trace_local: vec![widest_challenge.clone(); trace_width],
        trace_next: has_trace_next.then(|| vec![widest_challenge.clone(); trace_width]),
        quotient_chunks: vec![vec![widest_challenge.clone()]; quotient_chunks],
        commitments: vec![vec![widest_digest.clone()]; fri_rounds],
        commit_pow_witnesses: vec![maximum; fri_rounds],
        log_arities: vec![u8::MAX; fri_rounds],
    };
    let descriptor = ResumeDescriptorV1 {
        schema_version: 1,
        workload_id: workload_id.into(),
        workload_version: u32::MAX,
        logical_rows: rows,
        public_values: vec![maximum; public_value_count],
        resource_policy: policy.clone(),
        trace_commitment: Some(vec![widest_digest.clone()]),
        quotient_commitment: Some(vec![widest_digest]),
        fri_state: Some(fri_state),
    };
    let resume_payload = serde_json::to_vec(&descriptor)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;

    let lde_rows = rows.saturating_mul((quotient_chunks as u64).max(2));
    let mut artifacts = Vec::with_capacity(
        1usize
            .saturating_add(quotient_chunks)
            .saturating_add(fri_rounds)
            .saturating_add(2),
    );
    artifacts.push(sizing_artifact(
        PipelineArtifactKindV1::TraceLde,
        None,
        lde_rows,
        trace_width,
        8,
        "dft",
        "dft-a.bin",
    ));
    for ordinal in 0..quotient_chunks {
        artifacts.push(sizing_artifact(
            PipelineArtifactKindV1::QuotientLde,
            Some(ordinal as u32),
            lde_rows,
            2,
            8,
            "dft",
            "dft-a.bin",
        ));
    }
    let mut fri_len = lde_rows;
    for ordinal in 0..=fri_rounds {
        artifacts.push(sizing_artifact(
            PipelineArtifactKindV1::FriLayer,
            Some(ordinal as u32),
            fri_len,
            2,
            8,
            "fri-layer",
            "fri-layer.bin",
        ));
        fri_len = (fri_len / 2).max(1);
    }

    let identity_hash = [u8::MAX; 32];
    let challenger_state = vec![u8::MAX; challenger_snapshot_bytes];
    let previous = CheckpointManifestV2 {
        schema_version: 2,
        backend_hash: identity_hash,
        profile_hash: identity_hash,
        release_hash: identity_hash,
        dependency_lock_hash: identity_hash,
        workload_hash: identity_hash,
        input_hash: identity_hash,
        resource_policy_hash: identity_hash,
        completed_phase: if fri_rounds == 0 {
            PipelinePhaseV1::Openings
        } else {
            PipelinePhaseV1::FriLayer {
                layer: fri_rounds.saturating_sub(1) as u32,
            }
        },
        challenger_state: challenger_state.clone(),
        resume_payload: resume_payload.clone(),
        artifacts: artifacts.clone(),
    };
    artifacts.push(sizing_artifact(
        PipelineArtifactKindV1::ProofBundle,
        None,
        proof_bytes,
        1,
        1,
        "proof",
        "proof-bundle.bin",
    ));
    let replacement = CheckpointManifestV2 {
        completed_phase: PipelinePhaseV1::ProofAssembly,
        challenger_state,
        resume_payload,
        artifacts,
        ..previous.clone()
    };
    let previous_bytes = serde_json::to_vec_pretty(&previous)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?
        .len() as u64;
    let replacement_bytes = serde_json::to_vec_pretty(&replacement)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?
        .len() as u64;
    Ok(previous_bytes.saturating_add(replacement_bytes))
}

#[allow(clippy::too_many_arguments)]
fn sizing_artifact(
    kind: PipelineArtifactKindV1,
    ordinal: Option<u32>,
    rows: u64,
    columns: usize,
    element_width: usize,
    directory_prefix: &str,
    file_name: &str,
) -> CheckpointArtifactV2 {
    CheckpointArtifactV2 {
        kind,
        ordinal,
        relative_path: PathBuf::from(format!(
            "artifacts/{directory_prefix}-{MAX_ARTIFACT_PATH_PID}-{MAX_ARTIFACT_PATH_COUNTER}/{file_name}"
        )),
        digest: ArtifactDigest {
            rows,
            columns,
            element_width,
            blake3: [u8::MAX; 32],
        },
    }
}

/// Hook used at durable phase boundaries. Release binaries always use
/// `NoopFailureInjector`; the fault-injection feature provides an aborting
/// implementation for subprocess recovery tests.
pub trait FailureInjector {
    fn after_checkpoint(&self, phase: &PipelinePhaseV1);
}

#[derive(Clone, Copy, Debug, Default)]
pub struct NoopFailureInjector;

impl FailureInjector for NoopFailureInjector {
    fn after_checkpoint(&self, _phase: &PipelinePhaseV1) {}
}

#[cfg(feature = "fault-injection")]
#[derive(Clone, Copy, Debug, Default)]
pub struct EnvironmentAbortFailureInjector;

#[cfg(feature = "fault-injection")]
impl FailureInjector for EnvironmentAbortFailureInjector {
    fn after_checkpoint(&self, phase: &PipelinePhaseV1) {
        if std::env::var("TINYZKP_FAIL_AFTER").as_deref() == Ok(phase.to_string().as_str()) {
            std::process::abort();
        }
    }
}

/// Complete resource-bounded orchestration for the frozen Goldilocks profile.
/// The returned bytes deserialize as the official Plonky3 proof type.
pub fn prove_resource_with_policy<W>(
    workload: &W,
    policy: &ResourcePolicyV1,
) -> Result<PlannedResourceProofV1>
where
    W: ResourceBoundedWorkload + Sync,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<VerifierConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
{
    prove_resource_with_policy_observed_with_cancellation(
        workload,
        policy,
        CancellationToken::new(),
        |_| {},
    )
}

/// Execute a statically linked or declarative workload according to its
/// resource policy. Memory mode uses the unmodified upstream prover; scratch
/// mode uses the durable bounded pipeline and is therefore resumable.
pub fn prove_resource_with_policy_observed_with_cancellation<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    cancellation: CancellationToken,
    observe: Observe,
) -> Result<PlannedResourceProofV1>
where
    W: ResourceBoundedWorkload + Sync,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<VerifierConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
    Observe: FnMut(&ProverEventV1),
{
    prove_resource_with_policy_observed_with_cancellation_inner(
        workload,
        policy,
        None,
        cancellation,
        observe,
    )
}

/// Execute with an exact caller-owned checkpoint directory. In bounded mode,
/// the durable checkpoint is always `<checkpoint_dir>/checkpoint.json`; the
/// implementation never scans for or invents another job directory.
pub fn prove_resource_with_policy_observed_with_cancellation_at_checkpoint_dir<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    checkpoint_dir: &Path,
    cancellation: CancellationToken,
    observe: Observe,
) -> Result<PlannedResourceProofV1>
where
    W: ResourceBoundedWorkload + Sync,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<VerifierConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
    Observe: FnMut(&ProverEventV1),
{
    prove_resource_with_policy_observed_with_cancellation_inner(
        workload,
        policy,
        Some(checkpoint_dir),
        cancellation,
        observe,
    )
}

fn prove_resource_with_policy_observed_with_cancellation_inner<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    checkpoint_dir: Option<&Path>,
    cancellation: CancellationToken,
    mut observe: Observe,
) -> Result<PlannedResourceProofV1>
where
    W: ResourceBoundedWorkload + Sync,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<VerifierConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
    Observe: FnMut(&ProverEventV1),
{
    let plan = plan_resource_workload(workload, policy)?;
    match plan.selected_mode {
        ExecutionMode::Memory => {
            check_cancelled(&cancellation)?;
            observe(&ProverEventV1::ResourceEstimate {
                estimate: plan.conventional_estimate,
            });
            let proof_bytes = rayon::ThreadPoolBuilder::new()
                .num_threads(policy.max_threads)
                .build()
                .map_err(|_| BoundedProverError::UnsupportedProfile)?
                .install(|| prove_resource_reference(workload))?;
            check_cancelled(&cancellation)?;
            observe(&ProverEventV1::Phase {
                phase: PipelinePhaseV1::ProofAssembly,
                completed_phases: 1,
                total_phases: 1,
                checkpoint_path: None,
                resource_usage: measure_resource_usage(None),
            });
            Ok(PlannedResourceProofV1 {
                selected_mode: ExecutionMode::Memory,
                proof_bytes,
            })
        }
        ExecutionMode::Scratch => {
            let proof_bytes = match checkpoint_dir {
                Some(checkpoint_dir) => {
                    prove_resource_bounded_observed_with_cancellation_at_checkpoint_dir(
                        workload,
                        policy,
                        checkpoint_dir,
                        cancellation,
                        &mut observe,
                    )?
                }
                None => prove_resource_bounded_observed_with_cancellation(
                    workload,
                    policy,
                    cancellation,
                    &mut observe,
                )?,
            };
            Ok(PlannedResourceProofV1 {
                selected_mode: ExecutionMode::Scratch,
                proof_bytes,
            })
        }
    }
}

pub fn prove_resource_bounded<W>(workload: &W, policy: &ResourcePolicyV1) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
{
    prove_resource_bounded_observed(workload, policy, |_| {})
}

/// The profile-generic form of [`prove_resource_bounded`]: the durable,
/// resource-bounded pipeline at any [`DurableFieldProfile`].
///
/// Profiles with no durable checkpoint representation (everything except
/// Goldilocks today — see `DurableFieldProfile::capture_challenger`) prove
/// single-shot: no checkpoint is written, so no resume is offered, and a
/// half-finished job cannot be restarted.
pub fn prove_resource_bounded_with_profile<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
    policy: &ResourcePolicyV1,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    prove_resource_bounded_observed_with_control_inner::<PW, DE, P, Wk, _>(
        workload,
        policy,
        None,
        CancellationToken::new(),
        default_failure_injector(),
        |_| {},
    )
}

pub fn prove_resource_bounded_observed<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    observe: Observe,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    Observe: FnMut(&ProverEventV1),
{
    prove_resource_bounded_observed_with_cancellation(
        workload,
        policy,
        CancellationToken::new(),
        observe,
    )
}

pub fn prove_resource_bounded_observed_with_cancellation<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    cancellation: CancellationToken,
    observe: Observe,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    Observe: FnMut(&ProverEventV1),
{
    prove_resource_bounded_observed_with_control(
        workload,
        policy,
        cancellation,
        default_failure_injector(),
        observe,
    )
}

pub fn prove_resource_bounded_observed_with_cancellation_at_checkpoint_dir<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    checkpoint_dir: &Path,
    cancellation: CancellationToken,
    observe: Observe,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    Observe: FnMut(&ProverEventV1),
{
    prove_resource_bounded_observed_with_control_inner(
        workload,
        policy,
        Some(checkpoint_dir),
        cancellation,
        default_failure_injector(),
        observe,
    )
}

/// Executes the bounded prover with explicit cancellation, phase observation,
/// and durable-boundary fault injection. Release callers use the wrapper above,
/// which supplies [`NoopFailureInjector`]; tests can inject deterministic faults
/// without relying on process-global state.
pub fn prove_resource_bounded_observed_with_control<W, Observe>(
    workload: &W,
    policy: &ResourcePolicyV1,
    cancellation: CancellationToken,
    failure_injector: &dyn FailureInjector,
    observe: Observe,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    Observe: FnMut(&ProverEventV1),
{
    prove_resource_bounded_observed_with_control_inner(
        workload,
        policy,
        None,
        cancellation,
        failure_injector,
        observe,
    )
}

#[allow(clippy::too_many_arguments)]
fn prove_resource_bounded_observed_with_control_inner<
    const PW: usize,
    const DE: usize,
    P,
    Wk,
    Observe,
>(
    workload: &Wk,
    policy: &ResourcePolicyV1,
    checkpoint_dir: Option<&Path>,
    cancellation: CancellationToken,
    failure_injector: &dyn FailureInjector,
    mut observe: Observe,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
    Observe: FnMut(&ProverEventV1),
{
    policy.validate()?;
    check_cancelled(&cancellation)?;
    let rows =
        usize::try_from(workload.rows()).map_err(|_| BoundedProverError::UnsupportedProfile)?;
    if rows == 0 || !rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let air = workload.air();
    if air.preprocessed_width() != 0 || air.num_periodic_columns() != 0 {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let expected_public_values = workload.public_values();
    let expected_input_digest = workload.input_digest();
    if expected_public_values.len() != air.num_public_values() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let width = BaseAir::<P::Val>::width(&air);
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(&air, width, air.num_public_values());
    let full_estimate = estimate_air_pipeline::<PW, DE, P, _>(
        &air,
        workload.identity().id,
        air.num_public_values(),
        rows,
        policy,
    )?;
    observe(&ProverEventV1::ResourceEstimate {
        estimate: full_estimate.clone(),
    });
    policy.preflight_for_mode(ExecutionMode::Scratch, full_estimate)?;
    // Binary FRI performs one round per trace-degree bit; the final evaluation
    // vector retains exactly `blowup * final_poly_len` values.
    let fri_rounds = rows.trailing_zeros();
    let total_phases = 8 + fri_rounds;
    let mut completed_phases = 0u32;
    let job_dir = match checkpoint_dir {
        Some(checkpoint_dir) => create_exact_job_dir(checkpoint_dir)?,
        None => create_job_dir(&policy.scratch_dir)?,
    };
    let mut local_policy = policy.clone();
    local_policy.scratch_dir = job_dir.join("artifacts");
    create_private_dir(&local_policy.scratch_dir)?;
    let result = (|| {
        let challenger: ProfileChallengerFor<PW, DE, P> = StarkGenericConfig::initialise_challenger(
            &make_bounded_verifier_config::<PW, DE, P>(log_blowup),
        );
        let mut trace_store = ScratchMatrixStore::<P::Word>::create(
            &local_policy.scratch_dir,
            "trace.bin",
            rows as u64,
            width,
        )?;
        let block_rows = local_policy
            .tile_rows(<P::Word as CanonicalElement>::WIDTH, width)?
            .min(rows);
        let generated = if policy.max_threads == 1 {
            workload.write_trace(&mut trace_store, block_rows)?
        } else {
            rayon::ThreadPoolBuilder::new()
                .num_threads(policy.max_threads)
                .build()
                .map_err(|_| BoundedProverError::UnsupportedProfile)?
                .install(|| workload.write_trace(&mut trace_store, block_rows))?
        };
        if generated.identity != workload.identity()
            || generated.rows != workload.rows()
            || generated.columns != width
            || generated.public_values != expected_public_values
            || generated.input_digest != expected_input_digest
        {
            return Err(BoundedProverError::Workload(WorkloadError::InvalidShape));
        }
        let public_values = generated.public_values;
        let trace_artifact = checkpoint_artifact(
            &job_dir,
            PipelineArtifactKindV1::Trace,
            None,
            trace_store.path(),
            trace_store
                .digest()
                .ok_or(BoundedProverError::InvalidCheckpoint)?,
        )?;
        let trace_checkpoint = write_phase_checkpoint::<PW, DE, P, Wk>(
            workload,
            policy,
            &job_dir,
            generated.input_digest,
            &public_values,
            PipelinePhaseV1::Trace,
            None,
            &challenger,
            vec![trace_artifact],
        )?;
        emit_phase(
            &mut observe,
            PipelinePhaseV1::Trace,
            &mut completed_phases,
            total_phases,
            trace_checkpoint,
            &job_dir,
        );
        failure_injector.after_checkpoint(&PipelinePhaseV1::Trace);
        check_cancelled(&cancellation)?;

        let dft = ResourceBoundedDft::<PW, DE, P>::new(local_policy.clone())?;
        let trace_lde =
            dft.try_coset_lde_block_matrix(&trace_store, log_blowup, P::Val::GENERATOR)?;
        trace_lde.retain_for_resume();
        let (trace_lde_path, trace_lde_digest) = trace_lde.scratch_artifact()?;
        let trace_lde_artifact = checkpoint_artifact(
            &job_dir,
            PipelineArtifactKindV1::TraceLde,
            None,
            trace_lde_path,
            trace_lde_digest,
        )?;
        let trace_lde_checkpoint = write_phase_checkpoint::<PW, DE, P, Wk>(
            workload,
            policy,
            &job_dir,
            generated.input_digest,
            &public_values,
            PipelinePhaseV1::TraceLde,
            None,
            &challenger,
            vec![trace_lde_artifact.clone()],
        )?;
        trace_store.remove()?;
        emit_phase(
            &mut observe,
            PipelinePhaseV1::TraceLde,
            &mut completed_phases,
            total_phases,
            trace_lde_checkpoint,
            &job_dir,
        );
        failure_injector.after_checkpoint(&PipelinePhaseV1::TraceLde);
        check_cancelled(&cancellation)?;

        continue_from_trace_lde::<PW, DE, P, Wk, _>(
            workload,
            &air,
            rows,
            public_values,
            generated.input_digest,
            trace_lde,
            TraceLdeContinuation::FromTraceLde,
            None,
            None,
            &cancellation,
            policy,
            &job_dir,
            &local_policy,
            &mut observe,
            &mut completed_phases,
            total_phases,
            failure_injector,
        )
    })();
    let resumable = job_dir.join("checkpoint.json").is_file();
    let _ = cleanup_job_directory(
        &job_dir,
        policy.checkpoint_policy,
        result.is_ok(),
        resumable,
    );
    result
}

#[allow(clippy::too_many_arguments)]
fn continue_from_trace_lde<const PW: usize, const DE: usize, P, Wk, A>(
    workload: &Wk,
    air: &A,
    rows: usize,
    public_values: Vec<P::Val>,
    input_digest: [u8; 32],
    trace_lde: ResourceBoundedMatrix<PW, DE, P>,
    continuation: TraceLdeContinuation<PW, DE, P>,
    expected_trace_commitment: Option<&Vec<Vec<u64>>>,
    expected_challenger: Option<&ChallengerSnapshotV1>,
    cancellation: &CancellationToken,
    policy: &ResourcePolicyV1,
    job_dir: &Path,
    local_policy: &ResourcePolicyV1,
    observe: &mut dyn FnMut(&ProverEventV1),
    completed_phases: &mut u32,
    total_phases: u32,
    failure_injector: &dyn FailureInjector,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    A: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let width = BaseAir::<P::Val>::width(air);
    trace_lde.retain_for_resume();
    let (trace_lde_path, trace_lde_digest) = trace_lde.scratch_artifact()?;
    let trace_lde_artifact = checkpoint_artifact(
        job_dir,
        PipelineArtifactKindV1::TraceLde,
        None,
        trace_lde_path,
        trace_lde_digest,
    )?;
    let input_mmcs = make_durable_mmcs::<PW, DE, P>(local_policy.clone());
    let (trace_commit, trace_data) = input_mmcs.try_commit_bit_reversed(vec![trace_lde.clone()])?;
    if expected_trace_commitment
        .is_some_and(|expected| *expected != encode_commitment::<PW, DE, P>(&trace_commit))
    {
        return Err(BoundedProverError::InvalidCheckpoint);
    }

    let log_degree = rows.trailing_zeros() as usize;
    let trace_domain = p3_field::coset::TwoAdicMultiplicativeCoset::new(P::Val::ONE, log_degree)
        .ok_or(BoundedProverError::UnsupportedProfile)?;
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(air, width, public_values.len());
    let lde_rows = rows * (1usize << log_blowup);
    let mut challenger: ProfileChallengerFor<PW, DE, P> = StarkGenericConfig::initialise_challenger(
        &make_bounded_verifier_config::<PW, DE, P>(log_blowup),
    );
    challenger.observe(P::Val::from_u8(log_degree as u8));
    challenger.observe(P::Val::from_u8(log_degree as u8));
    challenger.observe(P::Val::ZERO);
    challenger.observe(trace_commit.clone());
    challenger.observe_slice(&public_values);
    let constraint_alpha: P::Challenge = challenger.sample_algebra_element();
    // `P::capture_challenger` returning `None` (a profile with no durable
    // checkpoint format) while a checkpoint claims an expected transcript is a
    // contradiction, so this comparison fails closed rather than skipping.
    if expected_challenger
        .is_some_and(|expected| P::capture_challenger(&challenger).as_ref() != Some(expected))
    {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    if !continuation.skips_trace_commitment_checkpoint() {
        let trace_commitment_checkpoint = write_phase_checkpoint::<PW, DE, P, Wk>(
            workload,
            policy,
            job_dir,
            input_digest,
            &public_values,
            PipelinePhaseV1::TraceCommitment,
            Some(&trace_commit),
            &challenger,
            vec![trace_lde_artifact.clone()],
        )?;
        emit_phase(
            observe,
            PipelinePhaseV1::TraceCommitment,
            completed_phases,
            total_phases,
            trace_commitment_checkpoint,
            job_dir,
        );
        failure_injector.after_checkpoint(&PipelinePhaseV1::TraceCommitment);
    }
    check_cancelled(cancellation)?;

    let layout = AirLayout {
        preprocessed_width: 0,
        main_width: width,
        num_public_values: public_values.len(),
        num_periodic_columns: 0,
        ..Default::default()
    };
    let log_num_quotient_chunks = get_log_num_quotient_chunks::<P::Val, _>(air, layout, 0);
    let num_quotient_chunks = 1usize << log_num_quotient_chunks;
    let quotient_domain = trace_domain.create_disjoint_domain(
        1usize
            .checked_shl((log_degree + log_num_quotient_chunks) as u32)
            .ok_or(BoundedProverError::UnsupportedProfile)?,
    );
    let (mut quotient_values, saved_quotient_ldes) = match continuation {
        TraceLdeContinuation::FromQuotient(values) => (Some(values), None),
        TraceLdeContinuation::FromQuotientLdes(ldes) => (None, Some(ldes)),
        TraceLdeContinuation::FromTraceLde | TraceLdeContinuation::AfterTraceCommitment => {
            (None, None)
        }
    };
    let resumed_from_quotient = quotient_values.is_some();
    let resumed_from_quotient_ldes = saved_quotient_ldes.is_some();
    if let Some(values) = quotient_values.as_ref() {
        // The column count is the EXTENSION DEGREE — the number of base-field
        // coordinates one quotient value occupies — not an arity. It was
        // written as a literal `2`, which is correct only for Goldilocks;
        // BabyBear stores 4 columns and this check would have rejected every
        // valid BabyBear resume.
        if values.rows() != quotient_domain.size() as u64
            || values.columns() != extension_degree::<PW, DE, P>()
        {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
    } else if !resumed_from_quotient_ldes {
        // `P` is not inferable from the arguments (`P::Word` is an associated
        // type, so `ScratchMatrixStore<P::Word>` does not pin it), so the
        // active profile is named explicitly.
        quotient_values = Some(stream_quotient_values::<PW, DE, P, _, _>(
            air,
            &public_values,
            trace_domain,
            quotient_domain,
            &trace_lde,
            constraint_alpha,
            local_policy,
            &local_policy.scratch_dir,
            "quotient.bin",
        )?);
    }
    if !resumed_from_quotient && !resumed_from_quotient_ldes {
        let values = quotient_values
            .as_ref()
            .ok_or(BoundedProverError::InvalidCheckpoint)?;
        let quotient_artifact = checkpoint_artifact(
            job_dir,
            PipelineArtifactKindV1::Quotient,
            None,
            values.path(),
            values
                .digest()
                .ok_or(BoundedProverError::InvalidCheckpoint)?,
        )?;
        let quotient_checkpoint = write_phase_checkpoint::<PW, DE, P, Wk>(
            workload,
            policy,
            job_dir,
            input_digest,
            &public_values,
            PipelinePhaseV1::Quotient,
            Some(&trace_commit),
            &challenger,
            vec![trace_lde_artifact.clone(), quotient_artifact],
        )?;
        emit_phase(
            observe,
            PipelinePhaseV1::Quotient,
            completed_phases,
            total_phases,
            quotient_checkpoint,
            job_dir,
        );
        failure_injector.after_checkpoint(&PipelinePhaseV1::Quotient);
        check_cancelled(cancellation)?;
    }

    let quotient_ldes = if let Some(ldes) = saved_quotient_ldes {
        // Same extension-degree column count as the quotient store above.
        if ldes.len() != num_quotient_chunks
            || ldes.iter().any(|matrix| {
                matrix.height() != lde_rows || matrix.width() != extension_degree::<PW, DE, P>()
            })
        {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        ldes
    } else {
        let dft = ResourceBoundedDft::<PW, DE, P>::new(local_policy.clone())?;
        build_quotient_chunk_ldes::<PW, DE, P>(
            quotient_domain,
            quotient_values
                .as_ref()
                .ok_or(BoundedProverError::InvalidCheckpoint)?,
            num_quotient_chunks,
            log_blowup,
            &dft,
            local_policy,
            &local_policy.scratch_dir,
        )?
    };
    if !resumed_from_quotient_ldes {
        let mut quotient_lde_artifacts = vec![trace_lde_artifact];
        for (ordinal, matrix) in quotient_ldes.iter().enumerate() {
            matrix.retain_for_resume();
            let (path, digest) = matrix.scratch_artifact()?;
            quotient_lde_artifacts.push(checkpoint_artifact(
                job_dir,
                PipelineArtifactKindV1::QuotientLde,
                Some(ordinal as u32),
                path,
                digest,
            )?);
        }
        let quotient_lde_checkpoint = write_phase_checkpoint::<PW, DE, P, Wk>(
            workload,
            policy,
            job_dir,
            input_digest,
            &public_values,
            PipelinePhaseV1::QuotientLde,
            Some(&trace_commit),
            &challenger,
            quotient_lde_artifacts,
        )?;
        quotient_values
            .take()
            .ok_or(BoundedProverError::InvalidCheckpoint)?
            .remove()?;
        emit_phase(
            observe,
            PipelinePhaseV1::QuotientLde,
            completed_phases,
            total_phases,
            quotient_lde_checkpoint,
            job_dir,
        );
        failure_injector.after_checkpoint(&PipelinePhaseV1::QuotientLde);
        check_cancelled(cancellation)?;
    }

    let (quotient_commit, quotient_data) =
        input_mmcs.try_commit_bit_reversed(quotient_ldes.clone())?;
    challenger.observe(quotient_commit.clone());
    let mut checkpoint = write_quotient_checkpoint::<PW, DE, P, Wk>(
        workload,
        policy,
        job_dir,
        input_digest,
        &public_values,
        &trace_lde,
        &quotient_ldes,
        &trace_commit,
        &quotient_commit,
        &challenger,
    )?;
    emit_phase(
        observe,
        PipelinePhaseV1::QuotientCommitment,
        completed_phases,
        total_phases,
        checkpoint
            .as_ref()
            .map(|context| context.root.join("checkpoint.json")),
        job_dir,
    );
    failure_injector.after_checkpoint(&PipelinePhaseV1::QuotientCommitment);
    check_cancelled(cancellation)?;

    finish_after_quotient::<PW, DE, P, _>(
        air,
        rows,
        trace_domain,
        public_values,
        trace_lde,
        quotient_ldes,
        input_mmcs,
        trace_data,
        quotient_data,
        trace_commit,
        quotient_commit,
        challenger,
        local_policy,
        checkpoint.as_mut(),
        cancellation,
        observe,
        completed_phases,
        total_phases,
        failure_injector,
    )
}

/// Conventional upstream prover for a statically linked partner workload.
/// This exists for evaluation/differential evidence; it intentionally owns the
/// full trace and is not the production bounded path.
pub fn prove_resource_reference<W>(workload: &W) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<ProverConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<VerifierConstraintFolder<'a, GoldilocksConfig<Radix2DitParallel<Val>>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, Val>>,
{
    prove_resource_reference_with_profile::<8, 4, GoldilocksProfile, W>(workload)
}

/// The profile-generic form of [`prove_resource_reference`].
pub fn prove_resource_reference_with_profile<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<ProverConstraintFolder<'a, OfficialConfig<PW, DE, P>>>
        + for<'a> Air<VerifierConstraintFolder<'a, OfficialConfig<PW, DE, P>>>
        + for<'a> Air<p3_air::DebugConstraintBuilder<'a, P::Val>>,
{
    let rows =
        usize::try_from(workload.rows()).map_err(|_| BoundedProverError::UnsupportedProfile)?;
    if rows == 0 || !rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let air = workload.air();
    let expected_public_values = workload.public_values();
    let expected_input_digest = workload.input_digest();
    if expected_public_values.len() != air.num_public_values() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let width = BaseAir::<P::Val>::width(&air);
    let mut store = MemoryMatrix::<P::Word>::preallocated(rows as u64, width)?;
    let generated = workload.write_trace(&mut store, rows)?;
    if generated.identity != workload.identity()
        || generated.rows != workload.rows()
        || generated.columns != width
        || generated.public_values != expected_public_values
        || generated.input_digest != expected_input_digest
    {
        return Err(BoundedProverError::Workload(WorkloadError::InvalidShape));
    }
    let mut words = vec![P::Word::default(); rows.saturating_mul(width)];
    store.read_rows(0, rows, &mut words)?;
    let trace = RowMajorMatrix::new(words.into_iter().map(Into::into).collect(), width);
    let log_blowup =
        quotient_log_blowup::<PW, DE, P, _>(&air, width, generated.public_values.len());
    let config = crate::prover::make_config_with_log_blowup::<PW, DE, P, _>(
        Radix2DitParallel::<P::Val>::default(),
        log_blowup,
    );
    let proof = prove(&config, &air, trace, &generated.public_values);
    let bytes = postcard::to_allocvec(&proof)
        .map_err(|error| BoundedProverError::Serialization(error.to_string()))?;
    verify(&config, &air, &proof, &generated.public_values)
        .map_err(|error| BoundedProverError::Verification(format!("{error:?}")))?;
    Ok(bytes)
}

/// Verify a serialized official Plonky3 proof for a statically linked partner
/// workload without regenerating or retaining its trace.
pub fn verify_resource_bounded_proof<W>(workload: &W, proof_bytes: &[u8]) -> Result<()>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
{
    verify_resource_bounded_proof_with_profile::<8, 4, GoldilocksProfile, W>(workload, proof_bytes)
}

/// The profile-generic form of [`verify_resource_bounded_proof`]. Decodes into
/// the UNMODIFIED upstream `p3_uni_stark::Proof` for the profile's stock
/// config and hands it to the stock verifier; TinyZKP supplies no verifier.
pub fn verify_resource_bounded_proof_with_profile<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
    proof_bytes: &[u8],
) -> Result<()>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let rows =
        usize::try_from(workload.rows()).map_err(|_| BoundedProverError::UnsupportedProfile)?;
    if rows == 0 || !rows.is_power_of_two() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let public_values = workload.public_values();
    if public_values.len() != workload.air().num_public_values() {
        return Err(BoundedProverError::UnsupportedProfile);
    }
    let air = workload.air();
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
        &air,
        BaseAir::<P::Val>::width(&air),
        public_values.len(),
    );
    let proof: Proof<OfficialConfig<PW, DE, P>> = postcard::from_bytes(proof_bytes)
        .map_err(|error| BoundedProverError::Serialization(error.to_string()))?;
    let config = crate::prover::make_config_with_log_blowup::<PW, DE, P, _>(
        Radix2DitParallel::<P::Val>::default(),
        log_blowup,
    );
    verify(&config, &air, &proof, &public_values)
        .map_err(|error| BoundedProverError::Verification(format!("{error:?}")))
}

#[allow(clippy::too_many_arguments)]
fn finish_after_quotient<const PW: usize, const DE: usize, P, A>(
    air: &A,
    rows: usize,
    trace_domain: p3_field::coset::TwoAdicMultiplicativeCoset<P::Val>,
    public_values: Vec<P::Val>,
    trace_lde: ResourceBoundedMatrix<PW, DE, P>,
    quotient_ldes: Vec<ResourceBoundedMatrix<PW, DE, P>>,
    input_mmcs: DurableInputMmcs<PW, DE, P>,
    trace_data: DurableCommitData<PW, DE, P>,
    quotient_data: DurableCommitData<PW, DE, P>,
    trace_commit: DurableCommitment<PW, DE, P>,
    quotient_commit: DurableCommitment<PW, DE, P>,
    mut challenger: ProfileChallengerFor<PW, DE, P>,
    policy: &ResourcePolicyV1,
    mut checkpoint: Option<&mut ProverCheckpointContext<PW, DE, P>>,
    cancellation: &CancellationToken,
    observe: &mut dyn FnMut(&ProverEventV1),
    completed_phases: &mut u32,
    total_phases: u32,
    failure_injector: &dyn FailureInjector,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let resource_root = policy.scratch_dir.parent().unwrap_or(&policy.scratch_dir);
    let log_degree = rows.trailing_zeros() as usize;
    let zeta: P::Challenge = challenger.sample_algebra_element();
    let zeta_next = trace_domain
        .next_point(zeta)
        .ok_or(BoundedProverError::UnsupportedProfile)?;
    let main_next = !air.main_next_row_columns().is_empty();
    let trace_local = interpolate_standard_lde(&trace_lde, rows, zeta, policy)?;
    let trace_next = if main_next {
        Some(interpolate_standard_lde(
            &trace_lde, rows, zeta_next, policy,
        )?)
    } else {
        None
    };
    let quotient_chunks: Vec<_> = quotient_ldes
        .iter()
        .map(|matrix| interpolate_standard_lde(matrix, rows, zeta, policy))
        .collect::<std::result::Result<_, _>>()?;

    challenger.observe_algebra_slice(&trace_local);
    if let Some(next) = &trace_next {
        challenger.observe_algebra_slice(next);
    }
    for chunk in &quotient_chunks {
        challenger.observe_algebra_slice(chunk);
    }
    let batching_alpha: P::Challenge = challenger.sample_algebra_element();

    let mut trace_points = vec![(zeta, trace_local.clone())];
    if let Some(next) = &trace_next {
        trace_points.push((zeta_next, next.clone()));
    }
    let mut reduction_inputs = vec![MatrixOpening {
        matrix: &trace_lde,
        points_and_values: trace_points,
    }];
    reduction_inputs.extend(
        quotient_ldes
            .iter()
            .zip(&quotient_chunks)
            .map(|(matrix, opening)| MatrixOpening {
                matrix,
                points_and_values: vec![(zeta, opening.clone())],
            }),
    );
    let reduced = build_reduced_opening_layer(&reduction_inputs, batching_alpha, policy)?;
    let openings_checkpoint = if let Some(context) = checkpoint.as_deref_mut() {
        context.set_openings(&trace_local, trace_next.as_deref(), &quotient_chunks)?;
        context.record_openings(&reduced, &challenger, failure_injector)?;
        Some(context.root.join("checkpoint.json"))
    } else {
        None
    };
    emit_phase(
        observe,
        PipelinePhaseV1::Openings,
        completed_phases,
        total_phases,
        openings_checkpoint,
        resource_root,
    );
    check_cancelled(cancellation)?;

    let challenge_mmcs = ExtensionMmcs::new(input_mmcs.clone());
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
        air,
        BaseAir::<P::Val>::width(air),
        public_values.len(),
    );
    let mut fri_params = FriParameters::new_benchmark(challenge_mmcs);
    fri_params.log_blowup = log_blowup;
    let opening_proof = prove_durable_fri_observed_batched(
        &fri_params,
        &input_mmcs,
        vec![reduced],
        &mut challenger,
        (rows * (1usize << log_blowup)).trailing_zeros() as usize,
        |indices| open_input_batches_sorted(&input_mmcs, indices, &trace_data, &quotient_data),
        policy,
        |layer, state| {
            let phase = PipelinePhaseV1::FriLayer { layer: layer.layer };
            let checkpoint_path = if let Some(context) = checkpoint.as_deref_mut() {
                context.record_fri_layer(layer, state, failure_injector)?;
                Some(context.root.join("checkpoint.json"))
            } else {
                None
            };
            emit_phase(
                observe,
                phase,
                completed_phases,
                total_phases,
                checkpoint_path,
                resource_root,
            );
            if cancellation.is_cancelled() {
                return Err(FRI_CANCELLED_SENTINEL.into());
            }
            Ok(())
        },
    );
    let opening_proof = match opening_proof {
        Ok(proof) => proof,
        Err(DurableFriError::Observer(message)) if message == FRI_CANCELLED_SENTINEL => {
            return Err(BoundedProverError::Cancelled);
        }
        Err(error) => return Err(error.into()),
    };

    let bytes = assemble_and_verify::<PW, DE, P, _>(
        air,
        log_degree,
        public_values,
        trace_commit,
        quotient_commit,
        trace_local,
        trace_next,
        quotient_chunks,
        opening_proof,
    )?;
    let proof_checkpoint = checkpoint
        .map(|context| context.record_proof(&bytes, &challenger))
        .transpose()?;
    emit_phase(
        observe,
        PipelinePhaseV1::ProofAssembly,
        completed_phases,
        total_phases,
        proof_checkpoint,
        resource_root,
    );
    failure_injector.after_checkpoint(&PipelinePhaseV1::ProofAssembly);
    check_cancelled(cancellation)?;
    Ok(bytes)
}

#[allow(clippy::type_complexity)]
fn open_input_batches_sorted<const PW: usize, const DE: usize, P>(
    input_mmcs: &DurableInputMmcs<PW, DE, P>,
    indices: &[usize],
    trace_data: &DurableCommitData<PW, DE, P>,
    quotient_data: &DurableCommitData<PW, DE, P>,
) -> std::result::Result<
    Vec<Vec<p3_commit::BatchOpening<P::Val, DurableInputMmcs<PW, DE, P>>>>,
    String,
>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    let trace = input_mmcs
        .open_batches_sorted(indices, trace_data)
        .map_err(|error| error.to_string())?;
    let quotient = input_mmcs
        .open_batches_sorted(indices, quotient_data)
        .map_err(|error| error.to_string())?;
    Ok(trace
        .into_iter()
        .zip(quotient)
        .map(|(trace, quotient)| vec![trace, quotient])
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn assemble_and_verify<const PW: usize, const DE: usize, P, A>(
    air: &A,
    log_degree: usize,
    public_values: Vec<P::Val>,
    trace_commit: DurableCommitment<PW, DE, P>,
    quotient_commit: DurableCommitment<PW, DE, P>,
    trace_local: Vec<P::Challenge>,
    trace_next: Option<Vec<P::Challenge>>,
    quotient_chunks: Vec<Vec<P::Challenge>>,
    opening_proof: crate::bounded_pcs::DurablePcsProof<PW, DE, P>,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let proof = Proof::<BoundedConfig<PW, DE, P>> {
        commitments: Commitments {
            trace: trace_commit,
            quotient_chunks: quotient_commit,
            random: None,
        },
        opened_values: OpenedValues {
            trace_local,
            trace_next,
            preprocessed_local: None,
            preprocessed_next: None,
            quotient_chunks,
            random: None,
        },
        opening_proof,
        degree_bits: log_degree,
    };
    let bytes = postcard::to_allocvec(&proof)
        .map_err(|error| BoundedProverError::Serialization(error.to_string()))?;

    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
        air,
        BaseAir::<P::Val>::width(air),
        public_values.len(),
    );
    let official_config = crate::prover::make_config_with_log_blowup::<PW, DE, P, _>(
        Radix2DitParallel::<P::Val>::default(),
        log_blowup,
    );
    let official_proof: Proof<OfficialConfig<PW, DE, P>> = postcard::from_bytes(&bytes)
        .map_err(|error| BoundedProverError::Serialization(error.to_string()))?;
    verify(&official_config, air, &official_proof, &public_values)
        .map_err(|error| BoundedProverError::Verification(format!("{error:?}")))?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn write_phase_checkpoint<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
    policy: &ResourcePolicyV1,
    job_dir: &Path,
    input_hash: [u8; 32],
    public_values: &[P::Val],
    completed_phase: PipelinePhaseV1,
    trace_commitment: Option<&DurableCommitment<PW, DE, P>>,
    challenger: &ProfileChallengerFor<PW, DE, P>,
    artifacts: Vec<CheckpointArtifactV2>,
) -> Result<Option<PathBuf>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
{
    if policy.checkpoint_policy == CheckpointPolicy::Disabled {
        return Ok(None);
    }
    // A profile with no durable checkpoint representation proves single-shot:
    // writing a manifest whose `challenger_state` could never be restored
    // would produce a checkpoint that only fails at resume time, after the
    // scratch artifacts it points at have already been retained.
    let Some(snapshot) = P::capture_challenger(challenger) else {
        return Ok(None);
    };
    let identity = workload.identity();
    let descriptor = ResumeDescriptorV1 {
        schema_version: 1,
        workload_id: identity.id.into(),
        workload_version: identity.version,
        logical_rows: workload.rows(),
        public_values: public_values.iter().map(canonical_u64::<P::Val>).collect(),
        resource_policy: policy.clone(),
        trace_commitment: trace_commitment.map(encode_commitment::<PW, DE, P>),
        quotient_commitment: None,
        fri_state: None,
    };
    let resume_payload = serde_json::to_vec(&descriptor)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
    let identity =
        checkpoint_identity::<PW, DE, P>(&descriptor, input_hash, policy.policy_hash()?)?;
    let manifest = CheckpointManifestV2 {
        schema_version: 2,
        backend_hash: identity.backend_hash,
        profile_hash: identity.profile_hash,
        release_hash: identity.release_hash,
        dependency_lock_hash: identity.dependency_lock_hash,
        workload_hash: identity.workload_hash,
        input_hash: identity.input_hash,
        resource_policy_hash: identity.resource_policy_hash,
        completed_phase,
        challenger_state: snapshot.encode()?,
        resume_payload,
        artifacts,
    };
    let path = job_dir.join("checkpoint.json");
    manifest.write_atomic(&path)?;
    Ok(Some(path))
}

#[allow(clippy::too_many_arguments)]
fn write_quotient_checkpoint<const PW: usize, const DE: usize, P, Wk>(
    workload: &Wk,
    policy: &ResourcePolicyV1,
    job_dir: &Path,
    input_hash: [u8; 32],
    public_values: &[P::Val],
    trace_lde: &ResourceBoundedMatrix<PW, DE, P>,
    quotient_ldes: &[ResourceBoundedMatrix<PW, DE, P>],
    trace_commitment: &DurableCommitment<PW, DE, P>,
    quotient_commitment: &DurableCommitment<PW, DE, P>,
    challenger: &ProfileChallengerFor<PW, DE, P>,
) -> Result<Option<ProverCheckpointContext<PW, DE, P>>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
{
    if policy.checkpoint_policy == CheckpointPolicy::Disabled {
        return Ok(None);
    }
    // See `write_phase_checkpoint`: no representable challenger snapshot means
    // no checkpoint, and therefore no `ProverCheckpointContext` for the FRI,
    // openings, and proof phases downstream either.
    let Some(snapshot) = P::capture_challenger(challenger) else {
        return Ok(None);
    };
    let Ok((trace_path, trace_digest)) = trace_lde.scratch_artifact() else {
        return Ok(None);
    };
    trace_lde.retain_for_resume();
    let mut artifacts = vec![checkpoint_artifact(
        job_dir,
        PipelineArtifactKindV1::TraceLde,
        None,
        trace_path,
        trace_digest,
    )?];
    for (ordinal, matrix) in quotient_ldes.iter().enumerate() {
        matrix.retain_for_resume();
        let (path, digest) = matrix.scratch_artifact()?;
        artifacts.push(checkpoint_artifact(
            job_dir,
            PipelineArtifactKindV1::QuotientLde,
            Some(ordinal as u32),
            path,
            digest,
        )?);
    }
    let identity = workload.identity();
    let descriptor = ResumeDescriptorV1 {
        schema_version: 1,
        workload_id: identity.id.into(),
        workload_version: identity.version,
        logical_rows: workload.rows(),
        public_values: public_values.iter().map(canonical_u64::<P::Val>).collect(),
        resource_policy: policy.clone(),
        trace_commitment: Some(encode_commitment::<PW, DE, P>(trace_commitment)),
        quotient_commitment: Some(encode_commitment::<PW, DE, P>(quotient_commitment)),
        fri_state: None,
    };
    let resume_payload = serde_json::to_vec(&descriptor)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
    let identity =
        checkpoint_identity::<PW, DE, P>(&descriptor, input_hash, policy.policy_hash()?)?;
    let manifest = CheckpointManifestV2 {
        schema_version: 2,
        backend_hash: identity.backend_hash,
        profile_hash: identity.profile_hash,
        release_hash: identity.release_hash,
        dependency_lock_hash: identity.dependency_lock_hash,
        workload_hash: identity.workload_hash,
        input_hash: identity.input_hash,
        resource_policy_hash: identity.resource_policy_hash,
        completed_phase: PipelinePhaseV1::QuotientCommitment,
        challenger_state: snapshot.encode()?,
        resume_payload,
        artifacts: artifacts.clone(),
    };
    manifest.write_atomic(job_dir.join("checkpoint.json"))?;
    Ok(Some(ProverCheckpointContext {
        profile: std::marker::PhantomData,
        root: job_dir.to_path_buf(),
        manifest,
        descriptor,
        base_artifacts: artifacts,
        fri_artifacts: BTreeMap::new(),
    }))
}

impl<const PW: usize, const DE: usize, P: DurableFieldProfile<PW, DE>>
    ProverCheckpointContext<PW, DE, P>
where
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    /// Every `record_*` method below is only reachable through a context that
    /// `write_quotient_checkpoint` returned, which it only does when
    /// `P::capture_challenger` succeeded — so these `ok_or` arms are the
    /// belt-and-braces case, not the live one.
    fn capture(challenger: &ProfileChallengerFor<PW, DE, P>) -> Result<Vec<u8>> {
        P::capture_challenger(challenger)
            .ok_or(BoundedProverError::InvalidCheckpoint)?
            .encode()
            .map_err(Into::into)
    }

    fn record_proof(
        &mut self,
        proof_bytes: &[u8],
        challenger: &ProfileChallengerFor<PW, DE, P>,
    ) -> Result<PathBuf> {
        if proof_bytes.is_empty() {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        let artifact_root = self.root.join("artifacts");
        let mut store = ScratchMatrixStore::<u8>::create(
            &artifact_root,
            "proof-bundle.bin",
            proof_bytes.len() as u64,
            1,
        )?;
        store.write_rows(0, proof_bytes.len(), proof_bytes)?;
        let digest = store.finalize()?;
        let artifact = checkpoint_artifact(
            &self.root,
            PipelineArtifactKindV1::ProofBundle,
            None,
            store.path(),
            digest,
        )?;
        self.manifest.completed_phase = PipelinePhaseV1::ProofAssembly;
        self.manifest.challenger_state = Self::capture(challenger)?;
        self.manifest.resume_payload = serde_json::to_vec(&self.descriptor)
            .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
        self.manifest.artifacts = self.base_artifacts.clone();
        self.manifest
            .artifacts
            .extend(self.fri_artifacts.values().cloned());
        self.manifest.artifacts.push(artifact);
        let path = self.root.join("checkpoint.json");
        self.manifest.write_atomic(&path)?;
        Ok(path)
    }

    fn set_openings(
        &mut self,
        trace_local: &[P::Challenge],
        trace_next: Option<&[P::Challenge]>,
        quotient_chunks: &[Vec<P::Challenge>],
    ) -> Result<()> {
        self.descriptor.fri_state = Some(FriResumeStateV1 {
            trace_local: encode_challenges::<PW, DE, P>(trace_local),
            trace_next: trace_next.map(encode_challenges::<PW, DE, P>),
            quotient_chunks: quotient_chunks
                .iter()
                .map(|chunk| encode_challenges::<PW, DE, P>(chunk))
                .collect(),
            commitments: Vec::new(),
            commit_pow_witnesses: Vec::new(),
            log_arities: Vec::new(),
        });
        Ok(())
    }

    fn record_fri_layer(
        &mut self,
        layer: FriLayerCheckpoint<'_, PW, DE, P>,
        challenger: &ProfileChallengerFor<PW, DE, P>,
        failure_injector: &dyn FailureInjector,
    ) -> std::result::Result<(), String> {
        self.record_fri_layer_inner(layer, challenger, failure_injector)
            .map_err(|error| error.to_string())
    }

    fn record_openings(
        &mut self,
        reduced: &ScratchChallengeVector<PW, DE, P>,
        challenger: &ProfileChallengerFor<PW, DE, P>,
        failure_injector: &dyn FailureInjector,
    ) -> Result<()> {
        reduced.retain_for_resume();
        let (path, digest) = reduced.scratch_artifact()?;
        let artifact = checkpoint_artifact(
            &self.root,
            PipelineArtifactKindV1::Openings,
            None,
            path,
            digest,
        )?;
        self.manifest.completed_phase = PipelinePhaseV1::Openings;
        self.manifest.challenger_state = Self::capture(challenger)?;
        self.manifest.resume_payload = serde_json::to_vec(&self.descriptor)
            .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
        self.manifest.artifacts = self.base_artifacts.clone();
        self.manifest.artifacts.push(artifact);
        self.manifest
            .write_atomic(self.root.join("checkpoint.json"))?;
        failure_injector.after_checkpoint(&PipelinePhaseV1::Openings);
        Ok(())
    }

    fn record_fri_layer_inner(
        &mut self,
        layer: FriLayerCheckpoint<'_, PW, DE, P>,
        challenger: &ProfileChallengerFor<PW, DE, P>,
        failure_injector: &dyn FailureInjector,
    ) -> Result<()> {
        let state = self
            .descriptor
            .fri_state
            .as_mut()
            .ok_or(BoundedProverError::InvalidCheckpoint)?;
        if state.commitments.len() != layer.layer as usize {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        state
            .commitments
            .push(encode_commitment::<PW, DE, P>(layer.commitment));
        state
            .commit_pow_witnesses
            .push(canonical_u64::<P::Val>(&layer.commit_pow_witness));
        state.log_arities.push(layer.log_arity);

        for (ordinal, vector) in [
            (layer.layer, layer.committed_layer),
            (layer.layer + 1, layer.next_layer),
        ] {
            vector.retain_for_resume();
            let (path, digest) = vector.scratch_artifact()?;
            let artifact = checkpoint_artifact(
                &self.root,
                PipelineArtifactKindV1::FriLayer,
                Some(ordinal),
                path,
                digest,
            )?;
            if let Some(existing) = self.fri_artifacts.insert(ordinal, artifact.clone()) {
                if existing != artifact {
                    return Err(BoundedProverError::InvalidCheckpoint);
                }
            }
        }
        self.manifest.completed_phase = PipelinePhaseV1::FriLayer { layer: layer.layer };
        self.manifest.challenger_state = Self::capture(challenger)?;
        self.manifest.resume_payload = serde_json::to_vec(&self.descriptor)
            .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
        self.manifest.artifacts = self.base_artifacts.clone();
        self.manifest
            .artifacts
            .extend(self.fri_artifacts.values().cloned());
        self.manifest
            .write_atomic(self.root.join("checkpoint.json"))?;
        failure_injector.after_checkpoint(&self.manifest.completed_phase);
        Ok(())
    }
}

fn reopen_fri_layers<const PW: usize, const DE: usize, P>(
    manifest: &CheckpointManifestV2,
    root: &Path,
    state: &FriResumeStateV1,
    completed_layer: u32,
) -> Result<Vec<ScratchChallengeVector<PW, DE, P>>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    if state.commitments.len() != completed_layer as usize + 1
        || state.commitments.len() != state.commit_pow_witnesses.len()
        || state.commitments.len() != state.log_arities.len()
    {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    let mut artifacts: Vec<_> = manifest
        .artifacts
        .iter()
        .filter(|artifact| artifact.kind == PipelineArtifactKindV1::FriLayer)
        .collect();
    artifacts.sort_by_key(|artifact| artifact.ordinal);
    if artifacts.len() != state.commitments.len() + 1
        || artifacts
            .iter()
            .enumerate()
            .any(|(ordinal, artifact)| artifact.ordinal != Some(ordinal as u32))
    {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    artifacts
        .into_iter()
        .map(|artifact| {
            ScratchChallengeVector::reopen(&root.join(&artifact.relative_path), artifact.digest)
                .map_err(BoundedProverError::from)
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn finish_from_openings_checkpoint<const PW: usize, const DE: usize, P, A>(
    air: &A,
    rows: usize,
    public_values: Vec<P::Val>,
    input_mmcs: DurableInputMmcs<PW, DE, P>,
    trace_data: DurableCommitData<PW, DE, P>,
    quotient_data: DurableCommitData<PW, DE, P>,
    trace_commitment: DurableCommitment<PW, DE, P>,
    quotient_commitment: DurableCommitment<PW, DE, P>,
    challenger: &mut ProfileChallengerFor<PW, DE, P>,
    policy: &ResourcePolicyV1,
    checkpoint: &mut ProverCheckpointContext<PW, DE, P>,
    cancellation: &CancellationToken,
    state: &FriResumeStateV1,
    reduced: ScratchChallengeVector<PW, DE, P>,
    failure_injector: &dyn FailureInjector,
    observe: &mut dyn FnMut(&ProverEventV1),
    completed_phases: &mut u32,
    total_phases: u32,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let trace_local = decode_challenges::<PW, DE, P>(&state.trace_local)?;
    let trace_next = state
        .trace_next
        .as_ref()
        .map(|values| decode_challenges::<PW, DE, P>(values))
        .transpose()?;
    let quotient_chunks = state
        .quotient_chunks
        .iter()
        .map(|values| decode_challenges::<PW, DE, P>(values))
        .collect::<Result<Vec<_>>>()?;
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
        air,
        BaseAir::<P::Val>::width(air),
        public_values.len(),
    );
    let mut fri_params = FriParameters::new_benchmark(ExtensionMmcs::new(input_mmcs.clone()));
    fri_params.log_blowup = log_blowup;
    let opening_proof = prove_durable_fri_observed_batched(
        &fri_params,
        &input_mmcs,
        vec![reduced],
        challenger,
        (rows * (1usize << log_blowup)).trailing_zeros() as usize,
        |indices| open_input_batches_sorted(&input_mmcs, indices, &trace_data, &quotient_data),
        policy,
        |layer, challenger| {
            let phase = PipelinePhaseV1::FriLayer { layer: layer.layer };
            checkpoint.record_fri_layer(layer, challenger, failure_injector)?;
            emit_phase(
                observe,
                phase,
                completed_phases,
                total_phases,
                Some(checkpoint.root.join("checkpoint.json")),
                &checkpoint.root,
            );
            if cancellation.is_cancelled() {
                return Err(FRI_CANCELLED_SENTINEL.into());
            }
            Ok(())
        },
    );
    let opening_proof = map_cancelled_fri(opening_proof)?;
    let bytes = assemble_and_verify::<PW, DE, P, _>(
        air,
        rows.trailing_zeros() as usize,
        public_values,
        trace_commitment,
        quotient_commitment,
        trace_local,
        trace_next,
        quotient_chunks,
        opening_proof,
    )?;
    let checkpoint_path = checkpoint.record_proof(&bytes, challenger)?;
    emit_phase(
        observe,
        PipelinePhaseV1::ProofAssembly,
        completed_phases,
        total_phases,
        Some(checkpoint_path),
        &checkpoint.root,
    );
    failure_injector.after_checkpoint(&PipelinePhaseV1::ProofAssembly);
    check_cancelled(cancellation)?;
    Ok(bytes)
}

#[allow(clippy::too_many_arguments)]
fn finish_from_fri_checkpoint<const PW: usize, const DE: usize, P, A>(
    air: &A,
    rows: usize,
    public_values: Vec<P::Val>,
    input_mmcs: DurableInputMmcs<PW, DE, P>,
    trace_data: DurableCommitData<PW, DE, P>,
    quotient_data: DurableCommitData<PW, DE, P>,
    trace_commitment: DurableCommitment<PW, DE, P>,
    quotient_commitment: DurableCommitment<PW, DE, P>,
    challenger: &mut ProfileChallengerFor<PW, DE, P>,
    policy: &ResourcePolicyV1,
    checkpoint: &mut ProverCheckpointContext<PW, DE, P>,
    cancellation: &CancellationToken,
    state: &FriResumeStateV1,
    layers: Vec<ScratchChallengeVector<PW, DE, P>>,
    failure_injector: &dyn FailureInjector,
    observe: &mut dyn FnMut(&ProverEventV1),
    completed_phases: &mut u32,
    total_phases: u32,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    A: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let trace_local = decode_challenges::<PW, DE, P>(&state.trace_local)?;
    let trace_next = state
        .trace_next
        .as_ref()
        .map(|values| decode_challenges::<PW, DE, P>(values))
        .transpose()?;
    let quotient_chunks = state
        .quotient_chunks
        .iter()
        .map(|values| decode_challenges::<PW, DE, P>(values))
        .collect::<Result<Vec<_>>>()?;
    let commitments = state
        .commitments
        .iter()
        .map(|commitment| decode_commitment::<PW, DE, P>(commitment))
        .collect::<Result<Vec<_>>>()?;
    let commit_pow_witnesses = decode_public_values::<PW, DE, P>(&state.commit_pow_witnesses)?;
    let log_arities: Vec<_> = state
        .log_arities
        .iter()
        .map(|arity| *arity as usize)
        .collect();
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
        air,
        BaseAir::<P::Val>::width(air),
        public_values.len(),
    );
    let mut fri_params = FriParameters::new_benchmark(ExtensionMmcs::new(input_mmcs.clone()));
    fri_params.log_blowup = log_blowup;
    let opening_proof = resume_durable_fri_observed_batched(
        &fri_params,
        &input_mmcs,
        layers,
        commitments,
        commit_pow_witnesses,
        log_arities,
        challenger,
        (rows * (1usize << log_blowup)).trailing_zeros() as usize,
        |indices| open_input_batches_sorted(&input_mmcs, indices, &trace_data, &quotient_data),
        policy,
        |layer, challenger| {
            let phase = PipelinePhaseV1::FriLayer { layer: layer.layer };
            checkpoint.record_fri_layer(layer, challenger, failure_injector)?;
            emit_phase(
                observe,
                phase,
                completed_phases,
                total_phases,
                Some(checkpoint.root.join("checkpoint.json")),
                &checkpoint.root,
            );
            if cancellation.is_cancelled() {
                return Err(FRI_CANCELLED_SENTINEL.into());
            }
            Ok(())
        },
    );
    let opening_proof = map_cancelled_fri(opening_proof)?;
    let bytes = assemble_and_verify::<PW, DE, P, _>(
        air,
        rows.trailing_zeros() as usize,
        public_values,
        trace_commitment,
        quotient_commitment,
        trace_local,
        trace_next,
        quotient_chunks,
        opening_proof,
    )?;
    let checkpoint_path = checkpoint.record_proof(&bytes, challenger)?;
    emit_phase(
        observe,
        PipelinePhaseV1::ProofAssembly,
        completed_phases,
        total_phases,
        Some(checkpoint_path),
        &checkpoint.root,
    );
    failure_injector.after_checkpoint(&PipelinePhaseV1::ProofAssembly);
    check_cancelled(cancellation)?;
    Ok(bytes)
}

fn resume_early_phase<const PW: usize, const DE: usize, P, Wk>(
    manifest: &CheckpointManifestV2,
    descriptor: &ResumeDescriptorV1,
    job_dir: &Path,
    workload: &Wk,
    cancellation: &CancellationToken,
    failure_injector: &dyn FailureInjector,
    observe: &mut dyn FnMut(&ProverEventV1),
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let rows = usize::try_from(descriptor.logical_rows)
        .map_err(|_| BoundedProverError::InvalidCheckpoint)?;
    let air = workload.air();
    let width = BaseAir::<P::Val>::width(&air);
    let public_values = decode_public_values::<PW, DE, P>(&descriptor.public_values)?;
    let mut local_policy = descriptor.resource_policy.clone();
    local_policy.scratch_dir = job_dir.join("artifacts");
    create_private_dir(&local_policy.scratch_dir)?;
    // Decode even when the earliest continuation recomputes the deterministic
    // transcript; malformed or non-canonical snapshots must never be accepted.
    // A profile with no snapshot representation cannot have written this
    // checkpoint, so restoring one fails closed.
    let saved_challenger = ChallengerSnapshotV1::decode(&manifest.challenger_state)?;
    P::restore_challenger(&saved_challenger).ok_or(BoundedProverError::InvalidCheckpoint)?;

    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(&air, width, public_values.len());
    let trace_lde = if manifest.completed_phase == PipelinePhaseV1::Trace {
        let artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == PipelineArtifactKindV1::Trace)
            .ok_or(BoundedProverError::InvalidCheckpoint)?;
        let trace = ScratchMatrixStore::<P::Word>::reopen(
            job_dir.join(&artifact.relative_path),
            artifact.digest,
        )?;
        if trace.rows() != rows as u64 || trace.columns() != width {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        let dft = ResourceBoundedDft::<PW, DE, P>::new(local_policy.clone())?;
        dft.try_coset_lde_block_matrix(&trace, log_blowup, P::Val::GENERATOR)?
    } else {
        let artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == PipelineArtifactKindV1::TraceLde)
            .ok_or(BoundedProverError::InvalidCheckpoint)?;
        ResourceBoundedMatrix::reopen_scratch(
            &job_dir.join(&artifact.relative_path),
            artifact.digest,
        )?
    };
    if trace_lde.height() != rows * (1usize << log_blowup) || trace_lde.width() != width {
        return Err(BoundedProverError::InvalidCheckpoint);
    }

    let (continuation, expected_trace_commitment, expected_challenger, completed_phases) =
        match manifest.completed_phase {
            PipelinePhaseV1::Trace | PipelinePhaseV1::TraceLde => {
                (TraceLdeContinuation::FromTraceLde, None, None, 2)
            }
            PipelinePhaseV1::TraceCommitment => (
                TraceLdeContinuation::AfterTraceCommitment,
                Some(
                    descriptor
                        .trace_commitment
                        .as_ref()
                        .ok_or(BoundedProverError::InvalidCheckpoint)?,
                ),
                Some(&saved_challenger),
                3,
            ),
            PipelinePhaseV1::Quotient => {
                let artifact = manifest
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.kind == PipelineArtifactKindV1::Quotient)
                    .ok_or(BoundedProverError::InvalidCheckpoint)?;
                let values = ScratchMatrixStore::<P::Word>::reopen(
                    job_dir.join(&artifact.relative_path),
                    artifact.digest,
                )?;
                (
                    TraceLdeContinuation::FromQuotient(values),
                    Some(
                        descriptor
                            .trace_commitment
                            .as_ref()
                            .ok_or(BoundedProverError::InvalidCheckpoint)?,
                    ),
                    Some(&saved_challenger),
                    4,
                )
            }
            PipelinePhaseV1::QuotientLde => {
                let mut artifacts: Vec<_> = manifest
                    .artifacts
                    .iter()
                    .filter(|artifact| artifact.kind == PipelineArtifactKindV1::QuotientLde)
                    .collect();
                artifacts.sort_by_key(|artifact| artifact.ordinal);
                if artifacts.is_empty()
                    || artifacts
                        .iter()
                        .enumerate()
                        .any(|(index, artifact)| artifact.ordinal != Some(index as u32))
                {
                    return Err(BoundedProverError::InvalidCheckpoint);
                }
                let ldes = artifacts
                    .into_iter()
                    .map(|artifact| {
                        ResourceBoundedMatrix::reopen_scratch(
                            &job_dir.join(&artifact.relative_path),
                            artifact.digest,
                        )
                    })
                    .collect::<std::result::Result<Vec<_>, _>>()?;
                (
                    TraceLdeContinuation::FromQuotientLdes(ldes),
                    Some(
                        descriptor
                            .trace_commitment
                            .as_ref()
                            .ok_or(BoundedProverError::InvalidCheckpoint)?,
                    ),
                    Some(&saved_challenger),
                    5,
                )
            }
            _ => return Err(BoundedProverError::InvalidCheckpoint),
        };
    let mut completed_phases = completed_phases;
    let total_phases = 8 + rows.trailing_zeros();
    continue_from_trace_lde::<PW, DE, P, Wk, _>(
        workload,
        &air,
        rows,
        public_values,
        workload.input_digest(),
        trace_lde,
        continuation,
        expected_trace_commitment,
        expected_challenger,
        cancellation,
        &descriptor.resource_policy,
        job_dir,
        &local_policy,
        observe,
        &mut completed_phases,
        total_phases,
        failure_injector,
    )
}

fn resume_assembled_proof<const PW: usize, const DE: usize, P, Wk>(
    manifest: &CheckpointManifestV2,
    descriptor: &ResumeDescriptorV1,
    job_dir: &Path,
    workload: &Wk,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
{
    let snapshot = ChallengerSnapshotV1::decode(&manifest.challenger_state)?;
    P::restore_challenger(&snapshot).ok_or(BoundedProverError::InvalidCheckpoint)?;
    let artifact = manifest
        .artifacts
        .iter()
        .find(|artifact| artifact.kind == PipelineArtifactKindV1::ProofBundle)
        .ok_or(BoundedProverError::InvalidCheckpoint)?;
    if artifact.digest.columns != 1 {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    let store =
        ScratchMatrixStore::<u8>::reopen(job_dir.join(&artifact.relative_path), artifact.digest)?;
    let proof_len =
        usize::try_from(store.rows()).map_err(|_| BoundedProverError::InvalidCheckpoint)?;
    let mut proof_bytes = vec![0u8; proof_len];
    store.read_rows(0, proof_len, &mut proof_bytes)?;
    let proof: Proof<OfficialConfig<PW, DE, P>> = postcard::from_bytes(&proof_bytes)
        .map_err(|error| BoundedProverError::Serialization(error.to_string()))?;
    let public_values = decode_public_values::<PW, DE, P>(&descriptor.public_values)?;
    let air = workload.air();
    let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
        &air,
        BaseAir::<P::Val>::width(&air),
        public_values.len(),
    );
    let config = crate::prover::make_config_with_log_blowup::<PW, DE, P, _>(
        Radix2DitParallel::<P::Val>::default(),
        log_blowup,
    );
    verify(&config, &air, &proof, &public_values)
        .map_err(|error| BoundedProverError::Verification(format!("{error:?}")))?;
    Ok(proof_bytes)
}

pub fn resume_resource_bounded_with<W>(checkpoint_path: &Path, workload: &W) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
{
    resume_resource_bounded_with_cancellation(checkpoint_path, workload, CancellationToken::new())
}

pub fn resume_resource_bounded_with_cancellation<W>(
    checkpoint_path: &Path,
    workload: &W,
    cancellation: CancellationToken,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
{
    resume_resource_bounded_with_cancellation_observed(
        checkpoint_path,
        workload,
        cancellation,
        |_| {},
    )
}

pub fn resume_resource_bounded_with_cancellation_observed<W, Observe>(
    checkpoint_path: &Path,
    workload: &W,
    cancellation: CancellationToken,
    observe: Observe,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    Observe: FnMut(&ProverEventV1),
{
    resume_resource_bounded_with_control(
        checkpoint_path,
        workload,
        cancellation,
        default_failure_injector(),
        observe,
    )
}

/// Validate a durable checkpoint and every referenced artifact without
/// resuming execution or changing any job state.
pub fn inspect_resource_bounded_checkpoint<W>(
    checkpoint_path: &Path,
    workload: &W,
    expected_policy: &ResourcePolicyV1,
) -> Result<CheckpointInspectionV1>
where
    W: ResourceBoundedWorkload,
{
    expected_policy.validate()?;
    let validated =
        validate_checkpoint_for_workload::<8, 4, GoldilocksProfile, W>(checkpoint_path, workload)?;
    if validated.descriptor.resource_policy != *expected_policy {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    Ok(CheckpointInspectionV1 {
        completed_phase: validated.manifest.completed_phase,
        artifact_count: validated.manifest.artifacts.len(),
    })
}

fn validate_checkpoint_for_workload<const PW: usize, const DE: usize, P, Wk>(
    checkpoint_path: &Path,
    workload: &Wk,
) -> Result<ValidatedCheckpointV1>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
{
    let manifest = CheckpointManifestV2::read(checkpoint_path)?;
    if !matches!(
        manifest.completed_phase,
        PipelinePhaseV1::Trace
            | PipelinePhaseV1::TraceLde
            | PipelinePhaseV1::TraceCommitment
            | PipelinePhaseV1::Quotient
            | PipelinePhaseV1::QuotientLde
            | PipelinePhaseV1::QuotientCommitment
            | PipelinePhaseV1::Openings
            | PipelinePhaseV1::FriLayer { .. }
            | PipelinePhaseV1::ProofAssembly
    ) {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    let descriptor: ResumeDescriptorV1 = serde_json::from_slice(&manifest.resume_payload)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
    validate_resume_descriptor::<PW, DE, P>(&descriptor)?;
    let workload_identity = workload.identity();
    if descriptor.workload_id != workload_identity.id
        || descriptor.workload_version != workload_identity.version
        || descriptor.logical_rows != workload.rows()
    {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    let expected_identity = checkpoint_identity::<PW, DE, P>(
        &descriptor,
        workload.input_digest(),
        descriptor.resource_policy.policy_hash()?,
    )?;
    if manifest.release_hash != expected_identity.release_hash {
        return Err(BoundedProverError::CheckpointReleaseMismatch);
    }
    manifest.validate_identity(expected_identity)?;
    let job_dir = checkpoint_path
        .parent()
        .ok_or(BoundedProverError::InvalidCheckpoint)?
        .to_path_buf();
    manifest.validate_artifacts(&job_dir)?;
    Ok(ValidatedCheckpointV1 {
        manifest,
        descriptor,
        job_dir,
    })
}

/// Resumes a statically linked workload with the same event and fault-control
/// surface used by uninterrupted proving.
pub fn resume_resource_bounded_with_control<W, Observe>(
    checkpoint_path: &Path,
    workload: &W,
    cancellation: CancellationToken,
    failure_injector: &dyn FailureInjector,
    observe: Observe,
) -> Result<Vec<u8>>
where
    W: ResourceBoundedWorkload,
    W::Air: BaseAir<Val>
        + Air<SymbolicAirBuilder<Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    Observe: FnMut(&ProverEventV1),
{
    resume_resource_bounded_with_control_inner::<8, 4, GoldilocksProfile, W, Observe>(
        checkpoint_path,
        workload,
        cancellation,
        failure_injector,
        observe,
    )
}

/// Resume is Goldilocks-only in practice — `ChallengerSnapshotV1` cannot
/// represent another profile's challenger — but the body is generic because it
/// shares `continue_from_trace_lde` and `finish_*` with the prove path. For a
/// profile whose `restore_challenger` returns `None` every path here fails
/// closed with `InvalidCheckpoint`, which is also unreachable: such a profile
/// never wrote a checkpoint to resume from.
fn resume_resource_bounded_with_control_inner<const PW: usize, const DE: usize, P, Wk, Observe>(
    checkpoint_path: &Path,
    workload: &Wk,
    cancellation: CancellationToken,
    failure_injector: &dyn FailureInjector,
    mut observe: Observe,
) -> Result<Vec<u8>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
    Wk: ResourceBoundedWorkload<PW, DE, P>,
    Wk::Air: BaseAir<P::Val>
        + Air<SymbolicAirBuilder<P::Val>>
        + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<PW, DE, P>>>,
    Observe: FnMut(&ProverEventV1),
{
    check_cancelled(&cancellation)?;
    let ValidatedCheckpointV1 {
        manifest,
        descriptor,
        job_dir,
    } = validate_checkpoint_for_workload::<PW, DE, P, Wk>(checkpoint_path, workload)?;
    let job_dir = job_dir.as_path();
    let rows = usize::try_from(descriptor.logical_rows)
        .map_err(|_| BoundedProverError::InvalidCheckpoint)?;
    let air = workload.air();
    let estimate = estimate_air_pipeline::<PW, DE, P, _>(
        &air,
        &descriptor.workload_id,
        descriptor.public_values.len(),
        rows,
        &descriptor.resource_policy,
    )?;
    observe(&ProverEventV1::ResourceEstimate { estimate });
    let total_phases = 8 + rows.trailing_zeros();

    if manifest.completed_phase == PipelinePhaseV1::ProofAssembly {
        let result =
            resume_assembled_proof::<PW, DE, P, Wk>(&manifest, &descriptor, job_dir, workload);
        if result.is_ok() {
            observe(&ProverEventV1::Phase {
                phase: PipelinePhaseV1::ProofAssembly,
                completed_phases: total_phases,
                total_phases,
                checkpoint_path: Some(checkpoint_path.to_path_buf()),
                resource_usage: measure_resource_usage(Some(job_dir)),
            });
        }
        let _ = cleanup_job_directory(
            job_dir,
            descriptor.resource_policy.checkpoint_policy,
            result.is_ok(),
            true,
        );
        return result;
    }

    if matches!(
        manifest.completed_phase,
        PipelinePhaseV1::Trace
            | PipelinePhaseV1::TraceLde
            | PipelinePhaseV1::TraceCommitment
            | PipelinePhaseV1::Quotient
            | PipelinePhaseV1::QuotientLde
    ) {
        let result = resume_early_phase::<PW, DE, P, Wk>(
            &manifest,
            &descriptor,
            job_dir,
            workload,
            &cancellation,
            failure_injector,
            &mut observe,
        );
        let _ = cleanup_job_directory(
            job_dir,
            descriptor.resource_policy.checkpoint_policy,
            result.is_ok(),
            true,
        );
        return result;
    }

    let result = (|| {
        let trace_artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == PipelineArtifactKindV1::TraceLde)
            .ok_or(BoundedProverError::InvalidCheckpoint)?;
        let trace_lde = ResourceBoundedMatrix::<PW, DE, P>::reopen_scratch(
            &job_dir.join(&trace_artifact.relative_path),
            trace_artifact.digest,
        )?;
        let mut quotient_artifacts: Vec<_> = manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == PipelineArtifactKindV1::QuotientLde)
            .collect();
        quotient_artifacts.sort_by_key(|artifact| artifact.ordinal);
        if quotient_artifacts.is_empty()
            || quotient_artifacts
                .iter()
                .enumerate()
                .any(|(index, artifact)| artifact.ordinal != Some(index as u32))
        {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        let quotient_ldes = quotient_artifacts
            .into_iter()
            .map(|artifact| {
                ResourceBoundedMatrix::reopen_scratch(
                    &job_dir.join(&artifact.relative_path),
                    artifact.digest,
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        let public_values = decode_public_values::<PW, DE, P>(&descriptor.public_values)?;
        let log_blowup = quotient_log_blowup::<PW, DE, P, _>(
            &air,
            BaseAir::<P::Val>::width(&air),
            public_values.len(),
        );
        let lde_rows = rows * (1usize << log_blowup);
        if rows == 0
            || !rows.is_power_of_two()
            || trace_lde.height() != lde_rows
            || quotient_ldes
                .iter()
                .any(|matrix| matrix.height() != lde_rows)
        {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        let mut local_policy = descriptor.resource_policy.clone();
        local_policy.scratch_dir = job_dir.join("artifacts");
        create_private_dir(&local_policy.scratch_dir)?;
        let input_mmcs = make_durable_mmcs::<PW, DE, P>(local_policy.clone());
        let (trace_commitment, trace_data) =
            input_mmcs.try_commit_bit_reversed(vec![trace_lde.clone()])?;
        let (quotient_commitment, quotient_data) =
            input_mmcs.try_commit_bit_reversed(quotient_ldes.clone())?;
        if Some(encode_commitment::<PW, DE, P>(&trace_commitment)) != descriptor.trace_commitment
            || Some(encode_commitment::<PW, DE, P>(&quotient_commitment))
                != descriptor.quotient_commitment
        {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        let snapshot = ChallengerSnapshotV1::decode(&manifest.challenger_state)?;
        let mut challenger =
            P::restore_challenger(&snapshot).ok_or(BoundedProverError::InvalidCheckpoint)?;
        let log_degree = rows.trailing_zeros() as usize;
        let trace_domain =
            p3_field::coset::TwoAdicMultiplicativeCoset::new(P::Val::ONE, log_degree)
                .ok_or(BoundedProverError::InvalidCheckpoint)?;
        let base_artifacts: Vec<_> = manifest
            .artifacts
            .iter()
            .filter(|artifact| {
                !matches!(
                    artifact.kind,
                    PipelineArtifactKindV1::FriLayer | PipelineArtifactKindV1::Openings
                )
            })
            .cloned()
            .collect();
        let fri_artifacts: BTreeMap<_, _> = manifest
            .artifacts
            .iter()
            .filter(|artifact| artifact.kind == PipelineArtifactKindV1::FriLayer)
            .filter_map(|artifact| artifact.ordinal.map(|ordinal| (ordinal, artifact.clone())))
            .collect();
        let mut checkpoint = ProverCheckpointContext::<PW, DE, P> {
            profile: std::marker::PhantomData,
            root: job_dir.to_path_buf(),
            manifest: manifest.clone(),
            descriptor: descriptor.clone(),
            base_artifacts,
            fri_artifacts,
        };
        let mut completed_phases = match manifest.completed_phase {
            PipelinePhaseV1::QuotientCommitment => 6,
            PipelinePhaseV1::Openings => 7,
            PipelinePhaseV1::FriLayer { layer } => 8 + layer,
            _ => return Err(BoundedProverError::InvalidCheckpoint),
        };
        match manifest.completed_phase {
            PipelinePhaseV1::QuotientCommitment => finish_after_quotient::<PW, DE, P, _>(
                &air,
                rows,
                trace_domain,
                public_values,
                trace_lde,
                quotient_ldes,
                input_mmcs,
                trace_data,
                quotient_data,
                trace_commitment,
                quotient_commitment,
                challenger,
                &local_policy,
                Some(&mut checkpoint),
                &cancellation,
                &mut observe,
                &mut completed_phases,
                total_phases,
                failure_injector,
            ),
            PipelinePhaseV1::FriLayer { layer } => {
                let state = descriptor
                    .fri_state
                    .as_ref()
                    .ok_or(BoundedProverError::InvalidCheckpoint)?;
                let layers = reopen_fri_layers::<PW, DE, P>(&manifest, job_dir, state, layer)?;
                finish_from_fri_checkpoint::<PW, DE, P, _>(
                    &air,
                    rows,
                    public_values,
                    input_mmcs,
                    trace_data,
                    quotient_data,
                    trace_commitment,
                    quotient_commitment,
                    &mut challenger,
                    &local_policy,
                    &mut checkpoint,
                    &cancellation,
                    state,
                    layers,
                    failure_injector,
                    &mut observe,
                    &mut completed_phases,
                    total_phases,
                )
            }
            PipelinePhaseV1::Openings => {
                let state = descriptor
                    .fri_state
                    .as_ref()
                    .ok_or(BoundedProverError::InvalidCheckpoint)?;
                if !state.commitments.is_empty() {
                    return Err(BoundedProverError::InvalidCheckpoint);
                }
                let artifact = manifest
                    .artifacts
                    .iter()
                    .find(|artifact| artifact.kind == PipelineArtifactKindV1::Openings)
                    .ok_or(BoundedProverError::InvalidCheckpoint)?;
                let reduced = ScratchChallengeVector::<PW, DE, P>::reopen(
                    &job_dir.join(&artifact.relative_path),
                    artifact.digest,
                )?;
                finish_from_openings_checkpoint::<PW, DE, P, _>(
                    &air,
                    rows,
                    public_values,
                    input_mmcs,
                    trace_data,
                    quotient_data,
                    trace_commitment,
                    quotient_commitment,
                    &mut challenger,
                    &local_policy,
                    &mut checkpoint,
                    &cancellation,
                    state,
                    reduced,
                    failure_injector,
                    &mut observe,
                    &mut completed_phases,
                    total_phases,
                )
            }
            _ => Err(BoundedProverError::InvalidCheckpoint),
        }
    })();
    let _ = cleanup_job_directory(
        job_dir,
        descriptor.resource_policy.checkpoint_policy,
        result.is_ok(),
        true,
    );
    result
}

pub fn resume_resource_bounded(checkpoint_path: &Path) -> Result<ResumedProofV1> {
    resume_resource_bounded_cancelable(checkpoint_path, CancellationToken::new())
}

pub fn resume_resource_bounded_cancelable(
    checkpoint_path: &Path,
    cancellation: CancellationToken,
) -> Result<ResumedProofV1> {
    resume_resource_bounded_cancelable_observed(checkpoint_path, cancellation, |_| {})
}

pub fn resume_resource_bounded_cancelable_observed<Observe>(
    checkpoint_path: &Path,
    cancellation: CancellationToken,
    mut observe: Observe,
) -> Result<ResumedProofV1>
where
    Observe: FnMut(&ProverEventV1),
{
    check_cancelled(&cancellation)?;
    let manifest = CheckpointManifestV2::read(checkpoint_path)?;
    let descriptor: ResumeDescriptorV1 = serde_json::from_slice(&manifest.resume_payload)
        .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
    validate_resume_descriptor::<8, 4, GoldilocksProfile>(&descriptor)?;
    let proof_bytes = match descriptor.workload_id.as_str() {
        "fibonacci" if descriptor.workload_version == 1 && descriptor.public_values.len() == 3 => {
            let workload = FibonacciWorkload {
                initial_a: descriptor.public_values[0],
                initial_b: descriptor.public_values[1],
                logical_rows: descriptor.logical_rows,
            };
            resume_resource_bounded_with_control(
                checkpoint_path,
                &workload,
                cancellation,
                default_failure_injector(),
                &mut observe,
            )?
        }
        "poseidon2_goldilocks"
            if descriptor.workload_version == 1 && descriptor.public_values.is_empty() =>
        {
            let workload = Poseidon2Workload {
                logical_rows: descriptor.logical_rows,
            };
            resume_resource_bounded_with_control(
                checkpoint_path,
                &workload,
                cancellation,
                default_failure_injector(),
                &mut observe,
            )?
        }
        _ => return Err(BoundedProverError::InvalidCheckpoint),
    };
    Ok(ResumedProofV1 {
        workload_id: descriptor.workload_id,
        logical_rows: descriptor.logical_rows,
        public_values: descriptor.public_values,
        resource_policy: descriptor.resource_policy,
        proof_bytes,
    })
}

fn checkpoint_artifact(
    root: &Path,
    kind: PipelineArtifactKindV1,
    ordinal: Option<u32>,
    path: &Path,
    digest: hc_stream::ArtifactDigest,
) -> Result<CheckpointArtifactV2> {
    let relative_path = path
        .strip_prefix(root)
        .map_err(|_| BoundedProverError::InvalidCheckpoint)?
        .to_path_buf();
    Ok(CheckpointArtifactV2 {
        kind,
        ordinal,
        relative_path,
        digest,
    })
}

/// `profile_hash` MUST bind the FIELD, not just the compatibility profile
/// string. `COMPATIBILITY_PROFILE` is a single global constant
/// ("tinyzkp-p3-goldilocks-v1") shared by every profile, and for a workload
/// like Fibonacci the workload hash and input digest are field-independent —
/// so without this, a Goldilocks checkpoint and a BabyBear checkpoint of the
/// same statement carry BYTE-IDENTICAL identities. Today nothing bad happens
/// only because `P::restore_challenger` returns `None` for BabyBear and every
/// resume fails closed. That protection is INCIDENTAL: the moment resumable
/// BabyBear checkpoints land, `restore_challenger` returns `Some` and the
/// cross-field binding would silently vanish. Binding the field here is a
/// one-line change now and a cross-field checkpoint-confusion bug later.
fn checkpoint_identity<const PW: usize, const DE: usize, P>(
    descriptor: &ResumeDescriptorV1,
    input_hash: [u8; 32],
    resource_policy_hash: [u8; 32],
) -> Result<CheckpointIdentityV2>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    let workload_bytes = serde_json::to_vec(&(
        descriptor.workload_id.as_str(),
        descriptor.workload_version,
        descriptor.logical_rows,
    ))
    .map_err(|error| BoundedProverError::CheckpointPayload(error.to_string()))?;
    let release = crate::release_identity();
    Ok(CheckpointIdentityV2 {
        backend_hash: *blake3::hash(b"hc-plonky3-resource-bounded-v1").as_bytes(),
        profile_hash: *blake3::hash(
            format!(
                "{COMPATIBILITY_PROFILE}:{PLONKY3_VERSION}:{}:{PW}:{DE}",
                P::FIELD_NAME
            )
            .as_bytes(),
        )
        .as_bytes(),
        release_hash: *blake3::hash(release.as_bytes()).as_bytes(),
        dependency_lock_hash: *blake3::hash(crate::prover::DEPENDENCY_LOCK_SHA256.as_bytes())
            .as_bytes(),
        workload_hash: *blake3::hash(&workload_bytes).as_bytes(),
        input_hash,
        resource_policy_hash,
    })
}

fn validate_resume_descriptor<const PW: usize, const DE: usize, P>(
    descriptor: &ResumeDescriptorV1,
) -> Result<()>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    if descriptor.schema_version != 1
        || descriptor.logical_rows == 0
        || !descriptor.logical_rows.is_power_of_two()
        || descriptor.workload_id.is_empty()
        || descriptor
            .trace_commitment
            .as_ref()
            .is_some_and(|commitment| commitment.len() != 1)
        || descriptor
            .quotient_commitment
            .as_ref()
            .is_some_and(|commitment| commitment.len() != 1)
    {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    descriptor.resource_policy.validate()?;
    decode_public_values::<PW, DE, P>(&descriptor.public_values)?;
    // The inner-length checks the fixed-size `[u64; 4]`/`[u64; 2]` array types
    // used to perform structurally now happen inside `decode_commitment` /
    // `decode_challenges`, which every branch below goes through.
    for commitment in descriptor
        .trace_commitment
        .iter()
        .chain(&descriptor.quotient_commitment)
    {
        decode_commitment::<PW, DE, P>(commitment)?;
    }
    if let Some(state) = &descriptor.fri_state {
        if state.commitments.len() != state.commit_pow_witnesses.len()
            || state.commitments.len() != state.log_arities.len()
            || state.log_arities.iter().any(|arity| *arity != 1)
        {
            return Err(BoundedProverError::InvalidCheckpoint);
        }
        decode_challenges::<PW, DE, P>(&state.trace_local)?;
        if let Some(next) = &state.trace_next {
            decode_challenges::<PW, DE, P>(next)?;
        }
        for chunk in &state.quotient_chunks {
            decode_challenges::<PW, DE, P>(chunk)?;
        }
        for commitment in &state.commitments {
            decode_commitment::<PW, DE, P>(commitment)?;
        }
        decode_public_values::<PW, DE, P>(&state.commit_pow_witnesses)?;
    }
    Ok(())
}

fn encode_commitment<const PW: usize, const DE: usize, P>(
    commitment: &DurableCommitment<PW, DE, P>,
) -> Vec<Vec<u64>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    commitment
        .roots()
        .iter()
        .map(|root| root.iter().map(canonical_u64::<P::Val>).collect())
        .collect()
}

fn decode_commitment<const PW: usize, const DE: usize, P>(
    values: &[Vec<u64>],
) -> Result<DurableFriCommitment<PW, DE, P>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    if values.len() != 1 {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    let roots = values
        .iter()
        .map(|root| {
            // Each root is exactly `DIGEST_ELEMS` canonical field elements: 4
            // for Goldilocks, 8 for BabyBear. `try_into` on the fixed-size
            // array is what enforces the length now that the wire type is a
            // `Vec`.
            let decoded = decode_public_values::<PW, DE, P>(root)?;
            <Vec<P::Val> as TryInto<[P::Val; DE]>>::try_into(decoded)
                .map_err(|_| BoundedProverError::InvalidCheckpoint)
        })
        .collect::<Result<Vec<[P::Val; DE]>>>()?;
    Ok(MerkleCap::new(roots))
}

fn decode_public_values<const PW: usize, const DE: usize, P>(values: &[u64]) -> Result<Vec<P::Val>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    // Non-canonical encodings must not be accepted: two distinct `u64`s that
    // reduce to the same field element would let one checkpoint decode to a
    // different public input than the one it was written for. The literal
    // Goldilocks modulus this replaced is now `P::modulus_u64()`.
    if values.iter().any(|value| *value >= P::modulus_u64()) {
        return Err(BoundedProverError::InvalidCheckpoint);
    }
    Ok(values
        .iter()
        .copied()
        .map(<P::Val as PrimeCharacteristicRing>::from_u64)
        .collect())
}

fn encode_challenges<const PW: usize, const DE: usize, P>(values: &[P::Challenge]) -> Vec<Vec<u64>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    values
        .iter()
        .map(|value| {
            // One entry per extension-field coordinate: 2 for Goldilocks, 4
            // for BabyBear. The two hand-written indices this replaced were a
            // degree-2 assumption.
            value
                .as_basis_coefficients_slice()
                .iter()
                .map(canonical_u64::<P::Val>)
                .collect()
        })
        .collect()
}

fn decode_challenges<const PW: usize, const DE: usize, P>(
    values: &[Vec<u64>],
) -> Result<Vec<P::Challenge>>
where
    P: DurableFieldProfile<PW, DE>,
    [P::Val; DE]: Serialize + for<'de> Deserialize<'de>,
{
    values
        .iter()
        .map(|value| {
            if value.len() != extension_degree::<PW, DE, P>() {
                return Err(BoundedProverError::InvalidCheckpoint);
            }
            let basis = decode_public_values::<PW, DE, P>(value)?;
            P::Challenge::from_basis_coefficients_slice(&basis)
                .ok_or(BoundedProverError::InvalidCheckpoint)
        })
        .collect()
}

fn canonical_u64<F: PrimeField64>(value: &F) -> u64 {
    F::as_canonical_u64(value)
}

fn check_cancelled(cancellation: &CancellationToken) -> Result<()> {
    if cancellation.is_cancelled() {
        Err(BoundedProverError::Cancelled)
    } else {
        Ok(())
    }
}

fn map_cancelled_fri<T>(result: std::result::Result<T, DurableFriError>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(DurableFriError::Observer(message)) if message == FRI_CANCELLED_SENTINEL => {
            Err(BoundedProverError::Cancelled)
        }
        Err(error) => Err(error.into()),
    }
}

fn emit_phase(
    observe: &mut dyn FnMut(&ProverEventV1),
    phase: PipelinePhaseV1,
    completed_phases: &mut u32,
    total_phases: u32,
    checkpoint_path: Option<PathBuf>,
    resource_root: &Path,
) {
    *completed_phases = completed_phases.saturating_add(1);
    observe(&ProverEventV1::Phase {
        phase,
        completed_phases: *completed_phases,
        total_phases,
        checkpoint_path,
        resource_usage: measure_resource_usage(Some(resource_root)),
    });
}

pub(crate) fn measure_resource_usage(resource_root: Option<&Path>) -> ResourceUsageV1 {
    ResourceUsageV1 {
        scratch_bytes: resource_root.map(directory_bytes).unwrap_or(0),
        resident_bytes: current_resident_bytes(),
    }
}

fn directory_bytes(root: &Path) -> u64 {
    let Ok(metadata) = fs::symlink_metadata(root) else {
        return 0;
    };
    if metadata.file_type().is_symlink() {
        return 0;
    }
    if metadata.is_file() {
        return metadata.len();
    }
    let Ok(entries) = fs::read_dir(root) else {
        return 0;
    };
    entries
        .filter_map(std::result::Result::ok)
        .map(|entry| directory_bytes(&entry.path()))
        .fold(0u64, u64::saturating_add)
}

#[cfg(target_os = "linux")]
fn current_resident_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))?
        .split_whitespace()
        .next()?
        .parse::<u64>()
        .ok()?;
    rss.checked_mul(1024)
}

#[cfg(not(target_os = "linux"))]
const fn current_resident_bytes() -> Option<u64> {
    None
}

#[cfg(feature = "fault-injection")]
fn default_failure_injector() -> &'static dyn FailureInjector {
    static INJECTOR: EnvironmentAbortFailureInjector = EnvironmentAbortFailureInjector;
    &INJECTOR
}

#[cfg(not(feature = "fault-injection"))]
fn default_failure_injector() -> &'static dyn FailureInjector {
    static INJECTOR: NoopFailureInjector = NoopFailureInjector;
    &INJECTOR
}

fn create_job_dir(root: &Path) -> Result<PathBuf> {
    create_unique_job_dir(root, "bounded-prover", &PROVER_JOB_COUNTER).map_err(Into::into)
}

fn create_exact_job_dir(path: &Path) -> Result<PathBuf> {
    let scratch_root = path
        .parent()
        .ok_or(StreamError::UnsafePath)?
        .canonicalize()
        .map_err(|_| StreamError::UnsafePath)?;
    let configured_name = path.file_name().ok_or(StreamError::UnsafePath)?;
    if !matches!(
        path.components().next_back(),
        Some(std::path::Component::Normal(_))
    ) {
        return Err(StreamError::UnsafePath.into());
    }
    let exact = scratch_root.join(configured_name);
    if exact.exists() {
        let metadata = fs::symlink_metadata(&exact)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StreamError::UnsafePath.into());
        }
        if fs::read_dir(&exact)?.next().is_some() {
            return Err(BoundedProverError::CheckpointStateExists);
        }
    } else {
        create_private_dir(&exact)?;
    }
    Ok(exact)
}

fn create_private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        let metadata = fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(StreamError::UnsafePath.into());
        }
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = fs::DirBuilder::new();
        builder.mode(0o700).create(path)?;
    }
    #[cfg(not(unix))]
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FibonacciWorkload, Poseidon2Workload};
    use hc_stream::{CheckpointPolicy, ResourceMode};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering as AtomicOrdering};
    use std::sync::Arc;
    use std::sync::Mutex;

    #[derive(Default)]
    struct RecordingFailureInjector {
        phases: Mutex<Vec<PipelinePhaseV1>>,
    }

    impl FailureInjector for RecordingFailureInjector {
        fn after_checkpoint(&self, phase: &PipelinePhaseV1) {
            self.phases.lock().unwrap().push(phase.clone());
        }
    }

    fn policy(root: &Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 2 * 1024 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        }
    }

    #[test]
    fn auto_plan_uses_conventional_peak_and_preflights_the_selected_estimate() {
        let dir = tempfile::tempdir().unwrap();
        let small = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 16,
        };
        let mut automatic = policy(dir.path());
        automatic.mode = ResourceMode::Auto;
        let memory_plan = plan_resource_workload(&small, &automatic).unwrap();
        assert_eq!(memory_plan.selected_mode, ExecutionMode::Memory);
        assert_eq!(
            memory_plan.preflight.estimate,
            memory_plan.conventional_estimate
        );

        let larger = Poseidon2Workload { logical_rows: 4096 };
        automatic.max_resident_bytes = 64 * 1024 * 1024;
        let scratch_plan = plan_resource_workload(&larger, &automatic).unwrap();
        assert!(
            scratch_plan.conventional_estimate.peak_resident_bytes
                > automatic.memory_selection_threshold()
        );
        assert_eq!(scratch_plan.selected_mode, ExecutionMode::Scratch);
        assert_eq!(
            scratch_plan.preflight.estimate,
            scratch_plan.bounded_estimate
        );
    }

    #[test]
    fn policy_executor_produces_the_same_official_bytes_in_both_modes() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 3,
            initial_b: 5,
            logical_rows: 16,
        };
        let reference = prove_resource_reference(&workload).unwrap();

        let mut memory_policy = policy(&dir.path().join("memory"));
        memory_policy.mode = ResourceMode::Auto;
        let memory = prove_resource_with_policy(&workload, &memory_policy).unwrap();
        assert_eq!(memory.selected_mode, ExecutionMode::Memory);
        assert_eq!(memory.proof_bytes, reference);

        let scratch =
            prove_resource_with_policy(&workload, &policy(&dir.path().join("scratch"))).unwrap();
        assert_eq!(scratch.selected_mode, ExecutionMode::Scratch);
        assert_eq!(scratch.proof_bytes, reference);
    }

    fn assert_scratch_estimate_tracks_measured_peak<W>(workload: &W)
    where
        W: ResourceBoundedWorkload,
        W::Air: BaseAir<Val>
            + Air<SymbolicAirBuilder<Val>>
            + for<'a> Air<VerifierConstraintFolder<'a, EvaluationConfig<8, 4, GoldilocksProfile>>>,
    {
        let dir = tempfile::tempdir().unwrap();
        let selected_policy = policy(dir.path());
        let estimate = estimate_resource_bounded_workload(workload, &selected_policy).unwrap();
        let stopped = Arc::new(AtomicBool::new(false));
        let measured_peak = Arc::new(AtomicU64::new(0));
        let monitor_root = dir.path().to_path_buf();
        let monitor_stopped = stopped.clone();
        let monitor_peak = measured_peak.clone();
        let monitor = std::thread::spawn(move || {
            while !monitor_stopped.load(AtomicOrdering::Acquire) {
                monitor_peak.fetch_max(directory_bytes(&monitor_root), AtomicOrdering::AcqRel);
                std::thread::yield_now();
            }
            monitor_peak.fetch_max(directory_bytes(&monitor_root), AtomicOrdering::AcqRel);
        });
        let phase_peak = Arc::new(AtomicU64::new(0));
        let observed_phase_peak = phase_peak.clone();
        let proof = prove_resource_bounded_observed(workload, &selected_policy, move |event| {
            if let ProverEventV1::Phase { resource_usage, .. } = event {
                observed_phase_peak.fetch_max(resource_usage.scratch_bytes, AtomicOrdering::AcqRel);
            }
        })
        .unwrap();
        stopped.store(true, AtomicOrdering::Release);
        monitor.join().unwrap();
        let actual = measured_peak.load(AtomicOrdering::Acquire);
        eprintln!(
            "scratch-calibration workload={} rows={} estimate={} measured={} phase_peak={} proof={}",
            workload.identity().id,
            workload.rows(),
            estimate.scratch_high_water_bytes,
            actual,
            phase_peak.load(AtomicOrdering::Acquire),
            proof.len(),
        );
        let difference = estimate.scratch_high_water_bytes.abs_diff(actual);
        assert!(
            difference <= estimate.scratch_high_water_bytes.div_ceil(10),
            "scratch estimate {} differs from measured peak {} by more than 10%",
            estimate.scratch_high_water_bytes,
            actual,
        );
    }

    #[test]
    fn full_pipeline_scratch_estimates_track_small_measured_peaks() {
        assert_scratch_estimate_tracks_measured_peak(&FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 1 << 10,
        });
        assert_scratch_estimate_tracks_measured_peak(&Poseidon2Workload {
            logical_rows: 1 << 10,
        });
    }

    #[test]
    #[ignore = "nightly release-mode calibration across multiple powers of two"]
    fn scratch_estimates_track_multiple_release_scale_powers() {
        for logical_rows in [1 << 10, 1 << 12, 1 << 14] {
            assert_scratch_estimate_tracks_measured_peak(&FibonacciWorkload {
                initial_a: 0,
                initial_b: 1,
                logical_rows,
            });
            assert_scratch_estimate_tracks_measured_peak(&Poseidon2Workload { logical_rows });
        }
    }

    #[test]
    fn fibonacci_bounded_proof_is_official_and_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 16,
        };
        let actual = prove_resource_bounded(&workload, &policy(dir.path())).unwrap();
        let expected = crate::ResourceBoundedUniStarkProver::prove_reference(
            crate::WorkloadKind::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            16,
        )
        .unwrap();
        assert_eq!(actual, expected.proof_bytes);
    }

    /// Known-answer test pinning the Goldilocks transcript to a CONSTANT.
    ///
    /// Every other byte-equality test in this file compares the bounded
    /// prover against the reference prover *in the same build*. Both sides
    /// call the same `profile_permutation()`, so a change to its seed, RNG,
    /// or round constants would move both sides together and leave every
    /// assertion green while silently emitting a different proof system.
    ///
    /// Phase 3A rewrites `dft`/`mmcs`/`fri`/`quotient`/`bounded_pcs`/
    /// `bounded_prover` to be generic over `DurableFieldProfile`, and the
    /// plan's stated safety net is "Goldilocks stays byte-identical". That
    /// net is only real if something outside the build holds the answer.
    /// This is that something.
    ///
    /// If this fails, the Goldilocks proof bytes changed. Do NOT update the
    /// constant to make it pass — per the plan's Global Constraints, a
    /// changed byte-equality expectation is a plan conflict: stop and ask.
    #[test]
    fn goldilocks_fibonacci_proof_matches_frozen_known_answer() {
        const FROZEN_FIBONACCI_16_PROOF_BLAKE3: &str =
            "ed94fb697d9c6ec95e08724bf960a1e3bb84b7b41954eed888688d2a8a174a02";

        let proof = crate::ResourceBoundedUniStarkProver::prove_reference(
            crate::WorkloadKind::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            16,
        )
        .unwrap();
        let digest = blake3::hash(&proof.proof_bytes).to_hex().to_string();
        assert_eq!(
            digest, FROZEN_FIBONACCI_16_PROOF_BLAKE3,
            "Goldilocks fibonacci(0,1,16) proof bytes changed; see this test's doc comment"
        );
    }

    /// BabyBear has no durable checkpoint representation, so the prover must
    /// write NO checkpoint rather than one it could never restore.
    ///
    /// This is the fail-closed half of `DurableFieldProfile::capture_challenger`
    /// returning `None`. Written with `RetainOnFailure` and an interrupted run —
    /// the exact configuration under which Goldilocks DOES leave a resumable
    /// `checkpoint.json` (see
    /// `cancellation_retains_only_an_explicitly_resumable_checkpoint`) — so a
    /// future change that started emitting Goldilocks-shaped snapshots for
    /// BabyBear fails here instead of at some later resume.
    #[test]
    fn babybear_writes_no_checkpoint_because_it_cannot_restore_one() {
        use crate::profile::BabyBearProfile;

        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 16,
        };
        let mut resumable = policy(dir.path());
        resumable.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let cancellation = CancellationToken::new();
        let observer_token = cancellation.clone();
        let mut observed_checkpoint_paths = 0usize;
        let result =
            prove_resource_bounded_observed_with_control_inner::<16, 8, BabyBearProfile, _, _>(
                &workload,
                &resumable,
                None,
                cancellation,
                default_failure_injector(),
                |event| {
                    if let ProverEventV1::Phase {
                        phase,
                        checkpoint_path,
                        ..
                    } = event
                    {
                        if checkpoint_path.is_some() {
                            observed_checkpoint_paths += 1;
                        }
                        if matches!(phase, PipelinePhaseV1::Quotient) {
                            observer_token.cancel();
                        }
                    }
                },
            );
        assert!(matches!(result, Err(BoundedProverError::Cancelled)));
        assert_eq!(
            observed_checkpoint_paths, 0,
            "BabyBear reported a checkpoint path it cannot have written"
        );
        let stray = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file());
        assert!(
            stray.is_none(),
            "BabyBear left an unrestorable checkpoint at {stray:?}"
        );
    }

    /// The Goldilocks counterpart of the test above, asserted in the same run so
    /// the two cannot silently converge: the identical policy and interruption
    /// DO leave a checkpoint for Goldilocks.
    #[test]
    fn goldilocks_still_writes_a_checkpoint_under_the_same_interruption() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 16,
        };
        let mut resumable = policy(dir.path());
        resumable.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let cancellation = CancellationToken::new();
        let observer_token = cancellation.clone();
        let result =
            prove_resource_bounded_observed_with_control_inner::<8, 4, GoldilocksProfile, _, _>(
                &workload,
                &resumable,
                None,
                cancellation,
                default_failure_injector(),
                |event| {
                    if matches!(
                        event,
                        ProverEventV1::Phase {
                            phase: PipelinePhaseV1::Quotient,
                            ..
                        }
                    ) {
                        observer_token.cancel();
                    }
                },
            );
        assert!(matches!(result, Err(BoundedProverError::Cancelled)));
        assert!(
            fs::read_dir(dir.path())
                .unwrap()
                .filter_map(std::result::Result::ok)
                .map(|entry| entry.path().join("checkpoint.json"))
                .any(|path| path.is_file()),
            "Goldilocks stopped writing resumable checkpoints"
        );
    }

    #[test]
    fn parallel_policy_emits_the_same_official_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 5,
            initial_b: 8,
            logical_rows: 64,
        };
        let mut parallel_policy = policy(dir.path());
        parallel_policy.max_threads = 4;
        let actual = prove_resource_bounded(&workload, &parallel_policy).unwrap();
        let expected = prove_resource_reference(&workload).unwrap();
        assert_eq!(actual, expected);
    }

    #[test]
    fn poseidon2_bounded_proof_is_official_and_byte_identical() {
        let dir = tempfile::tempdir().unwrap();
        let workload = Poseidon2Workload { logical_rows: 8 };
        let actual = prove_resource_bounded(&workload, &policy(dir.path())).unwrap();
        let expected = crate::ResourceBoundedUniStarkProver::prove_reference(
            crate::WorkloadKind::Poseidon2,
            8,
        )
        .unwrap();
        assert_eq!(actual, expected.proof_bytes);
    }

    #[test]
    fn explicit_failure_injector_tracks_every_durable_phase() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 16,
        };
        let injector = RecordingFailureInjector::default();
        let mut observed = Vec::new();
        prove_resource_bounded_observed_with_control(
            &workload,
            &policy(dir.path()),
            CancellationToken::new(),
            &injector,
            |event| {
                if let ProverEventV1::Phase {
                    phase,
                    checkpoint_path,
                    ..
                } = event
                {
                    assert!(checkpoint_path.is_some());
                    observed.push(phase.clone());
                }
            },
        )
        .unwrap();
        assert_eq!(*injector.phases.lock().unwrap(), observed);
        assert_eq!(observed.first(), Some(&PipelinePhaseV1::Trace));
        assert_eq!(observed.last(), Some(&PipelinePhaseV1::ProofAssembly));
    }

    #[test]
    fn resumed_prover_emits_estimate_progress_and_checkpoint_events() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 16,
        };
        let mut resumable = policy(dir.path());
        resumable.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let cancellation = CancellationToken::new();
        let observer_token = cancellation.clone();
        let result = prove_resource_bounded_observed_with_cancellation(
            &workload,
            &resumable,
            cancellation,
            move |event| {
                if matches!(
                    event,
                    ProverEventV1::Phase {
                        phase: PipelinePhaseV1::Quotient,
                        ..
                    }
                ) {
                    observer_token.cancel();
                }
            },
        );
        assert!(matches!(result, Err(BoundedProverError::Cancelled)));
        let checkpoint = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file())
            .unwrap();
        let mut saw_estimate = false;
        let mut phases = Vec::new();
        let resumed = resume_resource_bounded_cancelable_observed(
            &checkpoint,
            CancellationToken::new(),
            |event| match event {
                ProverEventV1::ResourceEstimate { .. } => saw_estimate = true,
                ProverEventV1::Phase {
                    phase,
                    completed_phases,
                    total_phases,
                    checkpoint_path,
                    resource_usage,
                } => {
                    assert!(*completed_phases <= *total_phases);
                    assert!(checkpoint_path.is_some());
                    assert!(resource_usage.scratch_bytes > 0);
                    phases.push(phase.clone());
                }
            },
        )
        .unwrap();
        assert!(saw_estimate);
        assert_eq!(phases.first(), Some(&PipelinePhaseV1::QuotientLde));
        assert_eq!(phases.last(), Some(&PipelinePhaseV1::ProofAssembly));
        let expected = prove_resource_reference(&workload).unwrap();
        assert_eq!(resumed.proof_bytes, expected);
    }

    #[test]
    fn maximum_canonical_fibonacci_input_resumes_to_identical_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: crate::GOLDILOCKS_MODULUS_U64 - 1,
            initial_b: 0,
            logical_rows: 16,
        };
        let mut resumable = policy(dir.path());
        resumable.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let cancellation = CancellationToken::new();
        let observer_token = cancellation.clone();
        let result = prove_resource_bounded_observed_with_cancellation(
            &workload,
            &resumable,
            cancellation,
            move |event| {
                if matches!(
                    event,
                    ProverEventV1::Phase {
                        phase: PipelinePhaseV1::TraceCommitment,
                        ..
                    }
                ) {
                    observer_token.cancel();
                }
            },
        );
        assert!(matches!(result, Err(BoundedProverError::Cancelled)));
        let checkpoint = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file())
            .unwrap();
        let resumed = resume_resource_bounded(&checkpoint).unwrap();
        let expected = prove_resource_reference(&workload).unwrap();
        assert_eq!(resumed.proof_bytes, expected);
    }

    #[test]
    fn full_pipeline_scratch_cap_fails_before_trace_generation() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 1024,
        };
        let mut constrained = policy(dir.path());
        constrained.max_scratch_bytes = 1;
        assert!(matches!(
            prove_resource_bounded(&workload, &constrained),
            Err(BoundedProverError::Stream(StreamError::ResourceLimit {
                resource: "scratch storage including headroom",
                ..
            }))
        ));
        assert!(fs::read_dir(dir.path()).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("bounded-prover-")));
    }

    #[test]
    fn cancellation_retains_only_an_explicitly_resumable_checkpoint() {
        let dir = tempfile::tempdir().unwrap();
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 64,
        };
        let mut resumable = policy(dir.path());
        resumable.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let cancellation = CancellationToken::new();
        let observer_token = cancellation.clone();
        let result = prove_resource_bounded_observed_with_cancellation(
            &workload,
            &resumable,
            cancellation,
            move |event| {
                if matches!(
                    event,
                    ProverEventV1::Phase {
                        phase: PipelinePhaseV1::Quotient,
                        ..
                    }
                ) {
                    observer_token.cancel();
                }
            },
        );
        assert!(matches!(result, Err(BoundedProverError::Cancelled)));
        let checkpoint = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file())
            .expect("resumable cancellation retains a checkpoint");
        assert_eq!(
            CheckpointManifestV2::read(&checkpoint)
                .unwrap()
                .completed_phase,
            PipelinePhaseV1::Quotient
        );
        let resumed = resume_resource_bounded(&checkpoint).unwrap();
        let expected = crate::ResourceBoundedUniStarkProver::prove_reference(
            crate::WorkloadKind::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            64,
        )
        .unwrap();
        assert_eq!(resumed.proof_bytes, expected.proof_bytes);

        let clean_dir = tempfile::tempdir().unwrap();
        let mut non_resumable = policy(clean_dir.path());
        non_resumable.checkpoint_policy = CheckpointPolicy::Disabled;
        let cancellation = CancellationToken::new();
        cancellation.cancel();
        assert!(matches!(
            prove_resource_bounded_observed_with_cancellation(
                &workload,
                &non_resumable,
                cancellation,
                |_| {}
            ),
            Err(BoundedProverError::Cancelled)
        ));
        assert!(fs::read_dir(clean_dir.path()).unwrap().next().is_none());
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn fault_injection_child() {
        let Some(root) = std::env::var_os("TINYZKP_TEST_SCRATCH") else {
            return;
        };
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 64,
        };
        let mut child_policy = policy(Path::new(&root));
        child_policy.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let _ = prove_resource_bounded(&workload, &child_policy);
        panic!("fault injector did not terminate the child process");
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn resume_checkpoint_child() {
        let Some(checkpoint) = std::env::var_os("TINYZKP_RESUME_CHECKPOINT") else {
            return;
        };
        resume_resource_bounded(Path::new(&checkpoint)).unwrap();
    }

    #[cfg(feature = "fault-injection")]
    fn crashed_checkpoint(phase: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("bounded_prover::tests::fault_injection_child")
            .arg("--nocapture")
            .env("TINYZKP_TEST_SCRATCH", dir.path())
            .env("TINYZKP_FAIL_AFTER", phase)
            .status()
            .unwrap();
        assert!(!status.success());

        let checkpoint = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file())
            .expect("aborted child must leave a resumable checkpoint");
        (dir, checkpoint)
    }

    #[cfg(feature = "fault-injection")]
    fn assert_crash_resumes_to_identical_proof_bytes(phase: &str) {
        let (_dir, checkpoint) = crashed_checkpoint(phase);
        let job_dir = checkpoint.parent().unwrap().to_path_buf();
        let resumed = resume_resource_bounded(&checkpoint).unwrap();
        let expected = crate::ResourceBoundedUniStarkProver::prove_reference(
            crate::WorkloadKind::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            64,
        )
        .unwrap();
        eprintln!(
            "tinyzkp-crash-proof phase={phase} resumed={} reference={}",
            blake3::hash(&resumed.proof_bytes),
            blake3::hash(&expected.proof_bytes),
        );
        assert_eq!(resumed.proof_bytes, expected.proof_bytes);
        assert!(!job_dir.exists());
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn single_checkpoint_phase_from_environment_resumes_to_identical_proof_bytes() {
        let Some(phase) = std::env::var_os("TINYZKP_SINGLE_CRASH_PHASE") else {
            return;
        };
        let phase = phase.to_string_lossy();
        let valid = matches!(
            phase.as_ref(),
            "trace"
                | "trace_lde"
                | "trace_commitment"
                | "quotient"
                | "quotient_lde"
                | "quotient_commitment"
                | "openings"
                | "fri_layer_0"
                | "fri_layer_1"
                | "fri_layer_2"
                | "fri_layer_3"
                | "fri_layer_4"
                | "fri_layer_5"
                | "proof_assembly"
        );
        assert!(valid, "unknown checkpoint phase requested: {phase}");
        assert_crash_resumes_to_identical_proof_bytes(&phase);
    }

    #[cfg(feature = "fault-injection")]
    fn assert_resume_skips_completed_phase(checkpoint_phase: &str, skipped_phase: &str) {
        let (_dir, checkpoint) = crashed_checkpoint(checkpoint_phase);
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("bounded_prover::tests::resume_checkpoint_child")
            .arg("--nocapture")
            .env("TINYZKP_RESUME_CHECKPOINT", &checkpoint)
            .env("TINYZKP_FAIL_AFTER", skipped_phase)
            .status()
            .unwrap();
        assert!(
            status.success(),
            "resume from {checkpoint_phase} re-executed completed phase {skipped_phase}"
        );
        assert!(!checkpoint.parent().unwrap().exists());
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn resume_consumes_the_exact_saved_early_phase_artifact() {
        assert_resume_skips_completed_phase("trace_commitment", "trace_commitment");
        assert_resume_skips_completed_phase("quotient", "quotient");
        assert_resume_skips_completed_phase("quotient_lde", "quotient_lde");
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn every_pre_fri_checkpoint_resumes_to_identical_proof_bytes() {
        for phase in [
            "trace",
            "trace_lde",
            "trace_commitment",
            "quotient",
            "quotient_lde",
            "quotient_commitment",
            "proof_assembly",
        ] {
            assert_crash_resumes_to_identical_proof_bytes(phase);
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn openings_checkpoint_resumes_to_identical_proof_bytes() {
        assert_crash_resumes_to_identical_proof_bytes("openings");
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn every_fri_layer_checkpoint_resumes_to_identical_proof_bytes() {
        // The 64-row frozen profile performs six binary folds; exercise every
        // durable layer rather than sampling only the first half of the loop.
        for layer in 0..6 {
            assert_crash_resumes_to_identical_proof_bytes(&format!("fri_layer_{layer}"));
        }
    }

    #[cfg(feature = "fault-injection")]
    #[test]
    fn corrupt_artifact_and_stale_release_fail_closed() {
        let (_corrupt_dir, corrupt_checkpoint) = crashed_checkpoint("fri_layer_0");
        let manifest = CheckpointManifestV2::read(&corrupt_checkpoint).unwrap();
        let artifact = manifest
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == PipelineArtifactKindV1::FriLayer)
            .unwrap();
        let path = corrupt_checkpoint
            .parent()
            .unwrap()
            .join(&artifact.relative_path);
        let mut bytes = fs::read(&path).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(path, bytes).unwrap();
        assert!(resume_resource_bounded(&corrupt_checkpoint).is_err());

        for identity in ["release", "profile", "dependency_lock"] {
            let (_stale_dir, stale_checkpoint) = crashed_checkpoint("quotient_commitment");
            let mut manifest = CheckpointManifestV2::read(&stale_checkpoint).unwrap();
            match identity {
                "release" => manifest.release_hash = [0; 32],
                "profile" => manifest.profile_hash = [0; 32],
                "dependency_lock" => manifest.dependency_lock_hash = [0; 32],
                _ => unreachable!(),
            }
            manifest.write_atomic(&stale_checkpoint).unwrap();
            assert!(
                resume_resource_bounded(&stale_checkpoint).is_err(),
                "stale {identity} checkpoint was accepted"
            );
        }
    }

    #[cfg(all(feature = "fault-injection", target_os = "linux"))]
    #[test]
    fn disk_full_failure_retains_a_resumable_checkpoint() {
        use std::io::Write;

        let Some(root) = std::env::var_os("TINYZKP_DISK_FULL_SCRATCH") else {
            return;
        };
        struct FillAfterTrace {
            root: PathBuf,
            filled: AtomicBool,
        }
        impl FailureInjector for FillAfterTrace {
            fn after_checkpoint(&self, phase: &PipelinePhaseV1) {
                if phase != &PipelinePhaseV1::Trace || self.filled.swap(true, Ordering::SeqCst) {
                    return;
                }
                let mut file = fs::File::create(self.root.join("disk-fill.bin")).unwrap();
                let block = vec![0xa5; 1024 * 1024];
                let write_error = loop {
                    match file.write_all(&block) {
                        Ok(()) => {}
                        Err(error) => break error,
                    }
                };
                assert_eq!(
                    write_error.raw_os_error(),
                    Some(28),
                    "disk-full injector must observe Linux ENOSPC"
                );
                let _ = file.sync_all();
            }
        }

        let root = PathBuf::from(root);
        let workload = FibonacciWorkload {
            initial_a: 0,
            initial_b: 1,
            logical_rows: 4096,
        };
        let mut disk_policy = policy(&root);
        disk_policy.max_scratch_bytes = 1024 * 1024 * 1024;
        disk_policy.checkpoint_policy = CheckpointPolicy::RetainOnFailure;
        let injector = FillAfterTrace {
            root: root.clone(),
            filled: AtomicBool::new(false),
        };
        let result = prove_resource_bounded_observed_with_control(
            &workload,
            &disk_policy,
            CancellationToken::new(),
            &injector,
            |_| {},
        );
        assert!(result.is_err(), "the full scratch device must fail closed");
        fs::remove_file(root.join("disk-fill.bin")).unwrap();
        let checkpoint = fs::read_dir(&root)
            .unwrap()
            .filter_map(std::result::Result::ok)
            .map(|entry| entry.path().join("checkpoint.json"))
            .find(|path| path.is_file())
            .expect("disk-full failure retained the trace checkpoint");
        let resumed = resume_resource_bounded(&checkpoint).unwrap();
        let reference = prove_resource_reference(&workload).unwrap();
        assert_eq!(resumed.proof_bytes, reference);
        eprintln!(
            "tinyzkp-disk-full-resume enospc=true resumed={} reference={}",
            blake3::hash(&resumed.proof_bytes),
            blake3::hash(&reference),
        );
    }
}
