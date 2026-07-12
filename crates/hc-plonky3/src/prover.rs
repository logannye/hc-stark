use crate::checkpoint::profile_permutation;
use crate::contracts::MAX_PROOF_BYTES;
use crate::workloads::{
    fibonacci_public_values, fibonacci_trace, poseidon2_goldilocks_air, poseidon2_trace,
    FibonacciAir,
};
use hc_stream::{
    ExecutionMode, PhaseEstimate, PipelinePhaseV1, ResourceEstimate, ResourceMode, ResourcePolicyV1,
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::{Radix2DitParallel, TwoAdicSubgroupDft};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{prove, verify, Proof, StarkConfig};
use serde::{Deserialize, Serialize};

pub const PLONKY3_VERSION: &str = "0.6.1";
pub const COMPATIBILITY_PROFILE: &str = "tinyzkp-p3-goldilocks-v1";
/// Canonical Goldilocks inputs are integers in `[0, p)`. Accepting arbitrary
/// `u64` values would make distinct manifests collapse to the same public
/// field element and would lose the original input across checkpoint resume.
pub const GOLDILOCKS_MODULUS_U64: u64 = 0xffff_ffff_0000_0001;
pub const DEPENDENCY_LOCK_SHA256: &str =
    "69f5e163151874abd6b298858e25ea89a1f3d91f93535dfb6d87e2a5d0ef3020";

/// Resolve the running release identity. Certified builds use their embedded
/// identity; development builds may supply an explicit operator identity.
pub fn release_identity() -> String {
    option_env!("HC_RELEASE_SHA")
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            std::env::var("HC_RELEASE_SHA")
                .ok()
                .filter(|value| !value.is_empty())
        })
        .unwrap_or_else(|| "development-unreleased".into())
}

pub(crate) type Val = Goldilocks;
pub(crate) type Challenge = BinomialExtensionField<Val, 2>;
pub(crate) type Permutation = Poseidon2Goldilocks<8>;
pub(crate) type Hash = PaddingFreeSponge<Permutation, 8, 4, 4>;
pub(crate) type Compression = TruncatedPermutation<Permutation, 2, 4, 8>;
pub(crate) type ValPacking = <Val as Field>::Packing;
pub(crate) type ValMmcs = MerkleTreeMmcs<ValPacking, ValPacking, Hash, Compression, 2, 4>;
pub(crate) type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
pub(crate) type Challenger = DuplexChallenger<Val, Permutation, 8, 4>;
pub(crate) type Pcs<Dft> = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
pub(crate) type GoldilocksConfig<Dft> = StarkConfig<Pcs<Dft>, Challenge, Challenger>;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("unsupported workload or row count")]
    InvalidWorkload,
    #[error("proof bundle exceeds the size limit")]
    ProofTooLarge,
    #[error("proof bundle profile or dependency version mismatch")]
    ProfileMismatch,
    #[error("proof digest mismatch")]
    DigestMismatch,
    #[error("official Plonky3 verifier rejected the proof: {0}")]
    Verification(String),
    #[error("proof serialization failed: {0}")]
    Serialization(String),
    #[error("failed to construct the resource-policy worker pool")]
    WorkerPool,
    #[error(transparent)]
    Dft(#[from] crate::dft::DftError),
    #[error(transparent)]
    Bounded(#[from] crate::bounded_prover::BoundedProverError),
}

pub type Result<T> = std::result::Result<T, BackendError>;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "workload", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkloadKind {
    Fibonacci { initial_a: u64, initial_b: u64 },
    Poseidon2,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InternalProofBundle {
    pub schema_version: u32,
    pub compatibility_profile: String,
    pub plonky3_version: String,
    pub workload: WorkloadKind,
    pub logical_rows: u64,
    pub public_values: Vec<u64>,
    pub proof_bytes: Vec<u8>,
    pub proof_digest: [u8; 32],
}

impl InternalProofBundle {
    pub fn validate_envelope(&self) -> Result<()> {
        if self.schema_version != 1
            || self.compatibility_profile != COMPATIBILITY_PROFILE
            || self.plonky3_version != PLONKY3_VERSION
        {
            return Err(BackendError::ProfileMismatch);
        }
        if self.proof_bytes.len() > MAX_PROOF_BYTES {
            return Err(BackendError::ProofTooLarge);
        }
        if blake3::hash(&self.proof_bytes).as_bytes() != &self.proof_digest {
            return Err(BackendError::DigestMismatch);
        }
        validate_rows(self.logical_rows)?;
        Ok(())
    }
}

/// Prover orchestration that emits the official `p3_uni_stark::Proof` encoding.
/// TinyZKP adds no custom transcript or verifier.
#[derive(Clone, Debug)]
pub struct ResourceBoundedUniStarkProver {
    policy: ResourcePolicyV1,
}

impl ResourceBoundedUniStarkProver {
    pub fn new(policy: ResourcePolicyV1) -> Result<Self> {
        policy.validate().map_err(crate::dft::DftError::from)?;
        Ok(Self { policy })
    }

    pub fn policy(&self) -> &ResourcePolicyV1 {
        &self.policy
    }

    pub fn prove(&self, workload: WorkloadKind, logical_rows: u64) -> Result<InternalProofBundle> {
        let rows = validate_rows(logical_rows)?;
        validate_workload(&workload)?;
        match workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => self.prove_fibonacci(initial_a, initial_b, rows),
            WorkloadKind::Poseidon2 => self.prove_poseidon2(rows),
        }
    }

    pub fn prove_with_events<Observe>(
        &self,
        workload: WorkloadKind,
        logical_rows: u64,
        observe: Observe,
    ) -> Result<InternalProofBundle>
    where
        Observe: FnMut(&crate::ProverEventV1),
    {
        self.prove_with_events_and_cancellation(
            workload,
            logical_rows,
            crate::CancellationToken::new(),
            observe,
        )
    }

    pub fn prove_with_events_and_cancellation<Observe>(
        &self,
        workload: WorkloadKind,
        logical_rows: u64,
        cancellation: crate::CancellationToken,
        mut observe: Observe,
    ) -> Result<InternalProofBundle>
    where
        Observe: FnMut(&crate::ProverEventV1),
    {
        let rows = validate_rows(logical_rows)?;
        validate_workload(&workload)?;
        if cancellation.is_cancelled() {
            return Err(BackendError::Bounded(crate::BoundedProverError::Cancelled));
        }
        let use_memory = match &workload {
            WorkloadKind::Fibonacci { .. } => uses_in_memory_pipeline(&self.policy, rows, 2, 1),
            WorkloadKind::Poseidon2 => uses_in_memory_pipeline(&self.policy, rows, 180, 2),
        };
        if use_memory {
            let estimate = match &workload {
                WorkloadKind::Fibonacci { .. } => conventional_pipeline_estimate(rows, 2, 1),
                WorkloadKind::Poseidon2 => conventional_pipeline_estimate(rows, 180, 2),
            };
            observe(&crate::ProverEventV1::ResourceEstimate { estimate });
            let proof = self.prove(workload, logical_rows)?;
            if cancellation.is_cancelled() {
                return Err(BackendError::Bounded(crate::BoundedProverError::Cancelled));
            }
            observe(&crate::ProverEventV1::Phase {
                phase: PipelinePhaseV1::ProofAssembly,
                completed_phases: 1,
                total_phases: 1,
                checkpoint_path: None,
                resource_usage: crate::bounded_prover::measure_resource_usage(None),
            });
            return Ok(proof);
        }
        match workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => {
                let proof_bytes = crate::prove_resource_bounded_observed_with_cancellation(
                    &crate::FibonacciWorkload {
                        initial_a,
                        initial_b,
                        logical_rows,
                    },
                    &self.policy,
                    cancellation,
                    &mut observe,
                )?;
                let public = crate::fibonacci_public_values(initial_a, initial_b, rows);
                Ok(bundle(
                    WorkloadKind::Fibonacci {
                        initial_a,
                        initial_b,
                    },
                    rows,
                    public
                        .iter()
                        .map(|value| value.as_canonical_u64())
                        .collect(),
                    proof_bytes,
                ))
            }
            WorkloadKind::Poseidon2 => {
                let proof_bytes = crate::prove_resource_bounded_observed_with_cancellation(
                    &crate::Poseidon2Workload { logical_rows },
                    &self.policy,
                    cancellation,
                    &mut observe,
                )?;
                Ok(bundle(WorkloadKind::Poseidon2, rows, vec![], proof_bytes))
            }
        }
    }

    pub fn verify(bundle: &InternalProofBundle) -> Result<()> {
        bundle.validate_envelope()?;
        validate_workload(&bundle.workload)?;
        let rows = validate_rows(bundle.logical_rows)?;
        let config = make_config(Radix2DitParallel::<Val>::default());
        match bundle.workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => {
                if bundle.public_values.len() != 3 {
                    return Err(BackendError::InvalidWorkload);
                }
                let expected = fibonacci_public_values(initial_a, initial_b, rows)
                    .into_iter()
                    .map(|value| value.as_canonical_u64())
                    .collect::<Vec<_>>();
                if bundle.public_values != expected {
                    return Err(BackendError::InvalidWorkload);
                }
                let public: Vec<_> = expected.into_iter().map(Val::from_u64).collect();
                let proof: Proof<GoldilocksConfig<Radix2DitParallel<Val>>> =
                    decode_proof(&bundle.proof_bytes)?;
                verify(&config, &FibonacciAir, &proof, &public)
                    .map_err(|error| BackendError::Verification(format!("{error:?}")))
            }
            WorkloadKind::Poseidon2 => {
                if !bundle.public_values.is_empty() {
                    return Err(BackendError::InvalidWorkload);
                }
                let proof: Proof<GoldilocksConfig<Radix2DitParallel<Val>>> =
                    decode_proof(&bundle.proof_bytes)?;
                verify(&config, &poseidon2_goldilocks_air(), &proof, &[])
                    .map_err(|error| BackendError::Verification(format!("{error:?}")))
            }
        }
    }

    /// Conventional upstream DFT path used only as the benchmark baseline.
    pub fn prove_reference(
        workload: WorkloadKind,
        logical_rows: u64,
    ) -> Result<InternalProofBundle> {
        let rows = validate_rows(logical_rows)?;
        validate_workload(&workload)?;
        match workload {
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            } => {
                let trace = fibonacci_trace::<Val>(initial_a, initial_b, rows);
                let public = vec![
                    Val::from_u64(initial_a),
                    Val::from_u64(initial_b),
                    trace.values[trace.values.len() - 1],
                ];
                let proof_bytes = prove_to_bytes(
                    Radix2DitParallel::<Val>::default(),
                    &FibonacciAir,
                    trace,
                    &public,
                )?;
                Ok(bundle(
                    WorkloadKind::Fibonacci {
                        initial_a,
                        initial_b,
                    },
                    rows,
                    public
                        .iter()
                        .map(|value| value.as_canonical_u64())
                        .collect(),
                    proof_bytes,
                ))
            }
            WorkloadKind::Poseidon2 => {
                let trace = poseidon2_trace(rows, 0);
                let proof_bytes = prove_to_bytes(
                    Radix2DitParallel::<Val>::default(),
                    &poseidon2_goldilocks_air(),
                    trace,
                    &[],
                )?;
                Ok(bundle(WorkloadKind::Poseidon2, rows, vec![], proof_bytes))
            }
        }
    }

    fn prove_fibonacci(
        &self,
        initial_a: u64,
        initial_b: u64,
        rows: usize,
    ) -> Result<InternalProofBundle> {
        if !uses_in_memory_pipeline(&self.policy, rows, 2, 1) {
            let proof_bytes = crate::bounded_prover::prove_resource_bounded(
                &crate::FibonacciWorkload {
                    initial_a,
                    initial_b,
                    logical_rows: rows as u64,
                },
                &self.policy,
            )?;
            let public = crate::fibonacci_public_values(initial_a, initial_b, rows);
            return Ok(bundle(
                WorkloadKind::Fibonacci {
                    initial_a,
                    initial_b,
                },
                rows,
                public
                    .iter()
                    .map(|value| value.as_canonical_u64())
                    .collect(),
                proof_bytes,
            ));
        }
        preflight_memory(&self.policy, conventional_pipeline_estimate(rows, 2, 1))?;
        let (public, proof_bytes) = in_policy_pool(&self.policy, || {
            let trace = fibonacci_trace::<Val>(initial_a, initial_b, rows);
            let public = vec![
                Val::from_u64(initial_a),
                Val::from_u64(initial_b),
                trace.values[trace.values.len() - 1],
            ];
            let proof_bytes = prove_to_bytes(
                Radix2DitParallel::<Val>::default(),
                &FibonacciAir,
                trace,
                &public,
            )?;
            Ok((public, proof_bytes))
        })?;
        Ok(bundle(
            WorkloadKind::Fibonacci {
                initial_a,
                initial_b,
            },
            rows,
            public
                .iter()
                .map(|value| value.as_canonical_u64())
                .collect(),
            proof_bytes,
        ))
    }

    fn prove_poseidon2(&self, rows: usize) -> Result<InternalProofBundle> {
        if !uses_in_memory_pipeline(&self.policy, rows, 180, 2) {
            let proof_bytes = crate::bounded_prover::prove_resource_bounded(
                &crate::Poseidon2Workload {
                    logical_rows: rows as u64,
                },
                &self.policy,
            )?;
            return Ok(bundle(WorkloadKind::Poseidon2, rows, vec![], proof_bytes));
        }
        preflight_memory(&self.policy, conventional_pipeline_estimate(rows, 180, 2))?;
        let proof_bytes = in_policy_pool(&self.policy, || {
            let trace = poseidon2_trace(rows, 0);
            prove_to_bytes(
                Radix2DitParallel::<Val>::default(),
                &poseidon2_goldilocks_air(),
                trace,
                &[],
            )
        })?;
        Ok(bundle(WorkloadKind::Poseidon2, rows, vec![], proof_bytes))
    }
}

pub(crate) fn uses_in_memory_pipeline(
    policy: &ResourcePolicyV1,
    rows: usize,
    trace_width: u64,
    quotient_chunks: u64,
) -> bool {
    match policy.mode {
        ResourceMode::Memory => true,
        ResourceMode::Scratch => false,
        ResourceMode::Auto => {
            // Conventional Plonky3 retains owned trace/LDE, quotient, MMCS,
            // and FRI vectors. This conservative profile-specific estimate is
            // used only for Auto selection; Scratch performs its own exact
            // phase preflight.
            conventional_pipeline_estimate(rows, trace_width, quotient_chunks).peak_resident_bytes
                <= policy.memory_selection_threshold()
        }
    }
}

pub(crate) fn conventional_pipeline_estimate(
    rows: usize,
    trace_width: u64,
    quotient_chunks: u64,
) -> ResourceEstimate {
    let peak_resident_bytes = (rows as u64)
        .saturating_mul(
            24u64
                .saturating_mul(trace_width)
                .saturating_add(32u64.saturating_mul(quotient_chunks))
                .saturating_add(448),
        )
        .saturating_add(32 * 1024 * 1024);
    ResourceEstimate {
        peak_resident_bytes,
        scratch_high_water_bytes: 1,
        total_read_bytes: 0,
        total_write_bytes: 0,
        phases: vec![PhaseEstimate {
            phase: "conventional_full_pipeline".into(),
            read_bytes: 0,
            write_bytes: 0,
        }],
    }
}

fn preflight_memory(policy: &ResourcePolicyV1, estimate: ResourceEstimate) -> Result<()> {
    policy
        .preflight_for_mode(ExecutionMode::Memory, estimate)
        .map_err(crate::dft::DftError::from)?;
    Ok(())
}

fn in_policy_pool<T: Send>(
    policy: &ResourcePolicyV1,
    operation: impl FnOnce() -> Result<T> + Send,
) -> Result<T> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(policy.max_threads)
        .build()
        .map_err(|_| BackendError::WorkerPool)?
        .install(operation)
}

fn validate_rows(rows: u64) -> Result<usize> {
    let rows = usize::try_from(rows).map_err(|_| BackendError::InvalidWorkload)?;
    if rows == 0 || !rows.is_power_of_two() || rows > (1usize << 30) {
        return Err(BackendError::InvalidWorkload);
    }
    Ok(rows)
}

fn validate_workload(workload: &WorkloadKind) -> Result<()> {
    match workload {
        WorkloadKind::Fibonacci {
            initial_a,
            initial_b,
        } if *initial_a < GOLDILOCKS_MODULUS_U64 && *initial_b < GOLDILOCKS_MODULUS_U64 => Ok(()),
        WorkloadKind::Poseidon2 => Ok(()),
        WorkloadKind::Fibonacci { .. } => Err(BackendError::InvalidWorkload),
    }
}

fn bundle(
    workload: WorkloadKind,
    rows: usize,
    public_values: Vec<u64>,
    proof_bytes: Vec<u8>,
) -> InternalProofBundle {
    InternalProofBundle {
        schema_version: 1,
        compatibility_profile: COMPATIBILITY_PROFILE.into(),
        plonky3_version: PLONKY3_VERSION.into(),
        workload,
        logical_rows: rows as u64,
        public_values,
        proof_digest: *blake3::hash(&proof_bytes).as_bytes(),
        proof_bytes,
    }
}

pub(crate) fn make_config<Dft: TwoAdicSubgroupDft<Val>>(dft: Dft) -> GoldilocksConfig<Dft> {
    make_config_with_log_blowup(dft, 1)
}

pub(crate) fn make_config_with_log_blowup<Dft: TwoAdicSubgroupDft<Val>>(
    dft: Dft,
    log_blowup: usize,
) -> GoldilocksConfig<Dft> {
    // Copied without parameter changes from Plonky3 v0.6.1's
    // `prove_goldilocks_poseidon2` example.
    let (permutation, hash, compression) = profile_components();
    let val_mmcs = ValMmcs::new(hash, compression, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let mut fri_parameters = FriParameters::new_benchmark(challenge_mmcs);
    fri_parameters.log_blowup = log_blowup;
    let pcs = Pcs::new(dft, val_mmcs, fri_parameters);
    let challenger = Challenger::new(permutation);
    GoldilocksConfig::new(pcs, challenger)
}

pub(crate) fn profile_components() -> (Permutation, Hash, Compression) {
    let permutation = profile_permutation();
    let hash = Hash::new(permutation.clone());
    let compression = Compression::new(permutation.clone());
    (permutation, hash, compression)
}

fn prove_to_bytes<Dft, Air>(
    dft: Dft,
    air: &Air,
    trace: RowMajorMatrix<Val>,
    public_values: &[Val],
) -> Result<Vec<u8>>
where
    Dft: TwoAdicSubgroupDft<Val>,
    Air: for<'a> p3_air::Air<p3_uni_stark::ProverConstraintFolder<'a, GoldilocksConfig<Dft>>>
        + for<'a> p3_air::Air<p3_air::DebugConstraintBuilder<'a, Val>>
        + p3_air::Air<p3_air::SymbolicAirBuilder<Val>>
        + p3_air::BaseAir<Val>,
{
    let config = make_config(dft);
    let proof = prove(&config, air, trace, public_values);
    let bytes = postcard::to_allocvec(&proof)
        .map_err(|error| BackendError::Serialization(error.to_string()))?;
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(BackendError::ProofTooLarge);
    }
    Ok(bytes)
}

fn decode_proof<Config: p3_uni_stark::StarkGenericConfig>(bytes: &[u8]) -> Result<Proof<Config>> {
    if bytes.len() > MAX_PROOF_BYTES {
        return Err(BackendError::ProofTooLarge);
    }
    postcard::from_bytes(bytes).map_err(|error| BackendError::Serialization(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ResourceBoundedDft;
    use hc_stream::{CheckpointPolicy, ResourceMode};

    fn policy(root: &std::path::Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 128 * 1024 * 1024,
            max_scratch_bytes: 1024 * 1024 * 1024,
            scratch_dir: root.to_path_buf(),
            max_threads: 1,
            checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
        }
    }

    fn memory_policy(root: &std::path::Path) -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Memory,
            ..policy(root)
        }
    }

    #[test]
    fn fibonacci_proof_is_accepted_by_unmodified_plonky3_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        let bundle = prover
            .prove(
                WorkloadKind::Fibonacci {
                    initial_a: 0,
                    initial_b: 1,
                },
                8,
            )
            .unwrap();
        ResourceBoundedUniStarkProver::verify(&bundle).unwrap();
    }

    #[test]
    fn maximum_goldilocks_public_value_is_bounded_and_official() {
        const MAX_GOLDILOCKS: u64 = 0xffff_ffff_0000_0000;
        let dir = tempfile::tempdir().unwrap();
        let workload = WorkloadKind::Fibonacci {
            initial_a: MAX_GOLDILOCKS,
            initial_b: 0,
        };
        let bounded = ResourceBoundedUniStarkProver::new(policy(dir.path()))
            .unwrap()
            .prove(workload.clone(), 16)
            .unwrap();
        let reference = ResourceBoundedUniStarkProver::prove_reference(workload, 16).unwrap();
        assert_eq!(bounded.proof_bytes, reference.proof_bytes);
        assert_eq!(bounded.public_values[0], MAX_GOLDILOCKS);
        ResourceBoundedUniStarkProver::verify(&bounded).unwrap();
    }

    #[test]
    fn noncanonical_fibonacci_inputs_are_rejected_before_proving_or_verification() {
        let dir = tempfile::tempdir().unwrap();
        let workload = WorkloadKind::Fibonacci {
            initial_a: GOLDILOCKS_MODULUS_U64,
            initial_b: 0,
        };
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        assert!(matches!(
            prover.prove(workload.clone(), 16),
            Err(BackendError::InvalidWorkload)
        ));
        assert!(matches!(
            ResourceBoundedUniStarkProver::prove_reference(workload, 16),
            Err(BackendError::InvalidWorkload)
        ));
    }

    #[test]
    fn poseidon2_proof_is_accepted_by_unmodified_plonky3_verifier() {
        let dir = tempfile::tempdir().unwrap();
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        let bundle = prover.prove(WorkloadKind::Poseidon2, 8).unwrap();
        ResourceBoundedUniStarkProver::verify(&bundle).unwrap();
    }

    #[test]
    fn public_value_and_proof_mutations_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let prover = ResourceBoundedUniStarkProver::new(policy(dir.path())).unwrap();
        let bundle = prover
            .prove(
                WorkloadKind::Fibonacci {
                    initial_a: 0,
                    initial_b: 1,
                },
                8,
            )
            .unwrap();

        let mut public_mutation = bundle.clone();
        public_mutation.public_values[2] ^= 1;
        assert!(ResourceBoundedUniStarkProver::verify(&public_mutation).is_err());

        let mut proof_mutation = bundle;
        proof_mutation.proof_bytes[0] ^= 1;
        assert!(matches!(
            ResourceBoundedUniStarkProver::verify(&proof_mutation),
            Err(BackendError::DigestMismatch)
        ));
    }

    #[test]
    fn official_verifier_rejects_mutations_in_every_major_proof_section() {
        let rows = 64usize;
        let internal = ResourceBoundedUniStarkProver::prove_reference(
            WorkloadKind::Fibonacci {
                initial_a: 0,
                initial_b: 1,
            },
            rows as u64,
        )
        .unwrap();
        let fresh = || -> Proof<GoldilocksConfig<Radix2DitParallel<Val>>> {
            decode_proof(&internal.proof_bytes).unwrap()
        };
        let trace = fibonacci_trace::<Val>(0, 1, rows);
        let public = vec![Val::ZERO, Val::ONE, *trace.values.last().unwrap()];
        let config = make_config(Radix2DitParallel::<Val>::default());
        let rejects = |candidate: &Proof<GoldilocksConfig<Radix2DitParallel<Val>>>| {
            assert!(verify(&config, &FibonacciAir, candidate, &public).is_err());
        };

        let mut candidate = fresh();
        let mut roots = candidate.commitments.trace.clone().into_roots();
        roots[0][0] += Val::ONE;
        candidate.commitments.trace = p3_merkle_tree::MerkleCap::new(roots);
        rejects(&candidate);

        let mut candidate = fresh();
        let mut roots = candidate.commitments.quotient_chunks.clone().into_roots();
        roots[0][0] += Val::ONE;
        candidate.commitments.quotient_chunks = p3_merkle_tree::MerkleCap::new(roots);
        rejects(&candidate);

        let mut candidate = fresh();
        candidate.opened_values.trace_local[0] += Challenge::ONE;
        rejects(&candidate);

        let mut candidate = fresh();
        let mut roots = candidate.opening_proof.commit_phase_commits[0]
            .clone()
            .into_roots();
        roots[0][0] += Val::ONE;
        candidate.opening_proof.commit_phase_commits[0] = p3_merkle_tree::MerkleCap::new(roots);
        rejects(&candidate);

        let mut candidate = fresh();
        candidate.opening_proof.final_poly[0] += Challenge::ONE;
        rejects(&candidate);

        let mut candidate = fresh();
        candidate.opening_proof.query_proofs[0].input_proof[0].opened_values[0][0] += Val::ONE;
        rejects(&candidate);

        let mut candidate = fresh();
        candidate.opening_proof.query_proofs[0].commit_phase_openings[0].sibling_values[0] +=
            Challenge::ONE;
        rejects(&candidate);
    }

    #[test]
    fn scratch_and_reference_dft_emit_identical_fibonacci_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let trace = fibonacci_trace::<Val>(0, 1, 8);
        let public = vec![Val::ZERO, Val::ONE, Val::from_u64(21)];
        let bounded = prove_to_bytes(
            ResourceBoundedDft::new(policy(dir.path())).unwrap(),
            &FibonacciAir,
            trace.clone(),
            &public,
        )
        .unwrap();
        let reference = prove_to_bytes(
            Radix2DitParallel::<Val>::default(),
            &FibonacciAir,
            trace,
            &public,
        )
        .unwrap();
        assert_eq!(bounded, reference);
    }

    #[test]
    fn scratch_and_reference_dft_emit_identical_poseidon2_proof_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let trace = poseidon2_trace(8, 0);
        let bounded = prove_to_bytes(
            ResourceBoundedDft::new(policy(dir.path())).unwrap(),
            &poseidon2_goldilocks_air(),
            trace.clone(),
            &[],
        )
        .unwrap();
        let reference = prove_to_bytes(
            Radix2DitParallel::<Val>::default(),
            &poseidon2_goldilocks_air(),
            trace,
            &[],
        )
        .unwrap();
        assert_eq!(bounded, reference);
    }

    #[test]
    fn memory_and_scratch_modes_emit_identical_official_proofs() {
        let dir = tempfile::tempdir().unwrap();
        let workload = WorkloadKind::Fibonacci {
            initial_a: 0,
            initial_b: 1,
        };
        let memory = ResourceBoundedUniStarkProver::new(memory_policy(dir.path()))
            .unwrap()
            .prove(workload.clone(), 16)
            .unwrap();
        let scratch = ResourceBoundedUniStarkProver::new(policy(dir.path()))
            .unwrap()
            .prove(workload, 16)
            .unwrap();
        assert_eq!(memory, scratch);
    }

    #[test]
    fn memory_mode_thread_limit_does_not_change_proof_bytes() {
        let one_dir = tempfile::tempdir().unwrap();
        let four_dir = tempfile::tempdir().unwrap();
        let workload = WorkloadKind::Fibonacci {
            initial_a: 17,
            initial_b: 29,
        };
        let one = ResourceBoundedUniStarkProver::new(memory_policy(one_dir.path()))
            .unwrap()
            .prove(workload.clone(), 32)
            .unwrap();
        let mut four_policy = memory_policy(four_dir.path());
        four_policy.max_threads = 4;
        let four = ResourceBoundedUniStarkProver::new(four_policy)
            .unwrap()
            .prove(workload, 32)
            .unwrap();
        assert_eq!(one.proof_bytes, four.proof_bytes);
    }

    #[test]
    fn auto_selects_memory_only_below_full_pipeline_seventy_percent_threshold() {
        let dir = tempfile::tempdir().unwrap();
        let mut auto = policy(dir.path());
        auto.mode = ResourceMode::Auto;
        assert!(uses_in_memory_pipeline(&auto, 16, 2, 1));
        assert!(!uses_in_memory_pipeline(&auto, 1 << 20, 180, 2));
    }

    #[test]
    fn explicit_memory_mode_rejects_an_insufficient_cap_before_trace_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let mut memory = memory_policy(dir.path());
        memory.max_resident_bytes = 16 * 1024 * 1024;
        let error = ResourceBoundedUniStarkProver::new(memory)
            .unwrap()
            .prove(WorkloadKind::Poseidon2, 1 << 20)
            .unwrap_err();
        assert!(matches!(
            error,
            BackendError::Dft(crate::dft::DftError::Stream(
                hc_stream::StreamError::ResourceLimit {
                    resource: "resident memory",
                    ..
                }
            ))
        ));
    }

    #[test]
    #[ignore = "nightly fixed-host proof equality matrix"]
    fn nightly_proof_equality_through_configured_power_of_two() {
        let max_log = std::env::var("TINYZKP_NIGHTLY_MAX_LOG")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(14)
            .clamp(10, 18);
        let mut logs = vec![10, 14, max_log];
        logs.sort_unstable();
        logs.dedup();
        for log_rows in logs {
            let rows = 1u64 << log_rows;
            for workload in [
                WorkloadKind::Fibonacci {
                    initial_a: (log_rows * 17) as u64,
                    initial_b: (log_rows * 29 + 1) as u64,
                },
                WorkloadKind::Poseidon2,
            ] {
                let dir = tempfile::tempdir().unwrap();
                let bounded_policy = ResourcePolicyV1 {
                    mode: ResourceMode::Scratch,
                    max_resident_bytes: 2 * 1024 * 1024 * 1024,
                    max_scratch_bytes: 64 * 1024 * 1024 * 1024,
                    scratch_dir: dir.path().into(),
                    max_threads: 8,
                    checkpoint_policy: CheckpointPolicy::DeleteOnSuccess,
                };
                let bounded = ResourceBoundedUniStarkProver::new(bounded_policy)
                    .unwrap()
                    .prove(workload.clone(), rows)
                    .unwrap();
                let conventional =
                    ResourceBoundedUniStarkProver::prove_reference(workload, rows).unwrap();
                assert_eq!(bounded.proof_bytes, conventional.proof_bytes);
                ResourceBoundedUniStarkProver::verify(&bounded).unwrap();
            }
        }
    }
}
