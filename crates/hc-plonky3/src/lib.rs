//! TinyZKP's Plonky3-first backend.
//!
//! The proof and verifier remain `p3-uni-stark` 0.6.1. TinyZKP supplies a
//! resource policy, scratch-backed DFT result matrices, workload manifests,
//! deterministic packaging, and recovery provenance.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
mod babybear_differential;
pub mod beta_fixtures;
mod bounded_pcs;
mod bounded_prover;
mod checkpoint;
pub mod contracts;
mod declarative;
mod dft;
pub mod estimate_params;
mod fri;
#[cfg(test)]
mod generic_prover_guard;
mod mmcs;
mod opening;
pub mod profile;
mod prover;
mod quotient;
mod scratch;
pub mod security_floor;
mod workloads;

// `dft`, `mmcs`, `fri`, `quotient`, and `bounded_pcs` are now generic over
// `DurableFieldProfile<PERM_WIDTH, DIGEST_ELEMS>`. The names re-exported here
// stay bound to each module's `goldilocks` pin, so this crate's public API is
// unchanged and every production entry point still names `GoldilocksProfile` —
// now explicitly, in exactly one place per module.
pub use bounded_pcs::goldilocks::{
    BoundedConfig, DurableChallengeMmcs, DurableInputMmcs, DurablePcsProof,
    ResourceBoundedVerifierPcs,
};
pub use bounded_pcs::{make_bounded_verifier_config, make_durable_mmcs};
#[cfg(feature = "fault-injection")]
pub use bounded_prover::EnvironmentAbortFailureInjector;
pub use bounded_prover::{
    estimate_builtin_manifest, estimate_resource_bounded_workload,
    estimate_resource_bounded_workload_with_profile, estimate_resource_conventional_workload,
    estimate_resource_conventional_workload_with_profile, inspect_resource_bounded_checkpoint,
    plan_resource_workload, plan_resource_workload_with_profile, preflight_builtin_manifest,
    prove_resource_bounded, prove_resource_bounded_observed,
    prove_resource_bounded_observed_with_cancellation,
    prove_resource_bounded_observed_with_cancellation_at_checkpoint_dir,
    prove_resource_bounded_observed_with_control, prove_resource_bounded_with_profile,
    prove_resource_reference, prove_resource_reference_with_profile, prove_resource_with_policy,
    prove_resource_with_policy_observed_with_cancellation,
    prove_resource_with_policy_observed_with_cancellation_at_checkpoint_dir,
    resume_resource_bounded, resume_resource_bounded_cancelable,
    resume_resource_bounded_cancelable_observed, resume_resource_bounded_with,
    resume_resource_bounded_with_cancellation, resume_resource_bounded_with_cancellation_observed,
    resume_resource_bounded_with_control, verify_resource_bounded_proof,
    verify_resource_bounded_proof_with_profile, BoundedProverError, CancellationToken,
    CheckpointInspectionV1, FailureInjector, NoopFailureInjector, PlannedResourceProofV1,
    ProverEventV1, ResourceExecutionPlanV1, ResourceUsageV1, ResumedProofV1,
};
pub use checkpoint::{
    ChallengerSnapshotError, ChallengerSnapshotV1, ProfileChallenger, ProfilePermutation,
};
pub use declarative::{
    estimate_declarative_execution_paths, estimate_declarative_statement,
    plan_declarative_statement, verify_declarative_proof, DeclarativeAir, UploadedTraceWorkload,
};
pub use dft::goldilocks::{ResourceBoundedDft, ResourceBoundedMatrix, ScratchPlonky3Matrix};
pub use dft::{BabyBearWord, GoldilocksWord};
pub use fri::goldilocks::{
    ChallengeArityMatrix, DurableFriCommitment, FriLayerCheckpoint, ScratchChallengeVector,
};
pub use fri::{
    fold_binary_layer, prove_durable_fri, prove_durable_fri_observed,
    prove_durable_fri_observed_batched, resume_durable_fri_observed,
    resume_durable_fri_observed_batched, DurableFriError, ProfileChallenge,
};
pub use mmcs::goldilocks::{DurableGoldilocksMmcs, DurableMerkleData};
pub use mmcs::DurableMmcsError;
pub use opening::goldilocks::MatrixOpening;
pub use opening::{build_reduced_opening_layer, interpolate_standard_lde, DurableOpeningError};
pub use profile::{
    declared_field_profile, BabyBearProfile, DeclaredFieldProfile, DurableFieldProfile,
    GoldilocksProfile, BABYBEAR_MODULUS_U64, DECLARED_FIELD_PROFILES,
};
pub use prover::{
    release_identity, BackendError, InternalProofBundle, ResourceBoundedUniStarkProver,
    WorkloadKind, COMPATIBILITY_PROFILE, DEPENDENCY_LOCK_SHA256, GOLDILOCKS_MODULUS_U64,
    PLONKY3_VERSION,
};
pub use quotient::{build_quotient_chunk_ldes, stream_quotient_values, StreamedQuotientError};
pub use workloads::{
    fibonacci_public_values, fibonacci_trace, poseidon2_goldilocks_air, poseidon2_trace,
    FibonacciAir, FibonacciWorkload, GeneratedTraceV1, Poseidon2GoldilocksAir, Poseidon2Workload,
    ResourceBoundedWorkload, WorkloadError, WorkloadIdentityV1,
};

/// `bounded_pcs`, `dft`, `fri`, `mmcs`, and `quotient` re-exported in their
/// PROFILE-GENERIC form, for callers proving at a profile other than
/// Goldilocks. The unsuffixed names above stay bound to the Goldilocks pins so
/// this crate's existing public API is unchanged.
pub mod generic {
    pub use crate::bounded_pcs::{
        BoundedConfig, DurableChallengeMmcs, DurableInputMmcs, DurablePcsProof,
        ResourceBoundedVerifierPcs,
    };
    pub use crate::dft::{ResourceBoundedDft, ResourceBoundedMatrix, ScratchPlonky3Matrix};
    pub use crate::fri::{
        ChallengeArityMatrix, DurableFriCommitment, FriLayerCheckpoint, ScratchChallengeVector,
    };
    pub use crate::mmcs::{DurableMerkleData, DurableProfileMmcs};
    pub use crate::quotient::EvaluationConfig;
}

/// Test-only fixtures shared across this crate's unit tests.
#[cfg(test)]
pub(crate) mod test_support {
    use hc_stream::{CheckpointPolicy, ResourceMode, ResourcePolicyV1};
    use std::path::PathBuf;

    /// The 2 GiB ceiling used by examples/plonky3/fibonacci-1m.json, so tests
    /// exercise the published release policy. `ResourcePolicyV1` has no
    /// `Default`, so every field is copied explicitly from that manifest.
    pub fn release_policy_2gib() -> ResourcePolicyV1 {
        ResourcePolicyV1 {
            mode: ResourceMode::Scratch,
            max_resident_bytes: 2 * 1024 * 1024 * 1024,
            max_scratch_bytes: 1_000_000_000,
            scratch_dir: PathBuf::from("/var/lib/tinyzkp-bench/scratch/fibonacci-1m"),
            max_threads: 4,
            checkpoint_policy: CheckpointPolicy::RetainOnFailure,
        }
    }
}
