//! TinyZKP's Plonky3-first backend.
//!
//! The proof and verifier remain `p3-uni-stark` 0.6.1. TinyZKP supplies a
//! resource policy, scratch-backed DFT result matrices, workload manifests,
//! deterministic packaging, and recovery provenance.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod beta_fixtures;
mod bounded_pcs;
mod bounded_prover;
mod checkpoint;
pub mod contracts;
mod declarative;
mod dft;
pub mod estimate_params;
mod fri;
mod mmcs;
mod opening;
mod prover;
mod quotient;
mod scratch;
mod workloads;

pub use bounded_pcs::{
    make_bounded_verifier_config, make_durable_mmcs, BoundedConfig, DurableChallengeMmcs,
    DurableInputMmcs, DurablePcsProof, ResourceBoundedVerifierPcs,
};
#[cfg(feature = "fault-injection")]
pub use bounded_prover::EnvironmentAbortFailureInjector;
pub use bounded_prover::{
    estimate_builtin_manifest, estimate_resource_bounded_workload,
    estimate_resource_conventional_workload, inspect_resource_bounded_checkpoint,
    plan_resource_workload, preflight_builtin_manifest, prove_resource_bounded,
    prove_resource_bounded_observed, prove_resource_bounded_observed_with_cancellation,
    prove_resource_bounded_observed_with_cancellation_at_checkpoint_dir,
    prove_resource_bounded_observed_with_control, prove_resource_reference,
    prove_resource_with_policy, prove_resource_with_policy_observed_with_cancellation,
    prove_resource_with_policy_observed_with_cancellation_at_checkpoint_dir,
    resume_resource_bounded, resume_resource_bounded_cancelable,
    resume_resource_bounded_cancelable_observed, resume_resource_bounded_with,
    resume_resource_bounded_with_cancellation, resume_resource_bounded_with_cancellation_observed,
    resume_resource_bounded_with_control, verify_resource_bounded_proof, BoundedProverError,
    CancellationToken, CheckpointInspectionV1, FailureInjector, NoopFailureInjector,
    PlannedResourceProofV1, ProverEventV1, ResourceExecutionPlanV1, ResourceUsageV1,
    ResumedProofV1,
};
pub use checkpoint::{
    ChallengerSnapshotError, ChallengerSnapshotV1, ProfileChallenger, ProfilePermutation,
};
pub use declarative::{
    estimate_declarative_execution_paths, estimate_declarative_statement,
    plan_declarative_statement, verify_declarative_proof, DeclarativeAir, UploadedTraceWorkload,
};
pub use dft::{GoldilocksWord, ResourceBoundedDft, ResourceBoundedMatrix, ScratchPlonky3Matrix};
pub use fri::{
    fold_binary_layer, prove_durable_fri, prove_durable_fri_observed,
    prove_durable_fri_observed_batched, resume_durable_fri_observed,
    resume_durable_fri_observed_batched, ChallengeArityMatrix, DurableFriCommitment,
    DurableFriError, FriLayerCheckpoint, ProfileChallenge, ScratchChallengeVector,
};
pub use mmcs::{DurableGoldilocksMmcs, DurableMerkleData, DurableMmcsError};
pub use opening::{
    build_reduced_opening_layer, interpolate_standard_lde, DurableOpeningError, MatrixOpening,
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
