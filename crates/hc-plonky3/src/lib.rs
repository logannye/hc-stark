//! TinyZKP's Plonky3-first backend.
//!
//! The proof and verifier remain `p3-uni-stark` 0.6.1. TinyZKP supplies a
//! resource policy, scratch-backed DFT result matrices, workload manifests,
//! deterministic packaging, and recovery provenance.

#![deny(unsafe_op_in_unsafe_fn)]

mod bounded_pcs;
mod bounded_prover;
mod checkpoint;
pub mod contracts;
mod dft;
mod fri;
mod mmcs;
mod opening;
mod prover;
mod quotient;
mod workloads;

pub use bounded_pcs::{
    make_bounded_verifier_config, make_durable_mmcs, BoundedConfig, DurableChallengeMmcs,
    DurableInputMmcs, DurablePcsProof, ResourceBoundedVerifierPcs,
};
#[cfg(feature = "fault-injection")]
pub use bounded_prover::EnvironmentAbortFailureInjector;
pub use bounded_prover::{
    estimate_builtin_manifest, estimate_resource_bounded_workload, preflight_builtin_manifest,
    prove_resource_bounded, prove_resource_bounded_observed,
    prove_resource_bounded_observed_with_cancellation,
    prove_resource_bounded_observed_with_control, prove_resource_reference,
    resume_resource_bounded, resume_resource_bounded_cancelable,
    resume_resource_bounded_cancelable_observed, resume_resource_bounded_with,
    resume_resource_bounded_with_cancellation, resume_resource_bounded_with_control,
    verify_resource_bounded_proof, BoundedProverError, CancellationToken, FailureInjector,
    NoopFailureInjector, ProverEventV1, ResourceUsageV1, ResumedProofV1,
};
pub use checkpoint::{
    ChallengerSnapshotError, ChallengerSnapshotV1, ProfileChallenger, ProfilePermutation,
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
    WorkloadKind, COMPATIBILITY_PROFILE, DEPENDENCY_LOCK_SHA256, PLONKY3_VERSION,
};
pub use quotient::{build_quotient_chunk_ldes, stream_quotient_values, StreamedQuotientError};
pub use workloads::{
    fibonacci_public_values, fibonacci_trace, poseidon2_goldilocks_air, poseidon2_trace,
    FibonacciAir, FibonacciWorkload, GeneratedTraceV1, Poseidon2GoldilocksAir, Poseidon2Workload,
    ResourceBoundedWorkload, WorkloadError, WorkloadIdentityV1,
};
