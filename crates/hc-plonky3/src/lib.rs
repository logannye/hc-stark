//! TinyZKP's Plonky3-first backend.
//!
//! The proof and verifier remain `p3-uni-stark` 0.6.1. TinyZKP supplies a
//! resource policy, scratch-backed DFT result matrices, workload manifests,
//! deterministic packaging, and recovery provenance.

#![deny(unsafe_op_in_unsafe_fn)]

pub mod contracts;
mod dft;
mod prover;
mod workloads;

pub use dft::{GoldilocksWord, ResourceBoundedDft, ResourceBoundedMatrix, ScratchPlonky3Matrix};
pub use prover::{
    BackendError, InternalProofBundle, ResourceBoundedUniStarkProver, WorkloadKind,
    COMPATIBILITY_PROFILE, PLONKY3_VERSION,
};
pub use workloads::{
    fibonacci_public_values, fibonacci_trace, poseidon2_goldilocks_air, poseidon2_trace,
    FibonacciAir, Poseidon2GoldilocksAir,
};
