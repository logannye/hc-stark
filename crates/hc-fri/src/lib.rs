// Note: simd_fold uses one localised `unsafe` block for the TypeId-gated
// transmute. The rest of the crate is unsafe-free; the hc-simd
// PackedField intrinsics are encapsulated inside hc-simd. We
// `#[allow]` rather than `forbid` at the crate level — the simd_fold
// module itself documents the safety invariant.
#![allow(unsafe_code)]

pub mod config;
pub mod layer;
pub mod oracles;
pub mod parallel;
pub mod prover;
pub mod queries;
pub mod simd_fold;
pub mod stream;
pub mod util;
pub mod verifier;

pub use config::FriConfig;
pub use prover::{FriProver, FriProverArtifacts};
pub use queries::{get_folding_ratio, is_valid_query_index, propagate_query_index, FriProof};
pub use verifier::FriVerifier;
