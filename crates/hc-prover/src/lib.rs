#![forbid(unsafe_code)]

pub mod block_tuner;
pub mod commitment;
pub mod config;
pub mod fri_height;
pub mod kzg;
pub mod merkle_height;
pub mod metrics;
pub mod pipeline;
pub mod prove;
pub mod queries;
mod trace_stream;
pub mod transcript;

pub use block_tuner::{recommend_block_size, AutoBlockConfig};
pub use commitment::{commitment_digest, Commitment, CommitmentScheme};
pub use config::ProverConfig;
pub use prove::{prove_stark_v5, prove_v5, PublicInputs, TraceRow};
// Legacy v3/v4 prove entry: deprecated (superseded by `prove_v5`), re-exported
// for the test corpus and language bindings that still reference it.
#[allow(deprecated)]
pub use prove::prove;
