//! Public SDK surface for `hc-stark`.
//!
//! The goal of this crate is to provide a stable interface for:
//! - proving (producing a versioned proof blob)
//! - verifying (consuming proof blobs)
//! - parsing/serializing proof files used by CLI/server

pub mod evm_proof;
pub mod proof;
pub mod proof_compress;
pub mod types;
