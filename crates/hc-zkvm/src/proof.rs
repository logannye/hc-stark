//! Witness, public IO, and proof envelope types for the zkVM.

use serde::{Deserialize, Serialize};

/// Execution witness: the input bytes the program reads via `ecall`, plus
/// any prover-side hints needed to reconstruct intermediate state.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ExecutionWitness {
    /// Bytes available to the program through input `ecall`s.
    pub input_bytes: Vec<u8>,
    /// Optional prover hints (e.g., precomputed memory page contents) — never
    /// trusted by the verifier; used only to speed up trace generation.
    pub prover_hints: Vec<u8>,
}

/// Public IO for an execution proof.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PublicIo {
    /// Hash of the input bytes the program consumed (binds proof to input).
    pub input_digest: [u8; 32],
    /// Output bytes the program produced via output `ecall`s.
    pub output_bytes: Vec<u8>,
    /// Number of cycles executed (a bounded public quantity used for billing
    /// and rate-limiting).
    pub cycles: u64,
}

/// Commitment to a program: a hash of the canonical-serialized instruction
/// stream and entry PC. Verifiers receive this — never the program text.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ProgramCommitment {
    pub digest: [u8; 32],
    pub label: Option<String>,
}

/// Opaque execution proof envelope.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionProof {
    pub version: u8,
    pub bytes: Vec<u8>,
}

impl ExecutionProof {
    pub const VERSION: u8 = 1;
}
