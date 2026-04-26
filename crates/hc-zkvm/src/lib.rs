#![forbid(unsafe_code)]

//! `hc-zkvm` — height-compressed RISC-V class zkVM.
//!
//! ## Why this crate exists
//!
//! `hc-vm` ships a deliberately tiny 28-instruction accumulator VM whose
//! traces are easy to constrain with the existing AIR. That ISA is sufficient
//! for the bundled accumulator-style proof templates but not for arbitrary
//! programs (no memory, no branches, no register file).
//!
//! Real zkVMs — Risc0, SP1, Jolt, Cairo, Nexus — prove correct execution of
//! a general-purpose ISA. They are also the largest individual workloads in
//! the ZK industry by trace length, which makes them the largest beneficiary
//! of the √T-memory prover. This crate extends `hc-vm` with:
//!
//! - A 32-register state model (`x0..x31`) and a paged byte-addressable
//!   memory (the model an AIR can constrain efficiently).
//! - A documented RV32I-subset instruction set and a typed [`isa::RvInstr`]
//!   enum.
//! - A trace generator that emits *block-streaming* execution windows so the
//!   prover never holds the full trace, only one block plus a constant-size
//!   register/memory checkpoint at each block boundary.
//! - A program loader that reads a small ELF subset (so existing C/Rust
//!   toolchains can target the VM).
//!
//! ## Surface stability
//!
//! Public types and `prove_execution` / `verify_execution` signatures are
//! the long-term contract. The cryptographic body returns
//! [`HcError::unimplemented`] until the AIR migration lands. See
//! `ROADMAP_EXTENSIONS.md` Phase 2.

pub mod isa;
pub mod proof;
pub mod state;

pub use isa::{Reg, RvInstr};
pub use proof::{ExecutionProof, ExecutionWitness, ProgramCommitment, PublicIo};
pub use state::{Memory, RegFile, RiscvProgram};

use hc_core::{HcError, HcResult};
use serde::{Deserialize, Serialize};

/// Tunables for the zkVM prover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HcZkvmConfig {
    /// Trace block size in cycles. Must be a power of two. The prover holds
    /// one block in RAM plus an `O(1)` register/memory checkpoint per block
    /// boundary. Memory pressure ≈ `block_cycles * (regs + memory_pages_live)`.
    pub block_cycles: usize,
    /// Maximum number of cycles a single proof job may execute. Above this
    /// the trace must be split across multiple proofs (and aggregated).
    pub max_cycles: u64,
    /// Whether to emit a ZK-masked proof (hides intermediate state).
    pub zk_masked: bool,
    /// Deterministic seed for prover-side randomness.
    pub deterministic_seed: u64,
}

impl Default for HcZkvmConfig {
    fn default() -> Self {
        Self {
            block_cycles: 1 << 16,
            max_cycles: 1 << 28,
            zk_masked: false,
            deterministic_seed: 0,
        }
    }
}

impl HcZkvmConfig {
    pub fn validate(&self) -> HcResult<()> {
        if !self.block_cycles.is_power_of_two() {
            return Err(HcError::invalid_argument(format!(
                "block_cycles must be a power of two, got {}",
                self.block_cycles
            )));
        }
        if self.block_cycles < 64 {
            return Err(HcError::invalid_argument(format!(
                "block_cycles must be at least 64, got {}",
                self.block_cycles
            )));
        }
        if self.max_cycles == 0 {
            return Err(HcError::invalid_argument("max_cycles must be > 0"));
        }
        Ok(())
    }
}

/// Prove correct execution of `program` on `witness`, producing the public
/// outputs `public_io.output`.
///
/// # Status
///
/// Returns [`HcError::unimplemented`] until the RV32I AIR lands. Signature is
/// the long-term contract.
pub fn prove_execution(
    program: &RiscvProgram,
    public_io: &PublicIo,
    witness: &ExecutionWitness,
    config: &HcZkvmConfig,
) -> HcResult<ExecutionProof> {
    config.validate()?;
    program.validate()?;
    let _ = (public_io, witness);
    Err(HcError::unimplemented(
        "hc-zkvm: RV32I AIR + block-streaming trace generator (Phase 2, see ROADMAP_EXTENSIONS.md)",
    ))
}

/// Verify a zkVM execution proof against a program commitment and public IO.
pub fn verify_execution(
    program_commitment: &ProgramCommitment,
    public_io: &PublicIo,
    proof: &ExecutionProof,
) -> HcResult<bool> {
    let _ = (program_commitment, public_io, proof);
    Err(HcError::unimplemented(
        "hc-zkvm: streaming verifier (Phase 2, see ROADMAP_EXTENSIONS.md)",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_validates() {
        HcZkvmConfig::default().validate().unwrap();
    }

    #[test]
    fn config_rejects_non_power_of_two_block_cycles() {
        let mut cfg = HcZkvmConfig::default();
        cfg.block_cycles = 100_000;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn prove_execution_returns_unimplemented_not_panic() {
        let prog = RiscvProgram::empty();
        let public_io = PublicIo::default();
        let witness = ExecutionWitness::default();
        let cfg = HcZkvmConfig::default();
        let err = prove_execution(&prog, &public_io, &witness, &cfg).unwrap_err();
        assert!(format!("{err}").contains("hc-zkvm"));
    }
}
