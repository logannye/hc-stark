//! RV32I-subset instruction set definition.
//!
//! Choosing the RV32I subset (rather than the full G/M/A/F/D extensions)
//! keeps the AIR transition constraints small and lets us reuse standard
//! C / Rust toolchains targeting `riscv32i-unknown-none`.

use serde::{Deserialize, Serialize};

/// A 5-bit register index (`x0..x31`). `x0` is hardwired to zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reg(pub u8);

impl Reg {
    pub const ZERO: Reg = Reg(0);

    pub fn new(idx: u8) -> Self {
        debug_assert!(idx < 32, "register index {idx} out of range");
        Self(idx)
    }
}

/// RV32I-subset opcode set. Sufficient to compile the typical zkVM workload
/// (no FP, no atomics, no privileged instructions).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RvInstr {
    // ── Arithmetic (R-type) ────────────────────────────────────────────────
    Add {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Sub {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Sll {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Slt {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Sltu {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Xor {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Srl {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Sra {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    Or {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },
    And {
        rd: Reg,
        rs1: Reg,
        rs2: Reg,
    },

    // ── Arithmetic (I-type) ────────────────────────────────────────────────
    Addi {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Slti {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Sltiu {
        rd: Reg,
        rs1: Reg,
        imm: u32,
    },
    Xori {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Ori {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Andi {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Slli {
        rd: Reg,
        rs1: Reg,
        shamt: u8,
    },
    Srli {
        rd: Reg,
        rs1: Reg,
        shamt: u8,
    },
    Srai {
        rd: Reg,
        rs1: Reg,
        shamt: u8,
    },

    // ── Loads ──────────────────────────────────────────────────────────────
    Lb {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Lh {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Lw {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Lbu {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },
    Lhu {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },

    // ── Stores ─────────────────────────────────────────────────────────────
    Sb {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Sh {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Sw {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },

    // ── Branches ───────────────────────────────────────────────────────────
    Beq {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Bne {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Blt {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Bge {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Bltu {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },
    Bgeu {
        rs1: Reg,
        rs2: Reg,
        imm: i32,
    },

    // ── Jumps ──────────────────────────────────────────────────────────────
    Jal {
        rd: Reg,
        imm: i32,
    },
    Jalr {
        rd: Reg,
        rs1: Reg,
        imm: i32,
    },

    // ── Upper-immediate ────────────────────────────────────────────────────
    Lui {
        rd: Reg,
        imm: u32,
    },
    Auipc {
        rd: Reg,
        imm: u32,
    },

    // ── System (host I/O) ──────────────────────────────────────────────────
    /// `ecall` — used to expose host I/O (read input chunk, write output
    /// chunk). The AIR treats it as a constrained boundary that commits the
    /// I/O delta into the public transcript.
    Ecall,
    /// `ebreak` — halts the VM. Useful for delimiting proof boundaries inside
    /// long-running programs.
    Ebreak,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reg_zero() {
        assert_eq!(Reg::ZERO.0, 0);
    }

    #[test]
    fn instr_serialize_roundtrip() {
        let i = RvInstr::Add {
            rd: Reg::new(1),
            rs1: Reg::new(2),
            rs2: Reg::new(3),
        };
        let s = serde_json::to_string(&i).unwrap();
        let j: RvInstr = serde_json::from_str(&s).unwrap();
        assert_eq!(i, j);
    }
}
