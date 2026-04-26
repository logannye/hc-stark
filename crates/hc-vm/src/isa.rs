//! Instruction Set Architecture for the hc-STARK virtual machine.
//!
//! The ISA is designed for provability: each instruction maps to a small number
//! of algebraic constraints in the AIR. Instructions are register-based with
//! 8 general-purpose registers (R0-R7).

/// Register identifier (0-7 for general purpose, with R0 as accumulator).
pub type RegId = u8;

/// Maximum number of general-purpose registers.
pub const NUM_REGISTERS: usize = 8;

/// Full instruction set for the provable VM.
///
/// Each instruction is designed to correspond to degree-2 or lower constraints
/// in the AIR (except Div/Inv which require auxiliary columns).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Instruction {
    // ── Legacy (backward-compatible) ──────────────────────────────────
    /// Add an immediate value to R0 (accumulator). Legacy instruction.
    AddImmediate(u64),

    // ── Arithmetic (register-register) ────────────────────────────────
    /// Rd = Rs1 + Rs2
    Add(RegId, RegId, RegId),
    /// Rd = Rs1 - Rs2
    Sub(RegId, RegId, RegId),
    /// Rd = Rs1 * Rs2
    Mul(RegId, RegId, RegId),
    /// Rd = -Rs (field negation)
    Neg(RegId, RegId),
    /// Rd = Rs^2
    Square(RegId, RegId),
    /// Rd = Rs^(-1) (field inverse, traps on zero)
    Inv(RegId, RegId),

    // ── Arithmetic (register-immediate) ──────────────────────────────
    /// Rd = Rs + imm
    AddI(RegId, RegId, u64),
    /// Rd = Rs * imm
    MulI(RegId, RegId, u64),

    // ── Data movement ─────────────────────────────────────────────────
    /// Rd = imm (load 64-bit immediate into register)
    LoadImm(RegId, u64),
    /// Rd = Rs (register copy)
    Move(RegId, RegId),

    // ── Memory operations ─────────────────────────────────────────────
    /// Rd = mem[Rs] (load from memory address in Rs)
    Load(RegId, RegId),
    /// mem[Rs1] = Rs2 (store Rs2 to memory address in Rs1)
    Store(RegId, RegId),

    // ── Comparison (sets flag register) ───────────────────────────────
    /// flag = (Rs1 == Rs2)
    Eq(RegId, RegId),
    /// flag = (Rs1 < Rs2) as field elements (non-deterministic hint)
    Lt(RegId, RegId),

    // ── Control flow ──────────────────────────────────────────────────
    /// PC = addr (unconditional jump)
    Jump(u32),
    /// if flag then PC = addr
    JumpIf(u32),
    /// if !flag then PC = addr
    JumpIfNot(u32),
    /// Push PC+1 to call stack, jump to addr
    Call(u32),
    /// Pop call stack, jump to saved PC
    Return,

    // ── Bitwise (range-check decomposition) ──────────────────────────
    /// Rd = Rs1 AND Rs2 (bitwise AND, values must be < 2^32)
    And(RegId, RegId, RegId),
    /// Rd = Rs1 OR Rs2 (bitwise OR, values must be < 2^32)
    Or(RegId, RegId, RegId),
    /// Rd = Rs1 XOR Rs2 (bitwise XOR, values must be < 2^32)
    Xor(RegId, RegId, RegId),
    /// Rd = Rs << imm (left shift, imm < 64)
    Shl(RegId, RegId, u8),
    /// Rd = Rs >> imm (right shift, imm < 64)
    Shr(RegId, RegId, u8),

    // ── Cryptographic ─────────────────────────────────────────────────
    /// Rd = assert_zero(Rs) — constrain Rs to be zero, trap otherwise.
    /// Used for constraint enforcement within programs.
    AssertZero(RegId),

    // ── System ────────────────────────────────────────────────────────
    /// No operation (advances PC by 1).
    Nop,
    /// Halt execution.
    Halt,
}

/// Opcode encoding for trace columns.
///
/// Each instruction has a unique opcode number used as a selector in the AIR.
/// These are the values that appear in the `opcode` column of the trace.
impl Instruction {
    pub fn opcode(&self) -> u64 {
        match self {
            Self::AddImmediate(_) => 0,
            Self::Add(_, _, _) => 1,
            Self::Sub(_, _, _) => 2,
            Self::Mul(_, _, _) => 3,
            Self::Neg(_, _) => 4,
            Self::Square(_, _) => 5,
            Self::Inv(_, _) => 6,
            Self::AddI(_, _, _) => 7,
            Self::MulI(_, _, _) => 8,
            Self::LoadImm(_, _) => 9,
            Self::Move(_, _) => 10,
            Self::Load(_, _) => 11,
            Self::Store(_, _) => 12,
            Self::Eq(_, _) => 13,
            Self::Lt(_, _) => 14,
            Self::Jump(_) => 15,
            Self::JumpIf(_) => 16,
            Self::JumpIfNot(_) => 17,
            Self::Call(_) => 18,
            Self::Return => 19,
            Self::And(_, _, _) => 20,
            Self::Or(_, _, _) => 21,
            Self::Xor(_, _, _) => 22,
            Self::Shl(_, _, _) => 23,
            Self::Shr(_, _, _) => 24,
            Self::AssertZero(_) => 25,
            Self::Nop => 26,
            Self::Halt => 27,
        }
    }

    /// Number of distinct opcodes.
    pub const NUM_OPCODES: usize = 28;
}

/// A sequence of instructions forming a program.
#[derive(Clone, Debug, Default)]
pub struct Program {
    pub instructions: Vec<Instruction>,
}

impl Program {
    pub fn new(instructions: Vec<Instruction>) -> Self {
        Self { instructions }
    }

    pub fn push(&mut self, instruction: Instruction) {
        self.instructions.push(instruction);
    }

    pub fn len(&self) -> usize {
        self.instructions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.instructions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_opcodes_unique() {
        use std::collections::HashSet;
        let instructions = vec![
            Instruction::AddImmediate(0),
            Instruction::Add(0, 0, 0),
            Instruction::Sub(0, 0, 0),
            Instruction::Mul(0, 0, 0),
            Instruction::Neg(0, 0),
            Instruction::Square(0, 0),
            Instruction::Inv(0, 0),
            Instruction::AddI(0, 0, 0),
            Instruction::MulI(0, 0, 0),
            Instruction::LoadImm(0, 0),
            Instruction::Move(0, 0),
            Instruction::Load(0, 0),
            Instruction::Store(0, 0),
            Instruction::Eq(0, 0),
            Instruction::Lt(0, 0),
            Instruction::Jump(0),
            Instruction::JumpIf(0),
            Instruction::JumpIfNot(0),
            Instruction::Call(0),
            Instruction::Return,
            Instruction::And(0, 0, 0),
            Instruction::Or(0, 0, 0),
            Instruction::Xor(0, 0, 0),
            Instruction::Shl(0, 0, 0),
            Instruction::Shr(0, 0, 0),
            Instruction::AssertZero(0),
            Instruction::Nop,
            Instruction::Halt,
        ];
        let opcodes: HashSet<u64> = instructions.iter().map(|i| i.opcode()).collect();
        assert_eq!(opcodes.len(), Instruction::NUM_OPCODES);
        assert_eq!(opcodes.len(), instructions.len());
    }
}
