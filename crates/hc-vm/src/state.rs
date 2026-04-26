//! VM state model: register file, program counter, flag, and trace row layout.

use hc_core::field::FieldElement;

use crate::isa::NUM_REGISTERS;

/// Complete VM state at a single execution step.
///
/// This is the "wide" state used during execution. The trace row is derived
/// from snapshots of this state at each step.
#[derive(Clone, Debug)]
pub struct VmState<F: FieldElement> {
    /// General-purpose registers R0-R7.
    pub regs: [F; NUM_REGISTERS],
    /// Program counter.
    pub pc: u32,
    /// Comparison flag (1 = true, 0 = false).
    pub flag: F,
    /// Call stack for Call/Return instructions.
    pub call_stack: Vec<u32>,
    /// Whether the VM has halted.
    pub halted: bool,
}

impl<F: FieldElement> VmState<F> {
    pub fn new() -> Self {
        Self {
            regs: [F::ZERO; NUM_REGISTERS],
            pc: 0,
            flag: F::ZERO,
            call_stack: Vec::new(),
            halted: false,
        }
    }

    pub fn with_registers(regs: [F; NUM_REGISTERS]) -> Self {
        Self {
            regs,
            pc: 0,
            flag: F::ZERO,
            call_stack: Vec::new(),
            halted: false,
        }
    }

    pub fn reg(&self, id: u8) -> F {
        self.regs[id as usize % NUM_REGISTERS]
    }

    pub fn set_reg(&mut self, id: u8, value: F) {
        self.regs[id as usize % NUM_REGISTERS] = value;
    }
}

impl<F: FieldElement> Default for VmState<F> {
    fn default() -> Self {
        Self::new()
    }
}

// ── Trace row format ──────────────────────────────────────────────────────

/// Number of columns in the execution trace.
///
/// Layout: [pc, opcode, r0..r7, flag, mem_addr, mem_val, imm]
/// = 1 + 1 + 8 + 1 + 1 + 1 + 1 = 14
pub const TRACE_WIDTH: usize = 14;

/// Column indices into the trace row.
pub mod col {
    pub const PC: usize = 0;
    pub const OPCODE: usize = 1;
    pub const R0: usize = 2;
    pub const R1: usize = 3;
    pub const R2: usize = 4;
    pub const R3: usize = 5;
    pub const R4: usize = 6;
    pub const R5: usize = 7;
    pub const R6: usize = 8;
    pub const R7: usize = 9;
    pub const FLAG: usize = 10;
    pub const MEM_ADDR: usize = 11;
    pub const MEM_VAL: usize = 12;
    pub const IMM: usize = 13;

    /// Register column for a given register ID.
    pub fn reg(id: u8) -> usize {
        R0 + id as usize
    }
}

/// A single row of the execution trace (fixed-width array).
pub type TraceRow<F> = [F; TRACE_WIDTH];

/// Build a trace row from the current VM state and instruction metadata.
pub fn snapshot_row<F: FieldElement>(
    state: &VmState<F>,
    opcode: u64,
    mem_addr: F,
    mem_val: F,
    imm: F,
) -> TraceRow<F> {
    let mut row = [F::ZERO; TRACE_WIDTH];
    row[col::PC] = F::from_u64(state.pc as u64);
    row[col::OPCODE] = F::from_u64(opcode);
    row[col::R0..col::R0 + NUM_REGISTERS].copy_from_slice(&state.regs[..NUM_REGISTERS]);
    row[col::FLAG] = state.flag;
    row[col::MEM_ADDR] = mem_addr;
    row[col::MEM_VAL] = mem_val;
    row[col::IMM] = imm;
    row
}

// ── Legacy 2-column row (backward compatibility) ──────────────────────────

/// Legacy 2-column row for the ToyAir (accumulator + delta).
///
/// Kept for backward compatibility with the existing prover/verifier pipeline,
/// which is hardcoded to `[F; 2]` traces.
#[derive(Clone, Copy, Debug)]
pub struct VmRow<F: FieldElement> {
    pub accumulator: F,
    pub delta: F,
}

impl<F: FieldElement> VmRow<F> {
    pub fn new(accumulator: F, delta: F) -> Self {
        Self { accumulator, delta }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn state_register_access() {
        let mut state = VmState::<F>::new();
        state.set_reg(3, F::from_u64(42));
        assert_eq!(state.reg(3), F::from_u64(42));
        assert_eq!(state.reg(0), F::ZERO);
    }

    #[test]
    fn snapshot_captures_state() {
        let mut state = VmState::<F>::new();
        state.pc = 5;
        state.set_reg(0, F::from_u64(100));
        state.flag = F::ONE;
        let row = snapshot_row(&state, 1, F::ZERO, F::ZERO, F::from_u64(7));
        assert_eq!(row[col::PC], F::from_u64(5));
        assert_eq!(row[col::OPCODE], F::from_u64(1));
        assert_eq!(row[col::R0], F::from_u64(100));
        assert_eq!(row[col::FLAG], F::ONE);
        assert_eq!(row[col::IMM], F::from_u64(7));
    }

    #[test]
    fn trace_width_matches_columns() {
        assert_eq!(TRACE_WIDTH, 14);
        assert_eq!(col::reg(7), col::R7);
    }
}
