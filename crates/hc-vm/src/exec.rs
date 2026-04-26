//! VM executor: runs programs and produces execution traces.

use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};

use crate::{
    isa::Instruction,
    memory::Memory,
    state::{snapshot_row, TraceRow, VmRow, VmState},
};

/// Maximum number of steps before the VM is forcibly halted (prevents infinite loops).
const MAX_STEPS: usize = 1 << 24; // ~16M steps

/// Execute a program with the full register-based VM, producing a wide trace.
///
/// Returns one trace row per executed instruction, plus a final "halt" row.
pub fn execute_full<F: FieldElement>(
    program: &[Instruction],
    initial_state: VmState<F>,
) -> HcResult<(Vec<TraceRow<F>>, Memory<F>)> {
    let mut state = initial_state;
    let mut memory = Memory::new();
    let mut trace = Vec::with_capacity(program.len() + 1);
    let mut steps = 0usize;

    while !state.halted && (state.pc as usize) < program.len() {
        if steps >= MAX_STEPS {
            return Err(HcError::message("VM exceeded maximum step count"));
        }

        let pc = state.pc as usize;
        let instr = program[pc];
        let opcode = instr.opcode();
        let mut mem_addr = F::ZERO;
        let mut mem_val = F::ZERO;
        let mut imm = F::ZERO;

        // Execute the instruction and advance state.
        match instr {
            Instruction::AddImmediate(val) => {
                imm = F::from_u64(val);
                let r0 = state.reg(0);
                state.set_reg(0, r0.add(imm));
                state.pc += 1;
            }
            Instruction::Add(rd, rs1, rs2) => {
                let result = state.reg(rs1).add(state.reg(rs2));
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::Sub(rd, rs1, rs2) => {
                let result = state.reg(rs1).sub(state.reg(rs2));
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::Mul(rd, rs1, rs2) => {
                let result = state.reg(rs1).mul(state.reg(rs2));
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::Neg(rd, rs) => {
                let result = state.reg(rs).neg();
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::Square(rd, rs) => {
                let result = state.reg(rs).square();
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::Inv(rd, rs) => {
                let val = state.reg(rs);
                let result = val
                    .inverse()
                    .ok_or_else(|| HcError::message("VM: inverse of zero"))?;
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::AddI(rd, rs, val) => {
                imm = F::from_u64(val);
                let result = state.reg(rs).add(imm);
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::MulI(rd, rs, val) => {
                imm = F::from_u64(val);
                let result = state.reg(rs).mul(imm);
                state.set_reg(rd, result);
                state.pc += 1;
            }
            Instruction::LoadImm(rd, val) => {
                imm = F::from_u64(val);
                state.set_reg(rd, imm);
                state.pc += 1;
            }
            Instruction::Move(rd, rs) => {
                let val = state.reg(rs);
                state.set_reg(rd, val);
                state.pc += 1;
            }
            Instruction::Load(rd, rs) => {
                let addr = state.reg(rs);
                mem_addr = addr;
                let val = memory.read(addr, steps);
                mem_val = val;
                state.set_reg(rd, val);
                state.pc += 1;
            }
            Instruction::Store(rs_addr, rs_val) => {
                let addr = state.reg(rs_addr);
                let val = state.reg(rs_val);
                mem_addr = addr;
                mem_val = val;
                memory.write(addr, val, steps);
                state.pc += 1;
            }
            Instruction::Eq(rs1, rs2) => {
                state.flag = if state.reg(rs1) == state.reg(rs2) {
                    F::ONE
                } else {
                    F::ZERO
                };
                state.pc += 1;
            }
            Instruction::Lt(rs1, rs2) => {
                // Non-deterministic: compare as u64 values.
                state.flag = if state.reg(rs1).to_u64() < state.reg(rs2).to_u64() {
                    F::ONE
                } else {
                    F::ZERO
                };
                state.pc += 1;
            }
            Instruction::Jump(addr) => {
                state.pc = addr;
            }
            Instruction::JumpIf(addr) => {
                if state.flag == F::ONE {
                    state.pc = addr;
                } else {
                    state.pc += 1;
                }
            }
            Instruction::JumpIfNot(addr) => {
                if state.flag == F::ZERO {
                    state.pc = addr;
                } else {
                    state.pc += 1;
                }
            }
            Instruction::Call(addr) => {
                state.call_stack.push(state.pc + 1);
                state.pc = addr;
            }
            Instruction::Return => {
                let ret_addr = state
                    .call_stack
                    .pop()
                    .ok_or_else(|| HcError::message("VM: return with empty call stack"))?;
                state.pc = ret_addr;
            }
            Instruction::And(rd, rs1, rs2) => {
                let a = state.reg(rs1).to_u64();
                let b = state.reg(rs2).to_u64();
                state.set_reg(rd, F::from_u64(a & b));
                state.pc += 1;
            }
            Instruction::Or(rd, rs1, rs2) => {
                let a = state.reg(rs1).to_u64();
                let b = state.reg(rs2).to_u64();
                state.set_reg(rd, F::from_u64(a | b));
                state.pc += 1;
            }
            Instruction::Xor(rd, rs1, rs2) => {
                let a = state.reg(rs1).to_u64();
                let b = state.reg(rs2).to_u64();
                state.set_reg(rd, F::from_u64(a ^ b));
                state.pc += 1;
            }
            Instruction::Shl(rd, rs, shift) => {
                let val = state.reg(rs).to_u64();
                let result = if shift < 64 { val << shift } else { 0 };
                state.set_reg(rd, F::from_u64(result));
                state.pc += 1;
            }
            Instruction::Shr(rd, rs, shift) => {
                let val = state.reg(rs).to_u64();
                let result = if shift < 64 { val >> shift } else { 0 };
                state.set_reg(rd, F::from_u64(result));
                state.pc += 1;
            }
            Instruction::AssertZero(rs) => {
                if state.reg(rs) != F::ZERO {
                    return Err(HcError::message("VM: assertion failed (non-zero register)"));
                }
                state.pc += 1;
            }
            Instruction::Nop => {
                state.pc += 1;
            }
            Instruction::Halt => {
                state.halted = true;
            }
        }

        // Now build the actual trace row with computed mem/imm values.
        let row = snapshot_row(&state, opcode, mem_addr, mem_val, imm);
        // We snapshot state AFTER execution so the next row shows the result.
        // But the row records the opcode and PC from BEFORE.
        // Adjust: use pre-execution PC.
        let mut final_row = row;
        final_row[0] = F::from_u64(pc as u64); // PC before execution
        trace.push(final_row);
        steps += 1;
    }

    // Final halt row.
    let halt_row = snapshot_row(
        &state,
        Instruction::Halt.opcode(),
        F::ZERO,
        F::ZERO,
        F::ZERO,
    );
    trace.push(halt_row);

    Ok((trace, memory))
}

// ── Legacy executor (backward compatibility) ──────────────────────────────

/// Legacy 2-column executor for ToyAir compatibility.
///
/// This preserves the original behavior: execute AddImmediate instructions
/// on a single accumulator, producing `[accumulator, delta]` rows.
pub fn execute<F: FieldElement>(program: &[Instruction], mut accumulator: F) -> Vec<VmRow<F>> {
    let mut trace = Vec::with_capacity(program.len() + 1);
    for instruction in program {
        match instruction {
            Instruction::AddImmediate(value) => {
                let delta = F::from_u64(*value);
                trace.push(VmRow::new(accumulator, delta));
                accumulator = accumulator.add(delta);
            }
            _ => {
                // Legacy executor only handles AddImmediate.
                // Other instructions are treated as nops with zero delta.
                trace.push(VmRow::new(accumulator, F::ZERO));
            }
        }
    }
    trace.push(VmRow::new(accumulator, F::ZERO));
    trace
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;
    use crate::state::col;
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn legacy_add_immediate() {
        let program = vec![Instruction::AddImmediate(10), Instruction::AddImmediate(20)];
        let rows = execute(&program, F::from_u64(5));
        assert_eq!(rows.len(), 3);
        assert_eq!(rows[0].accumulator, F::from_u64(5));
        assert_eq!(rows[0].delta, F::from_u64(10));
        assert_eq!(rows[2].accumulator, F::from_u64(35));
    }

    #[test]
    fn full_add_registers() {
        let program = vec![
            Instruction::LoadImm(0, 10),
            Instruction::LoadImm(1, 20),
            Instruction::Add(2, 0, 1),
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        // After Add(2, 0, 1): R2 should be 30.
        // The trace row for Add is at index 2 (0=LoadImm, 1=LoadImm, 2=Add).
        // The row records state AFTER execution, with pre-execution PC.
        assert_eq!(trace[2][col::R0], F::from_u64(10));
        assert_eq!(trace[2][col::R1], F::from_u64(20));
        assert_eq!(trace[2][col::R2], F::from_u64(30));
    }

    #[test]
    fn full_mul_and_sub() {
        let program = vec![
            Instruction::LoadImm(0, 7),
            Instruction::LoadImm(1, 6),
            Instruction::Mul(2, 0, 1), // R2 = 42
            Instruction::Sub(3, 2, 0), // R3 = 42 - 7 = 35
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        assert_eq!(trace[2][col::R2], F::from_u64(42));
        assert_eq!(trace[3][col::R3], F::from_u64(35));
    }

    #[test]
    fn full_memory_store_load() {
        let program = vec![
            Instruction::LoadImm(0, 100), // addr
            Instruction::LoadImm(1, 42),  // value
            Instruction::Store(0, 1),     // mem[100] = 42
            Instruction::LoadImm(2, 0),   // clear R2
            Instruction::Load(2, 0),      // R2 = mem[100] = 42
            Instruction::Halt,
        ];
        let (trace, mem) = execute_full::<F>(&program, VmState::new()).unwrap();
        assert_eq!(trace[4][col::R2], F::from_u64(42));
        assert_eq!(mem.access_log.len(), 2); // 1 write + 1 read
    }

    #[test]
    fn full_jump_and_halt() {
        let program = vec![
            Instruction::LoadImm(0, 1),  // R0 = 1
            Instruction::Jump(3),        // skip instruction 2
            Instruction::LoadImm(0, 99), // should be skipped
            Instruction::Halt,           // execution ends here
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        // R0 should be 1, not 99.
        let last = trace.last().unwrap();
        assert_eq!(last[col::R0], F::from_u64(1));
    }

    #[test]
    fn full_conditional_jump() {
        let program = vec![
            Instruction::LoadImm(0, 5),
            Instruction::LoadImm(1, 5),
            Instruction::Eq(0, 1),       // flag = 1 (equal)
            Instruction::JumpIf(5),      // jump to instruction 5
            Instruction::LoadImm(2, 99), // skipped
            Instruction::LoadImm(2, 42), // R2 = 42
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        let last = trace.last().unwrap();
        assert_eq!(last[col::R2], F::from_u64(42));
    }

    #[test]
    fn full_call_and_return() {
        // Main: LoadImm R0=1, Call subroutine at 4, Halt
        // Subroutine: AddI R0 R0 10, Return
        let program = vec![
            Instruction::LoadImm(0, 1),  // 0: R0 = 1
            Instruction::Call(3),        // 1: call subroutine at 3
            Instruction::Halt,           // 2: halt (return comes back here? no, PC+1=2)
            Instruction::AddI(0, 0, 10), // 3: R0 = R0 + 10
            Instruction::Return,         // 4: return to PC 2
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        let last = trace.last().unwrap();
        assert_eq!(last[col::R0], F::from_u64(11)); // 1 + 10
    }

    #[test]
    fn full_bitwise_operations() {
        let program = vec![
            Instruction::LoadImm(0, 0b1100),
            Instruction::LoadImm(1, 0b1010),
            Instruction::And(2, 0, 1), // 0b1000 = 8
            Instruction::Or(3, 0, 1),  // 0b1110 = 14
            Instruction::Xor(4, 0, 1), // 0b0110 = 6
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        assert_eq!(trace[2][col::R2], F::from_u64(8));
        assert_eq!(trace[3][col::R3], F::from_u64(14));
        assert_eq!(trace[4][col::R4], F::from_u64(6));
    }

    #[test]
    fn full_shift_operations() {
        let program = vec![
            Instruction::LoadImm(0, 1),
            Instruction::Shl(1, 0, 4), // 1 << 4 = 16
            Instruction::Shr(2, 1, 2), // 16 >> 2 = 4
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        assert_eq!(trace[1][col::R1], F::from_u64(16));
        assert_eq!(trace[2][col::R2], F::from_u64(4));
    }

    #[test]
    fn full_assert_zero_passes() {
        let program = vec![
            Instruction::AssertZero(0), // R0 starts at 0
            Instruction::Halt,
        ];
        let result = execute_full::<F>(&program, VmState::new());
        assert!(result.is_ok());
    }

    #[test]
    fn full_assert_zero_fails() {
        let program = vec![
            Instruction::LoadImm(0, 1),
            Instruction::AssertZero(0), // R0 = 1, should fail
            Instruction::Halt,
        ];
        let result = execute_full::<F>(&program, VmState::new());
        assert!(result.is_err());
    }

    #[test]
    fn full_inverse() {
        let program = vec![
            Instruction::LoadImm(0, 7),
            Instruction::Inv(1, 0),    // R1 = 7^(-1)
            Instruction::Mul(2, 0, 1), // R2 = 7 * 7^(-1) = 1
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        assert_eq!(trace[2][col::R2], F::ONE);
    }

    #[test]
    fn full_nop() {
        let program = vec![
            Instruction::LoadImm(0, 42),
            Instruction::Nop,
            Instruction::Nop,
            Instruction::Halt,
        ];
        let (trace, _) = execute_full::<F>(&program, VmState::new()).unwrap();
        let last = trace.last().unwrap();
        assert_eq!(last[col::R0], F::from_u64(42));
    }
}
