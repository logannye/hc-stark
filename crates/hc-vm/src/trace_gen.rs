//! Trace generation for STARK proofs from VM execution.

use hc_core::{error::HcResult, field::FieldElement};

use crate::{
    exec::{execute, execute_full},
    isa::Program,
    memory::Memory,
    state::{TraceRow, VmState},
};

/// Generate a legacy 2-column trace (accumulator + delta) for ToyAir.
///
/// This is backward-compatible with the existing prover/verifier pipeline.
pub fn generate_trace<F: FieldElement>(
    program: &Program,
    initial_accumulator: F,
) -> HcResult<Vec<[F; 2]>> {
    if program.is_empty() {
        return Err(hc_core::error::HcError::invalid_argument(
            "program must contain at least one instruction",
        ));
    }
    let rows = execute(&program.instructions, initial_accumulator);
    Ok(rows
        .into_iter()
        .map(|row| [row.accumulator, row.delta])
        .collect())
}

/// Generate a full N-column trace for the expanded VM.
///
/// Returns the trace rows and the memory access log (for offline checking).
pub fn generate_full_trace<F: FieldElement>(
    program: &Program,
) -> HcResult<(Vec<TraceRow<F>>, Memory<F>)> {
    if program.is_empty() {
        return Err(hc_core::error::HcError::invalid_argument(
            "program must contain at least one instruction",
        ));
    }
    execute_full(&program.instructions, VmState::new())
}

/// Generate a full trace with custom initial state.
pub fn generate_full_trace_with_state<F: FieldElement>(
    program: &Program,
    initial_state: VmState<F>,
) -> HcResult<(Vec<TraceRow<F>>, Memory<F>)> {
    if program.is_empty() {
        return Err(hc_core::error::HcError::invalid_argument(
            "program must contain at least one instruction",
        ));
    }
    execute_full(&program.instructions, initial_state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::Instruction;
    use crate::state::{col, TRACE_WIDTH};
    use hc_core::field::prime_field::GoldilocksField;

    type F = GoldilocksField;

    #[test]
    fn legacy_trace_matches_expected_values() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let trace = generate_trace(&program, F::new(5)).unwrap();
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0][0], F::new(5));
        assert_eq!(trace[1][0], F::new(6));
        assert_eq!(trace[2][0], F::new(8));
    }

    #[test]
    fn full_trace_fibonacci() {
        // Compute fib(6) = 8 using the full VM:
        // R0 = fib(n-1), R1 = fib(n-2), R2 = temp
        let program = Program::new(vec![
            Instruction::LoadImm(0, 1), // fib(1) = 1
            Instruction::LoadImm(1, 1), // fib(2) = 1
            // Loop body (PC 2-5):
            Instruction::Add(2, 0, 1), // R2 = R0 + R1
            Instruction::Move(1, 0),   // R1 = R0
            Instruction::Move(0, 2),   // R0 = R2
            // Loop control: repeat 4 more times
            Instruction::LoadImm(3, 1), // counter check (simplified: unrolled)
            // Unroll iterations 3-6:
            Instruction::Add(2, 0, 1),
            Instruction::Move(1, 0),
            Instruction::Move(0, 2),
            Instruction::Add(2, 0, 1),
            Instruction::Move(1, 0),
            Instruction::Move(0, 2),
            Instruction::Add(2, 0, 1),
            Instruction::Move(1, 0),
            Instruction::Move(0, 2),
            Instruction::Halt,
        ]);
        let (trace, _) = generate_full_trace::<F>(&program).unwrap();
        let last = trace.last().unwrap();
        assert_eq!(last[col::R0], F::from_u64(8)); // fib(6) = 8
    }

    #[test]
    fn full_trace_with_memory() {
        let program = Program::new(vec![
            Instruction::LoadImm(0, 0), // addr 0
            Instruction::LoadImm(1, 42),
            Instruction::Store(0, 1),   // mem[0] = 42
            Instruction::LoadImm(0, 1), // addr 1
            Instruction::LoadImm(1, 99),
            Instruction::Store(0, 1), // mem[1] = 99
            // Read them back
            Instruction::LoadImm(0, 0),
            Instruction::Load(2, 0), // R2 = mem[0] = 42
            Instruction::LoadImm(0, 1),
            Instruction::Load(3, 0),   // R3 = mem[1] = 99
            Instruction::Add(4, 2, 3), // R4 = 42 + 99 = 141
            Instruction::Halt,
        ]);
        let (trace, mem) = generate_full_trace::<F>(&program).unwrap();
        let last = trace.last().unwrap();
        assert_eq!(last[col::R4], F::from_u64(141));
        assert_eq!(mem.access_log.len(), 4); // 2 writes + 2 reads
    }

    #[test]
    fn full_trace_width() {
        let program = Program::new(vec![Instruction::Halt]);
        let (trace, _) = generate_full_trace::<F>(&program).unwrap();
        assert_eq!(trace[0].len(), TRACE_WIDTH);
    }
}
