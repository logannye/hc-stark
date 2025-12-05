use hc_core::{error::HcResult, field::FieldElement};

use crate::{exec::execute, isa::Program};

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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::isa::{Instruction, Program};
    use hc_core::field::prime_field::GoldilocksField;

    #[test]
    fn trace_matches_expected_values() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let trace = generate_trace(&program, GoldilocksField::new(5)).unwrap();
        assert_eq!(trace.len(), 3);
        assert_eq!(trace[0][0], GoldilocksField::new(5));
        assert_eq!(trace[1][0], GoldilocksField::new(6));
        assert_eq!(trace[2][0], GoldilocksField::new(8));
    }
}
