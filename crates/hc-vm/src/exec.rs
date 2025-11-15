use hc_core::field::FieldElement;

use crate::{isa::Instruction, state::VmRow};

pub fn execute<F: FieldElement>(program: &[Instruction], mut accumulator: F) -> Vec<VmRow<F>> {
    let mut trace = Vec::with_capacity(program.len() + 1);
    for instruction in program {
        match instruction {
            Instruction::AddImmediate(value) => {
                let delta = F::from_u64(*value);
                trace.push(VmRow::new(accumulator, delta));
                accumulator = accumulator.add(delta);
            }
        }
    }
    trace.push(VmRow::new(accumulator, F::ZERO));
    trace
}
