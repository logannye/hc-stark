#![forbid(unsafe_code)]

pub mod air;
pub mod constraints;
pub mod domain_mapping;
pub mod dsl;
pub mod eval;
pub mod multi_column;
pub mod selectors;
pub mod trace;

pub use air::DeepStarkAir;
pub use air::{Air, ToyAir};
pub use dsl::{ConstraintSystem, DslAir};
pub use eval::{evaluate, PublicInputs};
pub use multi_column::MultiColumnTrace;
pub use trace::TraceTable;

#[cfg(test)]
mod tests {
    use super::*;
    use hc_core::field::prime_field::GoldilocksField;
    use hc_vm::{generate_trace, Instruction, Program};

    #[test]
    fn vm_trace_passes_air_checks() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let rows = generate_trace(&program, GoldilocksField::new(5)).unwrap();
        let trace = TraceTable::new(rows).unwrap();
        let public_inputs = PublicInputs {
            initial_acc: GoldilocksField::new(5),
            final_acc: GoldilocksField::new(8),
        };
        evaluate(&trace, public_inputs).unwrap();
    }
}
