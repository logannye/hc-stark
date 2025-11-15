use anyhow::Result;
use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_vm::{Instruction, Program};

pub fn run_prove() -> Result<hc_prover::queries::ProverOutput<GoldilocksField>> {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(2, 2)?;
    Ok(prove(config, program, inputs)?)
}
