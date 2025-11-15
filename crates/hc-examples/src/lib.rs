#![forbid(unsafe_code)]

use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_vm::{Instruction, Program};

pub fn run_toy_example() -> hc_core::error::HcResult<()> {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(2, 2)?;
    let proof = prove(config, program, inputs)?;
    println!("Example trace root {:?}", proof.trace_root);
    Ok(())
}
