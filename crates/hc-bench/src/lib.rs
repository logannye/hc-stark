use std::time::Instant;

use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_vm::{Instruction, Program};

pub fn benchmark(iterations: usize) -> hc_core::error::HcResult<()> {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(2, 2)?;
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = prove(config, program.clone(), inputs.clone())?;
    }
    println!(
        "Bench ran {iterations} iterations in {:.2?}",
        start.elapsed()
    );
    Ok(())
}
