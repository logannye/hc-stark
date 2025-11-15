use hc_air::{evaluate, PublicInputs as AirPublicInputs, TraceTable};
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_fri::FriConfig;
use hc_vm::{generate_trace, Program};

use crate::{
    config::ProverConfig, fri_height, merkle_height, pipeline::phase3_queries,
    queries::ProverOutput,
};

pub type TraceRow<F> = [F; 2];

#[derive(Clone, Debug)]
pub struct PublicInputs<F> {
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn prove<F: FieldElement>(
    config: ProverConfig,
    program: Program,
    public_inputs: PublicInputs<F>,
) -> HcResult<ProverOutput<F>> {
    if program.instructions.is_empty() {
        return Err(HcError::invalid_argument(
            "program must contain instructions",
        ));
    }
    let rows = generate_trace(&program, public_inputs.initial_acc)?;
    let trace = TraceTable::new(rows.clone())?;
    let air_inputs = AirPublicInputs {
        initial_acc: public_inputs.initial_acc,
        final_acc: public_inputs.final_acc,
    };
    evaluate(&trace, air_inputs)?;
    let trace_root = merkle_height::compute_root(&rows)?;

    let mut fri_evals: Vec<F> = rows.iter().map(|row| row[0]).collect();
    while fri_evals.len() & (fri_evals.len() - 1) != 0 {
        fri_evals.push(*fri_evals.last().unwrap());
    }
    let fri_config = FriConfig::new(config.fri_final_poly_size)?;
    let fri_proof = fri_height::prove_fri(fri_config, fri_evals)?;

    phase3_queries::build_queries();
    Ok(ProverOutput {
        trace_root,
        fri_proof,
        public_inputs,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hc_vm::isa::Instruction;

    #[test]
    fn prover_generates_proof_for_toy_program() {
        let program = Program::new(vec![
            Instruction::AddImmediate(1),
            Instruction::AddImmediate(2),
        ]);
        let inputs = PublicInputs {
            initial_acc: hc_core::field::prime_field::GoldilocksField::new(5),
            final_acc: hc_core::field::prime_field::GoldilocksField::new(8),
        };
        let config = ProverConfig::new(2, 2).unwrap();
        let proof = prove(config, program, inputs.clone()).unwrap();
        assert_eq!(proof.public_inputs.final_acc, inputs.final_acc);
    }
}
