#![forbid(unsafe_code)]

use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_vm::{Instruction, Program};

pub mod zkml;

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
    println!(
        "Example trace commitment {:?}",
        hc_prover::commitment::commitment_digest(&proof.trace_commitment)
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::zkml::{
        dense_layer_replay, dense_layer_trace, run_dense_layer_example, DenseLayerInstance,
    };
    use hc_core::field::{prime_field::GoldilocksField, FieldElement};

    #[test]
    fn dense_layer_demo_executes() {
        let instance = DenseLayerInstance {
            inputs: vec![
                GoldilocksField::from_u64(2),
                GoldilocksField::from_u64(3),
                GoldilocksField::from_u64(4),
            ],
            weights: vec![
                vec![
                    GoldilocksField::from_u64(1),
                    GoldilocksField::from_u64(0),
                    GoldilocksField::from_u64(2),
                ],
                vec![
                    GoldilocksField::from_u64(5),
                    GoldilocksField::from_u64(1),
                    GoldilocksField::from_u64(1),
                ],
            ],
            biases: vec![GoldilocksField::from_u64(1), GoldilocksField::from_u64(0)],
        };
        run_dense_layer_example(instance).unwrap();
    }

    #[test]
    fn dense_layer_replay_streams_blocks() {
        let instance = DenseLayerInstance {
            inputs: vec![GoldilocksField::from_u64(2), GoldilocksField::from_u64(1)],
            weights: vec![vec![
                GoldilocksField::from_u64(3),
                GoldilocksField::from_u64(4),
            ]],
            biases: vec![GoldilocksField::from_u64(1)],
        };
        let trace = dense_layer_trace(&instance).unwrap();
        assert!(!trace.is_empty());
        let mut replay = dense_layer_replay(&instance, 2).unwrap();
        let first = replay.fetch_block(0).unwrap().to_vec();
        assert_eq!(first.len(), 2.min(trace.len()));
    }
}
