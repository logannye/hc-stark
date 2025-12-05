use hc_core::{
    error::HcResult,
    field::{prime_field::GoldilocksField, FieldElement},
};
use hc_prover::{config::ProverConfig, prove, PublicInputs, TraceRow};
use hc_replay::{
    block_range::BlockRange, config::ReplayConfig, trace_replay::TraceReplay, traits::BlockProducer,
};
use hc_vm::{trace_gen::generate_trace, Instruction, Program};

#[derive(Clone, Debug)]
pub struct DenseLayerInstance {
    pub inputs: Vec<GoldilocksField>,
    pub weights: Vec<Vec<GoldilocksField>>,
    pub biases: Vec<GoldilocksField>,
}

impl DenseLayerInstance {
    pub fn validate(&self) -> HcResult<()> {
        if self.weights.is_empty() {
            return Err(hc_core::error::HcError::invalid_argument(
                "dense layer requires at least one neuron",
            ));
        }
        if self.biases.len() != self.weights.len() {
            return Err(hc_core::error::HcError::invalid_argument(
                "bias vector length must match number of neurons",
            ));
        }
        for row in &self.weights {
            if row.len() != self.inputs.len() {
                return Err(hc_core::error::HcError::invalid_argument(
                    "weight row must match input dimensionality",
                ));
            }
        }
        Ok(())
    }

    pub fn to_program(&self) -> Program {
        let mut instructions = Vec::new();
        for (row, bias) in self.weights.iter().zip(self.biases.iter()) {
            instructions.push(Instruction::AddImmediate(bias.to_u64()));
            for (input, weight) in self.inputs.iter().zip(row.iter()) {
                let contribution = input.mul(*weight).to_u64();
                instructions.push(Instruction::AddImmediate(contribution));
            }
        }
        Program::new(instructions)
    }

    pub fn expected_accumulator(&self) -> GoldilocksField {
        let mut acc = GoldilocksField::ZERO;
        for (row, bias) in self.weights.iter().zip(self.biases.iter()) {
            let mut neuron = *bias;
            for (input, weight) in self.inputs.iter().zip(row.iter()) {
                neuron = neuron.add(input.mul(*weight));
            }
            acc = acc.add(neuron);
        }
        acc
    }
}

pub fn run_dense_layer_example(instance: DenseLayerInstance) -> HcResult<()> {
    instance.validate()?;
    let program = instance.to_program();
    let final_acc = instance.expected_accumulator();
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::ZERO,
        final_acc,
    };
    let config = ProverConfig::with_full_config(8, 2, 32, 4)?;
    let proof = prove(config, program, inputs)?;
    println!(
        "Dense layer demo complete (trace_commitment={}, trace_length={})",
        hc_prover::commitment::commitment_digest(&proof.trace_commitment),
        proof.trace_length
    );
    Ok(())
}

pub fn dense_layer_trace(
    instance: &DenseLayerInstance,
) -> HcResult<Vec<TraceRow<GoldilocksField>>> {
    instance.validate()?;
    let rows = generate_trace(&instance.to_program(), GoldilocksField::ZERO)?;
    Ok(rows)
}

pub fn dense_layer_replay(
    instance: &DenseLayerInstance,
    block_size: usize,
) -> HcResult<TraceReplay<DenseLayerTraceProducer, TraceRow<GoldilocksField>>> {
    let rows = dense_layer_trace(instance)?;
    let trace_len = rows.len();
    let producer = DenseLayerTraceProducer { rows };
    let config = ReplayConfig::new(block_size, trace_len)?;
    TraceReplay::new(config, producer)
}

pub struct DenseLayerTraceProducer {
    rows: Vec<TraceRow<GoldilocksField>>,
}

impl BlockProducer<TraceRow<GoldilocksField>> for DenseLayerTraceProducer {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<TraceRow<GoldilocksField>>> {
        let end = range.end().min(self.rows.len());
        Ok(self.rows[range.start..end].to_vec())
    }
}
