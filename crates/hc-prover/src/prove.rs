use std::time::Instant;

use hc_air::constraints::boundary::BoundaryConstraints;
use hc_air::{evaluate, PublicInputs as AirPublicInputs, TraceTable};
use hc_core::{
    error::{HcError, HcResult},
    field::FieldElement,
};
use hc_fri::{FriConfig, FriProof};
use hc_hash::{hash::HashDigest, Blake3, Transcript};
use hc_replay::{config::ReplayConfig, trace_replay::TraceReplay};
use hc_vm::{generate_trace, Program};

use crate::{
    config::ProverConfig,
    fri_height,
    metrics::ProverMetrics,
    pipeline::{phase1_commit, phase3_queries},
    queries::ProverOutput,
    trace_stream::SliceTraceProducer,
};

pub type TraceRow<F> = [F; 2];

#[derive(Clone, Debug)]
pub struct PublicInputs<F> {
    pub initial_acc: F,
    pub final_acc: F,
}

pub fn prove<F: FieldElement + hc_core::field::TwoAdicField>(
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
    if rows.is_empty() {
        return Err(HcError::invalid_argument("generated empty trace"));
    }
    let trace = TraceTable::new(rows.clone())?;
    let air_inputs = AirPublicInputs {
        initial_acc: public_inputs.initial_acc,
        final_acc: public_inputs.final_acc,
    };
    evaluate(&trace, air_inputs)?;
    let fri_config = FriConfig::new(config.fri_final_poly_size)?;
    let mut context = ProverContext::new(rows, config, fri_config, public_inputs);
    let mut frames = vec![Frame::BuildQueries, Frame::RunFri, Frame::CommitTrace];
    while let Some(frame) = frames.pop() {
        frame.execute(&mut context)?;
    }
    context.into_output()
}

enum Frame {
    CommitTrace,
    RunFri,
    BuildQueries,
}

impl Frame {
    fn execute<F: FieldElement + hc_core::field::TwoAdicField>(
        &self,
        ctx: &mut ProverContext<F>,
    ) -> HcResult<()> {
        match self {
            Frame::CommitTrace => ctx.run_commit(),
            Frame::RunFri => ctx.run_fri(),
            Frame::BuildQueries => ctx.build_output(),
        }
    }
}

struct ProverContext<F: FieldElement> {
    rows: Vec<TraceRow<F>>,
    config: ProverConfig,
    fri_config: FriConfig,
    public_inputs: PublicInputs<F>,
    transcript: Transcript<Blake3>,
    trace_root: Option<HashDigest>,
    composition_root: Option<HashDigest>,
    fri_proof: Option<FriProof<F>>,
    output: Option<ProverOutput<F>>,
    metrics: ProverMetrics,
}

impl<F: FieldElement + hc_core::field::TwoAdicField> ProverContext<F> {
    fn new(
        rows: Vec<TraceRow<F>>,
        config: ProverConfig,
        fri_config: FriConfig,
        public_inputs: PublicInputs<F>,
    ) -> Self {
        let mut transcript = Transcript::<Blake3>::new(b"hc-stark");
        // Initialize transcript with public inputs
        transcript.append_message(
            b"initial_acc",
            &public_inputs.initial_acc.to_u64().to_le_bytes(),
        );
        transcript.append_message(
            b"final_acc",
            &public_inputs.final_acc.to_u64().to_le_bytes(),
        );

        Self {
            rows,
            config,
            fri_config,
            public_inputs,
            transcript,
            trace_root: None,
            composition_root: None,
            fri_proof: None,
            output: None,
            metrics: ProverMetrics::default(),
        }
    }

    fn run_commit(&mut self) -> HcResult<()> {
        let producer = SliceTraceProducer { rows: &self.rows };
        let block_size = self.config.block_size.max(1);
        let replay_config = ReplayConfig::new(block_size, self.rows.len())?;
        let mut trace_replay = TraceReplay::new(replay_config, producer)?;
        let total_blocks = trace_replay.num_blocks();
        let boundary = BoundaryConstraints {
            initial_acc: self.public_inputs.initial_acc,
            final_acc: self.public_inputs.final_acc,
        };
        let (trace_root, composition_root) =
            phase1_commit::commit_trace_streaming(&mut trace_replay, &self.config, &boundary)?;
        self.trace_root = Some(trace_root);
        self.composition_root = Some(composition_root);
        self.metrics.add_trace_blocks(total_blocks);
        self.metrics.add_composition_blocks(total_blocks);
        Ok(())
    }

    fn run_fri(&mut self) -> HcResult<()> {
        let mut fri_evals: Vec<F> = self.rows.iter().map(|row| row[0]).collect();
        while fri_evals.len() & (fri_evals.len() - 1) != 0 {
            fri_evals.push(*fri_evals.last().unwrap());
        }
        let (proof, stats) = fri_height::prove_fri(self.fri_config, fri_evals)?;
        self.metrics.add_fri_blocks(stats.blocks_loaded);
        self.fri_proof = Some(proof);
        Ok(())
    }

    fn build_output(&mut self) -> HcResult<()> {
        let trace_root = self
            .trace_root
            .ok_or_else(|| HcError::message("missing trace root"))?;
        let fri_proof = self
            .fri_proof
            .take()
            .ok_or_else(|| HcError::message("missing FRI proof"))?;

        // Recreate trace replay for query answering
        let producer = SliceTraceProducer { rows: &self.rows };
        let block_size = self.config.block_size.max(1);
        let replay_config = ReplayConfig::new(block_size, self.rows.len())?;
        let mut trace_replay = TraceReplay::new(replay_config, producer)?;

        // Build query responses using the transcript and trace replay
        let query_timer = Instant::now();
        let query_response = Some(phase3_queries::build_queries(
            &mut self.transcript,
            &mut trace_replay,
            &fri_proof,
            self.config.query_count,
        )?);
        let elapsed_ms = query_timer.elapsed().as_millis() as u64;
        if let Some(response) = &query_response {
            self.metrics.record_fri_queries(
                self.config.query_count,
                response.fri_queries.len(),
                elapsed_ms,
            );
        }

        self.output = Some(ProverOutput {
            trace_root,
            fri_proof,
            public_inputs: self.public_inputs.clone(),
            query_response,
            metrics: self.metrics.clone(),
            trace_length: self.rows.len(),
        });
        Ok(())
    }

    fn into_output(mut self) -> HcResult<ProverOutput<F>> {
        self.output
            .take()
            .ok_or_else(|| HcError::message("prover output not built"))
    }
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
