use hc_core::{error::HcResult, field::FieldElement};
use hc_replay::{block_range::BlockRange, traits::BlockProducer};

use crate::TraceRow;

pub struct SliceTraceProducer<'a, F: FieldElement> {
    pub rows: &'a [TraceRow<F>],
}

impl<'a, F: FieldElement> BlockProducer<TraceRow<F>> for SliceTraceProducer<'a, F> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<TraceRow<F>>> {
        let end = range.end().min(self.rows.len());
        Ok(self.rows[range.start..end].to_vec())
    }
}

/// Replayable trace producer for the toy VM.
///
/// This avoids materializing the entire trace in memory: blocks are regenerated
/// from checkpoints on demand.
#[derive(Clone, Debug)]
pub struct VmTraceProducer<F: FieldElement> {
    program: hc_vm::Program,
    /// Accumulator value at the start of each trace block.
    checkpoints: Vec<F>,
    block_size: usize,
}

impl<F: FieldElement> VmTraceProducer<F> {
    pub fn new(program: hc_vm::Program, initial_acc: F, block_size: usize) -> HcResult<Self> {
        let block_size = block_size.max(1);
        let total_rows = program.instructions.len() + 1;
        let num_blocks = total_rows.div_ceil(block_size);
        let mut checkpoints = Vec::with_capacity(num_blocks);

        // Record accumulator at row 0 (before first instruction).
        checkpoints.push(initial_acc);

        // Walk instructions once, recording accumulator at block boundaries.
        let mut acc = initial_acc;
        for (idx, instruction) in program.instructions.iter().enumerate() {
            if let hc_vm::Instruction::AddImmediate(value) = instruction {
                acc = acc.add(F::from_u64(*value));
            }
            let next_row = idx + 1;
            if next_row % block_size == 0 && checkpoints.len() < num_blocks {
                checkpoints.push(acc);
            }
        }

        Ok(Self {
            program,
            checkpoints,
            block_size,
        })
    }

    fn accumulator_at_row(&self, row_index: usize) -> F {
        let checkpoint_idx = row_index / self.block_size;
        let checkpoint_row = checkpoint_idx * self.block_size;
        let mut acc = self.checkpoints[checkpoint_idx];
        for instruction in self.program.instructions[checkpoint_row..row_index].iter() {
            if let hc_vm::Instruction::AddImmediate(value) = instruction {
                acc = acc.add(F::from_u64(*value));
            }
        }
        acc
    }
}

impl<F: FieldElement> BlockProducer<TraceRow<F>> for VmTraceProducer<F> {
    fn produce(&self, range: BlockRange) -> HcResult<Vec<TraceRow<F>>> {
        let total_rows = self.program.instructions.len() + 1;
        let end = range.end().min(total_rows);
        if range.start >= end {
            return Ok(Vec::new());
        }

        let mut rows = Vec::with_capacity(end - range.start);
        let mut acc = self.accumulator_at_row(range.start);

        for row_index in range.start..end {
            if row_index < self.program.instructions.len() {
                let instruction = &self.program.instructions[row_index];
                match instruction {
                    hc_vm::Instruction::AddImmediate(value) => {
                        let delta = F::from_u64(*value);
                        rows.push([acc, delta]);
                        acc = acc.add(delta);
                    }
                    _ => {
                        // Legacy trace producer only handles AddImmediate;
                        // other instructions are treated as no-ops with zero delta.
                        rows.push([acc, F::ZERO]);
                    }
                }
            } else {
                // Final row (after executing all instructions).
                rows.push([acc, F::ZERO]);
            }
        }

        Ok(rows)
    }
}
