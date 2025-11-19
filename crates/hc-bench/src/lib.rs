use std::time::Instant;

use hc_core::field::prime_field::GoldilocksField;
use hc_prover::{config::ProverConfig, metrics::ProverMetrics, prove, PublicInputs};
use hc_vm::{Instruction, Program};
use serde_json::json;

pub mod lde;
pub mod merkle_paths;
pub use lde::bench_parallel_lde;
pub use merkle_paths::bench_merkle_paths;

pub fn benchmark(
    iterations: usize,
    block_size: usize,
) -> hc_core::error::HcResult<serde_json::Value> {
    let program = Program::new(vec![
        Instruction::AddImmediate(1),
        Instruction::AddImmediate(2),
    ]);
    let inputs = PublicInputs {
        initial_acc: GoldilocksField::new(5),
        final_acc: GoldilocksField::new(8),
    };
    let config = ProverConfig::new(block_size, 2)?;
    let start = Instant::now();
    let mut agg_metrics = ProverMetrics::default();
    for _ in 0..iterations {
        let proof = prove(config, program.clone(), inputs.clone())?;
        agg_metrics.add_trace_blocks(proof.metrics.trace_blocks_loaded);
        agg_metrics.add_fri_blocks(proof.metrics.fri_blocks_loaded);
    }
    let elapsed = start.elapsed();
    let summary = json!({
        "iterations": iterations,
        "block_size": block_size,
        "total_duration_ms": elapsed.as_secs_f64() * 1000.0,
        "avg_duration_ms": (elapsed.as_secs_f64() * 1000.0) / iterations as f64,
        "avg_trace_blocks": agg_metrics.trace_blocks_loaded as f64 / iterations as f64,
        "avg_fri_blocks": agg_metrics.fri_blocks_loaded as f64 / iterations as f64,
    });
    Ok(summary)
}
