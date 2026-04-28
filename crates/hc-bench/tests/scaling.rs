//! Feature-gated scaling tests.
//!
//! These are intended to back the repo's “√T-space / streaming” claims with
//! deterministic, machine-checkable invariants. They are not run in the default
//! `cargo test --workspace` because they can be slow on CI runners.

#![cfg(feature = "scaling-tests")]

use hc_core::field::{prime_field::GoldilocksField, FieldElement};
use hc_examples::zkml::DenseLayerInstance;
use hc_prover::{config::ProverConfig, prove, PublicInputs};
use hc_vm::{Instruction, Program};

/// Construct a toy program with `steps` instructions.
///
/// In the toy VM, trace length grows with instruction count, making this a cheap
/// way to sweep `T` without introducing new AIRs.
fn program_with_steps(steps: usize) -> Program {
    let mut instr = Vec::with_capacity(steps);
    for _ in 0..steps {
        instr.push(Instruction::AddImmediate(1));
    }
    Program::new(instr)
}

#[test]
fn trace_blocks_loaded_scales_approximately_linearly_in_t_over_b() {
    // Keep params stable; change only trace length.
    let block_size = 64;
    let config = ProverConfig::with_security_floor(
        block_size,
        2,
        10,
        2,
        hc_prover::config::SecurityFloor::relaxed(),
    )
    .unwrap()
    .with_protocol_version(3);

    // Two different trace lengths.
    let small_steps = 1 << 10; // 1024
    let large_steps = 1 << 12; // 4096

    let initial_acc = 5u64;
    let small_inputs = PublicInputs {
        initial_acc: GoldilocksField::new(initial_acc),
        final_acc: GoldilocksField::new(initial_acc + small_steps as u64),
    };
    let large_inputs = PublicInputs {
        initial_acc: GoldilocksField::new(initial_acc),
        final_acc: GoldilocksField::new(initial_acc + large_steps as u64),
    };

    let small = prove(config, program_with_steps(small_steps), small_inputs).unwrap();
    let large = prove(config, program_with_steps(large_steps), large_inputs).unwrap();

    // We expect trace_blocks_loaded to scale roughly like T / b (up to a modest
    // constant factor from replay). This test is coarse but catches catastrophic
    // regressions like O(T) buffering that would explode blocks_loaded.
    let small_blocks = small.metrics.trace_blocks_loaded.max(1) as f64;
    let large_blocks = large.metrics.trace_blocks_loaded.max(1) as f64;
    let ratio = large_blocks / small_blocks;

    // T increases by 4x; allow 6x to tolerate some replay overhead.
    assert!(
        ratio <= 6.0,
        "trace_blocks_loaded grew too fast: small={} large={} ratio={}",
        small.metrics.trace_blocks_loaded,
        large.metrics.trace_blocks_loaded,
        ratio
    );
    // Also ensure it actually increases (sanity).
    assert!(ratio >= 2.5, "unexpectedly low growth ratio: {ratio}");
}

#[test]
fn dense_layer_trace_blocks_loaded_scales_with_program_size() {
    // This is a more "realistic" workload that expands to many toy VM steps while still
    // exercising the same proving pipeline.
    let block_size = 64;
    let config = ProverConfig::with_security_floor(
        block_size,
        2,
        10,
        2,
        hc_prover::config::SecurityFloor::relaxed(),
    )
    .unwrap()
    .with_protocol_version(3);

    fn instance(dim: usize, neurons: usize) -> DenseLayerInstance {
        DenseLayerInstance {
            inputs: vec![GoldilocksField::new(3); dim],
            weights: vec![vec![GoldilocksField::new(5); dim]; neurons],
            biases: vec![GoldilocksField::new(7); neurons],
        }
    }

    let small = instance(16, 16);
    let large = instance(32, 32);

    let small_program = small.to_program();
    let large_program = large.to_program();
    assert!(large_program.len() > small_program.len());

    let small_inputs = PublicInputs {
        initial_acc: GoldilocksField::ZERO,
        final_acc: small.expected_accumulator(),
    };
    let large_inputs = PublicInputs {
        initial_acc: GoldilocksField::ZERO,
        final_acc: large.expected_accumulator(),
    };

    let small_proof = prove(config, small_program, small_inputs).unwrap();
    let large_proof = prove(config, large_program, large_inputs).unwrap();

    let small_blocks = small_proof.metrics.trace_blocks_loaded.max(1) as f64;
    let large_blocks = large_proof.metrics.trace_blocks_loaded.max(1) as f64;
    let ratio = large_blocks / small_blocks;

    // Program length grows by ~4x (since neurons*dim), allow slack.
    assert!(
        ratio <= 8.0,
        "dense layer trace_blocks_loaded grew too fast: small={} large={} ratio={}",
        small_proof.metrics.trace_blocks_loaded,
        large_proof.metrics.trace_blocks_loaded,
        ratio
    );
    assert!(ratio >= 2.0, "unexpectedly low growth ratio: {ratio}");
}
