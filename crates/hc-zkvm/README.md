# hc-zkvm

Height-compressed zkVM — proves correct execution of an RV32I-subset RISC-V
program in `O(√cycles)` prover memory.

## What it does

Given a RISC-V program and an input, `hc-zkvm` produces a STARK proof that

```
output = run(program, input)
```

without revealing the input. Verifiers receive only:

- A `ProgramCommitment` (hash of the instruction stream + entry PC)
- The output bytes in the clear (or output digest in ZK-masked mode)
- A succinct proof

## Why height compression matters here

Existing zkVMs (Risc0, SP1, Jolt, Cairo) materialize the entire execution
trace and run a monolithic prover. For a 30-million-cycle program that's
hundreds of GB of trace state.

The zkVM execution model is the canonical √T target:

- The trace is a chain of `(reg_file, memory, pc)` transitions — purely
  deterministic given the input.
- Block boundaries are constant-size checkpoints (32 registers + a few touched
  memory pages, hashed).
- Re-executing a block is cheap; storing it isn't. The replay engine recomputes
  block traces from checkpoints when FRI queries land in them.

## Status

Public types and `prove_execution` / `verify_execution` signatures are the
long-term contract. The cryptographic body returns `HcError::unimplemented`
and is tracked in `ROADMAP_EXTENSIONS.md` Phase 2.

## Roadmap

See [`ROADMAP_EXTENSIONS.md`](../../ROADMAP_EXTENSIONS.md) for the phased
delivery plan and target commercial template (`zkvm_execution`).
