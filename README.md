# hc-stark — Height-Compressed, Streaming STARK Prover

`hc-stark` is a **height-compressed, sublinear-space STARK prover** designed to make **very long zero-knowledge proofs** practical on fixed-memory hardware (CPUs, GPUs, and edge devices).

It implements a **√T-space, streaming prover** for STARK-style proofs: instead of buffering the entire trace and all derived polynomials, the prover walks a **height-compressed computation tree** and recomputes small tiles on demand from compact checkpoints.

The result:

- **Prover memory:** ~√T (up to polylog factors) instead of T  
- **Prover time:** ~T · polylog²(T) (near-standard STARK time with a small replay overhead)  
- **Verifier & proof:** unchanged STARK-like (polylog(T) verification, polylog(T) proof size)  
- **Security:** transparent + hash-based (STARK-style, plausibly post-quantum)

---

## 1. What is this repo?

This repository is a **reference implementation** of a height-compressed STARK (hc-STARK) prover, meant to demonstrate:

- How to **recast a STARK prover** as a **height-compressible computation**.
- How to **tile** traces and polynomials into `√T`-sized blocks and **stream** over them.
- How to build a **pointerless DFS + replay engine** that achieves √T-space while preserving exact correctness.
- How to plug this into **real proving use cases**: zkVM traces, zkML workloads, and rollup batch proofs.

You can think of `hc-stark` as:

> “A provably correct, streaming, low-memory STARK engine that trades a bit of extra CPU for a quadratic reduction in prover RAM.”

---

## 2. What does hc-stark do?

At a high level, hc-STARK implements the standard STARK stack, but with a different **execution model**:

- **Input:**
  - A deterministic transition function (VM / AIR),
  - A finite execution trace of length `T`,
  - Public inputs/outputs, and a soundness / security parameter.

- **Output:**
  - A STARK-style proof that the trace satisfies the AIR constraints.
  - The proof is:
    - **Transparent** (no trusted setup),
    - **Hash-based** (plausibly post-quantum),
    - **Succinct** (polylog(T) size),
    - **Fast to verify** (polylog(T) time).

- **Key property:**  
  The **prover** runs in **sublinear space**: its peak working set scales like  
  `~ √T · polylog(T)` rather than `~ T`.

This unlocks proving regimes that are currently painful or impossible with in-core STARKs:

- zkVM traces with **10¹¹+ steps** on a single machine,
- zkML workloads where the **model + data** don’t fit in RAM,
- rollup batch proofs for **massive block sequences**, without mega-RAM boxes.

---

## 3. How the repo is organized

*(Adapt these names to match your actual folders if they differ slightly.)*

```text
hc-stark/
  Cargo.toml
  rust-toolchain.toml
  README.md
  docs/
    whitepaper.md
    design_notes/
  scripts/
    test_suite.sh  # Comprehensive test suite (sanity/stress/ladder tests)

  crates/
    hc-core/       # Field arithmetic, FFTs (CPU + gpu-fft hook), error types
    hc-commit/     # Vector commitments + standard/streaming Merkle trees
    hc-hash/       # Hash digests, transcripts, Fiat–Shamir helpers
    hc-fri/        # Streaming FRI prover/verifier built on TraceReplay
    hc-air/        # AIR definitions (constraints, degrees, boundary conditions)
    hc-vm/         # Toy VM + trace generator used in tests/examples
    hc-replay/     # Block producers + deterministic replay engine
    hc-prover/     # Pointerless DFS scheduler + replay-aware prover pipeline
    hc-verifier/   # Standard STARK verifier matching the prover transcript
    hc-cli/        # End-to-end CLI (prove/verify/bench/inspect) + JSON I/O
    hc-bench/      # Programmatic benchmarking harness (√T metrics)
    hc-examples/   # Library of sample end-to-end flows
    hc-recursion/  # Aggregation + recursion scaffolding
```

**Separation of concerns:**

* `hc-core`, `hc-commit`, `hc-hash`, and `hc-fri` implement **generic primitives** usable by other projects.
* `hc-air` + `hc-vm` define concrete **computations to prove** (VMs, example AIRs).
* `hc-replay` abstracts deterministic block replays so higher layers can stay agnostic.
* `hc-prover` is where the **height compression logic** (scheduler + replay plumbing) lives.
* `hc-verifier` is intentionally “boring”: as close as possible to a standard STARK verifier, now paired with serialized proofs emitted by the CLI/bench harnesses.

---

## 4. How the prover works (and why it meets the whitepaper desiderata)

### 4.1 Classic STARK pipeline (conceptually)

A “normal” in-core STARK prover does something like:

1. **Trace generation:**
   Materialize the full execution trace (T rows × k columns) in memory.

2. **AIR evaluation and composition polynomial:**

   * Interpolate polynomials over the trace domain.
   * Apply constraint polynomials to produce a composition polynomial.
   * Possibly extend to larger evaluation domains.

3. **Commitments:**

   * Perform FFTs / IFFTs over full vectors of length T (or larger).
   * Build Merkle trees for each oracle (trace, composition, FRI layers).

4. **Query answering:**

   * On verifier’s challenge indices, fetch rows / evaluations.
   * Return corresponding Merkle authentication paths and polynomial values.

All major steps treat the trace and polynomial oracles as **monolithic arrays** of size Θ(T). Memory usage is **Θ(T)**.

### 4.2 Height-compressed STARK pipeline

hc-STARK refactors this into a **height-compressed computation tree**:

1. **Block tiling:**

   * Choose a block size `b ≈ √T`.
   * Think of the trace as `T / b ≈ √T` **blocks** of size `b`.
   * Do the same for polynomial oracles, FRI layers, etc.

2. **Computation tree:**

   * Each logical “STARK step” (e.g., building a Merkle tree, running FRI) is represented as a **binary tree of block computations**.
   * Leaves correspond to block-local operations (FFT on a tile, hashing a range, etc.).
   * Internal nodes combine children (e.g., merge partial tree roots, propagate FRI layers).

3. **Height compression + pointerless DFS:**

   * Reshape the natural left-deep tree into a **balanced binary tree** whose depth is **O(log T)**.
   * Traverse this tree with a **pointerless DFS**:

     * No explicit heap-allocated tree,
     * Just a small **stack of frames** (one per level),
     * Each frame holds at most O(1) “checkpoints” (hashes, random coins, block indices).

4. **Replay engine:**

   * Instead of keeping all blocks live, hc-STARK:

     * Stores **only O(1)** block(s) of size `b` at a time,
     * Recomputes blocks from nearby checkpoints using the VM/AIR and polynomial primitives.
   * Whenever a block is needed again (e.g., for answering queries or building higher FRI layers), it is **replayed** from checkpoints with **O(b)** working memory.

By choosing `b ≈ √T`, the prover’s peak space becomes:

* `O(b) + O(log T)` stack overhead,
* ⇒ **~√T · polylog(T)** in total.

### 4.3 Complexity summary (hc-STARK itself)

Let `T` be the trace length / domain size.

* **Prover space:**

  * Live block size: `b ≈ √T`
  * DFS stack: `O(log T)` small frames
  * ⇒ `Space_prover = ~O(√T · polylog T)`

* **Prover time:**

  * Each block: `~O(b · polylog b)` work,
  * Number of blocks: `~T / b ≈ √T`,
  * Some blocks are replayed along O(log T) tree height,
  * ⇒ conservative bound `Time_prover = ~O(T · log² T)`

* **Verifier & proof:**

  * Comparable to a standard STARK:

    * `Time_verifier = polylog(T)`
    * `Proof_size = polylog(T)`

---

## 5. Complexity & properties: hc-STARK vs other proving systems

This section compares hc-STARK against several prevailing ZKP paradigms along:

* **Asymptotic prover time**
* **Asymptotic prover space**
* **Verifier time**
* **Proof size**
* **Transparency** (trusted setup or not)
* **Post-quantum safety**

Let `T` denote the “size” of the computation (e.g., number of steps in a VM trace, or circuit size).

### 5.1 Side-by-side comparison

> Asymptotics hide polylog factors; we use `~O(·)` to mean “up to polylog(T)”.

| System / Paradigm                         | Prover Time (in T)  | Prover Space | Verifier Time                             | Proof Size        | Transparent? (No SRS)  | Post-Quantum Safe?*                           | Notes                                                  |
| ----------------------------------------- | ------------------- | ------------ | ----------------------------------------- | ----------------- | ---------------------- | --------------------------------------------- | ------------------------------------------------------ |
| **hc-STARK (this repo)**                  | `~O(T · log² T)`    | `~O(√T)`     | `~O(polylog T)`                           | `~O(polylog T)`   | **Yes**                | **Yes (hash-based; STARK-style assumptions)** | Streaming, √T-space; inherits STARK guarantees.        |
| **In-core STARK**                         | `~O(T · log T)`     | `O(T)`       | `~O(polylog T)`                           | `~O(polylog T)`   | **Yes**                | **Yes (hash-based; STARK-style assumptions)** | Classic design; RAM is the bottleneck.                 |
| **Pairing SNARK (Groth16/Plonk)**         | `~O(T · polylog T)` | `O(T)`       | `~O(1)` group ops + `polylog T` field ops | `O(1)` (constant) | **No** (needs SRS)     | **No** (EC pairings / discrete log)           | Tiny proofs; great verification; heavy setup & non-PQ. |
| **IPA/Bulletproof-style SNARKs**          | `~O(T · log T)`     | `O(T)`       | `~O(polylog T)`                           | `~O(log T)`       | Often **Yes** (no SRS) | **No** (discrete log)                         | Small proofs; no trusted setup; prover still O(T) RAM. |
| **PCP/IOP with generic hash commitments** | `~O(T · polylog T)` | `O(T)`       | `~O(polylog T)`                           | `~O(polylog T)`   | **Yes**                | **Yes (hash-based)**                          | Conceptual baseline for STARK-like systems.            |

* “Post-quantum safe?” here means: **no known polynomial-time quantum attacks under common assumptions**.
Hash-based, STARK-style systems are currently considered **much more “future-proof”** than discrete-log / pairing-based systems.

### 5.2 How hc-STARK fits into the landscape

* **vs In-core STARKs (same family):**

  * **Same security & cryptographic assumptions.**
  * **Same transparency**: no trusted setup.
  * **Same general prover/verifier interface**, same AIR / IOP structure.
  * **Key difference:** hc-STARK changes the **computational regime**:

    * RAM: `O(T)` → `~O(√T)`,
    * Time: `~O(T log T)` → `~O(T log² T)` (extra log factor from replay).
  * If RAM is cheap and T is moderate: classic STARKs win on simplicity.
  * If T is huge and RAM is the bottleneck: hc-STARK unlocks proofs that otherwise don’t fit at all.

* **vs Pairing-based SNARKs (Groth16/Plonk):**

  * SNARKs offer:

    * **Tiny proofs (constant size)**,
    * **Extremely fast verification**, great for on-chain verification.
  * But:

    * Require a **trusted setup** (universal or per-circuit SRS),
    * Rely on **elliptic-curve pairings / discrete log** ⇒ vulnerable to **quantum attacks** (Shor).
    * Prover still typically uses **O(T)** memory (large polynomials, FFTs, MSMs).
  * hc-STARK chooses the opposite trade-off:

    * Proofs are larger (polylog(T) rather than constant),
    * Verifier is slightly heavier (though still polylog(T)),
    * In exchange, you get **transparent, hash-based, PQ-friendly** security and **√T-space** provers.

* **vs IPA/Bulletproof-style systems:**

  * Bulletproofs and some IPA SNARKs are:

    * **Transparent or updatable** (no per-circuit SRS),
    * Have **logarithmic proof size**,
    * But still rely on EC discrete log ⇒ **not PQ safe**.
  * Prover memory is still effectively **O(T)**, because the underlying representation is vector-based.
  * hc-STARK again trades slightly larger proofs for:

    * **Hash-only assumptions**,
    * **Sublinear prover memory**.

### 5.3 Which use cases benefit the most from hc-STARK?

The √T-space design is especially valuable where:

* **T is enormous** (zkVMs, zkML, long-running off-chain compute, rollup batch proofs), and:
* **RAM / VRAM is the true bottleneck**, not raw compute cycles.

Concrete examples:

* zkRollups with **massive block batches** on commodity cloud machines,
* zkVMs with **billions of steps** running on a single GPU,
* zkML proving for large models and large batched inputs, where activation traces don’t fit in RAM,
* Verifiable off-chain compute platforms that want to run on **fixed-memory hardware tiers**.

In that regime, hc-STARK:

> *“Moves you from ‘what can I prove with my RAM?’ to ‘what can I prove with my CPU/GPU cycles?’”*

which is often the **more scalable and cloud-friendly axis to spend money on**.

---

## 6. How to use hc-STARK

### 6.1 Building and running examples

```bash
# Build everything
cargo build --workspace

# Run a simple zkVM example (e.g., Fibonacci)
cargo run -p hc-examples --bin zkvm_fib_prove

# Verify the corresponding proof
cargo run -p hc-examples --bin zkvm_fib_verify
```

Quick smoke tests via our CLI:

```bash
cargo run -p hc-cli -- prove --output proof.json
cargo run -p hc-cli -- verify --input proof.json
cargo run -p hc-cli -- bench --iterations 5 --block-size 64
```

You might expose flags like:

```bash
cargo run -p hc-examples --bin zkvm_fib_prove \
  -- --steps 100000000 \
     --block-size 10000 \
     --security-level 128 \
     --output proof.json
```

### 6.2 Running the comprehensive test suite

The project includes a comprehensive test suite that validates all functionality and verifies the O(√T) complexity claims:

```bash
# Run all tests (sanity, stress, and scaling analysis)
./scripts/test_suite.sh all

# Run specific test categories
./scripts/test_suite.sh sanity   # Basic functionality checks
./scripts/test_suite.sh stress   # Edge cases and parameter variations
./scripts/test_suite.sh ladder   # Scaling analysis with O(√T) verification
```

The test suite includes:

- **Sanity checks**: Build verification, unit tests, CLI roundtrip tests, and core library validation
- **Stress tests**: Multiple block sizes (1, 2, 4, ..., 512, 1024), multiple iterations, and edge cases
- **Ladder tests**: Systematic scaling analysis that validates O(√T) memory complexity and measures performance metrics
Test results are logged to timestamped files and include detailed performance metrics (duration, trace blocks loaded, FRI blocks loaded) for analysis.

The ladder phase now wraps each benchmark with `/usr/bin/time -v` when available, collecting `profile_duration` (ms) and `memory_kb` (RSS) per block size. These entries are appended to `$TEMP_DIR/ladder_results.json` and the analysis stage uses `jq`/`bc` to compute normalized ratios, demonstrating constant-time and √T-memory behavior. The script still works when `timeout`, `/usr/bin/time`, or `jq` are missing—warnings are emitted and raw JSON is kept for offline inspection.

### 6.3 Extending the system with a new AIR / VM

To define a new computation:

1. Implement a **VM / transition function** in `hc-vm` or a similar crate:

   * Define the state representation,
   * Implement “next state” and boundary conditions.

2. Define the corresponding **AIR** in `hc-air`:

   * Number of trace columns,
   * Constraint polynomials,
   * Boundary constraints, degree bounds, etc.

3. Wire it into `hc-prover`:

   * Implement a small adapter that:

     * Generates a trace stream,
     * Exposes “block replay” hooks (how to regenerate a block from a checkpoint).

4. Add an **example binary** in `examples/` that:

   * Constructs public inputs,
   * Runs the prover,
   * Serializes a proof,
   * Runs the verifier.

### 6.4 Benchmarking the time/space trade-off

Use the `benches/space_time` harness (or your own) to compare:

* hc-STARK vs a baseline in-core STARK prover, for the same AIR / trace.
* Measure:

  * Peak RSS (RAM),
  * Total runtime,
  * CPU/GPU utilization.

This demonstrates the **√T-space behavior** and the **polylogarithmic time overhead** empirically. The `hc-bench` and `hc-cli bench` helpers give you a repeatable harness for micro-benchmarks without wiring up your own scripts.

---

## 7. Status and roadmap

### ✅ Completed Features

* ✅ **Core primitives**: Fields, hashing, FFTs wired for **block-based, streaming operation** (including the `gpu-fft` hook).
* ✅ **Streaming architecture**: Streaming Merkle trees, FRI data paths, deterministic replay engine, and pointerless DFS scheduler.
* ✅ **Complete prover pipeline**: Height-compressed STARK prover with O(√T) memory complexity.
* ✅ **Query replay & verification**: Fiat-Shamir challenges are replayed with Merkle path checks, ensuring the verifier sees the same leaf values as the prover.
* ✅ **Verifier implementation**: Complete verifier now matches the prover transcript, validates Merkle paths via streaming replay, and enforces FRI query propagation.
* ✅ **Streaming Merkle replay**: `StreamingMerkle::extract_path` reconstructs Merkle paths via block replay without ever materializing the full tree.
* ✅ **Block-wise LDE/composition**: Each block is low-degree extended and combined into composition contributions with hashed commitments and new metrics.
* ✅ **CLI tooling**: Full CLI with `prove`, `verify`, and `bench` commands plus JSON serialization for proofs and query responses.
* ✅ **Benchmarking**: Performance metrics tracking (trace blocks, FRI blocks, duration) with `hc-bench`, plus matrix of scaling data.
* ✅ **Comprehensive test suite**: Sanity, stress, and ladder tests now log runtime and RSS metrics into `test_temp/ladder_results.json` for O(√T) verification.
* ✅ **Documentation**: Complete whitepaper, design notes, and implementation documentation.

### 🔄 Ongoing Work

* Expanding AIRs / zkVM examples beyond the toy VM.
* Adding CI/CD integration for automated testing and regression detection.
* Performance optimization and profiling for production workloads.

### Long-term Directions

* **GPU acceleration**: Flesh out the GPU backend (real kernels, not just the CPU shim) and expose multi-device scheduling policy.
* **Production integration**: Integrate with production zkVM frontends and zkML frameworks.
* **Distributed proving**: Explore multi-prover or distributed replay over the same height-compressed tree.
* **Advanced features**: Recursive proof composition, proof aggregation, and custom AIR optimizations.

---

## 8. Development standards (TL;DR)

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full checklist. Highlights:

- **Toolchain:** Rust `stable`, `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --all-targets`, `cargo doc --workspace --no-deps`.
- **Safety:** All crates use `#![forbid(unsafe_code)]`. Prefer pure functions and explicit data ownership.
- **Error handling:** Use `hc_core::HcError`, `HcResult<T>`, and the `hc_ensure!` macro; never `panic!` in library code.
- **Docs:** Every module starts with a `//!` overview and updates the relevant note under `docs/design_notes/`.
- **Benchmarks:** Keep `hc-bench` scenarios deterministic so nightly CI can compare regressions.

Following these guardrails ensures we ship a world-class, production-ready hc-STARK stack without regressing on correctness or security.

---

## 9. Current snapshot

- ✅ **Complete hc-STARK implementation**: Full height-compressed STARK prover with O(√T) memory complexity.
- ✅ **Streaming architecture**: Streaming Merkle trees, FRI protocol, and deterministic replay engine fully implemented.
- ✅ **Query answering**: Complete Fiat-Shamir query generation and Merkle path extraction for verifier challenges.
- ✅ **CLI tooling**: Full-featured CLI (`hc-cli`) with `prove`, `verify`, and `bench` commands.
- ✅ **Benchmarking**: Comprehensive benchmarking harness (`hc-bench`) with performance metrics.
- ✅ **Test suite**: Comprehensive test suite (`scripts/test_suite.sh`) validating all functionality and complexity claims.
- ✅ **Recursive proof scaffolding**: Basic recursion and aggregation infrastructure ready for extension.
- ✅ **GPU-ready architecture**: FFT backend trait (`hc_core::fft::backend::FftBackend`) ready for GPU acceleration.
- ✅ **Full test coverage**: All workspace tests passing via `cargo test --workspace`.
- ✅ **Documentation**: Complete whitepaper, design notes, and implementation documentation.

**Next**: Production use, performance optimization, GPU acceleration, and integration with zkVM/zkML frameworks.

---

If you’re interested in collaborating, extending this design, or plugging hc-STARK into your zk stack (rollups, zkML, verifiable compute), the structure of this repo is meant to make that as straightforward as possible: you get a **future-proof, transparent, PQ-friendly ZKP engine** with a **provably sublinear-space prover** as a first-class architectural primitive.