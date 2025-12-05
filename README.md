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
    hc-height/     # Experimental generalized height-compression interfaces
```

**Separation of concerns:**

* `hc-core`, `hc-commit`, `hc-hash`, `hc-fri`, and `hc-height` implement **generic primitives** usable by other projects.
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
cargo run -p hc-cli -- bench --iterations 5 --block-size 64 --scenario prover

# Streaming Merkle vs in-memory path replay
cargo run -p hc-cli -- bench --scenario merkle --leaves 4096 --queries 128 --fanout 2

# Batched LDE throughput micro-bench
cargo run -p hc-cli -- bench --scenario lde --columns 4 --degree 512 --samples 2048

# Recursion summary aggregation
cargo run -p hc-cli -- bench --scenario recursion --proofs 8

# Produce a Halo2-backed recursion artifact from two child proofs
cargo run -p hc-cli -- recursion \
  --proof proof_a.json \
  --proof proof_b.json \
  --artifact recursion_artifact.json \
  --metrics recursion_metrics.json

# Height-compressed Merkle vs KZG commitments
cargo run -p hc-cli -- bench --scenario height --leaves 65536 --block-size 128

# Auto-select a block size (√T heuristic + memory clamp)
hc-cli prove --auto-block --trace-length 1048576 --target-rss-mb 256
hc-cli bench --scenario prover --auto-block-size --trace-length 1048576 --target-rss-mb 256

# Experimental SNARK/KZG oracle (commitments streamed via ark-bn254)
hc-cli prove --commitment kzg --auto-block --output proof_kzg.json
# (verification currently mocks the KZG branch but exercises the pipeline end-to-end)

### Bench metrics & dashboards

All `hc-cli bench` scenarios accept `--metrics-dir <path>` (default `benchmarks`) and `--metrics-tag <label>` to persist JSONL/CSV history for dashboards. Example:

```bash
hc-cli bench \
  --scenario height \
  --auto-block-size \
  --metrics-tag nightly \
  --metrics-dir benchmarks \
  --leaves 65536 \
  --samples 3
```

This appends a record to `benchmarks/height_history.jsonl`, refreshes `height_latest.csv` (per-sample detail), and updates `height_history.csv` with per-run summaries. CI runs `scripts/aggregate_height_metrics.py` to turn those files into `height_dashboard.md` + `height_trend.png`, but you can run the script locally (optionally pointing `--out-dir` somewhere else) to inspect the latest regressions before pushing.

## CLI presets, auto-tuning & hardware detection

Auto-tuning is now a first-class feature; the CLI resolves block sizes and memory budgets by layering (in order of precedence) defaults → presets → config file → explicit flags. The built-in presets (`balanced`, `memory`, `latency`, `laptop`, `server`) encode sensible √T heuristics for common machines, while `.hc-cli.toml` lets you capture org-specific guidance.

### Preset lifecycle

- **Built-ins**: `--preset laptop` biases toward smaller blocks (good for 16–32 GB laptops); `--preset server` increases the max block cap and assumes large L3 caches; `--preset memory` minimizes RSS at the expense of more replays.
- **User presets**: any table under `[presets.<name>]` mirrors CLI flags (`auto_block`, `trace_length`, `target_rss_mb`, `hardware_detect`, `commitment`, etc.). These presets can point to shared tuner caches so CI and developers reuse the same history.
- **Resolution**: presets hydrate missing options, but you can still override anything per command (`--target-rss-mb 512` beats whatever the preset provided). The CLI prints the final profile, commitment scheme, and block size so you always see what was applied.

### `.hc-cli.toml` structure

```toml
# ~/.hc-cli.toml
[presets.gpu_lab]
auto_block = true
trace_length = 16777216         # hint used by √T heuristic before real traces are known
target_rss_mb = 4096            # treat as “VRAM budget” when running on a 24 GB GPU
profile = "latency"             # bias toward fewer replays on lab servers
hardware_detect = true          # let hc-cli inspect L3/cache sizes before clamping b
commitment = "kzg"              # default to the experimental SNARK-style oracle
tuner_cache = "/var/tmp/hc-stark/tuner_history.json"
```

### Hardware detection and GPU considerations

`--hardware-detect` (or `hardware_detect = true` in a preset) calls `hc_prover::block_tuner::detect_hardware_profile`, which gathers:

- total RAM to estimate an RSS ceiling when you don’t pass `--target-rss-mb`,
- L3 cache size to derive a conservative `b_{\max}` so active blocks remain cache-resident,
- an optional `HC_GPU_MEM_MB` environment override so GPU runners can map VRAM budgets into the same √T formula.

The auto tuner fuses those measurements with the analytical `b ≈ √T` starting point, then nudges the recommendation using historical replay factors (`tuner_history.json`). For GPU nodes, simply set `target_rss_mb` to the per-device VRAM you want to burn; the rest of the heuristics carry over unchanged because the prover already streams blocks through bounded buffers.

### Example workflows

```bash
# Laptop-friendly auto tuning with hardware detection and preset defaults
hc-cli prove \
  --preset laptop \
  --auto-block \
  --hardware-detect \
  --trace-length 1048576 \
  --output proof.json

# CI-style bench run that reuses shared tuner history without mutating it
hc-cli bench \
  --scenario prover \
  --auto-block-size \
  --preset server \
  --trace-length 8388608 \
  --no-tuner-cache \
  --target-rss-mb 16384

# Exercise the experimental KZG oracle end to end
hc-cli prove \
  --auto-block \
  --hardware-detect \
  --commitment kzg \
  --trace-length 2097152
```

All three commands emit the finalized block size, auto profile, commitment scheme, and (when applicable) the tuner cache path so you can correlate observed √T behavior with the configuration that produced it.

# Core FFT / field smoke tests (used by scripts/test_suite.sh sanity)
cargo run -p hc-core --example fft_test
cargo run -p hc-core --example field_test
```

For richer workloads, `hc-examples` includes a zkML **dense layer** harness that runs end-to-end with the streaming prover:

```bash
cargo test -p hc-examples tests::dense_layer_demo_executes -- --nocapture
```

The same module exposes `dense_layer_replay` so you can feed dense-layer traces into custom AIRs or benchmark replay performance.

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
- **Stress tests**: Includes streaming Merkle (`--scenario merkle`) and batched LDE (`--scenario lde`) micro-benches; JSON artifacts land in `benchmarks/stress_latest.json`.
- **Ladder tests**: Systematic scaling analysis that validates O(√T) memory complexity and measures performance metrics. Results are written to both `benchmarks/ladder_latest.json` and `benchmarks/ladder_latest.csv` for quick plotting.
Test results are logged to timestamped files and include detailed performance metrics (duration, trace blocks loaded, FRI blocks loaded) for analysis.

The ladder phase now wraps each benchmark with `/usr/bin/time -v` when available, collecting `profile_duration` (ms) and `memory_kb` (RSS) per block size. These entries are appended to `benchmarks/ladder_latest.json` (and `.csv`), and the analysis stage uses `jq`/`bc` to compute normalized ratios, demonstrating constant-time and √T-memory behavior. The script still works when `timeout`, `/usr/bin/time`, or `jq` are missing—warnings are emitted and raw JSON is kept for offline inspection. Artifact formats are documented under [`docs/benchmarks/`](docs/benchmarks/README.md).

Every `hc-cli bench` invocation emits a single-line JSON summary and updates `benchmarks/latest.json`, making it easy to feed CI dashboards or perf regressions without scraping logs.

### 6.3 Continuous integration & regression artifacts

`.github/workflows/ci.yml` runs on every push / PR and executes:

- `cargo fmt`, `cargo clippy --workspace --all-targets`, and `cargo test --workspace`
- `./scripts/test_suite.sh sanity`, `stress`, and `ladder`
- A lightweight prover benchmark (`hc-cli bench --iterations 2 --block-size 8 --scenario prover`)
- `./scripts/check_bench_thresholds.py benchmarks/latest.json benchmarks/ladder_latest.json` compares fresh metrics against `benchmarks/baseline.json` and fails the job if `avg_trace_blocks`, `avg_fri_blocks`, or durations drift beyond the allowed percentage.

The workflow uploads `benchmarks/latest.json`, `benchmarks/stress_latest.json`, and `benchmarks/ladder_latest.{json,csv}` via `actions/upload-artifact`, so dashboards (or humans) can diff √T behavior without reproducing long runs locally.

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
* ✅ **Streaming FRI Merkle proofs**: Every FRI layer is committed with a streaming Merkle tree; query responses carry real authentication paths that `hc-verifier` replays before hashing them into `QueryCommitments`.
* ✅ **Streaming Merkle replay**: `StreamingMerkle::extract_path` reconstructs Merkle paths via block replay without ever materializing the full tree.
* ✅ **Block-wise LDE/composition**: Each block is low-degree extended and combined into composition contributions with hashed commitments and new metrics.
* ✅ **Recursion planner & encodings**: `RecursionSpec::plan_for` emits deterministic batching schedules and the recursion circuit re-encodes `ProofSummary` commitments for outer proofs.
* ✅ **Richer workloads**: `hc-examples` ships zkML dense-layer traces plus replay helpers for benchmarking non-toy AIRs.
* ✅ **Recursion-ready verifier summaries**: `hc-verifier` now exposes `verify_with_summary` plus `QueryCommitments`, enabling `hc-recursion` to hash query responses deterministically.
* ✅ **Recursive aggregation flow**: `hc-recursion` emits schedule-aware aggregated proofs, `AggregatedProof::verify` replays the hash tree, `hc-cli bench --scenario recursion` benchmarks end-to-end wrapping, and a Halo2/KZG circuit now produces/validates real proofs over the summarized data.
* ✅ **Generalized height compression experiments**: The `hc-height` crate models streaming commitment builders (Merkle or KZG-style) so pointerless DFS + replay can be applied beyond STARKs.
* ✅ **Height-compression benchmarks**: `hc-cli bench --scenario height` compares streaming Merkle/KZG commitments against in-memory baselines and logs runtime deltas for §8.4 experiments.
* ✅ **Configurable streaming Merkle fanouts**: The height-compressed builder + replay extractor accept arbitrary fanouts and include property tests + micro-benchmarks.
* ✅ **Batched LDE kernels**: Parallel column evaluators (Rayon-backed) keep LDE + constraint evaluation within the √T memory envelope.
* ✅ **CLI tooling**: Full CLI with `prove`, `verify`, and `bench` commands plus JSON serialization for proofs and query responses.
* ✅ **Benchmarking**: `hc-bench` now ships scenario presets (`prover`, `merkle`, `lde`) so you can compare streaming vs in-memory paths and sequential vs batched LDE kernels. Summaries are emitted as JSON and copied into `benchmarks/latest.json`.
* ✅ **Comprehensive test suite**: Sanity, stress, and ladder tests log runtime + RSS metrics and persist JSON/CSV artifacts under `benchmarks/` for CI scraping.
* ✅ **CI & regression hooks**: GitHub Actions run fmt/clippy/tests + all suite modes, publish benchmark artifacts, and gate PRs via `scripts/check_bench_thresholds.py` against `benchmarks/baseline.json`.
* ✅ **Documentation**: Complete whitepaper, design notes, and implementation documentation.

### 🔄 Ongoing Work

* Recursive wrapping circuits: feeding the new `ProofSummary` (with query commitments) into zk circuits + scheduled fan-in trees.
* Multi-layer scheduling: richer recursion planning + multi-level aggregation specs.
* Automated CI dashboards that ingest `benchmarks/latest.json` / ladder CSVs to track √T metrics across commits.
* Expanding AIRs / zkVM examples beyond the toy VM + wiring GPU FFT backends.

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