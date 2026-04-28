# hc-STARK: Height-Compressed, Memory-Efficient STARK Provers

_Last updated: 2025-12-04_

---

## 1. Motivation: Prover RAM as the Bottleneck

Modern zero-knowledge proof systems – especially STARK-style systems – are increasingly used to prove correctness of very long computations:

- zkVMs / zkEVMs with tens of millions of steps
- zkML pipelines with large models and datasets
- Rollup provers that batch many L2 transactions into a single proof
- Verifiable off-chain compute (e.g., analytics, simulations, training steps)

In essentially all of these, **prover memory** is the hard bottleneck:

- Large execution traces (rows) and many columns (registers) produce **huge polynomials**.
- FFTs, permutation arguments, and FRI layers want access to large, contiguous buffers.
- Practically, provers need **hundreds of GB of RAM** or GPU VRAM to handle realistic workloads.

This leads to several problems:

1. **Cost & operational fragility**

   - You need very large bare-metal machines or specialized clusters.
   - Failures are painful: one out-of-memory event can kill a multi-hour proving job.
   - Horizontal scaling is non-trivial because the algorithms assume monolithic access to the entire trace/polynomials.

2. **Modeling constraints**

   - Developers design AIR/circuits under the constraint _“what we can fit in RAM”_, not _“what is the best model of the computation”_.
   - They compromise on:
     - Number of steps (e.g., fewer iterations, shorter traces),
     - Model fidelity (e.g., simplified VM semantics),
     - Data size (e.g., smaller batches / limited context).

3. **Under-utilized hardware locality**

   - CPUs and GPUs have deep memory hierarchies: L1/L2/L3 cache, NUMA, VRAM, HBM.
   - Ideally, the prover’s working set stays inside fast memory.
   - Current designs often thrash caches with multi-GB buffers, losing a lot of potential throughput.

**hc-STARK** is designed to change the constraint from:

> “We are RAM-bound”  

to

> “We are cycle-bound, but RAM fits.”

by rethinking **how** we walk the trace and build the proof.

---

## 2. Core Idea: √T-Space Height Compression for STARK Provers

Let:

- \( T \) be the length of the execution trace (number of rows / steps).
- Traditional STARK provers behave as if they need \( \Theta(T) \) space for polynomials / oracles.

The central algorithmic insight we exploit is:

> **Deterministic computations of length \(T\) can be simulated using only \(O(\sqrt{T})\) working memory** by:
> - partitioning the computation into blocks of size \( b \),
> - building a balanced computation tree over these blocks,
> - evaluating it with a height-compressed, pointerless DFS and a replay engine.

If we carefully re-express STARK proving as such a **height-compressible computation** over the trace and its derived polynomials, we get:

- A prover whose working set is \( O(b + T/b) \), minimized at \( b \approx \sqrt{T} \).
- Only \(O(\sqrt{T})\) trace/polynomial data in RAM/VRAM at any point.
- The ability to handle **arbitrarily long traces** on fixed-memory machines, at the cost of extra recomputation.

The rest of this document explains how we translate that complexity-theoretic idea into a concrete STARK architecture.

---

## 3. Mathematical Structure of hc-STARK

### 3.1 Block Tiling: \( b \approx \sqrt{T} \)

We start with a standard STARK-style execution trace:

- Rows indexed by \( t = 1, \dots, T \)
- Columns for state registers, inputs, etc.

We partition the trace into **time blocks** of length \( b \) rows:

- Number of blocks \( B = \lceil T / b \rceil \).
- Block \(k\) covers rows:
  \[
    [(k-1)b + 1, \dots, \min\{kb, T\}]
  \]

Each block is treated as a **self-contained micro-trace** with:

- A local window of rows,
- The local contributions to:
  - Execution constraints (AIR),
  - Boundary conditions,
  - Polynomial/evaluation oracles for Merkle/FRI.

Crucially:

- We never need to hold **all** blocks simultaneously in memory.
- For the algebraic layer, each block induces a small number of **local polynomials / evaluations** that can be reconstructed on demand.

### 3.2 From Linear Traces to Computation Trees

Naively, evaluating all constraints and building all polynomial oracles for the entire trace behaves like a **left-deep computation tree**:

- Each block depends on previous state,
- Global polynomials aggregate all blocks,
- A depth-first evaluation requires path data for \( \Theta(B) = \Theta(T/b) \) levels.

This causes the classic space blowup: path bookkeeping and partial results pile up.

Instead, we reshape the computation into a **balanced binary tree** over the blocks.

- Leaves: individual blocks \( [k, k] \).
- Internal node \(I = [i, j]\): “summary” of the combined effect of blocks \(i, \dots, j\):
  - On the execution trace and constraints;
  - On derived algebraic objects (e.g., FRI oracles).

This tree has height \( O(\log B) = O(\log (T/b)) \).

### 3.3 Height Compression: Logarithmic Evaluation Depth

The **Height Compression Theorem** (informally, in this context) says:

> There exists a uniform, logspace-computable way to:
> - reshape the canonical computation tree into a balanced binary tree,
> - schedule an evaluation order (a DFS),
> - such that along any root–leaf path:
>   - only \( O(\log B) \) “interfaces” or checkpoints are simultaneously alive,
>   - each interface is **constant-size metadata**,
>   - all heavy state is kept in local windows of size \( O(b) \) at the leaves.

In hc-STARK:

- An “interface” is a small summary of:
  - Which part of the trace we’re in (block indices),
  - The minimal necessary state to glue adjacent blocks (boundary states),
  - The bookkeeping needed to navigate the tree.

By carefully choosing:

- Midpoint splits (balanced intervals),
- A potential-based pebbling strategy, and
- A **pointerless DFS traversal** that recomputes indices instead of storing them,

we ensure that the **per-level descriptor is \(O(1)\)** (constant number of machine words), and only \(O(\log B)\) levels are active.

### 3.4 Replay Engine: Recompute Instead of Store

The **replay engine** is the key systems mechanism:

- Instead of storing all intermediate polynomial data, it:
  - Keeps **small checkpoints**,
  - Replays blocks from those checkpoints when needed.

For the STARK setting:

- A “block replay” means:
  - Re-deriving local constraint evaluations for the block,
  - Re-computing its contribution to Merkle leaves / FRI oracles,
  - Possibly re-running the underlying VM for those steps (if not pre-recorded as a trace).

The replay engine is designed so that:

- The live working set during replay is \( O(b) \).
- Checkpoints / interfaces are constant-size.
- Blocks can be replayed many times if needed, but:
  - they **fit in cache**,
  - recomputation trades CPU/GPU cycles for RAM.

### 3.5 Complexity Guarantees

Let:

- \( T \) = total number of steps / trace rows.
- \( b \) = block size (rows per block).
- \( B = \lceil T/b \rceil \) = number of blocks.

**Space (RAM / VRAM)**

The height-compressed DFS + replay engine leads to a working memory bound:

\[
S(b) = O\big(b\big) + O\big(B\big) = O\big(b + T/b\big)
\]

- \( O(b) \): memory needed for a single block’s local polynomials / trace slice.
- \( O(B) \): constant-size tokens for each interval/merge in the computation tree, managed in a streaming fashion.

Optimizing over \( b \) gives:

- Choose \( b \approx \sqrt{T} \).
- Then:

\[
S(b) = O\left( \sqrt{T} \right)
\]

In **practical terms**, this means:

- For a trace of length \( T \), memory usage grows like \( \sqrt{T} \), not \( T \).
- This drastically reduces the RAM/VRAM requirement for very long traces.

**Time**

We incur extra time by:

- Replaying blocks multiple times,
- Re-running FFTs or field operations on blocked tiles.

Roughly:

- If a “monolithic” STARK prover runs in time \( \tilde{O}(T) \) with space \( \Theta(T) \),
- hc-STARK will run in time:

\[
\tilde{O}\big(T \cdot \sqrt{T} \big)
\]

in the worst case, depending on how aggressively we reuse/replay blocks.

However:

- Many operations (e.g., per-block FFTs) are cache-resident and can run extremely fast.
- The **constant factors** are favorable because the working set is small and local.
- For the very long traces where memory is the limiting factor, paying more cycles is acceptable and often necessary.

The important takeaway:

> hc-STARK converts a **hard memory bottleneck** into a **soft time overhead**, which can be mitigated with more cores / GPUs.

### 3.6 Auto-tuned block sizing in practice

All of the mathematics above feed directly into the shipping CLI. The `hc_prover::block_tuner` module implements the \( b \approx \sqrt{T} \) heuristic, clamps it using measured cache / RAM / VRAM budgets, and biases the pick based on historical replay factors. Operators opt in per command or via presets:

```bash
# Laptop with 32 GB RAM: fit in cache, let the tuner record replay counts
hc-cli prove \
  --auto-block \
  --hardware-detect \
  --trace-length 1_048_576 \
  --target-rss-mb 256 \
  --output proof.json

# Lab GPU node (24 GB VRAM) running the experimental KZG oracle
hc-cli prove \
  --auto-block \
  --hardware-detect \
  --preset gpu_lab \
  --commitment kzg
```

Presets live in `.hc-cli.toml` and act as organizational policy files:

```toml
[presets.gpu_lab]
auto_block = true
trace_length = 16777216
target_rss_mb = 4096       # treat as VRAM budget
profile = "latency"
hardware_detect = true
commitment = "kzg"
tuner_cache = "/var/tmp/hc-stark/tuner_history.json"
```

The CLI announces the resolved profile, block size, and commitment scheme so operators can correlate observed √T telemetry with the exact assumptions that produced it. GPU-specific tiers simply set `target_rss_mb` (or the `HC_GPU_MEM_MB` env var) to the desired VRAM budget; the same √T math carries over because the prover already streams blocks through bounded buffers.

---

## 4. Preserving the Cryptographic Layer (Merkle + FRI)

The top-level principle is:

> We change **how we compute** the committed polynomials and their oracles, but we do **not** change:
>
> - The underlying hash primitives.
> - The FRI soundness guarantees.
> - The algebraic relations defining the AIR.

### 4.1 Execution Trace and AIR

We assume a standard STARK setup:

- A low-degree extension (LDE) of the execution trace table,
- An Algebraic Intermediate Representation (AIR) or equivalent constraint system,
- A FRI-based protocol to prove low-degree-ness.

hc-STARK modifies **how** we realize this in the prover:

- Instead of generating the entire extended trace and then building Merkle trees/FRI layers over it in one shot,
- We:
  - Generate / reconstruct the trace in **blocks**,
  - Evaluate constraints on those blocks,
  - Feed them into the Merkle/FRI oracles via a streaming interface.

### 4.2 Streaming Merkle Commitments

Merkle trees are traditionally built by:

- Laying out all leaves (e.g., evaluations) in memory,
- Hashing them pairwise up the tree.

In hc-STARK:

- Leaves (or leaf chunks) are produced **block by block**.
- We build the Merkle tree in a **streaming** manner:
  - Hash leaf blocks into internal nodes,
  - Store partial internal nodes as small checkpoints,
  - Discard raw leaf buffers after their contribution is folded in.

This is exactly where height compression logic helps:

- The Merkle tree is a computation tree over hash evaluations.
- Its evaluation is a classic height-compressible process:
  - Balanced,
  - Binary fan-in,
  - Deterministic.
- We apply the same pointerless DFS + replay discipline to keep the Merkle working set small.

> **Implementation note (Nov 2025):**  
> The streaming builder now accepts arbitrary fan-outs (matching the height-compressed layout for each trace). Path reconstruction mirrors the same fan-out and records every sibling deterministically, which lets us replay authentication paths straight from trace hashes without ever materializing interior nodes. `hc-bench` provides a `merkle_paths` scenario that measures replay latency vs an in-memory tree so we can monitor the √T invariants empirically.

### 4.3 Streaming FRI

The FRI protocol builds a sequence of oracles (layers) representing successive degree reductions.

Traditionally:

- The prover stores each full layer in memory for:
  - Random access,
  - Query answering.

In hc-STARK:

- Each FRI layer is **never fully materialized** as a big buffer.
- Instead, we:
  - Represent the layer as a function that can be evaluated on demand via replay,
  - Build and commit to it in tiles,
  - Answer queries by reconstructing only the necessary evaluation points and path hashes.

Again, FRI layers organize naturally as a computation graph:

- Each point on a layer is a small algebraic combination of a few points from the previous layer.
- This graph is height-compressible:
  - We can traverse it with pointerless DFS,
  - Cache only a small frontier,
  - Replay previous layers when necessary for queries.

Likewise, the low-degree extension (LDE) + composition step is executed via batched column evaluators: Rayon-backed kernels evaluate multiple coefficient columns over the same domain in parallel while keeping only √T-sized slices in memory. These batches feed both the trace commitment and FRI layer builders, so “compute more / store less” is enforced uniformly across the pipeline.

### 4.4 Soundness and Transparency

Because we:

- Use the same hash functions / Merkle constructions,
- Use the same or equivalent FRI scheme,
- Preserve the AIR / trace semantics,

the **cryptographic properties** remain:

- **Transparent**: no trusted setup.
- **Hash-based**: plausibly quantum-resistant (post-quantum).
- **Same soundness error** as conventional STARKs, up to small parameter tweaks (e.g., number of queries, domain sizes).

The change is strictly in the **implementation of the prover**, not in the protocol specification from the verifier’s perspective.

---

## 5. Comparison with Conventional STARK and SNARK Stacks

### 5.1 Complexity Summary

Let \( T \) be the trace length (number of steps).

| System              | Prover Space (vs \(T\))       | Prover Time (rough)           | Transparency | Quantum-safe?       |
|---------------------|-------------------------------|-------------------------------|-------------|---------------------|
| Conventional STARK  | \( \Theta(T) \)               | \( \tilde{O}(T) \)            | Yes         | Yes (hash-based)    |
| Conventional SNARK  | \( \Theta(T) \)               | \( \tilde{O}(T) \) or higher  | Often No    | Often No (pairings) |
| hc-STARK (this repo)| \( O(\sqrt{T}) \)             | \( \tilde{O}(T \cdot \sqrt{T}) \) (worst case) | Yes         | Yes (hash-based)    |

Notes:

- The SNARK line is a simplification; there are many variants, some with better asymptotics in different regimes but usually with:
  - Trusted setup, and/or
  - Non–post-quantum assumptions (pairings, elliptic curves).

- hc-STARK:
  - Trades extra time (replay) for drastically less memory,
  - Keeps the same cryptographic flavor as STARKs,
  - Is particularly attractive in **very-long-trace, high-soundness** regimes, where memory is the first thing to break.

### 5.2 Practical Regimes

- **Short traces (small \(T\))**:
  - Conventional STARKs are fine; hc-STARK may be overkill.
  - Replay overhead might dominate without giving memory benefits.

- **Medium traces**:
  - Both can work; hc-STARK is attractive where machine RAM is “just barely enough” or where you want to run multiple provers concurrently.

- **Very long traces (large \(T\))**:
  - Conventional STARKs often become impractical (need huge RAM/VRAM).
  - hc-STARK shines: you can push \(T\) arbitrarily high (modulo time) on a fixed-memory box.

- **GPU-accelerated scenarios**:
  - Conventional designs run into VRAM limits quickly.
  - hc-STARK’s blocked FFTs and tiled polynomials are **designed to sit in VRAM** and replay as needed.

---

## 6. Use Cases & System-Level Impact

### 6.1 zkVMs / zkEVMs

- Long-running programs, many syscalls, complex state machines.
- Today: often forced into:
  - Special-purpose circuits,
  - Aggressive batching/pipelining,
  - Manual trace splitting.

hc-STARK allows:

- A unified zkVM design,
- Arbitrarily long execution without changing the AIR,
- “Just keep running” semantics: trace length can grow without a RAM cliff.

### 6.2 zkML and Data-Intensive Workloads

- Proving large neural network inference,
- Streaming computations over large datasets.

hc-STARK enables:

- Layer-by-layer, block-by-block proofs,
- Memory usage proportional to the **largest layer/block**, not the entire dataset or training trace.

### 6.3 Rollups and Verifiable Compute

- Rollup sequencers and provers often want to batch many transactions.
- Conventional provers face a hard limit: “How many tx can we batch before we run out of RAM?”

With hc-STARK:

- The batch size is constrained primarily by **time** and **bandwidth**, not memory.
- You can run large batches (or even a continuously running prover) on stable, moderate-sized hardware.

---

## 7. Mapping to the `hc-stark` Codebase

The current repository layout mirrors the architecture described above:

- `hc-core/`
  - Field/FMT primitives, FFT implementations, and the new `fft_auto` helper that can dispatch to the `gpu-fft` feature flag.
  - Shared error handling and random utilities.
- `hc-commit/`
  - Vector commitments, standard + streaming (height-compressed) Merkle trees.
- `hc-hash/`
  - Blake3/SHA256 digests, transcripts, and Fiat–Shamir helpers.
- `hc-fri/`
  - Streaming FRI prover/verifier built on `TraceReplay`, exposing per-layer streaming stats.
- `hc-replay/`
  - Generic block producers plus the deterministic `TraceReplay` engine used by Merkle, FRI, and any block-sized consumer.
- `hc-prover/`
  - The pointerless DFS scheduler, replay integration, metrics collection, and proof orchestration.
- `hc-verifier/`
  - A conventional STARK verifier consuming the serialized proof artifacts, plus a `verify_with_summary` API that emits `QueryCommitments` so recursion layers can re-hash what was verified without replaying the whole transcript.
- Supporting crates (`hc-cli/`, `hc-bench/`, `hc-examples/`)
  - CLI drive commands (prove/verify/bench/inspect) and JSON proof serialization.
  - Benchmark harness that reports √T metrics (`avg_trace_blocks`, `avg_fri_blocks`) via the CLI and Rust APIs.
- `hc-recursion/`
  - Aggregation helpers that reuse the verifier summary, hash child proofs into a deterministic commitment, and (soon) feed those summaries into recursive circuits.

Together, these crates implement a **reference-quality height-compressed prover** whose RAM usage is dictated by the configured block size while surfacing enough observability (metrics + CLI tooling) to tune √T behavior on real workloads.

### 7.0 Protocol Transcript (v2) and Compatibility

In production, we treat the Fiat–Shamir transcript as a **versioned wire contract**:

- **Main transcript domain**: `hc-stark/v2`
- **FRI transcript domain**: `hc-stark/fri/v2`
- **Canonical labels**: structured, domain-separated labels under:
  - `pub/*` (public inputs)
  - `param/*` (protocol parameters)
  - `commit/*` (Merkle roots / commitments)
  - `chal/*` (Fiat–Shamir challenges)

The canonical registry lives in `hc_hash::protocol`:

- Domains: `DOMAIN_MAIN_V2`, `DOMAIN_FRI_V2`, `DOMAIN_COMPOSITION_V2`
- Labels: `hc_hash::protocol::label::*`

This ensures prover/verifier (and recursion) cannot silently diverge due to ad hoc strings or
accidental reordering.

### 7.1 Recursion Planner & Query Summaries

- `hc-verifier` now exposes `VerificationSummary` containing:
  - Fiat–Shamir seeds,
  - Commitment roots,
  - Deterministic `QueryCommitments` that hash the ordered trace/FRI query payloads.
- `hc-recursion::spec::plan_for` derives balanced aggregation schedules (`BatchPlan`, `RecursionSchedule`) so recursive wrappers can deterministically decide which summaries combine at each height.
- `hc-recursion::circuit` encodes those summaries as field elements and re-hashes `QueryCommitments` to guard against omission or re-ordering.
- A concrete Halo2/KZG circuit now enforces a `circuit_digest` constraint for every summary: it replays the `SummaryEncoding` words with Plonk-style accumulators and exposes the resulting digest as the circuit’s public input. The `hc-cli recursion` command produces a real Halo2 proof alongside the aggregated digest, so the recursion story is no longer a mock/verifier stub.

### 7.2 zkML Dense-Layer Reference Trace

- `hc-examples::zkml::dense_layer` constructs a fully streaming replay (`TraceReplay`) for dense layers.
- `run_dense_layer_example` drives a prove/verify cycle end-to-end, demonstrating how zkML traces hook into the general hc-STARK pipeline without bespoke glue code.
- Benchmark scenarios (`hc-cli bench --scenario prover`) default to this dense-layer workload, making it easy to track √T behavior on a realistic trace.

### 7.3 CI Workflow & Regression Artifacts

- `.github/workflows/ci.yml` runs the sanity/stress/ladder suites and uploads JSON/CSV artifacts under `benchmarks/`.
- `benchmarks/baseline.json` captures the current √T envelope (trace/fri blocks and duration) while `scripts/check_bench_thresholds.py` compares fresh runs against those baselines with configurable percentage tolerances.
- CI fails if `avg_trace_blocks`, `avg_fri_blocks`, `avg_duration_ms`, or the ladder sweep regress by more than the documented thresholds, ensuring √T guarantees stay intact as the code evolves.

---

## 8. Future Directions

Some directions that naturally follow from hc-STARK:

1. **Integration with production zkVMs**
   - Plug into an existing VM (e.g., RISC-V–based).
   - Use real-world benchmarks: rollup workloads, circuits, zkML.

2. **Multi-GPU / distributed replay**
   - Split block replays across GPUs / nodes.
   - Preserve height compression while adding parallelism.

3. **Adaptive block sizing**
   - Today’s CLI already implements the √T heuristic, hardware detection, presets, and persistent replay feedback (see §3.6), so most operators never hand-pick `b`. The next frontier is refining those models for multi-GPU rigs, mixing RSS + VRAM budgets, and folding the tuner history into CI dashboards so regressions in block choices are caught automatically.

4. **Generalized height compression**
   - Apply the same techniques to:
     - SNARKs (KZG/IPA commitments),
     - Polynomial IOP-based systems,
     - Non-zk verifiable computation.
   - The repo now ships a concrete harness (`hc-height` + `hc-cli bench --scenario height --leaves 65536 --block-size 128`) that compares streaming vs. full-buffer Merkle/KZG commitments, so we can validate √T behavior on non-STARK oracles before wiring them into the prover.
   - `hc-cli prove --commitment kzg --auto-block --hardware-detect` exercises an end-to-end streaming KZG path (the verifier currently performs a mock digest check while we finalize the MSM/IP circuit). This keeps the door open for swapping oracle families without touching the replay core.

As the implementation matures, this whitepaper will evolve to reflect the exact concrete protocol and measured performance characteristics of hc-STARK in practice.

---
