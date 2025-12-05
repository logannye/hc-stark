# block_sizing_and_parameters.md

_Last updated: 2025-12-04_

---

## 1. Goals of Block Sizing

The block size \( b \) (rows per block) is a central tuning parameter in hc-STARK. It directly influences:

- **Peak memory usage**,
- **Replay overhead / wall-clock time**,
- **Cache locality** on CPU / GPU,
- **Parallelization opportunities** (e.g., multi-thread, multi-GPU).

We treat \( b \) as a function of:

- \(T\): total trace length,
- Hardware characteristics (L2/L3 size, VRAM, memory bandwidth),
- Cryptographic/security parameters (field size, FRI blowup, number of queries).

The objective is to choose \( b \) such that:

1. **Working memory** \( S(b) \) is within a target budget \( S_{\text{target}} \),
2. **Replay overhead** is acceptable for the desired throughput.

---

## 2. Asymptotic Model

Ignoring constant factors, the hc-STARK prover’s working memory can be modeled as:

\[
S(b) \approx c_1 \cdot b + c_2 \cdot T / b + S_0,
\]

where:

- \(c_1\): per-block memory cost,
- \(c_2\): per-block “interface” cost (metadata / partial summaries),
- \(S_0\): fixed overhead (code, small buffers, system stacks).

This comes from:

- \(O(b)\) memory for the active block (trace slice + polynomials),
- \(O(T/b)\) blocks worth of small metadata and/or streaming structures.

The function \( f(b) = c_1 b + c_2 T / b \) is minimized at:

\[
b^\star = \sqrt{ \frac{c_2}{c_1} T }.
\]

In the idealized case \(c_1 \approx c_2\), we get:

- \( b^\star \approx \sqrt{T} \),
- \( S(b^\star) \sim 2\sqrt{c_1 c_2 T} = O(\sqrt{T}) \).

In practice, we use this asymptotic optimum as a starting point, then adjust based on hardware and security constraints.

---

## 3. Hardware-Constrained Block Sizing

### 3.1 Targeting a Memory Tier

Let:

- \( S_{\text{tier}} \) be the memory budget of the **fastest tier** we want the active block to live in:
  - Typical choices:
    - L2 cache (e.g., 1–4 MB),
    - L3 cache (e.g., 16–64 MB),
    - GPU VRAM per SM or global VRAM per process.

We want:

\[
\text{BLOCK_MEMORY}(b) \le S_{\text{tier}}.
\]

We approximate:

\[
\text{BLOCK_MEMORY}(b) \approx a_1 \cdot b + a_0,
\]

where:

- \(a_1\): per-row memory (trace columns + poly columns + scratch),
- \(a_0\): block-level overhead (e.g., precomputed constants).

Solving for \(b\):

\[
a_1 b + a_0 \le S_{\text{tier}} \quad \Rightarrow \quad
b \le \frac{S_{\text{tier}} - a_0}{a_1}.
\]

We denote this upper bound as \(b_{\max}^{\text{tier}}\).

### 3.2 Combining Asymptotic and Hardware Constraints

We have two main constraints:

1. Asymptotic ideal:  
   \( b^\star \approx \sqrt{T} \),
2. Hardware upper bound:  
   \( b \le b_{\max}^{\text{tier}} \).

We choose:

\[
b = \min\{ b^\star, b_{\max}^{\text{tier}} \},
\]

optionally snapped to a convenient value (e.g., power of two, multiple of SIMD width, GPU block size).

In pseudocode:

```text
b_star         = floor(sqrt(T))
b_max_tier     = floor((S_tier - a0) / a1)
b_candidate    = min(b_star, b_max_tier)

b = round_to_nice_value(b_candidate)
````

If `b_max_tier < 1` due to severe memory constraints, we fail fast and signal that the current hardware cannot support the workload.

---

## 4. Security-Related Considerations

### 4.1 FRI Parameters and Domain Sizes

Security parameters (soundness error, failure probability) influence:

* The size of the evaluation domain (N),
* Degree blowup factors,
* The number of FRI layers and queries.

Roughly:

* (N \approx \lambda \cdot T) for some over-sampling factor (\lambda \ge 1),
* FRI depth (\approx \log_\rho(N)) for folding ratio (\rho),
* Number of queries (q) controls soundness.

These parameters affect:

* The constant factor in per-block polynomial work,
* The number of times we may need to replay certain parts of the trace to answer queries.

However, they do **not fundamentally change** the (O(b + T/b)) memory shape. Instead, they scale the constants (c_1, c_2).

### 4.2 Query Patterns and Replay Hotspots

If the verifier’s queries concentrate on particular time indices (e.g., hotspots in the trace), we may see:

* Specific blocks replayed more often than others,
* Increased sensitivity of performance to block size.

Mitigation strategies:

1. **Randomization at the prover**:

   * Schedule block processing and caching strategies that anticipate common query patterns.
2. **Adaptive block sizing**:

   * Slightly vary (b) across regions of the trace (advanced).

These are advanced optimizations and are not required for correctness.

---

## 5. Trade-offs: Replay Overhead vs Memory

### 5.1 Small Blocks (Small (b))

Pros:

* Lower peak `BLOCK_MEMORY`.
* Easier to fit entirely in cache / VRAM.
* Finer-grained parallelism across cores / GPUs.

Cons:

* More blocks (B = T / b),
* Longer tree height (\log B),
* More replay events:

  * More block replays for Merkle construction,
  * More FRI oracle replays.

Net effect:

* Lower memory, higher CPU/GPU cycles.

### 5.2 Large Blocks (Large (b))

Pros:

* Fewer blocks (B),
* Shorter tree height,
* Fewer replays:

  * Each replay spans more computation, but there are fewer of them.

Cons:

* Larger `BLOCK_MEMORY`:

  * Risk spilling out of L2/L3/VRAM,
  * Potential cache thrash.
* Less flexibility in scheduling parallel work.

Net effect:

* Lower replay overhead, but higher memory pressure.

### 5.3 Practical Guidelines

1. **Start from hardware**:

   * Measure `S_tier` for your target cache/VRAM,
   * Compute `b_max_tier`,
   * Ensure `BLOCK_MEMORY(b_max_tier)` is well below `S_tier` (e.g., ~60–70% usage).

2. **Compare with (\sqrt{T})**:

   * If (b^\star \le b_{\max}^{\text{tier}}), use (b \approx b^\star),
   * Else, clamp to `b_max_tier`.

3. **Benchmark and refine**:

   * Run micro-benchmarks for a few candidate `b` values,
   * Profile replay count, cache misses, wall-clock time.

In `hc-stark`, we expose:

* A configuration parameter `ProverConfig::block_size`,
* A helper routine that can auto-suggest an initial `b` based on:

  * `T`,
  * measured memory,
  * CPU/GPU capabilities.

---

## 6. Summary

Block sizing is about balancing:

* Theoretical optimum ((b \approx \sqrt{T})),
* Hardware constraints (cache/VRAM),
* Security-induced constants (FRI parameters),
* Replay overhead.

By treating (b) as a first-class tuning parameter and respecting the shape (S(b) = O(b + T/b)), hc-STARK can:

* Stay within predictable memory bounds,
* Exploit cache and VRAM locality,
* Trade memory pressure for controlled replay overhead.

---

## 6. Measuring Block Choices in Practice

All of the math above is only useful after you validate it on real hardware. The repo now ships with:

- `hc-cli bench` – a convenience wrapper around the prover that reports the average wall-clock time plus the number of streamed trace/FRI blocks for a particular block size.
- `hc_bench::benchmark` – a Rust API you can embed in your own harnesses to sweep configurations or persist results alongside other telemetry.

Example:

```bash
cargo run -p hc-cli -- bench \
  --iterations 5 \
  --block-size 64
```

This emits JSON such as:

```json
{
  "iterations": 5,
  "block_size": 64,
  "total_duration_ms": 57.6,
  "avg_duration_ms": 11.52,
  "avg_trace_blocks": 192.0,
  "avg_fri_blocks": 64.0
}
```

`avg_trace_blocks` and `avg_fri_blocks` come directly from the prover’s streaming metrics (`ProverMetrics`) and therefore provide a concrete measurement of how close you are to the √T sweet spot. Increase `--block-size` to trade time for memory; decrease it to stay within tighter cache/VRAM budgets. The same instrumentation works on CPUs today and will extend to the GPU backend once the FFT hooks are wired up. 

> **GPU preview:** enabling the `gpu-fft` feature flag on `hc-core` switches `fft_auto` over to the placeholder `GpuBackend`. For now the GPU backend proxies to the CPU FFT while kernel work continues, but the configuration plumbing (feature flag + runtime “prefer GPU” switch) is ready so that experiments can begin without touching the prover logic.

---

## 7. CLI Integration: `--auto-block` and `--auto-block-size`

Starting in December 2025 the CLI understands the heuristics from this document:

- `hc-cli prove --auto-block --trace-length 1048576 --target-rss-mb 256`  
  feeds the hint (estimated trace length + RSS budget) into `hc_prover::block_tuner::recommend_block_size` and uses the suggestion when constructing `ProverConfig`.
- `hc-cli bench --scenario prover --auto-block-size --trace-length 1048576 --target-rss-mb 256`  
  applies the same logic before running the prover benchmark so you can sweep workloads without hand-picking block sizes per machine.

Both commands still accept explicit `--block-size` overrides; the auto flags only kick in when you opt-in. The tuner defaults to `trace_length = 1<<20`, `target_rss_mb = 512`, `min_block = 32`, and `max_block = 1<<15`, which matches the qualitative guidance earlier in this note.

---

## 8. Persistent Tuning Feedback (`tuner_history.json`)

Real workloads fluctuate, so we now persist the results of every prover run:

- Successful `hc-cli prove` executions append the final block size plus the measured replay counts (`ProverMetrics::trace_blocks_loaded`) into `~/.hc-stark/tuner_history.json` (or a custom path via `--tuner-cache path/to/file.json`).
- The history is keyed by `(auto profile, trace-length bucket)` and maintains a moving average of the best-known block size and observed replay factor. 
- `recommend_block_size_with_feedback` consumes that history before each new run, biasing the next guess toward proven-good configurations and nudging the block upward/downward when replay ratios have drifted.

Operational tips:

```bash
# Use the default cache (created automatically under ~/.hc-stark/)
hc-cli prove --auto-block --trace-length 16777216

# Point the cache somewhere else (e.g., shared CI workspace)
hc-cli prove --auto-block --tuner-cache /var/tmp/hc-stark/tuner_history.json

# Temporarily disable history reads/writes
hc-cli prove --auto-block --no-tuner-cache
```

The cache file is just prettified JSON, so you can inspect or graph it with your favorite tools:

```bash
cat ~/.hc-stark/tuner_history.json | jq '.entries | keys[]'
rm ~/.hc-stark/tuner_history.json  # reset if a machine’s profile changes drastically
```

`hc-cli bench --scenario prover --auto-block-size` respects the same flags, allowing CI to replay the exact heuristics used in production without mutating the cache (bench runs read from the cache but do not write new samples).

Named presets (`--preset laptop`, `--preset server`, etc.) and user-defined entries inside `.hc-cli.toml` simply populate those knobs before the run starts. CLI flags still win if you pass conflicting values, and every command prints the resolved block size/profile so it’s easy to see which preset (if any) was applied.

---

## 9. Presets, hardware detection & GPU tiers

### 9.1 `.hc-cli.toml` as a √T policy file

The `.hc-cli.toml` format mirrors the knobs described throughout this note. Each `[presets.<name>]` table can provide:

- `auto_block` / `auto_block_size`: opt-in to the √T heuristic plus hardware clamps.
- `trace_length`: a prior for \(T\) when the CLI can’t derive it from inputs.
- `target_rss_mb`: the working-set budget (RAM or VRAM) that stands in for \(S_{\text{tier}}\).
- `hardware_detect`: whether to let the CLI sample caches / memory before clamping \(b\).
- `profile`: one of `balanced`, `memory`, `latency`, `laptop`, or `server`, which tweaks the replay vs. memory trade-off.
- `commitment`: `stark` or `kzg`, ensuring presets can also select the oracle strategy.

Because presets are merged before CLI flags, you can capture per-lab defaults (e.g., “GPU rig with 24 GB VRAM, prefer KZG commitments”) while still overriding specifics per run.

### 9.2 Hardware detection heuristics

`detect_hardware_profile()` reads `/proc/cpuinfo` (or the macOS equivalents) to collect:

- total system RAM,
- the largest reported L3 cache,
- CPU core count (which feeds Rayon defaults),
- optional GPU metadata from `HC_GPU_MEM_MB` (set it in your shell or CI if you want VRAM-aware tuning without poking driver APIs).

The tuner converts those measurements back into the analytical bounds from §3:

\[
b^\star = \lfloor\sqrt{T}\rfloor,\qquad
b_{\max}^{\text{tier}} = \left\lfloor\frac{S_{\text{tier}} - a_0}{a_1}\right\rfloor
\]

with `S_tier` coming from `target_rss_mb` (if provided) or the hardware profile (RAM/VRAM budgets and cache sizes). L3 governs the maximum “hot” block size; RAM/VRAM governs the replay cache and composition buffers. The implementation keeps a 30–40 % safety margin so the live block fits in cache even when other processes are running. On GPU nodes you simply export `HC_GPU_MEM_MB` or set `target_rss_mb` to the per-device VRAM you can spare; the heuristic treats that number as the working-tier budget and keeps `b` within that envelope.

### 9.3 Example workflows

```bash
# Reuse a laptop preset, but override the target RSS for a smaller machine
hc-cli prove \
  --preset laptop \
  --auto-block \
  --target-rss-mb 192 \
  --hardware-detect

# Pin a GPU-friendly preset defined in ~/.hc-cli.toml
hc-cli prove \
  --preset gpu_lab \
  --auto-block \
  --hardware-detect \
  --commitment kzg

# Run a bench sweep with CI-safe defaults and a shared tuner cache
hc-cli bench \
  --scenario prover \
  --preset server \
  --auto-block-size \
  --tuner-cache /var/tmp/hc/tuner_history.json
```

These commands exercise the exact pipeline modeled in this document: the CLI estimates \(b \approx \sqrt{T}\), clamps it using L3/VRAM data, biases the choice using recorded replay factors, and surfaces the final numbers so you can tie observed √T metrics back to the hardware assumptions that produced them.