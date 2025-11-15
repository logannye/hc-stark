# block_sizing_and_parameters.md

_Last updated: YYYY-MM-DD_

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