# fri_streaming_design.md

_Last updated: YYYY-MM-DD_

---

## 1. Goals of the FRI Streaming Design

The FRI layer in **hc-STARK** is designed to satisfy:

1. **Streaming construction** of all FRI layers:
   - Never materialize full evaluation vectors in RAM.
   - Build Merkle commitments for each layer in a single pass.

2. **Block-based oracles**:
   - Align FRI evaluations with the same block/tiling structure used for the execution trace.
   - Allow the replay engine to regenerate only the needed blocks for queries.

3. **Bounded memory**:
   - Keep per-layer working set within `O(b + log N)` where:
     - `b` is the evaluation block size (aligned with trace block size when convenient),
     - `N` is the evaluation-domain size.

4. **Protocol compatibility**:
   - The transcript (Merkle roots, query answers) is indistinguishable from a conventional STARK using the same AIR/FRI parameters.
   - No changes required on the verifier side.

---

## 2. Brief FRI Recap

Given a polynomial \( f(X) \) over a finite field and an evaluation domain \(\mathcal{D}_0\) of size \(N_0\), FRI constructs a sequence of layers:

- \(L_0(x) = f(x)\) for \(x \in \mathcal{D}_0\),
- Repeatedly apply a **folding operation** to obtain:
  \[
    L_{\ell+1}(x') = \text{fold}_\ell(L_\ell, r_\ell, x')
  \]
  over domains \(\mathcal{D}_1, \mathcal{D}_2, \dots\),
- Each layer is committed via a Merkle tree,
- Verifier queries a small number of positions across layers to check low-degree-ness.

In a conventional implementation, each \(L_\ell\) is stored in full in memory. hc-STARK replaces this with a block-based streaming design.

---

## 3. Block-Based FRI Oracles

### 3.1 Domain Partitioning

Let:

- \(N_0 = |\mathcal{D}_0|\) be the size of the base evaluation domain.
- Choose a **FRI evaluation block size** \(b_{\text{eval}}\) (often set equal or proportional to the trace block size \(b\)).
- Define:
  \[
    B_0 = \left\lceil \frac{N_0}{b_{\text{eval}}} \right\rceil
  \]
  blocks for layer 0:
  \[
    \mathcal{D}_0^{(k)} = \{ x \in \mathcal{D}_0 \mid \text{index}(x) \in [(k-1)b_{\text{eval}} + 1, \dots, \min\{kb_{\text{eval}}, N_0\}] \}.
  \]

Similarly, for each FRI layer \(\ell\) with domain size \(N_\ell\), we define:

- Blocks \(\mathcal{D}_\ell^{(k)}\) of size \(b_\ell \le b_{\text{eval}}\),
- Number of blocks:
  \[
    B_\ell = \left\lceil \frac{N_\ell}{b_\ell} \right\rceil.
  \]

These blocks are the units of streaming evaluation and commitment.

### 3.2 Relating Trace Blocks to FRI Blocks

There are multiple compatible designs:

1. **Aligned blocks**:
   - Set \(b_{\text{eval}} = b\),
   - Use a domain layout where trace rows and FRI indices have a simple mapping (e.g., interleaving via fixed permutations).
   - Replay of a trace block directly yields the corresponding segment of FRI evaluations.

2. **Derived blocks**:
   - Keep an independent \(b_{\text{eval}}\),
   - Allow a many-to-one mapping from trace blocks to FRI blocks.
   - Replay engine composes outputs from multiple trace blocks into one FRI block when needed.

hc-STARK’s abstractions allow either design; the core requirement is that for each FRI block, the replay engine can deterministically reconstruct its evaluations using bounded memory.

---

## 4. Streaming Construction of FRI Layers

### 4.1 Single-Pass, Pipelined Construction

We conceptualize FRI layer construction as a pipeline:

- **Input**: Stream of base-layer evaluations \(L_0(x)\) in block order.
- **Output**: For each layer \(\ell\), a Merkle root committing to \(L_\ell\).

Pseudocode outline for building all layers in one pass:

```text
for each block k in 1..B0:
    // 1. Generate base-layer evaluations
    evals_0_block = generate_L0_block(k)        // size ~ b_eval

    // 2. Feed into Merkle builder for layer 0
    merkle_0.absorb_leaves(evals_0_block)

    // 3. Fold up through FRI pipeline
    current_block_evals = evals_0_block
    for ell in 0..(L-1): // L = num_layers-1
        folded_block = fri_fold_block(ell, current_block_evals, r_ell)
        merkle_(ell+1).absorb_leaves(folded_block)
        current_block_evals = folded_block

// 4. Finalize roots
for ell in 0..L:
    root_ell = merkle_ell.finalize()
````

Key properties:

* At each step, we only keep:

  * A single block’s worth of evaluations per layer in RAM,
  * Merkle frontier state per layer (O(log N_\ell) hashes),
  * FRI randomness (r_\ell).

* No full layer is ever materialized.

### 4.2 Folding in Blocks

The FRI folding operation typically maps pairs of evaluations to one:

* For example, if (\mathcal{D}*\ell) pairs ((x_0, x_1)) for each (x'\in\mathcal{D}*{\ell+1}), then:
  [
  L_{\ell+1}(x') = L_\ell(x_0) + \beta_\ell x' \cdot L_\ell(x_1),
  ]
  for some random (\beta_\ell).

In block form:

* For each block of (L_\ell) evaluations, we:

  * Partition it into pairs ((v_{2i}, v_{2i+1})),
  * Apply the folding rule per pair to compute a block of (L_{\ell+1}) evaluations.

Edge cases (odd domain sizes, padding) are handled locally within each block.

This ensures:

* We can compute (L_{\ell+1}) in streaming fashion,
* Only ever needing:

  * `O(b_\ell)` at layer (\ell),
  * `O(b_{\ell+1})` at layer (\ell+1).

---

## 5. Streaming Query Answering

After committing to all FRI layers, the verifier will (interactively or via Fiat–Shamir):

* Sample a set of query indices ({q_i}) at base layer (L_0),
* Induce a set of indices at each subsequent layer.

The prover must provide:

* For each query and each layer:

  * The evaluation at the specified index,
  * The corresponding Merkle authentication path.

### 5.1 Two Main Strategies

There are two compatible strategies:

1. **Path caching during commitment**:

   * During the initial streaming Merkle construction, if queries are known (e.g., in an interactive setting), we can:

     * Track the nodes needed for each path,
     * Store all paths in `O(q log N)` memory,
     * Answer queries without replay.
   * This is optimal for repeated queries but requires early knowledge of indices.

2. **Replay-based answering (hc-STARK style)**:

   * Commit phase and query phase are separated.
   * In the query phase:

     * Use the replay engine to regenerate only the relevant blocks for each query.
     * Rebuild only the Merkle subtrees needed to produce authentication paths.

hc-STARK is optimized for the second approach, leveraging its replay capabilities and height-compressed tree to keep memory bounded.

### 5.2 Replay-Based Query Answering

For each query index at layer 0:

1. Determine the **block index** (k) and **in-block offset**.

2. Use the replay engine to regenerate the FRI block (\mathcal{D}_0^{(k)}):

   * This may be via:

     * Trace replay,
     * Intermediate polynomial evaluation,
     * Or cached intermediate states.

3. Recompute the leaf hash for the index and reconstruct the authentication path by:

   * Streaming over the same block again (for trivial paths),
   * Or using the **streaming Merkle builder** in a “path extraction” mode (see `merkle_streaming.md`).

4. Propagate the query index to layer 1:

   * Use FRI folding relations and domain mapping to compute which index at (L_1) is relevant.

5. Repeat steps 1–4 for subsequent layers until reaching the final layer.

To keep memory bounded:

* We process queries in **sorted order by block**,
* For each relevant block, we:

  * Replay it once,
  * Extract all necessary evaluations and paths for all queries in that block,
  * Then discard block data.

---

## 6. Memory and Complexity Guarantees

Let:

* (q): number of FRI queries,
* (L): number of FRI layers,
* (N_\ell): domain size at layer (\ell).

Then, under the replay-based design:

* Memory:

  * Per active block: (O(b_\ell)),
  * Per Merkle frontier: (O(\log N_\ell)) per layer,
  * Additional: (O(q L)) for storing indices and responses.

  Total working set is dominated by `max(b_\ell + log N_\ell)` over all layers.

* Time:

  * Commit phase: one pass per block, per layer ⇒ (O(N_0 \cdot \text{polylog}(N_0))) with constant factors from the number of layers and per-point arithmetic.
  * Query phase: additional replay overhead proportional to:

    * (O(q \cdot L)),
    * With each replay bounded by block size.

This maintains the same asymptotic complexity as a conventional FRI implementation while fitting into the global hc-STARK (O(\sqrt{T}))-space regime.

---

## 7. Summary

The FRI streaming design in hc-STARK:

* Breaks each FRI layer into **blocks** compatible with the trace tiling,
* Constructs all Merkle-committed layers via a **single-pass pipeline**,
* Uses the replay engine to answer queries with **bounded memory**,
* Preserves the **same transcript and security properties** as a standard STARK implementation.

It is a direct instance of treating FRI as a **height-compressible computation** over an evaluation domain.