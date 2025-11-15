# merkle_streaming.md

_Last updated: YYYY-MM-DD_

---

## 1. Goals of Streaming Merkle Construction

The Merkle commitment layer in **hc-STARK** is designed to:

1. Build large Merkle trees (millions to billions of leaves) with:
   - O(1) or O(log N) additional memory beyond a small sliding window of leaves.
2. Support **streaming leaf ingestion**:
   - Leaves arrive in blocks (e.g., from trace/FRI streaming),
   - We never store the whole leaf list in RAM.
3. Enable **replay-friendly path reconstruction**:
   - Paths for verifier queries can be recomputed from replayed leaves and minimal auxiliary state.

This is a natural match for the **height-compressed computation** paradigm: a Merkle tree is itself a canonical example of a height-compressible structure.

---

## 2. Standard Merkle Tree Recap

Given:

- A list of leaves \(\ell_0, \ell_1, \dots, \ell_{N-1}\),
- A hash function \(H\),

We build a binary Merkle tree:

- Level 0: leaf hashes \(h^{(0)}_i = H(\ell_i)\),
- Level 1: \(h^{(1)}_i = H(h^{(0)}_{2i} || h^{(0)}_{2i+1})\),
- ...
- Root: \(h^{(d)}_0\) where \(d = \lceil \log_2 N \rceil\).

Conventional implementations store all \(h^{(0)}_i\) in memory before building higher levels. hc-STARK replaces this with an **online stack-based algorithm**.

---

## 3. Streaming Merkle Builder

### 3.1 Conceptual Overview

We treat leaf hashes as a stream:

- Leaves arrive one by one (or in small batches),
- As each leaf hash is produced, we push it onto a stack,
- Whenever the top two stack elements have the same height, we combine them into a parent hash and push that parent.

Each stack element represents a **subtree root** with:

- Hash value,
- Height (level),
- Position index (optional for bookkeeping).

This algorithm:

- Requires at most one subtree root per height at any time,
- Uses \(O(\log N)\) stack space.

### 3.2 Streaming Algorithm (Single Pass)

Let `Node(height, hash)` represent a node in the stack; the leaf level has `height = 0`.

Pseudocode:

```text
stack = empty

for i in 0..(N-1):
    leaf_hash = H(leaf_i)
    node = Node(height=0, hash=leaf_hash)
    stack.push(node)

    // Combine while there are two nodes with same height on top
    while stack.len >= 2 and stack.top.height == stack.second_to_top.height:
        right = stack.pop()
        left  = stack.pop()
        parent_hash = H(left.hash || right.hash)
        parent_node = Node(height=left.height + 1, hash=parent_hash)
        stack.push(parent_node)

// After consuming all leaves:
while stack.len >= 2:
    right = stack.pop()
    left  = stack.pop()
    parent_hash = H(left.hash || right.hash)
    stack.push(Node(height=left.height + 1, hash=parent_hash))

root = stack.pop().hash
````

Properties:

* The stack length is at most (\log_2 N + 1),
* Space complexity is (O(\log N)),
* The leaf array is never stored in full; only the current leaf or small block is in memory at any moment.

### 3.3 Integration with Block-Based Leaves

In hc-STARK:

* Leaves themselves are **evaluations** or **constraints** produced blockwise:

  * Example: a block of FRI evaluations for a specific layer,
  * Example: a block of AIR constraint evaluations.

The streaming Merkle builder is called as:

```text
for each block k:
    leaf_hashes_block = compute_leaf_hashes_for_block(k)
    for each leaf_hash in leaf_hashes_block:
        streaming_merkle.absorb_leaf(leaf_hash)
```

The internal stack logic is the same; we simply process leaves in blocks to match the trace/FRI tiling.

---

## 4. Streaming Path Reconstruction

To answer Merkle queries (provide authentication paths), we need to reconstruct:

* For a given leaf index `i`,
* The sequence of sibling hashes at each tree level.

There are two hc-STARK-compatible approaches:

### 4.1 On-the-Fly Path Extraction

During replay:

1. Regenerate leaves for the relevant block.
2. Re-run the streaming Merkle builder for **just that block’s portion** of the tree while:

   * Tracking the indices of queried leaves,
   * Capturing any sibling nodes that appear on the path.

For large trees, we often:

* Replay the entire tree in streaming fashion,
* But keep track only of the nodes required for queries.

This can be implemented efficiently by:

* Sorting query indices,
* Carrying a small state machine per query that:

  * Watches the stack combine operations,
  * Records siblings when appropriate.

Memory cost:

* (O(q \log N)) to store paths,
* (O(\log N)) for the builder’s stack.

### 4.2 Hybrid: Partial Path Caching

When queries are known early (e.g., in interactive settings):

* During the original commitment build, we:

  * Check for each leaf whether it belongs to a query index,
  * Store any sibling nodes needed for its path as they are combined.

This avoids replay for that Merkle tree at the cost of:

* Slightly more complexity in the builder,
* Path storage overhead.

hc-STARK’s core abstraction supports both; the default is on-the-fly replay-based extraction, leveraging the replay engine.

---

## 5. Minimal State Storage

The Merkle layer only needs to store:

1. The **root hash** (committed value),
2. Optional:

   * Configuration metadata (hash function ID, tree arity),
   * Integrity tags tying the root to the problem instance.

The full tree is **never** stored:

* All interior nodes can be recomputed via replay,
* The only persistent state per tree is `root` + a small header.

This aligns with the hc-STARK philosophy:

> Trade storage for deterministic recomputation under height-compressed control.

---

## 6. Complexity Summary

Let (N) be the number of leaves.

* **Memory**:

  * Stack size: (O(\log N)),
  * Plus a small block of current leaf values.

* **Time**:

  * Leaf hashing: (O(N)),
  * Internal node hashing: (O(N)),
  * Additional minor overhead for block-based iteration and optional path extraction.

This matches the optimal asymptotic behavior of any Merkle tree construction, while enabling **streaming** and **replay** in a sublinear-space prover.

---

## 7. Summary

The streaming Merkle design in hc-STARK:

* Treats Merkle tree construction as a height-compressible computation,
* Uses a stack-based online algorithm to build roots in a single pass,
* Stores only minimal state (root + configuration),
* Leverages replay to reconstruct paths and subtrees for queries.

It is the backbone of hc-STARK’s ability to commit to huge oracles without ever storing full evaluation vectors in RAM.