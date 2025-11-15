# height_compression.md

_Last updated: YYYY-MM-DD_

---

## 1. Formal Model of the Computation Tree

The height-compression layer in **hc-STARK** is built around a precise, interval-based model of the computation over the execution trace.

### 1.1 Blocks and Intervals

Let:

- \( T \in \mathbb{N} \) be the total trace length (rows / steps).
- \( b \in \mathbb{N} \) be the block size (rows per block).
- \( B = \lceil T / b \rceil \) be the number of blocks.

We label blocks:

- Block \(k \in \{1, \dots, B\}\) covers rows:
  \[
    I_k = \big[(k-1)b + 1, \dots, \min\{kb, T\}\big].
  \]

We define the **interval set**:

- \(\mathcal{I} = \{ [i,j] \mid 1 \le i \le j \le B \}\).

Each interval \([i,j]\) represents an **aggregate computation** over blocks \(i, i+1, \dots, j\).

### 1.2 Computation Tree

The **computation tree** is a full binary tree \(\mathcal{T}\) with:

- Leaves corresponding to singleton intervals:
  \[
    \text{Leaf nodes: } [k,k],\quad k = 1,\dots,B.
  \]
- Internal nodes corresponding to unions of disjoint child intervals:
  \[
    [i,j] = [i,m] \cup [m+1,j]
  \]
  where \( i \le m < j \).

Formally, a node is:

- A pair \( v = (i,j) \in \mathcal{I} \),
- With children:
  - Left child: \( v_L = (i,m) \),
  - Right child: \( v_R = (m+1,j) \).

The **root** of the tree is \([1,B]\).

We define a function:

- \(\text{blocks}(v) = \{k \mid i \le k \le j\}\) for \(v = (i,j)\).

### 1.3 Node State and Summaries

Each tree node \(v = (i,j)\) is associated with:

1. **Input state summary**:
   - Abstractly: a small object \( \sigma_{\text{in}}(v) \),
   - Encodes the boundary conditions and necessary context at the start of block \(i\).

2. **Output state summary**:
   - A small object \( \sigma_{\text{out}}(v) \),
   - Encodes boundary conditions at the end of block \(j\).

3. **Algebraic summary**:
   - A small object \( \alpha(v) \),
   - Represents the contribution of blocks \([i,j]\) to:
     - Merkle leaves / FRI oracles,
     - Boundary/cross-block constraints,
     - Any other global commitments.

All of \(\sigma_{\text{in}}(v)\), \(\sigma_{\text{out}}(v)\), and \(\alpha(v)\) are designed to be **constant-size**: \(O(1)\) machine words independent of \(T\).

### 1.4 Node Semantics

For each node \(v=(i,j)\), the semantics is:

> Given \(\sigma_{\text{in}}(v)\), re-running the underlying computation over blocks \(i,\dots,j\) produces:
> - The exact internal trace rows for those blocks,
> - The outgoing boundary summary \(\sigma_{\text{out}}(v)\),
> - The algebraic summary \(\alpha(v)\).

The leaves \([k,k]\) correspond to re-running exactly one block \(k\); internal nodes correspond to merging child summaries.

---

## 2. Balancing and Reshaping the Tree

### 2.1 Canonical (Left-Deep) Tree

Naively, a computation that steps through the trace linearly induces a **left-deep** tree:

- \( ([1,1], [1,2], [1,3], \dots, [1,B]) \),
- Each node extends the previous interval by one block.

This tree:

- Has depth \(\Theta(B)\),
- Leads to a DFS stack of size \(\Theta(B)\),
- Is disastrous for memory footprint.

### 2.2 Balanced Binary Tree Construction

To reduce depth, we build a **balanced binary tree** over intervals:

1. Construct the root as \([1,B]\).
2. Recursively split any interval \([i,j]\) into:
   - \( m = \left\lfloor \frac{i + j}{2} \right\rfloor \),
   - Left child: \([i,m]\),
   - Right child: \([m+1,j]\),
   - Stop when \(i = j\) (leaf).

This yields:

- Height: \( h = \lceil \log_2 B \rceil \),
- Maximum root-to-leaf path length: \( O(\log B) \).

### 2.3 Height Compression Strategy

**Height compression** is the method of:

- Evaluating \(\mathcal{T}\) in a way that:
  - Keeps only a small number of node interfaces alive at once,
  - Replays children as needed instead of storing all partial states.

We adopt a **pointerless DFS** order:

- Conceptually, we do a recursive DFS on \(\mathcal{T}\),
- Implementation-wise, we maintain a small explicit stack of **interval descriptors**:
  - Each descriptor encodes \([i,j]\) and a few bits of “phase” (e.g., `Entering`, `LeftDone`, `RightDone`),
  - No heap-allocated pointers or adjacency lists required.

The key property:

> The number of active descriptors on the stack = depth of the tree = \(O(\log B)\).

Because each descriptor is constant-size, stack memory is \(O(\log B)\).

---

## 3. DFS Invariants

To guarantee correctness and bounded memory, we maintain several invariants during DFS evaluation.

### 3.1 Structural Invariants

For each node \(v=(i,j)\):

1. **Balanced Interval**:  
   \( v \) either:
   - Is a leaf: \(i = j\),  
   - Or has two children: \([i,m]\) and \([m+1,j]\) with \(i \le m < j\).

2. **Monotone Coverage**:
   - The blocks covered by a node are contiguous.
   - There are no duplicates or gaps in \(\text{blocks}(v)\).

3. **Parent–Child Consistency**:
   - For each internal node \(v\):
     \[
       \text{blocks}(v) = \text{blocks}(v_L) \cup \text{blocks}(v_R),
     \]
     with \(\text{blocks}(v_L)\) and \(\text{blocks}(v_R)\) disjoint and ordered.

### 3.2 State Invariants

During DFS, each active node \(v\) on the stack maintains:

- A phase flag:
  - `Entering`: about to expand children,
  - `LeftDone`: left child evaluated and summarized,
  - `RightDone`: right child evaluated and summarized (node is ready to reduce),
  - `Completed`: summary computed and passed up.

- Summaries:
  - \(\sigma_{\text{in}}(v)\) is defined when we first push \(v\),
  - \(\sigma_{\text{out}}(v)\) and \(\alpha(v)\) are computed only once both children or the leaf block(s) have been processed.

**Invariants:**

1. **Input Summary Propagation**:
   - At any node \(v=(i,j)\) in `Entering` or `LeftDone` phase:
     - \(\sigma_{\text{in}}(v)\) is fully defined,
     - Matches the output summary of its parent’s left siblings or root input.

2. **Leaf Determinism**:
   - For leaves \([k,k]\):
     - Given \(\sigma_{\text{in}}([k,k])\), the replay of block \(k\) deterministically yields:
       - \(\sigma_{\text{out}}([k,k])\),
       - \(\alpha([k,k])\).

3. **Merge Determinism**:
   - For an internal node \(v=(i,j)\) with children \(v_L = (i,m)\) and \(v_R=(m+1,j)\):
     - Once \(\sigma_{\text{out}}(v_L)\) and \(\sigma_{\text{out}}(v_R)\) are known,
     - \(\sigma_{\text{out}}(v)\) and \(\alpha(v)\) are deterministic functions of:
       - \(\sigma_{\text{in}}(v)\),
       - \(\sigma_{\text{out}}(v_L)\),
       - \(\sigma_{\text{out}}(v_R)\),
       - \(\alpha(v_L)\),
       - \(\alpha(v_R)\).

4. **Stack Size Bound**:
   - At all times during DFS:
     - `stack_len <= 2 * height(\mathcal{T}) = O(\log B)`,
     - Because each node is pushed at most twice in a handcrafted iterative DFS.

### 3.3 Memory Invariants

Let:

- `BLOCK_MEMORY` be the maximum memory needed to replay a single block (trace slice + polynomials),
- `STACK_MEMORY` be the maximum memory for the DFS stack + summaries.

We maintain:

1. **Single-block Locality**:
   - At any point, at most one block replay is active:
     - \( \text{Memory} \le \text{BLOCK_MEMORY} \) for trace + algebraic evaluations.

2. **Bounded Stack**:
   - `STACK_MEMORY = O(\log B) * O(1)` = \(O(\log B)\) words.

3. **Total Working Set**:
   - \( S = \text{BLOCK_MEMORY} + \text{STACK_MEMORY} = O(b) + O(\log B) \).
   - When including per-block metadata for all \(B\) blocks in a streaming fashion, the dominating term is \(O(b + B) = O(b + T/b)\).

In combination with `block_sizing_and_parameters.md`, we tune \(b\) so that:

- \( S \leq S_{\text{target}} \) (e.g., L3 cache or VRAM capacity).

---

## 4. Summary

The height-compression layer:

- Models computation as a balanced binary tree over block intervals,
- Uses pointerless DFS to guarantee \(O(\log B)\) stack size,
- Maintains strict invariants on:
  - Interval structure,
  - State propagation,
  - Deterministic merges,
  - Memory usage.

This formalism ensures we can treat full-trace STARK proving as a **height-compressible computation** over blocks, which is the foundation for the \(O(\sqrt{T})\)-space guarantee in hc-STARK.
