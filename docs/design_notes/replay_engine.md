# replay_engine.md

_Last updated: YYYY-MM-DD_

---

## 1. Purpose of the Replay Engine

The **replay engine** is the component that makes hc-STARK’s height compression practically usable:

- It lets us **discard** large intermediate data (trace slices, polynomial buffers),
- And **reconstruct** any block’s contributions on demand,
- While ensuring **determinism**, **consistency**, and **bounded memory usage**.

The replay engine treats each block and each computation-tree node as a pure function of:

- A small checkpoint / interface,
- The description of the block interval,
- The global problem parameters (AIR, FRI config, cryptographic primitives).

---

## 2. Checkpoints

### 2.1 What is a Checkpoint?

A **checkpoint** is a compact data structure that summarizes all necessary information to **restart computation** for a given interval or block.

Conceptually, a checkpoint \(C\) contains:

1. **Global context IDs**:
   - Hash of AIR / constraint system,
   - Hash of trace-generation code version,
   - Hash of cryptographic parameters (field, hash function, FRI parameters).

2. **Local boundary state**:
   - \(\sigma_{\text{in}}(v)\) (for interval \(v\)) or \(\sigma_{\text{in}}([k,k])\) (for block \(k\)),
   - E.g., VM registers, program counter, memory root, etc.

3. **Interval metadata**:
   - The interval \([i,j]\) or block index \(k\),
   - Additional hints for scheduling or caching policies.

4. **Integrity tags**:
   - A Merkle root or hash commitment to:
     - The expected outputs of the interval (where applicable),
     - Or a cryptographic binding between input state and interval.

In the codebase, we model this as something like:

```rust
struct Checkpoint {
    global_id: GlobalContextId,
    interval: Interval,          // (start_block, end_block) or single block
    in_state_hash: StateDigest,  // hash of sigma_in
    state_payload: StatePayload, // optional small state structure
    integrity_tag: IntegrityTag, // hash tying (global_id, interval, in_state_hash, ... )
}
````

### 2.2 Checkpoint Types

We typically distinguish:

1. **Block checkpoints**:

   * Used to replay a single block (k),
   * Encodes (\sigma_{\text{in}}([k,k])).

2. **Node checkpoints**:

   * Associated with intervals ([i,j]),
   * Used to replay the entire node if necessary (e.g., for recomputing (\alpha([i,j])) or verifying internal consistency).

3. **Global root checkpoint**:

   * Represents the “entry point” of the entire proof generation,
   * Used to ensure everything is relative to a single, immutable problem specification.

---

## 3. Storage and Lifecycle of Checkpoints

### 3.1 In-Memory Representation

During a single proving run:

* Checkpoints are small and kept as part of:

  * The DFS stack,
  * A streaming “interval registry”,
  * An optional LRU cache of frequently replayed blocks.

We ensure that:

* The number of active checkpoints on the stack is (O(\log B)),
* Additional stored checkpoints for blocks/intervals are **constant-size**.

### 3.2 Persisted Checkpoints (Optional)

Optionally, checkpoints may be:

* Serialized to disk,
* Stored in a distributed key-value store,
* Used as recovery points for long-running provers.

This allows:

* Resuming a proof generation after a crash,
* Splitting work across distributed workers (advanced).

---

## 4. Regenerating a Block from Checkpoints

### 4.1 High-Level Outline

To replay block (k), we:

1. Locate or derive a checkpoint (C_k) containing (\sigma_{\text{in}}([k,k])),
2. Re-run the underlying VM or trace generator for rows in block (k),
3. Evaluate the AIR/constraints to obtain polynomials and local oracle values,
4. Output:

   * The block’s trace slice (if needed),
   * Local Merkle leaves / FRI evaluations,
   * (\sigma_{\text{out}}([k,k])) and (\alpha([k,k])),
5. Discard the heavy trace/polynomial data (keeping only summaries).

### 4.2 Detailed Steps

Given block index (k):

1. **Fetch checkpoint**:

   ```rust
   let ckpt = checkpoint_store.get_block_checkpoint(k);
   ```

   It must specify:

   * `ckpt.interval == [k,k]`,
   * A small `state_payload` from which we reconstruct the VM/trace state.

2. **Reconstruct input state**:

   ```rust
   let mut vm_state = reconstruct_state(ckpt.state_payload);
   assert!(hash_state(&vm_state) == ckpt.in_state_hash);
   ```

3. **Replay underlying computation** for rows of block (k):

   * Step the VM / transition function:

     * For each step, produce the row of the execution trace,
     * Collect the necessary columns for AIR evaluation.

4. **AIR & algebraic evaluations**:

   * For each row in block (k), compute:

     * Constraint evaluations,
     * Any intermediate values needed for Merkle/FRI leaves.

5. **Produce outputs**:

   * Compute:

     * `sigma_out_k` = (\sigma_{\text{out}}([k,k])),
     * `alpha_k` = (\alpha([k,k])),
     * Per-block Merkle leaf chunks / FRI contributions.

6. **Sanity checks**:

   * Verify that:

     * The replay uses correct global context (AIR ID, global_id),
     * Boundary conditions at the block’s end line up with any parent node expectations (if known).

7. **Emit and discard**:

   * Send the local contributions to:

     * A streaming Merkle builder,
     * A streaming FRI builder,
   * Discard the trace slice and internal buffers.

At this point, only:

* `sigma_out_k`,
* `alpha_k`,
* Any minimal metadata needed for higher-level intervals

remain in memory.

---

## 5. Interval Replay

Replaying an interval (v = [i,j]) is conceptually:

1. Retrieve `checkpoint_v` with (\sigma_{\text{in}}(v)),
2. Recursively replay blocks (i \dots j) or reuse already-computed child summaries,
3. Aggregate children summaries using a deterministic merge function.

In practice, we often:

* Reconstruct interval summaries by reusing block-level replay,
* Avoid storing “full” interval-level traces,
* Only compute intermediate `alpha` summaries and boundary states.

This is consistent with the height-compressed DFS semantics described in `height_compression.md`.

---

## 6. Failure Modes and Consistency Checks

Because the replay engine is the backbone of correctness, we adopt explicit safeguards.

### 6.1 Checkpoint Corruption or Mismatch

**Failure mode**: Checkpoint contents don’t match global context or expected state.

**Detection**:

* Every checkpoint includes:

  * `global_id` hash,
  * `in_state_hash`,
  * An `integrity_tag` that binds `(global_id, interval, in_state_hash, ...)`.

During replay, we validate:

```rust
assert!(ckpt.global_id == expected_global_id);
assert!(hash_state(reconstruct_state(ckpt.state_payload)) == ckpt.in_state_hash);
assert!(validate_integrity_tag(&ckpt));
```

If any assertion fails:

* Abort proving,
* Report a “checkpoint corruption / mismatch” error.

### 6.2 Non-deterministic Trace Generation

**Failure mode**: The underlying VM / trace generator is not fully deterministic.

This would cause:

* Different replays of the same checkpoint to produce different traces,
* Inconsistencies in Merkle leaves or FRI evaluations,
* Potential invalid proofs.

**Mitigation**:

* The VM and all randomness are required to be **pseudo-deterministic**:

  * Any randomness must come from PRFs seeded solely by:

    * The global problem ID,
    * Interval indices,
    * Fixed randomness recorded in checkpoints.

* Optionally, we can:

  * Store additional “replay hashes” when first generating a block,
  * On subsequent replays, hash partial outputs and compare.

### 6.3 Merkle / FRI Consistency

**Failure mode**: Replayed blocks yield data inconsistent with previously committed Merkle roots or FRI layers.

**Detection**:

* The streaming Merkle/FRI builders maintain:

  * Internal consistency checks,
  * Hash commitments at each layer.

If a block replay produces leaves that do not match:

* The expected Merkle root (if recomputed),
* Or previously stored per-layer commitments,

we abort the run.

### 6.4 Resource Exhaustion

**Failure mode**: Block replay consumes more memory than expected due to:

* Configuration errors,
* Bugs in polynomial routines,
* Unbounded data structures.

**Mitigation**:

* Explicit hard caps on memory use per block:

  * Use arena allocators with limited capacity,
  * Assert on overflow.

* Telemetry:

  * Record per-block peak memory,
  * Log anomalies.

---

## 7. Summary

The replay engine is the mechanism that enables hc-STARK’s:

* **O((\sqrt{T})) space** behavior via replay instead of storage,
* Strict separation between:

  * Small, persistent checkpoints,
  * Large, ephemeral block-level data.

It does so by:

* Defining precise, hash-bound checkpoints for each block/interval,
* Providing deterministic replays of trace slices and algebraic evaluations,
* Enforcing strong consistency checks to catch any mismatch or nondeterminism.

Together with the height-compressed computation tree and careful block sizing, the replay engine is what makes long-trace, memory-efficient STARK proving practical.
