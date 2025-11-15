# security_considerations.md

_Last updated: 2025-11-14_

---

## 1. Core Claim

The central security claim of **hc-STARK** is:

> Height compression and replay **do not weaken** the soundness, completeness, or zero-knowledge (when added) of the underlying STARK protocol, as long as:
> - The AIR, FRI parameters, and hash functions are unchanged,
> - The prover’s transcript (commitments, challenges, responses) is identical to that of a conventional STARK,
> - Implementation respects deterministic replay and correct randomness usage.

This document explains why and highlights key implementation pitfalls to avoid.

---

## 2. Why Height Compression / Replay Preserve Soundness

### 2.1 Protocol vs Implementation

A STARK protocol consists of:

1. A set of **algebraic statements** encoded by the AIR,
2. A sequence of **commitments** and **challenges**:
   - Merkle roots for oracles (trace, constraints, FRI layers),
   - Random field elements from verifier or Fiat–Shamir,
3. A final **accept/reject** rule used by the verifier.

**hc-STARK changes only the prover’s internal implementation**:

- How it constructs the oracles (streaming vs in-memory),
- How it manages state (height-compressed trees + replay),
- How it schedules computations (DFS over blocks/intervals).

The verifier’s view is unchanged if:

- Every Merkle root,
- Every FRI root,
- Every query answer and authentication path,

is identical to what a conventional prover would have produced for the same witness.

Formally, hc-STARK is a different \(\mathsf{P}^\*\) such that:

- \(\mathsf{view}_\mathsf{V}(\mathsf{P}, w) \equiv \mathsf{view}_\mathsf{V}(\mathsf{P}^\*, w)\),

for any witness \(w\). Soundness properties (unconditional/computational) are thus preserved.

### 2.2 No New Cheating Strategies

Height compression and replay:

- Restrict prover memory, but do **not** give the prover extra power.
- The prover is “less capable” than a hypothetical unbounded prover, not more.

Any cheating strategy \(\mathsf{P}^\*\) that exploits:

- Reordering computations,
- On-demand replays,

could be emulated by a conventional, fully in-memory prover. Thus, if the original protocol is sound against all (computationally bounded) provers, it remains sound against replay-based ones.

### 2.3 Deterministic Replays and Binding

For security, each replay must:

- Reproduce exactly the same outputs (evaluations, hashes) that were implicitly committed to earlier.

This is enforced by:

1. **Deterministic trace generation**:
   - Trace generator is a pure function of:
     - AIR,
     - Witness,
     - Global randomness and configuration.
2. **Checkpoint integrity**:
   - Checkpoints tie:
     - Interval indices,
     - Input states,
     - Global IDs,
   - To a cryptographic hash (`integrity_tag`).
3. **Consistent Merkle/FRI roots**:
   - Any mismatch between replayed leaves and previously derived roots causes the proof to be invalid.

As long as these conditions hold, replay is merely a storage optimization; it does not alter the committed object.

---

## 3. Completeness and Zero-Knowledge

### 3.1 Completeness

Completeness says: an honest prover with a valid witness should be able to convince the verifier with probability 1 (or overwhelming probability).

hc-STARK preserves completeness if:

- The streaming / height-compressed implementation can always finish:
  - Within available time/memory,
  - Without overflow or resource-exhaustion.
- There is no additional failure mode (e.g., checkpoint corruption) that causes a correct witness to be rejected.

Practical requirements:

- Robust checkpoint storage (in-memory + optional persistence),
- Carefully bounded memory usage to avoid OS-level OOM,
- Defensive checks around replay.

### 3.2 Zero-Knowledge

Plain STARKs are **not inherently zero-knowledge**; privacy is usually achieved via masking, randomization of constraints, or separate ZK compilers.

When hc-STARK is used with a **ZK-enhanced STARK**:

- The prover’s internal memory layout is different, but:
  - The **transcript** remains compatible with the original ZK construction,
  - Any simulator/extractor argument applies to hc-STARK as well.

Important:

- Height compression must not introduce **additional leakage**:
  - Checkpoints should not be persisted or exposed in logs or side channels,
  - The replay engine must not output partial trace fragments beyond what is committed and masked by the protocol.

If the underlying STARK is zero-knowledge, hc-STARK does not change that fact as long as internal state is kept secret and transient.

---

## 4. Quantum-Safety and Transparency

hc-STARK is based on:

- FRI,
- Merkle trees,
- Collision-resistant hash functions.

These ingredients are:

- **Transparent**: no trusted setup, only public randomness and hashing,
- **(Conjecturally) post-quantum**: security grounded in the hardness of finding hash collisions and preimages, not number-theoretic assumptions.

Height compression and replay:

- Do not introduce number-theoretic assumptions,
- Do not require structured reference strings.

Thus, the transparency and (conjectural) quantum-safety characteristics of the underlying STARK remain intact.

---

## 5. Side-Channel and Implementation Pitfalls

Height compression and replay change the **micro-architecture** of the prover. This can introduce new side-channel risks if carelessly implemented.

### 5.1 Timing and Memory-Access Leakage

**Pitfall**: Prover runtime and memory-access patterns may depend on secret witness data.

Examples:

- Branches in the trace generator that depend on private inputs,
- Different replay patterns depending on which blocks trigger more constraints.

Mitigations:

- Use constant-time coding practices for cryptographic primitives:
  - Hashing,
  - FRI folding arithmetic,
  - Merkle path assembly.
- Ensure that trace generation for private data does not leak via:
  - Early exits or data-dependent loops,
  - OS page-fault patterns.

In many real-world ZK applications, some leakage about the structure of the computation (e.g., number of steps) is acceptable, but witness-specific variations should be minimized.

### 5.2 Checkpoint Handling

**Pitfall**: Checkpoints may accidentally leak sensitive partial state if:

- Logged in plaintext,
- Stored unencrypted in persistent storage,
- Shared across tenants or processes.

Mitigations:

- Treat checkpoints as sensitive:
  - Encrypt at rest if persisted,
  - Avoid debug logs that dump checkpoint contents.
- Provide a clear separation between:
  - Public metadata (interval indices, global IDs),
  - Private state (VM registers, memory digests).

### 5.3 Randomness Usage

**Pitfall**: Misuse of randomness in FRI or maskings, especially with replay:

- Reusing random challenges incorrectly,
- Mixing global randomness and per-block randomness in inconsistent ways.

Mitigations:

- Derive all randomness from:
  - The transcript (Fiat–Shamir),
  - Well-defined PRFs keyed by global seeds.
- Never re-derive challenges using local, ad-hoc randomness.
- Make randomness derivation **deterministic and documented**:
  - E.g., `r_ell = H(root_ell || ell || "FRI_CHALLENGE")`.

### 5.4 Concurrency Bugs

Replay-based provers often run:

- Multi-threaded,
- Across multiple cores or GPUs.

**Pitfall**: Race conditions or cache invalidations produce:

- Inconsistent checkpoints,
- Corrupted Merkle roots,
- Non-deterministic transcripts.

Mitigations:

- Use concurrency-safe primitives around:
  - Checkpoint creation and updates,
  - Shared caches,
  - Global configuration objects.
- Introduce **deterministic scheduling** where necessary:
  - E.g., strict ordering on block processing for a given tree or FRI layer.

### 5.5 Incomplete Sanity Checks

**Pitfall**: Omitting or weakening integrity checks to “optimize performance” can allow subtle bugs or even adversarial manipulations.

Mitigations:

- Enforce:
  - Hash consistency of replays vs original commitments,
  - Strict matching of global IDs in all checkpoints,
  - Assertions on the size and structure of trees/layers.

---

## 6. Threat Model Clarifications

hc-STARK’s security arguments assume:

1. **Verifier**:
   - Follows the protocol as specified (honest verifier in most ZK settings).
2. **Prover**:
   - May be malicious, but is bounded by standard computational assumptions:
     - Cannot break hash collision resistance,
     - Cannot solve underlying hardness assumptions.

Under this model:

- Height compression is part of the prover’s internal strategy and cannot expand the prover’s capability beyond what is already considered in the security proof.
- Replay is treated as an internal optimization; any cheating attempt using replay would correspond to a cheating strategy in the original model.

---

## 7. Summary

From a protocol perspective:

- hc-STARK is a STARK with a specialized, memory-efficient prover implementation.
- The interaction and transcript are identical to those of a conventional STARK using the same AIR and FRI parameters.

Security-wise:

- Soundness, completeness, transparency, and (when present) zero-knowledge properties are **preserved**, not altered.
- The main risks are **implementation-level**:
  - Side-channel leakage,
  - Checkpoint mishandling,
  - Incorrect randomness derivation,
  - Concurrency bugs.

Careful engineering, combined with strict integrity checks and deterministic replay, ensures that height compression and replay deliver their asymptotic advantages **without compromising security**.
