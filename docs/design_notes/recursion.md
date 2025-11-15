<!-- 55f4f8d3-1b31-4a68-9d20-2a6b9df4c9d7 -->
# recursion.md

_Last updated: 2025-11-15_

---

## 1. Scope

The goal of `hc-recursion` is to provide a thin, deterministic wrapper around batches of hc-STARK proofs so that they can be re-verified (or re-committed) inside another proving system. The current milestone focuses on:

1. Verifying each proof in a batch (`hc_verifier::verify`).
2. Emitting a **proof summary** per child proof (trace root + public accumulator endpoints).
3. Hashing those summaries into a single **commitment** (`AggregatedProof::commitment`).
4. Enforcing simple batching rules (fan-in, depth) via `RecursionSpec`.

This is enough to feed an outer circuit: the circuit only needs to check the summaries/commitment, while each child proof has already been fully verified off-circuit.

---

## 2. Data model

```rust
pub struct ProofSummary<F> {
    trace_root: HashDigest,
    initial_acc: F,
    final_acc: F,
}

pub struct AggregatedProof<F> {
    total_proofs: usize,
    summaries: Vec<ProofSummary<F>>,
    digest: HashDigest,
}
```

* `summaries` preserves the metadata the outer recursion layer needs (e.g., to wire accumulators or enforce linking constraints).
* `digest` is a Blake3 commitment over all summaries. It is the single value an outer circuit needs to check.

---

## 3. Batching policy

`RecursionSpec` captures two knobs:

| Field     | Meaning                                   | Default |
|-----------|-------------------------------------------|---------|
| `fan_in`  | Max number of proofs per aggregation node | `8`     |
| `max_depth` | Planned total depth of the recursive tree | `4`     |

At the moment the wrapper only enforces the fan-in constraint. That is, `wrap_proofs_with_spec` will reject any batch with `proofs.len() > fan_in`. Future work will layer the tree shape (`max_depth`) on top so we can build multi-level recursion trees.

---

## 4. Roadmap

1. **Input commitments for recursion circuits**  
   Extend `ProofSummary` with the minimal set of values an outer circuit needs (e.g., FRI final layer commitments, Merkle roots, Fiat–Shamir challenges). Today we only store trace roots + accumulators.

2. **Multi-level scheduling**  
   Use `RecursionSpec` to plan full trees (e.g., batching `fan_in^level` proofs per level) and emit a schedule the outer driver can follow.

3. **Recursive verifier circuits**  
   Replace the placeholder `circuit::describe` with a concrete circuit that:
   - Takes `AggregatedProof::digest` + optional public inputs,
   - Recomputes the digest from supplied summaries,
   - Optionally replays the verifier logic (if we want full recursion instead of “verify then summarize”).

4. **Proof-carrying data**  
   Feed `AggregatedProof` objects back into `hc-prover` so that a top-level STARK proof can attest to many child proofs in a single shot (prover recursion).

5. **Interoperability**  
   Document how the summaries map into other proof systems (Plonkish, Halo2, etc.) so the recursion layer can be swapped out without touching the prover.

This staged plan mirrors the rest of hc-STARK: start with deterministic streaming summaries, then gradually fold them into the prover/verifier pipelines once the interfaces are stable.

