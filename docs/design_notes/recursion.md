<!-- 55f4f8d3-1b31-4a68-9d20-2a6b9df4c9d7 -->
# recursion.md

_Last updated: 2025-11-15_

---

## 1. Scope

The goal of `hc-recursion` is to provide a thin, deterministic wrapper around batches of hc-STARK proofs so that they can be re-verified (or re-committed) inside another proving system. The current milestone focuses on:

1. Verifying each proof in a batch (`hc_verifier::verify`).
2. Emitting a **proof summary** per child proof (trace commitment digest + public accumulator endpoints).
3. Hashing those summaries into a single **commitment** (`AggregatedProof::commitment`).
4. Enforcing simple batching rules (fan-in, depth) via `RecursionSpec`.

This is enough to feed an outer circuit: the circuit only needs to check the summaries/commitment, while each child proof has already been fully verified off-circuit.

---

## 2. Data model

```rust
pub struct ProofSummary<F> {
    trace_commitment_digest: HashDigest,
    initial_acc: F,
    final_acc: F,
    trace_length: usize,
    query_commitments: QueryCommitments,
    circuit_digest: F,
}

pub struct AggregatedProof<F> {
    total_proofs: usize,
    summaries: Vec<ProofSummary<F>>,
    digest: HashDigest,
}
```

* `summaries` now include `trace_length` (linking the Fiat–Shamir queries to the original domain), `query_commitments` (hashes over all trace/FRI query evaluations), and `circuit_digest` (the value enforced inside the Halo2 circuit).
* `digest` is a Blake3 commitment over all summaries. It is the single value an outer circuit needs to check.

`QueryCommitments` are produced by `hc-verifier::verify_with_summary` by replaying the Fiat–Shamir transcript, rechecking every Merkle path, and hashing the evaluations + indices in a canonical order. This gives recursion circuits a succinct object to check without shipping entire query payloads into the outer proof.

### 2.1 Recursion circuit

`hc-recursion` now contains a concrete Halo2/KZG circuit that enforces the `circuit_digest` relation for every summary:

1. Each summary is encoded into the same Goldilocks words that the aggregator hashes (`SummaryEncoding::as_fields`).
2. A running accumulator (`acc_i = acc_{i-1} + word_i`) is enforced with Plonk gates across the encoding rows.
3. The final accumulator becomes the public input for that summary; the public input exposed to Halo2 is exactly `circuit_digest` converted into the BN254 field.

The prover (via `halo2_proofs`) generates a real PLONK-style proof against a deterministically seeded KZG SRS, and the verifier recomputes the circuit + SRS from the summaries before checking the proof. This replaces the legacy mock wrapper and ensures that aggregated proofs now come with a succinct witness that a PLONK-ish circuit has actually validated the summaries.

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
   **(DONE)** – `ProofSummary` now carries `trace_length` + `QueryCommitments` so outer circuits can bind to the exact Fiat–Shamir transcript without replaying queries.

2. **Multi-level scheduling**  
   Use `RecursionSpec` to plan full trees (e.g., batching `fan_in^level` proofs per level) and emit a schedule the outer driver can follow.

3. **Recursive verifier circuits**  
   **(DONE)** – `hc-recursion::circuit::halo2` builds a Halo2/KZG circuit that re-encodes every summary, enforces the `circuit_digest` relation, and produces a real PLONK proof which is attached to each `AggregatedProofArtifact`. Future iterations can extend this circuit with full verifier logic if we want “verify then summarize.”

4. **Proof-carrying data**  
   Feed `AggregatedProof` objects back into `hc-prover` so that a top-level STARK proof can attest to many child proofs in a single shot (prover recursion).

5. **Interoperability**  
   Document how the summaries map into other proof systems (Plonkish, Halo2, etc.) so the recursion layer can be swapped out without touching the prover.

This staged plan mirrors the rest of hc-STARK: start with deterministic streaming summaries, then gradually fold them into the prover/verifier pipelines once the interfaces are stable.

---

## 5. Implementation status (Nov 2025)

- `RecursionSpec::plan_for(total_proofs)` now emits deterministic multi-level schedules (`RecursionLevel` + `BatchPlan`) and enforces both `fan_in` and `max_depth`.
- The `hc_recursion::circuit` module converts each `ProofSummary` into Goldilocks words, replays the `QueryCommitments`, and exposes a challenge helper that outer circuits can re-use.
- Tests cover tree planning, depth rejection, encoding round-trips, and deterministic aggregation batches driven directly by the schedule output.

