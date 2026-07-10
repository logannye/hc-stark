# Plonky3-first resource-bounded architecture

## Trust boundary

Plonky3 owns the AIR semantics, transcript, PCS/FRI behavior, proof type, and
verifier. TinyZKP supplies prover-side storage and orchestration. `ProofBundleV1`
is transport packaging and provenance, not a cryptographic statement layer.

## Intended dataflow

1. Validate `WorkloadManifestV1`, dependency profile, input digest, resource
   policy, scratch permissions, and free space before full input ingestion.
2. Stream trace blocks into a `MatrixStore`.
3. Transform with two preallocated scratch matrices using a tiled four-step
   FFT: sub-FFTs, twiddles, blocked transpose, sub-FFTs, reverse transpose.
4. Evaluate quotient constraints with boundary overlap and write directly to a
   commitment store.
5. Build Plonky3-compatible MMCS commitments with bounded frontiers and durable
   levels required for openings.
6. Persist, commit, and checkpoint one FRI layer at a time; release its
   predecessor only after durability.
7. Restore the exact official challenger state after a compatible checkpoint.
8. Generate openings through sorted block scans once queries are known.
9. Package the official proof and verify it under the unmodified verifier.

## Identity required for resume

A checkpoint is reusable only when backend, profile, release, dependency lock,
workload, input, resource policy, completed phase, challenger state, and every
artifact digest match. Unknown versions, non-canonical fields, path traversal,
symlinks, oversized artifacts, stale manifests, and corrupt chunks fail closed.

## Resource modes

- `memory`: only after preflight proves the job fits.
- `scratch`: explicit external-memory execution.
- `auto`: memory only when estimated peak is below 70% of the configured cap;
  otherwise scratch.

The current adapter is an intermediate compatibility implementation. It uses a
blockwise radix-2 DFT and cannot yet bound the complete Plonky3 prover because
upstream trace and later prover phases still allocate owned vectors. This is why
no full-pipeline memory gate is marked passed.
