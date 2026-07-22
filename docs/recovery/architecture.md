# Plonky3-first resource-bounded architecture

## Trust boundary

Plonky3 owns the AIR semantics, transcript, PCS/FRI behavior, proof type, and
verifier. TinyZKP supplies prover-side storage and orchestration. `ProofBundleV1`
is transport packaging and provenance, not a cryptographic statement layer.

## Implemented dataflow

1. Validate `WorkloadManifestV1`, dependency profile, input digest, resource
   policy, scratch permissions, and free space before full input ingestion.
2. Stream trace blocks into a `MatrixStore`.
3. Transform with two preallocated scratch matrices using a tiled four-step
   FFT: sub-FFTs, twiddles, blocked transpose, sub-FFTs, reverse transpose.
4. Evaluate quotient constraints with boundary overlap and write directly to a
   commitment store.
5. Build Plonky3-compatible MMCS commitments with contiguous source blocks,
   bounded parent buffers, and durable levels required for openings.
6. Persist and commit FRI layers one at a time. Durable source layers and MMCS
   levels remain available until transcript query positions are known.
7. Atomically checkpoint after trace generation, trace LDE, trace commitment,
   raw quotient, quotient LDE, quotient commitment, openings, every FRI layer,
   and verified proof assembly. Resume validates every identity and digest,
   reopens the earliest sufficient durable artifact, and never regenerates the
   trace once a trace or trace-LDE checkpoint exists.
8. Deduplicate sampled positions, generate input and FRI authentication paths
   through sorted contiguous scans at every Merkle level, then restore the
   official transcript query order.
9. Package the official proof, verify it under the unmodified verifier, and
   persist a final checksummed proof checkpoint before reporting completion.

SIGINT/SIGTERM cancellation is cooperative at durable phase boundaries. State
is retained only when the policy explicitly selects `retain-on-failure`;
otherwise cancellation cleans the job directory.

Every prove/resume phase event includes current scratch bytes and, on Linux,
whole-process resident bytes. These telemetry fields contain resource counts
and paths only; witness values are never included.

Fault injection is an explicit orchestration dependency. Production wrappers
always supply `NoopFailureInjector`; the opt-in `fault-injection` feature uses
the environment-backed abort injector for subprocess crash rotation and a
fixed-host loopback filesystem for disk-full/resume testing. The feature is not
enabled by release binaries.

`scripts/release/run_crash_matrix.py` executes each durable phase separately,
hashes owner-only logs, covers corruption/path/symlink/cancellation cases, and
marks evidence release-complete only when the Linux disk-full recovery case is
also present. The backend release gate parses that report rather than trusting
a manually asserted test result.

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

The Auto decision uses the conventional full-pipeline estimate. Once selected,
preflight validates that exact mode; it never feeds the smaller scratch estimate
back through Auto selection. Conventional benchmark baselines likewise record a
memory-mode estimate while preserving the source/normalized manifest contract.

The bounded path implements near-square four-step transforms, streamed trace and
quotient generation, scratch-backed MMCS, bounded interpolation/opening
reduction, and durable FRI. Small Fibonacci and Poseidon2 tests require exact
proof-byte equality with the conventional Plonky3 prover and acceptance by the
unmodified verifier. Scoped production publication is authorized by
release-bound automated evidence; independent reviews, design-partner
integration, and larger-capacity runs are advisory inputs rather than
publication gates.

Input MMCS leaves are hashed from contiguous source blocks and permuted into
Plonky3's bit-reversed commitment order with two within-group reversals around
a bounded tiled transpose. This avoids one random write per LDE row while
preserving the exact upstream root and openings.

Opening reduction scans each trace/quotient matrix in standard-order blocks,
computes wide row dot products in the bounded worker pool, and applies a
durable tiled bit-reversal only after the reduced vector is persisted. Query
authentication paths are likewise generated from sorted, deduplicated block
scans rather than transcript-order random reads.

`ResourcePolicyV1.max_threads` bounds dedicated Rayon pools for trace blocks,
independent four-step sub-FFTs, quotient rows, opening reductions, FRI folds,
Poseidon2 leaf/parent hashing, and the conventional in-memory path. Buffer
concurrency is also reduced by the resident-memory cap, and writes remain
serialized in canonical row order so thread count cannot change proof bytes.

## Evidence cadence

The owner-dispatched qualification workflow runs on an ephemeral
`ubuntu-24.04` GitHub-hosted runner. It covers both 1,048,576-row workloads and
the 16,777,216-row Fibonacci ceiling for the exact current `main` commit.
Before proving, it requires four effective CPUs, 15--17 GiB effective RAM,
non-rotational storage with at least 12,000,000,000 scratch bytes available,
and a runner-owned mode-0700 scratch root. Poseidon2 at 16,777,216 rows is a
post-GA capacity expansion and cannot satisfy the scoped production matrix.
An opt-in 134,217,728-row run is exploratory and can never satisfy or bypass a
release gate. Every run gets a unique owner-only scratch directory and a
normalized manifest; release validation hashes that manifest and proves that
only `scratch_dir` differs from the source workload manifest. A random
`benchmark_session_id` binds the baseline and bounded subprocesses to one
harness invocation. Typed CPU-count, physical-memory, block-device,
rotational and storage-class facts are captured in every report. Release evidence is
accepted only for the four-CPU/16-GiB hosted-runner class, and baseline/candidate host
facts must match exactly. Root-run fixed-host workflows always return the
owner-only raw reports to the workflow account before validation/upload.
`peak_rss_bytes` uses the worker's Linux `VmHWM` after official verification,
while interval polling remains a corroborating fallback. This prevents a
short-lived allocation peak from escaping the report. `cgroup_peak_bytes`
records the cgroup-v2 enforcement value; the release gate uses the latter for
cap compliance and the former for advertised RAM results.
The harness requires delegated `cpu`, `io`, `memory`, and `pids` controllers
and activates them on its dedicated parent before starting a worker. Doctor
failures still emit the complete estimate as a witness-free JSON event, so an
undersized disk can be provisioned correctly without beginning trace work.
