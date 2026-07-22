# TinyZKP Plonky3 backend threat model

## Security boundary

Plonky3 0.6.1 owns AIR semantics, the Fiat–Shamir transcript, PCS/FRI proof
types, and verification. TinyZKP changes prover-side orchestration and storage
only. A bounded proof must deserialize as the official Plonky3 proof and verify
under the unmodified `p3_uni_stark::verify` implementation.

`ProofBundleV1` packages the official proof, public values, workload manifest,
and release provenance. It is not a new statement or proof protocol.

The frozen profile is transparent verifiable computation. TinyZKP makes no
zero-knowledge or witness-privacy claim for backend v1.

## Adversaries and goals

An adversary may control proof/bundle/checkpoint bytes, scratch directory
contents, process timing and cancellation, and all untrusted workload input.
Relevant goals are:

1. make a false official proof verify;
2. alter public values, workload, profile, dependency lock, or release identity
   without detection;
3. resume from stale, corrupt, cross-workload, or attacker-selected artifacts;
4. escape the scratch root through traversal or symlinks;
5. cause unbounded allocation, disk exhaustion, verifier panic, or silent
   partial output;
6. leak witness values through progress events, manifests, reports, or logs.

## Controls

- Exact Plonky3 `0.6.1` crates, checksums, profile, Poseidon2 seed, FRI
  parameters, and postcard serializer are pinned by a compatibility manifest.
- Conventional, memory, scratch, and resumed execution must produce identical
  proof bytes for deterministic workloads.
- The unmodified verifier is run before a proof bundle is returned.
- JSON contracts reject unknown versions and fields and impose input-size
  limits before proof decoding. Proof bytes use canonical unpadded base64url
  and a BLAKE3 digest.
- Scratch elements use canonical field encoding, headers, dimensions, and
  payload digests. Owner-only paths, non-symlink checks, safe relative paths,
  preallocation, atomic manifests, and fail-closed reopen validation are
  required.
- On Unix, scratch and checkpoint readers traverse every path component with
  descriptor-relative `openat`/`O_NOFOLLOW`, require an owner-only,
  single-link regular file, compare two independently opened identities, and
  read only through the held descriptor. Unsupported non-Unix resume targets
  fail closed instead of falling back to a path-check/open sequence.
- `CheckpointManifestV2` binds backend, profile, release, dependency lock,
  workload, input, resource policy, phase, transcript state, and every resume
  artifact. The Poseidon2 permutation is reconstructed rather than serialized.
- Cgroup-v2 release benchmarks enforce the process memory ceiling and record
  whole-process peak memory, CPU, block I/O, scratch high-water, proof size,
  and official verification.
- CLI events contain phase/progress/provenance/resource metadata only; witness
  values are forbidden.
- Release publication derives from signed, source-bound evidence. Handwritten
  pass booleans, missing automated security results, or release-identity skew
  block publication. Outside review and partner acceptance are advisories.

## Residual risks and advisories

- Plonky3’s frozen benchmark FRI parameters have not received specialist or
  implementation review. That is disclosed as advisory risk, not represented
  as completed, and does not replace the automated verifier/security suite.
- Unit and subprocess fault injection cover every durable phase from trace
  generation through verified proof assembly. The machine-readable matrix also
  covers real disk-full recovery, chunk truncation/corruption, stale identity,
  path traversal, symlinks, and cancellation retention. Independent fixed-host
  reproduction remains an uncompleted advisory. The machine-readable crash
  matrix sends a real SIGTERM to the CLI, resumes its retained checkpoint, and
  requires proof-byte equality. Controlled-host power-loss simulation remains
  an outstanding validation item and is not represented by this matrix.
- Fixed-host 1M throughput and 2²⁴-row ceiling reports have not yet been
  independently reproduced. Reports bind comparison subprocesses with one
  session ID and record typed CPU, memory, block-device, rotational, and NVMe
  facts; the gate rejects mixed-host or nonconforming-host comparisons.
- Filesystem availability and SSD endurance remain operator responsibilities;
  preflight estimates cannot guarantee a disk will not fail mid-job.
- A statically linked partner AIR is part of the trusted integration surface
  and requires its own AIR correctness review.
