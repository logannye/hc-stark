# Backend recovery implementation status

Updated: 2026-07-10. This is a gap ledger, not a release announcement.

## Implemented locally

- WIP snapshot preserved on `codex/recovery-wip-snapshot`; clean recovery work
  is split into reviewable commits on `codex/plonky3-backend-recovery`.
- Website, API, MCP, checkout, billing-meter, and release paths are fail-closed
  in source. Live deployment and customer billing actions have not been run.
- Plonky3 crates are exact-pinned to `0.6.1` with lockfile checksums.
- The frozen upstream-style Goldilocks/Poseidon2 Uni-STARK configuration emits
  official Plonky3 proofs accepted by the unmodified verifier. Its seeded
  permutation and workload streams explicitly pin Xoshiro256++ so the 64-bit
  upstream example and 32-bit WASM verifier reconstruct identical parameters.
- Fibonacci and Poseidon2 reference AIRs pass official verification, mutation
  rejection, and deterministic proof-byte comparisons for small test cases.
  Fibonacci verification derives its public endpoint in constant memory rather
  than rebuilding the trace.
- `hc-stream` exposes resource policy, block matrix, matrix store, resource
  estimate, and checkpoint manifest contracts with checksummed owner-only
  scratch storage. Matrix stores support fallible caller-buffered rectangular
  reads and writes.
- The Plonky3 DFT adapter uses near-square four-step transforms, block-aligned
  transpose, bounded twiddles, and two scratch matrices. Its block-matrix path
  avoids a full owned input; the upstream `0.6.1` trait adapter accounts for
  the owned input imposed by that interface.
- Fibonacci and Poseidon2 traces are generated blockwise directly into matrix
  stores. Quotient evaluation, Poseidon2 MMCS construction, sorted/deduplicated
  openings, and every FRI layer are streamed through durable bounded stores.
- Commitment/opening bit reversals use tiled sequential passes instead of
  per-row random I/O. Policy-bounded worker pools cover trace, DFT, quotient,
  opening, MMCS, and FRI CPU work while preserving proof-byte determinism.
- Official challenger state and typed artifacts are checkpointed atomically at
  every pipeline phase. Memory, scratch, uninterrupted, and resumed modes emit
  identical proof bytes accepted by the unmodified verifier.
- Failure injection, corruption/path/symlink/cancellation tests, nine required
  fuzz targets, and machine-readable crash/fuzz evidence runners are present.
  Bundle fuzzing covers envelope validation separately from a valid-envelope
  target that always reaches the official Plonky3 proof decoder. The release
  validator requires every phase plus the Linux disk-full case.
- Rust artifact contracts, JSON Schema generation, proof packaging, strict size
  limits, and a cgroup-v2 benchmark harness are present. Replacement Rust,
  Python, TypeScript, and local-verification WASM contracts share golden
  vectors and remain publication-blocked. CI cross-compiles the WASM verifier
  with the explicit `getrandom` JavaScript backend, executes a golden-proof and
  mutation smoke in Node, and keeps filesystem resource preflight unavailable
  on that target.
- Cross-language `uint64` handling is lossless across Rust, Python, and
  TypeScript. The generated TypeScript contract uses `number | bigint`, its
  file loader preserves large JSON integers, and a maximum-Goldilocks manifest
  and full bounded proof match the Rust digest/reference proof exactly.
- Memory, scratch, and Auto modes now share one mode-aware full-pipeline
  preflight. Explicit memory mode fails before trace allocation when its
  conventional estimate exceeds the cap; Auto cannot accidentally reselect
  memory from the smaller bounded estimate. Baseline reports derive a separate
  conventional preflight without changing the normalized evidence manifest.
- Benchmark reports bind baseline and candidate runs with a shared session ID
  and typed host/storage facts. Release validation requires exactly 8 logical
  CPUs, 15–17 GiB physical memory, non-rotational NVMe scratch, and identical
  baseline/candidate machine identity. Fixed-host workflows reclaim 0600 raw
  reports from the privileged harness before validation and artifact upload.
  Process RSS and cgroup charged-memory peak are separately measured and
  validated rather than conflated.
- Candidate and final release evidence use separate fail-closed gates. The
  candidate builder computes artifact hashes and rejects manual pass/digest
  fields; signing finalization verifies Sigstore before it can add the final
  gate. Both 1M/16M workloads and independent reproduction are mandatory.
  Evidenced commands bind their release/profile/command/log, live identity is
  consumed from a typed site/API/MCP/CLI report, and critical/high review
  findings cannot be waived by risk acceptance.
- Signed finalization pins the GitHub Actions OIDC issuer/workflow identity and
  requires checksums for every production binary, the maintenance OCI image,
  compatibility/gate files, embedded CLI identity, and valid SPDX JSON SBOM.
  Final evidence is semantically validated before staged files replace any
  existing local evidence/config pair.
- External-record builders compute rather than copy resource-artifact,
  review-report, adapter-result, and partner-report hashes. Independent
  reproduction records are emitted only after both workloads pass both fixed
  resource gates; review ledgers bind their report bytes, and partner records
  are validated before atomic publication into local evidence.
- Review bundles require a deterministic SPDX 2.3 dependency inventory derived
  from the exact Cargo lock. Missing, malformed, or symlinked preliminary SBOMs
  fail closed; final release artifacts still receive a separate file-level
  SBOM during signed release assembly.
- Signed CLI builds embed the release identity used by proof bundles and
  checkpoint compatibility. Development builds may use an explicit non-empty
  operator identity, but runtime state cannot override a certified embedded
  SHA. Release CI unsets runtime identity variables and verifies the packaged
  binary still reports the embedded SHA/ref.
- Audited backend crates publish only from a published backend release; SDK
  tags must match package versions and the audited schemas/dependencies before
  any registry upload job starts.
- Production containers exclude legacy workers. Default production API, MCP,
  CLI, CI, and publication paths quarantine historical proving.
- Commercial offers, evaluation intake, billing containment, and maintenance
  site are represented in source.
- The partner adapter exposes generic preflight/prove/verify APIs, compare and
  single-mode workers, compact release-bound evidence, and a Linux cgroup-v2
  resource-report wrapper. External partner acceptance is still required.

## Not implemented or not yet evidenced

- 1M, 10M, or 100M full-pipeline release measurements;
- 4× RAM / 3× time acceptance at 1M or ≤2 GiB at 10M;
- external Plonky3 specialist review or independent implementation review;
- independent report reproduction, signed release, final artifact SBOM, or
  compatibility publication;
- external design-partner integration or paid evaluation conversion;
- optional benchmark-report intake endpoint;
- private Fleet controller or hosted capacity.

## External actions requiring operator/customer coordination

- deploy maintenance API, MCP, and website from one release and run external
  canaries;
- authenticate that the Stripe account is TinyZKP, archive legacy checkout
  routes, and stop charges only after affected customers are notified and a
  refund/credit decision is recorded;
- remove obsolete Cloudflare price bindings after confirming no supported path
  consumes them;
- commission the specialist and implementation reviews;
- provision a fixed 8-vCPU/16-GB NVMe benchmark host;
- recruit and contract a design partner.

The machine release gate remains
[`release/backend-v1-gates.json`](../../release/backend-v1-gates.json). A task
is not complete merely because code exists; the gate requires reproducible
evidence.
