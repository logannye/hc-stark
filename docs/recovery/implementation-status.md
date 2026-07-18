# Backend recovery implementation status

Updated: 2026-07-10. This is a gap ledger, not a release announcement.

## Implemented locally

- WIP snapshot preserved on `codex/recovery-wip-snapshot`; clean recovery work
  is split into reviewable commits on `codex/plonky3-backend-recovery`.
- API, MCP, checkout, billing-meter, and proving paths are fail-closed in the
  live containment release
  `5719292ad0c8c4b5f0f6b0500db41cdf6888134c`. That older website release does
  **not** satisfy the current no-email surface: read-only canaries on 2026-07-10
  found obfuscated email links, a `mailto:` security contact, and no dedicated
  `/requests` form. The replacement no-email containment source passes its
  local route, intake, identity, billing, and maintenance gates but has not
  been deployed. No customer cancellation, refund, rebill, or production
  proving action was run.
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
- Failure injection, corruption/path/symlink/cancellation tests, required
  fuzz targets, and machine-readable crash/fuzz evidence runners are present.
  Bundle fuzzing covers envelope validation separately from a valid-envelope
  target that always reaches the official Plonky3 proof decoder. The release
  validator requires every phase plus the Linux disk-full case.
- The fuzz smoke runner builds and hashes a deterministic bounded corpus from
  version-controlled fixtures for each target, so its time limit applies to
  fuzz execution rather than hours of accumulated-corpus initialization. Smoke
  seeds remain immutable while newly discovered units use a disposable corpus.
  Crash artifacts, logs, and evidence outputs are owner-only; release evidence
  records the compatibility profile and exact Rust identity, and cargo-fuzz is
  pinned to `0.13.2` in the manual qualification workflow.
  Full-corpus campaigns remain separate long-running evidence.
- The exact cargo-fuzz capture tool emits an owner-only, explicitly unreviewed
  platform candidate without changing trust. Manual qualification verifies
  that candidate against a separately committed digest before any expensive
  test; it fails closed while the Linux runner digest remains unreviewed.
- Rust artifact contracts, JSON Schema generation, proof packaging, strict size
  limits, and a cgroup-v2 benchmark harness are present. The active release
  ships the engine CLI and OCI image only; Python, TypeScript, hosted API, MCP,
  and maintenance-server publication paths are retired. The legacy WASM
  verifier remains a native-tested research artifact and is not a Guard v1
  release requirement.
- Cross-language `uint64` handling in archived clients was lossless across Rust, Python, and
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
  validated rather than conflated. Linux `VmHWM` is captured by the worker
  after verification so interval polling cannot miss a short-lived peak.
  The host contract also requires at least 500 GB available on the verified
  NVMe volume and a runner-owned mode-0700 scratch root. A standalone
  fixed-host preflight runs before the expensive workflow steps, and the same
  typed facts are embedded in each benchmark report.
- The blocking first-party resource run now has one resumable fixed-host matrix
  controller. It binds both workloads at 1M and 16M to one clean commit,
  embedded CLI identity, storage device, and host identity; seals a mode-0600
  artifact inventory; and revalidates digests and gate semantics before
  skipping completed work. Its terminal state explicitly remains ineligible
  for release because independent reproduction and the external gates cannot
  be satisfied by the first-party controller. Candidate and final gates now
  require the same hashed matrix manifest in both first-party resource gates,
  rebind every source manifest/report/normalized manifest, derive one stable
  host identity from all reports, and require the matrix's release authority
  to remain false.
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
- A non-release macOS 1M smoke completed both workloads in bounded and
  conventional modes. All four proofs passed the official verifier, and each
  workload's proof bytes matched exactly across modes. This does not satisfy a
  resource gate because the host was not Linux/cgroup-v2 or the fixed machine
  class; macOS retained freed large allocations in RSS.

## Not implemented or not yet evidenced

- 1,048,576-row and 16,777,216-row full-pipeline fixed-host release
  measurements for both reference workloads;
- 4× RAM / 3× time acceptance at 1,048,576 rows or ≤2 GiB at 16,777,216 rows;
- external Plonky3 specialist review or independent implementation review;
- independently reviewed Linux cargo-fuzz executable digest for the fixed
  evidence host;
- independent report reproduction, signed release, final artifact SBOM, or
  compatibility publication;
- three external workloads from at least two organizations, two standard annual
  purchases, and the five-machine unaided installation journey;
- specialist-approved production FRI parameters, counsel-approved commercial
  terms, and the merchant sandbox/live-owner lifecycle evidence.

Hosted intake, Fleet control, and hosted capacity are intentionally outside the
Guard product boundary rather than unfinished product work.

## External actions requiring operator/customer coordination

- merge and deploy the replacement no-email containment revision from one
  release, then require the external identity, capability, no-email route, and
  durable-intake canaries before any public announcement;
- obtain write-capable, least-privilege Stripe authorization to archive only
  positively identified TinyZKP catalog objects; the current restricted key
  cannot mutate them and the unrelated active product must remain untouched;
- resolve notification and refund/credit/`none_due` treatment for the active
  TinyZKP legacy customer before pausing or cancelling that subscription;
- commission the specialist and implementation reviews;
- provision a fixed 8-vCPU/16-GB NVMe benchmark host;
- recruit and contract a design partner.

The machine release gate remains
[`release/backend-v1-gates.json`](../../release/backend-v1-gates.json). A task
is not complete merely because code exists; the gate requires reproducible
evidence.
