# Backend recovery implementation status

Updated: 2026-07-09. This is a gap ledger, not a release announcement.

## Implemented locally

- WIP snapshot preserved on `codex/recovery-wip-snapshot`; clean recovery work
  is being split into reviewable commits on `codex/plonky3-backend-recovery`.
- Website, API, MCP, checkout, billing-meter, and release paths are fail-closed
  in source. Live deployment and customer billing actions have not been run.
- Plonky3 crates are exact-pinned to `0.6.1` with lockfile checksums.
- The frozen upstream-style Goldilocks/Poseidon2 Uni-STARK configuration emits
  official Plonky3 proofs accepted by the unmodified verifier.
- Fibonacci and Poseidon2 reference AIRs pass official verification, mutation
  rejection, and deterministic proof-byte comparisons for small test cases.
- `hc-stream` exposes resource policy, block matrix, matrix store, resource
  estimate, and checkpoint manifest contracts with checksummed owner-only
  scratch storage. Matrix stores support fallible caller-buffered rectangular
  reads and writes.
- The Plonky3 DFT adapter can consume a block matrix without an owned input and
  produces reference-equivalent output using two bounded butterfly tiles; the
  Plonky3 trait adapter accounts for the owned input imposed by upstream
  `0.6.1`.
- Rust artifact contracts, JSON Schema generation, proof packaging, strict size
  limits, and a cgroup-v2 benchmark harness are present.
- Production containers exclude legacy workers. Default production API, MCP,
  CLI, CI, and publication paths quarantine historical proving.
- Commercial offers, evaluation intake, billing containment, and maintenance
  site are represented in source.

## Not implemented or not yet evidenced

- streamed trace construction;
- tiled four-step FFT with near-square tile selection and block transpose;
- streamed quotient/MMCS/opening generation;
- layer-durable FRI and official challenger-state continuation;
- deterministic crash resume across every required phase;
- parser and resume fuzz targets for all new artifact formats;
- 1M, 10M, or 100M full-pipeline release measurements;
- 4× RAM / 3× time acceptance at 1M or ≤2 GiB at 10M;
- external Plonky3 specialist review or independent implementation review;
- independent report reproduction, signed release, SBOM, or compatibility
  publication;
- external design-partner integration or paid evaluation conversion;
- optional benchmark-report intake endpoint;
- replacement Python, TypeScript, and Rust artifact-contract SDKs (legacy
  hosted-proof clients remain publication-blocked);
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
