# TinyZKP

TinyZKP is an MIT-licensed, resource-bounded proving backend for Plonky3. Its
production objective is simple: let proving teams complete larger STARK traces
under an explicit RAM ceiling, using deterministic SSD scratch where global
transforms require it, while retaining the official Plonky3 proof format and
unmodified verifier.

> **Pre-release:** hosted proving, hosted verification, account creation,
> public checkout, legacy usage meters, and MCP commerce are disabled and
> excluded from active release and deployment paths. Their final decommission
> is not claimed yet. Do not
> use this repository as a production prover until every gate in
> [`release/backend-v1-gates.json`](release/backend-v1-gates.json) is passed.
> Guard checkout is independently fail-closed by
> [`release/guard-launch-state-v2.json`](release/guard-launch-state-v2.json),
> which is derived from signed evidence and an independently protected trust
> policy.

## Product boundary

TinyZKP does not introduce a new production transcript, verifier, proof format,
or security profile. The production path is pinned to Plonky3 `0.6.1` and the
upstream Goldilocks/Poseidon2 `p3-uni-stark` example configuration, frozen as
`tinyzkp-p3-goldilocks-v1`.

The differentiating layer is prover-side infrastructure:

- resource policies for RAM, scratch, threads, and checkpoint retention;
- checksummed, owner-only matrix stores and block-readable matrix access;
- a deterministic scratch-backed Plonky3 DFT adapter;
- official Plonky3 proof generation and verification for Fibonacci and
  Goldilocks Poseidon2 reference AIRs;
- versioned workload, proof-bundle, and benchmark-report contracts;
- Linux cgroup-v2 measurement from fresh process creation through verification;
- release provenance, compatibility locking, and fail-closed publication gates.

The resource-bounded pipeline is implemented locally: trace and quotient
generation, four-step transforms, MMCS, openings, and FRI use durable bounded
stores, and typed checkpoints preserve the official challenger state for
byte-identical resume. Plonky3 `0.6.1` still hands its generic DFT trait an
owned `RowMajorMatrix`; TinyZKP's bounded orchestration therefore uses the
separate block-matrix entry point. The implementation remains pre-production
until fixed-host resource evidence, independent reviews, and an external
design-partner integration satisfy the machine release gates.

Standalone TinyZKP protocols, legacy receipts, hosted services, recursion, zkML, zkVM, IPA,
Spartan, KZG, and rollup prototypes are research only. Legacy CLI access
requires the explicit `legacy-research` feature and is not compiled into the
public engine container or default CI path.

## Repository map

| Path | Purpose |
|---|---|
| `crates/hc-stream` | Resource policy, block matrices, matrix stores, preflight, and checkpoint contracts |
| `crates/hc-plonky3` | Pinned Plonky3 configuration, workloads, DFT adapter, official prover/verifier, and artifact contracts |
| `crates/hc-cli` | Production Plonky3 CLI and benchmark worker |
| `scripts/benchmark` | cgroup-v2 benchmark orchestration and report tooling |
| `release` | Dependency compatibility and mandatory release-gate evidence |
| `site` | Static Guard product, compatibility, evidence, documentation, and legal-status site |
| `docs/recovery` | Architecture, delivery, release, and operating documentation |

Server, MCP, billing, SDK, and hosted-beta sources remain temporarily on this
branch pending the obligation inventory, verified final exports, replacement
live smoke, and authorized decommission. Their workflows are disabled and
their binaries are excluded from active release and deployment payloads. The
`archive/hosted-beta-2026-07-17` tag preserves the historical snapshot; it is
not evidence that the remaining source or external infrastructure has already
been removed.

## Build and test

Rust `1.95.0` is pinned because Plonky3 `0.6.1` uses APIs unavailable on older
toolchains. Plonky3 and artifact-serialization dependencies are exact-pinned in the
workspace and verified against [`release/plonky3-compatibility-v1.json`](release/plonky3-compatibility-v1.json).

```bash
cargo test --locked -p hc-stream -p hc-plonky3 -p hc-cli
cargo clippy --locked -p hc-stream -p hc-plonky3 -p hc-cli \
  --all-targets -- -D warnings
python3 scripts/ci/guard_launch_gate.py --check
```

The hosted API/MCP/billing launch audit is retired and cannot authorize Guard.
The signed engine candidate, Guard candidate, static site, and OCI identities
must instead pass the Guard evidence and joint promotion controls.

## CLI

Export the public JSON Schemas from their Rust sources of truth:

```bash
tinyzkp-engine schema --output-dir /tmp/tinyzkp-schemas
```

Run the public compatibility and resource doctor against `JobManifestV1`:

```bash
tinyzkp-engine doctor --job job.json
```

Create and verify an official Plonky3 proof bundle:

```bash
tinyzkp-engine plonky3 prove \
  --manifest examples/plonky3/fibonacci-small.json \
  --output /tmp/fibonacci.proof.json
tinyzkp-engine plonky3 verify --bundle /tmp/fibonacci.proof.json
```

`tinyzkp-engine plonky3 resume` validates every checkpoint identity and durable
artifact, restores the official challenger state, and continues from the last
completed phase. Crash/resume tests require the resulting proof bytes to match
an uninterrupted run exactly.

Generic `prove` and `verify` commands return migration guidance. Historical
reproduction is available only in an offline research build:

```bash
cargo run -p hc-cli --features legacy-research -- legacy-research --help
```

The installed `tinyzkp-engine release` command emits JSON for cross-checking
the engine binary, OCI image, compatibility profile, and benchmark provenance
before publication. In a source-development checkout, its internal equivalent
is `cargo run --locked -p hc-cli -- release`.

## Benchmark integrity

Release measurements must run on Linux under cgroup v2, with baseline and
candidate each launched in a fresh process. The report includes hardware, OS,
storage, release SHA, dependency profile, exact command, CPU seconds,
whole-process peak memory, scratch high-water mark, block I/O, proof size,
verification time, and verifier result.

```bash
cargo build --release -p hc-cli
sudo python3 scripts/benchmark/run_plonky3_cgroup.py \
  --manifest examples/plonky3/fibonacci-small.json \
  --report /tmp/fibonacci-bounded.json
```

macOS measurements and component-only tests are useful for development but are
not acceptable release evidence. TinyZKP never infers full-prover memory,
throughput, cost, or capacity from a component benchmark.

Release targets remain blocked until independently reproduced:

- 1M rows: at least 4× lower peak RAM, at most 3× baseline wall time, and no
  more than 10% above the configured cap;
- 16,777,216 rows: at most 2 GiB whole-process peak memory, successful official
  verification, and scratch usage within 10% of preflight;
- deterministic crash recovery, parser/resource fuzzing, independent review,
  one external non-reference workload, signed artifacts, SBOM, checksums,
  and release identity agreement.

## Self-hosted behavior

The public product is a local binary and customer-operated OCI image. It has no
job API, account database, queue, worker fleet, proof storage, usage meter, or
runtime TinyZKP dependency. Customer witnesses, scratch data, and proofs remain
on customer-controlled storage.

The separate commercial Guard supervisor may activate a signed release through
the merchant-of-record. After activation, doctor, run, resume, policy, and
verify operations are offline. Cancellation prevents activation of future
releases but does not disable an already activated release.

## Commercial model

Proof-critical software remains MIT. TinyZKP intends to sell one
customer-operated product:

- Community: free MIT engine, verifier, schemas, doctor, reference workloads,
  and public evidence.
- TinyZKP Guard: $499/month or $4,990/year for one legal organization's
  internal use, with automatic mode selection, recovery supervision, CI policy,
  signed qualification, and access to new releases.

There is no free Guard trial, usage metering, Enterprise tier, Fleet/OEM plan,
hosted compute, custom AIR work, SLA, onboarding call, or included engineering.
The free engine and doctor are the evaluation path. Public checkout remains
disabled until the technical, legal, merchant, external-workload, unaided
installation, and first-customer gates are evidenced.

The machine-readable commercial source is [`site/pricing.json`](site/pricing.json).
See [`BUSINESS_GUIDE.md`](BUSINESS_GUIDE.md) for operating controls and
[`docs/recovery/implementation-status.md`](docs/recovery/implementation-status.md)
for the current gap ledger.

## Security and disclosure

Do not commit secrets, witness data, customer inputs, payment-provider credentials,
private keys, or production environment files. Scratch artifacts must be
owner-only and are untrusted on reopen; manifests, chunks, release identity,
dependency lock, workload, input, and policy must all be validated before
resume.

Report security issues through the private channel linked from
[tinyzkp.com/security](https://tinyzkp.com/security). Performance and security
claims require reproducible evidence; pre-release source is not a production
certification.

## License

This repository and its public engine code are MIT licensed. TinyZKP Guard is a
separate, commercially licensed supervisor. Guard must invoke the public engine
through the published file and CLI contracts; it may not fork proof semantics
or place proof-critical behavior behind the commercial license.
