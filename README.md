# TinyZKP

TinyZKP is an MIT-licensed, resource-bounded proving backend for Plonky3. Its
production objective is simple: let proving teams complete larger STARK traces
under an explicit RAM ceiling, using deterministic SSD scratch where global
transforms require it, while retaining the official Plonky3 proof format and
unmodified verifier.

> **Backend recovery:** hosted proving, hosted verification, account creation,
> public checkout, and legacy usage meters are disabled. The public API and MCP
> surface expose status, release identity, and capabilities only. Do not use this
> repository as a production prover until every gate in
> [`release/backend-v1-gates.json`](release/backend-v1-gates.json) is passed.

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

The current implementation is a compatibility prototype, not the completed
bounded-memory pipeline. Plonky3 `0.6.1` still hands the DFT an owned
`RowMajorMatrix`, trace generation is not yet streamed, the DFT is blockwise
radix-2 rather than the planned tiled four-step transform, and MMCS, quotient,
FRI, and challenger checkpoint recovery are not yet external-memory. These
limits are intentionally reflected by blocked release gates.

Standalone TinyZKP protocols, legacy receipts, recursion, zkML, zkVM, IPA,
Spartan, KZG, and rollup prototypes are research only. Legacy CLI access
requires the explicit `legacy-research` feature and is not compiled into the
production API, MCP service, container, or default CI path.

## Repository map

| Path | Purpose |
|---|---|
| `crates/hc-stream` | Resource policy, block matrices, matrix stores, preflight, and checkpoint contracts |
| `crates/hc-plonky3` | Pinned Plonky3 configuration, workloads, DFT adapter, official prover/verifier, and artifact contracts |
| `crates/hc-cli` | Production Plonky3 CLI and benchmark worker |
| `crates/hc-server` | Maintenance-only public API; historical implementation is retained but not compiled |
| `crates/hc-mcp` | Capability-only production MCP surface |
| `scripts/benchmark` | cgroup-v2 benchmark orchestration and report tooling |
| `release` | Dependency compatibility and mandatory release-gate evidence |
| `site` | Maintenance website and evaluation application |
| `billing` | Billing containment, customer-record preservation, contract invoicing tools, and backups |
| `docs/recovery` | Architecture, delivery, release, and operating documentation |

## Build and test

Rust `1.95.0` is pinned because Plonky3 `0.6.1` uses APIs unavailable on older
toolchains. Plonky3 and artifact-serialization dependencies are exact-pinned in the
workspace and verified against [`release/plonky3-compatibility-v1.json`](release/plonky3-compatibility-v1.json).

```bash
cargo test -p hc-stream -p hc-plonky3 -p hc-cli -p hc-server -p hc-mcp
cargo clippy -p hc-stream -p hc-plonky3 -p hc-cli -p hc-server -p hc-mcp \
  --all-targets -- -D warnings
python3 scripts/ci/production_launch_preflight.py
```

The recovery preflight deliberately does not run live canaries. After an
authorized deployment, add `--live` and the expected release SHA. Do not use
the legacy authenticated prove/verify smoke during recovery.

## CLI

Generate the three JSON Schemas from their Rust source of truth:

```bash
cargo run -p hc-cli -- schema --output-dir /tmp/tinyzkp-schemas
```

Create and verify an official Plonky3 proof bundle:

```bash
cargo run -p hc-cli -- plonky3 doctor --policy examples/plonky3/resource-policy.local.json
cargo run -p hc-cli -- plonky3 prove \
  --manifest examples/plonky3/fibonacci-small.json \
  --output /tmp/fibonacci.proof.json
cargo run -p hc-cli -- plonky3 verify --bundle /tmp/fibonacci.proof.json
```

`hc-cli plonky3 resume` currently validates the checkpoint envelope and then
fails closed because deterministic Plonky3 challenger continuation is not yet
implemented. It will not silently restart and label that behavior as resume.

Generic `prove` and `verify` commands return migration guidance. Historical
reproduction is available only in an offline research build:

```bash
cargo run -p hc-cli --features legacy-research -- legacy-research --help
```

`hc-cli release` emits JSON for cross-checking CLI, API, MCP, site, and
benchmark provenance before publication.

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
- 10M rows: at most 2 GiB whole-process peak memory, successful official
  verification, and scratch usage within 10% of preflight;
- deterministic crash recovery, parser/resource fuzzing, independent review,
  one external design-partner integration, signed artifacts, SBOM, checksums,
  and release identity agreement.

## Public service behavior

During recovery:

- `GET /healthz`, `GET /version`, and `GET /v1/capabilities` are available;
- proving paths return `503 protocol_upgrade`;
- hosted v5/v7 verification returns `422 legacy_statement_unbound`;
- MCP discovery exposes only `get_capabilities`;
- checkout, account creation, demos, and meter emission are disabled;
- tags cannot publish SDKs, WASM, or MCP binaries while backend-v1 gates are
  blocked.

Run [`scripts/monitoring/backend_recovery_canary.py`](scripts/monitoring/backend_recovery_canary.py)
from an external machine after deployment.

## Commercial model

Local software remains MIT. TinyZKP sells fixed-scope evaluations, signed LTS
releases, compatibility guidance, private deployment, policy enforcement,
checkpoint operations, observability, and commercial SLAs:

- Founding Evaluation: $25K for the first two customers;
- Standard Evaluation: $40K fixed, three weeks, fifteen engineering days;
- TinyZKP Certified after backend v1 release: $60K/year prepaid, one workload,
  at most ten support hours per quarter;
- TinyZKP Fleet/OEM after backend v1 release: $125K/year minimum prepaid;
- custom engineering: at least $300/hour, separately scoped.

Reserved hosted capacity remains unavailable until a signed customer exists,
the implementation is reviewed, and measured COGS support at least 80% gross
margin. There is no public Checkout path. Evaluation milestones use Stripe
Invoicing; annual agreements use `send_invoice` subscriptions.

The machine-readable commercial source is [`site/pricing.json`](site/pricing.json).
See [`BUSINESS_GUIDE.md`](BUSINESS_GUIDE.md) for operating controls and
[`docs/recovery/implementation-status.md`](docs/recovery/implementation-status.md)
for the current gap ledger.

## Security and disclosure

Do not commit secrets, witness data, customer inputs, Stripe credentials,
private keys, or production environment files. Scratch artifacts must be
owner-only and are untrusted on reopen; manifests, chunks, release identity,
dependency lock, workload, input, and policy must all be validated before
resume.

Report security issues through the address on
[tinyzkp.com/security](https://tinyzkp.com/security). Performance claims and
security claims require reproducible evidence; backend recovery is not a
production certification.

## License

The existing repository and new public backend code are MIT licensed. Private
Fleet control-plane modules may be created in a separate repository only after
a signed annual agreement; they must invoke the public CLI/container through
the published artifact contracts rather than fork the proof protocol.
