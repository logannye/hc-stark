# Open engine declarative AIR contract v1

The MIT-licensed engine accepts local, versioned JSON files and packed trace
chunks. It has no HTTP service. Doctor, proving, resume, and verification make
no network requests.

The installed executable is `tinyzkp-engine` (the Cargo package and development
binary remain named `hc-cli`).

## Public contracts

`tinyzkp-contracts` is the sole Rust authority for the Guard-facing contracts:

- `JobManifestV1`
- `DoctorReportV1`
- `CompatibilityReportV1`
- `ReasonV1`
- `ErrorEnvelopeV1`
- `ProgressEventV1`
- `JobResultV1`
- `SupportReportV1`
- `JobInspectResultV1`
- `GuardChannelV1`
- `GuardReleaseIndexV1`
- `PolicyBaselineV1`

Generate their twelve JSON Schemas, the standalone
`CompatibilityManifestV1` profile schema, and the proof-engine schemas with:

```text
tinyzkp-engine schema --output-dir <directory>
```

The exporter serializes every schema directly from the Rust authority. Release
CI compares the generated files with the published copies byte for byte.

`GuardChannelV1` is minted only for a software release. Its closed
`release_change_class` is `proof_critical` or `guard_package_only`; a site,
legal, or pricing-only update never creates a channel. The first
proof-critical GA channel has no predecessor. Every later proof-critical
channel and every package-only channel binds both the prior qualified release
identity and the SHA-256 of the signed release index that established it.
`GuardReleaseIndexV1` is a nonempty, unique, acyclic history with exactly one
current release and state-specific successor or withdrawal evidence.
JSON Schema enforces its closed shape and local field/state constraints, but it
cannot express release-identity or Guard-version uniqueness across entries,
artifact-name uniqueness within an entry, exact `current_release_identity`
linkage, successor target existence, or successor cycles. Consumers must also
deserialize the index and call `GuardReleaseIndexV1::validate`; schema
validation alone is insufficient.

## Compatibility doctor

Run doctor before purchasing or proving:

```text
tinyzkp-engine doctor --job <job-manifest-v1.json>
```

The sample at `examples/plonky3/job-manifest-v1.example.json` documents every
v1 field. The `--job` argument and every path inside the manifest must be
relative; absolute manifest paths are rejected. Workload paths resolve beneath
`roots.input_root`; job, output, and scratch paths resolve beneath their
respective roots.

Doctor validates declarations, platform, path containment, file type, stated
file size, compatibility, and resource estimates. It does not open trace chunk
contents, create job directories, or ingest a witness. Scratch and RAM failures
are reported before expensive ingestion.

Standard output is exactly one `DoctorReportV1`, including on compatibility
exit 10 and resource exit 12. Malformed or unsafe input produces exactly one
`ErrorEnvelopeV1`. Standard error contains only `ProgressEventV1` JSON Lines.

For `mode: auto`, the conventional path is selected only when its estimated
peak resident use is at most the exact integer value
`floor(ram_budget_bytes * 7 / 10)`. Otherwise the bounded path is selected.
Bounded preflight requires the estimate plus enough free capacity that the
estimate consumes no more than 90% of available scratch:
`estimate + ceil(estimate / 9)`. Both calculations are overflow-safe and shared
with Guard.

## Declarative AIR engine commands

The lower-level engine operations consume the proof-critical contracts.
`ResourcePolicyV1` uses the engine names `auto`, `memory`, and `scratch`;
Guard's public job names `auto`, `conventional`, and `bounded` map to them
without changing proof semantics.

Estimate and preflight both execution paths:

```text
tinyzkp-engine plonky3 estimate-air \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --public-inputs <public-inputs.json> \
  --policy <resource-policy.json>
```

Prove with an exact, caller-owned checkpoint directory:

```text
tinyzkp-engine plonky3 prove-air \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --chunks-dir <packed-trace-directory> \
  --public-inputs <public-inputs.json> \
  --policy <resource-policy.json> \
  --checkpoint-dir <job-directory/checkpoint> \
  --output <air-proof-bundle.json>
```

The checkpoint path is exactly
`<job-directory/checkpoint>/checkpoint.json`. Proving rejects a nonempty
checkpoint directory rather than silently reusing or overwriting job state.
`--reference` forces the conventional path for differential evidence while
retaining the configured resident-memory cap.

Inspect a bounded checkpoint before offering resume:

```text
tinyzkp-engine plonky3 inspect-checkpoint \
  --checkpoint <job-directory/checkpoint/checkpoint.json> \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --chunks-dir <packed-trace-directory> \
  --public-inputs <public-inputs.json> \
  --policy <resource-policy.json>
```

Inspection is strictly read-only. It validates `CheckpointManifestV2`
structure, the compressed and uncompressed trace chunk digests, canonical
Goldilocks values, every durable artifact digest, and exact backend, profile,
dependency-lock, engine-release, workload, input, and resource-policy
identity. The supplied policy must be the exact policy used to create the
checkpoint; reading the policy embedded in the checkpoint alone would prove
only internal consistency, not that it matches the caller's current job.
Inspection neither creates nor repairs state. Success is exactly one
`EngineCheckpointInspectResultV1`; the result contains no paths, input
identifiers, digests, policy details, witness values, or license material.
Missing, malformed, truncated, corrupt, unsafe, and stale-release checkpoints
fail closed through the finite reason vocabulary.

Resume the same exact release:

```text
tinyzkp-engine plonky3 resume-air \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --chunks-dir <packed-trace-directory> \
  --public-inputs <public-inputs.json> \
  --checkpoint <job-directory/checkpoint/checkpoint.json> \
  --output <air-proof-bundle.json>
```

Resume reconstructs the declarative workload and validates the checkpoint's
profile, dependency lock, exact engine release, workload identity, input
digest, resource policy, and artifact digests. A checkpoint from another
release or input contract fails closed.

Verify with the ordinary Plonky3 verifier:

```text
tinyzkp-engine plonky3 verify-air --bundle <air-proof-bundle.json>
```

For estimate, prove, resume, and verify, successful standard output is exactly
one versioned engine result. Failure standard output is exactly one
`ErrorEnvelopeV1`. Progress standard error is only versioned JSON Lines.

## Stable failure classes

| Exit | Class |
| ---: | --- |
| 10 | incompatible |
| 11 | invalid input |
| 12 | insufficient resources |
| 13 | resumable interruption |
| 14 | corrupt or stale checkpoint |
| 15 | verification failure |
| 16 | license failure |
| 70 | internal error |

The finite reason vocabulary and canonical remediation text are defined in
`ReasonV1`; callers must not infer behavior by parsing human-readable logs.

## Release evidence

The focused contract tests are:

```text
cargo test --locked -p tinyzkp-contracts
cargo test --locked -p hc-cli --test cli_roundtrip plonky3_air_job_contracts -- --exact
cargo test --locked -p hc-cli --test cli_roundtrip checkpoint_inspection_is_complete_typed_and_read_only -- --exact
cargo test --locked -p hc-cli --test cli_roundtrip declarative_air_sigterm_uses_exact_checkpoint_dir_and_typed_resume_protocol -- --exact
cargo test --locked -p hc-cli --test cli_roundtrip schemas_are_exported_from_rust_contracts -- --exact
```
