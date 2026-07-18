# Open engine declarative AIR contract v1

The open engine accepts local, versioned JSON files and packed trace chunks. It
does not expose an HTTP service and proving, resuming, and verification make no
network requests.

## Inputs

- `AirPackageV1` (`air-package-v1.schema.json`)
- `TraceManifestV1` (`trace-manifest-v1.schema.json`)
- `PublicInputsV1` (`public-inputs-v1.schema.json`)
- `ResourcePolicyV1` (embedded in the existing workload manifest schema)

Generate the public schemas with `hc-cli schema --output-dir <directory>`.

## Commands

Estimate and preflight both execution paths:

```text
hc-cli plonky3 estimate-air \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --public-inputs <public-inputs.json> \
  --policy <resource-policy.json>
```

Standard output is one JSON object:

```json
{
  "schema_version": 1,
  "selected_mode": "memory",
  "conventional_estimate": {},
  "bounded_estimate": {},
  "preflight": {}
}
```

For `auto`, the engine selects `memory` only when the conventional peak
resident estimate is at most 70% of `max_resident_bytes`. It otherwise selects
`scratch`, then preflights the bounded estimate. Explicit `memory` and
`scratch` modes are never silently changed.

Prove using the selected policy mode:

```text
hc-cli plonky3 prove-air \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --chunks-dir <packed-trace-directory> \
  --public-inputs <public-inputs.json> \
  --policy <resource-policy.json> \
  --output <air-proof-bundle.json>
```

`--reference` forces the conventional path for differential evidence while
still applying the configured resident-memory limit. The default path honors
`memory`, `scratch`, or `auto` from the policy. Output is written atomically as
`AirProofBundleV1`; progress is JSON Lines on standard error.

Resume a scratch-mode checkpoint:

```text
hc-cli plonky3 resume-air \
  --air <air.json> \
  --trace-manifest <trace-manifest.json> \
  --chunks-dir <packed-trace-directory> \
  --public-inputs <public-inputs.json> \
  --checkpoint <job-directory/checkpoint.json> \
  --output <air-proof-bundle.json>
```

Resume reconstructs the declarative workload and validates the checkpoint's
profile, dependency lock, release identity, workload identity, input digest,
resource policy, and artifact digests before continuing. Checkpoints from a
different exact release or different input contract fail closed.

Verify the resulting official proof:

```text
hc-cli plonky3 verify-air --bundle <air-proof-bundle.json>
```

The release evidence test for this contract is:

```text
cargo test -p hc-cli --test cli_roundtrip plonky3_air_job_contracts -- --exact
```
