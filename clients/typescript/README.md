# TinyZKP TypeScript artifact SDK

Local Node.js models and helpers for `WorkloadManifestV1`, `ProofBundleV1`, and
`BenchmarkReportV1`. These interfaces are generated from the Rust-emitted JSON
Schemas, and CI rejects generated-file drift. The package implements TinyZKP canonical JSON v1 and
BLAKE3 manifest digests, strict runtime validation, bounded file loading, and
safe local `hc-cli` invocation.

`BenchmarkReportV1` includes a 128-bit session identifier plus typed CPU,
physical-memory, block-device, rotational, and NVMe facts so release tooling
cannot mix a baseline and candidate from different host runs.

Rust `uint64` fields are exposed as `UInt64 = number | bigint`. File loaders
use lossless JSON parsing: values within JavaScript's safe range remain
`number`, while larger Goldilocks/public values become native `bigint`.
`canonicalJsonV1` serializes both forms as unquoted JSON integers, matching the
Rust manifest digest. Do not round-trip artifacts through `JSON.parse`.

```ts
import { fibonacciManifest, manifestDigestHex } from "tinyzkp";

const manifest = fibonacciManifest(0, 1, 2 ** 20, {
  mode: "scratch",
  max_resident_bytes: 512 * 1024 ** 2,
  max_scratch_bytes: 64 * 1024 ** 3,
  scratch_dir: "/var/tmp/tinyzkp",
  max_threads: 4,
  checkpoint_policy: "retain_on_failure",
});
console.log(manifestDigestHex(manifest));

const maximumFieldManifest = fibonacciManifest(
  18446744069414584320n,
  0,
  16,
  manifest.resource_policy,
);
```

The replacement package contains no hosted proving, polling, template,
legacy receipt, or remote-verification client. Cryptographic verification is
delegated to the pinned local CLI/WASM verifier.
