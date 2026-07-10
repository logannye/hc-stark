# TinyZKP Python artifact SDK

Typed local artifact models for TinyZKP’s resource-bounded Plonky3 backend.
Schema `TypedDict` models are generated from the Rust-emitted JSON Schemas;
CI rejects generated-file drift.
The package validates and hashes manifests, validates proof-bundle/report
envelopes, loads size-limited files, and invokes a local `hc-cli` binary.
Benchmark reports carry a 128-bit session identifier and typed CPU, memory, and
storage facts so release validation can bind a comparison to one host run.

```python
from tinyzkp import ResourcePolicyV1, WorkloadManifestV1

policy = ResourcePolicyV1(
    mode="scratch",
    max_resident_bytes=512 * 1024**2,
    max_scratch_bytes=64 * 1024**3,
    scratch_dir="/var/tmp/tinyzkp",
    max_threads=4,
    checkpoint_policy="retain_on_failure",
)
manifest = WorkloadManifestV1.fibonacci(0, 1, 1 << 20, policy)
print(manifest.digest_hex())
```

Cryptographic bundle verification is performed by `Cli.verify`; Python does
not reimplement Plonky3. There are no hosted proving, template, polling,
receipt, or remote-verification APIs in this replacement package.
