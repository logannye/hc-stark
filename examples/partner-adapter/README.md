# Statically linked partner adapter example

This crate demonstrates the supported partner integration boundary: a custom
AIR and block-generating `ResourceBoundedWorkload` are linked into a private
binary without changing TinyZKP’s built-in CLI registry or Plonky3’s proof
format/verifier.

The evaluation binary runs both conventional and bounded provers, requires
byte-identical official proofs, and atomically emits an owner-only evidence
artifact containing only the proof digest/size, frozen dependency provenance,
the generic full-pipeline preflight estimate, and verification result—never
witness rows or proof payloads. A real partner
acceptance record and cgroup resource report are still required by
`backend_release_ready.py`; this example cannot satisfy that external gate by
itself.

```bash
cargo run --release --manifest-path examples/partner-adapter/Cargo.toml -- \
  examples/partner-adapter/partner-manifest.example.json \
  /tmp/partner-evidence.json
```

On the fixed Linux host, produce the separately measured `resource_report`
artifact in a fresh cgroup-v2 subprocess:

```bash
cargo build --release --manifest-path examples/partner-adapter/Cargo.toml --locked
report_owner="$(id -u):$(id -g)"
reclaim_report() { sudo chown "$report_owner" /tmp/partner-resource-report*.json 2>/dev/null || true; }
trap reclaim_report EXIT
sudo --preserve-env=HC_RELEASE_SHA python3 examples/partner-adapter/run_cgroup.py \
  --manifest examples/partner-adapter/partner-manifest.example.json \
  --report /tmp/partner-resource-report.json
```

The binary also supports `--mode doctor`, `--mode bounded`, and
`--mode conventional` for programmatic evaluation. The default `compare` mode
is the adapter-result gate and requires exact proof-byte equality.
