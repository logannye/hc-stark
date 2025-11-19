# Benchmarks & Metrics Artifacts

`hc-stark` now ships structured benchmarking hooks so CI (or humans) can track √T-behavior without scraping logs.

## CLI Scenarios

| Scenario         | Command                                                                  | Output payload                                                                 |
|------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| `prover` (default) | `cargo run -p hc-cli -- bench --iterations N --block-size B`             | `avg_duration_ms`, `avg_trace_blocks`, `avg_fri_blocks`, duration/iteration    |
| `merkle`         | `cargo run -p hc-cli -- bench --scenario merkle --leaves L --queries Q`   | `streaming_ms`, `in_memory_ms`, `fanout`, leaf/query counts                    |
| `lde`            | `cargo run -p hc-cli -- bench --scenario lde --columns C --degree D --samples S` | `sequential_ms`, `parallel_ms`, derived `speedup` for the batched LDE kernel |

Each invocation prints a single-line JSON summary **and** writes a prettified record to `benchmarks/latest.json`:

```json
{
  "scenario": "merkle",
  "generated_at": 1763530000,
  "metrics": {
    "mode": "merkle_paths",
    "leaves": 4096,
    "queries": 128,
    "fanout": 2,
    "streaming_ms": 12.7,
    "in_memory_ms": 6.2
  }
}
```

## Test Suite Artifacts

`./scripts/test_suite.sh` now emits machine-parsable artifacts alongside the textual log:

- `benchmarks/stress_latest.json` captures every stress-test benchmark (block-size sweeps, merkle replay, batched LDE). Each entry is exactly the JSON emitted by `hc-cli bench`.
- `benchmarks/ladder_latest.json` stores the ladder sweep (block sizes, profiler timings, RSS, normalized ratios).
- `benchmarks/ladder_latest.csv` mirrors the ladder JSON with headers, so plotting tools can ingest it directly.

These files are re-generated on every run (the directory is git-ignored); CI jobs can publish them as build artifacts or feed dashboards.

## Quick Reference

```bash
# Prover micro-bench (default scenario)
cargo run -p hc-cli -- bench --iterations 5 --block-size 64

# Streaming Merkle vs in-memory path extraction
cargo run -p hc-cli -- bench --scenario merkle --leaves 4096 --queries 128 --fanout 2

# Batched LDE throughput benchmark
cargo run -p hc-cli -- bench --scenario lde --columns 4 --degree 512 --samples 2048

# Stress + ladder suites
./scripts/test_suite.sh stress
./scripts/test_suite.sh ladder
```

Use the JSON/CSV payloads to verify √T scaling empirically, gate regressions, or seed dashboards without parsing console noise.

