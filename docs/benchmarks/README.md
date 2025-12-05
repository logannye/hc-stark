# Benchmarks & Metrics Artifacts

`hc-stark` now ships structured benchmarking hooks so CI (or humans) can track √T-behavior without scraping logs.

## CLI Scenarios

| Scenario         | Command                                                                  | Output payload                                                                 |
|------------------|--------------------------------------------------------------------------|--------------------------------------------------------------------------------|
| `prover` (default) | `cargo run -p hc-cli -- bench --iterations N --block-size B`             | `avg_duration_ms`, `avg_trace_blocks`, `avg_fri_blocks`, duration/iteration    |
| `merkle`         | `cargo run -p hc-cli -- bench --scenario merkle --leaves L --queries Q`   | `streaming_ms`, `in_memory_ms`, `fanout`, leaf/query counts                    |
| `lde`            | `cargo run -p hc-cli -- bench --scenario lde --columns C --degree D --samples S` | `sequential_ms`, `parallel_ms`, derived `speedup` for the batched LDE kernel |
| `recursion`      | `cargo run -p hc-cli -- bench --scenario recursion --proofs P`            | `proofs`, recursion `depth`, total `batches`, aggregation duration            |
| `height`         | `cargo run -p hc-cli -- bench --scenario height --leaves L --block-size B --samples S` | Mean/stddev for Merkle & KZG streaming vs baseline time, peak RSS deltas, replay block counts, JSON per-sample detail + `benchmarks/height_latest.csv` |

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

Add `--metrics-dir path/to/out` (defaults to `benchmarks/`) and/or `--metrics-tag nightly` when invoking `hc-cli bench` to persist history suitable for dashboards. Every run appends to `<metrics-dir>/<scenario>_history.jsonl`; height runs also update `height_history.csv` (per-run stats) plus `height_latest.csv` (per-sample detail).

## Test Suite Artifacts

`./scripts/test_suite.sh` now emits machine-parsable artifacts alongside the textual log:

- `benchmarks/stress_latest.json` captures every stress-test benchmark (block-size sweeps, merkle replay, batched LDE). Each entry is exactly the JSON emitted by `hc-cli bench`.
- `benchmarks/ladder_latest.json` stores the ladder sweep (block sizes, profiler timings, RSS, normalized ratios).
- `benchmarks/ladder_latest.csv` mirrors the ladder JSON with headers, so plotting tools can ingest it directly.
- `benchmarks/recursion_latest.json` stores the summary emitted by `hc-cli recursion` (digest, depth, batches, witness field count) so CI can spot aggregation regressions.
- `benchmarks/recursion_latest_artifact.json` is a more detailed dump of the recursive wrapper (summaries, witness encodings, mock verification key, schedule) to help debug parent-proof pipelines or plug into future circuits.

These files are re-generated on every run (the directory is git-ignored); CI jobs can publish them as build artifacts or feed dashboards.

> The GitHub Actions workflow (`.github/workflows/ci.yml`) already runs the sanity/stress/ladder suites and uploads the entire `benchmarks/` directory so you can diff results per commit without re-running the harness locally.

## Baselines & Regression Thresholds

- `benchmarks/baseline.json` captures the current √T envelope:
  - `latest` holds canonical values for `avg_trace_blocks`, `avg_fri_blocks`, and `avg_duration_ms`.
  - `ladder.targets` records per-block-size duration / trace / fri counts from the ladder sweep.
  - Each section includes a `tolerance_pct` so we can tune how much drift is tolerated before flagging a regression.
- `scripts/check_bench_thresholds.py` reads the freshly generated `benchmarks/latest.json` + `ladder_latest.json`, compares them with the baseline, and fails CI when any metric deviates beyond the configured tolerance.
- To update the baseline:
  1. Run the full suite locally, inspect the new artifacts, and confirm they look healthy.
  2. Edit `benchmarks/baseline.json` with the new target numbers and (optionally) updated tolerances.
  3. Commit both the baseline change and the justification in your PR description so reviewers understand the expected shift.

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

## Dashboards & external consumption

- `benchmarks/height_history.jsonl` & `height_history.csv` capture every height benchmark run (timestamp, tag, leaves, block size, averages/stddev for Merkle vs KZG). These files are append-only and ready for ingestion by Grafana/Looker or any warehouse that understands JSONL/CSV.
- `scripts/aggregate_height_metrics.py` turns the history into `height_dashboard.md` (a human-friendly summary) and `height_trend.png` (if `matplotlib` is available). CI calls this script after each height benchmark and uploads both artifacts.
- To visualize locally:

```bash
python scripts/aggregate_height_metrics.py --history benchmarks/height_history.jsonl --out-dir dashboards/
```

- To plot or slice the CSV with Pandas:

```python
import pandas as pd
df = pd.read_csv("benchmarks/height_history.csv")
print(df.groupby("tag")[["merkle_stream_ms_avg", "kzg_stream_ms_avg"]].mean())
```

- Grafana/Looker users can point a file-based data source (or lightweight ingestion job) at `height_history.csv`/`.jsonl` to get trend lines for streaming vs full commitments, RSS deltas, and block counts per run. Include the `metrics_tag` flag in CI (e.g., `--metrics-tag nightly`) to label different hardware pools or branches.

