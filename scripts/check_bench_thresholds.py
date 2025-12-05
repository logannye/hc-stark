#!/usr/bin/env python3
import json
import math
import pathlib
import sys
from typing import Dict, Any

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read_json(path: pathlib.Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def rel_diff(actual: float, target: float) -> float:
    if math.isclose(target, 0.0):
        return 0.0
    return abs(actual - target) / abs(target)


def check_latest(baseline: Dict[str, Any], latest: Dict[str, Any]) -> Dict[str, float]:
    tolerance = float(baseline.get("tolerance_pct", 0.1))
    metrics = latest.get("metrics", {})
    failures = {}
    for key in ("avg_trace_blocks", "avg_fri_blocks", "avg_duration_ms"):
        target = float(baseline.get(key, 0.0))
        actual = float(metrics.get(key, 0.0))
        diff = rel_diff(actual, target)
        if diff > tolerance:
            failures[f"latest.{key}"] = diff
    return failures


def check_ladder(baseline: Dict[str, Any], ladder: Any) -> Dict[str, float]:
    tolerance = float(baseline.get("tolerance_pct", 0.15))
    targets = {entry["block_size"]: entry for entry in baseline.get("targets", [])}
    failures = {}
    for sample in ladder:
        block = sample["block_size"]
        baseline_entry = targets.get(block)
        if not baseline_entry:
            continue
        for key in ("duration", "trace_blocks", "fri_blocks"):
            target = float(baseline_entry.get(key, 0.0))
            actual = float(sample.get(key, 0.0))
            diff = rel_diff(actual, target)
            if diff > tolerance:
                failures[f"ladder[{block}].{key}"] = diff
    return failures


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: check_bench_thresholds.py benchmarks/latest.json benchmarks/ladder_latest.json",
            file=sys.stderr,
        )
        return 1

    latest_path = ROOT / sys.argv[1]
    ladder_path = ROOT / sys.argv[2]
    baseline_path = ROOT / "benchmarks" / "baseline.json"

    baseline = read_json(baseline_path)
    latest = read_json(latest_path)
    ladder = read_json(ladder_path)

    failures = {}
    failures.update(check_latest(baseline.get("latest", {}), latest))
    failures.update(check_ladder(baseline.get("ladder", {}), ladder))

    if failures:
        print("Benchmark regression detected:")
        for metric, diff in failures.items():
            print(f"  - {metric} deviated by {diff * 100:.1f}%")
        return 2

    print("Benchmark metrics within thresholds.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

