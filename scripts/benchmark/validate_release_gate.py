#!/usr/bin/env python3
"""Validate raw baseline/candidate reports against a named backend-v1 gate."""

from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
import sys


MAX_JSON_BYTES = 1024 * 1024
PROFILE = "tinyzkp-p3-goldilocks-v1"


def read_object(path: Path) -> dict[str, object]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{path} exceeds the 1 MiB report limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def validate_common(
    manifest: dict[str, object],
    baseline: dict[str, object],
    candidate: dict[str, object],
) -> list[str]:
    failures: list[str] = []
    for name, report in (("baseline", baseline), ("candidate", candidate)):
        if report.get("schema_version") != 1:
            failures.append(f"{name} schema_version must be 1")
        if report.get("scope") != "full_pipeline":
            failures.append(f"{name} must be a full_pipeline report")
        if report.get("dependency_profile") != PROFILE:
            failures.append(f"{name} dependency profile mismatch")
        if report.get("verification_succeeded") is not True or report.get("exit_status") != 0:
            failures.append(f"{name} did not complete official verification")
        for field in ("peak_rss_bytes", "scratch_high_water_bytes", "wall_time_ms"):
            value = report.get(field)
            if not isinstance(value, int) or value < 0:
                failures.append(f"{name} {field} must be a non-negative integer")
    for field in ("release_sha", "dependency_profile", "workload_manifest_digest_hex"):
        if baseline.get(field) != candidate.get(field):
            failures.append(f"baseline/candidate {field} mismatch")
    if baseline.get("mode") != "baseline":
        failures.append("baseline mode must be baseline")
    if candidate.get("mode") != "bounded":
        failures.append("candidate mode must be bounded")
    policy = manifest.get("resource_policy")
    if not isinstance(policy, dict):
        failures.append("manifest resource_policy is missing")
    elif isinstance(candidate.get("peak_rss_bytes"), int):
        cap = policy.get("max_resident_bytes")
        if not isinstance(cap, int) or cap <= 0:
            failures.append("manifest resident cap is invalid")
        elif candidate["peak_rss_bytes"] > math.floor(cap * 1.10):
            failures.append("candidate exceeded the configured resident cap by more than 10%")
    return failures


def validate_gate(
    gate: str,
    manifest: dict[str, object],
    baseline: dict[str, object],
    candidate: dict[str, object],
    *,
    preflight_scratch_estimate: int | None = None,
) -> list[str]:
    failures = validate_common(manifest, baseline, candidate)
    rows = manifest.get("logical_rows")
    baseline_rss = baseline.get("peak_rss_bytes")
    candidate_rss = candidate.get("peak_rss_bytes")
    baseline_ms = baseline.get("wall_time_ms")
    candidate_ms = candidate.get("wall_time_ms")
    if gate == "one-million":
        if rows != 1_048_576:
            failures.append("one-million gate requires exactly 1,048,576 logical rows")
        if not isinstance(baseline_rss, int) or not isinstance(candidate_rss, int) or candidate_rss <= 0:
            failures.append("one-million gate requires positive baseline and candidate peak RSS")
        elif baseline_rss / candidate_rss < 4.0:
            failures.append("one-million gate requires at least 4x RAM reduction")
        if not isinstance(baseline_ms, int) or not isinstance(candidate_ms, int) or baseline_ms <= 0:
            failures.append("one-million gate requires positive wall-time measurements")
        elif candidate_ms / baseline_ms > 3.0:
            failures.append("one-million gate requires candidate wall time within 3x baseline")
    elif gate == "ten-million":
        if not isinstance(rows, int) or rows < 10_000_000:
            failures.append("ten-million gate requires at least 10,000,000 logical rows")
        if not isinstance(candidate_rss, int) or candidate_rss > 2 * 1024**3:
            failures.append("ten-million gate requires candidate peak RSS at or below 2 GiB")
        scratch = candidate.get("scratch_high_water_bytes")
        if preflight_scratch_estimate is None or preflight_scratch_estimate <= 0:
            failures.append("ten-million gate requires a positive preflight scratch estimate")
        elif not isinstance(scratch, int) or abs(scratch - preflight_scratch_estimate) > math.ceil(preflight_scratch_estimate * 0.10):
            failures.append("ten-million scratch usage differs from preflight by more than 10%")
    else:
        failures.append(f"unknown release gate: {gate}")
    return failures


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", choices=("one-million", "ten-million"), required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--preflight-scratch-estimate", type=int)
    args = parser.parse_args(argv)
    try:
        failures = validate_gate(
            args.gate,
            read_object(args.manifest),
            read_object(args.baseline),
            read_object(args.candidate),
            preflight_scratch_estimate=args.preflight_scratch_estimate,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        failures = [str(exc)]
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print(f"PASS  {args.gate} backend-v1 resource gate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
