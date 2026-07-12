#!/usr/bin/env python3
"""Validate raw baseline/candidate reports against a named backend-v1 gate."""

from __future__ import annotations

import argparse
import copy
import json
import math
from pathlib import Path
import sys


MAX_JSON_BYTES = 1024 * 1024
PROFILE = "tinyzkp-p3-goldilocks-v1"
REPORT_REQUIRED_FIELDS = {
    "schema_version", "scope", "mode", "benchmark_session_id", "hardware",
    "physical_logical_cpu_count", "physical_memory_bytes", "effective_cpu_count",
    "effective_cpu_affinity", "effective_memory_max_bytes", "effective_swap_max_bytes",
    "cgroup_v2_path", "operating_system", "storage",
    "storage_device", "effective_storage_device", "storage_is_rotational", "storage_is_nvme",
    "storage_total_bytes", "storage_available_bytes", "scratch_directory_mode",
    "scratch_owned_by_runner",
    "release_sha", "dependency_profile", "exact_command", "normalized_manifest_path",
    "workload_manifest_digest_hex", "normalized_manifest_digest_hex", "preflight_estimate",
    "cpu_seconds", "wall_time_ms", "peak_rss_bytes", "cgroup_peak_bytes", "scratch_high_water_bytes",
    "read_bytes", "write_bytes", "proof_size_bytes", "verification_time_ms",
    "verification_succeeded", "exit_status",
}


def canonical_manifest_digest(manifest: dict[str, object]) -> str:
    try:
        from blake3 import blake3
    except ImportError as error:
        raise ValueError("release validation requires blake3==1.0.9") from error
    encoded = json.dumps(
        manifest,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return blake3(encoded).hexdigest()


def read_object(path: Path) -> dict[str, object]:
    if path.stat().st_size > MAX_JSON_BYTES:
        raise ValueError(f"{path} exceeds the 1 MiB report limit")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def validate_common(
    manifest: dict[str, object],
    baseline: dict[str, object] | None,
    candidate: dict[str, object],
    baseline_normalized: dict[str, object] | None,
    candidate_normalized: dict[str, object] | None,
) -> list[str]:
    failures: list[str] = []
    try:
        expected_manifest_digest = canonical_manifest_digest(manifest)
    except (TypeError, ValueError) as error:
        return [f"manifest cannot be canonically hashed: {error}"]
    reports = [("candidate", candidate, candidate_normalized)]
    if baseline is not None:
        reports.insert(0, ("baseline", baseline, baseline_normalized))
    for name, report, normalized_manifest in reports:
        keys = set(report)
        if not REPORT_REQUIRED_FIELDS.issubset(keys) or not keys.issubset(
            REPORT_REQUIRED_FIELDS | {"failure_diagnostic"}
        ):
            failures.append(f"{name} fields do not match BenchmarkReportV1")
        if report.get("schema_version") != 2:
            failures.append(f"{name} schema_version must be 2")
        if report.get("scope") != "full_pipeline":
            failures.append(f"{name} must be a full_pipeline report")
        session = report.get("benchmark_session_id")
        if (
            not isinstance(session, str)
            or len(session) != 32
            or any(character not in "0123456789abcdef" for character in session)
        ):
            failures.append(f"{name} benchmark session ID is malformed")
        for field in ("hardware", "operating_system", "storage", "storage_device"):
            if not isinstance(report.get(field), str) or not report.get(field):
                failures.append(f"{name} {field} is missing")
        affinity = report.get("effective_cpu_affinity")
        if (
            report.get("effective_cpu_count") != 8
            or not isinstance(affinity, list)
            or len(affinity) != 8
            or any(not isinstance(cpu, int) or isinstance(cpu, bool) or cpu < 0 for cpu in affinity)
            or len(set(affinity)) != 8
        ):
            failures.append(f"{name} release cgroup must expose exactly 8 effective CPUs")
        memory = report.get("effective_memory_max_bytes")
        if (
            not isinstance(memory, int)
            or isinstance(memory, bool)
            or not 15 * 1024**3 <= memory <= 17 * 1024**3
        ):
            failures.append(f"{name} release cgroup is not in the 16-GiB memory class")
        if report.get("effective_swap_max_bytes") != 0:
            failures.append(f"{name} release cgroup swap must be disabled")
        physical_cpus = report.get("physical_logical_cpu_count")
        if not isinstance(physical_cpus, int) or isinstance(physical_cpus, bool) or physical_cpus < 8:
            failures.append(f"{name} physical CPU inventory is missing or below 8 CPUs")
        physical_memory = report.get("physical_memory_bytes")
        if not isinstance(physical_memory, int) or isinstance(physical_memory, bool) or physical_memory < 15 * 1024**3:
            failures.append(f"{name} physical memory inventory is missing or below 15 GiB")
        cgroup_path = report.get("cgroup_v2_path")
        if not isinstance(cgroup_path, str) or not cgroup_path.startswith("/"):
            failures.append(f"{name} cgroup identity is missing")
        if report.get("effective_storage_device") != report.get("storage_device"):
            failures.append(f"{name} effective scratch storage identity mismatch")
        if report.get("storage_is_rotational") is not False:
            failures.append(f"{name} release scratch storage is rotational or unknown")
        if report.get("storage_is_nvme") is not True:
            failures.append(f"{name} release scratch storage is not verified NVMe")
        storage_total = report.get("storage_total_bytes")
        storage_available = report.get("storage_available_bytes")
        if (
            not isinstance(storage_total, int)
            or isinstance(storage_total, bool)
            or storage_total < 500_000_000_000
            or not isinstance(storage_available, int)
            or isinstance(storage_available, bool)
            or storage_available < 500_000_000_000
            or storage_available > storage_total
        ):
            failures.append(
                f"{name} release scratch storage must have at least 500 GB available"
            )
        if report.get("scratch_directory_mode") != 0o700:
            failures.append(f"{name} release scratch directory must have mode 0700")
        if report.get("scratch_owned_by_runner") is not True:
            failures.append(
                f"{name} release scratch directory is not owned by the benchmark runner"
            )
        if report.get("dependency_profile") != PROFILE:
            failures.append(f"{name} dependency profile mismatch")
        if report.get("workload_manifest_digest_hex") != expected_manifest_digest:
            failures.append(f"{name} workload manifest digest mismatch")
        if normalized_manifest is None:
            failures.append(f"{name} normalized manifest artifact is missing")
        else:
            try:
                normalized_digest = canonical_manifest_digest(normalized_manifest)
            except (TypeError, ValueError) as error:
                failures.append(f"{name} normalized manifest cannot be hashed: {error}")
            else:
                if report.get("normalized_manifest_digest_hex") != normalized_digest:
                    failures.append(f"{name} normalized manifest digest mismatch")
            comparable = copy.deepcopy(normalized_manifest)
            source_policy = manifest.get("resource_policy")
            normalized_policy = comparable.get("resource_policy")
            if not isinstance(source_policy, dict) or not isinstance(normalized_policy, dict):
                failures.append(f"{name} normalized manifest policy is missing")
            else:
                normalized_scratch = normalized_policy.get("scratch_dir")
                source_scratch = source_policy.get("scratch_dir")
                if (
                    not isinstance(normalized_scratch, str)
                    or not normalized_scratch
                    or normalized_scratch == source_scratch
                ):
                    failures.append(f"{name} normalized scratch directory is not unique")
                normalized_policy["scratch_dir"] = source_scratch
                if comparable != manifest:
                    failures.append(
                        f"{name} normalized manifest changed fields other than scratch_dir"
                    )
        if not isinstance(report.get("release_sha"), str) or not report.get("release_sha"):
            failures.append(f"{name} release identity is missing")
        if not isinstance(report.get("preflight_estimate"), dict):
            failures.append(f"{name} embedded preflight estimate is missing")
        else:
            estimate = report["preflight_estimate"]
            if set(estimate) != {
                "peak_resident_bytes", "scratch_high_water_bytes", "total_read_bytes",
                "total_write_bytes", "phases",
            }:
                failures.append(f"{name} preflight fields do not match ResourceEstimate")
            for field in (
                "peak_resident_bytes", "scratch_high_water_bytes", "total_read_bytes",
                "total_write_bytes",
            ):
                value = estimate.get(field)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    failures.append(f"{name} preflight {field} must be non-negative")
            phases = estimate.get("phases")
            if not isinstance(phases, list) or any(
                not isinstance(phase, dict)
                or set(phase) != {"phase", "read_bytes", "write_bytes"}
                or not isinstance(phase.get("phase"), str)
                or not phase.get("phase")
                or any(
                    not isinstance(phase.get(field), int)
                    or isinstance(phase.get(field), bool)
                    or phase.get(field) < 0
                    for field in ("read_bytes", "write_bytes")
                )
                for phase in phases
            ):
                failures.append(f"{name} preflight phases are malformed")
        if not isinstance(report.get("exact_command"), list) or not report.get("exact_command"):
            failures.append(f"{name} exact reproduction command is missing")
        elif any(not isinstance(value, str) or not value for value in report["exact_command"]):
            failures.append(f"{name} exact reproduction command is malformed")
        if not isinstance(report.get("normalized_manifest_path"), str) or not report.get(
            "normalized_manifest_path"
        ):
            failures.append(f"{name} normalized manifest path is missing")
        cpu_seconds = report.get("cpu_seconds")
        if (
            not isinstance(cpu_seconds, (int, float))
            or isinstance(cpu_seconds, bool)
            or not math.isfinite(cpu_seconds)
            or cpu_seconds < 0
        ):
            failures.append(f"{name} cpu_seconds must be finite and non-negative")
        for field in ("read_bytes", "write_bytes", "proof_size_bytes", "verification_time_ms"):
            value = report.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                failures.append(f"{name} {field} must be a non-negative integer")
        if report.get("verification_succeeded") is not True or report.get("exit_status") != 0:
            failures.append(f"{name} did not complete official verification")
        for field in (
            "peak_rss_bytes",
            "cgroup_peak_bytes",
            "scratch_high_water_bytes",
            "wall_time_ms",
        ):
            value = report.get(field)
            if not isinstance(value, int) or value < 0:
                failures.append(f"{name} {field} must be a non-negative integer")
        peak_rss = report.get("peak_rss_bytes")
        cgroup_peak = report.get("cgroup_peak_bytes")
        if not isinstance(peak_rss, int) or peak_rss <= 0:
            failures.append(f"{name} peak RSS must be positive")
        if not isinstance(cgroup_peak, int) or cgroup_peak <= 0:
            failures.append(f"{name} cgroup peak must be positive")
        elif isinstance(peak_rss, int) and cgroup_peak < peak_rss:
            failures.append(f"{name} cgroup peak cannot be below process RSS")
    if baseline is not None:
        for field in (
            "release_sha",
            "dependency_profile",
            "workload_manifest_digest_hex",
            "benchmark_session_id",
            "hardware",
            "physical_logical_cpu_count",
            "physical_memory_bytes",
            "effective_cpu_count",
            "effective_cpu_affinity",
            "effective_memory_max_bytes",
            "effective_swap_max_bytes",
            "cgroup_v2_path",
            "operating_system",
            "storage",
            "storage_device",
            "effective_storage_device",
            "storage_is_rotational",
            "storage_is_nvme",
            "storage_total_bytes",
            "storage_available_bytes",
            "scratch_directory_mode",
            "scratch_owned_by_runner",
        ):
            if baseline.get(field) != candidate.get(field):
                failures.append(f"baseline/candidate {field} mismatch")
        if baseline.get("mode") != "baseline":
            failures.append("baseline mode must be baseline")
    if candidate.get("mode") != "bounded":
        failures.append("candidate mode must be bounded")
    policy = manifest.get("resource_policy")
    if not isinstance(policy, dict):
        failures.append("manifest resource_policy is missing")
    elif isinstance(candidate.get("cgroup_peak_bytes"), int):
        cap = policy.get("max_resident_bytes")
        if not isinstance(cap, int) or cap <= 0:
            failures.append("manifest resident cap is invalid")
        elif candidate["cgroup_peak_bytes"] > math.floor(cap * 1.10):
            failures.append("candidate exceeded the configured resident cap by more than 10%")
    return failures


def validate_gate(
    gate: str,
    manifest: dict[str, object],
    baseline: dict[str, object] | None,
    candidate: dict[str, object],
    expected_release_sha: str | None = None,
    baseline_normalized: dict[str, object] | None = None,
    candidate_normalized: dict[str, object] | None = None,
) -> list[str]:
    failures = validate_common(
        manifest,
        baseline,
        candidate,
        baseline_normalized,
        candidate_normalized,
    )
    if expected_release_sha is not None:
        for name, report in (("candidate", candidate), ("baseline", baseline)):
            if report is not None and report.get("release_sha") != expected_release_sha:
                failures.append(f"{name} release identity does not match evidence")
    rows = manifest.get("logical_rows")
    baseline_rss = baseline.get("peak_rss_bytes") if baseline else None
    candidate_rss = candidate.get("peak_rss_bytes")
    baseline_ms = baseline.get("wall_time_ms") if baseline else None
    candidate_ms = candidate.get("wall_time_ms")
    if gate == "one-million":
        if baseline is None:
            failures.append("one-million gate requires a conventional baseline")
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
        if rows != 16_777_216:
            failures.append("ten-million gate requires the frozen 2^24-row workload")
        if not isinstance(candidate_rss, int) or candidate_rss > 2 * 1024**3:
            failures.append("ten-million gate requires candidate peak RSS at or below 2 GiB")
        scratch = candidate.get("scratch_high_water_bytes")
        preflight = candidate.get("preflight_estimate")
        preflight_scratch_estimate = (
            preflight.get("scratch_high_water_bytes") if isinstance(preflight, dict) else None
        )
        if not isinstance(preflight_scratch_estimate, int) or preflight_scratch_estimate <= 0:
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
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--candidate", type=Path, required=True)
    parser.add_argument("--expected-release-sha")
    args = parser.parse_args(argv)
    try:
        baseline = read_object(args.baseline) if args.baseline else None
        candidate = read_object(args.candidate)
        baseline_normalized = read_report_normalized_manifest(baseline) if baseline else None
        candidate_normalized = read_report_normalized_manifest(candidate)
        failures = validate_gate(
            args.gate,
            read_object(args.manifest),
            baseline,
            candidate,
            expected_release_sha=args.expected_release_sha,
            baseline_normalized=baseline_normalized,
            candidate_normalized=candidate_normalized,
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        failures = [str(exc)]
    if failures:
        for failure in failures:
            print(f"FAIL  {failure}", file=sys.stderr)
        return 1
    print(f"PASS  {args.gate} backend-v1 resource gate")
    return 0


def read_report_normalized_manifest(report: dict[str, object]) -> dict[str, object]:
    raw = report.get("normalized_manifest_path")
    if not isinstance(raw, str) or not raw:
        raise ValueError("report normalized manifest path is missing")
    return read_object(Path(raw))


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
