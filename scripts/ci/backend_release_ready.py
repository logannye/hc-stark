#!/usr/bin/env python3
"""Permit backend publication only from hashed, machine-validated evidence.

Human-edited `passed: true` flags are deliberately not accepted. External
reviews and partner acceptance remain human activities, but their reports,
finding ledgers, signatures, and acceptance records must be represented by
the evidence contract below before this gate can pass.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "release" / "backend-v1-gates.json"

EXPECTED_KINDS = {
    "clean_release_source": "source_scan",
    "plonky3_dependency_profile_pinned": "compatibility",
    "official_verifier_fibonacci": "test_run",
    "official_verifier_poseidon2": "test_run",
    "deterministic_cross_mode_proofs": "test_run",
    "one_million_row_resource_gate": "resource_one_million",
    "ten_million_row_resource_gate": "resource_ten_million",
    "independent_resource_reproduction": "independent_reproduction",
    "crash_resume_and_corruption_suite": "test_run",
    "plonky3_specialist_review": "review",
    "implementation_review_no_high_findings": "review",
    "external_design_partner_integration": "partner",
    "replacement_sdk_contracts": "test_run",
    "signed_release_sbom_and_checksums": "signed_release",
    "api_mcp_site_cli_identity_match": "identity_parity",
}
CRASH_PHASES = (
    "trace",
    "trace_lde",
    "trace_commitment",
    "quotient",
    "quotient_lde",
    "quotient_commitment",
    "openings",
    "fri_layer_0",
    "fri_layer_1",
    "fri_layer_2",
    "fri_layer_3",
    "fri_layer_4",
    "fri_layer_5",
    "proof_assembly",
)
CRASH_INTEGRITY_CASES = {
    "saved_artifact_reuse",
    "corrupt_artifact_and_stale_identity",
    "cancellation_retention",
    "truncation_and_checksum",
    "path_traversal",
    "symlink_rejection",
    "disk_full_resume",
}
FUZZ_TARGETS = {
    "workload_manifest_v1",
    "proof_bundle_v1",
    "plonky3_proof_bytes_v1",
    "benchmark_report_v1",
    "checkpoint_manifest_v2",
    "challenger_snapshot_v1",
    "scratch_artifact_header_v1",
    "checkpoint_identity_v2",
    "resume_checkpoint_v2",
}
FUZZ_SMOKE_SEED_LIMIT = 16
BENCHMARK_REPORT_REQUIRED_FIELDS = {
    "schema_version",
    "scope",
    "mode",
    "benchmark_session_id",
    "hardware",
    "logical_cpu_count",
    "total_memory_bytes",
    "operating_system",
    "storage",
    "storage_device",
    "storage_is_rotational",
    "storage_is_nvme",
    "release_sha",
    "dependency_profile",
    "exact_command",
    "normalized_manifest_path",
    "workload_manifest_digest_hex",
    "normalized_manifest_digest_hex",
    "preflight_estimate",
    "cpu_seconds",
    "wall_time_ms",
    "peak_rss_bytes",
    "cgroup_peak_bytes",
    "scratch_high_water_bytes",
    "read_bytes",
    "write_bytes",
    "proof_size_bytes",
    "verification_time_ms",
    "verification_succeeded",
    "exit_status",
}
SIGSTORE_ISSUER = "https://token.actions.githubusercontent.com"
SIGSTORE_IDENTITY_REGEXP = (
    r"^https://github\.com/logannye/hc-stark/\.github/workflows/"
    r"release-backend\.yml@refs/tags/backend-v[^/]+$"
)


def lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def valid_resource_estimate(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "peak_resident_bytes",
        "scratch_high_water_bytes",
        "total_read_bytes",
        "total_write_bytes",
        "phases",
    }:
        return False
    for field in (
        "peak_resident_bytes",
        "scratch_high_water_bytes",
        "total_read_bytes",
        "total_write_bytes",
    ):
        metric = value.get(field)
        if not isinstance(metric, int) or isinstance(metric, bool) or metric < 0:
            return False
    if value["peak_resident_bytes"] == 0 or value["scratch_high_water_bytes"] == 0:
        return False
    phases = value.get("phases")
    return isinstance(phases, list) and all(
        isinstance(phase, dict)
        and set(phase) == {"phase", "read_bytes", "write_bytes"}
        and isinstance(phase.get("phase"), str)
        and bool(phase.get("phase"))
        and all(
            isinstance(phase.get(field), int)
            and not isinstance(phase.get(field), bool)
            and phase.get(field) >= 0
            for field in ("read_bytes", "write_bytes")
        )
        for phase in phases
    )


def valid_benchmark_report_envelope(value: object) -> bool:
    if not isinstance(value, dict) or not BENCHMARK_REPORT_REQUIRED_FIELDS.issubset(value):
        return False
    if not set(value).issubset(BENCHMARK_REPORT_REQUIRED_FIELDS | {"failure_diagnostic"}):
        return False
    if (
        value.get("schema_version") != 1
        or value.get("scope") != "full_pipeline"
        or value.get("mode") not in {"baseline", "bounded"}
        or not lower_hex(value.get("benchmark_session_id"), 32)
        or value.get("dependency_profile") != "tinyzkp-p3-goldilocks-v1"
        or not lower_hex(value.get("workload_manifest_digest_hex"), 64)
        or not lower_hex(value.get("normalized_manifest_digest_hex"), 64)
        or value.get("verification_succeeded") is not True
        or value.get("exit_status") != 0
        or not valid_resource_estimate(value.get("preflight_estimate"))
    ):
        return False
    for field in (
        "hardware",
        "operating_system",
        "storage",
        "storage_device",
        "release_sha",
        "normalized_manifest_path",
    ):
        if not isinstance(value.get(field), str) or not value.get(field):
            return False
    if (
        not isinstance(value.get("logical_cpu_count"), int)
        or isinstance(value.get("logical_cpu_count"), bool)
        or not 0 < value["logical_cpu_count"] <= 2**32 - 1
        or not isinstance(value.get("total_memory_bytes"), int)
        or isinstance(value.get("total_memory_bytes"), bool)
        or not 0 < value["total_memory_bytes"] <= 2**64 - 1
        or not isinstance(value.get("storage_is_rotational"), bool)
        or not isinstance(value.get("storage_is_nvme"), bool)
        or not isinstance(value.get("exact_command"), list)
        or not value.get("exact_command")
        or any(not isinstance(item, str) or not item for item in value["exact_command"])
    ):
        return False
    metrics = (
        "wall_time_ms",
        "peak_rss_bytes",
        "cgroup_peak_bytes",
        "scratch_high_water_bytes",
        "read_bytes",
        "write_bytes",
        "proof_size_bytes",
        "verification_time_ms",
    )
    if any(
        not isinstance(value.get(field), int)
        or isinstance(value.get(field), bool)
        or not 0 <= value[field] <= 2**64 - 1
        for field in metrics
    ):
        return False
    cpu_seconds = value.get("cpu_seconds")
    return (
        isinstance(cpu_seconds, (int, float))
        and not isinstance(cpu_seconds, bool)
        and math.isfinite(cpu_seconds)
        and cpu_seconds >= 0
        and value["wall_time_ms"] > 0
        and value["peak_rss_bytes"] > 0
        and value["cgroup_peak_bytes"] >= value["peak_rss_bytes"]
        and value["proof_size_bytes"] > 0
        and (
            "failure_diagnostic" not in value
            or value.get("failure_diagnostic") is None
        )
    )


def read_object(path: Path) -> dict[str, object]:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"evidence file is missing or unsafe: {path}")
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"evidence file is oversized: {path}")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"evidence file must contain an object: {path}")
    return value


def safe_artifact(root: Path, raw: object) -> tuple[Path, dict[str, object]]:
    if not isinstance(raw, dict):
        raise ValueError("artifact descriptor must be an object")
    relative = raw.get("path")
    digest = raw.get("sha256")
    if not isinstance(relative, str) or not relative or not isinstance(digest, str):
        raise ValueError("artifact path and SHA-256 are required")
    candidate = Path(relative)
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"unsafe evidence path: {relative}")
    unresolved = root / candidate
    current = root
    contains_symlink = False
    for part in candidate.parts:
        current /= part
        if current.is_symlink():
            contains_symlink = True
            break
    path = unresolved.resolve()
    if (
        contains_symlink
        or not path.is_relative_to(root.resolve())
        or not path.is_file()
    ):
        raise ValueError(f"evidence artifact is missing or unsafe: {relative}")
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != digest:
        raise ValueError(f"evidence artifact digest mismatch: {relative}")
    return path, raw


def validate_review(
    metadata: dict[str, object],
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
    expected_scope: str,
) -> list[str]:
    failures: list[str] = []
    if not isinstance(metadata.get("reviewer"), str) or not metadata.get("reviewer"):
        failures.append("reviewer identity is missing")
    if not isinstance(metadata.get("completed_at"), str) or not metadata.get("completed_at"):
        failures.append("review completion time is missing")
    if metadata.get("review_scope") != expected_scope:
        failures.append("review scope is missing or incorrect")
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    missing = {"review_report", "remediation_ledger"} - set(roles)
    if missing:
        failures.extend(
            f"review evidence role is missing: {role}" for role in sorted(missing)
        )
        return failures
    try:
        ledger = read_object(roles["remediation_ledger"])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return failures + [f"review remediation ledger is malformed: {error}"]
    if (
        ledger.get("schema_version") != 1
        or ledger.get("release_sha") != release_sha
        or ledger.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or ledger.get("review_scope") != expected_scope
        or ledger.get("completed_at") != metadata.get("completed_at")
        or ledger.get("reviewer") != metadata.get("reviewer")
        or ledger.get("reviewer_independent") is not True
        or ledger.get("review_report_sha256")
        != hashlib.sha256(roles["review_report"].read_bytes()).hexdigest()
    ):
        failures.append("review remediation ledger is incomplete or release-skewed")
    findings = ledger.get("findings")
    if not isinstance(findings, list):
        return failures + ["review finding ledger is missing"]
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict):
            failures.append("review finding is malformed")
            continue
        finding_id = finding.get("id")
        if not isinstance(finding_id, str) or not finding_id or finding_id in finding_ids:
            failures.append("review finding ID is missing or duplicated")
            continue
        finding_ids.add(finding_id)
        severity = finding.get("severity")
        status = finding.get("status")
        if severity not in {"critical", "high", "medium", "low", "informational"}:
            failures.append("review finding severity is unsupported")
        if status not in {"open", "remediated", "accepted_by_reviewer"}:
            failures.append("review finding status is unsupported")
        if severity in {"critical", "high"} and (
            status != "remediated" or finding.get("reviewer_verified") is not True
        ):
            failures.append("critical/high review finding remains unresolved")
    return failures


def validate_crash_matrix(
    artifacts: list[tuple[Path, dict[str, object]]], release_sha: str
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["crash_matrix"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"crash matrix evidence is incomplete: {error}"]
    failures: list[str] = []
    if report.get("schema_version") != 1:
        failures.append("crash matrix schema version is unsupported")
    if report.get("release_sha") != release_sha:
        failures.append("crash matrix release identity mismatch")
    if report.get("profile") != "tinyzkp-p3-goldilocks-v1":
        failures.append("crash matrix compatibility profile mismatch")
    if report.get("build_profile") != "release":
        failures.append("crash matrix must exercise release binaries")
    if report.get("complete_for_release") is not True:
        failures.append("crash matrix is incomplete for release")
    cases = report.get("cases")
    if not isinstance(cases, list):
        return failures + ["crash matrix case list is missing"]
    expected = {f"checkpoint_{phase}" for phase in CRASH_PHASES} | CRASH_INTEGRITY_CASES
    actual: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("case"), str):
            failures.append("crash matrix contains a malformed case")
            continue
        name = case["case"]
        if name in actual:
            failures.append(f"crash matrix case is duplicated: {name}")
        actual.add(name)
        if case.get("exit_status") != 0 or not isinstance(case.get("command"), list):
            failures.append(f"crash matrix case did not pass reproducibly: {name}")
        digest = case.get("log_sha256")
        if not isinstance(digest, str) or len(digest) != 64:
            failures.append(f"crash matrix case log digest is malformed: {name}")
    for name in sorted(expected - actual):
        failures.append(f"required crash matrix case is missing: {name}")
    for name in sorted(actual - expected):
        failures.append(f"unknown crash matrix case: {name}")
    return failures


def validate_fuzz_smoke(
    artifacts: list[tuple[Path, dict[str, object]]], release_sha: str
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["fuzz_smoke"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"fuzz smoke evidence is incomplete: {error}"]
    failures: list[str] = []
    if (
        report.get("schema_version") != 1
        or report.get("release_sha") != release_sha
        or report.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or report.get("toolchain") != "nightly"
        or not isinstance(report.get("rustc_version"), str)
        or "commit-hash:" not in report["rustc_version"]
        or "release:" not in report["rustc_version"]
        or report.get("cargo_fuzz_version") != "cargo-fuzz 0.13.2"
        or report.get("all_targets_passed") is not True
    ):
        failures.append("fuzz smoke identity or completion status is invalid")
    targets = report.get("targets")
    if not isinstance(targets, list):
        return failures + ["fuzz smoke target list is missing"]
    actual: set[str] = set()
    for target in targets:
        if not isinstance(target, dict) or not isinstance(target.get("target"), str):
            failures.append("fuzz smoke contains a malformed target")
            continue
        name = target["target"]
        if name in actual:
            failures.append(f"fuzz smoke target is duplicated: {name}")
        actual.add(name)
        command = target.get("command")
        paths = (
            [Path(command[index]) for index in (5, 6)]
            if isinstance(command, list)
            and len(command) > 6
            and all(isinstance(command[index], str) and command[index] for index in (5, 6))
            else []
        )
        execution_path, corpus_path = paths if len(paths) == 2 else (None, None)
        artifact_option = command[11] if isinstance(command, list) and len(command) > 11 else None
        artifact_path = (
            Path(artifact_option.removeprefix("-artifact_prefix=").rstrip("/"))
            if isinstance(artifact_option, str)
            and artifact_option.startswith("-artifact_prefix=")
            and artifact_option.removeprefix("-artifact_prefix=").rstrip("/")
            else None
        )
        command_valid = (
            isinstance(command, list)
            and command[:5] == ["cargo", "+nightly", "fuzz", "run", name]
            and len(command) == 13
            and execution_path is not None
            and execution_path.name == name
            and execution_path.parent.name == "execution-corpus"
            and ".." not in execution_path.parts
            and corpus_path is not None
            and corpus_path.name == name
            and corpus_path.parent.name == "smoke-corpus"
            and ".." not in corpus_path.parts
            and command[7] == "--"
            and isinstance(command[8], str)
            and command[8].startswith("-max_total_time=")
            and command[8].removeprefix("-max_total_time=").isdigit()
            and int(command[8].removeprefix("-max_total_time=")) > 0
            and command[9] == "-rss_limit_mb=2048"
            and isinstance(command[10], str)
            and command[10].startswith("-timeout=")
            and command[10].removeprefix("-timeout=").isdigit()
            and int(command[10].removeprefix("-timeout=")) > 0
            and artifact_path is not None
            and artifact_path.name == name
            and artifact_path.parent.name == "artifacts"
            and ".." not in artifact_path.parts
            and command[12] == "-print_final_stats=1"
        )
        seed_count = target.get("smoke_seed_count")
        digest = target.get("smoke_corpus_sha256")
        log_digest = target.get("log_sha256")
        if (
            target.get("exit_status") != 0
            or target.get("artifacts") != []
            or not isinstance(target.get("duration_ms"), int)
            or isinstance(target.get("duration_ms"), bool)
            or target["duration_ms"] <= 0
            or not isinstance(target.get("log_bytes"), int)
            or isinstance(target.get("log_bytes"), bool)
            or target["log_bytes"] <= 0
            or not command_valid
            or not isinstance(seed_count, int)
            or isinstance(seed_count, bool)
            or not 1 <= seed_count <= FUZZ_SMOKE_SEED_LIMIT
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or not isinstance(log_digest, str)
            or len(log_digest) != 64
            or any(character not in "0123456789abcdef" for character in log_digest)
        ):
            failures.append(f"fuzz smoke target did not pass reproducibly: {name}")
    for name in sorted(FUZZ_TARGETS - actual):
        failures.append(f"required fuzz smoke target is missing: {name}")
    for name in sorted(actual - FUZZ_TARGETS):
        failures.append(f"unknown fuzz smoke target: {name}")
    return failures


def validate_test_run_evidence(
    artifacts: list[tuple[Path, dict[str, object]]],
    metadata: dict[str, object],
    release_sha: str,
    *,
    require_release_profile: bool,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["test_report"])
        log = roles["test_log"].read_bytes()
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"evidenced command artifacts are incomplete: {error}"]
    execution_profile = report.get("execution_profile")
    failures: list[str] = []
    if (
        report.get("schema_version") != 1
        or report.get("release_sha") != release_sha
        or report.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or execution_profile not in {"ci", "release"}
        or (require_release_profile and execution_profile != "release")
        or report.get("command") != metadata.get("command")
        or report.get("exit_status") != 0
        or metadata.get("exit_status") != 0
        or metadata.get("release_sha") != release_sha
        or metadata.get("execution_profile") != execution_profile
        or not isinstance(report.get("duration_ms"), int)
        or report.get("duration_ms", -1) < 0
        or not isinstance(report.get("started_at"), str)
        or not report.get("started_at")
        or not isinstance(report.get("finished_at"), str)
        or not report.get("finished_at")
        or report.get("log_bytes") != len(log)
        or report.get("log_sha256") != hashlib.sha256(log).hexdigest()
    ):
        failures.append("evidenced command report is incomplete or release-skewed")
    return failures


def validate_partner_evidence(
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
    metadata: dict[str, object] | None = None,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    required = {"adapter_result", "resource_report", "acceptance_record"}
    missing = required - set(roles)
    if missing:
        return [f"partner evidence role is missing: {role}" for role in sorted(missing)]
    failures: list[str] = []
    try:
        adapter = read_object(roles["adapter_result"])
        report = read_object(roles["resource_report"])
        acceptance = read_object(roles["acceptance_record"])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [f"partner machine evidence is malformed: {error}"]
    if (
        adapter.get("schema_version") != 1
        or adapter.get("mode") != "compare"
        or adapter.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or adapter.get("plonky3_version") != "0.6.1"
        or adapter.get("dependency_lock_sha256")
        != "7a3e859e9d457006e38737f418fdf16f0e538977c23bf9882b4225d43b3db455"
        or adapter.get("release_sha") != release_sha
        or adapter.get("official_verification") is not True
        or adapter.get("bounded_equals_conventional") is not True
        or adapter.get("witness_data_included") is not False
        or not valid_resource_estimate(adapter.get("preflight_estimate"))
        or not isinstance(adapter.get("proof_size_bytes"), int)
        or adapter.get("proof_size_bytes", 0) <= 0
        or not lower_hex(adapter.get("proof_blake3_hex"), 64)
    ):
        failures.append("partner adapter result is incomplete or release-skewed")
    if (
        not valid_benchmark_report_envelope(report)
        or report.get("mode") != "bounded"
        or report.get("release_sha") != release_sha
    ):
        failures.append("partner resource report is incomplete or release-skewed")
    if (
        acceptance.get("schema_version") != 1
        or acceptance.get("release_sha") != release_sha
        or acceptance.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or not isinstance(acceptance.get("acceptance_id"), str)
        or not acceptance.get("acceptance_id")
        or not isinstance(acceptance.get("partner_id"), str)
        or not acceptance.get("partner_id")
        or not isinstance(acceptance.get("accepted_at"), str)
        or not acceptance.get("accepted_at")
        or acceptance.get("official_verification") is not True
        or acceptance.get("bounded_equals_conventional") is not True
        or acceptance.get("witness_data_committed") is not False
        or acceptance.get("adapter_result_sha256")
        != hashlib.sha256(roles["adapter_result"].read_bytes()).hexdigest()
        or acceptance.get("resource_report_sha256")
        != hashlib.sha256(roles["resource_report"].read_bytes()).hexdigest()
        or (
            metadata is not None
            and acceptance.get("acceptance_id")
            != metadata.get("partner_acceptance_id")
        )
    ):
        failures.append("partner acceptance record is incomplete or release-skewed")
    return failures


def validate_identity_evidence(
    artifacts: list[tuple[Path, dict[str, object]]],
    metadata: dict[str, object],
    release_sha: str,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["identity_report"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"release identity report is unavailable: {error}"]
    surfaces = report.get("surfaces")
    expected_surfaces = {"api", "mcp", "site", "cli"}
    if (
        report.get("schema_version") != 1
        or report.get("release_sha") != release_sha
        or report.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or not isinstance(report.get("checked_at"), str)
        or not report.get("checked_at")
        or not isinstance(surfaces, dict)
        or set(surfaces) != expected_surfaces
    ):
        return ["release identity report is incomplete or release-skewed"]

    failures: list[str] = []
    package_versions: set[str] = set()
    report_identities: dict[str, str] = {}
    expected_urls = {
        "site": "https://tinyzkp.com/api/release",
        "api": "https://api.tinyzkp.com/version",
        "mcp": "https://mcp.tinyzkp.com/version",
    }
    for name in sorted(expected_surfaces):
        payload = surfaces.get(name)
        if not isinstance(payload, dict):
            failures.append(f"release identity surface is malformed: {name}")
            continue
        version = payload.get("package_version")
        identity = payload.get("release_sha")
        if (
            payload.get("service") != name
            or identity != release_sha
            or not isinstance(version, str)
            or not version
            or (
                name in expected_urls
                and payload.get("url") != expected_urls[name]
            )
            or (
                name == "cli"
                and (
                    not isinstance(payload.get("artifact"), str)
                    or not payload.get("artifact")
                )
            )
        ):
            failures.append(f"release identity surface is incomplete or skewed: {name}")
            continue
        package_versions.add(version)
        report_identities[name] = identity
    if len(package_versions) != 1:
        failures.append("release package versions do not match across surfaces")
    if metadata.get("identities") != report_identities:
        failures.append("release identity metadata does not match the machine report")
    benchmark = report.get("benchmark")
    if benchmark is not None and (
        not isinstance(benchmark, dict)
        or benchmark.get("release_sha") != release_sha
        or benchmark.get("dependency_profile") != "tinyzkp-p3-goldilocks-v1"
        or benchmark.get("verification_succeeded") is not True
    ):
        failures.append("benchmark release identity is incomplete or skewed")
    return failures


def validate_gate(
    name: str,
    gate: dict[str, object],
    *,
    root: Path,
    release_sha: str,
) -> list[str]:
    failures: list[str] = []
    expected_kind = EXPECTED_KINDS[name]
    if gate.get("kind") != expected_kind:
        failures.append(f"{name}: evidence kind must be {expected_kind}")
    if "passed" in gate:
        failures.append(f"{name}: manual passed booleans are forbidden")
    metadata = gate.get("metadata")
    if not isinstance(metadata, dict):
        metadata = {}
        failures.append(f"{name}: metadata object is missing")
    artifacts = gate.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        return failures + [f"{name}: hashed evidence artifacts are missing"]
    resolved: list[tuple[Path, dict[str, object]]] = []
    for artifact in artifacts:
        try:
            resolved.append(safe_artifact(root, artifact))
        except (OSError, ValueError) as error:
            failures.append(f"{name}: {error}")
    roles = [descriptor.get("role") for _, descriptor in resolved]
    if (
        any(not isinstance(role, str) or not role for role in roles)
        or len(roles) != len(set(roles))
    ):
        failures.append(f"{name}: artifact roles must be unique non-empty strings")

    if expected_kind == "source_scan":
        if metadata.get("secret_scan_clean") is not True or metadata.get("generated_scan_clean") is not True:
            failures.append(f"{name}: source scans are not clean")
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_test_run_evidence(
                resolved, metadata, release_sha, require_release_profile=False
            )
        )
    elif expected_kind in {"compatibility", "test_run"}:
        if name != "crash_resume_and_corruption_suite":
            failures.extend(
                f"{name}: {failure}"
                for failure in validate_test_run_evidence(
                    resolved,
                    metadata,
                    release_sha,
                    require_release_profile=name
                    in {
                        "official_verifier_fibonacci",
                        "official_verifier_poseidon2",
                        "deterministic_cross_mode_proofs",
                    },
                )
            )
        if name == "crash_resume_and_corruption_suite":
            if metadata.get("exit_status") != 0 or metadata.get("release_sha") != release_sha:
                failures.append(f"{name}: crash evidence metadata is incomplete")
            failures.extend(
                f"{name}: {failure}"
                for failure in validate_crash_matrix(resolved, release_sha)
            )
            failures.extend(
                f"{name}: {failure}"
                for failure in validate_fuzz_smoke(resolved, release_sha)
            )
    elif expected_kind.startswith("resource_"):
        failures.extend(validate_resource_gate(expected_kind, resolved, release_sha))
    elif expected_kind == "independent_reproduction":
        if (
            metadata.get("release_sha") != release_sha
            or metadata.get("independent") is not True
            or not metadata.get("reproducer")
            or not metadata.get("organization")
            or not metadata.get("completed_at")
        ):
            failures.append(f"{name}: independent reproducer metadata is incomplete")
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_independent_reproduction(
                resolved, metadata, release_sha
            )
        )
    elif expected_kind == "review":
        scope = (
            "plonky3_specialist"
            if name == "plonky3_specialist_review"
            else "implementation"
        )
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_review(metadata, resolved, release_sha, scope)
        )
    elif expected_kind == "partner":
        if (
            not metadata.get("partner_acceptance_id")
            or metadata.get("official_verification") is not True
            or metadata.get("witness_data_committed") is not False
            or metadata.get("bounded_and_conventional") is not True
        ):
            failures.append(f"{name}: partner acceptance contract is incomplete")
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_partner_evidence(resolved, release_sha, metadata)
        )
    elif expected_kind == "signed_release":
        role_paths = {descriptor.get("role"): path for path, descriptor in resolved}
        roles = set(role_paths)
        command = metadata.get("verification_command")
        command_valid = (
            isinstance(command, list)
            and len(command) == 9
            and all(isinstance(item, str) and item for item in command)
            and Path(command[0]).name == "cosign"
            and command[1:3] == ["verify-blob", "--bundle"]
            and Path(command[3]).name == role_paths.get("signature", Path("missing")).name
            and command[4:8]
            == [
                "--certificate-identity-regexp",
                SIGSTORE_IDENTITY_REGEXP,
                "--certificate-oidc-issuer",
                SIGSTORE_ISSUER,
            ]
            and Path(command[8]).name == role_paths.get("checksums", Path("missing")).name
        )
        if (
            metadata.get("signatures_verified") is not True
            or metadata.get("release_sha") != release_sha
            or metadata.get("signer_identity_regexp") != SIGSTORE_IDENTITY_REGEXP
            or metadata.get("signer_oidc_issuer") != SIGSTORE_ISSUER
            or not command_valid
            or not isinstance(metadata.get("checksum_entries"), int)
            or metadata.get("checksum_entries", 0) < 9
            or not {"sbom", "checksums", "signature"}.issubset(roles)
        ):
            failures.append(f"{name}: signed SBOM/checksum evidence is incomplete")
    elif expected_kind == "identity_parity":
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_identity_evidence(resolved, metadata, release_sha)
        )
    return failures


def validate_single_resource_gate(
    kind: str,
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        manifest = read_object(roles["manifest"])
        candidate = read_object(roles["candidate_report"])
        candidate_normalized = read_object(roles["candidate_normalized_manifest"])
        baseline = read_object(roles["baseline_report"]) if "baseline_report" in roles else None
        baseline_normalized = (
            read_object(roles["baseline_normalized_manifest"])
            if "baseline_report" in roles
            else None
        )
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"resource evidence is incomplete: {error}"]
    benchmark_dir = ROOT / "scripts" / "benchmark"
    if str(benchmark_dir) not in sys.path:
        sys.path.insert(0, str(benchmark_dir))
    import validate_release_gate as resource_gate

    gate_name = "one-million" if kind == "resource_one_million" else "ten-million"
    return resource_gate.validate_gate(
        gate_name,
        manifest,
        baseline,
        candidate,
        expected_release_sha=release_sha,
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    )


def validate_resource_gate(
    kind: str,
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
) -> list[str]:
    failures: list[str] = []
    for prefix, workload_id in (
        ("fibonacci", "fibonacci"),
        ("poseidon2", "poseidon2_goldilocks"),
    ):
        selected: list[tuple[Path, dict[str, object]]] = []
        for path, descriptor in artifacts:
            role = descriptor.get("role")
            marker = f"{prefix}_"
            if isinstance(role, str) and role.startswith(marker):
                selected.append((path, {**descriptor, "role": role.removeprefix(marker)}))
        if not selected:
            failures.append(f"{prefix} fixed-host evidence is missing")
            continue
        roles = {descriptor.get("role"): path for path, descriptor in selected}
        try:
            manifest = read_object(roles["manifest"])
        except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
            failures.append(f"{prefix} workload manifest is unavailable: {error}")
            continue
        if manifest.get("workload_id") != workload_id:
            failures.append(f"{prefix} workload identity is incorrect")
        failures.extend(
            f"{prefix}: {failure}"
            for failure in validate_single_resource_gate(kind, selected, release_sha)
        )
    return failures


def validate_independent_reproduction(
    artifacts: list[tuple[Path, dict[str, object]]],
    metadata: dict[str, object],
    release_sha: str,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        record = read_object(roles["reproduction_record"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"independent reproduction record is unavailable: {error}"]
    failures: list[str] = []
    expected_artifact_sha256 = {
        str(descriptor.get("role")): hashlib.sha256(path.read_bytes()).hexdigest()
        for path, descriptor in artifacts
        if descriptor.get("role") != "reproduction_record"
    }
    if (
        record.get("schema_version") != 1
        or record.get("release_sha") != release_sha
        or record.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or record.get("independent") is not True
        or record.get("reproducer") != metadata.get("reproducer")
        or record.get("organization") != metadata.get("organization")
        or record.get("completed_at") != metadata.get("completed_at")
        or record.get("official_verification") is not True
        or set(record.get("workloads", []))
        != {"fibonacci", "poseidon2_goldilocks"}
        or set(record.get("gates", [])) != {"one-million", "ten-million"}
        or record.get("artifact_sha256") != expected_artifact_sha256
    ):
        failures.append("independent reproduction record is incomplete or release-skewed")
    for gate_kind in ("resource_one_million", "resource_ten_million"):
        marker = "one_million_" if gate_kind.endswith("one_million") else "ten_million_"
        selected = [
            (path, {**descriptor, "role": str(descriptor.get("role", "")).removeprefix(marker)})
            for path, descriptor in artifacts
            if str(descriptor.get("role", "")).startswith(marker)
        ]
        failures.extend(
            f"{marker.removesuffix('_')}: {failure}"
            for failure in validate_resource_gate(gate_kind, selected, release_sha)
        )
    return failures


def evidence_failures(
    evidence: dict[str, object], *, root: Path = ROOT
) -> list[str]:
    problems: list[str] = []
    release_sha = evidence.get("release_sha")
    if evidence.get("schema_version") != 1 or not isinstance(release_sha, str) or not release_sha:
        problems.append("release evidence identity is malformed")
        return problems
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        return problems + ["release evidence gate map is missing"]
    missing = set(EXPECTED_KINDS) - set(gates)
    extra = set(gates) - set(EXPECTED_KINDS)
    problems.extend(f"required evidence gate is missing: {name}" for name in sorted(missing))
    problems.extend(f"unknown evidence gate: {name}" for name in sorted(extra))
    for name in sorted(set(EXPECTED_KINDS) & set(gates)):
        raw = gates[name]
        if not isinstance(raw, dict):
            problems.append(f"{name}: evidence descriptor is malformed")
            continue
        problems.extend(validate_gate(name, raw, root=root, release_sha=release_sha))
    if evidence.get("status") != "ready":
        problems.append("release remains explicitly blocked")
    return problems


def failures(config: dict[str, object], *, root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    if config.get("schema_version") != 2:
        problems.append("release gate config schema_version must be 2")
    evidence_path = config.get("evidence_manifest")
    if not isinstance(evidence_path, str) or not evidence_path:
        return problems + ["release evidence manifest path is missing"]
    try:
        evidence = read_object(root / evidence_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return problems + [f"release evidence manifest is unavailable: {error}"]
    problems.extend(evidence_failures(evidence, root=root))
    if (
        config.get("status") != "ready"
        and "release remains explicitly blocked" not in problems
    ):
        problems.append("release remains explicitly blocked")
    return problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    args = parser.parse_args(argv)
    config = read_object(args.config)
    problems = failures(config)
    if problems:
        for problem in problems:
            print(f"BLOCKED  {problem}", file=sys.stderr)
        return 1
    print("PASS  backend v1 release is ready for publication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
