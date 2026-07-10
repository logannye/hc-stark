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
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import zipfile

import source_tree_identity
import strict_json


RELEASE_SCRIPT_DIR = Path(__file__).resolve().parents[1] / "release"
if str(RELEASE_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_SCRIPT_DIR))
import evidence_runtime  # noqa: E402
import run_crash_matrix  # noqa: E402
import run_fuzz_smoke  # noqa: E402
import build_review_bundle  # noqa: E402
import run_evidenced_command  # noqa: E402


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
FUZZ_RELEASE_MIN_SECONDS = 60
FUZZ_TOOLCHAIN = "nightly-2026-04-15"
FUZZ_CARGO_COMMIT = "eb94155a9a60943bd7b1cb04abec42f5d0de6ddc"
FUZZ_RUSTC_COMMIT = "a5c825cd824ee0ef9463021078a2f464b4cc1a0d"
RELEASE_CARGO_COMMIT = "f2d3ce0bd7f24a49f8f72d9000448f8838c4e850"
RELEASE_RUSTC_COMMIT = "59807616e1fa2540724bfbac14d7976d7e4a3860"
MAX_EVIDENCE_TIMEOUT_SECONDS = 3600
MAX_EVIDENCE_ARTIFACT_BYTES = 256 * 1024 * 1024
MAX_EVIDENCE_STRING_BYTES = 4096
CRASH_PHASE_TEST = (
    "hc-plonky3",
    "bounded_prover::tests::single_checkpoint_phase_from_environment_resumes_to_identical_proof_bytes",
)
CRASH_INTEGRITY_TESTS = {
    "saved_artifact_reuse": (
        "hc-plonky3",
        "bounded_prover::tests::resume_consumes_the_exact_saved_early_phase_artifact",
    ),
    "corrupt_artifact_and_stale_identity": (
        "hc-plonky3",
        "bounded_prover::tests::corrupt_artifact_and_stale_release_fail_closed",
    ),
    "cancellation_retention": (
        "hc-plonky3",
        "bounded_prover::tests::cancellation_retains_only_an_explicitly_resumable_checkpoint",
    ),
    "truncation_and_checksum": (
        "hc-stream",
        "tests::scratch_matrix_round_trips_and_detects_corruption",
    ),
    "path_traversal": (
        "hc-stream",
        "tests::path_traversal_and_unnoted_retention_are_rejected",
    ),
    "symlink_rejection": (
        "hc-stream",
        "tests::symlinked_roots_and_artifacts_fail_closed",
    ),
    "disk_full_resume": (
        "hc-plonky3",
        "bounded_prover::tests::disk_full_failure_retains_a_resumable_checkpoint",
    ),
}
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
    "storage_total_bytes",
    "storage_available_bytes",
    "scratch_directory_mode",
    "scratch_owned_by_runner",
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
DEVICE_IDENTITY = re.compile(r"^[0-9]{1,10}:[0-9]{1,10}$")
MOUNT_OPTION = re.compile(r"^[a-z0-9_.=-]{1,64}$")
TOOL_FIRST_LINE = {
    "cargo": re.compile(
        r"^cargo ([0-9]+\.[0-9]+\.[0-9]+(?:-nightly)?) "
        r"\(([0-9a-f]{9}) ([0-9]{4}-[0-9]{2}-[0-9]{2})\)$"
    ),
    "rustc": re.compile(
        r"^rustc ([0-9]+\.[0-9]+\.[0-9]+(?:-nightly)?) "
        r"\(([0-9a-f]{9}) ([0-9]{4}-[0-9]{2}-[0-9]{2})\)$"
    ),
}

COMMON_RUNTIME_REPORT_KEYS = {
    "release_sha",
    "source_tree_sha256",
    "dependency_lock_sha256",
    "rust_toolchain_sha256",
    "profile",
    "partial",
    "environment_policy",
    "environment_policy_sha256",
    "cargo_identity",
    "rustc_identity",
    "tool_identity_file",
    "tool_identity_bytes",
    "tool_identity_sha256",
}
CRASH_REPORT_KEYS = COMMON_RUNTIME_REPORT_KEYS | {
    "schema_version",
    "build_profile",
    "case_timeout_seconds",
    "all_executed_cases_passed",
    "complete_for_release",
    "execution_boundary",
    "cases",
}
FUZZ_REPORT_KEYS = COMMON_RUNTIME_REPORT_KEYS | {
    "schema_version",
    "toolchain",
    "rustc_version",
    "cargo_fuzz_version",
    "cargo_fuzz_identity",
    "execution_boundary",
    "fuzz_dependency_lock_sha256",
    "seconds_per_target",
    "startup_timeout_seconds",
    "release_eligible",
    "all_targets_passed",
    "targets",
}
CRASH_CASE_BASE_KEYS = {
    "case",
    "command",
    "exit_status",
    "timed_out",
    "timeout_seconds",
    "duration_ms",
    "log_file",
    "log_bytes",
    "log_sha256",
    "test_execution",
}
CRASH_CHECKPOINT_KEYS = CRASH_CASE_BASE_KEYS | {
    "phase",
    "selected_environment",
    "observed_phase",
    "proof_blake3_hex",
    "reference_proof_blake3_hex",
    "proof_bytes_equal",
}
CRASH_DISK_FULL_KEYS = CRASH_CASE_BASE_KEYS | {
    "selected_environment",
    "disk_full_contract",
    "disk_full_contract_verified",
    "disk_full_enospc_observed",
    "proof_blake3_hex",
    "reference_proof_blake3_hex",
    "proof_bytes_equal",
}
FUZZ_TARGET_KEYS = {
    "target",
    "command",
    "exit_status",
    "timed_out",
    "timeout_seconds",
    "duration_ms",
    "log_file",
    "log_bytes",
    "log_sha256",
    "smoke_seed_count",
    "smoke_corpus_sha256",
    "smoke_corpus",
    "target_marker",
    "artifacts",
    "libfuzzer_done",
    "done_executed_units",
    "libfuzzer_elapsed_seconds",
    "executed_units",
    "peak_rss_mb",
}
TOOL_IDENTITY_RECORD_KEYS = {
    "schema_version",
    "release_sha",
    "source_tree_sha256",
    "dependency_lock_sha256",
    "rust_toolchain_sha256",
    "execution_profile",
    "toolchain",
    "environment_policy_sha256",
    "cargo_identity",
    "rustc_identity",
    "cargo_version_command",
    "rustc_version_command",
}


def lower_hex(value: object, length: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) == length
        and all(character in "0123456789abcdef" for character in value)
    )


def exact_int(value: object, expected: int | None = None) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and (expected is None or value == expected)
    )


def type_sensitive_equal(left: object, right: object) -> bool:
    try:
        return json.dumps(
            left, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ) == json.dumps(
            right, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        )
    except (TypeError, ValueError):
        return False


def bounded_string(value: object, *, maximum: int = MAX_EVIDENCE_STRING_BYTES) -> bool:
    if not isinstance(value, str) or not value or "\x00" in value:
        return False
    try:
        return len(value.encode("utf-8")) <= maximum
    except UnicodeEncodeError:
        return False


def stable_file_identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_mode,
        details.st_nlink,
        details.st_uid,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )


def canonical_device_identity(value: object) -> bool:
    if not isinstance(value, str) or DEVICE_IDENTITY.fullmatch(value) is None:
        return False
    major, minor = value.split(":", 1)
    return all(
        str(int(component)) == component and int(component) <= 2**32 - 1
        for component in (major, minor)
    )


def read_bounded_file(path: Path, *, maximum: int) -> bytes:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise ValueError(f"evidence file is unavailable: {path}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size < 0
        or before.st_size > maximum
    ):
        raise ValueError(f"evidence file is unsafe or oversized: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stable_file_identity(opened) != stable_file_identity(before)
        ):
            raise ValueError(f"evidence file identity changed: {path}")
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining > 0:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as error:
        raise ValueError(f"evidence file disappeared during validation: {path}") from error
    if (
        len(payload) > maximum
        or len(payload) != before.st_size
        or stable_file_identity(after) != stable_file_identity(before)
    ):
        raise ValueError(f"evidence file changed during validation: {path}")
    return payload


def bounded_file_sha256(path: Path) -> str:
    try:
        before = os.lstat(path)
    except OSError as error:
        raise ValueError(f"evidence file is unavailable: {path}") from error
    if (
        stat.S_ISLNK(before.st_mode)
        or not stat.S_ISREG(before.st_mode)
        or before.st_size < 0
        or before.st_size > MAX_EVIDENCE_ARTIFACT_BYTES
    ):
        raise ValueError(f"evidence file is unsafe or oversized: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    digest = hashlib.sha256()
    total = 0
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or stable_file_identity(opened) != stable_file_identity(before)
        ):
            raise ValueError(f"evidence file identity changed: {path}")
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_EVIDENCE_ARTIFACT_BYTES:
                raise ValueError(f"evidence file is oversized: {path}")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    try:
        after = os.lstat(path)
    except OSError as error:
        raise ValueError(f"evidence file disappeared during validation: {path}") from error
    if total != before.st_size or stable_file_identity(after) != stable_file_identity(
        before
    ):
        raise ValueError(f"evidence file changed during validation: {path}")
    return digest.hexdigest()


def parse_tool_version(
    value: object,
    *,
    executable_name: str,
    expected_release: str,
    expected_commit: str,
) -> bool:
    if not bounded_string(value, maximum=64 * 1024):
        return False
    lines = value.splitlines()
    if not lines:
        return False
    first = TOOL_FIRST_LINE[executable_name].fullmatch(lines[0])
    if (
        first is None
        or first.group(1) != expected_release
        or first.group(2) != expected_commit[:9]
    ):
        return False
    keyed: dict[str, str] = {}
    for line in lines[1:]:
        if ": " not in line:
            continue
        key, raw = line.split(": ", 1)
        if key in keyed:
            return False
        keyed[key] = raw
    return (
        keyed.get("release") == expected_release
        and keyed.get("commit-hash") == expected_commit
        and bounded_string(keyed.get("host"), maximum=256)
        and (
            executable_name != "rustc"
            or keyed.get("binary") == "rustc"
        )
    )


def tool_version_host(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    hosts = [line.removeprefix("host: ") for line in value.splitlines() if line.startswith("host: ")]
    return hosts[0] if len(hosts) == 1 and bounded_string(hosts[0], maximum=256) else None


def expected_crash_command(
    name: str, cargo_executable: str = "cargo"
) -> list[str] | None:
    if name.startswith("checkpoint_"):
        package, test_name = CRASH_PHASE_TEST
    else:
        spec = CRASH_INTEGRITY_TESTS.get(name)
        if spec is None:
            return None
        package, test_name = spec
    command = [
        cargo_executable,
        "test",
        "-p",
        package,
        "--lib",
        "--release",
        "--locked",
    ]
    if package == "hc-plonky3":
        command.extend(["--features", "fault-injection"])
    command.extend([test_name, "--", "--exact", "--nocapture"])
    return command


def parse_fuzz_summary(payload: bytes) -> dict[str, int | bool] | None:
    return run_fuzz_smoke.parse_libfuzzer_summary(payload)


def _tool_identity_valid(
    value: object,
    *,
    executable_name: str,
    expected_release: str,
    expected_commit: str,
) -> bool:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "version"}:
        return False
    path = value.get("path")
    version = value.get("version")
    return (
        bounded_string(path)
        and Path(path).is_absolute()
        and ".." not in Path(path).parts
        and Path(path).as_posix() == path
        and Path(path).name == executable_name
        and lower_hex(value.get("sha256"), 64)
        and parse_tool_version(
            version,
            executable_name=executable_name,
            expected_release=expected_release,
            expected_commit=expected_commit,
        )
    )


def _simple_tool_identity_valid(
    value: object, *, executable_name: str, exact_version: str
) -> bool:
    return (
        isinstance(value, dict)
        and set(value) == {"path", "sha256", "version"}
        and bounded_string(value.get("path"))
        and Path(str(value.get("path"))).is_absolute()
        and Path(str(value.get("path"))).name == executable_name
        and lower_hex(value.get("sha256"), 64)
        and value.get("version") == exact_version
    )


def validate_runtime_identity(
    report: dict[str, object],
    release_sha: str,
    *,
    root: Path = ROOT,
    cargo_release: str,
    cargo_commit: str,
    rustc_release: str,
    rustc_commit: str,
) -> list[str]:
    failures: list[str] = []
    try:
        expected_source_tree = source_tree_identity.source_tree_sha256(
            root, release_sha
        )
        expected_lock = evidence_runtime.commit_file_sha256(
            root, release_sha, "Cargo.lock"
        )
        expected_toolchain = evidence_runtime.commit_file_sha256(
            root, release_sha, "rust-toolchain.toml"
        )
    except ValueError as error:
        return [f"runtime source identity could not be recomputed: {error}"]
    expected_environment = evidence_runtime.environment_policy()
    if (
        report.get("release_sha") != release_sha
        or report.get("source_tree_sha256") != expected_source_tree
        or report.get("dependency_lock_sha256") != expected_lock
        or report.get("rust_toolchain_sha256") != expected_toolchain
        or report.get("partial") is not False
        or not type_sensitive_equal(
            report.get("environment_policy"), expected_environment
        )
        or report.get("environment_policy_sha256")
        != evidence_runtime.canonical_json_sha256(expected_environment)
    ):
        failures.append("runtime source/environment identity is incomplete or skewed")
    if not _tool_identity_valid(
        report.get("cargo_identity"),
        executable_name="cargo",
        expected_release=cargo_release,
        expected_commit=cargo_commit,
    ):
        failures.append("runtime Cargo identity is incomplete or unpinned")
    if not _tool_identity_valid(
        report.get("rustc_identity"),
        executable_name="rustc",
        expected_release=rustc_release,
        expected_commit=rustc_commit,
    ):
        failures.append("runtime rustc identity is incomplete or unpinned")
    cargo_identity = report.get("cargo_identity")
    rustc_identity = report.get("rustc_identity")
    cargo_host = tool_version_host(
        cargo_identity.get("version") if isinstance(cargo_identity, dict) else None
    )
    rustc_host = tool_version_host(
        rustc_identity.get("version") if isinstance(rustc_identity, dict) else None
    )
    try:
        anchor = evidence_runtime.toolchain_anchor(
            root,
            release_sha,
            execution_profile="fuzz" if cargo_release.endswith("-nightly") else "release",
            host=str(cargo_host),
        )
    except ValueError as error:
        failures.append(f"runtime toolchain provenance is unanchored: {error}")
    else:
        if (
            cargo_host is None
            or rustc_host != cargo_host
            or not isinstance(cargo_identity, dict)
            or not isinstance(rustc_identity, dict)
            or cargo_identity.get("sha256") != anchor["cargo_sha256"]
            or rustc_identity.get("sha256") != anchor["rustc_sha256"]
        ):
            failures.append("runtime tool executable digests do not match committed anchors")
    return failures


def validate_tool_identity_artifact(
    artifacts: list[tuple[Path, dict[str, object]]],
    report: dict[str, object],
    *,
    role: str,
    expected_file: str,
    execution_profile: str,
    toolchain: str,
    cargo_version_arguments: list[str],
    rustc_version_arguments: list[str],
) -> list[str]:
    matches = [(path, raw) for path, raw in artifacts if raw.get("role") == role]
    if len(matches) != 1:
        return [f"tool identity artifact role must occur exactly once: {role}"]
    path, descriptor = matches[0]
    try:
        payload = read_bounded_file(path, maximum=1024 * 1024)
        record = json.loads(payload)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return [f"tool identity artifact is malformed: {error}"]
    digest = hashlib.sha256(payload).hexdigest()
    cargo_identity = report.get("cargo_identity")
    rustc_identity = report.get("rustc_identity")
    cargo_path = (
        cargo_identity.get("path") if isinstance(cargo_identity, dict) else None
    )
    rustc_path = (
        rustc_identity.get("path") if isinstance(rustc_identity, dict) else None
    )
    expected_record = {
        "schema_version": 1,
        "release_sha": report.get("release_sha"),
        "source_tree_sha256": report.get("source_tree_sha256"),
        "dependency_lock_sha256": report.get("dependency_lock_sha256"),
        "rust_toolchain_sha256": report.get("rust_toolchain_sha256"),
        "execution_profile": execution_profile,
        "toolchain": toolchain,
        "environment_policy_sha256": report.get("environment_policy_sha256"),
        "cargo_identity": cargo_identity,
        "rustc_identity": rustc_identity,
        "cargo_version_command": [cargo_path, *cargo_version_arguments],
        "rustc_version_command": [rustc_path, *rustc_version_arguments],
    }
    if (
        not isinstance(record, dict)
        or set(record) != TOOL_IDENTITY_RECORD_KEYS
        or not exact_int(record.get("schema_version"), 1)
        or not type_sensitive_equal(record, expected_record)
        or payload != evidence_runtime.pretty_json_bytes(expected_record)
        or report.get("tool_identity_file") != expected_file
        or path.name != expected_file
        or not exact_int(report.get("tool_identity_bytes"), len(payload))
        or report.get("tool_identity_sha256") != digest
        or descriptor.get("sha256") != digest
    ):
        return ["tool identity artifact is incomplete, noncanonical, or skewed"]
    return []


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
    if not isinstance(value, dict) or not BENCHMARK_REPORT_REQUIRED_FIELDS.issubset(
        value
    ):
        return False
    if not set(value).issubset(
        BENCHMARK_REPORT_REQUIRED_FIELDS | {"failure_diagnostic"}
    ):
        return False
    if (
        not exact_int(value.get("schema_version"), 1)
        or value.get("scope") != "full_pipeline"
        or value.get("mode") not in {"baseline", "bounded"}
        or not lower_hex(value.get("benchmark_session_id"), 32)
        or value.get("dependency_profile") != "tinyzkp-p3-goldilocks-v1"
        or not lower_hex(value.get("workload_manifest_digest_hex"), 64)
        or not lower_hex(value.get("normalized_manifest_digest_hex"), 64)
        or value.get("verification_succeeded") is not True
        or not exact_int(value.get("exit_status"), 0)
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
        or not isinstance(value.get("storage_total_bytes"), int)
        or isinstance(value.get("storage_total_bytes"), bool)
        or not 0 < value["storage_total_bytes"] <= 2**64 - 1
        or not isinstance(value.get("storage_available_bytes"), int)
        or isinstance(value.get("storage_available_bytes"), bool)
        or not 0 < value["storage_available_bytes"] <= value["storage_total_bytes"]
        or not isinstance(value.get("scratch_directory_mode"), int)
        or isinstance(value.get("scratch_directory_mode"), bool)
        or value["scratch_directory_mode"] != 0o700
        or value.get("scratch_owned_by_runner") is not True
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
            "failure_diagnostic" not in value or value.get("failure_diagnostic") is None
        )
    )


def read_object(path: Path) -> dict[str, object]:
    value = strict_json.loads(
        read_bounded_file(path, maximum=16 * 1024 * 1024)
    )
    if not isinstance(value, dict):
        raise ValueError(f"evidence file must contain an object: {path}")
    return value


def safe_evidence_file(root: Path, raw: object) -> Path:
    if not isinstance(raw, str) or not raw:
        raise ValueError("evidence path must be a non-empty repository-relative string")
    relative = Path(raw)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"unsafe evidence path: {raw}")
    resolved_root = root.resolve()
    current = resolved_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"evidence path contains a symlink: {raw}")
    resolved = (resolved_root / relative).resolve()
    if not resolved.is_relative_to(resolved_root) or not resolved.is_file():
        raise ValueError(f"evidence file is missing or unsafe: {raw}")
    return resolved


def safe_artifact(root: Path, raw: object) -> tuple[Path, dict[str, object]]:
    if not isinstance(raw, dict) or set(raw) != {"role", "path", "sha256"}:
        raise ValueError("artifact descriptor must be an object")
    if not bounded_string(raw.get("role"), maximum=256):
        raise ValueError("artifact role must be a bounded non-empty string")
    relative = raw.get("path")
    digest = raw.get("sha256")
    if not bounded_string(relative) or not lower_hex(digest, 64):
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
    actual = bounded_file_sha256(path)
    if actual != digest:
        raise ValueError(f"evidence artifact digest mismatch: {relative}")
    return path, raw


def verify_external_signature(
    artifacts: list[tuple[Path, dict[str, object]]],
    *,
    root: Path,
    release_sha: str,
    claim_role: str,
    signature_role: str,
    signer_id: object,
    purpose: str,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    claim = roles.get(claim_role)
    bundle = roles.get(signature_role)
    if claim is None or bundle is None:
        return [f"external signature roles are incomplete for {purpose}"]
    if not bounded_string(signer_id, maximum=256):
        return [f"external signer ID is missing for {purpose}"]
    try:
        trust = evidence_runtime.release_trust(root, release_sha)
        signers = trust.get("external_signers")
        matches = [
            item
            for item in signers
            if isinstance(item, dict) and item.get("id") == signer_id
        ] if isinstance(signers, list) else []
        if len(matches) != 1:
            raise ValueError("external signer is not explicitly allowlisted")
        signer = matches[0]
        if set(signer) != {
            "id",
            "purposes",
            "certificate_identity_regexp",
            "oidc_issuer",
        }:
            raise ValueError("external signer allowlist schema is not closed")
        purposes = signer.get("purposes")
        identity = signer.get("certificate_identity_regexp")
        issuer = signer.get("oidc_issuer")
        if (
            not isinstance(purposes, list)
            or purpose not in purposes
            or len(purposes) != len(set(purposes))
            or not bounded_string(identity, maximum=2048)
            or not bounded_string(issuer, maximum=2048)
        ):
            raise ValueError("external signer is not allowlisted for this purpose")
        cosign = os.environ.get("TINYZKP_COSIGN") or shutil.which("cosign")
        if not cosign:
            raise ValueError("anchored cosign executable is unavailable")
        completed = evidence_runtime.run_anchored_cosign(
            root,
            release_sha,
            cosign,
            [
                "verify-blob",
                "--bundle",
                str(bundle),
                "--certificate-identity-regexp",
                str(identity),
                "--certificate-oidc-issuer",
                str(issuer),
                str(claim),
            ],
        )
        if completed.returncode != 0:
            raise ValueError(
                "external detached signature verification failed: "
                + completed.stdout[-1000:]
            )
    except (OSError, ValueError, subprocess.TimeoutExpired) as error:
        return [f"external truth claim is unauthenticated: {error}"]
    return []


def validate_review(
    metadata: dict[str, object],
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
    expected_scope: str,
    source_tree_sha256: str | None = None,
    *,
    root: Path = ROOT,
) -> list[str]:
    failures: list[str] = []
    if not lower_hex(source_tree_sha256, 64):
        failures.append("reviewed source-tree identity is missing")
    if not isinstance(metadata.get("reviewer"), str) or not metadata.get("reviewer"):
        failures.append("reviewer identity is missing")
    if not isinstance(metadata.get("completed_at"), str) or not metadata.get(
        "completed_at"
    ):
        failures.append("review completion time is missing")
    if metadata.get("review_scope") != expected_scope:
        failures.append("review scope is missing or incorrect")
    if set(metadata) != {"reviewer", "completed_at", "review_scope", "signer_id"}:
        failures.append("review metadata schema is not closed")
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    missing = {
        "review_bundle",
        "review_report",
        "remediation_ledger",
    } - set(roles)
    if missing:
        failures.extend(
            f"review evidence role is missing: {role}" for role in sorted(missing)
        )
        return failures
    try:
        ledger = read_object(roles["remediation_ledger"])
        manifest, manifest_bytes = build_review_bundle.verify_bundle(
            roles["review_bundle"], root=root, release_sha=release_sha
        )
    except (OSError, ValueError, json.JSONDecodeError, zipfile.BadZipFile) as error:
        return failures + [f"review evidence is malformed: {error}"]
    bundle_sha256 = hashlib.sha256(roles["review_bundle"].read_bytes()).hexdigest()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    expected_ledger_keys = {
        "schema_version",
        "release_sha",
        "profile",
        "review_scope",
        "completed_at",
        "reviewer",
        "reviewer_independent",
        "review_bundle_sha256",
        "review_manifest_sha256",
        "source_tree_sha256",
        "review_report_sha256",
        "findings",
        "signer_id",
    }
    if (
        set(ledger) != expected_ledger_keys
        or not exact_int(ledger.get("schema_version"), 1)
        or ledger.get("release_sha") != release_sha
        or ledger.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or ledger.get("review_scope") != expected_scope
        or ledger.get("completed_at") != metadata.get("completed_at")
        or ledger.get("reviewer") != metadata.get("reviewer")
        or ledger.get("reviewer_independent") is not True
        or ledger.get("review_report_sha256")
        != hashlib.sha256(roles["review_report"].read_bytes()).hexdigest()
        or ledger.get("review_bundle_sha256") != bundle_sha256
        or ledger.get("review_manifest_sha256") != manifest_sha256
        or ledger.get("source_tree_sha256") != source_tree_sha256
        or not exact_int(manifest.get("schema_version"), 2)
        or manifest.get("release_sha") != release_sha
        or manifest.get("source_tree_sha256") != source_tree_sha256
        or manifest.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or manifest.get("plonky3_version") != "0.6.1"
    ):
        failures.append(
            "review evidence is incomplete, bundle-skewed, or release-skewed"
        )
    findings = ledger.get("findings")
    if not isinstance(findings, list):
        return failures + ["review finding ledger is missing"]
    finding_ids: set[str] = set()
    for finding in findings:
        if not isinstance(finding, dict) or set(finding) != {
            "id",
            "severity",
            "status",
            "reviewer_verified",
        }:
            failures.append("review finding is malformed")
            continue
        finding_id = finding.get("id")
        if (
            not isinstance(finding_id, str)
            or not finding_id
            or finding_id in finding_ids
        ):
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
    if ledger.get("signer_id") != metadata.get("signer_id"):
        failures.append("review ledger signer identity is missing or skewed")
    failures.extend(
        verify_external_signature(
            artifacts,
            root=root,
            release_sha=release_sha,
            claim_role="remediation_ledger",
            signature_role="review_signature",
            signer_id=metadata.get("signer_id"),
            purpose=f"review:{expected_scope}",
        )
    )
    return failures


def valid_disk_full_contract(
    value: object, release_sha: str, source_tree_sha256: object
) -> bool:
    keys = {
        "schema_version",
        "created_by",
        "mount_path",
        "mount_device",
        "parent_device",
        "filesystem",
        "mount_options",
        "total_bytes",
        "available_bytes_before",
        "max_total_bytes",
        "owner_uid",
        "directory_mode",
        "release_sha",
        "source_tree_sha256",
        "sentinel_file",
        "sentinel_sha256",
    }
    if not isinstance(value, dict) or set(value) != keys:
        return False
    mount_path = value.get("mount_path")
    mount_options = value.get("mount_options")
    total_bytes = value.get("total_bytes")
    available_bytes = value.get("available_bytes_before")
    owner_uid = value.get("owner_uid")
    return (
        exact_int(value.get("schema_version"), 1)
        and value.get("created_by") == "tinyzkp-run-crash-matrix"
        and bounded_string(mount_path)
        and Path(mount_path).is_absolute()
        and ".." not in Path(mount_path).parts
        and Path(mount_path).as_posix() == mount_path
        and bounded_string(value.get("mount_device"), maximum=32)
        and canonical_device_identity(value.get("mount_device"))
        and bounded_string(value.get("parent_device"), maximum=32)
        and canonical_device_identity(value.get("parent_device"))
        and value.get("mount_device") != value.get("parent_device")
        and value.get("filesystem") in {"ext4", "tmpfs"}
        and isinstance(mount_options, list)
        and 4 <= len(mount_options) <= 32
        and all(isinstance(option, str) and option for option in mount_options)
        and all(MOUNT_OPTION.fullmatch(option) is not None for option in mount_options)
        and mount_options == sorted(set(mount_options))
        and run_crash_matrix.required_mount_options_present(mount_options)
        and exact_int(total_bytes)
        and run_crash_matrix.DISK_FULL_MIN_BYTES
        <= total_bytes
        <= run_crash_matrix.DISK_FULL_MAX_BYTES
        and exact_int(available_bytes)
        and 16 * 1024 * 1024 <= available_bytes <= total_bytes
        and exact_int(
            value.get("max_total_bytes"), run_crash_matrix.DISK_FULL_MAX_BYTES
        )
        and exact_int(owner_uid)
        and 0 <= owner_uid <= 2**32 - 1
        and exact_int(value.get("directory_mode"), 0o700)
        and value.get("release_sha") == release_sha
        and value.get("source_tree_sha256") == source_tree_sha256
        and value.get("sentinel_file") == run_crash_matrix.DISK_FULL_SENTINEL
        and lower_hex(value.get("sentinel_sha256"), 64)
    )


def validate_crash_matrix(
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
    *,
    root: Path = ROOT,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["crash_matrix"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"crash matrix evidence is incomplete: {error}"]
    failures = validate_runtime_identity(
        report,
        release_sha,
        root=root,
        cargo_release="1.95.0",
        cargo_commit=RELEASE_CARGO_COMMIT,
        rustc_release="1.95.0",
        rustc_commit=RELEASE_RUSTC_COMMIT,
    )
    failures.extend(
        validate_tool_identity_artifact(
            artifacts,
            report,
            role="crash_tool_identity",
            expected_file=run_crash_matrix.TOOL_IDENTITY_FILE,
            execution_profile="release",
            toolchain=run_crash_matrix.RELEASE_TOOLCHAIN,
            cargo_version_arguments=["-Vv"],
            rustc_version_arguments=["-Vv"],
        )
    )
    case_timeout = report.get("case_timeout_seconds")
    boundary = report.get("execution_boundary")
    if (
        set(report) != CRASH_REPORT_KEYS
        or not exact_int(report.get("schema_version"), 1)
        or report.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or report.get("build_profile") != "release"
        or report.get("complete_for_release") is not True
        or report.get("all_executed_cases_passed") is not True
        or not exact_int(case_timeout)
        or not 0 < case_timeout <= MAX_EVIDENCE_TIMEOUT_SECONDS
        or not isinstance(boundary, dict)
        or set(boundary)
        != {
            "kind",
            "abi_version",
            "source_write_allowed",
            "descriptor_execution",
            "writable_paths",
        }
        or boundary.get("kind") != "landlock-write-deny-v1"
        or not exact_int(boundary.get("abi_version"))
        or boundary.get("abi_version", 0) < 3
        or boundary.get("source_write_allowed") is not False
        or boundary.get("descriptor_execution") is not True
        or not isinstance(boundary.get("writable_paths"), list)
        or not {"cargo-target", "tmp"}.issubset(boundary.get("writable_paths", []))
    ):
        failures.append("crash matrix identity or completion status is invalid")
    cargo_identity = report.get("cargo_identity")
    cargo_path = (
        cargo_identity.get("path") if isinstance(cargo_identity, dict) else None
    )
    cases = report.get("cases")
    if not isinstance(cases, list):
        return failures + ["crash matrix case list is missing"]
    expected = {f"checkpoint_{phase}" for phase in CRASH_PHASES} | CRASH_INTEGRITY_CASES
    actual: set[str] = set()
    role_entries = {raw.get("role"): (path, raw) for path, raw in artifacts}
    observed_log_paths: set[Path] = set()
    observed_log_digests: set[str] = set()
    for case in cases:
        if not isinstance(case, dict) or not isinstance(case.get("case"), str):
            failures.append("crash matrix contains a malformed case")
            continue
        name = case["case"]
        if name in actual:
            failures.append(f"crash matrix case is duplicated: {name}")
        actual.add(name)
        expected_command = (
            expected_crash_command(name, str(cargo_path))
            if isinstance(cargo_path, str)
            else None
        )
        log_entry = role_entries.get(f"crash_log_{name}")
        log_path, log_descriptor = log_entry if log_entry is not None else (None, {})
        payload: bytes | None = None
        if log_path is not None:
            if log_path in observed_log_paths:
                failures.append(f"crash matrix reuses a log artifact path: {name}")
            observed_log_paths.add(log_path)
            try:
                payload = read_bounded_file(
                    log_path, maximum=MAX_EVIDENCE_ARTIFACT_BYTES
                )
            except (OSError, ValueError) as error:
                failures.append(f"crash matrix log is unreadable: {name}: {error}")
        if payload is not None:
            actual_log_digest = hashlib.sha256(payload).hexdigest()
            if actual_log_digest in observed_log_digests:
                failures.append(f"crash matrix reuses log artifact bytes: {name}")
            observed_log_digests.add(actual_log_digest)
        expected_test_name = (
            CRASH_PHASE_TEST[1]
            if name.startswith("checkpoint_")
            else (
                CRASH_INTEGRITY_TESTS[name][1] if name in CRASH_INTEGRITY_TESTS else ""
            )
        )
        parsed_execution = (
            run_crash_matrix.parse_test_execution(payload, expected_test_name)
            if payload is not None and expected_test_name
            else None
        )
        expected_case_keys = (
            CRASH_CHECKPOINT_KEYS
            if name.startswith("checkpoint_")
            else (
                CRASH_DISK_FULL_KEYS
                if name == "disk_full_resume"
                else CRASH_CASE_BASE_KEYS
            )
        )
        if (
            set(case) != expected_case_keys
            or not exact_int(case.get("exit_status"), 0)
            or case.get("timed_out") is not False
            or not exact_int(case.get("timeout_seconds"), case_timeout)
            or case.get("command") != expected_command
            or not exact_int(case.get("duration_ms"))
            or case.get("duration_ms", 0) <= 0
            or case.get("duration_ms", 0) > case_timeout * 1000 + 10_000
            or not type_sensitive_equal(case.get("test_execution"), parsed_execution)
            or not run_crash_matrix.test_execution_passed(parsed_execution)
        ):
            failures.append(f"crash matrix case did not run exactly once: {name}")
        digest = case.get("log_sha256")
        if (
            not lower_hex(digest, 64)
            or log_path is None
            or payload is None
            or case.get("log_file") != f"{name}.log"
            or log_path.name != f"{name}.log"
            or not exact_int(case.get("log_bytes"), len(payload))
            or digest != hashlib.sha256(payload).hexdigest()
            or log_descriptor.get("sha256") != digest
        ):
            failures.append(f"crash matrix case log artifact is mismatched: {name}")
        if name.startswith("checkpoint_"):
            phase = name.removeprefix("checkpoint_")
            parsed_marker = (
                run_crash_matrix.parse_checkpoint_marker(payload)
                if payload is not None
                else None
            )
            marker_fields = {
                field: case.get(field)
                for field in (
                    "observed_phase",
                    "proof_blake3_hex",
                    "reference_proof_blake3_hex",
                    "proof_bytes_equal",
                )
            }
            if (
                case.get("phase") != phase
                or case.get("selected_environment")
                != {"TINYZKP_SINGLE_CRASH_PHASE": phase}
                or parsed_marker is None
                or not type_sensitive_equal(marker_fields, parsed_marker)
                or parsed_marker.get("observed_phase") != phase
                or parsed_marker.get("proof_bytes_equal") is not True
            ):
                failures.append(
                    f"checkpoint phase/proof evidence is incomplete: {name}"
                )
        elif name == "disk_full_resume":
            parsed_marker = (
                run_crash_matrix.parse_disk_full_marker(payload)
                if payload is not None
                else None
            )
            marker_fields = {
                field: case.get(field)
                for field in (
                    "disk_full_enospc_observed",
                    "proof_blake3_hex",
                    "reference_proof_blake3_hex",
                    "proof_bytes_equal",
                )
            }
            if (
                case.get("selected_environment")
                != {"TINYZKP_DISK_FULL_SCRATCH": "<runner-owned-disk-full-scratch>"}
                or case.get("disk_full_contract_verified") is not True
                or parsed_marker is None
                or not type_sensitive_equal(marker_fields, parsed_marker)
                or parsed_marker.get("disk_full_enospc_observed") is not True
                or parsed_marker.get("proof_bytes_equal") is not True
                or not valid_disk_full_contract(
                    case.get("disk_full_contract"),
                    release_sha,
                    report.get("source_tree_sha256"),
                )
            ):
                failures.append(
                    "disk-full crash/resume evidence is incomplete or unsafe"
                )
    for name in sorted(expected - actual):
        failures.append(f"required crash matrix case is missing: {name}")
    for name in sorted(actual - expected):
        failures.append(f"unknown crash matrix case: {name}")
    return failures


def validate_fuzz_smoke(
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
    *,
    root: Path = ROOT,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["fuzz_smoke"])
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"fuzz smoke evidence is incomplete: {error}"]
    failures = validate_runtime_identity(
        report,
        release_sha,
        root=root,
        cargo_release="1.97.0-nightly",
        cargo_commit=FUZZ_CARGO_COMMIT,
        rustc_release="1.97.0-nightly",
        rustc_commit=FUZZ_RUSTC_COMMIT,
    )
    failures.extend(
        validate_tool_identity_artifact(
            artifacts,
            report,
            role="fuzz_tool_identity",
            expected_file=run_fuzz_smoke.TOOL_IDENTITY_FILE,
            execution_profile="fuzz",
            toolchain=FUZZ_TOOLCHAIN,
            cargo_version_arguments=["-Vv"],
            rustc_version_arguments=["-Vv"],
        )
    )
    seconds_per_target = report.get("seconds_per_target")
    startup_timeout = report.get("startup_timeout_seconds")
    try:
        expected_fuzz_lock = evidence_runtime.commit_file_sha256(
            root, release_sha, "fuzz/Cargo.lock"
        )
    except ValueError as error:
        failures.append(f"fuzz dependency identity could not be recomputed: {error}")
        expected_fuzz_lock = None
    cargo_identity = report.get("cargo_identity")
    cargo_host = tool_version_host(
        cargo_identity.get("version") if isinstance(cargo_identity, dict) else None
    )
    try:
        expected_cargo_fuzz = evidence_runtime.cargo_fuzz_anchor(
            root, release_sha, str(cargo_host)
        )
    except ValueError:
        expected_cargo_fuzz = None
    boundary = report.get("execution_boundary")
    if (
        set(report) != FUZZ_REPORT_KEYS
        or not exact_int(report.get("schema_version"), 1)
        or report.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or report.get("toolchain") != FUZZ_TOOLCHAIN
        or report.get("rustc_version")
        != (
            report.get("rustc_identity", {}).get("version")
            if isinstance(report.get("rustc_identity"), dict)
            else None
        )
        or report.get("cargo_fuzz_version") != "cargo-fuzz 0.13.2"
        or not _simple_tool_identity_valid(
            report.get("cargo_fuzz_identity"),
            executable_name="cargo-fuzz",
            exact_version="cargo-fuzz 0.13.2",
        )
        or report.get("cargo_fuzz_identity", {}).get("sha256")
        != expected_cargo_fuzz
        or report.get("fuzz_dependency_lock_sha256") != expected_fuzz_lock
        or not exact_int(seconds_per_target)
        or seconds_per_target < FUZZ_RELEASE_MIN_SECONDS
        or not exact_int(startup_timeout)
        or not 0 < startup_timeout <= MAX_EVIDENCE_TIMEOUT_SECONDS
        or report.get("release_eligible") is not True
        or report.get("all_targets_passed") is not True
        or not isinstance(boundary, dict)
        or set(boundary)
        != {
            "kind",
            "abi_version",
            "source_write_allowed",
            "descriptor_execution",
            "writable_roots",
            "target_scoped_writes",
        }
        or boundary.get("kind") != "landlock-write-deny-v1"
        or not exact_int(boundary.get("abi_version"))
        or boundary.get("abi_version", 0) < 3
        or boundary.get("source_write_allowed") is not False
        or boundary.get("descriptor_execution") is not True
        or boundary.get("writable_roots") != ["cargo-target", "tmp"]
        or boundary.get("target_scoped_writes")
        != ["execution-corpus", "artifacts"]
    ):
        failures.append("fuzz smoke identity or completion status is invalid")
    cargo_fuzz_identity = report.get("cargo_fuzz_identity")
    cargo_fuzz_path = (
        cargo_fuzz_identity.get("path")
        if isinstance(cargo_fuzz_identity, dict)
        else None
    )
    targets = report.get("targets")
    if not isinstance(targets, list):
        return failures + ["fuzz smoke target list is missing"]
    actual: set[str] = set()
    role_entries = {raw.get("role"): (path, raw) for path, raw in artifacts}
    observed_log_paths: set[Path] = set()
    observed_log_digests: set[str] = set()
    observed_command_roots: set[Path] = set()
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
            [Path(command[index]) for index in (3, 4)]
            if isinstance(command, list)
            and len(command) > 4
            and all(
                isinstance(command[index], str) and command[index] for index in (3, 4)
            )
            else []
        )
        execution_path, corpus_path = paths if len(paths) == 2 else (None, None)
        artifact_option = (
            command[9] if isinstance(command, list) and len(command) > 9 else None
        )
        artifact_path = (
            Path(artifact_option.removeprefix("-artifact_prefix=").rstrip("/"))
            if isinstance(artifact_option, str)
            and artifact_option.startswith("-artifact_prefix=")
            and artifact_option.removeprefix("-artifact_prefix=").rstrip("/")
            else None
        )
        execution_raw = command[3] if isinstance(command, list) and len(command) > 3 else None
        corpus_raw = command[4] if isinstance(command, list) and len(command) > 4 else None
        artifact_raw = (
            artifact_option.removeprefix("-artifact_prefix=").rstrip("/")
            if isinstance(artifact_option, str)
            and artifact_option.startswith("-artifact_prefix=")
            else None
        )
        command_roots = (
            {
                execution_path.parent.parent,
                corpus_path.parent.parent,
                artifact_path.parent.parent,
            }
            if execution_path is not None
            and corpus_path is not None
            and artifact_path is not None
            else set()
        )
        common_root = next(iter(command_roots)) if len(command_roots) == 1 else None
        if common_root is not None:
            observed_command_roots.add(common_root)
        command_valid = (
            isinstance(command, list)
            and isinstance(cargo_fuzz_path, str)
            and isinstance(seconds_per_target, int)
            and not isinstance(seconds_per_target, bool)
            and command[:3] == [cargo_fuzz_path, "run", name]
            and len(command) == 11
            and execution_path is not None
            and not execution_path.is_absolute()
            and bounded_string(execution_raw)
            and execution_path.as_posix() == execution_raw
            and "\\" not in execution_raw
            and execution_path.name == name
            and execution_path.parent.name == "execution-corpus"
            and ".." not in execution_path.parts
            and corpus_path is not None
            and not corpus_path.is_absolute()
            and bounded_string(corpus_raw)
            and corpus_path.as_posix() == corpus_raw
            and "\\" not in corpus_raw
            and corpus_path.name == name
            and corpus_path.parent.name == "smoke-corpus"
            and ".." not in corpus_path.parts
            and command[5] == "--"
            and isinstance(command[6], str)
            and command[6].startswith("-max_total_time=")
            and command[6].removeprefix("-max_total_time=").isdigit()
            and int(command[6].removeprefix("-max_total_time="))
            == report.get("seconds_per_target")
            and command[7] == "-rss_limit_mb=2048"
            and isinstance(command[8], str)
            and command[8].startswith("-timeout=")
            and command[8].removeprefix("-timeout=").isdigit()
            and int(command[8].removeprefix("-timeout="))
            == max(10, seconds_per_target)
            and artifact_path is not None
            and not artifact_path.is_absolute()
            and bounded_string(artifact_raw)
            and artifact_path.as_posix() == artifact_raw
            and "\\" not in artifact_raw
            and artifact_path.name == name
            and artifact_path.parent.name == "artifacts"
            and ".." not in artifact_path.parts
            and command[10] == "-print_final_stats=1"
            and common_root is not None
            and common_root != Path(".")
        )
        try:
            expected_corpus = run_fuzz_smoke.expected_corpus_descriptor(name)
        except (OSError, ValueError, json.JSONDecodeError):
            expected_corpus = None
        seed_count = target.get("smoke_seed_count")
        digest = target.get("smoke_corpus_sha256")
        log_digest = target.get("log_sha256")
        log_entry = role_entries.get(f"fuzz_log_{name}")
        log_path, log_descriptor = log_entry if log_entry is not None else (None, {})
        log_payload: bytes | None = None
        if log_path is not None:
            if log_path in observed_log_paths:
                failures.append(f"fuzz smoke reuses a log artifact path: {name}")
            observed_log_paths.add(log_path)
            try:
                log_payload = read_bounded_file(
                    log_path, maximum=MAX_EVIDENCE_ARTIFACT_BYTES
                )
            except (OSError, ValueError) as error:
                failures.append(f"fuzz smoke log is unreadable: {name}: {error}")
        if log_payload is not None:
            actual_log_digest = hashlib.sha256(log_payload).hexdigest()
            if actual_log_digest in observed_log_digests:
                failures.append(f"fuzz smoke reuses log artifact bytes: {name}")
            observed_log_digests.add(actual_log_digest)
        parsed_summary = (
            parse_fuzz_summary(log_payload) if log_payload is not None else None
        )
        expected_marker = (
            run_fuzz_smoke.expected_target_marker(
                name, str(expected_corpus.get("corpus_sha256"))
            )
            if isinstance(expected_corpus, dict)
            else None
        )
        parsed_marker = (
            run_fuzz_smoke.parse_target_marker(log_payload)
            if log_payload is not None
            else None
        )
        if (
            set(target) != FUZZ_TARGET_KEYS
            or not exact_int(target.get("exit_status"), 0)
            or target.get("timed_out") is not False
            or not exact_int(
                target.get("timeout_seconds"),
                seconds_per_target + startup_timeout
                if isinstance(seconds_per_target, int)
                and not isinstance(seconds_per_target, bool)
                and isinstance(startup_timeout, int)
                and not isinstance(startup_timeout, bool)
                else None,
            )
            or target.get("artifacts") != []
            or not exact_int(target.get("duration_ms"))
            or target["duration_ms"] <= 0
            or target.get("duration_ms", 0)
            > target.get("timeout_seconds", 0) * 1000 + 10_000
            or not exact_int(target.get("log_bytes"))
            or target["log_bytes"] <= 0
            or not command_valid
            or expected_corpus is None
            or not type_sensitive_equal(target.get("smoke_corpus"), expected_corpus)
            or not exact_int(
                seed_count,
                expected_corpus.get("seed_count")
                if isinstance(expected_corpus, dict)
                else None,
            )
            or digest
            != (
                expected_corpus.get("corpus_sha256")
                if isinstance(expected_corpus, dict)
                else None
            )
            or not isinstance(log_digest, str)
            or len(log_digest) != 64
            or any(character not in "0123456789abcdef" for character in log_digest)
            or log_path is None
            or target.get("log_file") != f"{name}.log"
            or log_path.name != f"{name}.log"
            or not exact_int(
                target.get("log_bytes"),
                len(log_payload) if log_payload is not None else None,
            )
            or log_digest
            != (
                hashlib.sha256(log_payload).hexdigest()
                if log_payload is not None
                else None
            )
            or log_descriptor.get("sha256") != log_digest
            or parsed_summary is None
            or expected_marker is None
            or parsed_marker is None
            or not type_sensitive_equal(target.get("target_marker"), expected_marker)
            or not type_sensitive_equal(parsed_marker, expected_marker)
            or target.get("libfuzzer_done") is not True
            or target.get("libfuzzer_done")
            != (parsed_summary.get("libfuzzer_done") if parsed_summary else None)
            or target.get("libfuzzer_elapsed_seconds")
            != (
                parsed_summary.get("libfuzzer_elapsed_seconds")
                if parsed_summary
                else None
            )
            or not exact_int(target.get("libfuzzer_elapsed_seconds"))
            or target.get("libfuzzer_elapsed_seconds", 0)
            < (
                seconds_per_target
                if isinstance(seconds_per_target, int)
                and not isinstance(seconds_per_target, bool)
                else FUZZ_RELEASE_MIN_SECONDS
            )
            or not exact_int(target.get("duration_ms"))
            or target.get("duration_ms", 0) + 2000
            < target.get("libfuzzer_elapsed_seconds", 0) * 1000
            or not exact_int(
                target.get("done_executed_units"),
                parsed_summary.get("done_executed_units") if parsed_summary else None,
            )
            or not exact_int(
                target.get("executed_units"),
                parsed_summary.get("executed_units") if parsed_summary else None,
            )
            or not type_sensitive_equal(
                target.get("done_executed_units"), target.get("executed_units")
            )
            or target.get("executed_units", 0) <= 0
            or target.get("peak_rss_mb")
            != (parsed_summary.get("peak_rss_mb") if parsed_summary else None)
            or not exact_int(target.get("peak_rss_mb"))
            or not 0 < target.get("peak_rss_mb", 0) <= 2048
        ):
            failures.append(f"fuzz smoke target did not pass reproducibly: {name}")
    for name in sorted(FUZZ_TARGETS - actual):
        failures.append(f"required fuzz smoke target is missing: {name}")
    for name in sorted(actual - FUZZ_TARGETS):
        failures.append(f"unknown fuzz smoke target: {name}")
    if len(observed_command_roots) != 1:
        failures.append("fuzz smoke commands do not share one canonical log root")
    return failures


def validate_test_run_evidence(
    artifacts: list[tuple[Path, dict[str, object]]],
    metadata: dict[str, object],
    release_sha: str,
    *,
    require_release_profile: bool,
    expected_gate: str,
    root: Path = ROOT,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    try:
        report = read_object(roles["test_report"])
        log = roles["test_log"].read_bytes()
    except (KeyError, OSError, ValueError, json.JSONDecodeError) as error:
        return [f"evidenced command artifacts are incomplete: {error}"]
    execution_profile = report.get("execution_profile")
    failures: list[str] = []
    spec = run_evidenced_command.GATES.get(expected_gate)
    expected_metadata_keys = {
        "release_sha",
        "exit_status",
        "execution_profile",
        "command",
        "gate_id",
    } | (
        {"secret_scan_clean", "generated_scan_clean"}
        if expected_gate == "clean_release_source"
        else set()
    )
    tools = report.get("tools")
    logical_command = spec.get("command") if isinstance(spec, dict) else None
    actual_command = report.get("actual_command")
    primary = logical_command[0] if isinstance(logical_command, list) else None
    primary_identity = tools.get(primary) if isinstance(tools, dict) else None
    expected_source_tree = source_tree_identity.source_tree_sha256(root, release_sha)
    expected_lock = evidence_runtime.commit_file_sha256(root, release_sha, "Cargo.lock")
    expected_toolchain = evidence_runtime.commit_file_sha256(
        root, release_sha, "rust-toolchain.toml"
    )
    try:
        reparsed = run_evidenced_command.parse_output(expected_gate, log)
    except (KeyError, UnicodeError, ValueError):
        reparsed = None
    anchored_cargo = True
    if isinstance(tools, dict) and "cargo" in tools:
        cargo_identity = tools.get("cargo")
        host = tool_version_host(
            cargo_identity.get("version")
            if isinstance(cargo_identity, dict)
            else None
        )
        try:
            anchor = evidence_runtime.toolchain_anchor(
                root,
                release_sha,
                execution_profile="release",
                host=str(host),
            )
        except ValueError:
            anchored_cargo = False
        else:
            rustc_identity = tools.get("rustc")
            anchored_cargo = (
                isinstance(cargo_identity, dict)
                and cargo_identity.get("sha256") == anchor["cargo_sha256"]
                and isinstance(rustc_identity, dict)
                and rustc_identity.get("sha256") == anchor["rustc_sha256"]
            )
    expected_tools = {str(primary)} if isinstance(primary, str) else set()
    if primary == "bash":
        expected_tools.update({"cargo", "rustc"})
    if expected_gate == "replacement_sdk_contracts":
        expected_tools.update({"python3", "node", "npm", "wasm-pack"})
    if primary == "cargo":
        expected_tools.add("rustc")
    boundary = report.get("write_boundary")
    anchored_generic_tools = True
    try:
        generic_anchors = evidence_runtime.gate_tool_anchors(root, release_sha)
    except ValueError:
        anchored_generic_tools = False
        generic_anchors = {}
    if isinstance(tools, dict):
        anchored_generic_tools = anchored_generic_tools and all(
            name in {"cargo", "rustc"}
            or generic_anchors.get(name) == identity.get("sha256")
            for name, identity in tools.items()
            if isinstance(identity, dict)
        )
    if (
        set(report)
        != {
            "schema_version",
            "release_sha",
            "source_tree_sha256",
            "dependency_lock_sha256",
            "rust_toolchain_sha256",
            "profile",
            "gate",
            "execution_profile",
            "logical_command",
            "actual_command",
            "descriptor_execution",
            "output_parser",
            "parsed_result",
            "timeout_seconds",
            "timed_out",
            "exit_status",
            "started_at",
            "finished_at",
            "duration_ms",
            "log_bytes",
            "log_sha256",
            "environment_policy",
            "environment_policy_sha256",
            "immutable_source",
            "write_boundary",
            "immutable_file_count",
            "tools",
        }
        or not exact_int(report.get("schema_version"), 2)
        or report.get("release_sha") != release_sha
        or report.get("source_tree_sha256") != expected_source_tree
        or report.get("dependency_lock_sha256") != expected_lock
        or report.get("rust_toolchain_sha256") != expected_toolchain
        or report.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or spec is None
        or report.get("gate") != expected_gate
        or metadata.get("gate_id") != expected_gate
        or set(metadata) != expected_metadata_keys
        or execution_profile != spec.get("profile")
        or (require_release_profile and execution_profile != "release")
        or report.get("logical_command") != logical_command
        or metadata.get("command") != logical_command
        or not isinstance(actual_command, list)
        or not isinstance(primary_identity, dict)
        or actual_command
        != [primary_identity.get("path"), *logical_command[1:]]
        or report.get("output_parser") != spec.get("parser")
        or report.get("descriptor_execution") is not True
        or not type_sensitive_equal(report.get("parsed_result"), reparsed)
        or not isinstance(reparsed, dict)
        or reparsed.get("passed") is not True
        or not exact_int(report.get("timeout_seconds"), spec.get("timeout"))
        or report.get("timed_out") is not False
        or not exact_int(report.get("exit_status"), 0)
        or not exact_int(metadata.get("exit_status"), 0)
        or metadata.get("release_sha") != release_sha
        or metadata.get("execution_profile") != execution_profile
        or not exact_int(report.get("duration_ms"))
        or report.get("duration_ms", 0) <= 0
        or report.get("duration_ms", 0) > report.get("timeout_seconds", 0) * 1000 + 10_000
        or not isinstance(report.get("started_at"), str)
        or not report.get("started_at")
        or not isinstance(report.get("finished_at"), str)
        or not report.get("finished_at")
        or report.get("log_bytes") != len(log)
        or report.get("log_sha256") != hashlib.sha256(log).hexdigest()
        or report.get("immutable_source") is not True
        or not isinstance(boundary, dict)
        or set(boundary) != {
            "kind",
            "abi_version",
            "source_write_allowed",
            "writable_paths",
        }
        or boundary.get("kind") != "landlock-write-deny-v1"
        or not exact_int(boundary.get("abi_version"))
        or boundary.get("abi_version", 0) < 3
        or boundary.get("source_write_allowed") is not False
        or boundary.get("writable_paths") != ["cargo-target", "sdk-work", "tmp"]
        or not exact_int(report.get("immutable_file_count"))
        or report.get("immutable_file_count", 0) <= 0
        or not type_sensitive_equal(
            report.get("environment_policy"), evidence_runtime.environment_policy()
        )
        or report.get("environment_policy_sha256")
        != evidence_runtime.canonical_json_sha256(evidence_runtime.environment_policy())
        or not isinstance(tools, dict)
        or not tools
        or set(tools) != expected_tools
        or not anchored_cargo
        or not anchored_generic_tools
        or any(
            not isinstance(value, dict)
            or set(value) != {"path", "sha256", "version"}
            or not bounded_string(value.get("path"))
            or not Path(str(value.get("path"))).is_absolute()
            or not lower_hex(value.get("sha256"), 64)
            or not bounded_string(value.get("version"), maximum=64 * 1024)
            for value in (tools.values() if isinstance(tools, dict) else [])
        )
    ):
        failures.append("evidenced command report is incomplete or release-skewed")
    if expected_gate == "replacement_sdk_contracts" and not (
        run_evidenced_command.sdk_python_lock_ready(root, release_sha)
    ):
        failures.append("replacement SDK Python dependency evidence is not hash-locked")
    return failures


def validate_partner_evidence(
    artifacts: list[tuple[Path, dict[str, object]]],
    release_sha: str,
    metadata: dict[str, object] | None = None,
    *,
    root: Path = ROOT,
) -> list[str]:
    roles = {descriptor.get("role"): path for path, descriptor in artifacts}
    required = {
        "adapter_result",
        "resource_report",
        "acceptance_record",
    }
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
        not exact_int(adapter.get("schema_version"), 1)
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
        or not exact_int(adapter.get("proof_size_bytes"))
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
    expected_acceptance_keys = {
        "schema_version",
        "release_sha",
        "profile",
        "acceptance_id",
        "partner_id",
        "accepted_at",
        "official_verification",
        "bounded_equals_conventional",
        "witness_data_committed",
        "adapter_result_sha256",
        "resource_report_sha256",
        "signer_id",
    }
    if (
        set(acceptance) != expected_acceptance_keys
        or not exact_int(acceptance.get("schema_version"), 1)
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
            and acceptance.get("acceptance_id") != metadata.get("partner_acceptance_id")
        )
    ):
        failures.append("partner acceptance record is incomplete or release-skewed")
    if metadata is None or acceptance.get("signer_id") != metadata.get("signer_id"):
        failures.append("partner signer identity is missing or skewed")
    failures.extend(
        verify_external_signature(
            artifacts,
            root=root,
            release_sha=release_sha,
            claim_role="acceptance_record",
            signature_role="partner_signature",
            signer_id=metadata.get("signer_id") if metadata else None,
            purpose="partner_acceptance",
        )
    )
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
        not exact_int(report.get("schema_version"), 1)
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
            or (name in expected_urls and payload.get("url") != expected_urls[name])
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
    source_tree_sha256: str | None = None,
) -> list[str]:
    failures: list[str] = []
    if set(gate) != {"kind", "metadata", "artifacts"}:
        failures.append(f"{name}: gate descriptor schema is not closed")
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
    if any(not isinstance(role, str) or not role for role in roles) or len(
        roles
    ) != len(set(roles)):
        failures.append(f"{name}: artifact roles must be unique non-empty strings")
    resolved_paths = [path for path, _ in resolved]
    if len(resolved_paths) != len(set(resolved_paths)):
        failures.append(f"{name}: artifact paths must be unique")

    if expected_kind == "source_scan":
        if (
            metadata.get("secret_scan_clean") is not True
            or metadata.get("generated_scan_clean") is not True
        ):
            failures.append(f"{name}: source scans are not clean")
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_test_run_evidence(
                resolved,
                metadata,
                release_sha,
                require_release_profile=False,
                expected_gate=name,
                root=root,
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
                    expected_gate=name,
                    root=root,
                )
            )
        if name == "crash_resume_and_corruption_suite":
            if (
                metadata.get("exit_status") != 0
                or metadata.get("release_sha") != release_sha
            ):
                failures.append(f"{name}: crash evidence metadata is incomplete")
            failures.extend(
                f"{name}: {failure}"
                for failure in validate_crash_matrix(resolved, release_sha, root=root)
            )
            failures.extend(
                f"{name}: {failure}"
                for failure in validate_fuzz_smoke(resolved, release_sha, root=root)
            )
    elif expected_kind.startswith("resource_"):
        failures.extend(validate_resource_gate(expected_kind, resolved, release_sha))
    elif expected_kind == "independent_reproduction":
        if (
            set(metadata)
            != {
                "release_sha",
                "independent",
                "reproducer",
                "organization",
                "completed_at",
                "signer_id",
            }
            or metadata.get("release_sha") != release_sha
            or metadata.get("independent") is not True
            or not metadata.get("reproducer")
            or not metadata.get("organization")
            or not metadata.get("completed_at")
        ):
            failures.append(f"{name}: independent reproducer metadata is incomplete")
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_independent_reproduction(
                resolved, metadata, release_sha, root=root
            )
        )
    elif expected_kind == "review":
        scope = (
            "plonky3_specialist"
            if name == "plonky3_specialist_review"
            else "implementation"
        )
        if not lower_hex(source_tree_sha256, 64):
            failures.append(f"{name}: reviewed source-tree identity is missing")
        else:
            failures.extend(
                f"{name}: {failure}"
                for failure in validate_review(
                    metadata,
                    resolved,
                    release_sha,
                    scope,
                    source_tree_sha256,
                    root=root,
                )
            )
    elif expected_kind == "partner":
        if (
            set(metadata)
            != {
                "partner_acceptance_id",
                "official_verification",
                "witness_data_committed",
                "bounded_and_conventional",
                "signer_id",
            }
            or not metadata.get("partner_acceptance_id")
            or metadata.get("official_verification") is not True
            or metadata.get("witness_data_committed") is not False
            or metadata.get("bounded_and_conventional") is not True
        ):
            failures.append(f"{name}: partner acceptance contract is incomplete")
        failures.extend(
            f"{name}: {failure}"
            for failure in validate_partner_evidence(
                resolved, release_sha, metadata, root=root
            )
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
            and Path(command[3]).name
            == role_paths.get("signature", Path("missing")).name
            and command[4:8]
            == [
                "--certificate-identity-regexp",
                SIGSTORE_IDENTITY_REGEXP,
                "--certificate-oidc-issuer",
                SIGSTORE_ISSUER,
            ]
            and Path(command[8]).name
            == role_paths.get("checksums", Path("missing")).name
        )
        if (
            metadata.get("signatures_verified") is not True
            or metadata.get("release_sha") != release_sha
            or not isinstance(metadata.get("source_release_sha"), str)
            or not lower_hex(metadata.get("source_tree_sha256"), 64)
            or metadata.get("release_tree_sha256") != metadata.get("source_tree_sha256")
            or metadata.get("evidence_only_delta_verified") is not True
            or not isinstance(metadata.get("evidence_delta_paths"), list)
            or any(
                not isinstance(path, str)
                or not (
                    path == "release/backend-v1-gates.json"
                    or path.startswith("release/evidence/")
                )
                for path in metadata.get("evidence_delta_paths", [])
            )
            or metadata.get("signer_identity_regexp") != SIGSTORE_IDENTITY_REGEXP
            or metadata.get("signer_oidc_issuer") != SIGSTORE_ISSUER
            or not command_valid
            or not exact_int(metadata.get("checksum_entries"))
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
        baseline = (
            read_object(roles["baseline_report"])
            if "baseline_report" in roles
            else None
        )
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
                selected.append(
                    (path, {**descriptor, "role": role.removeprefix(marker)})
                )
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
    *,
    root: Path = ROOT,
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
        if descriptor.get("role")
        not in {"reproduction_record", "reproduction_signature"}
    }
    expected_record_keys = {
        "schema_version",
        "release_sha",
        "profile",
        "independent",
        "reproducer",
        "organization",
        "completed_at",
        "official_verification",
        "workloads",
        "gates",
        "artifact_sha256",
        "signer_id",
    }
    if (
        set(record) != expected_record_keys
        or not exact_int(record.get("schema_version"), 1)
        or record.get("release_sha") != release_sha
        or record.get("profile") != "tinyzkp-p3-goldilocks-v1"
        or record.get("independent") is not True
        or record.get("reproducer") != metadata.get("reproducer")
        or record.get("organization") != metadata.get("organization")
        or record.get("completed_at") != metadata.get("completed_at")
        or record.get("official_verification") is not True
        or set(record.get("workloads", [])) != {"fibonacci", "poseidon2_goldilocks"}
        or set(record.get("gates", [])) != {"one-million", "ten-million"}
        or record.get("artifact_sha256") != expected_artifact_sha256
    ):
        failures.append(
            "independent reproduction record is incomplete or release-skewed"
        )
    for gate_kind in ("resource_one_million", "resource_ten_million"):
        marker = "one_million_" if gate_kind.endswith("one_million") else "ten_million_"
        selected = [
            (
                path,
                {
                    **descriptor,
                    "role": str(descriptor.get("role", "")).removeprefix(marker),
                },
            )
            for path, descriptor in artifacts
            if str(descriptor.get("role", "")).startswith(marker)
        ]
        failures.extend(
            f"{marker.removesuffix('_')}: {failure}"
            for failure in validate_resource_gate(gate_kind, selected, release_sha)
        )
    if record.get("signer_id") != metadata.get("signer_id"):
        failures.append("independent reproduction signer identity is missing or skewed")
    failures.extend(
        verify_external_signature(
            artifacts,
            root=root,
            release_sha=release_sha,
            claim_role="reproduction_record",
            signature_role="reproduction_signature",
            signer_id=metadata.get("signer_id"),
            purpose="independent_reproduction",
        )
    )
    return failures


def validate_review_execution_bindings(
    gates: dict[str, object], release_sha: str, *, root: Path = ROOT
) -> list[str]:
    """Bind signed review inputs to the exact evidence used by this candidate.

    The candidate builder performs the same check, but the publication gate
    must not trust callers to have used that builder. Every expected digest is
    therefore derived again from the final evidence manifest.
    """

    required_gates = {
        "one_million_row_resource_gate",
        "ten_million_row_resource_gate",
        "deterministic_cross_mode_proofs",
        "crash_resume_and_corruption_suite",
        "plonky3_specialist_review",
        "implementation_review_no_high_findings",
    }
    if not required_gates.issubset(gates):
        return []  # Missing gates are reported by the surrounding validator.

    def artifacts(gate_name: str) -> dict[str, dict[str, object]]:
        gate = gates.get(gate_name)
        if not isinstance(gate, dict):
            raise ValueError(f"{gate_name} descriptor is malformed")
        raw_artifacts = gate.get("artifacts")
        if not isinstance(raw_artifacts, list):
            raise ValueError(f"{gate_name} artifact list is missing")
        values: dict[str, dict[str, object]] = {}
        for raw in raw_artifacts:
            if not isinstance(raw, dict):
                raise ValueError(f"{gate_name} artifact descriptor is malformed")
            role = raw.get("role")
            if not isinstance(role, str) or not role or role in values:
                raise ValueError(f"{gate_name} artifact roles are malformed")
            values[role] = raw
        return values

    try:
        specialist = artifacts("plonky3_specialist_review").get("review_bundle")
        implementation = artifacts(
            "implementation_review_no_high_findings"
        ).get("review_bundle")
        if specialist is None or implementation is None:
            raise ValueError("review bundle artifact is missing")
        if specialist.get("sha256") != implementation.get("sha256"):
            raise ValueError("external reviews did not use the same review bundle")
        bundle_path, _ = safe_artifact(root, specialist)
        manifest, _ = build_review_bundle.verify_bundle(
            bundle_path, root=root, release_sha=release_sha
        )
        manifest_files = manifest.get("files")
        if not isinstance(manifest_files, list):
            raise ValueError("review manifest file inventory is missing")
        observed: dict[tuple[str, str], str] = {}
        for raw in manifest_files:
            if not isinstance(raw, dict) or raw.get("origin") != "artifact":
                continue
            category = raw.get("evidence_category")
            role = raw.get("evidence_role")
            digest = raw.get("source_sha256")
            if (
                not isinstance(category, str)
                or not category
                or not isinstance(role, str)
                or not role
                or not lower_hex(digest, 64)
                or (category, role) in observed
            ):
                raise ValueError("review execution-evidence identity is malformed")
            observed[(category, role)] = digest

        expected: dict[tuple[str, str], str] = {}
        one_million = artifacts("one_million_row_resource_gate")
        ten_million = artifacts("ten_million_row_resource_gate")
        for workload in ("fibonacci", "poseidon2"):
            for mode in ("baseline", "candidate"):
                role = f"{workload}_{mode}_report"
                expected[("raw-reports", f"one_million_{role}")] = str(
                    one_million[role]["sha256"]
                )
            role = f"{workload}_candidate_report"
            expected[("raw-reports", f"ten_million_{role}")] = str(
                ten_million[role]["sha256"]
            )
        known_answers = artifacts("deterministic_cross_mode_proofs")
        expected[("known-answers", "known_answer_test_report")] = str(
            known_answers["test_report"]["sha256"]
        )
        expected[("known-answers", "known_answer_test_log")] = str(
            known_answers["test_log"]["sha256"]
        )
        crash = artifacts("crash_resume_and_corruption_suite")
        for role, descriptor in crash.items():
            if role.startswith("crash_"):
                expected[("crash", role)] = str(descriptor["sha256"])
            elif role.startswith("fuzz_"):
                expected[("fuzz", role)] = str(descriptor["sha256"])
        for key, digest in expected.items():
            if observed.get(key) != digest:
                raise ValueError(
                    "review bundle does not contain exact candidate evidence: "
                    f"{key[0]}/{key[1]}"
                )
    except (KeyError, OSError, TypeError, ValueError) as error:
        return [f"review execution evidence is not candidate-bound: {error}"]
    return []


def evidence_failures(evidence: dict[str, object], *, root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    release_sha = evidence.get("release_sha")
    source_release_sha = evidence.get("source_release_sha")
    source_tree_sha256 = evidence.get("source_tree_sha256")
    expected_evidence_keys = {
        "schema_version",
        "status",
        "source_release_sha",
        "release_sha",
        "source_tree_sha256",
        "gates",
    }
    if set(evidence) != expected_evidence_keys:
        problems.append("release evidence schema is not closed")
    if (
        not exact_int(evidence.get("schema_version"), 1)
        or not isinstance(release_sha, str)
        or not release_sha
    ):
        problems.append("release evidence identity is malformed")
        return problems
    if (
        not isinstance(source_release_sha, str)
        or not source_release_sha
        or not lower_hex(source_tree_sha256, 64)
    ):
        problems.append("release source identity is malformed")
        return problems
    verified_release_tree: str | None = None
    verified_delta_paths: list[str] | None = None
    try:
        verified_release_tree, verified_delta_paths = (
            source_tree_identity.verify_evidence_only_transition(
                root,
                source_release_sha,
                release_sha,
                source_tree_sha256,
            )
        )
    except ValueError as error:
        problems.append(f"release source transition could not be verified: {error}")
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        return problems + ["release evidence gate map is missing"]
    missing = set(EXPECTED_KINDS) - set(gates)
    extra = set(gates) - set(EXPECTED_KINDS)
    problems.extend(
        f"required evidence gate is missing: {name}" for name in sorted(missing)
    )
    problems.extend(f"unknown evidence gate: {name}" for name in sorted(extra))
    for name in sorted(set(EXPECTED_KINDS) & set(gates)):
        raw = gates[name]
        if not isinstance(raw, dict):
            problems.append(f"{name}: evidence descriptor is malformed")
            continue
        gate_release_sha = (
            release_sha
            if name == "signed_release_sbom_and_checksums"
            else source_release_sha
        )
        problems.extend(
            validate_gate(
                name,
                raw,
                root=root,
                release_sha=gate_release_sha,
                source_tree_sha256=source_tree_sha256,
            )
        )
    problems.extend(
        validate_review_execution_bindings(
            gates, source_release_sha, root=root
        )
    )
    signed = gates.get("signed_release_sbom_and_checksums")
    signed_metadata = signed.get("metadata") if isinstance(signed, dict) else None
    if isinstance(signed_metadata, dict) and (
        signed_metadata.get("source_release_sha") != source_release_sha
        or signed_metadata.get("source_tree_sha256") != source_tree_sha256
        or signed_metadata.get("release_tree_sha256") != verified_release_tree
        or signed_metadata.get("evidence_delta_paths") != verified_delta_paths
    ):
        problems.append(
            "signed release evidence does not bind the candidate source identity"
        )
    if evidence.get("status") != "ready":
        problems.append("release remains explicitly blocked")
    return problems


def failures(config: dict[str, object], *, root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    if set(config) != {
        "schema_version",
        "release",
        "status",
        "evidence_manifest",
        "policy",
    }:
        problems.append("release gate config schema is not closed")
    if not exact_int(config.get("schema_version"), 2):
        problems.append("release gate config schema_version must be 2")
    evidence_path = config.get("evidence_manifest")
    if not isinstance(evidence_path, str) or not evidence_path:
        return problems + ["release evidence manifest path is missing"]
    try:
        evidence = read_object(safe_evidence_file(root, evidence_path))
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
