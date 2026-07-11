#!/usr/bin/env python3
"""Issue or verify deterministic PartnerPreflightV1 evidence offline.

This validator never executes the supplied commands. It binds already-created
source, binary, workload, policy, and resource-estimate artifacts by SHA-256.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import sys
from typing import Any

from evidence_common import (
    EXPECTED_VERIFIER,
    MAX_BOUND_ARTIFACT_BYTES,
    PLONKY3_VERSION,
    PROFILE_ID,
    EvidenceError,
    atomic_write_canonical,
    canonical_bytes,
    canonical_sha256,
    canonical_timestamp,
    command_argv,
    compatibility_identity,
    exact_object,
    load_json,
    nonempty_string,
    positive_integer,
    read_regular_bytes,
    safe_id,
    sha256_bytes,
    sha256_hex,
)
import evaluation_qualification


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMPATIBILITY = ROOT / "release" / "plonky3-compatibility-v1.json"
INPUT_SCHEMA = "tinyzkp-partner-preflight-input-v1"
EVIDENCE_SCHEMA = "tinyzkp-partner-preflight-v1"
WORKLOAD_SCHEMA = "tinyzkp-partner-workload-spec-v1"
PROFILE = PROFILE_ID
VERIFIER = EXPECTED_VERIFIER
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")

REQUEST_KEYS = {
    "schema_version",
    "preflight_id",
    "application_id",
    "checked_at",
    "operator_id",
    "inputs",
    "adapter",
    "commands",
    "host",
}
REQUEST_INPUT_KEYS = {
    "qualification_input_file_sha256",
    "qualification_evidence_sha256",
    "workload_spec_sha256",
    "adapter_source_sha256",
    "adapter_artifact_sha256",
    "resource_policy_sha256",
    "resource_estimate_sha256",
}
ADAPTER_KEYS = {"crate_name", "source_revision", "api", "artifact_kind"}
COMMAND_KEYS = {"build", "conventional", "bounded", "verify"}
HOST_KEYS = {
    "host_id",
    "host_fingerprint_sha256",
    "operating_system",
    "architecture",
    "logical_cpus",
    "resident_capacity_bytes",
    "available_scratch_bytes",
    "scratch_medium",
    "cgroup_v2",
}
WORKLOAD_KEYS = {
    "schema_version",
    "workload_id",
    "revision",
    "logical_rows",
    "generator_kind",
    "generator_sha256",
    "profile",
    "plonky3_version",
    "expected_verifier",
    "data_boundary",
}
POLICY_KEYS = {
    "mode",
    "max_resident_bytes",
    "max_scratch_bytes",
    "scratch_dir",
    "max_threads",
    "checkpoint_policy",
}
PREFLIGHT_REPORT_KEYS = {
    "selected_mode",
    "available_scratch_bytes",
    "memory_selection_threshold_bytes",
    "estimate",
}
ESTIMATE_KEYS = {
    "peak_resident_bytes",
    "scratch_high_water_bytes",
    "total_read_bytes",
    "total_write_bytes",
    "phases",
}
PHASE_KEYS = {"phase", "read_bytes", "write_bytes"}
EVIDENCE_KEYS = {
    "schema_version",
    "status",
    "preflight_id",
    "application_id",
    "checked_at",
    "operator_id",
    "compatibility",
    "bound_inputs",
    "workload",
    "adapter",
    "commands",
    "resource_policy",
    "host",
    "resource_estimate",
    "feasibility",
    "preflight_input_sha256",
    "preflight_input_file_sha256",
}
BOUND_INPUT_KEYS = REQUEST_INPUT_KEYS | {
    "adapter_source_bytes",
    "adapter_artifact_bytes",
}
FEASIBILITY_KEYS = {
    "resident_estimate_within_policy",
    "scratch_estimate_within_policy",
    "policy_within_host_capacity",
    "scratch_is_local_nvme",
    "cgroup_v2_available",
    "thread_limit_within_host",
    "commands_reviewed_not_executed",
}
SAFE_DATA_BOUNDARY = evaluation_qualification.SAFE_DATA_BOUNDARY


def _git_revision(value: Any, label: str) -> str:
    if not isinstance(value, str) or GIT_REVISION.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a full lowercase Git commit")
    return value


def _validate_workload_payload(payload: Any) -> dict[str, Any]:
    workload = exact_object(payload, WORKLOAD_KEYS, "partner workload specification")
    if workload.get("schema_version") != WORKLOAD_SCHEMA:
        raise EvidenceError(f"workload schema_version must equal {WORKLOAD_SCHEMA}")
    normalized = {
        "schema_version": WORKLOAD_SCHEMA,
        "workload_id": safe_id(workload.get("workload_id"), "workload.workload_id"),
        "revision": _git_revision(workload.get("revision"), "workload.revision"),
        "logical_rows": positive_integer(
            workload.get("logical_rows"), "workload.logical_rows"
        ),
        "generator_kind": workload.get("generator_kind"),
        "generator_sha256": sha256_hex(
            workload.get("generator_sha256"), "workload.generator_sha256"
        ),
        "profile": workload.get("profile"),
        "plonky3_version": workload.get("plonky3_version"),
        "expected_verifier": workload.get("expected_verifier"),
        "data_boundary": exact_object(
            workload.get("data_boundary"),
            evaluation_qualification.DATA_BOUNDARY_KEYS,
            "workload.data_boundary",
        ),
    }
    rows = normalized["logical_rows"]
    if rows > (1 << 30) or rows & (rows - 1):
        raise EvidenceError(
            "workload.logical_rows must be a power of two no greater than 2^30"
        )
    if normalized["generator_kind"] != "deterministic_non_sensitive":
        raise EvidenceError(
            "workload.generator_kind must be deterministic_non_sensitive"
        )
    if (
        normalized["profile"] != PROFILE
        or normalized["plonky3_version"] != PLONKY3_VERSION
        or normalized["expected_verifier"] != VERIFIER
    ):
        raise EvidenceError("partner workload uses an unsupported profile or verifier")
    if normalized["data_boundary"] != SAFE_DATA_BOUNDARY:
        raise EvidenceError("partner workload data boundary is unsafe")
    return normalized


def _load_and_validate_workload(
    path: Path,
    qualification: dict[str, Any],
) -> tuple[dict[str, Any], bytes]:
    payload, raw = load_json(path, "partner workload specification")
    normalized = _validate_workload_payload(payload)
    qualified_workload = qualification["workload"]
    for field in (
        "workload_id",
        "revision",
        "logical_rows",
        "generator_kind",
        "generator_sha256",
    ):
        if normalized[field] != qualified_workload[field]:
            raise EvidenceError(
                f"partner workload {field} differs from qualification evidence"
            )
    return normalized, raw


def _validate_policy_payload(payload: Any) -> dict[str, Any]:
    policy = exact_object(payload, POLICY_KEYS, "resource policy")
    if policy.get("mode") != "scratch":
        raise EvidenceError("resource policy mode must be scratch")
    max_resident = positive_integer(
        policy.get("max_resident_bytes"), "resource_policy.max_resident_bytes"
    )
    max_scratch = positive_integer(
        policy.get("max_scratch_bytes"), "resource_policy.max_scratch_bytes"
    )
    max_threads = positive_integer(
        policy.get("max_threads"), "resource_policy.max_threads", maximum=1024
    )
    scratch_dir = nonempty_string(
        policy.get("scratch_dir"), "resource_policy.scratch_dir", max_length=1024
    )
    pure = PurePosixPath(scratch_dir)
    if (
        not pure.is_absolute()
        or scratch_dir == "/"
        or ".." in pure.parts
        or str(pure) != scratch_dir
    ):
        raise EvidenceError(
            "resource_policy.scratch_dir must be a normalized absolute non-root path"
        )
    if policy.get("checkpoint_policy") != "retain_on_failure":
        raise EvidenceError(
            "resource policy checkpoint_policy must be retain_on_failure"
        )
    return {
        "mode": "scratch",
        "max_resident_bytes": max_resident,
        "max_scratch_bytes": max_scratch,
        "scratch_dir": scratch_dir,
        "max_threads": max_threads,
        "checkpoint_policy": "retain_on_failure",
    }


def _load_and_validate_policy(path: Path) -> tuple[dict[str, Any], bytes]:
    payload, raw = load_json(path, "resource policy")
    return _validate_policy_payload(payload), raw


def _validate_estimate_payload(payload: Any) -> dict[str, Any]:
    report = exact_object(payload, PREFLIGHT_REPORT_KEYS, "resource estimate report")
    if report.get("selected_mode") != "scratch":
        raise EvidenceError("resource estimate must select scratch mode")
    available = positive_integer(
        report.get("available_scratch_bytes"),
        "resource_estimate.available_scratch_bytes",
    )
    threshold = positive_integer(
        report.get("memory_selection_threshold_bytes"),
        "resource_estimate.memory_selection_threshold_bytes",
    )
    estimate = exact_object(report.get("estimate"), ESTIMATE_KEYS, "resource estimate")
    peak = positive_integer(
        estimate.get("peak_resident_bytes"), "resource_estimate.peak_resident_bytes"
    )
    scratch = positive_integer(
        estimate.get("scratch_high_water_bytes"),
        "resource_estimate.scratch_high_water_bytes",
    )
    reads = estimate.get("total_read_bytes")
    writes = estimate.get("total_write_bytes")
    for value, label in ((reads, "total_read_bytes"), (writes, "total_write_bytes")):
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise EvidenceError(
                f"resource_estimate.{label} must be a non-negative integer"
            )
    phases = estimate.get("phases")
    if not isinstance(phases, list) or len(phases) > 128:
        raise EvidenceError(
            "resource_estimate.phases must be an array of at most 128 entries"
        )
    normalized_phases: list[dict[str, Any]] = []
    for index, phase_value in enumerate(phases):
        phase = exact_object(
            phase_value, PHASE_KEYS, f"resource_estimate.phases[{index}]"
        )
        phase_reads = phase.get("read_bytes")
        phase_writes = phase.get("write_bytes")
        for amount, label in (
            (phase_reads, "read_bytes"),
            (phase_writes, "write_bytes"),
        ):
            if not isinstance(amount, int) or isinstance(amount, bool) or amount < 0:
                raise EvidenceError(
                    f"resource_estimate.phases[{index}].{label} must be a non-negative integer"
                )
        normalized_phases.append(
            {
                "phase": safe_id(
                    phase.get("phase"), f"resource_estimate.phases[{index}].phase"
                ),
                "read_bytes": phase_reads,
                "write_bytes": phase_writes,
            }
        )
    if sum(phase["read_bytes"] for phase in normalized_phases) > reads:
        raise EvidenceError("resource estimate phase reads exceed total_read_bytes")
    if sum(phase["write_bytes"] for phase in normalized_phases) > writes:
        raise EvidenceError("resource estimate phase writes exceed total_write_bytes")
    return {
        "selected_mode": "scratch",
        "available_scratch_bytes": available,
        "memory_selection_threshold_bytes": threshold,
        "estimate": {
            "peak_resident_bytes": peak,
            "scratch_high_water_bytes": scratch,
            "total_read_bytes": reads,
            "total_write_bytes": writes,
            "phases": normalized_phases,
        },
    }


def _load_and_validate_estimate(path: Path) -> tuple[dict[str, Any], bytes]:
    payload, raw = load_json(path, "resource estimate")
    return _validate_estimate_payload(payload), raw


def _validate_adapter(value: Any) -> dict[str, str]:
    adapter = exact_object(value, ADAPTER_KEYS, "adapter")
    if adapter.get("api") != "ResourceBoundedWorkloadV1":
        raise EvidenceError("adapter.api must be ResourceBoundedWorkloadV1")
    if adapter.get("artifact_kind") != "statically_linked_partner_binary":
        raise EvidenceError(
            "adapter.artifact_kind must be statically_linked_partner_binary"
        )
    return {
        "crate_name": safe_id(adapter.get("crate_name"), "adapter.crate_name"),
        "source_revision": _git_revision(
            adapter.get("source_revision"), "adapter.source_revision"
        ),
        "api": "ResourceBoundedWorkloadV1",
        "artifact_kind": "statically_linked_partner_binary",
    }


def _validate_commands(value: Any) -> dict[str, list[str]]:
    commands = exact_object(value, COMMAND_KEYS, "commands")
    normalized = {
        field: command_argv(commands.get(field), f"commands.{field}")
        for field in sorted(COMMAND_KEYS)
    }
    serialized = {tuple(command) for command in normalized.values()}
    if len(serialized) != len(normalized):
        raise EvidenceError(
            "build, conventional, bounded, and verify commands must be distinct"
        )
    return normalized


def _validate_host(value: Any) -> dict[str, Any]:
    host = exact_object(value, HOST_KEYS, "host")
    if host.get("operating_system") != "linux":
        raise EvidenceError("host.operating_system must be linux")
    if host.get("architecture") != "x86_64":
        raise EvidenceError("host.architecture must be x86_64")
    if host.get("scratch_medium") != "local_nvme":
        raise EvidenceError("host.scratch_medium must be local_nvme")
    if host.get("cgroup_v2") is not True:
        raise EvidenceError("host.cgroup_v2 must be true")
    return {
        "host_id": safe_id(host.get("host_id"), "host.host_id"),
        "host_fingerprint_sha256": sha256_hex(
            host.get("host_fingerprint_sha256"), "host.host_fingerprint_sha256"
        ),
        "operating_system": "linux",
        "architecture": "x86_64",
        "logical_cpus": positive_integer(
            host.get("logical_cpus"), "host.logical_cpus", maximum=4096
        ),
        "resident_capacity_bytes": positive_integer(
            host.get("resident_capacity_bytes"), "host.resident_capacity_bytes"
        ),
        "available_scratch_bytes": positive_integer(
            host.get("available_scratch_bytes"), "host.available_scratch_bytes"
        ),
        "scratch_medium": "local_nvme",
        "cgroup_v2": True,
    }


def _bound_file(path: Path, label: str) -> tuple[str, int]:
    raw = read_regular_bytes(path, label, max_bytes=MAX_BOUND_ARTIFACT_BYTES)
    return sha256_bytes(raw), len(raw)


def _expected_feasibility(
    policy: dict[str, Any],
    host: dict[str, Any],
    estimate: dict[str, Any],
) -> dict[str, bool]:
    peak = estimate["estimate"]["peak_resident_bytes"]
    scratch = estimate["estimate"]["scratch_high_water_bytes"]
    return {
        "resident_estimate_within_policy": peak <= policy["max_resident_bytes"],
        "scratch_estimate_within_policy": scratch <= policy["max_scratch_bytes"],
        "policy_within_host_capacity": (
            policy["max_resident_bytes"] <= host["resident_capacity_bytes"]
            and policy["max_scratch_bytes"] <= host["available_scratch_bytes"]
            and policy["max_scratch_bytes"] <= estimate["available_scratch_bytes"]
        ),
        "scratch_is_local_nvme": True,
        "cgroup_v2_available": True,
        "thread_limit_within_host": policy["max_threads"] <= host["logical_cpus"],
        "commands_reviewed_not_executed": True,
    }


def build_evidence(
    *,
    request_payload: Any,
    request_raw: bytes,
    qualification_input_payload: Any,
    qualification_input_raw: bytes,
    qualification_payload: Any,
    qualification_raw: bytes,
    workload_path: Path,
    adapter_source_path: Path,
    adapter_artifact_path: Path,
    policy_path: Path,
    estimate_path: Path,
    compatibility: dict[str, str],
) -> dict[str, Any]:
    request = exact_object(request_payload, REQUEST_KEYS, "partner preflight input")
    if request.get("schema_version") != INPUT_SCHEMA:
        raise EvidenceError(f"schema_version must equal {INPUT_SCHEMA}")
    preflight_id = safe_id(request.get("preflight_id"), "preflight_id")
    if not preflight_id.startswith("preflight_"):
        raise EvidenceError("preflight_id must start with preflight_")
    application_id = safe_id(request.get("application_id"), "application_id")
    checked_at = canonical_timestamp(request.get("checked_at"), "checked_at")
    operator_id = safe_id(request.get("operator_id"), "operator_id")

    if qualification_raw != canonical_bytes(qualification_payload):
        raise EvidenceError("qualification evidence must be canonical JSON")
    qualification = evaluation_qualification.validate_evidence(
        qualification_payload, compatibility
    )
    expected_qualification = evaluation_qualification.build_evidence(
        qualification_input_payload,
        qualification_input_raw,
        compatibility,
    )
    if qualification != expected_qualification:
        raise EvidenceError("qualification evidence differs from its bound input")
    if qualification["application_id"] != application_id:
        raise EvidenceError("application_id differs from qualification evidence")
    if checked_at < qualification["reviewed_at"]:
        raise EvidenceError("partner preflight checked_at cannot precede qualification")
    workload, workload_raw = _load_and_validate_workload(workload_path, qualification)
    policy, policy_raw = _load_and_validate_policy(policy_path)
    estimate, estimate_raw = _load_and_validate_estimate(estimate_path)
    adapter = _validate_adapter(request.get("adapter"))
    commands = _validate_commands(request.get("commands"))
    host = _validate_host(request.get("host"))
    source_sha, source_size = _bound_file(adapter_source_path, "adapter source archive")
    artifact_sha, artifact_size = _bound_file(adapter_artifact_path, "adapter artifact")
    actual_inputs = {
        "qualification_input_file_sha256": sha256_bytes(qualification_input_raw),
        "qualification_evidence_sha256": sha256_bytes(qualification_raw),
        "workload_spec_sha256": sha256_bytes(workload_raw),
        "adapter_source_sha256": source_sha,
        "adapter_artifact_sha256": artifact_sha,
        "resource_policy_sha256": sha256_bytes(policy_raw),
        "resource_estimate_sha256": sha256_bytes(estimate_raw),
    }
    expected_inputs = exact_object(request.get("inputs"), REQUEST_INPUT_KEYS, "inputs")
    for field, actual in actual_inputs.items():
        if sha256_hex(expected_inputs.get(field), f"inputs.{field}") != actual:
            raise EvidenceError(f"inputs.{field} does not match the supplied artifact")

    feasibility = _expected_feasibility(policy, host, estimate)
    if not all(feasibility.values()):
        failed = sorted(field for field, passed in feasibility.items() if not passed)
        raise EvidenceError("partner preflight is infeasible: " + ", ".join(failed))
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "status": "preflight_passed",
        "preflight_id": preflight_id,
        "application_id": application_id,
        "checked_at": checked_at,
        "operator_id": operator_id,
        "compatibility": dict(compatibility),
        "bound_inputs": {
            **actual_inputs,
            "adapter_source_bytes": source_size,
            "adapter_artifact_bytes": artifact_size,
        },
        "workload": workload,
        "adapter": adapter,
        "commands": commands,
        "resource_policy": policy,
        "host": host,
        "resource_estimate": estimate,
        "feasibility": feasibility,
        "preflight_input_sha256": canonical_sha256(request),
        "preflight_input_file_sha256": sha256_bytes(request_raw),
    }


def validate_evidence(value: Any, compatibility: dict[str, str]) -> dict[str, Any]:
    """Deeply validate PartnerPreflightV1 without reopening its bound files.

    Call :func:`verify` when the original files are available; it additionally
    recomputes this complete evidence object from their exact bytes.
    """
    evidence = exact_object(value, EVIDENCE_KEYS, "partner preflight evidence")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvidenceError(f"schema_version must equal {EVIDENCE_SCHEMA}")
    if evidence.get("status") != "preflight_passed":
        raise EvidenceError("partner preflight status must be preflight_passed")
    preflight_id = safe_id(evidence.get("preflight_id"), "preflight_id")
    if not preflight_id.startswith("preflight_"):
        raise EvidenceError("preflight_id must start with preflight_")
    application_id = safe_id(evidence.get("application_id"), "application_id")
    if not application_id.startswith("eval_"):
        raise EvidenceError("application_id must start with eval_")
    canonical_timestamp(evidence.get("checked_at"), "checked_at")
    safe_id(evidence.get("operator_id"), "operator_id")
    evidence_compatibility = exact_object(
        evidence.get("compatibility"),
        evaluation_qualification.COMPATIBILITY_KEYS,
        "compatibility",
    )
    if evidence_compatibility != compatibility:
        raise EvidenceError("partner preflight compatibility identity differs")
    bound = exact_object(evidence.get("bound_inputs"), BOUND_INPUT_KEYS, "bound_inputs")
    for field in REQUEST_INPUT_KEYS:
        sha256_hex(bound.get(field), f"bound_inputs.{field}")
    for field in ("adapter_source_bytes", "adapter_artifact_bytes"):
        positive_integer(
            bound.get(field),
            f"bound_inputs.{field}",
            maximum=MAX_BOUND_ARTIFACT_BYTES,
        )
    workload = _validate_workload_payload(evidence.get("workload"))
    adapter = _validate_adapter(evidence.get("adapter"))
    commands = _validate_commands(evidence.get("commands"))
    policy = _validate_policy_payload(evidence.get("resource_policy"))
    host = _validate_host(evidence.get("host"))
    estimate = _validate_estimate_payload(evidence.get("resource_estimate"))
    feasibility = exact_object(
        evidence.get("feasibility"), FEASIBILITY_KEYS, "feasibility"
    )
    expected_feasibility = _expected_feasibility(policy, host, estimate)
    if feasibility != expected_feasibility or not all(expected_feasibility.values()):
        raise EvidenceError(
            "partner preflight feasibility evidence is inconsistent or failed"
        )
    sha256_hex(evidence.get("preflight_input_sha256"), "preflight_input_sha256")
    sha256_hex(
        evidence.get("preflight_input_file_sha256"), "preflight_input_file_sha256"
    )
    normalized = {
        **evidence,
        "compatibility": dict(evidence_compatibility),
        "bound_inputs": dict(bound),
        "workload": workload,
        "adapter": adapter,
        "commands": commands,
        "resource_policy": policy,
        "host": host,
        "resource_estimate": estimate,
        "feasibility": expected_feasibility,
    }
    if normalized != evidence:
        raise EvidenceError("partner preflight evidence contains non-normalized values")
    return evidence


def issue(args: argparse.Namespace) -> dict[str, Any]:
    request, request_raw = load_json(args.input, "partner preflight input")
    qualification, qualification_raw = load_json(
        args.qualification, "qualification evidence"
    )
    qualification_input, qualification_input_raw = load_json(
        args.qualification_input, "qualification input"
    )
    compatibility = compatibility_identity(args.compatibility_manifest)
    evidence = build_evidence(
        request_payload=request,
        request_raw=request_raw,
        qualification_input_payload=qualification_input,
        qualification_input_raw=qualification_input_raw,
        qualification_payload=qualification,
        qualification_raw=qualification_raw,
        workload_path=args.workload_spec,
        adapter_source_path=args.adapter_source,
        adapter_artifact_path=args.adapter_artifact,
        policy_path=args.resource_policy,
        estimate_path=args.resource_estimate,
        compatibility=compatibility,
    )
    digest = atomic_write_canonical(args.output, evidence)
    return {
        "status": "preflight_passed",
        "preflight_id": evidence["preflight_id"],
        "application_id": evidence["application_id"],
        "evidence_path": str(args.output),
        "evidence_sha256": digest,
        "network_accessed": False,
        "commands_executed": False,
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    evidence, evidence_raw = load_json(args.evidence, "partner preflight evidence")
    if evidence_raw != canonical_bytes(evidence):
        raise EvidenceError("partner preflight evidence is not canonical JSON")
    compatibility = compatibility_identity(args.compatibility_manifest)
    checked = validate_evidence(evidence, compatibility)
    qualification, qualification_raw = load_json(
        args.qualification, "qualification evidence"
    )
    qualification_input, qualification_input_raw = load_json(
        args.qualification_input, "qualification input"
    )
    request, request_raw = load_json(args.input, "partner preflight input")
    expected = build_evidence(
        request_payload=request,
        request_raw=request_raw,
        qualification_input_payload=qualification_input,
        qualification_input_raw=qualification_input_raw,
        qualification_payload=qualification,
        qualification_raw=qualification_raw,
        workload_path=args.workload_spec,
        adapter_source_path=args.adapter_source,
        adapter_artifact_path=args.adapter_artifact,
        policy_path=args.resource_policy,
        estimate_path=args.resource_estimate,
        compatibility=compatibility,
    )
    if checked != expected:
        raise EvidenceError(
            "partner preflight evidence differs from recomputed evidence"
        )
    return {
        "status": "preflight_passed",
        "preflight_id": checked["preflight_id"],
        "application_id": checked["application_id"],
        "evidence_sha256": sha256_bytes(evidence_raw),
        "network_accessed": False,
        "commands_executed": False,
    }


def _add_bound_inputs(parser: argparse.ArgumentParser, *, include_output: bool) -> None:
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--qualification-input", type=Path, required=True)
    parser.add_argument("--qualification", type=Path, required=True)
    parser.add_argument("--workload-spec", type=Path, required=True)
    parser.add_argument("--adapter-source", type=Path, required=True)
    parser.add_argument("--adapter-artifact", type=Path, required=True)
    parser.add_argument("--resource-policy", type=Path, required=True)
    parser.add_argument("--resource-estimate", type=Path, required=True)
    parser.add_argument(
        "--compatibility-manifest", type=Path, default=DEFAULT_COMPATIBILITY
    )
    if include_output:
        parser.add_argument("--output", type=Path, required=True)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    issue_parser = subparsers.add_parser("issue", help="issue preflight evidence")
    _add_bound_inputs(issue_parser, include_output=True)
    verify_parser = subparsers.add_parser("verify", help="verify preflight evidence")
    verify_parser.add_argument("--evidence", type=Path, required=True)
    _add_bound_inputs(verify_parser, include_output=False)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = issue(args) if args.command == "issue" else verify(args)
    except (EvidenceError, OSError) as error:
        print(f"FAIL  {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
