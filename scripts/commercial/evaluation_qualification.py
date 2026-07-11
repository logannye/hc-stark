#!/usr/bin/env python3
"""Issue or verify deterministic EvaluationQualificationV1 evidence offline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
from typing import Any

from evidence_common import (
    EXPECTED_VERIFIER,
    EvidenceError,
    PLONKY3_VERSION as PINNED_PLONKY3_VERSION,
    PROFILE_ID,
    atomic_write_canonical,
    canonical_bytes,
    canonical_date,
    canonical_sha256,
    canonical_timestamp,
    compatibility_identity,
    exact_object,
    load_json,
    nonempty_string,
    positive_integer,
    safe_id,
    sha256_bytes,
    sha256_hex,
)


ROOT = Path(__file__).resolve().parents[2]
DEFAULT_COMPATIBILITY = ROOT / "release" / "plonky3-compatibility-v1.json"
INPUT_SCHEMA = "tinyzkp-evaluation-qualification-input-v1"
EVIDENCE_SCHEMA = "tinyzkp-evaluation-qualification-v1"
PROFILE = PROFILE_ID
PLONKY3_VERSION = PINNED_PLONKY3_VERSION
VERIFIER = EXPECTED_VERIFIER
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")

TOP_LEVEL_KEYS = {
    "schema_version",
    "application_id",
    "reviewed_at",
    "reviewer_id",
    "compatibility",
    "workload",
    "memory_constraint",
    "owners",
    "data_boundary",
}
EVIDENCE_KEYS = TOP_LEVEL_KEYS | {
    "status",
    "qualification_input_sha256",
    "qualification_input_file_sha256",
}
COMPATIBILITY_KEYS = {
    "profile",
    "plonky3_version",
    "expected_verifier",
    "compatibility_manifest_sha256",
}
INPUT_COMPATIBILITY_KEYS = {"profile", "plonky3_version", "expected_verifier"}
WORKLOAD_KEYS = {
    "workload_id",
    "description",
    "revision",
    "logical_rows",
    "generator_kind",
    "generator_reference",
    "generator_sha256",
}
MEMORY_KEYS = {
    "evidence_kind",
    "current_peak_rss_bytes",
    "oom_limit_bytes",
    "target_resident_bytes",
    "available_scratch_bytes",
    "scratch_medium",
    "qualifying_basis",
    "observed_to_target_milli_ratio",
}
INPUT_MEMORY_KEYS = MEMORY_KEYS - {
    "qualifying_basis",
    "observed_to_target_milli_ratio",
}
OWNER_KEYS = {
    "technical_owner_confirmed",
    "budget_owner_confirmed",
    "decision_by",
}
DATA_BOUNDARY_KEYS = {
    "public_or_non_sensitive_generator_only",
    "witness_transfer_allowed",
    "credentials_transfer_allowed",
    "customer_data_transfer_allowed",
    "proprietary_source_transfer_allowed",
}
SAFE_DATA_BOUNDARY = {
    "public_or_non_sensitive_generator_only": True,
    "witness_transfer_allowed": False,
    "credentials_transfer_allowed": False,
    "customer_data_transfer_allowed": False,
    "proprietary_source_transfer_allowed": False,
}


def _validate_compatibility(
    value: Any,
    expected: dict[str, str],
    *,
    evidence: bool,
) -> dict[str, str]:
    keys = COMPATIBILITY_KEYS if evidence else INPUT_COMPATIBILITY_KEYS
    compatibility = exact_object(value, keys, "compatibility")
    for field in ("profile", "plonky3_version", "expected_verifier"):
        if compatibility.get(field) != expected[field]:
            raise EvidenceError(f"compatibility.{field} is unsupported")
    if evidence:
        digest = sha256_hex(
            compatibility.get("compatibility_manifest_sha256"),
            "compatibility.compatibility_manifest_sha256",
        )
        if digest != expected["compatibility_manifest_sha256"]:
            raise EvidenceError(
                "qualification binds a different compatibility manifest"
            )
    return {field: str(compatibility[field]) for field in keys}


def _validate_workload(value: Any) -> dict[str, Any]:
    workload = exact_object(value, WORKLOAD_KEYS, "workload")
    workload_id = safe_id(workload.get("workload_id"), "workload.workload_id")
    description = nonempty_string(
        workload.get("description"), "workload.description", max_length=512
    )
    revision = workload.get("revision")
    if not isinstance(revision, str) or GIT_REVISION.fullmatch(revision) is None:
        raise EvidenceError("workload.revision must be a full lowercase Git commit")
    logical_rows = positive_integer(
        workload.get("logical_rows"), "workload.logical_rows"
    )
    if logical_rows > (1 << 30) or logical_rows & (logical_rows - 1):
        raise EvidenceError(
            "workload.logical_rows must be a power of two no greater than 2^30"
        )
    if workload.get("generator_kind") != "deterministic_non_sensitive":
        raise EvidenceError(
            "workload.generator_kind must be deterministic_non_sensitive"
        )
    generator_reference = nonempty_string(
        workload.get("generator_reference"),
        "workload.generator_reference",
        max_length=2048,
    )
    generator_sha256 = sha256_hex(
        workload.get("generator_sha256"), "workload.generator_sha256"
    )
    return {
        "workload_id": workload_id,
        "description": description,
        "revision": revision,
        "logical_rows": logical_rows,
        "generator_kind": "deterministic_non_sensitive",
        "generator_reference": generator_reference,
        "generator_sha256": generator_sha256,
    }


def _validate_memory(value: Any, *, evidence: bool) -> dict[str, Any]:
    keys = MEMORY_KEYS if evidence else INPUT_MEMORY_KEYS
    constraint = exact_object(value, keys, "memory_constraint")
    kind = constraint.get("evidence_kind")
    if kind not in {"oom", "measured_rss"}:
        raise EvidenceError(
            "memory_constraint.evidence_kind must be oom or measured_rss"
        )
    target = positive_integer(
        constraint.get("target_resident_bytes"),
        "memory_constraint.target_resident_bytes",
    )
    scratch = positive_integer(
        constraint.get("available_scratch_bytes"),
        "memory_constraint.available_scratch_bytes",
    )
    if constraint.get("scratch_medium") != "local_nvme":
        raise EvidenceError("memory_constraint.scratch_medium must be local_nvme")

    current = constraint.get("current_peak_rss_bytes")
    oom_limit = constraint.get("oom_limit_bytes")
    if kind == "measured_rss":
        current = positive_integer(current, "memory_constraint.current_peak_rss_bytes")
        if oom_limit is not None:
            raise EvidenceError("measured_rss evidence must not set oom_limit_bytes")
        if current * 2 < target * 3:
            raise EvidenceError(
                "measured RSS must be at least 1.5x the target RAM ceiling"
            )
        observed = current
        basis = "measured_rss_at_least_1_5x_target"
    else:
        if current is not None:
            raise EvidenceError("oom evidence must not set current_peak_rss_bytes")
        oom_limit = positive_integer(oom_limit, "memory_constraint.oom_limit_bytes")
        if oom_limit < target:
            raise EvidenceError(
                "numeric OOM limit must be at least the target RAM ceiling"
            )
        observed = oom_limit
        basis = "numeric_oom_at_or_above_target"
    ratio = observed * 1000 // target
    if evidence:
        if constraint.get("qualifying_basis") != basis:
            raise EvidenceError("memory_constraint.qualifying_basis is inconsistent")
        if constraint.get("observed_to_target_milli_ratio") != ratio:
            raise EvidenceError(
                "memory_constraint.observed_to_target_milli_ratio is inconsistent"
            )
    return {
        "evidence_kind": kind,
        "current_peak_rss_bytes": current,
        "oom_limit_bytes": oom_limit,
        "target_resident_bytes": target,
        "available_scratch_bytes": scratch,
        "scratch_medium": "local_nvme",
        "qualifying_basis": basis,
        "observed_to_target_milli_ratio": ratio,
    }


def _validate_owners(value: Any, reviewed_at: str) -> dict[str, Any]:
    owners = exact_object(value, OWNER_KEYS, "owners")
    if owners.get("technical_owner_confirmed") is not True:
        raise EvidenceError("owners.technical_owner_confirmed must be true")
    if owners.get("budget_owner_confirmed") is not True:
        raise EvidenceError("owners.budget_owner_confirmed must be true")
    decision_by = canonical_date(owners.get("decision_by"), "owners.decision_by")
    if decision_by < reviewed_at[:10]:
        raise EvidenceError("owners.decision_by cannot precede reviewed_at")
    return {
        "technical_owner_confirmed": True,
        "budget_owner_confirmed": True,
        "decision_by": decision_by,
    }


def _validate_data_boundary(value: Any) -> dict[str, bool]:
    boundary = exact_object(value, DATA_BOUNDARY_KEYS, "data_boundary")
    if boundary != SAFE_DATA_BOUNDARY:
        raise EvidenceError(
            "data_boundary must prohibit sensitive or proprietary transfers"
        )
    return dict(SAFE_DATA_BOUNDARY)


def build_evidence(
    payload: Any,
    raw: bytes,
    expected_compatibility: dict[str, str],
) -> dict[str, Any]:
    request = exact_object(payload, TOP_LEVEL_KEYS, "qualification input")
    if request.get("schema_version") != INPUT_SCHEMA:
        raise EvidenceError(f"schema_version must equal {INPUT_SCHEMA}")
    application_id = safe_id(request.get("application_id"), "application_id")
    if not application_id.startswith("eval_"):
        raise EvidenceError("application_id must start with eval_")
    reviewed_at = canonical_timestamp(request.get("reviewed_at"), "reviewed_at")
    reviewer_id = safe_id(request.get("reviewer_id"), "reviewer_id")
    _validate_compatibility(
        request.get("compatibility"), expected_compatibility, evidence=False
    )
    workload = _validate_workload(request.get("workload"))
    memory = _validate_memory(request.get("memory_constraint"), evidence=False)
    owners = _validate_owners(request.get("owners"), reviewed_at)
    boundary = _validate_data_boundary(request.get("data_boundary"))
    return {
        "schema_version": EVIDENCE_SCHEMA,
        "status": "qualified",
        "application_id": application_id,
        "reviewed_at": reviewed_at,
        "reviewer_id": reviewer_id,
        "compatibility": dict(expected_compatibility),
        "workload": workload,
        "memory_constraint": memory,
        "owners": owners,
        "data_boundary": boundary,
        "qualification_input_sha256": canonical_sha256(request),
        "qualification_input_file_sha256": sha256_bytes(raw),
    }


def validate_evidence(
    payload: Any,
    expected_compatibility: dict[str, str],
) -> dict[str, Any]:
    evidence = exact_object(payload, EVIDENCE_KEYS, "qualification evidence")
    if evidence.get("schema_version") != EVIDENCE_SCHEMA:
        raise EvidenceError(f"schema_version must equal {EVIDENCE_SCHEMA}")
    if evidence.get("status") != "qualified":
        raise EvidenceError("qualification status must be qualified")
    application_id = safe_id(evidence.get("application_id"), "application_id")
    if not application_id.startswith("eval_"):
        raise EvidenceError("application_id must start with eval_")
    reviewed_at = canonical_timestamp(evidence.get("reviewed_at"), "reviewed_at")
    safe_id(evidence.get("reviewer_id"), "reviewer_id")
    _validate_compatibility(
        evidence.get("compatibility"), expected_compatibility, evidence=True
    )
    _validate_workload(evidence.get("workload"))
    _validate_memory(evidence.get("memory_constraint"), evidence=True)
    _validate_owners(evidence.get("owners"), reviewed_at)
    _validate_data_boundary(evidence.get("data_boundary"))
    sha256_hex(evidence.get("qualification_input_sha256"), "qualification_input_sha256")
    sha256_hex(
        evidence.get("qualification_input_file_sha256"),
        "qualification_input_file_sha256",
    )
    return evidence


def issue(
    input_path: Path, output_path: Path, compatibility_path: Path
) -> dict[str, Any]:
    payload, raw = load_json(input_path, "qualification input")
    compatibility = compatibility_identity(compatibility_path)
    evidence = build_evidence(payload, raw, compatibility)
    digest = atomic_write_canonical(output_path, evidence)
    return {
        "status": "qualified",
        "application_id": evidence["application_id"],
        "evidence_path": str(output_path),
        "evidence_sha256": digest,
        "network_accessed": False,
        "commands_executed": False,
    }


def verify(
    evidence_path: Path,
    input_path: Path,
    compatibility_path: Path,
) -> dict[str, Any]:
    payload, raw = load_json(evidence_path, "qualification evidence")
    if raw != canonical_bytes(payload):
        raise EvidenceError("qualification evidence is not canonical JSON")
    input_payload, input_raw = load_json(input_path, "qualification input")
    compatibility = compatibility_identity(compatibility_path)
    evidence = validate_evidence(payload, compatibility)
    expected = build_evidence(input_payload, input_raw, compatibility)
    if evidence != expected:
        raise EvidenceError(
            "qualification evidence differs from recomputed input evidence"
        )
    return {
        "status": "qualified",
        "application_id": evidence["application_id"],
        "evidence_sha256": sha256_bytes(raw),
        "network_accessed": False,
        "commands_executed": False,
    }


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    issue_parser = subparsers.add_parser(
        "issue", help="validate input and issue evidence"
    )
    issue_parser.add_argument("--input", type=Path, required=True)
    issue_parser.add_argument("--output", type=Path, required=True)
    issue_parser.add_argument(
        "--compatibility-manifest", type=Path, default=DEFAULT_COMPATIBILITY
    )
    verify_parser = subparsers.add_parser("verify", help="verify existing evidence")
    verify_parser.add_argument("--evidence", type=Path, required=True)
    verify_parser.add_argument("--input", type=Path, required=True)
    verify_parser.add_argument(
        "--compatibility-manifest", type=Path, default=DEFAULT_COMPATIBILITY
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        result = (
            issue(args.input, args.output, args.compatibility_manifest)
            if args.command == "issue"
            else verify(args.evidence, args.input, args.compatibility_manifest)
        )
    except (EvidenceError, OSError) as error:
        print(f"FAIL  {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
