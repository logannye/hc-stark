#!/usr/bin/env python3
"""Build hash-bound external review, reproduction, and partner records."""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import tempfile
from typing import Iterator


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import backend_release_ready as release_gate  # noqa: E402
import source_tree_identity  # noqa: E402
import strict_json  # noqa: E402
import build_review_bundle  # noqa: E402


PROFILE = "tinyzkp-p3-goldilocks-v1"
MAX_INPUT_BYTES = 16 * 1024 * 1024
TEMPLATE_DIR = ROOT / "release" / "evidence" / "templates"
TEMPLATE_FILES = {
    "plonky3_specialist_review": "plonky3-specialist-review-v1.template.json",
    "implementation_review": "implementation-review-v1.template.json",
    "independent_reproduction": "independent-reproduction-v1.template.json",
    "design_partner_acceptance": "design-partner-acceptance-v1.template.json",
}
PLACEHOLDER = re.compile(r"(?:^|[^A-Z])REPLACE(?:_|\b)")
RFC3339_UTC = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
OPAQUE_PARTNER_ID = re.compile(r"partner-[0-9a-f]{16,64}\Z")
OPAQUE_ACCEPTANCE_ID = re.compile(r"acceptance-[0-9a-f]{16,64}\Z")


def resource_roles(*, baseline: bool) -> tuple[str, ...]:
    suffixes = ["manifest", "candidate_report", "candidate_normalized_manifest"]
    if baseline:
        suffixes.extend(("baseline_report", "baseline_normalized_manifest"))
    return tuple(
        f"{workload}_{suffix}"
        for workload in ("fibonacci", "poseidon2")
        for suffix in suffixes
    )


INDEPENDENT_RESOURCE_ROLES = tuple(
    [f"one_million_{role}" for role in resource_roles(baseline=True)]
    + [f"ten_million_{role}" for role in resource_roles(baseline=False)]
)


def safe_file(raw: Path) -> Path:
    candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"input is outside the repository: {raw}") from error
    current = ROOT
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"input contains a symlink: {raw}")
    if not candidate.is_file() or candidate.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError(f"input is missing or oversized: {raw}")
    return candidate


def safe_output(raw: Path) -> Path:
    candidate = raw if raw.is_absolute() else ROOT / raw
    candidate = candidate.absolute()
    try:
        relative = candidate.relative_to(ROOT.resolve())
    except ValueError as error:
        raise ValueError(f"output is outside the repository: {raw}") from error
    current = ROOT
    for part in relative.parent.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"output parent contains a symlink: {raw}")
    if candidate.is_symlink():
        raise ValueError(f"output is a symlink: {raw}")
    return candidate


def file_identity(details: os.stat_result) -> tuple[int, ...]:
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


def stable_file_bytes(raw: Path, *, require_private: bool) -> bytes:
    candidate = safe_file(raw)
    before_path = os.stat(candidate, follow_symlinks=False)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(candidate, flags)
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size > MAX_INPUT_BYTES
            or file_identity(before_path) != file_identity(before)
        ):
            raise ValueError("external evidence input has an unsafe file identity")
        if require_private and (
            before.st_uid != os.getuid() or stat.S_IMODE(before.st_mode) & 0o077
        ):
            raise ValueError(
                "completed external input must be owner-owned, single-link, and owner-only"
            )
        payload = bytearray()
        while True:
            block = os.read(descriptor, min(1024 * 1024, MAX_INPUT_BYTES + 1))
            if not block:
                break
            payload.extend(block)
            if len(payload) > MAX_INPUT_BYTES:
                raise ValueError("external evidence input changed or is oversized")
        after = os.fstat(descriptor)
        after_path = os.stat(candidate, follow_symlinks=False)
        if (
            file_identity(before) != file_identity(after)
            or file_identity(before) != file_identity(after_path)
            or len(payload) != before.st_size
        ):
            raise ValueError("external evidence input changed during its held read")
        return bytes(payload)
    finally:
        os.close(descriptor)


def write_bytes_exclusive(path: Path, payload: bytes) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
        0o600,
    )
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write while snapshotting external evidence")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def snapshot_artifacts(artifacts: dict[str, Path]) -> Iterator[dict[str, Path]]:
    snapshot_root = Path(
        tempfile.mkdtemp(prefix=".external-evidence-snapshot-", dir=ROOT)
    )
    os.chmod(snapshot_root, 0o700)
    snapshots: dict[str, Path] = {}
    try:
        for index, (role, source) in enumerate(sorted(artifacts.items())):
            snapshot = snapshot_root / f"{index:03d}.artifact"
            write_bytes_exclusive(
                snapshot, stable_file_bytes(source, require_private=False)
            )
            snapshots[role] = snapshot
        yield snapshots
    finally:
        shutil.rmtree(snapshot_root)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def staged_record_path(output: Path) -> Path:
    return output.with_name(f".{output.name}.validation-{os.getpid()}.json")


def reproduction_record(
    *,
    release_sha: str,
    reproducer: str,
    organization: str,
    completed_at: str,
    artifacts: dict[str, Path],
    signer_id: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": PROFILE,
        "independent": True,
        "reproducer": reproducer,
        "organization": organization,
        "completed_at": completed_at,
        "official_verification": True,
        "workloads": ["fibonacci", "poseidon2_goldilocks"],
        "gates": ["one-million", "ten-million"],
        "artifact_sha256": {
            role: sha256(path) for role, path in sorted(artifacts.items())
        },
        "signer_id": signer_id,
    }


def validate_findings(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list):
        raise ValueError("findings input must contain a JSON array")
    findings: list[dict[str, object]] = []
    identifiers: set[str] = set()
    for finding in value:
        if not isinstance(finding, dict) or set(finding) != {
            "id",
            "severity",
            "status",
            "reviewer_verified",
        }:
            raise ValueError(
                "each finding must contain exactly id/severity/status/reviewer_verified"
            )
        identifier = finding.get("id")
        if (
            not isinstance(identifier, str)
            or not identifier
            or identifier in identifiers
        ):
            raise ValueError("finding IDs must be unique non-empty strings")
        identifiers.add(identifier)
        if (
            finding.get("severity")
            not in {
                "critical",
                "high",
                "medium",
                "low",
                "informational",
            }
            or finding.get("status")
            not in {
                "open",
                "remediated",
                "accepted_by_reviewer",
            }
            or not isinstance(finding.get("reviewer_verified"), bool)
        ):
            raise ValueError(f"finding is malformed: {identifier}")
        findings.append(finding)
    return findings


def review_ledger(
    *,
    release_sha: str,
    scope: str,
    reviewer: str,
    completed_at: str,
    bundle: Path,
    review_manifest_sha256: str,
    source_tree_sha256: str,
    report: Path,
    findings: list[dict[str, object]],
    security_assessment: dict[str, object] | None,
    signer_id: str,
) -> dict[str, object]:
    return {
        "schema_version": 2,
        "release_sha": release_sha,
        "profile": PROFILE,
        "review_scope": scope,
        "completed_at": completed_at,
        "reviewer": reviewer,
        "reviewer_independent": True,
        "review_bundle_sha256": sha256(bundle),
        "review_manifest_sha256": review_manifest_sha256,
        "source_tree_sha256": source_tree_sha256,
        "review_report_sha256": sha256(report),
        "findings": findings,
        "security_assessment": security_assessment,
        "signer_id": signer_id,
    }


def partner_acceptance(
    *,
    release_sha: str,
    acceptance_id: str,
    partner_id: str,
    accepted_at: str,
    adapter_result: Path,
    resource_report: Path,
    signer_id: str,
) -> dict[str, object]:
    return {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": PROFILE,
        "acceptance_id": acceptance_id,
        "partner_id": partner_id,
        "accepted_at": accepted_at,
        "official_verification": True,
        "bounded_equals_conventional": True,
        "witness_data_committed": False,
        "adapter_result_sha256": sha256(adapter_result),
        "resource_report_sha256": sha256(resource_report),
        "signer_id": signer_id,
    }


def nonempty(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 256
        or any(ord(character) < 0x20 for character in value)
    ):
        raise ValueError(f"{label} must be non-empty and at most 256 characters")
    return value


def exact_int(value: object, expected: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value == expected


def contains_placeholder(value: object) -> bool:
    if isinstance(value, str):
        return PLACEHOLDER.search(value) is not None
    if isinstance(value, list):
        return any(contains_placeholder(item) for item in value)
    if isinstance(value, dict):
        return any(
            contains_placeholder(key) or contains_placeholder(item)
            for key, item in value.items()
        )
    return False


def completed_timestamp(value: object, label: str) -> str:
    value = nonempty(value, label) if isinstance(value, str) else ""
    if RFC3339_UTC.fullmatch(value) is None:
        raise ValueError(
            f"{label} must be canonical RFC3339 UTC (YYYY-MM-DDTHH:MM:SSZ)"
        )
    try:
        parsed = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise ValueError(f"{label} is not a real UTC timestamp") from error
    if parsed.year < 2020:
        raise ValueError(f"{label} predates the supported evidence epoch")
    return value


def input_artifacts(value: object, expected: tuple[str, ...]) -> dict[str, Path]:
    artifact_path_shape(value, expected)
    assert isinstance(value, dict)
    artifacts: dict[str, Path] = {}
    for role in expected:
        raw = value.get(role)
        assert isinstance(raw, str)
        artifacts[role] = safe_file(Path(raw))
    return artifacts


def artifact_path_shape(value: object, expected: tuple[str, ...]) -> None:
    if not isinstance(value, dict) or set(value) != set(expected):
        missing = sorted(set(expected) - set(value if isinstance(value, dict) else ()))
        extra = sorted(set(value if isinstance(value, dict) else ()) - set(expected))
        raise ValueError(
            f"artifact path roles mismatch; missing={missing}, extra={extra}"
        )
    for role in expected:
        raw = value.get(role)
        if not isinstance(raw, str) or not raw:
            raise ValueError(f"artifact path is missing for role: {role}")


def validate_security_assessment_shape(value: object) -> None:
    if (
        not isinstance(value, dict)
        or set(value) != release_gate.PROFILE_SECURITY_ASSESSMENT_KEYS
    ):
        raise ValueError("Plonky3 specialist security assessment schema is not closed")
    limitations = value.get("limitations")
    if (
        not exact_int(value.get("schema_version"), 1)
        or value.get("profile_id") != PROFILE
        or value.get("plonky3_version") != "0.6.1"
        or value.get("fri_constructor") != "FriParameters::new_benchmark"
        or not exact_int(value.get("log_blowup"), 1)
        or not exact_int(value.get("log_final_poly_len"), 0)
        or not exact_int(value.get("max_log_arity"), 1)
        or not exact_int(value.get("num_queries"), 100)
        or not exact_int(value.get("commit_proof_of_work_bits"), 0)
        or not exact_int(value.get("query_proof_of_work_bits"), 16)
        or not isinstance(value.get("conjectured_soundness_reviewed"), bool)
        or not isinstance(value.get("proven_soundness_reviewed"), bool)
        or not isinstance(value.get("duplicate_query_probability_reviewed"), bool)
        or not isinstance(value.get("challenger_capacity_reviewed"), bool)
        or not isinstance(value.get("minimum_security_bits"), int)
        or isinstance(value.get("minimum_security_bits"), bool)
        or not 0 <= value.get("minimum_security_bits", -1) <= 256
        or not isinstance(value.get("production_use_approved"), bool)
        or not isinstance(value.get("analysis_summary"), str)
        or not value.get("analysis_summary")
        or len(value.get("analysis_summary", "")) > 4096
        or not isinstance(limitations, list)
        or not 1 <= len(limitations) <= 16
        or any(
            not isinstance(item, str) or not item or len(item) > 1024
            for item in limitations
        )
    ):
        raise ValueError("Plonky3 specialist security assessment is malformed")


def validate_external_input(
    value: object,
    *,
    require_complete: bool,
    expected_kind: str | None = None,
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError("external record input must contain a JSON object")
    kind = value.get("record_type")
    if kind not in TEMPLATE_FILES:
        raise ValueError("external record_type is missing or unsupported")
    if expected_kind is not None and kind != expected_kind:
        raise ValueError(f"external record_type must equal {expected_kind}")
    if not exact_int(value.get("schema_version"), 1):
        raise ValueError("external input schema_version must equal 1")
    status = value.get("completion_status")
    if status not in {"incomplete", "completed"}:
        raise ValueError("completion_status must be incomplete or completed")
    if require_complete and status != "completed":
        raise ValueError("external input remains incomplete")
    if require_complete and contains_placeholder(value):
        raise ValueError("completed external input contains an unresolved placeholder")

    if kind in {"plonky3_specialist_review", "implementation_review"}:
        expected_keys = {
            "schema_version",
            "record_type",
            "completion_status",
            "release_sha",
            "reviewer",
            "reviewer_independent",
            "completed_at",
            "signer_id",
            "artifact_paths",
            "findings",
            "security_assessment",
        }
        if set(value) != expected_keys:
            raise ValueError("external review input schema is not closed")
        validate_findings(value.get("findings"))
        assessment = value.get("security_assessment")
        if kind == "plonky3_specialist_review":
            validate_security_assessment_shape(assessment)
        elif assessment is not None:
            raise ValueError("implementation review security_assessment must be null")
        artifact_path_shape(
            value.get("artifact_paths"), ("review_bundle", "review_report")
        )
        if not isinstance(value.get("reviewer_independent"), bool):
            raise ValueError("reviewer_independent conclusion must be a boolean")
        nonempty(value.get("reviewer"), "reviewer")
        nonempty(value.get("completed_at"), "completion time")
        nonempty(value.get("signer_id"), "signer ID")
        if require_complete:
            if value.get("reviewer_independent") is not True:
                raise ValueError("reviewer did not attest independence")
            input_artifacts(
                value.get("artifact_paths"), ("review_bundle", "review_report")
            )
            completed_timestamp(value.get("completed_at"), "completion time")
    elif kind == "independent_reproduction":
        expected_keys = {
            "schema_version",
            "record_type",
            "completion_status",
            "release_sha",
            "reproducer",
            "organization",
            "completed_at",
            "signer_id",
            "independent",
            "official_verification",
            "workloads",
            "gates",
            "artifact_paths",
        }
        if set(value) != expected_keys:
            raise ValueError("independent reproduction input schema is not closed")
        if value.get("workloads") != ["fibonacci", "poseidon2_goldilocks"]:
            raise ValueError("independent reproduction workloads are not frozen")
        if value.get("gates") != ["one-million", "ten-million"]:
            raise ValueError("independent reproduction gates are not frozen")
        if not isinstance(value.get("independent"), bool) or not isinstance(
            value.get("official_verification"), bool
        ):
            raise ValueError("independent reproduction conclusions must be booleans")
        artifact_path_shape(value.get("artifact_paths"), INDEPENDENT_RESOURCE_ROLES)
        nonempty(value.get("reproducer"), "reproducer")
        nonempty(value.get("organization"), "organization")
        nonempty(value.get("completed_at"), "completion time")
        nonempty(value.get("signer_id"), "signer ID")
        if require_complete:
            if value.get("independent") is not True:
                raise ValueError("reproducer did not attest independent execution")
            if value.get("official_verification") is not True:
                raise ValueError("reproducer did not attest official verification")
            input_artifacts(value.get("artifact_paths"), INDEPENDENT_RESOURCE_ROLES)
            completed_timestamp(value.get("completed_at"), "completion time")
    else:
        expected_keys = {
            "schema_version",
            "record_type",
            "completion_status",
            "release_sha",
            "acceptance_id",
            "partner_id",
            "accepted_at",
            "signer_id",
            "official_verification",
            "bounded_equals_conventional",
            "witness_data_committed",
            "artifact_paths",
        }
        if set(value) != expected_keys:
            raise ValueError("design-partner acceptance input schema is not closed")
        for field in (
            "official_verification",
            "bounded_equals_conventional",
            "witness_data_committed",
        ):
            if not isinstance(value.get(field), bool):
                raise ValueError(f"partner conclusion must be a boolean: {field}")
        artifact_path_shape(
            value.get("artifact_paths"), ("adapter_result", "resource_report")
        )
        nonempty(value.get("acceptance_id"), "acceptance ID")
        nonempty(value.get("partner_id"), "partner ID")
        nonempty(value.get("accepted_at"), "acceptance time")
        nonempty(value.get("signer_id"), "signer ID")
        if require_complete:
            if OPAQUE_ACCEPTANCE_ID.fullmatch(str(value.get("acceptance_id"))) is None:
                raise ValueError(
                    "acceptance ID must be an opaque acceptance-<hex> token"
                )
            if OPAQUE_PARTNER_ID.fullmatch(str(value.get("partner_id"))) is None:
                raise ValueError("partner ID must be an opaque partner-<hex> token")
            if value.get("official_verification") is not True:
                raise ValueError("partner did not attest official verification")
            if value.get("bounded_equals_conventional") is not True:
                raise ValueError("partner did not attest bounded/conventional equality")
            if value.get("witness_data_committed") is not False:
                raise ValueError(
                    "partner input claims customer witness data was committed"
                )
            input_artifacts(
                value.get("artifact_paths"), ("adapter_result", "resource_report")
            )
            completed_timestamp(value.get("accepted_at"), "acceptance time")

    if require_complete:
        release_sha = value.get("release_sha")
        if not isinstance(release_sha, str):
            raise ValueError("release SHA must be a string")
        source_tree_identity.require_canonical_commit(ROOT, release_sha)
    elif not isinstance(value.get("release_sha"), str):
        raise ValueError("template release SHA must be a string")
    return value


def load_external_input(
    path: Path, *, require_complete: bool, expected_kind: str | None = None
) -> dict[str, object]:
    value = strict_json.loads(stable_file_bytes(path, require_private=require_complete))
    return validate_external_input(
        value, require_complete=require_complete, expected_kind=expected_kind
    )


def external_source_artifacts(value: dict[str, object]) -> dict[str, Path]:
    validate_external_input(value, require_complete=True)
    kind = str(value["record_type"])
    artifact_values = value["artifact_paths"]
    if kind in {"plonky3_specialist_review", "implementation_review"}:
        return input_artifacts(artifact_values, ("review_bundle", "review_report"))
    if kind == "independent_reproduction":
        return input_artifacts(artifact_values, INDEPENDENT_RESOURCE_ROLES)
    return input_artifacts(artifact_values, ("adapter_result", "resource_report"))


def record_from_artifact_snapshot(
    value: dict[str, object], artifacts: dict[str, Path]
) -> dict[str, object]:
    kind = str(value["record_type"])
    release_sha = source_tree_identity.require_canonical_commit(
        ROOT, str(value["release_sha"])
    )

    if kind in {"plonky3_specialist_review", "implementation_review"}:
        manifest, manifest_bytes = build_review_bundle.verify_bundle(
            artifacts["review_bundle"], root=ROOT, release_sha=release_sha
        )
        source_tree_sha256 = source_tree_identity.source_tree_sha256(ROOT, release_sha)
        if (
            not isinstance(manifest, dict)
            or not exact_int(manifest.get("schema_version"), 2)
            or manifest.get("release_sha") != release_sha
            or manifest.get("source_tree_sha256") != source_tree_sha256
            or manifest.get("profile") != PROFILE
            or manifest.get("plonky3_version") != "0.6.1"
        ):
            raise ValueError("review bundle manifest is incomplete or release-skewed")
        scope = (
            "plonky3_specialist"
            if kind == "plonky3_specialist_review"
            else "implementation"
        )
        assessment = value["security_assessment"]
        if scope == "plonky3_specialist":
            failures = release_gate.validate_profile_security_assessment(
                assessment, require_production_approval=False
            )
            if failures:
                raise ValueError(failures[0])
        record = review_ledger(
            release_sha=release_sha,
            scope=scope,
            reviewer=str(value["reviewer"]),
            completed_at=str(value["completed_at"]),
            bundle=artifacts["review_bundle"],
            review_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
            source_tree_sha256=source_tree_sha256,
            report=artifacts["review_report"],
            findings=validate_findings(value["findings"]),
            security_assessment=assessment if isinstance(assessment, dict) else None,
            signer_id=str(value["signer_id"]),
        )
        return record

    if kind == "independent_reproduction":
        for gate_kind, marker in (
            ("resource_one_million", "one_million_"),
            ("resource_ten_million", "ten_million_"),
        ):
            selected = [
                (path, {"role": role.removeprefix(marker)})
                for role, path in artifacts.items()
                if role.startswith(marker)
            ]
            failures = release_gate.validate_resource_gate(
                gate_kind, selected, release_sha
            )
            if failures:
                raise ValueError(
                    "independent resource evidence failed validation: "
                    + "; ".join(failures)
                )
        return reproduction_record(
            release_sha=release_sha,
            reproducer=str(value["reproducer"]),
            organization=str(value["organization"]),
            completed_at=str(value["completed_at"]),
            artifacts=artifacts,
            signer_id=str(value["signer_id"]),
        )

    try:
        adapter = release_gate.read_object(artifacts["adapter_result"])
        report = release_gate.read_object(artifacts["resource_report"])
    except (OSError, ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"partner machine evidence is malformed: {error}") from error
    if (
        not release_gate.exact_int(adapter.get("schema_version"), 1)
        or adapter.get("mode") != "compare"
        or adapter.get("profile") != PROFILE
        or adapter.get("plonky3_version") != "0.6.1"
        or adapter.get("dependency_lock_sha256")
        != "0a28ab40dba2786a5106d274623d174b4c845b15ddd594629ebd98aa08612257"
        or adapter.get("release_sha") != release_sha
        or adapter.get("official_verification") is not True
        or adapter.get("bounded_equals_conventional") is not True
        or adapter.get("witness_data_included") is not False
        or not release_gate.valid_resource_estimate(adapter.get("preflight_estimate"))
        or not release_gate.exact_int(adapter.get("proof_size_bytes"))
        or adapter.get("proof_size_bytes", 0) <= 0
        or not release_gate.lower_hex(adapter.get("proof_blake3_hex"), 64)
    ):
        raise ValueError("partner adapter result is incomplete or release-skewed")
    if (
        not release_gate.valid_benchmark_report_envelope(report)
        or report.get("mode") != "bounded"
        or report.get("release_sha") != release_sha
    ):
        raise ValueError("partner resource report is incomplete or release-skewed")
    return partner_acceptance(
        release_sha=release_sha,
        acceptance_id=str(value["acceptance_id"]),
        partner_id=str(value["partner_id"]),
        accepted_at=str(value["accepted_at"]),
        adapter_result=artifacts["adapter_result"],
        resource_report=artifacts["resource_report"],
        signer_id=str(value["signer_id"]),
    )


def record_from_external_input(
    value: dict[str, object],
) -> tuple[dict[str, object], dict[str, Path]]:
    artifacts = external_source_artifacts(value)
    with snapshot_artifacts(artifacts) as snapshots:
        record = record_from_artifact_snapshot(value, snapshots)
    return record, artifacts


def template_input(kind: str) -> dict[str, object]:
    filename = TEMPLATE_FILES.get(kind)
    if filename is None:
        raise ValueError(f"unknown external record template: {kind}")
    path = TEMPLATE_DIR / filename
    value = strict_json.loads(stable_file_bytes(path, require_private=False))
    validated = validate_external_input(
        value, require_complete=False, expected_kind=kind
    )
    if validated.get("completion_status") != "incomplete" or not contains_placeholder(
        validated
    ):
        raise ValueError("tracked external record template is not fail-closed")
    return validated


def capture_external_input(
    input_path: Path, output_path: Path, *, expected_kind: str | None = None
) -> dict[str, object]:
    source = safe_file(input_path)
    value = load_external_input(
        source, require_complete=True, expected_kind=expected_kind
    )
    record, _ = record_from_external_input(value)
    output = safe_output(output_path)
    if source.resolve() == output.resolve():
        raise ValueError("external input and captured claim paths must differ")
    staged = staged_record_path(output)
    try:
        write_json_atomic(staged, record)
        os.replace(staged, output)
    finally:
        staged.unlink(missing_ok=True)
    return record


def external_metadata(value: dict[str, object]) -> dict[str, object]:
    kind = value["record_type"]
    if kind in {"plonky3_specialist_review", "implementation_review"}:
        return {
            "reviewer": value["reviewer"],
            "completed_at": value["completed_at"],
            "review_scope": (
                "plonky3_specialist"
                if kind == "plonky3_specialist_review"
                else "implementation"
            ),
            "signer_id": value["signer_id"],
        }
    if kind == "independent_reproduction":
        return {
            "release_sha": value["release_sha"],
            "independent": value["independent"],
            "reproducer": value["reproducer"],
            "organization": value["organization"],
            "completed_at": value["completed_at"],
            "signer_id": value["signer_id"],
        }
    return {
        "partner_acceptance_id": value["acceptance_id"],
        "official_verification": value["official_verification"],
        "witness_data_committed": value["witness_data_committed"],
        "bounded_and_conventional": value["bounded_equals_conventional"],
        "signer_id": value["signer_id"],
    }


def validate_signed_external_input(
    input_path: Path, claim_path: Path, signature_path: Path
) -> None:
    value = load_external_input(input_path, require_complete=True)
    source_artifacts = external_source_artifacts(value)
    claim = safe_file(claim_path)
    signature = safe_file(signature_path)
    combined = {
        **source_artifacts,
        "__captured_claim": claim,
        "__detached_signature": signature,
    }
    with snapshot_artifacts(combined) as snapshots:
        source_snapshots = {role: snapshots[role] for role in source_artifacts}
        expected_claim = record_from_artifact_snapshot(value, source_snapshots)
        captured_claim = snapshots["__captured_claim"]
        detached_signature = snapshots["__detached_signature"]
        observed_claim = strict_json.loads(
            stable_file_bytes(captured_claim, require_private=False)
        )
        if observed_claim != expected_claim:
            raise ValueError(
                "captured claim does not match the completed external input"
            )
        release_sha = str(value["release_sha"])
        metadata = external_metadata(value)
        kind = value["record_type"]

        if kind in {"plonky3_specialist_review", "implementation_review"}:
            artifacts = [
                (source_snapshots["review_bundle"], {"role": "review_bundle"}),
                (source_snapshots["review_report"], {"role": "review_report"}),
                (captured_claim, {"role": "remediation_ledger"}),
                (detached_signature, {"role": "review_signature"}),
            ]
            failures = release_gate.validate_review(
                metadata,
                artifacts,
                release_sha,
                str(metadata["review_scope"]),
                source_tree_identity.source_tree_sha256(ROOT, release_sha),
                root=ROOT,
            )
        elif kind == "independent_reproduction":
            artifacts = [
                (path, {"role": role}) for role, path in source_snapshots.items()
            ] + [
                (captured_claim, {"role": "reproduction_record"}),
                (detached_signature, {"role": "reproduction_signature"}),
            ]
            failures = release_gate.validate_independent_reproduction(
                artifacts, metadata, release_sha, root=ROOT
            )
        else:
            artifacts = [
                (source_snapshots["adapter_result"], {"role": "adapter_result"}),
                (source_snapshots["resource_report"], {"role": "resource_report"}),
                (captured_claim, {"role": "acceptance_record"}),
                (detached_signature, {"role": "partner_signature"}),
            ]
            failures = release_gate.validate_partner_evidence(
                artifacts, release_sha, metadata, root=ROOT
            )
        if failures:
            raise ValueError(
                "signed external evidence failed validation: " + "; ".join(failures)
            )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    template = commands.add_parser(
        "template",
        help="copy a tracked, deliberately incomplete external-input template",
    )
    template.add_argument("--kind", choices=tuple(TEMPLATE_FILES), required=True)
    template.add_argument("--output", type=Path, required=True)

    validate = commands.add_parser(
        "validate-input", help="validate a completed input and all referenced artifacts"
    )
    validate.add_argument("--input", type=Path, required=True)

    capture = commands.add_parser(
        "capture", help="capture a completed input as the canonical unsigned claim"
    )
    capture.add_argument("--input", type=Path, required=True)
    capture.add_argument("--output", type=Path, required=True)

    signed = commands.add_parser(
        "validate-signed",
        help="verify the captured claim, detached signature, signer, and release gate",
    )
    signed.add_argument("--input", type=Path, required=True)
    signed.add_argument("--claim", type=Path, required=True)
    signed.add_argument("--signature", type=Path, required=True)

    aliases = {
        "review-ledger": None,
        "reproduction": "independent_reproduction",
        "partner-acceptance": "design_partner_acceptance",
    }
    for command, kind in aliases.items():
        alias = commands.add_parser(
            command,
            help="typed capture alias; raw command-line truth claims are not accepted",
        )
        alias.add_argument("--input", type=Path, required=True)
        alias.add_argument("--output", type=Path, required=True)
        alias.set_defaults(expected_kind=kind)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.command == "template":
            output = safe_output(args.output)
            tracked = (TEMPLATE_DIR / TEMPLATE_FILES[args.kind]).resolve()
            if output.resolve() == tracked:
                raise ValueError(
                    "template output must not overwrite the tracked source"
                )
            write_json_atomic(output, template_input(args.kind))
            print(
                "INCOMPLETE external input template copied; it cannot satisfy a release gate"
            )
        elif args.command == "validate-input":
            value = load_external_input(args.input, require_complete=True)
            record_from_external_input(value)
            print("PASS completed external input and source artifacts validated")
        elif args.command == "capture":
            capture_external_input(args.input, args.output)
            print(
                "UNSIGNED external claim captured; detached signature validation is still required"
            )
        elif args.command == "validate-signed":
            validate_signed_external_input(args.input, args.claim, args.signature)
            print("PASS signed external evidence satisfies its release gate")
        else:
            expected_kind = getattr(args, "expected_kind", None)
            if args.command == "review-ledger":
                value = load_external_input(args.input, require_complete=True)
                if value["record_type"] not in {
                    "plonky3_specialist_review",
                    "implementation_review",
                }:
                    raise ValueError("review-ledger requires a completed review input")
                capture_external_input(args.input, args.output)
            else:
                capture_external_input(
                    args.input, args.output, expected_kind=expected_kind
                )
            print(
                "UNSIGNED external claim captured; detached signature validation is still required"
            )
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"external evidence record failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
