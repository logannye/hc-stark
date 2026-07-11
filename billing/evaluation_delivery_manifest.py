#!/usr/bin/env python3
"""Verify a complete, hash-bound TinyZKP evaluation delivery package."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
from types import MappingProxyType
from typing import Any, BinaryIO


SCHEMA_VERSION = "tinyzkp-evaluation-delivery-v1"
VERIFICATION_SCHEMA = "tinyzkp-official-verification-v1"
PROFILE = "tinyzkp-p3-goldilocks-v1"
VERIFIER = "unmodified-p3-uni-stark-0.6.1"
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$")
MAX_MANIFEST_BYTES = 256 * 1024
MAX_JSON_ARTIFACT_BYTES = 64 * 1024 * 1024
TOP_LEVEL_KEYS = {
    "schema_version",
    "status",
    "agreement_id",
    "offer_id",
    "workload_manifest_digest_hex",
    "scope_sha256",
    "qualification_sha256",
    "partner_preflight_sha256",
    "agreement_gate_sha256",
    "release_sha",
    "adapter_revision",
    "official_verifier_target",
    "artifacts",
    "retention",
    "data_boundary",
    "prepared_by",
    "completed_at",
    "accepted_at",
}
ARTIFACT_KEYS = {"name", "relative_path", "sha256", "size_bytes", "media_type"}
ARTIFACT_NAMES = {
    "workload_manifest",
    "adapter_artifact",
    "baseline_benchmark_report",
    "candidate_benchmark_report",
    "proof_bundle",
    "official_verification_report",
    "raw_measurements_archive",
    "reproduction_instructions",
    "known_limitations",
    "production_recommendation",
    "written_acceptance",
}
RETENTION_KEYS = {
    "policy_id",
    "application_delete_by",
    "artifact_retain_until",
    "artifact_delete_by",
    "deletion_owner",
}
DATA_BOUNDARY = MappingProxyType(
    {
        "witness_data_included": False,
        "credentials_included": False,
        "customer_personal_data_included": False,
        "private_source_included": False,
    }
)


def canonical_timestamp(raw: Any, field: str, *, future_allowed: bool) -> datetime:
    if not isinstance(raw, str) or not raw:
        raise ValueError(f"{field} is required")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError(f"{field} must be an RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError(f"{field} must include a UTC offset and second precision")
    if raw != parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"):
        raise ValueError(f"{field} must use canonical UTC Z form")
    if not future_allowed and parsed > datetime.now(timezone.utc):
        raise ValueError(f"{field} cannot be in the future")
    return parsed


def read_owner_only(path: Path, label: str, max_bytes: int) -> bytes:
    try:
        if path.is_symlink():
            raise ValueError(f"{label} must not be a symlink")
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError(f"{label} must be a regular file")
            if (
                stat.S_IMODE(metadata.st_mode) & 0o077
                or metadata.st_uid != os.geteuid()
            ):
                raise ValueError(f"{label} must be owner-only and operator-owned")
            raw = handle.read(max_bytes + 1)
        if not raw or len(raw) > max_bytes:
            raise ValueError(f"{label} is empty or oversized")
        return raw
    except OSError as error:
        raise ValueError(f"{label} is unavailable or unsafe") from error


def parse_json(raw: bytes, label: str) -> Any:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} duplicates JSON key: {key}")
            result[key] = value
        return result

    try:
        return json.loads(
            raw,
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"{label} contains forbidden number: {value}")
            ),
        )
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} must be UTF-8 JSON") from error


def sha256_file(handle: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    total = 0
    while True:
        block = handle.read(1024 * 1024)
        if not block:
            break
        digest.update(block)
        total += len(block)
    return digest.hexdigest(), total


def resolve_artifact(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise ValueError("artifact relative_path is malformed")
    pure = PurePosixPath(relative)
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError("artifact relative_path must stay below the artifact root")
    root_resolved = root.resolve(strict=True)
    candidate = root_resolved.joinpath(*pure.parts)
    try:
        candidate_resolved = candidate.resolve(strict=True)
        candidate_resolved.relative_to(root_resolved)
    except (OSError, ValueError) as error:
        raise ValueError(
            "artifact path escapes or is missing from the artifact root"
        ) from error
    if candidate.is_symlink() or candidate_resolved != candidate.absolute():
        raise ValueError("artifact path may not contain symlinks")
    return candidate_resolved


def verify_artifact(root: Path, descriptor: Any) -> tuple[dict[str, Any], Path]:
    if not isinstance(descriptor, dict) or set(descriptor) != ARTIFACT_KEYS:
        raise ValueError("delivery artifact descriptor fields are missing or unknown")
    name = descriptor.get("name")
    if name not in ARTIFACT_NAMES:
        raise ValueError("delivery artifact name is unsupported")
    if (
        not isinstance(descriptor.get("sha256"), str)
        or HEX_SHA256.fullmatch(descriptor["sha256"]) is None
    ):
        raise ValueError(f"delivery artifact {name} SHA-256 is malformed")
    if (
        not isinstance(descriptor.get("size_bytes"), int)
        or isinstance(descriptor["size_bytes"], bool)
        or descriptor["size_bytes"] <= 0
    ):
        raise ValueError(f"delivery artifact {name} size is malformed")
    if (
        not isinstance(descriptor.get("media_type"), str)
        or not descriptor["media_type"].strip()
    ):
        raise ValueError(f"delivery artifact {name} media type is required")
    path = resolve_artifact(root, descriptor.get("relative_path"))
    descriptor_fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor_fd, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError(f"delivery artifact {name} is not regular")
        if stat.S_IMODE(metadata.st_mode) & 0o077 or metadata.st_uid != os.geteuid():
            raise ValueError(
                f"delivery artifact {name} must be owner-only and operator-owned"
            )
        actual_sha, actual_size = sha256_file(handle)
    if actual_sha != descriptor["sha256"] or actual_size != descriptor["size_bytes"]:
        raise ValueError(f"delivery artifact {name} does not match its descriptor")
    return descriptor, path


def _load_json_artifact(path: Path, label: str) -> dict[str, Any]:
    raw = read_owner_only(path, label, MAX_JSON_ARTIFACT_BYTES)
    payload = parse_json(raw, label)
    if not isinstance(payload, dict):
        raise ValueError(f"{label} must be a JSON object")
    return payload


def validate_benchmark_reports(
    baseline: dict[str, Any], candidate: dict[str, Any], manifest: dict[str, Any]
) -> None:
    required = {
        "schema_version",
        "scope",
        "mode",
        "benchmark_session_id",
        "release_sha",
        "dependency_profile",
        "workload_manifest_digest_hex",
        "verification_succeeded",
        "exit_status",
    }
    for label, report, mode in (
        ("baseline", baseline, "baseline"),
        ("candidate", candidate, "bounded"),
    ):
        if not required <= set(report):
            raise ValueError(
                f"{label} benchmark report omits required BenchmarkReportV1 fields"
            )
        if (
            report["schema_version"] != 1
            or report["scope"] != "full_pipeline"
            or report["mode"] != mode
            or report["dependency_profile"] != PROFILE
            or report["verification_succeeded"] is not True
            or report["exit_status"] != 0
        ):
            raise ValueError(
                f"{label} benchmark report is not a passing full-pipeline report"
            )
        if report["release_sha"] != manifest["release_sha"]:
            raise ValueError(f"{label} benchmark report release differs from delivery")
        if (
            report["workload_manifest_digest_hex"]
            != manifest["workload_manifest_digest_hex"]
        ):
            raise ValueError(f"{label} benchmark report workload differs from delivery")
    if baseline["benchmark_session_id"] != candidate["benchmark_session_id"]:
        raise ValueError(
            "baseline and candidate reports are not from the same benchmark session"
        )


def validate_proof_bundle(
    bundle: dict[str, Any], manifest: dict[str, Any], workload_manifest: dict[str, Any]
) -> None:
    if bundle.get("schema_version") != 1 or not isinstance(
        bundle.get("provenance"), dict
    ):
        raise ValueError("proof bundle is not ProofBundleV1")
    provenance = bundle["provenance"]
    if (
        provenance.get("prover_version") != "0.6.1"
        or provenance.get("verifier_version") != "0.6.1"
        or provenance.get("dependency_profile") != PROFILE
        or provenance.get("release_sha") != manifest["release_sha"]
        or bundle.get("manifest_digest_hex") != manifest["workload_manifest_digest_hex"]
        or bundle.get("manifest") != workload_manifest
    ):
        raise ValueError("proof bundle provenance differs from delivery")
    if not isinstance(bundle.get("proof_digest_hex"), str) or not re.fullmatch(
        r"[0-9a-f]{64}", bundle["proof_digest_hex"]
    ):
        raise ValueError("proof bundle digest is malformed")


def validate_verification_report(
    report: dict[str, Any],
    manifest: dict[str, Any],
    proof_descriptor: dict[str, Any],
    bundle: dict[str, Any],
) -> None:
    exact_keys = {
        "schema_version",
        "verifier_target",
        "verification_succeeded",
        "proof_bundle_sha256",
        "proof_digest_hex",
        "release_sha",
        "verified_at",
        "exact_command",
    }
    if set(report) != exact_keys or report.get("schema_version") != VERIFICATION_SCHEMA:
        raise ValueError("official verification report fields are missing or unknown")
    if (
        report.get("verifier_target") != VERIFIER
        or report.get("verification_succeeded") is not True
        or report.get("proof_bundle_sha256") != proof_descriptor["sha256"]
        or report.get("proof_digest_hex") != bundle.get("proof_digest_hex")
        or report.get("release_sha") != manifest["release_sha"]
    ):
        raise ValueError(
            "official verification report is not bound to the delivered proof"
        )
    if (
        not isinstance(report.get("exact_command"), list)
        or not report["exact_command"]
        or any(
            not isinstance(item, str) or not item for item in report["exact_command"]
        )
    ):
        raise ValueError("official verification report exact_command is malformed")
    canonical_timestamp(report.get("verified_at"), "verified_at", future_allowed=False)


def validate_manifest(path: Path, artifact_root: Path) -> tuple[dict[str, Any], str]:
    if artifact_root.is_symlink():
        raise ValueError("delivery artifact root must not be a symlink")
    try:
        root_metadata = artifact_root.stat()
    except OSError as error:
        raise ValueError("delivery artifact root is unavailable") from error
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or stat.S_IMODE(root_metadata.st_mode) & 0o077
        or root_metadata.st_uid != os.geteuid()
    ):
        raise ValueError(
            "delivery artifact root must be an owner-only operator-owned directory"
        )
    raw = read_owner_only(path, "delivery manifest", MAX_MANIFEST_BYTES)
    manifest = parse_json(raw, "delivery manifest")
    if not isinstance(manifest, dict) or set(manifest) != TOP_LEVEL_KEYS:
        raise ValueError("delivery manifest fields are missing or unknown")
    if manifest["schema_version"] != SCHEMA_VERSION or manifest["status"] != "complete":
        raise ValueError("delivery manifest is not complete v1 evidence")
    if SAFE_ID.fullmatch(str(manifest.get("agreement_id", ""))) is None:
        raise ValueError("delivery agreement_id is malformed")
    if manifest["offer_id"] not in {"founding_evaluation", "standard_evaluation"}:
        raise ValueError("delivery offer is unsupported")
    for field in (
        "workload_manifest_digest_hex",
        "scope_sha256",
        "qualification_sha256",
        "partner_preflight_sha256",
        "agreement_gate_sha256",
    ):
        if (
            not isinstance(manifest[field], str)
            or HEX_SHA256.fullmatch(manifest[field]) is None
        ):
            raise ValueError(f"delivery {field} must be SHA-256")
    for field in ("release_sha", "adapter_revision"):
        if (
            not isinstance(manifest[field], str)
            or re.fullmatch(r"[0-9a-f]{40}", manifest[field]) is None
        ):
            raise ValueError(f"delivery {field} must be a full Git SHA")
    if manifest["official_verifier_target"] != VERIFIER:
        raise ValueError("delivery must target the frozen official verifier")
    if (
        not isinstance(manifest["prepared_by"], str)
        or len(manifest["prepared_by"].strip()) < 3
    ):
        raise ValueError("delivery prepared_by is required")
    completed = canonical_timestamp(
        manifest["completed_at"], "completed_at", future_allowed=False
    )
    accepted = canonical_timestamp(
        manifest["accepted_at"], "accepted_at", future_allowed=False
    )
    if accepted < completed:
        raise ValueError("written acceptance cannot precede completed delivery")
    if manifest["data_boundary"] != DATA_BOUNDARY:
        raise ValueError("delivery package crosses the permitted data boundary")
    retention = manifest["retention"]
    if not isinstance(retention, dict) or set(retention) != RETENTION_KEYS:
        raise ValueError("delivery retention fields are missing or unknown")
    if retention["policy_id"] != "tinyzkp-evaluation-retention-v1":
        raise ValueError("delivery retention policy is unsupported")
    if (
        not isinstance(retention["deletion_owner"], str)
        or len(retention["deletion_owner"].strip()) < 3
    ):
        raise ValueError("delivery deletion owner is required")
    application_delete = canonical_timestamp(
        retention["application_delete_by"], "application_delete_by", future_allowed=True
    )
    retain_until = canonical_timestamp(
        retention["artifact_retain_until"], "artifact_retain_until", future_allowed=True
    )
    delete_by = canonical_timestamp(
        retention["artifact_delete_by"], "artifact_delete_by", future_allowed=True
    )
    if (
        application_delete <= accepted
        or retain_until < accepted
        or delete_by < retain_until
    ):
        raise ValueError("delivery retention schedule is inconsistent")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(ARTIFACT_NAMES):
        raise ValueError(
            "delivery manifest must list every required artifact exactly once"
        )
    verified: dict[str, tuple[dict[str, Any], Path]] = {}
    for raw_descriptor in artifacts:
        descriptor, artifact_path = verify_artifact(artifact_root, raw_descriptor)
        if descriptor["name"] in verified:
            raise ValueError("delivery manifest repeats an artifact name")
        verified[descriptor["name"]] = (descriptor, artifact_path)
    if set(verified) != ARTIFACT_NAMES:
        raise ValueError("delivery manifest omits a required artifact")
    baseline = _load_json_artifact(
        verified["baseline_benchmark_report"][1], "baseline benchmark report"
    )
    candidate = _load_json_artifact(
        verified["candidate_benchmark_report"][1], "candidate benchmark report"
    )
    validate_benchmark_reports(baseline, candidate, manifest)
    workload_manifest = _load_json_artifact(
        verified["workload_manifest"][1], "workload manifest"
    )
    if (
        workload_manifest.get("schema_version") != 1
        or workload_manifest.get("backend") != "plonky3"
        or workload_manifest.get("profile") != PROFILE
        or workload_manifest.get("expected_verifier") != "p3_uni_stark_0.6.1"
        or workload_manifest.get("deterministic_seed") != 0
        or not isinstance(workload_manifest.get("logical_rows"), int)
        or isinstance(workload_manifest.get("logical_rows"), bool)
        or workload_manifest["logical_rows"] <= 0
    ):
        raise ValueError(
            "workload manifest is not the frozen WorkloadManifestV1 profile"
        )
    bundle = _load_json_artifact(verified["proof_bundle"][1], "proof bundle")
    validate_proof_bundle(bundle, manifest, workload_manifest)
    verification = _load_json_artifact(
        verified["official_verification_report"][1], "official verification report"
    )
    validate_verification_report(
        verification, manifest, verified["proof_bundle"][0], bundle
    )
    return manifest, hashlib.sha256(raw).hexdigest()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    _, digest = validate_manifest(args.manifest, args.artifact_root)
    print(json.dumps({"status": "complete", "manifest_sha256": digest}, sort_keys=True))


if __name__ == "__main__":
    main()
