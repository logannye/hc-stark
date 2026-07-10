#!/usr/bin/env python3
"""Create the attested authorization consumed by annual contract billing."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
CI_DIR = ROOT / "scripts" / "ci"
RELEASE_DIR = ROOT / "scripts" / "release"
for directory in (CI_DIR, RELEASE_DIR):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))
import backend_release_ready as gate  # noqa: E402
import finalize_signed_evidence as signed  # noqa: E402


VALIDATOR = "scripts/ci/backend_release_ready.py"
FINAL_SHA = re.compile(r"^[0-9a-f]{40}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
AUTHORIZATION_KEYS = {
    "schema_version",
    "status",
    "release_sha",
    "source_tree_sha256",
    "backend_evidence_sha256",
    "backend_release_ready_report_sha256",
    "signed_release_manifest_sha256",
    "signature_bundle_sha256",
    "verified_at",
    "validator",
    "validator_exit_code",
}


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical_timestamp(raw: str | None) -> str:
    if raw is None:
        return datetime.now(timezone.utc).replace(microsecond=0).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except (AttributeError, ValueError) as error:
        raise ValueError("verified_at must be a canonical UTC RFC 3339 timestamp") from error
    if parsed.tzinfo is None or parsed.microsecond != 0:
        raise ValueError("verified_at must be a canonical UTC RFC 3339 timestamp")
    canonical = parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if raw != canonical:
        raise ValueError("verified_at must be a canonical UTC RFC 3339 timestamp")
    return canonical


def safe_output(root: Path, raw: Path) -> Path:
    root = root.resolve()
    candidate = raw if raw.is_absolute() else root / raw
    candidate = candidate.absolute()
    if not candidate.is_relative_to(root):
        raise ValueError(f"commercial authorization output is outside the repository: {raw}")
    relative = candidate.relative_to(root)
    if ".." in relative.parts:
        raise ValueError(f"commercial authorization output is unsafe: {raw}")
    current = root
    for part in relative.parent.parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"commercial authorization output parent is unsafe: {raw}")
    if candidate.exists() and candidate.is_symlink():
        raise ValueError(f"commercial authorization output is unsafe: {raw}")
    resolved_parent = candidate.parent.resolve()
    if not resolved_parent.is_relative_to(root):
        raise ValueError(f"commercial authorization output parent is unsafe: {raw}")
    return resolved_parent / candidate.name


def canonical_json(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode() + b"\n"


def _stage(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return temporary


def write_pair_atomic(
    report_path: Path,
    report_payload: bytes,
    authorization_path: Path,
    authorization_payload: bytes,
) -> None:
    report_temporary: Path | None = None
    authorization_temporary: Path | None = None
    try:
        report_temporary = _stage(report_path, report_payload)
        authorization_temporary = _stage(authorization_path, authorization_payload)
        os.replace(report_temporary, report_path)
        report_temporary = None
        os.replace(authorization_temporary, authorization_path)
        authorization_temporary = None
        descriptor = os.open(report_path.parent, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        if authorization_path.parent != report_path.parent:
            descriptor = os.open(authorization_path.parent, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if report_temporary is not None:
            report_temporary.unlink(missing_ok=True)
        if authorization_temporary is not None:
            authorization_temporary.unlink(missing_ok=True)


def build(
    *,
    root: Path,
    config_path: Path,
    output_report: Path,
    output_authorization: Path,
    cosign: str,
    verified_at: str | None = None,
) -> tuple[dict[str, object], dict[str, object], str]:
    root = root.resolve()
    config_path = signed.safe_file(root, config_path)
    config = gate.read_object(config_path)
    problems = gate.failures(config, root=root)
    if problems:
        raise ValueError("backend release is not ready: " + "; ".join(problems))

    evidence_path = signed.safe_file(root, Path(str(config["evidence_manifest"])))
    evidence = gate.read_object(evidence_path)
    release_sha = evidence.get("release_sha")
    source_release_sha = evidence.get("source_release_sha")
    source_tree_sha256 = evidence.get("source_tree_sha256")
    if (
        not isinstance(release_sha, str)
        or FINAL_SHA.fullmatch(release_sha) is None
        or not isinstance(source_release_sha, str)
        or FINAL_SHA.fullmatch(source_release_sha) is None
        or not isinstance(source_tree_sha256, str)
        or SHA256.fullmatch(source_tree_sha256) is None
    ):
        raise ValueError("final backend evidence has a malformed source/release identity")

    gates = evidence.get("gates")
    signed_gate = (
        gates.get("signed_release_sbom_and_checksums")
        if isinstance(gates, dict)
        else None
    )
    descriptors = signed_gate.get("artifacts") if isinstance(signed_gate, dict) else None
    if not isinstance(descriptors, list):
        raise ValueError("signed backend release artifacts are missing")
    role_paths: dict[str, Path] = {}
    for descriptor in descriptors:
        path, validated = gate.safe_artifact(root, descriptor)
        role = validated.get("role")
        if not isinstance(role, str) or not role or role in role_paths:
            raise ValueError("signed backend release artifact roles are malformed or duplicated")
        role_paths[role] = path
    if set(role_paths) != {"sbom", "checksums", "signature"}:
        raise ValueError("signed backend release must contain exactly SBOM, checksums, and signature")

    sbom = role_paths["sbom"]
    checksums = role_paths["checksums"]
    signature = role_paths["signature"]
    signed.verify_spdx_sbom(sbom)
    checksum_entries = signed.verify_checksum_manifest(
        checksums, sbom, signed.REQUIRED_CHECKSUM_ENTRIES
    )
    if Path(cosign).name != "cosign":
        raise ValueError("cosign executable name must equal cosign")
    verification_command = [
        cosign,
        "verify-blob",
        "--bundle",
        str(signature),
        "--certificate-identity-regexp",
        signed.SIGSTORE_IDENTITY_REGEXP,
        "--certificate-oidc-issuer",
        signed.SIGSTORE_ISSUER,
        str(checksums),
    ]
    verified = gate.evidence_runtime.run_anchored_cosign(
        root,
        release_sha,
        cosign,
        verification_command[1:],
    )
    if verified.returncode != 0:
        raise ValueError(f"Sigstore verification failed: {verified.stdout[-2000:]}")

    timestamp = canonical_timestamp(verified_at)
    report = {
        "schema_version": 1,
        "status": "ready",
        "validator": VALIDATOR,
        "validator_exit_code": 0,
        "verified_at": timestamp,
        "release_sha": release_sha,
        "source_release_sha": source_release_sha,
        "source_tree_sha256": source_tree_sha256,
        "config": {
            "path": config_path.relative_to(root).as_posix(),
            "sha256": sha256(config_path),
        },
        "backend_evidence": {
            "path": evidence_path.relative_to(root).as_posix(),
            "sha256": sha256(evidence_path),
        },
        "signed_release_manifest": {
            "path": checksums.relative_to(root).as_posix(),
            "sha256": sha256(checksums),
            "checksum_entries": checksum_entries,
        },
        "signature_bundle": {
            "path": signature.relative_to(root).as_posix(),
            "sha256": sha256(signature),
            "verified": True,
            "identity_regexp": signed.SIGSTORE_IDENTITY_REGEXP,
            "oidc_issuer": signed.SIGSTORE_ISSUER,
        },
        "validator_problems": [],
    }
    report_payload = canonical_json(report)
    report_sha256 = hashlib.sha256(report_payload).hexdigest()
    authorization = {
        "schema_version": 1,
        "status": "ready",
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_sha256,
        "backend_evidence_sha256": sha256(evidence_path),
        "backend_release_ready_report_sha256": report_sha256,
        "signed_release_manifest_sha256": sha256(checksums),
        "signature_bundle_sha256": sha256(signature),
        "verified_at": timestamp,
        "validator": VALIDATOR,
        "validator_exit_code": 0,
    }
    if set(authorization) != AUTHORIZATION_KEYS:
        raise AssertionError("commercial authorization contract drifted")
    authorization_payload = canonical_json(authorization)
    authorization_sha256 = hashlib.sha256(authorization_payload).hexdigest()

    output_report = safe_output(root, output_report)
    output_authorization = safe_output(root, output_authorization)
    if output_report == output_authorization:
        raise ValueError("commercial report and authorization outputs must differ")
    write_pair_atomic(
        output_report,
        report_payload,
        output_authorization,
        authorization_payload,
    )
    return report, authorization, authorization_sha256


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-report", type=Path, required=True)
    parser.add_argument("--output-authorization", type=Path, required=True)
    parser.add_argument("--verified-at")
    args = parser.parse_args(argv)
    try:
        cosign = shutil.which("cosign")
        if cosign is None:
            raise ValueError("cosign is required to verify commercial release provenance")
        _, _, digest = build(
            root=ROOT,
            config_path=args.config,
            output_report=args.output_report,
            output_authorization=args.output_authorization,
            cosign=cosign,
            verified_at=args.verified_at,
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"commercial release authorization failed: {error}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": "ready",
                "authorization": str(args.output_authorization),
                "authorization_sha256": digest,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
