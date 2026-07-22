#!/usr/bin/env python3
"""Verify the owner-dispatched, keyless-signed backend candidate assembly."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
from typing import Callable

import assemble_backend_candidate as assembly
import build_candidate_evidence as candidate
import evidence_runtime


ROOT = Path(__file__).resolve().parents[2]
ASSEMBLY_NAME = "backend-candidate-assembly-v1.json"
BUNDLE_NAME = "backend-candidate-assembly-v1.sigstore.json"
WORKFLOW_PATH = ".github/workflows/assemble-backend-evidence.yml"
CERTIFICATE_IDENTITY = (
    "https://github.com/logannye/hc-stark/.github/workflows/"
    "assemble-backend-evidence.yml@refs/heads/main"
)
OIDC_ISSUER = "https://token.actions.githubusercontent.com"
MAX_JSON_BYTES = 16 * 1024 * 1024
CosignRunner = Callable[..., subprocess.CompletedProcess[str]]


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _read_object(root: Path, relative: str) -> tuple[Path, dict[str, object], bytes]:
    path = candidate.safe_existing_file(root, relative)
    payload = candidate.final_gate.read_bounded_file(path, maximum=MAX_JSON_BYTES)
    value = candidate.strict_json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"assembly JSON must contain an object: {relative}")
    return path, value, payload


def _snapshot(path: Path) -> tuple[tuple[int, ...], str]:
    details = os.lstat(path)
    if (
        not stat.S_ISREG(details.st_mode)
        or stat.S_ISLNK(details.st_mode)
        or details.st_nlink != 1
        or not 0 < details.st_size <= MAX_JSON_BYTES
    ):
        raise ValueError(f"assembly signature input is not a stable file: {path.name}")
    identity = (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
    )
    return identity, candidate.final_gate.bounded_file_sha256(path)


def _expected_bindings(
    root: Path, evidence: dict[str, object]
) -> tuple[list[dict[str, str]], dict[tuple[str, str], str]]:
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        raise ValueError("candidate gate inventory is missing")
    bindings: list[dict[str, str]] = []
    lookup: dict[tuple[str, str], str] = {}
    for gate in sorted(candidate.GATE_ROLES):
        raw_gate = gates.get(gate)
        artifacts = raw_gate.get("artifacts") if isinstance(raw_gate, dict) else None
        if not isinstance(artifacts, list):
            raise ValueError(f"candidate gate artifact inventory is missing: {gate}")
        for descriptor in artifacts:
            path, validated = candidate.final_gate.safe_artifact(root, descriptor)
            role = str(validated["role"])
            digest = str(validated["sha256"])
            key = (gate, role)
            if key in lookup:
                raise ValueError("candidate assembly contains a duplicate artifact role")
            lookup[key] = digest
            bindings.append(
                {
                    "gate": gate,
                    "role": role,
                    "path": path.relative_to(root).as_posix(),
                    "sha256": digest,
                }
            )
    expected_count = sum(len(roles) for roles in candidate.GATE_ROLES.values())
    if len(bindings) != expected_count:
        raise ValueError("candidate artifact binding inventory is incomplete")
    return bindings, lookup


def _verify_qualification_sources(
    *,
    root: Path,
    release_sha: str,
    raw: object,
    binding_lookup: dict[tuple[str, str], str],
) -> None:
    if not isinstance(raw, dict) or set(raw) != {"resource", "recovery"}:
        raise ValueError("assembly qualification source inventory is not closed")
    provenance_root = (
        root / "release" / "evidence" / "backend-v1" / release_sha / "provenance"
    )
    plan = assembly.artifact_plan()
    for kind in ("resource", "recovery"):
        value = raw[kind]
        if not isinstance(value, dict) or set(value) != {
            "path",
            "sha256",
            "checksum_manifest",
            "run",
        }:
            raise ValueError(f"{kind} assembly provenance binding is not closed")
        expected_path = provenance_root / f"{kind}-qualification-run-v1.json"
        path, stored_run, payload = _read_object(
            root, expected_path.relative_to(root).as_posix()
        )
        if value.get("path") != path.relative_to(root).as_posix():
            raise ValueError(f"{kind} assembly provenance path is skewed")
        if value.get("sha256") != _sha256(payload) or value.get("run") != stored_run:
            raise ValueError(f"{kind} assembly provenance digest is skewed")
        artifact = stored_run.get("artifact")
        archive_sha256 = (
            artifact.get("archive_sha256") if isinstance(artifact, dict) else None
        )
        if not isinstance(archive_sha256, str):
            raise ValueError(f"{kind} qualification archive identity is missing")
        assembly.validate_run_provenance_value(
            stored_run,
            kind=kind,
            release_sha=release_sha,
            archive_sha256=archive_sha256,
        )
        checksum_name = assembly.CHECKSUM_MANIFESTS[kind]
        checksum_path = candidate.safe_existing_file(
            root, (provenance_root / checksum_name).relative_to(root).as_posix()
        )
        checksum_payload = candidate.final_gate.read_bounded_file(
            checksum_path, maximum=1024 * 1024
        )
        checksum_binding = value.get("checksum_manifest")
        if not isinstance(checksum_binding, dict) or set(checksum_binding) != {
            "path",
            "sha256",
        }:
            raise ValueError(f"{kind} checksum binding is not closed")
        if checksum_binding != {
            "path": checksum_path.relative_to(root).as_posix(),
            "sha256": _sha256(checksum_payload),
        }:
            raise ValueError(f"{kind} checksum manifest digest is skewed")
        observed = assembly.parse_checksum_manifest(
            checksum_payload, label=f"{kind} qualification"
        )
        expected: dict[str, str] = {}
        for spec in plan:
            if spec.source_kind != kind:
                continue
            digest = binding_lookup[(spec.gate, spec.role)]
            previous = expected.setdefault(spec.source, digest)
            if previous != digest:
                raise ValueError(f"{kind} candidate source digest is inconsistent")
        if observed != expected:
            raise ValueError(f"{kind} checksum manifest differs from candidate bindings")


def verify(
    *,
    root: Path = ROOT,
    candidate_config: dict[str, object],
    expected_release_sha: str | None = None,
    cosign: str | Path | None = None,
    cosign_runner: CosignRunner = evidence_runtime.run_anchored_cosign,
) -> dict[str, object]:
    root = root.resolve()
    content_failures = candidate.prerelease.candidate_content_failures(
        candidate_config, root=root
    )
    if content_failures:
        raise ValueError("candidate content is invalid: " + "; ".join(content_failures))

    config_path, canonical_config, config_payload = _read_object(
        root, "release/backend-v1-gates.json"
    )
    if canonical_config != candidate_config:
        raise ValueError("candidate config differs from the canonical signed input")
    evidence_relative = canonical_config.get("evidence_manifest")
    if evidence_relative != "release/evidence/backend-v1-evidence.json":
        raise ValueError("candidate evidence manifest path is noncanonical")
    evidence_path, evidence, evidence_payload = _read_object(root, evidence_relative)
    release_sha = evidence.get("release_sha")
    if (
        not isinstance(release_sha, str)
        or assembly.RELEASE_SHA.fullmatch(release_sha) is None
        or (expected_release_sha is not None and release_sha != expected_release_sha)
    ):
        raise ValueError("assembly release source identity is skewed")

    provenance_root = (
        root / "release" / "evidence" / "backend-v1" / release_sha / "provenance"
    )
    assembly_path, report, _report_payload = _read_object(
        root, (provenance_root / ASSEMBLY_NAME).relative_to(root).as_posix()
    )
    bundle_path = candidate.safe_existing_file(
        root, (provenance_root / BUNDLE_NAME).relative_to(root).as_posix()
    )
    if set(report) != {
        "schema_version",
        "kind",
        "release_sha",
        "issued_at",
        "assembly_workflow",
        "qualification_sources",
        "candidate",
    } or report.get("schema_version") != 1 or isinstance(
        report.get("schema_version"), bool
    ) or report.get("kind") != "tinyzkp_backend_candidate_assembly_v1" or report.get(
        "release_sha"
    ) != release_sha:
        raise ValueError("assembly provenance identity is malformed")
    assembly.timestamp_value(report.get("issued_at"), label="issued_at")
    workflow = report.get("assembly_workflow")
    if not isinstance(workflow, dict) or set(workflow) != {
        "repository",
        "workflow_path",
        "workflow_ref",
        "run_id",
        "run_attempt",
        "actor",
        "triggering_actor",
    } or workflow.get("repository") != "logannye/hc-stark" or workflow.get(
        "workflow_path"
    ) != WORKFLOW_PATH or workflow.get("workflow_ref") != "refs/heads/main" or type(
        workflow.get("run_id")
    ) is not int or workflow.get("run_id", 0) <= 0 or type(
        workflow.get("run_attempt")
    ) is not int or workflow.get("run_attempt", 0) <= 0 or workflow.get(
        "actor"
    ) != "logannye" or workflow.get("triggering_actor") != "logannye":
        raise ValueError("assembly workflow identity is malformed")

    bindings, binding_lookup = _expected_bindings(root, evidence)
    raw_candidate = report.get("candidate")
    if not isinstance(raw_candidate, dict) or set(raw_candidate) != {
        "config_path",
        "config_sha256",
        "evidence_path",
        "evidence_sha256",
        "source_tree_sha256",
        "artifact_bindings",
    } or raw_candidate != {
        "config_path": config_path.relative_to(root).as_posix(),
        "config_sha256": _sha256(config_payload),
        "evidence_path": evidence_path.relative_to(root).as_posix(),
        "evidence_sha256": _sha256(evidence_payload),
        "source_tree_sha256": evidence.get("source_tree_sha256"),
        "artifact_bindings": bindings,
    }:
        raise ValueError("assembly candidate bindings are incomplete or skewed")
    _verify_qualification_sources(
        root=root,
        release_sha=release_sha,
        raw=report.get("qualification_sources"),
        binding_lookup=binding_lookup,
    )

    before = (_snapshot(assembly_path), _snapshot(bundle_path))
    executable = cosign or os.environ.get("TINYZKP_COSIGN") or shutil.which("cosign")
    if not executable:
        raise ValueError("anchored cosign executable is unavailable")
    arguments = [
        "verify-blob",
        "--bundle",
        str(bundle_path),
        "--certificate-identity",
        CERTIFICATE_IDENTITY,
        "--certificate-oidc-issuer",
        OIDC_ISSUER,
        "--certificate-github-workflow-sha",
        release_sha,
        "--certificate-github-workflow-ref",
        "refs/heads/main",
        "--certificate-github-workflow-repository",
        "logannye/hc-stark",
        "--certificate-github-workflow-trigger",
        "workflow_dispatch",
        str(assembly_path),
    ]
    completed = cosign_runner(root, release_sha, executable, arguments)
    if completed.returncode != 0:
        raise ValueError("assembly Sigstore certificate or signature is invalid")
    if before != (_snapshot(assembly_path), _snapshot(bundle_path)):
        raise ValueError("assembly signature inputs changed during verification")
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--candidate-config",
        type=Path,
        default=ROOT / "release" / "backend-v1-gates.json",
    )
    parser.add_argument("--expected-release-sha")
    args = parser.parse_args(argv)
    try:
        config = candidate.final_gate.read_object(args.candidate_config)
        verify(
            root=ROOT,
            candidate_config=config,
            expected_release_sha=args.expected_release_sha,
        )
    except (OSError, ValueError, json.JSONDecodeError, subprocess.TimeoutExpired) as error:
        print(f"backend assembly verification failed: {error}", file=sys.stderr)
        return 2
    print("PASS  backend candidate assembly signature and bindings are valid")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
