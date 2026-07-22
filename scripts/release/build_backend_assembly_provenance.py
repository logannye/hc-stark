#!/usr/bin/env python3
"""Bind a validated backend candidate and its qualification run provenance."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

import assemble_backend_candidate as assembly
import build_candidate_evidence as candidate


ROOT = Path(__file__).resolve().parents[2]
WORKFLOW_PATH = ".github/workflows/assemble-backend-evidence.yml"
MAX_JSON_BYTES = 16 * 1024 * 1024


def read_object(root: Path, path: Path) -> tuple[Path, dict[str, object], bytes]:
    relative = (
        path.relative_to(root).as_posix() if path.is_absolute() else path.as_posix()
    )
    resolved = candidate.safe_existing_file(root, relative)
    payload = candidate.final_gate.read_bounded_file(resolved, maximum=MAX_JSON_BYTES)
    try:
        value = candidate.strict_json.loads(payload)
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"assembly JSON is malformed: {path}") from error
    if not isinstance(value, dict):
        raise ValueError(f"assembly JSON must contain an object: {path}")
    return resolved, value, payload


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def positive_integer(value: int, *, label: str) -> int:
    if type(value) is not int or value <= 0:
        raise ValueError(f"{label} must be a positive integer")
    return value


def build_report(
    *,
    root: Path,
    release_sha: str,
    candidate_config: Path,
    resource_provenance: Path,
    recovery_provenance: Path,
    workflow_run_id: int,
    workflow_run_attempt: int,
    actor: str,
    triggering_actor: str,
    issued_at: str,
) -> dict[str, object]:
    root = root.resolve()
    if assembly.RELEASE_SHA.fullmatch(release_sha) is None:
        raise ValueError("release SHA must be one lowercase 40-hex commit")
    if actor != "logannye" or triggering_actor != "logannye":
        raise ValueError("assembly workflow must be owner-dispatched")
    positive_integer(workflow_run_id, label="workflow run ID")
    positive_integer(workflow_run_attempt, label="workflow run attempt")
    assembly.timestamp_value(issued_at, label="issued_at")

    config_path, config, config_payload = read_object(root, candidate_config)
    if config_path != root / "release" / "backend-v1-gates.json":
        raise ValueError("candidate config path is noncanonical")
    failures = candidate.prerelease.candidate_content_failures(config, root=root)
    if failures:
        raise ValueError("candidate config is not ready: " + "; ".join(failures))
    evidence_raw = config.get("evidence_manifest")
    if evidence_raw != "release/evidence/backend-v1-evidence.json":
        raise ValueError("candidate evidence manifest path is noncanonical")
    evidence_path, evidence, evidence_payload = read_object(root, Path(evidence_raw))
    if evidence.get("release_sha") != release_sha:
        raise ValueError("candidate evidence release identity is skewed")

    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        raise ValueError("candidate gate inventory is missing")
    bindings: list[dict[str, str]] = []
    for gate in sorted(candidate.prerelease.EXPECTED_GATES):
        raw_gate = gates.get(gate)
        artifacts = raw_gate.get("artifacts") if isinstance(raw_gate, dict) else None
        if not isinstance(artifacts, list):
            raise ValueError(f"candidate gate artifact inventory is missing: {gate}")
        for descriptor in artifacts:
            path, validated = candidate.final_gate.safe_artifact(root, descriptor)
            bindings.append(
                {
                    "gate": gate,
                    "role": str(validated["role"]),
                    "path": path.relative_to(root).as_posix(),
                    "sha256": str(validated["sha256"]),
                }
            )
    if len(bindings) != sum(len(value) for value in candidate.GATE_ROLES.values()):
        raise ValueError("candidate artifact binding inventory is incomplete")
    binding_lookup = {
        (binding["gate"], binding["role"]): binding["sha256"] for binding in bindings
    }

    qualifications: dict[str, object] = {}
    for kind, raw_path in (
        ("resource", resource_provenance),
        ("recovery", recovery_provenance),
    ):
        path, value, payload = read_object(root, raw_path)
        expected_path = (
            root
            / "release"
            / "evidence"
            / "backend-v1"
            / release_sha
            / "provenance"
            / f"{kind}-qualification-run-v1.json"
        )
        if path != expected_path:
            raise ValueError(f"{kind} qualification provenance path is noncanonical")
        artifact = value.get("artifact")
        archive_sha256 = (
            artifact.get("archive_sha256") if isinstance(artifact, dict) else None
        )
        if not isinstance(archive_sha256, str):
            raise ValueError(f"{kind} qualification archive identity is missing")
        assembly.validate_run_provenance_value(
            value,
            kind=kind,
            release_sha=release_sha,
            archive_sha256=archive_sha256,
        )
        checksum_name = assembly.CHECKSUM_MANIFESTS[kind]
        checksum_path = candidate.safe_existing_file(
            root, (path.parent / checksum_name).relative_to(root).as_posix()
        )
        checksum_payload = candidate.final_gate.read_bounded_file(
            checksum_path, maximum=1024 * 1024
        )
        checksum_entries = assembly.parse_checksum_manifest(
            checksum_payload, label=f"{kind} qualification"
        )
        expected_entries: dict[str, str] = {}
        for spec in assembly.artifact_plan():
            if spec.source_kind != kind:
                continue
            digest = binding_lookup[(spec.gate, spec.role)]
            previous = expected_entries.setdefault(spec.source, digest)
            if previous != digest:
                raise ValueError(
                    f"{kind} candidate contains conflicting source artifact digests"
                )
        if checksum_entries != expected_entries:
            raise ValueError(
                f"{kind} checksum manifest differs from candidate artifact bindings"
            )
        qualifications[kind] = {
            "path": path.relative_to(root).as_posix(),
            "sha256": sha256(payload),
            "checksum_manifest": {
                "path": checksum_path.relative_to(root).as_posix(),
                "sha256": sha256(checksum_payload),
            },
            "run": value,
        }

    return {
        "schema_version": 1,
        "kind": "tinyzkp_backend_candidate_assembly_v1",
        "release_sha": release_sha,
        "issued_at": issued_at,
        "assembly_workflow": {
            "repository": "logannye/hc-stark",
            "workflow_path": WORKFLOW_PATH,
            "workflow_ref": "refs/heads/main",
            "run_id": workflow_run_id,
            "run_attempt": workflow_run_attempt,
            "actor": actor,
            "triggering_actor": triggering_actor,
        },
        "qualification_sources": qualifications,
        "candidate": {
            "config_path": config_path.relative_to(root).as_posix(),
            "config_sha256": sha256(config_payload),
            "evidence_path": evidence_path.relative_to(root).as_posix(),
            "evidence_sha256": sha256(evidence_payload),
            "source_tree_sha256": evidence.get("source_tree_sha256"),
            "artifact_bindings": bindings,
        },
    }


def timestamp() -> str:
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--candidate-config", type=Path, required=True)
    parser.add_argument("--resource-provenance", type=Path, required=True)
    parser.add_argument("--recovery-provenance", type=Path, required=True)
    parser.add_argument("--workflow-run-id", type=int, required=True)
    parser.add_argument("--workflow-run-attempt", type=int, required=True)
    parser.add_argument("--actor", required=True)
    parser.add_argument("--triggering-actor", required=True)
    parser.add_argument("--issued-at", default=timestamp())
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = build_report(
            root=ROOT,
            release_sha=args.release_sha,
            candidate_config=args.candidate_config,
            resource_provenance=args.resource_provenance,
            recovery_provenance=args.recovery_provenance,
            workflow_run_id=args.workflow_run_id,
            workflow_run_attempt=args.workflow_run_attempt,
            actor=args.actor,
            triggering_actor=args.triggering_actor,
            issued_at=args.issued_at,
        )
        output = candidate.safe_output(ROOT, args.output)
        expected = (
            ROOT
            / "release"
            / "evidence"
            / "backend-v1"
            / args.release_sha
            / "provenance"
            / "backend-candidate-assembly-v1.json"
        )
        if output != expected:
            raise ValueError("assembly provenance output path is noncanonical")
        candidate.write_json_atomic(output, report)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"backend assembly provenance failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
