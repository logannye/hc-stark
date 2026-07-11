#!/usr/bin/env python3
"""Derive public-beta readiness from hash-bound first-party evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CHANNELS = ROOT / "release" / "release-channels-v1.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def current_sha(root: Path = ROOT) -> str:
    return subprocess.check_output(
        ["git", "rev-parse", "HEAD"], cwd=root, text=True
    ).strip()


def audit(evidence_path: Path, root: Path = ROOT, expected_sha: str | None = None) -> dict[str, Any]:
    channels = json.loads((root / "release" / "release-channels-v1.json").read_text())
    required = channels["channels"]["public_beta"]["required_gate_ids"]
    evidence = json.loads(evidence_path.read_text(encoding="utf-8"))
    failures: list[str] = []
    release_sha = evidence.get("release_sha")
    if evidence.get("schema_version") != 1 or evidence.get("release_channel") != "public_beta":
        failures.append("evidence schema/channel mismatch")
    if not isinstance(release_sha, str) or not GIT_SHA.fullmatch(release_sha):
        failures.append("release_sha must be a full lowercase Git SHA")
    if expected_sha is not None and release_sha != expected_sha:
        failures.append("evidence release_sha does not match candidate")
    gates = evidence.get("gates", {})
    if set(gates) != set(required):
        failures.append("evidence gate set differs from public-beta policy")
    verified: dict[str, list[dict[str, str]]] = {}
    for gate_id in required:
        artifacts = gates.get(gate_id, [])
        if not isinstance(artifacts, list) or not artifacts:
            failures.append(f"{gate_id}: missing evidence")
            continue
        verified[gate_id] = []
        for artifact in artifacts:
            if not isinstance(artifact, dict) or set(artifact) != {"path", "sha256"}:
                failures.append(f"{gate_id}: malformed artifact reference")
                continue
            relative = Path(str(artifact["path"]))
            digest = str(artifact["sha256"])
            path = (root / relative).resolve()
            try:
                path.relative_to(root.resolve())
            except ValueError:
                failures.append(f"{gate_id}: artifact escapes repository")
                continue
            if not SHA256.fullmatch(digest) or not path.is_file():
                failures.append(f"{gate_id}: missing artifact or invalid SHA-256")
                continue
            actual = file_sha256(path)
            if actual != digest:
                failures.append(f"{gate_id}: artifact digest mismatch")
                continue
            verified[gate_id].append({"path": relative.as_posix(), "sha256": actual})
    status = "ready" if not failures else "blocked"
    report = {
        "schema_version": 1,
        "release_channel": "public_beta",
        "status": status,
        "release_sha": release_sha,
        "evidence_manifest_sha256": hashlib.sha256(canonical_json(evidence)).hexdigest(),
        "verified_gates": verified,
        "failures": failures,
    }
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--release-sha", default=current_sha())
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = audit(args.evidence, expected_sha=args.release_sha)
    encoded = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(encoded, encoding="utf-8")
    else:
        print(encoded, end="")
    raise SystemExit(0 if report["status"] == "ready" else 1)


if __name__ == "__main__":
    main()
