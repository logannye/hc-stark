#!/usr/bin/env python3
"""Derive public-beta readiness from hash-bound first-party evidence."""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
CHANNELS = ROOT / "release" / "release-channels-v1.json"
SHA256 = re.compile(r"^[0-9a-f]{64}$")
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
PASSING_STATUSES = {"passed", "ready", "clean", "complete", "completed"}
FORBIDDEN_EVIDENCE = (b"sk_live_", b"sk_test_", b"whsec_", b"X-Amz-Signature=", b"__Host-tinyzkp_beta=")


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot load evidence validator: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def json_records(paths: list[Path]) -> list[tuple[Path, dict[str, Any]]]:
    records: list[tuple[Path, dict[str, Any]]] = []
    for path in paths:
        if path.suffix != ".json" or path.stat().st_size > 32 * 1024 * 1024:
            continue
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (UnicodeError, ValueError):
            continue
        if isinstance(value, dict):
            records.append((path, value))
    return records


def validate_gate_semantics(
    gate_id: str, paths: list[Path], release_sha: str, root: Path
) -> list[str]:
    failures: list[str] = []
    records = json_records(paths)
    identity_records = [
        value for _, value in records
        if value.get("release_sha") == release_sha and value.get("status") in PASSING_STATUSES
    ]
    if not identity_records:
        failures.append(f"{gate_id}: no passing exact-release semantic record")
        return failures
    try:
        if gate_id == "recovery_and_billing_replay":
            stripe_module = load_module(
                "public_beta_stripe_drill_gate", root / "billing" / "public_beta_stripe_drill.py"
            )
            stripe_records = [value for _, value in records if value.get("schema_version") == stripe_module.SCHEMA]
            if len(stripe_records) != 1:
                raise ValueError("requires exactly one Stripe sandbox drill record")
            stripe_module.validate_evidence(stripe_records[0], release_sha)
            if not any("restore" in path.name.lower() or "recovery" in path.name.lower() for path, _ in records):
                raise ValueError("requires a restore/recovery record")
        elif gate_id == "advertised_concurrency_load":
            load_module_value = load_module(
                "public_beta_load_gate", root / "scripts" / "load" / "run_public_beta_load.py"
            )
            matches = [value for _, value in records if value.get("schema_version") == 2 and value.get("concurrency") == 4]
            if len(matches) != 1:
                raise ValueError("requires exactly one four-job load record")
            load_module_value.validate_evidence(matches[0], release_sha)
        elif gate_id == "fault_and_fuzz":
            race_module = load_module(
                "public_beta_race_gate", root / "scripts" / "load" / "run_public_beta_races.py"
            )
            matches = [value for _, value in records if value.get("schema_version") == race_module.SCHEMA]
            if len(matches) != 1:
                raise ValueError("requires exactly one PostgreSQL race record")
            race_module.validate_evidence(matches[0], release_sha)
            if not any("fuzz" in path.name.lower() for path, _ in records):
                raise ValueError("requires a fuzz record")
        elif gate_id == "production_canary_24h":
            canary_module = load_module(
                "public_beta_canary_gate", root / "scripts" / "ci" / "validate_public_beta_canary.py"
            )
            matches = [value for _, value in records if value.get("release_channel") == "public_beta" and "hourly_verified_proofs" in value]
            if len(matches) != 1:
                raise ValueError("requires exactly one 24-hour canary record")
            problems = canary_module.validate(matches[0], release_sha)
            if problems:
                raise ValueError("; ".join(problems))
        elif gate_id == "internal_security":
            security = next((value for _, value in records if "unresolved_critical" in value), None)
            if security is None or security.get("unresolved_critical") != 0 or security.get("unresolved_high") != 0:
                raise ValueError("requires an explicit zero-critical/zero-high security record")
        elif gate_id == "signed_supply_chain":
            supply = next((value for _, value in records if "artifacts_signed" in value), None)
            if supply is None or any(supply.get(key) is not True for key in ("artifacts_signed", "sbom_complete", "provenance_verified")):
                raise ValueError("requires signatures, complete SBOMs, and verified provenance")
        elif gate_id == "release_identity":
            identity = next((value for _, value in records if isinstance(value.get("identities"), dict)), None)
            if identity is None or not identity["identities"] or any(item != release_sha for item in identity["identities"].values()):
                raise ValueError("all published identities must equal the candidate SHA")
    except (ValueError, KeyError, TypeError) as error:
        failures.append(f"{gate_id}: {error}")
    return failures


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
        verified_paths: list[Path] = []
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
            details = path.stat()
            if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) & 0o077:
                failures.append(f"{gate_id}: artifact is not operator-owned and owner-only")
                continue
            raw = path.read_bytes()
            if any(marker in raw for marker in FORBIDDEN_EVIDENCE):
                failures.append(f"{gate_id}: artifact contains a secret or bearer URL")
                continue
            actual = file_sha256(path)
            if actual != digest:
                failures.append(f"{gate_id}: artifact digest mismatch")
                continue
            verified[gate_id].append({"path": relative.as_posix(), "sha256": actual})
            verified_paths.append(path)
        if verified_paths:
            failures.extend(validate_gate_semantics(gate_id, verified_paths, str(release_sha), root))
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
