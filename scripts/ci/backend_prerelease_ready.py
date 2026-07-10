#!/usr/bin/env python3
"""Validate every backend release gate that precedes artifact signing."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

import backend_release_ready as final_gate


ROOT = Path(__file__).resolve().parents[2]
CONFIG_PATH = ROOT / "release" / "backend-v1-gates.json"
SIGNED_GATE = "signed_release_sbom_and_checksums"
EXPECTED_GATES = set(final_gate.EXPECTED_KINDS) - {SIGNED_GATE}


def evidence_failures(evidence: dict[str, object], *, root: Path) -> list[str]:
    problems: list[str] = []
    release_sha = evidence.get("release_sha")
    if evidence.get("schema_version") != 1 or not isinstance(release_sha, str) or not release_sha:
        return ["candidate evidence identity is malformed"]
    if evidence.get("status") != "candidate":
        problems.append("candidate evidence status must equal candidate")
    gates = evidence.get("gates")
    if not isinstance(gates, dict):
        return problems + ["candidate evidence gate map is missing"]
    missing = EXPECTED_GATES - set(gates)
    extra = set(gates) - EXPECTED_GATES
    problems.extend(f"candidate evidence gate is missing: {name}" for name in sorted(missing))
    problems.extend(f"unexpected candidate evidence gate: {name}" for name in sorted(extra))
    for name in sorted(EXPECTED_GATES & set(gates)):
        raw = gates[name]
        if not isinstance(raw, dict):
            problems.append(f"{name}: evidence descriptor is malformed")
            continue
        problems.extend(
            final_gate.validate_gate(name, raw, root=root, release_sha=release_sha)
        )
    return problems


def failures(config: dict[str, object], *, root: Path = ROOT) -> list[str]:
    problems: list[str] = []
    if config.get("schema_version") != 2:
        problems.append("release gate config schema_version must be 2")
    if config.get("status") != "candidate":
        problems.append("release gate config status must equal candidate")
    evidence_path = config.get("evidence_manifest")
    if not isinstance(evidence_path, str) or not evidence_path:
        return problems + ["candidate evidence manifest path is missing"]
    try:
        evidence = final_gate.read_object(root / evidence_path)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        return problems + [f"candidate evidence manifest is unavailable: {error}"]
    return problems + evidence_failures(evidence, root=root)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=CONFIG_PATH)
    args = parser.parse_args(argv)
    config = final_gate.read_object(args.config)
    problems = failures(config)
    if problems:
        for problem in problems:
            print(f"BLOCKED  {problem}", file=sys.stderr)
        return 1
    print("PASS  backend release candidate is ready for artifact signing")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
