#!/usr/bin/env python3
"""Permit publication only when every backend-v1 release gate has evidence."""

from __future__ import annotations

import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]


def failures(payload: dict[str, object]) -> list[str]:
    problems: list[str] = []
    if payload.get("status") != "ready":
        problems.append("release status is not ready")
    gates = payload.get("gates")
    if not isinstance(gates, dict) or not gates:
        return problems + ["release gate map is missing"]
    for name, raw in gates.items():
        if not isinstance(raw, dict) or raw.get("passed") is not True:
            problems.append(f"gate is not passed: {name}")
            continue
        evidence = raw.get("evidence")
        if not isinstance(evidence, str) or not evidence.strip():
            problems.append(f"gate has no evidence: {name}")
    return problems


def main() -> int:
    path = ROOT / "release" / "backend-v1-gates.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    problems = failures(payload)
    if problems:
        for problem in problems:
            print(f"BLOCKED  {problem}", file=sys.stderr)
        return 1
    print("PASS  backend v1 release is ready for publication")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
