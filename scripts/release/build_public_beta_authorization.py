#!/usr/bin/env python3
"""Build the fail-closed authorization consumed by hc-beta-api."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
CI = ROOT / "scripts" / "ci"
if str(CI) not in sys.path:
    sys.path.insert(0, str(CI))
import public_beta_gate  # noqa: E402


def build(evidence: Path, release_sha: str, root: Path = ROOT) -> dict[str, object]:
    report = public_beta_gate.audit(evidence, root=root, expected_sha=release_sha)
    if report["status"] != "ready":
        raise ValueError("public-beta evidence is not ready: " + "; ".join(report["failures"]))
    return {
        "schema_version": 1,
        "release_channel": "public_beta",
        "status": "ready",
        "release_sha": release_sha,
        "evidence_manifest_sha256": report["evidence_manifest_sha256"],
        "verified_gate_ids": sorted(report["verified_gates"]),
        "authorized_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    authorization = build(args.evidence, args.release_sha)
    args.output.write_text(json.dumps(authorization, indent=2, sort_keys=True) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()

