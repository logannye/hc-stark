#!/usr/bin/env python3
"""Retired hosted-service launch audit.

This command intentionally fails.  The former audit could report success when
every hosted API/MCP/billing gate was skipped, which is not a meaningful Guard
release decision.  Guard launch authority now lives in
``guard_launch_gate.py`` and digest-bound ``GuardLaunchEvidenceV2``.
"""

from __future__ import annotations

import argparse
import json
import sys


RETIREMENT_CODE = "retired_hosted_launch_audit"
REPLACEMENT = "python3 scripts/ci/guard_launch_gate.py --check"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true")
    parser.parse_args(argv)
    record = {
        "schema_version": 1,
        "status": "retired",
        "code": RETIREMENT_CODE,
        "replacement": REPLACEMENT,
        "passed": 0,
        "skipped": 0,
        "failed": 1,
    }
    if "--json" in (argv or []):
        print(json.dumps(record, sort_keys=True))
    else:
        print(
            "launch gate audit: RETIRED: hosted API/MCP/billing gates cannot "
            f"authorize Guard; use `{REPLACEMENT}`",
            file=sys.stderr,
        )
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
