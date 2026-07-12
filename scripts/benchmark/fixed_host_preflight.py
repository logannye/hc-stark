#!/usr/bin/env python3
"""Fail closed unless a host satisfies the TinyZKP release-benchmark contract."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "scripts" / "benchmark" / "run_plonky3_cgroup.py"
SPEC = importlib.util.spec_from_file_location("tinyzkp_cgroup_harness", HARNESS_PATH)
if SPEC is None or SPEC.loader is None:  # pragma: no cover - installation failure
    raise RuntimeError("cannot load the TinyZKP cgroup harness")
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)


def check(scratch_dir: Path, cgroup_parent: Path) -> dict[str, object]:
    HARNESS.ensure_cgroup_v2(cgroup_parent)
    metadata = HARNESS.collect_host_metadata(scratch_dir)
    failures = HARNESS.fixed_host_failures(metadata)
    return {
        "schema_version": 2,
        "release_sha": os.environ.get("HC_RELEASE_SHA", "development-unreleased"),
        "scratch_dir": str(scratch_dir.resolve()),
        "cgroup_parent": str(cgroup_parent.resolve()),
        "host": metadata,
        "passed": not failures,
        "failures": failures,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch-dir", type=Path, required=True)
    parser.add_argument(
        "--cgroup-parent",
        type=Path,
        default=Path("/sys/fs/cgroup/tinyzkp-bench"),
    )
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        report = check(args.scratch_dir, args.cgroup_parent)
    except (OSError, RuntimeError, ValueError) as error:
        report = {
            "schema_version": 2,
            "release_sha": os.environ.get(
                "HC_RELEASE_SHA", "development-unreleased"
            ),
            "scratch_dir": str(args.scratch_dir.absolute()),
            "cgroup_parent": str(args.cgroup_parent.absolute()),
            "host": None,
            "passed": False,
            "failures": [str(error)],
        }
    if args.output is not None:
        HARNESS.write_json(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    if not report["passed"]:
        print("fixed-host preflight failed", file=sys.stderr)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
