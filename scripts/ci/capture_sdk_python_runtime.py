#!/usr/bin/env python3
"""Print a candidate SDK Python runtime manifest for human review.

This command never edits the trust anchor and never marks its output trusted.
Run it on the fixed Linux evidence host, review the complete runtime provenance,
then deliberately update the committed anchor in a separate change.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

RELEASE_DIR = Path(__file__).resolve().parents[1] / "release"
if str(RELEASE_DIR) not in sys.path:
    sys.path.insert(0, str(RELEASE_DIR))
import evidence_runtime  # noqa: E402


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, default=Path(sys.executable))
    args = parser.parse_args(argv)
    path = args.python.resolve()
    identity = evidence_runtime.executable_identity(
        str(path), ["--version"], environment=evidence_runtime.sanitized_environment({"PATH": str(path.parent)}), root=Path.cwd()
    )
    descriptor, fd_path = evidence_runtime.open_executable_descriptor(
        path, expected_sha256=str(identity["sha256"])
    )
    try:
        runtime = evidence_runtime.python_runtime_manifest(
            fd_path,
            descriptor,
            environment=evidence_runtime.sanitized_environment({"PATH": f"{path.parent}:/usr/bin:/bin"}),
            root=Path.cwd(),
        )
    finally:
        __import__("os").close(descriptor)
    candidate = {
        "schema_version": 1,
        "target": "cp312-cp312-manylinux_2_17_x86_64",
        "status": "unreviewed",
        "runtime": runtime,
    }
    print(json.dumps(candidate, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
