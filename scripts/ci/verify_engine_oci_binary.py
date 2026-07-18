#!/usr/bin/env python3
"""Verify that an OCI archive embeds one exact prebuilt TinyZKP engine."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts" / "release"))
import build_engine_identity_report as identity  # noqa: E402


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--release-ref", required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--oci-archive", type=Path, required=True)
    args = parser.parse_args()
    try:
        engine = args.engine.resolve(strict=True)
        archive = args.oci_archive.resolve(strict=True)
        result = identity.oci_identity(
            archive,
            release_sha=args.release_sha,
            release_ref=args.release_ref,
            expected_engine_sha256=sha256_file(engine),
        )
    except (OSError, ValueError) as error:
        print(f"engine OCI parity: FAIL: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
