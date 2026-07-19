#!/usr/bin/env python3
"""Fail closed unless a downloaded engine draft has the exact release inventory."""

from __future__ import annotations

import argparse
from pathlib import Path


EXPECTED = {
    "SHA256SUMS",
    "SHA256SUMS.sigstore.json",
    "backend-v1-final-evidence.json",
    "backend-v1-final-gates.json",
    "backend-v1-gates.json",
    "engine-identity.json",
    "engine-release.json",
    "plonky3-compatibility-v1.json",
    "tinyzkp-engine.spdx.json",
    "tinyzkp-engine-linux-x86_64",
    "tinyzkp-engine.oci.tar",
}


def verify(directory: Path) -> None:
    if not directory.is_dir():
        raise ValueError("candidate directory is unavailable")
    observed = {
        path.name
        for path in directory.iterdir()
        if path.is_file() and not path.is_symlink()
    }
    if observed != EXPECTED:
        raise ValueError(
            f"engine candidate inventory differs; "
            f"missing={sorted(EXPECTED - observed)}, extra={sorted(observed - EXPECTED)}"
        )
    if any(path.is_symlink() or not path.is_file() for path in directory.iterdir()):
        raise ValueError("engine candidate contains a link or non-file entry")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        verify(args.directory)
    except ValueError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
