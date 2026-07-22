#!/usr/bin/env python3
"""Extract verified checksum manifests from closed qualification archives."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import zipfile

import assemble_backend_candidate as assembly


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--resource-archive", type=Path, required=True)
    parser.add_argument("--recovery-archive", type=Path, required=True)
    parser.add_argument("--resource-output", type=Path, required=True)
    parser.add_argument("--recovery-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        assembly.extract_checksum_manifests(
            resource_archive=args.resource_archive,
            recovery_archive=args.recovery_archive,
            resource_output=args.resource_output,
            recovery_output=args.recovery_output,
        )
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"qualification manifest extraction failed: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
