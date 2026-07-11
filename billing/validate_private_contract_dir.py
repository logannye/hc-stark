#!/usr/bin/env python3
"""Fail closed unless a private contract tree is owner-only and symlink-free."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import stat
import sys


def validate(root: Path) -> list[str]:
    failures: list[str] = []
    try:
        metadata = root.lstat()
    except OSError:
        return ["contract directory is missing or unreadable"]
    if stat.S_ISLNK(metadata.st_mode):
        return ["contract directory contains a symlink"]
    if not stat.S_ISDIR(metadata.st_mode):
        return ["contract directory is not a directory"]
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        failures.append("contract directory is not owner-only")
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        for name in [*directories, *files]:
            path = current_path / name
            try:
                child = path.lstat()
            except OSError:
                failures.append("contract directory contains an unreadable entry")
                continue
            if stat.S_ISLNK(child.st_mode):
                failures.append("contract directory contains a symlink")
            elif not (stat.S_ISDIR(child.st_mode) or stat.S_ISREG(child.st_mode)):
                failures.append("contract directory contains a special file")
            if stat.S_IMODE(child.st_mode) & 0o077:
                failures.append("contract directory is not owner-only")
    return sorted(set(failures))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args(argv)
    failures = validate(args.directory)
    if failures:
        for failure in failures:
            print(f"ERROR: {failure}", file=sys.stderr)
        return 1
    print("PASS private contract directory validation")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
