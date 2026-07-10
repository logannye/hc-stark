#!/usr/bin/env python3
"""Require one SDK tag to match Rust, Python, and TypeScript package versions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(
    r"^(\d+)\.(\d+)\.(\d+)(?:-(dev|alpha|beta|rc)\.(\d+))?$"
)


def python_version(semver: str) -> str:
    match = SEMVER.fullmatch(semver)
    if match is None:
        raise ValueError("SDK tag must be vMAJOR.MINOR.PATCH or a supported prerelease")
    major, minor, patch, prerelease, number = match.groups()
    base = f"{major}.{minor}.{patch}"
    if prerelease is None:
        return base
    marker = {"dev": ".dev", "alpha": "a", "beta": "b", "rc": "rc"}[prerelease]
    return f"{base}{marker}{number}"


def failures(tag: str, *, root: Path = ROOT) -> list[str]:
    semver = tag.removeprefix("v")
    if tag == semver or SEMVER.fullmatch(semver) is None:
        return ["SDK release tag must begin with v and contain a supported semantic version"]
    python = tomllib.loads((root / "clients/python/pyproject.toml").read_text(encoding="utf-8"))
    rust = tomllib.loads((root / "clients/rust/Cargo.toml").read_text(encoding="utf-8"))
    typescript = json.loads((root / "clients/typescript/package.json").read_text(encoding="utf-8"))
    expected = {
        "Python": python_version(semver),
        "Rust": semver,
        "TypeScript": semver,
    }
    actual = {
        "Python": python["project"]["version"],
        "Rust": rust["package"]["version"],
        "TypeScript": typescript["version"],
    }
    return [
        f"{name} package version {actual[name]!r} does not match tag {tag!r} (expected {value!r})"
        for name, value in expected.items()
        if actual[name] != value
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    args = parser.parse_args(argv)
    try:
        problems = failures(args.tag)
    except (OSError, KeyError, ValueError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
        problems = [str(error)]
    if problems:
        for problem in problems:
            print(f"BLOCKED  {problem}", file=sys.stderr)
        return 1
    print(f"PASS  SDK package versions match {args.tag}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
