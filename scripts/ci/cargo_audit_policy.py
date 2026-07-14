#!/usr/bin/env python3
"""Enforce a closed, checksummed policy over cargo-audit JSON output."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
from typing import Any


MAX_REPORT_BYTES = 32 * 1024 * 1024
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
ALLOWED_YANKED = frozenset(
    {
        (
            "spin",
            "0.9.8",
            REGISTRY,
            "6980e8d7511241f8acf4aebddbb1ff938df5eebe98691418c4468d0b72a96a67",
        ),
        (
            "spin",
            "0.10.0",
            REGISTRY,
            "d5fe4ccb98d9c292d56fec89a5e07da7fc4cf0dc11e156b41793132775d3e591",
        ),
    }
)


def validate_report(value: Any) -> list[tuple[str, str, str, str]]:
    if not isinstance(value, dict):
        raise ValueError("cargo-audit report must be an object")
    vulnerabilities = value.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict):
        raise ValueError("cargo-audit vulnerability summary is missing")
    count = vulnerabilities.get("count")
    if not isinstance(count, int) or isinstance(count, bool) or count != 0:
        raise ValueError("cargo-audit found a vulnerability")
    warnings = value.get("warnings")
    if not isinstance(warnings, dict):
        raise ValueError("cargo-audit warning summary is missing")

    observed: list[tuple[str, str, str, str]] = []
    for category, records in warnings.items():
        if not isinstance(records, list):
            raise ValueError("cargo-audit warning category is malformed")
        if not records:
            continue
        if category != "yanked":
            raise ValueError(f"cargo-audit warning category is not allowed: {category}")
        for record in records:
            package = record.get("package") if isinstance(record, dict) else None
            if not isinstance(package, dict):
                raise ValueError("cargo-audit yanked warning is malformed")
            identity = (
                package.get("name"),
                package.get("version"),
                package.get("source"),
                package.get("checksum"),
            )
            if not all(isinstance(item, str) and item for item in identity):
                raise ValueError("cargo-audit yanked package identity is malformed")
            typed_identity = tuple(identity)
            if typed_identity not in ALLOWED_YANKED:
                raise ValueError(
                    "cargo-audit found a yanked package outside the exact compatibility allowlist"
                )
            observed.append(typed_identity)
    if len(observed) != len(set(observed)):
        raise ValueError("cargo-audit repeated a yanked package identity")
    return sorted(observed)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    try:
        if not args.report.is_file() or args.report.is_symlink():
            raise ValueError("cargo-audit report is unavailable or unsafe")
        payload = args.report.read_bytes()
        if not payload or len(payload) > MAX_REPORT_BYTES:
            raise ValueError("cargo-audit report is empty or oversized")
        allowed = validate_report(json.loads(payload))
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"BLOCKED cargo-audit policy: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "passed",
                "vulnerabilities": 0,
                "accepted_yanked_compatibility_packages": [
                    {"name": name, "version": version, "sha256": checksum}
                    for name, version, _source, checksum in allowed
                ],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
