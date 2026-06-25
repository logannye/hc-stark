#!/usr/bin/env python3
"""Validate live Cloudflare Pages secret inventory for TinyZKP.

This check intentionally reads only secret names from `wrangler pages secret
list`; it never requests or prints secret values. Use it in live preflight before
running checkout canaries so missing bindings fail before public launch.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass

from site_deploy_check import ONE_OF_BINDINGS, REQUIRED_BINDINGS


SECRET_RE = re.compile(r"^\s*-\s+([A-Z][A-Z0-9_]*):\s+Value Encrypted\s*$")


@dataclass(frozen=True)
class Check:
    status: str
    name: str
    detail: str


def parse_secret_names(output: str) -> set[str]:
    names: set[str] = set()
    for line in output.splitlines():
        match = SECRET_RE.match(line)
        if match:
            names.add(match.group(1))
    return names


def validate_secret_names(secret_names: set[str]) -> list[Check]:
    checks: list[Check] = []
    for key in sorted(REQUIRED_BINDINGS):
        if key in secret_names:
            checks.append(Check("PASS", key, "present in Cloudflare Pages production secrets"))
        else:
            checks.append(Check("FAIL", key, "missing from Cloudflare Pages production secrets"))

    for alternatives in ONE_OF_BINDINGS:
        label = " / ".join(alternatives)
        present = sorted(key for key in alternatives if key in secret_names)
        if present:
            checks.append(Check("PASS", label, "at least one accepted proof-meter price secret is present: " + ", ".join(present)))
        else:
            checks.append(Check("FAIL", label, "missing all accepted proof-meter price secrets: " + ", ".join(alternatives)))
    return checks


def read_wrangler_secret_names(project_name: str, *, timeout: int) -> tuple[set[str], str]:
    completed = subprocess.run(
        ("wrangler", "pages", "secret", "list", "--project-name", project_name),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout,
        check=False,
    )
    output = completed.stdout or ""
    if completed.returncode != 0:
        raise RuntimeError(output.strip() or f"wrangler exited with {completed.returncode}")
    return parse_secret_names(output), output


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-name", default="tinyzkp", help="Cloudflare Pages project name")
    parser.add_argument("--timeout", type=int, default=30, help="Wrangler command timeout in seconds")
    args = parser.parse_args(argv)

    try:
        secret_names, _output = read_wrangler_secret_names(args.project_name, timeout=args.timeout)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as exc:
        print(f"FAIL wrangler secret inventory - {exc}", file=sys.stderr)
        return 1

    checks = validate_secret_names(secret_names)
    failures = [check for check in checks if check.status != "PASS"]
    for check in checks:
        print(f"{check.status:<4} {check.name} - {check.detail}")
    if failures:
        print(f"\n{len(failures)} Cloudflare Pages secret check(s) failed.", file=sys.stderr)
        return 1
    print("\nAll Cloudflare Pages production secrets are present.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
