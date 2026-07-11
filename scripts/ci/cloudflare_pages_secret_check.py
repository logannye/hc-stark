#!/usr/bin/env python3
"""Validate live Cloudflare Pages secret inventory for TinyZKP.

This check intentionally reads only secret names from `wrangler pages secret
list`; it never requests or prints secret values. Recovery Pages needs only the
internal webhook secret. Legacy Stripe prices, Stripe API keys, and demo keys
must be absent because no deployed Pages function consumes them.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
from dataclasses import dataclass

from site_deploy_check import REQUIRED_BINDINGS


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

    forbidden = sorted(
        name
        for name in secret_names
        if name.startswith("STRIPE_") or name == "TINYZKP_DEMO_API_KEY"
    )
    if forbidden:
        checks.append(
            Check(
                "FAIL",
                "legacy billing/demo secrets",
                "remove unused recovery secrets: " + ", ".join(forbidden),
            )
        )
    else:
        checks.append(Check("PASS", "legacy billing/demo secrets", "none present"))
    unexpected = sorted(secret_names - REQUIRED_BINDINGS - set(forbidden))
    if unexpected:
        checks.append(
            Check(
                "FAIL",
                "unexpected recovery secrets",
                "remove bindings not consumed by recovery Pages: "
                + ", ".join(unexpected),
            )
        )
    else:
        checks.append(
            Check("PASS", "unexpected recovery secrets", "none present")
        )
    return checks


def wrangler_environment(source: dict[str, str] | None = None) -> dict[str, str]:
    inherited = source if source is not None else dict(os.environ)
    environment = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "HOME": "/nonexistent",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "NO_COLOR": "1",
        "WRANGLER_SEND_METRICS": "false",
    }
    for key in ("CLOUDFLARE_API_TOKEN", "CLOUDFLARE_ACCOUNT_ID"):
        if inherited.get(key):
            environment[key] = inherited[key]
    return environment


def read_wrangler_secret_names(
    project_name: str,
    *,
    timeout: int,
    node_executable: pathlib.Path,
    wrangler_entrypoint: pathlib.Path,
) -> tuple[set[str], str]:
    if not node_executable.is_absolute() or not wrangler_entrypoint.is_absolute():
        raise RuntimeError("Node and Wrangler paths must be explicit absolute paths")
    completed = subprocess.run(
        (
            str(node_executable),
            str(wrangler_entrypoint),
            "pages",
            "secret",
            "list",
            "--project-name",
            project_name,
        ),
        env=wrangler_environment(),
        stdin=subprocess.DEVNULL,
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
    parser.add_argument(
        "--node-executable",
        required=True,
        type=pathlib.Path,
        help="Exact Node executable validated by the production toolchain gate",
    )
    parser.add_argument(
        "--wrangler-entrypoint",
        required=True,
        type=pathlib.Path,
        help="Exact local Wrangler entrypoint validated by the production toolchain gate",
    )
    args = parser.parse_args(argv)

    try:
        secret_names, _output = read_wrangler_secret_names(
            args.project_name,
            timeout=args.timeout,
            node_executable=args.node_executable,
            wrangler_entrypoint=args.wrangler_entrypoint,
        )
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
    print("\nCloudflare Pages recovery secret inventory is minimal and complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
