#!/usr/bin/env python3
"""Fail closed unless host and Pages use the same private INTERNAL_SECRET."""

from __future__ import annotations

import argparse
import hmac
import json
from pathlib import Path
import sys

from deploy_readiness_check import ProductionEnvError, load_private_env_file


def check_parity(host_env_file: Path, pages_bindings_file: Path) -> dict[str, object]:
    host = load_private_env_file(host_env_file)
    pages = load_private_env_file(pages_bindings_file, exact_mode_0600=True)
    host_secret = host.get("INTERNAL_SECRET", "")
    pages_secret = pages.get("INTERNAL_SECRET", "")
    if not host_secret or not pages_secret:
        raise ValueError("INTERNAL_SECRET must be present in both private configuration files")
    if not hmac.compare_digest(host_secret, pages_secret):
        raise ValueError("host and Pages INTERNAL_SECRET values do not match")
    return {
        "schema_version": 1,
        "status": "pass",
        "internal_secret_present_on_host": True,
        "internal_secret_present_on_pages": True,
        "internal_secret_values_match": True,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host-env-file", type=Path, required=True)
    parser.add_argument("--pages-bindings-file", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = check_parity(args.host_env_file, args.pages_bindings_file)
    except (ProductionEnvError, ValueError) as error:
        print(f"FAIL production secret parity: {error}", file=sys.stderr)
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
