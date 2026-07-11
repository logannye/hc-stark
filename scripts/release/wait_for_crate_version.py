#!/usr/bin/env python3
"""Wait until an exact crates.io version is readable from the public API."""

from __future__ import annotations

import argparse
import json
import time
import urllib.error
import urllib.parse
import urllib.request


def version_available(crate: str, version: str, timeout: float = 10.0) -> bool:
    crate = urllib.parse.quote(crate, safe="")
    version = urllib.parse.quote(version, safe="")
    request = urllib.request.Request(
        f"https://crates.io/api/v1/crates/{crate}/{version}",
        headers={"User-Agent": "TinyZKP-release/1.0 (https://tinyzkp.com)"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.load(response)
        return response.status == 200 and payload.get("version", {}).get("num") == urllib.parse.unquote(version)
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, json.JSONDecodeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("crate")
    parser.add_argument("version")
    parser.add_argument("--timeout-seconds", type=int, default=600)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    args = parser.parse_args()
    if args.timeout_seconds <= 0 or args.poll_seconds <= 0:
        parser.error("timeouts must be positive")
    deadline = time.monotonic() + args.timeout_seconds
    while time.monotonic() < deadline:
        if version_available(args.crate, args.version):
            print(f"crates.io exposes {args.crate} {args.version}")
            return 0
        time.sleep(min(args.poll_seconds, max(0.0, deadline - time.monotonic())))
    print(f"timed out waiting for crates.io {args.crate} {args.version}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
