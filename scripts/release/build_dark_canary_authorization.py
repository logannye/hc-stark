#!/usr/bin/env python3
"""Build the narrow authorization for allowlisted live billing canaries.

This authorization does not enable public API mode. It permits only creation
and exercise of the isolated live Stripe beta catalog while the API remains in
dark_canary exposure and Caddy remains in containment.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


GIT_SHA = re.compile(r"^[0-9a-f]{40}$")


def build(release_sha: str) -> dict[str, object]:
    if GIT_SHA.fullmatch(release_sha) is None:
        raise ValueError("release SHA must be a full lowercase Git commit")
    return {
        "schema_version": 1,
        "release_channel": "public_beta",
        "status": "dark_canary",
        "purpose": "stripe_live_canary",
        "release_sha": release_sha,
        "public_activation": False,
        "authorized_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat(),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(
        json.dumps(build(args.release_sha), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
