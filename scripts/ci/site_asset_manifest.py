#!/usr/bin/env python3
"""Compute the deterministic digest for critical TinyZKP site assets."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
ASSET_PATHS = (
    "/index.html",
    "/contact.html",
    "/requests.html",
    "/security.html",
    "/privacy.html",
    "/terms.html",
    "/status.html",
    "/.well-known/security.txt",
    "/pricing.json",
    "/openapi.json",
)


def build(site: Path) -> dict[str, object]:
    assets = []
    for public_path in ASSET_PATHS:
        path = site / public_path.lstrip("/")
        raw = path.read_bytes()
        assets.append(
            {
                "path": public_path,
                "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    canonical = json.dumps(assets, separators=(",", ":"), ensure_ascii=True).encode()
    return {
        "complete": True,
        "sha256": hashlib.sha256(canonical).hexdigest(),
        "assets": assets,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--site", type=Path, default=ROOT / "site")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    manifest = build(args.site)
    print(json.dumps(manifest, indent=2) if args.json else manifest["sha256"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
