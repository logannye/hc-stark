#!/usr/bin/env python3
"""Fail when the frozen Plonky3 profile and Cargo resolution diverge."""

from __future__ import annotations

import json
from pathlib import Path
import tomllib


ROOT = Path(__file__).resolve().parents[2]
MANIFEST = ROOT / "release" / "plonky3-compatibility-v1.json"
LOCK = ROOT / "Cargo.lock"
CARGO = ROOT / "Cargo.toml"


def main() -> int:
    profile = json.loads(MANIFEST.read_text(encoding="utf-8"))
    lock = tomllib.loads(LOCK.read_text(encoding="utf-8"))
    cargo = tomllib.loads(CARGO.read_text(encoding="utf-8"))
    failures: list[str] = []

    if profile.get("schema_version") != 1:
        failures.append("compatibility manifest schema_version must equal 1")
    if profile.get("profile_id") != "tinyzkp-p3-goldilocks-v1":
        failures.append("unexpected compatibility profile ID")

    locked = {
        package["name"]: (package["version"], package.get("checksum"))
        for package in lock["package"]
        if package["name"].startswith("p3-")
    }
    workspace_dependencies = cargo["workspace"]["dependencies"]
    for package in profile.get("pinned_crates", []):
        name = package["name"]
        expected = (package["version"], package["checksum"])
        if locked.get(name) != expected:
            failures.append(f"{name} Cargo.lock resolution differs: {locked.get(name)!r} != {expected!r}")
        if workspace_dependencies.get(name) != "=0.6.1":
            failures.append(f"{name} must be pinned exactly to =0.6.1 in Cargo.toml")

    source = (ROOT / "crates" / "hc-plonky3" / "src" / "prover.rs").read_text(
        encoding="utf-8"
    )
    for required in [
        'pub const PLONKY3_VERSION: &str = "0.6.1"',
        'pub const COMPATIBILITY_PROFILE: &str = "tinyzkp-p3-goldilocks-v1"',
        "FriParameters::new_benchmark",
        "Radix2DitParallel::<Val>::default()",
    ]:
        if required not in source:
            failures.append(f"backend source is missing frozen profile token {required!r}")

    if failures:
        print("Plonky3 compatibility gate failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS Plonky3 compatibility gate ({len(profile['pinned_crates'])} exact crates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
