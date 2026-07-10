#!/usr/bin/env python3
"""Fail when the frozen Plonky3 profile and Cargo resolution diverge."""

from __future__ import annotations

import json
import hashlib
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
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    failures: list[str] = []

    if profile.get("schema_version") != 1:
        failures.append("compatibility manifest schema_version must equal 1")
    if profile.get("profile_id") != "tinyzkp-p3-goldilocks-v1":
        failures.append("unexpected compatibility profile ID")
    expected_toolchain = profile.get("rust_toolchain")
    if toolchain.get("toolchain", {}).get("channel") != expected_toolchain:
        failures.append("rust-toolchain.toml differs from the compatibility manifest")
    if cargo["workspace"]["package"].get("rust-version") != str(expected_toolchain).removesuffix(".0"):
        failures.append("workspace rust-version differs from the compatibility manifest")
    if f"FROM rust:{str(expected_toolchain).removesuffix('.0')}-slim" not in (
        ROOT / "Dockerfile"
    ).read_text(encoding="utf-8"):
        failures.append("Docker builder toolchain differs from the compatibility manifest")
    actual_lock_hash = hashlib.sha256(LOCK.read_bytes()).hexdigest()
    if profile.get("cargo_lock_sha256") != actual_lock_hash:
        failures.append("Cargo.lock SHA-256 differs from the compatibility manifest")

    locked = {
        package["name"]: (package["version"], package.get("checksum"))
        for package in lock["package"]
        if package["name"].startswith("p3-")
    }
    locked_packages = {
        (package["name"], package["version"], package.get("checksum"))
        for package in lock["package"]
    }
    workspace_dependencies = cargo["workspace"]["dependencies"]
    for package in profile.get("pinned_crates", []):
        name = package["name"]
        expected = (package["version"], package["checksum"])
        if locked.get(name) != expected:
            failures.append(f"{name} Cargo.lock resolution differs: {locked.get(name)!r} != {expected!r}")
        if workspace_dependencies.get(name) != "=0.6.1":
            failures.append(f"{name} must be pinned exactly to =0.6.1 in Cargo.toml")

    for package in profile.get("artifact_dependencies", []):
        name = package["name"]
        expected = (package["version"], package["checksum"])
        if (name, expected[0], expected[1]) not in locked_packages:
            failures.append(
                f"artifact dependency {name} {expected!r} is absent from Cargo.lock"
            )

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
