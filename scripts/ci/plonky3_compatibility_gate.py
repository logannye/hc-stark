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
    backend_cargo = tomllib.loads(
        (ROOT / "crates" / "hc-plonky3" / "Cargo.toml").read_text(encoding="utf-8")
    )
    toolchain = tomllib.loads((ROOT / "rust-toolchain.toml").read_text(encoding="utf-8"))
    failures: list[str] = []

    if profile.get("schema_version") != 1:
        failures.append("compatibility manifest schema_version must equal 1")
    if profile.get("profile_id") != "tinyzkp-p3-goldilocks-v1":
        failures.append("unexpected compatibility profile ID")
    if profile.get("release_status") != "production_scoped_ga":
        failures.append("compatibility manifest must declare scoped production GA")
    expected_scope = {
        "distribution": ["linux_x86_64_cli", "linux_amd64_oci"],
        "qualification_runner": {
            "provider": "github_hosted",
            "image": "ubuntu-24.04",
            "effective_cpu_count": 4,
            "memory_class": "16_gib",
            "minimum_available_scratch_bytes": 12_000_000_000,
            "non_rotational_storage_required": True,
        },
        "qualified_workloads": [
            {
                "workload_id": "fibonacci",
                "maximum_logical_rows": 16_777_216,
                "bounded_peak_resident_estimate_bytes": 545_259_520,
                "bounded_scratch_estimate_bytes": 8_590_055_346,
                "scratch_required_with_headroom_bytes": 9_544_505_940,
            },
            {
                "workload_id": "poseidon2_goldilocks",
                "maximum_logical_rows": 1_048_576,
                "bounded_peak_resident_estimate_bytes": 385_875_968,
                "bounded_scratch_estimate_bytes": 10_569_876_514,
                "scratch_required_with_headroom_bytes": 11_744_307_238,
            },
        ],
        "post_ga_capacity_expansion": [
            {
                "workload_id": "poseidon2_goldilocks",
                "logical_rows": 16_777_216,
                "bounded_peak_resident_estimate_bytes": 763_363_328,
                "bounded_scratch_estimate_bytes": 169_114_584_484,
                "scratch_required_with_headroom_bytes": 187_905_093_872,
                "production_supported": False,
            }
        ],
    }
    if profile.get("production_scope") != expected_scope:
        failures.append("compatibility manifest production scope or estimates changed")
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
    locked_names = {package[0] for package in locked_packages}
    if "atomic-polyfill" in locked_names:
        failures.append("postcard default features reintroduced unmaintained atomic-polyfill")
    crossbeam_epochs = [
        package["version"] for package in lock["package"] if package["name"] == "crossbeam-epoch"
    ]
    if not crossbeam_epochs or any(
        tuple(int(part) for part in version.split(".")) < (0, 9, 20)
        for version in crossbeam_epochs
    ):
        failures.append("crossbeam-epoch must resolve to >=0.9.20")
    postcard = backend_cargo["dependencies"].get("postcard", {})
    if not isinstance(postcard, dict) or postcard.get("default-features") is not False:
        failures.append("postcard default features must remain disabled")
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
    checkpoint_source = (ROOT / "crates" / "hc-plonky3" / "src" / "checkpoint.rs").read_text(
        encoding="utf-8"
    )
    for required in [
        'pub const PLONKY3_VERSION: &str = "0.6.1"',
        'pub const COMPATIBILITY_PROFILE: &str = "tinyzkp-p3-goldilocks-v1"',
        "FriParameters::new_benchmark",
        "Radix2DitParallel::<Val>::default()",
        f'pub const DEPENDENCY_LOCK_SHA256: &str =\n    "{actual_lock_hash}"',
    ]:
        if required not in source:
            failures.append(f"backend source is missing frozen profile token {required!r}")
    if profile.get("configuration", {}).get("permutation_rng") != "rand-0.10.2::Xoshiro256PlusPlus":
        failures.append("compatibility profile does not pin the cross-target permutation RNG")
    if "Xoshiro256PlusPlus::seed_from_u64(1)" not in checkpoint_source:
        failures.append("backend does not reconstruct cross-target-stable permutation parameters")

    if failures:
        print("Plonky3 compatibility gate failed:")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(f"PASS Plonky3 compatibility gate ({len(profile['pinned_crates'])} exact crates)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
