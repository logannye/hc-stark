#!/usr/bin/env python3
"""Bind replacement SDK contracts to one audited backend source tree."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys
import tomllib


ROOT = Path(__file__).resolve().parents[2]
SCHEMAS = (
    "workload-manifest-v1.schema.json",
    "proof-bundle-v1.schema.json",
    "benchmark-report-v1.schema.json",
)


def package_version(root: Path, manifest: str) -> str:
    workspace = tomllib.loads((root / "Cargo.toml").read_text(encoding="utf-8"))
    package = tomllib.loads((root / manifest).read_text(encoding="utf-8"))["package"]
    version = package.get("version")
    if isinstance(version, str):
        return version
    if isinstance(version, dict) and version.get("workspace") is True:
        return workspace["workspace"]["package"]["version"]
    raise ValueError(f"cannot resolve package version for {manifest}")


def failures(backend_root: Path, *, sdk_root: Path = ROOT) -> list[str]:
    backend_root = backend_root.resolve()
    problems: list[str] = []
    for schema in SCHEMAS:
        sdk = sdk_root / "site/schemas" / schema
        backend = backend_root / "site/schemas" / schema
        if not sdk.is_file() or not backend.is_file() or sdk.read_bytes() != backend.read_bytes():
            problems.append(f"SDK schema differs from audited backend: {schema}")
    client = tomllib.loads((sdk_root / "clients/rust/Cargo.toml").read_text(encoding="utf-8"))
    for crate, manifest in (
        ("hc-stream", "crates/hc-stream/Cargo.toml"),
        ("hc-plonky3", "crates/hc-plonky3/Cargo.toml"),
    ):
        expected = package_version(backend_root, manifest)
        dependency = client.get("dependencies", {}).get(crate)
        actual = dependency.get("version") if isinstance(dependency, dict) else None
        if actual != expected:
            problems.append(
                f"Rust SDK {crate} dependency {actual!r} differs from audited backend {expected!r}"
            )
    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backend-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        problems = failures(args.backend_root)
    except (OSError, KeyError, ValueError, tomllib.TOMLDecodeError) as error:
        problems = [str(error)]
    if problems:
        for problem in problems:
            print(f"BLOCKED  {problem}", file=sys.stderr)
        return 1
    print("PASS  SDK contracts and crate dependencies match the audited backend")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
