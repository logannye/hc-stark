#!/usr/bin/env python3
"""Build a deterministic, hashed backend review ZIP for one release identity."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import zipfile


ROOT = Path(__file__).resolve().parents[2]
FIXED_ZIP_TIME = (2020, 1, 1, 0, 0, 0)
REQUIRED_FILES = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "release/plonky3-compatibility-v1.json",
    "release/backend-v1-gates.json",
    "docs/recovery/architecture.md",
    "docs/recovery/plonky3-transcript-equivalence.md",
    "docs/security/threat_model.md",
    "test-vectors/canonical-json-v1.json",
    "test-vectors/plonky3/fibonacci-16.manifest.json",
    "test-vectors/plonky3/fibonacci-16.bundle.json",
    "test-vectors/plonky3/fibonacci-max-field.manifest.json",
    "test-vectors/plonky3/poseidon2-8.manifest.json",
    "test-vectors/plonky3/poseidon2-8.bundle.json",
    "test-vectors/plonky3/benchmark-report-v1.json",
)
SOURCE_GLOBS = (
    "crates/hc-plonky3/**/*.rs",
    "crates/hc-plonky3/Cargo.toml",
    "crates/hc-plonky3/README.md",
    "crates/hc-stream/**/*.rs",
    "crates/hc-stream/Cargo.toml",
    "crates/hc-stream/README.md",
    "crates/hc-cli/**/*.rs",
    "crates/hc-cli/Cargo.toml",
    "fuzz/fuzz_targets/*.rs",
    "fuzz/Cargo.toml",
    "fuzz/Cargo.lock",
    "scripts/benchmark/*.py",
    "scripts/benchmark/requirements.txt",
    "scripts/ci/backend_release_ready.py",
    "scripts/ci/backend_prerelease_ready.py",
    "scripts/ci/backend_source_scan.py",
    "scripts/ci/generate_sdk_schema_models.py",
    "scripts/ci/check_plonky3_known_answers.sh",
    "scripts/ci/sdk_contract_gate.sh",
    "scripts/ci/plonky3_compatibility_gate.py",
    "scripts/release/*.py",
    "examples/partner-adapter/src/*.rs",
    "examples/partner-adapter/Cargo.toml",
    "examples/partner-adapter/Dockerfile",
    "examples/partner-adapter/README.md",
    "examples/partner-adapter/*.py",
    "clients/python/tinyzkp/*.py",
    "clients/python/pyproject.toml",
    "clients/typescript/src/*.ts",
    "clients/typescript/package.json",
    "clients/typescript/package-lock.json",
    "clients/rust/src/*.rs",
    "clients/rust/Cargo.toml",
    "clients/rust/Cargo.lock",
    "site/schemas/*.json",
    "crates/hc-wasm/src/*.rs",
    "crates/hc-wasm/Cargo.toml",
    "crates/hc-wasm/LICENSE",
    "examples/plonky3/*.json",
    ".github/workflows/ci.yml",
    ".github/workflows/nightly-backend.yml",
    ".github/workflows/benches.yml",
    ".github/workflows/release-backend.yml",
    ".github/workflows/publish-sdks.yml",
    ".github/workflows/sdks-ci.yml",
    ".github/workflows/publish-backend-crates.yml",
)


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def backend_sources() -> list[Path]:
    sources: set[Path] = set()
    for pattern in SOURCE_GLOBS:
        sources.update(path for path in ROOT.glob(pattern) if path.is_file())
    return sorted(sources)


def safe_optional(path: Path) -> Path:
    if path.is_symlink():
        raise ValueError(f"review input is missing or unsafe: {path}")
    resolved = path.resolve()
    if not resolved.is_file() or resolved.is_symlink():
        raise ValueError(f"review input is missing or unsafe: {path}")
    return resolved


def validate_spdx(path: Path) -> None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"review SBOM is not valid JSON: {path}") from error
    creation = value.get("creationInfo") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or value.get("spdxVersion") != "SPDX-2.3"
        or value.get("SPDXID") != "SPDXRef-DOCUMENT"
        or not isinstance(value.get("documentNamespace"), str)
        or not isinstance(creation, dict)
        or not isinstance(creation.get("created"), str)
        or not isinstance(value.get("packages"), list)
        or not value["packages"]
    ):
        raise ValueError(f"review SBOM is not a complete SPDX 2.3 dependency inventory: {path}")


def archive_name(path: Path, category: str | None = None) -> str:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
        return relative.as_posix()
    except ValueError:
        if category is None:
            raise
        return f"evidence/{category}/{path.name}"


def build_bundle(
    *,
    output: Path,
    release_sha: str,
    optional: dict[str, list[Path]],
) -> dict[str, object]:
    if not release_sha or len(release_sha) > 128:
        raise ValueError("release SHA must be non-empty and at most 128 characters")
    sboms = optional.get("sbom", [])
    if not sboms:
        raise ValueError("a preliminary SPDX SBOM is required for a review bundle")
    for sbom in sboms:
        validate_spdx(safe_optional(sbom))
    inputs = [ROOT / relative for relative in REQUIRED_FILES]
    inputs.extend(backend_sources())
    categorized: list[tuple[Path, str | None]] = [(safe_optional(path), None) for path in inputs]
    for category, paths in optional.items():
        categorized.extend((safe_optional(path), category) for path in paths)
    unique: dict[str, Path] = {}
    for path, category in categorized:
        name = archive_name(path, category)
        if name in unique and unique[name] != path:
            raise ValueError(f"duplicate review archive path: {name}")
        unique[name] = path

    files = [
        {"path": name, "sha256": sha256(path), "bytes": path.stat().st_size}
        for name, path in sorted(unique.items())
    ]
    manifest = {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": "tinyzkp-p3-goldilocks-v1",
        "plonky3_version": "0.6.1",
        "files": files,
        "reproduction_commands": [
            "cargo test -p hc-stream -p hc-plonky3 -p hc-cli --locked",
            "cargo build --release -p hc-cli --locked",
            "sudo --preserve-env=HC_RELEASE_SHA python3 scripts/benchmark/fixed_host_preflight.py --scratch-dir /var/lib/tinyzkp-bench/scratch/fibonacci-1m --output raw-reports/fixed-host-preflight.json",
            "sudo --preserve-env=HC_RELEASE_SHA python3 scripts/benchmark/run_plonky3_cgroup.py --manifest examples/plonky3/fibonacci-1m.json --mode throughput --require-fixed-host --baseline-memory-cap 17179869184 --report raw-reports/fibonacci-1m.json",
            "sudo --preserve-env=HC_RELEASE_SHA python3 scripts/benchmark/run_plonky3_cgroup.py --manifest examples/plonky3/poseidon2-1m.json --mode throughput --require-fixed-host --baseline-memory-cap 17179869184 --report raw-reports/poseidon2-1m.json",
            "sudo --preserve-env=HC_RELEASE_SHA python3 scripts/benchmark/run_plonky3_cgroup.py --manifest examples/plonky3/fibonacci-16m.json --mode ceiling --require-fixed-host --report raw-reports/fibonacci-16m.json",
            "sudo --preserve-env=HC_RELEASE_SHA python3 scripts/benchmark/run_plonky3_cgroup.py --manifest examples/plonky3/poseidon2-16m.json --mode ceiling --require-fixed-host --report raw-reports/poseidon2-16m.json",
            "sudo chown -R $(id -u):$(id -g) raw-reports",
            "python3 scripts/benchmark/validate_release_gate.py --gate one-million --expected-release-sha $HC_RELEASE_SHA --manifest examples/plonky3/fibonacci-1m.json --baseline raw-reports/fibonacci-1m.baseline.json --candidate raw-reports/fibonacci-1m.json",
            "python3 scripts/benchmark/validate_release_gate.py --gate one-million --expected-release-sha $HC_RELEASE_SHA --manifest examples/plonky3/poseidon2-1m.json --baseline raw-reports/poseidon2-1m.baseline.json --candidate raw-reports/poseidon2-1m.json",
            "python3 scripts/benchmark/validate_release_gate.py --gate ten-million --expected-release-sha $HC_RELEASE_SHA --manifest examples/plonky3/fibonacci-16m.json --candidate raw-reports/fibonacci-16m.json",
            "python3 scripts/benchmark/validate_release_gate.py --gate ten-million --expected-release-sha $HC_RELEASE_SHA --manifest examples/plonky3/poseidon2-16m.json --candidate raw-reports/poseidon2-16m.json",
            "python3 scripts/release/run_crash_matrix.py --output raw-reports/crash-matrix.json --log-dir raw-reports/crash-logs --disk-full-scratch /mnt/tinyzkp-disk-full",
            f"HC_RELEASE_SHA={release_sha} python3 scripts/release/run_fuzz_smoke.py --seconds 60 --rss-limit-mb 2048 --output raw-reports/fuzz-smoke.json --log-dir raw-reports/fuzz-logs",
        ],
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode() + b"\n"
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_name(f".{output.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "w+b") as handle:
            with zipfile.ZipFile(
                handle, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
            ) as bundle:
                for name, path in sorted(unique.items()):
                    info = zipfile.ZipInfo(name, FIXED_ZIP_TIME)
                    info.external_attr = 0o100644 << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    bundle.writestr(info, path.read_bytes())
                info = zipfile.ZipInfo("review-manifest.json", FIXED_ZIP_TIME)
                info.external_attr = 0o100644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                bundle.writestr(info, manifest_bytes)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, output)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return {**manifest, "bundle_sha256": sha256(output)}


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--raw-report", type=Path, action="append", default=[])
    parser.add_argument("--known-answer", type=Path, action="append", default=[])
    parser.add_argument("--fuzz-result", type=Path, action="append", default=[])
    parser.add_argument("--crash-result", type=Path, action="append", default=[])
    parser.add_argument("--sbom", type=Path, action="append", required=True)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    metadata = build_bundle(
        output=args.output,
        release_sha=args.release_sha,
        optional={
            "raw-reports": args.raw_report,
            "known-answers": args.known_answer,
            "fuzz": args.fuzz_result,
            "crash": args.crash_result,
            "sbom": args.sbom,
        },
    )
    print(json.dumps(metadata, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError) as error:
        print(f"review bundle failed: {error}", file=sys.stderr)
        raise SystemExit(2)
