#!/usr/bin/env python3
"""Run every backend fuzz target and emit hashed machine-readable evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time


ROOT = Path(__file__).resolve().parents[2]
TARGETS = (
    "workload_manifest_v1",
    "proof_bundle_v1",
    "plonky3_proof_bytes_v1",
    "benchmark_report_v1",
    "checkpoint_manifest_v2",
    "challenger_snapshot_v1",
    "scratch_artifact_header_v1",
    "checkpoint_identity_v2",
    "resume_checkpoint_v2",
)
SMOKE_SEED_LIMIT = 16
MAX_SMOKE_SEED_BYTES = 1024 * 1024
PROFILE = "tinyzkp-p3-goldilocks-v1"
CARGO_FUZZ_VERSION = "cargo-fuzz 0.13.2"
WORKLOAD_FIXTURES = (
    "test-vectors/plonky3/fibonacci-16.manifest.json",
    "test-vectors/plonky3/fibonacci-max-field.manifest.json",
    "test-vectors/plonky3/poseidon2-8.manifest.json",
)
BUNDLE_FIXTURES = (
    "test-vectors/plonky3/fibonacci-16.bundle.json",
    "test-vectors/plonky3/poseidon2-8.bundle.json",
)
BENCHMARK_FIXTURES = ("test-vectors/plonky3/benchmark-report-v1.json",)


def write_json_atomic(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(value, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"evidence directory is unsafe: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if not path.is_dir() or path.is_symlink():
        raise ValueError(f"evidence directory is unsafe: {path}")
    path.chmod(0o700)


def reset_private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError(f"evidence directory is unsafe: {path}")
    if path.exists():
        shutil.rmtree(path)
    private_directory(path)


def harden_tree(path: Path) -> None:
    if not path.exists():
        return
    if path.is_symlink():
        raise ValueError(f"evidence tree is unsafe: {path}")
    for root, directories, files in os.walk(path, topdown=True, followlinks=False):
        root_path = Path(root)
        root_path.chmod(0o700)
        for name in directories:
            child = root_path / name
            if child.is_symlink():
                raise ValueError(f"evidence tree contains a symlink: {child}")
            child.chmod(0o700)
        for name in files:
            child = root_path / name
            if child.is_symlink():
                raise ValueError(f"evidence tree contains a symlink: {child}")
            child.chmod(0o600)


def read_seed_file(relative: str) -> bytes:
    path = ROOT / relative
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"tracked fuzz seed is missing or unsafe: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as handle:
        payload = handle.read(MAX_SMOKE_SEED_BYTES + 1)
    if not 0 < len(payload) <= MAX_SMOKE_SEED_BYTES:
        raise ValueError(f"tracked fuzz seed is empty or oversized: {path}")
    return payload


def checkpoint_seed() -> bytes:
    return json.dumps(
        {
            "artifacts": [],
            "backend_hash": [0] * 32,
            "challenger_state": [],
            "completed_phase": "trace",
            "dependency_lock_hash": [0] * 32,
            "input_hash": [0] * 32,
            "profile_hash": [0] * 32,
            "release_hash": [0] * 32,
            "resource_policy_hash": [0] * 32,
            "resume_payload": [],
            "schema_version": 2,
            "workload_hash": [0] * 32,
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def seed_payloads(target: str) -> list[bytes]:
    if target not in TARGETS:
        raise ValueError(f"unknown fuzz target: {target}")
    if target == "workload_manifest_v1":
        seeds = [read_seed_file(path) for path in WORKLOAD_FIXTURES]
    elif target == "proof_bundle_v1":
        seeds = [read_seed_file(path) for path in BUNDLE_FIXTURES]
    elif target == "plonky3_proof_bytes_v1":
        seeds = []
        for path in BUNDLE_FIXTURES:
            bundle = json.loads(read_seed_file(path))
            encoded = bundle.get("proof_base64url")
            if not isinstance(encoded, str) or not encoded:
                raise ValueError(f"proof fixture lacks canonical proof bytes: {path}")
            try:
                seeds.append(
                    base64.b64decode(
                        encoded + "=" * (-len(encoded) % 4),
                        altchars=b"-_",
                        validate=True,
                    )
                )
            except (ValueError, TypeError) as error:
                raise ValueError(f"proof fixture is malformed: {path}") from error
    elif target == "benchmark_report_v1":
        seeds = [read_seed_file(path) for path in BENCHMARK_FIXTURES]
    elif target in {
        "checkpoint_manifest_v2",
        "checkpoint_identity_v2",
        "resume_checkpoint_v2",
    }:
        seeds = [checkpoint_seed()]
    elif target == "challenger_snapshot_v1":
        seeds = [b"\0"]
    else:
        seeds = [b"\0", b"TZSCRATCH1"]
    unique = {hashlib.sha256(payload).digest(): payload for payload in seeds if payload}
    return [unique[digest] for digest in sorted(unique, key=lambda value: (len(unique[value]), value))]


def prepare_smoke_corpus(target: str, *, log_dir: Path) -> tuple[Path, int, str]:
    """Copy a deterministic, bounded seed sample outside the source tree.

    LibFuzzer does not apply ``-max_total_time`` while it initializes a large
    corpus. Passing thousands of accumulated seeds therefore turns a nominal
    smoke test into an unbounded multi-hour job. Full-corpus fuzzing belongs in
    the long-running campaign; release smoke uses a hashed coverage sample.
    """
    candidates = seed_payloads(target)
    if not candidates:
        raise ValueError(f"fuzz target has no bounded seeds: {target}")
    count = min(SMOKE_SEED_LIMIT, len(candidates))
    if count == 1:
        selected = [candidates[0]]
    else:
        selected = [
            candidates[(index * (len(candidates) - 1)) // (count - 1)]
            for index in range(count)
        ]

    private_directory(log_dir)
    corpus_root = log_dir / "smoke-corpus"
    private_directory(corpus_root)
    destination = corpus_root / target
    if destination.exists():
        if destination.is_symlink():
            raise ValueError(f"smoke corpus destination is unsafe: {destination}")
        shutil.rmtree(destination)
    private_directory(destination)
    digest = hashlib.sha256()
    for index, payload in enumerate(selected):
        if not 0 < len(payload) <= MAX_SMOKE_SEED_BYTES:
            raise ValueError(f"fuzz seed is empty or oversized: {target}")
        payload_digest = hashlib.sha256(payload).hexdigest()
        output = destination / f"{index:02d}-{payload_digest[:16]}"
        descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(bytes.fromhex(payload_digest))
    return destination, len(selected), digest.hexdigest()


def run_target(target: str, *, seconds: int, rss_limit_mb: int, log_dir: Path) -> dict[str, object]:
    corpus_dir, seed_count, corpus_sha256 = prepare_smoke_corpus(target, log_dir=log_dir)
    execution_dir = log_dir / "execution-corpus" / target
    private_directory(execution_dir.parent)
    reset_private_directory(execution_dir)
    artifact_dir = log_dir / "artifacts" / target
    private_directory(artifact_dir.parent)
    reset_private_directory(artifact_dir)
    command = [
        "cargo",
        "+nightly",
        "fuzz",
        "run",
        target,
        str(execution_dir),
        str(corpus_dir),
        "--",
        f"-max_total_time={seconds}",
        f"-rss_limit_mb={rss_limit_mb}",
        f"-timeout={max(10, seconds)}",
        f"-artifact_prefix={artifact_dir}{os.sep}",
        "-print_final_stats=1",
    ]
    log_path = log_dir / f"{target}.log"
    started = time.monotonic()
    descriptor = os.open(
        log_path,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_TRUNC
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as log:
            completed = subprocess.run(
                command,
                cwd=ROOT,
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
            log.flush()
            os.fsync(log.fileno())
    finally:
        harden_tree(execution_dir)
        shutil.rmtree(execution_dir, ignore_errors=False)
        harden_tree(artifact_dir)
    payload = log_path.read_bytes()
    artifacts = [
        {
            "path": str(path.relative_to(artifact_dir)),
            "bytes": path.stat().st_size,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted(artifact_dir.rglob("*"))
        if path.is_file() and not path.is_symlink()
    ]
    return {
        "target": target,
        "command": command,
        "exit_status": completed.returncode,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "log_path": str(log_path),
        "log_bytes": len(payload),
        "log_sha256": hashlib.sha256(payload).hexdigest(),
        "smoke_seed_count": seed_count,
        "smoke_corpus_sha256": corpus_sha256,
        "artifacts": artifacts,
    }


def tool_version(command: list[str]) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
    )
    value = completed.stdout.strip()
    if completed.returncode != 0 or not value:
        raise RuntimeError(f"unable to identify fuzz toolchain: {' '.join(command)}")
    return value


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--rss-limit-mb", type=int, default=2048)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.seconds <= 0 or args.rss_limit_mb <= 0:
        parser.error("seconds and RSS limit must be positive")
    rustc_version = tool_version(["rustc", "+nightly", "-Vv"])
    cargo_fuzz_version = tool_version(["cargo", "+nightly", "fuzz", "--version"])
    if cargo_fuzz_version != CARGO_FUZZ_VERSION:
        raise RuntimeError(
            f"cargo-fuzz version mismatch: expected {CARGO_FUZZ_VERSION}, "
            f"found {cargo_fuzz_version}"
        )
    results = [
        run_target(
            target,
            seconds=args.seconds,
            rss_limit_mb=args.rss_limit_mb,
            log_dir=args.log_dir,
        )
        for target in TARGETS
    ]
    report = {
        "schema_version": 1,
        "release_sha": os.environ.get("HC_RELEASE_SHA", "development-unreleased"),
        "profile": PROFILE,
        "toolchain": "nightly",
        "rustc_version": rustc_version,
        "cargo_fuzz_version": cargo_fuzz_version,
        "all_targets_passed": all(result["exit_status"] == 0 for result in results),
        "targets": results,
    }
    write_json_atomic(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_targets_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
