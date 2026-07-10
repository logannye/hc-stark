#!/usr/bin/env python3
"""Run every backend fuzz target and emit hashed machine-readable evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
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


def run_target(target: str, *, seconds: int, rss_limit_mb: int, log_dir: Path) -> dict[str, object]:
    command = [
        "cargo",
        "+nightly",
        "fuzz",
        "run",
        target,
        "--",
        f"-max_total_time={seconds}",
        f"-rss_limit_mb={rss_limit_mb}",
        "-print_final_stats=1",
    ]
    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path = log_dir / f"{target}.log"
    started = time.monotonic()
    with log_path.open("wb") as log:
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
    payload = log_path.read_bytes()
    return {
        "target": target,
        "command": command,
        "exit_status": completed.returncode,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "log_path": str(log_path),
        "log_bytes": len(payload),
        "log_sha256": hashlib.sha256(payload).hexdigest(),
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seconds", type=int, default=60)
    parser.add_argument("--rss-limit-mb", type=int, default=2048)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.seconds <= 0 or args.rss_limit_mb <= 0:
        parser.error("seconds and RSS limit must be positive")
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
        "toolchain": "nightly",
        "all_targets_passed": all(result["exit_status"] == 0 for result in results),
        "targets": results,
    }
    write_json_atomic(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["all_targets_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
