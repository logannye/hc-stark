#!/usr/bin/env python3
"""Run and record a fixed-host customer_cubic8 declarative proof."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

import customer_cubic8


def run(command: list[str], *, capture: bool = False) -> str:
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"command failed: {completed.stderr[-2000:]}")
    return completed.stdout.strip() if capture else ""


def cgroup_limit(name: str) -> int | None:
    path = Path("/sys/fs/cgroup") / name
    try:
        raw = path.read_text(encoding="utf-8").strip()
        return None if raw == "max" else int(raw)
    except (OSError, ValueError):
        return None


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--rows", type=int, required=True)
    parser.add_argument("--mode", choices=("reference", "bounded"), required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    args = parser.parse_args()
    if len(args.release_sha) != 40 or any(char not in "0123456789abcdef" for char in args.release_sha):
        raise ValueError("release SHA must be canonical")
    args.work.mkdir(parents=True, exist_ok=True, mode=0o700)
    customer_cubic8.write_json(args.work / "air.json", customer_cubic8.build_air())
    initial = list(range(1, customer_cubic8.WIDTH + 1))
    final = customer_cubic8.write_trace(args.work / "trace.bin", args.rows, initial)
    air_digest = run([str(args.cli), "plonky3", "validate-air", "--air", str(args.work / "air.json")], capture=True)
    public = {"schema_version": 1, "air_digest_hex": air_digest, "values": initial + final}
    customer_cubic8.write_json(args.work / "public-inputs.json", public)
    run([
        str(args.cli), "plonky3", "pack-trace", "--air", str(args.work / "air.json"),
        "--trace", str(args.work / "trace.bin"), "--rows", str(args.rows),
        "--output-dir", str(args.work / "packed"), "--chunk-bytes", str(64 * 1024 * 1024),
    ])
    policy = {
        "mode": "scratch",
        "max_resident_bytes": 2 * 1024**3,
        "max_scratch_bytes": 1024**4,
        "scratch_dir": str(args.work / "scratch"),
        "max_threads": 8,
        "checkpoint_policy": "retain_on_failure",
    }
    customer_cubic8.write_json(args.work / "policy.json", policy)
    command = [
        str(args.cli), "plonky3", "prove-air", "--air", str(args.work / "air.json"),
        "--trace-manifest", str(args.work / "packed" / "trace-manifest.json"),
        "--chunks-dir", str(args.work / "packed"), "--public-inputs", str(args.work / "public-inputs.json"),
        "--policy", str(args.work / "policy.json"), "--output", str(args.work / "proof.json"),
    ]
    if args.mode == "reference":
        command.append("--reference")
    timing = args.work / f"time-{args.mode}.txt"
    timed_command = ["/usr/bin/time", "-v", "-o", str(timing), *command]
    started = time.monotonic_ns()
    run(timed_command)
    wall_time_ms = (time.monotonic_ns() - started) // 1_000_000
    peak_line = next(
        line for line in timing.read_text(encoding="utf-8").splitlines()
        if "Maximum resident set size (kbytes)" in line
    )
    peak_kib = int(peak_line.rsplit(":", 1)[1].strip())
    run([str(args.cli), "plonky3", "verify-air", "--bundle", str(args.work / "proof.json")])
    proof = json.loads((args.work / "proof.json").read_text(encoding="utf-8"))
    report = {
        "schema_version": 1,
        "workload_id": "customer_cubic8",
        "logical_rows": args.rows,
        "mode": args.mode,
        "release_sha": args.release_sha,
        "effective_cpu_count": len(os.sched_getaffinity(0)),
        "effective_memory_bytes": cgroup_limit("memory.max"),
        "peak_resident_bytes": peak_kib * 1024,
        "wall_time_ms": wall_time_ms,
        "proof_digest_hex": proof["proof_digest_hex"],
        "official_verification": True,
        "command": timed_command,
    }
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    args.output.chmod(0o600)


if __name__ == "__main__":
    main()
