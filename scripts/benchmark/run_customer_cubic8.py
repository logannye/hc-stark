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
import tempfile
import time

import customer_cubic8


BOUNDED_RESIDENT_CAP_BYTES = 512 * 1024**2
BOUNDED_MAX_THREADS = 2


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


def current_cgroup_path() -> Path:
    for line in Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines():
        hierarchy, controllers, relative = line.split(":", 2)
        if hierarchy == "0" and controllers == "":
            return Path("/sys/fs/cgroup") / relative.lstrip("/")
    raise RuntimeError("current cgroup-v2 identity is unavailable")


def cgroup_limit(name: str) -> int | None:
    path = current_cgroup_path() / name
    try:
        raw = path.read_text(encoding="utf-8").strip()
        return None if raw == "max" else int(raw)
    except (OSError, ValueError):
        return None


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if path.exists() or path.is_symlink():
        raise ValueError(f"refusing to replace report: {path}")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def process_rss_bytes(pid: int) -> int:
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1]) * 1024
    except (FileNotFoundError, ProcessLookupError, ValueError):
        return 0
    return 0


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
    args.work.mkdir(parents=True, exist_ok=False, mode=0o700)
    os.chmod(args.work, 0o700)
    customer_cubic8.write_json(args.work / "air.json", customer_cubic8.build_air())
    initial = list(range(1, customer_cubic8.WIDTH + 1))
    final = customer_cubic8.write_trace(args.work / "trace.bin", args.rows, initial)
    validation = json.loads(
        run(
            [
                str(args.cli),
                "plonky3",
                "validate-air",
                "--air",
                str(args.work / "air.json"),
            ],
            capture=True,
        )
    )
    if validation.get("valid") is not True:
        raise RuntimeError("signed CLI rejected customer_cubic8")
    air_digest = str(validation["air_digest_hex"])
    public = {"schema_version": 1, "air_digest_hex": air_digest, "values": initial + final}
    customer_cubic8.write_json(args.work / "public-inputs.json", public)
    run([
        str(args.cli), "plonky3", "pack-trace", "--air", str(args.work / "air.json"),
        "--trace", str(args.work / "trace.bin"), "--rows", str(args.rows),
        "--output-dir", str(args.work / "packed"), "--chunk-bytes", str(64 * 1024 * 1024),
    ])
    policy = {
        "mode": "scratch",
        "max_resident_bytes": BOUNDED_RESIDENT_CAP_BYTES,
        "max_scratch_bytes": 1024**4,
        "scratch_dir": str(args.work / "scratch"),
        "max_threads": BOUNDED_MAX_THREADS,
        "checkpoint_policy": "retain_on_failure",
    }
    customer_cubic8.write_json(args.work / "policy.json", policy)
    trace_manifest = args.work / "packed" / "trace-manifest-v1.json"
    if not trace_manifest.is_file():
        raise RuntimeError("pack-trace did not produce TraceManifestV1")
    command = [
        str(args.cli), "plonky3", "prove-air", "--air", str(args.work / "air.json"),
        "--trace-manifest", str(trace_manifest),
        "--chunks-dir", str(args.work / "packed"), "--public-inputs", str(args.work / "public-inputs.json"),
        "--policy", str(args.work / "policy.json"), "--output", str(args.work / "proof.json"),
    ]
    if args.mode == "reference":
        command.append("--reference")
    started = time.monotonic_ns()
    process = subprocess.Popen(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    peak_rss_bytes = 0
    while process.poll() is None:
        peak_rss_bytes = max(peak_rss_bytes, process_rss_bytes(process.pid))
        time.sleep(0.01)
    stdout, stderr = process.communicate()
    wall_time_ms = (time.monotonic_ns() - started) // 1_000_000
    if process.returncode != 0 or peak_rss_bytes <= 0:
        raise RuntimeError(f"proof command failed: {(stderr or stdout)[-2000:]}")
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
        "effective_swap_bytes": cgroup_limit("memory.swap.max"),
        "policy_resident_bytes": policy["max_resident_bytes"],
        "policy_max_threads": policy["max_threads"],
        "peak_resident_bytes": peak_rss_bytes,
        "wall_time_ms": wall_time_ms,
        "proof_digest_hex": proof["proof_digest_hex"],
        "official_verification": True,
        "command": command,
    }
    write_private_json(args.output, report)


if __name__ == "__main__":
    main()
