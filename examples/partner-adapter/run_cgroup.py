#!/usr/bin/env python3
"""Measure the example partner AIR in a fresh Linux cgroup-v2 process."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


ROOT = Path(__file__).resolve().parents[2]
HARNESS_PATH = ROOT / "scripts" / "benchmark" / "run_plonky3_cgroup.py"
SPEC = importlib.util.spec_from_file_location("tinyzkp_cgroup_harness", HARNESS_PATH)
assert SPEC and SPEC.loader
HARNESS = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(HARNESS)
PROFILE = "tinyzkp-p3-goldilocks-v1"


def run_doctor(binary: Path, manifest: Path) -> dict[str, object]:
    with tempfile.TemporaryDirectory(prefix="tinyzkp-partner-doctor-") as temp:
        output = Path(temp) / "doctor.json"
        command = [str(binary), "--mode", "doctor", str(manifest), str(output)]
        completed = subprocess.run(command, capture_output=True, text=True, check=False)
        if completed.returncode != 0 or not output.is_file():
            raise RuntimeError(f"partner preflight failed: {completed.stderr[-4000:]}")
        value = json.loads(output.read_text(encoding="utf-8"))
        if (
            not isinstance(value, dict)
            or value.get("mode") != "doctor"
            or value.get("profile") != PROFILE
            or not HARNESS.valid_resource_estimate(value.get("preflight_estimate"))
        ):
            raise RuntimeError("partner preflight returned malformed evidence")
        return value


def run_bounded(
    *,
    binary: Path,
    manifest: dict[str, object],
    manifest_path: Path,
    report_path: Path,
    cgroup_parent: Path,
    release_sha: str,
    benchmark_session_id: str,
    host_metadata: dict[str, object],
) -> dict[str, object]:
    memory_cap = int(manifest["resource_policy"]["max_resident_bytes"])
    cgroup = cgroup_parent / f"tinyzkp-partner-{uuid.uuid4().hex}"
    normalized_path, _, scratch = HARNESS.prepare_run_manifest(
        manifest, report_path, "bounded"
    )
    try:
        preflight = run_doctor(binary, normalized_path)
        HARNESS.configure_cgroup(cgroup, memory_cap)
        with tempfile.TemporaryDirectory(prefix="tinyzkp-partner-worker-") as temp:
            worker_output = Path(temp) / "worker.json"
            command = [
                str(binary),
                "--mode",
                "bounded",
                str(normalized_path),
                str(worker_output),
            ]
            started = time.monotonic()
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=HARNESS.child_join_cgroup(cgroup),
            )
            scratch_peak = 0
            observed_rss_peak = 0
            while process.poll() is None:
                scratch_peak = max(scratch_peak, HARNESS.directory_bytes(scratch))
                observed_rss_peak = max(
                    observed_rss_peak, HARNESS.process_rss_bytes(process.pid)
                )
                time.sleep(0.01)
            stdout, stderr = process.communicate()
            wall_ms = int((time.monotonic() - started) * 1000)
            scratch_peak = max(scratch_peak, HARNESS.directory_bytes(scratch))
            cgroup_peak = HARNESS.read_int(cgroup / "memory.peak")
            cpu_seconds = HARNESS.parse_cpu_stat(
                (cgroup / "cpu.stat").read_text(encoding="utf-8")
            )
            io_values = HARNESS.parse_key_values(
                (cgroup / "io.stat").read_text(encoding="utf-8")
            )
            worker: dict[str, object] = {}
            if worker_output.is_file():
                worker = json.loads(worker_output.read_text(encoding="utf-8"))
            scratch_peak = max(
                scratch_peak,
                int(worker.get("prover_scratch_high_water_bytes", 0)),
            )

        verified = worker.get("official_verification") is True and process.returncode == 0
        report: dict[str, object] = {
            "schema_version": 1,
            "scope": "full_pipeline",
            "mode": "bounded",
            "benchmark_session_id": benchmark_session_id,
            **host_metadata,
            "release_sha": release_sha,
            "dependency_profile": PROFILE,
            "exact_command": command,
            "normalized_manifest_path": str(normalized_path),
            "workload_manifest_digest_hex": run_doctor(binary, manifest_path)[
                "manifest_digest_hex"
            ],
            "normalized_manifest_digest_hex": worker.get("manifest_digest_hex", ""),
            "preflight_estimate": preflight["preflight_estimate"],
            "cpu_seconds": cpu_seconds,
            "wall_time_ms": wall_ms,
            "peak_rss_bytes": observed_rss_peak,
            "cgroup_peak_bytes": cgroup_peak,
            "scratch_high_water_bytes": scratch_peak,
            "read_bytes": io_values.get("rbytes", 0),
            "write_bytes": io_values.get("wbytes", 0),
            "proof_size_bytes": int(worker.get("proof_size_bytes", 0)),
            "verification_time_ms": int(worker.get("verification_time_ms", 0)),
            "verification_succeeded": verified,
            "exit_status": process.returncode,
        }
        if not verified:
            memory_events = ""
            try:
                memory_events = (cgroup / "memory.events").read_text(encoding="utf-8")
            except OSError:
                pass
            diagnostic = (stderr or stdout)[-3000:]
            report["failure_diagnostic"] = (
                f"{diagnostic}\ncgroup memory.events:\n{memory_events}"
            )[-4000:]
        return report
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        try:
            cgroup.rmdir()
        except OSError:
            pass


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument(
        "--binary",
        type=Path,
        default=Path(
            "target/release/tinyzkp-partner-adapter-example"
        ),
    )
    parser.add_argument(
        "--cgroup-parent", type=Path, default=Path("/sys/fs/cgroup/tinyzkp-bench")
    )
    args = parser.parse_args(argv)
    HARNESS.ensure_cgroup_v2(args.cgroup_parent)
    binary = args.binary.resolve()
    if not binary.is_file():
        raise RuntimeError(f"partner release binary not found: {binary}")
    manifest_path = args.manifest.resolve()
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    release_sha = os.environ.get("HC_RELEASE_SHA", "development-unreleased")
    host_metadata = HARNESS.collect_host_metadata(
        Path(manifest["resource_policy"]["scratch_dir"])
    )
    report = run_bounded(
        binary=binary,
        manifest=manifest,
        manifest_path=manifest_path,
        report_path=args.report,
        cgroup_parent=args.cgroup_parent,
        release_sha=release_sha,
        benchmark_session_id=uuid.uuid4().hex,
        host_metadata=host_metadata,
    )
    HARNESS.write_json(args.report, report)
    if not report["verification_succeeded"]:
        raise RuntimeError(f"partner worker failed; raw report preserved at {args.report}")
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"partner benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2)
