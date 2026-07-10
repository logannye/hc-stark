#!/usr/bin/env python3
"""Run checkpoint/crash integrity cases and emit hashed release evidence."""

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
PROFILE = "tinyzkp-p3-goldilocks-v1"
PHASES = (
    "trace",
    "trace_lde",
    "trace_commitment",
    "quotient",
    "quotient_lde",
    "quotient_commitment",
    "openings",
    "fri_layer_0",
    "fri_layer_1",
    "fri_layer_2",
    "fri_layer_3",
    "fri_layer_4",
    "fri_layer_5",
    "proof_assembly",
)
PHASE_TEST = (
    "hc-plonky3",
    "bounded_prover::tests::single_checkpoint_phase_from_environment_resumes_to_identical_proof_bytes",
)
INTEGRITY_CASES = (
    (
        "saved_artifact_reuse",
        "hc-plonky3",
        "bounded_prover::tests::resume_consumes_the_exact_saved_early_phase_artifact",
    ),
    (
        "corrupt_artifact_and_stale_identity",
        "hc-plonky3",
        "bounded_prover::tests::corrupt_artifact_and_stale_release_fail_closed",
    ),
    (
        "cancellation_retention",
        "hc-plonky3",
        "bounded_prover::tests::cancellation_retains_only_an_explicitly_resumable_checkpoint",
    ),
    (
        "truncation_and_checksum",
        "hc-stream",
        "tests::scratch_matrix_round_trips_and_detects_corruption",
    ),
    (
        "path_traversal",
        "hc-stream",
        "tests::path_traversal_and_unnoted_retention_are_rejected",
    ),
    (
        "symlink_rejection",
        "hc-stream",
        "tests::symlinked_roots_and_artifacts_fail_closed",
    ),
)
DISK_FULL_CASE = (
    "disk_full_resume",
    "hc-plonky3",
    "bounded_prover::tests::disk_full_failure_retains_a_resumable_checkpoint",
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


def run_case(
    name: str,
    package: str,
    test_name: str,
    *,
    log_dir: Path,
    release: bool,
    phase: str | None = None,
    disk_full_scratch: Path | None = None,
) -> dict[str, object]:
    command = ["cargo", "test", "-p", package]
    if release:
        command.append("--release")
    command.extend(["--locked"])
    if package == "hc-plonky3":
        command.extend(["--features", "fault-injection"])
    command.extend([test_name, "--", "--exact", "--nocapture"])
    environment = os.environ.copy()
    if phase is not None:
        environment["TINYZKP_SINGLE_CRASH_PHASE"] = phase
    if disk_full_scratch is not None:
        environment["TINYZKP_DISK_FULL_SCRATCH"] = str(disk_full_scratch)

    log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    log_path = log_dir / f"{name}.log"
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    started = time.monotonic()
    with os.fdopen(descriptor, "wb") as log:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
        log.flush()
        os.fsync(log.fileno())
    payload = log_path.read_bytes()
    result: dict[str, object] = {
        "case": name,
        "command": command,
        "exit_status": completed.returncode,
        "duration_ms": int((time.monotonic() - started) * 1000),
        "log_path": str(log_path),
        "log_bytes": len(payload),
        "log_sha256": hashlib.sha256(payload).hexdigest(),
    }
    if phase is not None:
        result["phase"] = phase
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--disk-full-scratch", type=Path)
    args = parser.parse_args(argv)
    if args.disk_full_scratch is not None and sys.platform != "linux":
        parser.error("the disk-full release case is supported only on Linux")

    cases = [
        run_case(
            f"checkpoint_{phase}",
            *PHASE_TEST,
            log_dir=args.log_dir,
            release=not args.debug,
            phase=phase,
        )
        for phase in PHASES
    ]
    cases.extend(
        run_case(
            name,
            package,
            test_name,
            log_dir=args.log_dir,
            release=not args.debug,
        )
        for name, package, test_name in INTEGRITY_CASES
    )
    if args.disk_full_scratch is not None:
        cases.append(
            run_case(
                *DISK_FULL_CASE,
                log_dir=args.log_dir,
                release=not args.debug,
                disk_full_scratch=args.disk_full_scratch,
            )
        )

    all_executed_cases_passed = all(case["exit_status"] == 0 for case in cases)
    complete_for_release = args.disk_full_scratch is not None and all_executed_cases_passed
    report = {
        "schema_version": 1,
        "release_sha": os.environ.get("HC_RELEASE_SHA", "development-unreleased"),
        "profile": PROFILE,
        "build_profile": "debug" if args.debug else "release",
        "all_executed_cases_passed": all_executed_cases_passed,
        "complete_for_release": complete_for_release,
        "cases": cases,
    }
    write_json_atomic(args.output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if all_executed_cases_passed else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
