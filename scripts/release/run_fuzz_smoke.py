#!/usr/bin/env python3
"""Run every backend fuzz target and emit hashed machine-readable evidence."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time

import evidence_runtime


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
    "air_package_v1",
    "trace_manifest_v1",
    "air_proof_bundle_v1",
    "zstd_trace_chunk_v1",
    "public_inputs_v1",
)
SMOKE_SEED_LIMIT = 16
MAX_SMOKE_SEED_BYTES = 1024 * 1024
PROFILE = "tinyzkp-p3-goldilocks-v1"
CARGO_FUZZ_VERSION = "cargo-fuzz 0.13.2"
FUZZ_TOOLCHAIN = "nightly-2026-04-15"
FUZZ_SANITIZER = "address"
FUZZ_ASAN_OPTIONS = "detect_odr_violation=0"
TOOL_IDENTITY_FILE = "fuzz-tool-identity.json"
RELEASE_MIN_SECONDS_PER_TARGET = 60
MAX_STARTUP_TIMEOUT_SECONDS = 3600
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
DECLARATIVE_AIR_DIGEST = (
    "b5cb62fdd7e9de8c7b4d965cd4fb3d38c423cdabea3efb4dba09cbd03195ebaa"
)
DONE_MARKER = re.compile(rb"(?m)^#(\d+)\s+DONE\b")
RUN_SUMMARY = re.compile(rb"(?m)^Done\s+(\d+)\s+runs\s+in\s+(\d+)\s+second\(s\)\s*$")
EXECUTED_UNITS = re.compile(rb"(?m)^stat::number_of_executed_units:\s*(\d+)\s*$")
PEAK_RSS = re.compile(rb"(?m)^stat::peak_rss_mb:\s*(\d+)\s*$")
TARGET_MARKER = re.compile(
    rb"(?m)^tinyzkp-fuzz-target-v1 target=([a-z0-9_]+) "
    rb"corpus_sha256=([0-9a-f]{64}) toolchain=([a-z0-9-]+)$"
)


def expected_target_marker(target: str, corpus_sha256: str) -> dict[str, str]:
    return {
        "target": target,
        "corpus_sha256": corpus_sha256,
        "toolchain": FUZZ_TOOLCHAIN,
    }


def target_marker_line(marker: dict[str, str]) -> bytes:
    return (
        f"tinyzkp-fuzz-target-v1 target={marker['target']} "
        f"corpus_sha256={marker['corpus_sha256']} "
        f"toolchain={marker['toolchain']}\n"
    ).encode("ascii")


def parse_target_marker(payload: bytes) -> dict[str, str] | None:
    matches = list(TARGET_MARKER.finditer(payload))
    if len(matches) != 1:
        return None
    target, corpus_sha256, toolchain = (
        value.decode("ascii") for value in matches[0].groups()
    )
    return {
        "target": target,
        "corpus_sha256": corpus_sha256,
        "toolchain": toolchain,
    }


def verify_opened_tool_descriptors(
    opened_tools: list[int], expected_sha256: tuple[str, ...]
) -> None:
    """Revalidate release-only executable descriptors after fuzzing.

    Partial diagnostics intentionally execute the identified tool paths
    directly and therefore have no held descriptors. Release evidence must
    provide the complete descriptor set; any partial set is an invariant
    violation rather than something ``zip`` may silently truncate.
    """
    if not opened_tools:
        return
    if len(opened_tools) != len(expected_sha256):
        raise RuntimeError("fuzz executable descriptor set is incomplete")
    for descriptor_value, expected in zip(
        opened_tools, expected_sha256, strict=True
    ):
        if evidence_runtime._digest_descriptor(descriptor_value) != expected:
            raise RuntimeError("fuzz executable changed during evidence generation")


def fuzz_environment(source: dict[str, str] | os._Environ[str]) -> dict[str, str]:
    """Return the scrubbed environment with the reviewed nightly selected."""
    environment = evidence_runtime.sanitized_environment(source)
    environment["RUSTUP_TOOLCHAIN"] = FUZZ_TOOLCHAIN
    return environment


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
                raise ValueError(f"evidence tree contains an unsafe file: {child}")
            child.chmod(0o700)
        for name in files:
            child = root_path / name
            details = os.lstat(child)
            if (
                stat.S_ISLNK(details.st_mode)
                or not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
            ):
                raise ValueError(f"evidence tree contains a symlink: {child}")
            os.chmod(child, 0o600, follow_symlinks=False)


def parse_libfuzzer_summary(payload: bytes) -> dict[str, int | bool] | None:
    done_matches = list(DONE_MARKER.finditer(payload))
    run_summaries = list(RUN_SUMMARY.finditer(payload))
    executed_summaries = list(EXECUTED_UNITS.finditer(payload))
    peak_summaries = list(PEAK_RSS.finditer(payload))
    if (
        len(done_matches) != 1
        or len(run_summaries) != 1
        or len(executed_summaries) != 1
        or len(peak_summaries) != 1
    ):
        return None
    done_units = int(done_matches[0].group(1))
    run_summary = run_summaries[0]
    executed_units = executed_summaries[0]
    peak_rss = peak_summaries[0]
    summary_runs, elapsed_seconds = (int(value) for value in run_summary.groups())
    units = int(executed_units.group(1))
    peak_rss_mb = int(peak_rss.group(1))
    if (
        done_units <= 0
        or summary_runs <= 0
        or units <= 0
        or done_units != summary_runs
        or summary_runs != units
        or peak_rss_mb <= 0
    ):
        return None
    return {
        "libfuzzer_done": True,
        "done_executed_units": done_units,
        "libfuzzer_elapsed_seconds": elapsed_seconds,
        "executed_units": units,
        "peak_rss_mb": peak_rss_mb,
    }


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


def declarative_air_seed() -> dict[str, object]:
    return {
        "schema_version": 1,
        "backend": "plonky3",
        "profile": PROFILE,
        "field": "goldilocks",
        "expected_verifier": "p3_uni_stark_0.6.1",
        "trace_width": 1,
        "public_inputs": [],
        "expressions": [
            {"op": "current", "column": 0},
            {"op": "next", "column": 0},
            {"op": "sub", "left": 1, "right": 0},
        ],
        "constraints": [{"kind": "transition", "expression": 2}],
    }


def public_inputs_seed() -> bytes:
    return json.dumps(
        {
            "schema_version": 1,
            "air_digest_hex": DECLARATIVE_AIR_DIGEST,
            "values": [],
        },
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def air_proof_bundle_seed() -> bytes:
    zero_digest = "0" * 64
    return json.dumps(
        {
            "schema_version": 1,
            "air": declarative_air_seed(),
            "air_digest_hex": DECLARATIVE_AIR_DIGEST,
            "trace_manifest": {
                "schema_version": 1,
                "air_digest_hex": DECLARATIVE_AIR_DIGEST,
                "trace_digest_hex": zero_digest,
                "logical_rows": 1024,
                "trace_width": 1,
                "field_encoding": "goldilocks_u64_le",
                "compression": "zstd",
                "chunk_uncompressed_bytes": 8192,
                "chunks": [
                    {
                        "index": 0,
                        "compressed_bytes": 1,
                        "uncompressed_bytes": 8192,
                        "blake3_hex": zero_digest,
                    }
                ],
            },
            "trace_manifest_digest_hex": zero_digest,
            "public_inputs": {
                "schema_version": 1,
                "air_digest_hex": DECLARATIVE_AIR_DIGEST,
                "values": [],
            },
            "public_inputs_digest_hex": zero_digest,
            "proof_base64url": "",
            "proof_digest_hex": zero_digest,
            "provenance": {
                "prover_version": "0.6.1",
                "verifier_version": "0.6.1",
                "release_sha": "fuzz-seed",
                "dependency_profile": PROFILE,
                "proof_serializer": "postcard-1.1.3",
            },
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
    elif target == "air_package_v1":
        seeds = [b"{}", b'{"schema_version":1}']
    elif target == "trace_manifest_v1":
        seeds = [b"[{},{}]", b'[{"schema_version":1},{"schema_version":1}]']
    elif target == "air_proof_bundle_v1":
        seeds = [b"{}", air_proof_bundle_seed()]
    elif target == "zstd_trace_chunk_v1":
        # A minimal valid empty Zstandard frame plus a truncated magic header
        # exercise both decoder construction and bounded failure paths.
        seeds = [bytes.fromhex("28b52ffd2000010000"), bytes.fromhex("28b52ffd")]
    elif target == "public_inputs_v1":
        seeds = [b"{}", public_inputs_seed()]
    else:
        seeds = [b"\0", b"TZSCRATCH1"]
    unique = {hashlib.sha256(payload).digest(): payload for payload in seeds if payload}
    return [
        unique[digest]
        for digest in sorted(unique, key=lambda value: (len(unique[value]), value))
    ]


def expected_corpus_descriptor(target: str) -> dict[str, object]:
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
    digest = hashlib.sha256()
    seeds = []
    for payload in selected:
        if not 0 < len(payload) <= MAX_SMOKE_SEED_BYTES:
            raise ValueError(f"fuzz seed is empty or oversized: {target}")
        payload_digest = hashlib.sha256(payload).hexdigest()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(bytes.fromhex(payload_digest))
        seeds.append({"bytes": len(payload), "sha256": payload_digest})
    return {
        "schema_version": 1,
        "selection": "evenly-spaced-sha256-sorted-v1",
        "seed_count": len(selected),
        "corpus_sha256": digest.hexdigest(),
        "seeds": seeds,
    }


def prepare_smoke_corpus(
    target: str, *, log_dir: Path
) -> tuple[Path, dict[str, object]]:
    """Copy a deterministic, bounded seed sample outside the source tree.

    LibFuzzer does not apply ``-max_total_time`` while it initializes a large
    corpus. Passing thousands of accumulated seeds therefore turns a nominal
    smoke test into an unbounded multi-hour job. Full-corpus fuzzing belongs in
    the long-running campaign; release smoke uses a hashed coverage sample.
    """
    descriptor = expected_corpus_descriptor(target)
    selected = seed_payloads(target)
    count = int(descriptor["seed_count"])
    if count == 1:
        selected = [selected[0]]
    else:
        selected = [
            selected[(index * (len(selected) - 1)) // (count - 1)]
            for index in range(count)
        ]

    evidence_runtime.ensure_private_directory(ROOT, log_dir)
    corpus_root = log_dir / "smoke-corpus"
    evidence_runtime.ensure_private_directory(ROOT, corpus_root)
    destination = corpus_root / target
    evidence_runtime.reset_private_directory(ROOT, log_dir, destination)
    for index, payload in enumerate(selected):
        payload_digest = hashlib.sha256(payload).hexdigest()
        output = destination / f"{index:02d}-{payload_digest[:16]}"
        output_descriptor = evidence_runtime.open_private_output(ROOT, output)
        with os.fdopen(output_descriptor, "wb") as handle:
            handle.write(payload)
    return destination, descriptor


def verify_prepared_corpus(path: Path, descriptor: dict[str, object]) -> None:
    files = sorted(item for item in path.iterdir() if item.is_file() and not item.is_symlink())
    digest = hashlib.sha256()
    seeds: list[dict[str, object]] = []
    for item in files:
        payload = item.read_bytes()
        payload_digest = hashlib.sha256(payload).hexdigest()
        digest.update(len(payload).to_bytes(8, "big"))
        digest.update(bytes.fromhex(payload_digest))
        seeds.append({"bytes": len(payload), "sha256": payload_digest})
    if (
        len(files) != descriptor.get("seed_count")
        or digest.hexdigest() != descriptor.get("corpus_sha256")
        or seeds != descriptor.get("seeds")
    ):
        raise ValueError("prepared fuzz corpus changed during execution")


def run_target(
    target: str,
    *,
    seconds: int,
    rss_limit_mb: int,
    log_dir: Path,
    target_dir: Path,
    target_triple: str,
    cargo_fuzz_executable: str = "cargo-fuzz",
    execution_cargo_fuzz: str | None = None,
    execution_root: Path = ROOT,
    pass_fds: tuple[int, ...] = (),
    write_boundary_paths: tuple[Path, ...] | None = None,
    run_write_boundary_paths: tuple[Path, ...] | None = None,
    environment: dict[str, str] | None = None,
    build_timeout_seconds: int = 900,
    timeout_seconds: int | None = None,
) -> dict[str, object]:
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", target_triple):
        raise ValueError("fuzz target triple is unsafe")
    log_dir = evidence_runtime.assert_no_symlink_ancestry(ROOT, log_dir)
    target_dir = evidence_runtime.assert_no_symlink_ancestry(ROOT, target_dir)
    corpus_dir, corpus_descriptor = prepare_smoke_corpus(target, log_dir=log_dir)
    execution_dir = log_dir / "execution-corpus" / target
    evidence_runtime.ensure_private_directory(ROOT, execution_dir.parent)
    evidence_runtime.reset_private_directory(ROOT, log_dir, execution_dir)
    artifact_dir = log_dir / "artifacts" / target
    evidence_runtime.ensure_private_directory(ROOT, artifact_dir.parent)
    evidence_runtime.reset_private_directory(ROOT, log_dir, artifact_dir)
    target_dir_command_path = target_dir.relative_to(ROOT.resolve()).as_posix()
    build_command = [
        cargo_fuzz_executable,
        "build",
        "--target",
        target_triple,
        "--target-dir",
        target_dir_command_path,
        target,
    ]
    execution_build_command = list(build_command)
    execution_build_command[5] = str(target_dir)
    if execution_cargo_fuzz is not None:
        execution_build_command[0] = execution_cargo_fuzz
    fuzz_binary_path = target_dir / target_triple / "release" / target
    fuzz_binary_command_path = fuzz_binary_path.relative_to(ROOT.resolve()).as_posix()
    run_command = [
        fuzz_binary_command_path,
        f"-max_total_time={seconds}",
        f"-rss_limit_mb={rss_limit_mb}",
        f"-timeout={max(10, seconds)}",
        f"-artifact_prefix={artifact_dir}{os.sep}",
        "-print_final_stats=1",
        str(execution_dir),
        str(corpus_dir),
    ]
    environment = dict(
        evidence_runtime.sanitized_environment(os.environ)
        if environment is None
        else environment
    )
    execution_command_path = execution_dir.relative_to(ROOT.resolve()).as_posix()
    corpus_command_path = corpus_dir.relative_to(ROOT.resolve()).as_posix()
    artifact_command_path = artifact_dir.relative_to(ROOT.resolve()).as_posix()
    run_command[4] = f"-artifact_prefix={artifact_command_path}/"
    run_command[6] = execution_command_path
    run_command[7] = corpus_command_path
    execution_command = list(run_command)
    execution_command[0] = str(fuzz_binary_path)
    execution_command[4] = f"-artifact_prefix={artifact_dir}/"
    execution_command[6] = str(execution_dir)
    execution_command[7] = str(corpus_dir)
    timeout_seconds = seconds + 900 if timeout_seconds is None else timeout_seconds
    target_marker = expected_target_marker(
        target, str(corpus_descriptor["corpus_sha256"])
    )
    log_path = log_dir / f"{target}.log"
    build_started = time.monotonic()
    descriptor = evidence_runtime.open_private_output(ROOT, log_path)
    fuzz_binary_descriptor: int | None = None
    try:
        with os.fdopen(descriptor, "wb") as log:
            log.write(target_marker_line(target_marker))
            log.flush()
            build_exit_status, build_timed_out = evidence_runtime.run_logged(
                execution_build_command,
                cwd=execution_root,
                environment=environment,
                log=log,
                timeout_seconds=build_timeout_seconds,
                pass_fds=pass_fds,
                write_boundary_paths=write_boundary_paths,
            )
            build_duration_ms = evidence_runtime.elapsed_milliseconds(build_started)
            if build_exit_status != 0 or build_timed_out:
                raise RuntimeError(f"fuzz target build failed: {target}")
            details = os.lstat(fuzz_binary_path)
            if (
                stat.S_ISLNK(details.st_mode)
                or not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_size <= 0
                or details.st_mode & 0o111 == 0
            ):
                raise RuntimeError(f"built fuzz executable is unsafe: {target}")
            fuzz_binary_sha256 = hashlib.sha256(fuzz_binary_path.read_bytes()).hexdigest()
            fuzz_binary_identity = {
                "path": fuzz_binary_command_path,
                "bytes": details.st_size,
                "sha256": fuzz_binary_sha256,
                "descriptor_execution": execution_cargo_fuzz is not None,
            }
            run_pass_fds = pass_fds
            if execution_cargo_fuzz is not None:
                fuzz_binary_descriptor, execution_fuzz_binary = (
                    evidence_runtime.open_executable_descriptor(
                        fuzz_binary_path, expected_sha256=fuzz_binary_sha256
                    )
                )
                execution_command[0] = execution_fuzz_binary
                run_pass_fds = (*pass_fds, fuzz_binary_descriptor)
            scoped_boundary = (
                (*run_write_boundary_paths, execution_dir, artifact_dir)
                if run_write_boundary_paths is not None
                else None
            )
            run_environment = dict(environment)
            run_environment["ASAN_OPTIONS"] = FUZZ_ASAN_OPTIONS
            run_started = time.monotonic()
            exit_status, timed_out = evidence_runtime.run_logged(
                execution_command,
                cwd=execution_root,
                environment=run_environment,
                log=log,
                timeout_seconds=timeout_seconds,
                pass_fds=run_pass_fds,
                write_boundary_paths=scoped_boundary,
            )
            duration_ms = evidence_runtime.elapsed_milliseconds(run_started)
            if (
                fuzz_binary_descriptor is not None
                and evidence_runtime._digest_descriptor(fuzz_binary_descriptor)
                != fuzz_binary_sha256
            ):
                raise RuntimeError("fuzz executable changed during evidence generation")
            log.flush()
            os.fsync(log.fileno())
            log_identity = evidence_runtime.private_file_identity(log.fileno())
    finally:
        if fuzz_binary_descriptor is not None:
            os.close(fuzz_binary_descriptor)
        harden_tree(execution_dir)
        shutil.rmtree(execution_dir, ignore_errors=False)
        harden_tree(artifact_dir)
    payload = evidence_runtime.read_private_output(ROOT, log_path, log_identity)
    verify_prepared_corpus(corpus_dir, corpus_descriptor)
    summary = parse_libfuzzer_summary(payload)
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
        "build_command": build_command,
        "build_exit_status": build_exit_status,
        "build_timed_out": build_timed_out,
        "build_timeout_seconds": build_timeout_seconds,
        "build_duration_ms": build_duration_ms,
        "run_command": run_command,
        "fuzz_binary": fuzz_binary_identity,
        "exit_status": exit_status,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "duration_ms": duration_ms,
        "log_file": log_path.name,
        "log_bytes": len(payload),
        "log_sha256": hashlib.sha256(payload).hexdigest(),
        "smoke_seed_count": corpus_descriptor["seed_count"],
        "smoke_corpus_sha256": corpus_descriptor["corpus_sha256"],
        "smoke_corpus": corpus_descriptor,
        "target_marker": target_marker,
        "artifacts": artifacts,
        "libfuzzer_done": summary.get("libfuzzer_done") if summary else False,
        "done_executed_units": summary.get("done_executed_units") if summary else None,
        "libfuzzer_elapsed_seconds": (
            summary.get("libfuzzer_elapsed_seconds") if summary else None
        ),
        "executed_units": summary.get("executed_units") if summary else None,
        "peak_rss_mb": summary.get("peak_rss_mb") if summary else None,
    }


def tool_version(command: list[str], environment: dict[str, str] | None = None) -> str:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
        text=True,
        timeout=60,
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
    parser.add_argument(
        "--partial",
        action="store_true",
        help="permit an explicitly non-release run shorter than the release minimum",
    )
    parser.add_argument("--startup-timeout-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    if (
        args.seconds <= 0
        or args.rss_limit_mb <= 0
        or not 0 < args.startup_timeout_seconds <= MAX_STARTUP_TIMEOUT_SECONDS
    ):
        parser.error(
            "seconds and RSS limit must be positive, and startup timeout must be "
            f"between 1 and {MAX_STARTUP_TIMEOUT_SECONDS} seconds"
        )
    if not args.partial and args.seconds < RELEASE_MIN_SECONDS_PER_TARGET:
        parser.error(
            f"release evidence requires at least {RELEASE_MIN_SECONDS_PER_TARGET} "
            "seconds per target; use --partial for a shorter diagnostic run"
        )
    if not args.partial and args.rss_limit_mb != 2048:
        parser.error("release evidence requires the frozen 2048 MiB fuzz RSS limit")

    output = evidence_runtime.assert_no_symlink_ancestry(ROOT, args.output)
    log_dir = evidence_runtime.assert_no_symlink_ancestry(ROOT, args.log_dir)
    evidence_root = output.parent
    if not log_dir.is_relative_to(evidence_root):
        parser.error("log directory must be contained by the output evidence directory")
    source_identity = evidence_runtime.release_source_identity(
        ROOT,
        os.environ.get("HC_RELEASE_SHA"),
        evidence_root=evidence_root,
        require_explicit_sha=not args.partial,
    )
    evidence_runtime.owner_ga_tool_policy(
        ROOT, str(source_identity["release_sha"])
    )
    fuzz_dependency_lock_sha256 = evidence_runtime.commit_file_sha256(
        ROOT, str(source_identity["release_sha"]), "fuzz/Cargo.lock"
    )
    if hashlib.sha256((ROOT / "fuzz" / "Cargo.lock").read_bytes()).hexdigest() != (
        fuzz_dependency_lock_sha256
    ):
        raise RuntimeError("working fuzz/Cargo.lock differs from the source commit")
    environment = fuzz_environment(os.environ)
    cargo_path = evidence_runtime.rustup_tool_path(
        FUZZ_TOOLCHAIN, "cargo", environment=environment, root=ROOT
    )
    rustc_path = evidence_runtime.rustup_tool_path(
        FUZZ_TOOLCHAIN, "rustc", environment=environment, root=ROOT
    )
    cargo_identity = evidence_runtime.executable_identity(
        str(cargo_path), ["-Vv"], environment=environment, root=ROOT
    )
    rustc_identity = evidence_runtime.executable_identity(
        str(rustc_path), ["-Vv"], environment=environment, root=ROOT
    )
    cargo_fuzz_identity = evidence_runtime.executable_identity(
        "cargo-fuzz", ["--version"], environment=environment, root=ROOT
    )
    cargo_fuzz_version = str(cargo_fuzz_identity["version"])
    if cargo_fuzz_version != CARGO_FUZZ_VERSION:
        raise RuntimeError(
            f"cargo-fuzz version mismatch: expected {CARGO_FUZZ_VERSION}, "
            f"found {cargo_fuzz_version}"
        )
    cargo_host = next(
        (
            line.removeprefix("host: ")
            for line in str(cargo_identity["version"]).splitlines()
            if line.startswith("host: ")
        ),
        None,
    )
    if not isinstance(cargo_host, str) or not re.fullmatch(
        r"[A-Za-z0-9_.-]+", cargo_host
    ):
        raise RuntimeError("pinned Cargo host triple is missing or unsafe")
    tool_identity_path = log_dir / TOOL_IDENTITY_FILE
    tool_identity_record = evidence_runtime.tool_identity_record(
        source_identity,
        cargo_identity,
        rustc_identity,
        execution_profile="fuzz",
        toolchain=FUZZ_TOOLCHAIN,
        cargo_version_command=[
            str(cargo_identity["path"]),
            "-Vv",
        ],
        rustc_version_command=[
            str(rustc_identity["path"]),
            "-Vv",
        ],
    )
    tool_identity_payload = evidence_runtime.pretty_json_bytes(tool_identity_record)
    evidence_runtime.write_json_atomic(
        ROOT, tool_identity_path, tool_identity_record
    )
    target_dir = evidence_runtime.reset_private_directory(
        ROOT, evidence_root, evidence_root / "cargo-target"
    )
    temp_dir = evidence_runtime.reset_private_directory(
        ROOT, evidence_root, evidence_root / "tmp"
    )
    environment.update(
        CARGO_TARGET_DIR=str(target_dir),
        TMPDIR=str(temp_dir),
        TMP=str(temp_dir),
        TEMP=str(temp_dir),
    )
    immutable: Path | None = None
    inventory: list[dict[str, object]] = []
    opened_tools: list[int] = []
    execution_root = ROOT
    execution_cargo_fuzz: str | None = None
    pass_fds: tuple[int, ...] = ()
    write_boundary_paths: tuple[Path, ...] | None = None
    boundary: dict[str, object] | None = None
    if not args.partial:
        abi = evidence_runtime.landlock_abi_version()
        immutable, inventory = evidence_runtime.materialize_read_only_source(
            ROOT,
            str(source_identity["release_sha"]),
            evidence_root=evidence_root,
        )
        execution_root = immutable
        write_boundary_paths = (target_dir, temp_dir)
        cargo_fd, cargo_executable = evidence_runtime.open_executable_descriptor(
            str(cargo_identity["path"]),
            expected_sha256=str(cargo_identity["sha256"]),
        )
        rustc_fd, rustc_executable = evidence_runtime.open_executable_descriptor(
            str(rustc_identity["path"]),
            expected_sha256=str(rustc_identity["sha256"]),
        )
        fuzz_fd, execution_cargo_fuzz = evidence_runtime.open_executable_descriptor(
            str(cargo_fuzz_identity["path"]),
            expected_sha256=str(cargo_fuzz_identity["sha256"]),
        )
        opened_tools = [cargo_fd, rustc_fd, fuzz_fd]
        pass_fds = tuple(opened_tools)
        environment.update(
            CARGO=cargo_executable,
            RUSTC=rustc_executable,
            RUSTUP_TOOLCHAIN=FUZZ_TOOLCHAIN,
        )
        boundary = {
            "kind": "landlock-write-deny-v1",
            "abi_version": abi,
            "source_write_allowed": False,
            "descriptor_execution": True,
            "build_writable_roots": [path.name for path in write_boundary_paths],
            "run_writable_roots": [temp_dir.name],
            "target_scoped_writes": ["execution-corpus", "artifacts"],
        }
    try:
        results = [
            run_target(
                target,
                seconds=args.seconds,
                rss_limit_mb=args.rss_limit_mb,
                log_dir=args.log_dir,
                target_dir=target_dir,
                target_triple=str(cargo_host),
                cargo_fuzz_executable=str(cargo_fuzz_identity["path"]),
                execution_cargo_fuzz=execution_cargo_fuzz,
                execution_root=execution_root,
                pass_fds=pass_fds,
                write_boundary_paths=write_boundary_paths,
                run_write_boundary_paths=(temp_dir,)
                if write_boundary_paths is not None
                else None,
                environment=environment,
                build_timeout_seconds=args.startup_timeout_seconds,
                timeout_seconds=args.seconds + args.startup_timeout_seconds,
            )
            for target in TARGETS
        ]
        if immutable is not None:
            evidence_runtime.verify_read_only_source(immutable, inventory)
        verify_opened_tool_descriptors(
            opened_tools,
            (
                str(cargo_identity["sha256"]),
                str(rustc_identity["sha256"]),
                str(cargo_fuzz_identity["sha256"]),
            ),
        )
    finally:
        for descriptor_value in opened_tools:
            os.close(descriptor_value)
        if immutable is not None:
            evidence_runtime.remove_read_only_source(ROOT, evidence_root, immutable)
    evidence_runtime.assert_release_source_unchanged(
        ROOT, source_identity, evidence_root=evidence_root
    )
    if hashlib.sha256((ROOT / "fuzz" / "Cargo.lock").read_bytes()).hexdigest() != (
        fuzz_dependency_lock_sha256
    ):
        raise RuntimeError("fuzz/Cargo.lock changed during evidence generation")
    release_eligible = (
        not args.partial
        and args.seconds >= RELEASE_MIN_SECONDS_PER_TARGET
        and args.rss_limit_mb == 2048
    )
    report = {
        "schema_version": 2,
        **source_identity,
        "profile": PROFILE,
        "toolchain": FUZZ_TOOLCHAIN,
        "partial": args.partial,
        "environment_policy": evidence_runtime.environment_policy(),
        "environment_policy_sha256": evidence_runtime.canonical_json_sha256(
            evidence_runtime.environment_policy()
        ),
        "cargo_identity": cargo_identity,
        "rustc_identity": rustc_identity,
        "rustc_version": rustc_identity["version"],
        "tool_identity_file": tool_identity_path.name,
        "tool_identity_bytes": len(tool_identity_payload),
        "tool_identity_sha256": hashlib.sha256(tool_identity_payload).hexdigest(),
        "cargo_fuzz_version": cargo_fuzz_version,
        "cargo_fuzz_identity": cargo_fuzz_identity,
        "sanitizer": FUZZ_SANITIZER,
        "sanitizer_runtime_environment": {"ASAN_OPTIONS": FUZZ_ASAN_OPTIONS},
        "execution_boundary": boundary,
        "fuzz_dependency_lock_sha256": fuzz_dependency_lock_sha256,
        "seconds_per_target": args.seconds,
        "startup_timeout_seconds": args.startup_timeout_seconds,
        "release_eligible": release_eligible,
        "all_targets_passed": all(
            result["exit_status"] == 0
            and result["build_exit_status"] == 0
            and result["build_timed_out"] is False
            and result["timed_out"] is False
            and result["artifacts"] == []
            and result["libfuzzer_done"] is True
            and isinstance(result["libfuzzer_elapsed_seconds"], int)
            and result["libfuzzer_elapsed_seconds"] >= args.seconds
            and result["duration_ms"] + 2000
            >= result["libfuzzer_elapsed_seconds"] * 1000
            and isinstance(result["executed_units"], int)
            and result["executed_units"] > 0
            and result["done_executed_units"] == result["executed_units"]
            and result["smoke_corpus"]
            == expected_corpus_descriptor(str(result["target"]))
            and isinstance(result["peak_rss_mb"], int)
            and 0 < result["peak_rss_mb"] <= args.rss_limit_mb
            for result in results
        ),
        "targets": results,
    }
    evidence_runtime.write_json_atomic(ROOT, output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return (
        0 if report["all_targets_passed"] and (release_eligible or args.partial) else 1
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
