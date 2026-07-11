#!/usr/bin/env python3
"""Run checkpoint/crash integrity cases and emit hashed release evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import time

import evidence_runtime


ROOT = Path(__file__).resolve().parents[2]
PROFILE = "tinyzkp-p3-goldilocks-v1"
RELEASE_TOOLCHAIN = "1.95.0"
TOOL_IDENTITY_FILE = "crash-tool-identity.json"
DISK_FULL_SENTINEL = ".tinyzkp-disk-full-volume-v1.json"
DISK_FULL_MIN_BYTES = 64 * 1024 * 1024
DISK_FULL_MAX_BYTES = 512 * 1024 * 1024
DISK_FULL_REQUIRED_MOUNT_OPTIONS = {"rw", "nodev", "nosuid", "noexec"}
MAX_CASE_TIMEOUT_SECONDS = 3600
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
        "sigterm_checkpoint_resume",
        "hc-cli",
        "sigterm_retains_resumable_checkpoint_and_resume_is_byte_identical",
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
PROOF_MARKER = re.compile(
    rb"tinyzkp-crash-proof phase=([a-z0-9_]+) "
    rb"resumed=([0-9a-f]{64}) reference=([0-9a-f]{64})"
)
DISK_FULL_MARKER = re.compile(
    rb"tinyzkp-disk-full-resume enospc=true "
    rb"resumed=([0-9a-f]{64}) reference=([0-9a-f]{64})"
)
TEST_RESULT = re.compile(
    rb"(?m)^test result: (ok|FAILED)\. (\d+) passed; (\d+) failed; "
    rb"(\d+) ignored; (\d+) measured; (\d+) filtered out; finished in [^\r\n]+$"
)
FAULT_ENVIRONMENT_KEYS = (
    "TINYZKP_SINGLE_CRASH_PHASE",
    "TINYZKP_DISK_FULL_SCRATCH",
    "TINYZKP_FAIL_AFTER",
    "TINYZKP_TEST_SCRATCH",
    "TINYZKP_RESUME_CHECKPOINT",
)


def parse_test_execution(payload: bytes, test_name: str) -> dict[str, object]:
    exact_test = re.compile(
        rb"(?m)^test " + re.escape(test_name.encode("utf-8")) + rb" \.\.\. ok$"
    )
    results = list(TEST_RESULT.finditer(payload))
    final = results[-1].groups() if results else None
    return {
        "test_name": test_name,
        "exact_test_occurrences": len(exact_test.findall(payload)),
        "result_summary_count": len(results),
        "result_status": final[0].decode("ascii") if final else None,
        "passed_tests": int(final[1]) if final else None,
        "failed_tests": int(final[2]) if final else None,
        "ignored_tests": int(final[3]) if final else None,
        "measured_tests": int(final[4]) if final else None,
        "filtered_tests": int(final[5]) if final else None,
    }


def test_execution_passed(value: object) -> bool:
    return (
        isinstance(value, dict)
        and type(value.get("exact_test_occurrences")) is int
        and value.get("exact_test_occurrences") == 1
        and type(value.get("result_summary_count")) is int
        and value.get("result_summary_count") == 1
        and value.get("result_status") == "ok"
        and type(value.get("passed_tests")) is int
        and value.get("passed_tests") == 1
        and type(value.get("failed_tests")) is int
        and value.get("failed_tests") == 0
    )


def parse_disk_full_marker(payload: bytes) -> dict[str, object]:
    markers = list(DISK_FULL_MARKER.finditer(payload))
    marker = markers[0] if len(markers) == 1 else None
    proof_digest = marker.group(1).decode("ascii") if marker is not None else None
    reference_digest = marker.group(2).decode("ascii") if marker is not None else None
    return {
        "disk_full_enospc_observed": marker is not None,
        "proof_blake3_hex": proof_digest,
        "reference_proof_blake3_hex": reference_digest,
        "proof_bytes_equal": marker is not None and proof_digest == reference_digest,
    }


def parse_checkpoint_marker(payload: bytes) -> dict[str, object]:
    markers = list(PROOF_MARKER.finditer(payload))
    marker = markers[0] if len(markers) == 1 else None
    if marker is None:
        return {
            "observed_phase": None,
            "proof_blake3_hex": None,
            "reference_proof_blake3_hex": None,
            "proof_bytes_equal": False,
        }
    marker_phase, resumed_digest, reference_digest = (
        value.decode("ascii") for value in marker.groups()
    )
    return {
        "observed_phase": marker_phase,
        "proof_blake3_hex": resumed_digest,
        "reference_proof_blake3_hex": reference_digest,
        "proof_bytes_equal": resumed_digest == reference_digest,
    }


def _mountinfo(path: Path) -> dict[str, str]:
    expected = path.as_posix().replace(" ", "\\040")
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) < 10 or "-" not in fields or fields[4] != expected:
            continue
        separator = fields.index("-")
        return {
            "device": fields[2],
            "mount_options": fields[5],
            "filesystem": fields[separator + 1],
            "source": fields[separator + 2],
        }
    raise ValueError("disk-full scratch is not an exact mounted filesystem")


def required_mount_options_present(options: object) -> bool:
    return (
        isinstance(options, (list, set, tuple))
        and all(isinstance(value, str) for value in options)
        and DISK_FULL_REQUIRED_MOUNT_OPTIONS.issubset(set(options))
    )


def create_disk_full_contract(
    path: Path, source_identity: dict[str, object]
) -> tuple[Path, dict[str, object]]:
    if sys.platform != "linux":
        raise ValueError("the disk-full release case is supported only on Linux")
    if not path.is_absolute():
        raise ValueError("disk-full scratch must be an absolute dedicated mount path")
    absolute = path.absolute()
    resolved = path.resolve(strict=True)
    if absolute != resolved:
        raise ValueError("disk-full scratch path contains a symlink")
    details = os.lstat(resolved)
    parent_details = os.stat(resolved.parent)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
        or details.st_dev == parent_details.st_dev
        or not resolved.is_mount()
    ):
        raise ValueError(
            "disk-full scratch must be an owner-only mount on a dedicated device"
        )
    filesystem = os.statvfs(resolved)
    total_bytes = filesystem.f_frsize * filesystem.f_blocks
    available_bytes = filesystem.f_frsize * filesystem.f_bavail
    if not DISK_FULL_MIN_BYTES <= total_bytes <= DISK_FULL_MAX_BYTES:
        raise ValueError(
            "disk-full scratch capacity must be between 64 MiB and 512 MiB"
        )
    if available_bytes < 16 * 1024 * 1024:
        raise ValueError("disk-full scratch lacks the minimum free capacity")
    entries = {entry.name for entry in resolved.iterdir()}
    if entries - {"lost+found"}:
        raise ValueError("disk-full scratch contains unexpected pre-existing files")
    mount = _mountinfo(resolved)
    mount_options = set(mount["mount_options"].split(","))
    if not required_mount_options_present(mount_options) or mount["filesystem"] not in {
        "ext4",
        "tmpfs",
    }:
        raise ValueError("disk-full scratch uses an unsupported mount contract")
    contract: dict[str, object] = {
        "schema_version": 1,
        "created_by": "tinyzkp-run-crash-matrix",
        "mount_path": str(resolved),
        "mount_device": mount["device"],
        "parent_device": f"{os.major(parent_details.st_dev)}:{os.minor(parent_details.st_dev)}",
        "filesystem": mount["filesystem"],
        "mount_options": sorted(mount_options),
        "total_bytes": total_bytes,
        "available_bytes_before": available_bytes,
        "max_total_bytes": DISK_FULL_MAX_BYTES,
        "owner_uid": details.st_uid,
        "directory_mode": stat.S_IMODE(details.st_mode),
        "release_sha": source_identity["release_sha"],
        "source_tree_sha256": source_identity["source_tree_sha256"],
    }
    sentinel = resolved / DISK_FULL_SENTINEL
    descriptor = os.open(
        sentinel,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(contract, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    payload = sentinel.read_bytes()
    contract["sentinel_file"] = sentinel.name
    contract["sentinel_sha256"] = hashlib.sha256(payload).hexdigest()
    return resolved, contract


def verify_disk_full_contract(path: Path, contract: dict[str, object]) -> bool:
    try:
        details = os.lstat(path)
        parent_details = os.stat(path.parent)
        filesystem = os.statvfs(path)
        mount = _mountinfo(path)
        sentinel = path / str(contract["sentinel_file"])
        sentinel_details = os.lstat(sentinel)
        sentinel_payload = sentinel.read_bytes()
        sentinel_value = json.loads(sentinel_payload)
    except (KeyError, OSError, ValueError, json.JSONDecodeError):
        return False
    expected_sentinel = {
        key: value
        for key, value in contract.items()
        if key not in {"sentinel_file", "sentinel_sha256"}
    }
    allowed_entries = {"lost+found", str(contract["sentinel_file"])}
    return (
        path.is_mount()
        and stat.S_ISDIR(details.st_mode)
        and details.st_uid == os.geteuid()
        and stat.S_IMODE(details.st_mode) == 0o700
        and details.st_dev != parent_details.st_dev
        and mount["device"] == contract.get("mount_device")
        and mount["filesystem"] == contract.get("filesystem")
        and set(mount["mount_options"].split(","))
        == set(contract.get("mount_options", []))
        and required_mount_options_present(contract.get("mount_options"))
        and filesystem.f_frsize * filesystem.f_blocks == contract.get("total_bytes")
        and stat.S_ISREG(sentinel_details.st_mode)
        and sentinel_details.st_uid == os.geteuid()
        and sentinel_details.st_nlink == 1
        and stat.S_IMODE(sentinel_details.st_mode) == 0o600
        and hashlib.sha256(sentinel_payload).hexdigest()
        == contract.get("sentinel_sha256")
        and sentinel_value == expected_sentinel
        and {entry.name for entry in path.iterdir()}.issubset(allowed_entries)
    )


def run_case(
    name: str,
    package: str,
    test_name: str,
    *,
    log_dir: Path,
    release: bool,
    phase: str | None = None,
    disk_full_scratch: Path | None = None,
    disk_full_contract: dict[str, object] | None = None,
    cargo_executable: str = "cargo",
    execution_cargo: str | None = None,
    execution_root: Path = ROOT,
    pass_fds: tuple[int, ...] = (),
    write_boundary_paths: tuple[Path, ...] | None = None,
    environment: dict[str, str] | None = None,
    timeout_seconds: int = 900,
) -> dict[str, object]:
    command = [cargo_executable, "test", "-p", package]
    if package == "hc-cli":
        command.extend(["--test", "cli_roundtrip"])
    else:
        command.append("--lib")
    if release:
        command.append("--release")
    command.extend(["--locked"])
    if package == "hc-plonky3":
        command.extend(["--features", "fault-injection"])
    command.extend([test_name, "--", "--exact", "--nocapture"])
    execution_command = list(command)
    if execution_cargo is not None:
        execution_command[0] = execution_cargo
    environment = dict(
        evidence_runtime.sanitized_environment(os.environ)
        if environment is None
        else environment
    )
    for key in FAULT_ENVIRONMENT_KEYS:
        environment.pop(key, None)
    if phase is not None:
        environment["TINYZKP_SINGLE_CRASH_PHASE"] = phase
    if disk_full_scratch is not None:
        environment["TINYZKP_DISK_FULL_SCRATCH"] = str(disk_full_scratch)

    evidence_runtime.ensure_private_directory(ROOT, log_dir)
    log_path = log_dir / f"{name}.log"
    descriptor = evidence_runtime.open_private_output(ROOT, log_path)
    started = time.monotonic()
    with os.fdopen(descriptor, "wb") as log:
        exit_status, timed_out = evidence_runtime.run_logged(
            execution_command,
            cwd=execution_root,
            environment=environment,
            log=log,
            timeout_seconds=timeout_seconds,
            pass_fds=pass_fds,
            write_boundary_paths=write_boundary_paths,
        )
        log.flush()
        os.fsync(log.fileno())
        log_identity = evidence_runtime.private_file_identity(log.fileno())
    payload = evidence_runtime.read_private_output(ROOT, log_path, log_identity)
    test_execution = parse_test_execution(payload, test_name)
    result: dict[str, object] = {
        "case": name,
        "command": command,
        "exit_status": exit_status,
        "timed_out": timed_out,
        "timeout_seconds": timeout_seconds,
        "duration_ms": evidence_runtime.elapsed_milliseconds(started),
        "log_file": log_path.name,
        "log_bytes": len(payload),
        "log_sha256": hashlib.sha256(payload).hexdigest(),
        "test_execution": test_execution,
    }
    if phase is not None:
        result["phase"] = phase
        result["selected_environment"] = {"TINYZKP_SINGLE_CRASH_PHASE": phase}
        result.update(parse_checkpoint_marker(payload))
    elif disk_full_scratch is not None:
        result["selected_environment"] = {
            "TINYZKP_DISK_FULL_SCRATCH": "<runner-owned-disk-full-scratch>"
        }
        result["disk_full_contract"] = disk_full_contract
        result["disk_full_contract_verified"] = isinstance(
            disk_full_contract, dict
        ) and verify_disk_full_contract(disk_full_scratch, disk_full_contract)
        result.update(parse_disk_full_marker(payload))
    return result


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--log-dir", type=Path, required=True)
    parser.add_argument("--debug", action="store_true")
    parser.add_argument(
        "--partial",
        action="store_true",
        help="permit an explicitly non-release run without the disk-full case",
    )
    parser.add_argument("--disk-full-scratch", type=Path)
    parser.add_argument("--case-timeout-seconds", type=int, default=900)
    args = parser.parse_args(argv)
    if not 0 < args.case_timeout_seconds <= MAX_CASE_TIMEOUT_SECONDS:
        parser.error(
            f"case timeout must be between 1 and {MAX_CASE_TIMEOUT_SECONDS} seconds"
        )
    if args.debug and not args.partial:
        parser.error("--debug is permitted only with explicit --partial")
    if not args.partial and args.disk_full_scratch is None:
        parser.error("release evidence requires a dedicated disk-full scratch mount")

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
    environment = evidence_runtime.sanitized_environment(os.environ)
    cargo_path = evidence_runtime.rustup_tool_path(
        RELEASE_TOOLCHAIN, "cargo", environment=environment, root=ROOT
    )
    rustc_path = evidence_runtime.rustup_tool_path(
        RELEASE_TOOLCHAIN, "rustc", environment=environment, root=ROOT
    )
    cargo_identity = evidence_runtime.executable_identity(
        str(cargo_path), ["-Vv"], environment=environment, root=ROOT
    )
    rustc_identity = evidence_runtime.executable_identity(
        str(rustc_path), ["-Vv"], environment=environment, root=ROOT
    )
    cargo_host = next(
        line.removeprefix("host: ")
        for line in str(cargo_identity["version"]).splitlines()
        if line.startswith("host: ")
    )
    tool_anchor = evidence_runtime.toolchain_anchor(
        ROOT,
        str(source_identity["release_sha"]),
        execution_profile="release",
        host=cargo_host,
    )
    if (
        cargo_identity["sha256"] != tool_anchor["cargo_sha256"]
        or rustc_identity["sha256"] != tool_anchor["rustc_sha256"]
    ):
        parser.error("release Cargo/rustc executables do not match committed anchors")
    tool_identity_path = log_dir / TOOL_IDENTITY_FILE
    tool_identity_record = evidence_runtime.tool_identity_record(
        source_identity,
        cargo_identity,
        rustc_identity,
        execution_profile="release",
        toolchain=RELEASE_TOOLCHAIN,
        cargo_version_command=[str(cargo_identity["path"]), "-Vv"],
        rustc_version_command=[str(rustc_identity["path"]), "-Vv"],
    )
    tool_identity_payload = evidence_runtime.pretty_json_bytes(tool_identity_record)
    evidence_runtime.write_json_atomic(
        ROOT, tool_identity_path, tool_identity_record
    )
    disk_full_scratch: Path | None = None
    disk_full_contract: dict[str, object] | None = None
    if args.disk_full_scratch is not None:
        try:
            disk_full_scratch, disk_full_contract = create_disk_full_contract(
                args.disk_full_scratch, source_identity
            )
        except (OSError, ValueError) as error:
            parser.error(str(error))

    immutable: Path | None = None
    inventory: list[dict[str, object]] = []
    opened_tools: list[int] = []
    execution_root = ROOT
    execution_cargo: str | None = None
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
        target_dir = evidence_runtime.reset_private_directory(
            ROOT, evidence_root, evidence_root / "cargo-target"
        )
        temp_dir = evidence_runtime.reset_private_directory(
            ROOT, evidence_root, evidence_root / "tmp"
        )
        allowed = [target_dir, temp_dir]
        if disk_full_scratch is not None:
            allowed.append(disk_full_scratch)
        write_boundary_paths = tuple(allowed)
        environment.update(
            CARGO_TARGET_DIR=str(target_dir),
            TMPDIR=str(temp_dir),
            TMP=str(temp_dir),
            TEMP=str(temp_dir),
        )
        cargo_fd, execution_cargo = evidence_runtime.open_executable_descriptor(
            str(cargo_identity["path"]),
            expected_sha256=str(cargo_identity["sha256"]),
        )
        rustc_fd, rustc_executable = evidence_runtime.open_executable_descriptor(
            str(rustc_identity["path"]),
            expected_sha256=str(rustc_identity["sha256"]),
        )
        opened_tools = [cargo_fd, rustc_fd]
        pass_fds = tuple(opened_tools)
        environment["RUSTC"] = rustc_executable
        boundary = {
            "kind": "landlock-write-deny-v1",
            "abi_version": abi,
            "source_write_allowed": False,
            "descriptor_execution": True,
            "writable_paths": [path.name for path in write_boundary_paths],
        }

    common = {
        "log_dir": args.log_dir,
        "release": not args.debug,
        "cargo_executable": str(cargo_identity["path"]),
        "execution_cargo": execution_cargo,
        "execution_root": execution_root,
        "pass_fds": pass_fds,
        "write_boundary_paths": write_boundary_paths,
        "environment": environment,
        "timeout_seconds": args.case_timeout_seconds,
    }
    try:
        cases = [
            run_case(
                f"checkpoint_{phase}",
                *PHASE_TEST,
                phase=phase,
                **common,
            )
            for phase in PHASES
        ]
        cases.extend(
            run_case(name, package, test_name, **common)
            for name, package, test_name in INTEGRITY_CASES
        )
        if disk_full_scratch is not None:
            cases.append(
                run_case(
                    *DISK_FULL_CASE,
                    disk_full_scratch=disk_full_scratch,
                    disk_full_contract=disk_full_contract,
                    **common,
                )
            )
        if immutable is not None:
            evidence_runtime.verify_read_only_source(immutable, inventory)
        for descriptor_value, expected in zip(
            opened_tools,
            (cargo_identity["sha256"], rustc_identity["sha256"]),
            strict=True,
        ):
            if evidence_runtime._digest_descriptor(descriptor_value) != expected:
                raise ValueError("release tool executable changed during crash evidence")
    finally:
        for descriptor_value in opened_tools:
            os.close(descriptor_value)
        if immutable is not None:
            evidence_runtime.remove_read_only_source(ROOT, evidence_root, immutable)

    all_executed_cases_passed = all(
        case["exit_status"] == 0
        and case.get("timed_out") is False
        and test_execution_passed(case.get("test_execution"))
        and (
            case.get("case") != "disk_full_resume"
            or (
                case.get("disk_full_contract_verified") is True
                and case.get("disk_full_enospc_observed") is True
                and case.get("proof_bytes_equal") is True
            )
        )
        and (
            not str(case["case"]).startswith("checkpoint_")
            or case.get("proof_bytes_equal") is True
        )
        for case in cases
    )
    evidence_runtime.assert_release_source_unchanged(
        ROOT, source_identity, evidence_root=evidence_root
    )
    complete_for_release = (
        not args.partial
        and not args.debug
        and disk_full_contract is not None
        and all_executed_cases_passed
    )
    report = {
        "schema_version": 1,
        **source_identity,
        "profile": PROFILE,
        "build_profile": "debug" if args.debug else "release",
        "partial": args.partial,
        "environment_policy": evidence_runtime.environment_policy(),
        "environment_policy_sha256": evidence_runtime.canonical_json_sha256(
            evidence_runtime.environment_policy()
        ),
        "cargo_identity": cargo_identity,
        "rustc_identity": rustc_identity,
        "tool_identity_file": tool_identity_path.name,
        "tool_identity_bytes": len(tool_identity_payload),
        "tool_identity_sha256": hashlib.sha256(tool_identity_payload).hexdigest(),
        "execution_boundary": boundary,
        "case_timeout_seconds": args.case_timeout_seconds,
        "all_executed_cases_passed": all_executed_cases_passed,
        "complete_for_release": complete_for_release,
        "cases": cases,
    }
    evidence_runtime.write_json_atomic(ROOT, output, report)
    print(json.dumps(report, indent=2, sort_keys=True))
    return (
        0 if complete_for_release or (args.partial and all_executed_cases_passed) else 1
    )


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
