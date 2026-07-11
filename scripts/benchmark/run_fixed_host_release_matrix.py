#!/usr/bin/env python3
"""Run the complete local TinyZKP backend-v1 fixed-host resource matrix.

This controller is intentionally local-only. It does not provision a host,
upload evidence, satisfy independent reproduction, or approve a release. A
successful run means only that all four *local* resource gates passed on one
eligible fixed host for one immutable source/CLI identity.

The matrix is resumable at workload boundaries. Completed entries are skipped
only after every recorded artifact digest and the release-gate semantics have
been revalidated. An interrupted workload is rerun from input generation so
the resulting report continues to measure the complete proving pipeline.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import stat
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK_DIR = ROOT / "scripts" / "benchmark"
CI_DIR = ROOT / "scripts" / "ci"
if str(CI_DIR) not in sys.path:
    sys.path.insert(0, str(CI_DIR))
import source_tree_identity  # noqa: E402

PROFILE = "tinyzkp-p3-goldilocks-v1"
PLONKY3_VERSION = "0.6.1"
BASELINE_MEMORY_CAP = 16 * 1024**3
MAX_JSON_BYTES = 2 * 1024 * 1024
MATRIX_KIND = "tinyzkp_fixed_host_release_matrix_v1"


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - install failure
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


HARNESS = _load_module(
    "tinyzkp_fixed_host_harness", BENCHMARK_DIR / "run_plonky3_cgroup.py"
)
GATE = _load_module(
    "tinyzkp_fixed_host_release_gate", BENCHMARK_DIR / "validate_release_gate.py"
)


@dataclass(frozen=True)
class MatrixEntry:
    entry_id: str
    workload: str
    logical_rows: int
    manifest_relative: str
    mode: str
    gate: str
    report_name: str
    scratch_relative: str

    @property
    def manifest_path(self) -> Path:
        return ROOT / self.manifest_relative


MATRIX: tuple[MatrixEntry, ...] = (
    MatrixEntry(
        "fibonacci_1m",
        "fibonacci",
        1_048_576,
        "examples/plonky3/fibonacci-1m.json",
        "throughput",
        "one-million",
        "fibonacci-1m.json",
        "fibonacci-1m",
    ),
    MatrixEntry(
        "poseidon2_1m",
        "poseidon2_goldilocks",
        1_048_576,
        "examples/plonky3/poseidon2-1m.json",
        "throughput",
        "one-million",
        "poseidon2-1m.json",
        "poseidon2-1m",
    ),
    MatrixEntry(
        "fibonacci_16m",
        "fibonacci",
        16_777_216,
        "examples/plonky3/fibonacci-16m.json",
        "ceiling",
        "ten-million",
        "fibonacci-16m.json",
        "fibonacci-16m",
    ),
    MatrixEntry(
        "poseidon2_16m",
        "poseidon2_goldilocks",
        16_777_216,
        "examples/plonky3/poseidon2-16m.json",
        "ceiling",
        "ten-million",
        "poseidon2-16m.json",
        "poseidon2-16m",
    ),
)


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def canonical_json_bytes(value: object) -> bytes:
    return json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n"


def _path_lstat(path: Path) -> os.stat_result:
    return path.lstat()


def _identity(details: os.stat_result) -> tuple[int, ...]:
    return (
        details.st_dev,
        details.st_ino,
        details.st_size,
        details.st_mtime_ns,
        details.st_ctime_ns,
        details.st_nlink,
        details.st_mode,
        details.st_uid,
        details.st_gid,
    )


def _open_stable_regular(path: Path) -> tuple[int, os.stat_result]:
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot safely open artifact: {path}") from error
    try:
        details = os.fstat(descriptor)
        path_details = _path_lstat(path)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_nlink != 1
            or _identity(details) != _identity(path_details)
        ):
            raise ValueError(f"artifact is not a stable single-link regular file: {path}")
        return descriptor, details
    except Exception:
        os.close(descriptor)
        raise


def _finish_stable_read(
    descriptor: int, path: Path, before: os.stat_result
) -> os.stat_result:
    after = os.fstat(descriptor)
    try:
        path_after = _path_lstat(path)
    except OSError as error:
        raise ValueError(f"artifact path disappeared during read: {path}") from error
    if _identity(before) != _identity(after) or _identity(after) != _identity(path_after):
        raise ValueError(f"artifact changed or was replaced during read: {path}")
    return after


def stable_file_snapshot(
    path: Path,
    *,
    max_bytes: int | None = None,
    include_bytes: bool = False,
) -> tuple[str, os.stat_result, bytes | None]:
    descriptor, before = _open_stable_regular(path)
    try:
        if max_bytes is not None and before.st_size > max_bytes:
            raise ValueError(f"artifact exceeds {max_bytes} bytes: {path}")
        digest = hashlib.sha256()
        payload = bytearray() if include_bytes else None
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
            if payload is not None:
                payload.extend(block)
        after = _finish_stable_read(descriptor, path, before)
        return digest.hexdigest(), after, bytes(payload) if payload is not None else None
    finally:
        os.close(descriptor)


def sha256_file(path: Path) -> str:
    digest, _, _ = stable_file_snapshot(path)
    return digest


def read_json_object(path: Path, *, max_bytes: int = MAX_JSON_BYTES) -> dict[str, object]:
    _, _, payload = stable_file_snapshot(
        path, max_bytes=max_bytes, include_bytes=True
    )
    assert payload is not None
    value = json.loads(payload)
    if not isinstance(value, dict):
        raise ValueError(f"JSON artifact must contain an object: {path}")
    return value


def runner_identity() -> tuple[int, int]:
    if os.geteuid() == 0:
        raw_uid = os.environ.get("SUDO_UID", "")
        raw_gid = os.environ.get("SUDO_GID", "")
        if raw_uid.isascii() and raw_uid.isdecimal() and raw_gid.isascii() and raw_gid.isdecimal():
            return int(raw_uid), int(raw_gid)
    return os.geteuid(), os.getegid()


def _absolute_without_symlinks(path: Path) -> Path:
    absolute = path.expanduser().absolute()
    resolved = absolute.resolve(strict=False)
    if absolute != resolved:
        raise ValueError(f"path contains a symlink component: {absolute}")
    return absolute


def ensure_private_directory(path: Path, uid: int, gid: int) -> Path:
    path = _absolute_without_symlinks(path)
    created = False
    if not path.exists():
        path.mkdir(parents=True, mode=0o700)
        created = True
    details = path.lstat()
    if not stat.S_ISDIR(details.st_mode):
        raise ValueError(f"private path is not a directory: {path}")
    if created:
        os.chmod(path, 0o700)
        if os.geteuid() == 0:
            os.chown(path, uid, gid)
        details = path.lstat()
    if stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError(f"private directory must have mode 0700: {path}")
    if details.st_uid != uid:
        raise ValueError(f"private directory is not owned by the benchmark runner: {path}")
    return path


def secure_artifact(path: Path, uid: int, gid: int) -> None:
    flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot safely open artifact for sealing: {path}") from error
    try:
        before = os.fstat(descriptor)
        path_before = _path_lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or _identity(before) != _identity(path_before)
        ):
            raise ValueError(f"artifact is not a stable single-link regular file: {path}")
        if before.st_uid not in {os.geteuid(), uid}:
            raise ValueError(f"artifact has an unexpected owner: {path}")
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        after = os.fstat(descriptor)
        path_after = _path_lstat(path)
        if (
            not stat.S_ISREG(after.st_mode)
            or after.st_nlink != 1
            or (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino)
            or _identity(after) != _identity(path_after)
            or stat.S_IMODE(after.st_mode) != 0o600
            or after.st_uid != uid
        ):
            raise ValueError(f"artifact could not be made owner-only: {path}")
    finally:
        os.close(descriptor)


def require_owner_artifact(path: Path, uid: int) -> None:
    _, details, _ = stable_file_snapshot(path)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_uid != uid
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise ValueError(f"existing matrix artifact is not owner-only: {path}")


def write_owner_json(path: Path, value: object, uid: int, gid: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(canonical_json_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)
    secure_artifact(path, uid, gid)
    directory_descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory_descriptor)
    finally:
        os.close(directory_descriptor)


class MatrixLock:
    def __init__(self, path: Path, uid: int, gid: int):
        self.path = path
        self.uid = uid
        self.gid = gid
        self.descriptor: int | None = None

    def __enter__(self) -> "MatrixLock":
        flags = os.O_RDWR | os.O_CREAT
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(self.path, flags, 0o600)
        details = os.fstat(descriptor)
        if not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
            os.close(descriptor)
            raise ValueError("matrix lock is not a single-link regular file")
        if details.st_uid not in {os.geteuid(), self.uid}:
            os.close(descriptor)
            raise ValueError("matrix lock has an unexpected owner")
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, self.uid, self.gid)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise RuntimeError("another fixed-host matrix controller is active") from error
        self.descriptor = descriptor
        return self

    def __exit__(self, *_args: object) -> None:
        if self.descriptor is not None:
            fcntl.flock(self.descriptor, fcntl.LOCK_UN)
            os.close(self.descriptor)
            self.descriptor = None


def validate_release_sha(value: str) -> str:
    if len(value) != 40 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("release SHA must be the exact lowercase 40-character Git commit ID")
    return value


def git_output(*arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=ROOT,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"git {' '.join(arguments)} failed: {completed.stderr[-1000:]}")
    return completed.stdout.strip()


def validate_source_identity(release_sha: str) -> str:
    if source_tree_identity.require_canonical_commit(ROOT, release_sha) != release_sha:
        raise ValueError("checked-out source does not match the requested release SHA")
    if git_output("rev-parse", "--verify", "HEAD^{commit}") != release_sha:
        raise ValueError("checked-out source does not match the requested release SHA")
    for arguments in (("diff", "--quiet", "HEAD", "--"), ("diff", "--cached", "--quiet", "--")):
        completed = subprocess.run(
            ["git", *arguments],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if completed.returncode == 1:
            raise ValueError("fixed-host evidence requires a clean tracked source tree")
        if completed.returncode != 0:
            raise RuntimeError(f"git source-integrity check failed: {completed.stderr[-1000:]}")
    return source_tree_identity.source_tree_sha256(ROOT, release_sha)


def validate_cli_identity(cli: Path, release_sha: str) -> dict[str, object]:
    environment = dict(os.environ)
    environment.pop("HC_RELEASE_SHA", None)
    environment.pop("HC_RELEASE_REF", None)
    completed = subprocess.run(
        [str(cli), "release"],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"hc-cli release identity failed: {completed.stderr[-1000:]}")
    value = json.loads(completed.stdout)
    if not isinstance(value, dict):
        raise ValueError("hc-cli release identity is not an object")
    expected = {
        "service": "cli",
        "release_sha": release_sha,
        "backend": "plonky3",
        "plonky3_version": PLONKY3_VERSION,
        "compatibility_profile": PROFILE,
    }
    for field, wanted in expected.items():
        if value.get(field) != wanted:
            raise ValueError(f"hc-cli {field} does not match the fixed release: expected {wanted}")
    lock_digest = value.get("dependency_lock_sha256")
    if not isinstance(lock_digest, str) or len(lock_digest) != 64 or any(
        character not in "0123456789abcdef" for character in lock_digest
    ):
        raise ValueError("hc-cli dependency lock identity is malformed")
    return value


def expected_scratch(entry: MatrixEntry, scratch_root: Path) -> Path:
    return scratch_root / entry.scratch_relative


def validate_matrix_manifest(entry: MatrixEntry, scratch_root: Path) -> dict[str, object]:
    manifest = read_json_object(entry.manifest_path)
    required = {
        "schema_version": 1,
        "profile": PROFILE,
        "workload_id": entry.workload,
        "logical_rows": entry.logical_rows,
    }
    for field, wanted in required.items():
        if manifest.get(field) != wanted:
            raise ValueError(f"{entry.entry_id} manifest {field} must equal {wanted!r}")
    policy = manifest.get("resource_policy")
    if not isinstance(policy, dict):
        raise ValueError(f"{entry.entry_id} manifest resource_policy is missing")
    expected_policy = {
        "mode": "scratch",
        "max_resident_bytes": 2 * 1024**3,
        "max_threads": 8,
        "checkpoint_policy": "retain_on_failure",
    }
    for field, wanted in expected_policy.items():
        if policy.get(field) != wanted:
            raise ValueError(f"{entry.entry_id} policy {field} must equal {wanted!r}")
    configured_scratch = Path(str(policy.get("scratch_dir", ""))).absolute()
    if configured_scratch != expected_scratch(entry, scratch_root):
        raise ValueError(
            f"{entry.entry_id} scratch path must be {expected_scratch(entry, scratch_root)}"
        )
    scratch_cap = policy.get("max_scratch_bytes")
    if not isinstance(scratch_cap, int) or isinstance(scratch_cap, bool) or scratch_cap < 500_000_000_000:
        raise ValueError(f"{entry.entry_id} scratch cap must be at least 500 GB")
    return manifest


def stable_host_identity(host: dict[str, object]) -> dict[str, object]:
    fields = (
        "hardware",
        "logical_cpu_count",
        "total_memory_bytes",
        "operating_system",
        "storage_device",
        "storage_is_rotational",
        "storage_is_nvme",
        "storage_total_bytes",
    )
    return {field: host.get(field) for field in fields}


def validate_preflight_report(
    path: Path,
    release_sha: str,
    scratch: Path,
    cgroup_parent: Path,
) -> dict[str, object]:
    report = read_json_object(path)
    if report.get("schema_version") != 1 or report.get("passed") is not True:
        raise ValueError(f"fixed-host preflight did not pass: {path}")
    if report.get("release_sha") != release_sha:
        raise ValueError("fixed-host preflight release identity mismatch")
    if Path(str(report.get("scratch_dir", ""))).resolve() != scratch.resolve():
        raise ValueError("fixed-host preflight scratch identity mismatch")
    if Path(str(report.get("cgroup_parent", ""))).resolve() != cgroup_parent.resolve():
        raise ValueError("fixed-host preflight cgroup identity mismatch")
    host = report.get("host")
    if not isinstance(host, dict):
        raise ValueError("fixed-host preflight host metadata is missing")
    failures = HARNESS.fixed_host_failures(host)
    if failures:
        raise ValueError("fixed-host preflight metadata is ineligible: " + "; ".join(failures))
    return host


def command_environment(release_sha: str) -> dict[str, str]:
    environment = dict(os.environ)
    environment["HC_RELEASE_SHA"] = release_sha
    return environment


def run_logged_command(
    command: list[str],
    *,
    release_sha: str,
    log_path: Path,
    uid: int,
    gid: int,
) -> None:
    temporary = log_path.with_name(f".{log_path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        with os.fdopen(descriptor, "w", encoding="utf-8", closefd=False) as log:
            log.write("command=" + json.dumps(command, separators=(",", ":")) + "\n")
            log.flush()
            completed = subprocess.run(
                command,
                cwd=ROOT,
                env=command_environment(release_sha),
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                text=True,
                check=False,
            )
            log.write(f"\nexit_status={completed.returncode}\n")
            log.flush()
            os.fsync(log.fileno())
    finally:
        os.close(descriptor)
    os.replace(temporary, log_path)
    secure_artifact(log_path, uid, gid)
    if completed.returncode != 0:
        raise RuntimeError(f"command failed with exit {completed.returncode}; see {log_path}")


def artifact_descriptor(role: str, path: Path, output_dir: Path) -> dict[str, object]:
    digest, details, _ = stable_file_snapshot(path)
    try:
        relative = path.resolve().relative_to(output_dir.resolve())
    except ValueError as error:
        raise ValueError(f"artifact escapes the matrix output directory: {path}") from error
    return {
        "role": role,
        "path": relative.as_posix(),
        "sha256": digest,
        "size_bytes": details.st_size,
        "mode": stat.S_IMODE(details.st_mode),
    }


def verify_artifact_descriptor(
    descriptor: dict[str, object], output_dir: Path, uid: int
) -> Path:
    if set(descriptor) != {"role", "path", "sha256", "size_bytes", "mode"}:
        raise ValueError("matrix artifact descriptor fields are malformed")
    raw_path = descriptor.get("path")
    if not isinstance(raw_path, str) or not raw_path or raw_path.startswith("/"):
        raise ValueError("matrix artifact path must be relative")
    path = (output_dir / raw_path).resolve()
    try:
        path.relative_to(output_dir.resolve())
    except ValueError as error:
        raise ValueError("matrix artifact path escapes the output directory") from error
    digest, details, _ = stable_file_snapshot(path)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_nlink != 1
        or details.st_uid != uid
        or stat.S_IMODE(details.st_mode) != 0o600
    ):
        raise ValueError(f"matrix artifact is not owner-only: {path}")
    if descriptor.get("mode") != 0o600 or descriptor.get("size_bytes") != details.st_size:
        raise ValueError(f"matrix artifact metadata changed: {path}")
    if descriptor.get("sha256") != digest:
        raise ValueError(f"matrix artifact digest changed: {path}")
    return path


def report_paths(entry: MatrixEntry, output_dir: Path) -> dict[str, Path]:
    candidate = output_dir / entry.report_name
    paths = {
        "host_preflight": output_dir / f"{candidate.stem}.host-preflight.json",
        "preflight_log": output_dir / f"{candidate.stem}.host-preflight.log",
        "candidate_report": candidate,
        "candidate_manifest": HARNESS.normalized_manifest_path(candidate, "bounded"),
        "benchmark_log": output_dir / f"{candidate.stem}.benchmark.log",
        "gate_log": output_dir / f"{candidate.stem}.gate.log",
    }
    if entry.mode == "throughput":
        baseline = HARNESS.baseline_report_path(candidate)
        paths["baseline_report"] = baseline
        paths["baseline_manifest"] = HARNESS.normalized_manifest_path(
            baseline, "conventional"
        )
    return paths


def validate_entry_gate(entry: MatrixEntry, output_dir: Path, release_sha: str) -> None:
    paths = report_paths(entry, output_dir)
    manifest = read_json_object(entry.manifest_path)
    candidate = read_json_object(paths["candidate_report"])
    baseline = (
        read_json_object(paths["baseline_report"])
        if "baseline_report" in paths
        else None
    )
    candidate_normalized = read_json_object(paths["candidate_manifest"])
    baseline_normalized = (
        read_json_object(paths["baseline_manifest"])
        if "baseline_manifest" in paths
        else None
    )
    if Path(str(candidate.get("normalized_manifest_path", ""))).resolve() != paths[
        "candidate_manifest"
    ].resolve():
        raise ValueError(f"{entry.entry_id} candidate normalized manifest path mismatch")
    if baseline is not None and Path(
        str(baseline.get("normalized_manifest_path", ""))
    ).resolve() != paths["baseline_manifest"].resolve():
        raise ValueError(f"{entry.entry_id} baseline normalized manifest path mismatch")
    failures = GATE.validate_gate(
        entry.gate,
        manifest,
        baseline,
        candidate,
        expected_release_sha=release_sha,
        baseline_normalized=baseline_normalized,
        candidate_normalized=candidate_normalized,
    )
    if failures:
        raise ValueError(f"{entry.entry_id} resource gate failed: " + "; ".join(failures))


def new_state(
    release_sha: str,
    source_tree_sha256: str,
    cli: Path,
    cli_identity: dict[str, object],
    output_dir: Path,
    scratch_root: Path,
    cgroup_parent: Path,
) -> dict[str, object]:
    now = utc_now()
    entries: list[dict[str, object]] = []
    for item in MATRIX:
        entries.append(
            {
                "entry_id": item.entry_id,
                "workload": item.workload,
                "logical_rows": item.logical_rows,
                "mode": item.mode,
                "gate": item.gate,
                "manifest_path": item.manifest_relative,
                "manifest_sha256": sha256_file(item.manifest_path),
                "status": "pending",
                "attempts": 0,
                "artifacts": [],
                "last_error": None,
                "completed_at": None,
            }
        )
    return {
        "schema_version": 1,
        "kind": MATRIX_KIND,
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_sha256,
        "profile": PROFILE,
        "plonky3_version": PLONKY3_VERSION,
        "source_root": str(ROOT),
        "cli_path": str(cli),
        "cli_sha256": sha256_file(cli),
        "cli_identity": cli_identity,
        "output_dir": str(output_dir),
        "scratch_root": str(scratch_root),
        "cgroup_parent": str(cgroup_parent),
        "created_at": now,
        "updated_at": now,
        "status": "pending",
        "fixed_host_evidence_eligible": False,
        "stable_host_identity": None,
        "local_matrix_gates_passed": False,
        "release_eligible": False,
        "authority": {
            "may_approve_backend_release": False,
            "may_provision_or_mutate_infrastructure": False,
            "may_publish_or_upload_evidence": False,
        },
        "external_gates": {
            "independent_reproduction": "required_external",
            "plonky3_specialist_review": "required_external",
            "implementation_review": "required_external",
            "design_partner_acceptance": "required_external",
            "signed_release_assembly": "required_external",
        },
        "entries": entries,
        "last_error": None,
        "completed_at": None,
    }


def validate_loaded_state(
    state: dict[str, object],
    *,
    release_sha: str,
    source_tree_sha256: str,
    cli: Path,
    output_dir: Path,
    scratch_root: Path,
    cgroup_parent: Path,
) -> None:
    expected = {
        "schema_version": 1,
        "kind": MATRIX_KIND,
        "release_sha": release_sha,
        "source_tree_sha256": source_tree_sha256,
        "profile": PROFILE,
        "plonky3_version": PLONKY3_VERSION,
        "source_root": str(ROOT),
        "cli_path": str(cli),
        "cli_sha256": sha256_file(cli),
        "output_dir": str(output_dir),
        "scratch_root": str(scratch_root),
        "cgroup_parent": str(cgroup_parent),
        "release_eligible": False,
    }
    for field, wanted in expected.items():
        if state.get(field) != wanted:
            raise ValueError(f"matrix state {field} does not match this invocation")
    authority = state.get("authority")
    if not isinstance(authority, dict) or any(value is not False for value in authority.values()):
        raise ValueError("matrix state overstates its release or infrastructure authority")
    external = state.get("external_gates")
    if not isinstance(external, dict) or any(
        value != "required_external" for value in external.values()
    ):
        raise ValueError("matrix state may not satisfy external release gates")
    entries = state.get("entries")
    if not isinstance(entries, list) or len(entries) != len(MATRIX):
        raise ValueError("matrix state entries are malformed")
    for expected_entry, raw in zip(MATRIX, entries, strict=True):
        if not isinstance(raw, dict) or raw.get("entry_id") != expected_entry.entry_id:
            raise ValueError("matrix state entry order or identity changed")
        if raw.get("manifest_sha256") != sha256_file(expected_entry.manifest_path):
            raise ValueError(f"{expected_entry.entry_id} source manifest changed")


def entry_state(state: dict[str, object], entry: MatrixEntry) -> dict[str, object]:
    entries = state["entries"]
    assert isinstance(entries, list)
    for raw in entries:
        if isinstance(raw, dict) and raw.get("entry_id") == entry.entry_id:
            return raw
    raise ValueError(f"matrix state is missing {entry.entry_id}")


def persist_state(path: Path, state: dict[str, object], uid: int, gid: int) -> None:
    state["updated_at"] = utc_now()
    # This controller can never satisfy the independent/external gates.
    state["release_eligible"] = False
    write_owner_json(path, state, uid, gid)


def descriptors_for_entry(
    entry: MatrixEntry, output_dir: Path, uid: int, gid: int
) -> list[dict[str, object]]:
    descriptors: list[dict[str, object]] = []
    for role, path in report_paths(entry, output_dir).items():
        secure_artifact(path, uid, gid)
        descriptors.append(artifact_descriptor(role, path, output_dir))
    return sorted(descriptors, key=lambda item: str(item["role"]))


def revalidate_complete_entry(
    entry: MatrixEntry,
    raw_state: dict[str, object],
    output_dir: Path,
    release_sha: str,
    uid: int,
) -> None:
    artifacts = raw_state.get("artifacts")
    if not isinstance(artifacts, list) or not artifacts:
        raise ValueError(f"{entry.entry_id} completed state has no artifacts")
    roles: set[str] = set()
    for descriptor in artifacts:
        if not isinstance(descriptor, dict):
            raise ValueError(f"{entry.entry_id} artifact descriptor is malformed")
        verify_artifact_descriptor(descriptor, output_dir, uid)
        role = descriptor.get("role")
        if not isinstance(role, str) or role in roles:
            raise ValueError(f"{entry.entry_id} artifact roles are malformed")
        roles.add(role)
    if roles != set(report_paths(entry, output_dir)):
        raise ValueError(f"{entry.entry_id} recorded artifact roles are incomplete")
    validate_entry_gate(entry, output_dir, release_sha)


def run_entry(
    entry: MatrixEntry,
    *,
    release_sha: str,
    cli: Path,
    output_dir: Path,
    scratch_root: Path,
    cgroup_parent: Path,
    uid: int,
    gid: int,
) -> dict[str, object]:
    paths = report_paths(entry, output_dir)
    scratch = expected_scratch(entry, scratch_root)
    preflight_command = build_preflight_command(entry, scratch_root, cgroup_parent, paths)
    run_logged_command(
        preflight_command,
        release_sha=release_sha,
        log_path=paths["preflight_log"],
        uid=uid,
        gid=gid,
    )
    secure_artifact(paths["host_preflight"], uid, gid)
    host = validate_preflight_report(
        paths["host_preflight"], release_sha, scratch, cgroup_parent
    )

    benchmark_command = build_benchmark_command(
        entry, cli, cgroup_parent, paths
    )
    run_logged_command(
        benchmark_command,
        release_sha=release_sha,
        log_path=paths["benchmark_log"],
        uid=uid,
        gid=gid,
    )

    gate_command = build_gate_command(entry, release_sha, paths)
    run_logged_command(
        gate_command,
        release_sha=release_sha,
        log_path=paths["gate_log"],
        uid=uid,
        gid=gid,
    )
    validate_entry_gate(entry, output_dir, release_sha)
    return host


def build_preflight_command(
    entry: MatrixEntry,
    scratch_root: Path,
    cgroup_parent: Path,
    paths: dict[str, Path],
) -> list[str]:
    return [
        sys.executable,
        str(BENCHMARK_DIR / "fixed_host_preflight.py"),
        "--scratch-dir",
        str(expected_scratch(entry, scratch_root)),
        "--cgroup-parent",
        str(cgroup_parent),
        "--output",
        str(paths["host_preflight"]),
    ]


def build_benchmark_command(
    entry: MatrixEntry,
    cli: Path,
    cgroup_parent: Path,
    paths: dict[str, Path],
) -> list[str]:
    command = [
        sys.executable,
        str(BENCHMARK_DIR / "run_plonky3_cgroup.py"),
        "--manifest",
        str(entry.manifest_path),
        "--mode",
        entry.mode,
        "--report",
        str(paths["candidate_report"]),
        "--hc-cli",
        str(cli),
        "--cgroup-parent",
        str(cgroup_parent),
        "--require-fixed-host",
    ]
    if entry.mode == "throughput":
        command.extend(["--baseline-memory-cap", str(BASELINE_MEMORY_CAP)])
    return command


def build_gate_command(
    entry: MatrixEntry, release_sha: str, paths: dict[str, Path]
) -> list[str]:
    command = [
        sys.executable,
        str(BENCHMARK_DIR / "validate_release_gate.py"),
        "--gate",
        entry.gate,
        "--expected-release-sha",
        release_sha,
        "--manifest",
        str(entry.manifest_path),
        "--candidate",
        str(paths["candidate_report"]),
    ]
    if entry.mode == "throughput":
        command.extend(["--baseline", str(paths["baseline_report"])])
    return command


def precheck_host(scratch: Path, cgroup_parent: Path) -> dict[str, object]:
    if platform.system() != "Linux":
        raise RuntimeError("fixed-host release evidence requires Linux")
    HARNESS.ensure_cgroup_v2(cgroup_parent)
    host = HARNESS.collect_host_metadata(scratch)
    failures = HARNESS.fixed_host_failures(host)
    if failures:
        raise RuntimeError("fixed host is ineligible: " + "; ".join(failures))
    return host


def execute(args: argparse.Namespace) -> int:
    uid, gid = runner_identity()
    output_dir = ensure_private_directory(args.output_dir, uid, gid)
    scratch_root = _absolute_without_symlinks(args.scratch_root)
    cgroup_parent = _absolute_without_symlinks(args.cgroup_parent)
    cli = _absolute_without_symlinks(args.hc_cli)
    if not cli.is_file():
        raise ValueError(f"release hc-cli does not exist: {cli}")
    release_sha = validate_release_sha(args.release_sha)
    state_path = output_dir / "fixed-host-release-matrix-v1.json"

    with MatrixLock(output_dir / ".fixed-host-release-matrix.lock", uid, gid):
        source_tree_sha256 = validate_source_identity(release_sha)
        cli_identity = validate_cli_identity(cli, release_sha)
        for item in MATRIX:
            validate_matrix_manifest(item, scratch_root)
            ensure_private_directory(expected_scratch(item, scratch_root), uid, gid)

        if state_path.exists():
            require_owner_artifact(state_path, uid)
            state = read_json_object(state_path)
            validate_loaded_state(
                state,
                release_sha=release_sha,
                source_tree_sha256=source_tree_sha256,
                cli=cli,
                output_dir=output_dir,
                scratch_root=scratch_root,
                cgroup_parent=cgroup_parent,
            )
        else:
            state = new_state(
                release_sha,
                source_tree_sha256,
                cli,
                cli_identity,
                output_dir,
                scratch_root,
                cgroup_parent,
            )
            persist_state(state_path, state, uid, gid)

        try:
            current_host = precheck_host(expected_scratch(MATRIX[0], scratch_root), cgroup_parent)
            current_identity = stable_host_identity(current_host)
            recorded_identity = state.get("stable_host_identity")
            if recorded_identity is not None and recorded_identity != current_identity:
                raise ValueError("resumed matrix must run on the original fixed host")
            state["stable_host_identity"] = current_identity
            state["fixed_host_evidence_eligible"] = True
            state["status"] = "running"
            state["last_error"] = None
            persist_state(state_path, state, uid, gid)

            for item in MATRIX:
                raw = entry_state(state, item)
                if raw.get("status") == "complete":
                    revalidate_complete_entry(item, raw, output_dir, release_sha, uid)
                    print(f"SKIP {item.entry_id}: recorded evidence revalidated", flush=True)
                    continue
                raw["status"] = "running"
                raw["attempts"] = int(raw.get("attempts", 0)) + 1
                raw["last_error"] = None
                raw["artifacts"] = []
                state["status"] = f"running:{item.entry_id}"
                persist_state(state_path, state, uid, gid)
                print(f"RUN  {item.entry_id}", flush=True)
                try:
                    host = run_entry(
                        item,
                        release_sha=release_sha,
                        cli=cli,
                        output_dir=output_dir,
                        scratch_root=scratch_root,
                        cgroup_parent=cgroup_parent,
                        uid=uid,
                        gid=gid,
                    )
                    if stable_host_identity(host) != current_identity:
                        raise ValueError(f"{item.entry_id} ran on a different fixed host")
                    raw["artifacts"] = descriptors_for_entry(item, output_dir, uid, gid)
                    raw["status"] = "complete"
                    raw["completed_at"] = utc_now()
                    raw["last_error"] = None
                    persist_state(state_path, state, uid, gid)
                except Exception as error:
                    raw["status"] = "failed"
                    raw["last_error"] = str(error)[-2000:]
                    state["status"] = f"failed:{item.entry_id}"
                    state["last_error"] = str(error)[-2000:]
                    persist_state(state_path, state, uid, gid)
                    raise

            state["status"] = "local_matrix_complete_external_gates_pending"
            state["local_matrix_gates_passed"] = True
            state["release_eligible"] = False
            state["completed_at"] = utc_now()
            state["last_error"] = None
            persist_state(state_path, state, uid, gid)
            print(
                json.dumps(
                    {
                        "local_matrix_gates_passed": True,
                        "release_eligible": False,
                        "state_manifest": str(state_path),
                        "next_gate": "independent external reproduction",
                    },
                    indent=2,
                    sort_keys=True,
                )
            )
            return 0
        except Exception as error:
            state["fixed_host_evidence_eligible"] = False
            state["local_matrix_gates_passed"] = False
            state["release_eligible"] = False
            if not str(state.get("status", "")).startswith("failed:"):
                state["status"] = "failed:precheck_or_resume"
            state["last_error"] = str(error)[-2000:]
            persist_state(state_path, state, uid, gid)
            raise


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("raw-reports/fixed-host-release-matrix"),
        help="owner-only directory for raw reports and resumable state",
    )
    parser.add_argument(
        "--scratch-root",
        type=Path,
        default=Path("/var/lib/tinyzkp-bench/scratch"),
        help="must match the four pinned workload manifests",
    )
    parser.add_argument(
        "--cgroup-parent",
        type=Path,
        default=Path("/sys/fs/cgroup/tinyzkp-bench"),
    )
    parser.add_argument("--hc-cli", type=Path, default=Path("target/release/hc-cli"))
    parser.add_argument(
        "--release-sha",
        default=os.environ.get("HC_RELEASE_SHA"),
        required=os.environ.get("HC_RELEASE_SHA") is None,
        help="exact immutable commit built into hc-cli (or HC_RELEASE_SHA)",
    )
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    try:
        return execute(parse_args(argv))
    except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"fixed-host release matrix failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
