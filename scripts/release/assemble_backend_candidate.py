#!/usr/bin/env python3
"""Stage exact backend qualification artifacts into candidate evidence input.

This command does not download Actions artifacts and does not claim that a run
passed.  Its caller supplies two already-authenticated artifact ZIPs.  The
command copies only the closed evidence inventory, builds the unhashed input
for ``build_candidate_evidence.py``, and invokes the existing semantic
validator before emitting that input.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys
import zipfile

import build_candidate_evidence as candidate


ROOT = Path(__file__).resolve().parents[2]
MAX_ARTIFACT_BYTES = candidate.final_gate.MAX_EVIDENCE_ARTIFACT_BYTES
MAX_SELECTED_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024 * 1024
RELEASE_SHA = re.compile(r"^[0-9a-f]{40}$")
LOCAL_GATES = (
    "clean_release_source",
    "plonky3_dependency_profile_pinned",
    "official_verifier_fibonacci",
    "official_verifier_poseidon2",
    "deterministic_cross_mode_proofs",
    "air_job_contracts",
)
PROVENANCE_POLICY = {
    "resource": {
        "workflow_path": ".github/workflows/benches.yml",
        "artifact_prefix": "plonky3-backend-release-matrix-",
    },
    "recovery": {
        "workflow_path": ".github/workflows/nightly-backend.yml",
        "artifact_prefix": "plonky3-recovery-fuzz-",
    },
}
CHECKSUM_MANIFESTS = {
    "resource": "qualification-SHA256SUMS",
    "recovery": "recovery-SHA256SUMS",
}


@dataclass(frozen=True)
class ArtifactSpec:
    gate: str
    role: str
    source_kind: str
    source: str
    destination: str | None


def artifact_plan() -> tuple[ArtifactSpec, ...]:
    specs: list[ArtifactSpec] = []
    for gate in LOCAL_GATES:
        specs.extend(
            (
                ArtifactSpec(
                    gate,
                    "test_report",
                    "local",
                    f"{gate}.test-report.json",
                    f"local/{gate}.test-report.json",
                ),
                ArtifactSpec(
                    gate,
                    "test_log",
                    "local",
                    f"{gate}.test.log",
                    f"local/{gate}.test.log",
                ),
            )
        )

    matrix = "fixed-host-release-matrix-v1.json"
    one_million = {
        "matrix_manifest": matrix,
        "fibonacci_manifest": "examples/plonky3/fibonacci-1m.json",
        "fibonacci_candidate_report": "fibonacci-1m.json",
        "fibonacci_candidate_normalized_manifest": (
            "fibonacci-1m.bounded.manifest.json"
        ),
        "fibonacci_baseline_report": "fibonacci-1m.baseline.json",
        "fibonacci_baseline_normalized_manifest": (
            "fibonacci-1m.baseline.conventional.manifest.json"
        ),
        "poseidon2_manifest": "examples/plonky3/poseidon2-1m.json",
        "poseidon2_candidate_report": "poseidon2-1m.json",
        "poseidon2_candidate_normalized_manifest": (
            "poseidon2-1m.bounded.manifest.json"
        ),
        "poseidon2_baseline_report": "poseidon2-1m.baseline.json",
        "poseidon2_baseline_normalized_manifest": (
            "poseidon2-1m.baseline.conventional.manifest.json"
        ),
    }
    ten_million = {
        "matrix_manifest": matrix,
        "fibonacci_manifest": "examples/plonky3/fibonacci-16m.json",
        "fibonacci_candidate_report": "fibonacci-16m.json",
        "fibonacci_candidate_normalized_manifest": (
            "fibonacci-16m.bounded.manifest.json"
        ),
    }
    tracked_roles = {
        "fibonacci_manifest",
        "poseidon2_manifest",
    }
    for gate, mapping in (
        ("one_million_row_resource_gate", one_million),
        ("ten_million_row_resource_gate", ten_million),
    ):
        for role, source in mapping.items():
            if role in tracked_roles:
                specs.append(ArtifactSpec(gate, role, "tracked", source, None))
            else:
                specs.append(
                    ArtifactSpec(
                        gate,
                        role,
                        "resource",
                        source,
                        f"resource/{source}",
                    )
                )

    crash_gate = "crash_resume_and_corruption_suite"
    specs.extend(
        (
            ArtifactSpec(
                crash_gate,
                "crash_matrix",
                "recovery",
                "crash-matrix.json",
                "recovery/crash-matrix.json",
            ),
            ArtifactSpec(
                crash_gate,
                "fuzz_smoke",
                "recovery",
                "fuzz-smoke.json",
                "recovery/fuzz-smoke.json",
            ),
            ArtifactSpec(
                crash_gate,
                "crash_tool_identity",
                "recovery",
                "crash-logs/crash-tool-identity.json",
                "recovery/crash-logs/crash-tool-identity.json",
            ),
            ArtifactSpec(
                crash_gate,
                "fuzz_tool_identity",
                "recovery",
                "fuzz-logs/fuzz-tool-identity.json",
                "recovery/fuzz-logs/fuzz-tool-identity.json",
            ),
        )
    )
    for name in candidate.CRASH_CASES:
        specs.append(
            ArtifactSpec(
                crash_gate,
                f"crash_log_{name}",
                "recovery",
                f"crash-logs/{name}.log",
                f"recovery/crash-logs/{name}.log",
            )
        )
    for name in candidate.FUZZ_TARGETS:
        specs.append(
            ArtifactSpec(
                crash_gate,
                f"fuzz_log_{name}",
                "recovery",
                f"fuzz-logs/{name}.log",
                f"recovery/fuzz-logs/{name}.log",
            )
        )

    index = {(spec.gate, spec.role): spec for spec in specs}
    expected = {
        (gate, role) for gate, roles in candidate.GATE_ROLES.items() for role in roles
    }
    if len(index) != len(specs) or set(index) != expected:
        raise ValueError(
            "candidate assembly plan differs from the release gate inventory"
        )
    return tuple(specs)


def safe_member_name(raw: str) -> str:
    if not raw or "\\" in raw or raw.startswith("/"):
        raise ValueError(f"Actions artifact contains an unsafe ZIP member: {raw!r}")
    pure = PurePosixPath(raw.rstrip("/"))
    if not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
        raise ValueError(f"Actions artifact contains an unsafe ZIP member: {raw!r}")
    normalized = pure.as_posix()
    if raw.rstrip("/") != normalized:
        raise ValueError(
            f"Actions artifact contains a noncanonical ZIP member: {raw!r}"
        )
    return normalized


def parse_checksum_manifest(payload: bytes, *, label: str) -> dict[str, str]:
    try:
        text = payload.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError(f"{label} checksum manifest is not ASCII") from error
    if not text.endswith("\n"):
        raise ValueError(f"{label} checksum manifest lacks a final newline")
    entries: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
        if match is None:
            raise ValueError(f"{label} checksum manifest is noncanonical")
        raw_name = match.group(2)
        name = raw_name.removeprefix("./")
        if raw_name not in {name, f"./{name}"} or safe_member_name(name) != name:
            raise ValueError(f"{label} checksum path is noncanonical")
        if name in entries:
            raise ValueError(f"{label} checksum path is duplicated: {name}")
        entries[name] = match.group(1)
    return entries


class EvidenceArchive:
    def __init__(self, path: Path, *, required: set[str], label: str):
        self.path = path.absolute()
        self.required = required
        self.label = label
        self.archive: zipfile.ZipFile | None = None
        self.members: dict[str, zipfile.ZipInfo] = {}
        self.before: os.stat_result | None = None

    def __enter__(self) -> "EvidenceArchive":
        try:
            before = os.lstat(self.path)
        except OSError as error:
            raise ValueError(f"{self.label} artifact ZIP is unavailable") from error
        if (
            not stat.S_ISREG(before.st_mode)
            or stat.S_ISLNK(before.st_mode)
            or before.st_nlink != 1
        ):
            raise ValueError(f"{self.label} artifact ZIP is not a stable regular file")
        if not 0 < before.st_size <= MAX_ARCHIVE_BYTES:
            raise ValueError(f"{self.label} artifact ZIP is empty or oversized")
        try:
            archive = zipfile.ZipFile(self.path)
        except (OSError, zipfile.BadZipFile) as error:
            raise ValueError(f"{self.label} artifact is not a valid ZIP") from error
        try:
            members: dict[str, zipfile.ZipInfo] = {}
            for info in archive.infolist():
                name = safe_member_name(info.filename)
                if name in members:
                    raise ValueError(
                        f"{self.label} artifact contains duplicate member: {name}"
                    )
                mode = info.external_attr >> 16
                if stat.S_ISLNK(mode) or info.flag_bits & 0x1:
                    raise ValueError(
                        f"{self.label} artifact contains a link or encrypted member: {name}"
                    )
                members[name] = info
            missing = self.required - set(members)
            if missing:
                raise ValueError(
                    f"{self.label} artifact is missing: {', '.join(sorted(missing))}"
                )
            selected_bytes = 0
            for name in self.required:
                info = members[name]
                if info.is_dir() or not 0 < info.file_size <= MAX_ARTIFACT_BYTES:
                    raise ValueError(
                        f"{self.label} evidence member is empty or oversized: {name}"
                    )
                selected_bytes += info.file_size
            if selected_bytes > MAX_SELECTED_BYTES:
                raise ValueError(f"{self.label} selected evidence exceeds 2 GiB")
        except Exception:
            archive.close()
            raise
        self.before = before
        self.archive = archive
        self.members = members
        return self

    def member_bytes(self, name: str, *, maximum: int = MAX_ARTIFACT_BYTES) -> bytes:
        if self.archive is None:
            raise RuntimeError("evidence archive is not open")
        info = self.members[name]
        if info.is_dir() or not 0 < info.file_size <= maximum:
            raise ValueError(f"{self.label} member is empty or oversized: {name}")
        with self.archive.open(info) as source:
            payload = source.read(maximum + 1)
            if len(payload) != info.file_size or len(payload) > maximum:
                raise ValueError(f"{self.label} member changed while reading: {name}")
            if source.read(1):
                raise ValueError(f"{self.label} member exceeds its ZIP size: {name}")
        return payload

    def member_sha256(self, name: str) -> str:
        if self.archive is None:
            raise RuntimeError("evidence archive is not open")
        info = self.members[name]
        if info.is_dir() or not 0 < info.file_size <= MAX_ARTIFACT_BYTES:
            raise ValueError(f"{self.label} member is empty or oversized: {name}")
        digest = hashlib.sha256()
        total = 0
        with self.archive.open(info) as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                total += len(block)
                if total > MAX_ARTIFACT_BYTES:
                    raise ValueError(f"{self.label} member exceeds limit: {name}")
                digest.update(block)
        if total != info.file_size:
            raise ValueError(f"{self.label} member changed while hashing: {name}")
        return digest.hexdigest()

    def verify_checksum_manifest(
        self, manifest_name: str, *, expected_files: set[str]
    ) -> bytes:
        payload = self.member_bytes(manifest_name, maximum=1024 * 1024)
        entries = parse_checksum_manifest(payload, label=self.label)
        if set(entries) != expected_files:
            raise ValueError(f"{self.label} checksum inventory differs from policy")

        archive_files = {
            name for name, info in self.members.items() if not info.is_dir()
        }
        expected_archive_files = expected_files | {manifest_name}
        if archive_files != expected_archive_files:
            raise ValueError(f"{self.label} ZIP file inventory differs from policy")
        allowed_directories = {
            PurePosixPath(name).parent.as_posix()
            for name in expected_files
            if PurePosixPath(name).parent.as_posix() != "."
        }
        archive_directories = {
            name for name, info in self.members.items() if info.is_dir()
        }
        if not archive_directories <= allowed_directories:
            raise ValueError(
                f"{self.label} ZIP directory inventory differs from policy"
            )

        for name, expected in entries.items():
            if self.member_sha256(name) != expected:
                raise ValueError(f"{self.label} checksum mismatch: {name}")
        return payload

    def copy(self, name: str, destination: Path) -> None:
        if self.archive is None:
            raise RuntimeError("evidence archive is not open")
        info = self.members[name]
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        temporary = destination.with_name(f".{destination.name}.{os.getpid()}.tmp")
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        total = 0
        try:
            with (
                self.archive.open(info) as source,
                os.fdopen(descriptor, "wb", closefd=False) as output,
            ):
                while True:
                    block = source.read(1024 * 1024)
                    if not block:
                        break
                    total += len(block)
                    if total > MAX_ARTIFACT_BYTES:
                        raise ValueError(f"ZIP evidence member exceeds limit: {name}")
                    output.write(block)
                output.flush()
                os.fsync(output.fileno())
            if total != info.file_size:
                raise ValueError(f"ZIP evidence member changed while reading: {name}")
            os.replace(temporary, destination)
            destination.chmod(0o600)
        finally:
            os.close(descriptor)
            temporary.unlink(missing_ok=True)

    def __exit__(self, exc_type, exc, traceback) -> None:
        assert self.archive is not None and self.before is not None
        self.archive.close()
        try:
            after = os.lstat(self.path)
        except OSError as error:
            raise ValueError(
                f"{self.label} artifact disappeared during assembly"
            ) from error
        before_identity = (
            self.before.st_dev,
            self.before.st_ino,
            self.before.st_size,
            self.before.st_mtime_ns,
            self.before.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity:
            raise ValueError(f"{self.label} artifact changed during assembly")


def archive_evidence_files(
    kind: str, plan: tuple[ArtifactSpec, ...] | None = None
) -> set[str]:
    if kind not in CHECKSUM_MANIFESTS:
        raise ValueError(f"unknown qualification archive kind: {kind}")
    selected = artifact_plan() if plan is None else plan
    return {spec.source for spec in selected if spec.source_kind == kind}


def extract_checksum_manifests(
    *,
    resource_archive: Path,
    recovery_archive: Path,
    resource_output: Path,
    recovery_output: Path,
) -> None:
    outputs = {"resource": resource_output, "recovery": recovery_output}
    archives = {"resource": resource_archive, "recovery": recovery_archive}
    if resource_output.absolute() == recovery_output.absolute():
        raise ValueError("qualification checksum outputs must be distinct")
    plan = artifact_plan()
    for kind in ("resource", "recovery"):
        manifest = CHECKSUM_MANIFESTS[kind]
        if outputs[kind].name != manifest:
            raise ValueError(f"{kind} checksum output must retain its canonical name")
        evidence_files = archive_evidence_files(kind, plan)
        with EvidenceArchive(
            archives[kind],
            required=evidence_files | {manifest},
            label=f"{kind} qualification",
        ) as archive:
            payload = archive.verify_checksum_manifest(
                manifest, expected_files=evidence_files
            )
        write_private(outputs[kind], payload)


def safe_local_file(root: Path, local_root: Path, relative: str) -> Path:
    root = root.resolve()
    local_root = (
        local_root.absolute()
        if local_root.is_absolute()
        else (root / local_root).absolute()
    )
    if not local_root.is_relative_to(root):
        raise ValueError("local evidence root must be inside the repository")
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError("local evidence path is unsafe")
    path = local_root / relative_path
    current = root
    for part in path.relative_to(root).parts:
        current /= part
        if current.is_symlink():
            raise ValueError(f"local evidence path contains a symlink: {relative}")
    if not path.is_file():
        raise ValueError(f"local evidence file is missing: {relative}")
    return path


def write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        path.chmod(0o600)
    finally:
        os.close(descriptor)
        temporary.unlink(missing_ok=True)


def stable_sha256(path: Path, *, maximum: int) -> str:
    before = os.lstat(path)
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or not 0 < before.st_size <= maximum
    ):
        raise ValueError(f"provenance input is unsafe or oversized: {path}")
    digest = hashlib.sha256()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        opened = os.fstat(descriptor)
        if (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
            raise ValueError(f"provenance input changed before reading: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(descriptor)
    after = os.lstat(path)
    if (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
        raise ValueError(f"provenance input changed while reading: {path}")
    return digest.hexdigest()


def timestamp_value(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ValueError(f"{label} must be one UTC timestamp")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise ValueError(f"{label} must be one UTC timestamp") from error
    if parsed.microsecond != 0:
        raise ValueError(f"{label} must have whole-second precision")
    return parsed


def read_run_provenance(
    path: Path,
    *,
    kind: str,
    release_sha: str,
    archive: Path,
) -> dict[str, object]:
    payload = candidate.final_gate.read_bounded_file(path, maximum=1024 * 1024)
    try:
        value = candidate.strict_json.loads(payload)
    except (ValueError, json.JSONDecodeError) as error:
        raise ValueError(f"{kind} run provenance is malformed") from error
    validate_run_provenance_value(
        value,
        kind=kind,
        release_sha=release_sha,
        archive_sha256=stable_sha256(archive, maximum=MAX_ARCHIVE_BYTES),
    )
    return value


def validate_run_provenance_value(
    value: object,
    *,
    kind: str,
    release_sha: str,
    archive_sha256: str,
) -> None:
    policy = PROVENANCE_POLICY[kind]
    expected_keys = {
        "schema_version",
        "repository",
        "workflow_path",
        "run_id",
        "run_attempt",
        "event",
        "head_branch",
        "head_sha",
        "status",
        "conclusion",
        "actor",
        "triggering_actor",
        "run_started_at",
        "artifact",
    }
    artifact = value.get("artifact") if isinstance(value, dict) else None
    if (
        not isinstance(value, dict)
        or set(value) != expected_keys
        or value.get("schema_version") != 1
        or value.get("repository") != "logannye/hc-stark"
        or value.get("workflow_path") != policy["workflow_path"]
        or type(value.get("run_id")) is not int
        or value.get("run_id", 0) <= 0
        or type(value.get("run_attempt")) is not int
        or value.get("run_attempt", 0) <= 0
        or value.get("event") != "workflow_dispatch"
        or value.get("head_branch") != "main"
        or value.get("head_sha") != release_sha
        or value.get("status") != "completed"
        or value.get("conclusion") != "success"
        or value.get("actor") != "logannye"
        or value.get("triggering_actor") != "logannye"
        or not isinstance(artifact, dict)
        or set(artifact) != {"id", "name", "created_at", "archive_sha256"}
        or type(artifact.get("id")) is not int
        or artifact.get("id", 0) <= 0
        or artifact.get("name") != str(policy["artifact_prefix"]) + release_sha
        or artifact.get("archive_sha256") != archive_sha256
    ):
        raise ValueError(f"{kind} run provenance is incomplete or release-skewed")
    started = timestamp_value(value.get("run_started_at"), label="run_started_at")
    created = timestamp_value(artifact.get("created_at"), label="artifact.created_at")
    if created < started:
        raise ValueError(f"{kind} artifact predates its selected run attempt")


def assemble(
    *,
    root: Path,
    release_sha: str,
    resource_archive: Path,
    recovery_archive: Path,
    resource_provenance: Path,
    recovery_provenance: Path,
    local_root: Path,
    output_root: Path,
    output_input: Path,
) -> dict[str, object]:
    root = root.resolve()
    if RELEASE_SHA.fullmatch(release_sha) is None:
        raise ValueError("release SHA must be one lowercase 40-hex commit")
    expected_output = root / "release" / "evidence" / "backend-v1" / release_sha
    output_root = output_root if output_root.is_absolute() else root / output_root
    if output_root.absolute() != expected_output:
        raise ValueError(
            "candidate evidence output must use the canonical release path"
        )
    if output_root.exists() or output_root.is_symlink():
        raise ValueError("candidate evidence output already exists")
    output_input = candidate.safe_output(root, output_input)
    plan = artifact_plan()
    provenance = {
        "resource": read_run_provenance(
            resource_provenance,
            kind="resource",
            release_sha=release_sha,
            archive=resource_archive,
        ),
        "recovery": read_run_provenance(
            recovery_provenance,
            kind="recovery",
            release_sha=release_sha,
            archive=recovery_archive,
        ),
    }

    resource_required = archive_evidence_files("resource", plan)
    recovery_required = archive_evidence_files("recovery", plan)
    local_paths = {
        spec.source: safe_local_file(root, local_root, spec.source)
        for spec in plan
        if spec.source_kind == "local"
    }
    for spec in plan:
        if spec.source_kind == "tracked":
            candidate.safe_existing_file(root, spec.source)

    copied: set[tuple[str, str, str]] = set()
    with (
        EvidenceArchive(
            resource_archive,
            required=resource_required | {CHECKSUM_MANIFESTS["resource"]},
            label="resource qualification",
        ) as resources,
        EvidenceArchive(
            recovery_archive,
            required=recovery_required | {CHECKSUM_MANIFESTS["recovery"]},
            label="recovery qualification",
        ) as recovery,
    ):
        checksum_payloads = {
            "resource": resources.verify_checksum_manifest(
                CHECKSUM_MANIFESTS["resource"], expected_files=resource_required
            ),
            "recovery": recovery.verify_checksum_manifest(
                CHECKSUM_MANIFESTS["recovery"], expected_files=recovery_required
            ),
        }
        output_root.mkdir(parents=True, mode=0o700)
        for spec in plan:
            if spec.destination is None:
                continue
            key = (spec.source_kind, spec.source, spec.destination)
            if key in copied:
                continue
            destination = output_root / spec.destination
            if spec.source_kind == "resource":
                resources.copy(spec.source, destination)
            elif spec.source_kind == "recovery":
                recovery.copy(spec.source, destination)
            elif spec.source_kind == "local":
                payload = candidate.final_gate.read_bounded_file(
                    local_paths[spec.source], maximum=MAX_ARTIFACT_BYTES
                )
                write_private(destination, payload)
            else:  # pragma: no cover - closed ArtifactSpec construction
                raise ValueError(f"unknown evidence source kind: {spec.source_kind}")
            copied.add(key)

    for kind, value in provenance.items():
        write_private(
            output_root / "provenance" / f"{kind}-qualification-run-v1.json",
            json.dumps(value, indent=2, sort_keys=True).encode("utf-8") + b"\n",
        )
        write_private(
            output_root / "provenance" / CHECKSUM_MANIFESTS[kind],
            checksum_payloads[kind],
        )

    source = {
        "schema_version": 1,
        "release_sha": release_sha,
        "gates": {
            gate: {
                "metadata": candidate.gate_metadata(gate, release_sha),
                "artifacts": [],
            }
            for gate in sorted(candidate.prerelease.EXPECTED_GATES)
        },
    }
    prefix = output_root.relative_to(root)
    for spec in plan:
        relative = (
            Path(spec.source) if spec.destination is None else prefix / spec.destination
        )
        source["gates"][spec.gate]["artifacts"].append(
            {"role": spec.role, "path": relative.as_posix()}
        )
    for gate, roles in candidate.GATE_ROLES.items():
        observed = [item["role"] for item in source["gates"][gate]["artifacts"]]
        if observed != roles:
            raise ValueError(f"{gate}: assembled artifact order differs from policy")

    candidate.construct_evidence(source, root=root)
    candidate.write_json_atomic(output_input, source)
    return source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--resource-archive", type=Path, required=True)
    parser.add_argument("--recovery-archive", type=Path, required=True)
    parser.add_argument("--resource-provenance", type=Path, required=True)
    parser.add_argument("--recovery-provenance", type=Path, required=True)
    parser.add_argument("--local-root", type=Path, required=True)
    parser.add_argument("--output-root", type=Path, required=True)
    parser.add_argument("--output-input", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        source = assemble(
            root=ROOT,
            release_sha=args.release_sha,
            resource_archive=args.resource_archive,
            recovery_archive=args.recovery_archive,
            resource_provenance=args.resource_provenance,
            recovery_provenance=args.recovery_provenance,
            local_root=args.local_root,
            output_root=args.output_root,
            output_input=args.output_input,
        )
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"backend candidate assembly failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(source, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
