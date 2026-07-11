#!/usr/bin/env python3
"""Verify reviewed fixed-host TinyZKP backup and restore evidence.

This command is deliberately verify-only. It never runs a backup, restores a
file, contacts the off-box store, or writes evidence. Production verification
uses one fixed root-private bundle and binds it to caller-supplied release,
host, and deployment identities.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import pathlib
import platform
import re
import stat
import sys
from typing import Any


FIXED_EVIDENCE_ROOT = pathlib.Path(
    "/var/lib/tinyzkp-private/backup/fixed-host-evidence"
)
FIXED_BUNDLE_NAME = "bundle.json"
FIXED_REVIEW_NAME = "review.json"
FIXED_RAW_NAME = "raw"
FIXED_MACHINE_ID = pathlib.Path("/etc/machine-id")
SCHEMA = "tinyzkp-fixed-host-backup-evidence-v1"
MAX_EVIDENCE_BYTES = 512 * 1024
MAX_STRUCTURED_ARTIFACT_BYTES = 2 * 1024 * 1024
MAX_LOG_ARTIFACT_BYTES = 64 * 1024 * 1024
MAX_TOTAL_ARTIFACT_BYTES = 512 * 1024 * 1024
MAX_EVIDENCE_AGE = timedelta(days=30)
MAX_CLOCK_SKEW = timedelta(minutes=5)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
RELEASE_RE = re.compile(r"^[0-9a-f]{40}$")
RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")
DEPLOYMENT_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{2,63}$")
TIMESTAMP_RE = re.compile(r"^[0-9]{8}_[0-9]{6}$")
UTC_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
SAFE_TEXT_RE = re.compile(r"^[ -~]+$")

CORE_JSON_ARTIFACTS = (
    "happy_path_report",
    "lock_contention_report",
    "service_uid_staging_report",
    "local_manifest",
    "offbox_roundtrip_report",
    "scratch_restore_report",
    "failure_cleanup_matrix",
    "signal_cleanup_matrix",
)
CORE_LOG_ARTIFACTS = (
    "happy_path_log",
    "lock_contention_log",
    "service_uid_staging_log",
    "offbox_roundtrip_log",
    "scratch_restore_log",
)
FAILURE_CASES = (
    ("writer_remained_active", "quiescence"),
    ("staging_creation_failure", "staging"),
    ("service_uid_snapshot_failure", "service_uid_snapshot"),
    ("root_descriptor_copy_failure", "root_descriptor_copy"),
    ("manifest_creation_failure", "manifest_create"),
    ("manifest_verification_failure", "manifest_verify"),
    ("offbox_upload_failure", "offbox_upload"),
    ("offbox_corrupt_readback", "offbox_readback"),
    ("disk_full_snapshot", "snapshot_write"),
)
SIGNAL_PHASES = (
    "after_quiesce",
    "service_uid_snapshot",
    "root_descriptor_copy",
    "manifest",
)
SIGNALS = (("hup", 129), ("int", 130), ("term", 143))
REVIEW_SCOPE = (
    "root_happy_path",
    "lock_contention",
    "service_uid_staging",
    "local_manifest",
    "offbox_roundtrip",
    "semantic_scratch_restore",
    "failure_cleanup_matrix",
    "signal_cleanup_matrix",
)
SQLITE_RESTORE_TARGETS = {
    "contract_billing.sqlite": "contract_billing",
    "evaluation_applications.sqlite": "evaluation_applications",
    "tenant_store.sqlite": "tenant",
    "usage.sqlite": "usage",
}


class EvidenceError(ValueError):
    """Fixed-host backup evidence is absent, unsafe, incomplete, or stale."""


def _sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError(f"JSON object duplicates {key!r}")
        result[key] = value
    return result


def _reject_number(token: str) -> object:
    raise EvidenceError(f"JSON number is not an integer: {token}")


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
        + "\n"
    ).encode("ascii")


def _parse_canonical_json(raw: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicates,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EvidenceError(f"{label} must be strict UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{label} must contain one JSON object")
    if raw != _canonical_json(value):
        raise EvidenceError(f"{label} encoding is not canonical")
    return value


def _exact_keys(value: dict[str, Any], expected: set[str], *, label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = ", ".join(sorted(expected - actual)) or "none"
        extra = ", ".join(sorted(actual - expected)) or "none"
        raise EvidenceError(
            f"{label} fields differ (missing: {missing}; extra: {extra})"
        )


def _exact_int(value: object, *, label: str, minimum: int, maximum: int) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise EvidenceError(f"{label} is outside its allowed integer range")
    return value


def _exact_bool(value: object, *, label: str, expected: bool = True) -> None:
    if value is not expected:
        raise EvidenceError(f"{label} must be {str(expected).lower()}")


def _digest(value: object, *, label: str) -> str:
    if not isinstance(value, str) or SHA256_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _safe_text(
    value: object, *, label: str, minimum: int = 1, maximum: int = 200
) -> str:
    if (
        not isinstance(value, str)
        or not minimum <= len(value) <= maximum
        or SAFE_TEXT_RE.fullmatch(value) is None
        or value != value.strip()
    ):
        raise EvidenceError(f"{label} must be bounded printable ASCII")
    return value


def _parse_utc(value: object, *, label: str) -> datetime:
    if not isinstance(value, str) or UTC_RE.fullmatch(value) is None:
        raise EvidenceError(f"{label} must be canonical UTC")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=timezone.utc
        )
    except ValueError as error:
        raise EvidenceError(f"{label} is not a real UTC time") from error


def _validate_directory(path: pathlib.Path, *, uid: int, label: str) -> os.stat_result:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != uid
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise EvidenceError(f"{label} must be owner-only mode 0700 and symlink-free")
    return metadata


def _validate_fixed_ancestors(path: pathlib.Path, *, uid: int) -> None:
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        try:
            metadata = current.lstat()
        except OSError as error:
            raise EvidenceError(
                "fixed evidence path component is unavailable"
            ) from error
        if (
            current.is_symlink()
            or not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise EvidenceError(
                "fixed evidence path components must be owner-controlled and symlink-free"
            )


def _read_private_file(
    path: pathlib.Path, *, uid: int, label: str, limit: int
) -> tuple[bytes, os.stat_result]:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or not 1 <= metadata.st_size <= limit
    ):
        raise EvidenceError(
            f"{label} must be a unique owner-only mode 0600 regular file within limits"
        )
    if not hasattr(os, "O_NOFOLLOW"):
        raise EvidenceError("fixed-host evidence verification requires O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError(f"{label} cannot be safely opened") from error
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ) != (metadata.st_dev, metadata.st_ino, metadata.st_size):
            raise EvidenceError(f"{label} changed before it was opened")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise EvidenceError(f"{label} exceeds its size limit")
            chunks.append(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
            opened.st_ctime_ns,
        ):
            raise EvidenceError(f"{label} changed while it was read")
    finally:
        os.close(descriptor)
    raw = b"".join(chunks)
    if len(raw) != metadata.st_size:
        raise EvidenceError(f"{label} was not read completely")
    return raw, metadata


def _stable_host_identity(path: pathlib.Path = FIXED_MACHINE_ID) -> str:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise EvidenceError("fixed host machine identity is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not 1 <= metadata.st_size <= 256
    ):
        raise EvidenceError("fixed host machine identity file is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise EvidenceError("fixed host machine identity cannot be opened") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino, opened.st_size) != (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
        ):
            raise EvidenceError("fixed host machine identity changed before open")
        raw = os.read(descriptor, 256)
        if os.read(descriptor, 1):
            raise EvidenceError("fixed host machine identity is oversized")
    finally:
        os.close(descriptor)
    try:
        value = raw.decode("ascii").strip().lower()
    except UnicodeDecodeError as error:
        raise EvidenceError("fixed host machine identity is malformed") from error
    if re.fullmatch(r"[0-9a-f]{32}", value) is None:
        raise EvidenceError("fixed host machine identity is malformed")
    return _sha256(value.encode("ascii"))


def _host_os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        lines = pathlib.Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except OSError as error:
        raise EvidenceError("fixed host OS identity is unavailable") from error
    for line in lines:
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key] = value.strip().strip('"')
    return values.get("ID", ""), values.get("VERSION_ID", "")


def _enforce_fixed_host(
    expected_host_identity: str, machine_id_file: pathlib.Path = FIXED_MACHINE_ID
) -> None:
    architecture = platform.machine().lower()
    if architecture == "amd64":
        architecture = "x86_64"
    if os.geteuid() != 0 or sys.platform != "linux" or architecture != "x86_64":
        raise EvidenceError("fixed-host evidence requires root on Linux x86_64")
    if _host_os_release() != ("debian", "12"):
        raise EvidenceError(
            "fixed-host evidence requires the reviewed Debian 12 profile"
        )
    if not hmac.compare_digest(
        _stable_host_identity(machine_id_file), expected_host_identity
    ):
        raise EvidenceError("expected host identity does not match this fixed host")


def _artifact_media(artifact_id: str) -> str:
    return (
        "application/json"
        if artifact_id in CORE_JSON_ARTIFACTS
        else "text/plain; charset=utf-8"
    )


def _expected_artifact_ids() -> tuple[str, ...]:
    failure_logs = tuple(f"failure_log_{case_id}" for case_id, _phase in FAILURE_CASES)
    signal_logs = tuple(
        f"signal_log_{signal}_{phase}"
        for signal, _exit_code in SIGNALS
        for phase in SIGNAL_PHASES
    )
    return (*CORE_JSON_ARTIFACTS, *CORE_LOG_ARTIFACTS, *failure_logs, *signal_logs)


def _artifact_path(artifact_id: str) -> str:
    extension = "json" if artifact_id in CORE_JSON_ARTIFACTS else "log"
    return f"raw/{artifact_id}.{extension}"


def _identity_fields(
    payload: dict[str, Any], bundle: dict[str, Any], *, label: str
) -> None:
    expected = {
        "run_id": bundle["run_id"],
        "release_sha": bundle["release_sha"],
        "host_identity_sha256": bundle["host"]["identity_sha256"],
        "deployment_id": bundle["deployment_id"],
    }
    for key, value in expected.items():
        if payload.get(key) != value:
            raise EvidenceError(f"{label} does not bind bundle {key}")
    if (
        type(payload.get("schema_version")) is not int
        or payload.get("schema_version") != 1
    ):
        raise EvidenceError(f"{label} schema version is unsupported")


def _active_services(value: object, *, label: str) -> None:
    expected = {
        "hc-billing-webhook.service": "active",
        "hc-stark.service": "active",
    }
    if value != expected:
        raise EvidenceError(f"{label} must show both production services active")


def _validate_bundle_header(
    bundle: dict[str, Any],
    *,
    expected_release_sha: str,
    expected_host_identity: str,
    expected_deployment_id: str,
    now: datetime,
) -> datetime:
    _exact_keys(
        bundle,
        {
            "schema_version",
            "status",
            "evidence_id",
            "captured_at",
            "release_sha",
            "host",
            "deployment_id",
            "run_id",
            "subject_artifact_set_sha256",
            "artifacts",
        },
        label="fixed-host bundle",
    )
    if (
        type(bundle["schema_version"]) is not int
        or bundle["schema_version"] != 1
        or bundle["status"] != "reviewed_pass"
    ):
        raise EvidenceError("fixed-host bundle is not reviewed passing evidence")
    _digest(bundle["evidence_id"], label="evidence ID")
    if bundle["release_sha"] != expected_release_sha:
        raise EvidenceError(
            "fixed-host bundle release does not match the expected release"
        )
    if bundle["deployment_id"] != expected_deployment_id:
        raise EvidenceError(
            "fixed-host bundle deployment does not match the expected deployment"
        )
    if (
        not isinstance(bundle["run_id"], str)
        or RUN_ID_RE.fullmatch(bundle["run_id"]) is None
    ):
        raise EvidenceError("fixed-host bundle run ID is invalid")
    _digest(bundle["subject_artifact_set_sha256"], label="subject artifact set")
    host = bundle["host"]
    if not isinstance(host, dict):
        raise EvidenceError("fixed-host bundle host profile must be an object")
    _exact_keys(
        host,
        {"identity_sha256", "os_id", "os_version_id", "architecture", "effective_uid"},
        label="fixed-host profile",
    )
    _exact_int(
        host["effective_uid"], label="fixed-host effective UID", minimum=0, maximum=0
    )
    if (
        host["identity_sha256"] != expected_host_identity
        or host["os_id"] != "debian"
        or host["os_version_id"] != "12"
        or host["architecture"] != "x86_64"
    ):
        raise EvidenceError(
            "fixed-host bundle host profile does not match the reviewed host"
        )
    captured_at = _parse_utc(bundle["captured_at"], label="bundle capture time")
    age = now - captured_at
    if age < -MAX_CLOCK_SKEW or age > MAX_EVIDENCE_AGE:
        raise EvidenceError("fixed-host backup evidence is stale or future-dated")
    return captured_at


def _validate_artifact_descriptors(
    bundle: dict[str, Any], raw_root: pathlib.Path, *, uid: int
) -> tuple[dict[str, bytes], str]:
    artifacts = bundle["artifacts"]
    expected_ids = _expected_artifact_ids()
    if not isinstance(artifacts, dict) or set(artifacts) != set(expected_ids):
        raise EvidenceError(
            "fixed-host bundle artifact set is incomplete or unexpected"
        )
    raw_files = {
        entry.name
        for entry in os.scandir(raw_root)
        if entry.is_file(follow_symlinks=False)
    }
    expected_names = {
        pathlib.PurePosixPath(_artifact_path(item)).name for item in expected_ids
    }
    if raw_files != expected_names or len(list(os.scandir(raw_root))) != len(
        expected_names
    ):
        raise EvidenceError(
            "fixed-host raw directory contains missing or unexpected entries"
        )

    contents: dict[str, bytes] = {}
    total_bytes = 0
    for artifact_id in expected_ids:
        descriptor = artifacts[artifact_id]
        if not isinstance(descriptor, dict):
            raise EvidenceError(f"artifact descriptor {artifact_id} must be an object")
        _exact_keys(
            descriptor,
            {"path", "media_type", "sha256", "size_bytes"},
            label=f"artifact descriptor {artifact_id}",
        )
        expected_path = _artifact_path(artifact_id)
        if descriptor["path"] != expected_path or descriptor[
            "media_type"
        ] != _artifact_media(artifact_id):
            raise EvidenceError(
                f"artifact descriptor {artifact_id} path or media type is invalid"
            )
        expected_size = _exact_int(
            descriptor["size_bytes"],
            label=f"artifact descriptor {artifact_id} size",
            minimum=1,
            maximum=(
                MAX_STRUCTURED_ARTIFACT_BYTES
                if artifact_id in CORE_JSON_ARTIFACTS
                else MAX_LOG_ARTIFACT_BYTES
            ),
        )
        expected_digest = _digest(
            descriptor["sha256"], label=f"artifact descriptor {artifact_id} hash"
        )
        artifact_path = raw_root / pathlib.PurePosixPath(expected_path).name
        raw, metadata = _read_private_file(
            artifact_path,
            uid=uid,
            label=f"raw artifact {artifact_id}",
            limit=(
                MAX_STRUCTURED_ARTIFACT_BYTES
                if artifact_id in CORE_JSON_ARTIFACTS
                else MAX_LOG_ARTIFACT_BYTES
            ),
        )
        if metadata.st_size != expected_size or not hmac.compare_digest(
            _sha256(raw), expected_digest
        ):
            raise EvidenceError(
                f"raw artifact {artifact_id} differs from its descriptor"
            )
        if artifact_id in CORE_JSON_ARTIFACTS:
            _parse_canonical_json(raw, label=f"raw artifact {artifact_id}")
        total_bytes += len(raw)
        if total_bytes > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceError(
                "fixed-host raw artifact set exceeds its total size limit"
            )
        contents[artifact_id] = raw

    subject = {item: artifacts[item] for item in sorted(artifacts)}
    subject_digest = _sha256(_canonical_json({"artifacts": subject}))
    if not hmac.compare_digest(subject_digest, bundle["subject_artifact_set_sha256"]):
        raise EvidenceError("fixed-host subject artifact set digest is invalid")
    return contents, subject_digest


def _validate_local_manifest(
    raw: bytes, backup_timestamp: str
) -> tuple[str, int, bool]:
    manifest = _parse_canonical_json(raw, label="local backup manifest")
    _exact_keys(
        manifest,
        {"schema_version", "timestamp", "required_artifacts", "artifacts"},
        label="local backup manifest",
    )
    if (
        type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["timestamp"] != backup_timestamp
    ):
        raise EvidenceError("local backup manifest version or timestamp is invalid")
    required = [
        f"api_keys_{backup_timestamp}.txt",
        f"contract_billing_{backup_timestamp}.sqlite",
        f"evaluation_applications_{backup_timestamp}.sqlite",
        f"tenant_store_{backup_timestamp}.sqlite",
        f"usage_{backup_timestamp}.sqlite",
    ]
    if manifest["required_artifacts"] != required:
        raise EvidenceError("local backup manifest required artifact policy is invalid")
    artifacts = manifest["artifacts"]
    if not isinstance(artifacts, list):
        raise EvidenceError("local backup manifest artifacts must be a list")
    allowed_order = [
        f"tenant_store_{backup_timestamp}.sqlite",
        f"usage_{backup_timestamp}.sqlite",
        f"evaluation_applications_{backup_timestamp}.sqlite",
        f"contract_billing_{backup_timestamp}.sqlite",
        f"api_keys_{backup_timestamp}.txt",
        f"contracts_{backup_timestamp}.tar.gz",
    ]
    names: list[str] = []
    for index, artifact in enumerate(artifacts):
        if not isinstance(artifact, dict):
            raise EvidenceError(
                "local backup manifest artifact record must be an object"
            )
        _exact_keys(
            artifact,
            {"name", "sha256", "size"},
            label=f"local backup manifest artifact {index}",
        )
        name = artifact["name"]
        if not isinstance(name, str) or name in names:
            raise EvidenceError(
                "local backup manifest artifact name is invalid or duplicate"
            )
        _digest(artifact["sha256"], label=f"local backup manifest artifact {name}")
        _exact_int(
            artifact["size"],
            label=f"local backup manifest artifact {name} size",
            minimum=1,
            maximum=1024 * 1024 * 1024,
        )
        names.append(name)
    expected_names = allowed_order[:5]
    if tuple(names) not in {tuple(expected_names), tuple(allowed_order)}:
        # Sets cannot contain lists; tuples make the two exact permitted orders explicit.
        raise EvidenceError(
            "local backup manifest artifact order or membership is invalid"
        )
    return _sha256(raw), len(names), names == allowed_order


def _validate_happy_path(
    report: dict[str, Any],
    bundle: dict[str, Any],
    manifest_sha256: str,
    captured_at: datetime,
) -> str:
    _exact_keys(
        report,
        {
            "schema_version",
            "run_id",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "started_at",
            "completed_at",
            "effective_uid",
            "source_branch",
            "source_tree_clean",
            "published_origin_main",
            "backup_script",
            "backup_exit_code",
            "backup_timestamp",
            "remote_date",
            "services",
            "writer_handles_after_stop",
            "local_manifest_source",
            "local_manifest_verified",
            "local_manifest_sha256",
            "staging_removed",
            "lock_released",
        },
        label="happy-path report",
    )
    _identity_fields(report, bundle, label="happy-path report")
    started = _parse_utc(report["started_at"], label="happy-path start time")
    completed = _parse_utc(report["completed_at"], label="happy-path completion time")
    if (
        not started <= completed
        or completed != captured_at
        or completed - started > timedelta(hours=24)
    ):
        raise EvidenceError("happy-path timing does not bind the bundle capture")
    _exact_int(
        report["effective_uid"], label="happy-path effective UID", minimum=0, maximum=0
    )
    _exact_int(
        report["backup_exit_code"], label="happy-path exit code", minimum=0, maximum=0
    )
    _exact_int(
        report["writer_handles_after_stop"],
        label="happy-path writer handles",
        minimum=0,
        maximum=0,
    )
    if (
        report["source_branch"] != "main"
        or report["source_tree_clean"] is not True
        or report["published_origin_main"] is not True
        or report["backup_script"] != "/opt/hc-stark/billing/backup.sh"
    ):
        raise EvidenceError("happy-path root/source/exit evidence is invalid")
    timestamp = report["backup_timestamp"]
    if not isinstance(timestamp, str) or TIMESTAMP_RE.fullmatch(timestamp) is None:
        raise EvidenceError("happy-path backup timestamp is invalid")
    try:
        timestamp_time = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
    except ValueError as error:
        raise EvidenceError("happy-path backup timestamp is not real") from error
    if report["remote_date"] != timestamp_time.strftime("%Y-%m-%d"):
        raise EvidenceError("happy-path remote date differs from the backup timestamp")
    expected_manifest = f"/opt/hc-stark/backups/manifest_{timestamp}.json"
    if (
        report["local_manifest_source"] != expected_manifest
        or report["local_manifest_verified"] is not True
        or report["local_manifest_sha256"] != manifest_sha256
        or report["staging_removed"] is not True
        or report["lock_released"] is not True
    ):
        raise EvidenceError("happy-path manifest or cleanup evidence is invalid")
    services = report["services"]
    expected_services = {
        "hc-billing-webhook.service": {
            "before": "active",
            "during": "inactive",
            "after": "active",
        },
        "hc-stark.service": {
            "before": "active",
            "during": "inactive",
            "after": "active",
        },
    }
    if services != expected_services:
        raise EvidenceError("happy-path service transition evidence is invalid")
    return timestamp


def _validate_lock_contention(report: dict[str, Any], bundle: dict[str, Any]) -> None:
    _exact_keys(
        report,
        {
            "schema_version",
            "run_id",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "lock_path",
            "lock_owner_uid",
            "lock_mode",
            "primary_acquired",
            "contender_effective_uid",
            "contender_exit_code",
            "contender_error",
            "primary_completed",
            "lock_reacquired_after",
        },
        label="lock-contention report",
    )
    _identity_fields(report, bundle, label="lock-contention report")
    if (
        report["lock_path"] != "/var/lib/tinyzkp-private/backup/backup.lock"
        or report["lock_owner_uid"] != 0
        or report["lock_mode"] != "0600"
        or report["primary_acquired"] is not True
        or report["contender_effective_uid"] != 0
        or report["contender_error"] != "another TinyZKP backup is already active"
        or report["primary_completed"] is not True
        or report["lock_reacquired_after"] is not True
    ):
        raise EvidenceError("lock-contention semantics are invalid")
    _exact_int(
        report["contender_exit_code"],
        label="lock contender exit code",
        minimum=1,
        maximum=255,
    )


def _validate_staging(
    report: dict[str, Any], bundle: dict[str, Any], timestamp: str
) -> None:
    _exact_keys(
        report,
        {
            "schema_version",
            "run_id",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "staging_root",
            "staging_root_owner_uid",
            "staging_root_group_gid",
            "staging_root_mode",
            "staging_leaf",
            "staging_leaf_owner_uid",
            "staging_leaf_group_gid",
            "staging_leaf_mode",
            "service_user",
            "service_uid",
            "service_gid",
            "snapshot_executor",
            "snapshot_effective_uid",
            "sqlite_snapshots",
            "root_copy_effective_uid",
            "root_descriptor_copy_count",
            "source_identity_stable",
            "staging_removed",
        },
        label="service-UID staging report",
    )
    _identity_fields(report, bundle, label="service-UID staging report")
    service_uid = _exact_int(
        report["service_uid"], label="service UID", minimum=1, maximum=2**31 - 1
    )
    service_gid = _exact_int(
        report["service_gid"], label="service GID", minimum=1, maximum=2**31 - 1
    )
    expected_snapshots = [
        "evaluation_applications.sqlite",
        "tenant_store.sqlite",
        "usage.sqlite",
    ]
    if (
        report["staging_root"] != "/var/lib/tinyzkp-backup-staging"
        or report["staging_root_owner_uid"] != 0
        or report["staging_root_group_gid"] != service_gid
        or report["staging_root_mode"] != "0710"
        or report["staging_leaf"] != f"/var/lib/tinyzkp-backup-staging/run_{timestamp}"
        or report["staging_leaf_owner_uid"] != service_uid
        or report["staging_leaf_group_gid"] != service_gid
        or report["staging_leaf_mode"] != "0700"
        or report["service_user"] != "tinyzkp-billing"
        or report["snapshot_executor"] != "runuser:tinyzkp-billing"
        or report["snapshot_effective_uid"] != service_uid
        or report["sqlite_snapshots"] != expected_snapshots
        or report["root_copy_effective_uid"] != 0
        or report["root_descriptor_copy_count"] != 3
        or report["source_identity_stable"] is not True
        or report["staging_removed"] is not True
    ):
        raise EvidenceError("service-UID staging/root-copy semantics are invalid")


def _validate_offbox(
    report: dict[str, Any],
    bundle: dict[str, Any],
    *,
    timestamp: str,
    manifest_sha256: str,
    manifest_artifact_count: int,
) -> None:
    _exact_keys(
        report,
        {
            "schema_version",
            "run_id",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "transport",
            "rclone_config",
            "remote_date",
            "upload_exit_code",
            "remote_object_count",
            "local_manifest_sha256",
            "download_exit_code",
            "downloaded_manifest_sha256",
            "downloaded_manifest_verified",
            "downloaded_artifact_digests_match_manifest",
            "encryption_verified",
            "anonymous_read_denied",
            "retention_verified",
            "scratch_download_root",
            "scratch_owner_uid",
            "scratch_mode",
            "scratch_removed",
        },
        label="off-box roundtrip report",
    )
    _identity_fields(report, bundle, label="off-box roundtrip report")
    remote_date = datetime.strptime(timestamp, "%Y%m%d_%H%M%S").strftime("%Y-%m-%d")
    expected_scratch = f"/var/lib/tinyzkp-backup-evidence-scratch/{bundle['run_id']}"
    if (
        report["transport"] != "rclone_crypt"
        or report["rclone_config"] != "/var/lib/tinyzkp-private/backup/rclone.conf"
        or report["remote_date"] != remote_date
        or report["upload_exit_code"] != 0
        or report["remote_object_count"] != manifest_artifact_count + 1
        or report["local_manifest_sha256"] != manifest_sha256
        or report["download_exit_code"] != 0
        or report["downloaded_manifest_sha256"] != manifest_sha256
        or report["downloaded_manifest_verified"] is not True
        or report["downloaded_artifact_digests_match_manifest"] is not True
        or report["encryption_verified"] is not True
        or report["anonymous_read_denied"] is not True
        or report["retention_verified"] is not True
        or report["scratch_download_root"] != expected_scratch
        or report["scratch_owner_uid"] != 0
        or report["scratch_mode"] != "0700"
        or report["scratch_removed"] is not True
    ):
        raise EvidenceError("off-box upload/readback semantics are invalid")


def _validate_restore(
    report: dict[str, Any],
    bundle: dict[str, Any],
    *,
    manifest_sha256: str,
    contracts_present: bool,
) -> None:
    _exact_keys(
        report,
        {
            "schema_version",
            "run_id",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "effective_uid",
            "source",
            "manifest_sha256",
            "manifest_verified",
            "scratch_root",
            "scratch_owner_uid",
            "scratch_mode",
            "production_paths_mutated",
            "checks",
            "scratch_removed",
        },
        label="scratch-restore report",
    )
    _identity_fields(report, bundle, label="scratch-restore report")
    expected_root = (
        f"/var/lib/tinyzkp-backup-evidence-scratch/{bundle['run_id']}/restore"
    )
    if (
        report["effective_uid"] != 0
        or report["source"] != "offbox_roundtrip"
        or report["manifest_sha256"] != manifest_sha256
        or report["manifest_verified"] is not True
        or report["scratch_root"] != expected_root
        or report["scratch_owner_uid"] != 0
        or report["scratch_mode"] != "0700"
        or report["production_paths_mutated"] is not False
        or report["scratch_removed"] is not True
    ):
        raise EvidenceError("scratch-restore root/manifest semantics are invalid")
    checks = report["checks"]
    expected_count = 6 if contracts_present else 5
    if not isinstance(checks, list) or len(checks) != expected_count:
        raise EvidenceError("scratch-restore semantic check set is incomplete")
    seen: set[str] = set()
    for check in checks:
        if not isinstance(check, dict) or not isinstance(check.get("target"), str):
            raise EvidenceError("scratch-restore semantic check must be an object")
        target = check["target"]
        if target in seen:
            raise EvidenceError("scratch-restore semantic check target is duplicate")
        seen.add(target)
        if target in SQLITE_RESTORE_TARGETS:
            _exact_keys(
                check,
                {
                    "target",
                    "kind",
                    "schema_profile",
                    "quick_check",
                    "schema_sha256",
                    "source_semantic_sha256",
                    "restored_semantic_sha256",
                    "source_row_count",
                    "restored_row_count",
                },
                label=f"scratch-restore check {target}",
            )
            source_digest = _digest(
                check["source_semantic_sha256"],
                label=f"{target} source semantic digest",
            )
            restored_digest = _digest(
                check["restored_semantic_sha256"],
                label=f"{target} restored semantic digest",
            )
            _digest(check["schema_sha256"], label=f"{target} schema digest")
            source_rows = _exact_int(
                check["source_row_count"],
                label=f"{target} source rows",
                minimum=0,
                maximum=10**12,
            )
            restored_rows = _exact_int(
                check["restored_row_count"],
                label=f"{target} restored rows",
                minimum=0,
                maximum=10**12,
            )
            if (
                check["kind"] != "sqlite"
                or check["schema_profile"] != SQLITE_RESTORE_TARGETS[target]
                or check["quick_check"] != "ok"
                or not hmac.compare_digest(source_digest, restored_digest)
                or source_rows != restored_rows
            ):
                raise EvidenceError(
                    f"scratch-restore SQLite semantics differ for {target}"
                )
        elif target == "api_keys.txt":
            _exact_keys(
                check,
                {
                    "target",
                    "kind",
                    "validation",
                    "source_semantic_sha256",
                    "restored_semantic_sha256",
                    "source_record_count",
                    "restored_record_count",
                },
                label="scratch-restore API-key check",
            )
            source_digest = _digest(
                check["source_semantic_sha256"], label="API-key source semantic digest"
            )
            restored_digest = _digest(
                check["restored_semantic_sha256"],
                label="API-key restored semantic digest",
            )
            source_count = _exact_int(
                check["source_record_count"],
                label="API-key source records",
                minimum=1,
                maximum=10**7,
            )
            restored_count = _exact_int(
                check["restored_record_count"],
                label="API-key restored records",
                minimum=1,
                maximum=10**7,
            )
            if (
                check["kind"] != "api_keys"
                or check["validation"] != "ok"
                or not hmac.compare_digest(source_digest, restored_digest)
                or source_count != restored_count
            ):
                raise EvidenceError("scratch-restore API-key semantics differ")
        elif target == "contracts":
            if not contracts_present:
                raise EvidenceError(
                    "scratch-restore report invents an absent contract archive"
                )
            _exact_keys(
                check,
                {
                    "target",
                    "kind",
                    "validation",
                    "source_tree_sha256",
                    "restored_tree_sha256",
                    "source_member_count",
                    "restored_member_count",
                },
                label="scratch-restore contract check",
            )
            source_digest = _digest(
                check["source_tree_sha256"], label="contract source tree digest"
            )
            restored_digest = _digest(
                check["restored_tree_sha256"], label="contract restored tree digest"
            )
            source_count = _exact_int(
                check["source_member_count"],
                label="contract source members",
                minimum=1,
                maximum=100000,
            )
            restored_count = _exact_int(
                check["restored_member_count"],
                label="contract restored members",
                minimum=1,
                maximum=100000,
            )
            if (
                check["kind"] != "contract_tree"
                or check["validation"] != "safe"
                or not hmac.compare_digest(source_digest, restored_digest)
                or source_count != restored_count
            ):
                raise EvidenceError("scratch-restore contract semantics differ")
        else:
            raise EvidenceError(f"scratch-restore target is unsupported: {target}")
    required_targets = {*SQLITE_RESTORE_TARGETS, "api_keys.txt"}
    if contracts_present:
        required_targets.add("contracts")
    if seen != required_targets:
        raise EvidenceError("scratch-restore semantic target set is incomplete")


def _validate_cleanup_matrix(
    report: dict[str, Any], bundle: dict[str, Any], *, signal_matrix: bool
) -> None:
    label = "signal cleanup matrix" if signal_matrix else "failure cleanup matrix"
    _exact_keys(
        report,
        {
            "schema_version",
            "run_id",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "cases",
        },
        label=label,
    )
    _identity_fields(report, bundle, label=label)
    cases = report["cases"]
    expected = (
        [
            (f"{signal}_{phase}", phase, exit_code, signal)
            for signal, exit_code in SIGNALS
            for phase in SIGNAL_PHASES
        ]
        if signal_matrix
        else [(case_id, phase, None, None) for case_id, phase in FAILURE_CASES]
    )
    if not isinstance(cases, list) or len(cases) != len(expected):
        raise EvidenceError(f"{label} case set is incomplete")
    for case, (case_id, phase, expected_exit, signal) in zip(cases, expected):
        if not isinstance(case, dict):
            raise EvidenceError(f"{label} case must be an object")
        expected_fields = {
            "case_id",
            "phase",
            "exit_code",
            "services_after",
            "staging_removed",
            "lock_released",
            "cleanup_verified",
            "retry_succeeded",
            "log_artifact",
        }
        if signal_matrix:
            expected_fields.add("signal")
        _exact_keys(case, expected_fields, label=f"{label} case {case_id}")
        if case["case_id"] != case_id or case["phase"] != phase:
            raise EvidenceError(f"{label} case order or identity is invalid")
        exit_code = _exact_int(
            case["exit_code"], label=f"{label} case exit code", minimum=1, maximum=255
        )
        if expected_exit is not None and exit_code != expected_exit:
            raise EvidenceError(f"{label} signal exit code is invalid")
        if signal_matrix and case["signal"] != signal.upper():
            raise EvidenceError(f"{label} signal identity is invalid")
        _active_services(case["services_after"], label=f"{label} case services")
        for key in (
            "staging_removed",
            "lock_released",
            "cleanup_verified",
            "retry_succeeded",
        ):
            _exact_bool(case[key], label=f"{label} case {key}")
        expected_log = (
            f"signal_log_{signal}_{phase}"
            if signal_matrix
            else f"failure_log_{case_id}"
        )
        if case["log_artifact"] != expected_log:
            raise EvidenceError(f"{label} case log binding is invalid")


def _validate_review(
    review: dict[str, Any],
    bundle: dict[str, Any],
    *,
    bundle_sha256: str,
    subject_sha256: str,
    captured_at: datetime,
    now: datetime,
) -> None:
    _exact_keys(
        review,
        {
            "schema_version",
            "status",
            "reviewer_name",
            "reviewer_organization",
            "independence_attested",
            "reviewed_at",
            "release_sha",
            "host_identity_sha256",
            "deployment_id",
            "run_id",
            "bundle_sha256",
            "subject_artifact_set_sha256",
            "scope",
            "open_critical_findings",
            "open_high_findings",
            "attestation_reference",
        },
        label="independent review",
    )
    _identity_fields(review, bundle, label="independent review")
    reviewer = _safe_text(
        review["reviewer_name"], label="independent reviewer", minimum=3
    )
    organization = _safe_text(
        review["reviewer_organization"], label="reviewer organization", minimum=2
    )
    if "tinyzkp" in reviewer.lower() or "tinyzkp" in organization.lower():
        raise EvidenceError("independent reviewer must be external to TinyZKP")
    reviewed_at = _parse_utc(review["reviewed_at"], label="independent review time")
    if reviewed_at < captured_at or reviewed_at > now + MAX_CLOCK_SKEW:
        raise EvidenceError("independent review time does not follow the capture")
    if (
        review["status"] != "approved"
        or review["independence_attested"] is not True
        or review["bundle_sha256"] != bundle_sha256
        or review["subject_artifact_set_sha256"] != subject_sha256
        or review["scope"] != list(REVIEW_SCOPE)
        or review["open_critical_findings"] != 0
        or review["open_high_findings"] != 0
    ):
        raise EvidenceError(
            "independent review does not approve the complete evidence subject"
        )
    _safe_text(
        review["attestation_reference"],
        label="independent review attestation reference",
        minimum=8,
        maximum=200,
    )


def validate_evidence(
    *,
    expected_release_sha: str,
    expected_host_identity_sha256: str,
    expected_deployment_id: str,
    evidence_root: pathlib.Path = FIXED_EVIDENCE_ROOT,
    required_uid: int = 0,
    now: datetime | None = None,
    enforce_fixed_host: bool = True,
    enforce_fixed_path: bool = True,
    machine_id_file: pathlib.Path = FIXED_MACHINE_ID,
) -> dict[str, object]:
    if RELEASE_RE.fullmatch(expected_release_sha) is None:
        raise EvidenceError("expected release SHA is not canonical")
    if SHA256_RE.fullmatch(expected_host_identity_sha256) is None:
        raise EvidenceError("expected host identity is not canonical")
    if DEPLOYMENT_RE.fullmatch(expected_deployment_id) is None:
        raise EvidenceError("expected deployment ID is not canonical")
    if enforce_fixed_path and evidence_root != FIXED_EVIDENCE_ROOT:
        raise EvidenceError("fixed-host evidence root path is not authorized")
    if enforce_fixed_host:
        _enforce_fixed_host(expected_host_identity_sha256, machine_id_file)
    if enforce_fixed_path:
        _validate_fixed_ancestors(evidence_root, uid=required_uid)

    root_identity = _validate_directory(
        evidence_root, uid=required_uid, label="fixed-host evidence root"
    )
    raw_root = evidence_root / FIXED_RAW_NAME
    raw_identity = _validate_directory(
        raw_root, uid=required_uid, label="raw artifact root"
    )
    root_entries = {entry.name for entry in os.scandir(evidence_root)}
    if root_entries != {FIXED_BUNDLE_NAME, FIXED_REVIEW_NAME, FIXED_RAW_NAME}:
        raise EvidenceError(
            "fixed-host evidence root contains missing or unexpected entries"
        )

    bundle_raw, _bundle_metadata = _read_private_file(
        evidence_root / FIXED_BUNDLE_NAME,
        uid=required_uid,
        label="fixed-host evidence bundle",
        limit=MAX_EVIDENCE_BYTES,
    )
    bundle = _parse_canonical_json(bundle_raw, label="fixed-host evidence bundle")
    checked_at = now or datetime.now(timezone.utc)
    captured_at = _validate_bundle_header(
        bundle,
        expected_release_sha=expected_release_sha,
        expected_host_identity=expected_host_identity_sha256,
        expected_deployment_id=expected_deployment_id,
        now=checked_at,
    )
    contents, subject_sha256 = _validate_artifact_descriptors(
        bundle, raw_root, uid=required_uid
    )

    happy = _parse_canonical_json(
        contents["happy_path_report"], label="happy-path report"
    )
    provisional_timestamp = happy.get("backup_timestamp")
    if not isinstance(provisional_timestamp, str):
        raise EvidenceError("happy-path report omits its backup timestamp")
    manifest_sha256, manifest_artifact_count, contracts_present = (
        _validate_local_manifest(contents["local_manifest"], provisional_timestamp)
    )
    timestamp = _validate_happy_path(happy, bundle, manifest_sha256, captured_at)
    _validate_lock_contention(
        _parse_canonical_json(
            contents["lock_contention_report"], label="lock-contention report"
        ),
        bundle,
    )
    _validate_staging(
        _parse_canonical_json(
            contents["service_uid_staging_report"], label="service-UID staging report"
        ),
        bundle,
        timestamp,
    )
    _validate_offbox(
        _parse_canonical_json(
            contents["offbox_roundtrip_report"], label="off-box roundtrip report"
        ),
        bundle,
        timestamp=timestamp,
        manifest_sha256=manifest_sha256,
        manifest_artifact_count=manifest_artifact_count,
    )
    _validate_restore(
        _parse_canonical_json(
            contents["scratch_restore_report"], label="scratch-restore report"
        ),
        bundle,
        manifest_sha256=manifest_sha256,
        contracts_present=contracts_present,
    )
    _validate_cleanup_matrix(
        _parse_canonical_json(
            contents["failure_cleanup_matrix"], label="failure cleanup matrix"
        ),
        bundle,
        signal_matrix=False,
    )
    _validate_cleanup_matrix(
        _parse_canonical_json(
            contents["signal_cleanup_matrix"], label="signal cleanup matrix"
        ),
        bundle,
        signal_matrix=True,
    )

    review_raw, _review_metadata = _read_private_file(
        evidence_root / FIXED_REVIEW_NAME,
        uid=required_uid,
        label="independent review",
        limit=MAX_EVIDENCE_BYTES,
    )
    review = _parse_canonical_json(review_raw, label="independent review")
    _validate_review(
        review,
        bundle,
        bundle_sha256=_sha256(bundle_raw),
        subject_sha256=subject_sha256,
        captured_at=captured_at,
        now=checked_at,
    )
    evidence_identity_sha256 = _sha256(
        _canonical_json(
            {
                "bundle_sha256": _sha256(bundle_raw),
                "review_sha256": _sha256(review_raw),
                "subject_artifact_set_sha256": subject_sha256,
            }
        )
    )

    final_root = evidence_root.lstat()
    final_raw = raw_root.lstat()
    if (final_root.st_dev, final_root.st_ino) != (
        root_identity.st_dev,
        root_identity.st_ino,
    ) or (
        final_raw.st_dev,
        final_raw.st_ino,
    ) != (raw_identity.st_dev, raw_identity.st_ino):
        raise EvidenceError(
            "fixed-host evidence directories changed during verification"
        )
    return {
        "schema_version": 1,
        "status": "reviewed_pass",
        "release_sha": expected_release_sha,
        "host_identity_sha256": expected_host_identity_sha256,
        "deployment_id": expected_deployment_id,
        "run_id": bundle["run_id"],
        "captured_at": bundle["captured_at"],
        "reviewed_at": review["reviewed_at"],
        "artifact_count": len(contents),
        "subject_artifact_set_sha256": subject_sha256,
        "evidence_identity_sha256": evidence_identity_sha256,
    }


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--expected-release-sha", required=True)
    parser.add_argument("--expected-host-identity-sha256")
    parser.add_argument("--expected-deployment-id", required=True)
    parser.add_argument(
        "--machine-id-file",
        type=pathlib.Path,
        default=FIXED_MACHINE_ID,
        help="root-owned machine-id file used to derive and cross-check the host identity",
    )
    parser.add_argument(
        "--json", action="store_true", help="emit the verified summary as JSON"
    )
    args = parser.parse_args(argv)
    try:
        derived_host_identity = _stable_host_identity(args.machine_id_file)
        if args.expected_host_identity_sha256 and not hmac.compare_digest(
            args.expected_host_identity_sha256, derived_host_identity
        ):
            raise EvidenceError(
                "explicit expected host identity differs from --machine-id-file"
            )
        report = validate_evidence(
            expected_release_sha=args.expected_release_sha,
            expected_host_identity_sha256=derived_host_identity,
            expected_deployment_id=args.expected_deployment_id,
            machine_id_file=args.machine_id_file,
        )
    except (EvidenceError, OSError) as error:
        print(f"FAIL fixed-host backup evidence - {error}", file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(report, sort_keys=True))
    else:
        print(
            "PASS fixed-host backup evidence "
            f"({report['artifact_count']} raw artifacts; run {report['run_id']})"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
