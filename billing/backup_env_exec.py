#!/usr/bin/env python3
"""Load backup settings from a private data-only env file, then exec backup.

The backup cron runs as root.  Shell-sourcing the deployment ``.env`` would
therefore turn every line in that file into root shell code.  This helper reads
the file without following symlinks, accepts assignments as inert UTF-8 data,
copies only the small backup allowlist into the child environment, and calls
``execve`` without involving a shell.
"""

from __future__ import annotations

import argparse
from datetime import datetime
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import pwd
import re
import secrets
import shutil
import sqlite3
import stat
import sys
import time
from urllib.parse import urlparse


MAX_ENV_BYTES = 64 * 1024
FIXED_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
BACKUP_ENV_MARKER = "data-only-v1"
BACKUP_CAPABILITY_ENV = "TINYZKP_BACKUP_CAPABILITY"
BACKUP_LOCK_ENV = "TINYZKP_BACKUP_LOCK_HELD"
FIXED_ENV_FILE = Path("/opt/hc-stark/.env")
FIXED_BACKUP_ROOT = Path("/opt/hc-stark/backups")
FIXED_DATA_ROOT = Path("/opt/hc-stark/data")
FIXED_CONTRACT_ROOT = Path("/var/lib/tinyzkp-private/contracts")
FIXED_BILLING_LEDGER = Path(
    "/var/lib/tinyzkp-private/billing/contract_billing.sqlite"
)
FIXED_LOADER_TOKEN = Path("/var/lib/tinyzkp-private/backup/loader-token")
FIXED_BACKUP_LOCK = Path("/var/lib/tinyzkp-private/backup/backup.lock")
FIXED_HTTP_TOKEN = Path("/var/lib/tinyzkp-private/backup/http-ingest-token")
FIXED_RCLONE_CONFIG = Path("/var/lib/tinyzkp-private/backup/rclone.conf")
FIXED_STAGING_ROOT = Path("/var/lib/tinyzkp-backup-staging")
FIXED_RESTORE_ROOT = Path("/opt/hc-stark/restore")
ASSIGNMENT = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")
SAFE_ABSOLUTE_PATH = re.compile(r"^/[A-Za-z0-9._/-]{1,4095}$")
SAFE_RCLONE_REMOTE = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}:[A-Za-z0-9._~/-]{1,1024}$"
)
SAFE_HTTPS_BASE_URL = re.compile(
    r"^https://[A-Za-z0-9.-]+(?::443)?(?:/[A-Za-z0-9._~%/-]*)?$"
)
LOCAL_PATH_KEYS = frozenset(
    {
        "HC_BACKUP_DATA_DIR",
        "HC_BACKUP_DIR",
        "HC_BACKUP_HTTP_TOKEN_FILE",
        "HC_CONTRACT_DATA_DIR",
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH",
    }
)
BACKUP_KEYS = frozenset(
    {
        "HC_BACKUP_DATA_DIR",
        "HC_BACKUP_DIR",
        "HC_BACKUP_HTTP_RETENTION_CONFIRMED",
        "HC_BACKUP_HTTP_TOKEN_FILE",
        "HC_BACKUP_HTTP_URL",
        "HC_BACKUP_REMOTE",
        "HC_BACKUP_RETENTION_DAYS",
        "HC_CONTRACT_DATA_DIR",
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH",
    }
)
BACKUP_ARTIFACT = re.compile(
    r"^(?:tenant_store|usage|evaluation_applications|contract_billing)_"
    r"[0-9]{8}_[0-9]{6}\.sqlite$"
    r"|^api_keys_[0-9]{8}_[0-9]{6}\.txt$"
    r"|^contracts_[0-9]{8}_[0-9]{6}\.tar\.gz$"
    r"|^manifest_[0-9]{8}_[0-9]{6}\.json$"
)
CURRENT_ARTIFACT_NAMES = (
    "tenant_store_{timestamp}.sqlite",
    "usage_{timestamp}.sqlite",
    "evaluation_applications_{timestamp}.sqlite",
    "contract_billing_{timestamp}.sqlite",
    "api_keys_{timestamp}.txt",
    "contracts_{timestamp}.tar.gz",
)
REQUIRED_CURRENT_ARTIFACTS = frozenset(
    {
        "tenant_store_{timestamp}.sqlite",
        "usage_{timestamp}.sqlite",
        "evaluation_applications_{timestamp}.sqlite",
        "contract_billing_{timestamp}.sqlite",
        "api_keys_{timestamp}.txt",
    }
)
SQLITE_PROFILE_COLUMNS = {
    "tenant": {
        "tenants": {"tenant_id", "api_key_hash", "status", "plan"},
        "processed_events": {"event_id", "processed_at_ms"},
        "magic_links": {"token_hash", "tenant_id", "expires_at_ms"},
        "sessions": {"token_hash", "tenant_id", "expires_at_ms"},
    },
    "usage": {
        "usage_log": {"tenant_id", "job_id", "trace_length", "billed"},
        "verify_log": {"tenant_id", "duration_ms", "completed_at_ms"},
        "failed_proofs": {"tenant_id", "job_id", "error", "failed_at_ms"},
    },
    "evaluation": {
        "evaluation_applications": {
            "application_id",
            "status",
            "retention_deadline",
            "qualification_json",
        }
    },
    "contract": {
        "billing_operations": {
            "operation_key",
            "plan_sha256",
            "action",
            "phase",
        }
    },
}
PROTECTED_BACKUP_ROOTS = tuple(
    Path(path)
    for path in (
        "/",
        "/Applications",
        "/Library",
        "/System",
        "/bin",
        "/boot",
        "/dev",
        "/etc",
        "/lib",
        "/lib64",
        "/proc",
        "/root",
        "/run",
        "/sbin",
        "/sys",
        "/usr",
    )
)


class BackupEnvError(ValueError):
    """A deployment env file is unsafe or is not data-only."""


def _validate_private_parent(path: Path, label: str) -> None:
    absolute = path.absolute()
    parent = absolute.parent
    try:
        parent_metadata = os.lstat(parent)
        resolved_parent = parent.resolve(strict=True)
    except OSError as error:
        raise BackupEnvError(f"{label} parent is unavailable or unsafe") from error
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or (os.geteuid() == 0 and resolved_parent != parent)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise BackupEnvError(
            f"{label} parent must be current-owner, non-writable, and symlink-free"
        )


def read_private_file(path: Path, *, label: str, max_bytes: int) -> bytes:
    """Read one unique owner-only regular file without following symlinks."""

    _validate_private_parent(path, label)

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BackupEnvError(
            f"{label} is unavailable or unsafe: {path}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BackupEnvError(f"{label} must be a regular non-symlink file")
        if metadata.st_nlink != 1:
            raise BackupEnvError(f"{label} must have exactly one hard link")
        if metadata.st_uid != os.geteuid():
            raise BackupEnvError(f"{label} must be owned by the current operator")
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BackupEnvError(f"{label} must be owner-only (0600 or stricter)")
        chunks = bytearray()
        while len(chunks) <= max_bytes:
            chunk = os.read(
                descriptor,
                min(8192, max_bytes + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
    finally:
        os.close(descriptor)
    if not raw:
        raise BackupEnvError(f"{label} is empty")
    if len(raw) > max_bytes:
        raise BackupEnvError(f"{label} exceeds {max_bytes} bytes")
    return raw


def read_private_env(path: Path) -> bytes:
    return read_private_file(path, label="backup env file", max_bytes=MAX_ENV_BYTES)


def parse_data_assignments(raw: bytes) -> dict[str, str]:
    """Parse simple KEY=value records; values are never expanded or executed."""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise BackupEnvError("backup env file must be UTF-8") from error
    if "\x00" in text:
        raise BackupEnvError("backup env file contains a NUL byte")

    parsed: dict[str, str] = {}
    seen: set[str] = set()
    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = ASSIGNMENT.fullmatch(line)
        if match is None:
            raise BackupEnvError(
                f"backup env line {line_number} is not a data-only KEY=value assignment"
            )
        key, value = match.groups()
        if key in seen:
            raise BackupEnvError(f"backup env key is duplicated: {key}")
        seen.add(key)
        value = value.strip()
        if value[:1] in {"'", '"'}:
            if len(value) < 2 or value[-1] != value[0]:
                raise BackupEnvError(
                    f"backup env line {line_number} has an unterminated quoted value"
                )
            value = value[1:-1]
        elif value[-1:] in {"'", '"'}:
            raise BackupEnvError(f"backup env line {line_number} has a stray quote")
        if any(ord(character) < 0x20 for character in value):
            raise BackupEnvError(
                f"backup env line {line_number} contains a control character"
            )
        parsed[key] = value
    return parsed


def parse_data_env(raw: bytes, *, production: bool = False) -> dict[str, str]:
    settings = {
        key: value
        for key, value in parse_data_assignments(raw).items()
        if key in BACKUP_KEYS
    }
    validate_backup_values(settings, production=production)
    return settings


def validate_backup_values(
    settings: dict[str, str], *, production: bool = False
) -> None:
    """Reject ambiguous or command-shaped backup configuration as data."""

    for key in LOCAL_PATH_KEYS:
        value = settings.get(key, "")
        if not value:
            continue
        if SAFE_ABSOLUTE_PATH.fullmatch(value) is None or ".." in Path(value).parts:
            raise BackupEnvError(f"{key} must be a safe absolute local path")

    retention = settings.get("HC_BACKUP_RETENTION_DAYS", "")
    if retention and (
        re.fullmatch(r"[1-9][0-9]{0,3}", retention) is None
        or int(retention) > 3650
    ):
        raise BackupEnvError(
            "HC_BACKUP_RETENTION_DAYS must be an integer from 1 through 3650"
        )

    remote = settings.get("HC_BACKUP_REMOTE", "")
    if remote and (
        SAFE_RCLONE_REMOTE.fullmatch(remote) is None
        or ".." in remote.split(":", 1)[1].split("/")
    ):
        raise BackupEnvError("HC_BACKUP_REMOTE is malformed or exceeds its limit")

    http_url = settings.get("HC_BACKUP_HTTP_URL", "")
    token_file = settings.get("HC_BACKUP_HTTP_TOKEN_FILE", "")
    if bool(http_url) != bool(token_file):
        raise BackupEnvError(
            "HC_BACKUP_HTTP_URL and HC_BACKUP_HTTP_TOKEN_FILE must be configured together"
        )
    if http_url:
        try:
            parsed = urlparse(http_url)
            port = parsed.port
        except ValueError as error:
            raise BackupEnvError("HC_BACKUP_HTTP_URL is malformed") from error
        if (
            len(http_url) > 2048
            or parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or parsed.query
            or port not in {None, 443}
            or SAFE_HTTPS_BASE_URL.fullmatch(http_url) is None
            or ".." in Path(parsed.path).parts
            or any(character.isspace() for character in http_url)
        ):
            raise BackupEnvError(
                "HC_BACKUP_HTTP_URL must be a credential-free HTTPS base URL"
            )
        if settings.get("HC_BACKUP_HTTP_RETENTION_CONFIRMED") != "1":
            raise BackupEnvError(
                "HC_BACKUP_HTTP_RETENTION_CONFIRMED must equal 1 for HTTP backups"
            )
    elif settings.get("HC_BACKUP_HTTP_RETENTION_CONFIRMED", "") not in {"", "0"}:
        raise BackupEnvError(
            "HC_BACKUP_HTTP_RETENTION_CONFIRMED is valid only for HTTP backups"
        )
    if remote and http_url:
        raise BackupEnvError("configure exactly one off-box backup transport")
    if production and token_file and Path(token_file) != FIXED_HTTP_TOKEN:
        raise BackupEnvError(
            f"HC_BACKUP_HTTP_TOKEN_FILE must be exactly {FIXED_HTTP_TOKEN}"
        )
    production_paths = {
        "HC_BACKUP_DIR": FIXED_BACKUP_ROOT,
        "HC_BACKUP_DATA_DIR": FIXED_DATA_ROOT,
        "HC_CONTRACT_DATA_DIR": FIXED_CONTRACT_ROOT,
        "TINYZKP_CONTRACT_BILLING_LEDGER_PATH": FIXED_BILLING_LEDGER,
    }
    if production and os.geteuid() == 0:
        for key, expected in production_paths.items():
            if settings.get(key) and Path(settings[key]) != expected:
                raise BackupEnvError(f"{key} must be exactly {expected}")


def environment_for_backup(
    path: Path,
    inherited: dict[str, str],
    *,
    test_timestamp: str | None = None,
    test_remote_date: str | None = None,
) -> dict[str, str]:
    """Build the complete backup child environment from trusted constants/data.

    ``inherited`` is intentionally ignored.  In particular, caller-provided
    PATH, dynamic-loader/Python injection variables, timestamp overrides and a
    forged loader marker must never cross the privilege boundary.
    """

    del inherited
    if os.geteuid() == 0 and path != FIXED_ENV_FILE:
        raise BackupEnvError(f"production backup env must be exactly {FIXED_ENV_FILE}")
    environment = {
        "PATH": FIXED_PATH,
        "LANG": "C",
        "LC_ALL": "C",
        "TZ": "UTC",
    }
    environment.update(
        parse_data_env(read_private_env(path), production=os.geteuid() == 0)
    )
    environment["RCLONE_CONFIG"] = str(FIXED_RCLONE_CONFIG)
    if test_timestamp is not None or test_remote_date is not None:
        if os.geteuid() == 0 or not test_timestamp or not test_remote_date:
            raise BackupEnvError("backup date overrides are available only to non-root tests")
        validate_backup_dates(test_timestamp, test_remote_date)
        environment["HC_BACKUP_DATE"] = test_timestamp
        environment["HC_BACKUP_REMOTE_DATE"] = test_remote_date
    environment["TINYZKP_BACKUP_ENV_LOADED"] = BACKUP_ENV_MARKER
    return environment


def read_loader_token(path: Path) -> str:
    raw = read_private_file(path, label="backup loader token", max_bytes=128)
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BackupEnvError("backup loader token must be ASCII") from error
    if re.fullmatch(r"[0-9a-f]{64}", token) is None:
        raise BackupEnvError("backup loader token must be 32 random bytes in hex")
    return token


def acquire_backup_lock(path: Path, *, production: bool = False) -> int:
    """Acquire the process-wide backup lock and return its inheritable fd.

    The descriptor deliberately survives the loader's ``execve`` so the shell
    holds the same open-file-description lock until the complete backup exits.
    """

    if production and (os.geteuid() != 0 or path != FIXED_BACKUP_LOCK):
        raise BackupEnvError(
            f"production backup lock requires root and the fixed path {FIXED_BACKUP_LOCK}"
        )
    _validate_private_parent(path, "backup process lock")
    flags = (
        os.O_RDWR
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise BackupEnvError("backup process lock is unavailable or unsafe") from error
    try:
        metadata = os.fstat(descriptor)
        expected_owner = 0 if production else os.geteuid()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != expected_owner
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise BackupEnvError(
                "backup process lock must be a unique owner-only regular file"
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise BackupEnvError("another TinyZKP backup is already active") from error
        os.set_inheritable(descriptor, True)
        return descriptor
    except Exception:
        os.close(descriptor)
        raise


def read_http_token(path: Path, *, production: bool = False) -> str:
    if production and path != FIXED_HTTP_TOKEN:
        raise BackupEnvError(
            f"HTTP backup token must be exactly {FIXED_HTTP_TOKEN}"
        )
    raw = read_private_file(path, label="HTTP backup token", max_bytes=1024)
    try:
        token = raw.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BackupEnvError("HTTP backup token must be ASCII") from error
    if not 32 <= len(token) <= 512 or re.fullmatch(r"[A-Za-z0-9._~-]+", token) is None:
        raise BackupEnvError("HTTP backup token has invalid length or characters")
    return token


def create_loader_token(path: Path) -> None:
    if path != FIXED_LOADER_TOKEN:
        raise BackupEnvError(f"loader token path must be exactly {FIXED_LOADER_TOKEN}")
    _validate_private_parent(path, "backup loader token")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        payload = (secrets.token_hex(32) + "\n").encode("ascii")
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise BackupEnvError("could not write backup loader token")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.chmod(path, 0o600, follow_symlinks=False)


def create_staging_directory(path: Path, uid: int, gid: int) -> None:
    if os.geteuid() != 0:
        raise BackupEnvError("backup staging creation requires root")
    if path.parent != FIXED_STAGING_ROOT or re.fullmatch(
        r"run_[0-9]{8}_[0-9]{6}", path.name
    ) is None:
        raise BackupEnvError("backup staging path is not canonical")
    parent = os.lstat(FIXED_STAGING_ROOT)
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or parent.st_gid != gid
        or stat.S_IMODE(parent.st_mode) != 0o710
    ):
        raise BackupEnvError("backup staging root must be root-owned mode 0710")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor = os.open(FIXED_STAGING_ROOT, flags)
    try:
        os.mkdir(path.name, mode=0o700, dir_fd=parent_descriptor)
        os.chown(
            path.name,
            uid,
            gid,
            dir_fd=parent_descriptor,
            follow_symlinks=False,
        )
        metadata = os.stat(
            path.name, dir_fd=parent_descriptor, follow_symlinks=False
        )
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise BackupEnvError("backup staging leaf ownership is invalid")
        os.fsync(parent_descriptor)
    finally:
        os.close(parent_descriptor)


def remove_staging_directory(path: Path) -> None:
    if os.geteuid() != 0 or path.parent != FIXED_STAGING_ROOT:
        raise BackupEnvError("backup staging removal requires the fixed root")
    if re.fullmatch(r"run_[0-9]{8}_[0-9]{6}", path.name) is None:
        raise BackupEnvError("backup staging path is not canonical")
    parent = os.lstat(FIXED_STAGING_ROOT)
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != 0
        or stat.S_IMODE(parent.st_mode) != 0o710
    ):
        raise BackupEnvError("backup staging root is unsafe")
    if path.exists() or path.is_symlink():
        metadata = os.lstat(path)
        if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISDIR(metadata.st_mode):
            raise BackupEnvError("backup staging leaf is unsafe")
        shutil.rmtree(path)
        _fsync_parent(path)


def ensure_service_data_root(path: Path, uid: int, gid: int) -> None:
    if os.geteuid() != 0 or path != FIXED_DATA_ROOT:
        raise BackupEnvError("service data root requires root and the fixed path")
    parent = path.parent
    parent_metadata = os.lstat(parent)
    if (
        stat.S_ISLNK(parent_metadata.st_mode)
        or not stat.S_ISDIR(parent_metadata.st_mode)
        or parent_metadata.st_uid != 0
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise BackupEnvError("service data parent is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(parent, flags)
    try:
        try:
            metadata = os.stat(path.name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            os.mkdir(path.name, mode=0o700, dir_fd=descriptor)
            os.chown(
                path.name, uid, gid, dir_fd=descriptor, follow_symlinks=False
            )
            metadata = os.stat(
                path.name, dir_fd=descriptor, follow_symlinks=False
            )
            os.fsync(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise BackupEnvError("service data root ownership is invalid")
    finally:
        os.close(descriptor)


def _normalized_absolute(path: Path, label: str) -> Path:
    raw = str(path)
    if SAFE_ABSOLUTE_PATH.fullmatch(raw) is None or ".." in path.parts:
        raise BackupEnvError(f"{label} must be a safe absolute local path")
    return Path(os.path.normpath(raw))


def _overlaps(first: Path, second: Path) -> bool:
    return first == second or first in second.parents or second in first.parents


def _reject_symlink_components(path: Path, *, allow_missing_leaf: bool = False) -> None:
    current = Path(path.anchor)
    for index, part in enumerate(path.parts[1:]):
        current /= part
        try:
            metadata = os.lstat(current)
        except FileNotFoundError:
            if allow_missing_leaf and index == len(path.parts[1:]) - 1:
                return
            raise BackupEnvError(f"path component does not exist: {current}")
        if stat.S_ISLNK(metadata.st_mode):
            raise BackupEnvError(f"path contains a symlink component: {current}")


def _validate_regular_file(path: Path, label: str) -> None:
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise BackupEnvError(f"{label} must be a regular non-symlink file")
    if metadata.st_nlink != 1:
        raise BackupEnvError(f"{label} must not be hard-linked")


def _allowed_source_owner_ids() -> set[int]:
    owners = {os.geteuid()}
    if os.geteuid() == 0:
        try:
            owners.add(pwd.getpwnam("tinyzkp-billing").pw_uid)
        except KeyError:
            pass
    return owners


def _source_metadata(path: Path, descriptor: int, label: str) -> os.stat_result:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise BackupEnvError(f"{label} changed or is not a unique regular file")
    if metadata.st_uid not in _allowed_source_owner_ids():
        raise BackupEnvError(f"{label} has an unexpected owner")
    if stat.S_IMODE(metadata.st_mode) & 0o077:
        raise BackupEnvError(f"{label} must be owner-only")
    try:
        path_metadata = os.lstat(path)
    except OSError as error:
        raise BackupEnvError(f"{label} changed while it was opened") from error
    if (
        path_metadata.st_dev != metadata.st_dev
        or path_metadata.st_ino != metadata.st_ino
        or stat.S_ISLNK(path_metadata.st_mode)
    ):
        raise BackupEnvError(f"{label} identity changed while it was opened")
    return metadata


def _fsync_parent(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path.parent, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_backup_dates(timestamp: str, remote_date: str) -> None:
    """Require semantically valid, mutually consistent canonical UTC dates."""

    try:
        parsed_timestamp = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
    except ValueError as error:
        raise BackupEnvError(
            "backup timestamp must use canonical UTC YYYYMMDD_HHMMSS format"
        ) from error
    try:
        parsed_remote = datetime.strptime(remote_date, "%Y-%m-%d")
    except ValueError as error:
        raise BackupEnvError(
            "backup remote date must use canonical UTC YYYY-MM-DD format"
        ) from error
    if parsed_timestamp.strftime("%Y%m%d_%H%M%S") != timestamp:
        raise BackupEnvError(
            "backup timestamp must use canonical UTC YYYYMMDD_HHMMSS format"
        )
    if parsed_remote.strftime("%Y-%m-%d") != remote_date:
        raise BackupEnvError(
            "backup remote date must use canonical UTC YYYY-MM-DD format"
        )
    if parsed_timestamp.date() != parsed_remote.date():
        raise BackupEnvError("backup timestamp and remote date must identify the same UTC day")


def validate_backup_layout(
    *,
    backup_dir: Path,
    data_dir: Path,
    contract_dir: Path,
    billing_ledger_path: Path,
    script_dir: Path,
    timestamp: str,
) -> None:
    """Prepare and validate an isolated backup root and all local sources."""

    backup = _normalized_absolute(backup_dir, "backup directory")
    if os.geteuid() == 0 and backup != FIXED_BACKUP_ROOT:
        raise BackupEnvError(
            f"production backup directory must be exactly {FIXED_BACKUP_ROOT}"
        )
    data = _normalized_absolute(data_dir, "backup data directory")
    contracts = _normalized_absolute(contract_dir, "contract directory")
    ledger = _normalized_absolute(billing_ledger_path, "billing ledger path")
    scripts = _normalized_absolute(script_dir, "backup script directory")

    for protected in PROTECTED_BACKUP_ROOTS:
        if backup == protected or (protected != Path("/") and protected in backup.parents):
            raise BackupEnvError(
                f"backup directory is inside a protected system root: {protected}"
            )
    for label, source in (
        ("backup data directory", data),
        ("contract directory", contracts),
        ("billing ledger", ledger),
        ("backup script directory", scripts),
    ):
        if _overlaps(backup, source):
            raise BackupEnvError(f"backup directory overlaps {label}")

    _reject_symlink_components(backup, allow_missing_leaf=True)
    if not backup.exists():
        parent_metadata = os.lstat(backup.parent)
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(parent_metadata.st_mode) & 0o022
        ):
            raise BackupEnvError(
                "backup directory parent must be operator-owned and not group/world-writable"
            )
        os.mkdir(backup, mode=0o700)

    root_metadata = os.lstat(backup)
    if stat.S_ISLNK(root_metadata.st_mode) or not stat.S_ISDIR(root_metadata.st_mode):
        raise BackupEnvError("backup directory must be a real directory, not a symlink")
    if root_metadata.st_uid != os.geteuid():
        raise BackupEnvError("backup directory must be owned by the current operator")
    if stat.S_IMODE(root_metadata.st_mode) & 0o077:
        raise BackupEnvError("backup directory must be owner-only (0700 or stricter)")

    for entry in os.scandir(backup):
        metadata = entry.stat(follow_symlinks=False)
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise BackupEnvError("backup directory contains a non-regular artifact")
        if metadata.st_uid != os.geteuid() or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BackupEnvError("backup artifact is not owner-only")
        if metadata.st_nlink != 1:
            raise BackupEnvError("backup artifact must not be hard-linked")
        if BACKUP_ARTIFACT.fullmatch(entry.name) is None:
            raise BackupEnvError("backup directory contains an unrecognized artifact")
        if f"_{timestamp}." in entry.name:
            raise BackupEnvError("backup artifact for this timestamp already exists")

    for label, directory in (
        ("backup data directory", data),
        ("contract directory", contracts),
        ("backup script directory", scripts),
    ):
        if directory.exists():
            _reject_symlink_components(directory)
            if not directory.is_dir():
                raise BackupEnvError(f"{label} must be a directory")

    for name in (
        "tenant_store.sqlite",
        "usage.sqlite",
        "evaluation_applications.sqlite",
        "api_keys.txt",
    ):
        source = data / name
        if source.exists() or source.is_symlink():
            _validate_regular_file(source, f"source {name}")
    if ledger.exists() or ledger.is_symlink():
        _reject_symlink_components(ledger)
        _validate_regular_file(ledger, "billing ledger")
    if contracts.exists():
        for root, directories, files in os.walk(contracts, followlinks=False):
            for name in directories:
                child = Path(root) / name
                metadata = os.lstat(child)
                if stat.S_ISLNK(metadata.st_mode):
                    raise BackupEnvError("contract directory contains a symlink")
            for name in files:
                child = Path(root) / name
                if child.is_symlink():
                    raise BackupEnvError("contract directory contains a symlink")
                _validate_regular_file(child, "contract file")


def prune_backup_artifacts(backup_dir: Path, retention_days: int) -> int:
    """Delete only exact TinyZKP artifact names older than the cutoff."""

    if not 1 <= retention_days <= 3650:
        raise BackupEnvError("retention days must be from 1 through 3650")
    backup = _normalized_absolute(backup_dir, "backup directory")
    if os.geteuid() == 0 and backup != FIXED_BACKUP_ROOT:
        raise BackupEnvError(
            f"production backup directory must be exactly {FIXED_BACKUP_ROOT}"
        )
    cutoff = time.time() - retention_days * 86400
    removed = 0
    for entry in os.scandir(backup):
        if BACKUP_ARTIFACT.fullmatch(entry.name) is None:
            continue
        metadata = entry.stat(follow_symlinks=False)
        if entry.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise BackupEnvError("refusing to prune a non-regular backup artifact")
        if metadata.st_nlink != 1:
            raise BackupEnvError("refusing to prune a hard-linked backup artifact")
        if metadata.st_mtime < cutoff:
            os.unlink(entry.path)
            removed += 1
    return removed


def snapshot_source(source: Path, destination: Path, kind: str) -> None:
    """Create one race-resistant O_EXCL snapshot while preserving SQLite WAL data."""

    source = _normalized_absolute(source, "backup source")
    destination = _normalized_absolute(destination, "backup destination")
    _reject_symlink_components(source.parent)
    _validate_private_parent(destination, "backup destination")
    parent_metadata = os.lstat(source.parent)
    owner_is_safe = parent_metadata.st_uid in _allowed_source_owner_ids()
    if os.geteuid() == 0 and kind == "sqlite":
        owner_is_safe = parent_metadata.st_uid == os.geteuid()
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or not owner_is_safe
        or stat.S_IMODE(parent_metadata.st_mode) & 0o077
    ):
        raise BackupEnvError("backup source parent must be private and operator-controlled")

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    destination_flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        destination_flags |= os.O_NOFOLLOW
    source_descriptor = os.open(source, source_flags)
    created = False
    destination_identity: tuple[int, int] | None = None
    try:
        source_metadata = _source_metadata(source, source_descriptor, "backup source")
        destination_descriptor = os.open(destination, destination_flags, 0o600)
        created = True
        destination_metadata = os.fstat(destination_descriptor)
        destination_identity = (destination_metadata.st_dev, destination_metadata.st_ino)
        try:
            if kind == "copy":
                source_digest = hashlib.sha256()
                while True:
                    chunk = os.read(source_descriptor, 1024 * 1024)
                    if not chunk:
                        break
                    source_digest.update(chunk)
                    view = memoryview(chunk)
                    while view:
                        count = os.write(destination_descriptor, view)
                        if count <= 0:
                            raise BackupEnvError("backup snapshot write was incomplete")
                        view = view[count:]
                os.fsync(destination_descriptor)
            elif kind != "sqlite":
                raise BackupEnvError("unknown backup snapshot kind")
        finally:
            os.close(destination_descriptor)

        if kind == "sqlite":
            # SQLite must open the real basename so sibling -wal/-shm files remain
            # visible.  The held descriptor plus immediate before/after identity
            # checks prevents a path replacement from being accepted silently.
            with sqlite3.connect(
                f"file:{source}?mode=ro", uri=True
            ) as source_connection:
                source_connection.execute("PRAGMA schema_version").fetchone()
                current = _source_metadata(source, source_descriptor, "SQLite source")
                if (current.st_dev, current.st_ino) != (
                    source_metadata.st_dev,
                    source_metadata.st_ino,
                ):
                    raise BackupEnvError("SQLite source identity changed before backup")
                with sqlite3.connect(destination) as destination_connection:
                    source_connection.backup(destination_connection)
                    destination_connection.commit()
                final_source = _source_metadata(
                    source, source_descriptor, "SQLite source"
                )
                if (final_source.st_dev, final_source.st_ino) != (
                    source_metadata.st_dev,
                    source_metadata.st_ino,
                ):
                    raise BackupEnvError("SQLite source identity changed during backup")
            with destination.open("rb") as destination_file:
                os.fsync(destination_file.fileno())
        else:
            with destination.open("rb") as destination_file:
                destination_digest = hashlib.sha256()
                while chunk := destination_file.read(1024 * 1024):
                    destination_digest.update(chunk)
            if not hmac.compare_digest(
                source_digest.digest(), destination_digest.digest()
            ):
                raise BackupEnvError("backup snapshot digest mismatch")

        final_metadata = os.lstat(destination)
        if (
            destination_identity is None
            or (final_metadata.st_dev, final_metadata.st_ino) != destination_identity
            or not stat.S_ISREG(final_metadata.st_mode)
            or final_metadata.st_nlink != 1
        ):
            raise BackupEnvError("backup destination identity changed")
        os.chmod(destination, 0o600, follow_symlinks=False)
        _fsync_parent(destination)
    except Exception:
        if created:
            try:
                current = os.lstat(destination)
                if destination_identity == (current.st_dev, current.st_ino):
                    os.unlink(destination)
            except FileNotFoundError:
                pass
        raise
    finally:
        os.close(source_descriptor)


def validate_sqlite_source(path: Path, profile: str) -> None:
    required = SQLITE_PROFILE_COLUMNS.get(profile)
    if required is None:
        raise BackupEnvError("unknown SQLite backup profile")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = _source_metadata(path, descriptor, "SQLite readiness source")
        parent = os.lstat(path.parent)
        if os.geteuid() == 0 and parent.st_uid != 0:
            raise BackupEnvError(
                "root must validate service SQLite through the service UID"
            )
        try:
            with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as connection:
                connection.execute("PRAGMA query_only=ON")
                check = connection.execute("PRAGMA quick_check").fetchall()
                if check != [("ok",)]:
                    raise BackupEnvError("SQLite backup source failed quick_check")
                for table, expected_columns in required.items():
                    row = connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?",
                        (table,),
                    ).fetchone()
                    if row is None:
                        raise BackupEnvError(
                            f"SQLite backup source is missing table {table}"
                        )
                    columns = {
                        str(item[1])
                        for item in connection.execute(
                            f'PRAGMA table_info("{table}")'
                        ).fetchall()
                    }
                    if not expected_columns.issubset(columns):
                        raise BackupEnvError(
                            f"SQLite backup source has an invalid {table} schema"
                        )
        except sqlite3.Error as error:
            raise BackupEnvError("SQLite backup source is unreadable") from error
        final = _source_metadata(path, descriptor, "SQLite readiness source")
        if (final.st_dev, final.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise BackupEnvError("SQLite readiness source identity changed")
    finally:
        os.close(descriptor)


def validate_api_key_source(path: Path) -> None:
    raw = read_private_file(path, label="API key backup source", max_bytes=4 * 1024 * 1024)
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise BackupEnvError("API key backup source must be UTF-8") from error
    seen: set[str] = set()
    records = 0
    for line in lines:
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if (
            len(parts) not in {2, 3}
            or any(not part or len(part) > 256 for part in parts)
            or any(re.fullmatch(r"[A-Za-z0-9._~-]+", part) is None for part in parts)
            or parts[0] in seen
        ):
            raise BackupEnvError("API key backup source contains a malformed record")
        seen.add(parts[0])
        records += 1
    if records == 0:
        raise BackupEnvError("API key backup source contains no active key records")


def restore_artifact(source: Path, destination: Path, uid: int, gid: int) -> None:
    """Atomically replace one fixed durable file while excluding its service UID."""

    if os.geteuid() != 0:
        raise BackupEnvError("durable restore requires root")
    allowed_data_names = {
        "tenant_store.sqlite",
        "usage.sqlite",
        "evaluation_applications.sqlite",
        "api_keys.txt",
    }
    is_service_data = (
        destination.parent == FIXED_DATA_ROOT
        and destination.name in allowed_data_names
    )
    is_root_ledger = destination == FIXED_BILLING_LEDGER
    if not is_service_data and not is_root_ledger:
        raise BackupEnvError("restore destination is not a fixed durable path")
    if is_root_ledger and (uid != 0 or gid != 0):
        raise BackupEnvError("contract ledger restore must remain root-owned")
    source_prefix = destination.stem
    source_suffix = destination.suffix
    if destination.name == "api_keys.txt":
        source_prefix, source_suffix = "api_keys", ".txt"
    if (
        source.parent != FIXED_RESTORE_ROOT
        or re.fullmatch(
            re.escape(source_prefix)
            + r"_[0-9]{8}_[0-9]{6}"
            + re.escape(source_suffix),
            source.name,
        )
        is None
    ):
        raise BackupEnvError("restore source is not a canonical staged artifact")
    _validate_private_parent(source, "restore source")

    source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        source_flags |= os.O_NOFOLLOW
        directory_flags |= os.O_NOFOLLOW
    if hasattr(os, "O_DIRECTORY"):
        directory_flags |= os.O_DIRECTORY
    source_descriptor = os.open(source, source_flags)
    directory_descriptor = os.open(destination.parent, directory_flags)
    temporary_name = f".tinyzkp-restore-{secrets.token_hex(16)}"
    temporary_created = False
    parent_metadata = os.fstat(directory_descriptor)
    original_uid = parent_metadata.st_uid
    original_gid = parent_metadata.st_gid
    original_mode = stat.S_IMODE(parent_metadata.st_mode)
    try:
        source_metadata = os.fstat(source_descriptor)
        if (
            not stat.S_ISREG(source_metadata.st_mode)
            or source_metadata.st_nlink != 1
            or source_metadata.st_uid != 0
            or stat.S_IMODE(source_metadata.st_mode) & 0o077
        ):
            raise BackupEnvError("restore source must be a unique root-private file")
        if not stat.S_ISDIR(parent_metadata.st_mode) or original_mode & 0o077:
            raise BackupEnvError("restore destination parent must be owner-only")
        if is_service_data and (original_uid != uid or original_gid != gid):
            raise BackupEnvError("service data directory ownership is unexpected")
        if is_root_ledger and original_uid != 0:
            raise BackupEnvError("contract ledger directory must be root-owned")

        os.fchown(directory_descriptor, 0, 0)
        os.fchmod(directory_descriptor, 0o700)
        destination_flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
        )
        if hasattr(os, "O_NOFOLLOW"):
            destination_flags |= os.O_NOFOLLOW
        output = os.open(
            temporary_name,
            destination_flags,
            0o600,
            dir_fd=directory_descriptor,
        )
        temporary_created = True
        try:
            while chunk := os.read(source_descriptor, 1024 * 1024):
                view = memoryview(chunk)
                while view:
                    count = os.write(output, view)
                    if count <= 0:
                        raise BackupEnvError("restore artifact write was incomplete")
                    view = view[count:]
            os.fsync(output)
        finally:
            os.close(output)
        os.chown(
            temporary_name,
            uid,
            gid,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        os.rename(
            temporary_name,
            destination.name,
            src_dir_fd=directory_descriptor,
            dst_dir_fd=directory_descriptor,
        )
        temporary_created = False
        for suffix in ("-wal", "-shm"):
            try:
                os.unlink(destination.name + suffix, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        final = os.stat(
            destination.name,
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != uid
            or final.st_gid != gid
            or stat.S_IMODE(final.st_mode) != 0o600
        ):
            raise BackupEnvError("restored artifact identity is invalid")
        os.fsync(directory_descriptor)
    finally:
        if temporary_created:
            try:
                os.unlink(temporary_name, dir_fd=directory_descriptor)
            except FileNotFoundError:
                pass
        os.fchown(directory_descriptor, original_uid, original_gid)
        os.fchmod(directory_descriptor, original_mode)
        os.fsync(directory_descriptor)
        os.close(directory_descriptor)
        os.close(source_descriptor)


def _artifact_digest(path: Path) -> tuple[str, int]:
    _validate_private_parent(path, "backup artifact")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise BackupEnvError("backup artifact is not a unique owner-only file")
        digest = hashlib.sha256()
        total = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
            total += len(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest(), total


def create_backup_manifest(backup_dir: Path, timestamp: str) -> Path:
    """Create a canonical manifest for the complete current backup run."""

    try:
        parsed = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
    except ValueError as error:
        raise BackupEnvError("backup timestamp is invalid") from error
    validate_backup_dates(timestamp, parsed.strftime("%Y-%m-%d"))
    backup = _normalized_absolute(backup_dir, "backup directory")
    if os.geteuid() == 0 and backup != FIXED_BACKUP_ROOT:
        raise BackupEnvError(
            f"production backup directory must be exactly {FIXED_BACKUP_ROOT}"
        )
    expected = [name.format(timestamp=timestamp) for name in CURRENT_ARTIFACT_NAMES]
    required = {
        name.format(timestamp=timestamp) for name in REQUIRED_CURRENT_ARTIFACTS
    }
    present = [name for name in expected if (backup / name).exists()]
    missing = sorted(required.difference(present))
    if missing:
        raise BackupEnvError(
            "required current-run backup artifacts are missing: " + ", ".join(missing)
        )
    artifacts = []
    for name in present:
        digest, size = _artifact_digest(backup / name)
        artifacts.append({"name": name, "sha256": digest, "size": size})
    payload = {
        "schema_version": 1,
        "timestamp": timestamp,
        "required_artifacts": sorted(required),
        "artifacts": artifacts,
    }
    destination = backup / f"manifest_{timestamp}.json"
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(destination, flags, 0o600)
    try:
        view = memoryview(encoded)
        while view:
            count = os.write(descriptor, view)
            if count <= 0:
                raise BackupEnvError("backup manifest write was incomplete")
            view = view[count:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_parent(destination)
    return destination


def verify_backup_manifest(path: Path) -> dict[str, object]:
    raw = read_private_file(path, label="backup manifest", max_bytes=64 * 1024)

    def reject_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise BackupEnvError(f"backup manifest key is duplicated: {key}")
            result[key] = value
        return result

    try:
        payload = json.loads(raw, object_pairs_hook=reject_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BackupEnvError("backup manifest is not canonical JSON") from error
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "timestamp",
        "required_artifacts",
        "artifacts",
    }:
        raise BackupEnvError("backup manifest fields are invalid")
    timestamp = payload["timestamp"]
    if type(payload["schema_version"]) is not int or payload["schema_version"] != 1 or not isinstance(timestamp, str):
        raise BackupEnvError("backup manifest version or timestamp is invalid")
    try:
        parsed = datetime.strptime(timestamp, "%Y%m%d_%H%M%S")
    except ValueError as error:
        raise BackupEnvError("backup manifest timestamp is invalid") from error
    validate_backup_dates(timestamp, parsed.strftime("%Y-%m-%d"))
    if path.name != f"manifest_{timestamp}.json":
        raise BackupEnvError("backup manifest filename does not match its timestamp")
    required = {
        name.format(timestamp=timestamp) for name in REQUIRED_CURRENT_ARTIFACTS
    }
    if payload["required_artifacts"] != sorted(required):
        raise BackupEnvError("backup manifest required artifact policy is invalid")
    artifacts = payload["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) < len(required):
        raise BackupEnvError("backup manifest artifact set is incomplete")
    seen: set[str] = set()
    for artifact in artifacts:
        if not isinstance(artifact, dict) or set(artifact) != {"name", "sha256", "size"}:
            raise BackupEnvError("backup manifest artifact record is invalid")
        name = artifact["name"]
        digest = artifact["sha256"]
        size = artifact["size"]
        if (
            not isinstance(name, str)
            or name not in [item.format(timestamp=timestamp) for item in CURRENT_ARTIFACT_NAMES]
            or name in seen
            or not isinstance(digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", digest) is None
            or type(size) is not int
            or size < 0
        ):
            raise BackupEnvError("backup manifest artifact record is invalid")
        seen.add(name)
        actual_digest, actual_size = _artifact_digest(path.parent / name)
        if not hmac.compare_digest(digest, actual_digest) or size != actual_size:
            raise BackupEnvError(f"backup manifest digest mismatch: {name}")
    if not required.issubset(seen):
        raise BackupEnvError("backup manifest is missing required artifacts")
    canonical = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != canonical:
        raise BackupEnvError("backup manifest encoding is not canonical")
    return payload


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="action", required=True)

    execute = subparsers.add_parser("exec")
    execute.add_argument("--env-file", type=Path, required=True)
    execute.add_argument("--loader-token-file", type=Path, required=True)
    execute.add_argument("--test-timestamp")
    execute.add_argument("--test-remote-date")
    execute.add_argument("command", nargs=argparse.REMAINDER)

    capability = subparsers.add_parser("verify-capability")
    capability.add_argument("--loader-token-file", type=Path, required=True)

    token = subparsers.add_parser("read-http-token")
    token.add_argument("--token-file", type=Path, required=True)

    create_token = subparsers.add_parser("create-loader-token")
    create_token.add_argument("--path", type=Path, required=True)

    validate_token = subparsers.add_parser("validate-loader-token")
    validate_token.add_argument("--path", type=Path, required=True)

    remote = subparsers.add_parser("read-remote")
    remote.add_argument("--env-file", type=Path, required=True)

    create_staging = subparsers.add_parser("create-staging")
    create_staging.add_argument("--path", type=Path, required=True)
    create_staging.add_argument("--uid", type=int, required=True)
    create_staging.add_argument("--gid", type=int, required=True)

    remove_staging = subparsers.add_parser("remove-staging")
    remove_staging.add_argument("--path", type=Path, required=True)

    data_root = subparsers.add_parser("ensure-service-data-root")
    data_root.add_argument("--path", type=Path, required=True)
    data_root.add_argument("--uid", type=int, required=True)
    data_root.add_argument("--gid", type=int, required=True)

    dates = subparsers.add_parser("validate-dates")
    dates.add_argument("--timestamp", required=True)
    dates.add_argument("--remote-date", required=True)

    layout = subparsers.add_parser("validate-layout")
    layout.add_argument("--backup-dir", type=Path, required=True)
    layout.add_argument("--data-dir", type=Path, required=True)
    layout.add_argument("--contract-dir", type=Path, required=True)
    layout.add_argument("--billing-ledger-path", type=Path, required=True)
    layout.add_argument("--script-dir", type=Path, required=True)
    layout.add_argument("--timestamp", required=True)

    prune = subparsers.add_parser("prune")
    prune.add_argument("--backup-dir", type=Path, required=True)
    prune.add_argument("--retention-days", type=int, required=True)

    snapshot = subparsers.add_parser("snapshot")
    snapshot.add_argument("--source", type=Path, required=True)
    snapshot.add_argument("--destination", type=Path, required=True)
    snapshot.add_argument("--kind", choices=("sqlite", "copy"), required=True)

    manifest = subparsers.add_parser("create-manifest")
    manifest.add_argument("--backup-dir", type=Path, required=True)
    manifest.add_argument("--timestamp", required=True)

    verify_manifest = subparsers.add_parser("verify-manifest")
    verify_manifest.add_argument("--path", type=Path, required=True)

    validate_sqlite = subparsers.add_parser("validate-sqlite")
    validate_sqlite.add_argument("--path", type=Path, required=True)
    validate_sqlite.add_argument(
        "--profile", choices=tuple(SQLITE_PROFILE_COLUMNS), required=True
    )

    validate_keys = subparsers.add_parser("validate-api-keys")
    validate_keys.add_argument("--path", type=Path, required=True)

    restore = subparsers.add_parser("restore-artifact")
    restore.add_argument("--source", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    restore.add_argument("--uid", type=int, required=True)
    restore.add_argument("--gid", type=int, required=True)

    args = parser.parse_args(argv)
    if args.action == "exec":
        if args.command[:1] == ["--"]:
            args.command = args.command[1:]
        if not args.command:
            parser.error("a command is required after --")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        if args.action == "exec":
            environment = environment_for_backup(
                args.env_file,
                os.environ,
                test_timestamp=args.test_timestamp,
                test_remote_date=args.test_remote_date,
            )
            environment[BACKUP_CAPABILITY_ENV] = read_loader_token(
                args.loader_token_file
            )
            lock_descriptor: int | None = None
            if os.geteuid() == 0:
                lock_descriptor = acquire_backup_lock(
                    FIXED_BACKUP_LOCK, production=True
                )
                environment[BACKUP_LOCK_ENV] = "exclusive-v1"
            try:
                os.execve(args.command[0], args.command, environment)
            finally:
                if lock_descriptor is not None:
                    os.close(lock_descriptor)
        elif args.action == "verify-capability":
            provided = os.environ.get(BACKUP_CAPABILITY_ENV, "")
            expected = read_loader_token(args.loader_token_file)
            if not provided or not hmac.compare_digest(provided, expected):
                raise BackupEnvError("backup loader capability is missing or invalid")
        elif args.action == "read-http-token":
            print(
                read_http_token(
                    args.token_file,
                    production=os.geteuid() == 0,
                )
            )
        elif args.action == "create-loader-token":
            create_loader_token(args.path)
        elif args.action == "validate-loader-token":
            read_loader_token(args.path)
        elif args.action == "read-remote":
            if os.geteuid() == 0 and args.env_file != FIXED_ENV_FILE:
                raise BackupEnvError(
                    f"production backup env must be exactly {FIXED_ENV_FILE}"
                )
            settings = parse_data_env(
                read_private_env(args.env_file), production=os.geteuid() == 0
            )
            remote_value = settings.get("HC_BACKUP_REMOTE", "")
            if not remote_value:
                raise BackupEnvError("HC_BACKUP_REMOTE is not configured")
            print(remote_value)
        elif args.action == "create-staging":
            create_staging_directory(args.path, args.uid, args.gid)
        elif args.action == "remove-staging":
            remove_staging_directory(args.path)
        elif args.action == "ensure-service-data-root":
            ensure_service_data_root(args.path, args.uid, args.gid)
        elif args.action == "validate-dates":
            validate_backup_dates(args.timestamp, args.remote_date)
        elif args.action == "validate-layout":
            validate_backup_layout(
                backup_dir=args.backup_dir,
                data_dir=args.data_dir,
                contract_dir=args.contract_dir,
                billing_ledger_path=args.billing_ledger_path,
                script_dir=args.script_dir,
                timestamp=args.timestamp,
            )
        elif args.action == "prune":
            prune_backup_artifacts(args.backup_dir, args.retention_days)
        elif args.action == "snapshot":
            snapshot_source(args.source, args.destination, args.kind)
        elif args.action == "create-manifest":
            print(create_backup_manifest(args.backup_dir, args.timestamp))
        elif args.action == "verify-manifest":
            verify_backup_manifest(args.path)
        elif args.action == "validate-sqlite":
            validate_sqlite_source(args.path, args.profile)
        elif args.action == "validate-api-keys":
            validate_api_key_source(args.path)
        elif args.action == "restore-artifact":
            restore_artifact(args.source, args.destination, args.uid, args.gid)
    except BackupEnvError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"ERROR: cannot execute backup command: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
