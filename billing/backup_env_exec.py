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
import os
from pathlib import Path
import re
import stat
import sys
from urllib.parse import urlparse


MAX_ENV_BYTES = 64 * 1024
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


class BackupEnvError(ValueError):
    """A deployment env file is unsafe or is not data-only."""


def read_private_env(path: Path) -> bytes:
    """Read an owner-only regular file once, refusing symlinks and races."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BackupEnvError(
            f"backup env file is unavailable or unsafe: {path}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise BackupEnvError("backup env file must be a regular non-symlink file")
        if metadata.st_uid != os.geteuid():
            raise BackupEnvError(
                "backup env file must be owned by the current operator"
            )
        if stat.S_IMODE(metadata.st_mode) & 0o077:
            raise BackupEnvError(
                "backup env file must be owner-only (0600 or stricter)"
            )
        chunks = bytearray()
        while len(chunks) <= MAX_ENV_BYTES:
            chunk = os.read(
                descriptor,
                min(8192, MAX_ENV_BYTES + 1 - len(chunks)),
            )
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
    finally:
        os.close(descriptor)
    if not raw:
        raise BackupEnvError("backup env file is empty")
    if len(raw) > MAX_ENV_BYTES:
        raise BackupEnvError("backup env file exceeds 64 KiB")
    return raw


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


def parse_data_env(raw: bytes) -> dict[str, str]:
    settings = {
        key: value
        for key, value in parse_data_assignments(raw).items()
        if key in BACKUP_KEYS
    }
    validate_backup_values(settings)
    return settings


def validate_backup_values(settings: dict[str, str]) -> None:
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


def environment_for_backup(path: Path, inherited: dict[str, str]) -> dict[str, str]:
    environment = dict(inherited)
    environment.update(parse_data_env(read_private_env(path)))
    validate_backup_values(
        {key: environment[key] for key in BACKUP_KEYS if key in environment}
    )
    environment["TINYZKP_BACKUP_ENV_LOADED"] = "1"
    return environment


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    try:
        environment = environment_for_backup(args.env_file, os.environ)
        os.execve(args.command[0], args.command, environment)
    except BackupEnvError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"ERROR: cannot execute backup command: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
