#!/usr/bin/env python3
"""Execute one release command and emit a release-bound, hashed test report."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


PROFILE = "tinyzkp-p3-goldilocks-v1"


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


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


def run(
    *,
    command: list[str],
    release_sha: str,
    execution_profile: str,
    report_path: Path,
    log_path: Path,
    cwd: Path,
) -> dict[str, object]:
    if not command or any(not value or "\0" in value for value in command):
        raise ValueError("evidenced command must contain non-empty arguments")
    if not release_sha or len(release_sha) > 128:
        raise ValueError("release SHA must be non-empty and at most 128 characters")
    if execution_profile not in {"ci", "release"}:
        raise ValueError("execution profile must be ci or release")
    log_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    environment = os.environ.copy()
    environment["HC_RELEASE_SHA"] = release_sha
    started_at = timestamp()
    started = time.monotonic()
    with os.fdopen(descriptor, "wb") as log:
        completed = subprocess.run(
            command,
            cwd=cwd,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=False,
        )
        log.flush()
        os.fsync(log.fileno())
    log_bytes = log_path.read_bytes()
    report: dict[str, object] = {
        "schema_version": 1,
        "release_sha": release_sha,
        "profile": PROFILE,
        "execution_profile": execution_profile,
        "command": command,
        "exit_status": completed.returncode,
        "started_at": started_at,
        "finished_at": timestamp(),
        "duration_ms": int((time.monotonic() - started) * 1000),
        "log_bytes": len(log_bytes),
        "log_sha256": hashlib.sha256(log_bytes).hexdigest(),
    }
    write_json_atomic(report_path, report)
    return report


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--execution-profile", choices=("ci", "release"), required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--cwd", type=Path, default=Path.cwd())
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        report = run(
            command=command,
            release_sha=args.release_sha,
            execution_profile=args.execution_profile,
            report_path=args.report,
            log_path=args.log,
            cwd=args.cwd.resolve(),
        )
    except (OSError, ValueError) as error:
        print(f"evidenced command failed to run: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["exit_status"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
