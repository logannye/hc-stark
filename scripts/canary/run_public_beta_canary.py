#!/usr/bin/env python3
"""Run and durably record the exact 24-hour public-beta canary contract."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time


WORKLOADS = ("fibonacci", "poseidon2", "customer_cubic8")
ZERO_FIELDS = (
    "verifier_failures",
    "unexplained_credit_differences",
    "stuck_leases",
    "unauthorized_artifact_accesses",
    "leaked_scratch_directories",
)
RELEASE_DURATION_SECONDS = 24 * 60 * 60
RELEASE_PROOF_INTERVAL_SECONDS = 60 * 60
RELEASE_CANCELLATION_INTERVAL_SECONDS = 6 * 60 * 60


def utc(epoch: float | None = None) -> str:
    return datetime.fromtimestamp(epoch or time.time(), timezone.utc).replace(
        microsecond=0
    ).isoformat()


def driver_identity(path: Path) -> str:
    if path.is_symlink():
        raise ValueError("canary driver must not be a symlink")
    path = path.resolve(strict=True)
    details = path.stat()
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_uid != os.geteuid()
        or details.st_nlink != 1
        or not os.access(path, os.X_OK)
    ):
        raise ValueError("canary driver must be an executable regular file")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def new_state(release_sha: str, driver_sha256: str, started_epoch: float) -> dict:
    return {
        "schema_version": 1,
        "release_channel": "public_beta",
        "release_sha": release_sha,
        "driver_sha256": driver_sha256,
        "started_at": utc(started_epoch),
        "started_epoch": started_epoch,
        "completed_at": None,
        "hourly_verified_proofs": [],
        "cancellation_refund_exercises": [],
        "live_billing_canaries": [],
        **{field: None for field in ZERO_FIELDS},
        "status": "running",
    }


def write_state(path: Path, state: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    details = parent.stat()
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_uid != os.geteuid()
        or stat.S_IMODE(details.st_mode) != 0o700
    ):
        raise ValueError("canary state directory must be owner-only")
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def invoke(driver: Path, arguments: list[str], environment: dict[str, str]) -> dict:
    completed = subprocess.run(
        [str(driver), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=60 * 65,
        check=False,
        env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"canary driver {' '.join(arguments)} failed: {completed.stderr[-1000:]}"
        )
    try:
        value = json.loads(completed.stdout)
    except ValueError as error:
        raise RuntimeError("canary driver returned malformed JSON") from error
    if not isinstance(value, dict):
        raise RuntimeError("canary driver result must be a JSON object")
    return value


def validate_event(kind: str, value: dict, expected: str | None = None) -> dict:
    if kind == "proof":
        if value.get("workload") != expected or value.get("official_verification") is not True:
            raise RuntimeError("canary proof did not officially verify")
    elif kind == "cancel":
        if value.get("full_reservation_released") is not True:
            raise RuntimeError("canary cancellation did not release the full reservation")
    elif kind == "billing":
        if (
            value.get("kind") != expected
            or value.get("synthetic") is not True
            or value.get("refunded") is not True
            or value.get("excluded_from_revenue") is not True
            or (expected == "subscription" and value.get("cancelled") is not True)
        ):
            raise RuntimeError("live billing canary is incomplete")
    return value


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", type=Path, required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--driver-env", action="append", default=[])
    parser.add_argument("--partial", action="store_true")
    parser.add_argument("--duration-seconds", type=int, default=RELEASE_DURATION_SECONDS)
    parser.add_argument(
        "--proof-interval-seconds", type=int, default=RELEASE_PROOF_INTERVAL_SECONDS
    )
    parser.add_argument(
        "--cancellation-interval-seconds",
        type=int,
        default=RELEASE_CANCELLATION_INTERVAL_SECONDS,
    )
    args = parser.parse_args()
    if len(args.release_sha) != 40 or any(
        byte not in "0123456789abcdef" for byte in args.release_sha
    ):
        raise SystemExit("release SHA must be a full lowercase Git commit")
    if not args.partial and (
        args.duration_seconds != RELEASE_DURATION_SECONDS
        or args.proof_interval_seconds != RELEASE_PROOF_INTERVAL_SECONDS
        or args.cancellation_interval_seconds
        != RELEASE_CANCELLATION_INTERVAL_SECONDS
    ):
        raise SystemExit("release canary timing is frozen; use --partial for development")
    if min(
        args.duration_seconds,
        args.proof_interval_seconds,
        args.cancellation_interval_seconds,
    ) <= 0:
        raise SystemExit("canary timing values must be positive")

    driver = args.driver.resolve(strict=True)
    identity = driver_identity(driver)
    environment = {"PATH": "/usr/local/bin:/usr/bin:/bin"}
    for name in args.driver_env:
        if name not in os.environ or not name.isidentifier():
            raise SystemExit(f"missing or invalid driver environment name: {name}")
        environment[name] = os.environ[name]
    if args.state.is_symlink():
        raise SystemExit("canary state must not be a symlink")
    if args.state.exists():
        details = args.state.stat()
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid != os.geteuid()
            or details.st_nlink != 1
            or stat.S_IMODE(details.st_mode) != 0o600
        ):
            raise SystemExit("canary state must be an owner-only regular file")
        state = json.loads(args.state.read_text(encoding="utf-8"))
        if (
            state.get("release_sha") != args.release_sha
            or state.get("driver_sha256") != identity
            or state.get("status") != "running"
        ):
            raise SystemExit("existing canary state is not resumable for this release/driver")
    else:
        state = new_state(args.release_sha, identity, time.time())
        write_state(args.state, state)

    for billing_kind in ("topup", "subscription"):
        if not any(
            item.get("kind") == billing_kind
            for item in state["live_billing_canaries"]
        ):
            result = validate_event(
                "billing",
                invoke(driver, ["billing", billing_kind], environment),
                billing_kind,
            )
            result["recorded_at"] = utc()
            state["live_billing_canaries"].append(result)
            write_state(args.state, state)

    started = float(state["started_epoch"])
    required_proofs = math.ceil(args.duration_seconds / args.proof_interval_seconds)
    required_cancellations = math.ceil(
        args.duration_seconds / args.cancellation_interval_seconds
    )
    while time.time() - started < args.duration_seconds or len(
        state["hourly_verified_proofs"]
    ) < required_proofs:
        proof_index = len(state["hourly_verified_proofs"])
        if proof_index < required_proofs and time.time() >= started + (
            proof_index * args.proof_interval_seconds
        ):
            workload = WORKLOADS[proof_index % len(WORKLOADS)]
            result = validate_event(
                "proof", invoke(driver, ["proof", workload], environment), workload
            )
            result["recorded_at"] = utc()
            state["hourly_verified_proofs"].append(result)
            write_state(args.state, state)
        cancellation_index = len(state["cancellation_refund_exercises"])
        if cancellation_index < required_cancellations and time.time() >= started + (
            cancellation_index * args.cancellation_interval_seconds
        ):
            result = validate_event(
                "cancel", invoke(driver, ["cancel"], environment)
            )
            result["recorded_at"] = utc()
            state["cancellation_refund_exercises"].append(result)
            write_state(args.state, state)
        if time.time() - started < args.duration_seconds:
            time.sleep(min(30, max(1, args.proof_interval_seconds // 10)))

    audit = invoke(driver, ["audit"], environment)
    for field in ZERO_FIELDS:
        value = audit.get(field)
        if value != 0:
            raise RuntimeError(f"canary audit requires {field}=0")
        state[field] = 0
    state["completed_at"] = utc()
    state["status"] = "passed"
    state.pop("started_epoch", None)
    write_state(args.state, state)


if __name__ == "__main__":
    main()
