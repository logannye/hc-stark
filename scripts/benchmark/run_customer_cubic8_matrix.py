#!/usr/bin/env python3
"""Run the resumable fixed-host customer_cubic8 public-beta matrix."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import uuid
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
BENCHMARK = ROOT / "scripts" / "benchmark"
SCHEMA = "customer-cubic8-fixed-host-matrix-v1"
ENTRIES = (
    ("reference_1m", 1_048_576, "reference", "customer-cubic8-1m.reference.json"),
    ("bounded_1m", 1_048_576, "bounded", "customer-cubic8-1m.bounded.json"),
    ("bounded_16m", 16_777_216, "bounded", "customer-cubic8-16m.bounded.json"),
)


def load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PREFLIGHT = load_module("customer_cubic8_preflight", BENCHMARK / "fixed_host_preflight.py")
VALIDATOR = load_module("customer_cubic8_validator", BENCHMARK / "validate_customer_cubic8.py")


def now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_directory(path: Path) -> Path:
    path = path.absolute()
    if path.resolve(strict=False) != path:
        raise ValueError(f"path contains a symlink component: {path}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    details = path.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o700:
        raise ValueError(f"directory must be operator-owned and mode 0700: {path}")
    return path


def write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def source_identity(release_sha: str) -> None:
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    if head != release_sha:
        raise ValueError("customer_cubic8 source does not match the candidate")
    status = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=ROOT, text=True
    )
    if status:
        raise ValueError("customer_cubic8 evidence requires a clean source tree")


def cli_identity(cli: Path, release_sha: str) -> dict[str, Any]:
    environment = dict(os.environ)
    environment.pop("HC_RELEASE_SHA", None)
    completed = subprocess.run(
        [str(cli), "release"],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        check=False,
        timeout=30,
    )
    value = json.loads(completed.stdout)
    if completed.returncode != 0 or value.get("release_sha") != release_sha:
        raise ValueError("signed CLI identity does not match the candidate")
    return value


def descriptor(path: Path, output: Path) -> dict[str, Any]:
    details = path.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
        raise ValueError(f"report is not operator-owned and mode 0600: {path}")
    return {
        "path": path.relative_to(output).as_posix(),
        "sha256": sha256_file(path),
    }


def validate_descriptor(value: object, output: Path) -> Path:
    if not isinstance(value, dict) or set(value) != {"path", "sha256"}:
        raise ValueError("customer_cubic8 report descriptor is malformed")
    path = (output / str(value["path"])).resolve()
    path.relative_to(output.resolve())
    if not path.is_file() or sha256_file(path) != value["sha256"]:
        raise ValueError("customer_cubic8 report digest changed")
    details = path.stat()
    if details.st_uid != os.geteuid() or stat.S_IMODE(details.st_mode) != 0o600:
        raise ValueError("customer_cubic8 report permissions changed")
    return path


def validate_reports(reports: dict[str, object], output: Path) -> None:
    if set(reports) != {entry[0] for entry in ENTRIES}:
        raise ValueError("customer_cubic8 report set is incomplete")
    loaded = {
        role: VALIDATOR.load(validate_descriptor(value, output))
        for role, value in reports.items()
    }
    VALIDATOR.validate(
        loaded["reference_1m"], loaded["bounded_1m"], loaded["bounded_16m"]
    )


def execute(args: argparse.Namespace) -> None:
    if len(args.release_sha) != 40 or any(character not in "0123456789abcdef" for character in args.release_sha):
        raise ValueError("release SHA must be canonical")
    output = private_directory(args.output_dir)
    work_root = private_directory(args.work_root)
    state_path = output / "customer-cubic8-fixed-host-matrix-v1.json"
    source_identity(args.release_sha)
    cli = args.cli.absolute()
    identity = cli_identity(cli, args.release_sha)
    preflight = PREFLIGHT.check(work_root, args.cgroup_parent.absolute())
    if preflight.get("passed") is not True:
        raise ValueError("customer_cubic8 fixed-host preflight failed: " + "; ".join(preflight["failures"]))
    host = preflight["host"]

    if state_path.exists():
        state = json.loads(state_path.read_text(encoding="utf-8"))
        if (
            state.get("schema_version") != SCHEMA
            or state.get("release_sha") != args.release_sha
            or state.get("cli_sha256") != sha256_file(cli)
            or state.get("host_identity") != host
        ):
            raise ValueError("customer_cubic8 matrix resume identity changed")
    else:
        state = {
            "schema_version": SCHEMA,
            "status": "running",
            "release_sha": args.release_sha,
            "created_at": now(),
            "completed_at": None,
            "cli_sha256": sha256_file(cli),
            "cli_identity": identity,
            "host_identity": host,
            "entries": {role: {"status": "pending", "attempts": 0} for role, *_ in ENTRIES},
            "reports": {},
            "local_matrix_gates_passed": False,
            "last_error": None,
        }
        write_private_json(state_path, state)

    environment = dict(os.environ)
    environment["HC_RELEASE_SHA"] = args.release_sha
    try:
        for role, rows, mode, filename in ENTRIES:
            existing = state["reports"].get(role)
            if state["entries"][role].get("status") == "complete" and existing:
                validate_descriptor(existing, output)
                print(f"SKIP {role}: report digest revalidated", flush=True)
                continue
            state["status"] = f"running:{role}"
            state["entries"][role]["status"] = "running"
            state["entries"][role]["attempts"] = int(state["entries"][role]["attempts"]) + 1
            write_private_json(state_path, state)
            report = output / filename
            if report.exists():
                report.unlink()
            work = work_root / f"{role}-{uuid.uuid4().hex}"
            command = [
                sys.executable,
                str(BENCHMARK / "run_customer_cubic8.py"),
                "--rows",
                str(rows),
                "--mode",
                mode,
                "--cli",
                str(cli),
                "--work",
                str(work),
                "--output",
                str(report),
                "--release-sha",
                args.release_sha,
            ]
            print(f"RUN  {role}", flush=True)
            try:
                subprocess.run(command, cwd=ROOT, env=environment, check=True)
            finally:
                shutil.rmtree(work, ignore_errors=True)
            state["reports"][role] = descriptor(report, output)
            state["entries"][role]["status"] = "complete"
            write_private_json(state_path, state)
        validate_reports(state["reports"], output)
        state["status"] = "passed"
        state["local_matrix_gates_passed"] = True
        state["completed_at"] = now()
        state["last_error"] = None
        write_private_json(state_path, state)
    except Exception as error:
        state["status"] = "failed"
        state["local_matrix_gates_passed"] = False
        state["last_error"] = str(error)[-2000:]
        write_private_json(state_path, state)
        raise
    print(json.dumps({"status": "passed", "matrix": str(state_path)}))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--cli", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--work-root", type=Path, required=True)
    parser.add_argument(
        "--cgroup-parent",
        type=Path,
        default=Path("/sys/fs/cgroup/tinyzkp-bench"),
    )
    execute(parser.parse_args())


if __name__ == "__main__":
    main()
