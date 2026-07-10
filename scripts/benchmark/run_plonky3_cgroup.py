#!/usr/bin/env python3
"""Run conventional and bounded Plonky3 proofs in fresh cgroup-v2 children.

The requested report path receives the bounded BenchmarkReportV1. A sibling
`*.baseline.json` contains the conventional report. The script refuses to run
without enforceable cgroup v2 controls; component-only/macOS measurements must
not be presented as release evidence.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import time
import uuid


PROFILE = "tinyzkp-p3-goldilocks-v1"


def parse_key_values(text: str) -> dict[str, int]:
    values: dict[str, int] = {}
    for token in text.split():
        if "=" not in token:
            continue
        key, raw = token.split("=", 1)
        try:
            values[key] = values.get(key, 0) + int(raw)
        except ValueError:
            continue
    return values


def parse_cpu_stat(text: str) -> float:
    fields = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            try:
                fields[parts[0]] = int(parts[1])
            except ValueError:
                pass
    return fields.get("usage_usec", 0) / 1_000_000


def directory_bytes(root: Path) -> int:
    if not root.exists():
        return 0
    total = 0
    for path in root.rglob("*"):
        try:
            if path.is_file() and not path.is_symlink():
                total += path.stat().st_size
        except FileNotFoundError:
            pass
    return total


def read_int(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (FileNotFoundError, ValueError):
        return 0


def write_control(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def ensure_cgroup_v2(parent: Path) -> None:
    root = Path("/sys/fs/cgroup")
    if platform.system() != "Linux" or not (root / "cgroup.controllers").is_file():
        raise RuntimeError("release benchmarks require Linux cgroup v2")
    parent.mkdir(parents=True, exist_ok=True)
    if not os.access(parent, os.W_OK):
        raise RuntimeError(f"cgroup parent is not writable: {parent}")


def configure_cgroup(path: Path, memory_cap: int) -> None:
    path.mkdir()
    write_control(path / "memory.max", str(memory_cap))
    if (path / "memory.swap.max").exists():
        write_control(path / "memory.swap.max", "0")
    if (path / "pids.max").exists():
        write_control(path / "pids.max", "512")


def child_join_cgroup(path: Path):
    def join() -> None:
        write_control(path / "cgroup.procs", str(os.getpid()))

    return join


def hardware_description() -> str:
    model = platform.processor() or platform.machine()
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.is_file():
        for line in cpuinfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.lower().startswith("model name") and ":" in line:
                model = line.split(":", 1)[1].strip()
                break
    return f"{model}; logical_cpus={os.cpu_count() or 0}"


def storage_description(scratch: Path) -> str:
    scratch.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(scratch)
    return f"path={scratch}; total_bytes={usage.total}; free_bytes={usage.free}"


def baseline_report_path(report: Path) -> Path:
    suffix = report.suffix or ".json"
    return report.with_name(f"{report.stem}.baseline{suffix}")


def run_one(
    *,
    cli: Path,
    manifest_path: Path,
    manifest: dict,
    mode: str,
    cgroup_parent: Path,
    release_sha: str,
    memory_cap: int,
) -> dict:
    cgroup = cgroup_parent / f"tinyzkp-{mode}-{uuid.uuid4().hex}"
    configure_cgroup(cgroup, memory_cap)
    scratch = Path(manifest["resource_policy"]["scratch_dir"])

    with tempfile.TemporaryDirectory(prefix=f"tinyzkp-{mode}-") as temp:
        worker_output = Path(temp) / "worker.json"
        command = [
            str(cli),
            "benchmark-worker",
            "--manifest",
            str(manifest_path),
            "--mode",
            mode,
            "--output",
            str(worker_output),
        ]
        started = time.monotonic()
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            preexec_fn=child_join_cgroup(cgroup),
        )
        scratch_peak = 0
        observed_memory_peak = 0
        while process.poll() is None:
            scratch_peak = max(scratch_peak, directory_bytes(scratch))
            observed_memory_peak = max(observed_memory_peak, read_int(cgroup / "memory.current"))
            time.sleep(0.01)
        stdout, stderr = process.communicate()
        wall_ms = int((time.monotonic() - started) * 1000)
        scratch_peak = max(scratch_peak, directory_bytes(scratch))
        memory_peak = max(observed_memory_peak, read_int(cgroup / "memory.peak"))
        cpu_seconds = parse_cpu_stat((cgroup / "cpu.stat").read_text(encoding="utf-8"))
        io_values = parse_key_values((cgroup / "io.stat").read_text(encoding="utf-8"))
        worker = {}
        if worker_output.is_file():
            worker = json.loads(worker_output.read_text(encoding="utf-8"))

    try:
        cgroup.rmdir()
    except OSError:
        pass

    verification_succeeded = bool(worker.get("verification_succeeded")) and process.returncode == 0
    report = {
        "schema_version": 1,
        "scope": "full_pipeline",
        "mode": "baseline" if mode == "conventional" else "bounded",
        "hardware": hardware_description(),
        "operating_system": platform.platform(),
        "storage": storage_description(scratch),
        "release_sha": release_sha,
        "dependency_profile": PROFILE,
        "exact_command": command,
        "workload_manifest_digest_hex": worker.get("manifest_digest_hex", ""),
        "cpu_seconds": cpu_seconds,
        "wall_time_ms": wall_ms,
        "peak_rss_bytes": memory_peak,
        "scratch_high_water_bytes": scratch_peak,
        "read_bytes": io_values.get("rbytes", 0),
        "write_bytes": io_values.get("wbytes", 0),
        "proof_size_bytes": int(worker.get("proof_size_bytes", 0)),
        "verification_time_ms": int(worker.get("verification_time_ms", 0)),
        "verification_succeeded": verification_succeeded,
        "exit_status": process.returncode,
    }
    if not verification_succeeded:
        report["failure_diagnostic"] = (stderr or stdout)[-4000:]
    return report


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    with temp.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temp, path)


def persist_report(path: Path, report: dict, label: str) -> None:
    """Persist raw evidence before converting an unsuccessful run into a gate failure."""
    write_json(path, report)
    if not report.get("verification_succeeded"):
        raise RuntimeError(
            f"{label} worker failed with exit {report.get('exit_status')}; "
            f"raw report preserved at {path}"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--baseline", choices=["conventional"], default="conventional")
    parser.add_argument("--candidate", choices=["bounded"], default="bounded")
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--hc-cli", type=Path, default=Path("target/release/hc-cli"))
    parser.add_argument(
        "--baseline-memory-cap",
        type=int,
        help="Optional conventional-process cap; candidate always uses the manifest cap",
    )
    parser.add_argument(
        "--cgroup-parent", type=Path, default=Path("/sys/fs/cgroup/tinyzkp-bench")
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    ensure_cgroup_v2(args.cgroup_parent)
    manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
    if manifest.get("profile") != PROFILE:
        raise RuntimeError("manifest does not use the frozen Plonky3 profile")
    cli = args.hc_cli.resolve()
    if not cli.is_file():
        raise RuntimeError(f"hc-cli release binary not found: {cli}")
    release_sha = os.environ.get("HC_RELEASE_SHA", "development-unreleased")
    candidate_memory_cap = int(manifest["resource_policy"]["max_resident_bytes"])
    baseline_memory_cap = args.baseline_memory_cap or candidate_memory_cap
    if baseline_memory_cap < candidate_memory_cap:
        raise RuntimeError("baseline memory cap cannot be below the candidate manifest cap")

    baseline_path = baseline_report_path(args.report)
    baseline = run_one(
        cli=cli,
        manifest_path=args.manifest.resolve(),
        manifest=manifest,
        mode=args.baseline,
        cgroup_parent=args.cgroup_parent,
        release_sha=release_sha,
        memory_cap=baseline_memory_cap,
    )
    persist_report(baseline_path, baseline, "conventional")
    candidate = run_one(
        cli=cli,
        manifest_path=args.manifest.resolve(),
        manifest=manifest,
        mode=args.candidate,
        cgroup_parent=args.cgroup_parent,
        release_sha=release_sha,
        memory_cap=candidate_memory_cap,
    )
    persist_report(args.report, candidate, "bounded")
    print(
        json.dumps(
            {
                "candidate_report": str(args.report),
                "baseline_report": str(baseline_path),
                "ram_reduction": (
                    baseline["peak_rss_bytes"] / candidate["peak_rss_bytes"]
                    if candidate["peak_rss_bytes"]
                    else None
                ),
                "wall_time_ratio": (
                    candidate["wall_time_ms"] / baseline["wall_time_ms"]
                    if baseline["wall_time_ms"]
                    else None
                ),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as error:
        print(f"benchmark failed: {error}", file=sys.stderr)
        raise SystemExit(2)
