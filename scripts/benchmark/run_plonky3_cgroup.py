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
import stat
import subprocess
import sys
import tempfile
import time
import uuid


PROFILE = "tinyzkp-p3-goldilocks-v1"
REQUIRED_CGROUP_CONTROLLERS = {"cpu", "io", "memory", "pids"}
MIN_FIXED_HOST_SCRATCH_AVAILABLE_BYTES = 500_000_000_000
MIN_EFFECTIVE_MEMORY_BYTES = 15 * 1024**3
MAX_EFFECTIVE_MEMORY_BYTES = 17 * 1024**3


def valid_resource_estimate(value: object) -> bool:
    if not isinstance(value, dict) or set(value) != {
        "peak_resident_bytes",
        "scratch_high_water_bytes",
        "total_read_bytes",
        "total_write_bytes",
        "phases",
    }:
        return False
    for field in (
        "peak_resident_bytes",
        "scratch_high_water_bytes",
        "total_read_bytes",
        "total_write_bytes",
    ):
        metric = value.get(field)
        if not isinstance(metric, int) or isinstance(metric, bool) or metric < 0:
            return False
    if value["peak_resident_bytes"] == 0 or value["scratch_high_water_bytes"] == 0:
        return False
    phases = value.get("phases")
    return isinstance(phases, list) and all(
        isinstance(phase, dict)
        and set(phase) == {"phase", "read_bytes", "write_bytes"}
        and isinstance(phase.get("phase"), str)
        and bool(phase.get("phase"))
        and all(
            isinstance(phase.get(field), int)
            and not isinstance(phase.get(field), bool)
            and phase.get(field) >= 0
            for field in ("read_bytes", "write_bytes")
        )
        for phase in phases
    )


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


def process_rss_bytes(pid: int) -> int:
    try:
        for line in (Path("/proc") / str(pid) / "status").read_text().splitlines():
            if line.startswith("VmRSS:"):
                fields = line.split()
                if len(fields) >= 2:
                    return int(fields[1]) * 1024
    except (FileNotFoundError, ProcessLookupError, ValueError):
        pass
    return 0


def authoritative_peak_rss(worker: dict[str, object], polled_peak: int) -> int:
    worker_peak = worker.get("peak_rss_bytes")
    if (
        not isinstance(worker_peak, int)
        or isinstance(worker_peak, bool)
        or worker_peak <= 0
    ):
        return 0
    return max(worker_peak, polled_peak)


def write_control(path: Path, value: str) -> None:
    path.write_text(value, encoding="utf-8")


def ensure_cgroup_v2(parent: Path) -> None:
    root = Path("/sys/fs/cgroup")
    if platform.system() != "Linux" or not (root / "cgroup.controllers").is_file():
        raise RuntimeError("release benchmarks require Linux cgroup v2")
    parent.mkdir(parents=True, exist_ok=True)
    if not os.access(parent, os.W_OK):
        raise RuntimeError(f"cgroup parent is not writable: {parent}")
    controllers_path = parent / "cgroup.controllers"
    subtree_path = parent / "cgroup.subtree_control"
    try:
        available = set(controllers_path.read_text(encoding="utf-8").split())
        enabled = set(subtree_path.read_text(encoding="utf-8").split())
    except OSError as error:
        raise RuntimeError("cgroup parent does not expose controller delegation") from error
    missing = REQUIRED_CGROUP_CONTROLLERS - available
    if missing:
        raise RuntimeError(
            "cgroup parent lacks delegated controllers: " + ", ".join(sorted(missing))
        )
    for controller in sorted(REQUIRED_CGROUP_CONTROLLERS - enabled):
        try:
            write_control(subtree_path, f"+{controller}")
        except OSError as error:
            raise RuntimeError(
                f"cannot enable cgroup controller {controller}; run with delegated privileges"
            ) from error
    enabled = set(subtree_path.read_text(encoding="utf-8").split())
    if not REQUIRED_CGROUP_CONTROLLERS.issubset(enabled):
        raise RuntimeError("cgroup controller activation did not persist")


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


def total_memory_bytes() -> int:
    meminfo = Path("/proc/meminfo")
    if meminfo.is_file():
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("MemTotal:"):
                fields = line.split()
                if len(fields) >= 2:
                    return int(fields[1]) * 1024
    page_size = int(os.sysconf("SC_PAGE_SIZE"))
    page_count = int(os.sysconf("SC_PHYS_PAGES"))
    return page_size * page_count


def cgroup_v2_identity() -> tuple[str, Path]:
    """Return the exact unified cgroup that constrains this process."""
    for line in Path("/proc/self/cgroup").read_text(encoding="utf-8").splitlines():
        hierarchy, controllers, relative = line.split(":", 2)
        if hierarchy == "0" and controllers == "":
            identity = "/" + relative.lstrip("/")
            return identity, Path("/sys/fs/cgroup") / identity.lstrip("/")
    raise RuntimeError("process is not attached to a cgroup-v2 hierarchy")


def required_cgroup_limit(path: Path, name: str) -> int:
    raw = (path / name).read_text(encoding="utf-8").strip()
    if raw == "max":
        raise RuntimeError(f"effective cgroup {name} is unbounded")
    try:
        value = int(raw)
    except ValueError as error:
        raise RuntimeError(f"effective cgroup {name} is malformed") from error
    if value < 0:
        raise RuntimeError(f"effective cgroup {name} is negative")
    return value


def benchmark_runner_uid() -> int:
    if os.geteuid() == 0:
        sudo_uid = os.environ.get("SUDO_UID", "")
        if sudo_uid.isascii() and sudo_uid.isdecimal():
            return int(sudo_uid)
    return os.geteuid()


def _block_characteristics(device_id: str) -> tuple[str, bool, bool]:
    link = Path("/sys/dev/block") / device_id
    if not link.exists():
        raise RuntimeError(f"scratch block device is not represented in sysfs: {device_id}")
    root = link.resolve()
    pending = [root]
    visited: set[Path] = set()
    names: set[str] = set()
    rotational_values: list[int] = []
    while pending:
        path = pending.pop()
        if path in visited:
            continue
        visited.add(path)
        names.add(path.name)
        names.update(part for part in path.parts if part.startswith("nvme"))
        for candidate in (path, *path.parents):
            if candidate == Path("/sys"):
                break
            rotational = candidate / "queue" / "rotational"
            if rotational.is_file():
                try:
                    rotational_values.append(int(rotational.read_text().strip()))
                except ValueError:
                    pass
                break
        slaves = path / "slaves"
        if slaves.is_dir():
            pending.extend(child.resolve() for child in slaves.iterdir())
    if not rotational_values:
        raise RuntimeError(f"scratch rotational status is unavailable: {device_id}")
    backing = ",".join(sorted(names))
    is_rotational = any(value != 0 for value in rotational_values)
    is_nvme = any(name.startswith("nvme") for name in names)
    return backing, is_rotational, is_nvme


def collect_host_metadata(scratch: Path) -> dict[str, object]:
    scratch.mkdir(parents=True, exist_ok=True)
    usage = shutil.disk_usage(scratch)
    scratch_stat = scratch.stat()
    device_id = f"{os.major(scratch_stat.st_dev)}:{os.minor(scratch_stat.st_dev)}"
    backing, is_rotational, is_nvme = _block_characteristics(device_id)
    storage_device = f"{device_id}:{backing}"
    cgroup_identity, cgroup_path = cgroup_v2_identity()
    effective_affinity = sorted(os.sched_getaffinity(0))
    return {
        "hardware": hardware_description(),
        "physical_logical_cpu_count": os.cpu_count() or 0,
        "physical_memory_bytes": total_memory_bytes(),
        "effective_cpu_count": len(effective_affinity),
        "effective_cpu_affinity": effective_affinity,
        "effective_memory_max_bytes": required_cgroup_limit(cgroup_path, "memory.max"),
        "effective_swap_max_bytes": required_cgroup_limit(cgroup_path, "memory.swap.max"),
        "cgroup_v2_path": cgroup_identity,
        "operating_system": platform.platform(),
        "storage": (
            f"device={storage_device};rotational={int(is_rotational)};"
            f"nvme={int(is_nvme)};total_bytes={usage.total};"
            f"available_bytes={usage.free}"
        ),
        "storage_device": storage_device,
        "effective_storage_device": storage_device,
        "storage_is_rotational": is_rotational,
        "storage_is_nvme": is_nvme,
        "storage_total_bytes": usage.total,
        "storage_available_bytes": usage.free,
        "scratch_directory_mode": stat.S_IMODE(scratch_stat.st_mode),
        "scratch_owned_by_runner": scratch_stat.st_uid == benchmark_runner_uid(),
    }


def fixed_host_failures(metadata: dict[str, object]) -> list[str]:
    failures: list[str] = []
    affinity = metadata.get("effective_cpu_affinity")
    if (
        metadata.get("effective_cpu_count") != 8
        or not isinstance(affinity, list)
        or len(affinity) != 8
        or any(not isinstance(cpu, int) or isinstance(cpu, bool) or cpu < 0 for cpu in affinity)
        or len(set(affinity)) != 8
    ):
        failures.append("release cgroup must expose exactly 8 effective CPUs")
    memory = metadata.get("effective_memory_max_bytes")
    if (
        not isinstance(memory, int)
        or isinstance(memory, bool)
        or not MIN_EFFECTIVE_MEMORY_BYTES <= memory <= MAX_EFFECTIVE_MEMORY_BYTES
    ):
        failures.append("release cgroup memory must be within the 16-GiB class")
    if metadata.get("effective_swap_max_bytes") != 0:
        failures.append("release cgroup swap must be disabled")
    physical_cpus = metadata.get("physical_logical_cpu_count")
    if not isinstance(physical_cpus, int) or isinstance(physical_cpus, bool) or physical_cpus < 8:
        failures.append("physical host CPU inventory is missing or below 8 CPUs")
    physical_memory = metadata.get("physical_memory_bytes")
    if not isinstance(physical_memory, int) or isinstance(physical_memory, bool) or physical_memory < MIN_EFFECTIVE_MEMORY_BYTES:
        failures.append("physical host memory inventory is missing or below 15 GiB")
    cgroup_identity = metadata.get("cgroup_v2_path")
    if not isinstance(cgroup_identity, str) or not cgroup_identity.startswith("/"):
        failures.append("release cgroup identity is missing")
    if metadata.get("effective_storage_device") != metadata.get("storage_device"):
        failures.append("effective scratch storage identity does not match physical storage")
    if metadata.get("storage_is_rotational") is not False:
        failures.append("release scratch storage must be non-rotational")
    if metadata.get("storage_is_nvme") is not True:
        failures.append("release scratch storage must be backed by NVMe")
    total = metadata.get("storage_total_bytes")
    available = metadata.get("storage_available_bytes")
    if (
        not isinstance(total, int)
        or isinstance(total, bool)
        or total < MIN_FIXED_HOST_SCRATCH_AVAILABLE_BYTES
        or not isinstance(available, int)
        or isinstance(available, bool)
        or available < MIN_FIXED_HOST_SCRATCH_AVAILABLE_BYTES
        or available > total
    ):
        failures.append("release scratch storage must have at least 500 GB available")
    if metadata.get("scratch_directory_mode") != 0o700:
        failures.append("release scratch directory must have mode 0700")
    if metadata.get("scratch_owned_by_runner") is not True:
        failures.append("release scratch directory must be owned by the benchmark runner")
    return failures


def baseline_report_path(report: Path) -> Path:
    suffix = report.suffix or ".json"
    return report.with_name(f"{report.stem}.baseline{suffix}")


def normalized_manifest_path(report: Path, mode: str) -> Path:
    suffix = report.suffix or ".json"
    return report.with_name(f"{report.stem}.{mode}.manifest{suffix}")


def prepare_run_manifest(manifest: dict, report_path: Path, mode: str) -> tuple[Path, dict, Path]:
    configured_root = Path(manifest["resource_policy"]["scratch_dir"])
    configured_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    scratch = Path(tempfile.mkdtemp(prefix=f"tinyzkp-{mode}-", dir=configured_root))
    scratch.chmod(0o700)
    normalized = json.loads(json.dumps(manifest))
    normalized["resource_policy"]["scratch_dir"] = str(scratch)
    path = normalized_manifest_path(report_path, mode)
    write_json(path, normalized)
    return path.resolve(), normalized, scratch


def doctor_metadata(cli: Path, manifest_path: Path) -> dict:
    completed = subprocess.run(
        [str(cli), "plonky3", "doctor", "--manifest", str(manifest_path)],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise RuntimeError(f"resource preflight failed: {completed.stderr[-4000:]}")
    report = json.loads(completed.stdout)
    if not isinstance(report, dict):
        raise RuntimeError("doctor did not return an object")
    return report


def preflight_manifest_payload(manifest: dict, mode: str, memory_cap: int) -> dict:
    payload = json.loads(json.dumps(manifest))
    if mode == "conventional":
        payload["resource_policy"]["mode"] = "memory"
        payload["resource_policy"]["max_resident_bytes"] = memory_cap
    elif mode != "bounded":
        raise RuntimeError("preflight mode must be conventional or bounded")
    return payload


def doctor_estimate(
    cli: Path, manifest_path: Path, mode: str, memory_cap: int
) -> dict:
    source = json.loads(manifest_path.read_text(encoding="utf-8"))
    payload = preflight_manifest_payload(source, mode, memory_cap)
    preflight_path = manifest_path.with_name(
        f".{manifest_path.stem}.preflight-{uuid.uuid4().hex}.json"
    )
    write_json(preflight_path, payload)
    try:
        metadata = doctor_metadata(cli, preflight_path)
    finally:
        preflight_path.unlink(missing_ok=True)
    estimate = metadata.get("estimate")
    if not valid_resource_estimate(estimate):
        raise RuntimeError("doctor did not return a ResourceEstimate")
    return estimate


def run_one(
    *,
    cli: Path,
    manifest: dict,
    mode: str,
    cgroup_parent: Path,
    release_sha: str,
    memory_cap: int,
    report_path: Path,
    source_manifest_digest: str,
    benchmark_session_id: str,
    host_metadata: dict[str, object],
) -> dict:
    cgroup = cgroup_parent / f"tinyzkp-{mode}-{uuid.uuid4().hex}"
    run_manifest_path, _, scratch = prepare_run_manifest(manifest, report_path, mode)
    try:
        preflight_estimate = doctor_estimate(
            cli, run_manifest_path, mode, memory_cap
        )
        configure_cgroup(cgroup, memory_cap)
        with tempfile.TemporaryDirectory(prefix=f"tinyzkp-{mode}-") as temp:
            worker_output = Path(temp) / "worker.json"
            command = [
                str(cli),
                "benchmark-worker",
                "--manifest",
                str(run_manifest_path),
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
            observed_rss_peak = 0
            while process.poll() is None:
                scratch_peak = max(scratch_peak, directory_bytes(scratch))
                observed_rss_peak = max(observed_rss_peak, process_rss_bytes(process.pid))
                time.sleep(0.01)
            stdout, stderr = process.communicate()
            wall_ms = int((time.monotonic() - started) * 1000)
            scratch_peak = max(scratch_peak, directory_bytes(scratch))
            cgroup_peak = read_int(cgroup / "memory.peak")
            cpu_seconds = parse_cpu_stat(
                (cgroup / "cpu.stat").read_text(encoding="utf-8")
            )
            io_values = parse_key_values(
                (cgroup / "io.stat").read_text(encoding="utf-8")
            )
            worker = {}
            if worker_output.is_file():
                worker = json.loads(worker_output.read_text(encoding="utf-8"))
            scratch_peak = max(
                scratch_peak,
                int(worker.get("prover_scratch_high_water_bytes", 0)),
            )
            observed_rss_peak = authoritative_peak_rss(worker, observed_rss_peak)

        verification_succeeded = (
            bool(worker.get("verification_succeeded"))
            and process.returncode == 0
            and observed_rss_peak > 0
        )
        report = {
            "schema_version": 2,
            "scope": "full_pipeline",
            "mode": "baseline" if mode == "conventional" else "bounded",
            "benchmark_session_id": benchmark_session_id,
            **host_metadata,
            "release_sha": release_sha,
            "dependency_profile": PROFILE,
            "exact_command": command,
            "normalized_manifest_path": str(run_manifest_path),
            "workload_manifest_digest_hex": source_manifest_digest,
            "normalized_manifest_digest_hex": worker.get("manifest_digest_hex", ""),
            "preflight_estimate": preflight_estimate,
            "cpu_seconds": cpu_seconds,
            "wall_time_ms": wall_ms,
            "peak_rss_bytes": observed_rss_peak,
            "cgroup_peak_bytes": cgroup_peak,
            "scratch_high_water_bytes": scratch_peak,
            "read_bytes": io_values.get("rbytes", 0),
            "write_bytes": io_values.get("wbytes", 0),
            "proof_size_bytes": int(worker.get("proof_size_bytes", 0)),
            "verification_time_ms": int(worker.get("verification_time_ms", 0)),
            "verification_succeeded": verification_succeeded,
            "exit_status": process.returncode,
        }
        if not verification_succeeded:
            memory_events = ""
            try:
                memory_events = (cgroup / "memory.events").read_text(encoding="utf-8")
            except OSError:
                pass
            diagnostic = (stderr or stdout)[-3000:]
            report["failure_diagnostic"] = (
                f"{diagnostic}\ncgroup memory.events:\n{memory_events}"
            )[-4000:]
        return report
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        try:
            cgroup.rmdir()
        except OSError:
            pass


def write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    descriptor = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
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
    parser.add_argument(
        "--mode",
        choices=["throughput", "ceiling"],
        default="throughput",
        help="throughput compares baseline/candidate; ceiling runs only the bounded candidate",
    )
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
    parser.add_argument(
        "--require-fixed-host",
        action="store_true",
        help="fail unless the host is the release 8-vCPU/16-GB/NVMe class",
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
    host_metadata = collect_host_metadata(
        Path(manifest["resource_policy"]["scratch_dir"])
    )
    if args.require_fixed_host:
        failures = fixed_host_failures(host_metadata)
        if failures:
            raise RuntimeError("; ".join(failures))
    benchmark_session_id = uuid.uuid4().hex
    source_manifest_digest = doctor_metadata(cli, args.manifest.resolve()).get(
        "manifest_digest_hex"
    )
    if not isinstance(source_manifest_digest, str) or len(source_manifest_digest) != 64:
        raise RuntimeError("doctor did not return the source manifest digest")
    candidate_memory_cap = int(manifest["resource_policy"]["max_resident_bytes"])
    baseline_memory_cap = args.baseline_memory_cap or candidate_memory_cap
    if baseline_memory_cap < candidate_memory_cap:
        raise RuntimeError("baseline memory cap cannot be below the candidate manifest cap")

    baseline = None
    baseline_path = None
    if args.mode == "throughput":
        baseline_path = baseline_report_path(args.report)
        baseline = run_one(
            cli=cli,
            manifest=manifest,
            mode="conventional",
            cgroup_parent=args.cgroup_parent,
            release_sha=release_sha,
            memory_cap=baseline_memory_cap,
            report_path=baseline_path,
            source_manifest_digest=source_manifest_digest,
            benchmark_session_id=benchmark_session_id,
            host_metadata=host_metadata,
        )
        persist_report(baseline_path, baseline, "conventional")
    candidate = run_one(
        cli=cli,
        manifest=manifest,
        mode="bounded",
        cgroup_parent=args.cgroup_parent,
        release_sha=release_sha,
        memory_cap=candidate_memory_cap,
        report_path=args.report,
        source_manifest_digest=source_manifest_digest,
        benchmark_session_id=benchmark_session_id,
        host_metadata=host_metadata,
    )
    persist_report(args.report, candidate, "bounded")
    print(
        json.dumps(
            {
                "candidate_report": str(args.report),
                "baseline_report": str(baseline_path) if baseline_path else None,
                "ram_reduction": (
                    baseline["peak_rss_bytes"] / candidate["peak_rss_bytes"]
                    if baseline and candidate["peak_rss_bytes"]
                    else None
                ),
                "wall_time_ratio": (
                    candidate["wall_time_ms"] / baseline["wall_time_ms"]
                    if baseline and baseline["wall_time_ms"]
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
