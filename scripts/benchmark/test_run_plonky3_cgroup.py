import importlib.util
from pathlib import Path

import pytest


MODULE_PATH = Path(__file__).with_name("run_plonky3_cgroup.py")
SPEC = importlib.util.spec_from_file_location("run_plonky3_cgroup", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_parse_io_stat_sums_devices():
    values = MODULE.parse_key_values(
        "8:0 rbytes=10 wbytes=20 rios=1 wios=2\n8:1 rbytes=30 wbytes=40 rios=3 wios=4"
    )
    assert values["rbytes"] == 40
    assert values["wbytes"] == 60


def test_parse_cpu_usage_and_baseline_path():
    assert MODULE.parse_cpu_stat("usage_usec 1250000\nuser_usec 1000000") == 1.25
    assert MODULE.baseline_report_path(Path("raw/report.json")) == Path(
        "raw/report.baseline.json"
    )


def test_process_rss_reads_linux_status_units(tmp_path, monkeypatch):
    fake_proc = tmp_path / "proc"
    status = fake_proc / "123" / "status"
    status.parent.mkdir(parents=True)
    status.write_text("Name:\ttest\nVmRSS:\t2048 kB\n", encoding="utf-8")
    real_path = MODULE.Path

    def mapped_path(value):
        if value == "/proc":
            return fake_proc
        return real_path(value)

    monkeypatch.setattr(MODULE, "Path", mapped_path)
    assert MODULE.process_rss_bytes(123) == 2 * 1024 * 1024


def test_worker_high_water_mark_is_authoritative_and_required():
    assert MODULE.authoritative_peak_rss({"peak_rss_bytes": 10_000}, 9_000) == 10_000
    assert MODULE.authoritative_peak_rss({"peak_rss_bytes": 9_000}, 10_000) == 10_000
    assert MODULE.authoritative_peak_rss({}, 10_000) == 0
    assert MODULE.authoritative_peak_rss({"peak_rss_bytes": True}, 10_000) == 0


def test_benchmark_runner_uid_honors_sudo_origin(monkeypatch):
    monkeypatch.setattr(MODULE.os, "geteuid", lambda: 0)
    monkeypatch.setenv("SUDO_UID", "1001")
    assert MODULE.benchmark_runner_uid() == 1001

    monkeypatch.setenv("SUDO_UID", "not-a-uid")
    assert MODULE.benchmark_runner_uid() == 0

    monkeypatch.setattr(MODULE.os, "geteuid", lambda: 501)
    monkeypatch.setenv("SUDO_UID", "1001")
    assert MODULE.benchmark_runner_uid() == 501


def test_failed_report_is_persisted_before_gate_failure(tmp_path):
    report_path = tmp_path / "candidate.json"
    report = {
        "verification_succeeded": False,
        "exit_status": 137,
        "failure_diagnostic": "cgroup memory limit reached",
    }

    with pytest.raises(RuntimeError, match="raw report preserved"):
        MODULE.persist_report(report_path, report, "bounded")

    assert report_path.is_file()
    assert "cgroup memory limit reached" in report_path.read_text()


def test_each_run_gets_a_private_normalized_scratch_directory(tmp_path):
    manifest = {
        "resource_policy": {
            "scratch_dir": str(tmp_path / "scratch"),
        }
    }
    first_path, first, first_scratch = MODULE.prepare_run_manifest(
        manifest, tmp_path / "first.json", "bounded"
    )
    second_path, second, second_scratch = MODULE.prepare_run_manifest(
        manifest, tmp_path / "second.json", "bounded"
    )
    try:
        assert first_scratch != second_scratch
        assert first["resource_policy"]["scratch_dir"] == str(first_scratch)
        assert second["resource_policy"]["scratch_dir"] == str(second_scratch)
        assert first_path.is_file() and second_path.is_file()
        assert first_scratch.stat().st_mode & 0o777 == 0o700
        assert first_path.stat().st_mode & 0o777 == 0o600
    finally:
        first_scratch.rmdir()
        second_scratch.rmdir()


def test_conventional_preflight_uses_memory_cap_without_mutating_evidence_manifest():
    manifest = {
        "resource_policy": {
            "mode": "scratch",
            "max_resident_bytes": 128,
            "scratch_dir": "/scratch/run",
        }
    }
    conventional = MODULE.preflight_manifest_payload(manifest, "conventional", 4096)
    bounded = MODULE.preflight_manifest_payload(manifest, "bounded", 4096)

    assert conventional["resource_policy"]["mode"] == "memory"
    assert conventional["resource_policy"]["max_resident_bytes"] == 4096
    assert bounded == manifest
    assert manifest["resource_policy"]["mode"] == "scratch"
    assert manifest["resource_policy"]["max_resident_bytes"] == 128


def test_fixed_host_validation_is_typed_and_fail_closed():
    valid = {
        "logical_cpu_count": 8,
        "total_memory_bytes": 16 * 1024**3,
        "storage_is_rotational": False,
        "storage_is_nvme": True,
        "storage_total_bytes": 1_000_000_000_000,
        "storage_available_bytes": 500_000_000_000,
        "scratch_directory_mode": 0o700,
        "scratch_owned_by_runner": True,
    }
    assert MODULE.fixed_host_failures(valid) == []

    invalid = {
        **valid,
        "logical_cpu_count": 16,
        "total_memory_bytes": 32 * 1024**3,
        "storage_is_rotational": True,
        "storage_is_nvme": False,
        "storage_available_bytes": 499_999_999_999,
        "scratch_directory_mode": 0o755,
        "scratch_owned_by_runner": False,
    }
    failures = MODULE.fixed_host_failures(invalid)
    assert len(failures) == 7
    assert "release scratch storage must have at least 500 GB available" in failures
    assert "release scratch directory must have mode 0700" in failures
    assert "release scratch directory must be owned by the benchmark runner" in failures


def test_cgroup_preflight_requires_all_measurement_controllers(tmp_path, monkeypatch):
    root = tmp_path / "cgroup"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu io memory pids", encoding="utf-8")
    parent = root / "tinyzkp-bench"
    parent.mkdir()
    (parent / "cgroup.controllers").write_text("cpu io memory pids", encoding="utf-8")
    (parent / "cgroup.subtree_control").write_text(
        "cpu io memory pids", encoding="utf-8"
    )
    real_path = MODULE.Path

    def mapped_path(value):
        if value == "/sys/fs/cgroup":
            return root
        return real_path(value)

    monkeypatch.setattr(MODULE, "Path", mapped_path)
    monkeypatch.setattr(MODULE.platform, "system", lambda: "Linux")
    MODULE.ensure_cgroup_v2(parent)

    (parent / "cgroup.controllers").write_text("cpu memory pids", encoding="utf-8")
    with pytest.raises(RuntimeError, match="lacks delegated controllers"):
        MODULE.ensure_cgroup_v2(parent)
