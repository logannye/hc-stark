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
