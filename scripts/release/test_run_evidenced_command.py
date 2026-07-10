import hashlib
import importlib.util
import json
from pathlib import Path
import stat
import sys


MODULE_PATH = Path(__file__).with_name("run_evidenced_command.py")
SPEC = importlib.util.spec_from_file_location("run_evidenced_command", MODULE_PATH)
assert SPEC and SPEC.loader
module = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = module
SPEC.loader.exec_module(module)


def test_successful_command_is_release_bound_and_hashed(tmp_path):
    report_path = tmp_path / "report.json"
    log_path = tmp_path / "command.log"
    report = module.run(
        command=["/usr/bin/printf", "verified output"],
        release_sha="abc123",
        execution_profile="release",
        report_path=report_path,
        log_path=log_path,
        cwd=tmp_path,
    )
    assert report["exit_status"] == 0
    assert report["release_sha"] == "abc123"
    assert report["log_sha256"] == hashlib.sha256(log_path.read_bytes()).hexdigest()
    assert json.loads(report_path.read_text()) == report
    assert stat.S_IMODE(report_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(log_path.stat().st_mode) == 0o600


def test_failing_command_is_recorded_without_shell_interpretation(tmp_path):
    report = module.run(
        command=["/bin/sh", "-c", "exit 7"],
        release_sha="abc123",
        execution_profile="ci",
        report_path=tmp_path / "report.json",
        log_path=tmp_path / "command.log",
        cwd=tmp_path,
    )
    assert report["exit_status"] == 7
