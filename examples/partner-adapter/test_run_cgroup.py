import importlib.util
import json
from pathlib import Path
import subprocess


MODULE_PATH = Path(__file__).with_name("run_cgroup.py")
SPEC = importlib.util.spec_from_file_location("partner_run_cgroup", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_doctor_requires_profile_and_preflight_estimate(tmp_path, monkeypatch):
    binary = tmp_path / "partner-adapter"
    binary.write_bytes(b"binary")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    def fake_run(command, **_kwargs):
        output = Path(command[-1])
        output.write_text(
            json.dumps(
                {
                    "mode": "doctor",
                    "profile": MODULE.PROFILE,
                    "manifest_digest_hex": "a" * 64,
                    "preflight_estimate": {
                        "peak_resident_bytes": 1,
                        "scratch_high_water_bytes": 1,
                        "total_read_bytes": 0,
                        "total_write_bytes": 0,
                        "phases": [],
                    },
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    result = MODULE.run_doctor(binary, manifest)
    assert result["manifest_digest_hex"] == "a" * 64
    assert result["preflight_estimate"]["peak_resident_bytes"] == 1


def test_doctor_rejects_partial_preflight_estimate(tmp_path, monkeypatch):
    binary = tmp_path / "partner-adapter"
    binary.write_bytes(b"binary")
    manifest = tmp_path / "manifest.json"
    manifest.write_text("{}", encoding="utf-8")

    def fake_run(command, **_kwargs):
        Path(command[-1]).write_text(
            json.dumps(
                {
                    "mode": "doctor",
                    "profile": MODULE.PROFILE,
                    "preflight_estimate": {"peak_resident_bytes": 1},
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, "", "")

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    try:
        MODULE.run_doctor(binary, manifest)
    except RuntimeError as error:
        assert "malformed evidence" in str(error)
    else:
        raise AssertionError("partial partner preflight estimate was accepted")
