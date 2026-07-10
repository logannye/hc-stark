import importlib.util
from pathlib import Path
import subprocess


MODULE_PATH = Path(__file__).with_name("run_fuzz_smoke.py")
SPEC = importlib.util.spec_from_file_location("run_fuzz_smoke", MODULE_PATH)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_all_backend_fuzz_surfaces_are_included():
    assert MODULE.TARGETS == (
        "workload_manifest_v1",
        "proof_bundle_v1",
        "plonky3_proof_bytes_v1",
        "benchmark_report_v1",
        "checkpoint_manifest_v2",
        "challenger_snapshot_v1",
        "scratch_artifact_header_v1",
        "checkpoint_identity_v2",
        "resume_checkpoint_v2",
    )


def test_run_target_hashes_log_and_pins_nightly_command(tmp_path, monkeypatch):
    def fake_run(command, **kwargs):
        kwargs["stdout"].write(b"fuzz target passed\n")
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(MODULE.subprocess, "run", fake_run)
    monkeypatch.setattr(MODULE, "ROOT", tmp_path)
    result = MODULE.run_target(
        "proof_bundle_v1",
        seconds=5,
        rss_limit_mb=256,
        log_dir=tmp_path / "logs",
    )
    assert result["exit_status"] == 0
    assert result["command"][:4] == ["cargo", "+nightly", "fuzz", "run"]
    assert len(result["log_sha256"]) == 64
    assert Path(result["log_path"]).read_text() == "fuzz target passed\n"
